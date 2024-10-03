// Copyright (C) Microsoft Corporation. All rights reserved.

//! TTRPC server.

use crate::message::read_message;
use crate::message::write_message;
use crate::message::ReadResult;
use crate::message::Request;
use crate::message::Response;
use crate::message::TooLongError;
use crate::message::MESSAGE_TYPE_REQUEST;
use crate::message::MESSAGE_TYPE_RESPONSE;
use crate::rpc::status_from_err;
use crate::rpc::ProtocolError;
use crate::service::Code;
use crate::service::GenericRpc;
use crate::service::ServiceRpc;
use crate::service::Status;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::future::TryJoin;
use futures_concurrency::stream::Merge;
use mesh::payload::Downcast;
use mesh::CancelContext;
use pal_async::driver::Driver;
use pal_async::socket::AsSockRef;
use pal_async::socket::Listener;
use pal_async::socket::PolledSocket;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use unicycle::FuturesUnordered;

/// A ttrpc server.
#[derive(Debug, Default)]
pub struct Server {
    services: HashMap<&'static str, mesh::Sender<(CancelContext, GenericRpc)>>,
}

impl Server {
    /// Creates a new ttrpc server.
    pub fn new() -> Self {
        Self {
            services: Default::default(),
        }
    }

    /// Adds or updates a channel for receiving service requests.
    pub fn add_service<T: ServiceRpc>(&mut self, send: mesh::Sender<(CancelContext, T)>)
    where
        GenericRpc: Downcast<T>,
    {
        self.services.insert(T::NAME, send.force_downcast());
    }

    /// Runs the server, listening on `listener` and servicing connections until
    /// `cancel`.
    pub async fn run(
        &mut self,
        driver: &(impl Driver + ?Sized),
        listener: impl Listener,
        cancel: mesh::OneshotReceiver<()>,
    ) -> anyhow::Result<()> {
        let mut listener = PolledSocket::new(driver, listener)?;
        let mut tasks = FuturesUnordered::new();
        let mut cancel = cancel.fuse();
        loop {
            let conn = futures::select! { // merge semantics
                r = listener.accept().fuse() => r,
                _ = tasks.next() => continue,
                _ = cancel => break,
            };
            if let Ok(conn) = conn.and_then(|(conn, _)| PolledSocket::new(driver, conn)) {
                tasks.push(async {
                    let _ = self.serve(conn).await.map_err(|err| {
                        tracing::error!(
                            error = err.as_ref() as &dyn std::error::Error,
                            "connection error"
                        )
                    });
                });
            }
        }
        Ok(())
    }

    /// Runs the server, servicing a single connection `conn`.
    pub async fn run_single(
        &mut self,
        driver: &(impl Driver + ?Sized),
        conn: impl AsSockRef + Read + Write,
    ) -> anyhow::Result<()> {
        self.serve(PolledSocket::new(driver, conn)?).await
    }

    async fn serve<'a>(
        &self,
        stream: PolledSocket<impl AsSockRef + Read + Write>,
    ) -> anyhow::Result<()> {
        let (mut reader, mut writer) = stream.split();
        let (stream_send, mut stream_recv) = mesh::channel();
        let ctx = CancelContext::new();
        let recv_task = async {
            let stream_send = stream_send; // move into this task
            while let Some(message) = read_message(&mut reader).await? {
                let (send, recv) = mesh::oneshot::<Result<Vec<u8>, Status>>();
                stream_send.send((message.stream_id, recv));

                let handle = handle_message(message).and_then(|request| {
                    let service = self.services.get(request.service.as_str()).ok_or_else(|| {
                        status_from_err(
                            Code::Unimplemented,
                            anyhow::anyhow!("unknown service {}", request.service),
                        )
                    })?;

                    let ctx = if request.timeout_nano == 0 {
                        ctx.clone()
                    } else {
                        ctx.with_timeout(std::time::Duration::from_nanos(request.timeout_nano))
                    };

                    Ok(move |port| {
                        service.send((
                            ctx,
                            GenericRpc {
                                method: request.method,
                                data: request.payload,
                                port,
                            },
                        ));
                    })
                });

                match handle {
                    Ok(handle) => handle(send.into()),
                    Err(err) => send.send(Err(err)),
                }
            }
            Ok(())
        };
        let send_task = async {
            let mut responses = FuturesUnordered::new();
            enum Event<T> {
                Request((u32, mesh::OneshotReceiver<Result<Vec<u8>, Status>>)),
                Response(T),
            }
            while let Some(event) = (
                (&mut stream_recv).map(Event::Request),
                (&mut responses).map(Event::Response),
            )
                .merge()
                .next()
                .await
            {
                match event {
                    Event::Request((stream_id, recv)) => {
                        let recv = recv.map(move |r| {
                            (
                                stream_id,
                                match r {
                                    Ok(Ok(payload)) => Response::Payload(payload),
                                    Ok(Err(status)) => Response::Status(status),
                                    Err(_) => Response::Status(Status {
                                        code: Code::Internal.into(),
                                        message: "unknown error".to_string(),
                                        details: Vec::new(),
                                    }),
                                },
                            )
                        });
                        responses.push(recv);
                    }
                    Event::Response((stream_id, payload)) => {
                        write_message(
                            &mut writer,
                            stream_id,
                            MESSAGE_TYPE_RESPONSE,
                            &mesh::payload::encode(payload),
                        )
                        .await?;
                    }
                }
            }
            anyhow::Result::<_>::Ok(())
        };
        (recv_task, send_task).try_join().await?;
        Ok(())
    }
}

fn handle_message(message: ReadResult) -> Result<Request, Status> {
    if message.stream_id % 2 != 1 {
        return Err(status_from_err(
            Code::InvalidArgument,
            ProtocolError::EvenStreamId,
        ));
    }

    match message.message_type {
        MESSAGE_TYPE_REQUEST => {
            let payload = message.payload.map_err(|err @ TooLongError { .. }| {
                status_from_err(Code::ResourceExhausted, err)
            })?;
            let request = mesh::payload::decode::<Request>(&payload)
                .map_err(|err| status_from_err(Code::InvalidArgument, err))?;

            tracing::debug!(
                stream_id = message.stream_id,
                service = %request.service,
                method = %request.method,
                timeout = request.timeout_nano / 1000 / 1000,
                "message",
            );

            Ok(request)
        }
        ty => Err(status_from_err(
            Code::InvalidArgument,
            ProtocolError::InvalidMessageType(ty),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::Server;
    use futures::executor::block_on;
    use pal_async::local::block_with_io;
    use pal_async::DefaultPool;
    use test_with_tracing::test;

    mod items {
        include!(concat!(env!("OUT_DIR"), "/ttrpc.example.v1.rs"));
    }

    #[test]
    fn client_server() {
        let (c, s) = unix_socket::UnixStream::pair().unwrap();
        let mut server = Server::new();
        let (send, mut recv) = mesh::channel();
        server.add_service::<items::Example>(send);
        let server_thread = std::thread::spawn(move || {
            block_with_io(|driver| async move { server.run_single(&driver, s).await })
        });

        let client_thread = std::thread::spawn(move || {
            DefaultPool::run_with(|driver| async move {
                let client = Client::new(&driver, c);
                let response = client
                    .call(
                        items::Example::Method1,
                        items::Method1Request {
                            foo: "abc".to_string(),
                            bar: "def".to_string(),
                        },
                    )
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(&response.foo, "abc123");
                assert_eq!(&response.bar, "def456");
                client.shutdown().await;
            })
        });

        block_on(async {
            let (_, req) = recv.recv().await.unwrap();
            match req {
                items::Example::Method1(input, resp) => {
                    assert_eq!(&input.foo, "abc");
                    assert_eq!(&input.bar, "def");
                    resp.send(Ok(items::Method1Response {
                        foo: input.foo + "123",
                        bar: input.bar + "456",
                    }));
                }
                _ => panic!("{:?}", &req),
            }

            recv.recv().await.unwrap_err();
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap().unwrap();
    }
}
