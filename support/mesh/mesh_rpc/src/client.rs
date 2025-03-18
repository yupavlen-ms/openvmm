// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TTRPC client.

use crate::message::MESSAGE_TYPE_REQUEST;
use crate::message::MESSAGE_TYPE_RESPONSE;
use crate::message::ReadResult;
use crate::message::Request;
use crate::message::Response;
use crate::message::TooLongError;
use crate::message::read_message;
use crate::message::write_message;
use crate::rpc::ProtocolError;
use crate::rpc::status_from_err;
use crate::service::Code;
use crate::service::DecodedRpc;
use crate::service::GenericRpc;
use crate::service::ServiceRpc;
use crate::service::Status;
use anyhow::Context as _;
use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::future::Race;
use mesh::Deadline;
use mesh::MeshPayload;
use mesh::payload::EncodeAs;
use mesh::payload::Timestamp;
use pal_async::driver::Driver;
use pal_async::socket::PolledSocket;
use pal_async::task::Spawn;
use pal_async::task::Task;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::future::pending;
use std::pin::pin;
use std::task::ready;
use std::time::Duration;
use unix_socket::UnixStream;

/// A TTRPC client connection.
pub struct Client {
    send: mesh::Sender<mesh::OwnedMessage>,
    task: Task<()>,
}

#[derive(MeshPayload)]
struct ClientRequest<T> {
    service: String,
    deadline: Option<EncodeAs<Deadline, Timestamp>>,
    wait_ready: bool,
    rpc: T,
}

/// Dials a connection to a server.
pub trait Dial: 'static + Send {
    /// A bidirectional byte stream connection to the server.
    type Stream: 'static + Send + AsyncRead + AsyncWrite;

    /// Connects to the server.
    fn dial(&mut self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}

/// A [`Dial`] implementation that connects to a Unix domain socket.
pub struct UnixDialier<T>(T, std::path::PathBuf);

impl<T: Driver> UnixDialier<T> {
    /// Returns a new dialier that connects to `path`.
    pub fn new(driver: T, path: impl Into<std::path::PathBuf>) -> Self {
        Self(driver, path.into())
    }
}

impl<T: Driver> Dial for UnixDialier<T> {
    type Stream = PolledSocket<UnixStream>;

    fn dial(&mut self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send {
        PolledSocket::connect_unix(&self.0, &self.1)
    }
}

/// A [`Dial`] implementation that uses an existing connection.
///
/// Once the connection terminates, subsequent connections will fail.
pub struct ExistingConnection<T>(Option<T>);

impl<T: 'static + Send + AsyncRead + AsyncWrite> ExistingConnection<T> {
    /// Returns a new dialier that uses `socket`, once.
    pub fn new(socket: T) -> Self {
        Self(Some(socket))
    }
}

impl<T: 'static + Send + AsyncRead + AsyncWrite> Dial for ExistingConnection<T> {
    type Stream = T;

    async fn dial(&mut self) -> std::io::Result<Self::Stream> {
        self.0.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "connection already used",
            )
        })
    }
}

/// A builder for [`Client`].
pub struct ClientBuilder {
    retry_timeout: Duration,
}

impl ClientBuilder {
    /// Returns a new client builder.
    pub fn new() -> Self {
        Self {
            // Use the gRPC default.
            retry_timeout: Duration::from_secs(20),
        }
    }

    /// Sets the timeout for a failed connection before attempting to reconnect.
    pub fn retry_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.retry_timeout = timeout;
        self
    }

    /// Builds a new client from a dialier.
    pub fn build(&self, driver: &(impl Driver + Spawn), dialer: impl Dial) -> Client {
        let (send, recv) = mesh::channel();
        let worker = ClientWorker {
            timer: PolledTimer::new(driver),
            failure_timer: PolledTimer::new(driver),
            dialer,
            waiting: VecDeque::new(),
            rpc_recv: Some(recv),
            last_failure: None,
            failure_timeout: self.retry_timeout,
        };
        let task = driver.spawn("ttrpc client", worker.run());
        Client {
            // Erase the type of the sender.
            send: mesh::local_node::Port::from(send).into(),
            task,
        }
    }
}

impl Client {
    /// Creates a new client from a dialer.
    pub fn new(driver: &(impl Driver + Spawn), dialer: impl Dial) -> Self {
        ClientBuilder::new().build(driver, dialer)
    }

    /// Returns a [`CallBuilder`] to build RPCs.
    pub fn call(&self) -> CallBuilder<'_> {
        CallBuilder {
            client: self,
            deadline: None,
            wait_ready: false,
        }
    }

    /// Shuts down the client, waiting for the associated task to complete.
    pub async fn shutdown(self) {
        drop(self.send);
        self.task.await;
    }
}

/// A builder for RPCs returned by [`Client::call`].
pub struct CallBuilder<'a> {
    client: &'a Client,
    deadline: Option<Deadline>,
    wait_ready: bool,
}

/// A future representing an RPC call.
pub struct Call<T>(mesh::OneshotReceiver<Result<T, Status>>);

impl<T> std::fmt::Debug for Call<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CallFuture").field(&self.0).finish()
    }
}

impl CallBuilder<'_> {
    /// Sets the timeout for the RPC.
    ///
    /// Internally, this will immediately compute a deadline that is `timeout` from now.
    pub fn timeout(&mut self, timeout: Option<Duration>) -> &mut Self {
        self.deadline = timeout.and_then(|timeout| Deadline::now().checked_add(timeout));
        self
    }

    /// Sets the deadline for the RPC.
    pub fn deadline(&mut self, deadline: Option<Deadline>) -> &mut Self {
        self.deadline = deadline;
        self
    }

    /// Sets whether the client should wait for the server to be ready before
    /// sending the RPC.
    ///
    /// If this is not set and a connection to the server cannot be established,
    /// the RPC will fail. Otherwise, the RPC will keep waiting for a connection
    /// until its deadline.
    pub fn wait_ready(&mut self, wait_ready: bool) -> &mut Self {
        self.wait_ready = wait_ready;
        self
    }

    /// Starts the RPC.
    ///
    /// To get the RPC result, `await` the returned future.
    #[must_use]
    pub fn start<F, R, T, U>(&self, rpc: F, input: T) -> Call<U>
    where
        F: FnOnce(T, mesh::OneshotSender<Result<U, Status>>) -> R,
        R: ServiceRpc,
        U: 'static + MeshPayload + Send,
    {
        let (send, recv) = mesh::oneshot();

        self.client
            .send
            .send(mesh::OwnedMessage::new(ClientRequest {
                service: R::NAME.to_string(),
                deadline: self.deadline.map(Into::into),
                rpc: DecodedRpc::Rpc(rpc(input, send)),
                wait_ready: self.wait_ready,
            }));

        Call(recv)
    }

    /// Used to send unknown requests for testing.
    #[cfg(test)]
    pub(crate) fn start_raw(&self, service: &str, method: &str, data: Vec<u8>) -> Call<Vec<u8>> {
        let (send, recv) = mesh::oneshot();

        self.client
            .send
            .send(mesh::OwnedMessage::new(ClientRequest {
                service: service.to_string(),
                deadline: self.deadline.map(Into::into),
                rpc: GenericRpc {
                    method: method.to_string(),
                    data,
                    port: send.into(),
                },
                wait_ready: self.wait_ready,
            }));

        Call(recv)
    }
}

impl<T: 'static + Send> Future for Call<T> {
    type Output = Result<T, Status>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match ready!(self.get_mut().0.poll_unpin(cx)) {
            Ok(r) => r,
            Err(err) => Err(status_from_err(Code::Unavailable, err)),
        }
        .into()
    }
}

struct ClientWorker<T> {
    dialer: T,
    timer: PolledTimer,
    failure_timer: PolledTimer,
    waiting: VecDeque<ClientRequest<GenericRpc>>,
    rpc_recv: Option<mesh::Receiver<ClientRequest<GenericRpc>>>,
    last_failure: Option<Instant>,
    failure_timeout: Duration,
}

impl<T: Dial> ClientWorker<T> {
    async fn run(mut self) {
        loop {
            let r = match self.wait_connect().await {
                None => break,
                Some(Ok(stream)) => {
                    tracing::debug!("connection established");
                    self.run_connection(stream).await.inspect_err(|err| {
                        tracing::debug!(
                            error = err.as_ref() as &dyn std::error::Error,
                            "connection failed"
                        );
                    })
                }
                Some(Err(err)) => {
                    tracing::debug!(error = &err as &dyn std::error::Error, "failed to connect");
                    Err(err.into())
                }
            };
            if let Err(err) = r {
                let status = status_from_err(Code::Unavailable, err);
                self.waiting = self
                    .waiting
                    .drain(..)
                    .filter_map(|req| {
                        if req.wait_ready {
                            return Some(req);
                        }
                        req.rpc.respond_status(status.clone());
                        None
                    })
                    .collect();
                self.last_failure = Some(Instant::now());
            }
        }
        tracing::debug!("shutting down");
    }

    async fn wait_connect(&mut self) -> Option<std::io::Result<T::Stream>> {
        let mut dial = pin!(self.dialer.dial());
        while self.rpc_recv.is_some() || !self.waiting.is_empty() {
            let oldest_deadline = self
                .waiting
                .iter()
                .filter_map(|v| v.deadline.map(|d| *d))
                .min();
            let sleep = async {
                if let Some(deadline) = oldest_deadline {
                    self.timer.sleep(deadline - Deadline::now()).await;
                } else {
                    pending().await
                }
            };
            let next = async {
                if let Some(recv) = &mut self.rpc_recv {
                    recv.next().await
                } else {
                    pending().await
                }
            };
            let connect = async {
                if !self.waiting.is_empty() {
                    if let Some(last_failure) = self.last_failure {
                        self.failure_timer
                            .sleep_until(last_failure + self.failure_timeout)
                            .await;
                    }
                    (&mut dial).await
                } else {
                    pending().await
                }
            };

            enum Event<T> {
                Request(Option<ClientRequest<GenericRpc>>),
                Timeout(()),
                Connect(std::io::Result<T>),
            }

            match (
                connect.map(Event::Connect),
                next.map(Event::Request),
                sleep.map(Event::Timeout),
            )
                .race()
                .await
            {
                Event::Request(req) => {
                    if let Some(req) = req {
                        self.waiting.push_back(req);
                    } else {
                        self.rpc_recv = None;
                    }
                }
                Event::Timeout(()) => {
                    let now = Deadline::now();
                    self.waiting = self
                        .waiting
                        .drain(..)
                        .filter_map(|req| {
                            if let Some(deadline) = req.deadline {
                                if *deadline <= now {
                                    req.rpc.respond_status(Status {
                                        code: Code::DeadlineExceeded as i32,
                                        message: "deadline exceeded".to_string(),
                                        details: Vec::new(),
                                    });
                                    return None;
                                }
                            }
                            Some(req)
                        })
                        .collect();
                }
                Event::Connect(r) => {
                    return Some(r);
                }
            }
        }
        None
    }

    async fn run_connection(&mut self, stream: T::Stream) -> anyhow::Result<()> {
        let (mut reader, mut writer) = AsyncReadExt::split(stream);
        let responses = Mutex::new(HashMap::<u32, mesh::OneshotSender<mesh::OwnedMessage>>::new());
        let recv_task = async {
            while let Some(message) = read_message(&mut reader)
                .await
                .context("fatal connection error")?
            {
                let stream_id = message.stream_id;
                tracing::debug!(stream_id, "response");

                let response_send = responses.lock().remove(&stream_id);

                let Some(response_send) = response_send else {
                    tracing::error!(stream_id, "response for unknown stream");
                    continue;
                };

                let result = handle_message(message);

                response_send.send(mesh::OwnedMessage::new(result));
            }
            Ok(())
        };

        let send_task = async {
            let mut next_stream_id = 1;
            loop {
                let request = if let Some(req) = self.waiting.pop_front() {
                    Some(req)
                } else if let Some(recv) = &mut self.rpc_recv {
                    recv.next().await
                } else {
                    None
                };
                let Some(request) = request else {
                    break;
                };
                responses
                    .lock()
                    .insert(next_stream_id, request.rpc.port.into());

                let payload = mesh::payload::encode(Request {
                    service: request.service,
                    method: request.rpc.method,
                    payload: request.rpc.data,
                    timeout_nano: request.deadline.map_or(0, |deadline| {
                        (*deadline - Deadline::now()).as_nanos() as u64
                    }),
                    metadata: vec![],
                });

                write_message(&mut writer, next_stream_id, MESSAGE_TYPE_REQUEST, &payload)
                    .await
                    .context("failed to write to connection")?;

                next_stream_id = next_stream_id.wrapping_add(2);
            }
            Ok(())
        };

        (send_task, recv_task).race().await
    }
}

fn handle_message(message: ReadResult) -> Result<Vec<u8>, Status> {
    match message.message_type {
        MESSAGE_TYPE_RESPONSE => {
            let payload = message.payload.map_err(|err @ TooLongError { .. }| {
                status_from_err(Code::ResourceExhausted, err)
            })?;

            let response = mesh::payload::decode(&payload)
                .map_err(|err| status_from_err(Code::Unknown, err))?;

            match response {
                Response::Payload(payload) => Ok(payload),
                Response::Status(status) => Err(status),
            }
        }
        ty => Err(status_from_err(
            Code::Internal,
            ProtocolError::InvalidMessageType(ty),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use super::Dial;
    use crate::service::Code;
    use mesh::CancelContext;
    use mesh::Deadline;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::socket::PolledSocket;
    use std::future::pending;
    use std::net::TcpStream;
    use std::time::Duration;
    use test_with_tracing::test;

    struct NeverDial;

    impl Dial for NeverDial {
        type Stream = PolledSocket<TcpStream>;

        async fn dial(&mut self) -> std::io::Result<Self::Stream> {
            pending().await
        }
    }

    struct FailDial;

    impl Dial for FailDial {
        type Stream = PolledSocket<TcpStream>;

        async fn dial(&mut self) -> std::io::Result<Self::Stream> {
            Err(std::io::ErrorKind::NotConnected.into())
        }
    }

    #[async_test]
    async fn test_failed_connect(driver: DefaultDriver) {
        let client = Client::new(&driver, FailDial);
        let err = client
            .call()
            .start_raw("service", "method", vec![])
            .await
            .unwrap_err();

        assert_eq!(err.code, Code::Unavailable as i32);
        assert!(err.message.contains("not connected"));
    }

    #[async_test]
    async fn test_delayed_connect_never(driver: DefaultDriver) {
        let client = Client::new(&driver, NeverDial);

        // The request should not fail within the cancel context timeout.
        CancelContext::new()
            .with_timeout(Duration::from_millis(250))
            .until_cancelled(
                client
                    .call()
                    .deadline(Some(Deadline::now() + Duration::from_secs(60)))
                    .start_raw("service", "method", vec![]),
            )
            .await
            .unwrap_err();
    }

    #[async_test]
    async fn test_delayed_connect(driver: DefaultDriver) {
        let client = Client::new(&driver, NeverDial);
        let err = client
            .call()
            .deadline(Some(Deadline::now() + Duration::from_millis(200)))
            .start_raw("service", "method", vec![])
            .await
            .unwrap_err();

        assert_eq!(err.code, Code::DeadlineExceeded as i32);
    }
}
