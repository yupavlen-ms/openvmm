// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use super::*;
use crate::protocol::Version;
use crate::rndisprot;
use crate::Arc;
use crate::GuestMemory;
use crate::Guid;
use crate::InspectMut;
use async_trait::async_trait;
use buffers::sub_allocation_size_for_mtu;
use futures::FutureExt;
use futures::StreamExt;
use futures::TryFutureExt;
use guestmem::ranges::PagedRanges;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use hvdef::hypercall::HvGuestOsId;
use hvdef::hypercall::HvGuestOsMicrosoft;
use hvdef::hypercall::HvGuestOsMicrosoftIds;
use mesh::rpc::Rpc;
use mesh::rpc::RpcError;
use mesh::rpc::RpcSend;
use net_backend::null::NullEndpoint;
use net_backend::DisconnectableEndpoint;
use net_backend::Endpoint;
use net_backend::EndpointAction;
use net_backend::QueueConfig;
use pal_async::async_test;
use pal_async::DefaultDriver;
use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::task::Poll;
use std::time::Duration;
use test_with_tracing::test;
use vmbus_async::queue::IncomingPacket;
use vmbus_async::queue::OutgoingPacket;
use vmbus_async::queue::Queue;
use vmbus_channel::bus::ChannelRequest;
use vmbus_channel::bus::GpadlRequest;
use vmbus_channel::bus::OfferInput;
use vmbus_channel::bus::OfferResources;
use vmbus_channel::bus::OpenData;
use vmbus_channel::bus::OpenRequest;
use vmbus_channel::bus::OpenResult;
use vmbus_channel::bus::ParentBus;
use vmbus_channel::channel::offer_channel;
use vmbus_channel::channel::ChannelHandle;
use vmbus_channel::channel::VmbusDevice;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMap;
use vmbus_channel::gpadl::GpadlMapView;
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_channel::ChannelClosed;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::SignalVmbusChannel;
use vmbus_core::protocol::UserDefinedData;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmbus_ring::IncomingRing;
use vmbus_ring::OutgoingRing;
use vmbus_ring::PAGE_SIZE;
use vmcore::interrupt::Interrupt;
use vmcore::save_restore::SavedStateBlob;
use vmcore::slim_event::SlimEvent;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

const VMNIC_CHANNEL_TYPE_GUID: Guid = Guid::from_static_str("f8615163-df3e-46c5-913f-f2d2f965ed0e");

enum ChannelResponse {
    Open(Option<OpenResult>),
    Close,
    Gpadl(bool),
    // TeardownGpadl(GpadlId),
    // Modify(i32),
}

#[derive(Clone)]
struct MockVmbus {
    pub memory: GuestMemory,
    pub child_info: Arc<futures::lock::Mutex<Option<OfferInput>>>,
}

impl MockVmbus {
    pub const AVAILABLE_GUEST_PAGES: usize = 16;

    pub fn new() -> Self {
        Self {
            memory: GuestMemory::allocate(Self::AVAILABLE_GUEST_PAGES * PAGE_SIZE),
            child_info: Arc::new(futures::lock::Mutex::new(None)),
        }
    }
}

#[async_trait]
impl ParentBus for MockVmbus {
    async fn add_child(&self, request: OfferInput) -> anyhow::Result<OfferResources> {
        *(self.child_info.lock().await) = Some(request);
        Ok(OfferResources::new(self.memory.clone(), None))
    }
    fn clone_bus(&self) -> Box<dyn ParentBus> {
        Box::new(self.clone())
    }
    fn use_event(&self) -> bool {
        false
    }
}

struct TestNicEndpointState {
    pub poll_iterations_required: u32,
    // Used to check the last set operation
    pub use_vf: Option<bool>,
    // Used for any queries since use_vf is often reset after check.
    pub last_use_vf: Option<bool>,
    pub stop_endpoint_counter: usize,
    pub link_status_updater: Option<mesh::Sender<VecDeque<bool>>>,
}

impl TestNicEndpointState {
    pub fn new() -> Arc<parking_lot::Mutex<Self>> {
        Arc::new(parking_lot::Mutex::new(Self {
            poll_iterations_required: 1,
            use_vf: None,
            last_use_vf: None,
            stop_endpoint_counter: 0,
            link_status_updater: None,
        }))
    }

    pub fn update_link_status(this: &Arc<parking_lot::Mutex<Self>>, link_status: &[bool]) {
        let locked_self = this.lock();
        let link_status_updater = locked_self.link_status_updater.as_ref().unwrap();
        let status_vec = link_status.iter().copied().collect::<VecDeque<bool>>();
        link_status_updater.send(status_vec);
    }
}

struct TestNicEndpointInner {
    pub null_endpoint: NullEndpoint,
    pub endpoint_state: Option<Arc<parking_lot::Mutex<TestNicEndpointState>>>,
}

impl TestNicEndpointInner {
    pub fn new(endpoint_state: Option<Arc<parking_lot::Mutex<TestNicEndpointState>>>) -> Self {
        Self {
            null_endpoint: NullEndpoint::new(),
            endpoint_state,
        }
    }
}

struct TestNicEndpoint {
    inner: Arc<futures::lock::Mutex<TestNicEndpointInner>>,
    is_ordered: bool,
    tx_offload_support: net_backend::TxOffloadSupport,
    multiqueue_support: net_backend::MultiQueueSupport,
    link_status_rx: mesh::Receiver<VecDeque<bool>>,
    pending_link_status_updates: VecDeque<bool>,
}

impl TestNicEndpoint {
    pub fn new(endpoint_state: Option<Arc<parking_lot::Mutex<TestNicEndpointState>>>) -> Self {
        let (link_status_tx, link_status_rx) = mesh::channel();
        if let Some(endpoint_state) = endpoint_state.as_ref() {
            let mut locked_state = endpoint_state.lock();
            locked_state.link_status_updater = Some(link_status_tx);
        }
        let inner = TestNicEndpointInner::new(endpoint_state);
        let is_ordered = <NullEndpoint as net_backend::Endpoint>::is_ordered(&inner.null_endpoint);
        let tx_offload_support =
            <NullEndpoint as net_backend::Endpoint>::tx_offload_support(&inner.null_endpoint);
        let multiqueue_support =
            <NullEndpoint as net_backend::Endpoint>::multiqueue_support(&inner.null_endpoint);
        Self {
            inner: Arc::new(futures::lock::Mutex::new(inner)),
            is_ordered,
            tx_offload_support,
            multiqueue_support,
            link_status_rx,
            pending_link_status_updates: VecDeque::new(),
        }
    }
}

impl InspectMut for TestNicEndpoint {
    fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
}

#[async_trait]
impl net_backend::Endpoint for TestNicEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "TestNicEndpoint"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig<'_>>,
        rss: Option<&net_backend::RssConfig<'_>>,
        queues: &mut Vec<Box<dyn net_backend::Queue>>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.null_endpoint.get_queues(config, rss, queues).await
    }

    async fn stop(&mut self) {
        let mut inner = self.inner.lock().await;
        if let Some(endpoint_state) = &inner.endpoint_state {
            let mut locked_data = endpoint_state.lock();
            locked_data.stop_endpoint_counter += 1;
        }
        <NullEndpoint as net_backend::Endpoint>::stop::<'_, '_>(&mut inner.null_endpoint).await
    }

    fn is_ordered(&self) -> bool {
        self.is_ordered
    }

    fn tx_offload_support(&self) -> net_backend::TxOffloadSupport {
        self.tx_offload_support
    }

    fn multiqueue_support(&self) -> net_backend::MultiQueueSupport {
        self.multiqueue_support
    }

    async fn get_data_path_to_guest_vf(&self) -> anyhow::Result<bool> {
        let locked_inner = self.inner.lock().await;
        let endpoint_state = locked_inner.endpoint_state.as_ref().unwrap();
        let locked_data = endpoint_state.lock();
        match locked_data.last_use_vf {
            Some(to_guest) => Ok(to_guest),
            None => Err(anyhow::anyhow!("Last data path state not set")),
        }
    }

    async fn set_data_path_to_guest_vf(&self, use_vf: bool) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let mut iter = {
            let locked_inner = inner.lock().await;
            let endpoint_state = locked_inner.endpoint_state.as_ref().unwrap();
            let mut locked_data = endpoint_state.lock();
            locked_data.use_vf = Some(use_vf);
            locked_data.last_use_vf = Some(use_vf);
            locked_data.poll_iterations_required
        };
        std::future::poll_fn(move |cx| {
            if iter <= 1 {
                Poll::Ready(Ok(()))
            } else {
                iter -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }

    async fn wait_for_endpoint_action(&mut self) -> EndpointAction {
        if self.pending_link_status_updates.is_empty() {
            self.pending_link_status_updates
                .append(&mut self.link_status_rx.select_next_some().await);
        }
        EndpointAction::LinkStatusNotify(self.pending_link_status_updates.pop_front().unwrap())
    }
}

struct TestNicDevice {
    pub driver: DefaultDriver,
    pub mock_vmbus: MockVmbus,
    pub offer_input: OfferInput,
    pub next_avail_guest_page: usize,
    pub next_avail_gpadl_id: u32,
    channel: ChannelHandle<Nic>,
}

impl TestNicDevice {
    pub async fn new(driver: &DefaultDriver) -> Self {
        let mock_vmbus = MockVmbus::new();
        Self::new_with_vmbus(driver, mock_vmbus).await
    }

    pub async fn new_with_vmbus(driver: &DefaultDriver, mock_vmbus: MockVmbus) -> Self {
        let builder = Nic::builder();
        let nic = builder.build(
            &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
            Guid::new_random(),
            Box::new(NullEndpoint::new()),
            [1, 2, 3, 4, 5, 6].into(),
            0,
        );
        Self::new_with_nic_and_vmbus(driver, mock_vmbus, nic).await
    }

    pub async fn new_with_nic(driver: &DefaultDriver, nic: Nic) -> Self {
        let mock_vmbus = MockVmbus::new();
        Self::new_with_nic_and_vmbus(driver, mock_vmbus, nic).await
    }

    pub async fn new_with_nic_and_vmbus(
        driver: &DefaultDriver,
        mock_vmbus: MockVmbus,
        nic: Nic,
    ) -> Self {
        let channel = offer_channel(driver, &mock_vmbus, nic)
            .await
            .expect("successful init");

        let offer_input = mock_vmbus.child_info.lock().await.take().unwrap();

        Self {
            driver: driver.clone(),
            mock_vmbus,
            offer_input,
            next_avail_guest_page: 0,
            next_avail_gpadl_id: 1,
            channel,
        }
    }

    pub async fn revoke_and_new(self) -> Self {
        self.send_to_channel(ChannelRequest::Close, (), |_| ChannelResponse::Close)
            .await
            .expect("Close request successful");

        drop(self.offer_input);
        let nic = mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(333))
            .until_cancelled(self.channel.revoke())
            .await
            .unwrap()
            .unwrap();

        Self::new_with_nic_and_vmbus(&self.driver, self.mock_vmbus, nic).await
    }

    pub fn reserve_guest_pages(&mut self, page_count: usize) -> (GpadlId, Vec<u64>) {
        if page_count >= MockVmbus::AVAILABLE_GUEST_PAGES - self.next_avail_guest_page {
            panic!(
                "Not enough guest pages available -- need to increase the count to at least {}",
                self.next_avail_guest_page + page_count
            );
        }

        let page_array: Vec<u64> = (self.next_avail_guest_page
            ..self.next_avail_guest_page + page_count + 1)
            .map(|e| {
                if e == self.next_avail_guest_page {
                    (page_count * PAGE_SIZE) as u64
                } else {
                    e as u64 - 1
                }
            })
            .collect();

        let result = (GpadlId(self.next_avail_gpadl_id), page_array);
        self.next_avail_guest_page += page_count;
        self.next_avail_gpadl_id += 1;
        result
    }

    pub async fn add_guest_pages(&mut self, page_count: usize) -> (GpadlId, Vec<u64>) {
        let (id, page_array) = self.reserve_guest_pages(page_count);
        let gpadl_response = self
            .send_to_channel(
                ChannelRequest::Gpadl,
                GpadlRequest {
                    id,
                    count: 1,
                    buf: page_array.clone(),
                },
                ChannelResponse::Gpadl,
            )
            .await
            .expect("Gpadl request successful");

        if let ChannelResponse::Gpadl(response) = gpadl_response {
            assert_eq!(response, true);
        } else {
            panic!("Unexpected return value");
        }

        (id, page_array)
    }

    async fn send_to_channel<I: 'static + Send, R: 'static + Send>(
        &self,
        req: impl FnOnce(Rpc<I, R>) -> ChannelRequest,
        input: I,
        f: impl 'static + Send + FnOnce(R) -> ChannelResponse,
    ) -> Result<ChannelResponse, RpcError> {
        self.offer_input.request_send.call(req, input).await.map(f)
    }

    async fn connect_vmbus_channel(&mut self) -> TestNicChannel<'_> {
        let gpadl_map = GpadlMap::new();
        let (ring_gpadl_id, page_array) = self.add_guest_pages(4).await;
        gpadl_map.add(
            ring_gpadl_id,
            MultiPagedRangeBuf::new(1, page_array).unwrap(),
        );

        let host_to_guest_event = Arc::new(SlimEvent::new());
        let host_to_guest_interrupt = {
            let event = host_to_guest_event.clone();
            Interrupt::from_fn(move || event.signal())
        };

        let open_request = OpenRequest {
            // Channel open-specific data.
            open_data: OpenData {
                target_vp: 0,
                ring_offset: 2,
                ring_gpadl_id,
                event_flag: 1,
                connection_id: 1,
                user_data: UserDefinedData::new_zeroed(),
            },
            // The interrupt used to signal the guest.
            interrupt: host_to_guest_interrupt,
            use_confidential_ring: false,
            use_confidential_external_memory: false,
        };

        let open_response = self
            .send_to_channel(ChannelRequest::Open, open_request, ChannelResponse::Open)
            .await
            .expect("open successful");

        let ChannelResponse::Open(Some(result)) = open_response else {
            panic!("Unexpected return value");
        };

        let mem = self.mock_vmbus.memory.clone();
        TestNicChannel::new(
            self,
            &mem,
            gpadl_map,
            ring_gpadl_id,
            host_to_guest_event,
            result.guest_to_host_interrupt,
        )
    }

    pub fn start_vmbus_channel(&mut self) {
        self.channel.start();
    }

    pub async fn stop_vmbus_channel(&mut self) {
        mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(333))
            .until_cancelled(self.channel.stop())
            .await
            .unwrap();
    }

    pub async fn save(&mut self) -> anyhow::Result<Option<SavedStateBlob>> {
        mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(333))
            .until_cancelled(self.channel.save())
            .await
            .unwrap()
    }

    pub async fn restore(
        &mut self,
        buffer: SavedStateBlob,
        gpadl_map: Arc<GpadlMap>,
        ring_gpadl_id: GpadlId,
        next_avail_guest_page: usize,
        next_avail_gpadl_id: u32,
        host_to_guest_interrupt: Interrupt,
    ) -> anyhow::Result<Option<Interrupt>> {
        // Restore the previous memory settings
        assert_eq!(self.next_avail_gpadl_id, 1);
        self.next_avail_gpadl_id = next_avail_gpadl_id;
        assert_eq!(self.next_avail_guest_page, 0);
        self.next_avail_guest_page = next_avail_guest_page;

        let gpadl_map_view = gpadl_map.view();
        let gpadl_map_contents = (1..next_avail_gpadl_id)
            .filter_map(|i| {
                let gpadl_id = GpadlId(i);
                if let Ok(gpadl_view) = gpadl_map_view.map(gpadl_id) {
                    Some((gpadl_id, (*gpadl_view).clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<(GpadlId, MultiPagedRangeBuf<Vec<u64>>)>>();

        let mut guest_to_host_interrupt = None;
        mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(1000))
            .until_cancelled(async {
                let restore = std::pin::pin!(self.channel.restore(buffer));
                let mut restore = restore.fuse();
                loop {
                    futures::select! {
                        result = restore => break result,
                        request = self.offer_input.server_request_recv.select_next_some() => {
                            match request {
                                vmbus_channel::bus::ChannelServerRequest::Restore(rpc) => {
                                    let gpadls = gpadl_map_contents.iter().map(|(gpadl_id, pages)| {
                                        let pages = pages.clone();
                                        vmbus_channel::bus::RestoredGpadl {
                                            request: GpadlRequest {
                                                id: *gpadl_id,
                                                count: 1,
                                                buf: pages.into_buffer(),
                                            },
                                            accepted: true,
                                        }
                                    }).collect::<Vec<vmbus_channel::bus::RestoredGpadl>>();
                                    rpc.handle_sync(|open| {
                                        guest_to_host_interrupt = open.map(|open| open.guest_to_host_interrupt);
                                        Ok(vmbus_channel::bus::RestoreResult {
                                            open_request: Some(OpenRequest {
                                                open_data: OpenData {
                                                    target_vp: 0,
                                                    ring_offset: 2,
                                                    ring_gpadl_id,
                                                    event_flag: 1,
                                                    connection_id: 1,
                                                    user_data: UserDefinedData::new_zeroed(),
                                                },
                                                interrupt: host_to_guest_interrupt.clone(),
                                                use_confidential_external_memory: false,
                                                use_confidential_ring: false,
                                            }),
                                            gpadls,
                                        })
                                    })
                                }
                                vmbus_channel::bus::ChannelServerRequest::Revoke(_) => (),
                            }
                        }
                    }
                }
            })
            .await
            .unwrap()?;

        Ok(guest_to_host_interrupt)
    }
}

struct TestNicChannel<'a> {
    pub mtu: u32,
    nic: &'a mut TestNicDevice,
    queue: Queue<GpadlRingMem>,
    transaction_id: u64,
    gpadl_map: Arc<GpadlMap>,
    recv_buf_id: GpadlId,
    send_buf_id: GpadlId,
    channel_id: GpadlId,
    host_to_guest_event: Arc<SlimEvent>,
    _guest_done: Arc<AtomicBool>,
}

impl<'a> TestNicChannel<'a> {
    pub fn new(
        nic: &'a mut TestNicDevice,
        mem: &GuestMemory,
        gpadl_map: Arc<GpadlMap>,
        channel_id: GpadlId,
        host_to_guest_event: Arc<SlimEvent>,
        guest_to_host_interrupt: Interrupt,
    ) -> Self {
        let guest_done = Arc::new(AtomicBool::new(false));
        let channel = gpadl_test_guest_channel(
            mem,
            &gpadl_map.clone().view(),
            channel_id,
            2,
            host_to_guest_event.clone(),
            guest_to_host_interrupt,
            guest_done.clone(),
        );
        let queue = Queue::new(channel).unwrap();
        Self {
            mtu: DEFAULT_MTU,
            nic,
            queue,
            transaction_id: 1,
            gpadl_map,
            recv_buf_id: GpadlId(0),
            send_buf_id: GpadlId(0),
            channel_id,
            host_to_guest_event,
            _guest_done: guest_done,
        }
    }

    pub async fn read_with_timeout<F, R>(&mut self, timeout: Duration, f: F) -> Result<R, ()>
    where
        F: FnOnce(&IncomingPacket<'_, GpadlRingMem>) -> R,
    {
        let (mut reader, _) = self.queue.split();
        let packet = mesh::CancelContext::new()
            .with_timeout(timeout)
            .until_cancelled(reader.read())
            .await
            .map_err(drop)?
            .unwrap();
        Ok(f(&packet))
    }

    pub async fn read_with<F, R>(&mut self, f: F) -> Result<R, ()>
    where
        F: FnOnce(&IncomingPacket<'_, GpadlRingMem>) -> R,
    {
        self.read_with_timeout(Duration::from_millis(333), f).await
    }

    pub async fn read_rndis_control_message_with_timeout<T>(
        &mut self,
        message_type: u32,
        timeout: Duration,
    ) -> Option<T>
    where
        T: AsBytes + FromBytes,
    {
        let mem = self.nic.mock_vmbus.memory.clone();
        let gpadl_map_view = self.gpadl_map.clone().view();
        let recv_buf = gpadl_map_view.map(self.recv_buf_id).unwrap();
        let mut transaction_id = None;
        let message = self
            .read_with_timeout(timeout, |packet| {
                match packet {
                    IncomingPacket::Data(data) => {
                        // Check for RNDIS packet
                        let mut reader = data.reader();
                        let header: protocol::MessageHeader = reader.read_plain().unwrap();
                        assert_eq!(
                            header.message_type,
                            protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET
                        );
                        // Verify it is a control channel message
                        let rndis_data: protocol::Message1SendRndisPacket =
                            reader.read_plain().unwrap();
                        assert_eq!(rndis_data.channel_type, protocol::CONTROL_CHANNEL_TYPE);

                        // Fetch RNDIS packet from external memory
                        let external_ranges = if let Some(id) = data.transfer_buffer_id() {
                            assert_eq!(id, 0);

                            data.read_transfer_ranges(recv_buf.iter()).unwrap()
                        } else {
                            data.read_external_ranges().unwrap()
                        };
                        let mut direct_reader =
                            PagedRanges::new(external_ranges.iter()).reader(&mem);

                        // Verify message_type matches caller expectations
                        let rndis_header: rndisprot::MessageHeader =
                            direct_reader.read_plain().unwrap();
                        assert_eq!(rndis_header.message_type, message_type);

                        transaction_id = data.transaction_id();
                        Some(direct_reader.read_plain::<T>().unwrap())
                    }
                    _ => panic!("Unexpected packet!"),
                }
            })
            .await
            .or_else(|_| Ok::<Option<T>, ()>(None))
            .unwrap();

        if let Some(transaction_id) = transaction_id {
            // Complete message
            let message = NvspMessage {
                header: protocol::MessageHeader {
                    message_type: protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE,
                },
                data: protocol::Message1SendRndisPacketComplete {
                    status: protocol::Status::SUCCESS,
                },
                padding: &[],
            };
            self.queue
                .split()
                .1
                .try_write(&OutgoingPacket {
                    transaction_id,
                    packet_type: OutgoingPacketType::Completion,
                    payload: &message.payload(),
                })
                .unwrap();
        }

        message
    }

    pub async fn read_rndis_control_message<T>(&mut self, message_type: u32) -> Option<T>
    where
        T: AsBytes + FromBytes,
    {
        self.read_rndis_control_message_with_timeout(message_type, Duration::from_millis(333))
            .await
    }

    pub async fn write(&mut self, packet: OutgoingPacket<'_, '_>) {
        let (_, mut writer) = self.queue.split();
        writer.write(packet).await.unwrap();
    }

    pub async fn send_initialize_message(&mut self) {
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE_TYPE_INIT,
            },
            data: protocol::MessageInit {
                protocol_version: Version::V5 as u32,
                protocol_version2: Version::V6 as u32,
            },
            padding: &[],
        };
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;
        self.read_with(|packet| match packet {
            IncomingPacket::Completion(completion) => {
                let mut reader = completion.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(header.message_type, protocol::MESSAGE_TYPE_INIT_COMPLETE);
                let completion_data: protocol::MessageInitComplete = reader.read_plain().unwrap();
                assert_eq!(completion_data.status, protocol::Status::SUCCESS);
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub async fn send_ndis_config_message(
        &mut self,
        capabilities: protocol::NdisConfigCapabilities,
    ) {
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
            },
            data: protocol::Message2SendNdisConfig {
                mtu: self.mtu,
                reserved: 0,
                capabilities,
            },
            padding: &[],
        };
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;
        self.read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub async fn send_ndis_version_message(&mut self) {
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
            },
            data: protocol::Message1SendNdisVersion {
                ndis_major_version: 6,
                ndis_minor_version: 30,
            },
            padding: &[],
        };
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;
        self.read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub async fn send_receive_buffer_message(&mut self) {
        // Need reserved control channel buffers and one queue buffer (more if subchannels are requested).
        let min_buffer_pages = ((RX_RESERVED_CONTROL_BUFFERS as usize + 1)
            * sub_allocation_size_for_mtu(DEFAULT_MTU) as usize)
            .div_ceil(PAGE_SIZE);
        let (gpadl_handle, page_array) = self.nic.add_guest_pages(min_buffer_pages).await;
        let recv_range = MultiPagedRangeBuf::new(1, page_array).unwrap();
        self.gpadl_map.add(gpadl_handle, recv_range);
        self.recv_buf_id = gpadl_handle;

        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
            },
            data: protocol::Message1SendReceiveBuffer {
                gpadl_handle,
                id: 0,
                reserved: 0,
            },
            padding: &[],
        };
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;
        self.read_with(|packet| match packet {
            IncomingPacket::Completion(completion) => {
                let mut reader = completion.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER_COMPLETE
                );
                let completion_data: protocol::Message1SendReceiveBufferComplete =
                    reader.read_plain().unwrap();
                assert_eq!(completion_data.status, protocol::Status::SUCCESS);
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub async fn send_send_buffer_message(&mut self) {
        let (gpadl_handle, page_array) = self.nic.add_guest_pages(1).await;
        let send_range = MultiPagedRangeBuf::new(1, page_array).unwrap();
        self.gpadl_map.add(gpadl_handle, send_range);
        self.send_buf_id = gpadl_handle;

        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
            },
            data: protocol::Message1SendSendBuffer {
                gpadl_handle,
                id: 0,
                reserved: 0,
            },
            padding: &[],
        };
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;

        self.read_with(|packet| match packet {
            IncomingPacket::Completion(completion) => {
                let mut reader = completion.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER_COMPLETE
                );
                let completion_data: protocol::Message1SendSendBufferComplete =
                    reader.read_plain().unwrap();
                assert_eq!(completion_data.status, protocol::Status::SUCCESS);
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub async fn initialize(&mut self, capabilities: protocol::NdisConfigCapabilities) {
        self.send_initialize_message().await;
        self.send_ndis_config_message(capabilities).await;
        self.send_ndis_version_message().await;
        self.send_receive_buffer_message().await;
        self.send_send_buffer_message().await;
    }

    pub async fn send_rndis_control_message_no_completion<T: AsBytes>(
        &mut self,
        message_type: u32,
        message: T,
        extra: &[u8],
    ) {
        let message_length = size_of::<rndisprot::MessageHeader>() + size_of::<T>() + extra.len();
        let mem = self.nic.mock_vmbus.memory.clone();
        let gpadl_view = self.gpadl_map.clone().view().map(self.send_buf_id).unwrap();
        let mut buf_writer = PagedRanges::new(&*gpadl_view).writer(&mem);
        buf_writer
            .write(
                rndisprot::MessageHeader {
                    message_type,
                    message_length: message_length as u32,
                }
                .as_bytes(),
            )
            .unwrap();

        buf_writer.write(message.as_bytes()).unwrap();

        if !extra.is_empty() {
            buf_writer.write(extra).unwrap();
        }

        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET,
            },
            data: protocol::Message1SendRndisPacket {
                channel_type: protocol::CONTROL_CHANNEL_TYPE,
                send_buffer_section_index: 0xffffffff,
                send_buffer_section_size: 0,
            },
            padding: &[],
        };
        let gpadl_map_view = self.gpadl_map.clone().view().map(self.send_buf_id).unwrap();
        let gpa_range = gpadl_map_view.first().unwrap().subrange(0, message_length);
        self.write(OutgoingPacket {
            transaction_id: self.transaction_id,
            packet_type: OutgoingPacketType::GpaDirect(&[gpa_range]),
            payload: &message.payload(),
        })
        .await;
        self.transaction_id += 1;
    }

    pub async fn send_rndis_control_message<T: AsBytes>(
        &mut self,
        message_type: u32,
        message: T,
        extra: &[u8],
    ) {
        self.send_rndis_control_message_no_completion(message_type, message, extra)
            .await;
        self.read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");
    }

    pub fn start(&mut self) {
        self.nic.start_vmbus_channel();
    }

    pub async fn stop(&mut self) {
        self.nic.stop_vmbus_channel().await;
    }

    pub async fn save(&mut self) -> anyhow::Result<Option<SavedStateBlob>> {
        self.nic.save().await
    }

    pub async fn restore(
        self,
        nic: &'_ mut TestNicDevice,
        buffer: SavedStateBlob,
    ) -> anyhow::Result<TestNicChannel<'_>> {
        let mem = self.nic.mock_vmbus.memory.clone();
        let host_to_guest_interrupt = {
            let event = self.host_to_guest_event.clone();
            Interrupt::from_fn(move || event.signal())
        };

        let gpadl_map = self.gpadl_map.clone();
        let channel_id = self.channel_id;
        let next_avail_guest_page = self.nic.next_avail_guest_page;
        let next_avail_gpadl_id = self.nic.next_avail_gpadl_id;

        let guest_to_host_interrupt = nic
            .restore(
                buffer,
                gpadl_map.clone(),
                channel_id,
                next_avail_guest_page,
                next_avail_gpadl_id,
                host_to_guest_interrupt,
            )
            .await?
            .expect("should be open");

        Ok(TestNicChannel::new(
            nic,
            &mem,
            gpadl_map,
            channel_id,
            self.host_to_guest_event,
            guest_to_host_interrupt,
        ))
    }
}

enum TestVirtualFunctionStateChange {
    Update(Rpc<(), ()>),
}

#[derive(Clone)]
struct TestVirtualFunctionState {
    id: Arc<parking_lot::Mutex<Option<u32>>>,
    send_runtime_update: Arc<parking_lot::Mutex<mesh::Sender<TestVirtualFunctionStateChange>>>,
    is_ready: Arc<(parking_lot::Mutex<Option<bool>>, event_listener::Event)>,
    oneshot_ready_callback: Arc<parking_lot::Mutex<Option<mesh::OneshotSender<Rpc<bool, ()>>>>>,
}

impl TestVirtualFunctionState {
    pub fn new(
        id: Option<u32>,
        send_runtime_update: mesh::Sender<TestVirtualFunctionStateChange>,
    ) -> Self {
        Self {
            id: Arc::new(parking_lot::Mutex::new(id)),
            send_runtime_update: Arc::new(parking_lot::Mutex::new(send_runtime_update)),
            is_ready: Default::default(),
            oneshot_ready_callback: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn id(&self) -> Option<u32> {
        *self.id.lock()
    }

    pub async fn update_id(
        &self,
        new_id: Option<u32>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<()> {
        *self.id.lock() = new_id;
        let send_update = self
            .send_runtime_update
            .lock()
            .call(TestVirtualFunctionStateChange::Update, ())
            .map_err(anyhow::Error::from);

        match timeout {
            Some(timeout) => {
                let mut ctx = mesh::CancelContext::new().with_timeout(timeout);
                ctx.until_cancelled(send_update)
                    .map_err(anyhow::Error::from)
                    .await?
            }
            None => send_update.await,
        }
    }

    pub async fn await_ready(&self, is_ready: bool, timeout: Duration) -> Result<(), ()> {
        let mut ctx = mesh::CancelContext::new().with_timeout(timeout);

        loop {
            let listener = self.is_ready.1.listen();
            {
                let mut val = self.is_ready.0.lock();
                if *val == Some(is_ready) {
                    val.take();
                    return Ok(());
                }
            }
            ctx.until_cancelled(listener).await.map_err(drop)?;
        }
    }

    pub fn is_ready_unchanged(&self) -> bool {
        self.is_ready.0.lock().is_none()
    }

    pub async fn set_ready(&self, is_ready: bool) {
        let ready_callback = self.oneshot_ready_callback.lock().take();
        if let Some(ready_callback) = ready_callback {
            ready_callback.call(|x| x, is_ready).await.unwrap();
        }
        *self.is_ready.0.lock() = Some(is_ready);
        self.is_ready.1.notify(usize::MAX);
    }
}

struct TestVirtualFunction {
    state: TestVirtualFunctionState,
    recv_update: mesh::Receiver<TestVirtualFunctionStateChange>,
}

impl TestVirtualFunction {
    pub fn new(id: u32) -> Self {
        let (tx, rx) = mesh::channel();
        Self {
            state: TestVirtualFunctionState::new(Some(id), tx),
            recv_update: rx,
        }
    }

    pub fn state(&self) -> TestVirtualFunctionState {
        self.state.clone()
    }
}

#[async_trait]
impl VirtualFunction for TestVirtualFunction {
    async fn id(&self) -> Option<u32> {
        self.state.id()
    }
    async fn guest_ready_for_device(&mut self) {
        tracing::info!(id = self.state.id(), "VF ready");
        self.state.set_ready(true).await;
    }
    async fn wait_for_state_change(&mut self) -> Rpc<(), ()> {
        match self.recv_update.select_next_some().await {
            TestVirtualFunctionStateChange::Update(rpc) => rpc,
        }
    }
}

fn make_test_guest_rings(
    mem: &GuestMemory,
    gpadl_map: &GpadlMapView,
    gpadl_id: GpadlId,
    ring_offset: u32,
) -> (IncomingRing<GpadlRingMem>, OutgoingRing<GpadlRingMem>) {
    let gpadl = AlignedGpadlView::new(gpadl_map.map(gpadl_id).unwrap()).unwrap();
    let (out_gpadl, in_gpadl) = match gpadl.split(ring_offset) {
        Ok(gpadls) => gpadls,
        Err(_) => panic!("Failed gpadl.split"),
    };
    (
        IncomingRing::new(GpadlRingMem::new(in_gpadl, mem).unwrap()).unwrap(),
        OutgoingRing::new(GpadlRingMem::new(out_gpadl, mem).unwrap()).unwrap(),
    )
}

pub fn gpadl_test_guest_channel(
    mem: &GuestMemory,
    gpadl_map: &GpadlMapView,
    gpadl_id: GpadlId,
    ring_offset: u32,
    host_to_guest_event: Arc<SlimEvent>,
    guest_to_host_interrupt: Interrupt,
    done: Arc<AtomicBool>,
) -> RawAsyncChannel<GpadlRingMem> {
    let (in_ring, out_ring) = make_test_guest_rings(mem, gpadl_map, gpadl_id, ring_offset);
    RawAsyncChannel {
        in_ring,
        out_ring,
        signal: Box::new(EventWithDone {
            local_event: host_to_guest_event,
            remote_interrupt: guest_to_host_interrupt,
            done,
        }),
    }
}

struct EventWithDone {
    remote_interrupt: Interrupt,
    local_event: Arc<SlimEvent>,
    done: Arc<AtomicBool>,
}

impl SignalVmbusChannel for EventWithDone {
    fn signal_remote(&self) {
        self.remote_interrupt.deliver();
    }

    fn poll_for_signal(&self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), ChannelClosed>> {
        if self.done.load(Ordering::Relaxed) {
            return Err(ChannelClosed).into();
        }
        self.local_event.poll_wait(cx).map(Ok)
    }
}

#[async_test]
async fn build_nic(driver: DefaultDriver) {
    let builder = Nic::builder();
    let unique_id = Guid::new_random();
    let nic = builder.build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver)),
        unique_id,
        Box::new(NullEndpoint::new()),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let offer_params = nic.offer();
    assert_eq!(offer_params.interface_id, VMNIC_CHANNEL_TYPE_GUID);
    assert_eq!(offer_params.instance_id, unique_id);
}

#[async_test]
async fn connect_nic_vmbus(driver: DefaultDriver) {
    let builder = Nic::builder();
    let unique_id = Guid::new_random();
    let nic = builder.build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        unique_id,
        Box::new(NullEndpoint::new()),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mock_vmbus = MockVmbus::new();
    let _channel = offer_channel(&driver, &mock_vmbus, nic)
        .await
        .expect("successful init");
}

#[async_test]
async fn send_initial_handshake(driver: DefaultDriver) {
    let mut nic = TestNicDevice::new(&driver).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel.send_initialize_message().await;
}

#[async_test]
async fn initialize_nic(driver: DefaultDriver) {
    let mut nic = TestNicDevice::new(&driver).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new())
        .await;
}

#[async_test]
async fn initialize_rndis(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let builder = Nic::builder();
    let nic = builder.build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new())
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    assert_eq!(initialize_complete.request_id, 123);
    assert_eq!(initialize_complete.status, rndisprot::STATUS_SUCCESS);
    assert_eq!(initialize_complete.major_version, rndisprot::MAJOR_VERSION);
    assert_eq!(initialize_complete.minor_version, rndisprot::MINOR_VERSION);

    // Not expecting an association packet because virtual function is not present
    assert!(channel
        .read_with(|_| panic!("No packet expected"))
        .await
        .is_err());

    assert_eq!(endpoint_state.lock().stop_endpoint_counter, 1);
}

#[async_test]
async fn initialize_rndis_no_sendbuffer(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let builder = Nic::builder();
    let nic = builder.build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;

    channel.send_initialize_message().await;
    channel
        .send_ndis_config_message(protocol::NdisConfigCapabilities::new())
        .await;
    channel.send_ndis_version_message().await;
    channel.send_receive_buffer_message().await;
    // Note: send_send_buffer_message() not called
    // Creating a Gpadl for the Rndis Init Message
    let (gpadl_handle, page_array) = channel.nic.add_guest_pages(1).await;
    let send_range = MultiPagedRangeBuf::new(1, page_array).unwrap();
    channel.gpadl_map.add(gpadl_handle, send_range);
    channel.send_buf_id = gpadl_handle;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    assert_eq!(initialize_complete.request_id, 123);
    assert_eq!(initialize_complete.status, rndisprot::STATUS_SUCCESS);
    assert_eq!(initialize_complete.major_version, rndisprot::MAJOR_VERSION);
    assert_eq!(initialize_complete.minor_version, rndisprot::MINOR_VERSION);

    // Not expecting an association packet because virtual function is not present
    assert!(channel
        .read_with(|_| panic!("No packet expected"))
        .await
        .is_err());

    assert_eq!(endpoint_state.lock().stop_endpoint_counter, 1);
}

#[async_test]
#[should_panic]
async fn initialize_rndis_no_sendbuffer_no_recvbuffer(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let builder = Nic::builder();
    let nic = builder.build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;

    channel.send_initialize_message().await;
    channel
        .send_ndis_config_message(protocol::NdisConfigCapabilities::new())
        .await;
    channel.send_ndis_version_message().await;
    // Note: send_receive_buffer_message() not called
    // Note: send_send_buffer_message() not called
    // Creating a Gpadl for the Rndis Init Message
    let (gpadl_handle, page_array) = channel.nic.add_guest_pages(1).await;
    let send_range = MultiPagedRangeBuf::new(1, page_array).unwrap();
    channel.gpadl_map.add(gpadl_handle, send_range);
    channel.send_buf_id = gpadl_handle;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;
}

#[async_test]
async fn initialize_rndis_with_vf(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    assert_eq!(initialize_complete.request_id, 123);
    assert_eq!(initialize_complete.status, rndisprot::STATUS_SUCCESS);
    assert_eq!(initialize_complete.major_version, rndisprot::MAJOR_VERSION);
    assert_eq!(initialize_complete.minor_version, rndisprot::MINOR_VERSION);

    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 1);
                assert_eq!(association_data.serial_number, test_vf_state.id().unwrap());
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    // Device will be made ready after packet is sent because Linux netvsc does not send completion packet.
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state.is_ready_unchanged());

    // send switch data path message
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);

    // send another switch data path, but require a few async iterations to actually switch the path.
    endpoint_state.lock().poll_iterations_required = 20;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::SYNTHETIC.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), false);
    assert_eq!(endpoint_state.lock().stop_endpoint_counter, 1);
}

#[async_test]
async fn initialize_rndis_with_vf_alternate_id(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let get_guest_os_id = Box::new(move || -> HvGuestOsId {
        let id: u64 = HvGuestOsMicrosoft::new()
            .with_os_id(HvGuestOsMicrosoftIds::WINDOWS_NT.0)
            .into();
        HvGuestOsId::from(id)
    });
    let builder = Nic::builder();
    let nic = builder
        .virtual_function(test_vf)
        .get_guest_os_id(get_guest_os_id)
        .build(
            &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
            Guid::new_random(),
            Box::new(endpoint),
            [1, 2, 3, 4, 5, 6].into(),
            99,
        );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    assert_eq!(initialize_complete.request_id, 123);
    assert_eq!(initialize_complete.status, rndisprot::STATUS_SUCCESS);
    assert_eq!(initialize_complete.major_version, rndisprot::MAJOR_VERSION);
    assert_eq!(initialize_complete.minor_version, rndisprot::MINOR_VERSION);

    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 1);
                assert_eq!(association_data.serial_number, 99);
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    // Device will be made ready after packet is sent because Linux netvsc does
    // not send completion packet.
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state.is_ready_unchanged());

    // send switch data path message
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);
}

#[async_test]
async fn initialize_rndis_with_vf_multi_open(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();

    channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Revoke and open a new vmbus channel. This happens from a normal
    // guest when transitioning from UEFI to the OS, or when the OS does a
    // soft restart. It will also happen when configuring parameters like
    // MTU, which is negotiated early.
    //

    let mut nic = nic.revoke_and_new().await;
    // VF should not be revoked when the vmbus channel is closed
    assert!(test_vf_state.is_ready_unchanged());
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;

    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    assert_eq!(initialize_complete.request_id, 123);
    assert_eq!(initialize_complete.status, rndisprot::STATUS_SUCCESS);
    assert_eq!(initialize_complete.major_version, rndisprot::MAJOR_VERSION);
    assert_eq!(initialize_complete.minor_version, rndisprot::MINOR_VERSION);

    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 1);
                assert_eq!(association_data.serial_number, test_vf_state.id().unwrap());
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    // send switch data path message
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);

    // send another switch data path, but require a few async iterations to actually switch the path.
    endpoint_state.lock().poll_iterations_required = 20;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::SYNTHETIC.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), false);
}

#[async_test]
async fn initialize_rndis_with_prev_vf_switch_data_path(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    // Starting device with the data path already switched.
    endpoint_state.lock().last_use_vf = Some(true);
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();

    channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    // The data path was already switched before the device started, so not
    // expecting any VF state change.
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_err());

    // send switch data path message
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::SYNTHETIC.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), false);
}

#[async_test]
async fn stop_start_with_vf(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let _initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let _association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    //
    // Test start/stop after VF is added
    //
    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    // VF should remain visible through start/stop
    channel.stop().await;
    assert!(test_vf_state.is_ready_unchanged());
    channel.start();
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Test start/stop with VF and data path switched.
    //
    endpoint_state.lock().poll_iterations_required = 5;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);

    // The switch data path triggers a VF update as it uses the common restore
    // 'guest VF' state logic.
    assert!(test_vf_state
        .await_ready(true, Duration::ZERO)
        .await
        .is_ok());

    // VF should remain visible through start/stop
    channel.stop().await;
    assert!(test_vf_state.is_ready_unchanged());
    channel.start();
    assert!(test_vf_state.is_ready_unchanged());
    // Data path should not be updated.
    assert!(endpoint_state.lock().use_vf.is_none());
}

#[async_test]
async fn save_restore_with_vf(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    let mock_vmbus = nic.mock_vmbus.clone();
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let _initialize_complete: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let _association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Save/restore.
    //
    channel.stop().await;
    let restore_state = channel.save().await.unwrap().unwrap();

    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let old_test_vf_state = test_vf_state;
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut nic = TestNicDevice::new_with_nic_and_vmbus(&driver, mock_vmbus.clone(), nic).await;
    let mut channel = channel.restore(&mut nic, restore_state).await.unwrap();
    channel.start();
    // VF should remain unchanged
    assert!(old_test_vf_state.is_ready_unchanged());
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Test save/restore after completion message is sent for VF_ASSOCIATION.
    //
    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    channel.stop().await;
    let restore_state = channel.save().await.unwrap().unwrap();

    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let old_test_vf_state = test_vf_state;
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut nic = TestNicDevice::new_with_nic_and_vmbus(&driver, mock_vmbus.clone(), nic).await;
    let mut channel = channel.restore(&mut nic, restore_state).await.unwrap();
    channel.start();
    // VF should remain unchanged
    assert!(old_test_vf_state.is_ready_unchanged());
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Test save/restore after VF is added and data path is switched.
    //
    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    endpoint_state.lock().poll_iterations_required = 5;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);
    channel.stop().await;
    let restore_state = channel.save().await.unwrap().unwrap();

    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut nic = TestNicDevice::new_with_nic_and_vmbus(&driver, mock_vmbus, nic).await;
    let mut channel = channel.restore(&mut nic, restore_state).await.unwrap();
    channel.start();
    assert!(test_vf_state.is_ready_unchanged());
    // Data path should be unchanged.
    assert!(endpoint_state.lock().use_vf.is_none());
}

#[async_test]
async fn save_restore_with_vf_multi_open(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    let mock_vmbus = nic.mock_vmbus.clone();
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    //
    // Add VF
    //
    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Disconnect/reconnect vmbus a couple of times, re-establishing connection on the second.
    //
    let mut nic = nic.revoke_and_new().await;
    // VF should not be revoked when the vmbus channel is closed
    assert!(test_vf_state.is_ready_unchanged());
    test_vf_state.set_ready(false).await;
    nic.start_vmbus_channel();
    let _ = nic.connect_vmbus_channel().await;
    let mut nic = nic.revoke_and_new().await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;

    // No network init has been done on newer channels, so VF should not be present.
    assert!(test_vf_state
        .await_ready(false, Duration::from_millis(333))
        .await
        .is_ok());

    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    //
    // Respond to the last VF association message.
    //
    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Invoke save/restore
    //
    channel.stop().await;
    let restore_state = channel.save().await.unwrap().unwrap();

    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let old_test_vf_state = test_vf_state;
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut nic = TestNicDevice::new_with_nic_and_vmbus(&driver, mock_vmbus.clone(), nic).await;
    let mut channel = channel.restore(&mut nic, restore_state).await.unwrap();
    channel.start();
    assert!(old_test_vf_state.is_ready_unchanged());
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Switch data path.
    //
    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    endpoint_state.lock().poll_iterations_required = 5;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);

    //
    // Disconnect/reconnect vmbus a couple of times, re-establishing connection on the second.
    //
    let mut nic = nic.revoke_and_new().await;
    nic.start_vmbus_channel();
    let _ = nic.connect_vmbus_channel().await;
    let mut nic = nic.revoke_and_new().await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();

    //
    // Invoke save/restore.
    //
    channel.stop().await;
    let restore_state = channel.save().await.unwrap().unwrap();

    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut nic = TestNicDevice::new_with_nic_and_vmbus(&driver, mock_vmbus, nic).await;
    let mut channel = channel.restore(&mut nic, restore_state).await.unwrap();
    channel.start();
    assert!(test_vf_state.is_ready_unchanged());
    assert_eq!(endpoint_state.lock().use_vf.take().unwrap_or(false), false);
}

async fn remove_vf_with_async_messages(
    channel: &mut TestNicChannel<'_>,
    test_vf_state: &TestVirtualFunctionState,
) -> anyhow::Result<()> {
    let eject_vf = async {
        let transaction_id = channel
            .read_with(|packet| match packet {
                IncomingPacket::Data(data) => {
                    let mut reader = data.reader();
                    let header: protocol::MessageHeader = reader.read_plain().unwrap();
                    assert_eq!(
                        header.message_type,
                        protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
                    );
                    let switch_data: protocol::Message4SwitchDataPath =
                        reader.read_plain().unwrap();
                    assert_eq!(
                        switch_data.active_data_path,
                        protocol::DataPath::SYNTHETIC.0
                    );
                    data.transaction_id().expect("should request completion")
                }
                _ => panic!("Unexpected packet"),
            })
            .await
            .expect("association packet");

        channel
            .write(OutgoingPacket {
                transaction_id,
                packet_type: OutgoingPacketType::Completion,
                payload: &[],
            })
            .await;

        let transaction_id = channel
            .read_with(|packet| match packet {
                IncomingPacket::Data(data) => {
                    let mut reader = data.reader();
                    let header: protocol::MessageHeader = reader.read_plain().unwrap();
                    assert_eq!(
                        header.message_type,
                        protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                    );
                    let association_data: protocol::Message4SendVfAssociation =
                        reader.read_plain().unwrap();
                    assert_eq!(association_data.vf_allocated, 0);
                    data.transaction_id().expect("should request completion")
                }
                _ => panic!("Unexpected packet"),
            })
            .await
            .expect("association packet");

        channel
            .write(OutgoingPacket {
                transaction_id,
                packet_type: OutgoingPacketType::Completion,
                payload: &[],
            })
            .await;

        // Linux guests will switch data path as part of VF ejection.
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
            },
            data: protocol::Message4SwitchDataPath {
                active_data_path: protocol::DataPath::SYNTHETIC.0,
            },
            padding: &[],
        };
        channel
            .write(OutgoingPacket {
                transaction_id: 123,
                packet_type: OutgoingPacketType::InBandWithCompletion,
                payload: &message.payload(),
            })
            .await;
        channel
            .read_with(|packet| match packet {
                IncomingPacket::Completion(_) => (),
                _ => panic!("Unexpected packet"),
            })
            .await
            .expect("completion message");
    };

    let eject_vf = std::pin::pin!(eject_vf);
    let mut fused_eject_vf = eject_vf.fuse();
    // Remove VF
    let update_id = std::pin::pin!(test_vf_state.update_id(None, None));
    let mut fused_update_id = update_id.fuse();
    // futures_concurrency::future::try_join seems promising, but unable to get it to work here
    loop {
        futures::select! {
            _ = fused_eject_vf => {}
            result = fused_update_id => result?,
            complete => break,
        }
    }
    Ok(())
}

#[async_test]
async fn dynamic_vf_support(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let (mut proxy_endpoint, mut proxy_endpoint_control) = DisconnectableEndpoint::new();
    proxy_endpoint_control.connect(Box::new(endpoint)).unwrap();
    proxy_endpoint.wait_for_endpoint_action().await;

    let test_vf = Box::new(TestVirtualFunction::new(123));
    let test_vf_state = test_vf.state();
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(proxy_endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;

    //
    // Add VF, but don't switch the data path
    //
    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Remove VF ID.
    //
    test_vf_state
        .update_id(None, Some(Duration::from_millis(100)))
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 0);
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state.is_ready_unchanged());

    //
    // Add back VF capability and switch data path
    //
    test_vf_state
        .update_id(Some(124), Some(Duration::from_millis(100)))
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 1);
                assert_eq!(association_data.serial_number, test_vf_state.id().unwrap());
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    //
    // Remove VF ID. The VF state that tracks whether the VF can be offered
    // to the guest should not change when the VF is removed. Since here
    // the VF was in a `can be offered` state, it should stay that way after
    // removing VF.
    //
    let mut ctx = mesh::CancelContext::new().with_timeout(Duration::from_millis(333));
    ctx.until_cancelled(remove_vf_with_async_messages(&mut channel, &test_vf_state))
        .map_err(anyhow::Error::from)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), false);
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Disconnect and reconnect endpoint
    //
    let mut stop_endpoint_counter = 0;
    let endpoint = proxy_endpoint_control.disconnect().await.unwrap().unwrap();
    proxy_endpoint_control.connect(endpoint).unwrap();
    assert_eq!(
        endpoint_state.lock().stop_endpoint_counter,
        stop_endpoint_counter + 1
    );
    stop_endpoint_counter += 1;
    assert!(test_vf_state.is_ready_unchanged());

    //
    // Add back guest VF and switch data path
    //
    test_vf_state
        .update_id(Some(125), Some(Duration::from_millis(100)))
        .await
        .unwrap();
    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                );
                let association_data: protocol::Message4SendVfAssociation =
                    reader.read_plain().unwrap();
                assert_eq!(association_data.vf_allocated, 1);
                assert_eq!(association_data.serial_number, test_vf_state.id().unwrap());
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");

    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());

    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
        },
        data: protocol::Message4SwitchDataPath {
            active_data_path: protocol::DataPath::VF.0,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 123,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| match packet {
            IncomingPacket::Completion(_) => (),
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("completion message");

    PolledTimer::new(&driver)
        .sleep(Duration::from_millis(333))
        .await;
    assert_eq!(endpoint_state.lock().use_vf.take().unwrap(), true);

    //
    // Disconnect endpoint with guest VF still active
    //
    let endpoint = proxy_endpoint_control.disconnect().await.unwrap().unwrap();
    proxy_endpoint_control.connect(endpoint).unwrap();
    assert_eq!(
        endpoint_state.lock().stop_endpoint_counter,
        stop_endpoint_counter + 1
    );
    assert!(channel
        .read_with(|_| panic!("No packet expected"))
        .await
        .is_err());
    assert!(test_vf_state
        .await_ready(true, Duration::from_millis(333))
        .await
        .is_ok());
    assert!(endpoint_state.lock().use_vf.is_none());
}

#[async_test]
async fn link_status_update(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let (mut proxy_endpoint, mut proxy_endpoint_control) = DisconnectableEndpoint::new();
    proxy_endpoint_control.connect(Box::new(endpoint)).unwrap();
    proxy_endpoint.wait_for_endpoint_action().await;

    let test_vf = Box::new(TestVirtualFunction::new(123));
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(proxy_endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
            rndisprot::InitializeRequest {
                request_id: 123,
                major_version: rndisprot::MAJOR_VERSION,
                minor_version: rndisprot::MINOR_VERSION,
                max_transfer_size: 0,
            },
            &[],
        )
        .await;
    let _: rndisprot::InitializeComplete = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT)
        .await
        .unwrap();

    let transaction_id = channel
        .read_with(|packet| match packet {
            IncomingPacket::Data(data) => {
                let mut reader = data.reader();
                let _: protocol::MessageHeader = reader.read_plain().unwrap();
                let _: protocol::Message4SendVfAssociation = reader.read_plain().unwrap();
                data.transaction_id().expect("should request completion")
            }
            _ => panic!("Unexpected packet"),
        })
        .await
        .expect("association packet");
    channel
        .write(OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &[],
        })
        .await;

    // Send link down
    TestNicEndpointState::update_link_status(&endpoint_state, [false].as_slice());
    // Verify message.
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_DISCONNECT);

    // Sending the same state as the current is considered a toggle.
    // For example, if the link is down, sending a down is a toggle down->up->down and vice versa.
    // And, there is a time delay in between the transition.
    TestNicEndpointState::update_link_status(&endpoint_state, [false].as_slice());
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_CONNECT);
    // The rndis read will wait for the link timeout duration. Just add a bit more delay as to
    // allow the notification to come through with higher reliability.
    PolledTimer::new(&driver)
        .sleep(Duration::from_millis(50))
        .await;
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_DISCONNECT);

    // Wait for a little bit and make sure the state has not changed.
    let link_status_msg: Option<rndisprot::IndicateStatus> = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await;
    assert!(link_status_msg.is_none());

    // Send link up
    TestNicEndpointState::update_link_status(&endpoint_state, [true].as_slice());
    // Verify message.
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_CONNECT);

    // Send quick down/up.
    TestNicEndpointState::update_link_status(&endpoint_state, [false, true].as_slice());
    // Verify message.
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_DISCONNECT);
    // The rndis read will wait for the link timeout duration. Just add a bit more delay as to
    // allow the notification to come through with higher reliability.
    PolledTimer::new(&driver)
        .sleep(Duration::from_millis(250))
        .await;
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_CONNECT);

    // Sending the same state as the current is considered a toggle.
    // For example, if the link is up, sending a up is a toggle up->down->up and vice versa.
    // And, there is a time delay in between the transition.
    TestNicEndpointState::update_link_status(&endpoint_state, [true].as_slice());
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_DISCONNECT);
    // The rndis read will wait for the link timeout duration. Just add a bit more delay as to
    // allow the notification to come through with higher reliability.
    PolledTimer::new(&driver)
        .sleep(Duration::from_millis(50))
        .await;
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_CONNECT);

    // Wait for a little bit and make sure the state has not changed.
    let link_status_msg: Option<rndisprot::IndicateStatus> = channel
        .read_rndis_control_message(rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG)
        .await;
    assert!(link_status_msg.is_none());

    // Request keep alive status but don't process results in order to exhaust buffer IDs.
    const FILL_BUFFER_COUNT: u32 = 16;
    for i in 0..FILL_BUFFER_COUNT {
        channel
            .send_rndis_control_message_no_completion(
                rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG,
                rndisprot::KeepaliveRequest { request_id: i },
                &[],
            )
            .await;
    }

    // Send quick down/up. The link status message will be blocked behind no free buffer IDs.
    TestNicEndpointState::update_link_status(&endpoint_state, [false, true].as_slice());

    // Clear ring buffer to free up buffer IDs and ring buffer space.
    for _ in 0..FILL_BUFFER_COUNT {
        channel
            .read_with(|packet| match packet {
                IncomingPacket::Completion(_) => (),
                _ => panic!("Unexpected data packet"),
            })
            .await
            .expect("completion message");
    }
    for _ in 0..FILL_BUFFER_COUNT {
        let _: rndisprot::KeepaliveComplete = channel
            .read_rndis_control_message(rndisprot::MESSAGE_TYPE_KEEPALIVE_CMPLT)
            .await
            .unwrap();
    }

    // The initial message could not be sent because it was blocked. Wait for it.
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message_with_timeout(
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG,
            LINK_DELAY_DURATION * 2,
        )
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_DISCONNECT);

    // There should also be a delay before the status returns to up.
    let link_status_msg: Option<rndisprot::IndicateStatus> = channel
        .read_rndis_control_message_with_timeout(
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG,
            Duration::from_millis(10),
        )
        .await;
    assert!(link_status_msg.is_none());
    // Wait for delayed message
    let link_status_msg: rndisprot::IndicateStatus = channel
        .read_rndis_control_message_with_timeout(
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG,
            LINK_DELAY_DURATION * 2,
        )
        .await
        .unwrap();
    assert_eq!(link_status_msg.status, rndisprot::STATUS_MEDIA_CONNECT);
}

#[async_test]
async fn send_rndis_reset_message(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;

    // Test Reset message. Will result in RndisMessageTypeNotImplemented, but not panic due to unimplemented!().
    // Note: Attempted to use tracing-test crate to check for Error in the trace, but there already exists a global trace dispatcher.
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_RESET_MSG,
            rndisprot::ResetRequest { reserved: 0 },
            &[],
        )
        .await;
}

#[async_test]
async fn send_rndis_indicate_status_message(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;

    // Test Indicate Status message. Will result in RndisMessageTypeNotImplemented, but not panic due to unimplemented!().
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG,
            rndisprot::IndicateStatus {
                status: 0,
                status_buffer_length: 0,
                status_buffer_offset: 0,
            },
            &[],
        )
        .await;
}

#[async_test]
async fn send_rndis_set_ex_message(driver: DefaultDriver) {
    let endpoint_state = TestNicEndpointState::new();
    let endpoint = TestNicEndpoint::new(Some(endpoint_state.clone()));
    let test_vf = Box::new(TestVirtualFunction::new(123));
    let builder = Nic::builder();
    let nic = builder.virtual_function(test_vf).build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(endpoint),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );

    let mut nic = TestNicDevice::new_with_nic(&driver, nic).await;
    nic.start_vmbus_channel();
    let mut channel = nic.connect_vmbus_channel().await;
    channel
        .initialize(protocol::NdisConfigCapabilities::new().with_sriov(true))
        .await;

    // Test Set Ex message. Will result in RndisMessageTypeNotImplemented, but not panic due to unimplemented!().
    channel
        .send_rndis_control_message(
            rndisprot::MESSAGE_TYPE_SET_EX_MSG,
            rndisprot::SetExRequest {
                request_id: 0,
                oid: rndisprot::Oid(0x00010102),
                information_buffer_length: 0,
                information_buffer_offset: 0,
                device_vc_handle: 0,
            },
            &[],
        )
        .await;
}
