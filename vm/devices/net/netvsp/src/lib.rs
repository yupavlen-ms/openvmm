// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The user-mode netvsp VMBus device implementation.

#![forbid(unsafe_code)]

mod buffers;
mod protocol;
pub mod resolver;
mod rndisprot;
mod rx_bufs;
mod saved_state;
mod test;

use crate::buffers::GuestBuffers;
use crate::protocol::Message1RevokeReceiveBuffer;
use crate::protocol::Message1RevokeSendBuffer;
use crate::protocol::Version;
use crate::protocol::VMS_SWITCH_RSS_MAX_SEND_INDIRECTION_TABLE_ENTRIES;
use crate::rndisprot::NDIS_HASH_FUNCTION_MASK;
use crate::rndisprot::NDIS_RSS_PARAM_FLAG_DISABLE_RSS;
use async_trait::async_trait;
use buffers::sub_allocation_size_for_mtu;
pub use buffers::BufferPool;
use futures::channel::mpsc;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::future::Race;
use guestmem::ranges::PagedRange;
use guestmem::ranges::PagedRanges;
use guestmem::ranges::PagedRangesReader;
use guestmem::AccessError;
use guestmem::GuestMemory;
use guestmem::GuestMemoryError;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use guid::Guid;
use hvdef::hypercall::HvGuestOsId;
use hvdef::hypercall::HvGuestOsMicrosoft;
use hvdef::hypercall::HvGuestOsMicrosoftIds;
use hvdef::hypercall::HvGuestOsOpenSourceType;
use inspect::Inspect;
use inspect::InspectMut;
use inspect::SensitivityLevel;
use inspect_counters::Counter;
use inspect_counters::Histogram;
use mesh::rpc::Rpc;
use net_backend::Endpoint;
use net_backend::EndpointAction;
use net_backend::L3Protocol;
use net_backend::QueueConfig;
use net_backend::RxId;
use net_backend::TxId;
use net_backend::TxSegment;
use net_backend_resources::mac_address::MacAddress;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use ring::gparange::MultiPagedRangeIter;
use rx_bufs::RxBuffers;
use rx_bufs::SubAllocationInUse;
use std::cmp;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::future::pending;
use std::mem::offset_of;
use std::ops::Range;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use task_control::AsyncRun;
use task_control::InspectTaskMut;
use task_control::StopTask;
use task_control::TaskControl;
use thiserror::Error;
use vmbus_async::queue;
use vmbus_async::queue::ExternalDataError;
use vmbus_async::queue::IncomingPacket;
use vmbus_async::queue::Queue;
use vmbus_channel::bus::OfferParams;
use vmbus_channel::bus::OpenRequest;
use vmbus_channel::channel::ChannelControl;
use vmbus_channel::channel::ChannelOpenError;
use vmbus_channel::channel::ChannelRestoreError;
use vmbus_channel::channel::DeviceResources;
use vmbus_channel::channel::RestoreControl;
use vmbus_channel::channel::SaveRestoreVmbusDevice;
use vmbus_channel::channel::VmbusDevice;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMapView;
use vmbus_channel::gpadl::GpadlView;
use vmbus_channel::gpadl::UnknownGpadlId;
use vmbus_channel::gpadl_ring::gpadl_channel;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_ring as ring;
use vmbus_ring::gparange::GpnList;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmbus_ring::OutgoingPacketType;
use vmbus_ring::RingMem;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SavedStateBlob;
use vmcore::vm_task::VmTaskDriver;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

// The minimum ring space required to handle a control message. Most control messages only need to send a completion
// packet, but also need room for an additional SEND_VF_ASSOCIATION message.
const MIN_CONTROL_RING_SIZE: usize = 144;

// The minimum ring space required to handle external state changes. Worst case requires a completion message plus two
// additional inband messages (SWITCH_DATA_PATH and SEND_VF_ASSOCIATION)
const MIN_STATE_CHANGE_RING_SIZE: usize = 196;

// Assign the VF_ASSOCIATION message a specific transaction ID so that the completion packet can be identified easily.
const VF_ASSOCIATION_TRANSACTION_ID: u64 = 0x8000000000000000;
// Assign the SWITCH_DATA_PATH message a specific transaction ID so that the completion packet can be identified easily.
const SWITCH_DATA_PATH_TRANSACTION_ID: u64 = 0x8000000000000001;

const NETVSP_MAX_SUBCHANNELS_PER_VNIC: u16 = 64;

// Arbitrary delay before adding the device to the guest. Older Linux
// clients can race when initializing the synthetic nic: the network
// negotiation is done first and then the device is asynchronously queued to
// receive a name (e.g. eth0). If the AN device is offered too quickly, it
// could get the "eth0" name. In provisioning scenarios, the scripts will make
// assumptions about which interface should be used, with eth0 being the
// default.
#[cfg(not(test))]
const VF_DEVICE_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const VF_DEVICE_DELAY: Duration = Duration::from_millis(100);

// Linux guests are known to not act on link state change notifications if
// they happen in quick succession.
#[cfg(not(test))]
const LINK_DELAY_DURATION: Duration = Duration::from_secs(5);
#[cfg(test)]
const LINK_DELAY_DURATION: Duration = Duration::from_millis(333);

#[derive(PartialEq)]
enum CoordinatorMessage {
    /// Update guest VF state based on current availability and the guest VF state tracked by the primary channel.
    /// This includes adding the guest VF device and switching the data path.
    UpdateGuestVfState,
    /// Restart endpoints and resume processing. This will also attempt to set VF and data path state to match current
    /// expectations.
    Restart,
    /// Start a timer.
    StartTimer(Instant),
}

struct Worker<T: RingMem> {
    channel_idx: u16,
    target_vp: u32,
    mem: GuestMemory,
    channel: NetChannel<T>,
    state: WorkerState,
    coordinator_send: mpsc::Sender<CoordinatorMessage>,
}

struct NetQueue {
    driver: VmTaskDriver,
    queue_state: Option<QueueState>,
}

impl<T: RingMem + 'static + Sync> InspectTaskMut<Worker<T>> for NetQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>, worker: Option<&mut Worker<T>>) {
        if worker.is_none() && self.queue_state.is_none() {
            req.ignore();
            return;
        }

        let mut resp = req.respond();
        resp.field("driver", &self.driver);
        if let Some(worker) = worker {
            resp.field(
                "protocol_state",
                match &worker.state {
                    WorkerState::Init(None) => "version",
                    WorkerState::Init(Some(_)) => "init",
                    WorkerState::Ready(_) => "ready",
                },
            )
            .field("ring", &worker.channel.queue)
            .field(
                "can_use_ring_size_optimization",
                worker.channel.can_use_ring_size_opt,
            );

            if let WorkerState::Ready(state) = &worker.state {
                resp.field(
                    "outstanding_tx_packets",
                    state.state.pending_tx_packets.len() - state.state.free_tx_packets.len(),
                )
                .field(
                    "pending_tx_completions",
                    state.state.pending_tx_completions.len(),
                )
                .field("free_tx_packets", state.state.free_tx_packets.len())
                .merge(&state.state.stats);
            }
        }

        if let Some(queue_state) = &mut self.queue_state {
            resp.field_mut("queue", &mut queue_state.queue)
                .field("rx_buffers", queue_state.rx_buffer_range.id_range.len())
                .field(
                    "rx_buffers_start",
                    queue_state.rx_buffer_range.id_range.start,
                );
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum WorkerState {
    Init(Option<InitState>),
    Ready(ReadyState),
}

impl WorkerState {
    fn ready(&self) -> Option<&ReadyState> {
        if let Self::Ready(state) = self {
            Some(state)
        } else {
            None
        }
    }

    fn ready_mut(&mut self) -> Option<&mut ReadyState> {
        if let Self::Ready(state) = self {
            Some(state)
        } else {
            None
        }
    }
}

struct InitState {
    version: Version,
    ndis_config: Option<NdisConfig>,
    ndis_version: Option<NdisVersion>,
    recv_buffer: Option<ReceiveBuffer>,
    send_buffer: Option<SendBuffer>,
}

#[derive(Copy, Clone, Debug, Inspect)]
struct NdisVersion {
    #[inspect(hex)]
    major: u32,
    #[inspect(hex)]
    minor: u32,
}

#[derive(Copy, Clone, Debug, Inspect)]
struct NdisConfig {
    #[inspect(safe)]
    mtu: u32,
    #[inspect(safe)]
    capabilities: protocol::NdisConfigCapabilities,
}

struct ReadyState {
    buffers: Arc<ChannelBuffers>,
    state: ActiveState,
    data: ProcessingData,
}

/// Represents a virtual function (VF) device used to expose accelerated
/// networking to the guest.
#[async_trait]
pub trait VirtualFunction: Sync + Send {
    /// Unique ID of the device. Used by the client to associate a device with
    /// its synthetic counterpart. A value of None signifies that the VF is not
    /// currently available for use.
    async fn id(&self) -> Option<u32>;
    /// Dynamically expose the device in the guest.
    async fn guest_ready_for_device(&mut self);
    /// Returns when there is a change in VF availability. The Rpc result will
    ///  indicate if the change was successfully handled.
    async fn wait_for_state_change(&mut self) -> Rpc<(), ()>;
}

struct Adapter {
    driver: VmTaskDriver,
    mac_address: MacAddress,
    max_queues: u16,
    indirection_table_size: u16,
    offload_support: OffloadConfig,
    ring_size_limit: AtomicUsize,
    free_tx_packet_threshold: usize,
    tx_fast_completions: bool,
    adapter_index: u32,
    get_guest_os_id: Option<Box<dyn Fn() -> HvGuestOsId + Send + Sync>>,
    num_sub_channels_opened: AtomicUsize,
    link_speed: u64,
}

struct QueueState {
    queue: Box<dyn net_backend::Queue>,
    rx_buffer_range: RxBufferRange,
    target_vp_set: bool,
}

struct RxBufferRange {
    id_range: Range<u32>,
    remote_buffer_id_recv: Option<mpsc::UnboundedReceiver<u32>>,
    remote_ranges: Arc<RxBufferRanges>,
}

impl RxBufferRange {
    fn new(
        ranges: Arc<RxBufferRanges>,
        id_range: Range<u32>,
        remote_buffer_id_recv: Option<mpsc::UnboundedReceiver<u32>>,
    ) -> Self {
        Self {
            id_range,
            remote_buffer_id_recv,
            remote_ranges: ranges,
        }
    }

    fn send_if_remote(&self, id: u32) -> bool {
        if self.id_range.contains(&id) {
            false
        } else {
            let i = id.saturating_sub(RX_RESERVED_CONTROL_BUFFERS)
                / self.remote_ranges.buffers_per_queue;
            let _ = self.remote_ranges.buffer_id_send[i as usize].unbounded_send(id);
            true
        }
    }
}

struct RxBufferRanges {
    buffers_per_queue: u32,
    buffer_id_send: Vec<mpsc::UnboundedSender<u32>>,
}

impl RxBufferRanges {
    fn new(buffer_count: u32, queue_count: u32) -> (Self, Vec<mpsc::UnboundedReceiver<u32>>) {
        let buffers_per_queue = (buffer_count - RX_RESERVED_CONTROL_BUFFERS) / queue_count;
        #[allow(clippy::disallowed_methods)] // TODO
        let (send, recv): (Vec<_>, Vec<_>) = (0..queue_count).map(|_| mpsc::unbounded()).unzip();
        (
            Self {
                buffers_per_queue,
                buffer_id_send: send,
            },
            recv,
        )
    }
}

struct RssState {
    key: [u8; 40],
    indirection_table: Vec<u16>,
}

/// The internal channel state.
struct NetChannel<T: RingMem> {
    adapter: Arc<Adapter>,
    queue: Queue<T>,
    gpadl_map: GpadlMapView,
    packet_size: usize,
    pending_send_size: usize,
    restart: Option<CoordinatorMessage>,
    can_use_ring_size_opt: bool,
}

/// Buffers used during packet processing.
struct ProcessingData {
    tx_segments: Vec<TxSegment>,
    tx_done: Box<[TxId]>,
    rx_ready: Box<[RxId]>,
    rx_done: Vec<RxId>,
    transfer_pages: Vec<ring::TransferPageRange>,
}

impl ProcessingData {
    fn new() -> Self {
        Self {
            tx_segments: Vec::new(),
            tx_done: vec![TxId(0); 8192].into(),
            rx_ready: vec![RxId(0); RX_BATCH_SIZE].into(),
            rx_done: Vec::with_capacity(RX_BATCH_SIZE),
            transfer_pages: Vec::with_capacity(RX_BATCH_SIZE),
        }
    }
}

/// Buffers used during channel processing. Separated out from the mutable state
/// to allow multiple concurrent references.
#[derive(Debug, Inspect)]
struct ChannelBuffers {
    version: Version,
    #[inspect(skip)]
    mem: GuestMemory,
    #[inspect(skip)]
    recv_buffer: ReceiveBuffer,
    #[inspect(skip)]
    send_buffer: Option<SendBuffer>,
    ndis_version: NdisVersion,
    #[inspect(safe)]
    ndis_config: NdisConfig,
}

/// An ID assigned to a control message. This is also its receive buffer index.
#[derive(Copy, Clone, Debug)]
struct ControlMessageId(u32);

/// Mutable state for a channel that has finished negotiation.
struct ActiveState {
    primary: Option<PrimaryChannelState>,

    pending_tx_packets: Vec<PendingTxPacket>,
    free_tx_packets: Vec<TxId>,
    pending_tx_completions: VecDeque<PendingTxCompletion>,

    rx_bufs: RxBuffers,

    stats: QueueStats,
}

#[derive(Inspect, Default)]
struct QueueStats {
    tx_stalled: Counter,
    rx_dropped_ring_full: Counter,
    spurious_wakes: Counter,
    rx_packets: Counter,
    tx_packets: Counter,
    tx_lso_packets: Counter,
    tx_checksum_packets: Counter,
    tx_packets_per_wake: Histogram<10>,
    rx_packets_per_wake: Histogram<10>,
}

#[derive(Debug)]
struct PendingTxCompletion {
    transaction_id: u64,
    tx_id: Option<TxId>,
}

#[derive(Clone, Copy)]
enum PrimaryChannelGuestVfState {
    /// No state has been assigned yet
    Initializing,
    /// State is being restored from a save
    Restoring(saved_state::GuestVfState),
    /// No VF available for the guest
    Unavailable,
    /// A VF was previously available to the guest, but is no longer available.
    UnavailableFromAvailable,
    /// A VF was previously available, but it is no longer available.
    UnavailableFromDataPathSwitchPending { to_guest: bool, id: Option<u64> },
    /// A VF was previously available, but it is no longer available.
    UnavailableFromDataPathSwitched,
    /// A VF is available for the guest.
    Available { vfid: u32 },
    /// A VF is available for the guest and has been advertised to the guest.
    AvailableAdvertised,
    /// A VF is ready for guest use.
    Ready,
    /// A VF is ready in the guest and guest has requested a data path switch.
    DataPathSwitchPending {
        to_guest: bool,
        id: Option<u64>,
        result: Option<bool>,
    },
    /// A VF is ready in the guest and is currently acting as the data path.
    DataPathSwitched,
    /// A VF is ready in the guest and was acting as the data path, but an external
    /// state change has moved it back to synthetic.
    DataPathSynthetic,
}

impl std::fmt::Display for PrimaryChannelGuestVfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrimaryChannelGuestVfState::Initializing => write!(f, "initializing"),
            PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::NoState) => write!(f, "restoring"),
            PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::AvailableAdvertised) => write!(f, "restoring from guest notified of vfid"),
            PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::Ready) => write!(f, "restoring from vf present"),
            PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::DataPathSwitchPending{to_guest, result, ..}) => {
                write!(f, "restoring from client requested data path switch: to {} {}",
                    if *to_guest { "guest" } else { "synthetic" },
                    if let Some(result) = result {
                        if *result {
                            "succeeded\""
                        } else {
                            "failed\""
                        }
                    } else {
                        "in progress\""
                    }
                )
            }
            PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::DataPathSwitched) => write!(f, "restoring from data path in guest"),
            PrimaryChannelGuestVfState::Unavailable => write!(f, "unavailable"),
            PrimaryChannelGuestVfState::UnavailableFromAvailable => {
                write!(f, "\"unavailable (previously available)\"")
            }
            PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending { .. } => {
                write!(f, "unavailable (previously switching data path)")
            }
            PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched => {
                write!(f, "\"unavailable (previously using guest VF)\"")
            }
            PrimaryChannelGuestVfState::Available{vfid} => write!(f, "available vfid: {}", vfid),
            PrimaryChannelGuestVfState::AvailableAdvertised => write!(f, "\"available, guest notified\""),
            PrimaryChannelGuestVfState::Ready => write!(f, "\"available and present in guest\""),
            PrimaryChannelGuestVfState::DataPathSwitchPending {
                to_guest, result, ..
            } => {
                write!(
                    f,
                    "\"switching to {} {}",
                    if *to_guest { "guest" } else { "synthetic" },
                    if let Some(result) = result {
                        if *result {
                            "succeeded\""
                        } else {
                            "failed\""
                        }
                    } else {
                        "in progress\""
                    }
                )
            }
            PrimaryChannelGuestVfState::DataPathSwitched => {
                write!(f, "\"available and data path switched\"")
            }
            PrimaryChannelGuestVfState::DataPathSynthetic => write!(
                f,
                "\"available but data path switched back to synthetic due to external state change\""
            ),
        }
    }
}

impl Inspect for PrimaryChannelGuestVfState {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.value(format!("{}", self).into());
    }
}

#[derive(Debug)]
enum PendingLinkAction {
    Default,
    Active(bool),
    Delay(bool),
}

struct PrimaryChannelState {
    guest_vf_state: PrimaryChannelGuestVfState,
    is_data_path_switched: Option<bool>,
    control_messages: VecDeque<ControlMessage>,
    control_messages_len: usize,
    free_control_buffers: Vec<ControlMessageId>,
    rss_state: Option<RssState>,
    requested_num_queues: u16,
    rndis_state: RndisState,
    offload_config: OffloadConfig,
    pending_offload_change: bool,
    tx_spread_sent: bool,
    guest_link_up: bool,
    pending_link_action: PendingLinkAction,
}

impl Inspect for PrimaryChannelState {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .sensitivity_field(
                "guest_vf_state",
                SensitivityLevel::Safe,
                self.guest_vf_state,
            )
            .sensitivity_field(
                "data_path_switched",
                SensitivityLevel::Safe,
                self.is_data_path_switched,
            )
            .sensitivity_field(
                "pending_control_messages",
                SensitivityLevel::Safe,
                self.control_messages.len(),
            )
            .sensitivity_field(
                "free_control_message_buffers",
                SensitivityLevel::Safe,
                self.free_control_buffers.len(),
            )
            .sensitivity_field(
                "pending_offload_change",
                SensitivityLevel::Safe,
                self.pending_offload_change,
            )
            .sensitivity_field("rndis_state", SensitivityLevel::Safe, self.rndis_state)
            .sensitivity_field(
                "offload_config",
                SensitivityLevel::Safe,
                &self.offload_config,
            )
            .sensitivity_field(
                "tx_spread_sent",
                SensitivityLevel::Safe,
                self.tx_spread_sent,
            )
            .sensitivity_field("guest_link_up", SensitivityLevel::Safe, self.guest_link_up)
            .sensitivity_field(
                "pending_link_action",
                SensitivityLevel::Safe,
                match &self.pending_link_action {
                    PendingLinkAction::Active(up) => format!("Active({:x?})", up),
                    PendingLinkAction::Delay(up) => format!("Delay({:x?})", up),
                    PendingLinkAction::Default => "None".to_string(),
                },
            );
    }
}

#[derive(Debug, Inspect, Clone)]
struct OffloadConfig {
    #[inspect(safe)]
    checksum_tx: ChecksumOffloadConfig,
    #[inspect(safe)]
    checksum_rx: ChecksumOffloadConfig,
    #[inspect(safe)]
    lso4: bool,
    #[inspect(safe)]
    lso6: bool,
}

#[derive(Debug, Inspect, Clone)]
struct ChecksumOffloadConfig {
    #[inspect(safe)]
    ipv4_header: bool,
    #[inspect(safe)]
    tcp4: bool,
    #[inspect(safe)]
    udp4: bool,
    #[inspect(safe)]
    tcp6: bool,
    #[inspect(safe)]
    udp6: bool,
}

impl ChecksumOffloadConfig {
    fn flags(
        &self,
    ) -> (
        rndisprot::Ipv4ChecksumOffload,
        rndisprot::Ipv6ChecksumOffload,
    ) {
        let on = rndisprot::NDIS_OFFLOAD_SUPPORTED;
        let mut v4 = rndisprot::Ipv4ChecksumOffload::new();
        let mut v6 = rndisprot::Ipv6ChecksumOffload::new();
        if self.ipv4_header {
            v4.set_ip_options_supported(on);
            v4.set_ip_checksum(on);
        }
        if self.tcp4 {
            v4.set_ip_options_supported(on);
            v4.set_tcp_options_supported(on);
            v4.set_tcp_checksum(on);
        }
        if self.tcp6 {
            v6.set_ip_extension_headers_supported(on);
            v6.set_tcp_options_supported(on);
            v6.set_tcp_checksum(on);
        }
        if self.udp4 {
            v4.set_ip_options_supported(on);
            v4.set_udp_checksum(on);
        }
        if self.udp6 {
            v6.set_ip_extension_headers_supported(on);
            v6.set_udp_checksum(on);
        }
        (v4, v6)
    }
}

impl OffloadConfig {
    fn ndis_offload(&self) -> rndisprot::NdisOffload {
        let checksum = {
            let (ipv4_tx_flags, ipv6_tx_flags) = self.checksum_tx.flags();
            let (ipv4_rx_flags, ipv6_rx_flags) = self.checksum_rx.flags();
            rndisprot::TcpIpChecksumOffload {
                ipv4_tx_encapsulation: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                ipv4_tx_flags,
                ipv4_rx_encapsulation: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                ipv4_rx_flags,
                ipv6_tx_encapsulation: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                ipv6_tx_flags,
                ipv6_rx_encapsulation: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                ipv6_rx_flags,
            }
        };

        let lso_v2 = {
            let mut lso = rndisprot::TcpLargeSendOffloadV2::new_zeroed();
            // Use the same maximum as vmswitch.
            const MAX_OFFLOAD_SIZE: u32 = 0xF53C;
            if self.lso4 {
                lso.ipv4_encapsulation = rndisprot::NDIS_ENCAPSULATION_IEEE_802_3;
                lso.ipv4_max_offload_size = MAX_OFFLOAD_SIZE;
                lso.ipv4_min_segment_count = 2;
            }
            if self.lso6 {
                lso.ipv6_encapsulation = rndisprot::NDIS_ENCAPSULATION_IEEE_802_3;
                lso.ipv6_max_offload_size = MAX_OFFLOAD_SIZE;
                lso.ipv6_min_segment_count = 2;
                lso.ipv6_flags = rndisprot::Ipv6LsoFlags::new()
                    .with_ip_extension_headers_supported(rndisprot::NDIS_OFFLOAD_SUPPORTED)
                    .with_tcp_options_supported(rndisprot::NDIS_OFFLOAD_SUPPORTED);
            }
            lso
        };

        rndisprot::NdisOffload {
            header: rndisprot::NdisObjectHeader {
                object_type: rndisprot::NdisObjectType::OFFLOAD,
                revision: 3,
                size: rndisprot::NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3 as u16,
            },
            checksum,
            lso_v2,
            ..FromZeros::new_zeroed()
        }
    }
}

#[derive(Debug, Inspect, PartialEq, Eq, Copy, Clone)]
pub enum RndisState {
    Initializing,
    Operational,
    Halted,
}

impl PrimaryChannelState {
    fn new(offload_config: OffloadConfig) -> Self {
        Self {
            guest_vf_state: PrimaryChannelGuestVfState::Initializing,
            is_data_path_switched: None,
            control_messages: VecDeque::new(),
            control_messages_len: 0,
            free_control_buffers: (0..RX_RESERVED_CONTROL_BUFFERS)
                .map(ControlMessageId)
                .collect(),
            rss_state: None,
            requested_num_queues: 1,
            rndis_state: RndisState::Initializing,
            pending_offload_change: false,
            offload_config,
            tx_spread_sent: false,
            guest_link_up: true,
            pending_link_action: PendingLinkAction::Default,
        }
    }

    fn restore(
        guest_vf_state: &saved_state::GuestVfState,
        rndis_state: &saved_state::RndisState,
        offload_config: &saved_state::OffloadConfig,
        pending_offload_change: bool,
        num_queues: u16,
        indirection_table_size: u16,
        rx_bufs: &RxBuffers,
        control_messages: Vec<saved_state::IncomingControlMessage>,
        rss_state: Option<saved_state::RssState>,
        tx_spread_sent: bool,
        guest_link_down: bool,
        pending_link_action: Option<bool>,
    ) -> Result<Self, NetRestoreError> {
        // Restore control messages.
        let control_messages_len = control_messages.iter().map(|msg| msg.data.len()).sum();

        let control_messages = control_messages
            .into_iter()
            .map(|msg| ControlMessage {
                message_type: msg.message_type,
                data: msg.data.into(),
            })
            .collect();

        // Compute the free control buffers.
        let free_control_buffers = (0..RX_RESERVED_CONTROL_BUFFERS)
            .filter_map(|id| rx_bufs.is_free(id).then_some(ControlMessageId(id)))
            .collect();

        let rss_state = rss_state
            .map(|rss| {
                if rss.indirection_table.len() != indirection_table_size as usize {
                    return Err(NetRestoreError::MismatchedIndirectionTableSize);
                }
                Ok(RssState {
                    key: rss
                        .key
                        .try_into()
                        .map_err(|_| NetRestoreError::InvalidRssKeySize)?,
                    indirection_table: rss.indirection_table,
                })
            })
            .transpose()?;

        let rndis_state = match rndis_state {
            saved_state::RndisState::Initializing => RndisState::Initializing,
            saved_state::RndisState::Operational => RndisState::Operational,
            saved_state::RndisState::Halted => RndisState::Halted,
        };

        let guest_vf_state = PrimaryChannelGuestVfState::Restoring(*guest_vf_state);
        let offload_config = OffloadConfig {
            checksum_tx: ChecksumOffloadConfig {
                ipv4_header: offload_config.checksum_tx.ipv4_header,
                tcp4: offload_config.checksum_tx.tcp4,
                udp4: offload_config.checksum_tx.udp4,
                tcp6: offload_config.checksum_tx.tcp6,
                udp6: offload_config.checksum_tx.udp6,
            },
            checksum_rx: ChecksumOffloadConfig {
                ipv4_header: offload_config.checksum_rx.ipv4_header,
                tcp4: offload_config.checksum_rx.tcp4,
                udp4: offload_config.checksum_rx.udp4,
                tcp6: offload_config.checksum_rx.tcp6,
                udp6: offload_config.checksum_rx.udp6,
            },
            lso4: offload_config.lso4,
            lso6: offload_config.lso6,
        };

        let pending_link_action = if let Some(pending) = pending_link_action {
            PendingLinkAction::Active(pending)
        } else {
            PendingLinkAction::Default
        };

        Ok(Self {
            guest_vf_state,
            is_data_path_switched: None,
            control_messages,
            control_messages_len,
            free_control_buffers,
            rss_state,
            requested_num_queues: num_queues,
            rndis_state,
            pending_offload_change,
            offload_config,
            tx_spread_sent,
            guest_link_up: !guest_link_down,
            pending_link_action,
        })
    }
}

struct ControlMessage {
    message_type: u32,
    data: Box<[u8]>,
}

const TX_PACKET_QUOTA: usize = 1024;

impl ActiveState {
    fn new(primary: Option<PrimaryChannelState>, recv_buffer_count: u32) -> Self {
        Self {
            primary,
            pending_tx_packets: vec![Default::default(); TX_PACKET_QUOTA],
            free_tx_packets: (0..TX_PACKET_QUOTA as u32).rev().map(TxId).collect(),
            pending_tx_completions: VecDeque::new(),
            rx_bufs: RxBuffers::new(recv_buffer_count),
            stats: Default::default(),
        }
    }

    fn restore(
        channel: &saved_state::Channel,
        recv_buffer_count: u32,
    ) -> Result<Self, NetRestoreError> {
        let mut active = Self::new(None, recv_buffer_count);
        let saved_state::Channel {
            pending_tx_completions,
            in_use_rx,
        } = channel;
        for rx in in_use_rx {
            active
                .rx_bufs
                .allocate(rx.buffers.as_slice().iter().copied())?;
        }
        for &transaction_id in pending_tx_completions {
            // Consume tx quota if any is available. If not, still
            // allow the restore since tx quota might change from
            // release to release.
            let tx_id = active.free_tx_packets.pop();
            if let Some(id) = tx_id {
                // This shouldn't be referenced, but set it in case it is in the future.
                active.pending_tx_packets[id.0 as usize].transaction_id = transaction_id;
            }
            active
                .pending_tx_completions
                .push_back(PendingTxCompletion {
                    transaction_id,
                    tx_id,
                });
        }
        Ok(active)
    }
}

/// The state for an rndis tx packet that's currently pending in the backend
/// endpoint.
#[derive(Default, Clone)]
struct PendingTxPacket {
    pending_packet_count: usize,
    transaction_id: u64,
}

/// The maximum batch size.
///
/// TODO: An even larger value is supported when RSC is enabled, so look into
/// this.
const RX_BATCH_SIZE: usize = 375;

/// The number of receive buffers to reserve for control message responses.
const RX_RESERVED_CONTROL_BUFFERS: u32 = 16;

/// A network adapter.
pub struct Nic {
    instance_id: Guid,
    resources: DeviceResources,
    coordinator: TaskControl<CoordinatorState, Coordinator>,
    coordinator_send: Option<mpsc::Sender<CoordinatorMessage>>,
    adapter: Arc<Adapter>,
    driver_source: VmTaskDriverSource,
}

pub struct NicBuilder {
    virtual_function: Option<Box<dyn VirtualFunction>>,
    limit_ring_buffer: bool,
    max_queues: u16,
    get_guest_os_id: Option<Box<dyn Fn() -> HvGuestOsId + Send + Sync>>,
}

impl NicBuilder {
    pub fn limit_ring_buffer(mut self, limit: bool) -> Self {
        self.limit_ring_buffer = limit;
        self
    }

    pub fn max_queues(mut self, max_queues: u16) -> Self {
        self.max_queues = max_queues;
        self
    }

    pub fn virtual_function(mut self, virtual_function: Box<dyn VirtualFunction>) -> Self {
        self.virtual_function = Some(virtual_function);
        self
    }

    pub fn get_guest_os_id(mut self, os_type: Box<dyn Fn() -> HvGuestOsId + Send + Sync>) -> Self {
        self.get_guest_os_id = Some(os_type);
        self
    }

    /// Creates a new NIC.
    pub fn build(
        self,
        driver_source: &VmTaskDriverSource,
        instance_id: Guid,
        endpoint: Box<dyn Endpoint>,
        mac_address: MacAddress,
        adapter_index: u32,
    ) -> Nic {
        let multiqueue = endpoint.multiqueue_support();

        let max_queues = self.max_queues.clamp(
            1,
            multiqueue.max_queues.min(NETVSP_MAX_SUBCHANNELS_PER_VNIC),
        );

        // If requested, limit the effective size of the outgoing ring buffer.
        // In a configuration where the NIC is processed synchronously, this
        // will ensure that we don't process incoming rx packets and tx packet
        // completions until the guest has processed the data it already has.
        let ring_size_limit = if self.limit_ring_buffer { 1024 } else { 0 };

        // If the endpoint completes tx packets quickly, then avoid polling the
        // incoming ring (and thus avoid arming the signal from the guest) as
        // long as there are any tx packets in flight. This can significantly
        // reduce the signal rate from the guest, improving batching.
        let free_tx_packet_threshold = if endpoint.tx_fast_completions() {
            TX_PACKET_QUOTA
        } else {
            // Avoid getting into a situation where there is always barely
            // enough quota.
            TX_PACKET_QUOTA / 4
        };

        let tx_offloads = endpoint.tx_offload_support();

        // Always claim support for rx offloads since we can mark any given
        // packet as having unknown checksum state.
        let offload_support = OffloadConfig {
            checksum_rx: ChecksumOffloadConfig {
                ipv4_header: true,
                tcp4: true,
                udp4: true,
                tcp6: true,
                udp6: true,
            },
            checksum_tx: ChecksumOffloadConfig {
                ipv4_header: tx_offloads.ipv4_header,
                tcp4: tx_offloads.tcp,
                tcp6: tx_offloads.tcp,
                udp4: tx_offloads.udp,
                udp6: tx_offloads.udp,
            },
            lso4: tx_offloads.tso,
            lso6: tx_offloads.tso,
        };

        let driver = driver_source.simple();
        let adapter = Arc::new(Adapter {
            driver,
            mac_address,
            max_queues,
            indirection_table_size: multiqueue.indirection_table_size,
            offload_support,
            free_tx_packet_threshold,
            ring_size_limit: ring_size_limit.into(),
            tx_fast_completions: endpoint.tx_fast_completions(),
            adapter_index,
            get_guest_os_id: self.get_guest_os_id,
            num_sub_channels_opened: AtomicUsize::new(0),
            link_speed: endpoint.link_speed(),
        });

        let coordinator = TaskControl::new(CoordinatorState {
            endpoint,
            adapter: adapter.clone(),
            virtual_function: self.virtual_function,
            pending_vf_state: CoordinatorStatePendingVfState::Ready,
        });

        Nic {
            instance_id,
            resources: Default::default(),
            coordinator,
            coordinator_send: None,
            adapter,
            driver_source: driver_source.clone(),
        }
    }
}

fn can_use_ring_opt<T: RingMem>(queue: &mut Queue<T>, guest_os_id: Option<HvGuestOsId>) -> bool {
    let Some(guest_os_id) = guest_os_id else {
        // guest os id not available.
        return false;
    };

    if !queue.split().0.supports_pending_send_size() {
        // guest does not support pending send size.
        return false;
    }

    let Some(open_source_os) = guest_os_id.open_source() else {
        // guest os is proprietary (ex: Windows)
        return true;
    };

    match HvGuestOsOpenSourceType(open_source_os.os_type()) {
        // Although FreeBSD indicates support for `pending send size`, it doesn't
        // implement it correctly. This was fixed in FreeBSD version `1400097`.
        // No known issues with other open source OS.
        HvGuestOsOpenSourceType::FREEBSD => open_source_os.version() >= 1400097,
        _ => true,
    }
}

impl Nic {
    pub fn builder() -> NicBuilder {
        NicBuilder {
            virtual_function: None,
            limit_ring_buffer: false,
            max_queues: !0,
            get_guest_os_id: None,
        }
    }

    pub fn shutdown(self) -> Box<dyn Endpoint> {
        let (state, _) = self.coordinator.into_inner();
        state.endpoint
    }
}

impl InspectMut for Nic {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        self.coordinator.inspect_mut(req);
    }
}

#[async_trait]
impl VmbusDevice for Nic {
    fn offer(&self) -> OfferParams {
        OfferParams {
            interface_name: "net".to_owned(),
            instance_id: self.instance_id,
            interface_id: Guid {
                data1: 0xf8615163,
                data2: 0xdf3e,
                data3: 0x46c5,
                data4: [0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0xe],
            },
            subchannel_index: 0,
            use_mnf: true,
            ..Default::default()
        }
    }

    fn max_subchannels(&self) -> u16 {
        self.adapter.max_queues
    }

    fn install(&mut self, resources: DeviceResources) {
        self.resources = resources;
    }

    async fn open(
        &mut self,
        channel_idx: u16,
        open_request: &OpenRequest,
    ) -> Result<(), ChannelOpenError> {
        // Start the coordinator task if this is the primary channel.
        let state = if channel_idx == 0 {
            self.insert_coordinator(1, false);
            WorkerState::Init(None)
        } else {
            self.coordinator.stop().await;
            // Get the buffers created when the primary channel was opened.
            let buffers = self.coordinator.state().unwrap().buffers.clone().unwrap();
            WorkerState::Ready(ReadyState {
                state: ActiveState::new(None, buffers.recv_buffer.count),
                buffers,
                data: ProcessingData::new(),
            })
        };

        let num_opened = self
            .adapter
            .num_sub_channels_opened
            .fetch_add(1, Ordering::SeqCst);
        let r = self.insert_worker(channel_idx, open_request, state, true);
        if channel_idx != 0
            && num_opened + 1 == self.coordinator.state_mut().unwrap().num_queues as usize
        {
            let coordinator = &mut self.coordinator.state_mut().unwrap();
            coordinator.workers[0].stop().await;
            coordinator.workers[0].start();
        }

        if r.is_err() && channel_idx == 0 {
            self.coordinator.remove();
        } else {
            self.coordinator.start();
        }
        r?;
        Ok(())
    }

    async fn close(&mut self, channel_idx: u16) {
        if !self.coordinator.has_state() {
            tracing::error!("Close called while vmbus channel is already closed");
            return;
        }

        // Stop the coordinator to get access to the workers.
        let restart = self.coordinator.stop().await;

        // Stop and remove the channel worker.
        {
            let worker = &mut self.coordinator.state_mut().unwrap().workers[channel_idx as usize];
            worker.stop().await;
            if worker.has_state() {
                worker.remove();
            }
        }

        self.adapter
            .num_sub_channels_opened
            .fetch_sub(1, Ordering::SeqCst);
        // Disable the endpoint.
        if channel_idx == 0 {
            for worker in &mut self.coordinator.state_mut().unwrap().workers {
                worker.task_mut().queue_state = None;
            }

            // Note that this await is not restartable.
            self.coordinator.task_mut().endpoint.stop().await;

            // Keep any VF's added to the guest. This is required to keep guest compat as
            // some apps (such as DPDK) relies on the VF sticking around even after vmbus
            // channel is closed.
            // The coordinator's job is done.
            self.coordinator.remove();
        } else {
            // Restart the coordinator.
            if restart {
                self.coordinator.start();
            }
        }
    }

    async fn retarget_vp(&mut self, channel_idx: u16, target_vp: u32) {
        if !self.coordinator.has_state() {
            return;
        }

        // Stop the coordinator and worker associated with this channel.
        let coordinator_running = self.coordinator.stop().await;
        let worker = &mut self.coordinator.state_mut().unwrap().workers[channel_idx as usize];
        let worker_running = worker.stop().await;
        let (net_queue, worker_state) = worker.get_mut();

        // Update the target VP on the driver.
        net_queue.driver.retarget_vp(target_vp);

        if let Some(worker_state) = worker_state {
            // Update the target VP in the worker state.
            worker_state.target_vp = target_vp;
            if let Some(queue_state) = &mut net_queue.queue_state {
                // Tell the worker to re-set the target VP on next run.
                queue_state.target_vp_set = false;
            }
        }

        if worker_running {
            worker.start();
        }

        if coordinator_running {
            self.coordinator.start();
        }
    }

    fn start(&mut self) {
        if !self.coordinator.is_running() {
            if let Some(coordinator) = self.coordinator.state_mut() {
                coordinator.start_workers();
            }
            self.coordinator.start();
        }
    }

    async fn stop(&mut self) {
        self.coordinator.stop().await;
        if let Some(coordinator) = self.coordinator.state_mut() {
            coordinator.stop_workers().await;
        }
    }

    fn supports_save_restore(&mut self) -> Option<&mut dyn SaveRestoreVmbusDevice> {
        Some(self)
    }
}

#[async_trait]
impl SaveRestoreVmbusDevice for Nic {
    async fn save(&mut self) -> Result<SavedStateBlob, SaveError> {
        let state = self.saved_state();
        Ok(SavedStateBlob::new(state))
    }

    async fn restore(
        &mut self,
        control: RestoreControl<'_>,
        state: SavedStateBlob,
    ) -> Result<(), RestoreError> {
        let state: saved_state::SavedState = state.parse()?;
        if let Err(err) = self.restore_state(control, state).await {
            tracing::error!(err = &err as &dyn std::error::Error, instance_id = %self.instance_id, "Failed restoring network vmbus state");
            Err(err.into())
        } else {
            Ok(())
        }
    }
}

impl Nic {
    /// Allocates and inserts a worker.
    ///
    /// The coordinator must be stopped.
    fn insert_worker(
        &mut self,
        channel_idx: u16,
        open_request: &OpenRequest,
        state: WorkerState,
        start: bool,
    ) -> Result<(), OpenError> {
        let coordinator = self.coordinator.state_mut().unwrap();

        // Retarget the driver now that the channel is open.
        let driver = coordinator.workers[channel_idx as usize]
            .task()
            .driver
            .clone();
        driver.retarget_vp(open_request.open_data.target_vp);

        let raw = gpadl_channel(&driver, &self.resources, open_request, channel_idx)
            .map_err(OpenError::Ring)?;
        let mut queue = Queue::new(raw).map_err(OpenError::Queue)?;
        let guest_os_id = self.adapter.get_guest_os_id.as_ref().map(|f| f());
        let can_use_ring_size_opt = can_use_ring_opt(&mut queue, guest_os_id);
        let worker = Worker {
            channel_idx,
            target_vp: open_request.open_data.target_vp,
            mem: self
                .resources
                .offer_resources
                .guest_memory(open_request)
                .clone(),
            channel: NetChannel {
                adapter: self.adapter.clone(),
                queue,
                gpadl_map: self.resources.gpadl_map.clone(),
                packet_size: protocol::PACKET_SIZE_V1,
                pending_send_size: 0,
                restart: None,
                can_use_ring_size_opt,
            },
            state,
            coordinator_send: self.coordinator_send.clone().unwrap(),
        };
        let instance_id = self.instance_id;
        let worker_task = &mut coordinator.workers[channel_idx as usize];
        worker_task.insert(
            driver,
            format!("netvsp-{}-{}", instance_id, channel_idx),
            worker,
        );
        if start {
            worker_task.start();
        }
        Ok(())
    }
}

impl Nic {
    /// If `restoring`, then restart the queues as soon as the coordinator starts.
    fn insert_coordinator(&mut self, num_queues: u16, restoring: bool) {
        let mut driver_builder = self.driver_source.builder();
        // Target each driver to VP 0 initially. This will be updated when the
        // channel is opened.
        driver_builder.target_vp(0);
        // If tx completions arrive quickly, then just do tx processing
        // on whatever processor the guest happens to signal from.
        // Subsequent transmits will be pulled from the completion
        // processor.
        driver_builder.run_on_target(!self.adapter.tx_fast_completions);

        #[allow(clippy::disallowed_methods)] // TODO
        let (send, recv) = mpsc::channel(1);
        self.coordinator_send = Some(send);
        self.coordinator.insert(
            &self.adapter.driver,
            format!("netvsp-{}-coordinator", self.instance_id),
            Coordinator {
                recv,
                channel_control: self.resources.channel_control.clone(),
                restart: restoring,
                workers: (0..self.adapter.max_queues)
                    .map(|i| {
                        TaskControl::new(NetQueue {
                            queue_state: None,
                            driver: driver_builder
                                .build(format!("netvsp-{}-{}", self.instance_id, i)),
                        })
                    })
                    .collect(),
                buffers: None,
                num_queues,
            },
        );
    }
}

#[derive(Debug, Error)]
enum NetRestoreError {
    #[error("unsupported protocol version {0:#x}")]
    UnsupportedVersion(u32),
    #[error("send/receive buffer invalid gpadl ID")]
    UnknownGpadlId(#[from] UnknownGpadlId),
    #[error("failed to restore channels")]
    Channel(#[source] ChannelRestoreError),
    #[error(transparent)]
    ReceiveBuffer(#[from] BufferError),
    #[error(transparent)]
    SuballocationMisconfigured(#[from] SubAllocationInUse),
    #[error(transparent)]
    Open(#[from] OpenError),
    #[error("invalid rss key size")]
    InvalidRssKeySize,
    #[error("mismatched indirection table size")]
    MismatchedIndirectionTableSize,
}

impl From<NetRestoreError> for RestoreError {
    fn from(err: NetRestoreError) -> Self {
        RestoreError::InvalidSavedState(anyhow::Error::new(err))
    }
}

impl Nic {
    async fn restore_state(
        &mut self,
        mut control: RestoreControl<'_>,
        state: saved_state::SavedState,
    ) -> Result<(), NetRestoreError> {
        if let Some(state) = state.open {
            let open = match &state.primary {
                saved_state::Primary::Version => vec![true],
                saved_state::Primary::Init(_) => vec![true],
                saved_state::Primary::Ready(ready) => {
                    ready.channels.iter().map(|x| x.is_some()).collect()
                }
            };

            let mut states: Vec<_> = open.iter().map(|_| None).collect();

            // N.B. This will restore the vmbus view of open channels, so any
            //      failures after this point could result in inconsistent
            //      state (vmbus believes the channel is open/active). There
            //      are a number of failure paths after this point because this
            //      call also restores vmbus device state, like the GPADL map.
            let requests = control
                .restore(&open)
                .await
                .map_err(NetRestoreError::Channel)?;

            match state.primary {
                saved_state::Primary::Version => {
                    states[0] = Some(WorkerState::Init(None));
                }
                saved_state::Primary::Init(init) => {
                    let version = check_version(init.version)
                        .ok_or(NetRestoreError::UnsupportedVersion(init.version))?;

                    let recv_buffer = init
                        .receive_buffer
                        .map(|recv_buffer| {
                            ReceiveBuffer::new(
                                &self.resources.gpadl_map,
                                recv_buffer.gpadl_id,
                                recv_buffer.id,
                                recv_buffer.sub_allocation_size,
                            )
                        })
                        .transpose()?;

                    let send_buffer = init
                        .send_buffer
                        .map(|send_buffer| {
                            SendBuffer::new(&self.resources.gpadl_map, send_buffer.gpadl_id)
                        })
                        .transpose()?;

                    let state = InitState {
                        version,
                        ndis_config: init.ndis_config.map(
                            |saved_state::NdisConfig { mtu, capabilities }| NdisConfig {
                                mtu,
                                capabilities: capabilities.into(),
                            },
                        ),
                        ndis_version: init.ndis_version.map(
                            |saved_state::NdisVersion { major, minor }| NdisVersion {
                                major,
                                minor,
                            },
                        ),
                        recv_buffer,
                        send_buffer,
                    };
                    states[0] = Some(WorkerState::Init(Some(state)));
                }
                saved_state::Primary::Ready(ready) => {
                    let saved_state::ReadyPrimary {
                        version,
                        receive_buffer,
                        send_buffer,
                        mut control_messages,
                        mut rss_state,
                        channels,
                        ndis_version,
                        ndis_config,
                        rndis_state,
                        guest_vf_state,
                        offload_config,
                        pending_offload_change,
                        tx_spread_sent,
                        guest_link_down,
                        pending_link_action,
                    } = ready;

                    let version = check_version(version)
                        .ok_or(NetRestoreError::UnsupportedVersion(version))?;

                    let request = requests[0].as_ref().unwrap();
                    let buffers = Arc::new(ChannelBuffers {
                        version,
                        mem: self.resources.offer_resources.guest_memory(request).clone(),
                        recv_buffer: ReceiveBuffer::new(
                            &self.resources.gpadl_map,
                            receive_buffer.gpadl_id,
                            receive_buffer.id,
                            receive_buffer.sub_allocation_size,
                        )?,
                        send_buffer: {
                            if let Some(send_buffer) = send_buffer {
                                Some(SendBuffer::new(
                                    &self.resources.gpadl_map,
                                    send_buffer.gpadl_id,
                                )?)
                            } else {
                                None
                            }
                        },
                        ndis_version: {
                            let saved_state::NdisVersion { major, minor } = ndis_version;
                            NdisVersion { major, minor }
                        },
                        ndis_config: {
                            let saved_state::NdisConfig { mtu, capabilities } = ndis_config;
                            NdisConfig {
                                mtu,
                                capabilities: capabilities.into(),
                            }
                        },
                    });

                    for (channel_idx, channel) in channels.iter().enumerate() {
                        let channel = if let Some(channel) = channel {
                            channel
                        } else {
                            continue;
                        };

                        let mut active = ActiveState::restore(channel, buffers.recv_buffer.count)?;

                        // Restore primary channel state.
                        if channel_idx == 0 {
                            let primary = PrimaryChannelState::restore(
                                &guest_vf_state,
                                &rndis_state,
                                &offload_config,
                                pending_offload_change,
                                channels.len() as u16,
                                self.adapter.indirection_table_size,
                                &active.rx_bufs,
                                std::mem::take(&mut control_messages),
                                rss_state.take(),
                                tx_spread_sent,
                                guest_link_down,
                                pending_link_action,
                            )?;
                            active.primary = Some(primary);
                        }

                        states[channel_idx] = Some(WorkerState::Ready(ReadyState {
                            buffers: buffers.clone(),
                            state: active,
                            data: ProcessingData::new(),
                        }));
                    }
                }
            }

            // Insert the coordinator and mark that it should try to start the
            // network endpoint when it starts running.
            self.insert_coordinator(states.len() as u16, true);

            for (channel_idx, (state, request)) in states.into_iter().zip(requests).enumerate() {
                if let Some(state) = state {
                    self.insert_worker(channel_idx as u16, &request.unwrap(), state, false)?;
                }
            }
        } else {
            control
                .restore(&[false])
                .await
                .map_err(NetRestoreError::Channel)?;
        }
        Ok(())
    }

    fn saved_state(&self) -> saved_state::SavedState {
        let open = if let Some(coordinator) = self.coordinator.state() {
            let primary = coordinator.workers[0].state().unwrap();
            let primary = match &primary.state {
                WorkerState::Init(None) => saved_state::Primary::Version,
                WorkerState::Init(Some(init)) => {
                    saved_state::Primary::Init(saved_state::InitPrimary {
                        version: init.version as u32,
                        ndis_config: init.ndis_config.map(|NdisConfig { mtu, capabilities }| {
                            saved_state::NdisConfig {
                                mtu,
                                capabilities: capabilities.into(),
                            }
                        }),
                        ndis_version: init.ndis_version.map(|NdisVersion { major, minor }| {
                            saved_state::NdisVersion { major, minor }
                        }),
                        receive_buffer: init.recv_buffer.as_ref().map(|x| x.saved_state()),
                        send_buffer: init.send_buffer.as_ref().map(|x| saved_state::SendBuffer {
                            gpadl_id: x.gpadl.id(),
                        }),
                    })
                }
                WorkerState::Ready(ready) => {
                    let primary = ready.state.primary.as_ref().unwrap();

                    let rndis_state = match primary.rndis_state {
                        RndisState::Initializing => saved_state::RndisState::Initializing,
                        RndisState::Operational => saved_state::RndisState::Operational,
                        RndisState::Halted => saved_state::RndisState::Halted,
                    };

                    let offload_config = saved_state::OffloadConfig {
                        checksum_tx: saved_state::ChecksumOffloadConfig {
                            ipv4_header: primary.offload_config.checksum_tx.ipv4_header,
                            tcp4: primary.offload_config.checksum_tx.tcp4,
                            udp4: primary.offload_config.checksum_tx.udp4,
                            tcp6: primary.offload_config.checksum_tx.tcp6,
                            udp6: primary.offload_config.checksum_tx.udp6,
                        },
                        checksum_rx: saved_state::ChecksumOffloadConfig {
                            ipv4_header: primary.offload_config.checksum_rx.ipv4_header,
                            tcp4: primary.offload_config.checksum_rx.tcp4,
                            udp4: primary.offload_config.checksum_rx.udp4,
                            tcp6: primary.offload_config.checksum_rx.tcp6,
                            udp6: primary.offload_config.checksum_rx.udp6,
                        },
                        lso4: primary.offload_config.lso4,
                        lso6: primary.offload_config.lso6,
                    };

                    let control_messages = primary
                        .control_messages
                        .iter()
                        .map(|message| saved_state::IncomingControlMessage {
                            message_type: message.message_type,
                            data: message.data.to_vec(),
                        })
                        .collect();

                    let rss_state = primary.rss_state.as_ref().map(|rss| saved_state::RssState {
                        key: rss.key.into(),
                        indirection_table: rss.indirection_table.clone(),
                    });

                    let pending_link_action = match primary.pending_link_action {
                        PendingLinkAction::Default => None,
                        PendingLinkAction::Active(action) | PendingLinkAction::Delay(action) => {
                            Some(action)
                        }
                    };

                    let channels = coordinator.workers[..coordinator.num_queues as usize]
                        .iter()
                        .map(|worker| {
                            worker.state().map(|worker| {
                                let channel = if let Some(ready) = worker.state.ready() {
                                    // In flight tx will be considered as dropped packets through save/restore, but need
                                    // to complete the requests back to the guest.
                                    let pending_tx_completions = ready
                                        .state
                                        .pending_tx_completions
                                        .iter()
                                        .map(|pending| pending.transaction_id)
                                        .chain(ready.state.pending_tx_packets.iter().filter_map(
                                            |inflight| {
                                                (inflight.pending_packet_count > 0)
                                                    .then_some(inflight.transaction_id)
                                            },
                                        ))
                                        .collect();

                                    saved_state::Channel {
                                        pending_tx_completions,
                                        in_use_rx: {
                                            ready
                                                .state
                                                .rx_bufs
                                                .allocated()
                                                .map(|id| saved_state::Rx {
                                                    buffers: id.collect(),
                                                })
                                                .collect()
                                        },
                                    }
                                } else {
                                    saved_state::Channel {
                                        pending_tx_completions: Vec::new(),
                                        in_use_rx: Vec::new(),
                                    }
                                };
                                channel
                            })
                        })
                        .collect();

                    let guest_vf_state = match primary.guest_vf_state {
                        PrimaryChannelGuestVfState::Initializing
                        | PrimaryChannelGuestVfState::Unavailable
                        | PrimaryChannelGuestVfState::Available { .. } => {
                            saved_state::GuestVfState::NoState
                        }
                        PrimaryChannelGuestVfState::UnavailableFromAvailable
                        | PrimaryChannelGuestVfState::AvailableAdvertised => {
                            saved_state::GuestVfState::AvailableAdvertised
                        }
                        PrimaryChannelGuestVfState::Ready => saved_state::GuestVfState::Ready,
                        PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending {
                            to_guest,
                            id,
                        } => saved_state::GuestVfState::DataPathSwitchPending {
                            to_guest,
                            id,
                            result: None,
                        },
                        PrimaryChannelGuestVfState::DataPathSwitchPending {
                            to_guest,
                            id,
                            result,
                        } => saved_state::GuestVfState::DataPathSwitchPending {
                            to_guest,
                            id,
                            result,
                        },
                        PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                        | PrimaryChannelGuestVfState::DataPathSwitched
                        | PrimaryChannelGuestVfState::DataPathSynthetic => {
                            saved_state::GuestVfState::DataPathSwitched
                        }
                        PrimaryChannelGuestVfState::Restoring(saved_state) => saved_state,
                    };

                    saved_state::Primary::Ready(saved_state::ReadyPrimary {
                        version: ready.buffers.version as u32,
                        receive_buffer: ready.buffers.recv_buffer.saved_state(),
                        send_buffer: ready.buffers.send_buffer.as_ref().map(|sb| {
                            saved_state::SendBuffer {
                                gpadl_id: sb.gpadl.id(),
                            }
                        }),
                        rndis_state,
                        guest_vf_state,
                        offload_config,
                        pending_offload_change: primary.pending_offload_change,
                        control_messages,
                        rss_state,
                        channels,
                        ndis_config: {
                            let NdisConfig { mtu, capabilities } = ready.buffers.ndis_config;
                            saved_state::NdisConfig {
                                mtu,
                                capabilities: capabilities.into(),
                            }
                        },
                        ndis_version: {
                            let NdisVersion { major, minor } = ready.buffers.ndis_version;
                            saved_state::NdisVersion { major, minor }
                        },
                        tx_spread_sent: primary.tx_spread_sent,
                        guest_link_down: !primary.guest_link_up,
                        pending_link_action,
                    })
                }
            };

            let state = saved_state::OpenState { primary };
            Some(state)
        } else {
            None
        };

        saved_state::SavedState { open }
    }
}

#[derive(Debug, Error)]
enum WorkerError {
    #[error("packet error")]
    Packet(#[source] PacketError),
    #[error("unexpected packet order: {0}")]
    UnexpectedPacketOrder(#[source] PacketOrderError),
    #[error("unknown rndis message type: {0}")]
    UnknownRndisMessageType(u32),
    #[error("memory access error")]
    Access(#[from] AccessError),
    #[error("rndis message too small")]
    RndisMessageTooSmall,
    #[error("unsupported rndis behavior")]
    UnsupportedRndisBehavior,
    #[error("vmbus queue error")]
    Queue(#[from] queue::Error),
    #[error("too many control messages")]
    TooManyControlMessages,
    #[error("invalid rndis packet completion")]
    InvalidRndisPacketCompletion,
    #[error("missing transaction id")]
    MissingTransactionId,
    #[error("invalid gpadl")]
    InvalidGpadl(#[source] guestmem::InvalidGpn),
    #[error("gpadl error")]
    GpadlError(#[source] GuestMemoryError),
    #[error("gpa direct error")]
    GpaDirectError(#[source] GuestMemoryError),
    #[error("endpoint")]
    Endpoint(#[source] anyhow::Error),
    #[error("message not supported on sub channel: {0}")]
    NotSupportedOnSubChannel(u32),
    #[error("the ring buffer ran out of space, which should not be possible")]
    OutOfSpace,
    #[error("send/receive buffer error")]
    Buffer(#[from] BufferError),
    #[error("invalid rndis state")]
    InvalidRndisState,
    #[error("rndis message type not implemented")]
    RndisMessageTypeNotImplemented,
    #[error("invalid TCP header offset")]
    InvalidTcpHeaderOffset,
    #[error("cancelled")]
    Cancelled(task_control::Cancelled),
    #[error("tearing down because send/receive buffer is revoked")]
    BufferRevoked,
}

impl From<task_control::Cancelled> for WorkerError {
    fn from(value: task_control::Cancelled) -> Self {
        Self::Cancelled(value)
    }
}

#[derive(Debug, Error)]
enum OpenError {
    #[error("error establishing ring buffer")]
    Ring(#[source] vmbus_channel::gpadl_ring::Error),
    #[error("error establishing vmbus queue")]
    Queue(#[source] queue::Error),
}

#[derive(Debug, Error)]
enum PacketError {
    #[error("UnknownType {0}")]
    UnknownType(u32),
    #[error("Access")]
    Access(#[source] AccessError),
    #[error("ExternalData")]
    ExternalData(#[source] ExternalDataError),
    #[error("InvalidSendBufferIndex")]
    InvalidSendBufferIndex,
}

#[derive(Debug, Error)]
enum PacketOrderError {
    #[error("Invalid PacketData")]
    InvalidPacketData,
    #[error("Unexpected RndisPacket")]
    UnexpectedRndisPacket,
    #[error("SendNdisVersion already exists")]
    SendNdisVersionExists,
    #[error("SendNdisConfig already exists")]
    SendNdisConfigExists,
    #[error("SendReceiveBuffer already exists")]
    SendReceiveBufferExists,
    #[error("SendReceiveBuffer missing MTU")]
    SendReceiveBufferMissingMTU,
    #[error("SendSendBuffer already exists")]
    SendSendBufferExists,
    #[error("SwitchDataPathCompletion during PrimaryChannelState")]
    SwitchDataPathCompletionPrimaryChannelState,
}

#[derive(Debug)]
enum PacketData {
    Init(protocol::MessageInit),
    SendNdisVersion(protocol::Message1SendNdisVersion),
    SendReceiveBuffer(protocol::Message1SendReceiveBuffer),
    SendSendBuffer(protocol::Message1SendSendBuffer),
    RevokeReceiveBuffer(Message1RevokeReceiveBuffer),
    RevokeSendBuffer(Message1RevokeSendBuffer),
    RndisPacket(protocol::Message1SendRndisPacket),
    RndisPacketComplete(protocol::Message1SendRndisPacketComplete),
    SendNdisConfig(protocol::Message2SendNdisConfig),
    SwitchDataPath(protocol::Message4SwitchDataPath),
    OidQueryEx(protocol::Message5OidQueryEx),
    SubChannelRequest(protocol::Message5SubchannelRequest),
    SendVfAssociationCompletion,
    SwitchDataPathCompletion,
}

#[derive(Debug)]
struct Packet<'a> {
    data: PacketData,
    transaction_id: Option<u64>,
    external_data: MultiPagedRangeBuf<GpnList>,
    send_buffer_suballocation: PagedRange<'a>,
}

type PacketReader<'a> = PagedRangesReader<
    'a,
    std::iter::Chain<std::iter::Once<PagedRange<'a>>, MultiPagedRangeIter<'a>>,
>;

impl Packet<'_> {
    fn rndis_reader<'a>(&'a self, mem: &'a GuestMemory) -> PacketReader<'a> {
        PagedRanges::new(
            std::iter::once(self.send_buffer_suballocation).chain(self.external_data.iter()),
        )
        .reader(mem)
    }
}

fn read_packet_data<T: IntoBytes + FromBytes + Immutable + KnownLayout>(
    reader: &mut impl MemoryRead,
) -> Result<T, PacketError> {
    reader.read_plain().map_err(PacketError::Access)
}

fn parse_packet<'a, T: RingMem>(
    packet_ref: &queue::PacketRef<'_, T>,
    send_buffer: Option<&'a SendBuffer>,
    version: Option<Version>,
) -> Result<Packet<'a>, PacketError> {
    let packet = match packet_ref.as_ref() {
        IncomingPacket::Data(data) => data,
        IncomingPacket::Completion(completion) => {
            let data = if completion.transaction_id() == VF_ASSOCIATION_TRANSACTION_ID {
                PacketData::SendVfAssociationCompletion
            } else if completion.transaction_id() == SWITCH_DATA_PATH_TRANSACTION_ID {
                PacketData::SwitchDataPathCompletion
            } else {
                let mut reader = completion.reader();
                let header: protocol::MessageHeader =
                    reader.read_plain().map_err(PacketError::Access)?;
                match header.message_type {
                    protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE => {
                        PacketData::RndisPacketComplete(read_packet_data(&mut reader)?)
                    }
                    typ => return Err(PacketError::UnknownType(typ)),
                }
            };
            return Ok(Packet {
                data,
                transaction_id: Some(completion.transaction_id()),
                external_data: MultiPagedRangeBuf::empty(),
                send_buffer_suballocation: PagedRange::empty(),
            });
        }
    };

    let mut reader = packet.reader();
    let header: protocol::MessageHeader = reader.read_plain().map_err(PacketError::Access)?;
    let mut send_buffer_suballocation = PagedRange::empty();
    let data = match header.message_type {
        protocol::MESSAGE_TYPE_INIT => PacketData::Init(read_packet_data(&mut reader)?),
        protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION if version >= Some(Version::V1) => {
            PacketData::SendNdisVersion(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER if version >= Some(Version::V1) => {
            PacketData::SendReceiveBuffer(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE1_TYPE_REVOKE_RECEIVE_BUFFER if version >= Some(Version::V1) => {
            PacketData::RevokeReceiveBuffer(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER if version >= Some(Version::V1) => {
            PacketData::SendSendBuffer(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE1_TYPE_REVOKE_SEND_BUFFER if version >= Some(Version::V1) => {
            PacketData::RevokeSendBuffer(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET if version >= Some(Version::V1) => {
            let message: protocol::Message1SendRndisPacket = read_packet_data(&mut reader)?;
            if message.send_buffer_section_index != 0xffffffff {
                send_buffer_suballocation = send_buffer
                    .ok_or(PacketError::InvalidSendBufferIndex)?
                    .gpadl
                    .first()
                    .unwrap()
                    .try_subrange(
                        message.send_buffer_section_index as usize * 6144,
                        message.send_buffer_section_size as usize,
                    )
                    .ok_or(PacketError::InvalidSendBufferIndex)?;
            }
            PacketData::RndisPacket(message)
        }
        protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG if version >= Some(Version::V2) => {
            PacketData::SendNdisConfig(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH if version >= Some(Version::V4) => {
            PacketData::SwitchDataPath(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE5_TYPE_OID_QUERY_EX if version >= Some(Version::V5) => {
            PacketData::OidQueryEx(read_packet_data(&mut reader)?)
        }
        protocol::MESSAGE5_TYPE_SUB_CHANNEL if version >= Some(Version::V5) => {
            PacketData::SubChannelRequest(read_packet_data(&mut reader)?)
        }
        typ => return Err(PacketError::UnknownType(typ)),
    };
    Ok(Packet {
        data,
        transaction_id: packet.transaction_id(),
        external_data: packet
            .read_external_ranges()
            .map_err(PacketError::ExternalData)?,
        send_buffer_suballocation,
    })
}

#[derive(Debug, Copy, Clone)]
struct NvspMessage<T> {
    header: protocol::MessageHeader,
    data: T,
    padding: &'static [u8],
}

impl<T: IntoBytes + Immutable + KnownLayout> NvspMessage<T> {
    fn payload(&self) -> [&[u8]; 3] {
        [self.header.as_bytes(), self.data.as_bytes(), self.padding]
    }
}

impl<T: RingMem> NetChannel<T> {
    fn message<P: IntoBytes + Immutable + KnownLayout>(
        &self,
        message_type: u32,
        data: P,
    ) -> NvspMessage<P> {
        let padding = self.padding(&data);
        NvspMessage {
            header: protocol::MessageHeader { message_type },
            data,
            padding,
        }
    }

    /// Returns zero padding bytes to round the payload up to the packet size.
    /// Only needed for Windows guests, which are picky about packet sizes.
    fn padding<P: IntoBytes + Immutable + KnownLayout>(&self, data: &P) -> &'static [u8] {
        static PADDING: &[u8] = &[0; protocol::PACKET_SIZE_V61];
        let padding_len = self.packet_size
            - cmp::min(
                self.packet_size,
                size_of::<protocol::MessageHeader>() + data.as_bytes().len(),
            );
        &PADDING[..padding_len]
    }

    fn send_completion(
        &mut self,
        transaction_id: Option<u64>,
        payload: &[&[u8]],
    ) -> Result<(), WorkerError> {
        match transaction_id {
            None => Ok(()),
            Some(transaction_id) => Ok(self
                .queue
                .split()
                .1
                .try_write(&queue::OutgoingPacket {
                    transaction_id,
                    packet_type: OutgoingPacketType::Completion,
                    payload,
                })
                .map_err(|err| match err {
                    queue::TryWriteError::Full(_) => WorkerError::OutOfSpace,
                    queue::TryWriteError::Queue(err) => WorkerError::Queue(err),
                })?),
        }
    }
}

static SUPPORTED_VERSIONS: &[Version] = &[
    Version::V1,
    Version::V2,
    Version::V4,
    Version::V5,
    Version::V6,
    Version::V61,
];

fn check_version(requested_version: u32) -> Option<Version> {
    SUPPORTED_VERSIONS
        .iter()
        .find(|version| **version as u32 == requested_version)
        .copied()
}

#[derive(Debug)]
struct ReceiveBuffer {
    gpadl: GpadlView,
    id: u16,
    count: u32,
    sub_allocation_size: u32,
}

#[derive(Debug, Error)]
enum BufferError {
    #[error("unsupported suballocation size {0}")]
    UnsupportedSuballocationSize(u32),
    #[error("unaligned gpadl")]
    UnalignedGpadl,
    #[error("unknown gpadl ID")]
    UnknownGpadlId(#[from] UnknownGpadlId),
}

impl ReceiveBuffer {
    fn new(
        gpadl_map: &GpadlMapView,
        gpadl_id: GpadlId,
        id: u16,
        sub_allocation_size: u32,
    ) -> Result<Self, BufferError> {
        if sub_allocation_size < sub_allocation_size_for_mtu(DEFAULT_MTU) {
            return Err(BufferError::UnsupportedSuballocationSize(
                sub_allocation_size,
            ));
        }
        let gpadl = gpadl_map.map(gpadl_id)?;
        let range = gpadl
            .contiguous_aligned()
            .ok_or(BufferError::UnalignedGpadl)?;
        let num_sub_allocations = range.len() as u32 / sub_allocation_size;
        if num_sub_allocations == 0 {
            return Err(BufferError::UnsupportedSuballocationSize(
                sub_allocation_size,
            ));
        }
        let recv_buffer = Self {
            gpadl,
            id,
            count: num_sub_allocations,
            sub_allocation_size,
        };
        Ok(recv_buffer)
    }

    fn range(&self, index: u32) -> PagedRange<'_> {
        self.gpadl.first().unwrap().subrange(
            (index * self.sub_allocation_size) as usize,
            self.sub_allocation_size as usize,
        )
    }

    fn transfer_page_range(&self, index: u32, len: usize) -> ring::TransferPageRange {
        assert!(len <= self.sub_allocation_size as usize);
        ring::TransferPageRange {
            byte_offset: index * self.sub_allocation_size,
            byte_count: len as u32,
        }
    }

    fn saved_state(&self) -> saved_state::ReceiveBuffer {
        saved_state::ReceiveBuffer {
            gpadl_id: self.gpadl.id(),
            id: self.id,
            sub_allocation_size: self.sub_allocation_size,
        }
    }
}

#[derive(Debug)]
struct SendBuffer {
    gpadl: GpadlView,
}

impl SendBuffer {
    fn new(gpadl_map: &GpadlMapView, gpadl_id: GpadlId) -> Result<Self, BufferError> {
        let gpadl = gpadl_map.map(gpadl_id)?;
        gpadl
            .contiguous_aligned()
            .ok_or(BufferError::UnalignedGpadl)?;
        Ok(Self { gpadl })
    }
}

impl<T: RingMem> NetChannel<T> {
    /// Process a single RNDIS message.
    fn handle_rndis_message(
        &mut self,
        buffers: &ChannelBuffers,
        state: &mut ActiveState,
        id: TxId,
        message_type: u32,
        mut reader: PacketReader<'_>,
        segments: &mut Vec<TxSegment>,
    ) -> Result<bool, WorkerError> {
        let is_packet = match message_type {
            rndisprot::MESSAGE_TYPE_PACKET_MSG => {
                self.handle_rndis_packet_message(
                    id,
                    reader,
                    &buffers.mem,
                    segments,
                    &mut state.stats,
                )?;
                true
            }
            rndisprot::MESSAGE_TYPE_HALT_MSG => false,
            n => {
                let control = state
                    .primary
                    .as_mut()
                    .ok_or(WorkerError::NotSupportedOnSubChannel(n))?;

                // This is a control message that needs a response. Responding
                // will require a suballocation to be available, which it may
                // not be right now. Enqueue the suballocation to a queue and
                // process the queue as suballocations become available.
                const CONTROL_MESSAGE_MAX_QUEUED_BYTES: usize = 100 * 1024;
                if reader.len() == 0 {
                    return Err(WorkerError::RndisMessageTooSmall);
                }
                // Do not let the queue get too large--the guest should not be
                // sending very many control messages at a time.
                if CONTROL_MESSAGE_MAX_QUEUED_BYTES - control.control_messages_len < reader.len() {
                    return Err(WorkerError::TooManyControlMessages);
                }
                control.control_messages_len += reader.len();
                control.control_messages.push_back(ControlMessage {
                    message_type,
                    data: reader.read_all()?.into(),
                });

                false
                // The queue will be processed in the main dispatch loop.
            }
        };
        Ok(is_packet)
    }

    /// Process an RNDIS package message (used to send an Ethernet frame).
    fn handle_rndis_packet_message(
        &mut self,
        id: TxId,
        reader: PacketReader<'_>,
        mem: &GuestMemory,
        segments: &mut Vec<TxSegment>,
        stats: &mut QueueStats,
    ) -> Result<(), WorkerError> {
        // Headers are guaranteed to be in a single PagedRange.
        let headers = reader
            .clone()
            .into_inner()
            .paged_ranges()
            .find(|r| !r.is_empty())
            .ok_or(WorkerError::RndisMessageTooSmall)?;
        let mut data = reader.into_inner();
        let request: rndisprot::Packet = headers.reader(mem).read_plain()?;
        if request.num_oob_data_elements != 0
            || request.oob_data_length != 0
            || request.oob_data_offset != 0
            || request.vc_handle != 0
        {
            return Err(WorkerError::UnsupportedRndisBehavior);
        }

        if data.len() < request.data_offset as usize
            || (data.len() - request.data_offset as usize) < request.data_length as usize
            || request.data_length == 0
        {
            return Err(WorkerError::RndisMessageTooSmall);
        }

        data.skip(request.data_offset as usize);
        data.truncate(request.data_length as usize);

        let mut metadata = net_backend::TxMetadata {
            id,
            len: request.data_length as usize,
            ..Default::default()
        };

        if request.per_packet_info_length != 0 {
            let mut ppi = headers
                .try_subrange(
                    request.per_packet_info_offset as usize,
                    request.per_packet_info_length as usize,
                )
                .ok_or(WorkerError::RndisMessageTooSmall)?;
            while !ppi.is_empty() {
                let h: rndisprot::PerPacketInfo = ppi.reader(mem).read_plain()?;
                if h.size == 0 {
                    return Err(WorkerError::RndisMessageTooSmall);
                }
                let (this, rest) = ppi
                    .try_split(h.size as usize)
                    .ok_or(WorkerError::RndisMessageTooSmall)?;
                let (_, d) = this
                    .try_split(h.per_packet_information_offset as usize)
                    .ok_or(WorkerError::RndisMessageTooSmall)?;
                match h.typ {
                    rndisprot::PPI_TCP_IP_CHECKSUM => {
                        let n: rndisprot::TxTcpIpChecksumInfo = d.reader(mem).read_plain()?;

                        metadata.offload_tcp_checksum =
                            (n.is_ipv4() || n.is_ipv6()) && n.tcp_checksum();
                        metadata.offload_udp_checksum =
                            (n.is_ipv4() || n.is_ipv6()) && !n.tcp_checksum() && n.udp_checksum();
                        metadata.offload_ip_header_checksum = n.is_ipv4() && n.ip_header_checksum();
                        metadata.l3_protocol = if n.is_ipv4() {
                            L3Protocol::Ipv4
                        } else if n.is_ipv6() {
                            L3Protocol::Ipv6
                        } else {
                            L3Protocol::Unknown
                        };
                        metadata.l2_len = ETHERNET_HEADER_LEN as u8;
                        if metadata.offload_tcp_checksum || metadata.offload_udp_checksum {
                            metadata.l3_len = if n.tcp_header_offset() >= metadata.l2_len as u16 {
                                n.tcp_header_offset() - metadata.l2_len as u16
                            } else if n.is_ipv4() {
                                let mut reader = data.clone().reader(mem);
                                reader.skip(metadata.l2_len as usize)?;
                                let mut b = 0;
                                reader.read(std::slice::from_mut(&mut b))?;
                                (b as u16 >> 4) * 4
                            } else {
                                // Hope there are no extensions.
                                40
                            };
                        }
                    }
                    rndisprot::PPI_LSO => {
                        let n: rndisprot::TcpLsoInfo = d.reader(mem).read_plain()?;

                        metadata.offload_tcp_segmentation = true;
                        metadata.offload_tcp_checksum = true;
                        metadata.offload_ip_header_checksum = n.is_ipv4();
                        metadata.l3_protocol = if n.is_ipv4() {
                            L3Protocol::Ipv4
                        } else {
                            L3Protocol::Ipv6
                        };
                        metadata.l2_len = ETHERNET_HEADER_LEN as u8;
                        if n.tcp_header_offset() < metadata.l2_len as u16 {
                            return Err(WorkerError::InvalidTcpHeaderOffset);
                        }
                        metadata.l3_len = n.tcp_header_offset() - metadata.l2_len as u16;
                        metadata.l4_len = {
                            let mut reader = data.clone().reader(mem);
                            reader
                                .skip(metadata.l2_len as usize + metadata.l3_len as usize + 12)?;
                            let mut b = 0;
                            reader.read(std::slice::from_mut(&mut b))?;
                            (b >> 4) * 4
                        };
                        metadata.max_tcp_segment_size = n.mss() as u16;
                    }
                    _ => {}
                }
                ppi = rest;
            }
        }

        let start = segments.len();
        for range in data.paged_ranges().flat_map(|r| r.ranges()) {
            let range = range.map_err(WorkerError::InvalidGpadl)?;
            segments.push(TxSegment {
                ty: net_backend::TxSegmentType::Tail,
                gpa: range.start,
                len: range.len() as u32,
            });
        }

        metadata.segment_count = segments.len() - start;

        stats.tx_packets.increment();
        if metadata.offload_tcp_checksum || metadata.offload_udp_checksum {
            stats.tx_checksum_packets.increment();
        }
        if metadata.offload_tcp_segmentation {
            stats.tx_lso_packets.increment();
        }

        segments[start].ty = net_backend::TxSegmentType::Head(metadata);

        Ok(())
    }

    /// Notify the adapter that the guest VF state has changed and it may
    /// need to send a message to the guest.
    fn guest_vf_is_available(
        &mut self,
        guest_vf_id: Option<u32>,
        version: Version,
        config: NdisConfig,
    ) -> Result<bool, WorkerError> {
        let serial_number = guest_vf_id.map(|vfid| self.adapter.get_guest_vf_serial_number(vfid));
        if version >= Version::V4 && config.capabilities.sriov() {
            tracing::info!(
                available = serial_number.is_some(),
                serial_number,
                "sending VF association message."
            );
            // N.B. MIN_CONTROL_RING_SIZE reserves room to send this packet.
            let message = {
                self.message(
                    protocol::MESSAGE4_TYPE_SEND_VF_ASSOCIATION,
                    protocol::Message4SendVfAssociation {
                        vf_allocated: if serial_number.is_some() { 1 } else { 0 },
                        serial_number: serial_number.unwrap_or(0),
                    },
                )
            };
            self.queue
                .split()
                .1
                .try_write(&queue::OutgoingPacket {
                    transaction_id: VF_ASSOCIATION_TRANSACTION_ID,
                    packet_type: OutgoingPacketType::InBandWithCompletion,
                    payload: &message.payload(),
                })
                .map_err(|err| match err {
                    queue::TryWriteError::Full(len) => {
                        tracing::error!(len, "failed to write vf association message");
                        WorkerError::OutOfSpace
                    }
                    queue::TryWriteError::Queue(err) => WorkerError::Queue(err),
                })?;
            Ok(true)
        } else {
            tracing::info!(
                available = serial_number.is_some(),
                serial_number,
                major = version.major(),
                minor = version.minor(),
                sriov_capable = config.capabilities.sriov(),
                "Skipping NvspMessage4TypeSendVFAssociation message"
            );
            Ok(false)
        }
    }

    /// Send the `NvspMessage5TypeSendIndirectionTable` message.
    fn guest_send_indirection_table(&mut self, version: Version, num_channels_opened: u32) {
        // N.B. MIN_STATE_CHANGE_RING_SIZE needs to be large enough to support sending the indirection table.
        if version < Version::V5 {
            return;
        }

        #[repr(C)]
        #[derive(IntoBytes, Immutable, KnownLayout)]
        struct SendIndirectionMsg {
            pub message: protocol::Message5SendIndirectionTable,
            pub send_indirection_table:
                [u32; VMS_SWITCH_RSS_MAX_SEND_INDIRECTION_TABLE_ENTRIES as usize],
        }

        // The offset to the send indirection table from the beginning of the NVSP message.
        let send_indirection_table_offset = offset_of!(SendIndirectionMsg, send_indirection_table)
            + size_of::<protocol::MessageHeader>();
        let mut data = SendIndirectionMsg {
            message: protocol::Message5SendIndirectionTable {
                table_entry_count: VMS_SWITCH_RSS_MAX_SEND_INDIRECTION_TABLE_ENTRIES,
                table_offset: send_indirection_table_offset as u32,
            },
            send_indirection_table: Default::default(),
        };

        for i in 0..data.send_indirection_table.len() {
            data.send_indirection_table[i] = i as u32 % num_channels_opened;
        }

        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE5_TYPE_SEND_INDIRECTION_TABLE,
            },
            data,
            padding: &[],
        };
        let result = self
            .queue
            .split()
            .1
            .try_write(&queue::OutgoingPacket {
                transaction_id: 0,
                packet_type: OutgoingPacketType::InBandNoCompletion,
                payload: &message.payload(),
            })
            .map_err(|err| match err {
                queue::TryWriteError::Full(len) => {
                    tracing::error!(len, "failed to write send indirection table message");
                    WorkerError::OutOfSpace
                }
                queue::TryWriteError::Queue(err) => WorkerError::Queue(err),
            });
        if let Err(err) = result {
            tracing::error!(err = %err, "Failed to notify guest about the send indirection table");
        }
    }

    /// Notify the guest that the data path has been switched back to synthetic
    /// due to some external state change.
    fn guest_vf_data_path_switched_to_synthetic(&mut self) {
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
            },
            data: protocol::Message4SwitchDataPath {
                active_data_path: protocol::DataPath::SYNTHETIC.0,
            },
            padding: &[],
        };
        let result = self
            .queue
            .split()
            .1
            .try_write(&queue::OutgoingPacket {
                transaction_id: SWITCH_DATA_PATH_TRANSACTION_ID,
                packet_type: OutgoingPacketType::InBandWithCompletion,
                payload: &message.payload(),
            })
            .map_err(|err| match err {
                queue::TryWriteError::Full(len) => {
                    tracing::error!(
                        len,
                        "failed to write MESSAGE4_TYPE_SWITCH_DATA_PATH message"
                    );
                    WorkerError::OutOfSpace
                }
                queue::TryWriteError::Queue(err) => WorkerError::Queue(err),
            });
        if let Err(err) = result {
            tracing::error!(err = %err, "Failed to notify guest that data path is now synthetic");
        }
    }

    /// Process an internal state change
    async fn handle_state_change(
        &mut self,
        primary: &mut PrimaryChannelState,
        buffers: &ChannelBuffers,
    ) -> Result<Option<CoordinatorMessage>, WorkerError> {
        // N.B. MIN_STATE_CHANGE_RING_SIZE needs to be large enough to support sending state change messages.
        // The worst case is UnavailableFromDataPathSwitchPending, which will send three messages:
        //      1. completion of switch data path request
        //      2. Switch data path notification (back to synthetic)
        //      3. Disassociate VF adapter.
        if let PrimaryChannelGuestVfState::Available { vfid } = primary.guest_vf_state {
            // Notify guest that a VF capability has recently arrived.
            if primary.rndis_state == RndisState::Operational {
                if self.guest_vf_is_available(Some(vfid), buffers.version, buffers.ndis_config)? {
                    primary.guest_vf_state = PrimaryChannelGuestVfState::AvailableAdvertised;
                    return Ok(Some(CoordinatorMessage::UpdateGuestVfState));
                } else if let Some(true) = primary.is_data_path_switched {
                    tracing::error!("Data path switched, but current guest negotiation does not support VTL0 VF");
                }
            }
            return Ok(None);
        }
        loop {
            primary.guest_vf_state = match primary.guest_vf_state {
                PrimaryChannelGuestVfState::UnavailableFromAvailable => {
                    // Notify guest that the VF is unavailable. It has already been surprise removed.
                    if primary.rndis_state == RndisState::Operational {
                        self.guest_vf_is_available(None, buffers.version, buffers.ndis_config)?;
                    }
                    PrimaryChannelGuestVfState::Unavailable
                }
                PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending {
                    to_guest,
                    id,
                } => {
                    // Complete the data path switch request.
                    self.send_completion(id, &[])?;
                    if to_guest {
                        PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                    } else {
                        PrimaryChannelGuestVfState::UnavailableFromAvailable
                    }
                }
                PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched => {
                    // Notify guest that the data path is now synthetic.
                    self.guest_vf_data_path_switched_to_synthetic();
                    PrimaryChannelGuestVfState::UnavailableFromAvailable
                }
                PrimaryChannelGuestVfState::DataPathSynthetic => {
                    // Notify guest that the data path is now synthetic.
                    self.guest_vf_data_path_switched_to_synthetic();
                    PrimaryChannelGuestVfState::Ready
                }
                PrimaryChannelGuestVfState::DataPathSwitchPending {
                    to_guest,
                    id,
                    result,
                } => {
                    let result = result.expect("DataPathSwitchPending should have been processed");
                    // Complete the data path switch request.
                    self.send_completion(id, &[])?;
                    if result {
                        if to_guest {
                            PrimaryChannelGuestVfState::DataPathSwitched
                        } else {
                            PrimaryChannelGuestVfState::Ready
                        }
                    } else {
                        if to_guest {
                            PrimaryChannelGuestVfState::DataPathSynthetic
                        } else {
                            tracing::error!(
                                "Failure when guest requested switch back to synthetic"
                            );
                            PrimaryChannelGuestVfState::DataPathSwitched
                        }
                    }
                }
                PrimaryChannelGuestVfState::Initializing
                | PrimaryChannelGuestVfState::Restoring(_) => {
                    panic!("Invalid guest VF state: {}", primary.guest_vf_state)
                }
                _ => break,
            };
        }
        Ok(None)
    }

    /// Process a control message, writing the response to the provided receive
    /// buffer suballocation.
    fn handle_rndis_control_message(
        &mut self,
        primary: &mut PrimaryChannelState,
        buffers: &ChannelBuffers,
        message_type: u32,
        mut reader: impl MemoryRead + Clone,
        id: u32,
    ) -> Result<(), WorkerError> {
        let mem = &buffers.mem;
        let buffer_range = &buffers.recv_buffer.range(id);
        match message_type {
            rndisprot::MESSAGE_TYPE_INITIALIZE_MSG => {
                if primary.rndis_state != RndisState::Initializing {
                    return Err(WorkerError::InvalidRndisState);
                }

                let request: rndisprot::InitializeRequest = reader.read_plain()?;

                tracing::trace!(
                    ?request,
                    "handling control message MESSAGE_TYPE_INITIALIZE_MSG"
                );

                primary.rndis_state = RndisState::Operational;

                let mut writer = buffer_range.writer(mem);
                let message_length = write_rndis_message(
                    &mut writer,
                    rndisprot::MESSAGE_TYPE_INITIALIZE_CMPLT,
                    0,
                    &rndisprot::InitializeComplete {
                        request_id: request.request_id,
                        status: rndisprot::STATUS_SUCCESS,
                        major_version: rndisprot::MAJOR_VERSION,
                        minor_version: rndisprot::MINOR_VERSION,
                        device_flags: rndisprot::DF_CONNECTIONLESS,
                        medium: rndisprot::MEDIUM_802_3,
                        max_packets_per_message: 8,
                        max_transfer_size: 0xEFFFFFFF,
                        packet_alignment_factor: 3,
                        af_list_offset: 0,
                        af_list_size: 0,
                    },
                )?;
                self.send_rndis_control_message(buffers, id, message_length)?;
                if let PrimaryChannelGuestVfState::Available { vfid } = primary.guest_vf_state {
                    if self.guest_vf_is_available(
                        Some(vfid),
                        buffers.version,
                        buffers.ndis_config,
                    )? {
                        // Ideally the VF would not be presented to the guest
                        // until the completion packet has arrived, so that the
                        // guest is prepared. This is most interesting for the
                        // case of a VF associated with multiple guest
                        // adapters, using a concept like vports. In this
                        // scenario it would be better if all of the adapters
                        // were aware a VF was available before the device
                        // arrived. This is not currently possible because the
                        // Linux netvsc driver ignores the completion requested
                        // flag on inband packets and won't send a completion
                        // packet.
                        primary.guest_vf_state = PrimaryChannelGuestVfState::AvailableAdvertised;
                        // restart will also add the VF based on the guest_vf_state
                        if self.restart.is_none() {
                            self.restart = Some(CoordinatorMessage::UpdateGuestVfState);
                        }
                    } else if let Some(true) = primary.is_data_path_switched {
                        tracing::error!("Data path switched, but current guest negotiation does not support VTL0 VF");
                    }
                }
            }
            rndisprot::MESSAGE_TYPE_QUERY_MSG => {
                let request: rndisprot::QueryRequest = reader.read_plain()?;

                tracing::trace!(?request, "handling control message MESSAGE_TYPE_QUERY_MSG");

                let (header, body) = buffer_range
                    .try_split(
                        size_of::<rndisprot::MessageHeader>()
                            + size_of::<rndisprot::QueryComplete>(),
                    )
                    .ok_or(WorkerError::RndisMessageTooSmall)?;
                let (status, tx) = match self.adapter.handle_oid_query(
                    buffers,
                    primary,
                    request.oid,
                    body.writer(mem),
                ) {
                    Ok(tx) => (rndisprot::STATUS_SUCCESS, tx),
                    Err(err) => (err.as_status(), 0),
                };

                let message_length = write_rndis_message(
                    &mut header.writer(mem),
                    rndisprot::MESSAGE_TYPE_QUERY_CMPLT,
                    tx,
                    &rndisprot::QueryComplete {
                        request_id: request.request_id,
                        status,
                        information_buffer_offset: size_of::<rndisprot::QueryComplete>() as u32,
                        information_buffer_length: tx as u32,
                    },
                )?;
                self.send_rndis_control_message(buffers, id, message_length)?;
            }
            rndisprot::MESSAGE_TYPE_SET_MSG => {
                let request: rndisprot::SetRequest = reader.read_plain()?;

                tracing::trace!(?request, "handling control message MESSAGE_TYPE_SET_MSG");

                let status = match self.adapter.handle_oid_set(primary, request.oid, reader) {
                    Ok(restart_endpoint) => {
                        // Restart the endpoint if the OID changed some critical
                        // endpoint property.
                        if restart_endpoint {
                            self.restart = Some(CoordinatorMessage::Restart);
                        }
                        rndisprot::STATUS_SUCCESS
                    }
                    Err(err) => {
                        tracelimit::warn_ratelimited!(oid = ?request.oid, error = &err as &dyn std::error::Error, "oid failure");
                        err.as_status()
                    }
                };

                let message_length = write_rndis_message(
                    &mut buffer_range.writer(mem),
                    rndisprot::MESSAGE_TYPE_SET_CMPLT,
                    0,
                    &rndisprot::SetComplete {
                        request_id: request.request_id,
                        status,
                    },
                )?;
                self.send_rndis_control_message(buffers, id, message_length)?;
            }
            rndisprot::MESSAGE_TYPE_RESET_MSG => {
                return Err(WorkerError::RndisMessageTypeNotImplemented)
            }
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG => {
                return Err(WorkerError::RndisMessageTypeNotImplemented)
            }
            rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG => {
                let request: rndisprot::KeepaliveRequest = reader.read_plain()?;

                tracing::trace!(
                    ?request,
                    "handling control message MESSAGE_TYPE_KEEPALIVE_MSG"
                );

                let message_length = write_rndis_message(
                    &mut buffer_range.writer(mem),
                    rndisprot::MESSAGE_TYPE_KEEPALIVE_CMPLT,
                    0,
                    &rndisprot::KeepaliveComplete {
                        request_id: request.request_id,
                        status: rndisprot::STATUS_SUCCESS,
                    },
                )?;
                self.send_rndis_control_message(buffers, id, message_length)?;
            }
            rndisprot::MESSAGE_TYPE_SET_EX_MSG => {
                return Err(WorkerError::RndisMessageTypeNotImplemented)
            }
            _ => return Err(WorkerError::UnknownRndisMessageType(message_type)),
        };
        Ok(())
    }

    fn try_send_rndis_message(
        &mut self,
        transaction_id: u64,
        channel_type: u32,
        recv_buffer_id: u16,
        transfer_pages: &[ring::TransferPageRange],
    ) -> Result<Option<usize>, WorkerError> {
        let message = self.message(
            protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET,
            protocol::Message1SendRndisPacket {
                channel_type,
                send_buffer_section_index: 0xffffffff,
                send_buffer_section_size: 0,
            },
        );
        let pending_send_size = match self.queue.split().1.try_write(&queue::OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::TransferPages(recv_buffer_id, transfer_pages),
            payload: &message.payload(),
        }) {
            Ok(()) => None,
            Err(queue::TryWriteError::Full(n)) => Some(n),
            Err(queue::TryWriteError::Queue(err)) => return Err(err.into()),
        };
        Ok(pending_send_size)
    }

    fn send_rndis_control_message(
        &mut self,
        buffers: &ChannelBuffers,
        id: u32,
        message_length: usize,
    ) -> Result<(), WorkerError> {
        let result = self.try_send_rndis_message(
            id as u64,
            protocol::CONTROL_CHANNEL_TYPE,
            buffers.recv_buffer.id,
            std::slice::from_ref(&buffers.recv_buffer.transfer_page_range(id, message_length)),
        )?;

        // Ring size is checked before control messages are processed, so failure to write is unexpected.
        match result {
            None => Ok(()),
            Some(len) => {
                tracelimit::error_ratelimited!(len, "failed to write control message completion");
                Err(WorkerError::OutOfSpace)
            }
        }
    }

    fn indicate_status(
        &mut self,
        buffers: &ChannelBuffers,
        id: u32,
        status: u32,
        payload: &[u8],
    ) -> Result<(), WorkerError> {
        let buffer = &buffers.recv_buffer.range(id);
        let mut writer = buffer.writer(&buffers.mem);
        let message_length = write_rndis_message(
            &mut writer,
            rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG,
            payload.len(),
            &rndisprot::IndicateStatus {
                status,
                status_buffer_length: payload.len() as u32,
                status_buffer_offset: if payload.is_empty() {
                    0
                } else {
                    size_of::<rndisprot::IndicateStatus>() as u32
                },
            },
        )?;
        writer.write(payload)?;
        self.send_rndis_control_message(buffers, id, message_length)?;
        Ok(())
    }

    /// Processes pending control messages until all are processed or there are
    /// no available suballocations.
    fn process_control_messages(
        &mut self,
        buffers: &ChannelBuffers,
        state: &mut ActiveState,
    ) -> Result<(), WorkerError> {
        let Some(primary) = &mut state.primary else {
            return Ok(());
        };

        while !primary.control_messages.is_empty()
            || (primary.pending_offload_change && primary.rndis_state == RndisState::Operational)
        {
            // Ensure the ring buffer has enough room to successfully complete control message handling.
            if !self.queue.split().1.can_write(MIN_CONTROL_RING_SIZE)? {
                self.pending_send_size = MIN_CONTROL_RING_SIZE;
                break;
            }
            let Some(id) = primary.free_control_buffers.pop() else {
                break;
            };

            // Mark the receive buffer in use to allow the guest to release it.
            assert!(state.rx_bufs.is_free(id.0));
            state.rx_bufs.allocate(std::iter::once(id.0)).unwrap();

            if let Some(message) = primary.control_messages.pop_front() {
                primary.control_messages_len -= message.data.len();
                self.handle_rndis_control_message(
                    primary,
                    buffers,
                    message.message_type,
                    message.data.as_ref(),
                    id.0,
                )?;
            } else if primary.pending_offload_change
                && primary.rndis_state == RndisState::Operational
            {
                let ndis_offload = primary.offload_config.ndis_offload();
                self.indicate_status(
                    buffers,
                    id.0,
                    rndisprot::STATUS_TASK_OFFLOAD_CURRENT_CONFIG,
                    &ndis_offload.as_bytes()[..ndis_offload.header.size.into()],
                )?;
                primary.pending_offload_change = false;
            } else {
                unreachable!();
            }
        }
        Ok(())
    }
}

/// Writes an RNDIS message to `writer`.
fn write_rndis_message<T: IntoBytes + Immutable + KnownLayout>(
    writer: &mut impl MemoryWrite,
    message_type: u32,
    extra: usize,
    payload: &T,
) -> Result<usize, AccessError> {
    let message_length = size_of::<rndisprot::MessageHeader>() + size_of_val(payload) + extra;
    writer.write(
        rndisprot::MessageHeader {
            message_type,
            message_length: message_length as u32,
        }
        .as_bytes(),
    )?;
    writer.write(payload.as_bytes())?;
    Ok(message_length)
}

#[derive(Debug, Error)]
enum OidError {
    #[error(transparent)]
    Access(#[from] AccessError),
    #[error("unknown oid")]
    UnknownOid,
    #[error("invalid oid input, bad field {0}")]
    InvalidInput(&'static str),
    #[error("bad ndis version")]
    BadVersion,
    #[error("feature {0} not supported")]
    NotSupported(&'static str),
}

impl OidError {
    fn as_status(&self) -> u32 {
        match self {
            OidError::UnknownOid | OidError::NotSupported(_) => rndisprot::STATUS_NOT_SUPPORTED,
            OidError::BadVersion => rndisprot::STATUS_BAD_VERSION,
            OidError::InvalidInput(_) => rndisprot::STATUS_INVALID_DATA,
            OidError::Access(_) => rndisprot::STATUS_FAILURE,
        }
    }
}

const DEFAULT_MTU: u32 = 1514;
const MIN_MTU: u32 = DEFAULT_MTU;
const MAX_MTU: u32 = 9216;

const ETHERNET_HEADER_LEN: u32 = 14;

impl Adapter {
    fn get_guest_vf_serial_number(&self, vfid: u32) -> u32 {
        if let Some(guest_os_id) = self.get_guest_os_id.as_ref().map(|f| f()) {
            // For enlightened guests (which is only Windows at the moment), send the
            // adapter index, which was previously set as the vport serial number.
            if guest_os_id
                .microsoft()
                .unwrap_or(HvGuestOsMicrosoft::from(0))
                .os_id()
                == HvGuestOsMicrosoftIds::WINDOWS_NT.0
            {
                self.adapter_index
            } else {
                vfid
            }
        } else {
            vfid
        }
    }

    fn handle_oid_query(
        &self,
        buffers: &ChannelBuffers,
        primary: &PrimaryChannelState,
        oid: rndisprot::Oid,
        mut writer: impl MemoryWrite,
    ) -> Result<usize, OidError> {
        tracing::debug!(?oid, "oid query");
        let available_len = writer.len();
        match oid {
            rndisprot::Oid::OID_GEN_SUPPORTED_LIST => {
                let supported_oids_common = &[
                    rndisprot::Oid::OID_GEN_SUPPORTED_LIST,
                    rndisprot::Oid::OID_GEN_HARDWARE_STATUS,
                    rndisprot::Oid::OID_GEN_MEDIA_SUPPORTED,
                    rndisprot::Oid::OID_GEN_MEDIA_IN_USE,
                    rndisprot::Oid::OID_GEN_MAXIMUM_LOOKAHEAD,
                    rndisprot::Oid::OID_GEN_CURRENT_LOOKAHEAD,
                    rndisprot::Oid::OID_GEN_MAXIMUM_FRAME_SIZE,
                    rndisprot::Oid::OID_GEN_MAXIMUM_TOTAL_SIZE,
                    rndisprot::Oid::OID_GEN_TRANSMIT_BLOCK_SIZE,
                    rndisprot::Oid::OID_GEN_RECEIVE_BLOCK_SIZE,
                    rndisprot::Oid::OID_GEN_LINK_SPEED,
                    rndisprot::Oid::OID_GEN_TRANSMIT_BUFFER_SPACE,
                    rndisprot::Oid::OID_GEN_RECEIVE_BUFFER_SPACE,
                    rndisprot::Oid::OID_GEN_VENDOR_ID,
                    rndisprot::Oid::OID_GEN_VENDOR_DESCRIPTION,
                    rndisprot::Oid::OID_GEN_VENDOR_DRIVER_VERSION,
                    rndisprot::Oid::OID_GEN_DRIVER_VERSION,
                    rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER,
                    rndisprot::Oid::OID_GEN_PROTOCOL_OPTIONS,
                    rndisprot::Oid::OID_GEN_MAC_OPTIONS,
                    rndisprot::Oid::OID_GEN_MEDIA_CONNECT_STATUS,
                    rndisprot::Oid::OID_GEN_MAXIMUM_SEND_PACKETS,
                    rndisprot::Oid::OID_GEN_NETWORK_LAYER_ADDRESSES,
                    rndisprot::Oid::OID_GEN_FRIENDLY_NAME,
                    // Ethernet objects operation characteristics
                    rndisprot::Oid::OID_802_3_PERMANENT_ADDRESS,
                    rndisprot::Oid::OID_802_3_CURRENT_ADDRESS,
                    rndisprot::Oid::OID_802_3_MULTICAST_LIST,
                    rndisprot::Oid::OID_802_3_MAXIMUM_LIST_SIZE,
                    // Ethernet objects statistics
                    rndisprot::Oid::OID_802_3_RCV_ERROR_ALIGNMENT,
                    rndisprot::Oid::OID_802_3_XMIT_ONE_COLLISION,
                    rndisprot::Oid::OID_802_3_XMIT_MORE_COLLISIONS,
                    // PNP operations characteristics */
                    // rndisprot::Oid::OID_PNP_SET_POWER,
                    // rndisprot::Oid::OID_PNP_QUERY_POWER,
                    // RNDIS OIDS
                    rndisprot::Oid::OID_GEN_RNDIS_CONFIG_PARAMETER,
                ];

                // NDIS6 OIDs
                let supported_oids_6 = &[
                    // Link State OID
                    rndisprot::Oid::OID_GEN_LINK_PARAMETERS,
                    rndisprot::Oid::OID_GEN_LINK_STATE,
                    rndisprot::Oid::OID_GEN_MAX_LINK_SPEED,
                    // NDIS 6 statistics OID
                    rndisprot::Oid::OID_GEN_BYTES_RCV,
                    rndisprot::Oid::OID_GEN_BYTES_XMIT,
                    // Offload related OID
                    rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS,
                    rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION,
                    rndisprot::Oid::OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES,
                    rndisprot::Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG,
                    // rndisprot::Oid::OID_802_3_ADD_MULTICAST_ADDRESS,
                    // rndisprot::Oid::OID_802_3_DELETE_MULTICAST_ADDRESS,
                ];

                let supported_oids_63 = &[
                    rndisprot::Oid::OID_GEN_RECEIVE_SCALE_CAPABILITIES,
                    rndisprot::Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS,
                ];

                match buffers.ndis_version.major {
                    5 => {
                        writer.write(supported_oids_common.as_bytes())?;
                    }
                    6 => {
                        writer.write(supported_oids_common.as_bytes())?;
                        writer.write(supported_oids_6.as_bytes())?;
                        if buffers.ndis_version.minor >= 30 {
                            writer.write(supported_oids_63.as_bytes())?;
                        }
                    }
                    _ => return Err(OidError::BadVersion),
                }
            }
            rndisprot::Oid::OID_GEN_HARDWARE_STATUS => {
                let status: u32 = 0; // NdisHardwareStatusReady
                writer.write(status.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MEDIA_SUPPORTED | rndisprot::Oid::OID_GEN_MEDIA_IN_USE => {
                writer.write(rndisprot::MEDIUM_802_3.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MAXIMUM_LOOKAHEAD
            | rndisprot::Oid::OID_GEN_CURRENT_LOOKAHEAD
            | rndisprot::Oid::OID_GEN_MAXIMUM_FRAME_SIZE => {
                let len: u32 = buffers.ndis_config.mtu - ETHERNET_HEADER_LEN;
                writer.write(len.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MAXIMUM_TOTAL_SIZE
            | rndisprot::Oid::OID_GEN_TRANSMIT_BLOCK_SIZE
            | rndisprot::Oid::OID_GEN_RECEIVE_BLOCK_SIZE => {
                let len: u32 = buffers.ndis_config.mtu;
                writer.write(len.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_LINK_SPEED => {
                let speed: u32 = (self.link_speed / 100) as u32; // In 100bps units
                writer.write(speed.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_TRANSMIT_BUFFER_SPACE
            | rndisprot::Oid::OID_GEN_RECEIVE_BUFFER_SPACE => {
                // This value is meaningless for virtual NICs. Return what vmswitch returns.
                writer.write((256u32 * 1024).as_bytes())?
            }
            rndisprot::Oid::OID_GEN_VENDOR_ID => {
                // Like vmswitch, use the first N bytes of Microsoft's MAC address
                // prefix as the vendor ID.
                writer.write(0x0000155du32.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_VENDOR_DESCRIPTION => writer.write(b"Microsoft Corporation")?,
            rndisprot::Oid::OID_GEN_VENDOR_DRIVER_VERSION
            | rndisprot::Oid::OID_GEN_DRIVER_VERSION => {
                writer.write(0x0100u16.as_bytes())? // 1.0. Vmswitch reports 19.0 for Mn.
            }
            rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER => writer.write(0u32.as_bytes())?,
            rndisprot::Oid::OID_GEN_MAC_OPTIONS => {
                let options: u32 = rndisprot::MAC_OPTION_COPY_LOOKAHEAD_DATA
                    | rndisprot::MAC_OPTION_TRANSFERS_NOT_PEND
                    | rndisprot::MAC_OPTION_NO_LOOPBACK;
                writer.write(options.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MEDIA_CONNECT_STATUS => {
                writer.write(rndisprot::MEDIA_STATE_CONNECTED.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MAXIMUM_SEND_PACKETS => writer.write(u32::MAX.as_bytes())?,
            rndisprot::Oid::OID_GEN_FRIENDLY_NAME => {
                let name16: Vec<u16> = "Network Device".encode_utf16().collect();
                let mut name = rndisprot::FriendlyName::new_zeroed();
                name.name[..name16.len()].copy_from_slice(&name16);
                writer.write(name.as_bytes())?
            }
            rndisprot::Oid::OID_802_3_PERMANENT_ADDRESS
            | rndisprot::Oid::OID_802_3_CURRENT_ADDRESS => {
                writer.write(&self.mac_address.to_bytes())?
            }
            rndisprot::Oid::OID_802_3_MAXIMUM_LIST_SIZE => {
                writer.write(0u32.as_bytes())?;
            }
            rndisprot::Oid::OID_802_3_RCV_ERROR_ALIGNMENT
            | rndisprot::Oid::OID_802_3_XMIT_ONE_COLLISION
            | rndisprot::Oid::OID_802_3_XMIT_MORE_COLLISIONS => writer.write(0u32.as_bytes())?,

            // NDIS6 OIDs:
            rndisprot::Oid::OID_GEN_LINK_STATE => {
                let link_state = rndisprot::LinkState {
                    header: rndisprot::NdisObjectHeader {
                        object_type: rndisprot::NdisObjectType::DEFAULT,
                        revision: 1,
                        size: size_of::<rndisprot::LinkState>() as u16,
                    },
                    media_connect_state: 1, /* MediaConnectStateConnected */
                    media_duplex_state: 0,  /* MediaDuplexStateUnknown */
                    padding: 0,
                    xmit_link_speed: self.link_speed,
                    rcv_link_speed: self.link_speed,
                    pause_functions: 0, /* NdisPauseFunctionsUnsupported */
                    auto_negotiation_flags: 0,
                };
                writer.write(link_state.as_bytes())?;
            }
            rndisprot::Oid::OID_GEN_MAX_LINK_SPEED => {
                let link_speed = rndisprot::LinkSpeed {
                    xmit: self.link_speed,
                    rcv: self.link_speed,
                };
                writer.write(link_speed.as_bytes())?;
            }
            rndisprot::Oid::OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES => {
                let ndis_offload = self.offload_support.ndis_offload();
                writer.write(&ndis_offload.as_bytes()[..ndis_offload.header.size.into()])?;
            }
            rndisprot::Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG => {
                let ndis_offload = primary.offload_config.ndis_offload();
                writer.write(&ndis_offload.as_bytes()[..ndis_offload.header.size.into()])?;
            }
            rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION => {
                writer.write(
                    &rndisprot::NdisOffloadEncapsulation {
                        header: rndisprot::NdisObjectHeader {
                            object_type: rndisprot::NdisObjectType::OFFLOAD_ENCAPSULATION,
                            revision: 1,
                            size: rndisprot::NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1 as u16,
                        },
                        ipv4_enabled: rndisprot::NDIS_OFFLOAD_SUPPORTED,
                        ipv4_encapsulation_type: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                        ipv4_header_size: ETHERNET_HEADER_LEN,
                        ipv6_enabled: rndisprot::NDIS_OFFLOAD_SUPPORTED,
                        ipv6_encapsulation_type: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
                        ipv6_header_size: ETHERNET_HEADER_LEN,
                    }
                    .as_bytes()[..rndisprot::NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1],
                )?;
            }
            rndisprot::Oid::OID_GEN_RECEIVE_SCALE_CAPABILITIES => {
                writer.write(
                    &rndisprot::NdisReceiveScaleCapabilities {
                        header: rndisprot::NdisObjectHeader {
                            object_type: rndisprot::NdisObjectType::RSS_CAPABILITIES,
                            revision: 2,
                            size: rndisprot::NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_2
                                as u16,
                        },
                        capabilities_flags: rndisprot::NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4
                            | rndisprot::NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6
                            | rndisprot::NDIS_HASH_FUNCTION_TOEPLITZ,
                        number_of_interrupt_messages: 1,
                        number_of_receive_queues: self.max_queues.into(),
                        number_of_indirection_table_entries: if self.indirection_table_size != 0 {
                            self.indirection_table_size
                        } else {
                            // DPDK gets confused if the table size is zero,
                            // even if there is only one queue.
                            128
                        },
                        padding: 0,
                    }
                    .as_bytes()[..rndisprot::NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_2],
                )?;
            }
            _ => {
                tracelimit::warn_ratelimited!(?oid, "query for unknown OID");
                return Err(OidError::UnknownOid);
            }
        };
        Ok(available_len - writer.len())
    }

    fn handle_oid_set(
        &self,
        primary: &mut PrimaryChannelState,
        oid: rndisprot::Oid,
        reader: impl MemoryRead + Clone,
    ) -> Result<bool, OidError> {
        tracing::debug!(?oid, "oid set");

        let mut restart_endpoint = false;
        match oid {
            rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER => {
                // TODO
            }
            rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS => {
                self.oid_set_offload_parameters(reader, primary)?;
            }
            rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION => {
                self.oid_set_offload_encapsulation(reader)?;
            }
            rndisprot::Oid::OID_GEN_RNDIS_CONFIG_PARAMETER => {
                self.oid_set_rndis_config_parameter(reader, primary)?;
            }
            rndisprot::Oid::OID_GEN_NETWORK_LAYER_ADDRESSES => {
                // TODO
            }
            rndisprot::Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS => {
                self.oid_set_rss_parameters(reader, primary)?;

                // Endpoints cannot currently change RSS parameters without
                // being restarted. This was a limitation driven by some DPDK
                // PMDs, and should be fixed.
                restart_endpoint = true;
            }
            _ => {
                tracelimit::warn_ratelimited!(?oid, "set of unknown OID");
                return Err(OidError::UnknownOid);
            }
        }
        Ok(restart_endpoint)
    }

    fn oid_set_rss_parameters(
        &self,
        mut reader: impl MemoryRead + Clone,
        primary: &mut PrimaryChannelState,
    ) -> Result<(), OidError> {
        // Vmswitch doesn't validate the NDIS header on this object, so read it manually.
        let mut params = rndisprot::NdisReceiveScaleParameters::new_zeroed();
        let len = reader.len().min(size_of_val(&params));
        reader.clone().read(&mut params.as_mut_bytes()[..len])?;

        if ((params.flags & NDIS_RSS_PARAM_FLAG_DISABLE_RSS) != 0)
            || ((params.hash_information & NDIS_HASH_FUNCTION_MASK) == 0)
        {
            primary.rss_state = None;
            return Ok(());
        }

        if params.hash_secret_key_size != 40 {
            return Err(OidError::InvalidInput("hash_secret_key_size"));
        }
        if params.indirection_table_size % 4 != 0 {
            return Err(OidError::InvalidInput("indirection_table_size"));
        }
        let indirection_table_size =
            (params.indirection_table_size / 4).min(self.indirection_table_size) as usize;
        let mut key = [0; 40];
        let mut indirection_table = vec![0u32; self.indirection_table_size as usize];
        reader
            .clone()
            .skip(params.hash_secret_key_offset as usize)?
            .read(&mut key)?;
        reader
            .skip(params.indirection_table_offset as usize)?
            .read(indirection_table[..indirection_table_size].as_mut_bytes())?;
        if indirection_table
            .iter()
            .any(|&x| x >= self.max_queues as u32)
        {
            return Err(OidError::InvalidInput("indirection_table"));
        }
        let (indir_init, indir_uninit) = indirection_table.split_at_mut(indirection_table_size);
        for (src, dest) in std::iter::repeat_with(|| indir_init.iter().copied())
            .flatten()
            .zip(indir_uninit)
        {
            *dest = src;
        }
        primary.rss_state = Some(RssState {
            key,
            indirection_table: indirection_table.iter().map(|&x| x as u16).collect(),
        });
        Ok(())
    }

    fn oid_set_offload_parameters(
        &self,
        reader: impl MemoryRead + Clone,
        primary: &mut PrimaryChannelState,
    ) -> Result<(), OidError> {
        let offload: rndisprot::NdisOffloadParameters = read_ndis_object(
            reader,
            rndisprot::NdisObjectType::DEFAULT,
            1,
            rndisprot::NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1,
        )?;

        tracing::debug!(?offload, "offload parameters");
        let rndisprot::NdisOffloadParameters {
            header: _,
            ipv4_checksum,
            tcp4_checksum,
            udp4_checksum,
            tcp6_checksum,
            udp6_checksum,
            lsov1,
            ipsec_v1: _,
            lsov2_ipv4,
            lsov2_ipv6,
            tcp_connection_ipv4: _,
            tcp_connection_ipv6: _,
            reserved: _,
            flags: _,
        } = offload;

        if lsov1 == rndisprot::OffloadParametersSimple::ENABLED {
            return Err(OidError::NotSupported("lsov1"));
        }
        if let Some((tx, rx)) = ipv4_checksum.tx_rx() {
            primary.offload_config.checksum_tx.ipv4_header = tx;
            primary.offload_config.checksum_rx.ipv4_header = rx;
        }
        if let Some((tx, rx)) = tcp4_checksum.tx_rx() {
            primary.offload_config.checksum_tx.tcp4 = tx;
            primary.offload_config.checksum_rx.tcp4 = rx;
        }
        if let Some((tx, rx)) = tcp6_checksum.tx_rx() {
            primary.offload_config.checksum_tx.tcp6 = tx;
            primary.offload_config.checksum_rx.tcp6 = rx;
        }
        if let Some((tx, rx)) = udp4_checksum.tx_rx() {
            primary.offload_config.checksum_tx.udp4 = tx;
            primary.offload_config.checksum_rx.udp4 = rx;
        }
        if let Some((tx, rx)) = udp6_checksum.tx_rx() {
            primary.offload_config.checksum_tx.udp6 = tx;
            primary.offload_config.checksum_rx.udp6 = rx;
        }
        if let Some(enable) = lsov2_ipv4.enable() {
            primary.offload_config.lso4 = enable && self.offload_support.lso4;
        }
        if let Some(enable) = lsov2_ipv6.enable() {
            primary.offload_config.lso6 = enable && self.offload_support.lso6;
        }
        primary.pending_offload_change = true;
        Ok(())
    }

    fn oid_set_offload_encapsulation(
        &self,
        reader: impl MemoryRead + Clone,
    ) -> Result<(), OidError> {
        let encap: rndisprot::NdisOffloadEncapsulation = read_ndis_object(
            reader,
            rndisprot::NdisObjectType::OFFLOAD_ENCAPSULATION,
            1,
            rndisprot::NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1,
        )?;
        if encap.ipv4_enabled == rndisprot::NDIS_OFFLOAD_SET_ON
            && (encap.ipv4_encapsulation_type != rndisprot::NDIS_ENCAPSULATION_IEEE_802_3
                || encap.ipv4_header_size != ETHERNET_HEADER_LEN)
        {
            return Err(OidError::NotSupported("ipv4 encap"));
        }
        if encap.ipv6_enabled == rndisprot::NDIS_OFFLOAD_SET_ON
            && (encap.ipv6_encapsulation_type != rndisprot::NDIS_ENCAPSULATION_IEEE_802_3
                || encap.ipv6_header_size != ETHERNET_HEADER_LEN)
        {
            return Err(OidError::NotSupported("ipv6 encap"));
        }
        Ok(())
    }

    fn oid_set_rndis_config_parameter(
        &self,
        reader: impl MemoryRead + Clone,
        primary: &mut PrimaryChannelState,
    ) -> Result<(), OidError> {
        let info: rndisprot::RndisConfigParameterInfo = reader.clone().read_plain()?;
        if info.name_length > 255 {
            return Err(OidError::InvalidInput("name_length"));
        }
        if info.value_length > 255 {
            return Err(OidError::InvalidInput("value_length"));
        }
        let name = reader
            .clone()
            .skip(info.name_offset as usize)?
            .read_n::<u16>(info.name_length as usize / 2)?;
        let name = String::from_utf16(&name).map_err(|_| OidError::InvalidInput("name"))?;
        let mut value = reader;
        value.skip(info.value_offset as usize)?;
        let mut value = value.limit(info.value_length as usize);
        match info.parameter_type {
            rndisprot::NdisParameterType::STRING => {
                let value = value.read_n::<u16>(info.value_length as usize / 2)?;
                let value =
                    String::from_utf16(&value).map_err(|_| OidError::InvalidInput("value"))?;
                let as_num = value.as_bytes().first().map_or(0, |c| c - b'0');
                let tx = as_num & 1 != 0;
                let rx = as_num & 2 != 0;

                tracing::debug!(name, value, "rndis config");
                match name.as_str() {
                    "*IPChecksumOffloadIPv4" => {
                        primary.offload_config.checksum_tx.ipv4_header = tx;
                        primary.offload_config.checksum_rx.ipv4_header = rx;
                    }
                    "*LsoV2IPv4" => {
                        primary.offload_config.lso4 = as_num != 0 && self.offload_support.lso4;
                    }
                    "*LsoV2IPv6" => {
                        primary.offload_config.lso6 = as_num != 0 && self.offload_support.lso6;
                    }
                    "*TCPChecksumOffloadIPv4" => {
                        primary.offload_config.checksum_tx.tcp4 = tx;
                        primary.offload_config.checksum_rx.tcp4 = rx;
                    }
                    "*TCPChecksumOffloadIPv6" => {
                        primary.offload_config.checksum_tx.tcp6 = tx;
                        primary.offload_config.checksum_rx.tcp6 = rx;
                    }
                    "*UDPChecksumOffloadIPv4" => {
                        primary.offload_config.checksum_tx.udp4 = tx;
                        primary.offload_config.checksum_rx.udp4 = rx;
                    }
                    "*UDPChecksumOffloadIPv6" => {
                        primary.offload_config.checksum_tx.udp6 = tx;
                        primary.offload_config.checksum_rx.udp6 = rx;
                    }
                    _ => {}
                }
            }
            rndisprot::NdisParameterType::INTEGER => {
                let value: u32 = value.read_plain()?;
                tracing::debug!(name, value, "rndis config");
            }
            parameter_type => tracelimit::warn_ratelimited!(
                name,
                ?parameter_type,
                "unhandled rndis config parameter type"
            ),
        }
        Ok(())
    }
}

fn read_ndis_object<T: IntoBytes + FromBytes + Debug + Immutable + KnownLayout>(
    mut reader: impl MemoryRead,
    object_type: rndisprot::NdisObjectType,
    min_revision: u8,
    min_size: usize,
) -> Result<T, OidError> {
    let mut buffer = T::new_zeroed();
    let sent_size = reader.len();
    let len = sent_size.min(size_of_val(&buffer));
    reader.read(&mut buffer.as_mut_bytes()[..len])?;
    validate_ndis_object_header(
        &rndisprot::NdisObjectHeader::read_from_prefix(buffer.as_bytes())
            .unwrap()
            .0, // TODO: zerocopy: use-rest-of-range (https://github.com/microsoft/openvmm/issues/759)
        sent_size,
        object_type,
        min_revision,
        min_size,
    )?;
    Ok(buffer)
}

fn validate_ndis_object_header(
    header: &rndisprot::NdisObjectHeader,
    sent_size: usize,
    object_type: rndisprot::NdisObjectType,
    min_revision: u8,
    min_size: usize,
) -> Result<(), OidError> {
    if header.object_type != object_type {
        return Err(OidError::InvalidInput("header.object_type"));
    }
    if sent_size < header.size as usize {
        return Err(OidError::InvalidInput("header.size"));
    }
    if header.revision < min_revision {
        return Err(OidError::InvalidInput("header.revision"));
    }
    if (header.size as usize) < min_size {
        return Err(OidError::InvalidInput("header.size"));
    }
    Ok(())
}

struct Coordinator {
    recv: mpsc::Receiver<CoordinatorMessage>,
    channel_control: ChannelControl,
    restart: bool,
    workers: Vec<TaskControl<NetQueue, Worker<GpadlRingMem>>>,
    buffers: Option<Arc<ChannelBuffers>>,
    num_queues: u16,
}

/// Removing the VF may result in the guest sending messages to switch the data
/// path, so these operations need to happen asynchronously with message
/// processing.
enum CoordinatorStatePendingVfState {
    /// No pending updates.
    Ready,
    /// Delay before adding VF.
    Delay {
        timer: PolledTimer,
        delay_until: Instant,
    },
    /// A VF update is pending.
    Pending,
}

struct CoordinatorState {
    endpoint: Box<dyn Endpoint>,
    adapter: Arc<Adapter>,
    virtual_function: Option<Box<dyn VirtualFunction>>,
    pending_vf_state: CoordinatorStatePendingVfState,
}

impl InspectTaskMut<Coordinator> for CoordinatorState {
    fn inspect_mut(
        &mut self,
        req: inspect::Request<'_>,
        mut coordinator: Option<&mut Coordinator>,
    ) {
        let mut resp = req.respond();

        let adapter = self.adapter.as_ref();
        resp.field("mac_address", adapter.mac_address)
            .field("max_queues", adapter.max_queues)
            .sensitivity_field(
                "offload_support",
                SensitivityLevel::Safe,
                &adapter.offload_support,
            )
            .field_mut_with("ring_size_limit", |v| -> anyhow::Result<_> {
                if let Some(v) = v {
                    let v: usize = v.parse()?;
                    adapter.ring_size_limit.store(v, Ordering::Relaxed);
                    // Bounce each task so that it sees the new value.
                    if let Some(this) = &mut coordinator {
                        for worker in &mut this.workers {
                            worker.update_with(|_, _| ());
                        }
                    }
                }
                Ok(adapter.ring_size_limit.load(Ordering::Relaxed))
            });

        resp.field("endpoint_type", self.endpoint.endpoint_type())
            .field(
                "endpoint_max_queues",
                self.endpoint.multiqueue_support().max_queues,
            )
            .sensitivity_field_mut("endpoint", SensitivityLevel::Safe, self.endpoint.as_mut());

        if let Some(coordinator) = coordinator {
            resp.sensitivity_child("queues", SensitivityLevel::Safe, |req| {
                let mut resp = req.respond();
                for (i, q) in coordinator.workers[..coordinator.num_queues as usize]
                    .iter_mut()
                    .enumerate()
                {
                    resp.field_mut(&i.to_string(), q);
                }
            });

            // Get the shared channel state from the primary channel.
            {
                let deferred = resp.request().defer();
                coordinator.workers[0].update_with(|_, worker| {
                    if let Some(state) = worker.and_then(|worker| worker.state.ready()) {
                        deferred.respond(|resp| {
                            resp.merge(&state.buffers);
                            resp.sensitivity_field(
                                "primary_channel_state",
                                SensitivityLevel::Safe,
                                &state.state.primary,
                            );
                        });
                    }
                })
            }
        }
    }
}

impl AsyncRun<Coordinator> for CoordinatorState {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        coordinator: &mut Coordinator,
    ) -> Result<(), task_control::Cancelled> {
        coordinator.process(stop, self).await
    }
}

impl Coordinator {
    async fn process(
        &mut self,
        stop: &mut StopTask<'_>,
        state: &mut CoordinatorState,
    ) -> Result<(), task_control::Cancelled> {
        let mut sleep_duration: Option<Instant> = None;
        loop {
            if self.restart {
                stop.until_stopped(self.stop_workers()).await?;
                // The queue restart operation is not restartable, so do not
                // poll on `stop` here.
                if let Err(err) = self.restart_queues(state).await {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "failed to restart queues"
                    );
                }
                if let Some(primary) = self.primary_mut() {
                    primary.is_data_path_switched =
                        state.endpoint.get_data_path_to_guest_vf().await.ok();
                    tracing::info!(
                        is_data_path_switched = primary.is_data_path_switched,
                        "Query data path state"
                    );
                }
                self.restore_guest_vf_state(state).await;
                self.restart = false;
            }
            enum Message {
                Internal(CoordinatorMessage),
                ChannelDisconnected,
                UpdateFromEndpoint(EndpointAction),
                UpdateFromVf(Rpc<(), ()>),
                OfferVfDevice,
                PendingVfStateComplete,
                TimerExpired,
            }
            self.start_workers();
            let timer_sleep = async {
                if let Some(sleep_duration) = sleep_duration {
                    let mut timer = PolledTimer::new(&state.adapter.driver);
                    timer.sleep_until(sleep_duration).await;
                } else {
                    pending::<()>().await;
                }
                Message::TimerExpired
            };
            let message = {
                let wait_for_message = async {
                    let internal_msg = self
                        .recv
                        .next()
                        .map(|x| x.map_or(Message::ChannelDisconnected, Message::Internal));
                    let endpoint_restart = state
                        .endpoint
                        .wait_for_endpoint_action()
                        .map(Message::UpdateFromEndpoint);
                    if let Some(vf) = state.virtual_function.as_mut() {
                        match state.pending_vf_state {
                            CoordinatorStatePendingVfState::Ready
                            | CoordinatorStatePendingVfState::Delay { .. } => {
                                let offer_device = async {
                                    if let CoordinatorStatePendingVfState::Delay {
                                        timer,
                                        delay_until,
                                    } = &mut state.pending_vf_state
                                    {
                                        timer.sleep_until(*delay_until).await;
                                    } else {
                                        pending::<()>().await;
                                    }
                                    Message::OfferVfDevice
                                };
                                (
                                    internal_msg,
                                    offer_device,
                                    endpoint_restart,
                                    vf.wait_for_state_change().map(Message::UpdateFromVf),
                                    timer_sleep,
                                )
                                    .race()
                                    .await
                            }
                            CoordinatorStatePendingVfState::Pending => {
                                // Allow the network workers to continue while
                                // waiting for the Vf add/remove call to
                                // complete, but block any other notifications
                                // while it is running. This is necessary to
                                // support Vf removal, which may trigger the
                                // guest to send a switch data path request and
                                // wait for a completion message as part of
                                // its eject handling. The switch data path
                                // request won't send a message here because
                                // the Vf is not available -- it will be a
                                // no-op.
                                vf.guest_ready_for_device().await;
                                Message::PendingVfStateComplete
                            }
                        }
                    } else {
                        (internal_msg, endpoint_restart, timer_sleep).race().await
                    }
                };
                stop.until_stopped(wait_for_message).await?
            };
            match message {
                Message::UpdateFromVf(rpc) => {
                    rpc.handle(|_| async {
                        self.update_guest_vf_state(state).await;
                    })
                    .await;
                }
                Message::OfferVfDevice => {
                    let stopped = if self.workers[0].is_running() {
                        self.workers[0].stop().await;
                        true
                    } else {
                        false
                    };
                    if let Some(primary) = self.primary_mut() {
                        if matches!(
                            primary.guest_vf_state,
                            PrimaryChannelGuestVfState::AvailableAdvertised
                        ) {
                            primary.guest_vf_state = PrimaryChannelGuestVfState::Ready;
                        }
                    }
                    if stopped {
                        self.workers[0].start();
                    }

                    state.pending_vf_state = CoordinatorStatePendingVfState::Pending;
                }
                Message::PendingVfStateComplete => {
                    state.pending_vf_state = CoordinatorStatePendingVfState::Ready;
                }
                Message::TimerExpired => {
                    // Kick the worker as requested.
                    if self.workers[0].is_running() {
                        self.workers[0].stop().await;
                        if let Some(primary) = self.primary_mut() {
                            if let PendingLinkAction::Delay(up) = primary.pending_link_action {
                                primary.pending_link_action = PendingLinkAction::Active(up);
                            }
                        }
                        self.workers[0].start();
                    }
                    sleep_duration = None;
                }
                Message::Internal(CoordinatorMessage::UpdateGuestVfState) => {
                    self.update_guest_vf_state(state).await;
                }
                Message::UpdateFromEndpoint(EndpointAction::RestartRequired) => self.restart = true,
                Message::UpdateFromEndpoint(EndpointAction::LinkStatusNotify(connect)) => {
                    let stopped = if self.workers[0].is_running() {
                        self.workers[0].stop().await;
                        true
                    } else {
                        false
                    };

                    // These are the only link state transitions that are tracked.
                    // 1. up -> down or down -> up
                    // 2. up -> down -> up or down -> up -> down.
                    // All other state transitions are coalesced into one of the above cases.
                    // For example, up -> down -> up -> down is treated as up -> down.
                    // N.B - Always queue up the incoming state to minimize the effects of loss
                    //       of any notifications (for example, during vtl2 servicing).
                    if let Some(primary) = self.primary_mut() {
                        primary.pending_link_action = PendingLinkAction::Active(connect);
                    }

                    // If there is any existing sleep timer running, cancel it out.
                    sleep_duration = None;
                    if stopped {
                        self.workers[0].start();
                    }
                }
                Message::Internal(CoordinatorMessage::Restart) => self.restart = true,
                Message::Internal(CoordinatorMessage::StartTimer(duration)) => {
                    sleep_duration = Some(duration);
                    // Restart primary task.
                    if self.workers[0].is_running() {
                        self.workers[0].stop().await;
                        self.workers[0].start();
                    }
                }
                Message::ChannelDisconnected => {
                    break;
                }
            };
        }
        Ok(())
    }

    async fn stop_workers(&mut self) {
        for worker in &mut self.workers {
            worker.stop().await;
        }
    }

    async fn restore_guest_vf_state(&mut self, c_state: &mut CoordinatorState) {
        let primary = match self.primary_mut() {
            Some(primary) => primary,
            None => return,
        };

        // Update guest VF state based on current endpoint properties.
        let virtual_function = c_state.virtual_function.as_mut();
        let guest_vf_id = match &virtual_function {
            Some(vf) => vf.id().await,
            None => None,
        };
        if let Some(guest_vf_id) = guest_vf_id {
            // Ensure guest VF is in proper state.
            match primary.guest_vf_state {
                PrimaryChannelGuestVfState::AvailableAdvertised
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::AvailableAdvertised,
                ) => {
                    if !primary.is_data_path_switched.unwrap_or(false) {
                        let timer = PolledTimer::new(&c_state.adapter.driver);
                        c_state.pending_vf_state = CoordinatorStatePendingVfState::Delay {
                            timer,
                            delay_until: Instant::now() + VF_DEVICE_DELAY,
                        };
                    }
                }
                PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                | PrimaryChannelGuestVfState::Ready
                | PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::Ready)
                | PrimaryChannelGuestVfState::DataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitchPending { .. },
                )
                | PrimaryChannelGuestVfState::DataPathSwitched
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitched,
                )
                | PrimaryChannelGuestVfState::DataPathSynthetic => {
                    c_state.pending_vf_state = CoordinatorStatePendingVfState::Pending;
                }
                _ => (),
            };
            // ensure data path is switched as expected
            if let PrimaryChannelGuestVfState::Restoring(
                saved_state::GuestVfState::DataPathSwitchPending {
                    to_guest,
                    id,
                    result,
                },
            ) = primary.guest_vf_state
            {
                // If the save was after the data path switch already occurred, don't do it again.
                if result.is_some() {
                    primary.guest_vf_state = PrimaryChannelGuestVfState::DataPathSwitchPending {
                        to_guest,
                        id,
                        result,
                    };
                    return;
                }
            }
            primary.guest_vf_state = match primary.guest_vf_state {
                PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                | PrimaryChannelGuestVfState::DataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitchPending { .. },
                )
                | PrimaryChannelGuestVfState::DataPathSynthetic => {
                    let (to_guest, id) = match primary.guest_vf_state {
                        PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending {
                            to_guest,
                            id,
                        }
                        | PrimaryChannelGuestVfState::DataPathSwitchPending {
                            to_guest, id, ..
                        }
                        | PrimaryChannelGuestVfState::Restoring(
                            saved_state::GuestVfState::DataPathSwitchPending {
                                to_guest, id, ..
                            },
                        ) => (to_guest, id),
                        _ => (true, None),
                    };
                    // Cancel any outstanding delay timers for VF offers if the data path is
                    // getting switched. Those timers are essentially no-op at this point.
                    if matches!(
                        c_state.pending_vf_state,
                        CoordinatorStatePendingVfState::Delay { .. }
                    ) {
                        c_state.pending_vf_state = CoordinatorStatePendingVfState::Ready;
                    }
                    let result = c_state.endpoint.set_data_path_to_guest_vf(to_guest).await;
                    let result = if let Err(err) = result {
                        tracing::error!(err = %err, to_guest, "Failed to switch guest VF data path");
                        false
                    } else {
                        primary.is_data_path_switched = Some(to_guest);
                        true
                    };
                    match primary.guest_vf_state {
                        PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending {
                            ..
                        }
                        | PrimaryChannelGuestVfState::DataPathSwitchPending { .. }
                        | PrimaryChannelGuestVfState::Restoring(
                            saved_state::GuestVfState::DataPathSwitchPending { .. },
                        ) => PrimaryChannelGuestVfState::DataPathSwitchPending {
                            to_guest,
                            id,
                            result: Some(result),
                        },
                        _ if result => PrimaryChannelGuestVfState::DataPathSwitched,
                        _ => PrimaryChannelGuestVfState::DataPathSynthetic,
                    }
                }
                PrimaryChannelGuestVfState::Initializing
                | PrimaryChannelGuestVfState::Unavailable
                | PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::NoState) => {
                    PrimaryChannelGuestVfState::Available { vfid: guest_vf_id }
                }
                PrimaryChannelGuestVfState::AvailableAdvertised
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::AvailableAdvertised,
                ) => {
                    if !primary.is_data_path_switched.unwrap_or(false) {
                        PrimaryChannelGuestVfState::AvailableAdvertised
                    } else {
                        // A previous instantiation already switched the data
                        // path.
                        PrimaryChannelGuestVfState::DataPathSwitched
                    }
                }
                PrimaryChannelGuestVfState::DataPathSwitched
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitched,
                ) => PrimaryChannelGuestVfState::DataPathSwitched,
                PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::Ready) => {
                    PrimaryChannelGuestVfState::Ready
                }
                _ => primary.guest_vf_state,
            };
        } else {
            // If the device was just removed, make sure the the data path is synthetic.
            match primary.guest_vf_state {
                PrimaryChannelGuestVfState::DataPathSwitchPending { to_guest, .. }
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitchPending { to_guest, .. },
                ) => {
                    if !to_guest {
                        if let Err(err) = c_state.endpoint.set_data_path_to_guest_vf(false).await {
                            tracing::warn!(err = %err, "Failed setting data path back to synthetic after guest VF was removed.");
                        }
                        primary.is_data_path_switched = Some(false);
                    }
                }
                PrimaryChannelGuestVfState::DataPathSwitched
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitched,
                ) => {
                    if let Err(err) = c_state.endpoint.set_data_path_to_guest_vf(false).await {
                        tracing::warn!(err = %err, "Failed setting data path back to synthetic after guest VF was removed.");
                    }
                    primary.is_data_path_switched = Some(false);
                }
                _ => (),
            }
            if let PrimaryChannelGuestVfState::AvailableAdvertised = primary.guest_vf_state {
                c_state.pending_vf_state = CoordinatorStatePendingVfState::Ready;
            }
            // Notify guest if VF is no longer available
            primary.guest_vf_state = match primary.guest_vf_state {
                PrimaryChannelGuestVfState::Initializing
                | PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::NoState)
                | PrimaryChannelGuestVfState::Available { .. } => {
                    PrimaryChannelGuestVfState::Unavailable
                }
                PrimaryChannelGuestVfState::AvailableAdvertised
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::AvailableAdvertised,
                )
                | PrimaryChannelGuestVfState::Ready
                | PrimaryChannelGuestVfState::Restoring(saved_state::GuestVfState::Ready) => {
                    PrimaryChannelGuestVfState::UnavailableFromAvailable
                }
                PrimaryChannelGuestVfState::DataPathSwitchPending { to_guest, id, .. }
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitchPending { to_guest, id, .. },
                ) => PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending {
                    to_guest,
                    id,
                },
                PrimaryChannelGuestVfState::DataPathSwitched
                | PrimaryChannelGuestVfState::Restoring(
                    saved_state::GuestVfState::DataPathSwitched,
                )
                | PrimaryChannelGuestVfState::DataPathSynthetic => {
                    PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                }
                _ => primary.guest_vf_state,
            }
        }
    }

    async fn restart_queues(&mut self, c_state: &mut CoordinatorState) -> Result<(), WorkerError> {
        // Drop all the queues and stop the endpoint. Collect the worker drivers to pass to the queues.
        let drivers = self
            .workers
            .iter_mut()
            .map(|worker| {
                let task = worker.task_mut();
                task.queue_state = None;
                task.driver.clone()
            })
            .collect::<Vec<_>>();

        c_state.endpoint.stop().await;

        let (primary_worker, subworkers) = if let [primary, sub @ ..] = self.workers.as_mut_slice()
        {
            (primary, sub)
        } else {
            unreachable!()
        };

        let state = primary_worker
            .state_mut()
            .and_then(|worker| worker.state.ready_mut());

        let state = if let Some(state) = state {
            state
        } else {
            return Ok(());
        };

        // Save the channel buffers for use in the subchannel workers.
        self.buffers = Some(state.buffers.clone());

        let num_queues = state.state.primary.as_ref().unwrap().requested_num_queues;
        let mut active_queues = Vec::new();
        let active_queue_count =
            if let Some(rss_state) = state.state.primary.as_ref().unwrap().rss_state.as_ref() {
                // Active queue count is computed as the number of unique entries in the indirection table
                active_queues.clone_from(&rss_state.indirection_table);
                active_queues.sort();
                active_queues.dedup();
                active_queues = active_queues
                    .into_iter()
                    .filter(|&index| index < num_queues)
                    .collect::<Vec<_>>();
                active_queues.len() as u16
            } else {
                num_queues
            };

        // Distribute the rx buffers to only the active queues.
        let (ranges, mut remote_buffer_id_recvs) =
            RxBufferRanges::new(state.buffers.recv_buffer.count, active_queue_count.into());
        let ranges = Arc::new(ranges);

        let mut queues = Vec::new();
        let mut rx_buffers = Vec::new();
        {
            let buffers = &state.buffers;
            let guest_buffers = Arc::new(
                GuestBuffers::new(
                    buffers.mem.clone(),
                    buffers.recv_buffer.gpadl.clone(),
                    buffers.recv_buffer.sub_allocation_size,
                    buffers.ndis_config.mtu,
                )
                .map_err(WorkerError::GpadlError)?,
            );

            // Get the list of free rx buffers from each task, then partition
            // the list per-active-queue, and produce the queue configuration.
            let mut queue_config = Vec::new();
            let initial_rx;
            {
                let states = std::iter::once(Some(&*state)).chain(
                    subworkers
                        .iter()
                        .map(|worker| worker.state().and_then(|worker| worker.state.ready())),
                );

                initial_rx = (RX_RESERVED_CONTROL_BUFFERS..state.buffers.recv_buffer.count)
                    .filter(|&n| {
                        states
                            .clone()
                            .flatten()
                            .all(|s| (s.state.rx_bufs.is_free(n)))
                    })
                    .map(RxId)
                    .collect::<Vec<_>>();

                let mut initial_rx = initial_rx.as_slice();
                let mut range_start = 0;
                let mut active_count = 0;
                for queue_index in 0..num_queues {
                    let queue_active =
                        active_queues.is_empty() || active_queues.contains(&queue_index);
                    let (range_end, end, buffer_id_recv) = if queue_active {
                        active_count += 1;
                        let range_end =
                            RX_RESERVED_CONTROL_BUFFERS + active_count * ranges.buffers_per_queue;
                        (
                            range_end,
                            initial_rx.partition_point(|id| id.0 < range_end),
                            Some(remote_buffer_id_recvs.remove(0)),
                        )
                    } else {
                        (range_start, 0, None)
                    };

                    let (this, rest) = initial_rx.split_at(end);
                    queue_config.push(QueueConfig {
                        pool: Box::new(BufferPool::new(guest_buffers.clone())),
                        initial_rx: this,
                        driver: Box::new(drivers[queue_index as usize].clone()),
                    });
                    initial_rx = rest;
                    rx_buffers.push(RxBufferRange::new(
                        ranges.clone(),
                        range_start..range_end,
                        buffer_id_recv,
                    ));

                    range_start = range_end;
                }
            }

            let primary = state.state.primary.as_mut().unwrap();
            tracing::debug!(num_queues, "enabling endpoint");

            let rss = primary
                .rss_state
                .as_ref()
                .map(|rss| net_backend::RssConfig {
                    key: &rss.key,
                    indirection_table: &rss.indirection_table,
                    flags: 0,
                });

            c_state
                .endpoint
                .get_queues(queue_config, rss.as_ref(), &mut queues)
                .await
                .map_err(WorkerError::Endpoint)?;

            assert_eq!(queues.len(), num_queues as usize);

            // Set the subchannel count.
            self.channel_control
                .enable_subchannels(num_queues - 1)
                .expect("already validated");

            self.num_queues = num_queues;
        }

        // Provide the queue and receive buffer ranges for each worker.
        for ((worker, queue), rx_buffer) in self.workers.iter_mut().zip(queues).zip(rx_buffers) {
            worker.task_mut().queue_state = Some(QueueState {
                queue,
                target_vp_set: false,
                rx_buffer_range: rx_buffer,
            });
        }

        Ok(())
    }

    fn start_workers(&mut self) {
        for worker in &mut self.workers {
            worker.start();
        }
    }

    fn primary_mut(&mut self) -> Option<&mut PrimaryChannelState> {
        self.workers[0]
            .state_mut()
            .unwrap()
            .state
            .ready_mut()?
            .state
            .primary
            .as_mut()
    }

    async fn update_guest_vf_state(&mut self, c_state: &mut CoordinatorState) {
        if !self.workers[0].is_running() {
            return;
        }
        self.workers[0].stop().await;
        self.restore_guest_vf_state(c_state).await;
        self.workers[0].start();
    }
}

impl<T: RingMem + 'static + Sync> AsyncRun<Worker<T>> for NetQueue {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        worker: &mut Worker<T>,
    ) -> Result<(), task_control::Cancelled> {
        match worker.process(stop, self).await {
            Ok(()) | Err(WorkerError::BufferRevoked) => {}
            Err(WorkerError::Cancelled(cancelled)) => return Err(cancelled),
            Err(err) => {
                tracing::error!(
                    channel_idx = worker.channel_idx,
                    error = &err as &dyn std::error::Error,
                    "netvsp error"
                );
            }
        }
        Ok(())
    }
}

impl<T: RingMem + 'static> Worker<T> {
    async fn process(
        &mut self,
        stop: &mut StopTask<'_>,
        queue: &mut NetQueue,
    ) -> Result<(), WorkerError> {
        // Be careful not to wait on actions with unbounded blocking time (e.g.
        // guest actions, or waiting for network packets to arrive) without
        // wrapping the wait on `stop.until_stopped`.
        loop {
            match &mut self.state {
                WorkerState::Init(initializing) => {
                    if self.channel_idx != 0 {
                        // Still waiting for the coordinator to provide receive
                        // buffers. The task will be restarted when they are available.
                        stop.until_stopped(pending()).await?
                    }

                    tracelimit::info_ratelimited!("network accepted");

                    let (buffers, state) = stop
                        .until_stopped(self.channel.initialize(initializing, self.mem.clone()))
                        .await??;

                    let state = ReadyState {
                        buffers: Arc::new(buffers),
                        state,
                        data: ProcessingData::new(),
                    };

                    // Wake up the coordinator task to start the queues.
                    let _ = self.coordinator_send.try_send(CoordinatorMessage::Restart);

                    tracelimit::info_ratelimited!("network initialized");
                    self.state = WorkerState::Ready(state);
                }
                WorkerState::Ready(state) => {
                    let queue_state = if let Some(queue_state) = &mut queue.queue_state {
                        if !queue_state.target_vp_set
                            && self.target_vp != vmbus_core::protocol::VP_INDEX_DISABLE_INTERRUPT
                        {
                            tracing::debug!(
                                channel_idx = self.channel_idx,
                                target_vp = self.target_vp,
                                "updating target VP"
                            );
                            queue_state.queue.update_target_vp(self.target_vp).await;
                            queue_state.target_vp_set = true;
                        }

                        queue_state
                    } else {
                        // This task will be restarted when the queues are ready.
                        stop.until_stopped(pending()).await?
                    };

                    let restart = self.channel.main_loop(stop, state, queue_state).await?;

                    assert_eq!(self.channel_idx, 0);
                    let _ = self.coordinator_send.try_send(restart);
                    stop.until_stopped(pending()).await?
                }
            }
        }
    }
}

impl<T: 'static + RingMem> NetChannel<T> {
    fn try_next_packet<'a>(
        &mut self,
        send_buffer: Option<&'a SendBuffer>,
        version: Option<Version>,
    ) -> Result<Option<Packet<'a>>, WorkerError> {
        let (mut read, _) = self.queue.split();
        let packet = match read.try_read() {
            Ok(packet) => {
                parse_packet(&packet, send_buffer, version).map_err(WorkerError::Packet)?
            }
            Err(queue::TryReadError::Empty) => return Ok(None),
            Err(queue::TryReadError::Queue(err)) => return Err(err.into()),
        };

        tracing::trace!(target: "netvsp/vmbus", data = ?packet.data, "incoming vmbus packet");
        Ok(Some(packet))
    }

    async fn next_packet<'a>(
        &mut self,
        send_buffer: Option<&'a SendBuffer>,
        version: Option<Version>,
    ) -> Result<Packet<'a>, WorkerError> {
        let (mut read, _) = self.queue.split();
        let mut packet_ref = read.read().await?;
        let packet =
            parse_packet(&packet_ref, send_buffer, version).map_err(WorkerError::Packet)?;
        if matches!(packet.data, PacketData::RndisPacket(_)) {
            // In WorkerState::Init if an rndis packet is received, assume it is MESSAGE_TYPE_INITIALIZE_MSG
            tracing::trace!(target: "netvsp/vmbus", "detected rndis initialization message");
            packet_ref.revert();
        }
        tracing::trace!(target: "netvsp/vmbus", data = ?packet.data, "incoming vmbus packet");
        Ok(packet)
    }

    fn is_ready_to_initialize(initializing: &InitState, allow_missing_send_buffer: bool) -> bool {
        (initializing.ndis_config.is_some() || initializing.version < Version::V2)
            && initializing.ndis_version.is_some()
            && (initializing.send_buffer.is_some() || allow_missing_send_buffer)
            && initializing.recv_buffer.is_some()
    }

    async fn initialize(
        &mut self,
        initializing: &mut Option<InitState>,
        mem: GuestMemory,
    ) -> Result<(ChannelBuffers, ActiveState), WorkerError> {
        let mut has_init_packet_arrived = false;
        loop {
            if let Some(initializing) = &mut *initializing {
                if Self::is_ready_to_initialize(initializing, false) || has_init_packet_arrived {
                    let recv_buffer = initializing.recv_buffer.take().unwrap();
                    let send_buffer = initializing.send_buffer.take();
                    let state = ActiveState::new(
                        Some(PrimaryChannelState::new(
                            self.adapter.offload_support.clone(),
                        )),
                        recv_buffer.count,
                    );
                    let buffers = ChannelBuffers {
                        version: initializing.version,
                        mem,
                        recv_buffer,
                        send_buffer,
                        ndis_version: initializing.ndis_version.take().unwrap(),
                        ndis_config: initializing.ndis_config.take().unwrap_or(NdisConfig {
                            mtu: DEFAULT_MTU,
                            capabilities: protocol::NdisConfigCapabilities::new(),
                        }),
                    };

                    break Ok((buffers, state));
                }
            }

            // Wait for enough room in the ring to avoid needing to track
            // completion packets.
            self.queue
                .split()
                .1
                .wait_ready(ring::PacketSize::completion(protocol::PACKET_SIZE_V61))
                .await?;

            let packet = self
                .next_packet(None, initializing.as_ref().map(|x| x.version))
                .await?;

            if let Some(initializing) = &mut *initializing {
                match packet.data {
                    PacketData::SendNdisConfig(config) => {
                        if initializing.ndis_config.is_some() {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::SendNdisConfigExists,
                            ));
                        }

                        // As in the vmswitch, if the MTU is invalid then use the default.
                        let mtu = if config.mtu >= MIN_MTU && config.mtu <= MAX_MTU {
                            config.mtu
                        } else {
                            DEFAULT_MTU
                        };

                        // The UEFI client expects a completion packet, which can be empty.
                        self.send_completion(packet.transaction_id, &[])?;
                        initializing.ndis_config = Some(NdisConfig {
                            mtu,
                            capabilities: config.capabilities,
                        });
                    }
                    PacketData::SendNdisVersion(version) => {
                        if initializing.ndis_version.is_some() {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::SendNdisVersionExists,
                            ));
                        }

                        // The UEFI client expects a completion packet, which can be empty.
                        self.send_completion(packet.transaction_id, &[])?;
                        initializing.ndis_version = Some(NdisVersion {
                            major: version.ndis_major_version,
                            minor: version.ndis_minor_version,
                        });
                    }
                    PacketData::SendReceiveBuffer(message) => {
                        if initializing.recv_buffer.is_some() {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::SendReceiveBufferExists,
                            ));
                        }

                        let mtu = if let Some(cfg) = &initializing.ndis_config {
                            cfg.mtu
                        } else if initializing.version < Version::V2 {
                            DEFAULT_MTU
                        } else {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::SendReceiveBufferMissingMTU,
                            ));
                        };

                        let sub_allocation_size = sub_allocation_size_for_mtu(mtu);

                        let recv_buffer = ReceiveBuffer::new(
                            &self.gpadl_map,
                            message.gpadl_handle,
                            message.id,
                            sub_allocation_size,
                        )?;

                        self.send_completion(
                            packet.transaction_id,
                            &self
                                .message(
                                    protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER_COMPLETE,
                                    protocol::Message1SendReceiveBufferComplete {
                                        status: protocol::Status::SUCCESS,
                                        num_sections: 1,
                                        sections: [protocol::ReceiveBufferSection {
                                            offset: 0,
                                            sub_allocation_size: recv_buffer.sub_allocation_size,
                                            num_sub_allocations: recv_buffer.count,
                                            end_offset: recv_buffer.sub_allocation_size
                                                * recv_buffer.count,
                                        }],
                                    },
                                )
                                .payload(),
                        )?;
                        initializing.recv_buffer = Some(recv_buffer);
                    }
                    PacketData::SendSendBuffer(message) => {
                        if initializing.send_buffer.is_some() {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::SendSendBufferExists,
                            ));
                        }

                        let send_buffer = SendBuffer::new(&self.gpadl_map, message.gpadl_handle)?;
                        self.send_completion(
                            packet.transaction_id,
                            &self
                                .message(
                                    protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER_COMPLETE,
                                    protocol::Message1SendSendBufferComplete {
                                        status: protocol::Status::SUCCESS,
                                        section_size: 6144,
                                    },
                                )
                                .payload(),
                        )?;

                        initializing.send_buffer = Some(send_buffer);
                    }
                    PacketData::RndisPacket(rndis_packet) => {
                        if !Self::is_ready_to_initialize(initializing, true) {
                            return Err(WorkerError::UnexpectedPacketOrder(
                                PacketOrderError::UnexpectedRndisPacket,
                            ));
                        }
                        tracing::debug!(
                            channel_type = rndis_packet.channel_type,
                            "RndisPacket received during initialization, assuming MESSAGE_TYPE_INITIALIZE_MSG"
                        );
                        has_init_packet_arrived = true;
                    }
                    _ => {
                        return Err(WorkerError::UnexpectedPacketOrder(
                            PacketOrderError::InvalidPacketData,
                        ));
                    }
                }
            } else {
                match packet.data {
                    PacketData::Init(init) => {
                        let requested_version = init.protocol_version;
                        let version = check_version(requested_version);
                        let mut message = self.message(
                            protocol::MESSAGE_TYPE_INIT_COMPLETE,
                            protocol::MessageInitComplete {
                                deprecated: protocol::INVALID_PROTOCOL_VERSION,
                                maximum_mdl_chain_length: 34,
                                status: protocol::Status::NONE,
                            },
                        );
                        if let Some(version) = version {
                            if version == Version::V1 {
                                message.data.deprecated = Version::V1 as u32;
                            }
                            message.data.status = protocol::Status::SUCCESS;
                        } else {
                            tracing::debug!(requested_version, "unrecognized version");
                        }
                        self.send_completion(packet.transaction_id, &message.payload())?;

                        if let Some(version) = version {
                            tracelimit::info_ratelimited!(?version, "network negotiated");

                            if version >= Version::V61 {
                                // Update the packet size so that the appropriate padding is
                                // appended for picky Windows guests.
                                self.packet_size = protocol::PACKET_SIZE_V61;
                            }
                            *initializing = Some(InitState {
                                version,
                                ndis_config: None,
                                ndis_version: None,
                                recv_buffer: None,
                                send_buffer: None,
                            });
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    async fn main_loop(
        &mut self,
        stop: &mut StopTask<'_>,
        ready_state: &mut ReadyState,
        queue_state: &mut QueueState,
    ) -> Result<CoordinatorMessage, WorkerError> {
        let buffers = &ready_state.buffers;
        let state = &mut ready_state.state;
        let data = &mut ready_state.data;

        let ring_spare_capacity = {
            let (_, send) = self.queue.split();
            let mut limit = if self.can_use_ring_size_opt {
                self.adapter.ring_size_limit.load(Ordering::Relaxed)
            } else {
                0
            };
            if limit == 0 {
                limit = send.capacity() - 2048;
            }
            send.capacity() - limit
        };

        // Handle any guest state changes since last run.
        if let Some(primary) = state.primary.as_mut() {
            if primary.requested_num_queues > 1 && !primary.tx_spread_sent {
                let num_channels_opened =
                    self.adapter.num_sub_channels_opened.load(Ordering::Relaxed);
                if num_channels_opened == primary.requested_num_queues as usize {
                    let (_, mut send) = self.queue.split();
                    stop.until_stopped(send.wait_ready(MIN_STATE_CHANGE_RING_SIZE))
                        .await??;
                    self.guest_send_indirection_table(buffers.version, num_channels_opened as u32);
                    primary.tx_spread_sent = true;
                }
            }
            if let PendingLinkAction::Active(up) = primary.pending_link_action {
                let (_, mut send) = self.queue.split();
                stop.until_stopped(send.wait_ready(MIN_STATE_CHANGE_RING_SIZE))
                    .await??;
                if let Some(id) = primary.free_control_buffers.pop() {
                    let connect = if primary.guest_link_up != up {
                        primary.pending_link_action = PendingLinkAction::Default;
                        up
                    } else {
                        // For the up -> down -> up OR down -> up -> down case, the first transition
                        // is sent immediately and the second transition is queued with a delay.
                        primary.pending_link_action =
                            PendingLinkAction::Delay(primary.guest_link_up);
                        !primary.guest_link_up
                    };
                    // Mark the receive buffer in use to allow the guest to release it.
                    assert!(state.rx_bufs.is_free(id.0));
                    state.rx_bufs.allocate(std::iter::once(id.0)).unwrap();
                    let state_to_send = if connect {
                        rndisprot::STATUS_MEDIA_CONNECT
                    } else {
                        rndisprot::STATUS_MEDIA_DISCONNECT
                    };
                    tracing::info!(
                        connect,
                        mac_address = %self.adapter.mac_address,
                        "sending link status"
                    );

                    self.indicate_status(buffers, id.0, state_to_send, &[])?;
                    primary.guest_link_up = connect;
                } else {
                    primary.pending_link_action = PendingLinkAction::Delay(up);
                }

                match primary.pending_link_action {
                    PendingLinkAction::Delay(_) => {
                        return Ok(CoordinatorMessage::StartTimer(
                            Instant::now() + LINK_DELAY_DURATION,
                        ))
                    }
                    PendingLinkAction::Active(_) => panic!("State should not be Active"),
                    _ => {}
                }
            }
            match primary.guest_vf_state {
                PrimaryChannelGuestVfState::Available { .. }
                | PrimaryChannelGuestVfState::UnavailableFromAvailable
                | PrimaryChannelGuestVfState::UnavailableFromDataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::UnavailableFromDataPathSwitched
                | PrimaryChannelGuestVfState::DataPathSwitchPending { .. }
                | PrimaryChannelGuestVfState::DataPathSynthetic => {
                    let (_, mut send) = self.queue.split();
                    stop.until_stopped(send.wait_ready(MIN_STATE_CHANGE_RING_SIZE))
                        .await??;
                    if let Some(message) = self.handle_state_change(primary, buffers).await? {
                        return Ok(message);
                    }
                }
                _ => (),
            }
        }

        loop {
            // If the ring is almost full, then do not poll the endpoint,
            // since this will cause us to spend time dropping packets and
            // reprogramming receive buffers. It's more efficient to let the
            // backend drop packets.
            let ring_full = {
                let (_, mut send) = self.queue.split();
                !send.can_write(ring_spare_capacity)?
            };

            let did_some_work = (!ring_full
                && self.process_endpoint_rx(buffers, state, data, queue_state.queue.as_mut())?)
                | self.process_ring_buffer(buffers, state, data, queue_state)?
                | (!ring_full
                    && self.process_endpoint_tx(state, data, queue_state.queue.as_mut())?)
                | self.transmit_pending_segments(state, data, queue_state)?
                | self.send_pending_packets(state)?;

            if !did_some_work {
                state.stats.spurious_wakes.increment();
            }

            // Process any outstanding control messages before sleeping in case
            // there are now suballocations available for use.
            self.process_control_messages(buffers, state)?;

            // This should be the only await point waiting on network traffic or
            // guest actions. Wrap it in `stop.until_stopped` to allow
            // cancellation.
            let restart = stop
                .until_stopped(std::future::poll_fn(
                    |cx| -> Poll<Option<CoordinatorMessage>> {
                        // If the ring is almost full, then don't wait for endpoint
                        // interrupts. This allows the interrupt rate to fall when the
                        // guest cannot keep up with the load.
                        if !ring_full {
                            // Check the network endpoint for tx completion or rx.
                            if queue_state.queue.poll_ready(cx).is_ready() {
                                tracing::trace!("endpoint ready");
                                return Poll::Ready(None);
                            }
                        }

                        // Check the incoming ring for tx, but only if there are enough
                        // free tx packets.
                        let (mut recv, mut send) = self.queue.split();
                        if state.free_tx_packets.len() >= self.adapter.free_tx_packet_threshold
                            && data.tx_segments.is_empty()
                            && recv.poll_ready(cx).is_ready()
                        {
                            tracing::trace!("incoming ring ready");
                            return Poll::Ready(None);
                        }

                        // Check the outgoing ring for space to send rx completions or
                        // control message sends, if any are pending.
                        //
                        // Also, if endpoint processing has been suspended due to the
                        // ring being nearly full, then ask the guest to wake us up when
                        // there is space again.
                        let mut pending_send_size = self.pending_send_size;
                        if ring_full {
                            pending_send_size = ring_spare_capacity;
                        }
                        if pending_send_size != 0
                            && send.poll_ready(cx, pending_send_size).is_ready()
                        {
                            tracing::trace!("outgoing ring ready");
                            return Poll::Ready(None);
                        }

                        // Collect any of this queue's receive buffers that were
                        // completed by a remote channel. This only happens when the
                        // subchannel count changes, so that receive buffer ownership
                        // moves between queues while some receive buffers are still in
                        // use.
                        if let Some(remote_buffer_id_recv) =
                            &mut queue_state.rx_buffer_range.remote_buffer_id_recv
                        {
                            while let Poll::Ready(Some(id)) =
                                remote_buffer_id_recv.poll_next_unpin(cx)
                            {
                                if id >= RX_RESERVED_CONTROL_BUFFERS {
                                    queue_state.queue.rx_avail(&[RxId(id)]);
                                } else {
                                    state
                                        .primary
                                        .as_mut()
                                        .unwrap()
                                        .free_control_buffers
                                        .push(ControlMessageId(id));
                                }
                            }
                        }

                        if let Some(restart) = self.restart.take() {
                            return Poll::Ready(Some(restart));
                        }

                        tracing::trace!("network waiting");
                        Poll::Pending
                    },
                ))
                .await?;

            if let Some(restart) = restart {
                break Ok(restart);
            }
        }
    }

    fn process_endpoint_rx(
        &mut self,
        buffers: &ChannelBuffers,
        state: &mut ActiveState,
        data: &mut ProcessingData,
        epqueue: &mut dyn net_backend::Queue,
    ) -> Result<bool, WorkerError> {
        let n = epqueue
            .rx_poll(&mut data.rx_ready)
            .map_err(WorkerError::Endpoint)?;
        if n == 0 {
            return Ok(false);
        }

        let transaction_id = data.rx_ready[0].0.into();
        let ready_ids = data.rx_ready[..n].iter().map(|&RxId(id)| id);

        state.rx_bufs.allocate(ready_ids.clone()).unwrap();

        // Always use the full suballocation size to avoid tracking the
        // message length. See RxBuf::header() for details.
        let len = buffers.recv_buffer.sub_allocation_size as usize;
        data.transfer_pages.clear();
        data.transfer_pages
            .extend(ready_ids.map(|id| buffers.recv_buffer.transfer_page_range(id, len)));

        match self.try_send_rndis_message(
            transaction_id,
            protocol::DATA_CHANNEL_TYPE,
            buffers.recv_buffer.id,
            &data.transfer_pages,
        )? {
            None => {
                // packet was sent
                state.stats.rx_packets.add(n as u64);
            }
            Some(_) => {
                // Ring buffer is full. Drop the packets and free the rx
                // buffers.
                state.stats.rx_dropped_ring_full.add(n as u64);

                state.rx_bufs.free(data.rx_ready[0].0);
                epqueue.rx_avail(&data.rx_ready[..n]);
            }
        }

        state.stats.rx_packets_per_wake.add_sample(n as u64);
        Ok(true)
    }

    fn process_endpoint_tx(
        &mut self,
        state: &mut ActiveState,
        data: &mut ProcessingData,
        epqueue: &mut dyn net_backend::Queue,
    ) -> Result<bool, WorkerError> {
        // Drain completed transmits.
        let n = epqueue
            .tx_poll(&mut data.tx_done)
            .map_err(WorkerError::Endpoint)?;
        if n == 0 {
            return Ok(false);
        }

        for &id in &data.tx_done[..n] {
            let tx_packet = &mut state.pending_tx_packets[id.0 as usize];
            assert!(tx_packet.pending_packet_count > 0);
            tx_packet.pending_packet_count -= 1;
            if tx_packet.pending_packet_count == 0 {
                self.complete_tx_packet(state, id)?;
            }
        }

        Ok(true)
    }

    fn switch_data_path(
        &mut self,
        state: &mut ActiveState,
        use_guest_vf: bool,
        transaction_id: Option<u64>,
    ) -> Result<(), WorkerError> {
        let primary = state.primary.as_mut().unwrap();
        let mut queue_switch_operation = false;
        match primary.guest_vf_state {
            PrimaryChannelGuestVfState::AvailableAdvertised | PrimaryChannelGuestVfState::Ready => {
                // Allow the guest to switch to VTL0, or if the current state
                // of the data path is unknown, allow a switch away from VTL0.
                // The latter case handles the scenario where the data path has
                // been switched but the synthetic device has been restarted.
                // The device is queried for the current state of the data path
                // but if it is unknown (upgraded from older version that
                // doesn't track this data, or failure during query) then the
                // safest option is to pass the request through.
                if use_guest_vf || primary.is_data_path_switched.is_none() {
                    primary.guest_vf_state = PrimaryChannelGuestVfState::DataPathSwitchPending {
                        to_guest: use_guest_vf,
                        id: transaction_id,
                        result: None,
                    };
                    queue_switch_operation = true;
                }
            }
            PrimaryChannelGuestVfState::DataPathSwitched => {
                if !use_guest_vf {
                    primary.guest_vf_state = PrimaryChannelGuestVfState::DataPathSwitchPending {
                        to_guest: false,
                        id: transaction_id,
                        result: None,
                    };
                    queue_switch_operation = true;
                }
            }
            _ if use_guest_vf => {
                tracing::warn!(
                    state = %primary.guest_vf_state,
                    use_guest_vf,
                    "Data path switch requested while device is in wrong state"
                );
            }
            _ => (),
        };
        if queue_switch_operation {
            // A restart will also try to switch the data path based on primary.guest_vf_state.
            if self.restart.is_none() {
                self.restart = Some(CoordinatorMessage::UpdateGuestVfState)
            };
        } else {
            self.send_completion(transaction_id, &[])?;
        }
        Ok(())
    }

    fn process_ring_buffer(
        &mut self,
        buffers: &ChannelBuffers,
        state: &mut ActiveState,
        data: &mut ProcessingData,
        queue_state: &mut QueueState,
    ) -> Result<bool, WorkerError> {
        let mut total_packets = 0;
        let mut did_some_work = false;
        loop {
            if state.free_tx_packets.is_empty() || !data.tx_segments.is_empty() {
                break;
            }
            let packet = if let Some(packet) =
                self.try_next_packet(buffers.send_buffer.as_ref(), Some(buffers.version))?
            {
                packet
            } else {
                break;
            };

            did_some_work = true;
            match packet.data {
                PacketData::RndisPacket(_) => {
                    assert!(data.tx_segments.is_empty());
                    let id = state.free_tx_packets.pop().unwrap();
                    let num_packets =
                        self.handle_rndis(buffers, id, state, &packet, &mut data.tx_segments)?;
                    total_packets += num_packets as u64;
                    state.pending_tx_packets[id.0 as usize].pending_packet_count += num_packets;

                    if num_packets != 0 {
                        if self.transmit_segments(state, data, queue_state, id, num_packets)?
                            < num_packets
                        {
                            state.stats.tx_stalled.increment();
                        }
                    } else {
                        self.complete_tx_packet(state, id)?;
                    }
                }
                PacketData::RndisPacketComplete(_completion) => {
                    data.rx_done.clear();
                    state
                        .release_recv_buffers(
                            packet
                                .transaction_id
                                .expect("completion packets have transaction id by construction"),
                            &queue_state.rx_buffer_range,
                            &mut data.rx_done,
                        )
                        .ok_or(WorkerError::InvalidRndisPacketCompletion)?;
                    queue_state.queue.rx_avail(&data.rx_done);
                }
                PacketData::SubChannelRequest(request) if state.primary.is_some() => {
                    let mut subchannel_count = 0;
                    let status = if request.operation == protocol::SubchannelOperation::ALLOCATE
                        && request.num_sub_channels <= self.adapter.max_queues.into()
                    {
                        subchannel_count = request.num_sub_channels;
                        protocol::Status::SUCCESS
                    } else {
                        protocol::Status::FAILURE
                    };

                    tracing::debug!(?status, subchannel_count, "subchannel request");
                    self.send_completion(
                        packet.transaction_id,
                        &self
                            .message(
                                protocol::MESSAGE5_TYPE_SUB_CHANNEL,
                                protocol::Message5SubchannelComplete {
                                    status,
                                    num_sub_channels: subchannel_count,
                                },
                            )
                            .payload(),
                    )?;

                    if subchannel_count > 0 {
                        let primary = state.primary.as_mut().unwrap();
                        primary.requested_num_queues = subchannel_count as u16 + 1;
                        primary.tx_spread_sent = false;
                        self.restart = Some(CoordinatorMessage::Restart);
                    }
                }
                PacketData::RevokeReceiveBuffer(Message1RevokeReceiveBuffer { id })
                | PacketData::RevokeSendBuffer(Message1RevokeSendBuffer { id })
                    if state.primary.is_some() =>
                {
                    tracing::debug!(
                        id,
                        "receive/send buffer revoked, terminating channel processing"
                    );
                    return Err(WorkerError::BufferRevoked);
                }
                PacketData::SendVfAssociationCompletion if state.primary.is_some() => (),
                PacketData::SwitchDataPath(switch_data_path) if state.primary.is_some() => {
                    self.switch_data_path(
                        state,
                        switch_data_path.active_data_path == protocol::DataPath::VF.0,
                        packet.transaction_id,
                    )?;
                }
                PacketData::SwitchDataPathCompletion if state.primary.is_some() => (),
                PacketData::OidQueryEx(oid_query) => {
                    tracing::warn!(oid = ?oid_query.oid, "unimplemented OID");
                    self.send_completion(
                        packet.transaction_id,
                        &self
                            .message(
                                protocol::MESSAGE5_TYPE_OID_QUERY_EX_COMPLETE,
                                protocol::Message5OidQueryExComplete {
                                    status: rndisprot::STATUS_NOT_SUPPORTED,
                                    bytes: 0,
                                },
                            )
                            .payload(),
                    )?;
                }
                p => {
                    tracing::warn!(request = ?p, "unexpected packet");
                    return Err(WorkerError::UnexpectedPacketOrder(
                        PacketOrderError::SwitchDataPathCompletionPrimaryChannelState,
                    ));
                }
            }
        }
        state.stats.tx_packets_per_wake.add_sample(total_packets);
        Ok(did_some_work)
    }

    fn transmit_pending_segments(
        &mut self,
        state: &mut ActiveState,
        data: &mut ProcessingData,
        queue_state: &mut QueueState,
    ) -> Result<bool, WorkerError> {
        if data.tx_segments.is_empty() {
            return Ok(false);
        }
        let net_backend::TxSegmentType::Head(metadata) = &data.tx_segments[0].ty else {
            unreachable!()
        };
        let id = metadata.id;
        let num_packets = state.pending_tx_packets[id.0 as usize].pending_packet_count;
        let packets_sent = self.transmit_segments(state, data, queue_state, id, num_packets)?;
        Ok(num_packets == packets_sent)
    }

    fn transmit_segments(
        &mut self,
        state: &mut ActiveState,
        data: &mut ProcessingData,
        queue_state: &mut QueueState,
        id: TxId,
        num_packets: usize,
    ) -> Result<usize, WorkerError> {
        let (sync, segments_sent) = queue_state
            .queue
            .tx_avail(&data.tx_segments)
            .map_err(WorkerError::Endpoint)?;

        assert!(segments_sent <= data.tx_segments.len());

        let packets_sent = if segments_sent == data.tx_segments.len() {
            num_packets
        } else {
            net_backend::packet_count(&data.tx_segments[..segments_sent])
        };

        data.tx_segments.drain(..segments_sent);

        if sync {
            state.pending_tx_packets[id.0 as usize].pending_packet_count -= packets_sent;
        }

        if state.pending_tx_packets[id.0 as usize].pending_packet_count == 0 {
            self.complete_tx_packet(state, id)?;
        }

        Ok(packets_sent)
    }

    fn handle_rndis(
        &mut self,
        buffers: &ChannelBuffers,
        id: TxId,
        state: &mut ActiveState,
        packet: &Packet<'_>,
        segments: &mut Vec<TxSegment>,
    ) -> Result<usize, WorkerError> {
        let mut num_packets = 0;
        let tx_packet = &mut state.pending_tx_packets[id.0 as usize];
        assert!(tx_packet.pending_packet_count == 0);
        tx_packet.transaction_id = packet
            .transaction_id
            .ok_or(WorkerError::MissingTransactionId)?;

        // Probe the data to catch accesses that are out of bounds. This
        // simplifies error handling for backends that use
        // [`GuestMemory::iova`].
        packet
            .external_data
            .iter()
            .try_for_each(|range| buffers.mem.probe_gpns(range.gpns()))
            .map_err(WorkerError::GpaDirectError)?;

        let mut reader = packet.rndis_reader(&buffers.mem);
        // There may be multiple RNDIS packets in a single
        // message, concatenated with each other. Consume
        // them until there is no more data in the RNDIS
        // message.
        while reader.len() > 0 {
            let mut this_reader = reader.clone();
            let header: rndisprot::MessageHeader = this_reader.read_plain()?;
            if self.handle_rndis_message(
                buffers,
                state,
                id,
                header.message_type,
                this_reader,
                segments,
            )? {
                num_packets += 1;
            }
            reader.skip(header.message_length as usize)?;
        }

        Ok(num_packets)
    }

    fn try_send_tx_packet(&mut self, transaction_id: u64) -> Result<bool, WorkerError> {
        let message = self.message(
            protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE,
            protocol::Message1SendRndisPacketComplete {
                status: protocol::Status::SUCCESS,
            },
        );
        let result = self.queue.split().1.try_write(&queue::OutgoingPacket {
            transaction_id,
            packet_type: OutgoingPacketType::Completion,
            payload: &message.payload(),
        });
        let sent = match result {
            Ok(()) => true,
            Err(queue::TryWriteError::Full(n)) => {
                self.pending_send_size = n;
                false
            }
            Err(queue::TryWriteError::Queue(err)) => return Err(err.into()),
        };
        Ok(sent)
    }

    fn send_pending_packets(&mut self, state: &mut ActiveState) -> Result<bool, WorkerError> {
        let mut did_some_work = false;
        while let Some(pending) = state.pending_tx_completions.front() {
            if !self.try_send_tx_packet(pending.transaction_id)? {
                return Ok(did_some_work);
            }
            did_some_work = true;
            if let Some(id) = pending.tx_id {
                state.free_tx_packets.push(id);
            }
            tracing::trace!(?pending, "sent tx completion");
            state.pending_tx_completions.pop_front();
        }

        self.pending_send_size = 0;
        Ok(did_some_work)
    }

    fn complete_tx_packet(&mut self, state: &mut ActiveState, id: TxId) -> Result<(), WorkerError> {
        let tx_packet = &mut state.pending_tx_packets[id.0 as usize];
        assert_eq!(tx_packet.pending_packet_count, 0);
        if self.pending_send_size == 0 && self.try_send_tx_packet(tx_packet.transaction_id)? {
            tracing::trace!(id = id.0, "sent tx completion");
            state.free_tx_packets.push(id);
        } else {
            tracing::trace!(id = id.0, "pended tx completion");
            state.pending_tx_completions.push_back(PendingTxCompletion {
                transaction_id: tx_packet.transaction_id,
                tx_id: Some(id),
            });
        }
        Ok(())
    }
}

impl ActiveState {
    fn release_recv_buffers(
        &mut self,
        transaction_id: u64,
        rx_buffer_range: &RxBufferRange,
        done: &mut Vec<RxId>,
    ) -> Option<()> {
        // The transaction ID specifies the first rx buffer ID.
        let first_id: u32 = transaction_id.try_into().ok()?;
        let ids = self.rx_bufs.free(first_id)?;
        for id in ids {
            if !rx_buffer_range.send_if_remote(id) {
                if id >= RX_RESERVED_CONTROL_BUFFERS {
                    done.push(RxId(id));
                } else {
                    self.primary
                        .as_mut()
                        .unwrap()
                        .free_control_buffers
                        .push(ControlMessageId(id));
                }
            }
        }
        Some(())
    }
}
