// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use self::bnic_defs::ManaCommandCode;
use self::bnic_defs::ManaCqeHeader;
use self::bnic_defs::ManaQueryVportCfgReq;
use self::bnic_defs::ManaRxcompOob;
use self::bnic_defs::ManaRxcompOobFlags;
use self::bnic_defs::ManaSetVportSerialNo;
use self::bnic_defs::ManaTxCompOob;
use self::bnic_defs::ManaTxCompOobOffsets;
use self::bnic_defs::CQE_TX_OKAY;
use self::bnic_defs::MANA_CQE_COMPLETION;
use crate::bnic::bnic_defs::ManaCfgRxSteerReq;
use crate::bnic::bnic_defs::ManaConfigVportReq;
use crate::bnic::bnic_defs::ManaConfigVportResp;
use crate::bnic::bnic_defs::ManaCreateWqobjReq;
use crate::bnic::bnic_defs::ManaCreateWqobjResp;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgReq;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgResp;
use crate::bnic::bnic_defs::ManaQueryVportCfgResp;
use crate::bnic::bnic_defs::ManaTxOob;
use crate::bnic::bnic_defs::CQE_RX_OKAY;
use crate::hwc::HwState;
use crate::queues::Queues;
use crate::VportConfig;
use anyhow::anyhow;
use anyhow::Context;
use gdma_defs::access::WqeAccess;
use gdma_defs::bnic as bnic_defs;
use gdma_defs::bnic::ManaDestroyWqobjReq;
use gdma_defs::bnic::ManaTxShortOob;
use gdma_defs::bnic::Tristate;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaReqHdr;
use gdma_defs::Wqe;
use guestmem::GuestMemory;
use guestmem::Limit;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use inspect::InspectMut;
use net_backend::BufferAccess;
use net_backend::Endpoint;
use net_backend::L3Protocol;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RxBufferSegment;
use net_backend::RxChecksumState;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use net_backend_resources::mac_address::MacAddress;
use parking_lot::Mutex;
use slab::Slab;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use task_control::AsyncRun;
use task_control::InspectTaskMut;
use task_control::StopTask;
use task_control::TaskControl;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

pub struct GuestBuffers {
    gm: GuestMemory,
    rx_packets: Arc<Mutex<Slab<RxPacket>>>,
    buffer_segments: Vec<RxBufferSegment>,
}

struct RxPacket {
    segments: Vec<RxBufferSegment>,
    len: u32,
    wqe_offset: u32,
    oob: ManaRxcompOob,
}

impl BufferAccess for GuestBuffers {
    fn guest_memory(&self) -> &GuestMemory {
        &self.gm
    }

    fn write_data(&mut self, id: RxId, mut data: &[u8]) {
        self.guest_addresses(id);
        let mut addrs = self.buffer_segments.iter();
        while !data.is_empty() {
            let addr = addrs.next().expect("packet too large");
            let len = data.len().min(addr.len as usize);
            let (this, next) = data.split_at(len);
            if let Err(err) = self.gm.write_at(addr.gpa, this) {
                tracing::warn!(
                    gpa = addr.gpa,
                    len,
                    error = &err as &dyn std::error::Error,
                    "rx memory write failure"
                );
            }
            data = next;
        }
    }

    fn guest_addresses(&mut self, id: RxId) -> &[RxBufferSegment] {
        self.buffer_segments
            .clone_from(&self.rx_packets.lock()[id.0 as usize].segments);
        &self.buffer_segments
    }

    fn capacity(&self, id: RxId) -> u32 {
        self.rx_packets.lock()[id.0 as usize].len
    }

    fn write_header(&mut self, id: RxId, metadata: &RxMetadata) {
        assert_eq!(metadata.offset, 0);

        let mut flags = ManaRxcompOobFlags::new();
        match metadata.ip_checksum {
            RxChecksumState::Unknown => {}
            RxChecksumState::Good => flags.set_rx_iphdr_csum_succeed(true),
            RxChecksumState::Bad => flags.set_rx_iphdr_csum_fail(true),
            RxChecksumState::ValidatedButWrong => {}
        }
        match metadata.l4_protocol {
            net_backend::L4Protocol::Unknown => {}
            net_backend::L4Protocol::Tcp => match metadata.l4_checksum {
                RxChecksumState::Unknown => {}
                RxChecksumState::Good => flags.set_rx_tcp_csum_succeed(true),
                RxChecksumState::Bad => flags.set_rx_tcp_csum_fail(true),
                RxChecksumState::ValidatedButWrong => {}
            },
            net_backend::L4Protocol::Udp => match metadata.l4_checksum {
                RxChecksumState::Unknown => {}
                RxChecksumState::Good => flags.set_rx_udp_csum_succeed(true),
                RxChecksumState::Bad => flags.set_rx_udp_csum_fail(true),
                RxChecksumState::ValidatedButWrong => {}
            },
        }

        let mut packets = self.rx_packets.lock();
        let packet = &mut packets[id.0 as usize];
        packet.oob = ManaRxcompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_cqe_type(CQE_RX_OKAY)
                .with_client_type(MANA_CQE_COMPLETION),
            rx_wqe_offset: packet.wqe_offset,
            flags,
            ..FromZeros::new_zeroed()
        };
        packet.oob.ppi[0].pkt_len = metadata.len as u16;
    }
}

pub struct BasicNic {
    vports: Vec<Vport>,
}

impl InspectMut for BasicNic {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .fields_mut("vports", self.vports.iter_mut().enumerate());
    }
}

struct Vport {
    mac_address: MacAddress,
    endpoint: Box<dyn Endpoint>,
    task: TaskControl<TxRxState, TxRxTask>,
    queue_cfg: QueueCfg,
    serial_no: u32,
}

impl InspectMut for Vport {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("mac_address", self.mac_address)
            .field_mut("endpoint", self.endpoint.as_mut())
            .field("tx_wq", self.queue_cfg.tx.map(|(wq, _cq)| wq))
            .field("tx_cq", self.queue_cfg.tx.map(|(_wq, cq)| cq))
            .field("rx_wq", self.queue_cfg.tx.map(|(wq, _cq)| wq))
            .field("rx_cq", self.queue_cfg.tx.map(|(_wq, cq)| cq))
            .merge(&mut self.task);
    }
}

struct QueueCfg {
    tx: Option<(u32, u32)>,
    rx: Option<(u32, u32)>,
}

impl BasicNic {
    pub fn new(vports: Vec<VportConfig>) -> Self {
        assert!(!vports.is_empty());

        let vports = vports
            .into_iter()
            .map(
                |VportConfig {
                     mac_address,
                     endpoint,
                 }| {
                    assert!(endpoint.is_ordered());
                    Vport {
                        mac_address,
                        endpoint,
                        task: TaskControl::new(TxRxState),
                        queue_cfg: QueueCfg { tx: None, rx: None },
                        serial_no: 0,
                    }
                },
            )
            .collect();

        Self { vports }
    }

    pub async fn handle_req(
        &mut self,
        state: &mut HwState,
        hdr: &GdmaReqHdr,
        mut read: Limit<WqeAccess<'_>>,
        mut write: Limit<WqeAccess<'_>>,
    ) -> anyhow::Result<usize> {
        tracing::debug!(msg_type = ?ManaCommandCode(hdr.req.msg_type), "bnic request");

        let response_len = match ManaCommandCode(hdr.req.msg_type) {
            ManaCommandCode::MANA_QUERY_DEV_CONFIG => {
                let _req: ManaQueryDeviceCfgReq = read
                    .read_plain()
                    .context("reading query dev config request")?;

                let resp = ManaQueryDeviceCfgResp {
                    pf_cap_flags1: 0.into(),
                    pf_cap_flags2: 0,
                    pf_cap_flags3: 0,
                    pf_cap_flags4: 0,
                    max_num_vports: self.vports.len() as u16,
                    reserved: 0,
                    max_num_eqs: 64,
                };

                write.write(resp.as_bytes())?;
                size_of_val(&resp)
            }
            ManaCommandCode::MANA_CONFIG_VPORT_TX => {
                let req: ManaConfigVportReq = read
                    .read_plain()
                    .context("reading config vport tx request")?;
                let _vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                let resp = ManaConfigVportResp {
                    tx_vport_offset: 0,
                    short_form_allowed: 1,
                    reserved: 0,
                };
                write.write(resp.as_bytes())?;
                size_of_val(&resp)
            }
            ManaCommandCode::MANA_CREATE_WQ_OBJ => {
                let req: ManaCreateWqobjReq =
                    read.read_plain().context("reading create wq obj request")?;
                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                let is_send = match req.wq_type {
                    GdmaQueueType::GDMA_RQ => false,
                    GdmaQueueType::GDMA_SQ => true,
                    ty => anyhow::bail!("unsupported queue type: {:?}", ty),
                };

                if (is_send && vport.queue_cfg.tx.is_some())
                    || (!is_send && vport.queue_cfg.rx.is_some())
                {
                    anyhow::bail!("queue already created");
                }

                let wq_region = state.get_dma_region(req.wq_gdma_region, req.wq_size)?;
                let cq_region = state.get_dma_region(req.cq_gdma_region, req.cq_size)?;

                let wq_id = state
                    .queues
                    .alloc_wq(is_send, wq_region.clone())
                    .context("failed to allocate wq")?;

                let cq_id = state
                    .queues
                    .alloc_cq(cq_region.clone(), req.cq_parent_qid)
                    .context("failed to allocate cq")?;

                let resp = ManaCreateWqobjResp {
                    wq_id,
                    cq_id,
                    wq_obj: req.vport, // use the vport # as the handle
                };

                *if is_send {
                    &mut vport.queue_cfg.tx
                } else {
                    &mut vport.queue_cfg.rx
                } = Some((wq_id, cq_id));

                write.write(resp.as_bytes())?;

                // Take ownership of the DMA regions.
                state.remove_dma_region(req.wq_gdma_region).unwrap();
                state.remove_dma_region(req.cq_gdma_region).unwrap();
                size_of_val(&resp)
            }
            ManaCommandCode::MANA_DESTROY_WQ_OBJ => {
                let req: ManaDestroyWqobjReq = read
                    .read_plain()
                    .context("failed to read destroy wq obj request")?;
                let vport = self
                    .vports
                    .get_mut(req.wq_obj_handle as usize)
                    .context("invalid obj handle")?;

                if vport.task.has_state() {
                    anyhow::bail!("queue still in use");
                }
                let (is_send, queues) = match req.wq_type {
                    GdmaQueueType::GDMA_RQ => (false, &mut vport.queue_cfg.rx),
                    GdmaQueueType::GDMA_SQ => (true, &mut vport.queue_cfg.tx),
                    ty => anyhow::bail!("unsupported queue type: {:?}", ty),
                };
                let (wq_id, cq_id) = queues.take().context("specified queue does not exist")?;
                state.queues.free_wq(is_send, wq_id).unwrap();
                state.queues.free_cq(cq_id).unwrap();
                0
            }
            ManaCommandCode::MANA_CONFIG_VPORT_RX => {
                let req: ManaCfgRxSteerReq = read
                    .read_plain()
                    .context("reading config vport rx request")?;
                tracing::debug!(?req, "rx config");
                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                match req.rx_enable {
                    Tristate::FALSE if vport.task.is_running() => {
                        vport.task.stop().await;
                        vport.task.remove();
                        vport.endpoint.stop().await;
                    }
                    Tristate::TRUE if !vport.task.is_running() => {
                        if let (Some((sq_id, sq_cq_id)), Some((rq_id, rq_cq_id))) =
                            (vport.queue_cfg.tx, vport.queue_cfg.rx)
                        {
                            let rx_packets = Arc::new(Default::default());

                            let mut queues = vec![];
                            vport
                                .endpoint
                                .get_queues(
                                    vec![QueueConfig {
                                        pool: Box::new(GuestBuffers {
                                            gm: state.queues.gm.clone(),
                                            rx_packets: Arc::clone(&rx_packets),
                                            buffer_segments: Vec::new(),
                                        }),
                                        initial_rx: &[],
                                        driver: Box::new(state.queues.driver.clone()),
                                    }],
                                    None,
                                    &mut queues,
                                )
                                .await?;

                            vport.task.insert(
                                &state.queues.driver,
                                "gdma-bnic",
                                TxRxTask {
                                    queues: state.queues.clone(),
                                    epqueue: queues.drain(..).next().unwrap(),
                                    rx_packets,
                                    sq_id,
                                    sq_cq_id,
                                    rq_id,
                                    rq_cq_id,
                                    tx_segment_buffer: Vec::new(),
                                    rx_buf_count: 0,
                                },
                            );
                            vport.task.start();
                        } else {
                            anyhow::bail!("queues not configured");
                        }
                    }
                    _ => {}
                }
                0
            }
            ManaCommandCode::MANA_VTL2_MOVE_FILTER => {
                anyhow::bail!("unsupported command MANA_VTL2_MOVE_FILTER");
            }
            ManaCommandCode::MANA_VTL2_QUERY_FILTER_STATE => {
                let req: gdma_defs::bnic::ManaQueryFilterStateReq = read
                    .read_plain()
                    .context("reading query vport filter state request")?;
                let _ = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                let resp = gdma_defs::bnic::ManaQueryFilterStateResponse {
                    direction_to_vtl0: 0,
                    reserved: [0; 7],
                };

                write.write(resp.as_bytes())?;
                size_of_val(&resp)
            }
            ManaCommandCode::MANA_QUERY_VPORT_CONFIG => {
                let req: ManaQueryVportCfgReq = read
                    .read_plain()
                    .context("reading query vport config request")?;
                let vport = self
                    .vports
                    .get_mut(req.vport_index as usize)
                    .context("invalid vport")?;

                let resp = ManaQueryVportCfgResp {
                    max_num_sq: 1,
                    max_num_rq: 1,
                    num_indirection_ent: 128,
                    reserved1: 0,
                    mac_addr: vport.mac_address.to_bytes(),
                    reserved2: [0; 2],
                    vport: req.vport_index.into(),
                };

                write.write(resp.as_bytes())?;
                size_of_val(&resp)
            }
            ManaCommandCode::MANA_VTL2_ASSIGN_SERIAL_NUMBER => {
                let req: ManaSetVportSerialNo =
                    read.read_plain().context("set vport serial number")?;
                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;
                vport.serial_no = req.serial_no;
                0
            }
            n => anyhow::bail!("unsupported request {:?}", n),
        };
        Ok(response_len)
    }
}

pub struct TxRxTask {
    queues: Arc<Queues>,
    epqueue: Box<dyn Queue>,
    rx_packets: Arc<Mutex<Slab<RxPacket>>>,
    sq_id: u32,
    sq_cq_id: u32,
    rq_id: u32,
    rq_cq_id: u32,
    tx_segment_buffer: Vec<TxSegment>,
    rx_buf_count: u32,
}

impl InspectTaskMut<TxRxTask> for TxRxState {
    fn inspect_mut(&mut self, req: inspect::Request<'_>, task: Option<&mut TxRxTask>) {
        let mut resp = req.respond();
        if let Some(task) = task {
            resp.field_mut("queue", &mut task.epqueue)
                .field("rx_bufs", task.rx_packets.lock().len());
        }
    }
}

impl TxRxTask {
    async fn process(&mut self) -> anyhow::Result<()> {
        let max_rx_buf = 256;

        enum Event {
            Sqe(Wqe),
            Rqe(u32, Wqe),
            Ready,
        }

        loop {
            let event = poll_fn(|cx| {
                if let Poll::Ready(wqe) = self.queues.poll_sq(self.sq_id, cx) {
                    return Poll::Ready(Event::Sqe(wqe));
                }
                if self.rx_buf_count < max_rx_buf {
                    if let Poll::Ready((wqe_offset, wqe)) = self.queues.poll_rq(self.rq_id, cx) {
                        self.rx_buf_count += 1;
                        return Poll::Ready(Event::Rqe(wqe_offset, wqe));
                    }
                }
                if self.epqueue.poll_ready(cx).is_ready() {
                    return Poll::Ready(Event::Ready);
                }
                Poll::Pending
            })
            .await;
            match event {
                Event::Sqe(sqe) => self.process_sqe(sqe)?,
                Event::Rqe(wqe_offset, wqe) => self.process_rqe(wqe, wqe_offset)?,
                Event::Ready => self.process_backend()?,
            }
        }
    }

    fn process_sqe(&mut self, sqe: Wqe) -> anyhow::Result<()> {
        tracing::trace!("tx wqe");
        let oob = sqe.oob();
        let oob = if oob.len() >= size_of::<ManaTxOob>() {
            ManaTxOob::read_from_prefix(oob).unwrap().0
        } else {
            ManaTxOob {
                // TODO: zerocopy: use details from SizeError in the returned context (https://github.com/microsoft/openvmm/issues/759)
                s_oob: ManaTxShortOob::read_from_prefix(oob)
                    .map_err(|_| anyhow!("oob too small"))?
                    .0,
                ..FromZeros::new_zeroed()
            }
        };

        let sge0 = sqe.sgl().first().context("no sgl")?;
        let total_len: usize = sqe.sgl().iter().map(|sge| sge.size as usize).sum();
        let mut meta = TxMetadata {
            id: TxId(0),
            segment_count: sqe.sgl().len(),
            len: total_len,
            offload_ip_header_checksum: oob.s_oob.comp_iphdr_csum(),
            offload_tcp_checksum: oob.s_oob.comp_tcp_csum(),
            offload_udp_checksum: oob.s_oob.comp_udp_csum(),
            offload_tcp_segmentation: false,
            l3_protocol: if oob.s_oob.is_outer_ipv4() {
                L3Protocol::Ipv4
            } else if oob.s_oob.is_outer_ipv6() {
                L3Protocol::Ipv6
            } else {
                L3Protocol::Unknown
            },
            l2_len: 14,
            l3_len: oob.s_oob.trans_off().clamp(14, 255) - 14,
            l4_len: 0,
            max_tcp_segment_size: 0,
        };

        if sqe.header.params.client_oob_in_sgl() {
            meta.l4_len =
                sge0.size
                    .saturating_sub(meta.l2_len as u32 + meta.l3_len as u32) as u8;
            meta.max_tcp_segment_size = sqe.header.params.gd_client_unit_data();
            meta.offload_tcp_segmentation = true;
        }

        let tx_segments = &mut self.tx_segment_buffer;
        tx_segments.clear();
        tx_segments.push(TxSegment {
            ty: TxSegmentType::Head(meta),
            gpa: sge0.address,
            len: sge0.size,
        });
        for sge in &sqe.sgl()[1..] {
            tx_segments.push(TxSegment {
                ty: TxSegmentType::Tail,
                gpa: sge.address,
                len: sge.size,
            });
        }
        let (sync, count) = self.epqueue.tx_avail(tx_segments)?;
        if sync || count == 0 {
            tracing::trace!("tx sync complete");
            self.post_tx_completion();
        }
        Ok(())
    }

    fn post_tx_completion(&mut self) {
        let tx_oob = ManaTxCompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_client_type(MANA_CQE_COMPLETION)
                .with_cqe_type(CQE_TX_OKAY),
            tx_data_offset: 0,
            offsets: ManaTxCompOobOffsets::new(),
            reserved: [0; 12],
        };
        self.queues
            .post_cq(self.sq_cq_id, tx_oob.as_bytes(), self.sq_id, true);
    }

    fn process_rqe(&mut self, wqe: Wqe, wqe_offset: u32) -> anyhow::Result<()> {
        let segments = wqe
            .sgl()
            .iter()
            .map(|sge| RxBufferSegment {
                gpa: sge.address,
                len: sge.size,
            })
            .collect();

        let len = wqe.sgl().iter().map(|sge| sge.size).sum();
        tracing::trace!(?segments, len, "rx wqe");
        let packet = RxPacket {
            segments,
            len,
            wqe_offset,
            oob: FromZeros::new_zeroed(),
        };
        let id = RxId(self.rx_packets.lock().insert(packet) as u32);
        self.epqueue.rx_avail(&[id]);
        Ok(())
    }

    fn process_backend(&mut self) -> anyhow::Result<()> {
        let mut packets = [RxId(0)];
        if self.epqueue.rx_poll(&mut packets)? > 0 {
            tracing::trace!("rx complete");
            let packet = self
                .rx_packets
                .lock()
                .try_remove(packets[0].0 as usize)
                .context("invalid rx id")?;

            self.queues
                .post_cq(self.rq_cq_id, packet.oob.as_bytes(), self.rq_id, false);

            self.rx_buf_count -= 1;
        }

        let mut packets = [TxId(0)];
        if self.epqueue.tx_poll(&mut packets)? > 0 {
            tracing::trace!("tx async complete");
            self.post_tx_completion();
        }

        Ok(())
    }
}

struct TxRxState;

impl AsyncRun<TxRxTask> for TxRxState {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        task: &mut TxRxTask,
    ) -> Result<(), task_control::Cancelled> {
        stop.until_stopped(async {
            if let Err(err) = task.process().await {
                tracing::error!(err = err.as_ref() as &dyn std::error::Error, "bnic failure");
            }
        })
        .await
    }
}
