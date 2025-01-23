// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interface to the common MANA commands.
use crate::queues::Cq;
use crate::queues::Doorbell;
use crate::queues::DoorbellPage;
use crate::queues::Eq;
use crate::queues::Wq;
use crate::resources::Resource;
use crate::resources::ResourceArena;
use anyhow::Context;
use futures::FutureExt;
use gdma_defs::Cqe;
use gdma_defs::EqeDataReconfig;
use gdma_defs::EstablishHwc;
use gdma_defs::GdmaChangeMsixVectorIndexForEq;
use gdma_defs::GdmaCreateDmaRegionReq;
use gdma_defs::GdmaCreateDmaRegionResp;
use gdma_defs::GdmaCreateQueueReq;
use gdma_defs::GdmaCreateQueueResp;
use gdma_defs::GdmaDestroyDmaRegionReq;
use gdma_defs::GdmaDevId;
use gdma_defs::GdmaDisableQueueReq;
use gdma_defs::GdmaGenerateTestEventReq;
use gdma_defs::GdmaListDevicesResp;
use gdma_defs::GdmaMsgHdr;
use gdma_defs::GdmaQueryMaxResourcesResp;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaRegisterDeviceResp;
use gdma_defs::GdmaReqHdr;
use gdma_defs::GdmaRequestType;
use gdma_defs::GdmaRespHdr;
use gdma_defs::GdmaVerifyVerReq;
use gdma_defs::GdmaVerifyVerResp;
use gdma_defs::HwcInitEqIdDb;
use gdma_defs::HwcInitTypeData;
use gdma_defs::HwcTxOob;
use gdma_defs::HwcTxOobFlags3;
use gdma_defs::HwcTxOobFlags4;
use gdma_defs::RegMap;
use gdma_defs::Sge;
use gdma_defs::SmcMessageType;
use gdma_defs::SmcProtoHdr;
use gdma_defs::DRIVER_CAP_FLAG_1_HWC_TIMEOUT_RECONFIG;
use gdma_defs::DRIVER_CAP_FLAG_1_HW_VPORT_LINK_AWARE;
use gdma_defs::DRIVER_CAP_FLAG_1_VARIABLE_INDIRECTION_TABLE_SUPPORT;
use gdma_defs::GDMA_EQE_COMPLETION;
use gdma_defs::GDMA_EQE_HWC_INIT_DATA;
use gdma_defs::GDMA_EQE_HWC_INIT_DONE;
use gdma_defs::GDMA_EQE_HWC_INIT_EQ_ID_DB;
use gdma_defs::GDMA_EQE_HWC_RECONFIG_DATA;
use gdma_defs::GDMA_EQE_TEST_EVENT;
use gdma_defs::GDMA_MESSAGE_V1;
use gdma_defs::GDMA_PAGE_TYPE_4K;
use gdma_defs::GDMA_STANDARD_HEADER_TYPE;
use gdma_defs::HWC_DATA_CONFIG_HWC_TIMEOUT;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT;
use gdma_defs::HWC_DEV_ID;
use gdma_defs::HWC_INIT_DATA_CQID;
use gdma_defs::HWC_INIT_DATA_GPA_MKEY;
use gdma_defs::HWC_INIT_DATA_PDID;
use gdma_defs::HWC_INIT_DATA_RQID;
use gdma_defs::HWC_INIT_DATA_SQID;
use gdma_defs::SMC_MSG_TYPE_DESTROY_HWC_VERSION;
use gdma_defs::SMC_MSG_TYPE_ESTABLISH_HWC_VERSION;
use gdma_defs::SMC_MSG_TYPE_REPORT_HWC_TIMEOUT_VERSION;
use inspect::Inspect;
use pal_async::driver::Driver;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use std::time::Duration;
use user_driver::backoff::Backoff;
use user_driver::interrupt::DeviceInterrupt;
use user_driver::memory::MemoryBlock;
use user_driver::memory::PAGE_SIZE;
use user_driver::memory::PAGE_SIZE64;
use user_driver::DeviceBacking;
use user_driver::DeviceRegisterIo;
use user_driver::HostDmaAllocator;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

const HWC_WARNING_TIME_IN_MS: u32 = 3000;
const HWC_TIMEOUT_DEFAULT_IN_MS: u32 = 10000;
const HWC_TIMEOUT_FOR_SHUTDOWN_IN_MS: u32 = 100;
const HWC_POLL_TIMEOUT_IN_MS: u64 = 10000;

#[derive(Inspect)]
struct Bar0<T: Inspect> {
    mem: T,
    map: RegMap,
    doorbell_shift: u32,
}

impl<T: DeviceRegisterIo + Inspect> Doorbell for Bar0<T> {
    fn page_count(&self) -> u32 {
        self.mem
            .len()
            .saturating_sub(self.map.vf_db_pages_zone_offset as usize) as u32
            >> self.doorbell_shift
    }

    fn write(&self, page_number: u32, address: u32, value: u64) {
        let offset = self.map.vf_db_pages_zone_offset
            + ((page_number as u64) << self.doorbell_shift)
            + address as u64;
        tracing::trace!(page_number, address, offset, value, "doorbell");

        // Ensure the doorbell write is ordered after the writes to the queues.
        safe_intrinsics::store_fence();
        self.mem.write_u64(offset as usize, value);
    }
}

#[derive(Inspect)]
pub struct GdmaDriver<T: DeviceBacking> {
    device: Option<T>,
    bar0: Arc<Bar0<T::Registers>>,
    #[inspect(skip)]
    dma_buffer: MemoryBlock,
    #[inspect(skip)]
    interrupts: Vec<Option<DeviceInterrupt>>,
    eq: Eq,
    cq: Cq,
    rq: Wq,
    sq: Wq,
    test_events: u64,
    eq_armed: bool,
    cq_armed: bool,
    gpa_mkey: u32,
    _pdid: u32,
    #[inspect(iter_by_key)]
    eq_id_msix: HashMap<u32, u32>,
    num_msix: u32,
    min_queue_avail: u32,
    hwc_activity_id: u32,
    #[inspect(skip)]
    link_toggle: Vec<(u32, bool)>,
    hwc_subscribed: bool,
    hwc_warning_time_in_ms: u32,
    hwc_timeout_in_ms: u32,
    hwc_failure: bool,
}

const EQ_PAGE: usize = 0;
const CQ_PAGE: usize = 1;
const RQ_PAGE: usize = 2;
const SQ_PAGE: usize = 3;
const REQUEST_PAGE: usize = 4;
const RESPONSE_PAGE: usize = 5;
const NUM_PAGES: usize = 6;

// RWQEs have no OOB and one SGL entry so they are always exactly 32 bytes.
const RWQE_SIZE: u32 = 32;

impl<T: DeviceBacking> Drop for GdmaDriver<T> {
    fn drop(&mut self) {
        if self.hwc_failure {
            return;
        }
        let data = self
            .bar0
            .mem
            .read_u32(self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28);
        if data == u32::MAX {
            tracing::error!("Device no longer present");
            return;
        }

        let hdr = SmcProtoHdr::new()
            .with_msg_type(SmcMessageType::SMC_MSG_TYPE_DESTROY_HWC.0)
            .with_msg_version(SMC_MSG_TYPE_DESTROY_HWC_VERSION);

        let hdr = u32::from_le_bytes(hdr.as_bytes().try_into().expect("known size"));
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28,
            hdr,
        );
        // Wait for the device to respond.
        let max_wait_time =
            std::time::Instant::now() + Duration::from_millis(HWC_POLL_TIMEOUT_IN_MS);
        let header = loop {
            let data = self
                .bar0
                .mem
                .read_u32(self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28);
            if data == u32::MAX {
                tracing::error!("Device no longer present");
                return;
            }
            let header = SmcProtoHdr::from(data);
            if !header.owner_is_pf() {
                break header;
            }
            if std::time::Instant::now() > max_wait_time {
                tracing::error!("MANA request timed out. SMC_MSG_TYPE_DESTROY_HWC");
                return;
            }
            std::hint::spin_loop();
        };

        if !header.is_response() {
            tracing::error!("expected response");
        }
        if header.status() != 0 {
            tracing::error!("DESTROY_HWC failed: {}", header.status());
        }
    }
}

impl<T: DeviceBacking> GdmaDriver<T> {
    pub fn doorbell(&self) -> Arc<dyn Doorbell> {
        self.bar0.clone() as _
    }

    pub async fn new(driver: &impl Driver, mut device: T, num_vps: u32) -> anyhow::Result<Self> {
        let bar0_mapping = device.map_bar(0)?;
        let bar0_len = bar0_mapping.len();
        if bar0_len < size_of::<RegMap>() {
            anyhow::bail!("bar0 ({} bytes) too small for reg map", bar0_mapping.len());
        }
        // Only allocate the HWC interrupt now. Rest will be allocated later.
        let num_msix = 1;
        let mut interrupt0 = device.map_interrupt(0, 0)?;
        let mut map = RegMap::new_zeroed();
        for i in 0..size_of_val(&map) / 4 {
            let v = bar0_mapping.read_u32(i * 4);
            // Unmapped device memory will return -1 on reads, so check the first 32
            // bits for this condition to get a clear error message early.
            if i == 0 && v == !0 {
                anyhow::bail!("bar0 read returned -1, device is not present");
            }
            map.as_bytes_mut()[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
        }

        tracing::debug!(?map, "register map");

        // Log on unknown major version numbers. This is not necessarily an
        // error, so continue.
        if map.major_version_number != 0 && map.major_version_number != 1 {
            tracing::warn!(
                major = map.major_version_number,
                minor = map.minor_version_number,
                micro = map.micro_version_number,
                "unrecognized major version"
            );
        }

        if map.vf_gdma_sriov_shared_sz != 32 {
            anyhow::bail!(
                "unexpected shared memory size: {}",
                map.vf_gdma_sriov_shared_sz
            );
        }

        if (bar0_len as u64).saturating_sub(map.vf_gdma_sriov_shared_reg_start)
            < map.vf_gdma_sriov_shared_sz as u64
        {
            anyhow::bail!(
                "bar0 ({} bytes) too small for shared memory at {}",
                bar0_mapping.len(),
                map.vf_gdma_sriov_shared_reg_start
            );
        }

        let dma_buffer = device
            .host_allocator()
            .allocate_dma_buffer(NUM_PAGES * PAGE_SIZE)?;
        let pages = dma_buffer.pfns();

        // Write the shared memory.
        fn low(n: u64) -> [u8; 6] {
            let n = n.to_ne_bytes();
            [n[0], n[1], n[2], n[3], n[4], n[5]]
        }

        let high = ((pages[EQ_PAGE] >> 48) & 0xf)
            | ((pages[CQ_PAGE] >> 44) & 0xf0)
            | ((pages[RQ_PAGE] >> 40) & 0xf00)
            | ((pages[SQ_PAGE] >> 36) & 0xf000);

        let establish = EstablishHwc {
            eq: low(pages[EQ_PAGE]),
            cq: low(pages[CQ_PAGE]),
            rq: low(pages[RQ_PAGE]),
            sq: low(pages[SQ_PAGE]),
            high: high as u16,
            msix: 0,
            hdr: SmcProtoHdr::new()
                .with_msg_type(SmcMessageType::SMC_MSG_TYPE_ESTABLISH_HWC.0)
                .with_msg_version(SMC_MSG_TYPE_ESTABLISH_HWC_VERSION),
        };

        let shmem = u32::slice_from(establish.as_bytes()).unwrap();
        assert!(shmem.len() == 8);
        for (i, &n) in shmem.iter().enumerate() {
            bar0_mapping.write_u32(map.vf_gdma_sriov_shared_reg_start as usize + i * 4, n);
        }

        // Wait for the device to respond.
        let mut backoff = Backoff::new(driver);
        let mut ctx =
            mesh::CancelContext::new().with_timeout(Duration::from_millis(HWC_POLL_TIMEOUT_IN_MS));
        let mut hw_failure = false;
        let header = loop {
            let header = SmcProtoHdr::from(
                bar0_mapping.read_u32(map.vf_gdma_sriov_shared_reg_start as usize + 28),
            );
            if !header.owner_is_pf() {
                break header;
            }
            if hw_failure {
                anyhow::bail!("MANA request timed out. SMC_MSG_TYPE_ESTABLISH_HWC");
            }
            hw_failure = matches!(
                ctx.until_cancelled(backoff.back_off()).await,
                Err(mesh::CancelReason::DeadlineExceeded)
            );
        };

        if !header.is_response() {
            anyhow::bail!("expected response");
        }
        if header.status() != 0 {
            anyhow::bail!("establish failed: {}", header.status());
        }

        let doorbell_shift = map.vf_db_page_sz.trailing_zeros();
        let bar0 = Arc::new(Bar0 {
            mem: bar0_mapping,
            map,
            doorbell_shift,
        });

        let mut eq = Eq::new_eq(dma_buffer.subblock(0, PAGE_SIZE), DoorbellPage::null(), 0);

        let mut cq_id = None;
        let mut rq_id = None;
        let mut sq_id = None;
        let mut db_id = None;
        let mut pdid = None;
        let mut gpa_mkey = None;
        let mut eq_armed = true;
        loop {
            let eqe = loop {
                if let Some(eqe) = eq.pop() {
                    eq_armed = false;
                    break eqe;
                }
                if !eq_armed {
                    eq.arm();
                    eq_armed = true;
                    // Check if the event arrived while arming.
                    if let Some(eqe) = eq.pop() {
                        // Remove any pending interrupt events.
                        let _ = interrupt0.wait().now_or_never();
                        eq_armed = false;
                        break eqe;
                    }
                }
                tracing::debug!("waiting for eq interrupt");
                Self::wait_for_hwc_interrupt(&mut interrupt0, None, HWC_TIMEOUT_DEFAULT_IN_MS)
                    .await?;
            };
            tracing::debug!(event_type = eqe.params.event_type(), "got init eqe");
            match eqe.params.event_type() {
                GDMA_EQE_HWC_INIT_EQ_ID_DB => {
                    let data = HwcInitEqIdDb::read_from_prefix(&eqe.data[..]).unwrap();
                    eq.set_id(data.eq_id().into());
                    eq.set_doorbell(DoorbellPage::new(bar0.clone(), data.doorbell().into())?);
                    db_id = Some(data.doorbell());
                }
                GDMA_EQE_HWC_INIT_DATA => {
                    let data = HwcInitTypeData::read_from_prefix(&eqe.data[..]).unwrap();
                    match data.ty() {
                        HWC_INIT_DATA_CQID => cq_id = Some(data.value()),
                        HWC_INIT_DATA_RQID => rq_id = Some(data.value()),
                        HWC_INIT_DATA_SQID => sq_id = Some(data.value()),
                        HWC_INIT_DATA_GPA_MKEY => gpa_mkey = Some(data.value()),
                        HWC_INIT_DATA_PDID => pdid = Some(data.value()),
                        _ => {}
                    }
                }
                GDMA_EQE_HWC_INIT_DONE => {
                    break;
                }
                ty => anyhow::bail!("unexpected event type {}", ty),
            }
        }

        // Ack the eq now to avoid overflow. This wasn't safe to do earlier
        // because we didn't know the eq's doorbell index yet.
        eq.ack();

        // From here on, the interrupt events have moved to the msix channel
        tracing::debug!("init sequence done");

        // Start the HWC notify channel for now. Rest of the notify channels
        // will be started later once it is known how many MSI-X are actually
        // available.
        let mut eq_id_msix = HashMap::new();
        eq_id_msix.insert(eq.id(), 0);
        tracing::info!("Created HWC with eq id: {}, msix: 0", eq.id());

        let db_id = db_id.context("db id not provided")? as u32;
        let gpa_mkey = gpa_mkey.context("gpa mem key not provided")?;
        let pdid = pdid.context("pdid not provided")?;

        let cq_id = cq_id.context("cq id not provided")?;
        let cq = Cq::new_cq(
            dma_buffer.subblock(CQ_PAGE * PAGE_SIZE, PAGE_SIZE),
            DoorbellPage::new(bar0.clone(), db_id)?,
            cq_id,
        );

        let rq_id = rq_id.context("rq id not provided")?;
        let rq = Wq::new_rq(
            dma_buffer.subblock(RQ_PAGE * PAGE_SIZE, PAGE_SIZE),
            DoorbellPage::new(bar0.clone(), db_id)?,
            rq_id,
        );

        let sq_id = sq_id.context("sq id not provided")?;
        let sq = Wq::new_sq(
            dma_buffer.subblock(SQ_PAGE * PAGE_SIZE, PAGE_SIZE),
            DoorbellPage::new(bar0.clone(), db_id)?,
            sq_id,
        );

        // To make debugging from the device side easier, randomize the upper
        // 16 bits of the ActivityId, so that requests can be distinguished.
        let mut rand_activity_id = [0_u8; 2];
        getrandom::getrandom(&mut rand_activity_id).unwrap();
        let hwc_activity_id = (u16::from_ne_bytes(rand_activity_id) as u32) << 16;
        let mut this = Self {
            device: Some(device),
            bar0,
            dma_buffer,
            eq,
            cq,
            rq,
            sq,
            interrupts: vec![Some(interrupt0)],
            test_events: 0,
            eq_armed,
            cq_armed: true,
            gpa_mkey,
            _pdid: pdid,
            eq_id_msix,
            num_msix,
            min_queue_avail: 0,
            hwc_activity_id,
            link_toggle: Vec::new(),
            hwc_subscribed: false,
            hwc_warning_time_in_ms: HWC_WARNING_TIME_IN_MS,
            hwc_timeout_in_ms: HWC_TIMEOUT_DEFAULT_IN_MS,
            hwc_failure: false,
        };

        this.push_rqe();

        let max_vf_resources = this
            .query_max_resources()
            .await
            .context("query_max_resources")?;
        tracing::info!("Max VF resources: {:?}", max_vf_resources);

        let device = this.device.as_mut().expect("device should be present");
        let num_msix = num_vps
            .min(max_vf_resources.max_msix)
            .min(device.max_interrupt_count());
        this.interrupts.resize_with(num_msix as usize, || None);
        this.num_msix = num_msix;
        this.min_queue_avail = max_vf_resources
            .max_eq
            .min(max_vf_resources.max_sq)
            .min(max_vf_resources.max_rq);

        Ok(this)
    }

    async fn report_hwc_timeout(&mut self, last_cmd_failed: bool, ms_elapsed_for_interrupt: u32) {
        // Perform initial check for ownership, failing without wait if device
        // is not present or owns shmem region
        let data = self
            .bar0
            .mem
            .read_u32(self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28);
        if data == u32::MAX {
            tracing::error!("Device no longer present");
            return;
        }
        let header = SmcProtoHdr::from(data);
        if header.owner_is_pf() {
            tracing::error!("pf owns shmem; skipping timeout report");
            return;
        }

        // Format and write payload information in the first seven 32-bit ranges
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize,
            self.rq.get_tail(),
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 4,
            self.sq.get_tail(),
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 8,
            self.cq.get_next(),
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 12,
            self.eq.get_next(),
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 16,
            0,
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 20,
            0,
        );
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 24,
            ((last_cmd_failed as u32) << 24) | (ms_elapsed_for_interrupt & 0xFFFFFF),
        );

        // Format and write header information in final 32-bit range, flipping
        // ownership to device for processing
        let msg_type = SmcMessageType::SMC_MSG_TYPE_REPORT_HWC_TIMEOUT.0;
        let hdr = SmcProtoHdr::new()
            .with_msg_type(msg_type)
            .with_msg_version(SMC_MSG_TYPE_REPORT_HWC_TIMEOUT_VERSION);
        let hdr = u32::from_le_bytes(hdr.as_bytes().try_into().expect("known size"));
        self.bar0.mem.write_u32(
            self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28,
            hdr,
        );

        // Wait for the device to respond
        let max_wait_time =
            std::time::Instant::now() + Duration::from_millis(HWC_POLL_TIMEOUT_IN_MS);
        let header = loop {
            let data = self
                .bar0
                .mem
                .read_u32(self.bar0.map.vf_gdma_sriov_shared_reg_start as usize + 28);
            if data == u32::MAX {
                tracing::error!(msg_type, "device no longer present");
                return;
            }
            let header = SmcProtoHdr::from(data);
            if !header.owner_is_pf() {
                break header;
            }
            if std::time::Instant::now() > max_wait_time {
                tracing::error!(msg_type, "shmem wait for response (vf ownership) timed out");
                return;
            }
            std::hint::spin_loop();
        };
        if !header.is_response() {
            tracing::error!(msg_type, "expected shmem response");
        }
        if header.status() != 0 {
            tracing::error!(msg_type, "response failed status={}", header.status());
        }
    }

    pub fn get_link_toggle_list(&mut self) -> Vec<(u32, bool)> {
        self.link_toggle.drain(..).collect()
    }

    pub fn device(&self) -> &T {
        self.device.as_ref().unwrap()
    }

    pub fn check_vf_resources(&self, num_vps: u32, num_queues_needed: u32) {
        // Currently, the SoC and the MANA UMED caps the MSI-X/VF to 32,
        // independent of the number of vNICs configured.
        if self.num_msix < num_vps.min(num_queues_needed) {
            tracing::warn!(
                num_queues_needed,
                self.num_msix,
                "Not enough MSI-X available to deliver required MANA network performance"
            )
        }

        if num_queues_needed > self.min_queue_avail {
            tracing::error!(
                num_queues_needed,
                self.min_queue_avail,
                "Not enough EQ's available to support all vNICs"
            )
        }
    }

    fn push_rqe(&mut self) {
        let n = self
            .rq
            .push(
                &(),
                [Sge {
                    address: self.dma_buffer.pfns()[RESPONSE_PAGE] * PAGE_SIZE64,
                    mem_key: self.gpa_mkey,
                    size: PAGE_SIZE as u32,
                }],
                None,
                0,
            )
            .expect("rq is not full");
        assert_eq!(n, RWQE_SIZE);
        self.rq.commit();
    }

    pub async fn request_version<Req: AsBytes, Resp: AsBytes + FromBytes>(
        &mut self,
        req_msg_type: u32,
        req_msg_version: u16,
        resp_msg_type: u32,
        resp_msg_version: u16,
        dev_id: GdmaDevId,
        req: Req,
    ) -> anyhow::Result<(Resp, u32)> {
        if self.hwc_failure {
            anyhow::bail!("Previous hardware failure");
        }
        let req_hdr = GdmaMsgHdr {
            hdr_type: GDMA_STANDARD_HEADER_TYPE,
            msg_type: req_msg_type,
            msg_version: req_msg_version,
            hwc_msg_id: 0,
            msg_size: (size_of::<GdmaReqHdr>() + size_of_val(&req)) as u32,
        };
        let expected_resp_hdr = GdmaMsgHdr {
            msg_type: resp_msg_type,
            msg_version: resp_msg_version,
            msg_size: (size_of::<GdmaRespHdr>() + size_of::<Resp>()) as u32,
            ..req_hdr
        };
        self.hwc_activity_id = self.hwc_activity_id.wrapping_add(1);
        let hdr = GdmaReqHdr {
            req: req_hdr,
            resp: expected_resp_hdr,
            dev_id,
            activity_id: self.hwc_activity_id,
        };

        tracing::trace!(
            request = format!("{:#x}", req_msg_type),
            activity_id = format!("{:#x}", hdr.activity_id),
            "HWC request",
        );
        self.dma_buffer.write_obj(REQUEST_PAGE * PAGE_SIZE, &hdr);
        self.dma_buffer
            .write_obj(REQUEST_PAGE * PAGE_SIZE + size_of_val(&hdr), &req);

        let oob = HwcTxOob {
            flags3: HwcTxOobFlags3::new().with_vscq_id(self.cq.id()),
            flags4: HwcTxOobFlags4::new().with_vsq_id(self.sq.id()),
            ..FromZeroes::new_zeroed()
        };

        let hw_access = async {
            let sqe_len = self
                .sq
                .push(
                    &oob,
                    [Sge {
                        address: self.dma_buffer.pfns()[REQUEST_PAGE] * PAGE_SIZE64,
                        mem_key: self.gpa_mkey,
                        size: (size_of_val(&hdr) + size_of_val(&req)) as u32,
                    }],
                    None,
                    0,
                )
                .expect("send queue should not be full");

            self.sq.commit();
            let req_phys_addr = self.dma_buffer.pfns()[REQUEST_PAGE] * PAGE_SIZE64;
            let sgl_phys_addr = self.dma_buffer.pfns()[SQ_PAGE] * PAGE_SIZE64;
            let mem_key = self.gpa_mkey;
            let cq_wait_context = || {
                format!(
                    "HWC request failed. request={:#x}, activity_id={:#x}, queue_phys_addr={:#x}, req_phys_addr={:#x}, write_size={}, mem_key={:#x}",
                    req_msg_type,
                    hdr.activity_id,
                    sgl_phys_addr,
                    req_phys_addr,
                    size_of_val(&hdr) + size_of_val(&req),
                    mem_key,
                )
            };
            self.wait_cq().await.with_context(cq_wait_context)?;
            self.wait_cq().await.with_context(cq_wait_context)?;
            self.sq.advance_head(sqe_len);
            self.rq.advance_head(RWQE_SIZE);
            self.push_rqe();

            let resp_hdr = self
                .dma_buffer
                .read_obj::<GdmaRespHdr>(RESPONSE_PAGE * PAGE_SIZE);

            if resp_hdr.response.msg_size < size_of::<Resp>() as u32 {
                anyhow::bail!(
                    "response too small, request={:#x}, activity_id={:#x}",
                    req_msg_type,
                    hdr.activity_id
                );
            }
            if resp_hdr.status != 0 {
                anyhow::bail!(
                    "failed with {:#x}, request={:#x}, activity_id={:#x}",
                    resp_hdr.status,
                    req_msg_type,
                    hdr.activity_id
                );
            }

            let resp = self
                .dma_buffer
                .read_obj::<Resp>(RESPONSE_PAGE * PAGE_SIZE + size_of_val(&resp_hdr));
            Ok(resp)
        };
        let resp = match hw_access.await {
            Ok(resp) => resp,
            Err(err) => {
                self.hwc_failure = true;
                return Err(err);
            }
        };

        tracing::trace!(
            request = format!("{:#x}", req_msg_type),
            activity_id = format!("{:#x}", hdr.activity_id),
            "HWC response success",
        );
        Ok((resp, self.hwc_activity_id))
    }

    pub async fn request<Req: AsBytes, Resp: AsBytes + FromBytes>(
        &mut self,
        msg_type: u32,
        dev_id: GdmaDevId,
        req: Req,
    ) -> anyhow::Result<Resp> {
        let (resp, _) = self
            .request_version(
                msg_type,
                GDMA_MESSAGE_V1,
                msg_type,
                GDMA_MESSAGE_V1,
                dev_id,
                req,
            )
            .await?;

        Ok(resp)
    }

    pub fn hwc_subscribe(&mut self) -> DeviceInterrupt {
        let interrupt = self.interrupts[0].clone().unwrap();
        if !self.eq_armed {
            self.eq.arm();
            self.eq_armed = true;
        }
        self.hwc_subscribed = true;
        interrupt
    }

    pub fn process_all_eqs(&mut self) -> bool {
        let mut eq_found = false;
        while let Some(eqe) = self.eq.pop() {
            self.eq_armed = false;
            eq_found = true;
            match eqe.params.event_type() {
                GDMA_EQE_COMPLETION => self.cq_armed = false,
                GDMA_EQE_TEST_EVENT => self.test_events += 1,
                GDMA_EQE_HWC_RECONFIG_DATA => {
                    let data = EqeDataReconfig::read_from_prefix(&eqe.data[..]).unwrap();
                    let mut value: [u8; 4] = [0; 4];
                    value[0..3].copy_from_slice(&data.data);
                    let value: u32 = u32::from_le_bytes(value);
                    match data.data_type {
                        HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT
                        | HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT => {
                            let link_connect =
                                data.data_type == HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT;
                            self.link_toggle.push((value, link_connect));
                            tracing::trace!(value, link_connect, "link status: vport index");
                        }
                        HWC_DATA_CONFIG_HWC_TIMEOUT => {
                            self.hwc_timeout_in_ms = value;
                            tracing::info!(
                                hwc_timeout_in_ms = self.hwc_timeout_in_ms,
                                "HWC timeout value"
                            );
                        }
                        unknown => tracing::error!(unknown, "unknown reconfig data type."),
                    }
                }
                ty => tracing::error!("unknown eq event {}", ty),
            }
            self.eq.ack();
        }

        if !self.eq_armed && self.hwc_subscribed {
            self.eq.arm();
            self.eq_armed = true;
        }
        eq_found
    }

    async fn wait_for_hwc_interrupt(
        hwc_event: &mut DeviceInterrupt,
        hwc_failure: Option<&mut bool>,
        hwc_timeout_in_ms: u32,
    ) -> anyhow::Result<()> {
        let mut ctx = mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(hwc_timeout_in_ms as u64));
        if let Err(err) = ctx.until_cancelled(hwc_event.wait()).await {
            if let Some(failed) = hwc_failure {
                *failed = true;
            }
            return Err(err).context("MANA request timed out. Waiting for HWC interrupt.");
        };

        Ok(())
    }

    async fn process_eqs_or_wait(&mut self) -> anyhow::Result<()> {
        loop {
            if self.process_all_eqs() {
                return Ok(());
            }

            if !self.eq_armed {
                tracing::trace!("arming eq");
                self.eq.arm();
                self.eq_armed = true;
                // Check if the event arrived while arming.
                if self.process_all_eqs() {
                    // Remove any pending interrupt events.
                    let _ = self.interrupts[0].as_mut().unwrap().wait().now_or_never();
                    return Ok(());
                }
            }
            tracing::trace!("waiting for eq interrupt");
            let before_wait = std::time::Instant::now();
            let wait_result = Self::wait_for_hwc_interrupt(
                self.interrupts[0].as_mut().unwrap(),
                Some(&mut self.hwc_failure),
                self.hwc_timeout_in_ms,
            )
            .await;

            let wait_failed = wait_result.is_err();
            let elapsed: u128 = before_wait.elapsed().as_millis();
            if wait_failed || elapsed > self.hwc_warning_time_in_ms as u128 {
                tracing::warn!(
                    wait_failed,
                    elapsed,
                    self.hwc_warning_time_in_ms,
                    "hwc {}",
                    match wait_failed {
                        true => "timeout",
                        false => "delay warning",
                    }
                );
                self.report_hwc_timeout(wait_failed, elapsed as u32).await;
                if !wait_failed {
                    // Increase warning threshold after each warning occurrence
                    self.hwc_warning_time_in_ms += HWC_WARNING_TIME_IN_MS;
                }
            }

            if wait_failed {
                return wait_result;
            }
        }
    }

    async fn wait_cq(&mut self) -> anyhow::Result<Cqe> {
        loop {
            if let Some(cqe) = self.cq.pop() {
                self.cq_armed = false;
                return Ok(cqe);
            }
            if !self.cq_armed {
                self.cq.arm();
                self.cq_armed = true;
                // Check if the event arrived while arming.
                if let Some(cqe) = self.cq.pop() {
                    // Consume any EQ events.
                    self.process_all_eqs();
                    self.cq_armed = false;
                    // Remove any pending interrupt events.
                    let _ = self.interrupts[0].as_mut().unwrap().wait().now_or_never();
                    return Ok(cqe);
                }
            }
            self.process_eqs_or_wait().await?;
        }
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub async fn test_eq(&mut self) -> anyhow::Result<()> {
        let n = self.test_events;
        self.request::<_, ()>(
            GdmaRequestType::GDMA_GENERATE_TEST_EQE.0,
            HWC_DEV_ID,
            GdmaGenerateTestEventReq {
                queue_index: self.eq.id(),
            },
        )
        .await?;
        while self.test_events == n {
            self.process_eqs_or_wait().await.with_context(|| {
                format!(
                    "HWC request failed. request={:#x}, activity_id={:#x}",
                    GdmaRequestType::GDMA_GENERATE_TEST_EQE.0,
                    self.hwc_activity_id
                )
            })?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub async fn verify_vf_driver_version(&mut self) -> anyhow::Result<()> {
        let resp: GdmaVerifyVerResp = self
            .request(
                GdmaRequestType::GDMA_VERIFY_VF_DRIVER_VERSION.0,
                HWC_DEV_ID,
                GdmaVerifyVerReq {
                    protocol_ver_min: 1,
                    protocol_ver_max: 1,
                    gd_drv_cap_flags1: DRIVER_CAP_FLAG_1_VARIABLE_INDIRECTION_TABLE_SUPPORT
                        | DRIVER_CAP_FLAG_1_HW_VPORT_LINK_AWARE
                        | DRIVER_CAP_FLAG_1_HWC_TIMEOUT_RECONFIG,
                    ..FromZeroes::new_zeroed()
                },
            )
            .await?;

        if resp.gdma_protocol_ver != 1 {
            anyhow::bail!("invalid protocol version");
        }
        Ok(())
    }

    pub async fn query_max_resources(&mut self) -> anyhow::Result<GdmaQueryMaxResourcesResp> {
        self.request(GdmaRequestType::GDMA_QUERY_MAX_RESOURCES.0, HWC_DEV_ID, ())
            .await
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub async fn list_devices(&mut self) -> anyhow::Result<Vec<GdmaDevId>> {
        let resp: GdmaListDevicesResp = self
            .request(GdmaRequestType::GDMA_LIST_DEVICES.0, HWC_DEV_ID, ())
            .await?;
        Ok(resp.devs[..resp.num_of_devs as usize].to_vec())
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub async fn register_device(
        &mut self,
        dev_id: GdmaDevId,
    ) -> anyhow::Result<GdmaRegisterDeviceResp> {
        self.request(GdmaRequestType::GDMA_REGISTER_DEVICE.0, dev_id, ())
            .await
    }

    pub async fn deregister_device(&mut self, dev_id: GdmaDevId) -> anyhow::Result<()> {
        self.hwc_timeout_in_ms = HWC_TIMEOUT_FOR_SHUTDOWN_IN_MS;
        self.request(GdmaRequestType::GDMA_DEREGISTER_DEVICE.0, dev_id, ())
            .await
    }

    pub fn into_device(mut self) -> T {
        self.device.take().unwrap()
    }

    fn start_listening(&mut self, eq_id: u32, msix: u32) -> DeviceInterrupt {
        let interrupt = self.interrupts[msix as usize]
            .clone()
            .expect("MSI-X should be present");
        if self.eq_id_msix.insert(eq_id, msix).is_some() {
            panic!(
                "duplicate eq id {}, [id, msix] {:?}",
                eq_id, &self.eq_id_msix
            );
        }
        interrupt
    }

    fn stop_listening(&mut self, eq_id: u32) {
        self.eq_id_msix.remove(&eq_id);
    }

    fn get_msix_for_cpu(&mut self, cpu: u32) -> anyhow::Result<u32> {
        let msix = cpu % self.num_msix;
        // Allocate MSI-X, if it hasn't been allocated so far.
        if self.interrupts[msix as usize].is_none() {
            let device = self.device.as_mut().expect("device should be present");
            let interrupt = device.map_interrupt(msix, cpu)?;
            self.interrupts[msix as usize] = Some(interrupt);
        }

        Ok(msix)
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub async fn retarget_eq(
        &mut self,
        dev_id: GdmaDevId,
        eq_id: u32,
        cpu: u32,
    ) -> anyhow::Result<Option<DeviceInterrupt>> {
        let msix_to = self.get_msix_for_cpu(cpu)?;
        tracing::info!("retargeting EQ {} to cpu: {}", eq_id, cpu);
        if let Some(msix) = self.eq_id_msix.get(&eq_id) {
            if *msix == msix_to {
                tracing::trace!("eq is already mapped to this msix, skipping");
                return Ok(None);
            }
        }
        self.stop_listening(eq_id);
        self.request::<_, ()>(
            GdmaRequestType::GDMA_CHANGE_MSIX_FOR_EQ.0,
            dev_id,
            GdmaChangeMsixVectorIndexForEq {
                queue_index: eq_id,
                msix: msix_to,
                reserved1: 0,
                reserved2: 0,
            },
        )
        .await?;
        let interrupt = self.start_listening(eq_id, msix_to);
        Ok(Some(interrupt))
    }

    #[tracing::instrument(skip(self, arena), level = "debug", err)]
    pub async fn create_eq(
        &mut self,
        arena: &mut ResourceArena,
        dev_id: GdmaDevId,
        gdma_region: u64,
        queue_size: u32,
        pdid: u32,
        doorbell_id: u32,
        cpu: u32,
    ) -> anyhow::Result<(u32, DeviceInterrupt)> {
        let msix = self.get_msix_for_cpu(cpu)?;
        let resp: GdmaCreateQueueResp = self
            .request(
                GdmaRequestType::GDMA_CREATE_QUEUE.0,
                dev_id,
                GdmaCreateQueueReq {
                    queue_type: GdmaQueueType::GDMA_EQ,
                    pdid,
                    doorbell_id,
                    gdma_region,
                    queue_size,
                    eq_pci_msix_index: msix,
                    ..FromZeroes::new_zeroed()
                },
            )
            .await?;

        // The eq takes ownership of the DMA region.
        arena.take_dma_region(gdma_region);

        arena.push(Resource::Eq {
            dev_id,
            eq_id: resp.queue_index,
        });
        tracing::trace!(id = resp.queue_index, cpu, msix, "created eq",);
        let interrupt = self.start_listening(resp.queue_index, msix);
        Ok((resp.queue_index, interrupt))
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub(crate) async fn disable_eq(&mut self, dev_id: GdmaDevId, eq_id: u32) -> anyhow::Result<()> {
        self.stop_listening(eq_id);
        self.request(
            GdmaRequestType::GDMA_DISABLE_QUEUE.0,
            dev_id,
            GdmaDisableQueueReq {
                queue_type: GdmaQueueType::GDMA_EQ,
                queue_index: eq_id,
                alloc_res_id_on_creation: 1, /* what is this? */
            },
        )
        .await
    }

    #[tracing::instrument(skip_all, level = "debug", err)]
    pub async fn create_dma_region(
        &mut self,
        arena: &mut ResourceArena,
        dev_id: GdmaDevId,
        mem: MemoryBlock,
    ) -> anyhow::Result<u64> {
        #[repr(C)]
        #[derive(AsBytes)]
        struct Req {
            req: GdmaCreateDmaRegionReq,
            pages: [u64; 16],
        }
        let pages = mem.pfns();
        let mut req = Req {
            req: GdmaCreateDmaRegionReq {
                length: mem.len() as u64,
                offset_in_page: mem.offset_in_page(),
                gdma_page_type: GDMA_PAGE_TYPE_4K,
                page_count: pages.len() as u32,
                page_addr_list_len: pages.len() as u32,
            },
            pages: [0; 16],
        };
        for (d, &s) in req.pages[..pages.len()].iter_mut().zip(pages) {
            *d = s * PAGE_SIZE64;
        }
        let resp: GdmaCreateDmaRegionResp = self
            .request(GdmaRequestType::GDMA_CREATE_DMA_REGION.0, dev_id, req)
            .await?;

        arena.push(Resource::MemoryBlock(ManuallyDrop::new(mem)));
        arena.push(Resource::DmaRegion {
            dev_id,
            gdma_region: resp.gdma_region,
        });

        // TODO: AddPages for larger region
        Ok(resp.gdma_region)
    }

    #[tracing::instrument(skip(self), level = "debug", err)]
    pub(crate) async fn destroy_dma_region(
        &mut self,
        dev_id: GdmaDevId,
        gdma_region: u64,
    ) -> anyhow::Result<()> {
        self.request(
            GdmaRequestType::GDMA_DESTROY_DMA_REGION.0,
            dev_id,
            GdmaDestroyDmaRegionReq { gdma_region },
        )
        .await
    }
}
