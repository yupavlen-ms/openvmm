// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NVMe namespace frontend.

use super::spec;
use super::spec::nvm;
use crate::driver::save_restore::SavedNamespaceData;
use crate::driver::IoIssuers;
use crate::queue_pair::admin_cmd;
use crate::queue_pair::Issuer;
use crate::queue_pair::RequestError;
use crate::NVME_PAGE_SHIFT;
use guestmem::ranges::PagedRange;
use guestmem::GuestMemory;
use inspect::Inspect;
use mesh::CancelContext;
use pal_async::task::Spawn;
use parking_lot::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use thiserror::Error;
use vmcore::vm_task::VmTaskDriver;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// An error getting a namespace.
#[derive(Debug, Error)]
#[expect(missing_docs)]
pub enum NamespaceError {
    #[error("namespace not found")]
    NotFound,
    #[error("formatted lba size invalid")]
    FlbasInvalid,
    #[error("lba format invalid: {0:?}")]
    LbaFormatInvalid(nvm::Lbaf),
    #[error("nvme request failed")]
    Request(#[source] RequestError),
    #[error("maximum data transfer size too small: 2^{0} pages")]
    MdtsInvalid(u8),
}

/// An NVMe namespace.
#[derive(Debug, Inspect)]
pub struct Namespace {
    nsid: u32,
    #[inspect(flatten)]
    state: Arc<DynamicState>,
    block_shift: u32,
    max_transfer_block_count: u32,
    preferred_deallocate_granularity: u16,
    reservation_capabilities: nvm::ReservationCapabilities,
    controller_identify: Arc<spec::IdentifyController>,
    #[inspect(skip)]
    issuers: Arc<IoIssuers>,
    #[inspect(skip)]
    _cancel_rescan: mesh::Cancel,
}

#[derive(Debug, Inspect)]
struct DynamicState {
    block_count: AtomicU64,
    #[inspect(skip)]
    resize_event: event_listener::Event,
    removed: AtomicBool,
    identify: Mutex<nvm::IdentifyNamespace>,
}

impl Namespace {
    pub(super) async fn new(
        driver: &VmTaskDriver,
        admin: Arc<Issuer>,
        rescan_event: Arc<event_listener::Event>,
        controller_identify: Arc<spec::IdentifyController>,
        io_issuers: &Arc<IoIssuers>,
        nsid: u32,
    ) -> Result<Self, NamespaceError> {
        tracing::info!("YSP: Namespace::new {}", nsid);
        let identify = identify_namespace(&admin, nsid)
            .await
            .map_err(NamespaceError::Request)?;

        Namespace::new_from_identify(
            driver,
            admin,
            rescan_event,
            controller_identify.clone(),
            io_issuers,
            nsid,
            identify,
        )
    }

    /// Create Namespace object from Identify data structure.
    fn new_from_identify(
        driver: &VmTaskDriver,
        admin: Arc<Issuer>,
        rescan_event: Arc<event_listener::Event>,
        controller_identify: Arc<spec::IdentifyController>,
        io_issuers: &Arc<IoIssuers>,
        nsid: u32,
        identify: nvm::IdentifyNamespace,
    ) -> Result<Self, NamespaceError> {
        if identify.nsze == 0 {
            return Err(NamespaceError::NotFound);
        }
        tracing::info!("YSP: identify nsze={} ncap={}", identify.nsze, identify.ncap);

        let lba_format_index = identify.flbas.low_index();
        if lba_format_index > identify.nlbaf {
            return Err(NamespaceError::FlbasInvalid);
        }

        let lbaf = identify.lbaf[lba_format_index as usize];
        let block_shift = lbaf.lbads();
        if !matches!(block_shift, 9..=16) {
            return Err(NamespaceError::LbaFormatInvalid(lbaf));
        }

        let max_transfer_block_count = {
            let mdts = if controller_identify.mdts != 0 {
                controller_identify.mdts
            } else {
                u8::MAX
            };
            let max_transfer_bits = mdts.saturating_add(NVME_PAGE_SHIFT);
            1 << max_transfer_bits
                .checked_sub(block_shift)
                .ok_or(NamespaceError::MdtsInvalid(mdts))?
                .min(16)
        };

        let preferred_deallocate_granularity = if identify.nsfeat.optperf() {
            identify.npdg
        } else {
            1
        };

        let reservation_capabilities = if controller_identify.oncs.reservations() {
            identify.rescap
        } else {
            nvm::ReservationCapabilities::new()
        };

        let state = Arc::new(DynamicState {
            block_count: identify.nsze.into(),
            removed: false.into(),
            identify: Mutex::new(identify),
            resize_event: Default::default(),
        });

        // Spawn a task, but detach is so that it doesn't get dropped while NVMe
        // request is in flight. Use a cancel context, whose cancel gets dropped
        // when `self` gets dropped, so that it terminates after finishing any
        // requests.
        let (mut ctx, cancel_rescan) = CancelContext::new().with_cancel();
        driver
            .spawn(format!("nvme_poll_rescan_{nsid}"), {
                let state = state.clone();
                async move {
                    state
                        .poll_for_rescans(&mut ctx, &admin, nsid, &rescan_event)
                        .await
                }
            })
            .detach();

        Ok(Self {
            nsid,
            state,
            max_transfer_block_count,
            block_shift: block_shift.into(),
            preferred_deallocate_granularity,
            reservation_capabilities,
            controller_identify,
            issuers: io_issuers.clone(),
            _cancel_rescan: cancel_rescan,
        })
    }

    /// Gets the current block count.
    pub fn block_count(&self) -> u64 {
        self.state.block_count.load(Ordering::Relaxed)
    }

    /// Wait for the block count to be different from `block_count`.
    pub async fn wait_resize(&self, block_count: u64) -> u64 {
        loop {
            let listen = self.state.resize_event.listen();
            let current = self.block_count();
            if current != block_count {
                break current;
            }
            listen.await;
        }
    }

    /// Gets the block size in bytes.
    pub fn block_size(&self) -> u32 {
        1 << self.block_shift
    }

    fn check_active(&self) -> Result<(), RequestError> {
        if self.state.removed.load(Ordering::Relaxed) {
            // The namespace has been removed. Return invalid namespace even if
            // the namespace has returned to avoid accidentally accessing the
            // wrong disk.
            return Err(RequestError::Nvme(
                spec::Status::INVALID_NAMESPACE_OR_FORMAT.into(),
            ));
        }
        Ok(())
    }

    async fn issuer(&self, cpu: u32) -> Result<&Issuer, RequestError> {
        self.issuers.get(cpu).await
    }

    /// Reads from the namespace.
    pub async fn read(
        &self,
        target_cpu: u32,
        lba: u64,
        block_count: u32,
        guest_memory: &GuestMemory,
        mem: PagedRange<'_>,
    ) -> Result<(), RequestError> {
        self.check_active()?;
        if block_count == 0 {
            return Ok(());
        }
        assert!(block_count <= self.max_transfer_block_count);
        let len = (block_count as usize) << self.block_shift;
        if len > mem.len() {
            panic!(
                "invalid block count: {len} > {mem_len}",
                mem_len = mem.len()
            );
        }
        self.issuer(target_cpu)
            .await?
            .issue_external(
                spec::Command {
                    cdw10: nvm::Cdw10ReadWrite::new().with_sbla_low(lba as u32).into(),
                    cdw11: nvm::Cdw11ReadWrite::new()
                        .with_sbla_high((lba >> 32) as u32)
                        .into(),
                    cdw12: nvm::Cdw12ReadWrite::new()
                        .with_nlb_z((block_count - 1) as u16)
                        .into(),
                    ..nvm_cmd(nvm::NvmOpcode::READ, self.nsid)
                },
                guest_memory,
                mem.subrange(0, len),
            )
            .await?;
        Ok(())
    }

    /// Writes to the namespace.
    pub async fn write(
        &self,
        target_cpu: u32,
        lba: u64,
        block_count: u32,
        fua: bool,
        guest_memory: &GuestMemory,
        mem: PagedRange<'_>,
    ) -> Result<(), RequestError> {
        self.check_active()?;
        if block_count == 0 {
            return Ok(());
        }
        assert!(block_count <= self.max_transfer_block_count);
        let len = (block_count as usize) << self.block_shift;
        if len > mem.len() {
            panic!(
                "invalid block count: {len} > {mem_len}",
                mem_len = mem.len()
            );
        }
        self.issuer(target_cpu)
            .await?
            .issue_external(
                spec::Command {
                    cdw10: nvm::Cdw10ReadWrite::new().with_sbla_low(lba as u32).into(),
                    cdw11: nvm::Cdw11ReadWrite::new()
                        .with_sbla_high((lba >> 32) as u32)
                        .into(),
                    cdw12: nvm::Cdw12ReadWrite::new()
                        .with_nlb_z((block_count - 1) as u16)
                        .with_fua(fua)
                        .into(),
                    ..nvm_cmd(nvm::NvmOpcode::WRITE, self.nsid)
                },
                guest_memory,
                mem.subrange(0, len),
            )
            .await?;
        Ok(())
    }

    /// Flushes the namespace to persistent media.
    pub async fn flush(&self, target_cpu: u32) -> Result<(), RequestError> {
        self.check_active()?;
        self.issuer(target_cpu)
            .await?
            .issue_neither(spec::Command {
                ..nvm_cmd(nvm::NvmOpcode::FLUSH, self.nsid)
            })
            .await?;
        Ok(())
    }

    /// Returns the maximum size for a read or write, in blocks.
    pub fn max_transfer_block_count(&self) -> u32 {
        self.max_transfer_block_count
    }

    /// Returns whether the namespace support dataset management, needed to call
    /// [`Self::deallocate`].
    pub fn supports_dataset_management(&self) -> bool {
        self.controller_identify.oncs.dataset_management()
    }

    /// The preferred granularity for unmap requests.
    pub fn preferred_deallocate_granularity(&self) -> u16 {
        self.preferred_deallocate_granularity
    }

    /// Returns the maximum number of ranges to pass to [`Self::deallocate`].
    pub fn dataset_management_range_limit(&self) -> usize {
        // TODO: query DMRL
        256
    }

    /// Returns the maximum size of a single range to pass to
    /// [`Self::deallocate`].
    pub fn dataset_management_range_size_limit(&self) -> u32 {
        // TODO: query DMRSL
        u32::MAX
    }

    /// Issues a dataset management command to deallocate the specified ranges.
    ///
    /// The device may ignore ranges or LBA counts beyond a certain point. Use
    /// [`Self::dataset_management_range_limit`] and
    /// [`Self::dataset_management_range_size_limit`] to get the
    /// controller-reported bounds.
    pub async fn deallocate(
        &self,
        target_cpu: u32,
        ranges: &[nvm::DsmRange],
    ) -> Result<(), RequestError> {
        self.check_active()?;
        // Limit the requested ranges.
        let ranges = &ranges[..ranges.len().min(256)];
        self.issuer(target_cpu)
            .await?
            .issue_in(
                spec::Command {
                    cdw10: nvm::Cdw10Dsm::new()
                        .with_nr_z((ranges.len() - 1) as u8)
                        .into(),
                    cdw11: nvm::Cdw11Dsm::new().with_ad(true).into(),
                    ..nvm_cmd(nvm::NvmOpcode::DSM, self.nsid)
                },
                ranges.as_bytes(),
            )
            .await?;
        Ok(())
    }

    /// Gets the namespace's reservation capabilities.
    pub fn reservation_capabilities(&self) -> nvm::ReservationCapabilities {
        self.reservation_capabilities
    }

    /// Gets the namespace's reservation report.
    pub async fn reservation_report_extended(
        &self,
        target_cpu: u32,
    ) -> Result<
        (
            nvm::ReservationReportExtended,
            Vec<nvm::RegisteredControllerExtended>,
        ),
        RequestError,
    > {
        let mut data = vec![0; 4096];
        let issuer = self.issuer(target_cpu).await?;
        loop {
            issuer
                .issue_out(
                    spec::Command {
                        cdw10: nvm::Cdw10ReservationReport::new()
                            .with_numd_z((data.len() / 4 - 1) as u32)
                            .into(),
                        cdw11: nvm::Cdw11ReservationReport::new().with_eds(true).into(),
                        ..nvm_cmd(nvm::NvmOpcode::RESERVATION_REPORT, self.nsid)
                    },
                    &mut data,
                )
                .await?;

            let header = nvm::ReservationReportExtended::read_from_prefix(&data[..]).unwrap();
            let len = size_of_val(&header)
                + header.report.regctl.get() as usize
                    * size_of::<nvm::RegisteredControllerExtended>();

            if len > data.len() {
                data.resize(len, 0);
                continue;
            }

            let mut controllers = vec![
                nvm::RegisteredControllerExtended::new_zeroed();
                header.report.regctl.get().into()
            ];

            controllers
                .as_bytes_mut()
                .copy_from_slice(&data[size_of_val(&header)..len]);

            break Ok((header, controllers));
        }
    }

    /// Acquires a reservation.
    pub async fn reservation_acquire(
        &self,
        target_cpu: u32,
        action: nvm::ReservationAcquireAction,
        crkey: u64,
        prkey: u64,
        reservation_type: nvm::ReservationType,
    ) -> Result<(), RequestError> {
        let data = nvm::ReservationAcquire { crkey, prkey };
        self.issuer(target_cpu)
            .await?
            .issue_in(
                spec::Command {
                    cdw10: nvm::Cdw10ReservationAcquire::new()
                        .with_racqa(action.0)
                        .with_rtype(reservation_type.0)
                        .into(),
                    ..nvm_cmd(nvm::NvmOpcode::RESERVATION_ACQUIRE, self.nsid)
                },
                data.as_bytes(),
            )
            .await?;

        Ok(())
    }

    /// Releases a reservation.
    pub async fn reservation_release(
        &self,
        target_cpu: u32,
        action: nvm::ReservationReleaseAction,
        crkey: u64,
        reservation_type: nvm::ReservationType,
    ) -> Result<(), RequestError> {
        let data = nvm::ReservationRelease { crkey };
        self.issuer(target_cpu)
            .await?
            .issue_in(
                spec::Command {
                    cdw10: nvm::Cdw10ReservationRelease::new()
                        .with_rrela(action.0)
                        .with_rtype(reservation_type.0)
                        .into(),
                    ..nvm_cmd(nvm::NvmOpcode::RESERVATION_RELEASE, self.nsid)
                },
                data.as_bytes(),
            )
            .await?;

        Ok(())
    }

    /// Modifies a reservation registration.
    pub async fn reservation_register(
        &self,
        target_cpu: u32,
        action: nvm::ReservationRegisterAction,
        crkey: Option<u64>,
        nrkey: u64,
        ptpl: Option<bool>,
    ) -> Result<(), RequestError> {
        let data = nvm::ReservationRegister {
            crkey: crkey.unwrap_or(0),
            nrkey,
        };
        let cptpl = match ptpl {
            None => nvm::ChangePersistThroughPowerLoss::NO_CHANGE,
            Some(false) => nvm::ChangePersistThroughPowerLoss::CLEAR,
            Some(true) => nvm::ChangePersistThroughPowerLoss::SET,
        };
        self.issuer(target_cpu)
            .await?
            .issue_in(
                spec::Command {
                    cdw10: nvm::Cdw10ReservationRegister::new()
                        .with_rrega(action.0)
                        .with_iekey(crkey.is_none())
                        .with_cptpl(cptpl.0)
                        .into(),
                    ..nvm_cmd(nvm::NvmOpcode::RESERVATION_REGISTER, self.nsid)
                },
                data.as_bytes(),
            )
            .await?;

        Ok(())
    }

    /// Return Namespace ID.
    pub fn nsid(&self) -> u32 {
        self.nsid
    }

    /// Save namespace object data for servicing.
    pub fn save(&self) -> SavedNamespaceData {
        tracing::info!("YSP: Namespace::save nsid={}", self.nsid);
        SavedNamespaceData {
            nsid: self.nsid,
            identify_ns: self.state.identify.lock().clone(),
        }
    }

    /// Restore namespace object data after servicing.
    pub(super) fn restore(
        driver: &VmTaskDriver,
        admin: Arc<Issuer>,
        rescan_event: Arc<event_listener::Event>,
        identify_ctrl: Arc<spec::IdentifyController>,
        io_issuers: &Arc<IoIssuers>,
        saved_state: &SavedNamespaceData,
    ) -> Result<Self, NamespaceError> {
        tracing::info!("YSP: Namespace::restore nsid={}", saved_state.nsid);
        let SavedNamespaceData { nsid, identify_ns } = saved_state;

        Namespace::new_from_identify(
            driver,
            admin,
            rescan_event,
            identify_ctrl.clone(),
            io_issuers,
            *nsid,
            identify_ns.clone(),
        )
    }
}

impl DynamicState {
    async fn poll_for_rescans(
        &self,
        ctx: &mut CancelContext,
        admin: &Issuer,
        nsid: u32,
        rescan_event: &event_listener::Event,
    ) {
        loop {
            let listen = rescan_event.listen();
            tracing::debug!("rescan");
            // Query again even the first time through the loop to make sure
            // we didn't miss the initial rescan notification.
            match identify_namespace(admin, nsid).await {
                Ok(identify) => {
                    if identify.nsze == 0 {
                        tracing::info!(nsid, "namespace was hot removed");
                        self.removed.store(true, Ordering::Relaxed);
                    } else {
                        let old_block_count = self.block_count.load(Ordering::Relaxed);
                        let new_block_count = identify.nsze;
                        if old_block_count != new_block_count {
                            tracing::info!(
                                old_block_count,
                                new_block_count,
                                "nvme disk size changed"
                            );
                            self.block_count.store(new_block_count, Ordering::Relaxed);
                            self.resize_event.notify(usize::MAX);
                        } else {
                            tracing::debug!("rescanned, no change");
                        }
                    }
                    *self.identify.lock() = identify;
                }
                Err(err) => {
                    tracing::warn!(
                        nsid,
                        error = &err as &dyn std::error::Error,
                        "failed to query namespace during rescan"
                    );
                }
            }

            if ctx.until_cancelled(listen).await.is_err() {
                break;
            }
        }
    }
}

async fn identify_namespace(
    admin: &Issuer,
    nsid: u32,
) -> Result<nvm::IdentifyNamespace, RequestError> {
    let mut identify = nvm::IdentifyNamespace::new_zeroed();
    admin
        .issue_out(
            spec::Command {
                nsid,
                cdw10: spec::Cdw10Identify::new()
                    .with_cns(spec::Cns::NAMESPACE.0)
                    .into(),
                ..admin_cmd(spec::AdminOpcode::IDENTIFY)
            },
            identify.as_bytes_mut(),
        )
        .await?;
    Ok(identify)
}

fn nvm_cmd(opcode: nvm::NvmOpcode, nsid: u32) -> spec::Command {
    spec::Command {
        cdw0: spec::Cdw0::new().with_opcode(opcode.0),
        nsid,
        ..FromZeroes::new_zeroed()
    }
}
