// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Hv1State;
use crate::WhpPartition;
use crate::WhpPartitionAndVtl;
use crate::WhpPartitionInner;
use guestmem::DoorbellRegistration;
use hvdef::HvError;
use hvdef::HvMessageType;
use hvdef::Vtl;
use hvdef::HV_PAGE_SIZE_USIZE;
use pal_event::Event;
use parking_lot::Mutex;
use sparse_mmap::alloc::Allocation;
use sparse_mmap::alloc::SharedMem;
use std::os::windows::prelude::*;
use std::sync::Arc;
use std::sync::Weak;
use tracing_helpers::ErrorValueExt;
use virt::SynicMonitor;
use virt::VpIndex;
use vmcore::interrupt::Interrupt;
use vmcore::monitor::MonitorId;
use vmcore::synic::GuestEventPort;
use winapi::shared::winerror::ERROR_PROC_NOT_FOUND;
use winapi::shared::winerror::HRESULT_FROM_WIN32;

struct RegisteredPort {
    partition: Weak<WhpPartitionInner>,
    handles: Vec<(Vtl, whp::NotificationPortHandle)>,
}

impl Drop for RegisteredPort {
    fn drop(&mut self) {
        if let Some(partition) = self.partition.upgrade() {
            for (vtl, handle) in self.handles.drain(..) {
                partition.vtlp(vtl).whp.delete_notification_port(handle);
            }
        }
    }
}

impl virt::Synic for WhpPartition {
    fn new_host_event_port(
        &self,
        connection_id: u32,
        minimum_vtl: Vtl,
        event: &Event,
    ) -> Result<Option<Box<dyn Sync + Send>>, vmcore::synic::Error> {
        // Try to register the event directly with WHP.
        let handles = self
            .inner
            .vtlps()
            .filter_map(|(vtl, vtlp)| {
                if vtl < minimum_vtl {
                    return None;
                }

                let result = vtlp.whp.create_notification_port(
                    whp::NotificationPortParameters::Event { connection_id },
                    event.as_handle(),
                );
                match result {
                    Ok(handle) => Some(Ok((vtl, handle))),
                    Err(e) if e.code() == HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND) => {
                        // notification ports are not supported; TODO-remove once old Iron builds age out
                        None
                    }
                    Err(e) => Some(Err(vmcore::synic::Error::Hypervisor(
                        vmcore::synic::HypervisorError(e.into()),
                    ))),
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Some(Box::new(RegisteredPort {
            partition: Arc::downgrade(&self.inner),
            handles,
        })))
    }

    fn post_message(&self, vtl: Vtl, vp: VpIndex, sint: u8, typ: u32, payload: &[u8]) {
        self.inner
            .post_message(vtl, vp, sint, HvMessageType(typ), payload);
    }

    fn new_guest_event_port(&self) -> Box<dyn GuestEventPort> {
        match &self.inner.vtl0.hvstate {
            Hv1State::Offloaded | Hv1State::Disabled => {
                if self.inner.vtl2.is_none() {
                    let (trigger, event) = self
                        .inner
                        .vtl0
                        .whp
                        .create_trigger(whp::TriggerParameters::SynicEvent {
                            vp_index: !0,
                            sint: 0,
                            flag: 0,
                        })
                        .expect("oom creating trigger");

                    Box::new(OffloadedGuestEventPort {
                        partition: Arc::downgrade(&self.inner),
                        trigger: Some(trigger),
                        event: event.into(),
                    })
                } else {
                    Box::new(OffloadedGuestEventPortNoTrigger {
                        partition: Arc::downgrade(&self.inner),
                        params: Default::default(),
                    })
                }
            }
            Hv1State::Emulated(_) => Box::new(EmulatedGuestEventPort {
                partition: Arc::downgrade(&self.inner),
                params: Default::default(),
            }),
        }
    }

    fn prefer_os_events(&self) -> bool {
        true
    }

    fn monitor_support(&self) -> Option<&dyn SynicMonitor> {
        // TODO AARCH64: monitor page accesses are atomic instructions, which
        // require a user-mode instruction emulator. Remove this check once we
        // add one.
        if cfg!(guest_arch = "aarch64") {
            return None;
        }
        if self.inner.vtl0.mapper.overlays_supported() {
            Some(self)
        } else {
            None
        }
    }
}

impl SynicMonitor for WhpPartition {
    fn register_monitor(&self, monitor_id: MonitorId, connection_id: u32) -> Box<dyn Send> {
        self.inner
            .monitor_page
            .register_monitor(monitor_id, connection_id)
    }

    fn set_monitor_page(&self, gpa: Option<u64>) -> anyhow::Result<()> {
        let mut overlays = crate::memory::OverlayMapper::new(&self.inner.vtl0);
        let old_gpa = self.inner.monitor_page.set_gpa(gpa);
        if let Some(old_gpa) = old_gpa {
            tracing::debug!(old_gpa, "unregistered monitor page");
            overlays.remove_overlay_page(old_gpa);
        }

        if let Some(gpa) = gpa {
            let mem = Arc::new(SharedMem::new(Allocation::new(HV_PAGE_SIZE_USIZE).unwrap()));
            if !overlays.add_overlay_page(gpa, mem, false, false) {
                // Unset the monitor page so we won't try to remove a registration that doesn't
                // belong to us.
                self.inner.monitor_page.set_gpa(None);
                anyhow::bail!("monitor page overlay already existed");
            }

            tracing::debug!(gpa, "registered monitor page");
        }

        Ok(())
    }
}

/// Implements `GuestEventPort` for partitions with offloaded Hypervisor
/// enlightments for VTL2, where triggers cannot be used.
#[derive(Debug, Clone)]
struct OffloadedGuestEventPortNoTrigger {
    partition: Weak<WhpPartitionInner>,
    params: Arc<Mutex<Option<WhpEventPortParams>>>,
}

#[derive(Debug, Copy, Clone)]
struct WhpEventPortParams {
    vtl: Vtl,
    vp: VpIndex,
    sint: u8,
    flag: u16,
}

impl GuestEventPort for OffloadedGuestEventPortNoTrigger {
    fn interrupt(&self) -> Interrupt {
        let this = self.clone();
        Interrupt::from_fn(move || {
            if let Some(WhpEventPortParams {
                vtl,
                vp,
                sint,
                flag,
            }) = *this.params.lock()
            {
                if let Some(partition) = this.partition.upgrade() {
                    let Some(vpref) = partition.vp(vp) else {
                        tracelimit::warn_ratelimited!(
                            vp = vp.index(),
                            "invalid vp for synic event port"
                        );
                        return;
                    };
                    match vpref.whp(vtl).signal_synic_event(sint, flag) {
                        Ok(newly_signaled) => {
                            if newly_signaled {
                                vpref.ensure_vtl_runnable(vtl);
                            }
                        }
                        Err(err) => match err.hv_result().map(HvError::from) {
                            Some(err @ HvError::InvalidSynicState) => {
                                tracing::debug!(
                                    vp = vp.index(),
                                    sint,
                                    flag,
                                    error = err.as_error(),
                                    "failed to signal synic (expected)"
                                );
                            }
                            _ => {
                                tracing::error!(
                                    vp = vp.index(),
                                    sint,
                                    flag,
                                    error = err.as_error(),
                                    "failed to signal synic"
                                );
                            }
                        },
                    }
                }
            }
        })
    }

    fn clear(&mut self) {
        *self.params.lock() = None;
    }

    fn set(
        &mut self,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> Result<(), vmcore::synic::HypervisorError> {
        *self.params.lock() = Some(WhpEventPortParams {
            vtl,
            vp: VpIndex::new(vp),
            sint,
            flag,
        });
        Ok(())
    }
}

/// Implements `GuestEventPort` for partitions with offloaded Hypervisor
/// enlightments.
#[derive(Debug)]
struct OffloadedGuestEventPort {
    partition: Weak<WhpPartitionInner>,
    trigger: Option<whp::TriggerHandle>,
    event: Event,
}

impl GuestEventPort for OffloadedGuestEventPort {
    fn interrupt(&self) -> Interrupt {
        Interrupt::from_event(self.event.clone())
    }

    fn clear(&mut self) {
        if let Some(partition) = self.partition.upgrade() {
            partition
                .vtl0
                .whp
                .update_trigger(
                    self.trigger.as_ref().unwrap(),
                    whp::TriggerParameters::SynicEvent {
                        vp_index: !0,
                        sint: 0,
                        flag: 0,
                    },
                )
                .expect("cannot fail");
        }
    }

    fn set(
        &mut self,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> Result<(), vmcore::synic::HypervisorError> {
        assert_eq!(vtl, Vtl::Vtl0);
        if let Some(partition) = self.partition.upgrade() {
            partition
                .vtl0
                .whp
                .update_trigger(
                    self.trigger.as_ref().unwrap(),
                    whp::TriggerParameters::SynicEvent {
                        vp_index: vp,
                        sint,
                        flag,
                    },
                )
                .expect("cannot fail");
        }

        Ok(())
    }
}

impl Drop for OffloadedGuestEventPort {
    fn drop(&mut self) {
        if let Some(partition) = self.partition.upgrade() {
            partition
                .vtl0
                .whp
                .delete_trigger(self.trigger.take().unwrap());
        }
    }
}

/// Implements `GuestEventPort` for partitions with emulated Hypervisor
/// enlightments.
#[derive(Clone)]
struct EmulatedGuestEventPort {
    partition: Weak<WhpPartitionInner>,
    params: Arc<Mutex<Option<WhpEventPortParams>>>,
}

impl GuestEventPort for EmulatedGuestEventPort {
    fn interrupt(&self) -> Interrupt {
        let this = self.clone();
        Interrupt::from_fn(move || {
            if let Some(WhpEventPortParams {
                vtl,
                vp,
                sint,
                flag,
            }) = *this.params.lock()
            {
                if let Some(partition) = this.partition.upgrade() {
                    let Hv1State::Emulated(hv) = &partition.vtlp(vtl).hvstate else {
                        unreachable!()
                    };
                    let _ = hv.synic[vtl].signal_event(
                        &partition.gm,
                        vp,
                        sint,
                        flag,
                        &mut partition.synic_interrupt(vp, vtl),
                    );
                }
            }
        })
    }

    fn clear(&mut self) {
        *self.params.lock() = None;
    }

    fn set(
        &mut self,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> Result<(), vmcore::synic::HypervisorError> {
        *self.params.lock() = Some(WhpEventPortParams {
            vtl,
            vp: VpIndex::new(vp),
            sint,
            flag,
        });

        Ok(())
    }
}

impl DoorbellRegistration for WhpPartitionAndVtl {
    fn register_doorbell(
        &self,
        guest_address: u64,
        value: Option<u64>,
        length: Option<u32>,
        event: &Event,
    ) -> std::io::Result<Box<dyn Send + Sync>> {
        let entry = WhpDoorbellEntry::new(
            &self.partition,
            self.vtl,
            guest_address,
            value,
            length,
            event,
        )?;
        Ok(Box::new(entry))
    }
}

struct WhpDoorbellEntry {
    partition: Weak<WhpPartitionInner>,
    minimum_vtl: Vtl,
    guest_address: u64,
    value: Option<u64>,
    length: Option<u32>,
}

impl WhpDoorbellEntry {
    fn new(
        partition: &Arc<WhpPartitionInner>,
        minimum_vtl: Vtl,
        guest_address: u64,
        value: Option<u64>,
        length: Option<u32>,
        event: &Event,
    ) -> std::io::Result<WhpDoorbellEntry> {
        let mut this = None;
        for (vtl, vtlp) in partition.vtlps().rev() {
            if vtl < minimum_vtl {
                break;
            }
            tracing::debug!(?vtl, guest_address, value, length, "registering doorbell");
            unsafe {
                vtlp.whp.register_doorbell(
                    &whp::DoorbellMatch {
                        guest_address,
                        value,
                        length,
                    },
                    event.as_handle().as_raw_handle(),
                )?;
            };

            this.get_or_insert_with(|| Self {
                partition: Arc::downgrade(partition),
                minimum_vtl: vtl,
                guest_address,
                value,
                length,
            })
            .minimum_vtl = vtl;
        }

        Ok(this.expect("at least one vtl is enabled"))
    }
}

impl Drop for WhpDoorbellEntry {
    fn drop(&mut self) {
        if let Some(partition) = self.partition.upgrade() {
            for (vtl, vtlp) in partition.vtlps().rev() {
                if vtl < self.minimum_vtl {
                    break;
                }
                tracing::debug!(
                    ?vtl,
                    guest_address = self.guest_address,
                    value = self.value,
                    length = self.length,
                    "unregistering doorbell"
                );
                vtlp.whp
                    .unregister_doorbell(&whp::DoorbellMatch {
                        guest_address: self.guest_address,
                        value: self.value,
                        length: self.length,
                    })
                    .expect("cannot fail");
            }
        }
    }
}

#[cfg(guest_arch = "x86_64")]
mod x86 {
    use crate::WhpPartitionAndVtl;
    use pci_core::msi::MsiInterruptTarget;
    use tracing_helpers::ErrorValueExt;
    use virt::irqcon::MsiRequest;

    impl MsiInterruptTarget for WhpPartitionAndVtl {
        fn new_interrupt(&self) -> Box<dyn pci_core::msi::MsiControl> {
            let partition = self.partition.clone();
            let vtl = self.vtl;
            Box::new(move |address, data| {
                if let Err(err) = partition.interrupt(vtl, MsiRequest { address, data }) {
                    tracelimit::warn_ratelimited!(
                        address,
                        data,
                        error = err.as_error(),
                        "failed to deliver MSI"
                    );
                }
            })
        }
    }
}
