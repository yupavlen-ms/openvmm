// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Type definitions for the VM's servicing state.

pub use state::*;

use crate::worker::FirmwareType;

mod state {
    use mesh::payload::Protobuf;
    use openhcl_dma_manager::save_restore::OpenhclDmaManagerState;
    use state_unit::SavedStateUnit;
    use vmcore::save_restore::SaveRestore;
    use vmcore::save_restore::SavedStateRoot;

    #[derive(Protobuf, SavedStateRoot)]
    #[mesh(package = "underhill")]
    pub struct ServicingState {
        /// State needed for VM initialization.
        #[mesh(1)]
        pub init_state: ServicingInitState,
        /// Saved state from the state units.
        #[mesh(2)]
        pub units: Vec<SavedStateUnit>,
    }

    /// Servicing state needed to optimize emuplat glue on restore.
    #[derive(Protobuf)]
    #[mesh(package = "underhill")]
    pub struct EmuplatSavedState {
        #[mesh(1)]
        pub rtc_local_clock: <crate::emuplat::local_clock::UnderhillLocalClock as SaveRestore>::SavedState,
        #[mesh(2)]
        pub get_backed_adjust_gpa_range: Option<<crate::emuplat::i440bx_host_pci_bridge::GetBackedAdjustGpaRange as SaveRestore>::SavedState>,
        #[mesh(3)]
        pub netvsp_state: Vec<crate::emuplat::netvsp::SavedState>,
    }

    #[derive(Protobuf)]
    #[mesh(package = "underhill")]
    pub struct NvmeSavedState {
        /// NVMe manager (worker) saved state.
        #[mesh(1)]
        pub nvme_state: crate::nvme_manager::save_restore::NvmeManagerSavedState,
    }

    /// Servicing state needed to create the LoadedVm object.
    #[derive(Protobuf)]
    #[mesh(package = "underhill")]
    pub struct ServicingInitState {
        /// The firmware type the VM booted with.
        #[mesh(1)]
        pub firmware_type: Firmware,
        /// The hypervisor reference time when the state units were stopped.
        #[mesh(2)]
        pub vm_stop_reference_time: u64,
        /// The correlation ID to emit with events, activities, etc...
        /// for tracing and diagnostic purposes.
        #[mesh(3)]
        pub correlation_id: Option<guid::Guid>,
        /// Saved state from emuplat glue.
        #[mesh(4)]
        pub emuplat: EmuplatSavedState,
        /// The result of the flush logs request, if there is one.
        #[mesh(5)]
        pub flush_logs_result: Option<FlushLogsResult>,
        /// VMGS related saved state
        #[mesh(6)]
        pub vmgs: (
            vmgs::save_restore::state::SavedVmgsState,
            disk_get_vmgs::save_restore::SavedBlockStorageMetadata,
        ),
        /// Intercept the host-provided shutdown IC device.
        #[mesh(7)]
        pub overlay_shutdown_device: bool,
        /// NVMe saved state.
        #[mesh(10000)]
        pub nvme_state: Option<NvmeSavedState>,
        /// Dma manager state
        #[mesh(10001)]
        pub dma_manager_state: Option<OpenhclDmaManagerState>,
    }

    #[derive(Protobuf)]
    #[mesh(package = "underhill")]
    pub struct FlushLogsResult {
        #[mesh(1)]
        pub duration_us: u64,
        #[mesh(2)]
        pub error: Option<String>,
    }

    /// The VM's firmware type.
    #[derive(Copy, Clone, Protobuf)]
    #[mesh(package = "underhill")]
    pub enum Firmware {
        #[mesh(1)]
        Uefi,
        #[mesh(2)]
        Pcat,
        #[mesh(3)]
        None,
    }
}

impl From<FirmwareType> for Firmware {
    fn from(value: FirmwareType) -> Self {
        match value {
            FirmwareType::Uefi => Self::Uefi,
            FirmwareType::Pcat => Self::Pcat,
            FirmwareType::None => Self::None,
        }
    }
}

impl From<Firmware> for FirmwareType {
    fn from(value: Firmware) -> Self {
        match value {
            Firmware::Uefi => Self::Uefi,
            Firmware::Pcat => Self::Pcat,
            Firmware::None => Self::None,
        }
    }
}

#[expect(clippy::option_option)]
pub mod transposed {
    use super::*;
    use openhcl_dma_manager::save_restore::OpenhclDmaManagerState;
    use vmcore::save_restore::SaveRestore;

    /// A transposed `Option<ServicingInitState>`, where each field of
    /// `ServicingInitState` gets wrapped in an `Option`
    #[derive(Default)]
    pub struct OptionServicingInitState {
        pub firmware_type: Option<Firmware>,
        pub vm_stop_reference_time: Option<u64>,
        pub emuplat: OptionEmuplatSavedState,
        pub flush_logs_result: Option<Option<FlushLogsResult>>,
        pub vmgs: Option<(
            vmgs::save_restore::state::SavedVmgsState,
            disk_get_vmgs::save_restore::SavedBlockStorageMetadata,
        )>,
        pub overlay_shutdown_device: Option<bool>,
        pub nvme_state: Option<Option<NvmeSavedState>>,
        pub dma_manager_state: Option<Option<OpenhclDmaManagerState>>,
    }

    /// A transposed `Option<EmuplatSavedState>`, where each field of
    /// `EmuplatSavedState` gets wrapped in an `Option`
    #[derive(Default)]
    pub struct OptionEmuplatSavedState {
        pub rtc_local_clock: Option<<crate::emuplat::local_clock::UnderhillLocalClock as SaveRestore>::SavedState>,
        pub get_backed_adjust_gpa_range: Option<Option<<crate::emuplat::i440bx_host_pci_bridge::GetBackedAdjustGpaRange as SaveRestore>::SavedState>>,
        pub netvsp_state: Option<Vec<crate::emuplat::netvsp::SavedState>>,
    }

    impl From<Option<ServicingInitState>> for OptionServicingInitState {
        fn from(state: Option<ServicingInitState>) -> Self {
            if let Some(state) = state {
                let ServicingInitState {
                    firmware_type,
                    vm_stop_reference_time,
                    correlation_id: _correlation_id,
                    emuplat:
                        EmuplatSavedState {
                            rtc_local_clock,
                            get_backed_adjust_gpa_range,
                            netvsp_state,
                        },
                    flush_logs_result,
                    vmgs,
                    overlay_shutdown_device,
                    nvme_state,
                    dma_manager_state,
                } = state;

                OptionServicingInitState {
                    firmware_type: Some(firmware_type),
                    vm_stop_reference_time: Some(vm_stop_reference_time),
                    emuplat: OptionEmuplatSavedState {
                        rtc_local_clock: Some(rtc_local_clock),
                        get_backed_adjust_gpa_range: Some(get_backed_adjust_gpa_range),
                        netvsp_state: Some(netvsp_state),
                    },
                    flush_logs_result: Some(flush_logs_result),
                    vmgs: Some(vmgs),
                    overlay_shutdown_device: Some(overlay_shutdown_device),
                    nvme_state: Some(nvme_state),
                    dma_manager_state: Some(dma_manager_state),
                }
            } else {
                OptionServicingInitState::default()
            }
        }
    }
}
