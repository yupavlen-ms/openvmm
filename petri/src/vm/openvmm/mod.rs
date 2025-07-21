// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code managing the lifetime of a `PetriVmOpenVmm`. All VMs live the same lifecycle:
//! * A `PetriVmConfigOpenVmm` is built for the given firmware and architecture in `construct`.
//! * The configuration is optionally modified from the defaults using the helpers in `modify`.
//! * The `PetriVmOpenVmm` is started by the code in `start`.
//! * The VM is interacted with through the methods in `runtime`.
//! * The VM is either shut down by the code in `runtime`, or gets dropped and cleaned up automatically.

mod construct;
mod modify;
mod runtime;
mod start;

pub use runtime::PetriVmOpenVmm;

use crate::Firmware;
use crate::PetriLogFile;
use crate::PetriLogSource;
use crate::PetriVmConfig;
use crate::PetriVmResources;
use crate::PetriVmgsResource;
use crate::PetriVmmBackend;
use crate::disk_image::AgentImage;
use crate::linux_direct_serial_agent::LinuxDirectSerialAgent;
use crate::openhcl_diag::OpenHclDiagHandler;
use anyhow::Context;
use async_trait::async_trait;
use disk_backend_resources::LayeredDiskHandle;
use disk_backend_resources::layer::DiskLayerHandle;
use disk_backend_resources::layer::RamDiskLayerHandle;
use framebuffer::FramebufferAccess;
use get_resources::ged::FirmwareEvent;
use guid::Guid;
use hvlite_defs::config::Config;
use hvlite_helpers::disk::open_disk_type;
use hyperv_ic_resources::shutdown::ShutdownRpc;
use mesh::Receiver;
use mesh::Sender;
use net_backend_resources::mac_address::MacAddress;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use pal_async::task::Task;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_common::tags::OsFlavor;
use petri_artifacts_core::ArtifactResolver;
use petri_artifacts_core::ResolvedArtifact;
use std::path::PathBuf;
use tempfile::TempPath;
use unix_socket::UnixListener;
use vm_resource::IntoResource;
use vm_resource::Resource;
use vm_resource::kind::DiskHandleKind;
use vmgs_resources::VmgsResource;
use vtl2_settings_proto::Vtl2Settings;

/// The instance guid used for all of our SCSI drives.
pub(crate) const SCSI_INSTANCE: Guid = guid::guid!("27b553e8-8b39-411b-a55f-839971a7884f");

/// The instance guid for the NVMe controller automatically added for boot media.
pub(crate) const BOOT_NVME_INSTANCE: Guid = guid::guid!("92bc8346-718b-449a-8751-edbf3dcd27e4");

/// The instance guid for the MANA nic automatically added when specifying `PetriVmConfigOpenVmm::with_nic`
const MANA_INSTANCE: Guid = guid::guid!("f9641cf4-d915-4743-a7d8-efa75db7b85a");

/// The namespace ID for the NVMe controller automatically added for boot media.
pub(crate) const BOOT_NVME_NSID: u32 = 37;

/// The LUN ID for the NVMe controller automatically added for boot media.
pub(crate) const BOOT_NVME_LUN: u32 = 1;

/// The MAC address used by the NIC assigned with [`PetriVmConfigOpenVmm::with_nic`].
pub const NIC_MAC_ADDRESS: MacAddress = MacAddress::new([0x00, 0x15, 0x5D, 0x12, 0x12, 0x12]);

/// OpenVMM Petri Backend
pub struct OpenVmmPetriBackend {
    openvmm_path: ResolvedArtifact,
}

#[async_trait]
impl PetriVmmBackend for OpenVmmPetriBackend {
    type VmmConfig = PetriVmConfigOpenVmm;
    type VmRuntime = PetriVmOpenVmm;

    fn check_compat(firmware: &Firmware, arch: MachineArch) -> bool {
        arch == MachineArch::host()
            && !(firmware.is_openhcl() && (!cfg!(windows) || arch == MachineArch::Aarch64))
            && !(firmware.is_pcat() && arch == MachineArch::Aarch64)
    }

    fn new(resolver: &ArtifactResolver<'_>) -> Self {
        OpenVmmPetriBackend {
            openvmm_path: resolver
                .require(petri_artifacts_vmm_test::artifacts::OPENVMM_NATIVE)
                .erase(),
        }
    }

    async fn run(
        self,
        config: PetriVmConfig,
        modify_vmm_config: Option<impl FnOnce(PetriVmConfigOpenVmm) -> PetriVmConfigOpenVmm + Send>,
        resources: &PetriVmResources,
    ) -> anyhow::Result<Self::VmRuntime> {
        let mut config = PetriVmConfigOpenVmm::new(&self.openvmm_path, config, resources)?;

        if let Some(f) = modify_vmm_config {
            config = f(config);
        }

        config.run().await
    }
}

/// Configuration state for a test VM.
pub struct PetriVmConfigOpenVmm {
    // Direct configuration related information.
    firmware: Firmware,
    arch: MachineArch,
    config: Config,

    // Runtime resources
    resources: PetriVmResourcesOpenVmm,

    // Logging
    openvmm_log_file: PetriLogFile,

    // Resources that are only used during startup.
    ged: Option<get_resources::ged::GuestEmulationDeviceHandle>,
    framebuffer_access: Option<FramebufferAccess>,
}
/// Various channels and resources used to interact with the VM while it is running.
struct PetriVmResourcesOpenVmm {
    log_stream_tasks: Vec<Task<anyhow::Result<()>>>,
    firmware_event_recv: Receiver<FirmwareEvent>,
    shutdown_ic_send: Sender<ShutdownRpc>,
    kvp_ic_send: Sender<hyperv_ic_resources::kvp::KvpConnectRpc>,
    expected_boot_event: Option<FirmwareEvent>,
    ged_send: Option<Sender<get_resources::ged::GuestEmulationRequest>>,
    pipette_listener: PolledSocket<UnixListener>,
    vtl2_pipette_listener: Option<PolledSocket<UnixListener>>,
    openhcl_diag_handler: Option<OpenHclDiagHandler>,
    linux_direct_serial_agent: Option<LinuxDirectSerialAgent>,

    // Externally injected management stuff also needed at runtime.
    driver: DefaultDriver,
    agent_image: Option<AgentImage>,
    openhcl_agent_image: Option<AgentImage>,
    openvmm_path: ResolvedArtifact,
    output_dir: PathBuf,
    log_source: PetriLogSource,

    // TempPaths that cannot be dropped until the end.
    vtl2_vsock_path: Option<TempPath>,
    _vmbus_vsock_path: TempPath,

    vtl2_settings: Option<Vtl2Settings>,
}

impl PetriVmConfigOpenVmm {
    /// Get the OS that the VM will boot into.
    pub fn os_flavor(&self) -> OsFlavor {
        self.firmware.os_flavor()
    }
}

fn memdiff_disk_from_artifact(
    artifact: &ResolvedArtifact,
) -> anyhow::Result<Resource<DiskHandleKind>> {
    let path = artifact.as_ref();
    let disk = open_disk_type(path, true)
        .with_context(|| format!("failed to open disk: {}", path.display()))?;
    Ok(LayeredDiskHandle {
        layers: vec![
            RamDiskLayerHandle { len: None }.into_resource().into(),
            DiskLayerHandle(disk).into_resource().into(),
        ],
    }
    .into_resource())
}

fn memdiff_vmgs_from_artifact(vmgs: &PetriVmgsResource) -> anyhow::Result<VmgsResource> {
    let convert_disk =
        |disk: &Option<ResolvedArtifact>| -> anyhow::Result<Resource<DiskHandleKind>> {
            if let Some(disk) = disk {
                memdiff_disk_from_artifact(disk)
            } else {
                Ok(LayeredDiskHandle::single_layer(RamDiskLayerHandle {
                    len: Some(vmgs_format::VMGS_DEFAULT_CAPACITY),
                })
                .into_resource())
            }
        };

    Ok(match vmgs {
        PetriVmgsResource::Disk(disk) => VmgsResource::Disk(convert_disk(disk)?),
        PetriVmgsResource::ReprovisionOnFailure(disk) => {
            VmgsResource::ReprovisionOnFailure(convert_disk(disk)?)
        }
        PetriVmgsResource::Reprovision(disk) => VmgsResource::Reprovision(convert_disk(disk)?),
        PetriVmgsResource::Ephemeral => VmgsResource::Ephemeral,
    })
}
