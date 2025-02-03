// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::emuplat;
use crate::partition::BindHvliteVp;
use crate::partition::HvlitePartition;
use crate::vmgs_non_volatile_store::HvLiteVmgsNonVolatileStore;
use crate::worker::rom::RomBuilder;
use acpi::dsdt;
use anyhow::Context;
use cfg_if::cfg_if;
use chipset_device_resources::IRQ_LINE_SET;
use debug_ptr::DebugPtr;
use disk_backend::resolve::ResolveDiskParameters;
use disk_backend::Disk;
use firmware_uefi::UefiCommandSet;
use floppy_resources::FloppyDiskConfig;
use futures::executor::block_on;
use futures::future::try_join_all;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::prelude::*;
use guestmem::GuestMemory;
use guid::Guid;
use hvdef::Vtl;
use hvdef::HV_PAGE_SIZE;
use hvlite_defs::config::Aarch64TopologyConfig;
use hvlite_defs::config::Config;
use hvlite_defs::config::DeviceVtl;
use hvlite_defs::config::GicConfig;
use hvlite_defs::config::Hypervisor;
use hvlite_defs::config::HypervisorConfig;
use hvlite_defs::config::LoadMode;
use hvlite_defs::config::MemoryConfig;
use hvlite_defs::config::ProcessorTopologyConfig;
use hvlite_defs::config::SerialPipes;
use hvlite_defs::config::VirtioBus;
use hvlite_defs::config::VmbusConfig;
use hvlite_defs::config::VpciDeviceConfig;
use hvlite_defs::config::Vtl2BaseAddressType;
use hvlite_defs::config::Vtl2Config;
use hvlite_defs::config::X2ApicConfig;
use hvlite_defs::config::X86TopologyConfig;
use hvlite_defs::rpc::PulseSaveRestoreError;
use hvlite_defs::rpc::VmRpc;
use hvlite_defs::worker::VmWorkerParameters;
use hvlite_defs::worker::VM_WORKER;
use hvlite_pcat_locator::RomFileLocation;
use ide_resources::GuestMedia;
use ide_resources::IdeDeviceConfig;
use igvm::IgvmFile;
use input_core::InputData;
use input_core::MultiplexedInputHandle;
use inspect::Inspect;
use membacking::GuestMemoryBuilder;
use membacking::GuestMemoryManager;
use membacking::SharedMemoryBacking;
use memory_range::MemoryRange;
use mesh::error::RemoteError;
use mesh::payload::message::ProtobufMessage;
use mesh::payload::Protobuf;
use mesh::MeshPayload;
use mesh_worker::Worker;
use mesh_worker::WorkerId;
use mesh_worker::WorkerRpc;
use missing_dev::MissingDevManifest;
use pal_async::local::block_with_io;
use pal_async::task::Spawn;
use pal_async::task::Task;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use pci_core::msi::MsiInterruptSet;
use pci_core::PciInterruptPin;
use scsi_core::ResolveScsiDeviceHandleParams;
use scsidisk::atapi_scsi::AtapiScsiDisk;
use scsidisk::SimpleScsiDisk;
use serial_16550_resources::ComPort;
use state_unit::SavedStateUnit;
use state_unit::SpawnedUnit;
use state_unit::StateUnits;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use storvsp::ScsiControllerDisk;
use tracing_helpers::ErrorValueExt;
use virt::ProtoPartition;
use virt::VpIndex;
use virtio::resolve::VirtioResolveInput;
use virtio::LegacyWrapper;
use virtio::PciInterruptModel;
use virtio::VirtioMmioDevice;
use virtio::VirtioPciDevice;
use virtio_serial::VirtioSerialDevice;
use vm_loader::initial_regs::initial_regs;
use vm_resource::kind::DiskHandleKind;
use vm_resource::kind::KeyboardInputHandleKind;
use vm_resource::kind::MouseInputHandleKind;
use vm_resource::kind::VirtioDeviceHandle;
use vm_resource::kind::VmbusDeviceHandleKind;
use vm_resource::Resource;
use vm_resource::ResourceResolver;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::aarch64::Aarch64Topology;
use vm_topology::processor::aarch64::GicInfo;
use vm_topology::processor::x86::X2ApicState;
use vm_topology::processor::x86::X86Topology;
use vm_topology::processor::ArchTopology;
use vm_topology::processor::ProcessorTopology;
use vm_topology::processor::TopologyBuilder;
use vmbus_channel::channel::VmbusDevice;
use vmbus_server::hvsock::HvsockRelay;
use vmbus_server::HvsockRelayChannel;
use vmbus_server::VmbusServer;
use vmcore::save_restore::SavedStateRoot;
use vmcore::vm_task::thread::ThreadDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;
use vmcore::vmtime::VmTimeSource;
use vmgs_broker::resolver::VmgsFileResolver;
use vmm_core::acpi_builder::AcpiTablesBuilder;
use vmm_core::input_distributor::InputDistributor;
use vmm_core::partition_unit::block_on_vp;
use vmm_core::partition_unit::Halt;
use vmm_core::partition_unit::PartitionUnit;
use vmm_core::partition_unit::PartitionUnitParams;
use vmm_core::synic::SynicPorts;
use vmm_core::vmbus_unit::offer_channel_unit;
use vmm_core::vmbus_unit::offer_vmbus_device_handle_unit;
use vmm_core::vmbus_unit::ChannelUnit;
use vmm_core::vmbus_unit::VmbusServerHandle;
use vmm_core_defs::HaltReason;
use vmotherboard::options::BaseChipsetDevices;
use vmotherboard::options::BaseChipsetFoundation;
use vmotherboard::options::BaseChipsetManifest;
use vmotherboard::BaseChipsetBuilder;
use vmotherboard::BaseChipsetBuilderOutput;
use vmotherboard::ChipsetDeviceHandle;
use vmotherboard::ChipsetDevices;
use vpci::bus::VpciBus;

const PM_BASE: u16 = 0x400;
const SYSTEM_IRQ_ACPI: u32 = 9;

const WDAT_PORT: u16 = 0x30;

/// Creates a thread to run low-performance devices on.
pub fn new_device_thread() -> (JoinHandle<()>, DefaultDriver) {
    let pool = DefaultPool::new();
    let driver = pool.driver();
    let thread = thread::Builder::new()
        .name("basic_device_thread".into())
        .spawn(move || pool.run())
        .unwrap();
    (thread, driver)
}

impl Manifest {
    fn from_config(config: Config) -> Self {
        Self {
            load_mode: config.load_mode,
            floppy_disks: config.floppy_disks,
            ide_disks: config.ide_disks,
            vpci_devices: config.vpci_devices,
            hypervisor: config.hypervisor,
            memory: config.memory,
            processor_topology: config.processor_topology,
            chipset: config.chipset,
            #[cfg(windows)]
            kernel_vmnics: config.kernel_vmnics,
            input: config.input,
            framebuffer: config.framebuffer,
            vga_firmware: config.vga_firmware,
            vtl2_gfx: config.vtl2_gfx,
            virtio_console_pci: config.virtio_console_pci,
            virtio_serial: config.virtio_serial,
            virtio_devices: config.virtio_devices,
            vmbus: config.vmbus,
            vtl2_vmbus: config.vtl2_vmbus,
            #[cfg(all(windows, feature = "virt_whp"))]
            vpci_resources: config.vpci_resources,
            format_vmgs: config.format_vmgs,
            vmgs_disk: config.vmgs_disk,
            secure_boot_enabled: config.secure_boot_enabled,
            custom_uefi_vars: config.custom_uefi_vars,
            firmware_event_send: config.firmware_event_send,
            debugger_rpc: config.debugger_rpc,
            vmbus_devices: config.vmbus_devices,
            chipset_devices: config.chipset_devices,
            generation_id_recv: config.generation_id_recv,
        }
    }
}

/// This is the manifest of devices with resolved resources (handles, channels).
///
/// Currently this is identical to `Config`, but that will change in future
/// updates.
#[derive(MeshPayload)]
pub struct Manifest {
    load_mode: LoadMode,
    floppy_disks: Vec<FloppyDiskConfig>,
    ide_disks: Vec<IdeDeviceConfig>,
    vpci_devices: Vec<VpciDeviceConfig>,
    memory: MemoryConfig,
    processor_topology: ProcessorTopologyConfig,
    hypervisor: HypervisorConfig,
    chipset: BaseChipsetManifest,
    #[cfg(windows)]
    kernel_vmnics: Vec<hvlite_defs::config::KernelVmNicConfig>,
    input: mesh::MpscReceiver<InputData>,
    framebuffer: Option<framebuffer::Framebuffer>,
    vga_firmware: Option<RomFileLocation>,
    vtl2_gfx: bool,
    virtio_console_pci: bool,
    virtio_serial: Option<SerialPipes>,
    virtio_devices: Vec<(VirtioBus, Resource<VirtioDeviceHandle>)>,
    vmbus: Option<VmbusConfig>,
    vtl2_vmbus: Option<VmbusConfig>,
    #[cfg(all(windows, feature = "virt_whp"))]
    vpci_resources: Vec<virt_whp::device::DeviceHandle>,
    format_vmgs: bool,
    vmgs_disk: Option<Resource<DiskHandleKind>>,
    secure_boot_enabled: bool,
    custom_uefi_vars: firmware_uefi_custom_vars::CustomVars,
    firmware_event_send: Option<mesh::MpscSender<get_resources::ged::FirmwareEvent>>,
    debugger_rpc: Option<mesh::Receiver<vmm_core_defs::debug_rpc::DebugRequest>>,
    vmbus_devices: Vec<(DeviceVtl, Resource<VmbusDeviceHandleKind>)>,
    chipset_devices: Vec<ChipsetDeviceHandle>,
    generation_id_recv: Option<mesh::Receiver<[u8; 16]>>,
}

#[derive(Protobuf, SavedStateRoot)]
#[mesh(package = "openvmm")]
pub struct SavedState {
    #[mesh(1)]
    pub units: Vec<SavedStateUnit>,
}

async fn open_simple_disk(
    resolver: &ResourceResolver,
    disk_type: Resource<DiskHandleKind>,
    read_only: bool,
) -> anyhow::Result<Disk> {
    let disk = resolver
        .resolve(
            disk_type,
            ResolveDiskParameters {
                read_only,
                _async_trait_workaround: &(),
            },
        )
        .await?;
    Ok(disk.0)
}

#[derive(MeshPayload)]
pub struct RestartState {
    hypervisor: Hypervisor,
    manifest: Manifest,
    running: bool,
    saved_state: SavedState,
    shared_memory: SharedMemoryBacking,
    rpc: mesh::Receiver<VmRpc>,
    notify: mesh::Sender<HaltReason>,
}

// Used for locating VM information in a debugger
// Do not use during program execution
static LOADED_VM: DebugPtr<LoadedVm> = DebugPtr::new();

/// The VM worker, used to create and run a VM partition.
pub struct VmWorker {
    vm: LoadedVm,
    rpc: mesh::Receiver<VmRpc>,
    device_thread: JoinHandle<()>,
}

impl Worker for VmWorker {
    type Parameters = VmWorkerParameters;
    type State = RestartState;
    const ID: WorkerId<Self::Parameters> = VM_WORKER;

    fn new(parameters: Self::Parameters) -> anyhow::Result<Self> {
        let (device_thread, device_driver) = new_device_thread();

        let manifest = Manifest::from_config(parameters.cfg);

        // Choose the hypervisor to use.
        let hypervisor = if let Some(hv) = parameters.hypervisor {
            hv
        } else {
            choose_hypervisor()?
        };

        let vm = block_on(InitializedVm::new(
            VmTaskDriverSource::new(ThreadDriverBackend::new(device_driver)),
            hypervisor,
            manifest,
            None,
        ))?;
        let saved_state = parameters
            .saved_state
            .map(|m| m.parse())
            .transpose()
            .context("failed to decode saved state")?;

        let vm = block_with_io(|_| vm.load(saved_state, parameters.notify))?;

        LOADED_VM.store(&vm);

        Ok(Self {
            vm,
            rpc: parameters.rpc,
            device_thread,
        })
    }

    fn restart(state: Self::State) -> anyhow::Result<Self> {
        let RestartState {
            hypervisor,
            manifest,
            running,
            saved_state,
            shared_memory,
            rpc,
            notify,
        } = state;
        let (device_thread, device_driver) = new_device_thread();

        let vm = block_on(InitializedVm::new(
            VmTaskDriverSource::new(ThreadDriverBackend::new(device_driver)),
            hypervisor,
            manifest,
            Some(shared_memory),
        ))?;
        block_with_io(|_| async {
            let mut vm = vm.load(Some(saved_state), notify).await?;

            LOADED_VM.store(&vm);

            if running {
                vm.resume().await;
            }
            Ok(Self {
                vm,
                rpc,
                device_thread,
            })
        })
    }

    fn run(self, worker_rpc: mesh::Receiver<WorkerRpc<Self::State>>) -> anyhow::Result<()> {
        DefaultPool::run_with(|driver| async {
            let driver = driver;
            self.vm.run(&driver, self.rpc, worker_rpc).await
        });
        self.device_thread.join().unwrap();
        Ok(())
    }
}

/// A VM that has been initialized but not yet loaded (i.e. the saved state is
/// not yet available).
struct InitializedVm {
    hypervisor: Hypervisor,
    partition: Arc<dyn HvlitePartition>,
    vps: Vec<Box<dyn BindHvliteVp>>,
    vmtime_keeper: VmTimeKeeper,
    vmtime_source: VmTimeSource,
    memory_manager: GuestMemoryManager,
    gm: GuestMemory,
    cfg: Manifest,
    mem_layout: MemoryLayout,
    processor_topology: ProcessorTopology,
    igvm_file: Option<IgvmFile>,
    driver_source: VmTaskDriverSource,
}

trait BuildTopology<T: ArchTopology + Inspect> {
    fn to_topology(&self) -> anyhow::Result<ProcessorTopology<T>>;
}

trait ExtractTopologyConfig {
    type Config;
    fn to_config(&self) -> ProcessorTopologyConfig<Self::Config>;
}

impl ExtractTopologyConfig for ProcessorTopology<X86Topology> {
    type Config = X86TopologyConfig;

    fn to_config(&self) -> ProcessorTopologyConfig<X86TopologyConfig> {
        ProcessorTopologyConfig {
            proc_count: self.vp_count(),
            vps_per_socket: Some(self.reserved_vps_per_socket()),
            enable_smt: Some(self.smt_enabled()),
            arch: X86TopologyConfig {
                apic_id_offset: self.vp_arch(VpIndex::BSP).apic_id,
                x2apic: match self.apic_mode() {
                    vm_topology::processor::x86::ApicMode::XApic => X2ApicConfig::Unsupported,
                    vm_topology::processor::x86::ApicMode::X2ApicSupported => {
                        X2ApicConfig::Supported
                    }
                    vm_topology::processor::x86::ApicMode::X2ApicEnabled => X2ApicConfig::Enabled,
                },
            },
        }
    }
}

impl BuildTopology<X86Topology> for ProcessorTopologyConfig<X86TopologyConfig> {
    fn to_topology(&self) -> anyhow::Result<ProcessorTopology<X86Topology>> {
        let mut builder = TopologyBuilder::from_host_topology()?;
        builder.apic_id_offset(self.arch.apic_id_offset);
        if let Some(smt) = self.enable_smt {
            builder.smt_enabled(smt);
        }
        if let Some(count) = self.vps_per_socket {
            builder.vps_per_socket(count);
        }
        let x2apic = match self.arch.x2apic {
            X2ApicConfig::Auto => {
                // FUTURE: query the hypervisor for a recommendation.
                X2ApicState::Supported
            }
            X2ApicConfig::Supported => X2ApicState::Supported,
            X2ApicConfig::Unsupported => X2ApicState::Unsupported,
            X2ApicConfig::Enabled => X2ApicState::Enabled,
        };
        builder.x2apic(x2apic);
        Ok(builder.build(self.proc_count)?)
    }
}

impl ExtractTopologyConfig for ProcessorTopology<Aarch64Topology> {
    type Config = Aarch64TopologyConfig;
    fn to_config(&self) -> ProcessorTopologyConfig<Aarch64TopologyConfig> {
        ProcessorTopologyConfig {
            proc_count: self.vp_count(),
            vps_per_socket: Some(self.reserved_vps_per_socket()),
            enable_smt: Some(self.smt_enabled()),
            arch: Aarch64TopologyConfig {
                gic_config: Some(GicConfig {
                    gic_distributor_base: self.gic_distributor_base(),
                    gic_redistributors_base: self.gic_redistributors_base(),
                }),
            },
        }
    }
}

impl BuildTopology<Aarch64Topology> for ProcessorTopologyConfig<Aarch64TopologyConfig> {
    fn to_topology(&self) -> anyhow::Result<ProcessorTopology<Aarch64Topology>> {
        let gic = if let Some(gic_config) = &self.arch.gic_config {
            GicInfo {
                gic_distributor_base: gic_config.gic_distributor_base,
                gic_redistributors_base: gic_config.gic_redistributors_base,
            }
        } else {
            GicInfo {
                gic_distributor_base: hvlite_defs::config::DEFAULT_GIC_DISTRIBUTOR_BASE,
                gic_redistributors_base: hvlite_defs::config::DEFAULT_GIC_REDISTRIBUTORS_BASE,
            }
        };

        let mut builder = TopologyBuilder::new_aarch64(gic);
        if let Some(smt) = self.enable_smt {
            builder.smt_enabled(smt);
        }
        if let Some(count) = self.vps_per_socket {
            builder.vps_per_socket(count);
        } else {
            builder.vps_per_socket(self.proc_count);
        }
        Ok(builder.build(self.proc_count)?)
    }
}

/// A VM that has been loaded and can be run.
///
/// Most new state should be added to [`LoadedVmInner`].
pub(crate) struct LoadedVm {
    state_units: StateUnits,
    inner: LoadedVmInner,
    running: bool,
}

/// Most of the VM state for [`LoadedVm`], excluding things that are necessary
/// for state machine transitions.
struct LoadedVmInner {
    driver_source: VmTaskDriverSource,
    resolver: ResourceResolver,
    hypervisor: Hypervisor,
    partition_unit: PartitionUnit,
    partition: Arc<dyn HvlitePartition>,
    _chipset_devices: ChipsetDevices,
    _vmtime: SpawnedUnit<VmTimeKeeper>,
    _scsi_devices: Vec<SpawnedUnit<ChannelUnit<storvsp::StorageDevice>>>,
    memory_manager: GuestMemoryManager,
    gm: GuestMemory,
    vtl0_hvsock_relay: Option<HvsockRelay>,
    vtl2_hvsock_relay: Option<HvsockRelay>,
    vmbus_server: Option<VmbusServerHandle>,
    vtl2_vmbus_server: Option<VmbusServerHandle>,
    #[cfg(windows)]
    _vmbus_proxy: Option<vmbus_server::ProxyIntegration>,
    #[cfg(windows)]
    _kernel_vmnics: Vec<vmswitch::kernel::KernelVmNic>,
    memory_cfg: MemoryConfig,
    mem_layout: MemoryLayout,
    processor_topology: ProcessorTopology,
    hypervisor_cfg: HypervisorConfig,
    vmbus_redirect: bool,
    vmbus_devices: Vec<SpawnedUnit<ChannelUnit<dyn VmbusDevice>>>,

    input_distributor: SpawnedUnit<InputDistributor>,
    vtl2_framebuffer_gpa_base: Option<u64>,

    // TODO reclaim these from existing threads
    virtio_serial: Option<SerialPipes>,

    chipset_cfg: BaseChipsetManifest,
    #[cfg_attr(not(guest_arch = "x86_64"), allow(dead_code))]
    virtio_mmio_count: usize,
    #[cfg_attr(not(guest_arch = "x86_64"), allow(dead_code))]
    virtio_mmio_irq: u32,
    /// ((device, function), interrupt)
    #[cfg_attr(not(guest_arch = "x86_64"), allow(dead_code))]
    pci_legacy_interrupts: Vec<((u8, Option<u8>), u32)>,
    firmware_event_send: Option<mesh::MpscSender<get_resources::ged::FirmwareEvent>>,

    load_mode: LoadMode,
    igvm_file: Option<IgvmFile>,
    next_igvm_file: Option<IgvmFile>,
    _vmgs_task: Option<Task<()>>,
    vmgs_client_inspect_handle: Option<vmgs_broker::VmgsClient>,
}

fn choose_hypervisor() -> anyhow::Result<Hypervisor> {
    cfg_if! {
        if #[cfg(target_os = "linux")] {
            #[cfg(all(feature = "virt_mshv", guest_is_native, guest_arch = "x86_64"))]
            if virt::Hypervisor::is_available(&virt_mshv::LinuxMshv)? {
                return Ok(Hypervisor::MsHv);
            }
            #[cfg(all(feature = "virt_kvm", guest_is_native))]
            if virt::Hypervisor::is_available(&virt_kvm::Kvm)? {
                return Ok(Hypervisor::Kvm);
            }
        } else if #[cfg(all(target_os = "windows", guest_is_native))] {
            #[cfg(feature = "virt_whp")]
            if virt::Hypervisor::is_available(&virt_whp::Whp)? {
                return Ok(Hypervisor::Whp);
            }
        } else if #[cfg(all(target_os = "macos", guest_is_native, guest_arch = "aarch64"))] {
            #[cfg(feature = "virt_hvf")]
            if virt::Hypervisor::is_available(&virt_hvf::HvfHypervisor)? {
                return Ok(Hypervisor::Hvf);
            }
        }
    }
    anyhow::bail!("no hypervisor available");
}

fn convert_vtl2_config(
    vtl2_cfg: Option<&Vtl2Config>,
    load_mode: &LoadMode,
    igvm_file: Option<&IgvmFile>,
) -> anyhow::Result<Option<virt::Vtl2Config>> {
    let vtl2_cfg = match vtl2_cfg {
        Some(cfg) => cfg,
        None => return Ok(None),
    };

    let late_map_vtl0_memory = match vtl2_cfg.late_map_vtl0_memory {
        Some(policy) => {
            use super::vm_loaders::igvm::vtl2_memory_info;
            use virt::LateMapVtl0AllowedRanges;
            let igvm_file = igvm_file.context("vtl2 configured but not loading from igvm")?;

            let allowed_ranges = if let LoadMode::Igvm {
                vtl2_base_address, ..
            } = load_mode
            {
                let range = vtl2_memory_info(igvm_file).context("invalid igvm file")?;
                match vtl2_base_address {
                    Vtl2BaseAddressType::File => {
                        // Allowed range is the file range as-is.
                        LateMapVtl0AllowedRanges::Ranges(vec![range])
                    }
                    Vtl2BaseAddressType::Absolute(base) => {
                        // This file must support relocations.
                        if !crate::worker::vm_loaders::igvm::supports_relocations(igvm_file) {
                            anyhow::bail!("vtl2 base address is absolute but igvm file does not support relocations");
                        }

                        // Use the size, but the base is the requested load
                        // base.
                        LateMapVtl0AllowedRanges::Ranges(vec![MemoryRange::new(
                            *base..(*base + range.len()),
                        )])
                    }
                    Vtl2BaseAddressType::MemoryLayout { .. } => {
                        LateMapVtl0AllowedRanges::MemoryLayout
                    }
                    Vtl2BaseAddressType::Vtl2Allocate { .. } => {
                        // When VTL2 is doing allocation, we do not know which
                        // ranges we should disallow late map access of.
                        anyhow::bail!("late map vtl0 memory is not supported when VTL2 is doing self allocation of ram");
                    }
                }
            } else {
                anyhow::bail!("vtl2 configured but not loading from igvm");
            };

            Some(virt::LateMapVtl0MemoryConfig {
                allowed_ranges,
                policy: policy.into(),
            })
        }
        None => None,
    };

    let config = virt::Vtl2Config {
        vtl0_alias_map: vtl2_cfg.vtl0_alias_map,
        late_map_vtl0_memory,
    };

    Ok(Some(config))
}

impl InitializedVm {
    /// Creates and initializes a VM.
    async fn new(
        driver_source: VmTaskDriverSource,
        hypervisor: Hypervisor,
        cfg: Manifest,
        shared_memory: Option<SharedMemoryBacking>,
    ) -> anyhow::Result<Self> {
        match hypervisor {
            #[cfg(all(target_os = "linux", feature = "virt_kvm", guest_is_native))]
            Hypervisor::Kvm => {
                Self::new_with_hypervisor(
                    driver_source,
                    &mut virt_kvm::Kvm,
                    hypervisor,
                    cfg,
                    shared_memory,
                )
                .await
            }
            #[cfg(all(
                target_os = "linux",
                feature = "virt_mshv",
                guest_is_native,
                guest_arch = "x86_64"
            ))]
            Hypervisor::MsHv => {
                Self::new_with_hypervisor(
                    driver_source,
                    &mut virt_mshv::LinuxMshv,
                    hypervisor,
                    cfg,
                    shared_memory,
                )
                .await
            }
            #[cfg(all(target_os = "windows", feature = "virt_whp", guest_is_native))]
            Hypervisor::Whp => {
                Self::new_with_hypervisor(
                    driver_source,
                    &mut virt_whp::Whp,
                    hypervisor,
                    cfg,
                    shared_memory,
                )
                .await
            }
            #[cfg(all(
                target_os = "macos",
                guest_arch = "aarch64",
                guest_is_native,
                feature = "virt_hvf"
            ))]
            Hypervisor::Hvf => {
                Self::new_with_hypervisor(
                    driver_source,
                    &mut virt_hvf::HvfHypervisor,
                    hypervisor,
                    cfg,
                    shared_memory,
                )
                .await
            }
            _ => {
                let _ = (cfg, driver_source, shared_memory);
                anyhow::bail!("hypervisor {} not supported", hypervisor);
            }
        }
    }

    #[allow(dead_code)]
    async fn new_with_hypervisor<P, H>(
        driver_source: VmTaskDriverSource,
        hypervisor: &mut H,
        hypervisor_type: Hypervisor,
        cfg: Manifest,
        shared_memory: Option<SharedMemoryBacking>,
    ) -> anyhow::Result<Self>
    where
        H: virt::Hypervisor<Partition = P>,
        P: 'static + HvlitePartition,
    {
        tracing::info!(mem_size = cfg.memory.mem_size, "guest RAM config");

        let vmtime_keeper = VmTimeKeeper::new(&driver_source.simple(), VmTime::from_100ns(0));
        let vmtime_source = vmtime_keeper
            .builder()
            .build(&driver_source.simple())
            .await
            .unwrap();

        // Pre-parse the igvm file early.
        let igvm_file = if let LoadMode::Igvm { file, .. } = &cfg.load_mode {
            let igvm_file = super::vm_loaders::igvm::read_igvm_file(file)
                .context("reading igvm file failed")?;
            Some(igvm_file)
        } else {
            None
        };

        let hv_config = if cfg.hypervisor.with_hv {
            cfg_if::cfg_if! {
                if #[cfg(all(windows, feature = "virt_whp"))] {
                    let allow_device_assignment = !cfg.vpci_resources.is_empty();
                } else {
                    let allow_device_assignment = false;
                }
            }

            Some(virt::HvConfig {
                offload_enlightenments: !cfg.hypervisor.user_mode_hv_enlightenments,
                allow_device_assignment,
                vtl2: convert_vtl2_config(
                    cfg.hypervisor.with_vtl2.as_ref(),
                    &cfg.load_mode,
                    igvm_file.as_ref(),
                )?,
            })
        } else {
            None
        };

        let processor_topology = cfg.processor_topology.to_topology()?;

        let proto = hypervisor
            .new_partition(virt::ProtoPartitionConfig {
                processor_topology: &processor_topology,
                hv_config,
                vmtime: &vmtime_source,
                user_mode_apic: cfg.hypervisor.user_mode_apic,
                isolation: cfg
                    .hypervisor
                    .with_isolation
                    .map(|typ| typ.into())
                    .unwrap_or(virt::IsolationType::None),
            })
            .context("failed to create the prototype partition")?;

        let physical_address_size = proto.max_physical_address_size();

        // Determine if a special vtl2 memory allocation should be used.
        let vtl2_range = if let LoadMode::Igvm {
            vtl2_base_address, ..
        } = &cfg.load_mode
        {
            match vtl2_base_address {
                Vtl2BaseAddressType::File
                | Vtl2BaseAddressType::Absolute(_)
                | Vtl2BaseAddressType::Vtl2Allocate { .. } => None,
                Vtl2BaseAddressType::MemoryLayout { size } => {
                    let vtl2_range = super::vm_loaders::igvm::vtl2_memory_range(
                        physical_address_size,
                        cfg.memory.mem_size,
                        &cfg.memory.mmio_gaps,
                        igvm_file
                            .as_ref()
                            .expect("igvm file should be already parsed"),
                        *size,
                    )
                    .context("unable to determine vtl2 memory range")?;
                    tracing::info!(?vtl2_range, "vtl2 memory range selected");

                    Some(vtl2_range)
                }
            }
        } else {
            None
        };

        // Choose the memory layout of the VM.
        let mem_layout = MemoryLayout::new(
            physical_address_size,
            cfg.memory.mem_size,
            &cfg.memory.mmio_gaps,
            vtl2_range,
        )
        .context("invalid memory configuration")?;

        let mut memory_builder = GuestMemoryBuilder::new();
        memory_builder = memory_builder
            .existing_backing(shared_memory)
            .vtl0_alias_map(
                cfg.hypervisor
                    .with_vtl2
                    .as_ref()
                    .map(|cfg| cfg.vtl0_alias_map)
                    .unwrap_or_default(),
            )
            .prefetch_ram(cfg.memory.prefetch_memory)
            .x86_legacy_support(
                matches!(cfg.load_mode, LoadMode::Pcat { .. }) || cfg.chipset.with_hyperv_vga,
            );

        #[cfg(all(windows, feature = "virt_whp"))]
        if !cfg.vpci_resources.is_empty() {
            memory_builder = memory_builder.pin_mappings(true);
        }

        cfg_if! {
            if #[cfg(windows)] {
                let vtl2_memory_process = if cfg.hypervisor.with_vtl2.is_some() {
                    // VTL2 needs a separate memory hosting process.
                    let process = pal::windows::process::empty_process()
                        .context("could not launch a memory process for VTL2")?;
                    Some(Box::new(process) as _)
                } else {
                    None
                };
            } else {
                let vtl2_memory_process = None;
            }
        }

        let mut memory_manager = memory_builder
            .build(&mem_layout)
            .await
            .context("failed to build guest memory")?;

        let gm = memory_manager
            .client()
            .guest_memory()
            .await
            .context("failed to get guest memory")?;
        let mut cpuid = Vec::new();

        // Add in Hyper-V VMM CPUID leaves.
        if cfg.hypervisor.with_hv {
            // Only advertise extended IOAPIC on non-PCAT systems.
            let extended_ioapic_rte = !matches!(cfg.load_mode, LoadMode::Pcat { .. });
            cpuid.extend(vmm_core::cpuid::hyperv_cpuid_leaves(extended_ioapic_rte));
        }

        // Add in topology CPUID leaves.
        #[cfg(guest_arch = "x86_64")]
        vmm_core::cpuid::topology::topology_cpuid(
            &processor_topology,
            &|eax, ecx| proto.cpuid(eax, ecx),
            &mut cpuid,
        )
        .context("failed to compute topology cpuid")?;

        let (partition, vps) = proto
            .build(virt::PartitionConfig {
                mem_layout: &mem_layout,
                guest_memory: &gm,
                cpuid: &cpuid,
            })
            .context("failed to create the partition")?;

        let vps = vps.into_iter().map(|vp| Box::new(vp) as _).collect();

        let partition = Arc::new(partition);

        memory_manager
            .attach_partition(Vtl::Vtl0, &partition.memory_mapper(Vtl::Vtl0), None)
            .await
            .context("failed to attach memory to the partition")?;

        if cfg.hypervisor.with_vtl2.is_some() {
            memory_manager
                .attach_partition(
                    Vtl::Vtl2,
                    &partition.memory_mapper(Vtl::Vtl2),
                    vtl2_memory_process,
                )
                .await
                .context("failed to attach memory to VTL2")?;
        }

        Ok(Self {
            hypervisor: hypervisor_type,
            partition,
            vps,
            vmtime_keeper,
            vmtime_source,
            memory_manager,
            gm,
            cfg,
            mem_layout,
            processor_topology,
            igvm_file,
            driver_source,
        })
    }

    /// Loads the state for an initialized VM.
    ///
    // FUTURE: move more of this logic into new() so that more can be done
    //         outside the VM-PHU/live migration blackout window.
    async fn load(
        self,
        saved_state: Option<SavedState>,
        client_notify_send: mesh::Sender<HaltReason>,
    ) -> Result<LoadedVm, anyhow::Error> {
        use vmotherboard::options::dev;

        let Self {
            hypervisor,
            partition,
            vps,
            vmtime_keeper,
            vmtime_source,
            memory_manager,
            gm,
            cfg,
            mem_layout,
            processor_topology,
            igvm_file,
            driver_source,
        } = self;

        let mut resolver = ResourceResolver::new();

        let (vmgs_client, vmgs_task) = if let Some(vmgs_file) = cfg.vmgs_disk {
            let disk = open_simple_disk(&resolver, vmgs_file, false).await?;
            let vmgs = if cfg.format_vmgs {
                vmgs::Vmgs::format_new(disk)
                    .await
                    .context("failed to format vmgs file")?
            } else {
                vmgs::Vmgs::open(disk)
                    .await
                    .context("failed to open vmgs file")?
            };

            let (vmgs_client, vmgs_task) =
                vmgs_broker::spawn_vmgs_broker(driver_source.builder().build("vmgs_broker"), vmgs);
            resolver.add_resolver(VmgsFileResolver::new(vmgs_client.clone()));
            (Some(vmgs_client), Some(vmgs_task))
        } else {
            (None, None)
        };

        // For sanity: we immediately restrict `vmgs_client` to the
        // `HvLiteVmgsNonVolatileStore` API, since we don't want code past this
        // point to interact with VMGS as anything but an opaque
        // `NonVolatileStore`
        //
        // ...but we keep a reference to the original untyped client, since we need
        // to pass it to LoadedVm so that we can `inspect` VMGS at runtime.
        let vmgs_client_inspect_handle = vmgs_client.clone();
        let vmgs_client: Option<&dyn HvLiteVmgsNonVolatileStore> =
            vmgs_client.as_ref().map(|x| x as _);

        let (halt_vps, halt_request_recv) = Halt::new();
        let halt_vps = Arc::new(halt_vps);

        resolver.add_resolver(vmm_core::platform_resolvers::HaltResolver(halt_vps.clone()));

        // Save the serial handles for restart.
        //
        // TODO: instead, take the handles back from the serial device and input threads.
        let virtio_serial_dup = cfg
            .virtio_serial
            .as_ref()
            .map(|p| p.try_clone())
            .transpose()
            .context("cloning virtio_serial")?;

        let generation_id_recv = cfg.generation_id_recv.unwrap_or_else(|| mesh::channel().1);

        let logger = Box::new(emuplat::firmware::MeshLogger::new(
            cfg.firmware_event_send.clone(),
        ));

        let mapper = memory_manager.device_memory_mapper();

        #[cfg_attr(not(guest_arch = "x86_64"), allow(unused_mut))]
        let mut deps_hyperv_firmware_pcat = None;
        let mut deps_hyperv_firmware_uefi = None;
        match &cfg.load_mode {
            LoadMode::Uefi { .. } => {
                deps_hyperv_firmware_uefi = Some(dev::HyperVFirmwareUefi {
                    config: firmware_uefi::UefiConfig {
                        custom_uefi_vars: cfg.custom_uefi_vars,
                        secure_boot: cfg.secure_boot_enabled,
                        initial_generation_id: {
                            let mut generation_id = [0; 16];
                            getrandom::getrandom(&mut generation_id).expect("rng failure");
                            generation_id
                        },
                        use_mmio: cfg!(not(guest_arch = "x86_64")),
                        command_set: if cfg!(guest_arch = "x86_64") {
                            UefiCommandSet::X64
                        } else {
                            UefiCommandSet::Aarch64
                        },
                    },
                    logger,
                    nvram_storage: {
                        use hcl_compat_uefi_nvram_storage::HclCompatNvram;
                        use uefi_nvram_storage::in_memory::InMemoryNvram;
                        use vmm_core::emuplat::hcl_compat_uefi_nvram_storage::VmgsStorageBackendAdapter;

                        match vmgs_client {
                            Some(vmgs) => Box::new(HclCompatNvram::new(
                                VmgsStorageBackendAdapter(
                                    vmgs.as_non_volatile_store(vmgs::FileId::BIOS_NVRAM, true)
                                        .context("failed to instantiate UEFI NVRAM store")?,
                                ),
                                None,
                            )),
                            None => Box::new(InMemoryNvram::new()),
                        }
                    },
                    generation_id_recv,
                    watchdog_platform: {
                        use emuplat::watchdog::HvLiteWatchdogPlatform;
                        use vmcore::non_volatile_store::EphemeralNonVolatileStore;

                        // UEFI watchdog doesn't persist to VMGS at this time
                        let store = EphemeralNonVolatileStore::new_boxed();

                        // Request an NMI on watchdog timeout.
                        #[cfg(guest_arch = "x86_64")]
                        let on_timeout = {
                            let partition = partition.clone();
                            Box::new(move || {
                                // Unlike Hyper-V, we only send the NMI to the BSP.
                                partition.request_msi(
                                    Vtl::Vtl0,
                                    virt::irqcon::MsiRequest::new_x86(
                                        virt::irqcon::DeliveryMode::NMI,
                                        0,
                                        false,
                                        0,
                                        false,
                                    ),
                                );
                            })
                        };
                        #[cfg(guest_arch = "aarch64")]
                        let on_timeout = {
                            let halt = halt_vps.clone();
                            Box::new(move || halt.halt(HaltReason::Reset))
                        };

                        Box::new(HvLiteWatchdogPlatform::new(store, on_timeout).await?)
                    },
                    vsm_config: None,
                    // TODO: persist SystemTimeClock time across reboots.
                    time_source: Box::new(local_clock::SystemTimeClock::new()),
                })
            }
            #[cfg(guest_arch = "x86_64")]
            LoadMode::Pcat {
                firmware,
                boot_order,
            } => {
                tracing::debug!(?firmware, "Loading BIOS firmware.");
                let rom_builder = RomBuilder::new("bios".into(), Box::new(mapper.clone()));
                let rom = rom_builder.build_from_file_location(firmware)?;
                // TODO: move mtrr replay to a resource.
                let halt_vps = halt_vps.clone();
                deps_hyperv_firmware_pcat = Some(dev::HyperVFirmwarePcat {
                    logger,
                    generation_id_recv,
                    rom: Some(Box::new(rom)),
                    replay_mtrrs: Box::new(move || halt_vps.replay_mtrrs()),
                    config: {
                        let acpi_tables_builder = AcpiTablesBuilder {
                            processor_topology: &processor_topology,
                            mem_layout: &mem_layout,
                            cache_topology: None,
                            with_ioapic: cfg.chipset.with_generic_ioapic,
                            with_pic: cfg.chipset.with_generic_pic,
                            with_pit: cfg.chipset.with_generic_pit,
                            with_psp: cfg.chipset.with_generic_psp,
                            pm_base: PM_BASE,
                            acpi_irq: SYSTEM_IRQ_ACPI,
                        };
                        let srat = acpi_tables_builder.build_srat();
                        firmware_pcat::config::PcatBiosConfig {
                            processor_topology: processor_topology.clone(),
                            mem_layout: mem_layout.clone(),
                            srat,

                            hibernation_enabled: false,
                            initial_generation_id: {
                                let mut generation_id = [0; 16];
                                getrandom::getrandom(&mut generation_id).expect("rng failure");
                                generation_id
                            },
                            boot_order: {
                                use firmware_pcat::config::BootDevice;
                                use firmware_pcat::config::BootDeviceStatus;
                                use hvlite_defs::config::PcatBootDevice;
                                boot_order.map(|dev| BootDeviceStatus {
                                    kind: match dev {
                                        PcatBootDevice::Floppy => BootDevice::Floppy,
                                        PcatBootDevice::HardDrive => BootDevice::HardDrive,
                                        PcatBootDevice::Optical => BootDevice::Optical,
                                        PcatBootDevice::Network => BootDevice::Network,
                                    },
                                    // TODO: accurately model this?
                                    attached: true,
                                })
                            },
                            num_lock_enabled: false,
                            // TODO: these are all very bogus values, and need to be swapped out with something better
                            smbios: firmware_pcat::config::SmbiosConstants {
                                bios_guid: Guid {
                                    data1: 0xC4066C45,
                                    data2: 0x503D,
                                    data3: 0x40E8,
                                    data4: [0xB1, 0x5C, 0x31, 0x26, 0x4E, 0x5F, 0xE1, 0xD9],
                                },
                                system_serial_number: "9583-9572-9874-4843-7295-1653-92".into(),
                                base_board_serial_number: "9583-9572-9874-4843-7295-1653-92".into(),
                                chassis_serial_number: "9583-9572-9874-4843-7295-1653-92".into(),
                                chassis_asset_tag: "9583-9572-9874-4843-7295-1653-92".into(),
                                bios_lock_string: "00000000000000000000000000000000".into(),
                                processor_manufacturer: b"\0".to_vec(),
                                processor_version: b"\0".to_vec(),
                                cpu_info_bundle: None,
                            },
                        }
                    },
                })
            }
            _ => {}
        };

        let synic = Arc::new(SynicPorts::new(partition.clone().into_synic()));

        let vtl2_framebuffer_gpa_base = if cfg.vtl2_gfx {
            // calculate a safe place to put the framebuffer mapping in GPA space
            // this places it after the end of ram at the first place it won't overlap with MMIO
            let len = cfg
                .framebuffer
                .as_ref()
                .context("no framebuffer configured")?
                .len();
            let mut gpa = mem_layout.end_of_ram();
            for mmio in mem_layout.mmio() {
                if gpa < mmio.end() && mmio.start() < gpa + len as u64 {
                    gpa = mmio.end();
                }
            }
            tracing::debug!("Vtl2 framebuffer gpa base: {:#x}", gpa);
            Some(gpa)
        } else {
            None
        };

        let state_units = StateUnits::new();

        let vmtime = state_units
            .add("vmtime")
            .spawn(driver_source.simple(), {
                |recv| {
                    let mut vmtime = vmtime_keeper;
                    async move {
                        vmm_core::vmtime_unit::run_vmtime(&mut vmtime, recv).await;
                        vmtime
                    }
                }
            })
            .unwrap();

        let mut input_distributor = InputDistributor::new(cfg.input);
        resolver.add_async_resolver::<KeyboardInputHandleKind, _, MultiplexedInputHandle, _>(
            input_distributor.client().clone(),
        );
        resolver.add_async_resolver::<MouseInputHandleKind, _, MultiplexedInputHandle, _>(
            input_distributor.client().clone(),
        );

        let input_distributor = state_units
            .add("input")
            .spawn(driver_source.simple(), |mut recv| async move {
                input_distributor.run(&mut recv).await;
                input_distributor
            })
            .unwrap();

        let mut pci_legacy_interrupts = Vec::new();

        let mut ide_drives = [[None, None], [None, None]];
        let mut storvsp_ide_disks = Vec::new();
        if cfg.chipset.with_hyperv_ide {
            pci_legacy_interrupts.push(((7, None), 14));
            pci_legacy_interrupts.push(((7, None), 15));

            for disk_cfg in cfg.ide_disks {
                let path = disk_cfg.path;
                let media = match disk_cfg.guest_media {
                    GuestMedia::Dvd(disk_type) => {
                        let dvd = resolver
                            .resolve(
                                disk_type,
                                ResolveScsiDeviceHandleParams {
                                    driver_source: &driver_source,
                                },
                            )
                            .await
                            .context("failed to open IDE DVD")?;

                        let scsi_disk = Arc::new(AtapiScsiDisk::new(dvd.0));
                        ide::DriveMedia::optical_disk(scsi_disk.clone())
                    }
                    GuestMedia::Disk {
                        disk_type,
                        read_only,
                        disk_parameters,
                    } => {
                        let disk = open_simple_disk(&resolver, disk_type, read_only)
                            .await
                            .context("failed to open IDE disk")?;

                        // Only disks get accelerator channels. DVDs dont.
                        let scsi_disk = ScsiControllerDisk::new(Arc::new(SimpleScsiDisk::new(
                            disk.clone(),
                            disk_parameters.unwrap_or_default(),
                        )));
                        storvsp_ide_disks.push((path, scsi_disk));
                        ide::DriveMedia::hard_disk(disk.clone())
                    }
                };

                let old_media = ide_drives
                    .get_mut(path.channel as usize)
                    .context("invalid ide channel")?
                    .get_mut(path.drive as usize)
                    .context("invalid ide device")?
                    .replace(media);

                if old_media.is_some() {
                    anyhow::bail!(
                        "ide drive {}:{} is already in use",
                        path.channel,
                        path.drive
                    );
                }
            }
        }

        let deps_hyperv_guest_watchdog = if cfg.chipset.with_hyperv_guest_watchdog {
            Some(dev::HyperVGuestWatchdogDeps {
                port_base: WDAT_PORT,
                watchdog_platform: {
                    use emuplat::watchdog::HvLiteWatchdogPlatform;
                    use vmcore::non_volatile_store::EphemeralNonVolatileStore;

                    let store = match vmgs_client {
                        Some(vmgs) => vmgs
                            .as_non_volatile_store(vmgs::FileId::GUEST_WATCHDOG, false)
                            .context("failed to instantiate guest watchdog store")?,
                        None => EphemeralNonVolatileStore::new_boxed(),
                    };

                    // TODO: use a `PowerRequestHandleKind` resource.
                    let trigger_reset = {
                        let halt = halt_vps.clone();
                        Box::new(move || halt.halt(HaltReason::Reset))
                    };

                    Box::new(HvLiteWatchdogPlatform::new(store, trigger_reset).await?)
                },
            })
        } else {
            None
        };

        let initial_rtc_cmos = if matches!(cfg.load_mode, LoadMode::Pcat { .. }) {
            Some(firmware_pcat::default_cmos_values(&mem_layout))
        } else {
            None
        };

        let deps_generic_cmos_rtc = (cfg.chipset.with_generic_cmos_rtc).then(|| {
            // TODO: persist SystemTimeClock time across reboots.
            // TODO: move to instantiate via a resource.
            let time_source = Box::new(local_clock::SystemTimeClock::new());
            dev::GenericCmosRtcDeps {
                irq: 8,
                time_source,
                century_reg_idx: 0x32, // TODO: automatically sync with FADT
                initial_cmos: initial_rtc_cmos,
            }
        });

        #[cfg(guest_arch = "x86_64")]
        let deps_generic_ioapic =
            (cfg.chipset.with_generic_ioapic).then(|| dev::GenericIoApicDeps {
                num_entries: virt::irqcon::IRQ_LINES as u8,
                routing: Box::new(vmm_core::emuplat::ioapic::IoApicRouting(
                    partition.clone().ioapic_routing(),
                )),
            });

        #[cfg(guest_arch = "aarch64")]
        let deps_generic_ioapic = if cfg.chipset.with_generic_ioapic {
            anyhow::bail!("ioapic not supported on this architecture");
        } else {
            None
        };

        let deps_generic_isa_dma =
            (cfg.chipset.with_generic_isa_dma).then_some(dev::GenericIsaDmaDeps {});

        let mut primary_disk_drive = floppy::DriveRibbon::None;
        let mut secondary_disk_drive = floppy::DriveRibbon::None;
        if cfg.chipset.with_winbond_super_io_and_floppy_full {
            let mut pri_drives = Vec::new();
            let mut sec_drives = Vec::new();
            for (index, disk_cfg) in cfg.floppy_disks.into_iter().enumerate() {
                let FloppyDiskConfig {
                    disk_type,
                    read_only,
                } = disk_cfg;

                let disk = open_simple_disk(&resolver, disk_type, read_only)
                    .await
                    .context("failed to open floppy disk")?;
                tracing::trace!("floppy opened based on config into DriveRibbon");

                if index == 0 {
                    pri_drives.push(disk);
                } else if index == 1 {
                    sec_drives.push(disk)
                } else {
                    tracing::error!("more than 2 floppy controllers are not supported");
                    break;
                }
            }

            primary_disk_drive = floppy::DriveRibbon::from_vec(pri_drives)?;
            secondary_disk_drive = floppy::DriveRibbon::from_vec(sec_drives)?;
        }

        // must enforce exclusivity here due to how the
        // `{primary,secondary}_disk_drive` vars get "claimed" by each device.
        let (deps_generic_isa_floppy, deps_winbond_super_io_and_floppy_full) = match (
            cfg.chipset.with_generic_isa_floppy,
            cfg.chipset.with_winbond_super_io_and_floppy_full,
        ) {
            (true, true) => anyhow::bail!("cannot have both generic and winbond floppy"),
            (true, false) => {
                if !matches!(secondary_disk_drive, floppy::DriveRibbon::None) {
                    anyhow::bail!("more than 1 generic floppy controller is not supported")
                }

                (
                    // Use "standard" ISA constants for IRQ, DMA, and IO Port
                    // assignment
                    Some(dev::GenericIsaFloppyDeps {
                        irq: 6,
                        dma_channel: 2,
                        pio_base: 0x3f0,
                        drives: primary_disk_drive,
                    }),
                    None,
                )
            }
            (false, true) => (
                None,
                Some(dev::WinbondSuperIoAndFloppyFullDeps {
                    primary_disk_drive,
                    secondary_disk_drive,
                }),
            ),
            (false, false) => (None, None),
        };

        let pci_bus_id_generic = vmotherboard::BusId::new("generic");
        let pci_bus_id_piix4 = vmotherboard::BusId::new("i440bx");

        let deps_generic_pci_bus =
            (cfg.chipset.with_generic_pci_bus).then_some(dev::GenericPciBusDeps {
                bus_id: pci_bus_id_generic.clone(),
                pio_addr: pci_bus::standard_x86_io_ports::ADDR_START,
                pio_data: pci_bus::standard_x86_io_ports::DATA_START,
            });

        let deps_generic_pic = (cfg.chipset.with_generic_pic).then_some(dev::GenericPicDeps {});

        let deps_generic_pit = (cfg.chipset.with_generic_pit).then_some(dev::GenericPitDeps {});
        let deps_generic_psp = (cfg.chipset.with_generic_psp).then_some(dev::GenericPspDeps {});

        let deps_hyperv_framebuffer =
            (cfg.chipset.with_hyperv_framebuffer).then(|| dev::HyperVFramebufferDeps {
                fb_mapper: Box::new(mapper.clone()),
                fb: cfg.framebuffer.unwrap(),
                vtl2_framebuffer_gpa_base,
            });

        let deps_hyperv_power_management =
            (cfg.chipset.with_hyperv_power_management).then_some(dev::HyperVPowerManagementDeps {
                acpi_irq: SYSTEM_IRQ_ACPI,
                pio_base: PM_BASE,
                pm_timer_assist: None,
            });

        let deps_hyperv_vga = if cfg.chipset.with_hyperv_vga {
            let vga_firmware = cfg.vga_firmware.as_ref().context("no VGA BIOS file")?;
            let rom_builder = RomBuilder::new("vga".into(), Box::new(mapper.clone()));
            let rom = rom_builder.build_from_file_location(vga_firmware)?;

            Some(dev::HyperVVgaDeps {
                attached_to: pci_bus_id_piix4.clone(),
                rom: Some(Box::new(rom)),
            })
        } else {
            None
        };

        let deps_i440bx_host_pci_bridge =
            (cfg.chipset.with_i440bx_host_pci_bridge).then(|| dev::I440BxHostPciBridgeDeps {
                attached_to: pci_bus_id_piix4.clone(),
                adjust_gpa_range: Box::new(
                    emuplat::i440bx_host_pci_bridge::ManageRamGpaRange::new(
                        memory_manager.ram_visibility_control(),
                    ),
                ),
            });

        let deps_piix4_pci_bus = (cfg.chipset.with_piix4_pci_bus).then(|| dev::Piix4PciBusDeps {
            bus_id: pci_bus_id_piix4.clone(),
        });

        let deps_piix4_cmos_rtc = (cfg.chipset.with_piix4_cmos_rtc).then(|| {
            // TODO: persist SystemTimeClock time across reboots.
            // TODO: move to instantiate via a resource.
            let time_source = Box::new(local_clock::SystemTimeClock::new());
            dev::Piix4CmosRtcDeps {
                time_source,
                initial_cmos: initial_rtc_cmos,
                enlightened_interrupts: true, // As advertised by the PCAT BIOS.
            }
        });

        let [primary_channel_drives, secondary_channel_drives] = ide_drives;
        let deps_hyperv_ide = (cfg.chipset.with_hyperv_ide).then_some(dev::HyperVIdeDeps {
            attached_to: pci_bus_id_piix4.clone(),
            primary_channel_drives,
            secondary_channel_drives,
        });

        let deps_piix4_pci_isa_bridge =
            (cfg.chipset.with_piix4_pci_isa_bridge).then_some(dev::Piix4PciIsaBridgeDeps {
                attached_to: pci_bus_id_piix4.clone(),
            });
        let deps_piix4_pci_usb_uhci_stub =
            (cfg.chipset.with_piix4_pci_usb_uhci_stub).then_some(dev::Piix4PciUsbUhciStubDeps {
                attached_to: pci_bus_id_piix4.clone(),
            });
        let deps_piix4_power_management =
            (cfg.chipset.with_piix4_power_management).then_some(dev::Piix4PowerManagementDeps {
                attached_to: pci_bus_id_piix4.clone(),
                pm_timer_assist: None,
            });

        let base_chipset_devices = {
            BaseChipsetDevices {
                deps_generic_cmos_rtc,
                deps_generic_ioapic,
                deps_generic_isa_dma,
                deps_generic_isa_floppy,
                deps_generic_pci_bus,
                deps_generic_pic,
                deps_generic_pit,
                deps_generic_psp,
                deps_hyperv_firmware_pcat,
                deps_hyperv_firmware_uefi,
                deps_hyperv_framebuffer,
                deps_hyperv_guest_watchdog,
                deps_hyperv_ide,
                deps_hyperv_power_management,
                deps_hyperv_vga,
                deps_i440bx_host_pci_bridge,
                deps_piix4_cmos_rtc,
                deps_piix4_pci_bus,
                deps_piix4_pci_isa_bridge,
                deps_piix4_pci_usb_uhci_stub,
                deps_piix4_power_management,
                deps_underhill_vga_proxy: None,
                deps_winbond_super_io_and_floppy_stub: None,
                deps_winbond_super_io_and_floppy_full,
            }
        };

        let BaseChipsetBuilderOutput {
            mut chipset_builder,
            device_interfaces: base_chipset_device_interfaces,
        } = BaseChipsetBuilder::new(
            BaseChipsetFoundation {
                is_restoring: false,
                untrusted_dma_memory: gm.clone(),
                // There is no access to encrypted memory on the host, so this
                // may be misleading. Presumably in any confidential VM
                // scenario, devices using this will not be present or will be
                // implemented by a paravisor. But it still must be set for
                // non-confidential scenarios.
                trusted_vtl0_dma_memory: gm.clone(),
                power_event_handler: halt_vps.clone(),
                debug_event_handler: halt_vps.clone(),
                vmtime: &vmtime_source,
                vmtime_unit: vmtime.handle(),
                doorbell_registration: partition.clone().into_doorbell_registration(Vtl::Vtl0),
            },
            base_chipset_devices,
        )
        .with_expected_manifest(cfg.chipset.clone())
        .with_device_handles(cfg.chipset_devices)
        .with_trace_unknown_pio(true) // todo: add CLI param?
        .build(&driver_source, &state_units, &resolver)
        .await?;

        if cfg.chipset.with_generic_pci_bus {
            // HACK: We don't currently have an appropriate generic bus root to
            // put on the PCI bus, so we just fake one.
            //
            // This seems to appease Linux just fine
            chipset_builder
                .arc_mutex_device("fake-bus-root")
                .on_pci_bus(pci_bus_id_generic.clone())
                .add(|services| {
                    missing_dev::MissingDev::from_manifest(
                        MissingDevManifest::new().claim_pci((0, 0, 0), 0x8086, 0x7111),
                        &mut services.register_mmio(),
                        &mut services.register_pio(),
                    )
                })?;
        }

        // Add the GIC.
        #[cfg(guest_arch = "aarch64")]
        chipset_builder.add_external_line_target(
            IRQ_LINE_SET,
            0..=vmm_core::emuplat::gic::SPI_RANGE.end() - vmm_core::emuplat::gic::SPI_RANGE.start(),
            *vmm_core::emuplat::gic::SPI_RANGE.start(),
            "gic",
            Arc::new(vmm_core::emuplat::gic::GicInterruptTarget::new(
                partition.clone().control_gic(Vtl::Vtl0),
            )),
        );

        // Add the x86 BSP's LINTs for the PIC to use.
        #[cfg(guest_arch = "x86_64")]
        chipset_builder.add_external_line_target(
            chipset_device_resources::BSP_LINT_LINE_SET,
            0..=1,
            0,
            "bsp",
            partition.clone().into_lint_target(Vtl::Vtl0),
        );

        if let Some(framebuffer) = base_chipset_device_interfaces.framebuffer_local_control {
            resolver.add_resolver(framebuffer);
        }

        let pci_inta_line = {
            const PCI_LEGACY_INTA_IRQ: u32 = 11;
            const PCI_INTA_IRQ: u32 = 16;
            if cfg.chipset.with_i440bx_host_pci_bridge {
                // Hyper-V hard-wires this to 11.
                Some(PCI_LEGACY_INTA_IRQ)
            } else if cfg.chipset.with_generic_pci_bus {
                // Avoid an ISA interrupt to avoid conflicts and to avoid needing to
                // configure the line as level-triggered in the MADT (necessary for
                // Linux when the PIC is missing).
                if cfg.chipset.with_generic_pic {
                    Some(PCI_LEGACY_INTA_IRQ)
                } else {
                    Some(PCI_INTA_IRQ)
                }
            } else {
                None
            }
        };

        let mut scsi_devices = Vec::new();
        let mut vtl0_hvsock_relay = None;
        #[cfg(windows)]
        let mut vmbus_proxy = None;
        #[cfg(windows)]
        let mut kernel_vmnics = Vec::new();
        let mut vpci_serial: Option<virtio_serial::SerialIo> = None;
        let mut vmbus_server = None;
        let mut vtl2_vmbus_server = None;
        let mut vtl2_hvsock_relay = None;
        let mut vmbus_redirect = false;

        if let Some(vmbus_cfg) = cfg.vmbus {
            if !cfg.hypervisor.with_hv {
                anyhow::bail!("vmbus required hypervisor enlightements");
            }

            vmbus_redirect = vmbus_cfg.vtl2_redirect;
            let hvsock_channel = HvsockRelayChannel::new();

            let (vtl2_vmbus, vtl2_request_send) = if let Some(vtl2_vmbus_cfg) = cfg.vtl2_vmbus {
                let (server_request_send, server_request_recv) = mesh::channel();
                let vtl2_hvsock_channel = HvsockRelayChannel::new();

                let vmbus_driver = driver_source.simple();
                let vtl2_vmbus = VmbusServer::builder(&vmbus_driver, synic.clone(), gm.clone())
                    .vtl(Vtl::Vtl2)
                    .max_version(
                        vtl2_vmbus_cfg
                            .vmbus_max_version
                            .map(vmbus_core::MaxVersionInfo::new),
                    )
                    .hvsock_notify(Some(vtl2_hvsock_channel.server_half))
                    .external_requests(Some(server_request_recv))
                    .enable_mnf(true)
                    .build()
                    .context("failed to create VTL2 vmbus server")?;

                let vtl2_vmbus = VmbusServerHandle::new(
                    &vmbus_driver,
                    state_units.add("vtl2_vmbus"),
                    vtl2_vmbus,
                )
                .context("failed to add vmbus state unit")?;

                let relay = HvsockRelay::new(
                    vmbus_driver,
                    vtl2_vmbus.control().clone(),
                    vtl2_hvsock_channel.relay_half,
                    vtl2_vmbus_cfg.vsock_path.map(Into::into),
                    vtl2_vmbus_cfg.vsock_listener,
                )
                .context("failed to create vtl2 hvsock relay")?;

                vtl2_hvsock_relay = Some(relay);

                (Some(vtl2_vmbus), Some(server_request_send))
            } else {
                (None, None)
            };

            let vmbus_driver = driver_source.simple();
            let vmbus = VmbusServer::builder(&vmbus_driver, synic.clone(), gm.clone())
                .hvsock_notify(Some(hvsock_channel.server_half))
                .external_server(vtl2_request_send)
                .use_message_redirect(vmbus_cfg.vtl2_redirect)
                .max_version(
                    vmbus_cfg
                        .vmbus_max_version
                        .map(vmbus_core::MaxVersionInfo::new),
                )
                .delay_max_version(matches!(cfg.load_mode, LoadMode::Uefi { .. }))
                .enable_mnf(true)
                .build()
                .context("failed to create vmbus server")?;

            // Start the vmbus kernel proxy if it's in use.
            #[cfg(windows)]
            if let Some(proxy_handle) = vmbus_cfg.vmbusproxy_handle {
                vmbus_proxy = Some(
                    vmbus
                        .start_kernel_proxy(&vmbus_driver, proxy_handle)
                        .await
                        .context("failed to start the vmbus proxy")?,
                )
            }

            let vmbus = VmbusServerHandle::new(&vmbus_driver, state_units.add("vmbus"), vmbus)
                .context("failed to add vmbus state unit")?;

            let relay = HvsockRelay::new(
                vmbus_driver,
                vmbus.control().clone(),
                hvsock_channel.relay_half,
                vmbus_cfg.vsock_path.map(Into::into),
                vmbus_cfg.vsock_listener,
            )
            .context("failed to create hvsock relay")?;

            vtl0_hvsock_relay = Some(relay);
            vmbus_server = Some(vmbus);
            vtl2_vmbus_server = vtl2_vmbus;
        }

        fn make_ids(name: &str, instance_id: Option<Guid>) -> (String, String, Guid, u64) {
            let guid = instance_id.unwrap_or_else(Guid::new_random);
            // TODO: clarify how the device ID is constructed
            let device_id = (guid.data2 as u64) << 16 | (guid.data3 as u64 & 0xfff8);
            let vpci_device_name = format!("vpci:{guid}");
            let device_name = format!("{name}:vpci-{guid}");
            (vpci_device_name, device_name, guid, device_id)
        }

        async fn add_virtio_vpci(
            driver_source: &VmTaskDriverSource,
            partition: &Arc<dyn HvlitePartition>,
            vmbus_server: &Option<VmbusServerHandle>,
            mapper: &dyn guestmem::MemoryMapper,
            device_name: &str,
            chipset_builder: &mut vmotherboard::ChipsetBuilder<'_>,
            device: Box<dyn virtio::VirtioDevice>,
        ) -> anyhow::Result<()> {
            let (vpci_device_name, device_name, instance_id, device_id) =
                make_ids(device_name, None);

            let mut msi_set = MsiInterruptSet::new();
            let device = chipset_builder
                .arc_mutex_device(device_name)
                .with_external_pci()
                .try_add(|services| {
                    VirtioPciDevice::new(
                        device,
                        PciInterruptModel::Msix(&mut msi_set),
                        partition.clone().into_doorbell_registration(Vtl::Vtl0),
                        &mut services.register_mmio(),
                        Some(mapper),
                    )
                    .context("failed to create a virtio pci device")
                })?;

            {
                let mut builder = chipset_builder.arc_mutex_device(vpci_device_name);
                let mut mmio = builder.services().register_mmio();
                builder
                    .try_add_async(|_services| async {
                        let vmbus = vmbus_server.as_ref().context("vmbus not configured")?;
                        let hv_device = partition
                            .new_virtual_device(Vtl::Vtl0, device_id)
                            .context("failed to create virtual device")?;

                        let msi_controller = hv_device.clone().target();
                        let interrupt_mapper = hv_device.clone().interrupt_mapper();
                        msi_set.connect(msi_controller.as_ref());

                        let bus = VpciBus::new(
                            driver_source,
                            instance_id,
                            device,
                            &mut mmio,
                            vmbus.control().as_ref(),
                            interrupt_mapper,
                        )
                        .await?;

                        anyhow::Ok(bus)
                    })
                    .await?;
            }

            Ok(())
        }

        // Synthetic devices
        {
            // Arbitrary default
            const DEFAULT_IO_QUEUE_DEPTH: u32 = 256;
            if let Some(vmbus) = &vmbus_server {
                for (path, scsi_disk) in storvsp_ide_disks {
                    scsi_devices.push(
                        offer_channel_unit(
                            &driver_source.simple(),
                            &state_units,
                            vmbus,
                            storvsp::StorageDevice::build_ide(
                                &driver_source,
                                path.channel,
                                path.drive,
                                scsi_disk,
                                DEFAULT_IO_QUEUE_DEPTH,
                            ),
                        )
                        .await?,
                    );
                }
            }

            #[cfg(windows)]
            for nic_config in cfg.kernel_vmnics {
                let mut nic = vmswitch::kernel::KernelVmNic::new(
                    &Guid::new_random(),
                    "nic",
                    "nic",
                    nic_config.mac_address.into(),
                    &nic_config.instance_id,
                    vmbus_proxy
                        .as_ref()
                        .context("missing vmbusproxy handle")?
                        .handle(),
                )
                .context("failed to create a kernel vmnic")?;

                nic.connect(&vmswitch::kernel::SwitchPortId {
                    switch: nic_config.switch_port_id.switch,
                    port: nic_config.switch_port_id.port,
                })
                .context("failed to connect kernel vmnic")?;

                nic.resume().context("failed to resume the kernel vmnic")?;
                kernel_vmnics.push(nic);
            }

            if partition.supports_virtual_devices() {
                if vmbus_server.is_some() {
                    let serial = VirtioSerialDevice::new(1, &gm);
                    vpci_serial = Some(serial.io());
                    add_virtio_vpci(
                        &driver_source,
                        &partition,
                        &vmbus_server,
                        &mapper,
                        "virtio-serial-vpci",
                        &mut chipset_builder,
                        Box::new(LegacyWrapper::new(&driver_source, serial, &gm)),
                    )
                    .await?;
                }

                for dev_cfg in cfg.vpci_devices {
                    let vmbus = match dev_cfg.vtl {
                        DeviceVtl::Vtl0 => vmbus_server.as_ref().context("vmbus not enabled")?,
                        DeviceVtl::Vtl1 => anyhow::bail!("not supported"),
                        DeviceVtl::Vtl2 => vtl2_vmbus_server
                            .as_ref()
                            .context("VTL2 vmbus not enabled")?,
                    };

                    let vtl = match dev_cfg.vtl {
                        DeviceVtl::Vtl0 => Vtl::Vtl0,
                        DeviceVtl::Vtl1 => Vtl::Vtl1,
                        DeviceVtl::Vtl2 => Vtl::Vtl2,
                    };

                    vmm_core::device_builder::build_vpci_device(
                        &driver_source,
                        &resolver,
                        &gm,
                        vmbus.control(),
                        dev_cfg.instance_id,
                        dev_cfg.resource,
                        &mut chipset_builder,
                        partition.clone().into_doorbell_registration(vtl),
                        Some(&mapper),
                        |device_id| {
                            let hv_device = partition.new_virtual_device(
                                match dev_cfg.vtl {
                                    DeviceVtl::Vtl0 => Vtl::Vtl0,
                                    DeviceVtl::Vtl1 => Vtl::Vtl1,
                                    DeviceVtl::Vtl2 => Vtl::Vtl2,
                                },
                                device_id,
                            )?;
                            Ok((
                                hv_device.clone().target(),
                                hv_device.clone().interrupt_mapper(),
                            ))
                        },
                    )
                    .await?;
                }

                #[cfg(all(windows, feature = "virt_whp"))]
                for resource in cfg.vpci_resources {
                    let vmbus = vmbus_server
                        .as_ref()
                        .context("vmbus must be enabled to assign devices")?
                        .control()
                        .as_ref();

                    // TODO: abstract this behind the trait object properly.
                    let pd = partition.as_any();
                    let p = pd.downcast_ref::<virt_whp::WhpPartition>().unwrap();
                    let (vpci_bus_name, device_name, instance_id, device_id) =
                        make_ids("assigned-device", None);

                    let hv_device = Arc::new(
                        p.new_physical_device(Vtl::Vtl0, device_id, resource.0)
                            .context("failed to get physical device for assignment")?,
                    );

                    let device = chipset_builder
                        .arc_mutex_device(device_name)
                        .with_external_pci()
                        .try_add(|_services| {
                            virt_whp::device::AssignedPciDevice::new(hv_device.clone())
                        })
                        .context("failed to assign device")?;

                    {
                        let mut builder = chipset_builder.arc_mutex_device(vpci_bus_name);
                        let mut register_mmio = builder.services().register_mmio();
                        builder
                            .try_add_async(|_services| async {
                                VpciBus::new(
                                    &driver_source,
                                    instance_id,
                                    device,
                                    &mut register_mmio,
                                    vmbus,
                                    crate::partition::VpciDevice::interrupt_mapper(hv_device),
                                )
                                .await
                            })
                            .await?;
                    }
                }
            }
        }

        // Add vmbus devices.
        let mut vmbus_devices = Vec::new();
        for (vtl, resource) in cfg.vmbus_devices {
            let vmbus = match vtl {
                DeviceVtl::Vtl0 => vmbus_server
                    .as_ref()
                    .context("failed to find vmbus for vtl0"),
                DeviceVtl::Vtl1 => anyhow::bail!("vtl1 scsi controllers unsupported"),
                DeviceVtl::Vtl2 => vtl2_vmbus_server
                    .as_ref()
                    .context("failed to find vmbus for vtl2"),
            }
            .with_context(|| format!("failed to resolve vmbus resource {}", resource.id()))?;
            vmbus_devices.push(
                offer_vmbus_device_handle_unit(
                    &driver_source,
                    &state_units,
                    vmbus,
                    &resolver,
                    resource,
                )
                .await?,
            );
        }

        // add virtio devices

        // virtio-mmio does not currently work with UEFI or PCAT because the
        // DSDT does not get updated and the reported MMIO ranges conflict.
        let with_virtio_serial_mmio = matches!(cfg.load_mode, LoadMode::Linux { .. });

        // Construct virtio devices.
        //
        // TODO: allocate PCI and MMIO space better.
        let mut pci_device_number = 10;
        let mut virtio_mmio_start = mem_layout.mmio()[1].end();
        let mut virtio_mmio_count = 0;

        // Avoid an ISA interrupt to avoid conflicts and to avoid needing to
        // configure the line as level-triggered in the MADT (necessary for
        // Linux when the PIC is missing).
        let virtio_mmio_irq = {
            const VIRTIO_MMIO_IOAPIC_IRQ: u32 = 17;
            const VIRTIO_MMIO_PIC_IRQ: u32 = 5;
            if cfg.chipset.with_generic_pic {
                VIRTIO_MMIO_PIC_IRQ
            } else {
                VIRTIO_MMIO_IOAPIC_IRQ
            }
        };
        for (bus, device) in cfg.virtio_devices.into_iter() {
            let id = device.id().to_string();
            let device = resolver
                .resolve(
                    device,
                    VirtioResolveInput {
                        driver_source: &driver_source,
                        guest_memory: &gm,
                    },
                )
                .await?;
            match bus {
                VirtioBus::Mmio => {
                    let mmio_start = virtio_mmio_start - 0x1000;
                    virtio_mmio_start -= 0x1000;
                    let id = format!("{id}-{mmio_start}");
                    chipset_builder.arc_mutex_device(id).add(|services| {
                        VirtioMmioDevice::new(
                            device.0,
                            services.new_line(IRQ_LINE_SET, "interrupt", virtio_mmio_irq),
                            partition.clone().into_doorbell_registration(Vtl::Vtl0),
                            mmio_start,
                            0x1000,
                        )
                    })?;
                    virtio_mmio_count += 1;
                }
                VirtioBus::Pci => {
                    let pci_inta_line = pci_inta_line.context("missing PCI INT#A line")?;

                    let device_number = pci_device_number;
                    pci_device_number += 1;
                    pci_legacy_interrupts.push(((device_number, None), pci_inta_line));

                    let bus = if cfg.chipset.with_piix4_pci_bus {
                        pci_bus_id_piix4.clone()
                    } else {
                        pci_bus_id_generic.clone()
                    };

                    chipset_builder
                        .arc_mutex_device(format!("{id}-pci"))
                        .with_pci_addr(0, device_number, 0)
                        .on_pci_bus(bus)
                        .try_add(|services| {
                            VirtioPciDevice::new(
                                device.0,
                                PciInterruptModel::IntX(
                                    PciInterruptPin::IntA,
                                    services.new_line(IRQ_LINE_SET, "interrupt", pci_inta_line),
                                ),
                                partition.clone().into_doorbell_registration(Vtl::Vtl0),
                                &mut services.register_mmio(),
                                Some(&mapper),
                            )
                        })?;
                }
            }
        }

        let mut virt_serial_io = None;
        {
            if with_virtio_serial_mmio {
                // Consoles only have one port, or need to implement VIRTIO_CONSOLE_CONSOLE_PORT
                let virt_serial = VirtioSerialDevice::new(1, &gm);
                virt_serial_io = Some(virt_serial.io());
                chipset_builder
                    .arc_mutex_device("virtio-serial")
                    .add(|services| {
                        VirtioMmioDevice::new(
                            Box::new(LegacyWrapper::new(&driver_source, virt_serial, &gm)),
                            services.new_line(IRQ_LINE_SET, "interrupt", virtio_mmio_irq),
                            partition.clone().into_doorbell_registration(Vtl::Vtl0),
                            virtio_mmio_start - 0x1000,
                            0x1000,
                        )
                    })?;
                virtio_mmio_start -= 0x1000;
            }
        }

        let (virtio_serial_input, mut virtio_serial_output) =
            cfg.virtio_serial.map(|x| (x.input, x.output)).unzip();
        if let Some(Some(mut input)) = virtio_serial_input {
            let virtio_serial = if cfg.virtio_console_pci {
                vpci_serial.clone()
            } else {
                virt_serial_io.clone()
            };
            if let Some(mut virtio_serial) = virtio_serial {
                thread::Builder::new()
                    .name("virtio serial input".into())
                    .spawn(move || {
                        let mut buf = [0; 32];
                        loop {
                            let n = input.read(&mut buf).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            virtio_serial.queue_input_bytes(&buf[..n]).unwrap();
                        }
                    })
                    .unwrap();
            }
        }

        {
            let virtio_serial = if cfg.virtio_console_pci {
                vpci_serial
            } else {
                virt_serial_io.clone()
            };
            if let Some(virtio_serial) = virtio_serial {
                virtio_serial.open_port(0);
                let virt_serial_read = virtio_serial.get_port_read_fn(0);
                thread::Builder::new()
                    .name("virtio serial out".into())
                    .spawn(move || loop {
                        let data = (virt_serial_read)();
                        if data.is_empty() {
                            break;
                        }
                        if let Some(Some(stdout)) = &mut virtio_serial_output {
                            let result = stdout.write_all(data.as_slice());
                            if let Err(error) = result {
                                tracing::error!(
                                    error = error.as_error(),
                                    "virtio console write failed"
                                );
                                break;
                            }
                            let result = stdout.flush();
                            if let Err(error) = result {
                                tracing::error!(
                                    error = error.as_error(),
                                    "virtio console flush failed"
                                );
                            }
                        }
                    })
                    .unwrap();
            }
        }

        assert!(virtio_mmio_start >= mem_layout.mmio()[1].start());

        let (chipset, devices) = chipset_builder.build()?;
        let chipset = vmm_core::vmotherboard_adapter::ChipsetPlusSynic::new(synic.clone(), chipset);

        let (partition_unit, vp_runners) = PartitionUnit::new(
            driver_source.simple(),
            state_units
                .add("partition")
                .depends_on(devices.chipset_unit())
                .depends_on(vmtime.handle()),
            partition.clone().into_vm_partition(),
            PartitionUnitParams {
                processor_topology: &processor_topology,
                halt_vps,
                halt_request_recv,
                client_notify_send,
                vtl_guest_memory: [
                    Some(&gm),
                    None,
                    cfg.hypervisor.with_vtl2.is_some().then_some(&gm),
                ],
                debugger_rpc: cfg.debugger_rpc,
            },
        )
        .context("failed to create partition unit")?;

        // Start the VP backing threads.
        try_join_all(vps.into_iter().zip(vp_runners).enumerate().map(
            |(vp_index, (mut vp, runner))| {
                let partition = partition.clone().into_request_yield();
                let chipset = chipset.clone();
                let (send, recv) = mesh::oneshot();
                thread::Builder::new()
                    .name(format!("vp-{}", vp_index))
                    .spawn(move || match vp.bind() {
                        Ok(mut vp) => {
                            send.send(Ok(()));
                            block_on_vp(
                                partition,
                                VpIndex::new(vp_index as u32),
                                vp.run(runner, &chipset),
                            )
                        }
                        Err(err) => {
                            send.send(Err(err));
                        }
                    })
                    .unwrap();

                async move {
                    recv.await
                        .unwrap()
                        .with_context(|| format!("failed to bind vp {vp_index}"))
                }
            },
        ))
        .await?;

        let mut this = LoadedVm {
            state_units,
            running: false,
            inner: LoadedVmInner {
                driver_source,
                resolver,
                hypervisor,
                partition_unit,
                partition,
                _chipset_devices: devices,
                _vmtime: vmtime,
                _scsi_devices: scsi_devices,
                memory_manager,
                gm,
                vtl0_hvsock_relay,
                vtl2_hvsock_relay,
                vmbus_server,
                vtl2_vmbus_server,
                hypervisor_cfg: cfg.hypervisor,
                memory_cfg: cfg.memory,
                mem_layout,
                processor_topology,
                vmbus_redirect,
                input_distributor,
                vtl2_framebuffer_gpa_base,
                virtio_serial: virtio_serial_dup,
                #[cfg(windows)]
                _vmbus_proxy: vmbus_proxy,
                #[cfg(windows)]
                _kernel_vmnics: kernel_vmnics,
                vmbus_devices,
                chipset_cfg: cfg.chipset,
                firmware_event_send: cfg.firmware_event_send,
                load_mode: cfg.load_mode,
                virtio_mmio_count,
                virtio_mmio_irq,
                pci_legacy_interrupts,
                igvm_file,
                next_igvm_file: None,
                _vmgs_task: vmgs_task,
                vmgs_client_inspect_handle,
            },
        };

        if let Some(saved_state) = saved_state {
            this.restore(saved_state)
                .await
                .context("loadedvm restore failed")?;
        } else {
            this.inner.load_firmware(false).await?;
        }

        Ok(this)
    }
}

impl LoadedVmInner {
    async fn load_firmware(&mut self, vtl2_only: bool) -> anyhow::Result<()> {
        let cache_topology = if cfg!(guest_arch = "aarch64") {
            Some(
                cache_topology::CacheTopology::from_host()
                    .context("failed to get cache topology")?,
            )
        } else {
            None
        };
        let acpi_builder = AcpiTablesBuilder {
            processor_topology: &self.processor_topology,
            mem_layout: &self.mem_layout,
            cache_topology: cache_topology.as_ref(),
            with_ioapic: self.chipset_cfg.with_generic_ioapic,
            with_psp: self.chipset_cfg.with_generic_psp,
            with_pic: self.chipset_cfg.with_generic_pic,
            with_pit: self.chipset_cfg.with_generic_pit,
            pm_base: PM_BASE,
            acpi_irq: SYSTEM_IRQ_ACPI,
        };

        if vtl2_only {
            assert!(matches!(self.load_mode, LoadMode::Igvm { .. }));
        }

        #[cfg_attr(not(guest_arch = "x86_64"), allow(unused_mut))]
        let (mut regs, initial_page_vis) = match &self.load_mode {
            LoadMode::None => return Ok(()),
            #[cfg(guest_arch = "x86_64")]
            &LoadMode::Linux {
                ref kernel,
                ref initrd,
                ref cmdline,
                enable_serial,
                ref custom_dsdt,
            } => {
                let kernel_config = super::vm_loaders::linux::KernelConfig {
                    kernel,
                    initrd,
                    cmdline,
                    mem_layout: &self.mem_layout,
                };
                let regs =
                    super::vm_loaders::linux::load_linux_x86(&kernel_config, &self.gm, |gpa| {
                        let tables = if let Some(dsdt) = custom_dsdt {
                            acpi_builder.build_acpi_tables_custom_dsdt(gpa, dsdt)
                        } else {
                            acpi_builder.build_acpi_tables(gpa, |mem_layout, dsdt| {
                                add_devices_to_dsdt(
                                    mem_layout,
                                    dsdt,
                                    &self.chipset_cfg,
                                    enable_serial,
                                    self.virtio_mmio_count,
                                    self.virtio_mmio_irq,
                                    &self.pci_legacy_interrupts,
                                )
                            })
                        };

                        super::vm_loaders::linux::AcpiTables {
                            rdsp: tables.rdsp,
                            tables: tables.tables,
                        }
                    })?;

                (regs, Vec::new())
            }
            #[cfg(guest_arch = "aarch64")]
            &LoadMode::Linux {
                ref kernel,
                ref initrd,
                ref cmdline,
                enable_serial,
                custom_dsdt: _,
            } => {
                let kernel_config = super::vm_loaders::linux::KernelConfig {
                    kernel,
                    initrd,
                    cmdline,
                    mem_layout: &self.mem_layout,
                };
                let regs = super::vm_loaders::linux::load_linux_arm64(
                    &kernel_config,
                    &self.gm,
                    enable_serial,
                    &self.processor_topology,
                )?;

                (regs, Vec::new())
            }
            &LoadMode::Uefi {
                ref firmware,
                enable_debugging,
                enable_memory_protections,
                disable_frontpage,
                enable_tpm,
                enable_battery,
                enable_serial,
                enable_vpci_boot,
                uefi_console_mode,
            } => {
                let madt = acpi_builder.build_madt();
                let srat = acpi_builder.build_srat();
                let pptt = cache_topology.is_some().then(|| acpi_builder.build_pptt());
                let load_settings = super::vm_loaders::uefi::UefiLoadSettings {
                    debugging: enable_debugging,
                    memory_protections: enable_memory_protections,
                    frontpage: !disable_frontpage,
                    tpm: enable_tpm,
                    battery: enable_battery,
                    guest_watchdog: self.chipset_cfg.with_hyperv_guest_watchdog,
                    vpci_boot: enable_vpci_boot,
                    serial: enable_serial,
                    uefi_console_mode,
                };
                let regs = super::vm_loaders::uefi::load_uefi(
                    firmware,
                    &self.gm,
                    &self.processor_topology,
                    &self.mem_layout,
                    load_settings,
                    &madt,
                    &srat,
                    pptt.as_deref(),
                )?;

                (regs, Vec::new())
            }
            #[cfg(guest_arch = "x86_64")]
            LoadMode::Pcat { .. } => {
                let regs = super::vm_loaders::pcat::load_pcat(&self.gm, &self.mem_layout)?;

                (regs, Vec::new())
            }
            &LoadMode::Igvm {
                file: _,
                ref cmdline,
                vtl2_base_address,
                com_serial,
            } => {
                let madt = acpi_builder.build_madt();
                let srat = acpi_builder.build_srat();
                const ENTROPY_SIZE: usize = 64;
                let mut entropy = [0u8; ENTROPY_SIZE];
                getrandom::getrandom(&mut entropy).unwrap();

                let params = crate::worker::vm_loaders::igvm::LoadIgvmParams {
                    igvm_file: self.igvm_file.as_ref().expect("should be already read"),
                    gm: &self.gm,
                    processor_topology: &self.processor_topology,
                    mem_layout: &self.mem_layout,
                    cmdline,
                    acpi_tables: super::vm_loaders::igvm::AcpiTables {
                        madt: &madt,
                        srat: &srat,
                        slit: None,
                        pptt: None,
                    },
                    vtl2_base_address,
                    vtl2_framebuffer_gpa_base: self.vtl2_framebuffer_gpa_base,
                    vtl2_only,
                    with_vmbus_redirect: self.vmbus_redirect,
                    com_serial,
                    entropy: Some(&entropy),
                };
                super::vm_loaders::igvm::load_igvm(params)?
            }
            #[allow(unreachable_patterns)]
            _ => anyhow::bail!("load mode not supported on this platform"),
        };

        // Don't setup variable MTRRs if VTL2 is present. It's expected that
        // VTL2 will setup MTRRs for VTL0 if needed.
        #[cfg(guest_arch = "x86_64")]
        if self.hypervisor_cfg.with_vtl2.is_none() {
            regs.extend(loader::common::compute_variable_mtrrs(&self.mem_layout));
        }

        // Only set initial page visibility on isolated partitions.
        if self.hypervisor_cfg.with_isolation.is_some() {
            tracing::debug!(?initial_page_vis, "initial_page_vis");
            self.partition_unit
                .set_initial_page_visibility(initial_page_vis)
                .await
                .context("failed to set initial page visibility")?;
        }

        let initial_regs = initial_regs(
            &regs,
            self.partition.caps(),
            &self.processor_topology.vp_arch(VpIndex::BSP),
        );

        tracing::debug!(?initial_regs, "initial_registers");
        self.partition_unit
            .set_initial_regs(
                if self.hypervisor_cfg.with_vtl2.is_some() {
                    Vtl::Vtl2
                } else {
                    Vtl::Vtl0
                },
                initial_regs,
            )
            .await
            .context("failed to set initial register state")?;

        Ok(())
    }
}

impl LoadedVm {
    async fn resume(&mut self) -> bool {
        if self.running {
            return false;
        }
        self.state_units.start().await;
        self.running = true;
        true
    }

    async fn pause(&mut self) -> bool {
        if !self.running {
            return false;
        }
        self.state_units.stop().await;
        self.running = false;
        true
    }

    pub async fn run(
        mut self,
        driver: &impl Spawn,
        mut rpc_recv: mesh::Receiver<VmRpc>,
        mut worker_rpc: mesh::Receiver<WorkerRpc<RestartState>>,
    ) {
        enum Event {
            WorkerRpc(Result<WorkerRpc<RestartState>, mesh::RecvError>),
            VmRpc(Result<VmRpc, mesh::RecvError>),
        }

        // Start a task to handle state unit inspections by filtering the worker
        // RPC requests. This is done so that inspect on state units works even
        // during state transitions.
        let (worker_rpc_send, worker_rpc_recv) = mesh::channel();
        let _filter_rpc_task = driver.spawn("loaded-vm-worker-rpc-filter", {
            let state_units = self.state_units.inspector();
            async move {
                while let Some(rpc) = worker_rpc.next().await {
                    match rpc {
                        WorkerRpc::Inspect(req) => req.respond(|resp| {
                            worker_rpc_send.send(WorkerRpc::Inspect(
                                resp.merge(&state_units).request().defer(),
                            ));
                        }),
                        rpc => worker_rpc_send.send(rpc),
                    }
                }
            }
        });
        let mut worker_rpc = worker_rpc_recv;

        loop {
            let event: Event = {
                let a = rpc_recv.recv().map(Event::VmRpc);
                let b = worker_rpc.recv().map(Event::WorkerRpc);
                (a, b).race().await
            };

            match event {
                Event::WorkerRpc(Err(_)) => break,
                Event::WorkerRpc(Ok(message)) => match message {
                    WorkerRpc::Stop => break,
                    WorkerRpc::Restart(rpc) => {
                        let mut stopped = false;
                        // First run the non-destructive operations.
                        let r = async {
                            let shared_memory = self.inner.memory_manager.shared_memory_backing();
                            if self.running {
                                self.state_units.stop().await;
                                stopped = true;
                            }
                            let saved_state = self.save().await?;
                            anyhow::Ok((shared_memory, saved_state))
                        }
                        .await;
                        match r {
                            Ok((shared_memory, saved_state)) => {
                                rpc.complete(Ok(self
                                    .serialize(rpc_recv, shared_memory, saved_state)
                                    .await));

                                return;
                            }
                            Err(err) => {
                                if stopped {
                                    self.state_units.start().await;
                                }
                                rpc.complete(Err(RemoteError::new(err)));
                            }
                        }
                    }
                    WorkerRpc::Inspect(deferred) => deferred.respond(|resp| {
                        resp.field("memory", &self.inner.memory_manager)
                            .field("memory_layout", &self.inner.mem_layout)
                            .field("resolver", &self.inner.resolver)
                            .field("vmgs", &self.inner.vmgs_client_inspect_handle);
                    }),
                },
                Event::VmRpc(Err(_)) => break,
                Event::VmRpc(Ok(message)) => match message {
                    VmRpc::Reset(rpc) => rpc.handle_failable(|()| self.reset(true)).await,
                    VmRpc::ClearHalt(rpc) => {
                        rpc.handle(|()| self.inner.partition_unit.clear_halt())
                            .await
                    }
                    VmRpc::Resume(rpc) => rpc.handle(|()| self.resume()).await,
                    VmRpc::Pause(rpc) => rpc.handle(|()| self.pause()).await,
                    VmRpc::Save(rpc) => {
                        rpc.handle_failable(|()| async {
                            self.save().await.map(ProtobufMessage::new)
                        })
                        .await
                    }
                    VmRpc::Nmi(rpc) => rpc.handle_sync(|vpindex| {
                        if vpindex < self.inner.processor_topology.vp_count() {
                            // Send an NMI MSI to the processor. We could raise
                            // LINT1 instead, which would allow the guest to
                            // reconfigure the LINT to do something other than
                            // an NMI. Since this is for diagnostics, that
                            // doesn't seem like what we want.
                            //
                            // AARCH64-TODO: is there an equivalent?
                            #[cfg(guest_arch = "x86_64")]
                            self.inner.partition.request_msi(
                                Vtl::Vtl0,
                                virt::irqcon::MsiRequest::new_x86(
                                    virt::irqcon::DeliveryMode::NMI,
                                    self.inner
                                        .processor_topology
                                        .vp_arch(VpIndex::new(vpindex))
                                        .apic_id,
                                    false,
                                    0,
                                    false,
                                ),
                            );
                        }
                    }),
                    VmRpc::AddVmbusDevice(rpc) => {
                        rpc.handle_failable(|(vtl, resource)| {
                            let this = &mut self;
                            async move {
                                let vmbus = match vtl {
                                    DeviceVtl::Vtl0 => this.inner.vmbus_server.as_ref(),
                                    DeviceVtl::Vtl1 => None,
                                    DeviceVtl::Vtl2 => this.inner.vtl2_vmbus_server.as_ref(),
                                }
                                .context("no vmbus available")?;
                                let device = offer_vmbus_device_handle_unit(
                                    &this.inner.driver_source,
                                    &this.state_units,
                                    vmbus,
                                    &this.inner.resolver,
                                    resource,
                                )
                                .await?;
                                this.inner.vmbus_devices.push(device);
                                this.state_units.start_stopped_units().await;
                                anyhow::Ok(())
                            }
                        })
                        .await
                    }
                    VmRpc::ConnectHvsock(rpc) => {
                        let ((mut ctx, service_id, vtl), response) = rpc.split();
                        if let Some(relay) = self.hvsock_relay(vtl) {
                            let fut = relay.connect(&mut ctx, service_id);
                            driver
                                .spawn("vmrpc-hvsock-connect", async move {
                                    response.complete(fut.await.map_err(RemoteError::new))
                                })
                                .detach();
                        } else {
                            response.complete(Err(RemoteError::new(anyhow::anyhow!(
                                "hvsock is not available"
                            ))));
                        }
                    }
                    VmRpc::PulseSaveRestore(rpc) => {
                        rpc.handle(|()| async {
                            if !self.inner.partition.supports_reset() {
                                return Err(PulseSaveRestoreError::ResetNotSupported);
                            }
                            let paused = self.pause().await;
                            self.save_reset_restore().await?;

                            if paused {
                                self.resume().await;
                            }
                            Ok(())
                        })
                        .await
                    }
                    VmRpc::StartReloadIgvm(rpc) => {
                        rpc.handle_failable_sync(|file| self.start_reload_igvm(&file))
                    }
                    VmRpc::CompleteReloadIgvm(rpc) => {
                        rpc.handle_failable(|complete| self.complete_reload_igvm(complete))
                            .await
                    }
                    VmRpc::ReadMemory(rpc) => {
                        rpc.handle_failable_sync(|(gpa, size)| {
                            let mut bytes = vec![0u8; size];
                            self.inner
                                .gm
                                .read_at(gpa, bytes.as_mut_slice())
                                .map(|_| bytes)
                        });
                    }
                    VmRpc::WriteMemory(rpc) => rpc.handle_failable_sync(|(gpa, bytes)| {
                        self.inner.gm.write_at(gpa, bytes.as_slice())
                    }),
                },
            }
        }

        self.inner.partition_unit.teardown().await;
        if let Some(vmbus) = self.inner.vmbus_server {
            vmbus.remove().await.shutdown().await;
        }
    }

    fn start_reload_igvm(&mut self, file: &File) -> anyhow::Result<()> {
        // Clear any previously staged IGVM file.
        self.inner.next_igvm_file = None;

        // Load the new IGVM file into memory.
        let igvm_file =
            super::vm_loaders::igvm::read_igvm_file(file).context("reading igvm file failed")?;

        self.inner.next_igvm_file = Some(igvm_file);
        Ok(())
    }

    async fn complete_reload_igvm(&mut self, complete: bool) -> anyhow::Result<()> {
        if !complete {
            self.inner.next_igvm_file = None;
            return Ok(());
        }

        let r = async {
            // Grab the staged IGVM file.
            let next_igvm_file = self
                .inner
                .next_igvm_file
                .take()
                .context("no staged igvm file")?;

            // Stop the partition and VTL2 vmbus so that we can reset vmbus and
            // reset the VTL2 register state.
            //
            // When these units will be resumed when `stopped_units` is dropped.
            let vtl2_vmbus = self
                .inner
                .vtl2_vmbus_server
                .as_ref()
                .context("missing vtl2 vmbus")?
                .unit_handle();

            // FUTURE: instead of stopping the partition as a state unit, just stop
            // the VPs via a side call to the partition unit. This distinction will
            // become important when stopping a VM stops the VM's perception of
            // time--we don't want to stop VM time during VTL2 servicing.
            self.state_units
                .stop_subset([vtl2_vmbus, self.inner.partition_unit.unit_handle()])
                .await;

            // Reset vmbus VTL2 state so that all DMA transactions to VTL2 memory
            // stop. We don't need to reset the individual devices, since resetting
            // vmbus will close all the channels.
            self.state_units
                .force_reset([vtl2_vmbus])
                .await
                .context("failed to reset vtl2 vmbus")?;

            // Reload the VTL2 firmware.
            //
            // When the initial registers are set, this will implicitly reset VTL2
            // state as well.
            let _old_igvm_file = self.inner.igvm_file.replace(next_igvm_file);
            self.inner
                .load_firmware(true)
                .await
                .context("failed to reload VTL2 firmware")?;

            Ok(())
        }
        .await;

        // Resume the stopped units.
        self.state_units.start_stopped_units().await;
        r
    }

    /// Get the associated hvsock relay for a given vtl, if any.
    fn hvsock_relay(&self, vtl: DeviceVtl) -> Option<&HvsockRelay> {
        match vtl {
            DeviceVtl::Vtl0 => self.inner.vtl0_hvsock_relay.as_ref(),
            DeviceVtl::Vtl1 => None,
            DeviceVtl::Vtl2 => self.inner.vtl2_hvsock_relay.as_ref(),
        }
    }

    /// Saves the VM's processor, partition, and device state.
    ///
    /// TODO: virtio & vmbus unsupported.
    async fn save(&mut self) -> anyhow::Result<SavedState> {
        Ok(SavedState {
            units: self.state_units.save().await?,
        })
    }

    /// Restore state on the VM.
    async fn restore(&mut self, state: SavedState) -> anyhow::Result<()> {
        self.state_units.restore(state.units).await?;
        Ok(())
    }

    /// Do a save, reset, restore.
    async fn save_reset_restore(&mut self) -> anyhow::Result<()> {
        let state = self.save().await?;
        self.reset(false).await?;
        self.restore(state).await?;
        Ok(())
    }

    /// Prepares for restart, serializing the worker's state.
    async fn serialize(
        mut self,
        rpc: mesh::Receiver<VmRpc>,
        shared_memory: SharedMemoryBacking,
        saved_state: SavedState,
    ) -> RestartState {
        let notify = self.inner.partition_unit.teardown().await;
        let input = self.inner.input_distributor.remove().await.into_inner();

        if let Some(vmbus_server) = self.inner.vmbus_server.take() {
            vmbus_server.remove().await.shutdown().await;
        }

        let manifest = Manifest {
            load_mode: self.inner.load_mode,
            floppy_disks: vec![], // TODO
            ide_disks: vec![],    // TODO
            vpci_devices: vec![], // TODO
            memory: self.inner.memory_cfg,
            processor_topology: self.inner.processor_topology.to_config(),
            chipset: self.inner.chipset_cfg,
            vmbus: None,      // TODO
            vtl2_vmbus: None, // TODO
            hypervisor: self.inner.hypervisor_cfg,
            #[cfg(windows)]
            kernel_vmnics: vec![], // TODO
            input,
            framebuffer: None,         // TODO
            vga_firmware: None,        // TODO
            vtl2_gfx: false,           // TODO
            virtio_console_pci: false, // TODO
            virtio_serial: self.inner.virtio_serial,
            virtio_devices: vec![], // TODO
            #[cfg(all(windows, feature = "virt_whp"))]
            vpci_resources: vec![], // TODO
            vmgs_disk: None,        // TODO
            format_vmgs: false,     // TODO
            secure_boot_enabled: false, // TODO
            custom_uefi_vars: Default::default(), // TODO
            firmware_event_send: self.inner.firmware_event_send,
            debugger_rpc: None,       // TODO
            vmbus_devices: vec![],    // TODO
            chipset_devices: vec![],  // TODO
            generation_id_recv: None, // TODO
        };
        RestartState {
            hypervisor: self.inner.hypervisor,
            manifest,
            running: self.running,
            saved_state,
            shared_memory,
            rpc,
            notify,
        }
    }

    async fn reset(&mut self, reload_firmware: bool) -> anyhow::Result<()> {
        let resume = self.pause().await;

        self.state_units.reset().await?;
        // TODO: _vmnic
        // TODO: gdb?

        // Load again
        if reload_firmware {
            self.inner.load_firmware(false).await?;
        }

        if resume {
            self.resume().await;
        }
        Ok(())
    }
}

#[cfg_attr(not(guest_arch = "x86_64"), allow(dead_code))]
fn add_devices_to_dsdt(
    mem_layout: &MemoryLayout,
    dsdt: &mut dsdt::Dsdt,
    cfg: &BaseChipsetManifest,
    serial_uarts: bool,
    virtio_mmio_count: usize,
    virtio_mmio_irq: u32,
    pci_legacy_interrupts: &[((u8, Option<u8>), u32)], // ((device, function), interrupt)
) {
    dsdt.add_apic();

    // Any serial port configured means all are enabled.
    if serial_uarts {
        for (name, com_port, ddn, uid) in [
            (b"\\_SB.UAR1", ComPort::Com1, b"COM1", 1),
            (b"\\_SB.UAR2", ComPort::Com2, b"COM2", 2),
            (b"\\_SB.UAR3", ComPort::Com3, b"COM3", 3),
            (b"\\_SB.UAR4", ComPort::Com4, b"COM4", 4),
        ]
        .iter()
        .copied()
        {
            dsdt.add_uart(name, ddn, uid, com_port.io_port(), com_port.irq().into());
        }
    }

    assert!(
        mem_layout.mmio().len() >= 2,
        "the DSDT describes two MMIO regions"
    );
    let low_mmio_gap = mem_layout.mmio()[0];
    let mut high_mmio_space: std::ops::Range<u64> = mem_layout.mmio()[1].into();
    // Device(\_SB.VI00)
    // {
    //     Name(_HID, "LNRO0005")
    //     Name(_UID, 0)
    //     Name(_CRS, ResourceTemplate()
    //     {
    //         QWORDMemory(,,,,,ReadWrite,0,0x1fffff000,0x1ffffffff,0,0x1000)
    //         Interrupt(ResourceConsumer, Level, ActiveHigh, Exclusive)
    //             {5}
    //     })
    // }
    // TODO: manage MMIO space better than this
    for i in 0..virtio_mmio_count {
        high_mmio_space.end -= HV_PAGE_SIZE;
        let mut device = dsdt::Device::new(format!("\\_SB.VI{i:02}").as_bytes());
        device.add_object(&dsdt::NamedString::new(b"_HID", b"LNRO0005"));
        device.add_object(&dsdt::NamedInteger::new(b"_UID", i as u64));
        let mut crs = dsdt::CurrentResourceSettings::new();
        crs.add_resource(&dsdt::QwordMemory::new(high_mmio_space.end, HV_PAGE_SIZE));
        let mut intr = dsdt::Interrupt::new(virtio_mmio_irq);
        intr.is_edge_triggered = false;
        crs.add_resource(&intr);
        device.add_object(&crs);
        dsdt.add_object(&device);
    }

    let high_mmio_gap = MemoryRange::new(high_mmio_space);

    if cfg.with_generic_pci_bus || cfg.with_i440bx_host_pci_bridge {
        // TODO: actually plumb through legacy PCI interrupts
        dsdt.add_pci(low_mmio_gap, high_mmio_gap, pci_legacy_interrupts);
    } else {
        dsdt.add_mmio_module(low_mmio_gap, high_mmio_gap);
    }

    dsdt.add_vmbus(cfg.with_generic_pci_bus || cfg.with_i440bx_host_pci_bridge);
    dsdt.add_rtc();
}
