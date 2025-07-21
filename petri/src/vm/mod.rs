// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Hyper-V VM management
#[cfg(windows)]
pub mod hyperv;
/// OpenVMM VM management
pub mod openvmm;

use crate::PetriLogSource;
use crate::PetriTestParams;
use crate::ShutdownKind;
use crate::disk_image::AgentImage;
use crate::openhcl_diag::OpenHclDiagHandler;
use async_trait::async_trait;
use get_resources::ged::FirmwareEvent;
use pal_async::DefaultDriver;
use petri_artifacts_common::tags::GuestQuirks;
use petri_artifacts_common::tags::IsOpenhclIgvm;
use petri_artifacts_common::tags::IsTestVmgs;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_common::tags::OsFlavor;
use petri_artifacts_core::ArtifactResolver;
use petri_artifacts_core::ResolvedArtifact;
use petri_artifacts_core::ResolvedOptionalArtifact;
use pipette_client::PipetteClient;
use std::path::PathBuf;
use vmm_core_defs::HaltReason;

/// The set of artifacts and resources needed to instantiate a
/// [`PetriVmBuilder`].
pub struct PetriVmArtifacts<T: PetriVmmBackend> {
    /// Artifacts needed to launch the host VMM used for the test
    pub backend: T,
    /// Firmware and/or OS to load into the VM and associated settings
    pub firmware: Firmware,
    /// The architecture of the VM
    pub arch: MachineArch,
    /// Agent to run in the guest
    pub agent_image: Option<AgentImage>,
    /// Agent to run in OpenHCL
    pub openhcl_agent_image: Option<AgentImage>,
}

impl<T: PetriVmmBackend> PetriVmArtifacts<T> {
    /// Resolves the artifacts needed to instantiate a [`PetriVmBuilder`].
    ///
    /// Returns `None` if the supplied configuration is not supported on this platform.
    pub fn new(
        resolver: &ArtifactResolver<'_>,
        firmware: Firmware,
        arch: MachineArch,
    ) -> Option<Self> {
        if !T::check_compat(&firmware, arch) {
            return None;
        }
        Some(Self {
            backend: T::new(resolver),
            arch,
            agent_image: Some(AgentImage::new(resolver, arch, firmware.os_flavor())),
            openhcl_agent_image: if firmware.is_openhcl() {
                Some(AgentImage::new(resolver, arch, OsFlavor::Linux))
            } else {
                None
            },
            firmware,
        })
    }
}

/// Petri VM builder
pub struct PetriVmBuilder<T: PetriVmmBackend> {
    /// Artifacts needed to launch the host VMM used for the test
    backend: T,
    /// VM configuration
    config: PetriVmConfig,
    /// Function to modify the VMM-specific configuration
    modify_vmm_config: Option<Box<dyn FnOnce(T::VmmConfig) -> T::VmmConfig + Send>>,
    /// VMM-agnostic resources
    resources: PetriVmResources,
}

/// Petri VM configuration
pub struct PetriVmConfig {
    /// The name of the VM
    pub name: String,
    /// The architecture of the VM
    pub arch: MachineArch,
    /// Firmware and/or OS to load into the VM and associated settings
    pub firmware: Firmware,
    /// The amount of memory, in bytes, to assign to the VM
    pub memory: MemoryConfig,
    /// The processor tology for the VM
    pub proc_topology: ProcessorTopology,
    /// Agent to run in the guest
    pub agent_image: Option<AgentImage>,
    /// Agent to run in OpenHCL
    pub openhcl_agent_image: Option<AgentImage>,
    /// VM guest state
    pub vmgs: PetriVmgsResource,
}

/// Resources used by a Petri VM during contruction and runtime
pub struct PetriVmResources {
    driver: DefaultDriver,
    output_dir: PathBuf,
    log_source: PetriLogSource,
}

/// Trait for VMM-specific contruction and runtime resources
#[async_trait]
pub trait PetriVmmBackend {
    /// VMM-specific configuration
    type VmmConfig;

    /// Runtime object
    type VmRuntime: PetriVmRuntime;

    /// Check whether the combination of firmware and architecture is
    /// supported on the VMM.
    fn check_compat(firmware: &Firmware, arch: MachineArch) -> bool;

    /// Resolve any artifacts needed to use this backend
    fn new(resolver: &ArtifactResolver<'_>) -> Self;

    /// Create and start VM from the generic config using the VMM backend
    async fn run(
        self,
        config: PetriVmConfig,
        modify_vmm_config: Option<impl FnOnce(Self::VmmConfig) -> Self::VmmConfig + Send>,
        resources: &PetriVmResources,
    ) -> anyhow::Result<Self::VmRuntime>;
}

/// A constructed Petri VM
pub struct PetriVm<T: PetriVmmBackend> {
    arch: MachineArch,
    _resources: PetriVmResources,
    runtime: T::VmRuntime,
}

impl<T: PetriVmmBackend> PetriVmBuilder<T> {
    /// Create a new VM configuration.
    pub fn new(
        params: &PetriTestParams<'_>,
        artifacts: PetriVmArtifacts<T>,
        driver: &DefaultDriver,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            backend: artifacts.backend,
            config: PetriVmConfig {
                name: params.test_name.to_owned(),
                arch: artifacts.arch,
                firmware: artifacts.firmware,
                memory: Default::default(),
                proc_topology: Default::default(),
                agent_image: artifacts.agent_image,
                openhcl_agent_image: artifacts.openhcl_agent_image,
                vmgs: PetriVmgsResource::Ephemeral,
            },
            modify_vmm_config: None,
            resources: PetriVmResources {
                driver: driver.clone(),
                output_dir: params.output_dir.to_owned(),
                log_source: params.logger.clone(),
            },
        })
    }
}

impl<T: PetriVmmBackend> PetriVmBuilder<T> {
    /// Build and boot the requested VM. Does not configure and start pipette.
    /// Should only be used for testing platforms that pipette does not support.
    pub async fn run_without_agent(mut self) -> anyhow::Result<PetriVm<T>> {
        self.config.agent_image = None;
        self.run_core().await
    }

    /// Run the VM, configuring pipette to automatically start, but do not wait
    /// for it to connect. This is useful for tests where the first boot attempt
    /// is expected to not succeed, but pipette functionality is still desired.
    pub async fn run_with_lazy_pipette(self) -> anyhow::Result<PetriVm<T>> {
        assert!(self.config.agent_image.is_some());
        self.run_core().await
    }

    /// Run the VM, launching pipette and returning a client to it.
    pub async fn run(self) -> anyhow::Result<(PetriVm<T>, PipetteClient)> {
        let mut vm = self.run_with_lazy_pipette().await?;
        let client = vm.wait_for_agent().await?;
        Ok((vm, client))
    }

    async fn run_core(self) -> anyhow::Result<PetriVm<T>> {
        let arch = self.config.arch;
        let runtime = self
            .backend
            .run(self.config, self.modify_vmm_config, &self.resources)
            .await?;
        Ok(PetriVm {
            arch,
            _resources: self.resources,
            runtime,
        })
    }

    /// Set the VM to enable secure boot and inject the templates per OS flavor.
    pub fn with_secure_boot(mut self) -> Self {
        self.config
            .firmware
            .uefi_config_mut()
            .expect("Secure boot is only supported for UEFI firmware.")
            .secure_boot_enabled = true;

        match self.os_flavor() {
            OsFlavor::Windows => self.with_windows_secure_boot_template(),
            OsFlavor::Linux => self.with_uefi_ca_secure_boot_template(),
            _ => panic!(
                "Secure boot unsupported for OS flavor {:?}",
                self.os_flavor()
            ),
        }
    }

    /// Inject Windows secure boot templates into the VM's UEFI.
    pub fn with_windows_secure_boot_template(mut self) -> Self {
        self.config
            .firmware
            .uefi_config_mut()
            .expect("Secure boot is only supported for UEFI firmware.")
            .secure_boot_template = Some(SecureBootTemplate::MicrosoftWindows);
        self
    }

    /// Inject UEFI CA secure boot templates into the VM's UEFI.
    pub fn with_uefi_ca_secure_boot_template(mut self) -> Self {
        self.config
            .firmware
            .uefi_config_mut()
            .expect("Secure boot is only supported for UEFI firmware.")
            .secure_boot_template = Some(SecureBootTemplate::MicrosoftUefiCertificateAuthority);
        self
    }

    /// Set the VM to use the specified processor topology.
    pub fn with_processor_topology(mut self, topology: ProcessorTopology) -> Self {
        self.config.proc_topology = topology;
        self
    }

    /// Set the VM to use the specified processor topology.
    pub fn with_memory(mut self, memory: MemoryConfig) -> Self {
        self.config.memory = memory;
        self
    }

    /// Sets a custom OpenHCL IGVM file to use.
    pub fn with_custom_openhcl(mut self, artifact: ResolvedArtifact<impl IsOpenhclIgvm>) -> Self {
        match &mut self.config.firmware {
            Firmware::OpenhclLinuxDirect { igvm_path, .. }
            | Firmware::OpenhclPcat { igvm_path, .. }
            | Firmware::OpenhclUefi { igvm_path, .. } => {
                *igvm_path = artifact.erase();
            }
            Firmware::LinuxDirect { .. } | Firmware::Uefi { .. } | Firmware::Pcat { .. } => {
                panic!("Custom OpenHCL is only supported for OpenHCL firmware.")
            }
        }
        self
    }

    /// Sets the command line for the paravisor.
    pub fn with_openhcl_command_line(mut self, additional_command_line: &str) -> Self {
        append_cmdline(
            &mut self
                .config
                .firmware
                .openhcl_config_mut()
                .expect("OpenHCL command line is only supported for OpenHCL firmware.")
                .command_line,
            additional_command_line,
        );
        self
    }

    /// Enable confidential filtering, even if the VM is not confidential.
    pub fn with_confidential_filtering(self) -> Self {
        if !self.config.firmware.is_openhcl() {
            panic!("Confidential filtering is only supported for OpenHCL");
        }
        self.with_openhcl_command_line(&format!(
            "{}=1 {}=0",
            underhill_confidentiality::OPENHCL_CONFIDENTIAL_ENV_VAR_NAME,
            underhill_confidentiality::OPENHCL_CONFIDENTIAL_DEBUG_ENV_VAR_NAME
        ))
    }

    /// Adds a file to the VM's pipette agent image.
    pub fn with_agent_file(mut self, name: &str, artifact: ResolvedArtifact) -> Self {
        self.config
            .agent_image
            .as_mut()
            .expect("no guest pipette")
            .add_file(name, artifact);
        self
    }

    /// Adds a file to the paravisor's pipette agent image.
    pub fn with_openhcl_agent_file(mut self, name: &str, artifact: ResolvedArtifact) -> Self {
        self.config
            .openhcl_agent_image
            .as_mut()
            .expect("no openhcl pipette")
            .add_file(name, artifact);
        self
    }

    /// Sets whether UEFI frontpage is enabled.
    pub fn with_uefi_frontpage(mut self, enable: bool) -> Self {
        self.config
            .firmware
            .uefi_config_mut()
            .expect("UEFI frontpage is only supported for UEFI firmware.")
            .disable_frontpage = !enable;
        self
    }

    /// Run the VM with Enable VMBus relay enabled
    pub fn with_vmbus_redirect(mut self, enable: bool) -> Self {
        self.config
            .firmware
            .openhcl_config_mut()
            .expect("VMBus redirection is only supported for OpenHCL firmware.")
            .vmbus_redirect = enable;
        self
    }

    /// Specify the guest state lifetime for the VM
    pub fn with_guest_state_lifetime(
        mut self,
        guest_state_lifetime: PetriGuestStateLifetime,
    ) -> Self {
        let disk = match self.config.vmgs {
            PetriVmgsResource::Disk(disk)
            | PetriVmgsResource::ReprovisionOnFailure(disk)
            | PetriVmgsResource::Reprovision(disk) => disk,
            PetriVmgsResource::Ephemeral => None,
        };
        self.config.vmgs = match guest_state_lifetime {
            PetriGuestStateLifetime::Disk => PetriVmgsResource::Disk(disk),
            PetriGuestStateLifetime::ReprovisionOnFailure => {
                PetriVmgsResource::ReprovisionOnFailure(disk)
            }
            PetriGuestStateLifetime::Reprovision => PetriVmgsResource::Reprovision(disk),
            PetriGuestStateLifetime::Ephemeral => {
                if disk.is_some() {
                    panic!("attempted to use ephemeral guest state after specifying backing vmgs")
                }
                PetriVmgsResource::Ephemeral
            }
        };
        self
    }

    /// Use the specified backing VMGS file
    pub fn with_backing_vmgs(mut self, disk: ResolvedArtifact<impl IsTestVmgs>) -> Self {
        match &mut self.config.vmgs {
            PetriVmgsResource::Disk(installed_disk)
            | PetriVmgsResource::ReprovisionOnFailure(installed_disk)
            | PetriVmgsResource::Reprovision(installed_disk) => {
                if installed_disk.is_some() {
                    panic!("already specified a backing vmgs file");
                }
                *installed_disk = Some(disk.erase());
            }
            PetriVmgsResource::Ephemeral => {
                panic!("attempted to specify a backing vmgs with ephemeral guest state")
            }
        }
        self
    }

    /// Get VM's guest OS flavor
    pub fn os_flavor(&self) -> OsFlavor {
        self.config.firmware.os_flavor()
    }

    /// Get whether the VM will use OpenHCL
    pub fn is_openhcl(&self) -> bool {
        self.config.firmware.is_openhcl()
    }

    /// Get the backend-specific config builder
    pub fn modify_backend(
        mut self,
        f: impl FnOnce(T::VmmConfig) -> T::VmmConfig + 'static + Send,
    ) -> Self {
        if self.modify_vmm_config.is_some() {
            panic!("only one modify_backend allowed");
        }
        self.modify_vmm_config = Some(Box::new(f));
        self
    }
}

impl<T: PetriVmmBackend> PetriVm<T> {
    /// Wait for the VM to halt, returning the reason for the halt.
    pub async fn wait_for_halt(&mut self) -> anyhow::Result<HaltReason> {
        self.runtime.wait_for_halt().await
    }

    /// Wait for the VM to halt, returning the reason for the halt,
    /// and cleanly tear down the VM.
    pub async fn wait_for_teardown(mut self) -> anyhow::Result<HaltReason> {
        let halt_reason = self.runtime.wait_for_halt().await?;
        self.runtime.teardown().await?;
        Ok(halt_reason)
    }
    /// Test that we are able to inspect OpenHCL.
    pub async fn test_inspect_openhcl(&mut self) -> anyhow::Result<()> {
        self.openhcl_diag()?.test_inspect().await
    }
    /// Wait for VTL 2 to report that it is ready to respond to commands.
    /// Will fail if the VM is not running OpenHCL.
    ///
    /// This should only be necessary if you're doing something manual. All
    /// Petri-provided methods will wait for VTL 2 to be ready automatically.
    pub async fn wait_for_vtl2_ready(&mut self) -> anyhow::Result<()> {
        self.openhcl_diag()?.wait_for_vtl2().await
    }

    /// Wait for a connection from a pipette agent running in the guest.
    /// Useful if you've rebooted the vm or are otherwise expecting a fresh connection.
    pub async fn wait_for_agent(&mut self) -> anyhow::Result<PipetteClient> {
        self.runtime.wait_for_agent(false).await
    }

    /// Wait for a connection from a pipette agent running in VTL 2.
    /// Useful if you've reset VTL 2 or are otherwise expecting a fresh connection.
    /// Will fail if the VM is not running OpenHCL.
    pub async fn wait_for_vtl2_agent(&mut self) -> anyhow::Result<PipetteClient> {
        // VTL 2's pipette doesn't auto launch, only launch it on demand
        self.launch_vtl2_pipette().await?;
        self.runtime.wait_for_agent(true).await
    }

    /// Waits for an event emitted by the firmware about its boot status, and
    /// verifies that it is the expected success value.
    ///
    /// * Linux Direct guests do not emit a boot event, so this method immediately returns Ok.
    /// * PCAT guests may not emit an event depending on the PCAT version, this
    ///   method is best effort for them.
    pub async fn wait_for_successful_boot_event(&mut self) -> anyhow::Result<()> {
        self.runtime.wait_for_successful_boot_event().await
    }

    /// Waits for an event emitted by the firmware about its boot status, and
    /// returns that status.
    pub async fn wait_for_boot_event(&mut self) -> anyhow::Result<FirmwareEvent> {
        self.runtime.wait_for_boot_event().await
    }

    /// Instruct the guest to shutdown via the Hyper-V shutdown IC.
    pub async fn send_enlightened_shutdown(&mut self, kind: ShutdownKind) -> anyhow::Result<()> {
        self.runtime.send_enlightened_shutdown(kind).await
    }

    /// Instruct the OpenHCL to restart the VTL2 paravisor. Will fail if the VM
    /// is not running OpenHCL. Will also fail if the VM is not running.
    pub async fn restart_openhcl(
        &mut self,
        new_openhcl: ResolvedArtifact<impl IsOpenhclIgvm>,
        flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()> {
        self.runtime
            .restart_openhcl(&new_openhcl.erase(), flags)
            .await
    }

    /// Get VM's guest OS flavor
    pub fn arch(&self) -> MachineArch {
        self.arch
    }

    /// Get the inner runtime backend to make backend-specific calls
    pub fn backend(&mut self) -> &mut T::VmRuntime {
        &mut self.runtime
    }

    async fn launch_vtl2_pipette(&self) -> anyhow::Result<()> {
        // Start pipette through DiagClient
        let res = self
            .openhcl_diag()?
            .run_vtl2_command(
                "sh",
                &[
                    "-c",
                    "mkdir /cidata && mount LABEL=cidata /cidata && sh -c '/cidata/pipette &'",
                ],
            )
            .await?;

        if !res.exit_status.success() {
            anyhow::bail!("Failed to start VTL 2 pipette: {:?}", res);
        }

        Ok(())
    }

    fn openhcl_diag(&self) -> anyhow::Result<&OpenHclDiagHandler> {
        if let Some(ohd) = self.runtime.openhcl_diag() {
            Ok(ohd)
        } else {
            anyhow::bail!("VM is not configured with OpenHCL")
        }
    }
}

/// A running VM that tests can interact with.
#[async_trait]
pub trait PetriVmRuntime {
    /// Cleanly tear down the VM immediately.
    async fn teardown(self) -> anyhow::Result<()>;
    /// Wait for the VM to halt, returning the reason for the halt.
    async fn wait_for_halt(&mut self) -> anyhow::Result<HaltReason>;
    /// Wait for a connection from a pipette agent
    async fn wait_for_agent(&mut self, set_high_vtl: bool) -> anyhow::Result<PipetteClient>;
    /// Get an OpenHCL diagnostics handler for the VM
    fn openhcl_diag(&self) -> Option<&OpenHclDiagHandler>;
    /// Waits for an event emitted by the firmware about its boot status, and
    /// verifies that it is the expected success value.
    ///
    /// * Linux Direct guests do not emit a boot event, so this method immediately returns Ok.
    /// * PCAT guests may not emit an event depending on the PCAT version, this
    ///   method is best effort for them.
    async fn wait_for_successful_boot_event(&mut self) -> anyhow::Result<()>;
    /// Waits for an event emitted by the firmware about its boot status, and
    /// returns that status.
    async fn wait_for_boot_event(&mut self) -> anyhow::Result<FirmwareEvent>;
    /// Instruct the guest to shutdown via the Hyper-V shutdown IC.
    async fn send_enlightened_shutdown(&mut self, kind: ShutdownKind) -> anyhow::Result<()>;
    /// Instruct the OpenHCL to restart the VTL2 paravisor. Will fail if the VM
    /// is not running OpenHCL. Will also fail if the VM is not running.
    async fn restart_openhcl(
        &mut self,
        new_openhcl: &ResolvedArtifact,
        flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()>;
}

/// Common processor topology information for the VM.
pub struct ProcessorTopology {
    /// The number of virtual processors.
    pub vp_count: u32,
    /// Whether SMT (hyperthreading) is enabled.
    pub enable_smt: Option<bool>,
    /// The number of virtual processors per socket.
    pub vps_per_socket: Option<u32>,
    /// The APIC configuration (x86-64 only).
    pub apic_mode: Option<ApicMode>,
}

impl Default for ProcessorTopology {
    fn default() -> Self {
        Self {
            vp_count: 2,
            enable_smt: None,
            vps_per_socket: None,
            apic_mode: None,
        }
    }
}

/// The APIC mode for the VM.
#[derive(Debug, Clone, Copy)]
pub enum ApicMode {
    /// xAPIC mode only.
    Xapic,
    /// x2APIC mode supported but not enabled at boot.
    X2apicSupported,
    /// x2APIC mode enabled at boot.
    X2apicEnabled,
}

/// Common memory configuration information for the VM.
pub struct MemoryConfig {
    /// Specifies the amount of memory, in bytes, to assign to the
    /// virtual machine.
    pub startup_bytes: u64,
    /// Specifies the minimum and maximum amount of dynamic memory, in bytes.
    ///
    /// Dynamic memory will be disabled if this is `None`.
    pub dynamic_memory_range: Option<(u64, u64)>,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            startup_bytes: 0x1_0000_0000,
            dynamic_memory_range: None,
        }
    }
}

/// UEFI firmware configuration
#[derive(Debug)]
pub struct UefiConfig {
    /// Enable secure boot
    pub secure_boot_enabled: bool,
    /// Secure boot template
    pub secure_boot_template: Option<SecureBootTemplate>,
    /// Disable the UEFI frontpage which will cause the VM to shutdown instead when unable to boot.
    pub disable_frontpage: bool,
}

impl Default for UefiConfig {
    fn default() -> Self {
        Self {
            secure_boot_enabled: false,
            secure_boot_template: None,
            disable_frontpage: true,
        }
    }
}

/// OpenHCL configuration
#[derive(Debug, Default, Clone)]
pub struct OpenHclConfig {
    /// Emulate SCSI via NVME to VTL2, with the provided namespace ID on
    /// the controller with `BOOT_NVME_INSTANCE`.
    pub vtl2_nvme_boot: bool,
    /// Whether to enable VMBus redirection
    pub vmbus_redirect: bool,
    /// Command line to pass to OpenHCL
    pub command_line: Option<String>,
}

/// Firmware to load into the test VM.
#[derive(Debug)]
pub enum Firmware {
    /// Boot Linux directly, without any firmware.
    LinuxDirect {
        /// The kernel to boot.
        kernel: ResolvedArtifact,
        /// The initrd to use.
        initrd: ResolvedArtifact,
    },
    /// Boot Linux directly, without any firmware, with OpenHCL in VTL2.
    OpenhclLinuxDirect {
        /// The path to the IGVM file to use.
        igvm_path: ResolvedArtifact,
        /// OpenHCL configuration
        openhcl_config: OpenHclConfig,
    },
    /// Boot a PCAT-based VM.
    Pcat {
        /// The guest OS the VM will boot into.
        guest: PcatGuest,
        /// The firmware to use.
        bios_firmware: ResolvedOptionalArtifact,
        /// The SVGA firmware to use.
        svga_firmware: ResolvedOptionalArtifact,
    },
    /// Boot a PCAT-based VM with OpenHCL in VTL2.
    OpenhclPcat {
        /// The guest OS the VM will boot into.
        guest: PcatGuest,
        /// The path to the IGVM file to use.
        igvm_path: ResolvedArtifact,
        /// The firmware to use.
        bios_firmware: ResolvedOptionalArtifact,
        /// The SVGA firmware to use.
        svga_firmware: ResolvedOptionalArtifact,
        /// OpenHCL configuration
        openhcl_config: OpenHclConfig,
    },
    /// Boot a UEFI-based VM.
    Uefi {
        /// The guest OS the VM will boot into.
        guest: UefiGuest,
        /// The firmware to use.
        uefi_firmware: ResolvedArtifact,
        /// UEFI configuration
        uefi_config: UefiConfig,
    },
    /// Boot a UEFI-based VM with OpenHCL in VTL2.
    OpenhclUefi {
        /// The guest OS the VM will boot into.
        guest: UefiGuest,
        /// The isolation type of the VM.
        isolation: Option<IsolationType>,
        /// The path to the IGVM file to use.
        igvm_path: ResolvedArtifact,
        /// UEFI configuration
        uefi_config: UefiConfig,
        /// OpenHCL configuration
        openhcl_config: OpenHclConfig,
    },
}

impl Firmware {
    /// Constructs a standard [`Firmware::LinuxDirect`] configuration.
    pub fn linux_direct(resolver: &ArtifactResolver<'_>, arch: MachineArch) -> Self {
        use petri_artifacts_vmm_test::artifacts::loadable::*;
        match arch {
            MachineArch::X86_64 => Firmware::LinuxDirect {
                kernel: resolver.require(LINUX_DIRECT_TEST_KERNEL_X64).erase(),
                initrd: resolver.require(LINUX_DIRECT_TEST_INITRD_X64).erase(),
            },
            MachineArch::Aarch64 => Firmware::LinuxDirect {
                kernel: resolver.require(LINUX_DIRECT_TEST_KERNEL_AARCH64).erase(),
                initrd: resolver.require(LINUX_DIRECT_TEST_INITRD_AARCH64).erase(),
            },
        }
    }

    /// Constructs a standard [`Firmware::OpenhclLinuxDirect`] configuration.
    pub fn openhcl_linux_direct(resolver: &ArtifactResolver<'_>, arch: MachineArch) -> Self {
        use petri_artifacts_vmm_test::artifacts::openhcl_igvm::*;
        match arch {
            MachineArch::X86_64 => Firmware::OpenhclLinuxDirect {
                igvm_path: resolver.require(LATEST_LINUX_DIRECT_TEST_X64).erase(),
                openhcl_config: Default::default(),
            },
            MachineArch::Aarch64 => todo!("Linux direct not yet supported on aarch64"),
        }
    }

    /// Constructs a standard [`Firmware::Pcat`] configuration.
    pub fn pcat(resolver: &ArtifactResolver<'_>, guest: PcatGuest) -> Self {
        use petri_artifacts_vmm_test::artifacts::loadable::*;
        Firmware::Pcat {
            guest,
            bios_firmware: resolver.try_require(PCAT_FIRMWARE_X64).erase(),
            svga_firmware: resolver.try_require(SVGA_FIRMWARE_X64).erase(),
        }
    }

    /// Constructs a standard [`Firmware::Uefi`] configuration.
    pub fn uefi(resolver: &ArtifactResolver<'_>, arch: MachineArch, guest: UefiGuest) -> Self {
        use petri_artifacts_vmm_test::artifacts::loadable::*;
        let uefi_firmware = match arch {
            MachineArch::X86_64 => resolver.require(UEFI_FIRMWARE_X64).erase(),
            MachineArch::Aarch64 => resolver.require(UEFI_FIRMWARE_AARCH64).erase(),
        };
        Firmware::Uefi {
            guest,
            uefi_firmware,
            uefi_config: Default::default(),
        }
    }

    /// Constructs a standard [`Firmware::OpenhclUefi`] configuration.
    pub fn openhcl_uefi(
        resolver: &ArtifactResolver<'_>,
        arch: MachineArch,
        guest: UefiGuest,
        isolation: Option<IsolationType>,
        vtl2_nvme_boot: bool,
    ) -> Self {
        use petri_artifacts_vmm_test::artifacts::openhcl_igvm::*;
        let igvm_path = match arch {
            MachineArch::X86_64 if isolation.is_some() => resolver.require(LATEST_CVM_X64).erase(),
            MachineArch::X86_64 => resolver.require(LATEST_STANDARD_X64).erase(),
            MachineArch::Aarch64 => resolver.require(LATEST_STANDARD_AARCH64).erase(),
        };
        Firmware::OpenhclUefi {
            guest,
            isolation,
            igvm_path,
            uefi_config: Default::default(),
            openhcl_config: OpenHclConfig {
                vtl2_nvme_boot,
                ..Default::default()
            },
        }
    }

    fn is_openhcl(&self) -> bool {
        match self {
            Firmware::OpenhclLinuxDirect { .. }
            | Firmware::OpenhclUefi { .. }
            | Firmware::OpenhclPcat { .. } => true,
            Firmware::LinuxDirect { .. } | Firmware::Pcat { .. } | Firmware::Uefi { .. } => false,
        }
    }

    fn isolation(&self) -> Option<IsolationType> {
        match self {
            Firmware::OpenhclUefi { isolation, .. } => *isolation,
            Firmware::LinuxDirect { .. }
            | Firmware::Pcat { .. }
            | Firmware::Uefi { .. }
            | Firmware::OpenhclLinuxDirect { .. }
            | Firmware::OpenhclPcat { .. } => None,
        }
    }

    fn is_linux_direct(&self) -> bool {
        match self {
            Firmware::LinuxDirect { .. } | Firmware::OpenhclLinuxDirect { .. } => true,
            Firmware::Pcat { .. }
            | Firmware::Uefi { .. }
            | Firmware::OpenhclUefi { .. }
            | Firmware::OpenhclPcat { .. } => false,
        }
    }

    fn is_pcat(&self) -> bool {
        match self {
            Firmware::Pcat { .. } | Firmware::OpenhclPcat { .. } => true,
            Firmware::Uefi { .. }
            | Firmware::OpenhclUefi { .. }
            | Firmware::LinuxDirect { .. }
            | Firmware::OpenhclLinuxDirect { .. } => false,
        }
    }

    fn os_flavor(&self) -> OsFlavor {
        match self {
            Firmware::LinuxDirect { .. } | Firmware::OpenhclLinuxDirect { .. } => OsFlavor::Linux,
            Firmware::Uefi {
                guest: UefiGuest::GuestTestUefi { .. } | UefiGuest::None,
                ..
            }
            | Firmware::OpenhclUefi {
                guest: UefiGuest::GuestTestUefi { .. } | UefiGuest::None,
                ..
            } => OsFlavor::Uefi,
            Firmware::Pcat {
                guest: PcatGuest::Vhd(cfg),
                ..
            }
            | Firmware::OpenhclPcat {
                guest: PcatGuest::Vhd(cfg),
                ..
            }
            | Firmware::Uefi {
                guest: UefiGuest::Vhd(cfg),
                ..
            }
            | Firmware::OpenhclUefi {
                guest: UefiGuest::Vhd(cfg),
                ..
            } => cfg.os_flavor,
            Firmware::Pcat {
                guest: PcatGuest::Iso(cfg),
                ..
            }
            | Firmware::OpenhclPcat {
                guest: PcatGuest::Iso(cfg),
                ..
            } => cfg.os_flavor,
        }
    }

    fn quirks(&self) -> GuestQuirks {
        match self {
            Firmware::Pcat {
                guest: PcatGuest::Vhd(cfg),
                ..
            }
            | Firmware::Uefi {
                guest: UefiGuest::Vhd(cfg),
                ..
            }
            | Firmware::OpenhclUefi {
                guest: UefiGuest::Vhd(cfg),
                ..
            } => cfg.quirks,
            Firmware::Pcat {
                guest: PcatGuest::Iso(cfg),
                ..
            } => cfg.quirks,
            _ => Default::default(),
        }
    }

    fn expected_boot_event(&self) -> Option<FirmwareEvent> {
        match self {
            Firmware::LinuxDirect { .. } | Firmware::OpenhclLinuxDirect { .. } => None,
            Firmware::Pcat { .. } | Firmware::OpenhclPcat { .. } => {
                // TODO: Handle older PCAT versions that don't fire the event
                Some(FirmwareEvent::BootAttempt)
            }
            Firmware::Uefi {
                guest: UefiGuest::None,
                ..
            }
            | Firmware::OpenhclUefi {
                guest: UefiGuest::None,
                ..
            } => Some(FirmwareEvent::NoBootDevice),
            Firmware::Uefi { .. } | Firmware::OpenhclUefi { .. } => {
                Some(FirmwareEvent::BootSuccess)
            }
        }
    }

    fn openhcl_config(&self) -> Option<&OpenHclConfig> {
        match self {
            Firmware::OpenhclLinuxDirect { openhcl_config, .. }
            | Firmware::OpenhclUefi { openhcl_config, .. }
            | Firmware::OpenhclPcat { openhcl_config, .. } => Some(openhcl_config),
            Firmware::LinuxDirect { .. } | Firmware::Pcat { .. } | Firmware::Uefi { .. } => None,
        }
    }

    fn openhcl_config_mut(&mut self) -> Option<&mut OpenHclConfig> {
        match self {
            Firmware::OpenhclLinuxDirect { openhcl_config, .. }
            | Firmware::OpenhclUefi { openhcl_config, .. }
            | Firmware::OpenhclPcat { openhcl_config, .. } => Some(openhcl_config),
            Firmware::LinuxDirect { .. } | Firmware::Pcat { .. } | Firmware::Uefi { .. } => None,
        }
    }

    fn uefi_config(&self) -> Option<&UefiConfig> {
        match self {
            Firmware::Uefi { uefi_config, .. } | Firmware::OpenhclUefi { uefi_config, .. } => {
                Some(uefi_config)
            }
            Firmware::LinuxDirect { .. }
            | Firmware::OpenhclLinuxDirect { .. }
            | Firmware::Pcat { .. }
            | Firmware::OpenhclPcat { .. } => None,
        }
    }

    fn uefi_config_mut(&mut self) -> Option<&mut UefiConfig> {
        match self {
            Firmware::Uefi { uefi_config, .. } | Firmware::OpenhclUefi { uefi_config, .. } => {
                Some(uefi_config)
            }
            Firmware::LinuxDirect { .. }
            | Firmware::OpenhclLinuxDirect { .. }
            | Firmware::Pcat { .. }
            | Firmware::OpenhclPcat { .. } => None,
        }
    }
}

/// The guest the VM will boot into. A boot drive with the chosen setup
/// will be automatically configured.
#[derive(Debug)]
pub enum PcatGuest {
    /// Mount a VHD as the boot drive.
    Vhd(BootImageConfig<boot_image_type::Vhd>),
    /// Mount an ISO as the CD/DVD drive.
    Iso(BootImageConfig<boot_image_type::Iso>),
}

impl PcatGuest {
    fn artifact(&self) -> &ResolvedArtifact {
        match self {
            PcatGuest::Vhd(disk) => &disk.artifact,
            PcatGuest::Iso(disk) => &disk.artifact,
        }
    }
}

/// The guest the VM will boot into. A boot drive with the chosen setup
/// will be automatically configured.
#[derive(Debug)]
pub enum UefiGuest {
    /// Mount a VHD as the boot drive.
    Vhd(BootImageConfig<boot_image_type::Vhd>),
    /// The UEFI test image produced by our guest-test infrastructure.
    GuestTestUefi(ResolvedArtifact),
    /// No guest, just the firmware.
    None,
}

impl UefiGuest {
    /// Construct a standard [`UefiGuest::GuestTestUefi`] configuration.
    pub fn guest_test_uefi(resolver: &ArtifactResolver<'_>, arch: MachineArch) -> Self {
        use petri_artifacts_vmm_test::artifacts::test_vhd::*;
        let artifact = match arch {
            MachineArch::X86_64 => resolver.require(GUEST_TEST_UEFI_X64).erase(),
            MachineArch::Aarch64 => resolver.require(GUEST_TEST_UEFI_AARCH64).erase(),
        };
        UefiGuest::GuestTestUefi(artifact)
    }

    fn artifact(&self) -> Option<&ResolvedArtifact> {
        match self {
            UefiGuest::Vhd(vhd) => Some(&vhd.artifact),
            UefiGuest::GuestTestUefi(p) => Some(p),
            UefiGuest::None => None,
        }
    }
}

/// Type-tags for [`BootImageConfig`](super::BootImageConfig)
pub mod boot_image_type {
    mod private {
        pub trait Sealed {}
        impl Sealed for super::Vhd {}
        impl Sealed for super::Iso {}
    }

    /// Private trait use to seal the set of artifact types BootImageType
    /// supports.
    pub trait BootImageType: private::Sealed {}

    /// BootImageConfig for a VHD file
    #[derive(Debug)]
    pub enum Vhd {}

    /// BootImageConfig for an ISO file
    #[derive(Debug)]
    pub enum Iso {}

    impl BootImageType for Vhd {}
    impl BootImageType for Iso {}
}

/// Configuration information for the boot drive of the VM.
#[derive(Debug)]
pub struct BootImageConfig<T: boot_image_type::BootImageType> {
    /// Artifact handle corresponding to the boot media.
    artifact: ResolvedArtifact,
    /// The OS flavor.
    os_flavor: OsFlavor,
    /// Any quirks needed to boot the guest.
    ///
    /// Most guests should not need any quirks, and can use `Default`.
    quirks: GuestQuirks,
    /// Marker denoting what type of media `artifact` corresponds to
    _type: core::marker::PhantomData<T>,
}

impl BootImageConfig<boot_image_type::Vhd> {
    /// Create a new BootImageConfig from a VHD artifact handle
    pub fn from_vhd<A>(artifact: ResolvedArtifact<A>) -> Self
    where
        A: petri_artifacts_common::tags::IsTestVhd,
    {
        BootImageConfig {
            artifact: artifact.erase(),
            os_flavor: A::OS_FLAVOR,
            quirks: A::quirks(),
            _type: std::marker::PhantomData,
        }
    }
}

impl BootImageConfig<boot_image_type::Iso> {
    /// Create a new BootImageConfig from an ISO artifact handle
    pub fn from_iso<A>(artifact: ResolvedArtifact<A>) -> Self
    where
        A: petri_artifacts_common::tags::IsTestIso,
    {
        BootImageConfig {
            artifact: artifact.erase(),
            os_flavor: A::OS_FLAVOR,
            quirks: A::quirks(),
            _type: std::marker::PhantomData,
        }
    }
}

/// Isolation type
#[derive(Debug, Clone, Copy)]
pub enum IsolationType {
    /// VBS
    Vbs,
    /// SNP
    Snp,
    /// TDX
    Tdx,
}

/// Flags controlling servicing behavior.
#[derive(Default, Debug, Clone, Copy)]
pub struct OpenHclServicingFlags {
    /// Preserve DMA memory for NVMe devices if supported.
    pub enable_nvme_keepalive: bool,
    /// Skip any logic that the vmm may have to ignore servicing updates if the supplied igvm file version is not different than the one currently running.
    pub override_version_checks: bool,
    /// Hint to the OpenHCL runtime how much time to wait when stopping / saving the OpenHCL.
    pub stop_timeout_hint_secs: Option<u16>,
}

/// Petri VM guest state resource
#[derive(Debug, Clone)]
pub enum PetriVmgsResource {
    /// Use disk to store guest state
    Disk(Option<ResolvedArtifact>),
    /// Use disk to store guest state, reformatting if corrupted.
    ReprovisionOnFailure(Option<ResolvedArtifact>),
    /// Format and use disk to store guest state
    Reprovision(Option<ResolvedArtifact>),
    /// Store guest state in memory
    Ephemeral,
}

/// Petri VM guest state lifetime
#[derive(Debug, Clone, Copy)]
pub enum PetriGuestStateLifetime {
    /// Use a differencing disk backed by a blank, tempory VMGS file
    /// or other artifact if one is provided
    Disk,
    /// Same as default, except reformat the backing disk if corrupted
    ReprovisionOnFailure,
    /// Same as default, except reformat the backing disk
    Reprovision,
    /// Store guest state in memory (no backing disk)
    Ephemeral,
}

/// UEFI secure boot template
#[derive(Debug, Clone, Copy)]
pub enum SecureBootTemplate {
    /// The Microsoft Windows template.
    MicrosoftWindows,
    /// The Microsoft UEFI certificate authority template.
    MicrosoftUefiCertificateAuthority,
}

fn append_cmdline(cmd: &mut Option<String>, add_cmd: &str) {
    if let Some(cmd) = cmd.as_mut() {
        cmd.push(' ');
        cmd.push_str(add_cmd);
    } else {
        *cmd = Some(add_cmd.to_string());
    }
}
