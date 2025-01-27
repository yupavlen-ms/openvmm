// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`OpenvmmKnownPathsTestArtifactResolver`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_core::ErasedArtifactHandle;
use std::env::consts::EXE_EXTENSION;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;
use vmm_test_images::KnownIso;
use vmm_test_images::KnownVhd;

/// An implementation of [`petri_artifacts_core::TestArtifactResolverBackend`]
/// that resolves artifacts to various "known paths" within the context of
/// the OpenVMM repository.
pub struct OpenvmmKnownPathsTestArtifactResolver;

impl petri_artifacts_core::TestArtifactResolverBackend for OpenvmmKnownPathsTestArtifactResolver {
    #[rustfmt::skip]
    fn resolve(&self, id: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
        use petri_artifacts_common::artifacts as common;
        use petri_artifacts_vmm_test::artifacts::*;

        match id {
            _ if id == common::PIPETTE_WINDOWS_X64 => pipette_path(MachineArch::X86_64, PipetteFlavor::Windows),
            _ if id == common::PIPETTE_LINUX_X64 => pipette_path(MachineArch::X86_64, PipetteFlavor::Linux),
            _ if id == common::PIPETTE_WINDOWS_AARCH64 => pipette_path(MachineArch::Aarch64, PipetteFlavor::Windows),
            _ if id == common::PIPETTE_LINUX_AARCH64 => pipette_path(MachineArch::Aarch64, PipetteFlavor::Linux),

            _ if id == common::TEST_LOG_DIRECTORY => test_log_directory_path(),

            _ if id == OPENVMM_NATIVE => openvmm_native_executable_path(),
            _ if id == OPENHCL_DUMP_DIRECTORY => openhcl_dump_path(),

            _ if id == loadable::LINUX_DIRECT_TEST_KERNEL_X64 => linux_direct_x64_test_kernel_path(),
            _ if id == loadable::LINUX_DIRECT_TEST_KERNEL_AARCH64 => linux_direct_arm_image_path(),
            _ if id == loadable::LINUX_DIRECT_TEST_INITRD_X64 => linux_direct_test_initrd_path(MachineArch::X86_64),
            _ if id == loadable::LINUX_DIRECT_TEST_INITRD_AARCH64 => linux_direct_test_initrd_path(MachineArch::Aarch64),

            _ if id == loadable::PCAT_FIRMWARE_X64 => pcat_firmware_path(),
            _ if id == loadable::SVGA_FIRMWARE_X64 => svga_firmware_path(),
            _ if id == loadable::UEFI_FIRMWARE_X64 => uefi_firmware_path(MachineArch::X86_64),
            _ if id == loadable::UEFI_FIRMWARE_AARCH64 => uefi_firmware_path(MachineArch::Aarch64),

            _ if id == openhcl_igvm::LATEST_STANDARD_X64 => openhcl_bin_path(MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::Standard),
            _ if id == openhcl_igvm::LATEST_CVM_X64 => openhcl_bin_path(MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::Cvm),
            _ if id == openhcl_igvm::LATEST_LINUX_DIRECT_TEST_X64 => openhcl_bin_path(MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::LinuxDirect),
            _ if id == openhcl_igvm::LATEST_STANDARD_AARCH64 => openhcl_bin_path(MachineArch::Aarch64, OpenhclVersion::Latest, OpenhclFlavor::Standard),

            _ if id == openhcl_igvm::um_bin::LATEST_LINUX_DIRECT_TEST_X64 => openhcl_extras_path(OpenhclVersion::Latest,OpenhclFlavor::LinuxDirect,OpenhclExtras::UmBin),
            _ if id == openhcl_igvm::um_dbg::LATEST_LINUX_DIRECT_TEST_X64 => openhcl_extras_path(OpenhclVersion::Latest,OpenhclFlavor::LinuxDirect,OpenhclExtras::UmDbg),

            _ if id == test_vhd::GUEST_TEST_UEFI_X64 => guest_test_uefi_disk_path(MachineArch::X86_64),
            _ if id == test_vhd::GUEST_TEST_UEFI_AARCH64 => guest_test_uefi_disk_path(MachineArch::Aarch64),
            _ if id == test_vhd::GEN1_WINDOWS_DATA_CENTER_CORE2022_X64 => get_guest_vhd_path(KnownVhd::Gen1WindowsDataCenterCore2022),
            _ if id == test_vhd::GEN2_WINDOWS_DATA_CENTER_CORE2022_X64 => get_guest_vhd_path(KnownVhd::Gen2WindowsDataCenterCore2022),
            _ if id == test_vhd::FREE_BSD_13_2_X64 => get_guest_vhd_path(KnownVhd::FreeBsd13_2),
            _ if id == test_vhd::UBUNTU_2204_SERVER_X64 => get_guest_vhd_path(KnownVhd::Ubuntu2204Server),
            _ if id == test_vhd::UBUNTU_2404_SERVER_AARCH64 => get_guest_vhd_path(KnownVhd::Ubuntu2404ServerAarch64),

            _ if id == test_iso::FREE_BSD_13_2_X64 => get_guest_iso_path(KnownIso::FreeBsd13_2),

            _ => anyhow::bail!("no support for given artifact type"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum PipetteFlavor {
    Windows,
    Linux,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum OpenhclVersion {
    Latest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum OpenhclFlavor {
    Standard,
    Cvm,
    LinuxDirect,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum OpenhclExtras {
    UmBin,
    UmDbg,
}

/// The architecture specific fragment of the name of the directory used by rust when referring to specific targets.
fn target_arch_path(arch: MachineArch) -> &'static str {
    match arch {
        MachineArch::X86_64 => "x86_64",
        MachineArch::Aarch64 => "aarch64",
    }
}

fn get_guest_vhd_path(vhd: KnownVhd) -> Result<PathBuf, anyhow::Error> {
    let images_dir = std::env::var("VMM_TEST_IMAGES");
    let full_path = Path::new(images_dir.as_deref().unwrap_or("images"));

    get_path(
        full_path,
        vhd.filename(),
        MissingCommand::Xtask {
            xtask_args: &["guest-test", "download-image", "--vhds", &vhd.name()],
            description: "guest vhd image",
        },
    )
}

fn get_guest_iso_path(iso: KnownIso) -> Result<PathBuf, anyhow::Error> {
    let images_dir = std::env::var("VMM_TEST_IMAGES");
    let full_path = Path::new(images_dir.as_deref().unwrap_or("images"));

    get_path(
        full_path,
        iso.filename(),
        MissingCommand::Xtask {
            xtask_args: &["guest-test", "download-image", "--isos", &iso.name()],
            description: "guest iso image",
        },
    )
}

/// Path to the output location of our guest-test image for UEFI.
fn guest_test_uefi_disk_path(arch: MachineArch) -> anyhow::Result<PathBuf> {
    // `guest_test_uefi` is always at `{arch}-unknown-uefi/debug`
    get_path(
        format!("target/{}-unknown-uefi/debug", target_arch_path(arch)),
        "guest_test_uefi.img",
        MissingCommand::Xtask {
            xtask_args: &[
                "guest-test",
                "uefi",
                &format!(
                    "--boot{}",
                    match arch {
                        MachineArch::X86_64 => "x64",
                        MachineArch::Aarch64 => "aa64",
                    }
                ),
            ],
            description: "guest_test_uefi image",
        },
    )
}

/// Path to the output location of the pipette executable.
fn pipette_path(arch: MachineArch, os_flavor: PipetteFlavor) -> anyhow::Result<PathBuf> {
    // Always use (statically-built) musl on Linux to avoid needing libc
    // compatibility.
    let (target_suffixes, binary) = match os_flavor {
        PipetteFlavor::Windows => (vec!["pc-windows-msvc", "pc-windows-gnu"], "pipette.exe"),
        PipetteFlavor::Linux => (vec!["unknown-linux-musl"], "pipette"),
    };
    for (index, target_suffix) in target_suffixes.iter().enumerate() {
        let target = format!("{}-{}", target_arch_path(arch), target_suffix);
        match get_path(
            format!("target/{target}/debug"),
            binary,
            MissingCommand::Build {
                package: "pipette",
                target: Some(&target),
            },
        ) {
            Ok(path) => return Ok(path),
            Err(err) => {
                if index < target_suffixes.len() - 1 {
                    continue;
                } else {
                    anyhow::bail!(
                        "None of the suffixes {:?} had `pipette` built, {err:?}",
                        target_suffixes
                    );
                }
            }
        }
    }

    unreachable!()
}

/// Path to the output location of the hvlite executable.
fn openvmm_native_executable_path() -> anyhow::Result<PathBuf> {
    get_output_executable_path("openvmm")
}

/// Path to our packaged linux direct test kernel.
fn linux_direct_x64_test_kernel_path() -> anyhow::Result<PathBuf> {
    get_path(
        ".packages/underhill-deps-private",
        "x64/vmlinux",
        MissingCommand::Restore {
            description: "linux direct test kernel",
        },
    )
}

/// Path to our packaged linux direct test initrd.
fn linux_direct_test_initrd_path(arch: MachineArch) -> anyhow::Result<PathBuf> {
    get_path(
        ".packages/underhill-deps-private",
        format!(
            "{}/initrd",
            match arch {
                MachineArch::X86_64 => "x64",
                MachineArch::Aarch64 => "aarch64",
            }
        ),
        MissingCommand::Restore {
            description: "linux direct test initrd",
        },
    )
}

/// Path to our packaged linux direct test kernel.
fn linux_direct_arm_image_path() -> anyhow::Result<PathBuf> {
    get_path(
        ".packages/underhill-deps-private",
        "aarch64/Image",
        MissingCommand::Restore {
            description: "linux direct test kernel",
        },
    )
}

/// Path to our packaged PCAT firmware.
fn pcat_firmware_path() -> anyhow::Result<PathBuf> {
    get_path(
        ".packages",
        "Microsoft.Windows.VmFirmware.Pcat.amd64fre/content/vmfirmwarepcat.dll",
        MissingCommand::Restore {
            description: "PCAT firmware binary",
        },
    )
}

/// Path to our packaged SVGA firmware.
fn svga_firmware_path() -> anyhow::Result<PathBuf> {
    get_path(
        ".packages",
        "Microsoft.Windows.VmEmulatedDevices.amd64fre/content/VmEmulatedDevices.dll",
        MissingCommand::Restore {
            description: "SVGA firmware binary",
        },
    )
}

/// Path to our packaged UEFI firmware image.
fn uefi_firmware_path(arch: MachineArch) -> anyhow::Result<PathBuf> {
    get_path(
        ".packages",
        match arch {
            MachineArch::X86_64 => {
                "hyperv.uefi.mscoreuefi.x64.RELEASE/MsvmX64/RELEASE_VS2022/FV/MSVM.fd"
            }
            MachineArch::Aarch64 => {
                "hyperv.uefi.mscoreuefi.AARCH64.RELEASE/MsvmAARCH64/RELEASE_VS2022/FV/MSVM.fd"
            }
        },
        MissingCommand::Restore {
            description: "UEFI firmware binary",
        },
    )
}

/// Path to the output location of the requested OpenHCL package.
fn openhcl_bin_path(
    arch: MachineArch,
    version: OpenhclVersion,
    flavor: OpenhclFlavor,
) -> anyhow::Result<PathBuf> {
    let (path, name, cmd) = match (arch, version, flavor) {
        (MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::Standard) => (
            "flowey-out/artifacts/build-igvm/debug/x64",
            "openhcl-x64.bin",
            MissingCommand::XFlowey {
                description: "OpenHCL IGVM file",
                xflowey_args: &["build-igvm", "x64"],
            },
        ),
        (MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::Cvm) => (
            "flowey-out/artifacts/build-igvm/debug/x64-cvm",
            "openhcl-x64-cvm.bin",
            MissingCommand::XFlowey {
                description: "OpenHCL IGVM file",
                xflowey_args: &["build-igvm", "x64-cvm"],
            },
        ),
        (MachineArch::X86_64, OpenhclVersion::Latest, OpenhclFlavor::LinuxDirect) => (
            "flowey-out/artifacts/build-igvm/debug/x64-test-linux-direct",
            "openhcl-x64-test-linux-direct.bin",
            MissingCommand::XFlowey {
                description: "OpenHCL IGVM file",
                xflowey_args: &["build-igvm", "x64-test-linux-direct"],
            },
        ),
        (MachineArch::Aarch64, OpenhclVersion::Latest, OpenhclFlavor::Standard) => (
            "flowey-out/artifacts/build-igvm/debug/aarch64",
            "openhcl-aarch64.bin",
            MissingCommand::XFlowey {
                description: "OpenHCL IGVM file",
                xflowey_args: &["build-igvm", "aarch64"],
            },
        ),
        _ => anyhow::bail!("no openhcl bin with given arch, version, and flavor"),
    };

    get_path(path, name, cmd)
}

/// Path to the specified build artifact for the requested OpenHCL package.
fn openhcl_extras_path(
    version: OpenhclVersion,
    flavor: OpenhclFlavor,
    item: OpenhclExtras,
) -> anyhow::Result<PathBuf> {
    if !matches!(version, OpenhclVersion::Latest) || !matches!(flavor, OpenhclFlavor::LinuxDirect) {
        anyhow::bail!("Debug symbol path currently only available for LATEST_LINUX_DIRECT_TEST")
    }

    let (path, name) = match item {
        OpenhclExtras::UmBin => (
            "flowey-out/artifacts/build-igvm/debug/x64-test-linux-direct",
            "openvmm_hcl_msft",
        ),
        OpenhclExtras::UmDbg => (
            "flowey-out/artifacts/build-igvm/debug/x64-test-linux-direct",
            "openvmm_hcl_msft.dbg",
        ),
    };

    get_path(
        path,
        name,
        MissingCommand::XFlowey {
            description: "OpenHCL IGVM file",
            xflowey_args: &["build-igvm", "x64-test-linux-direct"],
        },
    )
}

/// Path to our standard test output directory.
fn test_log_directory_path() -> anyhow::Result<PathBuf> {
    Ok(if let Some(path) = std::env::var_os("TEST_OUTPUT_PATH") {
        PathBuf::from(path)
    } else {
        get_repo_root()?.join("vmm_test_results")
    })
}

/// Path to the location for OpenHCL crash dump files.
fn openhcl_dump_path() -> anyhow::Result<PathBuf> {
    static DUMP_PATH: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    Ok(
        if let Some(path) = std::env::var_os("OPENHCL_DUMP_PATH")
            .or_else(|| std::env::var_os("HVLITE_UNDERHILL_DUMP_PATH"))
        {
            PathBuf::from(path)
        } else {
            DUMP_PATH
                .get_or_init(|| TempDir::new().unwrap())
                .path()
                .to_owned()
        },
    )
}

const VMM_TESTS_DIR_ENV_VAR: &str = "VMM_TESTS_CONTENT_DIR";
const VMM_TESTS_REPO_ROOT_ENV_VAR: &str = "VMM_TESTS_REPO_ROOT";

/// Gets a path to the root of the repo.
pub fn get_repo_root() -> anyhow::Result<PathBuf> {
    if let Ok(env_dir) = std::env::var(VMM_TESTS_REPO_ROOT_ENV_VAR) {
        let repo_root = PathBuf::from(&env_dir);

        if repo_root.exists() {
            Ok(repo_root)
        } else {
            anyhow::bail!(
                "{} from {} does not exist",
                repo_root.display(),
                VMM_TESTS_REPO_ROOT_ENV_VAR
            )
        }
    } else {
        Ok(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
    }
}

/// Attempts to find the given file, first checking for it relative to the test
/// content directory, then falling back to the provided search path.
///
/// Note that the file name can be a multi-segment path (e.g. `foo/bar.txt`) so
/// that it must be in subdirectory of the test content directory. This is useful
/// when multiple files with the same name are needed in different contexts.
///
/// If the search path is relative it is treated as relative to the repo root.
/// If it is absolute it is used unchanged.
///
/// If the file cannot be found then the provided command will be returned as an
/// easily printable error.
// DEVNOTE: `pub` in order to re-use logic in closed-source known_paths resolver
pub fn get_path(
    search_path: impl AsRef<Path>,
    file_name: impl AsRef<Path>,
    missing_cmd: MissingCommand<'_>,
) -> anyhow::Result<PathBuf> {
    let search_path = search_path.as_ref();
    let file_name = file_name.as_ref();
    if file_name.is_absolute() {
        anyhow::bail!("{} should be a relative path", file_name.display());
    }

    if let Ok(env_dir) = std::env::var(VMM_TESTS_DIR_ENV_VAR) {
        let full_path = Path::new(&env_dir).join(file_name);

        if full_path.exists() {
            return Ok(full_path);
        }
    }

    let file_path = if search_path.is_absolute() {
        search_path.to_owned()
    } else {
        get_repo_root()?.join(search_path)
    };

    let full_path = file_path.join(file_name);
    if !full_path.exists() {
        eprintln!("Failed to find {:?}.", full_path);
        missing_cmd.to_error()?;
    }

    Ok(full_path)
}

/// Attempts to find the path to a rust executable built by Cargo, checking
/// the test content directory if the environment variable is set.
// DEVNOTE: `pub` in order to re-use logic in closed-source known_paths resolver
pub fn get_output_executable_path(name: &str) -> anyhow::Result<PathBuf> {
    let mut path: PathBuf = std::env::current_exe()?;
    // Sometimes we end up inside deps instead of the output dir, but if we
    // are we can just go up a level.
    if path.parent().and_then(|x| x.file_name()).unwrap() == "deps" {
        path.pop();
    }

    get_path(
        path.parent().unwrap(),
        Path::new(name).with_extension(EXE_EXTENSION),
        MissingCommand::Build {
            package: name,
            target: None,
        },
    )
}

/// A description of a command that can be run to create a missing file.
// DEVNOTE: `pub` in order to re-use logic in closed-source known_paths resolver
#[derive(Copy, Clone)]
#[expect(missing_docs)] // Self-describing field names.
pub enum MissingCommand<'a> {
    /// A `cargo build` invocation.
    Build {
        package: &'a str,
        target: Option<&'a str>,
    },
    /// A `cargo xtask` invocation.
    Xtask {
        description: &'a str,
        xtask_args: &'a [&'a str],
    },
    /// A `cargo xflowey` invocation.
    XFlowey {
        description: &'a str,
        xflowey_args: &'a [&'a str],
    },
    /// A `xflowey restore-packages` invocation.
    Restore { description: &'a str },
    /// A custom command.
    Custom { description: &'a str, cmd: &'a str },
}

impl MissingCommand<'_> {
    fn to_error(self) -> anyhow::Result<()> {
        match self {
            MissingCommand::Build { package, target } => anyhow::bail!(
                "Failed to find {package} binary. Run `cargo build {target_args}-p {package}` to build it.",
                target_args = target.map_or(String::new(), |target| format!("--target {} ", target)),
            ),
            MissingCommand::Xtask {
                description,
                xtask_args: args,
            } => {
                anyhow::bail!(
                    "Failed to find {}. Run `cargo xtask {}` to create it.",
                    description,
                    args.join(" ")
                )
            }
            MissingCommand::XFlowey { description, xflowey_args: args } => anyhow::bail!(
                    "Failed to find {}. Run `cargo xflowey {}` to create it.",
                    description,
                    args.join(" ")
                ),
            MissingCommand::Restore { description } => {
                anyhow::bail!("Failed to find {}. Run `cargo xflowey restore-packages`.", description)
            }
            MissingCommand::Custom { description, cmd } => {
                anyhow::bail!(
                    "Failed to find {}. Run `{}` to create it.",
                    description,
                    cmd
                )
            }
        }
    }
}
