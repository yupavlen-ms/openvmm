// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Functions for interacting with the BIOS_NVRAM file in a VMGS file

use crate::storage_backend::VmgsStorageBackend;
use crate::vmgs_file_open;
use crate::vmgs_json;
use crate::Error;
use crate::FilePathArg;
use crate::KeyPathArg;
use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use fs_err::File;
use guid::Guid;
use hcl_compat_uefi_nvram_storage::HclCompatNvram;
use std::io::Write;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use ucs2::Ucs2LeVec;
use uefi_nvram_specvars::boot_order;
use uefi_nvram_specvars::parse_nvram_entry;
use uefi_nvram_specvars::signature_list::SignatureList;
use uefi_nvram_specvars::ParsedNvramEntry;
use uefi_nvram_storage::NvramStorage;
use uefi_specs::uefi::nvram::vars::EFI_GLOBAL_VARIABLE;
use uefi_specs::uefi::time::EFI_TIME;
use vmgs::disk::vhd_file::FileDiskFlag;
use vmgs::Vmgs;

#[derive(Args)]
pub(crate) struct OutputArgs {
    /// Output file path (defaults to terminal)
    #[clap(short = 'o', long, alias = "outpath")]
    output_path: Option<PathBuf>,
    /// Only print about one line's worth of bytes of each entry
    #[clap(short = 't', long)]
    truncate: bool,
}

#[derive(Subcommand)]
pub(crate) enum UefiNvramOperation {
    /// Dump/Read UEFI NVRAM variables
    Dump {
        #[command(flatten)]
        file_path: FilePathArg,
        #[command(flatten)]
        key_path: KeyPathArg,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Dump/Read UEFI NVRAM variables from a JSON file generated by
    /// HvGuestState from a VMGSv1 file
    DumpFromJson {
        /// JSON file path
        #[clap(short = 'f', long, alias = "filepath")]
        file_path: PathBuf,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Attempt to repair boot by deleting all boot entries from the UEFI NVRAM
    RemoveBootEntries {
        #[command(flatten)]
        file_path: FilePathArg,
        #[command(flatten)]
        key_path: KeyPathArg,
        /// Don't actually delete anything, just print the boot entries
        #[clap(short = 'n', long)]
        dry_run: bool,
    },
    /// Remove a UEFI NVRAM variable
    RemoveEntry {
        #[command(flatten)]
        file_path: FilePathArg,
        #[command(flatten)]
        key_path: KeyPathArg,
        /// Name of the NVRAM entry
        #[clap(short = 'n', long)]
        name: String,
        /// Vendor GUID of the NVRAM entry
        #[clap(short = 'v', long)]
        vendor: String,
    },
}

pub(crate) async fn do_command(operation: UefiNvramOperation) -> Result<(), Error> {
    match operation {
        UefiNvramOperation::Dump {
            file_path,
            key_path,
            output,
        } => {
            vmgs_file_dump_nvram(
                file_path.file_path,
                output.output_path,
                key_path.key_path,
                output.truncate,
            )
            .await
        }
        UefiNvramOperation::DumpFromJson { file_path, output } => {
            dump_nvram_from_json(file_path, output.output_path, output.truncate)
        }
        UefiNvramOperation::RemoveBootEntries {
            file_path,
            key_path,
            dry_run,
        } => vmgs_file_remove_boot_entries(file_path.file_path, key_path.key_path, dry_run).await,
        UefiNvramOperation::RemoveEntry {
            file_path,
            key_path,
            name,
            vendor,
        } => {
            vmgs_file_remove_nvram_entry(file_path.file_path, key_path.key_path, name, vendor).await
        }
    }
}

/// Get UEFI variables from the VMGS file, and write to `data_path`.
async fn vmgs_file_dump_nvram(
    file_path: impl AsRef<Path>,
    output_path: Option<impl AsRef<Path>>,
    key_path: Option<impl AsRef<Path>>,
    truncate: bool,
) -> Result<(), Error> {
    let mut nvram_storage = vmgs_file_open_nvram(file_path, key_path, FileDiskFlag::Read).await?;

    let mut out: Box<dyn Write + Send> = if let Some(path) = output_path {
        Box::new(File::create(path.as_ref()).map_err(Error::DataFile)?)
    } else {
        Box::new(std::io::stdout())
    };

    dump_nvram(&mut nvram_storage, &mut out, truncate).await
}

async fn dump_nvram(
    nvram_storage: &mut HclCompatNvram<VmgsStorageBackend>,
    out: &mut impl Write,
    truncate: bool,
) -> Result<(), Error> {
    let mut printed_one = false;
    for entry in nvram_storage.iter().await? {
        let meta = NvramEntryMetadata {
            vendor: entry.vendor.to_string(),
            name: entry.name.to_string(),
            timestamp: Some(entry.timestamp),
            attr: entry.attr,
            size: entry.data.len(),
        };
        let entry = parse_nvram_entry(&meta.name, entry.data)?;
        print_nvram_entry(out, &meta, &entry, truncate).map_err(Error::DataFile)?;
        printed_one = true;
    }
    if !printed_one {
        writeln!(out, "NVRAM empty").map_err(Error::DataFile)?;
    }
    Ok(())
}

/// Get UEFI variables from a JSON file and write to `output_path`.
fn dump_nvram_from_json(
    file_path: impl AsRef<Path>,
    output_path: Option<impl AsRef<Path>>,
    truncate: bool,
) -> Result<(), Error> {
    let file = File::open(file_path.as_ref()).map_err(Error::VmgsFile)?;

    let runtime_state: vmgs_json::RuntimeState = serde_json::from_reader(file)?;

    let nvram_state = runtime_state
        .devices
        .get(vmgs_json::BIOS_LOADER_DEVICE_ID)
        .ok_or(Error::Json("Missing BIOS_LOADER_DEVICE_ID".to_string()))?
        .states
        .get("Nvram")
        .ok_or(Error::Json("Missing Nvram".to_string()))?;

    let vendors = match nvram_state {
        vmgs_json::State::Nvram { vendors, .. } => vendors,
        _ => return Err(Error::Json("Nvram state invalid".to_string())),
    };

    let mut out: Box<dyn Write> = if let Some(path) = output_path {
        Box::new(File::create(path.as_ref()).map_err(Error::DataFile)?)
    } else {
        Box::new(std::io::stdout())
    };

    for (vendor, val) in vendors.iter() {
        for (name, var) in val.variables.iter() {
            let meta = NvramEntryMetadata {
                vendor: vendor.clone(),
                name: name.clone(),
                timestamp: None,
                attr: var.attributes,
                size: var.data.len(),
            };
            let entry = parse_nvram_entry(&meta.name, &var.data)?;
            print_nvram_entry(&mut out, &meta, &entry, truncate).map_err(Error::DataFile)?;
        }
    }
    Ok(())
}

/// Similar to [`uefi_nvram_storage::in_memory::VariableEntry`], but with metadata
/// members that are easier to manipulate
struct NvramEntryMetadata {
    pub vendor: String,
    pub name: String,
    pub timestamp: Option<EFI_TIME>,
    pub attr: u32,
    pub size: usize,
}

fn print_nvram_entry(
    out: &mut impl Write,
    meta: &NvramEntryMetadata,
    entry: &ParsedNvramEntry<'_>,
    truncate: bool,
) -> std::io::Result<()> {
    const LINE_WIDTH: usize = 80;

    write!(
        out,
        "Vendor: {:?}\nName: {:?}\nAttributes: {:#x}\nSize: {:#x}\n",
        meta.vendor, meta.name, meta.attr, meta.size,
    )?;

    if let Some(timestamp) = meta.timestamp {
        writeln!(out, "Timestamp: {}", timestamp)?;
    }

    match entry {
        ParsedNvramEntry::BootOrder(boot_order) => {
            write!(out, "Boot Order:")?;
            for x in boot_order {
                write!(out, " {}", x)?;
            }
            writeln!(out)?;
        }
        ParsedNvramEntry::Boot(load_option) => {
            writeln!(
                out,
                "Load Option: attributes: {:x}, description: {}",
                load_option.attributes, load_option.description
            )?;
            for path in &load_option.device_paths {
                writeln!(out, "  - {:x?}", path)?;
            }
            if let Some(opt) = load_option.opt {
                let prefix = "  - opt: ";
                write!(out, "{}", prefix)?;
                print_hex_compact(out, opt, truncate.then(|| LINE_WIDTH - prefix.len()))?;
                writeln!(out)?;
            }
        }
        ParsedNvramEntry::SignatureList(sig_lists) => {
            writeln!(out, "Signature Lists:")?;
            for sig in sig_lists {
                match sig {
                    SignatureList::Sha256(list) => {
                        writeln!(out, "  - [Sha256]")?;
                        for sig in list {
                            let prefix = format!(
                                "      - Signature Owner: {} Data: ",
                                sig.header.signature_owner
                            );
                            write!(out, "{}", &prefix)?;
                            print_hex_compact(
                                out,
                                sig.data.0.deref(),
                                truncate.then(|| LINE_WIDTH - prefix.len()),
                            )?;
                            writeln!(out)?;
                        }
                    }
                    SignatureList::X509(sig) => {
                        let prefix = format!(
                            "  - [X509] Signature Owner: {} Data: ",
                            sig.header.signature_owner
                        );
                        write!(out, "{}", &prefix)?;
                        print_hex_compact(
                            out,
                            sig.data.0.deref(),
                            truncate.then(|| LINE_WIDTH - prefix.len()),
                        )?;
                        writeln!(out)?;
                    }
                }
            }
        }
        ParsedNvramEntry::Unknown(data) => {
            let prefix = "data: ";
            write!(out, "{}", prefix)?;
            print_hex_compact(out, data, truncate.then(|| LINE_WIDTH - prefix.len()))?;
            writeln!(out)?;
        }
    }

    writeln!(out)?;

    Ok(())
}

fn print_hex_compact(
    out: &mut impl Write,
    data: &[u8],
    truncate: Option<usize>,
) -> std::io::Result<()> {
    if let Some(truncate) = truncate {
        let ellipsis = "...";
        let num_bytes = (truncate - ellipsis.len()) / 2;
        for byte in data.iter().take(num_bytes) {
            write!(out, "{:02x}", byte)?;
        }
        if data.len() > num_bytes {
            write!(out, "{}", ellipsis)?;
        }
    } else {
        for byte in data {
            write!(out, "{:02x}", byte)?;
        }
    }

    Ok(())
}

async fn vmgs_file_open_nvram(
    file_path: impl AsRef<Path>,
    key_path: Option<impl AsRef<Path>>,
    flag: FileDiskFlag,
) -> Result<HclCompatNvram<VmgsStorageBackend>, Error> {
    let vmgs = vmgs_file_open(file_path, key_path, flag, false).await?;
    let encrypted = vmgs.is_encrypted();

    open_nvram(vmgs, encrypted)
}

fn open_nvram(vmgs: Vmgs, encrypted: bool) -> Result<HclCompatNvram<VmgsStorageBackend>, Error> {
    let nvram_storage = HclCompatNvram::new(
        VmgsStorageBackend::new(vmgs, vmgs::FileId::BIOS_NVRAM, encrypted)
            .map_err(Error::VmgsStorageBackend)?,
        None,
    );

    Ok(nvram_storage)
}

/// Delete all boot entries in the BIOS NVRAM VMGS file in an attempt to repair a VM that is failing to boot.
/// This will trigger UEFI to attempt a default boot of all installed devices until one succeeds.
async fn vmgs_file_remove_boot_entries(
    file_path: impl AsRef<Path>,
    key_path: Option<impl AsRef<Path>>,
    dry_run: bool,
) -> Result<(), Error> {
    let mut nvram_storage =
        vmgs_file_open_nvram(file_path, key_path, FileDiskFlag::ReadWrite).await?;

    if dry_run {
        println!("Printing Boot Entries (Dry-run)");
    } else {
        println!("Deleting Boot Entries");
    }

    let name = Ucs2LeVec::from("BootOrder".to_string());
    let (_, boot_order_bytes, _) = nvram_storage
        .get_variable(&name, EFI_GLOBAL_VARIABLE)
        .await?
        .ok_or(Error::MissingNvramEntry(name.clone()))?;
    let boot_order = boot_order::parse_boot_order(&boot_order_bytes)
        .map_err(uefi_nvram_specvars::ParseError::BootOrder)?;

    if !dry_run {
        if !nvram_storage
            .remove_variable(&name, EFI_GLOBAL_VARIABLE)
            .await?
        {
            return Err(Error::MissingNvramEntry(name));
        }
    }

    for (i, boot_option_num) in boot_order.enumerate() {
        let name = Ucs2LeVec::from(format!("Boot{:04x}", boot_option_num));
        let (_, boot_option_bytes, _) = nvram_storage
            .get_variable(&name, EFI_GLOBAL_VARIABLE)
            .await?
            .ok_or(Error::MissingNvramEntry(name.clone()))?;
        let boot_option = boot_order::EfiLoadOption::parse(&boot_option_bytes)
            .map_err(uefi_nvram_specvars::ParseError::BootOrder)?;

        println!("{i}: {}: {:x?}", &name, boot_option);

        if !dry_run {
            if !nvram_storage
                .remove_variable(&name, EFI_GLOBAL_VARIABLE)
                .await?
            {
                return Err(Error::MissingNvramEntry(name));
            }
        }
    }

    Ok(())
}

/// Remove an entry from the BIOS NVRAM VMGS file
async fn vmgs_file_remove_nvram_entry(
    file_path: impl AsRef<Path>,
    key_path: Option<impl AsRef<Path>>,
    name: String,
    vendor: String,
) -> Result<(), Error> {
    let mut nvram_storage =
        vmgs_file_open_nvram(file_path, key_path, FileDiskFlag::ReadWrite).await?;

    let name = Ucs2LeVec::from(name);
    let vendor = Guid::from_str(&vendor)?;

    if !nvram_storage.remove_variable(&name, vendor).await? {
        return Err(Error::MissingNvramEntry(name));
    }

    Ok(())
}
