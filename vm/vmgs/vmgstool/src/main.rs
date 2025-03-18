// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

mod storage_backend;
mod uefi_nvram;
mod vmgs_json;

use anyhow::Result;
use clap::Args;
use clap::Parser;
use disk_backend::Disk;
use disk_vhd1::Vhd1Disk;
use fs_err::File;
use pal_async::DefaultPool;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;
use uefi_nvram::UefiNvramOperation;
use vmgs::Error as VmgsError;
use vmgs::Vmgs;
use vmgs::vmgs_helpers::get_active_header;
use vmgs::vmgs_helpers::read_headers;
use vmgs::vmgs_helpers::validate_header;
use vmgs_format::EncryptionAlgorithm;
use vmgs_format::FileId;
use vmgs_format::VMGS_BYTES_PER_BLOCK;
use vmgs_format::VMGS_DEFAULT_CAPACITY;
use vmgs_format::VMGS_ENCRYPTION_KEY_SIZE;
use vmgs_format::VmgsHeader;

const ONE_MEGA_BYTE: u64 = 1024 * 1024;
const ONE_GIGA_BYTE: u64 = ONE_MEGA_BYTE * 1024;

#[derive(Debug, Error)]
enum Error {
    #[error("VMGS file IO")]
    VmgsFile(#[source] std::io::Error),
    #[error("VHD file error")]
    Vhd1(#[source] disk_vhd1::OpenError),
    #[error("invalid disk")]
    InvalidDisk(#[source] disk_backend::InvalidDisk),
    #[error("VMGS format")]
    Vmgs(#[from] vmgs::Error),
    #[error("VMGS file already exists")]
    FileExists,
    #[cfg(with_encryption)]
    #[error("Adding encryption key")]
    EncryptionKey(#[source] vmgs::Error),
    #[error("Data file / STDOUT IO")]
    DataFile(#[source] std::io::Error),
    #[error("The VMGS file has zero size")]
    ZeroSize,
    #[error("The VMGS file has a non zero size but the contents are empty")]
    EmptyFile,
    #[error("Invalid VMGS file size: {0} {1}")]
    InvalidVmgsFileSize(u64, String),
    #[error("VMGS file is encrypted, but no encryption key was provided")]
    AlreadyEncrypted,
    #[error("Key file IO")]
    KeyFile(#[source] std::io::Error),
    #[error("Key must be {0} bytes long, is {1} bytes instead")]
    InvalidKeySize(u64, u64),
    #[error("File is not encrypted")]
    NotEncrypted,
    #[error("File is VMGSv1 format")]
    V1Format,
    #[error("VmgsStorageBackend")]
    VmgsStorageBackend(#[from] storage_backend::EncryptionNotSupported),
    #[error("NVRAM storage")]
    NvramStorage(#[from] uefi_nvram_storage::NvramStorageError),
    #[error("UEFI NVRAM variable parsing")]
    NvramParsing(#[from] uefi_nvram_specvars::ParseError),
    #[error("NVRAM entry not found: {0}")]
    MissingNvramEntry(ucs2::Ucs2LeVec),
    #[error("GUID parsing")]
    Guid(#[from] guid::ParseError),
    #[error("JSON parsing")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Bad JSON contents: {0}")]
    Json(String),
    #[error("File ID {0:?} already exists. Use `--allow-overwrite` to ignore.")]
    FileIdExists(FileId),
    #[error("VMGS file is encrypted using GspById")]
    GspByIdEncryption,
}

/// Automation requires certain exit codes to be guaranteed
/// main matches Error enum to ExitCode
///
/// query-encryption must return ErrorNotEncrypted if file is not encrypted
/// dump-headers must return ErrorEmpty when file is blank
/// query-size must return ErrorNotFound when file id is uninitialized
/// ExitCode::Error returned for all other errors
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
enum ExitCode {
    Error = 1,
    ErrorNotEncrypted = 2,
    ErrorEmpty = 3,
    ErrorNotFound = 4,
    ErrorV1 = 5,
    ErrorGspById = 6,
}

#[derive(Debug, Clone, Copy)]
enum VmgsEncryptionScheme {
    GspKey,
    GspById,
    None,
}

#[derive(Args)]
struct FilePathArg {
    /// VMGS file path
    #[clap(short = 'f', long, alias = "filepath")]
    file_path: PathBuf,
}

#[derive(Args)]
struct KeyPathArg {
    /// Encryption key file path. The file must contain a key that is 32 bytes long.
    #[clap(short = 'k', long, alias = "keypath")]
    key_path: Option<PathBuf>,
}

#[derive(Args)]
struct FileIdArg {
    /// VMGS File ID
    #[clap(short = 'i', long, alias = "fileid", value_parser = parse_file_id)]
    file_id: FileId,
}

#[derive(Parser)]
#[clap(name = "vmgstool", about = "Tool to interact with VMGS files.")]
enum Options {
    /// Create and initialize `filepath` as a VMGS file of size `filesize`.
    ///
    /// `keypath` and `encryptionalgorithm` must both be specified if encrypted
    /// guest state is required.
    Create {
        #[command(flatten)]
        file_path: FilePathArg,
        /// VMGS file size, default = 4194816 (~4MB)
        #[clap(short = 's', long, alias = "filesize")]
        file_size: Option<u64>,
        /// Encryption key file path. The file must contain a key that is 32 bytes long.
        ///
        /// `encryptionalgorithm` must also be specified when using this flag.
        #[clap(
            short = 'k',
            long,
            alias = "keypath",
            requires = "encryption_algorithm"
        )]
        key_path: Option<PathBuf>,
        /// Encryption algorithm. Currently AES_GCM is the only algorithm supported.
        ///
        /// `keypath` must also be specified when using this flag.
        #[clap(short = 'e', long, alias = "encryptionalgorithm", requires = "key_path", value_parser = parse_encryption_algorithm)]
        encryption_algorithm: Option<EncryptionAlgorithm>,
        /// Force creation of the VMGS file. If the VMGS filepath already exists,
        /// this flag allows an existing file to be overwritten.
        #[clap(long, alias = "forcecreate")]
        force_create: bool,
    },
    /// Write data into the specified file ID of the VMGS file.
    ///
    /// The proper key file must be specified to write encrypted data.
    Write {
        #[command(flatten)]
        file_path: FilePathArg,
        /// Data file path to read
        #[clap(short = 'd', long, alias = "datapath")]
        data_path: PathBuf,
        #[command(flatten)]
        file_id: FileIdArg,
        #[command(flatten)]
        key_path: KeyPathArg,
        /// Overwrite the VMGS data at `fileid`, even if it already exists with nonzero size
        #[clap(long, alias = "allowoverwrite")]
        allow_overwrite: bool,
    },
    /// Dump/read data from the specified file ID of the VMGS file.
    ///
    /// The proper key file must be specified to read encrypted data. If the data
    /// is encrypted and no key is specified, the data will be dumped without
    /// decrypting.
    Dump {
        #[command(flatten)]
        file_path: FilePathArg,
        /// Data file path to write
        #[clap(short = 'd', long, alias = "datapath")]
        data_path: Option<PathBuf>,
        #[command(flatten)]
        file_id: FileIdArg,
        #[command(flatten)]
        key_path: KeyPathArg,
        /// When dumping to stdout, dump data as raw bytes instead of ASCII hex
        #[clap(long, conflicts_with = "data_path")]
        raw_stdout: bool,
    },
    /// Dump headers of the VMGS file at `filepath` to the console.
    DumpHeaders {
        #[command(flatten)]
        file_path: FilePathArg,
    },
    /// Get the size of the specified `fileid` within the VMGS file
    QuerySize {
        #[command(flatten)]
        file_path: FilePathArg,
        #[command(flatten)]
        file_id: FileIdArg,
    },
    /// Replace the current encryption key with a new provided key
    ///
    /// Both key files must contain a key that is 32 bytes long.
    UpdateKey {
        #[command(flatten)]
        file_path: FilePathArg,
        /// Current encryption key file path.
        #[clap(short = 'k', long, alias = "keypath")]
        key_path: PathBuf,
        /// New encryption key file path.
        #[clap(short = 'n', long, alias = "newkeypath")]
        new_key_path: PathBuf,
        /// Encryption algorithm. Currently AES_GCM is the only algorithm supported.
        #[clap(short = 'e', long, alias = "encryptionalgorithm", value_parser = parse_encryption_algorithm)]
        encryption_algorithm: EncryptionAlgorithm,
    },
    /// Encrypt an existing VMGS file
    Encrypt {
        #[command(flatten)]
        file_path: FilePathArg,
        /// Encryption key file path. The file must contain a key that is 32 bytes long.
        #[clap(short = 'k', long, alias = "keypath")]
        key_path: PathBuf,
        /// Encryption algorithm. Currently AES_GCM is the only algorithm supported.
        #[clap(short = 'e', long, alias = "encryptionalgorithm", value_parser = parse_encryption_algorithm)]
        encryption_algorithm: EncryptionAlgorithm,
    },
    /// Query whether a VMGS file is encrypted
    QueryEncryption {
        #[command(flatten)]
        file_path: FilePathArg,
    },
    /// UEFI NVRAM operations
    UefiNvram {
        #[clap(subcommand)]
        operation: UefiNvramOperation,
    },
}

fn parse_file_id(file_id: &str) -> Result<FileId, std::num::ParseIntError> {
    Ok(match file_id {
        "FILE_TABLE" => FileId::FILE_TABLE,
        "BIOS_NVRAM" => FileId::BIOS_NVRAM,
        "TPM_PPI" => FileId::TPM_PPI,
        "TPM_NVRAM" => FileId::TPM_NVRAM,
        "RTC_SKEW" => FileId::RTC_SKEW,
        "ATTEST" => FileId::ATTEST,
        "KEY_PROTECTOR" => FileId::KEY_PROTECTOR,
        "VM_UNIQUE_ID" => FileId::VM_UNIQUE_ID,
        "GUEST_FIRMWARE" => FileId::GUEST_FIRMWARE,
        "CUSTOM_UEFI" => FileId::CUSTOM_UEFI,
        "GUEST_WATCHDOG" => FileId::GUEST_WATCHDOG,
        "HW_KEY_PROTECTOR" => FileId::HW_KEY_PROTECTOR,
        "GUEST_SECRET_KEY" => FileId::GUEST_SECRET_KEY,
        "EXTENDED_FILE_TABLE" => FileId::EXTENDED_FILE_TABLE,
        v => FileId(v.parse::<u32>()?),
    })
}

fn parse_encryption_algorithm(algorithm: &str) -> Result<EncryptionAlgorithm, &'static str> {
    match algorithm {
        "AES_GCM" => Ok(EncryptionAlgorithm::AES_GCM),
        _ => Err("Encryption algorithm not supported"),
    }
}

fn extract_version(ver: u32) -> String {
    let major = (ver >> 16) & 0xFF;
    let minor = ver & 0xFF;
    format!("{major}.{minor}")
}

fn parse_legacy_args() -> Vec<String> {
    use std::env;
    let mut args: Vec<String> = env::args().collect();
    if let Some(cmd) = args.get(1) {
        let cmd_lower = cmd.to_ascii_lowercase();
        let new_cmd = match &cmd_lower[..] {
            "-c" | "-create" => Some("create"),
            "-w" | "-write" => Some("write"),
            "-r" | "-dump" => Some("dump"),
            "-rh" | "-dumpheaders" => Some("dump-headers"),
            "-qs" | "-querysize" => Some("query-size"),
            "-uk" | "-updatekey" => Some("update-key"),
            "-e" | "-encrypt" => Some("encrypt"),
            _ => None,
        };

        if let Some(new_cmd) = new_cmd {
            eprintln!("Warning: Using legacy arguments. Please migrate to the new syntax.");
            args[1] = new_cmd.to_string();

            let mut index = 2;
            while let Some(arg) = args.get(index) {
                let arg_lower = arg.to_ascii_lowercase();
                if let Some(new_arg) = match &arg_lower[..] {
                    "-f" | "-filepath" => Some("--file-path"),
                    "-s" | "-filesize" => Some("--file-size"),
                    "-i" | "-fileid" => Some("--file-id"),
                    "-d" | "-datapath" => Some("--data-path"),
                    "-ow" | "-allowoverwrite" => Some("--allow-overwrite"),
                    "-k" | "-keypath" => Some("--key-path"),
                    "-n" | "-newkeypath" => Some("--new-key-path"),
                    "-ea" | "-encryptionalgorithm" => Some("--encryption-algorithm"),
                    "-fc" | "-forcecreate" => Some("--force-create"),
                    _ => None,
                } {
                    args[index] = new_arg.to_string();
                }
                index += 1;
            }
        }
    }
    args
}

fn main() {
    DefaultPool::run_with(async |_| match do_main().await {
        Ok(_) => eprintln!("The operation completed successfully."),
        Err(e) => {
            let exit_code = match e {
                Error::NotEncrypted => ExitCode::ErrorNotEncrypted,
                Error::EmptyFile => ExitCode::ErrorEmpty,
                Error::ZeroSize => ExitCode::ErrorEmpty,
                Error::Vmgs(VmgsError::FileInfoAllocated) => ExitCode::ErrorNotFound,
                Error::V1Format => ExitCode::ErrorV1,
                Error::GspByIdEncryption => ExitCode::ErrorGspById,
                _ => ExitCode::Error,
            };

            eprintln!("EXIT CODE: {} ({:?})", exit_code as i32, exit_code);
            eprintln!("ERROR: {}", e);
            let mut error_source = std::error::Error::source(&e);
            while let Some(e2) = error_source {
                eprintln!("- {}", e2);
                error_source = e2.source();
            }

            std::process::exit(exit_code as i32);
        }
    })
}

async fn do_main() -> Result<(), Error> {
    let opt = Options::parse_from(parse_legacy_args());

    match opt {
        Options::Create {
            file_path,
            file_size,
            key_path,
            encryption_algorithm,
            force_create,
        } => {
            let encryption_alg_key = encryption_algorithm.map(|x| (x, key_path.unwrap()));
            vmgs_file_create(
                file_path.file_path,
                file_size,
                force_create,
                encryption_alg_key,
            )
            .await
        }
        Options::Dump {
            file_path,
            data_path,
            file_id,
            key_path,
            raw_stdout,
        } => {
            vmgs_file_read(
                file_path.file_path,
                data_path,
                file_id.file_id,
                key_path.key_path,
                raw_stdout,
            )
            .await
        }
        Options::Write {
            file_path,
            data_path,
            file_id,
            key_path,
            allow_overwrite,
        } => {
            vmgs_file_write(
                file_path.file_path,
                data_path,
                file_id.file_id,
                key_path.key_path,
                allow_overwrite,
            )
            .await
        }
        Options::DumpHeaders { file_path } => vmgs_file_dump_headers(file_path.file_path).await,
        Options::QuerySize { file_path, file_id } => {
            vmgs_file_query_file_size(file_path.file_path, file_id.file_id).await
        }
        Options::UpdateKey {
            file_path,
            key_path,
            new_key_path,
            encryption_algorithm,
        } => {
            vmgs_file_update_key(
                file_path.file_path,
                encryption_algorithm,
                Some(key_path),
                new_key_path,
            )
            .await
        }
        Options::Encrypt {
            file_path,
            key_path,
            encryption_algorithm,
        } => {
            vmgs_file_update_key(
                file_path.file_path,
                encryption_algorithm,
                None as Option<PathBuf>,
                key_path,
            )
            .await
        }
        Options::QueryEncryption { file_path } => {
            vmgs_file_query_encryption(file_path.file_path).await
        }
        Options::UefiNvram { operation } => uefi_nvram::do_command(operation).await,
    }
}

async fn vmgs_file_update_key(
    file_path: impl AsRef<Path>,
    encryption_alg: EncryptionAlgorithm,
    key_path: Option<impl AsRef<Path>>,
    new_key_path: impl AsRef<Path>,
) -> Result<(), Error> {
    let new_encryption_key = read_key_path(new_key_path)?;
    let mut vmgs = vmgs_file_open(file_path, key_path, OpenMode::ReadWrite, false).await?;

    vmgs_update_key(&mut vmgs, encryption_alg, new_encryption_key.as_ref()).await
}

#[cfg_attr(not(with_encryption), allow(unused_variables))]
async fn vmgs_update_key(
    vmgs: &mut Vmgs,
    encryption_alg: EncryptionAlgorithm,
    new_encryption_key: &[u8],
) -> Result<(), Error> {
    #[cfg(not(with_encryption))]
    unreachable!("encryption requires the encryption feature");
    #[cfg(with_encryption)]
    {
        let old_key_index = vmgs.get_active_datastore_key_index();
        vmgs.add_new_encryption_key(new_encryption_key, encryption_alg)
            .await
            .map_err(Error::EncryptionKey)?;
        if let Some(key_index) = old_key_index {
            vmgs.remove_encryption_key(key_index).await?;
        }

        Ok(())
    }
}

async fn vmgs_file_create(
    path: impl AsRef<Path>,
    file_size: Option<u64>,
    force_create: bool,
    encryption_alg_key: Option<(EncryptionAlgorithm, impl AsRef<Path>)>,
) -> Result<(), Error> {
    let disk = vhdfiledisk_create(path, file_size, force_create)?;

    let encryption_key = encryption_alg_key
        .as_ref()
        .map(|(_, key_path)| read_key_path(key_path))
        .transpose()?;
    let encryption_alg_key =
        encryption_alg_key.map(|(alg, _)| (alg, encryption_key.as_deref().unwrap()));

    let _ = vmgs_create(disk, encryption_alg_key).await?;

    Ok(())
}

fn vhdfiledisk_create(
    path: impl AsRef<Path>,
    req_file_size: Option<u64>,
    force_create: bool,
) -> Result<Disk, Error> {
    const MIN_VMGS_FILE_SIZE: u64 = 4 * VMGS_BYTES_PER_BLOCK as u64;
    const SECTOR_SIZE: u64 = 512;

    let file_size = req_file_size.unwrap_or(VMGS_DEFAULT_CAPACITY);
    if file_size < MIN_VMGS_FILE_SIZE || file_size % SECTOR_SIZE != 0 {
        return Err(Error::InvalidVmgsFileSize(
            file_size,
            format!(
                "Must be a multiple of {} and at least {}",
                SECTOR_SIZE, MIN_VMGS_FILE_SIZE
            ),
        ));
    }

    if force_create && Path::new(path.as_ref()).exists() {
        eprintln!(
            "File already exists. Recreating the file {:?}",
            path.as_ref()
        );
    }

    eprintln!("Creating file: {}", path.as_ref().display());
    let file = match fs_err::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .create_new(!force_create)
        .truncate(true)
        .open(path.as_ref())
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::FileExists);
        }
        Err(err) => return Err(Error::VmgsFile(err)),
    };

    eprintln!(
        "Setting file size to {}{}",
        file_size,
        if req_file_size.is_some() {
            ""
        } else {
            " (default)"
        }
    );
    file.set_len(file_size).map_err(Error::VmgsFile)?;

    eprintln!("Formatting VHD");
    Vhd1Disk::make_fixed(file.file()).map_err(Error::Vhd1)?;
    let disk = Vhd1Disk::open_fixed(file.into(), false).map_err(Error::Vhd1)?;
    Disk::new(disk).map_err(Error::InvalidDisk)
}

#[cfg_attr(not(with_encryption), allow(unused_mut), allow(unused_variables))]
async fn vmgs_create(
    disk: Disk,
    encryption_alg_key: Option<(EncryptionAlgorithm, &[u8])>,
) -> Result<Vmgs, Error> {
    eprintln!("Formatting VMGS");
    let mut vmgs = Vmgs::format_new(disk).await?;

    if let Some((algorithm, encryption_key)) = encryption_alg_key {
        #[cfg(with_encryption)]
        let _key_index = vmgs
            .add_new_encryption_key(encryption_key, algorithm)
            .await
            .map_err(Error::EncryptionKey)?;
        #[cfg(not(with_encryption))]
        unreachable!("Encryption requires the encryption feature");
    }

    Ok(vmgs)
}

async fn vmgs_file_write(
    file_path: impl AsRef<Path>,
    data_path: impl AsRef<Path>,
    file_id: FileId,
    key_path: Option<impl AsRef<Path>>,
    allow_overwrite: bool,
) -> Result<(), Error> {
    eprintln!(
        "Opening source (raw data file): {}",
        data_path.as_ref().display()
    );

    let mut file = File::open(data_path.as_ref()).map_err(Error::DataFile)?;
    let mut buf = Vec::new();

    // manually allow, since we want to differentiate between the file not being
    // accessible, and a read operation failing
    file.read_to_end(&mut buf).map_err(Error::DataFile)?;

    eprintln!("Read {} bytes", buf.len());

    let encrypt = key_path.is_some();
    let mut vmgs = vmgs_file_open(file_path, key_path, OpenMode::ReadWrite, false).await?;

    vmgs_write(&mut vmgs, file_id, &buf, encrypt, allow_overwrite).await?;

    Ok(())
}

async fn vmgs_write(
    vmgs: &mut Vmgs,
    file_id: FileId,
    data: &[u8],
    encrypt: bool,
    allow_overwrite: bool,
) -> Result<(), Error> {
    eprintln!("Writing File ID {} ({:?})", file_id.0, file_id);

    if !allow_overwrite {
        if let Ok(info) = vmgs.get_file_info(file_id) {
            if info.valid_bytes > 0 {
                return Err(Error::FileIdExists(file_id));
            }
        }
    }

    if encrypt {
        #[cfg(with_encryption)]
        vmgs.write_file_encrypted(file_id, data).await?;
        #[cfg(not(with_encryption))]
        unreachable!("Encryption requires the encryption feature");
    } else {
        vmgs.write_file_allow_overwrite_encrypted(file_id, data)
            .await?;
    }

    Ok(())
}

/// Get data from VMGS file, and write to `data_path`.
async fn vmgs_file_read(
    file_path: impl AsRef<Path>,
    data_path: Option<impl AsRef<Path>>,
    file_id: FileId,
    key_path: Option<impl AsRef<Path>>,
    raw_stdout: bool,
) -> Result<(), Error> {
    let decrypt = key_path.is_some();
    let mut vmgs = vmgs_file_open(file_path, key_path, OpenMode::ReadOnly, true).await?;

    let buf = vmgs_read(&mut vmgs, file_id, decrypt).await?;

    eprintln!("Read {} bytes", buf.len());
    let data_size = vmgs.get_file_info(file_id)?.valid_bytes as usize;
    if buf.len() != data_size {
        eprintln!("Warning: Bytes read from VMGS doesn't match file info");
    }

    if let Some(path) = data_path {
        eprintln!("Writing contents to {}", path.as_ref().display());
        let mut file = File::create(path.as_ref()).map_err(Error::DataFile)?;
        file.write_all(&buf).map_err(Error::DataFile)?;
    } else {
        eprintln!("Writing contents to stdout");
        if raw_stdout {
            let mut stdout = std::io::stdout();
            stdout.write_all(&buf).map_err(Error::DataFile)?;
        } else {
            for c in buf.chunks(16) {
                for b in c {
                    print!("0x{:02x},", b);
                }
                println!(
                    "{:missing$}// {}",
                    ' ',
                    c.iter()
                        .map(|c| if c.is_ascii_graphic() {
                            *c as char
                        } else {
                            '.'
                        })
                        .collect::<String>(),
                    missing = (16 - c.len()) * 5 + 1
                );
            }
        }
    }

    Ok(())
}

async fn vmgs_read(vmgs: &mut Vmgs, file_id: FileId, decrypt: bool) -> Result<Vec<u8>, Error> {
    eprintln!("Reading File ID {} ({:?})", file_id.0, file_id);
    Ok(if decrypt {
        vmgs.read_file(file_id).await?
    } else {
        vmgs.read_file_raw(file_id).await?
    })
}

async fn vmgs_file_dump_headers(file_path: impl AsRef<Path>) -> Result<(), Error> {
    let file = File::open(file_path.as_ref()).map_err(Error::VmgsFile)?;
    let validate_result = vmgs_file_validate(&file);
    let disk = Disk::new(Vhd1Disk::open_fixed(file.into(), true).map_err(Error::Vhd1)?)
        .map_err(Error::InvalidDisk)?;

    let headers_result = match read_headers(disk).await {
        Ok((header1, header2)) => vmgs_dump_headers(&header1, &header2),
        Err(e) => Err(e.into()),
    };

    if validate_result.is_err() {
        validate_result
    } else {
        headers_result
    }
}

fn vmgs_dump_headers(header1: &VmgsHeader, header2: &VmgsHeader) -> Result<(), Error> {
    println!("FILE HEADERS");
    println!("{0:<23} {1:^70} {2:^70}", "Field", "Header 1", "Header 2");
    println!("{} {} {}", "-".repeat(23), "-".repeat(70), "-".repeat(70));

    let signature1 = format!("{:#018x}", header1.signature);
    let signature2 = format!("{:#018x}", header2.signature);
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "Signature:", signature1, signature2
    );

    println!(
        "{0:<23} {1:>70} {2:>70}",
        "Version:",
        extract_version(header1.version),
        extract_version(header2.version)
    );
    println!(
        "{0:<23} {1:>70x} {2:>70x}",
        "Checksum:", header1.checksum, header2.checksum
    );
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "Sequence:", header1.sequence, header2.sequence
    );
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "HeaderSize:", header1.header_size, header2.header_size
    );

    let file_table_offset1 = format!("{:#010x}", header1.file_table_offset);
    let file_table_offset2 = format!("{:#010x}", header2.file_table_offset);
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "FileTableOffset:", file_table_offset1, file_table_offset2
    );

    println!(
        "{0:<23} {1:>70} {2:>70}",
        "FileTableSize:", header1.file_table_size, header2.file_table_size
    );

    let encryption_algorithm1 = format!("{:#06x}", header1.encryption_algorithm.0);
    let encryption_algorithm2 = format!("{:#06x}", header2.encryption_algorithm.0);
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "EncryptionAlgorithm:", encryption_algorithm1, encryption_algorithm2
    );

    let reserved1 = format!("{:#06x}", header1.reserved);
    let reserved2 = format!("{:#06x}", header2.reserved);

    println!("{0:<23} {1:>70} {2:>70}", "Reserved:", reserved1, reserved2);

    println!("{0:<23}", "MetadataKey1:");

    let key1_nonce = format!("0x{}", hex::encode(header1.metadata_keys[0].nonce));
    let key2_nonce = format!("0x{}", hex::encode(header2.metadata_keys[0].nonce));
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "Nonce:", key1_nonce, key2_nonce
    );

    let key1_reserved = format!("{:#010x}", header1.metadata_keys[0].reserved);
    let key2_reserved = format!("{:#010x}", header2.metadata_keys[0].reserved);
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "Reserved:", key1_reserved, key2_reserved
    );

    let key1_auth_tag = format!(
        "0x{}",
        hex::encode(header1.metadata_keys[0].authentication_tag)
    );
    let key2_auth_tag = format!(
        "0x{}",
        hex::encode(header2.metadata_keys[0].authentication_tag)
    );
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "AuthenticationTag:", key1_auth_tag, key2_auth_tag
    );

    let key1_encryption_key = format!("0x{}", hex::encode(header1.metadata_keys[0].encryption_key));
    let key2_encryption_key = format!("0x{}", hex::encode(header2.metadata_keys[0].encryption_key));
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "EncryptionKey:", key1_encryption_key, key2_encryption_key
    );

    println!("{0:<23}", "MetadataKey2:");
    let key1_nonce = format!("0x{}", hex::encode(header1.metadata_keys[1].nonce));
    let key2_nonce = format!("0x{}", hex::encode(header2.metadata_keys[1].nonce));
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "Nonce:", key1_nonce, key2_nonce
    );

    let key1_reserved = format!("0x{:#010x}", header1.metadata_keys[1].reserved);
    let key2_reserved = format!("0x{:#010x}", header2.metadata_keys[1].reserved);
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "Reserved:", key1_reserved, key2_reserved
    );

    let key1_auth_tag = format!(
        "0x{}",
        hex::encode(header1.metadata_keys[1].authentication_tag)
    );
    let key2_auth_tag = format!(
        "0x{}",
        hex::encode(header2.metadata_keys[1].authentication_tag)
    );
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "AuthenticationTag:", key1_auth_tag, key2_auth_tag
    );

    let key1_encryption_key = format!("0x{}", hex::encode(header1.metadata_keys[1].encryption_key));
    let key2_encryption_key = format!("0x{}", hex::encode(header2.metadata_keys[1].encryption_key));
    println!(
        "    {0:<19} {1:>70} {2:>70}",
        "EncryptionKey:", key1_encryption_key, key2_encryption_key
    );

    let key1_reserved1 = format!("0x{:#010x}", header1.reserved_1);
    let key2_reserved1 = format!("0x{:#010x}", header2.reserved_1);
    println!(
        "{0:<23} {1:>70} {2:>70}",
        "Reserved:", key1_reserved1, key2_reserved1
    );

    println!("{} {} {}\n", "-".repeat(23), "-".repeat(70), "-".repeat(70));

    print!("Verifying header 1... ");
    let header1_result = validate_header(header1);
    match &header1_result {
        Ok(_) => println!("[VALID]"),
        Err(e) => println!("[INVALID] Error: {}", e),
    }

    print!("Verifying header 2... ");
    let header2_result = validate_header(header2);
    match &header2_result {
        Ok(_) => println!("[VALID]"),
        Err(e) => println!("[INVALID] Error: {}", e),
    }

    match get_active_header(header1_result, header2_result) {
        Ok(active_index) => match active_index {
            0 => println!("Active header is 1"),
            1 => println!("Active header is 2"),
            _ => unreachable!(),
        },
        Err(e) => {
            println!("Unable to determine active header");
            return Err(Error::Vmgs(e));
        }
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OpenMode {
    ReadOnly,
    ReadWrite,
}

async fn vmgs_file_open(
    file_path: impl AsRef<Path>,
    key_path: Option<impl AsRef<Path>>,
    open_mode: OpenMode,
    encrypted_no_key_ok: bool,
) -> Result<Vmgs, Error> {
    eprintln!("Opening VMGS File: {}", file_path.as_ref().display());
    let file = fs_err::OpenOptions::new()
        .read(true)
        .write(open_mode == OpenMode::ReadWrite)
        .open(file_path.as_ref())
        .map_err(Error::VmgsFile)?;

    vmgs_file_validate(&file)?;

    let disk = Disk::new(
        Vhd1Disk::open_fixed(file.into(), open_mode == OpenMode::ReadOnly).map_err(Error::Vhd1)?,
    )
    .map_err(Error::InvalidDisk)?;
    let encryption_key = key_path.map(read_key_path).transpose()?;

    let res = vmgs_open(disk, encryption_key.as_deref(), encrypted_no_key_ok).await;

    if matches!(
        res,
        Err(Error::Vmgs(VmgsError::InvalidFormat(_)))
            | Err(Error::Vmgs(VmgsError::CorruptFormat(_)))
    ) {
        eprintln!("VMGS is corrupted or invalid. Dumping headers.");
        let _ = vmgs_file_dump_headers(file_path.as_ref()).await;
    }

    res
}

#[cfg_attr(not(with_encryption), allow(unused_mut), allow(unused_variables))]
async fn vmgs_open(
    disk: Disk,
    encryption_key: Option<&[u8]>,
    encrypted_no_key_ok: bool,
) -> Result<Vmgs, Error> {
    let mut vmgs: Vmgs = Vmgs::open(disk).await?;

    if let Some(encryption_key) = encryption_key {
        #[cfg(with_encryption)]
        if vmgs.is_encrypted() {
            let _key_index = vmgs.unlock_with_encryption_key(encryption_key).await?;
        } else {
            return Err(Error::NotEncrypted);
        }
        #[cfg(not(with_encryption))]
        unreachable!("Encryption requires the encryption feature");
    } else if vmgs.is_encrypted() {
        if encrypted_no_key_ok {
            eprintln!("Warning: Opening encrypted file without decrypting");
        } else {
            return Err(Error::AlreadyEncrypted);
        }
    }

    Ok(vmgs)
}

fn read_key_path(path: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    eprintln!("Reading encryption key: {}", path.as_ref().display());
    let metadata = fs_err::metadata(&path).map_err(Error::KeyFile)?;
    if metadata.len() != VMGS_ENCRYPTION_KEY_SIZE as u64 {
        return Err(Error::InvalidKeySize(
            VMGS_ENCRYPTION_KEY_SIZE as u64,
            metadata.len(),
        ));
    }

    let bytes = fs_err::read(&path).map_err(Error::KeyFile)?;
    if bytes.len() != metadata.len() as usize {
        return Err(Error::InvalidKeySize(
            VMGS_ENCRYPTION_KEY_SIZE as u64,
            bytes.len() as u64,
        ));
    }

    Ok(bytes)
}

async fn vmgs_file_query_file_size(
    file_path: impl AsRef<Path>,
    file_id: FileId,
) -> Result<(), Error> {
    let vmgs = vmgs_file_open(file_path, None as Option<PathBuf>, OpenMode::ReadOnly, true).await?;

    let file_size = vmgs_query_file_size(&vmgs, file_id)?;

    println!(
        "File ID {} ({:?}) has a size of {}",
        file_id.0, file_id, file_size
    );

    Ok(())
}

fn vmgs_query_file_size(vmgs: &Vmgs, file_id: FileId) -> Result<u64, Error> {
    Ok(vmgs.get_file_info(file_id)?.valid_bytes)
}

async fn vmgs_file_query_encryption(file_path: impl AsRef<Path>) -> Result<(), Error> {
    print!("{} is ", file_path.as_ref().display());

    let vmgs = vmgs_file_open(file_path, None as Option<PathBuf>, OpenMode::ReadOnly, true).await?;

    match (
        vmgs.get_encryption_algorithm(),
        vmgs_get_encryption_scheme(&vmgs),
    ) {
        (EncryptionAlgorithm::NONE, VmgsEncryptionScheme::None) => {
            println!("not encrypted");
            // Returning an error for HA to easily parse
            Err(Error::NotEncrypted)
        }
        (EncryptionAlgorithm::AES_GCM, VmgsEncryptionScheme::GspKey) => {
            println!("encrypted with AES GCM encryption algorithm using GspKey");
            Ok(())
        }
        (EncryptionAlgorithm::AES_GCM, VmgsEncryptionScheme::GspById) => {
            println!("encrypted with AES GCM encryption algorithm using GspById");
            Err(Error::GspByIdEncryption)
        }
        (alg, scheme) => {
            unreachable!("Invalid encryption algorithm ({alg:?}) / scheme ({scheme:?})");
        }
    }
}

fn vmgs_get_encryption_scheme(vmgs: &Vmgs) -> VmgsEncryptionScheme {
    if vmgs_query_file_size(vmgs, FileId::KEY_PROTECTOR).is_ok() {
        VmgsEncryptionScheme::GspKey
    } else if vmgs_query_file_size(vmgs, FileId::VM_UNIQUE_ID).is_ok() {
        VmgsEncryptionScheme::GspById
    } else {
        VmgsEncryptionScheme::None
    }
}

fn vmgs_file_validate(file: &File) -> Result<(), Error> {
    vmgs_file_validate_not_empty(file)?;
    vmgs_file_validate_not_v1(file)?;
    Ok(())
}

/// Validate if the VMGS file is empty. This is a special case for Azure and
/// we want to return an error code (ERROR_EMPTY) instead of ERROR_FILE_CORRUPT.
/// A file can be empty in the following 2 cases:
///     1) the size is zero
///     2) the size is non-zero but there is no content inside the file except the footer.
fn vmgs_file_validate_not_empty(mut file: &File) -> Result<(), Error> {
    const VHD_DISK_FOOTER_PACKED_SIZE: u64 = 512;
    const MAX_VMGS_FILE_SIZE: u64 = 4 * ONE_GIGA_BYTE;

    let file_size = file.metadata().map_err(Error::VmgsFile)?.len();

    if file_size > MAX_VMGS_FILE_SIZE {
        return Err(Error::InvalidVmgsFileSize(
            file_size,
            format!("Must be less than {}", MAX_VMGS_FILE_SIZE),
        ));
    }

    if file_size == 0 {
        return Err(Error::ZeroSize);
    }

    // Special case - check that the file has a non zero size but the contents are empty
    // except for the file footer which is ignored.
    // This is to differentiate between a file without any content for an Azure scenario.
    // The VMGS file received by the HostAgent team from DiskRP contains a footer that
    // should be ignored during the empty file comparison.
    if file_size < VHD_DISK_FOOTER_PACKED_SIZE {
        return Err(Error::InvalidVmgsFileSize(
            file_size,
            format!("Must be greater than {}", VHD_DISK_FOOTER_PACKED_SIZE),
        ));
    }

    let bytes_to_compare = file_size - VHD_DISK_FOOTER_PACKED_SIZE;
    let mut bytes_read = 0;
    let mut empty_file = true;
    let mut buf = vec![0; 32 * ONE_MEGA_BYTE as usize];

    // Fragment reads to 32 MB when checking that file contents are 0
    while bytes_read < bytes_to_compare {
        let bytes_to_read =
            std::cmp::min(32 * ONE_MEGA_BYTE, bytes_to_compare - bytes_read) as usize;

        file.read(&mut buf[..bytes_to_read])
            .map_err(Error::VmgsFile)?;

        if !buf[..bytes_to_read].iter().all(|&x| x == 0) {
            empty_file = false;
            break;
        }

        bytes_read += buf.len() as u64;
    }

    if empty_file {
        return Err(Error::EmptyFile);
    }

    Ok(())
}

/// Validate that this is not a VMGSv1 file
fn vmgs_file_validate_not_v1(mut file: &File) -> Result<(), Error> {
    const EFI_SIGNATURE: &[u8] = b"EFI PART";
    let mut maybe_efi_signature = [0; EFI_SIGNATURE.len()];
    file.seek(std::io::SeekFrom::Start(512))
        .map_err(Error::VmgsFile)?;
    file.read(&mut maybe_efi_signature)
        .map_err(Error::VmgsFile)?;
    if maybe_efi_signature == EFI_SIGNATURE {
        return Err(Error::V1Format);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::async_test;
    use tempfile::tempdir;

    async fn test_vmgs_create(
        path: impl AsRef<Path>,
        file_size: Option<u64>,
        force_create: bool,
        encryption_alg_key: Option<(EncryptionAlgorithm, &[u8])>,
    ) -> Result<(), Error> {
        let disk = vhdfiledisk_create(path, file_size, force_create)?;
        let _ = vmgs_create(disk, encryption_alg_key).await?;
        Ok(())
    }

    async fn test_vmgs_open(
        path: impl AsRef<Path>,
        open_mode: OpenMode,
        encryption_key: Option<&[u8]>,
        encrypted_no_key_ok: bool,
    ) -> Result<Vmgs, Error> {
        let file = fs_err::OpenOptions::new()
            .read(true)
            .write(open_mode == OpenMode::ReadWrite)
            .open(path.as_ref())
            .map_err(Error::VmgsFile)?;
        vmgs_file_validate(&file)?;
        let disk = Disk::new(
            Vhd1Disk::open_fixed(file.into(), open_mode == OpenMode::ReadOnly)
                .map_err(Error::Vhd1)?,
        )
        .unwrap();
        let vmgs = vmgs_open(disk, encryption_key, encrypted_no_key_ok).await?;
        Ok(vmgs)
    }

    async fn test_vmgs_query_file_size(
        file_path: impl AsRef<Path>,
        file_id: FileId,
    ) -> Result<u64, Error> {
        let vmgs =
            vmgs_file_open(file_path, None as Option<PathBuf>, OpenMode::ReadOnly, true).await?;

        vmgs_query_file_size(&vmgs, file_id)
    }

    #[cfg(with_encryption)]
    async fn test_vmgs_query_encryption(
        file_path: impl AsRef<Path>,
    ) -> Result<EncryptionAlgorithm, Error> {
        let vmgs =
            vmgs_file_open(file_path, None as Option<PathBuf>, OpenMode::ReadOnly, true).await?;

        Ok(vmgs.get_encryption_algorithm())
    }

    #[cfg(with_encryption)]
    async fn test_vmgs_update_key(
        file_path: impl AsRef<Path>,
        encryption_alg: EncryptionAlgorithm,
        encryption_key: Option<&[u8]>,
        new_encryption_key: &[u8],
    ) -> Result<(), Error> {
        let mut vmgs =
            test_vmgs_open(file_path, OpenMode::ReadWrite, encryption_key, false).await?;

        vmgs_update_key(&mut vmgs, encryption_alg, new_encryption_key).await
    }

    // Create a new test file path.
    fn new_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.vmgs");
        (dir, file_path)
    }

    #[async_test]
    async fn read_invalid_file() {
        let (_dir, path) = new_path();

        let result = test_vmgs_open(path, OpenMode::ReadOnly, None, false).await;

        assert!(result.is_err());
    }

    #[async_test]
    async fn read_empty_file() {
        let (_dir, path) = new_path();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let mut vmgs = test_vmgs_open(path, OpenMode::ReadOnly, None, false)
            .await
            .unwrap();
        let result = vmgs_read(&mut vmgs, FileId::FILE_TABLE, false).await;
        assert!(result.is_err());
    }

    #[async_test]
    async fn read_write_file() {
        let (_dir, path) = new_path();
        let buf = b"Plain text data".to_vec();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let mut vmgs = test_vmgs_open(path, OpenMode::ReadWrite, None, false)
            .await
            .unwrap();

        vmgs_write(&mut vmgs, FileId::ATTEST, &buf, false, false)
            .await
            .unwrap();
        let read_buf = vmgs_read(&mut vmgs, FileId::ATTEST, false).await.unwrap();

        assert_eq!(buf, read_buf);
    }

    #[async_test]
    async fn multiple_write_file() {
        let (_dir, path) = new_path();
        let buf_1 = b"Random super sensitive data".to_vec();
        let buf_2 = b"Other super secret data".to_vec();
        let buf_3 = b"I'm storing so much data".to_vec();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let mut vmgs = test_vmgs_open(path, OpenMode::ReadWrite, None, false)
            .await
            .unwrap();

        vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_1, false, false)
            .await
            .unwrap();
        let read_buf_1 = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, false)
            .await
            .unwrap();

        assert_eq!(buf_1, read_buf_1);

        vmgs_write(&mut vmgs, FileId::TPM_PPI, &buf_2, false, false)
            .await
            .unwrap();
        let read_buf_2 = vmgs_read(&mut vmgs, FileId::TPM_PPI, false).await.unwrap();

        assert_eq!(buf_2, read_buf_2);

        let result = vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_3, false, false).await;
        assert!(result.is_err());

        vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_3, false, true)
            .await
            .unwrap();
        let read_buf_3 = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, false)
            .await
            .unwrap();

        assert_eq!(buf_2, read_buf_2);
        assert_eq!(buf_3, read_buf_3);
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn read_write_encrypted_file() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];
        let buf_1 = b"123".to_vec();

        test_vmgs_create(
            &path,
            None,
            false,
            Some((EncryptionAlgorithm::AES_GCM, &encryption_key)),
        )
        .await
        .unwrap();

        let mut vmgs = test_vmgs_open(path, OpenMode::ReadWrite, Some(&encryption_key), false)
            .await
            .unwrap();

        vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_1, true, false)
            .await
            .unwrap();
        let read_buf = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, true)
            .await
            .unwrap();

        assert!(read_buf == buf_1);

        // try to normal write encrypted VMGs
        vmgs_write(&mut vmgs, FileId::TPM_PPI, &buf_1, false, false)
            .await
            .unwrap();

        // try to normal read encrypted FileId
        let _encrypted_read = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, false)
            .await
            .unwrap();
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn encrypted_read_write_plain_file() {
        // You shouldn't be able to use encryption if you create the VMGS
        // file without encryption.
        let (_dir, path) = new_path();
        let encryption_key = vec![5; VMGS_ENCRYPTION_KEY_SIZE];

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let result = test_vmgs_open(path, OpenMode::ReadWrite, Some(&encryption_key), false).await;

        assert!(result.is_err());
    }

    #[async_test]
    async fn query_size() {
        let (_dir, path) = new_path();
        let buf = b"Plain text data".to_vec();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        {
            let mut vmgs = test_vmgs_open(&path, OpenMode::ReadWrite, None, false)
                .await
                .unwrap();

            vmgs_write(&mut vmgs, FileId::ATTEST, &buf, false, false)
                .await
                .unwrap();
        }

        let file_size = test_vmgs_query_file_size(&path, FileId::ATTEST)
            .await
            .unwrap();
        assert_eq!(file_size, buf.len() as u64);
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn query_encrypted_file() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];
        let buf_1 = b"123".to_vec();

        test_vmgs_create(
            &path,
            None,
            false,
            Some((EncryptionAlgorithm::AES_GCM, &encryption_key)),
        )
        .await
        .unwrap();

        {
            let mut vmgs = test_vmgs_open(&path, OpenMode::ReadWrite, Some(&encryption_key), false)
                .await
                .unwrap();

            vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_1, true, false)
                .await
                .unwrap();
        }

        let file_size = test_vmgs_query_file_size(&path, FileId::BIOS_NVRAM)
            .await
            .unwrap();
        assert_eq!(file_size, buf_1.len() as u64);
    }

    #[async_test]
    async fn test_validate_vmgs_file_not_empty() {
        let buf: Vec<u8> = (0..255).collect();
        let (_dir, path) = new_path();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let mut file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        let result = vmgs_file_validate_not_empty(&file);
        matches!(result, Err(Error::ZeroSize));

        file.seek(std::io::SeekFrom::Start(1024)).unwrap();
        file.write_all(&buf).unwrap();
        let result = vmgs_file_validate_not_empty(&file);
        matches!(result, Err(Error::VmgsFile(_)));
    }

    #[async_test]
    async fn test_misaligned_size() {
        let (_dir, path) = new_path();
        //File size must be % 512 to be valid, should produce error and file should not be created
        let result = test_vmgs_create(&path, Some(65537), false, None).await;
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[async_test]
    async fn test_forcecreate() {
        let (_dir, path) = new_path();
        let result = test_vmgs_create(&path, Some(4194304), false, None).await;
        assert!(result.is_ok());
        // Recreating file should fail without force create flag
        let result = test_vmgs_create(&path, Some(4194304), false, None).await;
        assert!(result.is_err());
        // Should be able to resize the file when force create is passed in
        let result = test_vmgs_create(&path, Some(8388608), true, None).await;
        assert!(result.is_ok());
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn test_update_encryption_key() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];
        let new_encryption_key = vec![6; 32];
        let buf_1 = b"123".to_vec();

        test_vmgs_create(
            &path,
            None,
            false,
            Some((EncryptionAlgorithm::AES_GCM, &encryption_key)),
        )
        .await
        .unwrap();

        {
            let mut vmgs = test_vmgs_open(&path, OpenMode::ReadWrite, Some(&encryption_key), false)
                .await
                .unwrap();

            vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_1, true, false)
                .await
                .unwrap();
        }

        test_vmgs_update_key(
            &path,
            EncryptionAlgorithm::AES_GCM,
            Some(&encryption_key),
            &new_encryption_key,
        )
        .await
        .unwrap();

        {
            let mut vmgs =
                test_vmgs_open(&path, OpenMode::ReadOnly, Some(&new_encryption_key), false)
                    .await
                    .unwrap();

            let read_buf = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, true)
                .await
                .unwrap();
            assert!(read_buf == buf_1);
        }

        // Old key should no longer work
        let result = test_vmgs_open(&path, OpenMode::ReadOnly, Some(&encryption_key), false).await;
        assert!(result.is_err());
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn test_add_encryption_key() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];
        let buf_1 = b"123".to_vec();

        test_vmgs_create(&path, None, false, None).await.unwrap();

        test_vmgs_update_key(&path, EncryptionAlgorithm::AES_GCM, None, &encryption_key)
            .await
            .unwrap();

        let mut vmgs = test_vmgs_open(&path, OpenMode::ReadWrite, Some(&encryption_key), false)
            .await
            .unwrap();

        vmgs_write(&mut vmgs, FileId::BIOS_NVRAM, &buf_1, true, false)
            .await
            .unwrap();

        let read_buf = vmgs_read(&mut vmgs, FileId::BIOS_NVRAM, true)
            .await
            .unwrap();

        assert!(read_buf == buf_1);
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn test_query_encryption_update() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];

        test_vmgs_create(&path, None, false, None).await.unwrap();

        let encryption_algorithm = test_vmgs_query_encryption(&path).await.unwrap();
        assert_eq!(encryption_algorithm, EncryptionAlgorithm::NONE);

        test_vmgs_update_key(&path, EncryptionAlgorithm::AES_GCM, None, &encryption_key)
            .await
            .unwrap();

        let encryption_algorithm = test_vmgs_query_encryption(&path).await.unwrap();
        assert_eq!(encryption_algorithm, EncryptionAlgorithm::AES_GCM);
    }

    #[cfg(with_encryption)]
    #[async_test]
    async fn test_query_encryption_new() {
        let (_dir, path) = new_path();
        let encryption_key = vec![5; 32];

        test_vmgs_create(
            &path,
            None,
            false,
            Some((EncryptionAlgorithm::AES_GCM, &encryption_key)),
        )
        .await
        .unwrap();

        let encryption_algorithm = test_vmgs_query_encryption(&path).await.unwrap();
        assert_eq!(encryption_algorithm, EncryptionAlgorithm::AES_GCM);
    }
}
