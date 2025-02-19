// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::symlink;
use super::util;
use super::VolumeState;
use ::windows::Wdk::Storage::FileSystem;
use ::windows::Wdk::System::SystemServices;
use ::windows::Win32::Foundation;
use ::windows::Win32::Storage::FileSystem as W32Fs;
use ::windows::Win32::System::Ioctl;
use ::windows::Win32::System::SystemServices as W32Ss;
use bitfield_struct::bitfield;
use headervec::HeaderVec;
use pal::windows::UnicodeString;
use std::marker::PhantomData;
use std::mem::offset_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use windows::Win32::System;

const LX_UTIL_DEFAULT_PERMISSIONS: u32 = 0o777;

const LX_UTIL_FS_DIR_WRITE_ACCESS: u32 =
    W32Fs::FILE_ADD_FILE.0 | W32Fs::FILE_ADD_SUBDIRECTORY.0 | W32Fs::FILE_DELETE_CHILD.0;

const LX_UTIL_FS_CALLER_HAS_TRAVERSE_PRIVILEGE: u32 = 0x1;

const LX_UTIL_FS_ALLOCATION_BLOCK_SIZE: u64 = 512;

const LX_UTIL_FS_NAME_LENGTH: usize = 16;

pub const LX_DRVFS_DISABLE_NONE: u32 = 0;
pub const LX_DRVFS_DISABLE_QUERY_BY_NAME_AND_STAT_INFO: u32 = 2;

const REPARSE_DATA_BUFFER_HEADER_SIZE: usize = 8;

const LX_PATH_MAX: u16 = 4096;

const LX_UTIL_SYMLINK_DATA_VERSION_1: u32 = 1;
const LX_UTIL_SYMLINK_DATA_VERSION_2: u32 = 2;

const LX_UTIL_SYMLINK_TARGET_OFFSET: u32 = offset_of!(SymlinkData, target) as u32;
const LX_UTIL_SYMLINK_REPARSE_BASE_SIZE: u32 =
    REPARSE_DATA_BUFFER_HEADER_SIZE as u32 + LX_UTIL_SYMLINK_TARGET_OFFSET;

#[repr(C)]
#[derive(Clone, Copy)]
struct SymlinkData {
    version: u32,
    // 12 bytes to make this struct the same size as REPARSE_DATA_BUFFER
    target: [u8; 12],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SymlinkReparseData {
    buffer: [u8; REPARSE_DATA_BUFFER_HEADER_SIZE],
    symlink: SymlinkData,
}

#[repr(C)]
#[derive(Clone, Copy)]
union SymlinkReparse {
    pub header: FileSystem::REPARSE_DATA_BUFFER,
    pub data: SymlinkReparseData,
}

impl SymlinkReparse {
    fn default() -> SymlinkReparse {
        SymlinkReparse {
            header: FileSystem::REPARSE_DATA_BUFFER::default(),
        }
    }
}

#[bitfield(u32)]
pub struct FsCompatibilityFlags {
    pub supports_query_by_name: bool,
    pub supports_stat_info: bool,
    pub supports_stable_file_id: bool,
    pub supports_case_sensitive_search: bool,
    pub supports_reparse_points: bool,
    pub supports_hard_links: bool,
    pub supports_permission_mapping: bool,
    pub supports_posix_unlink_rename: bool,
    pub custom_fallback_mode: bool,
    pub server_reparse_points: bool,
    pub asynchronous_mode: bool,
    pub supports_stat_lx_info: bool,
    pub supports_metadata: bool,
    pub supports_case_sensitive_dir: bool,
    pub supports_xattr: bool,
    pub supports_ignore_read_only_disposition: bool,
    #[bits(16)]
    _reserved: u16,
}

pub struct FsContext {
    pub compatibility_flags: FsCompatibilityFlags,
    _phantom: PhantomData<()>, // Prevent manual construction
}

impl FsContext {
    /// Initialize an FsContext. The compatibility flags will be set based on the
    /// capabilities of the filesystem.
    pub fn new(
        file_handle: &OwnedHandle,
        fallback_mode: u32,
        async_mode: bool,
    ) -> lx::Result<Self> {
        // Get the filesystem attributes
        let mut iosb = Default::default();
        let mut fs_attributes: HeaderVec<FileSystem::FILE_FS_ATTRIBUTE_INFORMATION, u16, 1> =
            HeaderVec::with_capacity(Default::default(), LX_UTIL_FS_NAME_LENGTH);
        let mut device_info = SystemServices::FILE_FS_DEVICE_INFORMATION::default();

        // SAFETY: Calling Win32 API as documented
        unsafe {
            let _ = util::check_status(FileSystem::NtQueryVolumeInformationFile(
                Foundation::HANDLE(file_handle.as_raw_handle()),
                &mut iosb,
                fs_attributes.as_mut_ptr().cast(),
                fs_attributes.total_byte_capacity() as _,
                FileSystem::FileFsAttributeInformation,
            ))?;
            let _ = util::check_status(FileSystem::NtQueryVolumeInformationFile(
                Foundation::HANDLE(file_handle.as_raw_handle()),
                &mut iosb,
                (std::ptr::from_mut::<SystemServices::FILE_FS_DEVICE_INFORMATION>(
                    &mut device_info,
                ))
                .cast(),
                size_of::<SystemServices::FILE_FS_DEVICE_INFORMATION>() as _,
                FileSystem::FileFsDeviceInformation,
            ))?;
        };

        let is_remote = device_info.Characteristics & SystemServices::FILE_REMOTE_DEVICE != 0;
        let attr = fs_attributes.head.FileSystemAttributes;

        // SMB does not properly support POSIX unlink/rename.
        let supports_posix_rename =
            attr & W32Ss::FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0 && !is_remote;

        let mut flags = FsCompatibilityFlags::new()
            .with_supports_stable_file_id(attr & W32Ss::FILE_SUPPORTS_OPEN_BY_FILE_ID != 0)
            .with_supports_posix_unlink_rename(supports_posix_rename)
            .with_supports_ignore_read_only_disposition(supports_posix_rename)
            // SMB does not properly support case sensitivity.
            .with_supports_case_sensitive_search(
                attr & W32Ss::FILE_CASE_SENSITIVE_SEARCH != 0 && !is_remote,
            )
            // SMB claims it supports reparse points, but it's only partial support.
            // It appears it only allows NT symlinks to be created (which can then not
            // be followed due to security restrictions); arbitrary reparse points
            // do not work. Therefore, treat SMB as if it doesn't support reparse
            // points.
            .with_supports_reparse_points(
                attr & W32Ss::FILE_SUPPORTS_REPARSE_POINTS != 0 && !is_remote,
            )
            .with_supports_hard_links(attr & W32Ss::FILE_SUPPORTS_HARD_LINKS != 0)
            // On network file systems, permission mapping may not work correctly. If
            // the share is being accessed with different credentials than the logged
            // on user, this would still use the logged on credentials to determine
            // effective access. This leads to incorrect permission bits, which can
            // cause the VFS permission checks to deny access incorrectly. Samba on
            // Linux also returns fake ACLs which break permission mapping.
            .with_supports_permission_mapping(!is_remote)
            .with_server_reparse_points(is_remote)
            .with_asynchronous_mode(async_mode)
            .with_supports_xattr(attr & W32Ss::FILE_SUPPORTS_EXTENDED_ATTRIBUTES != 0);

        // Determine whether query information by name, FILE_STAT_INFORMATION and
        // FILE_STAT_LX_INFORMATION are supported.
        determine_fallback_mode(file_handle, &mut flags, fallback_mode);

        // Determine if per-directory case-sensitivity is supported.
        if util::query_information_file::<FileSystem::FILE_CASE_SENSITIVE_INFORMATION>(file_handle)
            .is_ok()
        {
            flags.set_supports_case_sensitive_dir(true);
        };

        // Metadata support requires EAs and FILE_STAT_LX_INFORMATION.
        if flags.supports_xattr() && flags.supports_stat_lx_info() {
            flags.set_supports_metadata(true);
        }

        Ok(FsContext {
            compatibility_flags: flags,
            _phantom: PhantomData,
        })
    }
}

unsafe impl Send for FsContext {}
unsafe impl Sync for FsContext {}

#[bitfield(u8)]
pub struct RenameFlags {
    pub escape_name: bool,
    pub posix_semantics: bool,
    #[bits(6)]
    _reserved: u8,
}

#[derive(Default)]
pub struct InodeAttributes {
    pub uid: Option<lx::uid_t>,
    pub gid: Option<lx::gid_t>,
    pub mode: Option<lx::mode_t>,
    pub device_id: Option<lx::dev_t>,
}

pub fn rename(
    file_handle: &OwnedHandle,
    target_parent: &OwnedHandle,
    target_path: &Path,
    fs_context: &FsContext,
    flags: RenameFlags,
) -> lx::Result<()> {
    // Set the POSIX semantics flag if the FS supports POSIX unlink rename
    let new_flags = flags.with_posix_semantics(
        fs_context
            .compatibility_flags
            .supports_posix_unlink_rename(),
    );

    util::rename(file_handle, target_parent, target_path, new_flags)
}

/// Implements the chmod operation.
///
/// N.B. Linux permission bits are not fully supported. Only the read-only
/// attribute can be modified by altering the write bits of the file.
///
/// N.B. For unsupported changes this function returns success even though it
/// did nothing.
pub fn chmod(file_handle: &OwnedHandle, mode: lx::mode_t) -> lx::Result<()> {
    let info: FileSystem::FILE_BASIC_INFORMATION = util::query_information_file(file_handle)?;

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        Ok(())
    } else if mode & 0o222 == 0 {
        util::set_readonly_attribute(file_handle, info.FileAttributes, true)
    } else {
        util::set_readonly_attribute(file_handle, info.FileAttributes, false)
    }
}

pub fn delete_file(fs_context: &FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    let result = delete_file_core(fs_context, file_handle);

    match result {
        Ok(_) => result,
        Err(e) => {
            if e.value() == lx::EIO {
                result
            } else {
                delete_read_only_file(fs_context, file_handle)
            }
        }
    }
}

pub fn delete_file_core(fs_context: &FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    if fs_context
        .compatibility_flags
        .supports_posix_unlink_rename()
    {
        delete_file_core_posix(fs_context, file_handle)
    } else {
        delete_file_core_non_posix(file_handle)
    }
}

pub fn delete_read_only_file(fs_context: &FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    let info: FileSystem::FILE_BASIC_INFORMATION = util::query_information_file(file_handle)?;

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 == 0 {
        Err(lx::Error::from_lx(lx::EIO))
    } else {
        delete_file_core(fs_context, file_handle)
    }
}

fn delete_file_core_non_posix(file_handle: &OwnedHandle) -> lx::Result<()> {
    let info = FileSystem::FILE_DISPOSITION_INFORMATION { DeleteFile: true };

    util::set_information_file(file_handle, &info)
}

fn delete_file_core_posix(fs_context: &FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    let mut ignore_read_only_disposition = fs_context
        .compatibility_flags
        .supports_ignore_read_only_disposition();
    loop {
        // Set the flags for FILE_DISPOSITION_INFORMATION_EX and set
        // FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE if the flag is set in
        // fs_context
        let flags: FileSystem::FILE_DISPOSITION_INFORMATION_EX_FLAGS =
            FileSystem::FILE_DISPOSITION_INFORMATION_EX_FLAGS(
                FileSystem::FILE_DISPOSITION_DELETE.0
                    | FileSystem::FILE_DISPOSITION_POSIX_SEMANTICS.0
                    | if ignore_read_only_disposition {
                        FileSystem::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.0
                    } else {
                        0
                    },
            );
        let info = FileSystem::FILE_DISPOSITION_INFORMATION_EX { Flags: flags };

        let result = util::set_information_file(file_handle, &info);

        match result {
            Ok(_) => return result,
            Err(e) => {
                if e.value() == lx::EPERM && ignore_read_only_disposition {
                    // Try again without the IGNORE_READONLY_ATTRIBUTE flag.
                    ignore_read_only_disposition = false;
                    continue;
                }
            }
        }

        return result;
    }
}

/// Convert file attributes and security to a Linux file mode. If any of the metadata
/// fields provided in `info` is invalid, its flag will be removed from the LxFlags field.
pub fn convert_mode(
    fs_context: &FsContext,
    info: &FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<lx::mode_t> {
    let mut local_mode: lx::mode_t;
    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        && (info.ReparseTag == FileSystem::IO_REPARSE_TAG_LX_SYMLINK as u32
            || info.ReparseTag == W32Ss::IO_REPARSE_TAG_SYMLINK
            || info.ReparseTag == W32Ss::IO_REPARSE_TAG_MOUNT_POINT)
    {
        return Ok(lx::S_IFLNK | 0o777);
    }

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        local_mode = lx::S_IFDIR;
    } else {
        local_mode = lx::S_IFREG;
    }

    // If the file system doesn't support permission mapping, just return full
    // access.
    //
    // N.B. For read-only files, the write bits are removed from the mode.
    if !fs_context.compatibility_flags.supports_permission_mapping() {
        local_mode |= LX_UTIL_DEFAULT_PERMISSIONS;
        if lx::s_isreg(local_mode) && info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 != 0 {
            local_mode &= !0o222;
        }
    } else {
        // Report read permission if the user has read access to a file, or list
        // access to a directory.
        static_assertions::const_assert_eq!(W32Fs::FILE_READ_DATA.0, W32Fs::FILE_LIST_DIRECTORY.0);

        if info.EffectiveAccess & W32Fs::FILE_READ_DATA.0 != 0 {
            local_mode |= 0o444;
        }

        // Report write permission if the user has write access to a file. For
        // directories, write permission is included if the user either has add
        // file, add subdirectory, or delete child permission.
        //
        // N.B. If the user has only one of the directory permissions reported
        //      as write access, the other operations will fail due to NT access
        //      checks.
        //
        // N.B. For regular files, write permission is not reported if the
        //      read-only attribute is set.
        if !lx::s_isdir(local_mode) {
            if (info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 == 0)
                && (info.EffectiveAccess & W32Fs::FILE_WRITE_DATA.0 != 0)
            {
                local_mode |= 0o222;
            }
        } else if info.EffectiveAccess & LX_UTIL_FS_DIR_WRITE_ACCESS != 0 {
            local_mode |= 0o222;
        }

        // Report execute permission if the user has execute access to a file,
        // or traverse access to a directory. For directories, the bypass
        // traverse checking privilege is also checked.
        static_assertions::const_assert_eq!(W32Fs::FILE_EXECUTE.0, W32Fs::FILE_TRAVERSE.0);

        if info.EffectiveAccess & W32Fs::FILE_EXECUTE.0 == W32Fs::FILE_EXECUTE.0
            || (lx::s_isdir(local_mode) && flags & LX_UTIL_FS_CALLER_HAS_TRAVERSE_PRIVILEGE != 0)
        {
            local_mode |= 0o111;
        }
    }

    // Apply the masks if the mode was automatically determined.
    //
    // N.B. If the mode was present but invalid, the flag for it will have
    //      been removed.
    //
    // N.B. The masks are not applied to symlinks, because they should always
    //      have their access mask set to 777.
    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0 {
        debug_assert!(!lx::s_islnk(local_mode));

        local_mode &= umask;
        if lx::s_isdir(local_mode) {
            local_mode &= dmask;
        } else {
            local_mode &= fmask;
        }
    }

    Ok(local_mode)
}

/// Determine the owner and node to use for a file. If any of the metadata fields provided
/// in `info` is invalid, its flag will be removed from the LxFlags field.
pub fn determine_inode_attributes(
    fs_context: &FsContext,
    info: &mut FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<InodeAttributes> {
    validate_lx_attributes(info);
    let mut attributes = InodeAttributes::default();

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0) || lx::s_islnk(info.LxMode) {
        let mode = convert_mode(fs_context, info, flags, umask, fmask, dmask)?;
        attributes.mode = Some(mode);

        debug_assert!(
            info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0
                || !lx::s_islnk(mode)
                || mode == (lx::S_IFLNK | 0o777)
        );
    } else {
        attributes.mode = Some(info.LxMode);
    }

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_UID != 0 {
        attributes.uid = Some(info.LxUid);
    }

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_GID != 0 {
        attributes.gid = Some(info.LxGid);
    }

    if lx::s_ischr(info.LxMode) || lx::s_isblk(info.LxMode) {
        if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_DEVICE_ID != 0 {
            attributes.device_id = Some(lx::make_dev(info.LxDeviceIdMajor, info.LxDeviceIdMinor));
        } else {
            attributes.device_id = Some(0);
        }
    }

    Ok(attributes)
}

/// Validate the LX attributes on a file and removes flags
/// for invalid attributes
pub fn validate_lx_attributes(info: &mut FileSystem::FILE_STAT_LX_INFORMATION) {
    let mut expected_file_type: lx::mode_t;

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE != 0 {
        if info.LxMode & !lx::MODE_VALID_BITS != 0 {
            info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_MODE;
        } else {
            expected_file_type = 0;
            if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                expected_file_type = util::reparse_tag_to_file_mode(info.ReparseTag);
            }

            if expected_file_type == 0 {
                if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                    expected_file_type = lx::S_IFDIR;
                } else {
                    expected_file_type = lx::S_IFREG;
                }
            }

            if info.LxMode & lx::S_IFMT != expected_file_type {
                info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_MODE;
            }
        }
    }

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_UID != 0) && (info.LxUid == lx::UID_INVALID)
    {
        info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_UID;
    }

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_GID != 0) && (info.LxUid == lx::GID_INVALID)
    {
        info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_GID;
    }
}

/// Convert the allocation size reported by NT to a block count
/// used in the results of the stat system call in Linux
pub fn allocation_size_to_block_count(allocation_size: i64, block_size: u32) -> u64 {
    let mut result = 0;
    let size = allocation_size as u64;

    if size >= block_size as u64 {
        result = size / LX_UTIL_FS_ALLOCATION_BLOCK_SIZE;
        if size % LX_UTIL_FS_ALLOCATION_BLOCK_SIZE != 0 {
            result += 1;
        }
    }

    result
}

/// Convert file information to a stat structure used by Linux.
///
/// N.B. This routine does not provide all fields. The file system's device ID
/// is not provided.
pub fn get_lx_attr(
    fs_context: &FsContext,
    info: &mut FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    block_size: u32,
    default_uid: lx::uid_t,
    default_gid: lx::gid_t,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<lx::Stat> {
    let inode_attr = determine_inode_attributes(fs_context, info, flags, umask, fmask, dmask)?;
    let mode = inode_attr.mode.unwrap_or(0);
    let file_size: u64;
    let block_count: u64;

    if lx::s_isdir(mode) {
        file_size = block_size as u64;
        block_count = 0;
    } else {
        file_size = info.EndOfFile as u64;
        block_count = allocation_size_to_block_count(info.AllocationSize, block_size)
    }

    // lx::Stat has different padding members on ARM and x86. As such, don't construct it manually,
    // but just fill out the individual fields.
    let mut stat: lx::Stat = unsafe { std::mem::zeroed() };
    stat.uid = inode_attr.uid.unwrap_or(default_uid);
    stat.gid = inode_attr.gid.unwrap_or(default_gid);
    stat.mode = mode;
    stat.device_nr_special = inode_attr.device_id.unwrap_or(0) as _;
    stat.inode_nr = info.FileId as _;
    stat.link_count = info.NumberOfLinks as _;
    stat.access_time = util::nt_time_to_timespec(info.LastAccessTime, true);
    stat.write_time = util::nt_time_to_timespec(info.LastWriteTime, true);
    stat.change_time = if info.ChangeTime == 0 {
        // Some file systems do not provide a change time. If this is the case,
        // use the write time.
        util::nt_time_to_timespec(info.LastWriteTime, true)
    } else {
        util::nt_time_to_timespec(info.ChangeTime, true)
    };
    stat.block_size = block_size as _;
    stat.file_size = file_size;
    stat.block_count = block_count;

    Ok(stat)
}

/// Query the stat information for a handle. If the filesystem does not support FILE_STAT_INFORMATION,
/// one will be constructed using different queries.
pub fn query_stat_information(
    file_handle: &OwnedHandle,
    fs_context: &FsContext,
) -> lx::Result<FileSystem::FILE_STAT_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_info() {
        util::query_information_file(file_handle)
    } else {
        debug_assert!(!fs_context.compatibility_flags.supports_query_by_name());

        let granted_access = if fs_context.compatibility_flags.supports_permission_mapping() {
            util::check_security(file_handle, W32Ss::MAXIMUM_ALLOWED)?
        } else {
            0
        };

        let mut iosb = Default::default();
        let mut all_information: FileSystem::FILE_ALL_INFORMATION = Default::default();
        let (buf, len) = util::FileInformationClass::as_ptr_len_mut(&mut all_information);

        // SAFETY: Calling NtQueryInformationFile as documented.
        // Don't use util::query_information_file so we can check for STATUS_BUFFER_OVERFLOW, which indicates that
        // the buffer wasn't big enough to have the file name at the end of the FILE_NAME_INFORMATION written.
        // In this case, the rest of the buffer is still valid.
        let status = unsafe {
            FileSystem::NtQueryInformationFile(
                Foundation::HANDLE(file_handle.as_raw_handle()),
                &mut iosb,
                buf.cast(),
                len.try_into().unwrap(),
                FileSystem::FileAllInformation,
            )
        };

        // STATUS_BUFFER_OVERFLOW is acceptable, the result is still valid.
        if status != Foundation::STATUS_SUCCESS && status != Foundation::STATUS_BUFFER_OVERFLOW {
            return Err(util::nt_status_to_lx(status));
        }

        let reparse_tag = if all_information.BasicInformation.FileAttributes
            & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0
            != 0
        {
            let tag_information: SystemServices::FILE_ATTRIBUTE_TAG_INFORMATION =
                util::query_information_file(file_handle)?;

            debug_assert!(
                tag_information.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            );
            tag_information.ReparseTag
        } else {
            0
        };

        Ok(FileSystem::FILE_STAT_INFORMATION {
            FileId: all_information.InternalInformation.IndexNumber,
            CreationTime: all_information.BasicInformation.CreationTime,
            LastAccessTime: all_information.BasicInformation.LastAccessTime,
            LastWriteTime: all_information.BasicInformation.LastWriteTime,
            ChangeTime: all_information.BasicInformation.ChangeTime,
            AllocationSize: all_information.StandardInformation.AllocationSize,
            EndOfFile: all_information.StandardInformation.EndOfFile,
            FileAttributes: all_information.BasicInformation.FileAttributes,
            ReparseTag: reparse_tag,
            NumberOfLinks: all_information.StandardInformation.NumberOfLinks,
            EffectiveAccess: granted_access,
        })
    }
}

// TODO?: FILE_STAT_LX_INFORMATION is a superset of FILE_STAT_INFORMATION, so it'd be
// possible to do this by creating a buffer large enough for FILE_STAT_LX_INFORMATION
// and casting
fn stat_info_to_stat_lx_info(
    stat_info: FileSystem::FILE_STAT_INFORMATION,
) -> FileSystem::FILE_STAT_LX_INFORMATION {
    FileSystem::FILE_STAT_LX_INFORMATION {
        FileId: stat_info.FileId,
        CreationTime: stat_info.CreationTime,
        LastAccessTime: stat_info.LastAccessTime,
        LastWriteTime: stat_info.LastWriteTime,
        ChangeTime: stat_info.ChangeTime,
        AllocationSize: stat_info.AllocationSize,
        EndOfFile: stat_info.EndOfFile,
        FileAttributes: stat_info.FileAttributes,
        ReparseTag: stat_info.ReparseTag,
        NumberOfLinks: stat_info.NumberOfLinks,
        EffectiveAccess: stat_info.EffectiveAccess,
        ..Default::default()
    }
}

/// Query the stat information with metadata for a handle. If the filesystem does not support FILE_STAT_INFORMATION,
/// one will be constructed using different queries.
pub fn query_stat_lx_information(
    file_handle: &OwnedHandle,
    fs_context: &FsContext,
) -> lx::Result<FileSystem::FILE_STAT_LX_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_lx_info() {
        util::query_information_file(file_handle)
    } else {
        let stat_info = query_stat_information(file_handle, fs_context)?;
        let mut info = stat_info_to_stat_lx_info(stat_info);

        if fs_context.compatibility_flags.supports_case_sensitive_dir()
            && stat_info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0
        {
            let case_sensitive_info: FileSystem::FILE_CASE_SENSITIVE_INFORMATION =
                util::query_information_file(file_handle)?;

            if case_sensitive_info.Flags & W32Ss::FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                info.LxFlags |= FileSystem::LX_FILE_CASE_SENSITIVE_DIR;
            }
        }

        Ok(info)
    }
}

/// Query the stat information with metadata for a file based on its name. If the filesystem does not
/// support FILE_STAT_INFORMATION, one will be constructed using different queries.
pub fn query_stat_lx_information_by_name(
    fs_context: &FsContext,
    parent_handle: Option<&OwnedHandle>,
    path: &UnicodeString,
) -> lx::Result<FileSystem::FILE_STAT_LX_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_lx_info() {
        util::query_information_file_by_name(parent_handle, path)
    } else {
        let stat_info: FileSystem::FILE_STAT_INFORMATION =
            util::query_information_file_by_name(parent_handle, path)?;
        let mut info = stat_info_to_stat_lx_info(stat_info);

        if fs_context.compatibility_flags.supports_case_sensitive_dir()
            && stat_info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0
        {
            let case_sensitive_info: FileSystem::FILE_CASE_SENSITIVE_INFORMATION =
                util::query_information_file_by_name(parent_handle, path)?;

            if case_sensitive_info.Flags & W32Ss::FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                info.LxFlags |= FileSystem::LX_FILE_CASE_SENSITIVE_DIR;
            }
        }

        Ok(info)
    }
}

fn query_reparse_data(
    file_handle: &OwnedHandle,
) -> lx::Result<(
    System::IO::IO_STATUS_BLOCK,
    HeaderVec<SymlinkReparse, u8, 1>,
)> {
    let tail_size = W32Fs::MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize - size_of::<SymlinkReparse>();
    let mut reparse_buffer =
        HeaderVec::<SymlinkReparse, u8, 1>::with_capacity(SymlinkReparse::default(), tail_size);
    let mut iosb = Default::default();

    // SAFETY: calling Win32 API as documented.
    unsafe {
        let _ = util::check_status(FileSystem::NtFsControlFile(
            Foundation::HANDLE(file_handle.as_raw_handle()),
            Some(Foundation::HANDLE::default()),
            None,
            None,
            &mut iosb,
            Ioctl::FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(reparse_buffer.as_mut_ptr().cast()),
            reparse_buffer.total_byte_capacity() as u32,
        ))?;
        reparse_buffer.set_tail_len(tail_size);
    };

    if iosb.Information < REPARSE_DATA_BUFFER_HEADER_SIZE {
        Err(lx::Error::EIO)
    } else {
        Ok((iosb, reparse_buffer))
    }
}

/// Determines the length of a symbolic link. This function should not be called for version 1
/// links since their length can be determined from the file size.
pub fn read_link_length(file_handle: &OwnedHandle, state: &VolumeState) -> lx::Result<u32> {
    let (_, reparse_buffer) = query_reparse_data(file_handle)?;

    // SAFETY: Accessing union field of type returned from Win32 API
    let reparse_tag = unsafe { reparse_buffer.head.header.ReparseTag };
    const IO_REPARSE_TAG_LX_SYMLINK: u32 = FileSystem::IO_REPARSE_TAG_LX_SYMLINK as u32;

    match reparse_tag {
        IO_REPARSE_TAG_LX_SYMLINK => {
            // SAFETY: Accessing union field of type returned from Win32 API
            let version = unsafe { reparse_buffer.head.data.symlink.version };
            match version {
                LX_UTIL_SYMLINK_DATA_VERSION_2 => {
                    // SAFETY: Accessing union field of type returned from Win32 API
                    let data_length = unsafe { reparse_buffer.head.header.ReparseDataLength };
                    Ok(data_length as u32 - LX_UTIL_SYMLINK_TARGET_OFFSET)
                }
                _ => Err(lx::Error::EIO),
            }
        }
        W32Ss::IO_REPARSE_TAG_SYMLINK | W32Ss::IO_REPARSE_TAG_MOUNT_POINT => {
            // SAFETY: Accessing union field of type returned from Win32 API).
            // The reparse buffer is well-formed as returned from Win32.
            unsafe {
                let header = &(reparse_buffer.head.header);
                symlink::read_nt_symlink_length(header, state)
            }
        }
        _ => Err(lx::Error::EIO),
    }
}

/// Reads the target of a symbolic link. If this function returns None, this is a V1 symlink whose
/// target is stored in the file data.
pub fn read_reparse_link(
    file_handle: &OwnedHandle,
    state: &VolumeState,
) -> lx::Result<Option<String>> {
    let (iosb, reparse_buffer) = query_reparse_data(file_handle)?;

    // SAFETY: Accessing union field of type returned from Win32 API
    let reparse_tag = unsafe { reparse_buffer.head.header.ReparseTag };
    const IO_REPARSE_TAG_LX_SYMLINK: u32 = FileSystem::IO_REPARSE_TAG_LX_SYMLINK as u32;

    match reparse_tag {
        IO_REPARSE_TAG_LX_SYMLINK => {
            // SAFETY: Accessing union field of type returned from Win32 API
            let version = unsafe { reparse_buffer.head.data.symlink.version };
            match version {
                LX_UTIL_SYMLINK_DATA_VERSION_1 => {
                    if iosb.Information != LX_UTIL_SYMLINK_REPARSE_BASE_SIZE as usize {
                        Err(lx::Error::EIO)
                    } else {
                        Ok(None)
                    }
                }
                LX_UTIL_SYMLINK_DATA_VERSION_2 => {
                    // SAFETY: Accessing union field of type returned from Win32 API
                    let data_length = unsafe { reparse_buffer.head.header.ReparseDataLength };
                    let path_length = data_length - LX_UTIL_SYMLINK_TARGET_OFFSET as u16;
                    if iosb.Information < LX_UTIL_SYMLINK_REPARSE_BASE_SIZE as usize
                        || iosb.Information
                            != REPARSE_DATA_BUFFER_HEADER_SIZE + data_length as usize
                    {
                        Err(lx::Error::EIO)
                    } else {
                        if path_length > LX_PATH_MAX {
                            Err(lx::Error::EIO)
                        } else {
                            // SAFETY: The section of memory used to construct the string is guaranteed to
                            // be valid by the Win32 API due to the previous checks
                            let str = std::str::from_utf8(unsafe {
                                std::slice::from_raw_parts(
                                    reparse_buffer.head.data.symlink.target.as_ptr(),
                                    path_length as usize,
                                )
                            })
                            .map_err(|_| lx::Error::EIO)?;

                            Ok(Some(str.to_string()))
                        }
                    }
                }
                _ => Err(lx::Error::EIO),
            }
        }
        W32Ss::IO_REPARSE_TAG_SYMLINK | W32Ss::IO_REPARSE_TAG_MOUNT_POINT => {
            // SAFETY: Accessing union field of type returned from Win32 API).
            // The reparse buffer is well-formed as returned from Win32.
            unsafe {
                let header = &reparse_buffer.head.header;
                symlink::read_nt_symlink(header, state).map(Some)
            }
        }
        _ => Err(lx::Error::EIO),
    }
}

fn determine_fallback_mode(
    file_handle: &OwnedHandle,
    flags: &mut FsCompatibilityFlags,
    fallback_mode: u32,
) {
    let empty_string = UnicodeString::empty();
    if fallback_mode == LX_DRVFS_DISABLE_NONE {
        if util::query_information_file_by_name::<FileSystem::FILE_STAT_LX_INFORMATION>(
            Some(file_handle),
            &empty_string,
        )
        .is_ok()
        {
            flags.set_supports_query_by_name(true);
            flags.set_supports_stat_info(true);
            flags.set_supports_stat_lx_info(true);
            return;
        };

        // FILE_STAT_LX_INFORMATION didn't work, so try it with FILE_STAT_INFORMATION.
        if util::query_information_file_by_name::<FileSystem::FILE_STAT_INFORMATION>(
            Some(file_handle),
            &empty_string,
        )
        .is_ok()
        {
            flags.set_supports_query_by_name(true);
            flags.set_supports_stat_info(true);
            return;
        };
    }

    // Check if FILE_STAT_(LX_)INFORMATION is supported even if query by name is not.
    if fallback_mode < LX_DRVFS_DISABLE_QUERY_BY_NAME_AND_STAT_INFO {
        if util::query_information_file_by_name::<FileSystem::FILE_STAT_LX_INFORMATION>(
            Some(file_handle),
            &empty_string,
        )
        .is_ok()
        {
            flags.set_supports_stat_info(true);
            flags.set_supports_stat_lx_info(true);
            return;
        };

        if util::query_information_file_by_name::<FileSystem::FILE_STAT_INFORMATION>(
            Some(file_handle),
            &empty_string,
        )
        .is_ok()
        {
            flags.set_supports_query_by_name(true);
            flags.set_supports_stat_info(true);
        };
    }
}
