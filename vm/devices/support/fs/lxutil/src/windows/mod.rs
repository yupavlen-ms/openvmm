// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: Calling into lxutil external dll.
#![expect(unsafe_code)]
#![expect(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

mod macros;

pub(crate) mod api;
pub(crate) mod fs;
pub(crate) mod path;
mod readdir;
mod symlink;
mod util;

use super::PathExt;
use super::SetAttributes;
use ::windows::Wdk::Storage::FileSystem;
use ::windows::Wdk::System::SystemServices;
use ::windows::Win32::Foundation;
use ntapi::ntioapi;
use pal::windows;
use pal::windows::UnicodeString;
use parking_lot::Mutex;
use std::ffi;
use std::mem;
use std::os::windows::prelude::*;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use winapi::shared::basetsd;
use winapi::shared::ntdef;
use winapi::um::winnt;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const DOT_ENTRY_COUNT: lx::off_t = 2;

// State that LxVolume can share with LxFiles.
pub struct VolumeState {
    fs_context: fs::FsContext,
    options: super::LxVolumeOptions,
    block_size: ntdef::ULONG,
}

impl VolumeState {
    pub fn new(
        fs_context: fs::FsContext,
        options: super::LxVolumeOptions,
        block_size: ntdef::ULONG,
    ) -> Arc<Self> {
        Arc::new(VolumeState {
            fs_context,
            options,
            block_size,
        })
    }

    pub fn get_attributes_by_handle(
        &self,
        handle: &OwnedHandle,
    ) -> lx::Result<util::LxStatInformation> {
        util::get_attributes_by_handle(&self.fs_context, self, handle)
    }

    pub fn get_attributes(
        &self,
        root_handle: Option<&OwnedHandle>,
        path: &Path,
        existing_handle: Option<&OwnedHandle>,
    ) -> lx::Result<util::LxStatInformation> {
        util::get_attributes(&self.fs_context, self, root_handle, path, existing_handle)
    }

    pub fn read_reparse_link(&self, handle: &OwnedHandle) -> lx::Result<Option<String>> {
        fs::read_reparse_link(handle, self)
    }
}

// Windows implementation of LxVolume.
// See crate::LxVolume for more detailed comments.
pub struct LxVolume {
    root: OwnedHandle,
    root_path: PathBuf,
    state: Arc<VolumeState>,
}

impl LxVolume {
    pub fn new(root_path: &Path, options: &super::LxVolumeOptions) -> lx::Result<Self> {
        api::delay_load_lxutil()?;

        unsafe {
            // Open a handle to the root.
            let (root, _) = util::open_relative_file(
                None,
                root_path,
                util::MINIMUM_PERMISSIONS,
                ntioapi::FILE_OPEN,
                winnt::FILE_ATTRIBUTE_DIRECTORY,
                ntioapi::FILE_DIRECTORY_FILE,
                None,
            )?;

            // Determine the capabilities of the file system.
            let fs_context = fs::FsContext::new(&root, fs::LX_DRVFS_DISABLE_NONE, false)?;

            let mut options = options.clone();
            if !fs_context.compatibility_flags.supports_metadata() {
                options.metadata = false;
            }

            if !fs_context.compatibility_flags.supports_case_sensitive_dir() {
                options.create_case_sensitive_dirs = false;
            }

            // Determine the block size for use in stat calls.
            // N.B. If this volume contains more than one file system, this value could be wrong for
            //      some queries. However, this is not the intended use of this class.
            let block_size = api::LxUtilFsGetFileSystemBlockSize(root.as_raw_handle());
            Ok(Self {
                root,
                #[expect(clippy::disallowed_methods, reason = "need actual canonical path here")]
                root_path: root_path.canonicalize()?,
                state: VolumeState::new(fs_context, options, block_size),
            })
        }
    }

    pub fn supports_stable_file_id(&self) -> bool {
        self.state
            .fs_context
            .compatibility_flags
            .supports_stable_file_id()
    }

    fn check_sandbox_enforcement(&self, path: &Path) -> lx::Result<()> {
        if !self.state.options.sandbox {
            return Ok(());
        }
        let mut cur_path = PathBuf::new();
        for next_path in path.components() {
            let next_path = match next_path {
                Component::Normal(next) => next,
                _ => return Err(lx::Error::EINVAL),
            };

            if util::is_dos_device_name(next_path)? {
                return Err(lx::Error::EACCES);
            }

            if let Some(extension) = Path::new(next_path).extension() {
                let ext = extension.to_ascii_lowercase();
                if self
                    .state
                    .options
                    .sandbox_disallowed_extensions
                    .contains(&ext)
                {
                    return Err(lx::Error::EACCES);
                }
            }

            cur_path = cur_path.join(next_path);

            let information = match self.state.get_attributes(
                Some(&self.root),
                cur_path.as_path(),
                None,
            ) {
                Ok(info) => info.stat,
                Err(err) => {
                    // Non-existent paths are not filtered
                    if err == lx::Error::ENOENT {
                        return Ok(());
                    }
                    // Otherwise couldn't get attributes, so safest recourse is to fail
                    tracing::warn!(path = %path.display(), ?err, "Unable to get attributes; denying access");
                    return Err(lx::Error::EACCES);
                }
            };
            if information.FileAttributes
                & (winnt::FILE_ATTRIBUTE_HIDDEN
                    | winnt::FILE_ATTRIBUTE_SYSTEM
                    | winnt::FILE_ATTRIBUTE_OFFLINE
                    | winnt::FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0
            {
                return Err(lx::Error::EACCES);
            }
        }

        Ok(())
    }

    pub fn lstat(&self, path: &Path) -> lx::Result<lx::Stat> {
        assert!(path.is_relative());

        // Special-case returning attributes of the root itself to just use the existing handle.
        let mut info = if path.as_os_str().is_empty() {
            self.state.get_attributes_by_handle(&self.root)?
        } else {
            self.check_sandbox_enforcement(path)?;
            self.state.get_attributes(Some(&self.root), path, None)?
        };

        util::file_info_to_stat(
            &self.state.fs_context,
            &mut info,
            &self.state.options,
            self.state.block_size,
        )
    }

    pub fn set_attr(&self, path: &Path, attr: SetAttributes) -> lx::Result<()> {
        self.set_attr_helper(path, attr, false)?;
        Ok(())
    }

    pub fn set_attr_stat(&self, path: &Path, attr: SetAttributes) -> lx::Result<lx::Stat> {
        Ok(self.set_attr_helper(path, attr, true)?.unwrap())
    }

    pub fn open(
        &self,
        path: &Path,
        flags: i32,
        mut options: Option<super::LxCreateOptions>,
    ) -> lx::Result<LxFile> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        // Convert flags to relevant NT options.
        let desired_access = util::open_flags_to_access_mask(flags);
        let (file_attributes, create_options) = util::open_flags_to_attributes_options(flags);
        let disposition = util::open_flags_to_disposition(flags);

        // This function creates a regular file and ignores the file type in the specified mode.
        if let Some(opt) = options.as_mut() {
            opt.mode = lx::S_IFREG | (opt.mode & 0o7777);
        }

        unsafe {
            // Try to open/create the file.
            let (file, create_result) = self.create_file(
                path,
                desired_access,
                disposition,
                file_attributes,
                create_options,
                options,
                0,
            )?;

            // O_TRUNC can't be handled with FILE_OVERWRITE because that clears metadata, so handle
            // it here.
            if flags & lx::O_TRUNC != 0 && create_result != ntioapi::FILE_CREATED as usize {
                util::check_lx_error(api::LxUtilFsTruncate(file.as_raw_handle(), 0))?;
            }

            let is_app_exec_alias = match self.state.get_attributes_by_handle(&file) {
                Ok(info) => info.is_app_execution_alias,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to get attributes for newly opened file");
                    false
                }
            };
            Ok(LxFile {
                handle: file,
                state: Arc::clone(&self.state),
                enumerator: None,
                access: desired_access,
                kill_priv: AtomicBool::new(true),
                is_app_exec_alias: Mutex::new(is_app_exec_alias),
            })
        }
    }

    pub fn mkdir(&self, path: &Path, options: super::LxCreateOptions) -> lx::Result<()> {
        self.mkdir_helper(path, options)?;
        Ok(())
    }

    pub fn mkdir_stat(&self, path: &Path, options: super::LxCreateOptions) -> lx::Result<lx::Stat> {
        let handle = self.mkdir_helper(path, options)?;
        self.get_stat_by_handle(&handle)
    }

    pub fn symlink(
        &self,
        path: &Path,
        target: &lx::LxStr,
        options: super::LxCreateOptions,
    ) -> lx::Result<()> {
        self.symlink_helper(path, target, options)?;
        Ok(())
    }

    pub fn symlink_stat(
        &self,
        path: &Path,
        target: &lx::LxStr,
        options: super::LxCreateOptions,
    ) -> lx::Result<lx::Stat> {
        let handle = self.symlink_helper(path, target, options)?;
        self.get_stat_by_handle(&handle)
    }

    pub fn read_link(&self, path: &Path) -> lx::Result<lx::LxString> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;

        // Open the file to read its reparse data.
        let mut handle = self.open_file(path, winnt::FILE_READ_ATTRIBUTES, 0)?;
        let mut target = String::new();
        unsafe {
            // Try to read the link target from the reparse data.
            let target_string = self.state.read_reparse_link(&handle)?;
            // TODO: Remove this once LxUtilSymlinkRead is implemented and re-work to just use the Option
            if target_string.is_some() {
                target = target_string.unwrap();
            }

            // If the function succeeded but returned a NULL buffer, this is a V1 LX symlink which must be
            // opened for read to read the target.
            // N.B. The initial open above does not use FILE_READ_DATA because some symlinks (notably the
            //      back-compat symlinks that Windows creates for things like "C:\Documents and Settings")
            //      deny this permission.
            if target.is_empty() {
                handle = util::reopen_file(
                    &handle,
                    winnt::FILE_READ_ATTRIBUTES | winnt::FILE_READ_DATA,
                )?;

                let mut wide_target = UnicodeString::empty();

                util::check_lx_error(api::LxUtilSymlinkRead(
                    handle.as_raw_handle(),
                    wide_target.as_mut_ptr(),
                ))?;

                target = String::from_utf16(wide_target.as_slice()).map_err(|_| lx::Error::EIO)?;
            }
        }

        Ok(target.into())
    }

    pub fn unlink(&self, path: &Path, flags: i32) -> lx::Result<()> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;

        // Directories can be pre-filtered with FILE_DIRECTORY_FILE. We cannot use
        // FILE_NON_DIRECTORY_FILE, because without AT_REMOVEDIR this function still needs to
        // remove NT symlinks which are directories.
        let mut create_options = ntioapi::FILE_OPEN_REPARSE_POINT;
        if flags & lx::AT_REMOVEDIR != 0 {
            create_options |= ntioapi::FILE_DIRECTORY_FILE;
        }

        let handle = self.open_file(
            path,
            winnt::DELETE | winnt::FILE_READ_ATTRIBUTES,
            create_options,
        )?;

        // Query file attributes to check if it matches what AT_REMOVEDIR wants.
        let info: FileSystem::FILE_BASIC_INFORMATION = util::query_information_file(&handle)?;
        if flags & lx::AT_REMOVEDIR != 0 {
            // Must be a directory and not a reparse point (NT directory symlinks are treated
            // as files).
            if info.FileAttributes & winnt::FILE_ATTRIBUTE_DIRECTORY == 0
                || info.FileAttributes & winnt::FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(lx::Error::ENOTDIR);
            }
        } else {
            // Must be a regular file, or a reparse point directory.
            if info.FileAttributes & winnt::FILE_ATTRIBUTE_DIRECTORY != 0
                && info.FileAttributes & winnt::FILE_ATTRIBUTE_REPARSE_POINT == 0
            {
                return Err(lx::Error::EISDIR);
            }
        }

        self.delete_file(&handle)
    }

    pub fn mknod(
        &self,
        path: &Path,
        options: super::LxCreateOptions,
        device_id: lx::dev_t,
    ) -> lx::Result<()> {
        self.mknod_helper(path, options, device_id)?;
        Ok(())
    }

    pub fn mknod_stat(
        &self,
        path: &Path,
        options: super::LxCreateOptions,
        device_id: lx::dev_t,
    ) -> lx::Result<lx::Stat> {
        let handle = self.mknod_helper(path, options, device_id)?;
        self.get_stat_by_handle(&handle)
    }

    pub fn rename(&self, path: &Path, new_path: &Path, flags: u32) -> lx::Result<()> {
        assert!(path.is_relative());
        assert!(new_path.is_relative());
        self.check_sandbox_enforcement(path)?;
        self.check_sandbox_enforcement(new_path)?;

        // Currently, no flags are supported.
        // TODO: RENAME_NOREPLACE could be trivially supported. The other flags would require NT
        //       changes to be atomic.
        if flags != 0 {
            return Err(lx::Error::EINVAL);
        }

        let handle = self.open_file(path, winnt::FILE_READ_ATTRIBUTES | winnt::DELETE, 0)?;

        let flags = fs::RenameFlags::default();
        let error = match fs::rename(&handle, &self.root, new_path, &self.state.fs_context, flags) {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };

        // If the rename failed and POSIX rename is not supported, the target may need to be removed
        // beforehand in case it's a directory (superseding rename does not work in this case), or in
        // case it's read-only.
        // N.B. This MUST be done after attempting the rename because on non-case-sensitive file
        //      systems renaming foo to FOO would otherwise delete the original file.
        if (error.value() == lx::EPERM
            || error.value() == lx::EACCES
            || error.value() == lx::EEXIST)
            && !self
                .state
                .fs_context
                .compatibility_flags
                .supports_posix_unlink_rename()
        {
            match self.open_file(new_path, winnt::DELETE, 0) {
                Ok(target_handle) => self.delete_file(&target_handle)?,
                Err(err) => {
                    // ENOENT means the rename can proceed.
                    if err.value() != lx::ENOENT {
                        return Err(err);
                    }
                }
            }

            // Retry the rename.
            fs::rename(&handle, &self.root, new_path, &self.state.fs_context, flags)?;
        } else {
            return Err(error);
        }

        Ok(())
    }

    pub fn link(&self, path: &Path, new_path: &Path) -> lx::Result<()> {
        self.link_helper(path, new_path)?;
        Ok(())
    }

    pub fn link_stat(&self, path: &Path, new_path: &Path) -> lx::Result<lx::Stat> {
        let handle = self.link_helper(path, new_path)?;
        self.get_stat_by_handle(&handle)
    }

    pub fn stat_fs(&self, path: &Path) -> lx::Result<lx::StatFs> {
        assert!(path.is_relative());
        let handle = self.open_file(path, winnt::FILE_READ_ATTRIBUTES, 0)?;
        unsafe {
            let mut stat_fs = mem::zeroed();
            util::check_lx_error(api::LxUtilFsGetLxFileSystemAttributes(
                handle.as_raw_handle(),
                0,
                &mut stat_fs,
            ))?;

            Ok(stat_fs)
        }
    }

    pub fn set_xattr(
        &self,
        path: &Path,
        name: &lx::LxStr,
        value: &[u8],
        flags: i32,
    ) -> lx::Result<()> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        if !self.state.options.override_xattrs.is_empty() {
            tracing::info!(
                path = %path.display(),
                ?name,
                "Ignoring xattr write on volume with overridden xattrs"
            );
            return Ok(());
        }

        if !self.supports_xattr() {
            return Err(lx::Error::ENOTSUP);
        }

        let system = name.as_bytes().starts_with(b"system.");
        let name = util::create_ansi_string(name)?;
        let desired_access = if system {
            winnt::FILE_WRITE_ATTRIBUTES
        } else if flags != 0 {
            // If there are flags, read access is required to check if the attribute exists.
            winnt::FILE_WRITE_EA | winnt::FILE_READ_EA
        } else {
            winnt::FILE_WRITE_EA
        };

        let file = self.open_file(path, desired_access, 0)?;
        let value = api::LX_UTIL_BUFFER {
            Buffer: value.as_ptr() as *mut ffi::c_void,
            Size: value.len(),
            Flags: 0,
        };

        unsafe {
            if system {
                util::check_lx_error(api::LxUtilXattrSetSystem(
                    file.as_raw_handle(),
                    name.as_ref(),
                    &value,
                    flags,
                ))
            } else {
                util::check_lx_error(api::LxUtilXattrSet(
                    file.as_raw_handle(),
                    name.as_ref(),
                    &value,
                    flags,
                ))
            }
        }
    }

    pub fn get_xattr(
        &self,
        path: &Path,
        name: &lx::LxStr,
        value: Option<&mut [u8]>,
    ) -> lx::Result<usize> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        if !self.state.options.override_xattrs.is_empty() {
            let name = match name.to_str() {
                Some(name) => name,
                None => {
                    tracing::warn!(path = %path.display(), ?name, "Invalid xattr name");
                    return Err(lx::Error::EINVAL);
                }
            };
            match self.state.options.override_xattrs.get(name) {
                Some(val) => {
                    let len = val.len();
                    if let Some(ret_val) = value {
                        if ret_val.len() < len {
                            return Err(lx::Error::ERANGE);
                        }
                        ret_val[..len].copy_from_slice(val);
                    }
                    return Ok(len);
                }
                None => {
                    tracing::trace!(path = %path.display(), name, "Not an overridden xattr name");
                    return Err(lx::Error::ENOENT);
                }
            }
        }

        if !self.supports_xattr() {
            return Err(lx::Error::ENOTSUP);
        }

        let system = name.as_bytes().starts_with(b"system.");
        let name = util::create_ansi_string(name)?;
        let desired_access = if system {
            winnt::FILE_READ_ATTRIBUTES
        } else {
            winnt::FILE_READ_EA
        };

        let file = self.open_file(path, desired_access, 0)?;

        // Set the buffer to NULL if no value buffer is provided, to query the attribute's size.
        let mut value = if let Some(value) = value {
            api::LX_UTIL_BUFFER {
                Buffer: value.as_mut_ptr().cast::<ffi::c_void>(),
                Size: value.len(),
                Flags: 0,
            }
        } else {
            api::LX_UTIL_BUFFER::default()
        };

        unsafe {
            if system {
                util::check_lx_error_size(api::LxUtilXattrGetSystem(
                    file.as_raw_handle(),
                    name.as_ref(),
                    &mut value,
                ))
            } else {
                util::check_lx_error_size(api::LxUtilXattrGet(
                    file.as_raw_handle(),
                    name.as_ref(),
                    &mut value,
                ))
            }
        }
    }

    pub fn list_xattr(&self, path: &Path, list: Option<&mut [u8]>) -> lx::Result<usize> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        if !self.state.options.override_xattrs.is_empty() {
            let len = self
                .state
                .options
                .override_xattrs
                .keys()
                .fold(0usize, |a, k| a + k.len() + 1);
            if let Some(list) = list {
                if list.len() < len {
                    return Err(lx::Error::ERANGE);
                }
                let mut offset = 0;
                for key in self.state.options.override_xattrs.keys() {
                    let len = key.len();
                    list[offset..offset + len].copy_from_slice(key.as_bytes());
                    list[offset + len] = 0;
                    offset += len + 1;
                }
            }
            return Ok(len);
        }

        if !self.supports_xattr() {
            return Err(lx::Error::ENOTSUP);
        }

        // Set the list pointer to NULL if no list buffer was provided, to query the size.
        let mut list_local: *const u8 = ptr::null();
        let list_ptr = if list.is_some() {
            &mut list_local as *mut _
        } else {
            ptr::null_mut()
        };

        let mut desired_access = winnt::FILE_READ_EA;
        if self.supports_case_sensitive_dir() {
            desired_access |= winnt::FILE_READ_ATTRIBUTES;
        }

        let file = self.open_file(path, desired_access, 0)?;
        unsafe {
            let mut flags = 0;

            // If the file system supports case sensitive directories, and this is a directory,
            // include the "system.wsl_case_sensitive" attribute in the list.
            if self.supports_case_sensitive_dir() {
                let result = util::query_information_file::<
                    SystemServices::FILE_ATTRIBUTE_TAG_INFORMATION,
                >(&file);

                if let Ok(info) = result {
                    if info.FileAttributes & winnt::FILE_ATTRIBUTE_DIRECTORY != 0
                        && !util::is_symlink(info.FileAttributes, info.ReparseTag)
                    {
                        flags |= api::LX_UTIL_XATTR_LIST_CASE_SENSITIVE_DIR;
                    }
                }
            }

            let size = util::check_lx_error_size(api::LxUtilXattrList(
                file.as_raw_handle(),
                flags,
                list_ptr,
            ))?;

            // If the list should be returned, copy it into the output buffer.
            if !list_local.is_null() {
                let list_local = windows::RtlHeapBuffer::from_raw(list_local.cast_mut(), size);
                let list = list.unwrap();
                if size > list.len() {
                    return Err(lx::Error::ERANGE);
                }

                list[..size].copy_from_slice(&list_local);
            }

            Ok(size)
        }
    }

    pub fn remove_xattr(&self, path: &Path, name: &lx::LxStr) -> lx::Result<()> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        if !self.state.options.override_xattrs.is_empty() {
            tracing::info!(
                path = %path.display(),
                ?name,
                "Ignoring xattr remove on volume with overridden xattrs"
            );
            return Ok(());
        }
        if !self.supports_xattr() || name.as_bytes().starts_with(b"system.") {
            return Err(lx::Error::ENOTSUP);
        }

        let name = util::create_ansi_string(name)?;
        let file = self.open_file(path, winnt::FILE_READ_EA | winnt::FILE_WRITE_EA, 0)?;
        unsafe { util::check_lx_error(api::LxUtilXattrRemove(file.as_raw_handle(), name.as_ref())) }
    }

    fn supports_xattr(&self) -> bool {
        self.state.fs_context.compatibility_flags.supports_xattr()
    }

    fn supports_case_sensitive_dir(&self) -> bool {
        self.state
            .fs_context
            .compatibility_flags
            .supports_case_sensitive_dir()
    }

    fn mkdir_helper(
        &self,
        path: &Path,
        mut options: super::LxCreateOptions,
    ) -> lx::Result<OwnedHandle> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;

        let mut desired_access = util::MINIMUM_PERMISSIONS;
        if self.state.options.create_case_sensitive_dirs {
            desired_access |= winnt::DELETE | winnt::FILE_WRITE_ATTRIBUTES;
        }

        // The file type in the mode is ignored; this function only creates directories.
        options.mode = lx::S_IFDIR | (options.mode & 0o1777);
        let (handle, _) = self.create_file(
            path,
            desired_access,
            ntioapi::FILE_CREATE,
            winnt::FILE_ATTRIBUTE_DIRECTORY,
            ntioapi::FILE_DIRECTORY_FILE | ntioapi::FILE_OPEN_REPARSE_POINT,
            Some(options),
            0,
        )?;

        if self.state.options.create_case_sensitive_dirs {
            // If setting case sensitive info fails, the file should be deleted.
            let delete_on_failure = pal::ScopeExit::new(|| {
                let _ = fs::delete_file(&self.state.fs_context, &handle);
            });

            let info = FileSystem::FILE_CASE_SENSITIVE_INFORMATION {
                Flags: api::FILE_CS_FLAG_CASE_SENSITIVE_DIR,
            };

            util::set_information_file(&handle, &info)?;
            delete_on_failure.dismiss();
        }

        Ok(handle)
    }

    fn symlink_helper(
        &self,
        path: &Path,
        target: &lx::LxStr,
        mut options: super::LxCreateOptions,
    ) -> lx::Result<OwnedHandle> {
        assert!(path.is_relative() && !path.as_os_str().is_empty());
        self.check_sandbox_enforcement(path)?;

        // Convert the target to its native Windows format.
        let win_target = Path::from_lx(target);

        // Determine whether a NT symlink can be created, and if so whether it should be a file or
        // directory.
        let link_type = if let Ok(win_target) = &win_target {
            self.determine_symlink_type(path.parent().unwrap(), win_target)
        } else {
            SymlinkType::Lx
        };

        // Create the reparse point data for the symlink type.
        let mut create_options = ntioapi::FILE_OPEN_REPARSE_POINT;
        let reparse_data = match link_type {
            SymlinkType::Lx => util::create_link_reparse_buffer(target)?,
            SymlinkType::Nt(dir) => {
                if dir {
                    create_options |= ntioapi::FILE_DIRECTORY_FILE;
                }

                // In this path, win_target cannot be an error.
                util::create_nt_link_reparse_buffer(win_target.unwrap().as_os_str())?
            }
        };

        // Mode is ignored, as symlinks always have full permissions mode.
        options.mode = lx::S_IFLNK | 0o777;
        let (handle, _) = self.create_file(
            path,
            util::MINIMUM_PERMISSIONS | winnt::FILE_WRITE_ATTRIBUTES | winnt::DELETE,
            ntioapi::FILE_CREATE,
            0,
            create_options,
            Some(options),
            0,
        )?;

        // If setting the reparse point fails, the file should be deleted.
        let delete_on_failure = pal::ScopeExit::new(|| {
            let _ = fs::delete_file(&self.state.fs_context, &handle);
        });

        // Try to set the reparse point.
        if let Err(e) = util::set_reparse_point(&handle, &reparse_data) {
            if let SymlinkType::Lx = link_type {
                return Err(e);
            }

            // If creating an NT link failed with a permission error (which means the user was not
            // elevated and doesn't have developer mode enabled), fall back to an LX link and try
            // again.
            let reparse_data = util::create_link_reparse_buffer(target)?;
            util::set_reparse_point(&handle, &reparse_data)?;
        }

        delete_on_failure.dismiss();
        Ok(handle)
    }

    /// Helper to create a hard link.
    fn link_helper(&self, path: &Path, new_path: &Path) -> lx::Result<OwnedHandle> {
        assert!(path.is_relative());
        assert!(new_path.is_relative());
        self.check_sandbox_enforcement(path)?;
        self.check_sandbox_enforcement(new_path)?;

        if !self
            .state
            .fs_context
            .compatibility_flags
            .supports_hard_links()
        {
            return Err(lx::Error::EPERM);
        }

        let handle = self.open_file(
            path,
            util::MINIMUM_PERMISSIONS | winnt::FILE_WRITE_ATTRIBUTES | winnt::SYNCHRONIZE,
            0,
        )?;

        util::create_link(&handle, &self.root, new_path)?;
        Ok(handle)
    }

    // Helper to set attributes and optionally retrieve them.
    fn set_attr_helper(
        &self,
        path: &Path,
        attr: SetAttributes,
        get_attr: bool,
    ) -> lx::Result<Option<lx::Stat>> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;
        let desired_access = util::permissions_for_set_attr(&attr, self.state.options.metadata);
        let file = self.open_file(path, desired_access, 0)?;
        util::set_attr(&file, &self.state, attr)?;
        if get_attr {
            Ok(Some(self.get_stat_by_handle(&file)?))
        } else {
            Ok(None)
        }
    }

    fn mknod_helper(
        &self,
        path: &Path,
        options: super::LxCreateOptions,
        mut device_id: lx::dev_t,
    ) -> lx::Result<OwnedHandle> {
        assert!(path.is_relative());
        self.check_sandbox_enforcement(path)?;

        if !lx::s_isreg(options.mode)
            && !lx::s_ischr(options.mode)
            && !lx::s_isblk(options.mode)
            && !lx::s_isfifo(options.mode)
            && !lx::s_issock(options.mode)
        {
            return Err(lx::Error::EINVAL);
        }

        if !lx::s_isreg(options.mode) && !self.state.options.metadata {
            return Err(lx::Error::EPERM);
        }

        if !lx::s_ischr(options.mode) && !lx::s_isblk(options.mode) {
            device_id = 0;
        }

        let mode = options.mode;
        let (handle, _) = self.create_file(
            path,
            util::MINIMUM_PERMISSIONS | winnt::FILE_WRITE_ATTRIBUTES | winnt::DELETE,
            ntioapi::FILE_CREATE,
            0,
            ntioapi::FILE_OPEN_REPARSE_POINT,
            Some(options),
            device_id,
        )?;

        if !lx::s_isreg(mode) {
            // If setting the reparse point fails, the file should be deleted.
            let delete_on_failure = pal::ScopeExit::new(|| {
                let _ = fs::delete_file(&self.state.fs_context, &handle);
            });

            /// Only the required header for FSCTL_SET_REPARSE_POINT, with data length of zero.
            /// See ntifs.h REPARSE_DATA_BUFFER.
            #[allow(non_camel_case_types, non_snake_case)]
            #[repr(C)]
            #[derive(Clone, Copy, IntoBytes, Immutable, KnownLayout, FromBytes)]
            struct REPARSE_DATA_BUFFER {
                ReparseTag: u32,
                ReparseDataLength: u16,
                Reserved: u16,
            }

            let reparse_tag = util::file_mode_to_reparse_tag(mode);

            let reparse_buffer = REPARSE_DATA_BUFFER {
                ReparseTag: reparse_tag,
                ReparseDataLength: 0,
                Reserved: 0,
            };

            util::set_reparse_point(&handle, reparse_buffer.as_bytes())?;

            delete_on_failure.dismiss();
        }

        Ok(handle)
    }

    // Helper to create files using a relative path from the root of this volume.
    fn create_file(
        &self,
        path: &Path,
        desired_access: winnt::ACCESS_MASK,
        disposition: ntdef::ULONG,
        mut file_attributes: ntdef::ULONG,
        create_options: ntdef::ULONG,
        options: Option<super::LxCreateOptions>,
        device_id: lx::dev_t,
    ) -> lx::Result<(OwnedHandle, basetsd::ULONG_PTR)> {
        self.check_sandbox_enforcement(path)?;
        unsafe {
            assert!(
                disposition == ntioapi::FILE_OPEN
                    || disposition == ntioapi::FILE_OPEN_IF
                    || disposition == ntioapi::FILE_CREATE
            );

            // TODO: Async support.
            let create_options = create_options | ntioapi::FILE_SYNCHRONOUS_IO_ALERT;
            let desired_access = desired_access | winnt::SYNCHRONIZE;

            let mut ea_buffer = [0u8; api::LX_UTIL_FS_METADATA_EA_BUFFER_SIZE];
            let mut ea = None;
            if disposition != ntioapi::FILE_OPEN {
                // If a new file is being created, create an EA buffer for Linux metadata.
                let mut options = options.ok_or(lx::Error::EINVAL)?;
                if self.state.options.metadata {
                    util::apply_attr_overrides(
                        &self.state,
                        Some(&mut options.uid),
                        Some(&mut options.gid),
                        Some(&mut options.mode),
                    );
                    self.determine_creation_info(path, &mut options.mode, &mut options.gid)?;
                    util::apply_attr_overrides(
                        &self.state,
                        Some(&mut options.uid),
                        Some(&mut options.gid),
                        Some(&mut options.mode),
                    );
                    let len = api::LxUtilFsCreateMetadataEaBuffer(
                        options.uid,
                        options.gid,
                        options.mode,
                        device_id,
                        ea_buffer.as_mut_ptr().cast::<ffi::c_void>(),
                    ) as usize;

                    ea = Some(&ea_buffer[..len]);
                }

                // Set the read-only attribute if no write bits are set.
                if lx::s_isreg(options.mode) && options.mode & 0o222 == 0 {
                    file_attributes |= winnt::FILE_ATTRIBUTE_READONLY;
                }
            }

            util::open_relative_file(
                Some(&self.root),
                path,
                desired_access,
                disposition,
                file_attributes,
                create_options,
                ea,
            )
        }
    }

    /// Helper to open existing files using a relative path from the root of this volume.
    ///
    /// N.B. This function always adds FILE_OPEN_REPARSE_POINT to the options.
    fn open_file(
        &self,
        path: &Path,
        desired_access: winnt::ACCESS_MASK,
        create_options: ntdef::ULONG,
    ) -> lx::Result<OwnedHandle> {
        self.check_sandbox_enforcement(path)?;
        let (handle, _) = self.create_file(
            path,
            desired_access,
            ntioapi::FILE_OPEN,
            0,
            create_options | ntioapi::FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )?;

        Ok(handle)
    }

    /// Deletes a file, clearing the read-only attribute if necessary.
    fn delete_file(&self, handle: &OwnedHandle) -> lx::Result<()> {
        let result = fs::delete_file_core(&self.state.fs_context, handle);

        match result {
            Ok(_) => result,
            Err(e) => {
                // Read-only files can fail to be deleted with EIO if:
                // - The file system didn't support FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.
                // - The file system's permission check for that flag failed.
                if e.value() == lx::EIO {
                    result
                } else {
                    // Reopen with the correct permissions to query and clear the read-only attribute,
                    // and try again.
                    let handle = util::reopen_file(
                        handle,
                        winnt::DELETE | winnt::FILE_READ_ATTRIBUTES | winnt::FILE_WRITE_ATTRIBUTES,
                    )?;

                    fs::delete_read_only_file(&self.state.fs_context, &handle)
                }
            }
        }
    }

    // Determines whether the mode and gid must be changed based on the parent's set-group-id bit.
    fn determine_creation_info(
        &self,
        path: &Path,
        mode: &mut lx::mode_t,
        gid: &mut lx::gid_t,
    ) -> lx::Result<()> {
        let dir = if let Some(parent) = path.parent() {
            parent
        } else {
            // This means the user is attempting to create the root, which makes no sense, so
            // nothing to do here.
            return Ok(());
        };

        let info = self.state.get_attributes(Some(&self.root), dir, None)?;
        // If the parent doesn't have explicit mode metadata, it can't have the set-group-id bit.
        if info.stat.LxFlags & api::LX_FILE_METADATA_HAS_MODE != 0 {
            util::determine_creation_info(info.stat.LxMode, info.stat.LxGid, mode, gid);
        }

        Ok(())
    }

    // Determines what kind of symlink to create for a given target.
    fn determine_symlink_type(&self, symlink_parent: &Path, target: &Path) -> SymlinkType {
        // Can't create NT symlinks for absolute paths.
        // N.B. This complicated check is necessary because is_absolute returns false for paths that
        //      have no drive letter, or paths that use the form C:foo (without a \).
        if target.has_root() || matches!(target.components().next(), Some(Component::Prefix(_))) {
            return SymlinkType::Lx;
        }

        // Get the canonical form of the target. If the target doesn't exist, create an LX symlink.
        let mut path = self.root_path.clone();
        path.push(symlink_parent);
        path.push(target);
        path = {
            #[expect(clippy::disallowed_methods)] // need actual canonical path here
            match path.canonicalize() {
                Ok(p) => p,
                Err(_) => return SymlinkType::Lx,
            }
        };

        // If the target isn't inside the volume, create an LX symlink.
        // TODO: Improve this; this doesn't protect against paths that walk out of the volume
        //       and then back in.
        if !path.starts_with(&self.root_path) {
            return SymlinkType::Lx;
        }

        // Determine the attributes of the found target. If an error occurs, create an LX symlink.
        let info = match self.state.get_attributes(None, &path, None) {
            Ok(i) => i.stat,
            Err(_) => return SymlinkType::Lx,
        };

        // If the target is an LX symlink, create an LX symlink. Otherwise the file type should
        // match the target.
        if info.FileAttributes & winnt::FILE_ATTRIBUTE_REPARSE_POINT != 0
            && info.ReparseTag == api::IO_REPARSE_TAG_LX_SYMLINK
        {
            SymlinkType::Lx
        } else if info.FileAttributes & winnt::FILE_ATTRIBUTE_DIRECTORY != 0 {
            SymlinkType::Nt(true)
        } else {
            SymlinkType::Nt(false)
        }
    }

    fn get_stat_by_handle(&self, handle: &OwnedHandle) -> lx::Result<lx::Stat> {
        let mut info = self.state.get_attributes_by_handle(handle)?;
        util::file_info_to_stat(
            &self.state.fs_context,
            &mut info,
            &self.state.options,
            self.state.block_size,
        )
    }
}

// Windows version of an LxFile.
// See `crate::LxFile` for more comments.
pub struct LxFile {
    handle: OwnedHandle,
    state: Arc<VolumeState>,
    enumerator: Option<readdir::DirectoryEnumerator>,
    access: winnt::ACCESS_MASK,
    kill_priv: AtomicBool,
    is_app_exec_alias: Mutex<bool>,
}

impl LxFile {
    pub fn fstat(&self) -> lx::Result<lx::Stat> {
        let mut info = self.state.get_attributes_by_handle(&self.handle)?;
        *self.is_app_exec_alias.lock() = info.is_app_execution_alias;
        util::file_info_to_stat(
            &self.state.fs_context,
            &mut info,
            &self.state.options,
            self.state.block_size,
        )
    }

    pub fn set_attr(&self, mut attr: SetAttributes) -> lx::Result<()> {
        util::set_attr_check_kill_priv(&self.handle, &self.state, &mut attr)?;

        let desired_access = util::permissions_for_set_attr(&attr, self.state.options.metadata);

        // Only reopen if there's an operation that requires it, and we don't already have the
        // required permissions.
        let mut _file = None;
        let handle = if self.access & desired_access != desired_access
            && (attr.mode.is_some()
                || attr.uid.is_some()
                || attr.gid.is_some()
                || !attr.atime.is_omit()
                || !attr.mtime.is_omit()
                || !attr.ctime.is_omit())
        {
            let handle = util::reopen_file(&self.handle, desired_access)?;
            _file = Some(handle);
            _file.as_ref().unwrap()
        } else {
            &self.handle
        };

        // Do truncate with the original handle, even if we reopened, so the write requirement
        // is enforced.
        util::set_attr_core(handle, &self.handle, &self.state, &attr)?;

        if self.state.options.metadata {
            if let Some(mode) = attr.mode {
                if mode & (lx::S_ISUID | lx::S_ISGID) != 0 {
                    self.kill_priv.swap(true, Ordering::AcqRel);
                }
            }
        }

        Ok(())
    }

    pub fn pread(&self, buffer: &mut [u8], offset: lx::off_t) -> lx::Result<usize> {
        if offset < 0 {
            return Err(lx::Error::EINVAL);
        }
        unsafe {
            let mut iosb = mem::zeroed();
            let buffer_ptr = buffer.as_mut_ptr().cast::<ffi::c_void>();
            let buffer_len: u32 = buffer.len().try_into().map_err(|_| lx::Error::EINVAL)?;

            if *self.is_app_exec_alias.lock() {
                Ok(api::LxUtilFsReadAppExecLink(
                    offset.try_into().expect("Invalid offset"),
                    buffer_ptr,
                    buffer_len as usize,
                ))
            } else {
                let mut nt_offset: ntdef::LARGE_INTEGER = mem::zeroed();
                *nt_offset.QuadPart_mut() = offset;
                // TODO: Async I/O.
                util::check_status_rw(ntioapi::NtReadFile(
                    self.handle.as_raw_handle(),
                    ptr::null_mut(),
                    None,
                    ptr::null_mut(),
                    &mut iosb,
                    buffer_ptr,
                    buffer_len,
                    &mut nt_offset,
                    ptr::null_mut(),
                ))?;

                Ok(iosb.Information)
            }
        }
    }

    pub fn pwrite(
        &self,
        buffer: &[u8],
        offset: lx::off_t,
        thread_uid: lx::uid_t,
    ) -> lx::Result<usize> {
        unsafe {
            // When metadata is enabled, the Linux behavior of clearing set-user-ID and set-group-ID
            // on write must be emulated. This should actually be based on CAP_FSETID, but that
            // information is not available so simply check for the root user instead.
            // For performance, this is not checked every time, so if the mode is changed external
            // to this LxFile, it will not be reset.
            if self.state.options.metadata
                && thread_uid != 0
                && self.kill_priv.swap(false, Ordering::AcqRel)
            {
                let stat = self.fstat()?;
                if stat.mode & (lx::S_ISUID | lx::S_ISGID) != 0 {
                    let mut attr = SetAttributes::default();
                    attr.mode = Some(stat.mode & !(lx::S_ISUID | lx::S_ISGID));
                    self.set_attr(attr)?;
                }
            }

            let mut iosb = mem::zeroed();
            let buffer_ptr = buffer.as_ptr() as *mut ffi::c_void;
            let buffer_len = buffer.len().try_into().map_err(|_| lx::Error::EINVAL)?;

            let mut nt_offset: ntdef::LARGE_INTEGER = mem::zeroed();
            *nt_offset.QuadPart_mut() = offset;

            // TODO: Async I/O.
            util::check_status_rw(ntioapi::NtWriteFile(
                self.handle.as_raw_handle(),
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                &mut iosb,
                buffer_ptr,
                buffer_len,
                &mut nt_offset,
                ptr::null_mut(),
            ))?;

            Ok(iosb.Information)
        }
    }

    pub fn read_dir<F>(&mut self, offset: lx::off_t, mut callback: F) -> lx::Result<()>
    where
        F: FnMut(lx::DirEntry) -> lx::Result<bool>,
    {
        if self.enumerator.is_none() {
            self.enumerator = Some(readdir::DirectoryEnumerator::new(false)?);
        }

        let enumerator = self.enumerator.as_mut().unwrap();
        let mut local_offset = offset;

        // Write the . and .. entries, since lxutil doesn't return them.
        if !Self::process_dot_entries(&mut local_offset, &mut callback)? {
            return Ok(());
        }

        assert!(local_offset >= DOT_ENTRY_COUNT);

        let mut offset = local_offset - DOT_ENTRY_COUNT;
        enumerator.read_dir(
            &self.handle,
            &self.state.fs_context,
            &mut offset,
            &mut callback,
        )?;

        Ok(())
    }

    pub fn fsync(&self, data_only: bool) -> lx::Result<()> {
        // Linux allows using fsync on files that have been opened read-only, while
        // Windows does not, so reopen the file if necessary.
        let mut _reopened = None;
        let handle = if self.access & (winnt::FILE_WRITE_DATA | winnt::FILE_APPEND_DATA) != 0 {
            &self.handle
        } else {
            let file = match util::reopen_file(&self.handle, winnt::FILE_WRITE_DATA) {
                Ok(file) => file,
                // If FILE_WRITE_DATA failed, try again with FILE_APPEND_DATA
                Err(_) => match util::reopen_file(&self.handle, winnt::FILE_APPEND_DATA) {
                    Ok(file) => file,
                    Err(e) => {
                        // If this failed due to an access denied, just return success because on
                        // Linux this is supposed to succeed with read-only access and some
                        // applications break if it doesn't.
                        if e.value() == lx::EACCES {
                            return Ok(());
                        }

                        return Err(e);
                    }
                },
            };

            _reopened = Some(file);
            _reopened.as_ref().unwrap()
        };

        let flags = if data_only {
            winnt::FLUSH_FLAGS_FILE_DATA_ONLY
        } else {
            0
        };

        unsafe {
            let mut iosb = mem::zeroed();
            let _ = util::check_status(Foundation::NTSTATUS(ntioapi::NtFlushBuffersFileEx(
                handle.as_raw_handle(),
                flags,
                ptr::null_mut(),
                0,
                &mut iosb,
            )))?;
        }

        Ok(())
    }

    // Helper to emit the . and .. entries.
    fn process_dot_entries<F>(offset: &mut lx::off_t, callback: &mut F) -> lx::Result<bool>
    where
        F: FnMut(lx::DirEntry) -> lx::Result<bool>,
    {
        if *offset == 0
            && !Self::process_dir_entry(offset, callback, 0, lx::LxString::from("."), lx::DT_DIR)?
        {
            return Ok(false);
        }

        if *offset == 1
            && !Self::process_dir_entry(offset, callback, 0, lx::LxString::from(".."), lx::DT_DIR)?
        {
            return Ok(false);
        }

        Ok(true)
    }

    // Helper to call the user's closure for a directory
    fn process_dir_entry<F>(
        offset: &mut lx::off_t,
        callback: &mut F,
        inode_nr: ntdef::ULONGLONG,
        name: lx::LxString,
        file_type: u8,
    ) -> lx::Result<bool>
    where
        F: FnMut(lx::DirEntry) -> lx::Result<bool>,
    {
        let entry = lx::DirEntry {
            name,
            inode_nr,
            offset: *offset + 1, // Pass the offset of the next entry.
            file_type,
        };

        let result = (callback)(entry)?;

        // Update the offset only if the user wants to continue.
        if result {
            *offset += 1;
        }

        Ok(result)
    }
}

// Symbolic link type.
pub enum SymlinkType {
    Lx,
    Nt(bool), // True for directory links; false for file links.
}
