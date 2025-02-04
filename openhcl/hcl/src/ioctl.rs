// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interface to `mshv_vtl` driver.

// Used to implement the [`private::BackingPrivate`] trait.
#![allow(private_interfaces)]

mod deferred;

pub mod aarch64;
pub mod snp;
pub mod tdx;
pub mod x64;

use self::deferred::DeferredActionSlots;
use self::deferred::DeferredActions;
use self::ioctls::*;
use crate::ioctl::deferred::DeferredAction;
use crate::protocol;
use crate::protocol::hcl_intr_offload_flags;
use crate::protocol::hcl_run;
use crate::protocol::EnterModes;
use crate::protocol::HCL_REG_PAGE_OFFSET;
use crate::protocol::HCL_VMSA_GUEST_VSM_PAGE_OFFSET;
use crate::protocol::HCL_VMSA_PAGE_OFFSET;
use crate::protocol::MSHV_APIC_PAGE_OFFSET;
use crate::GuestVtl;
use hvdef::hypercall::AssertVirtualInterrupt;
use hvdef::hypercall::HostVisibilityType;
use hvdef::hypercall::HvGpaRange;
use hvdef::hypercall::HvGpaRangeExtended;
use hvdef::hypercall::HvInputVtl;
use hvdef::hypercall::HvInterceptParameters;
use hvdef::hypercall::HvInterceptType;
use hvdef::hypercall::HvRegisterAssoc;
use hvdef::hypercall::HypercallOutput;
use hvdef::hypercall::InitialVpContextX64;
use hvdef::hypercall::ModifyHostVisibility;
use hvdef::HvAllArchRegisterName;
#[cfg(guest_arch = "aarch64")]
use hvdef::HvArm64RegisterName;
use hvdef::HvError;
use hvdef::HvMapGpaFlags;
use hvdef::HvMessage;
use hvdef::HvRegisterName;
use hvdef::HvRegisterValue;
use hvdef::HvRegisterVsmPartitionConfig;
use hvdef::HvStatus;
use hvdef::HvX64RegisterName;
use hvdef::HvX64RegisterPage;
use hvdef::HypercallCode;
use hvdef::Vtl;
use hvdef::HV_PAGE_SIZE;
use hvdef::HV_PARTITION_ID_SELF;
use hvdef::HV_VP_INDEX_SELF;
use memory_range::MemoryRange;
use pal::unix::pthread::*;
use parking_lot::Mutex;
use private::BackingPrivate;
use sidecar_client::NewSidecarClientError;
use sidecar_client::SidecarClient;
use sidecar_client::SidecarRun;
use sidecar_client::SidecarVp;
use std::cell::RefCell;
use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::os::unix::prelude::*;
use std::ptr::addr_of;
use std::ptr::addr_of_mut;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Once;
use thiserror::Error;
use x86defs::snp::SevVmsa;
use x86defs::tdx::TdCallResultCode;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// Error returned by HCL operations.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum Error {
    #[error("failed to open mshv device")]
    OpenMshv(#[source] io::Error),
    #[error("failed to open hvcall device")]
    OpenHvcall(#[source] io::Error),
    #[error("failed to open lower VTL memory device")]
    OpenGpa(#[source] io::Error),
    #[error("ReturnToLowerVtl")]
    ReturnToLowerVtl(#[source] nix::Error),
    #[error("AddVtl0Memory")]
    AddVtl0Memory(#[source] nix::Error),
    #[error("hcl_set_vp_register")]
    SetVpRegister(#[source] nix::Error),
    #[error("hcl_get_vp_register")]
    GetVpRegister(#[source] nix::Error),
    #[error("failed to get VP register {reg:#x?} from hypercall")]
    GetVpRegisterHypercall {
        #[cfg(guest_arch = "x86_64")]
        reg: HvX64RegisterName,
        #[cfg(guest_arch = "aarch64")]
        reg: HvArm64RegisterName,
        #[source]
        err: HvError,
    },
    #[error("hcl_request_interrupt")]
    RequestInterrupt(#[source] HvError),
    #[error("hcl_cancel_vp failed")]
    CancelVp(#[source] nix::Error),
    #[error("failed to signal event")]
    SignalEvent(#[source] HvError),
    #[error("failed to post message")]
    PostMessage(#[source] HvError),
    #[error("failed to mmap the vp context {:?}", .1.map(|vtl| format!("for VTL {:?}", vtl)).unwrap_or("".to_string()))]
    MmapVp(#[source] io::Error, Option<Vtl>),
    #[error("failed to set the poll file")]
    SetPollFile(#[source] nix::Error),
    #[error("failed to check hcl capabilities")]
    CheckExtensions(#[source] nix::Error),
    #[error("failed to mmap the register page")]
    MmapRegPage(#[source] io::Error),
    #[error("invalid num signal events")]
    NumSignalEvent(#[source] io::Error),
    #[error("failed to create vtl")]
    CreateVTL(#[source] nix::Error),
    #[error("Gva to gpa translation failed")]
    TranslateGvaToGpa(#[source] TranslateGvaToGpaError),
    #[error("gpa failed vtl access check")]
    CheckVtlAccess(#[source] HvError),
    #[error("failed to set registers using set_vp_registers hypercall")]
    SetRegisters(#[source] HvError),
    #[error("Unknown register name: {0:x}")]
    UnknownRegisterName(u32),
    #[error("Invalid register value")]
    InvalidRegisterValue,
    #[error("failed to set host visibility")]
    SetHostVisibility(#[source] nix::Error),
    #[error("failed to allocate host overlay page")]
    HostOverlayPageExhausted,
    #[error("sidecar error")]
    Sidecar(#[source] sidecar_client::SidecarError),
    #[error("failed to open sidecar")]
    OpenSidecar(#[source] NewSidecarClientError),
    #[error("mismatch between requested isolation type {requested:?} and supported isolation type {supported:?}")]
    MismatchedIsolation {
        supported: IsolationType,
        requested: IsolationType,
    },
}

/// Error for IOCTL errors specifically.
#[derive(Debug, Error)]
#[error("hcl request failed")]
pub struct IoctlError(#[source] pub(crate) nix::Error);

/// Error returned when issuing hypercalls.
#[derive(Debug, Error)]
#[expect(missing_docs)]
pub enum HypercallError {
    #[error("hypercall failed with {0:?}")]
    Hypervisor(HvError),
    #[error("ioctl failed")]
    Ioctl(#[source] IoctlError),
}

impl HypercallError {
    pub(crate) fn check(r: Result<i32, nix::Error>) -> Result<(), Self> {
        match r {
            Ok(n) => HvStatus(n.try_into().expect("hypervisor result out of range"))
                .result()
                .map_err(Self::Hypervisor),
            Err(err) => Err(Self::Ioctl(IoctlError(err))),
        }
    }
}

/// Errors when issuing hypercalls via the kernel direct interface.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum HvcallError {
    #[error("kernel rejected the hypercall, most likely due to the hypercall code not being allowed via set_allowed_hypercalls")]
    HypercallIoctlFailed(#[source] nix::Error),
    #[error("input parameters are larger than a page")]
    InputParametersTooLarge,
    #[error("output parameters are larger than a page")]
    OutputParametersTooLarge,
    #[error("output and input list lengths do not match")]
    InputOutputRepListMismatch,
}

/// Error applying VTL protections.
// TODO: move to `underhill_mem`.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum ApplyVtlProtectionsError {
    #[error(
        "hypervisor returned {output:?} error {hv_error:?} when protecting pages {range} for vtl {vtl:?}"
    )]
    Hypervisor {
        range: MemoryRange,
        output: HypercallOutput,
        #[source]
        hv_error: HvError,
        vtl: HvInputVtl,
    },
    #[error(
        "{failed_operation} when protecting pages {range} with {permissions:x?} for vtl {vtl:?}"
    )]
    Snp {
        #[source]
        failed_operation: snp::SnpPageError,
        range: MemoryRange,
        permissions: x86defs::snp::SevRmpAdjust,
        vtl: HvInputVtl,
    },
    #[error("tdcall failed with {error:?} when protecting pages {range} with permissions {permissions:x?} for vtl {vtl:?}")]
    Tdx {
        error: TdCallResultCode,
        range: MemoryRange,
        permissions: x86defs::tdx::TdgMemPageGpaAttr,
        vtl: HvInputVtl,
    },
    #[error("no valid protections for vtl {0:?}")]
    InvalidVtl(Vtl),
}

/// Error setting guest VSM configuration.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum SetGuestVsmConfigError {
    #[error(
        "hypervisor returned error {hv_error:?} when configuring guest vsm {enable_guest_vsm:?}"
    )]
    Hypervisor {
        enable_guest_vsm: bool,
        hv_error: HvError,
    },
}

/// Error getting the VP idnex from an APIC ID.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum GetVpIndexFromApicIdError {
    #[error("hypervisor returned error {hv_error:?} when querying vp index for {apic_id}")]
    Hypervisor { hv_error: HvError, apic_id: u32 },
}

/// Error setting VSM partition configuration.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum SetVsmPartitionConfigError {
    #[error(
        "hypervisor returned error {hv_error:?} when configuring vsm partition config {config:?}"
    )]
    Hypervisor {
        config: HvRegisterVsmPartitionConfig,
        hv_error: HvError,
    },
}

/// Error translating a GVA to a GPA.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum TranslateGvaToGpaError {
    #[error("hypervisor returned error {hv_error:?} on gva {gva:x}")]
    Hypervisor { gva: u64, hv_error: HvError },
    #[error("sidecar kernel failed on gva {gva:x}")]
    Sidecar {
        gva: u64,
        #[source]
        error: sidecar_client::SidecarError,
    },
}

/// Result from [`Hcl::check_vtl_access`] if vtl permissions were violated
#[derive(Debug)]
pub struct CheckVtlAccessResult {
    /// The intercepting VTL.
    pub vtl: Vtl,
    /// The flags that were denied.
    pub denied_flags: HvMapGpaFlags,
}

/// Error accepting pages.
// TODO: move to `underhill_mem`.
#[derive(Error, Debug)]
#[expect(missing_docs)]
pub enum AcceptPagesError {
    #[error("hypervisor returned {output:?} error {hv_error:?} when accepting pages {range}")]
    Hypervisor {
        range: MemoryRange,
        output: HypercallOutput,
        hv_error: HvError,
    },
    #[error("{failed_operation} when protecting pages {range}")]
    Snp {
        failed_operation: snp::SnpPageError,
        range: MemoryRange,
    },
    #[error("tdcall failed with {error:?} when accepting pages {range}")]
    Tdx {
        error: tdcall::AcceptPagesError,
        range: MemoryRange,
    },
}

// Action translation(to HVCALL) for pin/unpin GPA range.
#[derive(Debug, Copy, Clone)]
enum GpaPinUnpinAction {
    PinGpaRange,
    UnpinGpaRange,
}

/// Error pinning a GPA.
#[derive(Error, Debug)]
#[error("partial success: {ranges_processed} operations succeeded, but encountered an error")]
struct PinUnpinError {
    ranges_processed: usize,
    error: HvError,
}

/// Result of translate gva hypercall from [`Hcl`]
pub struct TranslateResult {
    /// The GPA that the GVA translated to.
    pub gpa_page: u64,
    /// Whether the page was an overlay page.
    pub overlay_page: bool, // Note: hardcoded to false on WHP
}

/// Possible types for rep hypercalls
enum HvcallRepInput<'a, T> {
    /// The actual elements to rep over
    Elements(&'a [T]),
    /// The elements for the rep are implied and only a count is needed
    Count(u16),
}

mod ioctls {
    #![allow(non_camel_case_types)]

    use crate::protocol;
    use hvdef::hypercall::HvRegisterAssoc;
    use nix::ioctl_none;
    use nix::ioctl_read;
    use nix::ioctl_readwrite;
    use nix::ioctl_write_ptr;

    // The unsafe interface to the `mshv` kernel module comprises
    // the following IOCTLs.
    const MSHV_IOCTL: u8 = 0xb8;
    const MSHV_VTL_RETURN_TO_LOWER_VTL: u16 = 0x27;
    const MSHV_SET_VP_REGISTERS: u16 = 0x6;
    const MSHV_GET_VP_REGISTERS: u16 = 0x5;
    const MSHV_HVCALL_SETUP: u16 = 0x1E;
    const MSHV_HVCALL: u16 = 0x1F;
    const MSHV_VTL_ADD_VTL0_MEMORY: u16 = 0x21;
    const MSHV_VTL_SET_POLL_FILE: u16 = 0x25;
    const MSHV_CREATE_VTL: u16 = 0x1D;
    const MSHV_CHECK_EXTENSION: u16 = 0x00;
    const MSHV_VTL_PVALIDATE: u16 = 0x28;
    const MSHV_VTL_RMPADJUST: u16 = 0x29;
    const MSHV_VTL_TDCALL: u16 = 0x32;
    const MSHV_VTL_READ_VMX_CR4_FIXED1: u16 = 0x33;
    const MSHV_VTL_GUEST_VSM_VMSA_PFN: u16 = 0x34;
    const MSHV_VTL_RMPQUERY: u16 = 0x35;
    const MSHV_INVLPGB: u16 = 0x36;
    const MSHV_TLBSYNC: u16 = 0x37;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct mshv_vp_registers {
        pub count: ::std::os::raw::c_int,
        pub regs: *mut HvRegisterAssoc,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct mshv_pvalidate {
        /// Execute the pvalidate instruction on the set of memory pages specified
        pub start_pfn: ::std::os::raw::c_ulonglong,
        pub page_count: ::std::os::raw::c_ulonglong,
        pub validate: ::std::os::raw::c_uchar,
        pub terminate_on_failure: ::std::os::raw::c_uchar,
        /// Set to 1 if the page is RAM (from the kernel's perspective), 0 if
        /// it's device memory.
        pub ram: u8,
        pub padding: [::std::os::raw::c_uchar; 1],
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct mshv_rmpadjust {
        /// Execute the rmpadjust instruction on the set of memory pages specified
        pub start_pfn: ::std::os::raw::c_ulonglong,
        pub page_count: ::std::os::raw::c_ulonglong,
        pub value: ::std::os::raw::c_ulonglong,
        pub terminate_on_failure: ::std::os::raw::c_uchar,
        /// Set to 1 if the page is RAM (from the kernel's perspective), 0 if
        /// it's device memory.
        pub ram: u8,
        pub padding: [::std::os::raw::c_uchar; 6],
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct mshv_rmpquery {
        /// Execute the rmpquery instruction on the set of memory pages specified
        pub start_pfn: ::std::os::raw::c_ulonglong,
        pub page_count: ::std::os::raw::c_ulonglong,
        pub terminate_on_failure: ::std::os::raw::c_uchar,
        /// Set to 1 if the page is RAM (from the kernel's perspective), 0 if
        /// it's device memory.
        pub ram: u8,
        pub padding: [::std::os::raw::c_uchar; 6],
        /// Output array for the flags, must have at least `page_count` entries.
        pub flags: *mut ::std::os::raw::c_ulonglong,
        /// Output array for the page sizes, must have at least `page_count` entries.
        pub page_size: *mut ::std::os::raw::c_ulonglong,
        /// Output for the amount of pages processed, a scalar.
        pub pages_processed: *mut ::std::os::raw::c_ulonglong,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct mshv_tdcall {
        pub rax: u64, // Call code and returned status
        pub rcx: u64,
        pub rdx: u64,
        pub r8: u64,
        pub r9: u64,
        pub r10_out: u64, // only supported as output
        pub r11_out: u64, // only supported as output
    }

    ioctl_none!(
        /// Relinquish the processor to VTL0.
        hcl_return_to_lower_vtl,
        MSHV_IOCTL,
        MSHV_VTL_RETURN_TO_LOWER_VTL
    );

    ioctl_write_ptr!(
        /// Set a VTL0 register for the current processor of the current
        /// partition.
        /// It is not allowed to set registers for other processors or
        /// other partitions for the security and coherency reasons.
        hcl_set_vp_register,
        MSHV_IOCTL,
        MSHV_SET_VP_REGISTERS,
        mshv_vp_registers
    );

    ioctl_readwrite!(
        /// Get a VTL0 register for the current processor of the current
        /// partition.
        /// It is not allowed to get registers of other processors or
        /// other partitions for the security and coherency reasons.
        hcl_get_vp_register,
        MSHV_IOCTL,
        MSHV_GET_VP_REGISTERS,
        mshv_vp_registers
    );

    ioctl_write_ptr!(
        /// Adds the VTL0 memory as a ZONE_DEVICE memory (I/O) to support
        /// DMA from the guest.
        hcl_add_vtl0_memory,
        MSHV_IOCTL,
        MSHV_VTL_ADD_VTL0_MEMORY,
        protocol::hcl_pfn_range_t
    );

    ioctl_write_ptr!(
        /// Sets the file to be polled while running a VP in VTL0. If the file
        /// becomes readable, then the VP run will be cancelled.
        hcl_set_poll_file,
        MSHV_IOCTL,
        MSHV_VTL_SET_POLL_FILE,
        protocol::hcl_set_poll_file
    );

    ioctl_write_ptr!(
        /// Sets up the hypercall allow map. Allowed once
        /// per fd.
        hcl_hvcall_setup,
        MSHV_IOCTL,
        MSHV_HVCALL_SETUP,
        protocol::hcl_hvcall_setup
    );

    ioctl_readwrite!(
        /// Performs a hypercall from the user mode.
        hcl_hvcall,
        MSHV_IOCTL,
        MSHV_HVCALL,
        protocol::hcl_hvcall
    );

    ioctl_write_ptr!(
        /// Executes the pvalidate instruction on a page range.
        hcl_pvalidate_pages,
        MSHV_IOCTL,
        MSHV_VTL_PVALIDATE,
        mshv_pvalidate
    );

    ioctl_write_ptr!(
        /// Executes the rmpadjust instruction on a page range.
        hcl_rmpadjust_pages,
        MSHV_IOCTL,
        MSHV_VTL_RMPADJUST,
        mshv_rmpadjust
    );

    ioctl_write_ptr!(
        /// Executes the rmpquery instruction on a page range.
        hcl_rmpquery_pages,
        MSHV_IOCTL,
        MSHV_VTL_RMPQUERY,
        mshv_rmpquery
    );

    ioctl_readwrite!(
        /// Executes a tdcall.
        hcl_tdcall,
        MSHV_IOCTL,
        MSHV_VTL_TDCALL,
        mshv_tdcall
    );

    ioctl_read!(
        hcl_read_vmx_cr4_fixed1,
        MSHV_IOCTL,
        MSHV_VTL_READ_VMX_CR4_FIXED1,
        u64
    );

    ioctl_readwrite!(
        hcl_read_guest_vsm_page_pfn,
        MSHV_IOCTL,
        MSHV_VTL_GUEST_VSM_VMSA_PFN,
        u64
    );

    pub const HCL_CAP_REGISTER_PAGE: u32 = 1;
    pub const HCL_CAP_VTL_RETURN_ACTION: u32 = 2;
    pub const HCL_CAP_DR6_SHARED: u32 = 3;

    ioctl_write_ptr!(
        /// Check for the presence of an extension capability.
        hcl_check_extension,
        MSHV_IOCTL,
        MSHV_CHECK_EXTENSION,
        u32
    );

    ioctl_read!(mshv_create_vtl, MSHV_IOCTL, MSHV_CREATE_VTL, u8);

    #[repr(C)]
    pub struct mshv_invlpgb {
        pub rax: u64,
        pub _pad0: u32,
        pub edx: u32,
        pub _pad1: u32,
        pub ecx: u32,
    }

    ioctl_write_ptr!(
        /// Issue an INVLPGB instruction.
        hcl_invlpgb,
        MSHV_IOCTL,
        MSHV_INVLPGB,
        mshv_invlpgb
    );

    ioctl_none!(
        /// Issue a TLBSYNC instruction.
        hcl_tlbsync,
        MSHV_IOCTL,
        MSHV_TLBSYNC
    );
}

/// The `/dev/mshv_vtl_low` device for accessing VTL0 memory.
pub struct MshvVtlLow {
    file: File,
}

impl MshvVtlLow {
    /// Opens the device.
    pub fn new() -> Result<Self, Error> {
        let file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mshv_vtl_low")
            .map_err(Error::OpenGpa)?;

        Ok(Self { file: file.into() })
    }

    /// Gets the device file.
    pub fn get(&self) -> &File {
        &self.file
    }

    /// The flag to set in the file offset to map guest memory as shared instead
    /// of private.
    pub const SHARED_MEMORY_FLAG: u64 = 1 << 63;
}

/// An open `/dev/mshv` device file.
pub struct Mshv {
    file: File,
}

impl Mshv {
    /// Opens the mshv device.
    pub fn new() -> Result<Self, Error> {
        let file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mshv")
            .map_err(Error::OpenMshv)?;

        Ok(Self { file: file.into() })
    }

    fn check_extension(&self, cap: u32) -> Result<bool, Error> {
        // SAFETY: calling IOCTL as documented, with no special requirements.
        let supported = unsafe {
            hcl_check_extension(self.file.as_raw_fd(), &cap).map_err(Error::CheckExtensions)?
        };
        Ok(supported != 0)
    }

    /// Opens an mshv_vtl device file.
    pub fn create_vtl(&self) -> Result<MshvVtl, Error> {
        let cap = &mut 0_u8;
        // SAFETY: calling IOCTL as documented, with no special requirements.
        let supported =
            unsafe { mshv_create_vtl(self.file.as_raw_fd(), cap).map_err(Error::CreateVTL)? };
        // SAFETY: calling IOCTL as documented, with no special requirements.
        let vtl_file = unsafe { File::from_raw_fd(supported) };
        Ok(MshvVtl { file: vtl_file })
    }
}

/// An open mshv_vtl device file.
#[derive(Debug)]
pub struct MshvVtl {
    file: File,
}

impl MshvVtl {
    /// Adds the VTL0 memory as a ZONE_DEVICE memory (I/O) to support DMA from the guest.
    pub fn add_vtl0_memory(&self, mem_range: MemoryRange, shared: bool) -> Result<(), Error> {
        let flags = if shared {
            MshvVtlLow::SHARED_MEMORY_FLAG / HV_PAGE_SIZE
        } else {
            0
        };
        let ram_disposition = protocol::hcl_pfn_range_t {
            start_pfn: mem_range.start_4k_gpn() | flags,
            last_pfn: mem_range.end_4k_gpn(),
        };

        // SAFETY: calling IOCTL as documented, with no special requirements.
        unsafe {
            hcl_add_vtl0_memory(self.file.as_raw_fd(), &ram_disposition)
                .map_err(Error::AddVtl0Memory)?;
        }

        Ok(())
    }
}

#[cfg(guest_arch = "x86_64")]
fn is_vtl_shared_mtrr(reg: HvX64RegisterName) -> bool {
    matches!(
        reg,
        HvX64RegisterName::MsrMtrrCap
            | HvX64RegisterName::MsrMtrrDefType
            | HvX64RegisterName::MsrMtrrPhysBase0
            | HvX64RegisterName::MsrMtrrPhysBase1
            | HvX64RegisterName::MsrMtrrPhysBase2
            | HvX64RegisterName::MsrMtrrPhysBase3
            | HvX64RegisterName::MsrMtrrPhysBase4
            | HvX64RegisterName::MsrMtrrPhysBase5
            | HvX64RegisterName::MsrMtrrPhysBase6
            | HvX64RegisterName::MsrMtrrPhysBase7
            | HvX64RegisterName::MsrMtrrPhysBase8
            | HvX64RegisterName::MsrMtrrPhysBase9
            | HvX64RegisterName::MsrMtrrPhysBaseA
            | HvX64RegisterName::MsrMtrrPhysBaseB
            | HvX64RegisterName::MsrMtrrPhysBaseC
            | HvX64RegisterName::MsrMtrrPhysBaseD
            | HvX64RegisterName::MsrMtrrPhysBaseE
            | HvX64RegisterName::MsrMtrrPhysBaseF
            | HvX64RegisterName::MsrMtrrPhysMask0
            | HvX64RegisterName::MsrMtrrPhysMask1
            | HvX64RegisterName::MsrMtrrPhysMask2
            | HvX64RegisterName::MsrMtrrPhysMask3
            | HvX64RegisterName::MsrMtrrPhysMask4
            | HvX64RegisterName::MsrMtrrPhysMask5
            | HvX64RegisterName::MsrMtrrPhysMask6
            | HvX64RegisterName::MsrMtrrPhysMask7
            | HvX64RegisterName::MsrMtrrPhysMask8
            | HvX64RegisterName::MsrMtrrPhysMask9
            | HvX64RegisterName::MsrMtrrPhysMaskA
            | HvX64RegisterName::MsrMtrrPhysMaskB
            | HvX64RegisterName::MsrMtrrPhysMaskC
            | HvX64RegisterName::MsrMtrrPhysMaskD
            | HvX64RegisterName::MsrMtrrPhysMaskE
            | HvX64RegisterName::MsrMtrrPhysMaskF
            | HvX64RegisterName::MsrMtrrFix64k00000
            | HvX64RegisterName::MsrMtrrFix16k80000
            | HvX64RegisterName::MsrMtrrFix16kA0000
            | HvX64RegisterName::MsrMtrrFix4kC0000
            | HvX64RegisterName::MsrMtrrFix4kC8000
            | HvX64RegisterName::MsrMtrrFix4kD0000
            | HvX64RegisterName::MsrMtrrFix4kD8000
            | HvX64RegisterName::MsrMtrrFix4kE0000
            | HvX64RegisterName::MsrMtrrFix4kE8000
            | HvX64RegisterName::MsrMtrrFix4kF0000
            | HvX64RegisterName::MsrMtrrFix4kF8000
    )
}

/// Indicate whether reg is shared across VTLs.
///
/// This function is not complete: DR6 may or may not be shared, depending on
/// the processor type; the caller needs to check HvRegisterVsmCapabilities.
/// Some MSRs are not included here as they are not represented in
/// HvX64RegisterName, including MSR_TSC_FREQUENCY, MSR_MCG_CAP,
/// MSR_MCG_STATUS, MSR_RESET, MSR_GUEST_IDLE, and MSR_DEBUG_DEVICE_OPTIONS.
#[cfg(guest_arch = "x86_64")]
fn is_vtl_shared_reg(reg: HvX64RegisterName) -> bool {
    is_vtl_shared_mtrr(reg)
        || matches!(
            reg,
            HvX64RegisterName::VpIndex
                | HvX64RegisterName::VpRuntime
                | HvX64RegisterName::TimeRefCount
                | HvX64RegisterName::Rax
                | HvX64RegisterName::Rbx
                | HvX64RegisterName::Rcx
                | HvX64RegisterName::Rdx
                | HvX64RegisterName::Rsi
                | HvX64RegisterName::Rdi
                | HvX64RegisterName::Rbp
                | HvX64RegisterName::Cr2
                | HvX64RegisterName::R8
                | HvX64RegisterName::R9
                | HvX64RegisterName::R10
                | HvX64RegisterName::R11
                | HvX64RegisterName::R12
                | HvX64RegisterName::R13
                | HvX64RegisterName::R14
                | HvX64RegisterName::R15
                | HvX64RegisterName::Dr0
                | HvX64RegisterName::Dr1
                | HvX64RegisterName::Dr2
                | HvX64RegisterName::Dr3
                | HvX64RegisterName::Xmm0
                | HvX64RegisterName::Xmm1
                | HvX64RegisterName::Xmm2
                | HvX64RegisterName::Xmm3
                | HvX64RegisterName::Xmm4
                | HvX64RegisterName::Xmm5
                | HvX64RegisterName::Xmm6
                | HvX64RegisterName::Xmm7
                | HvX64RegisterName::Xmm8
                | HvX64RegisterName::Xmm9
                | HvX64RegisterName::Xmm10
                | HvX64RegisterName::Xmm11
                | HvX64RegisterName::Xmm12
                | HvX64RegisterName::Xmm13
                | HvX64RegisterName::Xmm14
                | HvX64RegisterName::Xmm15
                | HvX64RegisterName::FpMmx0
                | HvX64RegisterName::FpMmx1
                | HvX64RegisterName::FpMmx2
                | HvX64RegisterName::FpMmx3
                | HvX64RegisterName::FpMmx4
                | HvX64RegisterName::FpMmx5
                | HvX64RegisterName::FpMmx6
                | HvX64RegisterName::FpMmx7
                | HvX64RegisterName::FpControlStatus
                | HvX64RegisterName::XmmControlStatus
                | HvX64RegisterName::Xfem
        )
}

/// Indicate whether reg is shared across VTLs.
#[cfg(guest_arch = "aarch64")]
fn is_vtl_shared_reg(reg: HvArm64RegisterName) -> bool {
    use hvdef::HvArm64RegisterName;

    matches!(
        reg,
        HvArm64RegisterName::X0
            | HvArm64RegisterName::X1
            | HvArm64RegisterName::X2
            | HvArm64RegisterName::X3
            | HvArm64RegisterName::X4
            | HvArm64RegisterName::X5
            | HvArm64RegisterName::X6
            | HvArm64RegisterName::X7
            | HvArm64RegisterName::X8
            | HvArm64RegisterName::X9
            | HvArm64RegisterName::X10
            | HvArm64RegisterName::X11
            | HvArm64RegisterName::X12
            | HvArm64RegisterName::X13
            | HvArm64RegisterName::X14
            | HvArm64RegisterName::X15
            | HvArm64RegisterName::X16
            | HvArm64RegisterName::X17
            | HvArm64RegisterName::X19
            | HvArm64RegisterName::X20
            | HvArm64RegisterName::X21
            | HvArm64RegisterName::X22
            | HvArm64RegisterName::X23
            | HvArm64RegisterName::X24
            | HvArm64RegisterName::X25
            | HvArm64RegisterName::X26
            | HvArm64RegisterName::X27
            | HvArm64RegisterName::X28
            | HvArm64RegisterName::XFp
            | HvArm64RegisterName::XLr
    )
}

/// The `/dev/mshv_hvcall` device for issuing hypercalls directly to the
/// hypervisor.
#[derive(Debug)]
pub struct MshvHvcall(File);

impl MshvHvcall {
    /// Opens the device.
    pub fn new() -> Result<Self, Error> {
        let file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mshv_hvcall")
            .map_err(Error::OpenHvcall)?;

        Ok(Self(file.into()))
    }

    /// Set allowed hypercalls.
    pub fn set_allowed_hypercalls(&self, codes: &[HypercallCode]) {
        type ItemType = u64;
        let item_size_bytes = size_of::<ItemType>();
        let item_size_bits = item_size_bytes * 8;

        let mut allow_bitmap = Vec::<ItemType>::new();
        for &code in codes {
            let map_index = (code.0 as usize) / item_size_bits;
            if map_index >= allow_bitmap.len() {
                allow_bitmap.resize(map_index + 1, 0);
            }
            allow_bitmap[map_index] |= (1 as ItemType) << (code.0 % item_size_bits as u16);
        }

        let hvcall_setup = protocol::hcl_hvcall_setup {
            allow_bitmap_size: (allow_bitmap.len() * item_size_bytes) as u64,
            allow_bitmap_ptr: allow_bitmap.as_ptr(),
        };

        // SAFETY: following the IOCTL definition.
        unsafe {
            hcl_hvcall_setup(self.0.as_raw_fd(), &hvcall_setup)
                .expect("Hypercall setup IOCTL must be supported");
        }
    }

    /// Accepts VTL 0 pages with no host visibility.
    ///
    /// [`HypercallCode::HvCallAcceptGpaPages`] must be allowed.
    pub fn accept_gpa_pages(
        &self,
        range: MemoryRange,
        memory_type: hvdef::hypercall::AcceptMemoryType,
    ) -> Result<(), AcceptPagesError> {
        const MAX_INPUT_ELEMENTS: usize = (HV_PAGE_SIZE as usize
            - size_of::<hvdef::hypercall::AcceptGpaPages>())
            / size_of::<u64>();

        let span = tracing::span!(tracing::Level::INFO, "accept_pages", ?range);
        let _enter = span.enter();

        let mut current_page = range.start() / HV_PAGE_SIZE;
        let end = range.end() / HV_PAGE_SIZE;

        while current_page < end {
            let header = hvdef::hypercall::AcceptGpaPages {
                partition_id: HV_PARTITION_ID_SELF,
                page_attributes: hvdef::hypercall::AcceptPagesAttributes::new()
                    .with_memory_type(memory_type.0)
                    .with_host_visibility(HostVisibilityType::PRIVATE)
                    .with_vtl_set(0), // vtl protections cannot be applied for VTL 0 memory
                vtl_permission_set: hvdef::hypercall::VtlPermissionSet {
                    vtl_permission_from_1: [0; hvdef::hypercall::HV_VTL_PERMISSION_SET_SIZE],
                },
                gpa_page_base: current_page,
            };

            let remaining_pages = end - current_page;
            let count = remaining_pages.min(MAX_INPUT_ELEMENTS as u64);

            // SAFETY: The input header and rep slice are the correct types for
            //         this hypercall. A dummy type of u8 is provided to satisfy
            //         the compiler for input and output rep type. The given
            //         input and slices are valid references while this function
            //         is called.
            //
            //         The hypercall output is validated right after the hypercall is issued.
            let output = unsafe {
                self.hvcall_rep::<hvdef::hypercall::AcceptGpaPages, u8, u8>(
                    HypercallCode::HvCallAcceptGpaPages,
                    &header,
                    HvcallRepInput::Count(count as u16),
                    None,
                )
                .expect("kernel hypercall submission should always succeed")
            };

            output
                .result()
                .map_err(|err| AcceptPagesError::Hypervisor {
                    range: MemoryRange::from_4k_gpn_range(current_page..current_page + count),
                    output,
                    hv_error: err,
                })?;

            current_page += count;

            assert_eq!(output.elements_processed() as u64, count);
        }
        Ok(())
    }

    /// Modifies the host visibility of the given pages.
    ///
    /// [`HypercallCode::HvCallModifySparseGpaPageHostVisibility`] must be allowed.
    //
    // TODO SNP: this isn't really safe. Probably this should be an IOCTL in the
    // kernel so that it can validate the page ranges are VTL0 memory.
    pub fn modify_gpa_visibility(
        &self,
        host_visibility: HostVisibilityType,
        mut gpns: &[u64],
    ) -> Result<(), HvError> {
        const GPNS_PER_CALL: usize = (HV_PAGE_SIZE as usize
            - size_of::<hvdef::hypercall::ModifySparsePageVisibility>())
            / size_of::<u64>();

        while !gpns.is_empty() {
            let n = gpns.len().min(GPNS_PER_CALL);
            // SAFETY: The input header and rep slice are the correct types for this hypercall.
            //         The hypercall output is validated right after the hypercall is issued.
            let result = unsafe {
                self.hvcall_rep(
                    HypercallCode::HvCallModifySparseGpaPageHostVisibility,
                    &hvdef::hypercall::ModifySparsePageVisibility {
                        partition_id: HV_PARTITION_ID_SELF,
                        host_visibility: ModifyHostVisibility::new()
                            .with_host_visibility(host_visibility),
                        reserved: 0,
                    },
                    HvcallRepInput::Elements(&gpns[..n]),
                    None::<&mut [u8]>,
                )
                .unwrap()
            };

            match result.result() {
                Ok(()) => {
                    assert_eq!({ result.elements_processed() }, n);
                }
                Err(HvError::Timeout) => {}
                Err(e) => return Err(e),
            }
            gpns = &gpns[result.elements_processed()..];
        }
        Ok(())
    }

    /// Given a constructed hcl_hvcall protocol object, issues an IOCTL to invoke a hypercall via
    /// the direct hypercall kernel interface. This function will retry hypercalls if the hypervisor
    /// times out the hypercall.
    ///
    /// Input and output data are referenced as pointers in the call object.
    ///
    /// `Ok(HypercallOutput)` is returned if the kernel was successful in issuing the hypercall. A
    /// caller must check the return value for the result of the hypercall.
    ///
    /// Before invoking hypercalls, a list of hypercalls that are allowed
    /// has to be set with `Hcl::set_allowed_hypercalls`:
    /// ```ignore
    /// set_allowed_hypercalls(&[
    ///     hvdef::HypercallCode::HvCallCheckForIoIntercept,
    ///     hvdef::HypercallCode::HvCallInstallIntercept,
    /// ]);
    /// ```
    /// # Safety
    /// This function makes no guarantees that the given input header, input and output types are
    /// valid for the given hypercall. It is the caller's responsibility to use the correct types
    /// with the specified hypercall.
    ///
    /// The caller must ensure that the input and output data are valid for the lifetime of this
    /// call.
    ///
    /// A caller must check the returned [HypercallOutput] for success or failure from the
    /// hypervisor.
    ///
    /// Hardware isolated VMs cannot trust the output from the hypervisor and so it must be
    /// validated by the caller if needed.
    unsafe fn invoke_hvcall_ioctl(
        &self,
        mut call_object: protocol::hcl_hvcall,
    ) -> Result<HypercallOutput, HvcallError> {
        loop {
            // SAFETY: following the IOCTL definition. The data referenced in the call
            // lives as long as `self` does thus the lifetime elision doesn't contradict
            // the compiler's invariants.
            //
            // The hypervisor is trusted to fill out the output page with a valid
            // representation of an instance the output type, except in the case of hardware
            // isolated VMs where the caller must validate output as needed.
            unsafe {
                hcl_hvcall(self.0.as_raw_fd(), &mut call_object)
                    .map_err(HvcallError::HypercallIoctlFailed)?;
            }

            if call_object.status.call_status() == Err(HvError::Timeout).into() {
                // Any hypercall can timeout, even one that doesn't have reps. Continue processing
                // from wherever the hypervisor left off.  The rep start index isn't checked for
                // validity, since it is only being used as an input to the untrusted hypervisor.
                // This applies to both simple and rep hypercalls.
                call_object
                    .control
                    .set_rep_start(call_object.status.elements_processed());
            } else {
                if call_object.control.rep_count() == 0 {
                    // For non-rep hypercalls, the elements processed field should be 0.
                    assert_eq!(call_object.status.elements_processed(), 0);
                } else {
                    // Hardware isolated VMs cannot trust output from the hypervisor, but check for
                    // consistency between the number of elements processed and the expected count. A
                    // violation of this assertion indicates a buggy or malicious hypervisor.
                    assert!(
                        (call_object.status.result().is_ok()
                            && call_object.control.rep_count()
                                == call_object.status.elements_processed())
                            || (call_object.status.result().is_err()
                                && call_object.control.rep_count()
                                    > call_object.status.elements_processed())
                    );
                }

                return Ok(call_object.status);
            }
        }
    }

    /// Issues a non-rep hypercall to the hypervisor via the direct hypercall kernel interface.
    /// This is not intended to be used directly by external callers, rather via write safe hypercall wrappers.
    /// This call constructs the appropriate hypercall input control from the described parameters.
    ///
    /// `Ok(HypercallOutput)` is returned if the kernel was successful in issuing the hypercall. A caller must check the
    /// return value for the result of the hypercall.
    ///
    /// `code` is the hypercall code.
    /// `input` is the input type required by the hypercall.
    /// `output` is the output type required by the hypercall.
    ///
    /// Before invoking hypercalls, a list of hypercalls that are allowed
    /// has to be set with `Hcl::set_allowed_hypercalls`:
    /// ```ignore
    /// set_allowed_hypercalls(&[
    ///     hvdef::HypercallCode::HvCallCheckForIoIntercept,
    ///     hvdef::HypercallCode::HvCallInstallIntercept,
    /// ]);
    /// ```
    /// # Safety
    /// This function makes no guarantees that the given input header, input and output types are valid for the
    /// given hypercall. It is the caller's responsibility to use the correct types with the specified hypercall.
    ///
    /// A caller must check the returned [HypercallOutput] for success or failure from the hypervisor.
    ///
    /// Hardware isolated VMs cannot trust the output from the hypervisor and so it must be validated by the
    /// caller if needed.
    unsafe fn hvcall<I, O>(
        &self,
        code: HypercallCode,
        input: &I,
        output: &mut O,
    ) -> Result<HypercallOutput, HvcallError>
    where
        I: AsBytes + Sized,
        O: AsBytes + FromBytes + Sized,
    {
        const fn assert_size<I, O>()
        where
            I: Sized,
            O: Sized,
        {
            assert!(size_of::<I>() <= HV_PAGE_SIZE as usize);
            assert!(size_of::<O>() <= HV_PAGE_SIZE as usize);
        }
        assert_size::<I, O>();

        let control = hvdef::hypercall::Control::new().with_code(code.0);

        let call_object = protocol::hcl_hvcall {
            control,
            input_data: input.as_bytes().as_ptr().cast(),
            input_size: size_of::<I>(),
            status: FromZeroes::new_zeroed(),
            output_data: output.as_bytes().as_ptr().cast(),
            output_size: size_of::<O>(),
        };

        // SAFETY: The data referenced in the call lives as long as `self` does.
        unsafe { self.invoke_hvcall_ioctl(call_object) }
    }

    /// Issues a rep hypercall to the hypervisor via the direct hypercall kernel
    /// interface. Like the non-rep version, this is not intended to be used
    /// externally other than to construct safe wrappers. This call constructs
    /// the appropriate hypercall input control from the described parameters.
    ///
    /// `Ok(HypercallOutput)` is returned if the kernel was successful in
    /// issuing the hypercall. A caller must check the return value for the
    /// result of the hypercall.
    ///
    /// `code` is the hypercall code. `input_header` is the hypercall fixed
    /// length input header. Variable length headers are not supported.
    /// `input_rep` is the list of input elements. The length of the slice is
    /// used as the rep count.
    ///
    /// `output_rep` is the optional output rep list. A caller must check the
    /// returned [HypercallOutput] for the number of valid elements in this
    /// list.
    ///
    /// # Safety
    /// This function makes no guarantees that the given input header, input rep
    /// and output rep types are valid for the given hypercall. It is the
    /// caller's responsibility to use the correct types with the specified
    /// hypercall.
    ///
    /// A caller must check the returned [HypercallOutput] for success or
    /// failure from the hypervisor and processed rep count.
    ///
    /// Hardware isolated VMs cannot trust output from the hypervisor. This
    /// routine will ensure that the hypervisor either returns success with all
    /// elements processed, or returns failure with an incomplete number of
    /// elements processed. Actual validation of the output elements is the
    /// respsonsibility of the caller.
    unsafe fn hvcall_rep<InputHeader, InputRep, O>(
        &self,
        code: HypercallCode,
        input_header: &InputHeader,
        input_rep: HvcallRepInput<'_, InputRep>,
        output_rep: Option<&mut [O]>,
    ) -> Result<HypercallOutput, HvcallError>
    where
        InputHeader: AsBytes + Sized,
        InputRep: AsBytes + Sized,
        O: AsBytes + FromBytes + Sized,
    {
        // Construct input buffer.
        let (input, count) = match input_rep {
            HvcallRepInput::Elements(e) => {
                ([input_header.as_bytes(), e.as_bytes()].concat(), e.len())
            }
            HvcallRepInput::Count(c) => (input_header.as_bytes().to_vec(), c.into()),
        };

        if input.len() > HV_PAGE_SIZE as usize {
            return Err(HvcallError::InputParametersTooLarge);
        }

        if let Some(output_rep) = &output_rep {
            if output_rep.as_bytes().len() > HV_PAGE_SIZE as usize {
                return Err(HvcallError::OutputParametersTooLarge);
            }

            if count != output_rep.len() {
                return Err(HvcallError::InputOutputRepListMismatch);
            }
        }

        let (output_data, output_size) = match output_rep {
            Some(output_rep) => (
                output_rep.as_bytes().as_ptr().cast(),
                output_rep.as_bytes().len(),
            ),
            None => (std::ptr::null(), 0),
        };

        let control = hvdef::hypercall::Control::new()
            .with_code(code.0)
            .with_rep_count(count);

        let call_object = protocol::hcl_hvcall {
            control,
            input_data: input.as_ptr().cast(),
            input_size: input.len(),
            status: HypercallOutput::new(),
            output_data,
            output_size,
        };

        // SAFETY: The data referenced in the call lives as long as `self` does.
        unsafe { self.invoke_hvcall_ioctl(call_object) }
    }

    /// Issues a non-rep hypercall with variable input to the hypervisor via the direct hypercall kernel interface.
    /// This is not intended to be used directly by external callers, rather via write safe hypercall wrappers.
    /// This call constructs the appropriate hypercall input control from the described parameters.
    ///
    /// `Ok(HypercallOutput)` is returned if the kernel was successful in issuing the hypercall. A caller must check the
    /// return value for the result of the hypercall.
    ///
    /// `code` is the hypercall code.
    /// `input` is the input type required by the hypercall.
    /// `output` is the output type required by the hypercall.
    /// `variable_input` is the contents of the variable input to the hypercall. The length must be a multiple of 8 bytes.
    ///
    /// # Safety
    /// This function makes no guarantees that the given input header, input and output types are valid for the
    /// given hypercall. It is the caller's responsibility to use the correct types with the specified hypercall.
    ///
    /// A caller must check the returned [HypercallOutput] for success or failure from the hypervisor.
    ///
    /// Hardware isolated VMs cannot trust the output from the hypervisor and so it must be validated by the
    /// caller if needed.
    unsafe fn hvcall_var<I, O>(
        &self,
        code: HypercallCode,
        input: &I,
        variable_input: &[u8],
        output: &mut O,
    ) -> Result<HypercallOutput, HvcallError>
    where
        I: AsBytes + Sized,
        O: AsBytes + FromBytes + Sized,
    {
        const fn assert_size<I, O>()
        where
            I: Sized,
            O: Sized,
        {
            assert!(size_of::<I>() <= HV_PAGE_SIZE as usize);
            assert!(size_of::<O>() <= HV_PAGE_SIZE as usize);
        }
        assert_size::<I, O>();
        assert!(variable_input.len() % 8 == 0);

        let input = [input.as_bytes(), variable_input].concat();
        if input.len() > HV_PAGE_SIZE as usize {
            return Err(HvcallError::InputParametersTooLarge);
        }

        let control = hvdef::hypercall::Control::new()
            .with_code(code.0)
            .with_variable_header_size(variable_input.len() / 8);

        let call_object = protocol::hcl_hvcall {
            control,
            input_data: input.as_bytes().as_ptr().cast(),
            input_size: input.len(),
            status: FromZeroes::new_zeroed(),
            output_data: output.as_bytes().as_ptr().cast(),
            output_size: size_of::<O>(),
        };

        // SAFETY: The data referenced in the call lives as long as `self` does.
        unsafe { self.invoke_hvcall_ioctl(call_object) }
    }

    /// Sets the VTL protection mask for the specified memory range.
    ///
    /// [`HypercallCode::HvCallModifyVtlProtectionMask`] must be allowed.
    pub fn modify_vtl_protection_mask(
        &self,
        range: MemoryRange,
        map_flags: HvMapGpaFlags,
        target_vtl: HvInputVtl,
    ) -> Result<(), ApplyVtlProtectionsError> {
        let header = hvdef::hypercall::ModifyVtlProtectionMask {
            partition_id: HV_PARTITION_ID_SELF,
            map_flags,
            target_vtl,
            reserved: [0; 3],
        };

        const MAX_INPUT_ELEMENTS: usize = (HV_PAGE_SIZE as usize
            - size_of::<hvdef::hypercall::ModifyVtlProtectionMask>())
            / size_of::<u64>();

        let span = tracing::span!(tracing::Level::INFO, "modify_vtl_protection_mask", ?range);
        let _enter = span.enter();

        let start = range.start() / HV_PAGE_SIZE;
        let end = range.end() / HV_PAGE_SIZE;

        // Reuse the same vector for every hypercall.
        let mut pages = Vec::new();
        for current_page in (start..end).step_by(MAX_INPUT_ELEMENTS) {
            let remaining_pages = end - current_page;
            let count = remaining_pages.min(MAX_INPUT_ELEMENTS as u64);
            pages.clear();
            pages.extend(current_page..current_page + count);

            // SAFETY: The input header and rep slice are the correct types for this hypercall. A dummy type of u8 is
            //         provided to satisfy the compiler for output rep type. The given input and slices are valid
            //         references while this function is called.
            //
            //         The hypercall output is validated right after the hypercall is issued.
            let output = unsafe {
                self.hvcall_rep::<hvdef::hypercall::ModifyVtlProtectionMask, u64, u8>(
                    HypercallCode::HvCallModifyVtlProtectionMask,
                    &header,
                    HvcallRepInput::Elements(pages.as_slice()),
                    None,
                )
                .expect("kernel hypercall submission should always succeed")
            };

            output.result().map_err(|err| {
                let page_range =
                    *pages.first().expect("not empty")..*pages.last().expect("not empty") + 1;
                ApplyVtlProtectionsError::Hypervisor {
                    range: MemoryRange::from_4k_gpn_range(page_range),
                    output,
                    hv_error: err,
                    vtl: target_vtl,
                }
            })?;

            assert_eq!(output.elements_processed() as u64, count);
        }

        Ok(())
    }

    /// Get a single VP register for the given VTL via hypercall.
    fn get_vp_register_for_vtl_inner(
        &self,
        target_vtl: HvInputVtl,
        name: HvRegisterName,
    ) -> Result<HvRegisterValue, Error> {
        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index: HV_VP_INDEX_SELF,
            target_vtl,
            rsvd: [0; 3],
        };
        let mut output = [HvRegisterValue::new_zeroed()];

        // SAFETY: The input header and rep slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.hvcall_rep(
                HypercallCode::HvCallGetVpRegisters,
                &header,
                HvcallRepInput::Elements(&[name]),
                Some(&mut output),
            )
            .expect("get_vp_register hypercall should not fail")
        };

        // Status must be success with 1 rep completed
        status
            .result()
            .map_err(|err| Error::GetVpRegisterHypercall {
                reg: name.into(),
                err,
            })?;
        assert_eq!(status.elements_processed(), 1);

        Ok(output[0])
    }

    /// Get a single VP register for the given VTL via hypercall. Only a select
    /// set of registers are supported; others will cause a panic.
    #[cfg(guest_arch = "x86_64")]
    pub fn get_vp_register_for_vtl(
        &self,
        vtl: HvInputVtl,
        name: HvX64RegisterName,
    ) -> Result<HvRegisterValue, Error> {
        match vtl.target_vtl().unwrap() {
            None | Some(Vtl::Vtl2) => {
                assert!(matches!(
                    name,
                    HvX64RegisterName::GuestVsmPartitionConfig
                        | HvX64RegisterName::VsmPartitionConfig
                        | HvX64RegisterName::VsmPartitionStatus
                        | HvX64RegisterName::VsmCapabilities
                        | HvX64RegisterName::TimeRefCount
                        | HvX64RegisterName::VsmVpSecureConfigVtl0
                        | HvX64RegisterName::VsmVpSecureConfigVtl1
                ));
            }
            Some(Vtl::Vtl1) => {
                todo!("TODO: allowed registers for VTL1");
            }
            Some(Vtl::Vtl0) => {
                // Only VTL-private registers can go through this path.
                // VTL-shared registers have to go through the kernel (either
                // via the CPU context page or via the dedicated ioctl), as
                // they may require special handling there.
                //
                // Register access should go through the register page if
                // possible (as a performance optimization). In practice,
                // registers that are normally available on the register page
                // are handled here only when it is unavailable (e.g., running
                // in WHP).
                assert!(!is_vtl_shared_reg(name));
            }
        }

        self.get_vp_register_for_vtl_inner(vtl, name.into())
    }

    /// Get a single VP register for the given VTL via hypercall. Only a select
    /// set of registers are supported; others will cause a panic.
    #[cfg(guest_arch = "aarch64")]
    pub fn get_vp_register_for_vtl(
        &self,
        vtl: HvInputVtl,
        name: HvArm64RegisterName,
    ) -> Result<HvRegisterValue, Error> {
        match vtl.target_vtl().unwrap() {
            None | Some(Vtl::Vtl2) => {
                assert!(matches!(
                    name,
                    HvArm64RegisterName::GuestVsmPartitionConfig
                        | HvArm64RegisterName::VsmPartitionConfig
                        | HvArm64RegisterName::VsmPartitionStatus
                        | HvArm64RegisterName::VsmCapabilities
                        | HvArm64RegisterName::TimeRefCount
                        | HvArm64RegisterName::VsmVpSecureConfigVtl0
                        | HvArm64RegisterName::VsmVpSecureConfigVtl1
                        | HvArm64RegisterName::PrivilegesAndFeaturesInfo
                ));
            }
            Some(Vtl::Vtl1) => {
                // TODO: allowed registers for VTL1
                todo!();
            }
            Some(Vtl::Vtl0) => {
                // Only VTL-private registers can go through this path.
                // VTL-shared registers have to go through the kernel (either
                // via the CPU context page or via the dedicated ioctl), as
                // they may require special handling there.
                assert!(!is_vtl_shared_reg(name));
            }
        }

        self.get_vp_register_for_vtl_inner(vtl, name.into())
    }
}

/// The HCL device and collection of fds.
#[derive(Debug)]
pub struct Hcl {
    mshv_hvcall: MshvHvcall,
    mshv_vtl: MshvVtl,
    vps: Vec<HclVp>,
    supports_vtl_ret_action: bool,
    supports_register_page: bool,
    dr6_shared: bool,
    isolation: IsolationType,
    snp_register_bitmap: [u8; 64],
    sidecar: Option<SidecarClient>,
}

/// The isolation type for a partition.
// TODO: Add guest_arch cfgs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IsolationType {
    /// No isolation.
    None,
    /// Hyper-V software isolation.
    Vbs,
    /// AMD SNP.
    Snp,
    /// Intel TDX.
    Tdx,
}

impl IsolationType {
    /// Returns true if the isolation type is not `None`.
    pub fn is_isolated(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns whether the isolation type is hardware-backed.
    pub fn is_hardware_isolated(&self) -> bool {
        matches!(self, Self::Snp | Self::Tdx)
    }
}

impl Hcl {
    /// Returns true if DR6 is a shared register on this processor.
    pub fn dr6_shared(&self) -> bool {
        self.dr6_shared
    }
}

struct MappedPage<T>(NonNull<T>);

impl<T> MappedPage<T> {
    fn new(fd: &File, pg_off: i64) -> io::Result<Self> {
        // SAFETY: calling mmap as documented to create a new mapping.
        let ptr = unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE);
            libc::mmap(
                std::ptr::null_mut(),
                page_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                pg_off * page_size,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self(NonNull::new(ptr).unwrap().cast()))
    }
}

impl<T> Debug for MappedPage<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MappedPage").field(&self.0).finish()
    }
}

impl<T> Drop for MappedPage<T> {
    fn drop(&mut self) {
        // SAFETY: unmapping memory mapped at construction.
        unsafe {
            libc::munmap(
                self.0.as_ptr().cast(),
                libc::sysconf(libc::_SC_PAGESIZE) as usize,
            );
        }
    }
}

// SAFETY: this is just a pointer value.
unsafe impl<T> Send for MappedPage<T> {}
// SAFETY: see above comment
unsafe impl<T> Sync for MappedPage<T> {}

#[derive(Debug)]
struct HclVp {
    state: Mutex<VpState>,
    run: MappedPage<hcl_run>,
    backing: BackingState,
}

#[derive(Debug)]
enum BackingState {
    Mshv {
        reg_page: Option<MappedPage<HvX64RegisterPage>>,
    },
    Snp {
        vmsa: MappedPage<SevVmsa>,
        vmsa_vtl1: MappedPage<SevVmsa>,
    },
    // TODO GUEST_VSM: vtl 1 vp state
    Tdx {
        apic_page: MappedPage<[u32; 1024]>,
    },
}

#[derive(Debug)]
enum VpState {
    Running(Pthread),
    NotRunning,
}

impl HclVp {
    fn new(
        hcl: &Hcl,
        vp: u32,
        map_reg_page: bool,
        isolation_type: IsolationType,
    ) -> Result<Self, Error> {
        let fd = &hcl.mshv_vtl.file;
        let run: MappedPage<hcl_run> =
            MappedPage::new(fd, vp as i64).map_err(|e| Error::MmapVp(e, None))?;
        // SAFETY: `proxy_irr_blocked` is not accessed by any other VPs/kernel at this point (`HclVp` creation)
        // so we know we have exclusive access. Initializing to block all vectors by default
        let proxy_irr_blocked = unsafe { &mut *addr_of_mut!((*run.0.as_ptr()).proxy_irr_blocked) };
        proxy_irr_blocked.fill(0xFFFFFFFF);

        let backing = match isolation_type {
            IsolationType::None | IsolationType::Vbs => BackingState::Mshv {
                reg_page: if map_reg_page {
                    Some(
                        MappedPage::new(fd, HCL_REG_PAGE_OFFSET | vp as i64)
                            .map_err(Error::MmapRegPage)?,
                    )
                } else {
                    None
                },
            },
            IsolationType::Snp => BackingState::Snp {
                vmsa: MappedPage::new(fd, HCL_VMSA_PAGE_OFFSET | vp as i64)
                    .map_err(|e| Error::MmapVp(e, Some(Vtl::Vtl0)))?,
                vmsa_vtl1: MappedPage::new(fd, HCL_VMSA_GUEST_VSM_PAGE_OFFSET | vp as i64)
                    .map_err(|e| Error::MmapVp(e, Some(Vtl::Vtl1)))?,
            },
            IsolationType::Tdx => BackingState::Tdx {
                apic_page: MappedPage::new(fd, MSHV_APIC_PAGE_OFFSET | vp as i64)
                    .map_err(|e| Error::MmapVp(e, Some(Vtl::Vtl0)))?,
            },
        };

        Ok(Self {
            state: Mutex::new(VpState::NotRunning),
            run,
            backing,
        })
    }
}

/// Object used to run and to access state for a specific VP.
pub struct ProcessorRunner<'a, T> {
    hcl: &'a Hcl,
    vp: &'a HclVp,
    sidecar: Option<SidecarVp<'a>>,
    _no_send: PhantomData<*const u8>, // prevent Send/Sync
    run: NonNull<hcl_run>,
    intercept_message: NonNull<HvMessage>,
    state: T,
}

/// An error returned by [`Hcl::runner`].
#[derive(Debug, Error)]
pub enum NoRunner {
    /// The partition is for a different isolation type.
    #[error("mismatched isolation type")]
    MismatchedIsolation,
    /// A sidecar VP was requested, but no sidecar was provided.
    #[error("missing sidecar")]
    MissingSidecar,
    /// The sidecar VP could not be contacted.
    #[error("sidecar communication error")]
    Sidecar(#[source] sidecar_client::SidecarError),
}

/// An isolation-type-specific backing for a processor runner.
pub trait Backing: BackingPrivate {}

impl<T: BackingPrivate> Backing for T {}

mod private {
    use super::Error;
    use super::HclVp;
    use super::NoRunner;
    use super::ProcessorRunner;
    use crate::GuestVtl;
    use hvdef::HvRegisterName;
    use hvdef::HvRegisterValue;
    use sidecar_client::SidecarVp;

    pub trait BackingPrivate: Sized {
        fn new(vp: &HclVp, sidecar: Option<&SidecarVp<'_>>) -> Result<Self, NoRunner>;

        fn try_set_reg(
            runner: &mut ProcessorRunner<'_, Self>,
            vtl: GuestVtl,
            name: HvRegisterName,
            value: HvRegisterValue,
        ) -> Result<bool, Error>;

        fn must_flush_regs_on(runner: &ProcessorRunner<'_, Self>, name: HvRegisterName) -> bool;

        fn try_get_reg(
            runner: &ProcessorRunner<'_, Self>,
            vtl: GuestVtl,
            name: HvRegisterName,
        ) -> Result<Option<HvRegisterValue>, Error>;
    }
}

impl<T> Drop for ProcessorRunner<'_, T> {
    fn drop(&mut self) {
        self.flush_deferred_actions();
        let actions = DEFERRED_ACTIONS.with(|actions| actions.take());
        assert!(actions.is_none_or(|a| a.is_empty()));
        let old_state = std::mem::replace(&mut *self.vp.state.lock(), VpState::NotRunning);
        assert!(matches!(old_state, VpState::Running(thread) if thread == Pthread::current()));
    }
}

impl<T> ProcessorRunner<'_, T> {
    /// Flushes any pending deferred actions. Must be called if preparing the
    /// partition for save/restore (servicing), since otherwise the deferred
    /// actions will be lost.
    pub fn flush_deferred_actions(&mut self) {
        if self.sidecar.is_none() {
            DEFERRED_ACTIONS.with(|actions| {
                let mut actions = actions.borrow_mut();
                actions.as_mut().unwrap().run_actions(self.hcl);
            })
        }
    }
}

impl<'a, T: Backing> ProcessorRunner<'a, T> {
    // Registers that are shared between VTLs need to be handled by the kernel
    // as they may require special handling there. set_reg and get_reg will
    // handle these registers using a dedicated ioctl, instead of the general-
    // purpose Set/GetVpRegisters hypercalls.
    #[cfg(guest_arch = "x86_64")]
    fn is_kernel_managed(&self, name: HvX64RegisterName) -> bool {
        if name == HvX64RegisterName::Dr6 {
            self.hcl.dr6_shared()
        } else {
            is_vtl_shared_reg(name)
        }
    }

    #[cfg(guest_arch = "aarch64")]
    fn is_kernel_managed(&self, name: HvArm64RegisterName) -> bool {
        is_vtl_shared_reg(name)
    }

    fn set_reg(&mut self, vtl: GuestVtl, regs: &[HvRegisterAssoc]) -> Result<(), Error> {
        if regs.is_empty() {
            return Ok(());
        }

        if let Some(sidecar) = &mut self.sidecar {
            sidecar
                .set_vp_registers(vtl.into(), regs)
                .map_err(Error::Sidecar)?;
        } else {
            // TODO: group up to MSHV_VP_MAX_REGISTERS regs. The kernel
            // currently has a bug where it only supports one register at a
            // time. Once that's fixed, this code could set a group of
            // registers in one ioctl.
            for reg in regs {
                let hc_regs = &mut [HvRegisterAssoc {
                    name: reg.name,
                    pad: [0; 3],
                    value: reg.value,
                }];

                if self.is_kernel_managed(reg.name.into()) {
                    let hv_vp_register_args = mshv_vp_registers {
                        count: 1,
                        regs: hc_regs.as_mut_ptr(),
                    };
                    // SAFETY: ioctl call with correct types.
                    unsafe {
                        hcl_set_vp_register(
                            self.hcl.mshv_vtl.file.as_raw_fd(),
                            &hv_vp_register_args,
                        )
                        .map_err(Error::SetVpRegister)?;
                    }
                } else {
                    let hc_regs = [HvRegisterAssoc {
                        name: reg.name,
                        pad: [0; 3],
                        value: reg.value,
                    }];
                    self.set_vp_registers_hvcall_inner(vtl.into(), &hc_regs)
                        .map_err(Error::SetRegisters)?;
                }
            }
        }
        Ok(())
    }

    fn get_reg(&mut self, vtl: GuestVtl, regs: &mut [HvRegisterAssoc]) -> Result<(), Error> {
        if regs.is_empty() {
            return Ok(());
        }

        if let Some(sidecar) = &mut self.sidecar {
            sidecar
                .get_vp_registers(vtl.into(), regs)
                .map_err(Error::Sidecar)?;
        } else {
            // TODO: group up to MSHV_VP_MAX_REGISTERS regs. The kernel
            // currently has a bug where it only supports one register at a
            // time. Once that's fixed, this code could set a group of
            // registers in one ioctl.
            for reg in regs {
                if self.is_kernel_managed(reg.name.into()) {
                    let mut mshv_vp_register_args = mshv_vp_registers {
                        count: 1,
                        regs: reg,
                    };
                    // SAFETY: we know that our file is a vCPU fd, we know the kernel will only read the
                    // correct amount of memory from our pointer, and we verify the return result.
                    unsafe {
                        hcl_get_vp_register(
                            self.hcl.mshv_vtl.file.as_raw_fd(),
                            &mut mshv_vp_register_args,
                        )
                        .map_err(Error::GetVpRegister)?;
                    }
                } else {
                    reg.value = self
                        .hcl
                        .mshv_hvcall
                        .get_vp_register_for_vtl(vtl.into(), reg.name.into())?;
                }
            }
        }
        Ok(())
    }

    /// Clears the cancel flag so that the VP can be run again.
    pub fn clear_cancel(&mut self) {
        if !self.is_sidecar() {
            // SAFETY: self.run is mapped, and the cancel field is atomically
            // accessed by everyone.
            let cancel = unsafe { &*addr_of!((*self.run.as_ptr()).cancel).cast::<AtomicU32>() };
            cancel.store(0, Ordering::SeqCst);
        }
    }

    /// Set the halted state of the VP. If `true`, then `run()` will not
    /// actually run the VP but will just wait for a cancel request or signal.
    pub fn set_halted(&mut self, halted: bool) {
        // SAFETY: the `flags` field of the run page will not be concurrently
        // updated.
        let flags = unsafe { &mut *addr_of_mut!((*self.run.as_ptr()).flags) };
        if halted {
            *flags |= protocol::MSHV_VTL_RUN_FLAG_HALTED
        } else {
            *flags &= !protocol::MSHV_VTL_RUN_FLAG_HALTED
        }
    }

    /// Gets the proxied interrupt request bitmap from the hypervisor.
    pub fn proxy_irr(&mut self) -> Option<[u32; 8]> {
        // SAFETY: the `scan_proxy_irr` and `proxy_irr` fields of the run page
        // are concurrently updated by the kernel on multiple processors. They
        // are accessed atomically everywhere.
        unsafe {
            let scan_proxy_irr =
                &*(addr_of!((*self.run.as_ptr()).scan_proxy_irr).cast::<AtomicU8>());
            let proxy_irr = &*(addr_of!((*self.run.as_ptr()).proxy_irr).cast::<[AtomicU32; 8]>());
            if scan_proxy_irr.load(Ordering::Acquire) == 0 {
                return None;
            }

            scan_proxy_irr.store(0, Ordering::SeqCst);
            let mut r = [0; 8];
            for (irr, r) in proxy_irr.iter().zip(r.iter_mut()) {
                if irr.load(Ordering::Relaxed) != 0 {
                    *r = irr.swap(0, Ordering::Relaxed);
                }
            }
            Some(r)
        }
    }

    /// Update the `proxy_irr_blocked` in run page
    pub fn update_proxy_irr_filter(&mut self, irr_filter: &[u32; 8]) {
        // SAFETY: `proxy_irr_blocked` is accessed by current VP only, but could
        // be concurrently accessed by kernel too, hence accessing as Atomic
        let proxy_irr_blocked = unsafe {
            &mut *(addr_of_mut!((*self.run.as_ptr()).proxy_irr_blocked).cast::<[AtomicU32; 8]>())
        };

        // `irr_filter` bitmap has bits set for all allowed vectors (i.e. SINT and device interrupts)
        // Replace current `proxy_irr_blocked` with the given `irr_filter` bitmap.
        // By default block all (i.e. set all), and only allow (unset) given vectors from `irr_filter`.
        for (filter, irr) in proxy_irr_blocked.iter_mut().zip(irr_filter.iter()) {
            filter.store(!irr, Ordering::Relaxed);
            tracing::debug!(irr, "update_proxy_irr_filter");
        }
    }

    /// Gets the proxy_irr_exit bitmask. This mask ensures that
    /// the masked interrupts always exit to user-space, and cannot
    /// be injected in the kernel. Interrupts matching this condition
    /// will be left on the proxy_irr field.
    pub fn proxy_irr_exit_mut(&mut self) -> &mut [u32; 8] {
        // SAFETY: The `proxy_irr_exit` field of the run page will not be concurrently updated.
        unsafe { &mut (*self.run.as_ptr()).proxy_irr_exit }
    }

    /// Gets the current offload_flags from the run page.
    pub fn offload_flags_mut(&mut self) -> &mut hcl_intr_offload_flags {
        // SAFETY: The `offload_flags` field of the run page will not be concurrently updated.
        unsafe { &mut (*self.run.as_ptr()).offload_flags }
    }

    /// Runs the VP via the sidecar kernel.
    pub fn run_sidecar(&mut self) -> Result<SidecarRun<'_, 'a>, Error> {
        self.sidecar.as_mut().unwrap().run().map_err(Error::Sidecar)
    }

    /// Run the following VP until an exit, error, or interrupt (cancel or
    /// signal) occurs.
    ///
    /// Returns `Ok(true)` if there is an exit to process, `Ok(false)` if there
    /// was a signal or cancel request.
    pub fn run(&mut self) -> Result<bool, Error> {
        assert!(self.sidecar.is_none());
        // Apply any deferred actions to the run page.
        DEFERRED_ACTIONS.with(|actions| {
            let mut actions = actions.borrow_mut();
            let actions = actions.as_mut().unwrap();
            if self.hcl.supports_vtl_ret_action {
                // SAFETY: there are no concurrent accesses to the deferred action
                // slots.
                let mut slots = unsafe { DeferredActionSlots::new(self.run) };
                actions.copy_to_slots(&mut slots, self.hcl);
            } else {
                actions.run_actions(self.hcl);
            }
        });

        // N.B. cpu_context and exit_context are mutated by this call.
        //
        // SAFETY: no safety requirements for this ioctl.
        let r = unsafe { hcl_return_to_lower_vtl(self.hcl.mshv_vtl.file.as_raw_fd()) };

        let has_intercept = match r {
            Ok(_) => true,
            Err(nix::errno::Errno::EINTR) => false,
            Err(err) => return Err(Error::ReturnToLowerVtl(err)),
        };
        Ok(has_intercept)
    }

    /// Gets a reference to enter mode value, used by the kernel to specify the
    /// mode used when entering a lower VTL.
    pub fn enter_mode(&mut self) -> Option<&mut EnterModes> {
        if self.sidecar.is_some() {
            None
        } else {
            // SAFETY: self.run is mapped, and the mode field can only be mutated or accessed by
            // this object (or the kernel while `run` is called).
            Some(unsafe { &mut *addr_of_mut!((*self.run.as_ptr()).mode) })
        }
    }

    /// Returns a reference to the exit message from the last exit.
    pub fn exit_message(&self) -> &HvMessage {
        // SAFETY: the exit message will not be concurrently accessed by the
        // kernel while this VP is in VTL2.
        unsafe { self.intercept_message.as_ref() }
    }

    /// Returns whether this is a sidecar VP.
    pub fn is_sidecar(&self) -> bool {
        self.sidecar.is_some()
    }
}

impl<T: Backing> ProcessorRunner<'_, T> {
    fn get_vp_registers_inner<R: Copy + Into<HvRegisterName>>(
        &mut self,
        vtl: GuestVtl,
        names: &[R],
        values: &mut [HvRegisterValue],
    ) -> Result<(), Error> {
        assert_eq!(names.len(), values.len());
        let mut assoc = Vec::new();
        let mut offset = Vec::new();
        for (i, (&name, value)) in names.iter().zip(values.iter_mut()).enumerate() {
            if let Some(v) = T::try_get_reg(self, vtl, name.into())? {
                *value = v;
            } else {
                assoc.push(HvRegisterAssoc {
                    name: name.into(),
                    pad: Default::default(),
                    value: FromZeroes::new_zeroed(),
                });
                offset.push(i);
            }
        }

        self.get_reg(vtl, &mut assoc)?;
        for (&i, assoc) in offset.iter().zip(&assoc) {
            values[i] = assoc.value;
        }
        Ok(())
    }

    /// Get the following register on the current VP.
    ///
    /// This will fail for registers that are in the mmapped CPU context, i.e.
    /// registers that are shared between VTL0 and VTL2.
    pub fn get_vp_register(
        &mut self,
        vtl: GuestVtl,
        #[cfg(guest_arch = "x86_64")] name: HvX64RegisterName,
        #[cfg(guest_arch = "aarch64")] name: HvArm64RegisterName,
    ) -> Result<HvRegisterValue, Error> {
        let mut value = [0u64.into(); 1];
        self.get_vp_registers_inner(vtl, &[name], &mut value)?;
        Ok(value[0])
    }

    /// Get the following VP registers on the current VP.
    ///
    /// # Panics
    /// Panics if `names.len() != values.len()`.
    pub fn get_vp_registers(
        &mut self,
        vtl: GuestVtl,
        #[cfg(guest_arch = "x86_64")] names: &[HvX64RegisterName],
        #[cfg(guest_arch = "aarch64")] names: &[HvArm64RegisterName],
        values: &mut [HvRegisterValue],
    ) -> Result<(), Error> {
        self.get_vp_registers_inner(vtl, names, values)
    }

    /// Set the following register on the current VP.
    ///
    /// This will fail for registers that are in the mmapped CPU context, i.e.
    /// registers that are shared between VTL0 and VTL2.
    pub fn set_vp_register(
        &mut self,
        vtl: GuestVtl,
        #[cfg(guest_arch = "x86_64")] name: HvX64RegisterName,
        #[cfg(guest_arch = "aarch64")] name: HvArm64RegisterName,
        value: HvRegisterValue,
    ) -> Result<(), Error> {
        self.set_vp_registers(vtl, [(name, value)])
    }

    /// Sets a set of VP registers.
    pub fn set_vp_registers<I>(&mut self, vtl: GuestVtl, values: I) -> Result<(), Error>
    where
        I: IntoIterator,
        I::Item: Into<HvRegisterAssoc> + Clone,
    {
        let mut assoc = Vec::new();
        for HvRegisterAssoc { name, value, .. } in values.into_iter().map(Into::into) {
            if !assoc.is_empty() && T::must_flush_regs_on(self, name) {
                self.set_reg(vtl, &assoc)?;
                assoc.clear();
            }
            if !T::try_set_reg(self, vtl, name, value)? {
                assoc.push(HvRegisterAssoc {
                    name,
                    pad: Default::default(),
                    value,
                });
            }
        }
        if !assoc.is_empty() {
            self.set_reg(vtl, &assoc)?;
        }
        Ok(())
    }

    fn set_vp_registers_hvcall_inner(
        &mut self,
        vtl: Vtl,
        registers: &[HvRegisterAssoc],
    ) -> Result<(), HvError> {
        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index: HV_VP_INDEX_SELF,
            target_vtl: vtl.into(),
            rsvd: [0; 3],
        };

        tracing::trace!(?registers, "HvCallSetVpRegisters rep");

        // SAFETY: The input header and rep slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.hcl
                .mshv_hvcall
                .hvcall_rep::<hvdef::hypercall::GetSetVpRegisters, HvRegisterAssoc, u8>(
                    HypercallCode::HvCallSetVpRegisters,
                    &header,
                    HvcallRepInput::Elements(registers),
                    None,
                )
                .expect("set_vp_registers hypercall should not fail")
        };

        // Status must be success
        status.result()?;
        Ok(())
    }

    /// Sets the following registers on the current VP and given VTL using a
    /// direct hypercall.
    ///
    /// This should not be used on the fast path. Therefore only a select set of
    /// registers are supported, and others will cause a panic.
    ///
    /// This function can be used with VTL2 as a target.
    pub fn set_vp_registers_hvcall<I>(&mut self, vtl: Vtl, values: I) -> Result<(), HvError>
    where
        I: IntoIterator,
        I::Item: Into<HvRegisterAssoc> + Clone,
    {
        let registers: Vec<HvRegisterAssoc> = values.into_iter().map(Into::into).collect();

        assert!(registers.iter().all(
            |HvRegisterAssoc {
                 name,
                 pad: _,
                 value: _,
             }| matches!(
                (*name).into(),
                HvX64RegisterName::PendingEvent0
                    | HvX64RegisterName::PendingEvent1
                    | HvX64RegisterName::Sipp
                    | HvX64RegisterName::Sifp
                    | HvX64RegisterName::Ghcb
                    | HvX64RegisterName::VsmPartitionConfig
                    | HvX64RegisterName::VsmVpWaitForTlbLock
                    | HvX64RegisterName::VsmVpSecureConfigVtl0
                    | HvX64RegisterName::VsmVpSecureConfigVtl1
            )
        ));
        self.set_vp_registers_hvcall_inner(vtl, &registers)
    }

    /// Sets the VTL that should be returned to when underhill exits
    pub fn set_exit_vtl(&mut self, vtl: GuestVtl) {
        // SAFETY: self.run is mapped, and the target_vtl field can only be
        // mutated or accessed by this object and only before the kernel is
        // invoked during `run`
        unsafe { self.run.as_mut().target_vtl = vtl.into() }
    }
}

thread_local! {
    static DEFERRED_ACTIONS: RefCell<Option<DeferredActions>> = const { RefCell::new(None) };
}

impl Hcl {
    /// Returns a new HCL instance.
    pub fn new(isolation: IsolationType, sidecar: Option<SidecarClient>) -> Result<Hcl, Error> {
        static SIGNAL_HANDLER_INIT: Once = Once::new();
        // SAFETY: The signal handler does not perform any actions that are forbidden
        // for signal handlers to perform, as it performs nothing.
        SIGNAL_HANDLER_INIT.call_once(|| unsafe {
            signal_hook::low_level::register(libc::SIGRTMIN(), || {
                // Do nothing, the ioctl will now return with EINTR.
            })
            .unwrap();
        });

        // Open both mshv fds
        let mshv_fd = Mshv::new()?;

        // Validate the hypervisor's advertised isolation type matches the
        // requested isolation type. In CVM scenarios, this is not trusted, so
        // we still need the isolation type from the caller.
        //
        // FUTURE: the kernel driver should probably tell us this, especially
        // since the kernel ABI is different for different isolation types.
        let supported_isolation = if cfg!(guest_arch = "x86_64") {
            // xtask-fmt allow-target-arch cpu-intrinsic
            #[cfg(target_arch = "x86_64")]
            {
                let result = safe_intrinsics::cpuid(
                    hvdef::HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION,
                    0,
                );
                match result.ebx & 0xF {
                    0 => IsolationType::None,
                    1 => IsolationType::Vbs,
                    2 => IsolationType::Snp,
                    3 => IsolationType::Tdx,
                    ty => panic!("unknown isolation type {ty:#x}"),
                }
            }
            // xtask-fmt allow-target-arch cpu-intrinsic
            #[cfg(not(target_arch = "x86_64"))]
            {
                unreachable!()
            }
        } else {
            IsolationType::None
        };

        if isolation != supported_isolation {
            return Err(Error::MismatchedIsolation {
                supported: supported_isolation,
                requested: isolation,
            });
        }

        let supports_vtl_ret_action = mshv_fd.check_extension(HCL_CAP_VTL_RETURN_ACTION)?;
        let supports_register_page = mshv_fd.check_extension(HCL_CAP_REGISTER_PAGE)?;
        let dr6_shared = mshv_fd.check_extension(HCL_CAP_DR6_SHARED)?;
        tracing::debug!(
            supports_vtl_ret_action,
            supports_register_page,
            "HCL capabilities",
        );

        let vtl_fd = mshv_fd.create_vtl()?;

        // Open the hypercall pseudo-device
        let mshv_hvcall = MshvHvcall::new()?;

        // Override certain features for hardware isolated VMs.
        // TODO: vtl return actions are inhibited for hardware isolated VMs because they currently
        // are a pessimization since interrupt handling (and synic handling) are all done from
        // within VTL2. Future vtl return actions may be different, requiring granular handling.
        let supports_vtl_ret_action = supports_vtl_ret_action && !isolation.is_hardware_isolated();
        let supports_register_page = supports_register_page && !isolation.is_hardware_isolated();
        let dr6_shared = dr6_shared && !isolation.is_hardware_isolated();
        let snp_register_bitmap = [0u8; 64];

        Ok(Hcl {
            mshv_hvcall,
            mshv_vtl: vtl_fd,
            vps: Vec::new(),
            supports_vtl_ret_action,
            supports_register_page,
            dr6_shared,
            isolation,
            snp_register_bitmap,
            sidecar,
        })
    }

    /// Set allowed hypercalls.
    pub fn set_allowed_hypercalls(&self, codes: &[HypercallCode]) {
        self.mshv_hvcall.set_allowed_hypercalls(codes)
    }

    /// Initializes SNP register tweak bitmap
    pub fn set_snp_register_bitmap(&mut self, register_bitmap: [u8; 64]) {
        self.snp_register_bitmap = register_bitmap;
    }

    /// Adds `vp_count` VPs.
    pub fn add_vps(&mut self, vp_count: u32) -> Result<(), Error> {
        self.vps = (0..vp_count)
            .map(|vp| HclVp::new(self, vp, self.supports_register_page, self.isolation))
            .collect::<Result<_, _>>()?;

        Ok(())
    }

    /// Registers with the hypervisor for an intercept.
    pub fn register_intercept(
        &self,
        intercept_type: HvInterceptType,
        access_type_mask: u32,
        intercept_parameters: HvInterceptParameters,
    ) -> Result<(), HvError> {
        let intercept_info = hvdef::hypercall::InstallIntercept {
            partition_id: HV_PARTITION_ID_SELF,
            access_type_mask,
            intercept_type,
            intercept_parameters,
        };

        // SAFETY: calling hypercall with appropriate input and output.
        unsafe {
            self.mshv_hvcall
                .hvcall(
                    HypercallCode::HvCallInstallIntercept,
                    &intercept_info,
                    &mut (),
                )
                .unwrap()
                .result()
        }
    }

    /// Returns the base CPU that manages the given sidecar VP.
    pub fn sidecar_base_cpu(&self, vp_index: u32) -> Option<u32> {
        Some(self.sidecar.as_ref()?.base_cpu(vp_index))
    }

    /// Create a VP runner for the given partition.
    pub fn runner<T: Backing>(
        &self,
        vp_index: u32,
        use_sidecar: bool,
    ) -> Result<ProcessorRunner<'_, T>, NoRunner> {
        let vp = &self.vps[vp_index as usize];

        let sidecar = if use_sidecar {
            Some(
                self.sidecar
                    .as_ref()
                    .ok_or(NoRunner::MissingSidecar)?
                    .vp(vp_index),
            )
        } else {
            None
        };

        let state = T::new(vp, sidecar.as_ref())?;

        // Set this thread as the runner.
        let VpState::NotRunning =
            std::mem::replace(&mut *vp.state.lock(), VpState::Running(Pthread::current()))
        else {
            panic!("another runner already exists")
        };

        if sidecar.is_none() {
            DEFERRED_ACTIONS.with(|actions| {
                assert!(actions.replace(Some(Default::default())).is_none());
            });
        }

        let intercept_message = sidecar.as_ref().map_or(
            // SAFETY: The run page is guaranteed to be mapped and valid.
            // While the exit message might not be filled in yet we're only computing its address.
            unsafe { std::ptr::addr_of!((*vp.run.0.as_ptr()).exit_message) }.cast(),
            |s| s.intercept_message(),
        );

        let intercept_message = NonNull::new(intercept_message.cast_mut()).unwrap();

        Ok(ProcessorRunner {
            hcl: self,
            vp,
            run: vp.run.0,
            intercept_message,
            _no_send: PhantomData,
            state,
            sidecar,
        })
    }

    /// Trigger the following interrupt request.
    pub fn request_interrupt(
        &self,
        interrupt_control: hvdef::HvInterruptControl,
        destination_address: u64,
        requested_vector: u32,
        target_vtl: GuestVtl,
    ) -> Result<(), Error> {
        tracing::trace!(
            ?interrupt_control,
            destination_address,
            requested_vector,
            "requesting interrupt"
        );

        assert!(!self.isolation.is_hardware_isolated());

        let request = AssertVirtualInterrupt {
            partition_id: HV_PARTITION_ID_SELF,
            interrupt_control,
            destination_address,
            requested_vector,
            target_vtl: target_vtl as u8,
            rsvd0: 0,
            rsvd1: 0,
        };

        // SAFETY: calling the hypercall with correct input buffer.
        let output = unsafe {
            self.mshv_hvcall.hvcall(
                HypercallCode::HvCallAssertVirtualInterrupt,
                &request,
                &mut (),
            )
        }
        .unwrap();

        output.result().map_err(Error::RequestInterrupt)
    }

    /// Attempts to signal a given vp/sint/flag combo using HvSignalEventDirect.
    ///
    /// No result is returned because this request may be deferred until the
    /// hypervisor is returning to a lower VTL.
    pub fn signal_event_direct(&self, vp: u32, sint: u8, flag: u16) {
        tracing::trace!(vp, sint, flag, "signaling event");

        DEFERRED_ACTIONS.with(|actions| {
            // Push a deferred action if we are running on a VP thread.
            if let Some(actions) = actions.borrow_mut().as_mut() {
                actions.push(self, DeferredAction::SignalEvent { vp, sint, flag });
            } else {
                // Signal the event directly.
                if let Err(err) = self.hvcall_signal_event_direct(vp, sint, flag) {
                    tracelimit::warn_ratelimited!(
                        error = &err as &dyn std::error::Error,
                        vp,
                        sint,
                        flag,
                        "failed to signal event"
                    );
                }
            }
        })
    }

    fn hvcall_signal_event_direct(&self, vp: u32, sint: u8, flag: u16) -> Result<bool, Error> {
        let signal_event_input = hvdef::hypercall::SignalEventDirect {
            target_partition: HV_PARTITION_ID_SELF,
            target_vp: vp,
            target_vtl: Vtl::Vtl0 as u8,
            target_sint: sint,
            flag_number: flag,
        };
        let mut signal_event_output = hvdef::hypercall::SignalEventDirectOutput {
            newly_signaled: 0,
            rsvd: [0; 7],
        };

        // SAFETY: calling the hypercall with correct input buffer.
        let output = unsafe {
            self.mshv_hvcall.hvcall(
                HypercallCode::HvCallSignalEventDirect,
                &signal_event_input,
                &mut signal_event_output,
            )
        }
        .unwrap();

        output
            .result()
            .map(|_| signal_event_output.newly_signaled != 0)
            .map_err(Error::SignalEvent)
    }

    /// Attempts to post a given message to a vp/sint combo using HvPostMessageDirect.
    pub fn post_message_direct(
        &self,
        vp: u32,
        sint: u8,
        message: &HvMessage,
    ) -> Result<(), HvError> {
        tracing::trace!(vp, sint, "posting message");

        let post_message = hvdef::hypercall::PostMessageDirect {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index: vp,
            vtl: Vtl::Vtl0 as u8,
            padding0: [0; 3],
            sint,
            padding1: [0; 3],
            message: *message,
        };

        // SAFETY: calling the hypercall with correct input buffer.
        let output = unsafe {
            self.mshv_hvcall.hvcall(
                HypercallCode::HvCallPostMessageDirect,
                &post_message,
                &mut (),
            )
        }
        .unwrap();

        output.result()
    }

    /// Sets a file to poll during run. When the file's poll state changes, the
    /// run will be automatically cancelled.
    pub fn set_poll_file(&self, vp: u32, file: RawFd) -> Result<(), Error> {
        // SAFETY: calling the IOCTL as defined. This is safe even if the caller
        // does not own `file` since all this does is register the file for
        // polling.
        unsafe {
            hcl_set_poll_file(
                self.mshv_vtl.file.as_raw_fd(),
                &protocol::hcl_set_poll_file {
                    cpu: vp as i32,
                    fd: file,
                },
            )
            .map_err(Error::SetPollFile)?;
        }
        Ok(())
    }

    /// Gets the current hypervisor reference time.
    pub fn reference_time(&self) -> Result<u64, Error> {
        Ok(self
            .get_vp_register(HvAllArchRegisterName::TimeRefCount, HvInputVtl::CURRENT_VTL)?
            .as_u64())
    }

    /// Get a single VP register for the given VTL via hypercall. Only a select
    /// set of registers are supported; others will cause a panic.
    #[cfg(guest_arch = "x86_64")]
    pub fn get_vp_register(
        &self,
        name: impl Into<HvX64RegisterName>,
        vtl: HvInputVtl,
    ) -> Result<HvRegisterValue, Error> {
        self.mshv_hvcall.get_vp_register_for_vtl(vtl, name.into())
    }

    /// Get a single VP register for the given VTL via hypercall. Only a select
    /// set of registers are supported; others will cause a panic.
    #[cfg(guest_arch = "aarch64")]
    pub fn get_vp_register(
        &self,
        name: impl Into<HvArm64RegisterName>,
        vtl: HvInputVtl,
    ) -> Result<HvRegisterValue, Error> {
        self.mshv_hvcall.get_vp_register_for_vtl(vtl, name.into())
    }

    /// Set a single VP register via hypercall as VTL2. Only a select set of registers are
    /// supported, others will cause a panic.
    fn set_vp_register(
        &self,
        name: HvRegisterName,
        value: HvRegisterValue,
        vtl: HvInputVtl,
    ) -> Result<(), HvError> {
        match vtl.target_vtl().unwrap() {
            None | Some(Vtl::Vtl2) => {
                #[cfg(guest_arch = "x86_64")]
                assert!(matches!(
                    name.into(),
                    HvX64RegisterName::GuestVsmPartitionConfig
                        | HvX64RegisterName::VsmPartitionConfig
                        | HvX64RegisterName::PmTimerAssist
                ));

                #[cfg(guest_arch = "aarch64")]
                assert!(matches!(
                    name.into(),
                    HvArm64RegisterName::GuestVsmPartitionConfig
                        | HvArm64RegisterName::VsmPartitionConfig
                ));
            }
            Some(Vtl::Vtl1) => {
                // TODO: allowed registers for VTL1
                todo!();
            }
            Some(Vtl::Vtl0) => {
                // TODO: allowed registers for VTL0
                todo!();
            }
        }

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index: HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };

        let input = HvRegisterAssoc {
            name,
            pad: Default::default(),
            value,
        };

        tracing::trace!(?name, register = ?value, "HvCallSetVpRegisters");

        // SAFETY: The input header and rep slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let output = unsafe {
            self.mshv_hvcall
                .hvcall_rep::<hvdef::hypercall::GetSetVpRegisters, HvRegisterAssoc, u8>(
                    HypercallCode::HvCallSetVpRegisters,
                    &header,
                    HvcallRepInput::Elements(&[input]),
                    None,
                )
                .expect("set_vp_registers hypercall should not fail")
        };

        output.result()?;

        // hypercall must succeed with 1 rep completed
        assert_eq!(output.elements_processed(), 1);
        Ok(())
    }

    /// Translate the following gva to a gpa page.
    ///
    /// The caller must ensure `control_flags.input_vtl()` is set to a specific
    /// VTL.
    #[cfg(guest_arch = "aarch64")]
    pub fn translate_gva_to_gpa(
        &self,
        gva: u64,
        control_flags: hvdef::hypercall::TranslateGvaControlFlagsArm64,
    ) -> Result<Result<TranslateResult, aarch64::TranslateErrorAarch64>, TranslateGvaToGpaError>
    {
        use hvdef::hypercall;

        assert!(!self.isolation.is_hardware_isolated());
        assert!(
            control_flags.input_vtl().use_target_vtl(),
            "did not specify a target VTL"
        );

        let header = hypercall::TranslateVirtualAddressArm64 {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index: HV_VP_INDEX_SELF,
            reserved: 0,
            control_flags,
            gva_page: gva >> hvdef::HV_PAGE_SHIFT,
        };

        let mut output: hypercall::TranslateVirtualAddressExOutputArm64 = FromZeroes::new_zeroed();

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall(
                    HypercallCode::HvCallTranslateVirtualAddressEx,
                    &header,
                    &mut output,
                )
                .expect("translate can never fail")
        };

        status
            .result()
            .map_err(|hv_error| TranslateGvaToGpaError::Hypervisor { gva, hv_error })?;

        // Note: WHP doesn't currently support TranslateVirtualAddressEx, so overlay_page, cache_type,
        // event_info aren't trustworthy values if the results came from WHP.
        match output.translation_result.result.result_code() {
            c if c == hypercall::TranslateGvaResultCode::SUCCESS.0 => Ok(Ok(TranslateResult {
                gpa_page: output.gpa_page,
                overlay_page: output.translation_result.result.overlay_page(),
            })),
            x => Ok(Err(aarch64::TranslateErrorAarch64 { code: x })),
        }
    }

    fn to_hv_gpa_range_array(gpa_memory_ranges: &[MemoryRange]) -> Vec<HvGpaRange> {
        const PAGES_PER_ENTRY: u64 = 2048;
        const PAGE_SIZE: u64 = HV_PAGE_SIZE;

        // Estimate the total number of pages across all memory ranges
        let estimated_size: usize = gpa_memory_ranges
            .iter()
            .map(|memory_range| {
                let total_pages = (memory_range.end() - memory_range.start()).div_ceil(PAGE_SIZE);
                total_pages.div_ceil(PAGES_PER_ENTRY)
            })
            .sum::<u64>() as usize;

        // Create a vector with the estimated size
        let mut hv_gpa_ranges = Vec::with_capacity(estimated_size);

        for memory_range in gpa_memory_ranges {
            // Calculate the total number of pages in the memory range
            let total_pages = (memory_range.end() - memory_range.start()).div_ceil(PAGE_SIZE);

            // Convert start address to page number
            let start_page = memory_range.start_4k_gpn();

            // Generate the ranges and append them to the vector
            hv_gpa_ranges.extend(
                (0..total_pages)
                    .step_by(PAGES_PER_ENTRY as usize)
                    .map(|start| {
                        let end = std::cmp::min(total_pages, start + PAGES_PER_ENTRY);
                        let pages_in_this_range = end - start;
                        let gpa_page_number = start_page + start;

                        let extended = HvGpaRangeExtended::new()
                            .with_additional_pages(pages_in_this_range - 1)
                            .with_large_page(false) // Assuming not a large page
                            .with_gpa_page_number(gpa_page_number);

                        HvGpaRange(extended.into_bits())
                    }),
            );
        }

        hv_gpa_ranges // Return the vector at the end
    }

    fn pin_unpin_gpa_ranges_internal(
        &self,
        gpa_ranges: &[HvGpaRange],
        action: GpaPinUnpinAction,
    ) -> Result<(), PinUnpinError> {
        const PIN_REQUEST_HEADER_SIZE: usize =
            size_of::<hvdef::hypercall::PinUnpinGpaPageRangesHeader>();
        const MAX_INPUT_ELEMENTS: usize =
            (HV_PAGE_SIZE as usize - PIN_REQUEST_HEADER_SIZE) / size_of::<u64>();

        let header = hvdef::hypercall::PinUnpinGpaPageRangesHeader { reserved: 0 };
        let mut ranges_processed = 0;

        for chunk in gpa_ranges.chunks(MAX_INPUT_ELEMENTS) {
            // SAFETY: This unsafe block is valid because:
            // 1. The code and header going to match the expected input for the hypercall.
            //
            // 2. Hypercall result is checked right after the hypercall is issued.
            //
            let output = unsafe {
                self.mshv_hvcall
                    .hvcall_rep(
                        match action {
                            GpaPinUnpinAction::PinGpaRange => HypercallCode::HvCallPinGpaPageRanges,
                            GpaPinUnpinAction::UnpinGpaRange => {
                                HypercallCode::HvCallUnpinGpaPageRanges
                            }
                        },
                        &header,
                        HvcallRepInput::Elements(chunk),
                        None::<&mut [u8]>,
                    )
                    .expect("submitting pin/unpin hypercall should not fail")
            };

            ranges_processed += output.elements_processed();

            output.result().map_err(|e| PinUnpinError {
                ranges_processed,
                error: e,
            })?;
        }

        // At end all the ranges should be processed
        if ranges_processed == gpa_ranges.len() {
            Ok(())
        } else {
            Err(PinUnpinError {
                ranges_processed,
                error: HvError::OperationFailed,
            })
        }
    }

    fn perform_pin_unpin_gpa_ranges(
        &self,
        gpa_ranges: &[MemoryRange],
        action: GpaPinUnpinAction,
        rollback_action: GpaPinUnpinAction,
    ) -> Result<(), HvError> {
        let hv_gpa_ranges: Vec<HvGpaRange> = Self::to_hv_gpa_range_array(gpa_ranges);

        // Attempt to pin/unpin the ranges
        match self.pin_unpin_gpa_ranges_internal(&hv_gpa_ranges, action) {
            Ok(_) => Ok(()),
            Err(PinUnpinError {
                error,
                ranges_processed,
            }) => {
                // Unpin the ranges that were successfully pinned
                let pinned_ranges = &hv_gpa_ranges[..ranges_processed];
                if let Err(rollback_error) =
                    self.pin_unpin_gpa_ranges_internal(pinned_ranges, rollback_action)
                {
                    // Panic if rollback is failing
                    panic!(
                        "Failed to perform action {:?} on ranges. Error : {:?}. \
                        Attempted to rollback {:?} ranges out of {:?}.\n rollback error: {:?}",
                        action,
                        error,
                        ranges_processed,
                        gpa_ranges.len(),
                        rollback_error
                    );
                }
                // Surface the original error
                Err(error)
            }
        }
    }

    /// Pins the specified guest physical address ranges in the hypervisor.
    /// The memory ranges passed to this function must be VA backed memory.
    /// If a partial failure occurs (i.e., some but not all the ranges were successfully pinned),
    /// the function will automatically attempt to unpin any successfully pinned ranges.
    /// This "rollback" behavior ensures that no partially pinned state remains, which
    /// could otherwise lead to inconsistencies.
    ///
    pub fn pin_gpa_ranges(&self, ranges: &[MemoryRange]) -> Result<(), HvError> {
        self.perform_pin_unpin_gpa_ranges(
            ranges,
            GpaPinUnpinAction::PinGpaRange,
            GpaPinUnpinAction::UnpinGpaRange,
        )
    }

    /// Unpins the specified guest physical address ranges in the hypervisor.
    /// The memory ranges passed to this function must be VA backed memory.
    /// If a partial failure occurs (i.e., some but not all the ranges were successfully unpinned),
    /// the function will automatically attempt to pin any successfully unpinned ranges. This "rollback"
    /// behavior ensures that no partially unpinned state remains, which could otherwise lead to inconsistencies.
    ///
    pub fn unpin_gpa_ranges(&self, ranges: &[MemoryRange]) -> Result<(), HvError> {
        self.perform_pin_unpin_gpa_ranges(
            ranges,
            GpaPinUnpinAction::UnpinGpaRange,
            GpaPinUnpinAction::PinGpaRange,
        )
    }

    /// Read the vsm capabilities register for VTL2.
    pub fn get_vsm_capabilities(&self) -> Result<hvdef::HvRegisterVsmCapabilities, Error> {
        let caps = hvdef::HvRegisterVsmCapabilities::from(
            self.get_vp_register(
                HvAllArchRegisterName::VsmCapabilities,
                HvInputVtl::CURRENT_VTL,
            )?
            .as_u64(),
        );

        let caps = match self.isolation {
            IsolationType::None | IsolationType::Vbs => caps,
            // TODO SNP: Return actions may be useful, but with alternate injection many of these need
            // cannot actually be processed by the hypervisor without returning to VTL2.
            // Filter them out for now.
            IsolationType::Snp => hvdef::HvRegisterVsmCapabilities::new()
                .with_deny_lower_vtl_startup(caps.deny_lower_vtl_startup())
                .with_intercept_page_available(caps.intercept_page_available()),
            // TODO TDX: Figure out what these values should be.
            IsolationType::Tdx => hvdef::HvRegisterVsmCapabilities::new()
                .with_deny_lower_vtl_startup(caps.deny_lower_vtl_startup())
                .with_intercept_page_available(caps.intercept_page_available()),
        };
        Ok(caps)
    }

    /// Set the [`hvdef::HvRegisterVsmPartitionConfig`] register.
    pub fn set_vtl2_vsm_partition_config(
        &self,
        vsm_config: HvRegisterVsmPartitionConfig,
    ) -> Result<(), SetVsmPartitionConfigError> {
        self.set_vp_register(
            HvAllArchRegisterName::VsmPartitionConfig.into(),
            HvRegisterValue::from(u64::from(vsm_config)),
            HvInputVtl::CURRENT_VTL,
        )
        .map_err(|e| SetVsmPartitionConfigError::Hypervisor {
            config: vsm_config,
            hv_error: e,
        })
    }

    /// Get the [`hvdef::HvRegisterGuestVsmPartitionConfig`] register
    pub fn get_guest_vsm_partition_config(
        &self,
    ) -> Result<hvdef::HvRegisterGuestVsmPartitionConfig, Error> {
        Ok(hvdef::HvRegisterGuestVsmPartitionConfig::from(
            self.get_vp_register(
                HvAllArchRegisterName::GuestVsmPartitionConfig,
                HvInputVtl::CURRENT_VTL,
            )?
            .as_u64(),
        ))
    }

    /// Configure guest VSM.
    /// The only configuration attribute currently supported is changing the maximum number of
    /// guest-visible virtual trust levels for the partition. (VTL 1)
    pub fn set_guest_vsm_partition_config(
        &self,
        enable_guest_vsm: bool,
    ) -> Result<(), SetGuestVsmConfigError> {
        let register_value = hvdef::HvRegisterGuestVsmPartitionConfig::new()
            .with_maximum_vtl(if enable_guest_vsm { 1 } else { 0 })
            .with_reserved(0);

        tracing::trace!(enable_guest_vsm, "set_guest_vsm_partition_config");
        if self.isolation.is_hardware_isolated() {
            unimplemented!("set_guest_vsm_partition_config");
        }

        self.set_vp_register(
            HvAllArchRegisterName::GuestVsmPartitionConfig.into(),
            HvRegisterValue::from(u64::from(register_value)),
            HvInputVtl::CURRENT_VTL,
        )
        .map_err(|e| SetGuestVsmConfigError::Hypervisor {
            enable_guest_vsm,
            hv_error: e,
        })
    }

    /// Sets the Power Management Timer assist in the hypervisor.
    #[cfg(guest_arch = "x86_64")]
    pub fn set_pm_timer_assist(&self, port: Option<u16>) -> Result<(), HvError> {
        tracing::debug!(?port, "set_pm_timer_assist");
        if self.isolation.is_hardware_isolated() {
            if port.is_some() {
                unimplemented!("set_pm_timer_assist");
            }
        }

        let val = HvRegisterValue::from(u64::from(match port {
            Some(p) => hvdef::HvPmTimerInfo::new()
                .with_port(p)
                .with_enabled(true)
                .with_width_24(false),
            None => 0.into(),
        }));

        self.set_vp_register(
            HvX64RegisterName::PmTimerAssist.into(),
            val,
            HvInputVtl::CURRENT_VTL,
        )
    }

    /// Sets the Power Management Timer assist in the hypervisor.
    #[cfg(guest_arch = "aarch64")]
    pub fn set_pm_timer_assist(&self, port: Option<u16>) -> Result<(), HvError> {
        tracing::debug!(?port, "set_pm_timer_assist unimplemented on aarch64");
        Err(HvError::UnknownRegisterName)
    }

    /// Sets the VTL protection mask for the specified memory range.
    pub fn modify_vtl_protection_mask(
        &self,
        range: MemoryRange,
        map_flags: HvMapGpaFlags,
        target_vtl: HvInputVtl,
    ) -> Result<(), ApplyVtlProtectionsError> {
        if self.isolation.is_hardware_isolated() {
            // TODO SNP TODO TDX - required for vmbus relay monitor page support
            todo!();
        }

        self.mshv_hvcall
            .modify_vtl_protection_mask(range, map_flags, target_vtl)
    }

    /// Checks whether the target vtl has vtl permissions for the given gpa
    pub fn check_vtl_access(
        &self,
        gpa: u64,
        target_vtl: GuestVtl,
        flags: HvMapGpaFlags,
    ) -> Result<Option<CheckVtlAccessResult>, Error> {
        assert!(!self.isolation.is_hardware_isolated());

        let header = hvdef::hypercall::CheckSparseGpaPageVtlAccess {
            partition_id: HV_PARTITION_ID_SELF,
            target_vtl: HvInputVtl::from(target_vtl),
            desired_access: u32::from(flags) as u8,
            reserved0: 0,
            reserved1: 0,
        };

        let mut output = [hvdef::hypercall::CheckSparseGpaPageVtlAccessOutput::new()];

        // SAFETY: The input header and rep slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall.hvcall_rep::<hvdef::hypercall::CheckSparseGpaPageVtlAccess, u64, hvdef::hypercall::CheckSparseGpaPageVtlAccessOutput>(
                HypercallCode::HvCallCheckSparseGpaPageVtlAccess,
                &header,
                HvcallRepInput::Elements(&[gpa >> hvdef::HV_PAGE_SHIFT]),
                Some(&mut output),
            )
            .expect("check_vtl_access hypercall should not fail")
        };

        // TODO GUEST_VSM: for isolated VMs, if the status is operation denied,
        // return memory unaccepted?
        status.result().map_err(Error::CheckVtlAccess)?;

        let access_result = output[0];

        if access_result.result_code() as u32
            != hvdef::hypercall::CheckGpaPageVtlAccessResultCode::SUCCESS.0
        {
            return Ok(Some(CheckVtlAccessResult {
                vtl: (access_result.intercepting_vtl() as u8)
                    .try_into()
                    .expect("checking vtl permissions failure should return valid vtl"),
                denied_flags: (access_result.denied_access() as u32).into(),
            }));
        }

        assert_eq!(status.elements_processed(), 1);
        Ok(None)
    }

    /// Enables a vtl for the partition
    pub fn enable_partition_vtl(
        &self,
        vtl: GuestVtl,
        flags: hvdef::hypercall::EnablePartitionVtlFlags,
    ) -> Result<(), HvError> {
        use hvdef::hypercall;

        let header = hypercall::EnablePartitionVtl {
            partition_id: HV_PARTITION_ID_SELF,
            target_vtl: vtl.into(),
            flags,
            reserved_z0: 0,
            reserved_z1: 0,
        };

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall(HypercallCode::HvCallEnablePartitionVtl, &header, &mut ())
                .expect("submitting hypercall should not fail")
        };

        status.result()
    }

    /// Enables a vtl on a vp
    pub fn enable_vp_vtl(
        &self,
        vp_index: u32,
        vtl: GuestVtl,
        hv_vp_context: InitialVpContextX64,
    ) -> Result<(), HvError> {
        use hvdef::hypercall;

        let header = hypercall::EnableVpVtlX64 {
            partition_id: HV_PARTITION_ID_SELF,
            vp_index,
            target_vtl: vtl.into(),
            reserved: [0; 3],
            vp_vtl_context: hv_vp_context,
        };

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall(HypercallCode::HvCallEnableVpVtl, &header, &mut ())
                .expect("submitting hypercall should not fail")
        };

        status.result()
    }

    /// Gets the PFN for the VTL 1 VMSA
    pub fn vtl1_vmsa_pfn(&self, vp_index: u32) -> u64 {
        let mut vp_pfn = vp_index as u64; // input vp, output pfn

        // SAFETY: The ioctl requires no prerequisites other than the VTL 1 VMSA
        // should be mapped. This ioctl should never fail as long as the vtl 1
        // VMSA was mapped.
        unsafe {
            hcl_read_guest_vsm_page_pfn(self.mshv_vtl.file.as_raw_fd(), &mut vp_pfn)
                .expect("should always succeed");
        }

        vp_pfn
    }

    /// Returns the isolation type for the partition.
    pub fn isolation(&self) -> IsolationType {
        self.isolation
    }

    /// Reads MSR_IA32_VMX_CR4_FIXED1 in kernel mode.
    pub fn read_vmx_cr4_fixed1(&self) -> u64 {
        let mut value = 0;

        // SAFETY: The ioctl requires no prerequisites other than a location to
        // write the read MSR. This ioctl should never fail.
        unsafe {
            hcl_read_vmx_cr4_fixed1(self.mshv_vtl.file.as_raw_fd(), &mut value)
                .expect("should always succeed");
        }

        value
    }

    /// Invokes the HvCallMemoryMappedIoRead hypercall
    pub fn memory_mapped_io_read(&self, gpa: u64, data: &mut [u8]) -> Result<(), HvError> {
        assert!(data.len() <= hvdef::hypercall::HV_HYPERCALL_MMIO_MAX_DATA_LENGTH);

        let header = hvdef::hypercall::MemoryMappedIoRead {
            gpa,
            access_width: data.len() as u32,
            reserved_z0: 0,
        };

        let mut output: hvdef::hypercall::MemoryMappedIoReadOutput = FromZeroes::new_zeroed();

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall(
                    HypercallCode::HvCallMemoryMappedIoRead,
                    &header,
                    &mut output,
                )
                .expect("submitting hypercall should not fail")
        };

        // Only copy the data if the hypercall was successful
        if status.result().is_ok() {
            data.copy_from_slice(&output.data[..data.len()]);
        };

        status.result()
    }

    /// Invokes the HvCallMemoryMappedIoWrite hypercall
    pub fn memory_mapped_io_write(&self, gpa: u64, data: &[u8]) -> Result<(), HvError> {
        assert!(data.len() <= hvdef::hypercall::HV_HYPERCALL_MMIO_MAX_DATA_LENGTH);

        let mut header = hvdef::hypercall::MemoryMappedIoWrite {
            gpa,
            access_width: data.len() as u32,
            reserved_z0: 0,
            data: [0; hvdef::hypercall::HV_HYPERCALL_MMIO_MAX_DATA_LENGTH],
        };

        header.data[..data.len()].copy_from_slice(data);

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall(HypercallCode::HvCallMemoryMappedIoWrite, &header, &mut ())
                .expect("submitting hypercall should not fail")
        };

        status.result()
    }

    /// Invokes the HvCallRetargetDeviceInterrupt hypercall.
    /// `target_processors` must be sorted in ascending order.
    pub fn retarget_device_interrupt(
        &self,
        device_id: u64,
        entry: hvdef::hypercall::InterruptEntry,
        vector: u32,
        multicast: bool,
        target_processors: &[u32],
    ) -> Result<(), HvError> {
        let header = hvdef::hypercall::RetargetDeviceInterrupt {
            partition_id: HV_PARTITION_ID_SELF,
            device_id,
            entry,
            rsvd: 0,
            target_header: hvdef::hypercall::InterruptTarget {
                vector,
                flags: hvdef::hypercall::HvInterruptTargetFlags::default()
                    .with_multicast(multicast)
                    .with_processor_set(true),
                // Always use a generic processor set to simplify construction. This hypercall is
                // invoked relatively infrequently, the overhead should be acceptable.
                mask_or_format: hvdef::hypercall::HV_GENERIC_SET_SPARSE_4K,
            },
        };

        // The processor set is initialized with only the banks field, set to 0.
        let mut processor_set = vec![0u64; 1];
        let mut last_bank = None;
        let mut last_processor = None;
        for processor in target_processors {
            if let Some(last_processor) = last_processor {
                assert!(*processor > last_processor);
            }

            let bank = *processor as usize / 64;
            let bit = *processor as usize % 64;
            if Some(bank) != last_bank {
                processor_set.push(0);
                processor_set[0] |= 1 << bank;
                last_bank = Some(bank);
            }
            *processor_set.last_mut().unwrap() |= 1 << bit;
            last_processor = Some(*processor);
        }

        // SAFETY: The input header and slice are the correct types for this hypercall.
        //         The hypercall output is validated right after the hypercall is issued.
        let status = unsafe {
            self.mshv_hvcall
                .hvcall_var(
                    HypercallCode::HvCallRetargetDeviceInterrupt,
                    &header,
                    processor_set.as_bytes(),
                    &mut (),
                )
                .expect("submitting hypercall should not fail")
        };

        status.result()
    }

    /// Gets the permissions for a vtl.
    /// Currently unused, but available for debugging purposes
    #[cfg(debug_assertions)]
    pub fn rmp_query(&self, gpa: u64, vtl: GuestVtl) -> x86defs::snp::SevRmpAdjust {
        use x86defs::snp::SevRmpAdjust;

        let page_count = 1u64;
        let flags = [u64::from(SevRmpAdjust::new().with_target_vmpl(match vtl {
            GuestVtl::Vtl0 => 2,
            GuestVtl::Vtl1 => 1,
        }))];
        let page_size = [0u64];
        let pages_processed = 0;

        debug_assert!(flags.len() == page_count as usize);
        debug_assert!(page_size.len() == page_count as usize);

        let query = mshv_rmpquery {
            start_pfn: gpa / HV_PAGE_SIZE,
            page_count,
            terminate_on_failure: 0,
            ram: 0,
            padding: Default::default(),
            flags: flags.as_ptr().cast_mut(),
            page_size: page_size.as_ptr().cast_mut(),
            pages_processed: core::ptr::from_ref(&pages_processed).cast_mut(),
        };

        // SAFETY: the input query is the correct type for this ioctl
        unsafe {
            hcl_rmpquery_pages(self.mshv_vtl.file.as_raw_fd(), &query)
                .expect("should always succeed");
        }
        debug_assert!(pages_processed <= page_count);

        SevRmpAdjust::from(flags[0])
    }

    /// Issues an INVLPGB instruction.
    pub fn invlpgb(&self, rax: u64, edx: u32, ecx: u32) {
        let data = mshv_invlpgb {
            rax,
            edx,
            ecx,
            _pad0: 0,
            _pad1: 0,
        };
        // SAFETY: ioctl has no prerequisites.
        unsafe {
            hcl_invlpgb(self.mshv_vtl.file.as_raw_fd(), &data).expect("should always succeed");
        }
    }

    /// Issues a TLBSYNC instruction.
    pub fn tlbsync(&self) {
        // SAFETY: ioctl has no prerequisites.
        unsafe {
            hcl_tlbsync(self.mshv_vtl.file.as_raw_fd()).expect("should always succeed");
        }
    }
}
