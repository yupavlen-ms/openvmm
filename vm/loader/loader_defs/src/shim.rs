// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Loader definitions for the openhcl boot loader (`openhcl_boot`).

use open_enum::open_enum;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Shim parameters set by the loader at IGVM build time. These contain shim
/// base relative offsets and sizes instead of absolute addresses. Sizes are in
/// bytes.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct ShimParamsRaw {
    /// The offset to the Linux kernel entry point.
    pub kernel_entry_offset: i64,
    /// The offset to the [`crate::paravisor::ParavisorCommandLine`] structure.
    pub cmdline_offset: i64,
    /// The offset to the initrd.
    pub initrd_offset: i64,
    /// The size of the initrd.
    pub initrd_size: u64,
    /// The crc32 of the initrd.
    pub initrd_crc: u32,
    /// Isolation type supported by the igvm file.
    pub supported_isolation_type: SupportedIsolationType,
    /// The offset to the start of the VTL2 memory region.
    pub memory_start_offset: i64,
    /// The size of the VTL2 memory region.
    pub memory_size: u64,
    /// The offset to the parameter region.
    pub parameter_region_offset: i64,
    /// The size of the parameter region.
    pub parameter_region_size: u64,
    /// The offset to the VTL2 reserved region.
    pub vtl2_reserved_region_offset: i64,
    /// The size of the VTL2 reserved region.
    pub vtl2_reserved_region_size: u64,
    /// The offset to the sidecar memory region.
    pub sidecar_offset: i64,
    /// The size of the sidecar memory region.
    pub sidecar_size: u64,
    /// The offset to the entry point for the sidecar.
    pub sidecar_entry_offset: i64,
    /// The offset to the populated portion of VTL2 memory.
    pub used_start: i64,
    /// The offset to the end of the populated portion of VTL2 memory.
    pub used_end: i64,
    /// The offset to the bounce buffer range. This is 0 if unavailable.
    pub bounce_buffer_start: i64,
    /// The size of the bounce buffer range. This is 0 if unavailable.
    pub bounce_buffer_size: u64,
}

open_enum! {
    /// Possible isolation types supported by the shim.
    #[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
    pub enum SupportedIsolationType: u32 {
        // Starting from 1 for consistency with None usually being 0, but
        // the IGVM file for None and Vbs will likely be the same, so None will
        // not be enumerated here.At runtime, calls will be made to query
        // the actual isolation type of the partition.
        /// VBS-isolation is supported.
        VBS = 1,
        /// AMD SEV-SNP isolation is supported
        SNP = 2,
        /// Intel TDX isolation is supported
        TDX = 3,
    }
}

open_enum! {
    /// The memory type reported from the bootshim to usermode, for which VTL a
    /// given memory range is for.
    pub enum MemoryVtlType: u32 {
        /// This memory is for VTL0.
        VTL0 = 0,
        /// This memory is used by VTL2 as regular ram.
        VTL2_RAM = 1,
        /// This memory holds VTL2 config data, which is marked as reserved to
        /// the kernel.
        VTL2_CONFIG = 2,
        /// This memory is used by the VTL2 sidecar as it's image, and is marked
        /// as reserved to the kernel.
        VTL2_SIDECAR_IMAGE = 3,
        /// This memory is used by the VTL2 sidecar as node memory, and is
        /// marked as reserved to the kernel.
        VTL2_SIDECAR_NODE = 4,
        /// This range is mmio for VTL0.
        VTL0_MMIO = 5,
        /// This range is mmio for VTL2.
        VTL2_MMIO = 6,
        /// This memory holds VTL2 data which should be preserved by the kernel
        /// and usermode. Today, this is only used for SNP: VMSA, CPUID pages,
        /// and secrets pages.
        VTL2_RESERVED = 7,
        /// This memory is used by VTL2 usermode as a persisted GPA page pool.
        /// This memory is part of VTL2's address space, not VTL0's. It is
        /// marked as reserved to the kernel.
        VTL2_GPA_POOL = 8,
    }
}

impl MemoryVtlType {
    /// Returns true if this range is a ram type.
    pub fn ram(&self) -> bool {
        matches!(
            *self,
            MemoryVtlType::VTL0
                | MemoryVtlType::VTL2_RAM
                | MemoryVtlType::VTL2_CONFIG
                | MemoryVtlType::VTL2_SIDECAR_IMAGE
                | MemoryVtlType::VTL2_SIDECAR_NODE
                | MemoryVtlType::VTL2_RESERVED
                | MemoryVtlType::VTL2_GPA_POOL
        )
    }
}
