// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Calculate DMA hint value if not provided by host.

use crate::log;
use igvm_defs::MemoryMapEntryType;
use super::PartitionInfo;

struct DmaLookupStruct {
    /// Logical processors for VM.
    vp_count: u32,
    /// Vtl2AddressRangeSize - Vtl2MmioAddressRangeSize.
    vtl2_memory_mb: u32,
    /// DMA hint in MiB.
    dma_hint_mb: u32,
}

/// Lookup table for DMA hint calculation.
const LookupTable: &'static [DmaLookupStruct] = &[
    DmaLookupStruct {
        vp_count: 2,
        vtl2_memory_mb: 98,
        dma_hint_mb: 4,
    },
    DmaLookupStruct {
        vp_count: 4,
        vtl2_memory_mb: 110,
        dma_hint_mb: 6,
    },
    DmaLookupStruct {
        vp_count: 8,
        vtl2_memory_mb: 148,
        dma_hint_mb: 10,
    },
    DmaLookupStruct {
        vp_count: 16,
        vtl2_memory_mb: 256,
        dma_hint_mb: 18,
    },
    DmaLookupStruct {
        vp_count: 32,
        vtl2_memory_mb: 516,
        dma_hint_mb: 36,
    },
    DmaLookupStruct {
        vp_count: 48,
        vtl2_memory_mb: 718,
        dma_hint_mb: 52,
    },
    DmaLookupStruct {
        vp_count: 64,
        vtl2_memory_mb: 924,
        dma_hint_mb: 68,
    },
    DmaLookupStruct {
        vp_count: 96,
        vtl2_memory_mb: 1340,
        dma_hint_mb: 102,
    },
];

pub fn vtl2_calculate_dma_hint(vp_count: usize, storage: &PartitionInfo) -> u64 {
    let mut dma_hint = 0;
    log!("YSP: vp_count = {}", vp_count);
    let mem_size = storage
        .vtl2_ram
        .iter()
        .filter(|m| m.mem_type == MemoryMapEntryType::VTL2_PROTECTABLE)
        .map(|e| e.range.len())
        .sum::<u64>();
    // Sanity check for the calculated memory size.
    if mem_size > 0 && mem_size < 0xFFFFFFFF00000 {
        let mem_size_mb = (mem_size / 1048576) as u32;
        log!("YSP: mem_size_mb = {}", mem_size_mb);

        LookupTable
            .iter()
            .filter(|e| e.vp_count == vp_count as u32)
            .for_each(|f| {
                if f.vtl2_memory_mb == mem_size_mb {
                    // Found exact match.
                    dma_hint = f.dma_hint_mb as u64;
                } else {
                    // Try to extrapolate based on similar values.
                }
        });
    }

    dma_hint
}
