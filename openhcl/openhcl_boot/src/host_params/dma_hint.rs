// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Calculate DMA hint value if not provided by host.

use crate::log;
use igvm_defs::{MemoryMapEntryType, PAGE_SIZE_4K};
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
const LOOKUP_TABLE: &'static [DmaLookupStruct] = &[
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

/// Returns calculated DMA hint value, in 4k pages.
pub fn vtl2_calculate_dma_hint(vp_count: usize, storage: &PartitionInfo) -> u64 {
    let mut dma_hint_4k = 0;
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

        let mut min_vtl2_memory_mb = 1000000;
        let mut max_vtl2_memory_mb = 0;
        // TODO: If we won't allow floats in boot-shim, replace with scaled integers
        let mut min_ratio: f32 = 0.1;
        let mut max_ratio: f32 = 0.01;

        let mut min_vp_count = 1;
        let mut max_vp_count = 4096;

        for f in LOOKUP_TABLE {
            if f.vp_count == vp_count as u32 {
                if f.vtl2_memory_mb == mem_size_mb {
                    // Found exact match.
                    dma_hint_4k = f.dma_hint_mb as u64 * 1048576 / PAGE_SIZE_4K;
                    break;
                } else {
                    // Prepare for possible extrapolation.
                    min_vtl2_memory_mb = min_vtl2_memory_mb.min(f.vtl2_memory_mb);
                    max_vtl2_memory_mb = max_vtl2_memory_mb.max(f.vtl2_memory_mb);
                    min_ratio = min_ratio.min(f.dma_hint_mb as f32 / f.vtl2_memory_mb as f32);
                    max_ratio = max_ratio.max(f.dma_hint_mb as f32 / f.vtl2_memory_mb as f32);
                }
            } else if f.vp_count < vp_count as u32 {
                // Find the nearest VP counts if exact match is not in the table.
                min_vp_count = min_vp_count.max(f.vp_count);
            } else if f.vp_count > vp_count as u32 {
                max_vp_count = max_vp_count.min(f.vp_count);
            }
        }

        // It is possible there were no matching entries in the lookup table.
        // (i.e. unexpected VP count).
        if max_vtl2_memory_mb == 0 {
            LOOKUP_TABLE
            .iter()
            .filter(|e| e.vp_count == min_vp_count || e.vp_count == max_vp_count)
            .for_each(|f| {
                // Prepare for possible extrapolation.
                min_vtl2_memory_mb = min_vtl2_memory_mb.min(f.vtl2_memory_mb);
                max_vtl2_memory_mb = max_vtl2_memory_mb.max(f.vtl2_memory_mb);
                min_ratio = min_ratio.min(f.dma_hint_mb as f32 / f.vtl2_memory_mb as f32);
                max_ratio = max_ratio.max(f.dma_hint_mb as f32 / f.vtl2_memory_mb as f32);
            });
        }
        
        if dma_hint_4k == 0 {
            // If we didn't find an exact match for our vp_count, try to extrapolate.
            dma_hint_4k = (mem_size_mb as f32 * ((min_ratio + max_ratio) / 2.0)) as u64 *
                1048576 /
                PAGE_SIZE_4K;
        }
    }

    dma_hint_4k
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::host_params::MemoryEntry;
    use crate::MemoryRange;

    #[test]
    fn test_vtl2_calculate_dma_hint() {
        let mut storage = PartitionInfo::new();
        
        storage.vtl2_ram.clear();
        storage.vtl2_ram.push(MemoryEntry {
            range: MemoryRange::new(0x0..0x6200000),
            mem_type: MemoryMapEntryType::VTL2_PROTECTABLE,
            vnode: 0,
        });
        assert_eq!(vtl2_calculate_dma_hint(2, &storage), 1024);
        
        storage.vtl2_ram.clear();
        storage.vtl2_ram.push(MemoryEntry {
            range: MemoryRange::new(0x0..0x6E00000),
            mem_type: MemoryMapEntryType::VTL2_PROTECTABLE,
            vnode: 0,
        });
        assert_eq!(vtl2_calculate_dma_hint(4, &storage), 1536);

        // Test VP count higher than max from LOOKUP_TABLE.
        storage.vtl2_ram.clear();
        storage.vtl2_ram.push(MemoryEntry {
            range: MemoryRange::new(0x0..0x7000000),
            mem_type: MemoryMapEntryType::VTL2_PROTECTABLE,
            vnode: 0,
        });
        // TODO: Unfinished, maybe the return value is incorrect.
        assert_eq!(vtl2_calculate_dma_hint(112, &storage), 2048);
    }
}
