// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Calculate DMA hint value if not provided by host.

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

/// Round up to next 2MiB.
fn round_up_to_2mb(pages_4k: u64) -> u64 {
    (pages_4k + 511) & !(511)
}

/// Returns calculated DMA hint value, in 4k pages.
pub fn vtl2_calculate_dma_hint(vp_count: usize, storage: &PartitionInfo) -> u64 {
    let mut dma_hint_4k = 0;
    let mem_size = storage
        .vtl2_ram
        .iter()
        .filter(|m| m.mem_type == MemoryMapEntryType::VTL2_PROTECTABLE)
        .map(|e| e.range.len())
        .sum::<u64>();
    // Sanity check for the calculated memory size.
    if mem_size > 0 && mem_size < 0xFFFFFFFF00000 {
        let mem_size_mb = (mem_size / 1048576) as u32;

        let mut min_vtl2_memory_mb = 1000000;
        let mut max_vtl2_memory_mb = 0;

        // To avoid using floats, scale ratios to 1:1000.
        let mut min_ratio_1000th = 100000;
        let mut max_ratio_1000th = 1000;

        let mut min_vp_count = 1;
        let mut max_vp_count = vp_count as u32;

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
                    min_ratio_1000th = min_ratio_1000th.min(f.vtl2_memory_mb as u32 * 1000 / f.dma_hint_mb as u32);
                    max_ratio_1000th = max_ratio_1000th.max(f.vtl2_memory_mb as u32 * 1000 / f.dma_hint_mb as u32);
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
                min_vtl2_memory_mb = min_vtl2_memory_mb.min(f.vtl2_memory_mb);
                max_vtl2_memory_mb = max_vtl2_memory_mb.max(f.vtl2_memory_mb);
                min_ratio_1000th = min_ratio_1000th.min(f.vtl2_memory_mb as u32 * 1000 / f.dma_hint_mb as u32);
                max_ratio_1000th = max_ratio_1000th.max(f.vtl2_memory_mb as u32 * 1000 / f.dma_hint_mb as u32);
            });
        }

        if dma_hint_4k == 0 {
            // If we didn't find an exact match for our vp_count, try to extrapolate.
            dma_hint_4k = (mem_size_mb as u64 * 1000u64 * (1048576u64 / PAGE_SIZE_4K)) /
                ((min_ratio_1000th + max_ratio_1000th) as u64 / 2u64);

            // And then round up to 2MiB.
            dma_hint_4k = round_up_to_2mb(dma_hint_4k);
        }
    }

    dma_hint_4k
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::host_params::MemoryEntry;
    use crate::MemoryRange;
    use test_with_tracing::test;

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
        assert_eq!(vtl2_calculate_dma_hint(112, &storage), 2560);

        // Test unusual VP count.
        storage.vtl2_ram.clear();
        storage.vtl2_ram.push(MemoryEntry {
            range: MemoryRange::new(0x0..0x6000000),
            mem_type: MemoryMapEntryType::VTL2_PROTECTABLE,
            vnode: 0,
        });
        assert_eq!(vtl2_calculate_dma_hint(52, &storage), 2048);

        storage.vtl2_ram.clear();
        storage.vtl2_ram.push(MemoryEntry {
            range: MemoryRange::new(0x0..0x8000000),
            mem_type: MemoryMapEntryType::VTL2_PROTECTABLE,
            vnode: 0,
        });
        assert_eq!(vtl2_calculate_dma_hint(52, &storage), 2560);
    }
}
