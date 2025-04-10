// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Calculate DMA hint value if not provided by host.

use crate::log;
use igvm_defs::MemoryMapEntryType;
use super::PartitionInfo;

pub fn vtl2_calculate_dma_hint(vp_count: usize, storage: &PartitionInfo) -> u64 {
    log!("YSP: vp_count = {}", vp_count);
    let mem_size = storage
        .vtl2_ram
        .iter()
        .filter(|m| m.mem_type == MemoryMapEntryType::VTL2_PROTECTABLE)
        .map(|e| e.range.len())
        .sum::<u64>();
    log!("YSP: mem_size = {}", mem_size);
    16384
}
