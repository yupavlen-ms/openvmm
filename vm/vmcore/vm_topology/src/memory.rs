// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tools to the compute guest memory layout.

use memory_range::MemoryRange;
use thiserror::Error;

const PAGE_SIZE: u64 = 4096;
const FOUR_GB: u64 = 0x1_0000_0000;

/// Represents a page-aligned byte range of memory, with additional metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "mesh", derive(mesh_protobuf::Protobuf))]
#[cfg_attr(feature = "inspect", derive(inspect::Inspect))]
pub struct MemoryRangeWithNode {
    /// The memory range.
    pub range: MemoryRange,
    /// The virtual NUMA node the range belongs to.
    pub vnode: u32,
}

/// Describes the memory layout of a guest.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "inspect", derive(inspect::Inspect))]
pub struct MemoryLayout {
    #[cfg_attr(feature = "inspect", inspect(with = "inspect_ranges_with_metadata"))]
    ram: Vec<MemoryRangeWithNode>,
    #[cfg_attr(feature = "inspect", inspect(with = "inspect_ranges"))]
    mmio: Vec<MemoryRange>,
    /// The RAM range used by VTL2. This is not present in any of the stats
    /// above.
    vtl2_range: Option<MemoryRange>,
}

#[cfg(feature = "inspect")]
fn inspect_ranges(ranges: &[MemoryRange]) -> impl '_ + inspect::Inspect {
    inspect::iter_by_key(ranges.iter().map(|range| {
        (
            range.to_string(),
            inspect::adhoc(|i| {
                i.respond().hex("length", range.len());
            }),
        )
    }))
}

#[cfg(feature = "inspect")]
fn inspect_ranges_with_metadata(ranges: &[MemoryRangeWithNode]) -> impl '_ + inspect::Inspect {
    inspect::iter_by_key(ranges.iter().map(|range| {
        (
            range.range.to_string(),
            inspect::adhoc(|i| {
                i.respond()
                    .hex("length", range.range.len())
                    .hex("vnode", range.vnode);
            }),
        )
    }))
}

/// Memory layout creation error.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid memory size.
    #[error("invalid memory size")]
    BadSize,
    /// Invalid MMIO gap configuration.
    #[error("invalid MMIO gap configuration")]
    BadMmioGaps,
    /// Invalid memory ranges.
    #[error("invalid memory or MMIO ranges")]
    BadMemoryRanges,
    /// VTL2 range is below the end of ram, and overlaps.
    #[error("vtl2 range is below end of ram")]
    Vtl2RangeBeforeEndOfRam,
}

fn validate_ranges(ranges: &[MemoryRange]) -> Result<(), Error> {
    validate_ranges_core(ranges, |x| x)
}

fn validate_ranges_with_metadata(ranges: &[MemoryRangeWithNode]) -> Result<(), Error> {
    validate_ranges_core(ranges, |x| &x.range)
}

/// Ensures everything in a list of ranges is non-empty, in order, and
/// non-overlapping.
fn validate_ranges_core<T>(ranges: &[T], getter: impl Fn(&T) -> &MemoryRange) -> Result<(), Error> {
    if ranges.iter().any(|x| getter(x).is_empty())
        || !ranges.iter().zip(ranges.iter().skip(1)).all(|(x, y)| {
            let x = getter(x);
            let y = getter(y);
            x <= y && !x.overlaps(y)
        })
    {
        return Err(Error::BadMemoryRanges);
    }

    Ok(())
}

impl MemoryLayout {
    /// Makes a new memory layout for a guest with `ram_size` bytes of memory
    /// and MMIO gaps at the locations specified by `gaps`.
    ///
    /// `ram_size` must be a multiple of the page size. Each gap must be
    /// non-empty, and the gaps must be in order and non-overlapping.
    ///
    /// `vtl2_range` describes a range of memory reserved for VTL2.
    /// It is not reported in ram.
    ///
    /// All RAM is assigned to NUMA node 0.
    pub fn new(
        ram_size: u64,
        gaps: &[MemoryRange],
        vtl2_range: Option<MemoryRange>,
    ) -> Result<Self, Error> {
        if ram_size == 0 || ram_size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::BadSize);
        }

        validate_ranges(gaps)?;
        let mut ram = Vec::new();
        let mut remaining = ram_size;
        let mut remaining_gaps = gaps.iter().cloned();
        let mut last_end = 0;

        while remaining > 0 {
            let (this, next_end) = if let Some(gap) = remaining_gaps.next() {
                (remaining.min(gap.start() - last_end), gap.end())
            } else {
                (remaining, 0)
            };

            ram.push(MemoryRangeWithNode {
                range: MemoryRange::new(last_end..last_end + this),
                vnode: 0,
            });
            remaining -= this;
            last_end = next_end;
        }

        Self::build(ram, gaps.to_vec(), vtl2_range)
    }

    /// Makes a new memory layout for a guest with the given mmio gaps and
    /// memory ranges.
    ///
    /// `memory` and `gaps` ranges must be in sorted order and non-overlapping,
    /// and describe page aligned ranges.
    pub fn new_from_ranges(
        memory: &[MemoryRangeWithNode],
        gaps: &[MemoryRange],
    ) -> Result<Self, Error> {
        validate_ranges_with_metadata(memory)?;
        validate_ranges(gaps)?;
        Self::build(memory.to_vec(), gaps.to_vec(), None)
    }

    /// Builds the memory layout.
    ///
    /// `ram` and `mmio` must already be known to be sorted.
    fn build(
        ram: Vec<MemoryRangeWithNode>,
        mmio: Vec<MemoryRange>,
        vtl2_range: Option<MemoryRange>,
    ) -> Result<Self, Error> {
        let mut all_ranges = ram
            .iter()
            .map(|x| &x.range)
            .chain(&mmio)
            .chain(&vtl2_range)
            .copied()
            .collect::<Vec<_>>();

        all_ranges.sort();
        validate_ranges(&all_ranges)?;

        if all_ranges
            .iter()
            .zip(all_ranges.iter().skip(1))
            .any(|(x, y)| x.overlaps(y))
        {
            return Err(Error::BadMemoryRanges);
        }

        let last_ram_entry = ram.last().ok_or(Error::BadMemoryRanges)?;
        let end_of_ram = last_ram_entry.range.end();

        if let Some(range) = vtl2_range {
            if range.start() < end_of_ram {
                return Err(Error::Vtl2RangeBeforeEndOfRam);
            }
        }

        Ok(Self {
            ram,
            mmio,
            vtl2_range,
        })
    }

    /// The MMIO gap ranges.
    pub fn mmio(&self) -> &[MemoryRange] {
        &self.mmio
    }

    /// The populated RAM ranges. This does not include the vtl2_range.
    pub fn ram(&self) -> &[MemoryRangeWithNode] {
        &self.ram
    }

    /// A special memory range for VTL2, if any. This memory range is treated
    /// like RAM, but is only used to hold VTL2 and is located above ram and
    /// mmio.
    pub fn vtl2_range(&self) -> Option<MemoryRange> {
        self.vtl2_range
    }

    /// The total RAM size in bytes. This is not contiguous.
    pub fn ram_size(&self) -> u64 {
        self.ram.iter().map(|r| r.range.len()).sum()
    }

    /// One past the last byte of RAM.
    pub fn end_of_ram(&self) -> u64 {
        // always at least one RAM range
        self.ram.last().expect("mmio set").range.end()
    }

    /// The bytes of RAM below 4GB.
    pub fn ram_below_4gb(&self) -> u64 {
        self.ram
            .iter()
            .filter(|r| r.range.end() < FOUR_GB)
            .map(|r| r.range.len())
            .sum()
    }

    /// The bytes of RAM at or above 4GB.
    pub fn ram_above_4gb(&self) -> u64 {
        self.ram
            .iter()
            .filter(|r| r.range.end() >= FOUR_GB)
            .map(|r| r.range.len())
            .sum()
    }

    /// The bytes of RAM above the high MMIO gap.
    ///
    /// Returns None if there aren't exactly 2 MMIO gaps.
    pub fn ram_above_high_mmio(&self) -> Option<u64> {
        if self.mmio.len() != 2 {
            return None;
        }

        Some(
            self.ram
                .iter()
                .filter(|r| r.range.start() >= self.mmio[1].end())
                .map(|r| r.range.len())
                .sum(),
        )
    }

    /// The ending RAM address below 4GB.
    ///
    /// Returns None if there is no RAM mapped below 4GB.
    pub fn max_ram_below_4gb(&self) -> Option<u64> {
        Some(
            self.ram
                .iter()
                .rev()
                .find(|r| r.range.end() < FOUR_GB)?
                .range
                .end(),
        )
    }

    /// One past the last byte of RAM, or the highest mmio range.
    pub fn end_of_ram_or_mmio(&self) -> u64 {
        std::cmp::max(self.mmio.last().expect("mmio set").end(), self.end_of_ram())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    #[test]
    fn layout() {
        let mmio = &[
            MemoryRange::new(GB..2 * GB),
            MemoryRange::new(3 * GB..4 * GB),
        ];
        let ram = &[
            MemoryRangeWithNode {
                range: MemoryRange::new(0..GB),
                vnode: 0,
            },
            MemoryRangeWithNode {
                range: MemoryRange::new(2 * GB..3 * GB),
                vnode: 0,
            },
            MemoryRangeWithNode {
                range: MemoryRange::new(4 * GB..TB + 2 * GB),
                vnode: 0,
            },
        ];

        let layout = MemoryLayout::new(TB, mmio, None).unwrap();
        assert_eq!(
            layout.ram(),
            &[
                MemoryRangeWithNode {
                    range: MemoryRange::new(0..GB),
                    vnode: 0
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(2 * GB..3 * GB),
                    vnode: 0
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(4 * GB..TB + 2 * GB),
                    vnode: 0
                },
            ]
        );
        assert_eq!(layout.mmio(), mmio);
        assert_eq!(layout.ram_size(), TB);
        assert_eq!(layout.end_of_ram(), TB + 2 * GB);

        let layout = MemoryLayout::new_from_ranges(ram, mmio).unwrap();
        assert_eq!(
            layout.ram(),
            &[
                MemoryRangeWithNode {
                    range: MemoryRange::new(0..GB),
                    vnode: 0
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(2 * GB..3 * GB),
                    vnode: 0
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(4 * GB..TB + 2 * GB),
                    vnode: 0
                },
            ]
        );
        assert_eq!(layout.mmio(), mmio);
        assert_eq!(layout.ram_size(), TB);
        assert_eq!(layout.end_of_ram(), TB + 2 * GB);
    }

    #[test]
    fn bad_layout() {
        MemoryLayout::new(TB + 1, &[], None).unwrap_err();
        let mmio = &[
            MemoryRange::new(3 * GB..4 * GB),
            MemoryRange::new(GB..2 * GB),
        ];
        MemoryLayout::new(TB, mmio, None).unwrap_err();

        MemoryLayout::new_from_ranges(&[], mmio).unwrap_err();

        let ram = &[MemoryRangeWithNode {
            range: MemoryRange::new(0..GB),
            vnode: 0,
        }];
        MemoryLayout::new_from_ranges(ram, mmio).unwrap_err();

        let ram = &[MemoryRangeWithNode {
            range: MemoryRange::new(0..GB + MB),
            vnode: 0,
        }];
        let mmio = &[
            MemoryRange::new(GB..2 * GB),
            MemoryRange::new(3 * GB..4 * GB),
        ];
        MemoryLayout::new_from_ranges(ram, mmio).unwrap_err();
    }
}
