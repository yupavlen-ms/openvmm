// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This module implements a fixed memory allocator for allocating pages at specific location.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

mod mapped_dma;

pub use mapped_dma::FixedDmaBuffer;
pub use save_restore::MemPoolSavedState;
pub use save_restore::MemPoolState;

use anyhow::Context;
use hvdef::HV_PAGE_SIZE;
use inspect::Inspect;
use memory_range::MemoryRange;
use parking_lot::Mutex;
use std::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;
use user_driver::memory::MemoryBlock;
use user_driver::vfio::VfioDmaBuffer;
use user_driver::HostDmaAllocator;

/// Error returned when unable to allocate memory.
#[derive(Debug, Error)]
#[error("unable to allocate fixed pool size {size} with tag {tag}")]
pub struct FixedPoolOutOfMemory {
    size: u64,
    tag: String,
}

/// Error returned when unable to restore memory chunk.
#[derive(Debug, Error)]
#[error("unable to restore matching chunk pfn {pfn} size {size} with tag {tag}")]
pub struct FixedPoolNoMatchingChunk {
    pfn: u64,
    size: u64,
    tag: String,
}

/// Memory integrity error.
#[derive(Debug, Error)]
#[error("pool integrity error leaked blocks {leaked_blocks}")]
pub struct FixedPoolIntegrity {
    leaked_blocks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Inspect)]
#[inspect(external_tag)]
enum State {
    Free {
        #[inspect(hex)]
        base_pfn: u64,
        #[inspect(hex)]
        size_pages: u64,
    },
    Allocated {
        #[inspect(hex)]
        base_pfn: u64,
        #[inspect(hex)]
        size_pages: u64,
        tag: String,
    },
    Restored {
        #[inspect(hex)]
        base_pfn: u64,
        #[inspect(hex)]
        size_pages: u64,
        tag: String,
    },
    Confirmed {
        #[inspect(hex)]
        base_pfn: u64,
        #[inspect(hex)]
        size_pages: u64,
        tag: String,
    },
}

#[derive(Inspect, Debug)]
struct FixedPoolInner {
    #[inspect(iter_by_index)]
    state: Vec<State>,
}

/// A handle for fixed pool allocation. When dropped, the allocation is freed.
#[derive(Debug)]
pub struct FixedPoolHandle {
    inner: Arc<Mutex<FixedPoolInner>>,
    base_pfn: u64,
    size_pages: u64,
}

impl FixedPoolHandle {
    /// The base pfn for this allocation.
    pub fn base_pfn(&self) -> u64 {
        self.base_pfn
    }

    /// The number of 4K pages for this allocation.
    pub fn size_pages(&self) -> u64 {
        self.size_pages
    }
}

impl Drop for FixedPoolHandle {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();

        let index = inner
            .state
            .iter()
            .position(|state| {
                if let State::Allocated {
                    base_pfn: base,
                    size_pages: len,
                    tag: _,
                }
                | State::Restored {
                    base_pfn: base,
                    size_pages: len,
                    tag: _,
                }
                | State::Confirmed {
                    base_pfn: base,
                    size_pages: len,
                    tag: _,
                } = state
                {
                    *base == self.base_pfn && *len == self.size_pages
                } else {
                    false
                }
            })
            .expect("must find allocation");

        inner.state[index] = State::Free {
            base_pfn: self.base_pfn,
            size_pages: self.size_pages,
        };
    }
}

/// A page allocator for fixed memory buffer.
///
/// Pages are allocated via [`FixedPoolAllocator`] from [`Self::allocator`].
///
/// This struct is considered the "owner" of the pool allowing for save/restore.
///
#[derive(Inspect)]
pub struct FixedPool {
    #[inspect(flatten)]
    inner: Arc<Mutex<FixedPoolInner>>,
}

impl FixedPool {
    /// Create a fixed pool allocator, with the specified memory.
    // YSP: FIXME: See if we need MemoryRangeWithNode?
    pub fn new(fixed_pool: &[MemoryRange]) -> anyhow::Result<Self> {
        let mut pages = Vec::new();
        for range in fixed_pool {
            tracing::info!("YSP: FixedPool::new pfn={:X} len={}", range.start() / HV_PAGE_SIZE, range.len());
            pages.push(State::Free {
                base_pfn: range.start() / HV_PAGE_SIZE,
                size_pages: range.len() / HV_PAGE_SIZE,
            });
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(FixedPoolInner { state: pages })),
        })
    }

    /// Save memory pool allocation map.
    pub fn save(&self) -> anyhow::Result<MemPoolSavedState> {
        let inner = self.inner.lock();

        let mut mem_pool = Vec::new();
        inner.state.iter().for_each(|e| {
            if let State::Allocated {
                base_pfn: base,
                size_pages: len,
                tag: id,
            }
            | State::Restored {
                base_pfn: base,
                size_pages: len,
                tag: id,
            }
            | State::Confirmed {
                base_pfn: base,
                size_pages: len,
                tag: id,
            } = e
            {
                tracing::info!("YSP: saving memblock pfn {} len {}", *base, *len);
                mem_pool.push(MemPoolState {
                    base_pfn: *base,
                    size_pages: *len,
                    tag: id.clone(),
                    allocated: true,
                });
            } else if let State::Free {
                base_pfn: base,
                size_pages: len,
            } = e
            {
                tracing::info!("YSP: saving FREE memblock pfn {} len {}", *base, *len);
                mem_pool.push(MemPoolState {
                    base_pfn: *base,
                    size_pages: *len,
                    tag: "".into(),
                    allocated: false,
                });
            } else {
                unreachable!("invalid mem pool state");
            }
        });

        Ok(MemPoolSavedState { mem_pool })
    }

    /// Restore memory pool from allocation map.
    pub fn restore(
        fixed_pool: &[MemoryRange],
        saved_state: MemPoolSavedState,
    ) -> anyhow::Result<Self> {
        let mut pages = Vec::new();
        saved_state.mem_pool.iter().for_each(|chunk| {
            let linear = MemoryRange::from_4k_gpn_range(std::ops::Range {
                start: chunk.base_pfn,
                end: chunk.base_pfn + chunk.size_pages,
            });
            for range in fixed_pool {
                if range.contains(&linear) {
                    if chunk.allocated {
                        tracing::info!("YSP: restoring memblock pfn {} len {}", chunk.base_pfn, chunk.size_pages);
                        pages.push(State::Restored {
                            base_pfn: chunk.base_pfn,
                            size_pages: chunk.size_pages,
                            tag: chunk.tag.clone(),
                        });
                    } else {
                        tracing::info!("YSP: restoring FREE memblock pfn {} len {}", chunk.base_pfn, chunk.size_pages);
                        pages.push(State::Free {
                            base_pfn: chunk.base_pfn,
                            size_pages: chunk.size_pages,
                        });
                    }
                }
            }
        });

        Ok(Self {
            inner: Arc::new(Mutex::new(FixedPoolInner { state: pages })),
        })
    }

    /// Validate memory pool after restore finishes.
    pub fn validate(&self) -> anyhow::Result<(), FixedPoolIntegrity> {
        let inner = self.inner.lock();
        let leaked_blocks = inner
            .state
            .iter()
            .filter(|chunk| matches!(chunk, State::Restored { .. }))
            .count();

        if leaked_blocks > 0 {
            tracing::info!("YSP: validate FAIL count={}", leaked_blocks);
            return Err(FixedPoolIntegrity { leaked_blocks });
        }
        tracing::info!("YSP: validate SUCCESS");

        Ok(())
    }

    /// Return an allocator instance that can be used to allocate pages.
    pub fn allocator(&self) -> FixedPoolAllocator {
        FixedPoolAllocator {
            inner: self.inner.clone(),
        }
    }

    /// Return a spawner that allows creating multiple allocators.
    pub fn allocator_spawner(&self) -> FixedPoolAllocatorSpawner {
        FixedPoolAllocatorSpawner {
            inner: self.inner.clone(),
        }
    }
    
}

/// A spawner for [`FixedPoolAllocator`] instances.
///
/// Useful when you need to create multiple allocators, without having ownership
/// of the actual [`FixedPool`].
#[derive(Debug)]
pub struct FixedPoolAllocatorSpawner {
    inner: Arc<Mutex<FixedPoolInner>>,
}

impl FixedPoolAllocatorSpawner {
    /// Create an allocator instance that can be used to allocate pages.
    pub fn allocator(&self) -> anyhow::Result<FixedPoolAllocator> {
        FixedPoolAllocator::new(&self.inner)
    }
}

/// A page allocator for fixed memory.
///
/// Pages are allocated via the [`Self::alloc`] method and freed by dropping the
/// associated handle returned.
#[derive(Clone, Debug)]
pub struct FixedPoolAllocator {
    inner: Arc<Mutex<FixedPoolInner>>,
}

impl FixedPoolAllocator {
    const VFIO_MSHV_TAG: &str = "mshv_dma";

    fn new(inner: &Arc<Mutex<FixedPoolInner>>) -> anyhow::Result<Self> {
        Ok(Self {
            inner: inner.clone(),
        })
    }

    /// Allocate contiguous pages from the fixed pool with the given
    /// tag. If a contiguous region of free pages is not available, then an
    /// error is returned.
    pub fn alloc(
        &self,
        size_pages: NonZeroU64,
        tag: String,
    ) -> Result<FixedPoolHandle, FixedPoolOutOfMemory> {
        let mut inner = self.inner.lock();
        let size_pages = size_pages.get();

        let index = inner
            .state
            .iter()
            .position(|state| match state {
                State::Free {
                    base_pfn: _,
                    size_pages: len,
                } => *len >= size_pages,
                State::Allocated { .. } | State::Restored { .. } | State::Confirmed { .. } => false,
            })
            .ok_or(FixedPoolOutOfMemory {
                size: size_pages,
                tag: tag.clone(),
            })?;

        let base_pfn = match inner.state.swap_remove(index) {
            State::Free {
                base_pfn: base,
                size_pages: len,
            } => {
                inner.state.push(State::Allocated {
                    base_pfn: base,
                    size_pages,
                    tag,
                });

                if len > size_pages {
                    inner.state.push(State::Free {
                        base_pfn: base + size_pages,
                        size_pages: len - size_pages,
                    });
                }

                base
            }
            State::Allocated { .. } | State::Restored { .. } | State::Confirmed { .. } => {
                unreachable!()
            }
        };
        tracing::info!("YSP: FixedPoolAllocator::alloc'd {:X} pages={} index={}", base_pfn, size_pages, index);

        Ok(FixedPoolHandle {
            inner: self.inner.clone(),
            base_pfn,
            size_pages,
        })
    }

    /// Verifies that request to restore a mapping is valid
    /// and matches the saved state.
    fn restore(
        &self,
        req_pfn: u64,
        req_pages: NonZeroU64,
        tag: String,
    ) -> Result<FixedPoolHandle, FixedPoolNoMatchingChunk> {
        let mut inner = self.inner.lock();
        let req_pages = req_pages.get();

        let index = inner
            .state
            .iter()
            .position(|state| match state {
                State::Restored {
                    base_pfn: restored_pfn,
                    size_pages: restored_pages,
                    tag: _,
                } => *restored_pfn == req_pfn && *restored_pages == req_pages,
                State::Free { .. } | State::Allocated { .. } | State::Confirmed { .. } => false,
            })
            .ok_or(FixedPoolNoMatchingChunk {
                pfn: req_pfn,
                size: req_pages,
                tag: tag.clone(),
            })?;

        tracing::info!("YSP: Found matching chunk index={} for pfn={:X} size={}", index, req_pfn, req_pages);
        match inner.state.swap_remove(index) {
            State::Restored {
                base_pfn: _,
                size_pages: _,
                tag: _,
            } => {
                tracing::info!("YSP: yehaaaw");
                // Push the requested block to the collection.
                inner.state.push(State::Confirmed {
                    base_pfn: req_pfn,
                    size_pages: req_pages,
                    tag,
                });

                Ok(FixedPoolHandle {
                    inner: self.inner.clone(),
                    base_pfn: req_pfn,
                    size_pages: req_pages,
                })
            }
            State::Free { .. } | State::Allocated { .. } | State::Confirmed { .. } => {
                tracing::info!("YSP: oopsie");
                Err(FixedPoolNoMatchingChunk {
                    pfn: req_pfn,
                    size: req_pages,
                    tag,
                })
            }
        }
    }
}

#[cfg(feature = "vfio")]
impl VfioDmaBuffer for FixedPoolAllocator {
    /// Create new DMA buffer in heap memory.
    fn create_dma_buffer(&self, len: usize) -> anyhow::Result<MemoryBlock> {
        tracing::info!("YSP: FixedPoolAllocator::create_dma_buffer size={}", len);
        if len == 0 {
            anyhow::bail!("allocation of size 0 not supported");
        }

        if len as u64 % HV_PAGE_SIZE != 0 {
            anyhow::bail!("not a page-size multiple");
        }

        let size_pages = len as u64 / HV_PAGE_SIZE;
        let alloc = self
            .alloc(
                size_pages.try_into().expect("already checked nonzero"),
                FixedPoolAllocator::VFIO_MSHV_TAG.into(),
            )
            .context("failed to allocate fixed mem")?;

        let gpa_fd = hcl::ioctl::MshvVtlLow::new().context("failed to open gpa fd")?;
        let mapping = sparse_mmap::SparseMapping::new(len).context("failed to create mapping")?;
        let gpa = alloc.base_pfn() * HV_PAGE_SIZE;
        tracing::info!("YSP: fixed buff pfn {:X} gpa {:X}", alloc.base_pfn(), gpa);

        // No need to set bit 63 because this buffer is visible to VTL2 only.
        mapping
            .map_file(0, len, gpa_fd.get(), gpa, true)
            .context("sparse mapping failed")?;
        // Zeroinit the memory, there are servicing cases where this is needed.
        mapping.fill_at(0, 0, len)?;

        let pfns: Vec<_> = (alloc.base_pfn()..alloc.base_pfn() + alloc.size_pages).collect();

        // YSP: FIXME: Debug code
        let mut checker: [u8; 8] = [0; 8];
        mapping.read_at(0, checker.as_mut_slice())?;
        tracing::info!(
            "YSP: read [{} {} {} {} {} {} {} {}]",
            checker[0],
            checker[1],
            checker[2],
            checker[3],
            checker[4],
            checker[5],
            checker[6],
            checker[7],
        );

        Ok(MemoryBlock::new(FixedDmaBuffer {
            mapping,
            _alloc: alloc,
            pfns,
        }))
    }

    /// Restore DMA buffer at the same location after servicing.
    fn restore_dma_buffer(&self, len: usize, base_pfn: u64) -> anyhow::Result<MemoryBlock> {
        tracing::info!("YSP: CORRECT FixedPoolAllocator::restore_dma_buffer len={} pfn [{:X}]", len, base_pfn);
        if len == 0 {
            anyhow::bail!("allocation of size 0 not supported");
        }

        if len as u64 % HV_PAGE_SIZE != 0 {
            anyhow::bail!("not a page-size multiple");
        }

        let size_pages = len as u64 / HV_PAGE_SIZE;
        let alloc = self
            .restore(
                base_pfn,
                size_pages.try_into().expect("already checked nonzero"),
                FixedPoolAllocator::VFIO_MSHV_TAG.into(),
            )
            .context("failed to restore fixed mem")?;

        let gpa_fd = hcl::ioctl::MshvVtlLow::new().context("failed to open gpa fd")?;
        let mapping = sparse_mmap::SparseMapping::new(len).context("failed to create mapping")?;
        let gpa = alloc.base_pfn() * HV_PAGE_SIZE;
        tracing::info!("YSP: restored pfn {:X} gpa {:X}", alloc.base_pfn(), gpa);

        // No need to set bit 63 because this buffer is visible to VTL2 only.
        mapping
            .map_file(0, len, gpa_fd.get(), gpa, true)
            .context("unable to map allocation")?;

        let pfns: Vec<_> = (alloc.base_pfn()..alloc.base_pfn() + alloc.size_pages).collect();

        // YSP: FIXME: Debug code
        let mut checker: [u8; 8] = [0; 8];
        mapping.read_at(0, checker.as_mut_slice())?;
        tracing::info!(
            "YSP: read [{} {} {} {} {} {} {} {}]",
            checker[0],
            checker[1],
            checker[2],
            checker[3],
            checker[4],
            checker[5],
            checker[6],
            checker[7],
        );

        Ok(MemoryBlock::new(FixedDmaBuffer {
            mapping,
            _alloc: alloc,
            pfns,
        }))
    }
}

#[cfg(feature = "vfio")]
impl HostDmaAllocator for FixedPoolAllocator {
    fn allocate_dma_buffer(&self, len: usize) -> anyhow::Result<MemoryBlock> {
        tracing::info!("YSP: CORRECT allocate_dma_buffer {}", len);
        self.create_dma_buffer(len)
    }

    fn attach_dma_buffer(&self, len: usize, base_pfn: u64) -> anyhow::Result<MemoryBlock> {
        tracing::info!("YSP: CORRECT attach_dma_buffer len={} pfn[0]={:X}", len, base_pfn);
        self.restore_dma_buffer(len, base_pfn)
    }
}

/// Save and restore memory allocation pool state for servicing.
pub mod save_restore {
    use mesh::payload::Protobuf;

    #[derive(Protobuf)]
    #[mesh(package = "page_pool")]
    /// Fixed pool single chunk state for save/restore.
    pub struct MemPoolState {
        /// Base PFN for the chunk.
        #[mesh(1)]
        pub base_pfn: u64,
        /// Number of pages for this chunk.
        #[mesh(2)]
        pub size_pages: u64,
        /// Allocated or free.
        #[mesh(3)]
        pub allocated: bool,
        /// ID tag.
        #[mesh(4)]
        pub tag: String,
    }

    #[derive(Protobuf)]
    #[mesh(package = "page_pool")]
    /// Save-restore memory allocation mapping.
    pub struct MemPoolSavedState {
        /// Memory pool allocation map.
        #[mesh(1)]
        pub mem_pool: Vec<MemPoolState>,
    }
}

// YSP: rewrite
#[cfg(test)]
mod test {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn test_fixed_alloc() {
        let state = vec![State::Free {
            base_pfn: 10,
            size_pages: 20,
        }];
        let alloc = FixedPoolAllocator {
            inner: Arc::new(Mutex::new(FixedPoolInner { state })),
        };

        let a1 = alloc.alloc(5.try_into().unwrap(), "alloc1".into()).unwrap();
        assert_eq!(a1.base_pfn, 10);
        assert_eq!(a1.size_pages, 5);

        let a2 = alloc
            .alloc(15.try_into().unwrap(), "alloc2".into())
            .unwrap();
        assert_eq!(a2.base_pfn, 15);
        assert_eq!(a2.size_pages, 15);

        assert!(alloc.alloc(1.try_into().unwrap(), "failed".into()).is_err());

        drop(a1);
        drop(a2);

        let inner = alloc.inner.lock();
        assert_eq!(inner.state.len(), 2);
    }

    #[test]
    fn test_fixed_restore() {
        // Prepare the pool.
        let mem_range_vec = vec![
            MemoryRange::from_4k_gpn_range(std::ops::Range {start: 10, end: 90,}),
        ];
        let pool = FixedPool::new(&mem_range_vec.as_slice()).unwrap();
        let alloc = pool.allocator();

        // Allocate some block(s) as a baseline.
        let r1 = alloc
            .alloc(
                13.try_into().unwrap(),
                "restore1".into(),
            )
            .unwrap();
        assert_eq!(r1.base_pfn, 10);
        assert_eq!(r1.size_pages, 13);

        let r2 = alloc
            .alloc(
                30.try_into().unwrap(),
                "restore2".into(),
            )
            .unwrap();
        assert_eq!(r2.base_pfn, 23);
        assert_eq!(r2.size_pages, 30);

        // Save pool state into a datastore.
        let st = pool.save().unwrap();
        tracing::info!("YSP: SAVED!!!");
        assert_eq!(st.mem_pool.len(), 3);
        drop(r2);
        drop(r1);
        drop(pool);

        // Create another pool.
        let pool = FixedPool::restore(&mem_range_vec.as_slice(), st).unwrap();

        // Allocate another chunk on top of restored ones.
        let r3 = alloc
            .alloc(
                25.try_into().unwrap(),
                "restore3".into(),
            )
            .unwrap();
        assert_eq!(r3.base_pfn, 53);
        assert_eq!(r3.size_pages, 25);
    }
}
