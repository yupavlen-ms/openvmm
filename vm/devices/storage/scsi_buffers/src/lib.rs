// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Functionality for referencing locked memory buffers for the lifetime of an
//! IO.

#![warn(missing_docs)]
// UNSAFETY: Handling raw pointers and transmuting between types for different use cases.
#![expect(unsafe_code)]

use guestmem::ranges::PagedRange;
use guestmem::AccessError;
use guestmem::GuestMemory;
use guestmem::LockedRange;
use guestmem::LockedRangeImpl;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use safeatomic::AsAtomicBytes;
use smallvec::SmallVec;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// A pointer/length pair that is ABI compatible with the iovec type on Linux.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct AtomicIoVec {
    /// The address of the buffer.
    pub address: *const AtomicU8,
    /// The length of the buffer in bytes.
    pub len: usize,
}

impl Default for AtomicIoVec {
    fn default() -> Self {
        Self {
            address: std::ptr::null(),
            len: 0,
        }
    }
}

impl From<&'_ [AtomicU8]> for AtomicIoVec {
    fn from(p: &'_ [AtomicU8]) -> Self {
        Self {
            address: p.as_ptr(),
            len: p.len(),
        }
    }
}

impl AtomicIoVec {
    /// Returns a pointer to a slice backed by the buffer.
    ///
    /// # Safety
    /// The caller must ensure this iovec points to [valid](std::ptr#Safety)
    /// data.
    pub unsafe fn as_slice_unchecked(&self) -> &[AtomicU8] {
        // SAFETY: guaranteed by caller.
        unsafe { std::slice::from_raw_parts(self.address, self.len) }
    }
}

/// SAFETY: AtomicIoVec just represents a pointer and length and can be
/// sent/accessed anywhere freely.
unsafe impl Send for AtomicIoVec {}
// SAFETY: see above comment
unsafe impl Sync for AtomicIoVec {}

/// Wrapper around an &[AtomicU8] guaranteed to be ABI compatible with the
/// `iovec` type on Linux.
#[derive(Debug, Copy, Clone, Default)]
#[repr(transparent)]
pub struct IoBuffer<'a> {
    io_vec: AtomicIoVec,
    phantom: PhantomData<&'a AtomicU8>,
}

impl<'a> IoBuffer<'a> {
    /// Wraps `buffer` and returns it.
    pub fn new(buffer: &'a [AtomicU8]) -> Self {
        Self {
            io_vec: AtomicIoVec {
                address: buffer.as_ptr(),
                len: buffer.len(),
            },
            phantom: PhantomData,
        }
    }

    /// Reinterprets `io_vec` as `IoBuffer`.
    ///
    /// # Safety
    /// `io_vec` must reference a valid buffer for the lifetime of `Self`.
    pub unsafe fn from_io_vec(io_vec: &AtomicIoVec) -> &Self {
        // SAFETY: IoBuffer is #[repr(transparent)] over AtomicIoVec
        unsafe { std::mem::transmute(io_vec) }
    }

    /// Reinterprets the `io_vecs` slice as `[IoBuffer]`.
    ///
    /// # Safety
    /// `io_vecs` must reference valid buffers for the lifetime of `Self`.
    pub unsafe fn from_io_vecs(io_vecs: &[AtomicIoVec]) -> &[Self] {
        // SAFETY: IoBuffer is #[repr(transparent)] over AtomicIoVec
        unsafe { std::mem::transmute(io_vecs) }
    }

    /// Returns a pointer to the beginning of the buffer.
    pub fn as_ptr(&self) -> *const AtomicU8 {
        self.io_vec.address
    }

    /// Returns the buffer's length in bytes.
    pub fn len(&self) -> usize {
        self.io_vec.len
    }
}

impl Deref for IoBuffer<'_> {
    type Target = [AtomicU8];

    fn deref(&self) -> &Self::Target {
        // SAFETY: the buffer is guaranteed to be valid for the lifetime of
        // self.
        unsafe { self.io_vec.as_slice_unchecked() }
    }
}

const PAGE_SIZE: usize = 4096;

#[repr(C, align(4096))]
#[derive(Clone, IntoBytes, Immutable, KnownLayout, FromBytes)]
struct Page([u8; PAGE_SIZE]);

const ZERO_PAGE: Page = Page([0; PAGE_SIZE]);

/// A page-aligned buffer used to double-buffer IO data.
pub struct BounceBuffer {
    pages: Vec<Page>,
    io_vec: AtomicIoVec,
}

impl BounceBuffer {
    /// Allocates a new bounce buffer of `size` bytes.
    pub fn new(size: usize) -> Self {
        let mut pages = vec![ZERO_PAGE; size.div_ceil(PAGE_SIZE)];
        let io_vec = pages.as_mut_bytes()[..size].as_atomic_bytes().into();
        BounceBuffer { pages, io_vec }
    }

    fn len(&self) -> usize {
        self.io_vec.len
    }

    /// Returns the bounce buffer memory.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        // SAFETY: while there are no concurrent references (e.g., via io_vec),
        // the buffer in pages is exclusively owned, and it is accessible as a
        // byte array.
        unsafe { std::slice::from_raw_parts_mut(self.pages.as_mut_ptr().cast::<u8>(), self.len()) }
    }

    /// Returns a reference to the underlying buffer.
    ///
    /// This is returned in a form convenient for using with IO functions.
    pub fn io_vecs(&self) -> &[IoBuffer<'_>] {
        std::slice::from_ref({
            // SAFETY: io_vec contains a pointer to the live data in pages.
            unsafe { IoBuffer::from_io_vec(&self.io_vec) }
        })
    }
}

/// A set of locked memory ranges, represented by [`IoBuffer`]s.
pub struct LockedIoBuffers(LockedRangeImpl<LockedIoVecs>);

impl LockedIoBuffers {
    /// Returns the slice of IO buffers.
    pub fn io_vecs(&self) -> &[IoBuffer<'_>] {
        // SAFETY: the LockedRangeImpl passed to new guarantees that only
        // vectors with valid lifetimes were passed to
        // LockedGuestBuffers::push_sub_range.
        unsafe { IoBuffer::from_io_vecs(&self.0.get().0) }
    }
}

struct LockedIoVecs(SmallVec<[AtomicIoVec; 64]>);

impl LockedIoVecs {
    fn new() -> Self {
        Self(Default::default())
    }
}

impl LockedRange for LockedIoVecs {
    fn push_sub_range(&mut self, sub_range: &[AtomicU8]) {
        self.0.push(sub_range.into());
    }

    fn pop_sub_range(&mut self) -> Option<(*const AtomicU8, usize)> {
        self.0.pop().map(|buffer| (buffer.address, buffer.len))
    }
}

/// An accessor for the memory associated with an IO request.
#[derive(Clone, Debug)]
pub struct RequestBuffers<'a> {
    range: PagedRange<'a>,
    guest_memory: &'a GuestMemory,
    is_write: bool,
}

impl<'a> RequestBuffers<'a> {
    /// Creates a new request buffer from the given memory ranges.
    pub fn new(guest_memory: &'a GuestMemory, range: PagedRange<'a>, is_write: bool) -> Self {
        Self {
            range,
            guest_memory,
            is_write,
        }
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// Return the total length of the buffers in bytes.
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Returns the guest memory accessor.
    pub fn guest_memory(&self) -> &GuestMemory {
        self.guest_memory
    }

    /// Return the internal paged range.
    pub fn range(&self) -> PagedRange<'_> {
        self.range
    }

    /// Returns whether the buffers are all aligned to at least `alignment`
    /// bytes.
    ///
    /// `alignment` must be a power of two.
    pub fn is_aligned(&self, alignment: usize) -> bool {
        assert!(alignment.is_power_of_two());
        ((self.range.offset() | self.range.len() | PAGE_SIZE) & (alignment - 1)) == 0
    }

    /// Gets a memory writer for the buffers.
    ///
    /// Returns an empty writer if the buffers are only available for read access.
    pub fn writer(&self) -> impl MemoryWrite + '_ {
        let range = if self.is_write {
            self.range
        } else {
            PagedRange::empty()
        };
        range.writer(self.guest_memory)
    }

    /// Gets a memory reader for the buffers.
    pub fn reader(&self) -> impl MemoryRead + '_ {
        self.range.reader(self.guest_memory)
    }

    /// Locks the guest memory ranges described by this buffer and returns an
    /// object containing [`IoBuffer`]s, suitable for executing asynchronous I/O
    /// operations.
    pub fn lock(&self, for_write: bool) -> Result<LockedIoBuffers, AccessError> {
        if for_write && !self.is_write {
            return Err(AccessError::ReadOnly);
        }
        Ok(LockedIoBuffers(
            self.guest_memory
                .lock_range(self.range, LockedIoVecs::new())?,
        ))
    }

    /// Returns a subrange of this set of buffers.
    ///
    /// Panics if `offset + len > self.len()`.
    pub fn subrange(&self, offset: usize, len: usize) -> Self {
        Self {
            range: self.range.subrange(offset, len),
            guest_memory: self.guest_memory,
            is_write: self.is_write,
        }
    }
}

/// A memory range.
#[derive(Debug, Clone)]
pub struct OwnedRequestBuffers {
    gpns: Vec<u64>,
    offset: usize,
    len: usize,
    is_write: bool,
}

impl OwnedRequestBuffers {
    /// A new memory range with the given guest page numbers.
    pub fn new(gpns: &[u64]) -> Self {
        Self::new_unaligned(gpns, 0, gpns.len() * PAGE_SIZE)
    }

    /// A new memory range with the given guest page numbers, offset by `offset`
    /// bytes, and of `len` bytes length.
    pub fn new_unaligned(gpns: &[u64], offset: usize, len: usize) -> Self {
        Self {
            gpns: gpns.to_vec(),
            offset,
            len,
            is_write: true,
        }
    }

    /// A new memory range containing the linear address range from
    /// `offset..offset+len`.
    pub fn linear(offset: u64, len: usize, is_write: bool) -> Self {
        let start_page = offset / PAGE_SIZE as u64;
        let end_page = offset + (len as u64).div_ceil(PAGE_SIZE as u64);
        let gpns: Vec<u64> = (start_page..end_page).collect();
        Self {
            gpns,
            offset: (offset % PAGE_SIZE as u64) as usize,
            len,
            is_write,
        }
    }

    /// A [`RequestBuffers`] referencing this memory range.
    pub fn buffer<'a>(&'a self, guest_memory: &'a GuestMemory) -> RequestBuffers<'a> {
        RequestBuffers::new(
            guest_memory,
            PagedRange::new(self.offset, self.len, &self.gpns).unwrap(),
            self.is_write,
        )
    }

    /// The length of the range in bytes.
    pub fn len(&self) -> usize {
        self.len
    }
}

/// Tracks an active bounce buffer, signaling to the bounce buffer tracker
/// upon drop that pages can be reclaimed.
pub struct TrackedBounceBuffer<'a> {
    /// The active bounce buffer being tracked.
    pub buffer: BounceBuffer,
    /// Reference to free page counter for current IO thread.
    free_pages: &'a AtomicUsize,
    /// Used to signal pending bounce buffer requests of newly freed pages.
    event: &'a event_listener::Event,
}

impl Drop for TrackedBounceBuffer<'_> {
    fn drop(&mut self) {
        let pages = self.buffer.len().div_ceil(4096);
        self.free_pages.fetch_add(pages, Ordering::SeqCst);
        self.event.notify(usize::MAX);
    }
}

/// Tracks active bounce buffers against a set limit of pages. If no limit is
/// specified a default of 8Mb will be applied. This limit is tracked per thread
/// specified by the backing AffinitizedThreadpool.
#[derive(Debug)]
pub struct BounceBufferTracker {
    /// Active bounce buffer pages on a given thread.
    free_pages: Vec<AtomicUsize>,
    /// Event used by TrackedBounceBuffer to signal pages have been dropped.
    event: Vec<event_listener::Event>,
}

impl BounceBufferTracker {
    /// Create a new bounce buffer tracker.
    pub fn new(max_bounce_buffer_pages: usize, threads: usize) -> Self {
        let mut free_pages = Vec::with_capacity(threads);
        let mut event = Vec::with_capacity(threads);

        (0..threads).for_each(|_| {
            event.push(event_listener::Event::new());
            free_pages.push(AtomicUsize::new(max_bounce_buffer_pages));
        });

        Self { free_pages, event }
    }

    /// Attempts to acquire bounce buffers from the tracker proceeding if pages
    /// are available or waiting until a tracked bounce buffer is dropped, which
    /// triggers the per-thread event to indicate newly freed pages.
    pub async fn acquire_bounce_buffers<'a, 'b>(
        &'b self,
        size: usize,
        thread: usize,
    ) -> Box<TrackedBounceBuffer<'a>>
    where
        'b: 'a,
    {
        let pages = size.div_ceil(4096);
        let event = self.event.get(thread).unwrap();
        let free_pages = self.free_pages.get(thread).unwrap();

        loop {
            let listener = event.listen();
            if free_pages
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(pages))
                .is_ok()
            {
                break;
            }
            listener.await;
        }

        Box::new(TrackedBounceBuffer {
            buffer: BounceBuffer::new(size),
            free_pages,
            event,
        })
    }
}
