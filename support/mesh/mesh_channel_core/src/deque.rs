// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implementation of a type-erased vector-based queue.

// UNSAFETY: Needed to erase types to avoid monomorphization overhead.
#![expect(unsafe_code)]

use core::fmt;
use std::alloc::Layout;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::ptr::drop_in_place;

/// A type-erased vector-based queue.
///
/// This is used instead of `VecDeque<T>` to avoid monomorphization overhead.
///
/// # Safety
/// The use of this type is precarious, because the various operations are not
/// type-checked with the element type. Use with care.
///
/// Additionally, this type is `Send` and `Sync` even though the underlying
/// element types may not be. It is the caller's responsibility to ensure that
/// this is wrapped in something with the appropriate `PhantomData` to prevent
/// it from being `Send` or `Sync` when it shouldn't be.
pub struct ErasedVecDeque {
    buf: NonNull<u8>,
    cap: usize,
    head: usize,
    len: usize,
    vtable: &'static ElementVtable,
}

impl fmt::Debug for ErasedVecDeque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedVecDeque")
            .field("cap", &self.cap)
            .field("head", &self.head)
            .field("len", &self.len)
            .finish()
    }
}

// SAFETY: `ErasedVecDeque` is `Send` and `Sync` even though the underlying
// element types may not be. It is the caller's responsibility to ensure that
// they don't send or share this across threads when it shouldn't be.
unsafe impl Send for ErasedVecDeque {}
// SAFETY: see above.
unsafe impl Sync for ErasedVecDeque {}

/// The vtable for a type-erased element type.
pub struct ElementVtable {
    layout: Layout,
    element_len: usize, // different from layout.size() for ZSTs
    drop: Option<unsafe fn(*mut ())>,
}

impl ElementVtable {
    /// Creates a new vtable for the given element type.
    pub const fn new<T>() -> Self {
        /// # Safety
        /// The caller must ensure that `p` is a valid pointer to a `T`, the type
        /// that this vtable was created with.
        unsafe fn drop_fn<T>(p: *mut ()) {
            // SAFETY: `p` is a valid owned pointer to a `T`.
            unsafe {
                drop_in_place(p.cast::<T>());
            }
        }

        Self {
            layout: Layout::new::<T>(),
            element_len: if size_of::<T>() == 0 {
                align_of::<T>()
            } else {
                assert!(size_of::<T>() >= align_of::<T>());
                size_of::<T>()
            },
            drop: if std::mem::needs_drop::<T>() {
                Some(drop_fn::<T>)
            } else {
                None
            },
        }
    }
}

/// A reference to a type-erased element in the queue.
///
/// This is used instead of a raw pointer to ensure the queue storage is not
/// reused while the element is still in use.
pub struct InPlaceElement<'a>(NonNull<()>, PhantomData<&'a mut ErasedVecDeque>);

impl InPlaceElement<'_> {
    pub fn as_ptr(&self) -> *mut () {
        self.0.as_ptr()
    }
}

/// An element reserved in the queue by [`ErasedVecDeque::reserve_one`].
pub struct ReservedElement<'a>(&'a mut ErasedVecDeque, usize);

impl ReservedElement<'_> {
    /// Returns a pointer to the reserved element.
    pub fn as_ptr(&self) -> *mut () {
        let Self(ref deque, offset) = *self;
        // SAFETY: `offset` is a valid offset into `buf`.
        let ptr = unsafe { deque.buf.add(offset).cast() };
        ptr.as_ptr()
    }

    /// Commits the reserved element.
    ///
    /// # Safety
    /// The caller must ensure that the element has been written to the buffer.
    pub unsafe fn commit(self) {
        let Self(deque, _) = self;
        deque.len += deque.vtable.element_len;
        debug_assert!(deque.len <= deque.cap);
    }
}

impl ErasedVecDeque {
    /// Creates a new empty `ErasedVecDeque` with the given element vtable.
    pub fn new(vtable: &'static ElementVtable) -> Self {
        Self {
            buf: NonNull::dangling(),
            cap: if vtable.layout.size() == 0 {
                isize::MAX as usize
            } else {
                0
            },
            head: 0,
            len: 0,
            vtable,
        }
    }

    /// Returns whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn offset(&self, i: usize) -> usize {
        if self.vtable.layout.size() == 0 {
            return 0;
        }
        let offset = self.head.wrapping_add(i);
        let offset = if offset >= self.cap {
            offset - self.cap
        } else {
            offset
        };
        debug_assert!(offset + self.vtable.layout.size() <= self.cap);
        offset
    }

    /// # Safety
    /// The caller must ensure that `i` is in bounds.
    unsafe fn buf_at(&mut self, i: usize) -> InPlaceElement<'_> {
        let offset = self.offset(i);
        // SAFETY: `i` is a valid index into `buf`.
        let ptr = unsafe { self.buf.add(offset).cast() };
        InPlaceElement(ptr, PhantomData)
    }

    /// Reserves space for one element and returns a reference to it.
    ///
    /// The caller must write the element to the returned pointer and then call
    /// [`ReservedElement::commit`] to commit the element.
    pub fn reserve_one(&mut self) -> ReservedElement<'_> {
        if self.len >= self.cap {
            self.grow();
        }
        let offset = self.offset(self.len);
        ReservedElement(self, offset)
    }

    /// Pushes a new element to the back of the queue.
    ///
    /// # Safety
    /// The caller must ensure that `value` is a valid owned pointer to the
    /// element type that this queue was created with.
    ///
    /// Additionally, once at least one element has been pushed to this
    /// queue, the caller must ensure that the queue is not sent/shared across
    /// threads unless the element type is `Send` and `Sync`.
    pub unsafe fn push_back(&mut self, value: *const ()) {
        let len = self.vtable.layout.size();
        let dst = self.reserve_one();
        // SAFETY: the caller ensures that `value` is a valid owned pointer to the
        // element type.
        unsafe {
            std::ptr::copy_nonoverlapping(value.cast(), dst.as_ptr().cast::<u8>(), len);
        }
        // SAFETY: the value has been written.
        unsafe { dst.commit() };
    }

    /// Pops the front element from the queue and returns a pointer to it.
    ///
    /// The caller is responsible for taking ownership of the element to ensure
    /// that it is properly dropped.
    pub fn pop_front_in_place(&mut self) -> Option<InPlaceElement<'_>> {
        if self.len == 0 {
            return None;
        };
        let head = self.head;
        self.head = self.offset(self.vtable.layout.size());
        self.len -= self.vtable.element_len;
        // SAFETY: `head` is a valid index into `buf`.
        let ptr = unsafe { self.buf.add(head).cast() };
        Some(InPlaceElement(ptr, PhantomData))
    }

    /// Clears the queue of elements.
    pub fn clear(&mut self) {
        let mut i = 0;
        if let Some(drop_fn) = self.vtable.drop {
            while i < self.len {
                // SAFETY: the element at `i` is valid.
                unsafe {
                    drop_fn(self.buf_at(i).as_ptr());
                }
                i += self.vtable.layout.size();
            }
        }
        self.len = 0;
    }

    /// Clears the queue and frees the underlying buffer.
    pub fn clear_and_shrink(&mut self) {
        self.clear();
        if self.cap > 0 && self.vtable.layout.size() != 0 {
            // SAFETY: `buf` contains a valid unaliased allocation with the
            // given size and alignment.
            unsafe {
                std::alloc::dealloc(
                    self.buf.as_ptr(),
                    Layout::from_size_align_unchecked(self.cap, self.vtable.layout.align()),
                );
            }
            self.cap = 0;
        }
    }

    fn grow(&mut self) {
        assert!(self.vtable.layout.size() != 0, "zst overflow");
        let align = self.vtable.layout.align();
        let (new_cap, buf) = if self.cap == 0 {
            let element_size = self.vtable.layout.size();
            // Start with 4 elements, but only if the element size is not too
            // big (these constants are arbitrary).
            let new_cap = if element_size >= 256 {
                element_size
            } else {
                element_size * 4
            };
            // SAFETY: `new_cap` is non-zero and at least as big as `align`,
            // which is a power of 2.
            let buf =
                unsafe { std::alloc::alloc(Layout::from_size_align_unchecked(new_cap, align)) };
            (new_cap, buf)
        } else {
            // Double the capacity (geometric growth) to ensure amortized O(1)
            // push_back.
            let new_cap = self.cap.checked_mul(2).unwrap();
            // SAFETY: `buf` is a valid allocation with the given layout, and
            // `new_cap` is non-zero.
            let buf = unsafe {
                std::alloc::realloc(
                    self.buf.as_ptr(),
                    Layout::from_size_align_unchecked(self.cap, align),
                    new_cap,
                )
            };
            (new_cap, buf)
        };
        let Some(buf) = NonNull::new(buf) else {
            // SAFETY: these layout parameters were validated above.
            let layout = unsafe { Layout::from_size_align_unchecked(new_cap, align) };
            std::alloc::handle_alloc_error(layout);
        };
        // Move the trailing elements to the end of the new buffer.
        if self.len > 0 && self.head + self.len > self.cap {
            let n = self.cap - self.head;
            let new_head = new_cap - n;
            // SAFETY: `buf` is valid for reads and writes at the given offsets.
            unsafe {
                std::ptr::copy(buf.as_ptr().add(self.head), buf.as_ptr().add(new_head), n);
            }
            self.head = new_head;
        }
        self.buf = buf;
        self.cap = new_cap;
    }
}

impl Drop for ErasedVecDeque {
    fn drop(&mut self) {
        self.clear_and_shrink();
    }
}

#[cfg(test)]
mod tests {
    use super::ElementVtable;
    use super::ErasedVecDeque;
    use std::mem::MaybeUninit;

    #[test]
    fn test_erased_vecdeque() {
        let mut deque = ErasedVecDeque::new(const { &ElementVtable::new::<String>() });
        assert!(deque.is_empty());
        for _ in 0..1000 {
            for _ in 0..7 {
                // SAFETY: providing a valid owned pointer to the element type.
                unsafe {
                    deque.push_back(MaybeUninit::new(String::from("foo")).as_ptr().cast());
                }
            }
            for _ in 0..3 {
                // SAFETY: casting to the correct type and reading the value.
                let result = unsafe {
                    deque
                        .pop_front_in_place()
                        .unwrap()
                        .as_ptr()
                        .cast::<String>()
                        .read()
                };
                assert_eq!(&result, "foo");
            }
        }
        drop(deque);
    }

    #[test]
    fn test_zst() {
        let mut deque = ErasedVecDeque::new(const { &ElementVtable::new::<()>() });
        assert!(deque.is_empty());
        for _ in 0..1000 {
            for _ in 0..7 {
                // SAFETY: providing a valid owned pointer to the element type.
                unsafe {
                    deque.push_back(MaybeUninit::new(()).as_ptr().cast());
                }
            }
            for _ in 0..3 {
                // SAFETY: the values are of type `()`.
                unsafe { deque.pop_front_in_place().unwrap().as_ptr().read() };
            }
        }
        drop(deque);
    }
}
