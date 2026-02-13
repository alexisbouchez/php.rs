//! Request-scoped arena allocator.
//!
//! PHP allocates memory per-request and frees everything in bulk when the
//! request ends. This arena provides that pattern: allocate many small objects
//! during a request, then drop them all at once.
//!
//! Equivalent to the per-request heap in php-src/Zend/zend_alloc.c.

use std::alloc::{self, Layout};
use std::ptr::NonNull;

/// A chunk of memory in the arena.
struct Chunk {
    /// Raw memory block.
    data: NonNull<u8>,
    /// Layout used to allocate this chunk (for deallocation).
    layout: Layout,
    /// Current offset into the chunk (next free byte).
    offset: usize,
}

impl Chunk {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).expect("invalid layout");
        // SAFETY: layout has non-zero size and valid alignment.
        let data = unsafe { NonNull::new(alloc::alloc(layout)).expect("allocation failed") };
        Self {
            data,
            layout,
            offset: 0,
        }
    }

    /// Try to allocate `layout` from this chunk. Returns pointer or None.
    fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        // Align the current offset
        let aligned = (self.offset + layout.align() - 1) & !(layout.align() - 1);
        let end = aligned + layout.size();
        if end > self.layout.size() {
            return None;
        }
        // SAFETY: aligned offset is within bounds.
        let ptr = unsafe { NonNull::new_unchecked(self.data.as_ptr().add(aligned)) };
        self.offset = end;
        Some(ptr)
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        // SAFETY: data was allocated with this layout.
        unsafe {
            alloc::dealloc(self.data.as_ptr(), self.layout);
        }
    }
}

/// Default chunk size: 256 KB (matches PHP's heap segment size).
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Request-scoped arena allocator.
///
/// Allocations are bump-pointer fast. All memory is freed when the arena
/// is dropped (at request end).
pub struct Arena {
    /// Active chunks.
    chunks: Vec<Chunk>,
    /// Default chunk size for new allocations.
    chunk_size: usize,
    /// Total bytes allocated across all chunks.
    total_allocated: usize,
    /// Total bytes used (requested by callers).
    total_used: usize,
}

impl Arena {
    /// Create a new arena with default chunk size.
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            total_allocated: 0,
            total_used: 0,
        }
    }

    /// Create a new arena with a custom chunk size.
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunks: Vec::new(),
            chunk_size: chunk_size.max(64),
            total_allocated: 0,
            total_used: 0,
        }
    }

    /// Allocate memory for a value of type `T` and write it.
    ///
    /// Returns a raw pointer. The memory is valid until the arena is dropped.
    pub fn alloc<T>(&mut self, value: T) -> *mut T {
        let layout = Layout::new::<T>();
        let ptr = self.alloc_raw(layout);
        let typed = ptr.as_ptr() as *mut T;
        // SAFETY: ptr is properly aligned and sized for T.
        unsafe {
            typed.write(value);
        }
        typed
    }

    /// Allocate raw memory with the given layout.
    pub fn alloc_raw(&mut self, layout: Layout) -> NonNull<u8> {
        self.total_used += layout.size();

        // Try the current chunk first
        if let Some(chunk) = self.chunks.last_mut() {
            if let Some(ptr) = chunk.alloc(layout) {
                return ptr;
            }
        }

        // Need a new chunk
        let size = self.chunk_size.max(layout.size() + layout.align());
        let mut chunk = Chunk::new(size);
        self.total_allocated += size;
        let ptr = chunk
            .alloc(layout)
            .expect("fresh chunk too small for allocation");
        self.chunks.push(chunk);
        ptr
    }

    /// Total bytes allocated by the arena (chunk capacity).
    pub fn total_allocated(&self) -> usize {
        self.total_allocated
    }

    /// Total bytes used by callers.
    pub fn total_used(&self) -> usize {
        self.total_used
    }

    /// Number of chunks allocated.
    pub fn num_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Reset the arena, freeing all memory. Equivalent to request shutdown.
    pub fn reset(&mut self) {
        self.chunks.clear();
        self.total_allocated = 0;
        self.total_used = 0;
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_basic_alloc() {
        let mut arena = Arena::with_chunk_size(1024);
        let p1 = arena.alloc(42u64);
        let p2 = arena.alloc(99u64);
        unsafe {
            assert_eq!(*p1, 42);
            assert_eq!(*p2, 99);
        }
        assert_eq!(arena.num_chunks(), 1);
    }

    #[test]
    fn test_arena_multiple_chunks() {
        let mut arena = Arena::with_chunk_size(64);
        let mut ptrs = Vec::new();
        // Allocate enough to span multiple chunks
        for i in 0..20u64 {
            ptrs.push(arena.alloc(i));
        }
        for (i, ptr) in ptrs.iter().enumerate() {
            unsafe {
                assert_eq!(**ptr, i as u64);
            }
        }
        assert!(arena.num_chunks() > 1);
    }

    #[test]
    fn test_arena_reset() {
        let mut arena = Arena::with_chunk_size(1024);
        arena.alloc(1u64);
        arena.alloc(2u64);
        assert!(arena.total_used() > 0);

        arena.reset();
        assert_eq!(arena.total_allocated(), 0);
        assert_eq!(arena.total_used(), 0);
        assert_eq!(arena.num_chunks(), 0);
    }

    #[test]
    fn test_arena_alignment() {
        let mut arena = Arena::with_chunk_size(1024);
        let p1 = arena.alloc(1u8);
        let p2 = arena.alloc(2u64); // requires 8-byte alignment
        assert_eq!((p2 as usize) % 8, 0);
        unsafe {
            assert_eq!(*p1, 1u8);
            assert_eq!(*p2, 2u64);
        }
    }

    #[test]
    fn test_arena_large_alloc() {
        let mut arena = Arena::with_chunk_size(64);
        // Allocate something larger than the chunk size
        let big = arena.alloc([0u8; 256]);
        unsafe {
            assert_eq!((*big).len(), 256);
        }
    }

    #[test]
    fn test_arena_total_used_tracking() {
        let mut arena = Arena::with_chunk_size(1024);
        arena.alloc(0u64); // 8 bytes
        arena.alloc(0u32); // 4 bytes
        arena.alloc(0u8); // 1 byte
        assert_eq!(arena.total_used(), 8 + 4 + 1);
    }
}
