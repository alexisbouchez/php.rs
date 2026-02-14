//! Core garbage collection: reference counting + cycle detection.
//!
//! Implements the Bacon & Rajan concurrent cycle collection algorithm
//! adapted from php-src/Zend/zend_gc.c.
//!
//! The algorithm has three phases:
//! 1. **Mark** — Starting from purple roots, decrement refcounts and color grey
//! 2. **Scan** — Nodes with refcount > 0 are live (black); == 0 are garbage (white)
//! 3. **Collect** — Free all white nodes

use std::cell::Cell;
use std::ptr::NonNull;

/// GC node colors used in cycle detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GcColor {
    /// In use — live node.
    Black = 0,
    /// Possible root of a cycle (refcount was decremented but > 0).
    Purple = 1,
    /// Being scanned — refcount tentatively decremented.
    Grey = 2,
    /// Garbage — member of an unreachable cycle.
    White = 3,
}

/// Header prepended to every GC-managed value.
///
/// Equivalent to `zend_refcounted_h` in php-src.
#[derive(Debug)]
pub struct GcHeader {
    /// Reference count.
    refcount: Cell<u32>,
    /// Color for cycle detection.
    color: Cell<GcColor>,
    /// Index in the root buffer (0 = not in buffer).
    root_index: Cell<u32>,
}

impl GcHeader {
    /// Create a new header with refcount 1.
    pub fn new() -> Self {
        Self {
            refcount: Cell::new(1),
            color: Cell::new(GcColor::Black),
            root_index: Cell::new(0),
        }
    }

    /// Get the current reference count.
    pub fn refcount(&self) -> u32 {
        self.refcount.get()
    }

    /// Increment the reference count.
    pub fn add_ref(&self) {
        self.refcount.set(self.refcount.get() + 1);
    }

    /// Decrement the reference count. Returns the new count.
    pub fn del_ref(&self) -> u32 {
        let rc = self.refcount.get();
        debug_assert!(rc > 0, "refcount underflow");
        let new_rc = rc - 1;
        self.refcount.set(new_rc);
        new_rc
    }

    /// Set the refcount directly (used during GC mark/scan).
    pub fn set_refcount(&self, rc: u32) {
        self.refcount.set(rc);
    }

    /// Get the current color.
    pub fn color(&self) -> GcColor {
        self.color.get()
    }

    /// Set the color.
    pub fn set_color(&self, color: GcColor) {
        self.color.set(color);
    }

    /// Get the root buffer index.
    pub fn root_index(&self) -> u32 {
        self.root_index.get()
    }

    /// Set the root buffer index.
    pub fn set_root_index(&self, idx: u32) {
        self.root_index.set(idx);
    }

    /// Check if this node is in the root buffer.
    pub fn in_root_buffer(&self) -> bool {
        self.root_index.get() != 0
    }
}

impl Default for GcHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A heap-allocated value with a GC header.
///
/// This is the GC-managed allocation unit. Each `GcBox` contains a refcount
/// header followed by the user value.
#[repr(C)]
pub struct GcBox<T: ?Sized> {
    /// GC header (refcount, color, root index).
    pub header: GcHeader,
    /// The managed value.
    pub value: T,
}

/// Trait for values that participate in garbage collection.
///
/// Types that can contain references to other GC-managed values must implement
/// this trait so the cycle detector can traverse the object graph.
pub trait GcTracer {
    /// Visit all GC-managed children of this value.
    ///
    /// The callback should be called for each child reference. This is used
    /// by the cycle detector to traverse the object graph.
    fn trace(&self, tracer: &mut dyn FnMut(NonNull<GcBox<dyn GcTracer>>));
}

/// A reference-counted pointer to a GC-managed value.
///
/// Similar to `Rc<T>` but with GC cycle detection support.
/// Cloning increments the refcount; dropping decrements it.
pub struct GcRef<T: GcTracer> {
    ptr: NonNull<GcBox<T>>,
}

impl<T: GcTracer> GcRef<T> {
    /// Allocate a new GC-managed value with refcount 1.
    pub fn new(value: T) -> Self {
        let boxed = Box::new(GcBox {
            header: GcHeader::new(),
            value,
        });
        let ptr = NonNull::from(Box::leak(boxed));
        Self { ptr }
    }

    /// Get a reference to the GC header.
    pub fn header(&self) -> &GcHeader {
        // SAFETY: ptr is valid for the lifetime of this GcRef.
        unsafe { &self.ptr.as_ref().header }
    }

    /// Get the current reference count.
    pub fn refcount(&self) -> u32 {
        self.header().refcount()
    }

    /// Get a reference to the managed value.
    pub fn value(&self) -> &T {
        // SAFETY: ptr is valid.
        unsafe { &self.ptr.as_ref().value }
    }

    /// Get a mutable reference to the managed value.
    ///
    /// # Safety
    /// Caller must ensure no other references exist to the value.
    pub unsafe fn value_mut(&mut self) -> &mut T {
        // SAFETY: caller guarantees uniqueness.
        unsafe { &mut self.ptr.as_mut().value }
    }

    /// Get the raw pointer to the GcBox (for root buffer tracking).
    pub fn as_ptr(&self) -> NonNull<GcBox<T>> {
        self.ptr
    }

    /// Erase the type to a trait object pointer (for the root buffer).
    pub fn as_dyn_ptr(&self) -> NonNull<GcBox<dyn GcTracer>>
    where
        T: 'static,
    {
        // SAFETY: GcBox<T> where T: GcTracer can be coerced to GcBox<dyn GcTracer>.
        // We need to convert NonNull<GcBox<T>> to NonNull<GcBox<dyn GcTracer>>.
        let raw: *mut GcBox<T> = self.ptr.as_ptr();
        let fat: *mut GcBox<dyn GcTracer> = raw as *mut GcBox<dyn GcTracer>;
        // SAFETY: raw is non-null.
        unsafe { NonNull::new_unchecked(fat) }
    }
}

impl<T: GcTracer> Clone for GcRef<T> {
    fn clone(&self) -> Self {
        self.header().add_ref();
        Self { ptr: self.ptr }
    }
}

impl<T: GcTracer> Drop for GcRef<T> {
    fn drop(&mut self) {
        let header = self.header();
        let new_rc = header.del_ref();
        if new_rc == 0 {
            // SAFETY: refcount is 0, no other references exist.
            unsafe {
                drop(Box::from_raw(self.ptr.as_ptr()));
            }
        }
        // If new_rc > 0 and this is an array/object, the caller should
        // call gc_possible_root() to add it to the root buffer.
    }
}

impl<T: GcTracer + std::fmt::Debug> std::fmt::Debug for GcRef<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcRef")
            .field("refcount", &self.refcount())
            .field("value", self.value())
            .finish()
    }
}

/// Default GC threshold: collect when this many roots are buffered.
const GC_THRESHOLD_DEFAULT: usize = 10_000;

/// Threshold adjustment step.
const GC_THRESHOLD_STEP: usize = 10_000;

/// Minimum freed count to consider lowering threshold.
const GC_THRESHOLD_TRIGGER: usize = 100;

/// The cycle collector — manages the root buffer and runs collection.
///
/// Equivalent to `zend_gc_globals` in php-src.
pub struct GcCollector {
    /// Root buffer: possible cycle roots.
    roots: Vec<Option<NonNull<GcBox<dyn GcTracer>>>>,
    /// Number of active roots.
    num_roots: usize,
    /// Collection trigger threshold.
    threshold: usize,
    /// Whether the collector is currently running.
    active: bool,
    /// Statistics: number of GC runs.
    pub gc_runs: usize,
    /// Statistics: total nodes collected.
    pub collected: usize,
}

impl GcCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            roots: Vec::new(),
            num_roots: 0,
            threshold: GC_THRESHOLD_DEFAULT,
            active: false,
            gc_runs: 0,
            collected: 0,
        }
    }

    /// Number of active roots in the buffer.
    pub fn num_roots(&self) -> usize {
        self.num_roots
    }

    /// Current threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Set threshold (for testing).
    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }

    /// Add a possible root to the root buffer.
    ///
    /// Called when a refcounted value's refcount is decremented but remains > 0.
    /// The value might be part of a cycle.
    ///
    /// # Safety
    /// The pointer must be valid and the GcBox must live until removed from the buffer.
    pub unsafe fn possible_root(&mut self, ptr: NonNull<GcBox<dyn GcTracer>>) {
        let header = &ptr.as_ref().header;
        if header.in_root_buffer() {
            return; // Already tracked
        }

        header.set_color(GcColor::Purple);
        let idx = self.roots.len() + 1; // 1-based (0 = not in buffer)
        header.set_root_index(idx as u32);
        self.roots.push(Some(ptr));
        self.num_roots += 1;
    }

    /// Remove a root from the buffer (e.g., when the value is freed).
    ///
    /// # Safety
    /// The pointer must be valid.
    pub unsafe fn remove_root(&mut self, ptr: NonNull<GcBox<dyn GcTracer>>) {
        let header = &ptr.as_ref().header;
        let idx = header.root_index() as usize;
        if idx > 0 && idx <= self.roots.len() {
            self.roots[idx - 1] = None;
            self.num_roots -= 1;
        }
        header.set_root_index(0);
        header.set_color(GcColor::Black);
    }

    /// Check if collection should run, and run it if so.
    ///
    /// Returns the number of nodes collected.
    pub fn collect_if_needed(&mut self) -> usize {
        if self.num_roots >= self.threshold && !self.active {
            self.collect_cycles()
        } else {
            0
        }
    }

    /// Run cycle collection. Returns the number of nodes collected.
    ///
    /// Implements the 3-phase Bacon & Rajan algorithm:
    /// 1. Mark: color purple roots grey, decrement child refcounts
    /// 2. Scan: nodes with refcount > 0 → black (live), == 0 → white (garbage)
    /// 3. Collect: free all white nodes
    pub fn collect_cycles(&mut self) -> usize {
        if self.active {
            return 0;
        }
        self.active = true;
        self.gc_runs += 1;

        // Phase 1: Mark
        self.mark_roots();

        // Phase 2: Scan
        self.scan_roots();

        // Phase 3: Collect
        let freed = self.collect_roots();

        // Adjust threshold
        if freed < GC_THRESHOLD_TRIGGER {
            self.threshold += GC_THRESHOLD_STEP;
        } else if self.threshold > GC_THRESHOLD_DEFAULT {
            self.threshold -= GC_THRESHOLD_STEP;
        }

        self.collected += freed;
        self.active = false;
        freed
    }

    /// Phase 1: Mark all purple roots as grey, decrementing child refcounts.
    fn mark_roots(&mut self) {
        let roots: Vec<_> = self.roots.iter().filter_map(|r| *r).collect();

        for ptr in roots {
            // SAFETY: roots contain valid pointers.
            unsafe {
                let header = &ptr.as_ref().header;
                if header.color() == GcColor::Purple {
                    header.set_color(GcColor::Grey);
                    Self::mark_grey(ptr);
                }
            }
        }
    }

    /// Recursively mark a node grey, decrementing child refcounts.
    ///
    /// # Safety
    /// `ptr` must be a valid pointer to a GcBox.
    unsafe fn mark_grey(ptr: NonNull<GcBox<dyn GcTracer>>) {
        let gc_box = ptr.as_ref();
        gc_box.value.trace(&mut |child| {
            let child_header = &child.as_ref().header;
            child_header.del_ref();
            if child_header.color() != GcColor::Grey {
                child_header.set_color(GcColor::Grey);
                Self::mark_grey(child);
            }
        });
    }

    /// Phase 2: Scan grey nodes. Refcount > 0 → black (live), == 0 → white (garbage).
    fn scan_roots(&self) {
        let roots: Vec<_> = self.roots.iter().filter_map(|r| *r).collect();

        for ptr in roots {
            // SAFETY: roots contain valid pointers.
            unsafe {
                let header = &ptr.as_ref().header;
                if header.color() == GcColor::Grey {
                    Self::scan(ptr);
                }
            }
        }
    }

    /// Scan a single node: if refcount > 0, mark black and restore children.
    /// If refcount == 0, mark white (garbage).
    ///
    /// # Safety
    /// `ptr` must be valid.
    unsafe fn scan(ptr: NonNull<GcBox<dyn GcTracer>>) {
        let gc_box = ptr.as_ref();
        let header = &gc_box.header;

        if header.refcount() > 0 {
            // This node is live — restore refcounts and mark black
            Self::scan_black(ptr);
        } else {
            // This node is garbage
            header.set_color(GcColor::White);
            gc_box.value.trace(&mut |child| {
                let child_header = &child.as_ref().header;
                if child_header.color() == GcColor::Grey {
                    Self::scan(child);
                }
            });
        }
    }

    /// Mark a node black (live) and restore child refcounts.
    ///
    /// # Safety
    /// `ptr` must be valid.
    unsafe fn scan_black(ptr: NonNull<GcBox<dyn GcTracer>>) {
        let gc_box = ptr.as_ref();
        gc_box.header.set_color(GcColor::Black);
        gc_box.value.trace(&mut |child| {
            let child_header = &child.as_ref().header;
            child_header.add_ref();
            if child_header.color() != GcColor::Black {
                Self::scan_black(child);
            }
        });
    }

    /// Phase 3: Collect all white (garbage) nodes.
    ///
    /// We gather all garbage nodes first, then free them in a second pass.
    /// This avoids use-after-free when multiple roots in the buffer point
    /// into the same cycle (e.g., A ↔ B both in the root buffer — freeing
    /// B while processing A would make the later access to B invalid).
    fn collect_roots(&mut self) -> usize {
        let roots: Vec<_> = self.roots.drain(..).collect();
        self.num_roots = 0;

        // Phase 1: Gather all white (garbage) nodes into a list,
        // marking them black to prevent revisiting.
        let mut garbage: Vec<NonNull<GcBox<dyn GcTracer>>> = Vec::new();

        for entry in &roots {
            if let Some(ptr) = entry {
                // SAFETY: root buffer entries are valid.
                unsafe {
                    let header = &ptr.as_ref().header;
                    header.set_root_index(0);

                    if header.color() == GcColor::White {
                        Self::gather_white(*ptr, &mut garbage);
                    } else {
                        header.set_color(GcColor::Black);
                    }
                }
            }
        }

        // Phase 2: Free all garbage nodes.
        let freed = garbage.len();
        for ptr in garbage {
            // SAFETY: each pointer appears exactly once (gather_white marks black on visit).
            unsafe {
                drop(Box::from_raw(ptr.as_ptr()));
            }
        }

        freed
    }

    /// Recursively gather white (garbage) nodes into the collection list.
    ///
    /// Marks each visited node black to prevent double-collection.
    ///
    /// # Safety
    /// `ptr` must be valid.
    unsafe fn gather_white(
        ptr: NonNull<GcBox<dyn GcTracer>>,
        garbage: &mut Vec<NonNull<GcBox<dyn GcTracer>>>,
    ) {
        let gc_box = ptr.as_ref();
        let header = &gc_box.header;

        if header.color() != GcColor::White {
            return;
        }

        header.set_color(GcColor::Black);
        header.set_root_index(0);
        garbage.push(ptr);

        gc_box.value.trace(&mut |child| {
            Self::gather_white(child, garbage);
        });
    }

    /// Reset the collector (request shutdown).
    pub fn reset(&mut self) {
        self.roots.clear();
        self.num_roots = 0;
        self.gc_runs = 0;
        self.collected = 0;
        self.threshold = GC_THRESHOLD_DEFAULT;
        self.active = false;
    }
}

impl Default for GcCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // 6.1 Reference counting
    // =========================================================================

    /// A simple GC-managed integer for testing.
    #[derive(Debug)]
    struct GcInt(i64);

    impl GcTracer for GcInt {
        fn trace(&self, _tracer: &mut dyn FnMut(NonNull<GcBox<dyn GcTracer>>)) {
            // Leaf node — no children to trace.
        }
    }

    #[test]
    fn test_gc_header_new() {
        let header = GcHeader::new();
        assert_eq!(header.refcount(), 1);
        assert_eq!(header.color(), GcColor::Black);
        assert!(!header.in_root_buffer());
    }

    #[test]
    fn test_gc_header_add_del_ref() {
        let header = GcHeader::new();
        assert_eq!(header.refcount(), 1);

        header.add_ref();
        assert_eq!(header.refcount(), 2);

        header.add_ref();
        assert_eq!(header.refcount(), 3);

        let rc = header.del_ref();
        assert_eq!(rc, 2);
        assert_eq!(header.refcount(), 2);
    }

    #[test]
    fn test_gc_header_color() {
        let header = GcHeader::new();
        assert_eq!(header.color(), GcColor::Black);

        header.set_color(GcColor::Purple);
        assert_eq!(header.color(), GcColor::Purple);

        header.set_color(GcColor::Grey);
        assert_eq!(header.color(), GcColor::Grey);

        header.set_color(GcColor::White);
        assert_eq!(header.color(), GcColor::White);
    }

    #[test]
    fn test_gcref_new_and_drop() {
        let r = GcRef::new(GcInt(42));
        assert_eq!(r.refcount(), 1);
        assert_eq!(r.value().0, 42);
    }

    #[test]
    fn test_gcref_clone_increments() {
        let r1 = GcRef::new(GcInt(10));
        assert_eq!(r1.refcount(), 1);

        let r2 = r1.clone();
        assert_eq!(r1.refcount(), 2);
        assert_eq!(r2.refcount(), 2);

        drop(r2);
        assert_eq!(r1.refcount(), 1);
    }

    #[test]
    fn test_gcref_multiple_clones() {
        let r1 = GcRef::new(GcInt(7));
        let r2 = r1.clone();
        let r3 = r1.clone();
        assert_eq!(r1.refcount(), 3);

        drop(r3);
        assert_eq!(r1.refcount(), 2);

        drop(r2);
        assert_eq!(r1.refcount(), 1);

        drop(r1);
        // Value is freed here — no leak
    }

    // =========================================================================
    // 6.4 Simple refcount lifecycle
    // =========================================================================

    #[test]
    fn test_refcount_lifecycle() {
        // Simulate: $a = new GcInt(42);
        let a = GcRef::new(GcInt(42));
        assert_eq!(a.refcount(), 1);

        // $b = $a; (share reference)
        let b = a.clone();
        assert_eq!(a.refcount(), 2);

        // unset($a);
        drop(a);
        assert_eq!(b.refcount(), 1);

        // unset($b); — value is freed
        drop(b);
    }

    // =========================================================================
    // GcCollector tests
    // =========================================================================

    #[test]
    fn test_collector_new() {
        let gc = GcCollector::new();
        assert_eq!(gc.num_roots(), 0);
        assert_eq!(gc.threshold(), GC_THRESHOLD_DEFAULT);
    }

    #[test]
    fn test_collector_possible_root() {
        let mut gc = GcCollector::new();
        let r = GcRef::new(GcInt(1));
        let dyn_ptr = r.as_dyn_ptr();

        unsafe {
            gc.possible_root(dyn_ptr);
        }

        assert_eq!(gc.num_roots(), 1);
        assert!(r.header().in_root_buffer());
        assert_eq!(r.header().color(), GcColor::Purple);

        // Adding same root again should not duplicate
        unsafe {
            gc.possible_root(dyn_ptr);
        }
        assert_eq!(gc.num_roots(), 1);

        // Prevent double-free: manually remove from buffer and reset header
        unsafe {
            gc.remove_root(dyn_ptr);
        }
    }

    #[test]
    fn test_collector_remove_root() {
        let mut gc = GcCollector::new();
        let r = GcRef::new(GcInt(1));
        let dyn_ptr = r.as_dyn_ptr();

        unsafe {
            gc.possible_root(dyn_ptr);
            assert_eq!(gc.num_roots(), 1);

            gc.remove_root(dyn_ptr);
            assert_eq!(gc.num_roots(), 0);
            assert!(!r.header().in_root_buffer());
        }
    }

    #[test]
    fn test_collector_collect_empty() {
        let mut gc = GcCollector::new();
        let freed = gc.collect_cycles();
        assert_eq!(freed, 0);
        assert_eq!(gc.gc_runs, 1);
    }

    #[test]
    fn test_collector_leaf_not_garbage() {
        // A leaf node (no children) with external refs should not be collected
        let mut gc = GcCollector::new();
        let r = GcRef::new(GcInt(42));
        let dyn_ptr = r.as_dyn_ptr();

        unsafe {
            gc.possible_root(dyn_ptr);
        }

        let freed = gc.collect_cycles();
        assert_eq!(freed, 0); // Not garbage — still referenced by `r`
    }

    #[test]
    fn test_collector_reset() {
        let mut gc = GcCollector::new();
        gc.gc_runs = 5;
        gc.collected = 100;

        gc.reset();
        assert_eq!(gc.gc_runs, 0);
        assert_eq!(gc.collected, 0);
        assert_eq!(gc.num_roots(), 0);
    }

    #[test]
    fn test_collector_threshold_adjustment() {
        let mut gc = GcCollector::new();
        let initial = gc.threshold();

        // Collecting 0 garbage → threshold increases
        gc.collect_cycles();
        assert_eq!(gc.threshold(), initial + GC_THRESHOLD_STEP);
    }

    // =========================================================================
    // 6.5 Circular reference detection
    // =========================================================================

    /// A GC-managed node that can reference another node, forming cycles.
    /// Equivalent to a PHP array that contains a reference to itself:
    /// `$a = []; $a[0] = &$a;`
    struct GcNode {
        /// Optional reference to another GC-managed node.
        child: Cell<Option<NonNull<GcBox<dyn GcTracer>>>>,
    }

    impl GcNode {
        fn new() -> Self {
            Self {
                child: Cell::new(None),
            }
        }

        fn set_child(&self, ptr: NonNull<GcBox<dyn GcTracer>>) {
            self.child.set(Some(ptr));
        }
    }

    impl GcTracer for GcNode {
        fn trace(&self, tracer: &mut dyn FnMut(NonNull<GcBox<dyn GcTracer>>)) {
            if let Some(child) = self.child.get() {
                tracer(child);
            }
        }
    }

    impl std::fmt::Debug for GcNode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GcNode")
                .field("has_child", &self.child.get().is_some())
                .finish()
        }
    }

    #[test]
    fn test_circular_reference_detection() {
        // Simulate: $a = []; $a[0] = &$a;
        // This creates a self-referencing cycle that only cycle detection can free.

        let mut gc = GcCollector::new();

        // Create two nodes that reference each other: A → B → A
        let a = GcRef::new(GcNode::new());
        let b = GcRef::new(GcNode::new());

        let a_dyn = a.as_dyn_ptr();
        let b_dyn = b.as_dyn_ptr();

        // A references B
        a.value().set_child(b_dyn);
        // B references A
        b.value().set_child(a_dyn);

        // Increment refcounts to account for the cross-references
        a.header().add_ref(); // B → A adds a ref
        b.header().add_ref(); // A → B adds a ref

        assert_eq!(a.refcount(), 2); // held by `a` + B's child
        assert_eq!(b.refcount(), 2); // held by `b` + A's child

        // Now "unset" the local references by converting to raw pointers
        // (simulating unset($a); unset($b);)
        // This decrements refcount but doesn't free because of cross-refs
        a.header().del_ref();
        b.header().del_ref();

        assert_eq!(a.refcount(), 1); // Only B's child reference
        assert_eq!(b.refcount(), 1); // Only A's child reference

        // Add both as possible roots
        unsafe {
            gc.possible_root(a_dyn);
            gc.possible_root(b_dyn);
        }
        assert_eq!(gc.num_roots(), 2);

        // Forget the Rust-side GcRefs to avoid double-free
        // (the GC will handle freeing these)
        std::mem::forget(a);
        std::mem::forget(b);

        // Run cycle collection
        let freed = gc.collect_cycles();

        // Both nodes should have been detected as a cycle and freed
        assert_eq!(freed, 2, "expected 2 nodes freed from cycle");
        assert_eq!(gc.collected, 2);
        assert_eq!(gc.gc_runs, 1);
    }

    #[test]
    fn test_self_referencing_cycle() {
        // Simulate: $a = []; $a[0] = &$a; (self-loop)
        let mut gc = GcCollector::new();

        let a = GcRef::new(GcNode::new());
        let a_dyn = a.as_dyn_ptr();

        // A references itself
        a.value().set_child(a_dyn);
        a.header().add_ref(); // self-ref adds a ref

        assert_eq!(a.refcount(), 2);

        // "unset" the local reference
        a.header().del_ref();
        assert_eq!(a.refcount(), 1); // only the self-reference

        unsafe {
            gc.possible_root(a_dyn);
        }

        std::mem::forget(a);

        let freed = gc.collect_cycles();
        assert_eq!(freed, 1, "self-referencing node should be collected");
    }

    #[test]
    fn test_mixed_live_and_garbage() {
        // Create a cycle (A ↔ B) and a live node (C with external ref).
        // Only A and B should be collected.
        let mut gc = GcCollector::new();

        let a = GcRef::new(GcNode::new());
        let b = GcRef::new(GcNode::new());
        let c = GcRef::new(GcNode::new());

        let a_dyn = a.as_dyn_ptr();
        let b_dyn = b.as_dyn_ptr();
        let c_dyn = c.as_dyn_ptr();

        // Cycle: A → B → A
        a.value().set_child(b_dyn);
        b.value().set_child(a_dyn);
        a.header().add_ref();
        b.header().add_ref();

        // "unset" A and B
        a.header().del_ref();
        b.header().del_ref();

        // C is live (still held by `c` variable)
        // Add all as roots
        unsafe {
            gc.possible_root(a_dyn);
            gc.possible_root(b_dyn);
            gc.possible_root(c_dyn);
        }

        // Forget A and B (GC owns them now)
        std::mem::forget(a);
        std::mem::forget(b);

        let freed = gc.collect_cycles();

        // A and B are garbage (cycle with no external refs)
        // C is live (refcount 1 from Rust variable `c`)
        assert_eq!(freed, 2, "only the cycle should be collected");

        // c is still live
        assert_eq!(c.refcount(), 1);

        // Clean up c's root info
        unsafe {
            gc.remove_root(c_dyn);
        }
    }

    // =========================================================================
    // 6.6 Memory cleanup at request end
    // =========================================================================

    #[test]
    fn test_request_end_cleanup() {
        // Simulate a request that creates values, then cleans up
        let mut gc = GcCollector::new();

        // Create some values
        let r1 = GcRef::new(GcInt(1));
        let r2 = GcRef::new(GcInt(2));
        let r3 = r1.clone();

        assert_eq!(r1.refcount(), 2);
        assert_eq!(r2.refcount(), 1);

        // Drop all references
        drop(r3);
        drop(r1);
        drop(r2);

        // Reset GC (request end)
        gc.reset();
        assert_eq!(gc.num_roots(), 0);
        assert_eq!(gc.gc_runs, 0);
    }

    // =========================================================================
    // 6.7 Benchmark-style: large object graph
    // =========================================================================

    #[test]
    fn test_large_root_buffer() {
        let mut gc = GcCollector::new();
        gc.set_threshold(100); // Low threshold for testing

        let mut nodes = Vec::new();
        for _ in 0..50 {
            let node = GcRef::new(GcNode::new());
            let dyn_ptr = node.as_dyn_ptr();
            unsafe {
                gc.possible_root(dyn_ptr);
            }
            nodes.push(node);
        }
        assert_eq!(gc.num_roots(), 50);

        // All nodes are still live (held by `nodes` vec)
        let freed = gc.collect_cycles();
        assert_eq!(freed, 0);

        // Clean up root info since nodes are still alive
        for node in &nodes {
            let dyn_ptr = node.as_dyn_ptr();
            unsafe {
                gc.remove_root(dyn_ptr);
            }
        }
    }
}
