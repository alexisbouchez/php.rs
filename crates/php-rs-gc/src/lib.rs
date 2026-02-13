//! PHP garbage collector
//!
//! This crate implements reference counting, cycle detection, and
//! request-scoped memory management.
//! Equivalent to php-src/Zend/zend_gc.c and zend_alloc.c
//!
//! # Architecture
//!
//! PHP uses a hybrid memory management strategy:
//! 1. **Reference counting** for deterministic cleanup of non-cyclic values
//! 2. **Cycle detection** (Bacon & Rajan algorithm) for circular references
//! 3. **Request-scoped arena** for bulk deallocation at request end
//!
//! The cycle detector uses a 4-color marking scheme:
//! - **Black**: In use (live)
//! - **Purple**: Possible root of a cycle (refcount was decremented)
//! - **Grey**: Being scanned (refcount tentatively decremented)
//! - **White**: Garbage (part of unreachable cycle)

pub mod arena;
pub mod gc;

pub use arena::Arena;
pub use gc::{GcBox, GcCollector, GcColor, GcHeader, GcRef, GcTracer};
