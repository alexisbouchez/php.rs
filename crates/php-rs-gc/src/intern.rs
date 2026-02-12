//! String interning pool for copy-on-write string semantics.
//!
//! PHP interns commonly-used strings (function names, variable names, class names)
//! to avoid repeated allocations. This module provides a thread-local interning pool
//! that maps string contents to shared `Rc<str>` references.
//!
//! Equivalent to php-src/Zend/zend_string.h interned string pool.

use std::collections::HashMap;
use std::rc::Rc;

/// A string interning pool that deduplicates strings within a request scope.
///
/// Interned strings are stored as `Rc<str>` so cloning is just a reference count bump.
/// The pool is designed to be reset at request end (matching PHP's request lifecycle).
pub struct StringPool {
    /// Map from string content to interned reference.
    pool: HashMap<u64, Rc<str>>,
    /// Total number of intern requests.
    total_lookups: u64,
    /// Number of cache hits (string was already interned).
    cache_hits: u64,
}

impl StringPool {
    /// Create a new empty string pool.
    pub fn new() -> Self {
        Self {
            pool: HashMap::with_capacity(256),
            total_lookups: 0,
            cache_hits: 0,
        }
    }

    /// Intern a string, returning a shared reference.
    ///
    /// If the string has been interned before, returns the existing `Rc<str>`.
    /// Otherwise, creates a new `Rc<str>` and stores it in the pool.
    pub fn intern(&mut self, s: &str) -> Rc<str> {
        self.total_lookups += 1;
        let hash = self.hash_str(s);
        if let Some(existing) = self.pool.get(&hash) {
            // Verify it's actually the same string (hash collision check)
            if &**existing == s {
                self.cache_hits += 1;
                return Rc::clone(existing);
            }
        }
        let rc: Rc<str> = Rc::from(s);
        self.pool.insert(hash, Rc::clone(&rc));
        rc
    }

    /// Intern an owned String, avoiding allocation if already interned.
    pub fn intern_owned(&mut self, s: String) -> Rc<str> {
        self.total_lookups += 1;
        let hash = self.hash_str(&s);
        if let Some(existing) = self.pool.get(&hash) {
            if &**existing == s.as_str() {
                self.cache_hits += 1;
                return Rc::clone(existing);
            }
        }
        let rc: Rc<str> = Rc::from(s.as_str());
        self.pool.insert(hash, Rc::clone(&rc));
        rc
    }

    /// Check if a string is interned.
    pub fn is_interned(&self, s: &str) -> bool {
        let hash = self.hash_str(s);
        self.pool
            .get(&hash)
            .map_or(false, |existing| &**existing == s)
    }

    /// Number of unique strings in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Cache hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        if self.total_lookups == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / self.total_lookups as f64
    }

    /// Reset the pool, freeing all interned strings. Call at request end.
    pub fn reset(&mut self) {
        self.pool.clear();
        self.total_lookups = 0;
        self.cache_hits = 0;
    }

    /// FNV-1a hash for fast string hashing.
    #[inline]
    fn hash_str(&self, s: &str) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in s.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_returns_same_rc() {
        let mut pool = StringPool::new();
        let a = pool.intern("hello");
        let b = pool.intern("hello");
        assert!(Rc::ptr_eq(&a, &b));
    }

    #[test]
    fn test_intern_different_strings() {
        let mut pool = StringPool::new();
        let a = pool.intern("hello");
        let b = pool.intern("world");
        assert!(!Rc::ptr_eq(&a, &b));
        assert_eq!(&*a, "hello");
        assert_eq!(&*b, "world");
    }

    #[test]
    fn test_intern_owned() {
        let mut pool = StringPool::new();
        let a = pool.intern("test");
        let b = pool.intern_owned("test".to_string());
        assert!(Rc::ptr_eq(&a, &b));
    }

    #[test]
    fn test_is_interned() {
        let mut pool = StringPool::new();
        assert!(!pool.is_interned("hello"));
        pool.intern("hello");
        assert!(pool.is_interned("hello"));
    }

    #[test]
    fn test_pool_reset() {
        let mut pool = StringPool::new();
        pool.intern("a");
        pool.intern("b");
        pool.intern("c");
        assert_eq!(pool.len(), 3);
        pool.reset();
        assert_eq!(pool.len(), 0);
        assert!(!pool.is_interned("a"));
    }

    #[test]
    fn test_hit_ratio() {
        let mut pool = StringPool::new();
        pool.intern("hello"); // miss
        pool.intern("hello"); // hit
        pool.intern("hello"); // hit
        pool.intern("world"); // miss
        assert!((pool.hit_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_pool_len() {
        let mut pool = StringPool::new();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        pool.intern("a");
        pool.intern("b");
        pool.intern("a"); // duplicate
        assert_eq!(pool.len(), 2);
        assert!(!pool.is_empty());
    }
}
