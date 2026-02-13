//! PHP sysvshm extension.
//!
//! Implements System V shared memory functions using in-process HashMap storage.
//! Reference: php-src/ext/sysvshm/

use std::cell::RefCell;
use std::collections::HashMap;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by sysvshm functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysvShmError {
    /// Failed to attach to shared memory.
    AttachFailed,
    /// The shared memory segment was not found.
    NotFound,
    /// The variable was not found.
    VariableNotFound,
    /// Generic error.
    Error(String),
}

impl std::fmt::Display for SysvShmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysvShmError::AttachFailed => write!(f, "Failed to attach to shared memory"),
            SysvShmError::NotFound => write!(f, "Shared memory segment not found"),
            SysvShmError::VariableNotFound => write!(f, "Variable not found in shared memory"),
            SysvShmError::Error(msg) => write!(f, "sysvshm error: {}", msg),
        }
    }
}

// ── Shared memory data structure ──────────────────────────────────────────────

/// Represents a System V shared memory segment.
///
/// Uses a HashMap<String, Vec<u8>> to store variables keyed by their integer key
/// (converted to string for storage).
#[derive(Debug, Clone)]
pub struct SysvShm {
    /// The IPC key for this segment.
    pub key: i64,
    /// The maximum size of the shared memory segment.
    pub size: usize,
    /// The stored variables. Keys are stringified integer keys.
    pub data: HashMap<String, Vec<u8>>,
    /// Permission bits.
    pub perm: i32,
}

// ── Thread-local shared memory storage ────────────────────────────────────────

thread_local! {
    static SHM_STORE: RefCell<HashMap<i64, SysvShm>> = RefCell::new(HashMap::new());
}

// ── Shared memory functions ───────────────────────────────────────────────────

/// shm_attach() - Creates or open a shared memory segment.
///
/// Parameters:
/// - `key`: The IPC key.
/// - `memsize`: The size of the shared memory segment (minimum 1).
/// - `perm`: Permission bits.
pub fn shm_attach(key: i64, memsize: usize, perm: i32) -> Result<SysvShm, SysvShmError> {
    if memsize == 0 {
        return Err(SysvShmError::AttachFailed);
    }

    SHM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        let shm = store.entry(key).or_insert_with(|| SysvShm {
            key,
            size: memsize,
            data: HashMap::new(),
            perm,
        });
        Ok(shm.clone())
    })
}

/// shm_detach() - Disconnects from shared memory segment.
///
/// Returns true on success. Does not destroy the segment.
pub fn shm_detach(shm: &SysvShm) -> bool {
    // In our in-process implementation, detach is essentially a no-op.
    // The segment remains in the store for other references.
    let _ = shm;
    true
}

/// shm_remove() - Removes shared memory from Unix systems.
///
/// Returns true on success.
pub fn shm_remove(shm: &SysvShm) -> bool {
    SHM_STORE.with(|store| store.borrow_mut().remove(&shm.key).is_some())
}

/// shm_get_var() - Returns a variable from shared memory.
///
/// Returns the variable data, or None if not found.
pub fn shm_get_var(shm: &SysvShm, variable_key: i64) -> Option<Vec<u8>> {
    let key_str = variable_key.to_string();
    SHM_STORE.with(|store| {
        let store = store.borrow();
        store
            .get(&shm.key)
            .and_then(|s| s.data.get(&key_str).cloned())
    })
}

/// shm_put_var() - Inserts or updates a variable in shared memory.
///
/// Returns true on success.
pub fn shm_put_var(shm: &mut SysvShm, variable_key: i64, variable: &[u8]) -> bool {
    let key_str = variable_key.to_string();

    // Check total size.
    let current_total: usize = shm.data.values().map(|v| v.len()).sum();
    let existing_size = shm.data.get(&key_str).map(|v| v.len()).unwrap_or(0);
    let new_total = current_total - existing_size + variable.len();

    if new_total > shm.size {
        return false; // Would exceed segment size.
    }

    shm.data.insert(key_str.clone(), variable.to_vec());

    // Update the backing store.
    SHM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(stored) = store.get_mut(&shm.key) {
            stored.data.insert(key_str, variable.to_vec());
        }
    });

    true
}

/// shm_has_var() - Check whether a specific entry exists.
///
/// Returns true if the variable exists in the shared memory segment.
pub fn shm_has_var(shm: &SysvShm, variable_key: i64) -> bool {
    let key_str = variable_key.to_string();
    SHM_STORE.with(|store| {
        let store = store.borrow();
        store
            .get(&shm.key)
            .map(|s| s.data.contains_key(&key_str))
            .unwrap_or(false)
    })
}

/// shm_remove_var() - Removes a variable from shared memory.
///
/// Returns true on success.
pub fn shm_remove_var(shm: &mut SysvShm, variable_key: i64) -> bool {
    let key_str = variable_key.to_string();

    let removed_local = shm.data.remove(&key_str).is_some();

    let removed_store = SHM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(stored) = store.get_mut(&shm.key) {
            stored.data.remove(&key_str).is_some()
        } else {
            false
        }
    });

    removed_local || removed_store
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_key(key: i64) {
        SHM_STORE.with(|store| {
            store.borrow_mut().remove(&key);
        });
    }

    #[test]
    fn test_shm_attach() {
        let key = 3000;
        cleanup_key(key);

        let shm = shm_attach(key, 65536, 0o666).unwrap();
        assert_eq!(shm.key, key);
        assert_eq!(shm.size, 65536);
        assert_eq!(shm.perm, 0o666);
        assert!(shm.data.is_empty());

        cleanup_key(key);
    }

    #[test]
    fn test_shm_attach_zero_size() {
        let result = shm_attach(3099, 0, 0o666);
        assert!(matches!(result, Err(SysvShmError::AttachFailed)));
    }

    #[test]
    fn test_shm_put_and_get_var() {
        let key = 3001;
        cleanup_key(key);

        let mut shm = shm_attach(key, 65536, 0o666).unwrap();

        assert!(shm_put_var(&mut shm, 1, b"hello world"));
        let val = shm_get_var(&shm, 1);
        assert_eq!(val, Some(b"hello world".to_vec()));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_has_var() {
        let key = 3002;
        cleanup_key(key);

        let mut shm = shm_attach(key, 65536, 0o666).unwrap();
        assert!(!shm_has_var(&shm, 42));

        shm_put_var(&mut shm, 42, b"test");
        assert!(shm_has_var(&shm, 42));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_remove_var() {
        let key = 3003;
        cleanup_key(key);

        let mut shm = shm_attach(key, 65536, 0o666).unwrap();
        shm_put_var(&mut shm, 1, b"data");
        assert!(shm_has_var(&shm, 1));

        assert!(shm_remove_var(&mut shm, 1));
        assert!(!shm_has_var(&shm, 1));

        // Removing non-existent variable.
        assert!(!shm_remove_var(&mut shm, 999));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_get_nonexistent_var() {
        let key = 3004;
        cleanup_key(key);

        let shm = shm_attach(key, 65536, 0o666).unwrap();
        assert_eq!(shm_get_var(&shm, 999), None);

        cleanup_key(key);
    }

    #[test]
    fn test_shm_detach() {
        let key = 3005;
        cleanup_key(key);

        let mut shm = shm_attach(key, 65536, 0o666).unwrap();
        shm_put_var(&mut shm, 1, b"persist");
        assert!(shm_detach(&shm));

        // Data should still exist in the store after detach.
        let shm2 = shm_attach(key, 65536, 0o666).unwrap();
        assert_eq!(shm_get_var(&shm2, 1), Some(b"persist".to_vec()));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_remove() {
        let key = 3006;
        cleanup_key(key);

        let shm = shm_attach(key, 65536, 0o666).unwrap();
        assert!(shm_remove(&shm));

        // Should fail to remove again.
        assert!(!shm_remove(&shm));
    }

    #[test]
    fn test_shm_put_var_exceeds_size() {
        let key = 3007;
        cleanup_key(key);

        let mut shm = shm_attach(key, 10, 0o666).unwrap();
        // Try to store 20 bytes in a 10-byte segment.
        assert!(!shm_put_var(&mut shm, 1, &[0xAA; 20]));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_put_var_update_existing() {
        let key = 3008;
        cleanup_key(key);

        let mut shm = shm_attach(key, 65536, 0o666).unwrap();
        shm_put_var(&mut shm, 1, b"original");
        shm_put_var(&mut shm, 1, b"updated");

        let val = shm_get_var(&shm, 1);
        assert_eq!(val, Some(b"updated".to_vec()));

        cleanup_key(key);
    }

    #[test]
    fn test_shm_error_display() {
        assert_eq!(
            SysvShmError::AttachFailed.to_string(),
            "Failed to attach to shared memory"
        );
        assert_eq!(
            SysvShmError::NotFound.to_string(),
            "Shared memory segment not found"
        );
        assert_eq!(
            SysvShmError::VariableNotFound.to_string(),
            "Variable not found in shared memory"
        );
        assert_eq!(
            SysvShmError::Error("test".to_string()).to_string(),
            "sysvshm error: test"
        );
    }
}
