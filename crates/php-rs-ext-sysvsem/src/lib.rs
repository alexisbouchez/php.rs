//! PHP sysvsem extension.
//!
//! Implements System V semaphore functions using in-process state.
//! Reference: php-src/ext/sysvsem/

use std::cell::RefCell;
use std::collections::HashMap;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by sysvsem functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysvSemError {
    /// Failed to acquire the semaphore.
    AcquireFailed,
    /// The semaphore could not be created.
    CreateFailed,
    /// The semaphore was not found.
    NotFound,
    /// The semaphore is already at max acquisitions and non-blocking was requested.
    WouldBlock,
    /// Generic error.
    Error(String),
}

impl std::fmt::Display for SysvSemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysvSemError::AcquireFailed => write!(f, "Failed to acquire semaphore"),
            SysvSemError::CreateFailed => write!(f, "Failed to create semaphore"),
            SysvSemError::NotFound => write!(f, "Semaphore not found"),
            SysvSemError::WouldBlock => write!(f, "Operation would block"),
            SysvSemError::Error(msg) => write!(f, "sysvsem error: {}", msg),
        }
    }
}

// ── Semaphore data structure ──────────────────────────────────────────────────

/// Represents a System V semaphore.
#[derive(Debug, Clone)]
pub struct SysvSemaphore {
    /// The IPC key for this semaphore.
    pub key: i64,
    /// Maximum number of concurrent acquisitions allowed.
    pub max_acquire: i32,
    /// Current number of acquisitions held.
    pub current: i32,
    /// Permission bits.
    pub perms: i32,
    /// Whether to auto-release on request shutdown.
    pub auto_release: bool,
}

// ── Thread-local semaphore storage ────────────────────────────────────────────

thread_local! {
    static SEM_STORE: RefCell<HashMap<i64, SysvSemaphore>> = RefCell::new(HashMap::new());
}

// ── Semaphore functions ───────────────────────────────────────────────────────

/// sem_get() - Get a semaphore id.
///
/// Creates a new semaphore or returns an existing one for the given key.
///
/// Parameters:
/// - `key`: The IPC key.
/// - `max_acquire`: Maximum number of processes that can acquire the semaphore simultaneously.
/// - `perms`: Permission bits (default 0666).
/// - `auto_release`: Whether to auto-release on request shutdown.
pub fn sem_get(
    key: i64,
    max_acquire: i32,
    perms: i32,
    auto_release: bool,
) -> Result<SysvSemaphore, SysvSemError> {
    if max_acquire < 1 {
        return Err(SysvSemError::CreateFailed);
    }

    SEM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        let sem = store.entry(key).or_insert_with(|| SysvSemaphore {
            key,
            max_acquire,
            current: 0,
            perms,
            auto_release,
        });
        Ok(sem.clone())
    })
}

/// sem_acquire() - Acquire a semaphore.
///
/// Returns true if the semaphore was successfully acquired.
/// If `non_blocking` is true, returns false instead of blocking when the semaphore is full.
pub fn sem_acquire(sem: &mut SysvSemaphore, non_blocking: bool) -> bool {
    SEM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(stored) = store.get_mut(&sem.key) {
            if stored.current >= stored.max_acquire {
                if non_blocking {
                    return false;
                }
                // In a real implementation this would block.
                // In our stub, we just fail.
                return false;
            }
            stored.current += 1;
            sem.current = stored.current;
            true
        } else {
            false
        }
    })
}

/// sem_release() - Release a semaphore.
///
/// Returns true if the semaphore was successfully released.
pub fn sem_release(sem: &mut SysvSemaphore) -> bool {
    SEM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(stored) = store.get_mut(&sem.key) {
            if stored.current <= 0 {
                return false;
            }
            stored.current -= 1;
            sem.current = stored.current;
            true
        } else {
            false
        }
    })
}

/// sem_remove() - Remove a semaphore.
///
/// Returns true if the semaphore was successfully removed.
pub fn sem_remove(sem: &SysvSemaphore) -> bool {
    SEM_STORE.with(|store| store.borrow_mut().remove(&sem.key).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_key(key: i64) {
        SEM_STORE.with(|store| {
            store.borrow_mut().remove(&key);
        });
    }

    #[test]
    fn test_sem_get() {
        let key = 2000;
        cleanup_key(key);

        let sem = sem_get(key, 1, 0o666, true).unwrap();
        assert_eq!(sem.key, key);
        assert_eq!(sem.max_acquire, 1);
        assert_eq!(sem.current, 0);
        assert_eq!(sem.perms, 0o666);
        assert!(sem.auto_release);

        cleanup_key(key);
    }

    #[test]
    fn test_sem_get_invalid_max_acquire() {
        let result = sem_get(2099, 0, 0o666, true);
        assert!(matches!(result, Err(SysvSemError::CreateFailed)));

        let result = sem_get(2099, -1, 0o666, true);
        assert!(matches!(result, Err(SysvSemError::CreateFailed)));
    }

    #[test]
    fn test_sem_acquire_and_release() {
        let key = 2001;
        cleanup_key(key);

        let mut sem = sem_get(key, 1, 0o666, true).unwrap();
        assert!(sem_acquire(&mut sem, false));
        assert_eq!(sem.current, 1);

        // Should not be able to acquire again (max_acquire = 1).
        assert!(!sem_acquire(&mut sem, true));

        // Release.
        assert!(sem_release(&mut sem));
        assert_eq!(sem.current, 0);

        // Now we can acquire again.
        assert!(sem_acquire(&mut sem, false));

        cleanup_key(key);
    }

    #[test]
    fn test_sem_multiple_acquire() {
        let key = 2002;
        cleanup_key(key);

        let mut sem = sem_get(key, 3, 0o666, false).unwrap();
        assert!(sem_acquire(&mut sem, false));
        assert!(sem_acquire(&mut sem, false));
        assert!(sem_acquire(&mut sem, false));
        // Fourth should fail.
        assert!(!sem_acquire(&mut sem, true));
        assert_eq!(sem.current, 3);

        cleanup_key(key);
    }

    #[test]
    fn test_sem_release_without_acquire() {
        let key = 2003;
        cleanup_key(key);

        let mut sem = sem_get(key, 1, 0o666, true).unwrap();
        // Should fail — nothing to release.
        assert!(!sem_release(&mut sem));

        cleanup_key(key);
    }

    #[test]
    fn test_sem_remove() {
        let key = 2004;
        cleanup_key(key);

        let sem = sem_get(key, 1, 0o666, true).unwrap();
        assert!(sem_remove(&sem));

        // Should not be found anymore.
        assert!(!sem_remove(&sem));

        cleanup_key(key);
    }

    #[test]
    fn test_sem_get_existing() {
        let key = 2005;
        cleanup_key(key);

        let mut sem1 = sem_get(key, 2, 0o666, true).unwrap();
        sem_acquire(&mut sem1, false);

        // Getting the same key should return existing semaphore state.
        let sem2 = sem_get(key, 2, 0o666, true).unwrap();
        assert_eq!(sem2.current, 1); // Should reflect the acquisition.

        cleanup_key(key);
    }

    #[test]
    fn test_sem_non_blocking_acquire() {
        let key = 2006;
        cleanup_key(key);

        let mut sem = sem_get(key, 1, 0o666, true).unwrap();
        assert!(sem_acquire(&mut sem, false));

        // Non-blocking acquire should fail immediately.
        assert!(!sem_acquire(&mut sem, true));

        cleanup_key(key);
    }

    #[test]
    fn test_sem_error_display() {
        assert_eq!(
            SysvSemError::AcquireFailed.to_string(),
            "Failed to acquire semaphore"
        );
        assert_eq!(
            SysvSemError::CreateFailed.to_string(),
            "Failed to create semaphore"
        );
        assert_eq!(SysvSemError::NotFound.to_string(), "Semaphore not found");
        assert_eq!(
            SysvSemError::WouldBlock.to_string(),
            "Operation would block"
        );
        assert_eq!(
            SysvSemError::Error("test".to_string()).to_string(),
            "sysvsem error: test"
        );
    }
}
