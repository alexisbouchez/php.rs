//! PHP shmop extension.
//!
//! Implements shared memory operations using in-process Vec<u8> backing store.
//! Reference: php-src/ext/shmop/

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by shmop functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShmopError {
    /// The shared memory segment could not be created.
    CreateFailed(String),
    /// The shared memory segment was not found.
    NotFound,
    /// The segment already exists and "n" (exclusive create) was used.
    AlreadyExists,
    /// Invalid flags were provided.
    InvalidFlags,
    /// Read out of bounds.
    OutOfBounds,
    /// The segment has been deleted.
    Deleted,
}

impl std::fmt::Display for ShmopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShmopError::CreateFailed(msg) => write!(f, "shmop_open failed: {}", msg),
            ShmopError::NotFound => write!(f, "Shared memory segment not found"),
            ShmopError::AlreadyExists => write!(f, "Shared memory segment already exists"),
            ShmopError::InvalidFlags => write!(f, "Invalid flags"),
            ShmopError::OutOfBounds => write!(f, "Read/write out of bounds"),
            ShmopError::Deleted => write!(f, "Shared memory segment has been deleted"),
        }
    }
}

// ── Shared memory block ───────────────────────────────────────────────────────

/// Represents a shared memory block, backed by an in-process Vec<u8>.
#[derive(Debug, Clone)]
pub struct ShmopBlock {
    /// The IPC key for this segment.
    pub key: i64,
    /// The size of the shared memory segment.
    pub size: usize,
    /// The backing data store.
    pub data: Vec<u8>,
    /// The flags used to open this segment ("a", "c", "w", "n").
    pub flags: String,
    /// The permission mode bits.
    pub mode: i32,
    /// Whether this segment has been deleted.
    pub deleted: bool,
}

// ── Thread-local storage for shared memory segments ───────────────────────────

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SHM_STORE: RefCell<HashMap<i64, Vec<u8>>> = RefCell::new(HashMap::new());
}

// ── shmop functions ───────────────────────────────────────────────────────────

/// shmop_open() - Create or open shared memory block.
///
/// Flags:
/// - "a" — access (read-only) an existing segment
/// - "c" — create a new segment, or open existing
/// - "w" — read & write access to an existing segment
/// - "n" — create a new segment; fail if one already exists for the given key
pub fn shmop_open(key: i64, flags: &str, mode: i32, size: usize) -> Result<ShmopBlock, ShmopError> {
    match flags {
        "a" | "w" => {
            // Access existing segment.
            SHM_STORE.with(|store| {
                let store = store.borrow();
                if let Some(data) = store.get(&key) {
                    Ok(ShmopBlock {
                        key,
                        size: data.len(),
                        data: data.clone(),
                        flags: flags.to_string(),
                        mode,
                        deleted: false,
                    })
                } else {
                    Err(ShmopError::NotFound)
                }
            })
        }
        "c" => {
            // Create or open existing.
            SHM_STORE.with(|store| {
                let mut store = store.borrow_mut();
                let data = store.entry(key).or_insert_with(|| vec![0u8; size]);
                Ok(ShmopBlock {
                    key,
                    size: data.len(),
                    data: data.clone(),
                    flags: flags.to_string(),
                    mode,
                    deleted: false,
                })
            })
        }
        "n" => {
            // Create new; fail if exists.
            SHM_STORE.with(|store| {
                let mut store = store.borrow_mut();
                if store.contains_key(&key) {
                    return Err(ShmopError::AlreadyExists);
                }
                let data = vec![0u8; size];
                store.insert(key, data.clone());
                Ok(ShmopBlock {
                    key,
                    size,
                    data,
                    flags: flags.to_string(),
                    mode,
                    deleted: false,
                })
            })
        }
        _ => Err(ShmopError::InvalidFlags),
    }
}

/// shmop_read() - Read data from shared memory block.
///
/// Returns the data as a Vec<u8>.
pub fn shmop_read(shm: &ShmopBlock, start: usize, count: usize) -> Result<Vec<u8>, ShmopError> {
    if shm.deleted {
        return Err(ShmopError::Deleted);
    }
    if start >= shm.data.len() {
        return Err(ShmopError::OutOfBounds);
    }
    let end = std::cmp::min(start + count, shm.data.len());
    Ok(shm.data[start..end].to_vec())
}

/// shmop_write() - Write data into shared memory block.
///
/// Returns the number of bytes written.
pub fn shmop_write(shm: &mut ShmopBlock, data: &[u8], offset: usize) -> Result<usize, ShmopError> {
    if shm.deleted {
        return Err(ShmopError::Deleted);
    }
    if shm.flags == "a" {
        return Err(ShmopError::CreateFailed(
            "Cannot write to read-only segment".to_string(),
        ));
    }
    if offset >= shm.size {
        return Err(ShmopError::OutOfBounds);
    }
    let available = shm.size - offset;
    let to_write = std::cmp::min(data.len(), available);
    shm.data[offset..offset + to_write].copy_from_slice(&data[..to_write]);

    // Update the backing store.
    SHM_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(stored) = store.get_mut(&shm.key) {
            stored[offset..offset + to_write].copy_from_slice(&data[..to_write]);
        }
    });

    Ok(to_write)
}

/// shmop_size() - Get size of shared memory block.
pub fn shmop_size(shm: &ShmopBlock) -> usize {
    shm.size
}

/// shmop_delete() - Delete shared memory block.
///
/// Marks the segment for deletion. Returns true on success.
pub fn shmop_delete(shm: &mut ShmopBlock) -> bool {
    if shm.deleted {
        return false;
    }
    SHM_STORE.with(|store| {
        store.borrow_mut().remove(&shm.key);
    });
    shm.deleted = true;
    true
}

/// shmop_close() - Close shared memory block.
///
/// This is a no-op since PHP 8.0 (Shmop objects are closed on destruction).
/// Kept for backward compatibility.
#[deprecated(note = "shmop_close() is deprecated since PHP 8.0")]
pub fn shmop_close(_shm: &ShmopBlock) {
    // No-op since PHP 8.0.
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use super::*;

    fn cleanup_key(key: i64) {
        SHM_STORE.with(|store| {
            store.borrow_mut().remove(&key);
        });
    }

    #[test]
    fn test_shmop_create_and_read() {
        let key = 100;
        cleanup_key(key);

        let shm = shmop_open(key, "c", 0o644, 1024).unwrap();
        assert_eq!(shmop_size(&shm), 1024);

        // Freshly created segment should be all zeroes.
        let data = shmop_read(&shm, 0, 10).unwrap();
        assert_eq!(data, vec![0u8; 10]);

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_write_and_read() {
        let key = 101;
        cleanup_key(key);

        let mut shm = shmop_open(key, "c", 0o644, 1024).unwrap();
        let written = shmop_write(&mut shm, b"Hello, World!", 0).unwrap();
        assert_eq!(written, 13);

        let data = shmop_read(&shm, 0, 13).unwrap();
        assert_eq!(data, b"Hello, World!");

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_write_with_offset() {
        let key = 102;
        cleanup_key(key);

        let mut shm = shmop_open(key, "c", 0o644, 1024).unwrap();
        shmop_write(&mut shm, b"Hello", 0).unwrap();
        shmop_write(&mut shm, b"World", 5).unwrap();

        let data = shmop_read(&shm, 0, 10).unwrap();
        assert_eq!(data, b"HelloWorld");

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_open_existing_with_access_flag() {
        let key = 103;
        cleanup_key(key);

        // Create the segment first.
        let mut shm = shmop_open(key, "c", 0o644, 256).unwrap();
        shmop_write(&mut shm, b"test data", 0).unwrap();

        // Open with access flag.
        let shm2 = shmop_open(key, "a", 0o644, 0).unwrap();
        let data = shmop_read(&shm2, 0, 9).unwrap();
        assert_eq!(data, b"test data");

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_open_nonexistent_fails() {
        let key = 104;
        cleanup_key(key);

        let result = shmop_open(key, "a", 0o644, 0);
        assert!(matches!(result, Err(ShmopError::NotFound)));

        let result = shmop_open(key, "w", 0o644, 0);
        assert!(matches!(result, Err(ShmopError::NotFound)));
    }

    #[test]
    fn test_shmop_exclusive_create() {
        let key = 105;
        cleanup_key(key);

        // First create should succeed.
        let _shm = shmop_open(key, "n", 0o644, 512).unwrap();

        // Second create with "n" should fail.
        let result = shmop_open(key, "n", 0o644, 512);
        assert!(matches!(result, Err(ShmopError::AlreadyExists)));

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_invalid_flags() {
        let result = shmop_open(200, "x", 0o644, 256);
        assert!(matches!(result, Err(ShmopError::InvalidFlags)));
    }

    #[test]
    fn test_shmop_delete() {
        let key = 106;
        cleanup_key(key);

        let mut shm = shmop_open(key, "c", 0o644, 256).unwrap();
        assert!(shmop_delete(&mut shm));
        assert!(shm.deleted);

        // Can't delete again.
        assert!(!shmop_delete(&mut shm));

        // Opening with "a" should now fail.
        let result = shmop_open(key, "a", 0o644, 0);
        assert!(matches!(result, Err(ShmopError::NotFound)));
    }

    #[test]
    fn test_shmop_read_out_of_bounds() {
        let key = 107;
        cleanup_key(key);

        let shm = shmop_open(key, "c", 0o644, 10).unwrap();
        let result = shmop_read(&shm, 100, 5);
        assert_eq!(result, Err(ShmopError::OutOfBounds));

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_write_readonly() {
        let key = 108;
        cleanup_key(key);

        // Create the segment.
        shmop_open(key, "c", 0o644, 256).unwrap();

        // Open as read-only.
        let mut shm = shmop_open(key, "a", 0o644, 0).unwrap();
        let result = shmop_write(&mut shm, b"test", 0);
        assert!(result.is_err());

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_close_noop() {
        let key = 109;
        cleanup_key(key);

        let shm = shmop_open(key, "c", 0o644, 64).unwrap();
        #[allow(deprecated)]
        shmop_close(&shm);
        // Segment should still be accessible.
        assert_eq!(shmop_size(&shm), 64);

        cleanup_key(key);
    }

    #[test]
    fn test_shmop_error_display() {
        assert_eq!(
            ShmopError::NotFound.to_string(),
            "Shared memory segment not found"
        );
        assert_eq!(
            ShmopError::AlreadyExists.to_string(),
            "Shared memory segment already exists"
        );
        assert_eq!(ShmopError::InvalidFlags.to_string(), "Invalid flags");
        assert_eq!(
            ShmopError::OutOfBounds.to_string(),
            "Read/write out of bounds"
        );
        assert_eq!(
            ShmopError::Deleted.to_string(),
            "Shared memory segment has been deleted"
        );
    }

    #[test]
    fn test_shmop_write_truncated_at_boundary() {
        let key = 110;
        cleanup_key(key);

        let mut shm = shmop_open(key, "c", 0o644, 10).unwrap();
        // Write 20 bytes into a 10-byte segment at offset 5.
        let written = shmop_write(&mut shm, &[0xAA; 20], 5).unwrap();
        assert_eq!(written, 5); // Only 5 bytes fit.

        cleanup_key(key);
    }
}
