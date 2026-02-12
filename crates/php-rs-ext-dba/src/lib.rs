//! DBA (Database Abstraction) extension for php.rs
//!
//! Implements dbm-style database abstraction with pluggable handler backends.
//! The "flatfile" handler is implemented using an in-memory HashMap.
//! Other handlers (inifile, db4, gdbm) are registered as stubs.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DbaError
// ---------------------------------------------------------------------------

/// An error from the DBA subsystem.
#[derive(Debug, Clone, PartialEq)]
pub struct DbaError {
    pub message: String,
}

impl DbaError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for DbaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DBA error: {}", self.message)
    }
}

impl std::error::Error for DbaError {}

// ---------------------------------------------------------------------------
// DbaMode — Open mode
// ---------------------------------------------------------------------------

/// The mode in which a DBA database is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbaMode {
    /// Open for reading only.
    Read,
    /// Open for reading and writing.
    ReadWrite,
    /// Create the database (read-write, create if not exists).
    Create,
    /// Truncate and create a new database.
    New,
}

impl DbaMode {
    /// Parse a mode string into a DbaMode.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(mode: &str) -> Option<DbaMode> {
        match mode {
            "r" => Some(DbaMode::Read),
            "w" => Some(DbaMode::ReadWrite),
            "c" => Some(DbaMode::Create),
            "n" => Some(DbaMode::New),
            _ => None,
        }
    }

    /// Returns the mode as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            DbaMode::Read => "r",
            DbaMode::ReadWrite => "w",
            DbaMode::Create => "c",
            DbaMode::New => "n",
        }
    }

    /// Whether this mode allows writing.
    pub fn is_writable(&self) -> bool {
        matches!(self, DbaMode::ReadWrite | DbaMode::Create | DbaMode::New)
    }
}

// ---------------------------------------------------------------------------
// DbaHandle — An open database handle
// ---------------------------------------------------------------------------

/// Represents an open DBA database handle.
#[derive(Debug, Clone)]
pub struct DbaHandle {
    /// The handler name (e.g. "flatfile", "inifile", "db4").
    pub handler_name: String,
    /// The file path of the database.
    pub path: String,
    /// The open mode.
    pub mode: DbaMode,
    /// In-memory key-value data store (for flatfile handler).
    pub data: HashMap<String, String>,
    /// Iterator state: ordered keys for iteration.
    key_order: Vec<String>,
    /// Current position in the key iterator.
    key_pos: usize,
}

impl DbaHandle {
    fn new(handler: &str, path: &str, mode: DbaMode) -> Self {
        Self {
            handler_name: handler.to_string(),
            path: path.to_string(),
            mode,
            data: HashMap::new(),
            key_order: Vec::new(),
            key_pos: 0,
        }
    }

    /// Rebuild the ordered key list for iteration.
    fn rebuild_key_order(&mut self) {
        self.key_order = self.data.keys().cloned().collect();
        self.key_order.sort();
    }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Open a DBA database.
///
/// Equivalent to PHP's `dba_open()`.
///
/// `path` is the file path; `mode` is "r", "w", "c", or "n";
/// `handler` is the backend handler name.
pub fn dba_open(path: &str, mode: &str, handler: &str) -> Result<DbaHandle, DbaError> {
    let dba_mode = DbaMode::from_str(mode).ok_or_else(|| {
        DbaError::new(&format!(
            "Invalid mode '{}': must be 'r', 'w', 'c', or 'n'",
            mode
        ))
    })?;

    // Validate handler.
    let valid_handlers = ["flatfile", "inifile", "db4", "gdbm"];
    if !valid_handlers.contains(&handler) {
        return Err(DbaError::new(&format!(
            "No handler '{}' available. Available handlers: {}",
            handler,
            valid_handlers.join(", ")
        )));
    }

    if path.is_empty() {
        return Err(DbaError::new("Path cannot be empty"));
    }

    Ok(DbaHandle::new(handler, path, dba_mode))
}

/// Close a DBA database handle.
///
/// Equivalent to PHP's `dba_close()`.
pub fn dba_close(_handle: DbaHandle) {
    // Handle is consumed/dropped.
}

/// Check if a key exists in the database.
///
/// Equivalent to PHP's `dba_exists()`.
pub fn dba_exists(key: &str, handle: &DbaHandle) -> bool {
    handle.data.contains_key(key)
}

/// Fetch a value by key.
///
/// Equivalent to PHP's `dba_fetch()`.
pub fn dba_fetch(key: &str, handle: &DbaHandle) -> Option<String> {
    handle.data.get(key).cloned()
}

/// Insert a new key-value pair. Returns false if the key already exists.
///
/// Equivalent to PHP's `dba_insert()`.
pub fn dba_insert(key: &str, value: &str, handle: &mut DbaHandle) -> bool {
    if !handle.mode.is_writable() {
        return false;
    }
    if handle.data.contains_key(key) {
        return false;
    }
    handle.data.insert(key.to_string(), value.to_string());
    handle.rebuild_key_order();
    true
}

/// Replace (insert or update) a key-value pair.
///
/// Equivalent to PHP's `dba_replace()`.
pub fn dba_replace(key: &str, value: &str, handle: &mut DbaHandle) -> bool {
    if !handle.mode.is_writable() {
        return false;
    }
    handle.data.insert(key.to_string(), value.to_string());
    handle.rebuild_key_order();
    true
}

/// Delete a key from the database.
///
/// Equivalent to PHP's `dba_delete()`.
pub fn dba_delete(key: &str, handle: &mut DbaHandle) -> bool {
    if !handle.mode.is_writable() {
        return false;
    }
    let removed = handle.data.remove(key).is_some();
    if removed {
        handle.rebuild_key_order();
    }
    removed
}

/// Get the first key in the database.
///
/// Equivalent to PHP's `dba_firstkey()`.
pub fn dba_firstkey(handle: &mut DbaHandle) -> Option<String> {
    handle.rebuild_key_order();
    handle.key_pos = 0;
    if handle.key_order.is_empty() {
        None
    } else {
        handle.key_pos = 1;
        Some(handle.key_order[0].clone())
    }
}

/// Get the next key in the database (after a previous firstkey/nextkey call).
///
/// Equivalent to PHP's `dba_nextkey()`.
pub fn dba_nextkey(handle: &mut DbaHandle) -> Option<String> {
    if handle.key_pos >= handle.key_order.len() {
        return None;
    }
    let key = handle.key_order[handle.key_pos].clone();
    handle.key_pos += 1;
    Some(key)
}

/// List all currently open DBA database files.
///
/// Equivalent to PHP's `dba_list()`.
///
/// In a real implementation this would track open handles globally.
/// Here we just return a single-element list for the given handle.
pub fn dba_list(handle: &DbaHandle) -> Vec<String> {
    vec![handle.path.clone()]
}

/// Return a list of available DBA handler names.
///
/// Equivalent to PHP's `dba_handlers()`.
pub fn dba_handlers() -> Vec<String> {
    vec![
        "flatfile".to_string(),
        "inifile".to_string(),
        "db4".to_string(),
        "gdbm".to_string(),
    ]
}

/// Synchronize the database to disk.
///
/// Equivalent to PHP's `dba_sync()`.
/// Always returns true for the in-memory flatfile handler.
pub fn dba_sync(_handle: &DbaHandle) -> bool {
    true
}

/// Optimize the database.
///
/// Equivalent to PHP's `dba_optimize()`.
/// Always returns true for the in-memory flatfile handler.
pub fn dba_optimize(_handle: &DbaHandle) -> bool {
    true
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handle() -> DbaHandle {
        dba_open("/tmp/test.db", "c", "flatfile").expect("open should succeed")
    }

    #[test]
    fn test_open_success() {
        let handle = test_handle();
        assert_eq!(handle.handler_name, "flatfile");
        assert_eq!(handle.path, "/tmp/test.db");
        assert_eq!(handle.mode, DbaMode::Create);
        assert!(handle.data.is_empty());
    }

    #[test]
    fn test_open_invalid_mode() {
        let result = dba_open("/tmp/test.db", "x", "flatfile");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Invalid mode"));
    }

    #[test]
    fn test_open_invalid_handler() {
        let result = dba_open("/tmp/test.db", "c", "nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("No handler"));
    }

    #[test]
    fn test_open_empty_path() {
        let result = dba_open("", "c", "flatfile");
        assert!(result.is_err());
    }

    #[test]
    fn test_insert_and_fetch() {
        let mut handle = test_handle();
        assert!(dba_insert("name", "Alice", &mut handle));
        assert_eq!(dba_fetch("name", &handle), Some("Alice".to_string()));
    }

    #[test]
    fn test_insert_duplicate_fails() {
        let mut handle = test_handle();
        assert!(dba_insert("key", "val1", &mut handle));
        assert!(!dba_insert("key", "val2", &mut handle));
        // Original value should remain.
        assert_eq!(dba_fetch("key", &handle), Some("val1".to_string()));
    }

    #[test]
    fn test_replace() {
        let mut handle = test_handle();
        assert!(dba_insert("key", "val1", &mut handle));
        assert!(dba_replace("key", "val2", &mut handle));
        assert_eq!(dba_fetch("key", &handle), Some("val2".to_string()));
    }

    #[test]
    fn test_replace_inserts_if_missing() {
        let mut handle = test_handle();
        assert!(dba_replace("newkey", "newval", &mut handle));
        assert_eq!(dba_fetch("newkey", &handle), Some("newval".to_string()));
    }

    #[test]
    fn test_exists() {
        let mut handle = test_handle();
        assert!(!dba_exists("key", &handle));
        dba_insert("key", "val", &mut handle);
        assert!(dba_exists("key", &handle));
    }

    #[test]
    fn test_delete() {
        let mut handle = test_handle();
        dba_insert("key", "val", &mut handle);
        assert!(dba_exists("key", &handle));
        assert!(dba_delete("key", &mut handle));
        assert!(!dba_exists("key", &handle));
    }

    #[test]
    fn test_delete_nonexistent() {
        let mut handle = test_handle();
        assert!(!dba_delete("nonexistent", &mut handle));
    }

    #[test]
    fn test_fetch_nonexistent() {
        let handle = test_handle();
        assert_eq!(dba_fetch("nonexistent", &handle), None);
    }

    #[test]
    fn test_read_only_mode_prevents_writes() {
        let mut handle = dba_open("/tmp/test.db", "r", "flatfile").expect("open should succeed");
        assert!(!dba_insert("key", "val", &mut handle));
        assert!(!dba_replace("key", "val", &mut handle));
        assert!(!dba_delete("key", &mut handle));
    }

    #[test]
    fn test_firstkey_and_nextkey() {
        let mut handle = test_handle();
        dba_insert("banana", "yellow", &mut handle);
        dba_insert("apple", "red", &mut handle);
        dba_insert("cherry", "red", &mut handle);

        // Keys should be returned in sorted order.
        let first = dba_firstkey(&mut handle);
        assert_eq!(first, Some("apple".to_string()));

        let second = dba_nextkey(&mut handle);
        assert_eq!(second, Some("banana".to_string()));

        let third = dba_nextkey(&mut handle);
        assert_eq!(third, Some("cherry".to_string()));

        let done = dba_nextkey(&mut handle);
        assert!(done.is_none());
    }

    #[test]
    fn test_firstkey_empty_database() {
        let mut handle = test_handle();
        assert!(dba_firstkey(&mut handle).is_none());
    }

    #[test]
    fn test_handlers() {
        let handlers = dba_handlers();
        assert!(handlers.contains(&"flatfile".to_string()));
        assert!(handlers.contains(&"inifile".to_string()));
        assert!(handlers.contains(&"db4".to_string()));
        assert!(handlers.contains(&"gdbm".to_string()));
    }

    #[test]
    fn test_list() {
        let handle = test_handle();
        let list = dba_list(&handle);
        assert_eq!(list, vec!["/tmp/test.db".to_string()]);
    }

    #[test]
    fn test_sync_and_optimize() {
        let handle = test_handle();
        assert!(dba_sync(&handle));
        assert!(dba_optimize(&handle));
    }

    #[test]
    fn test_mode_parsing() {
        assert_eq!(DbaMode::from_str("r"), Some(DbaMode::Read));
        assert_eq!(DbaMode::from_str("w"), Some(DbaMode::ReadWrite));
        assert_eq!(DbaMode::from_str("c"), Some(DbaMode::Create));
        assert_eq!(DbaMode::from_str("n"), Some(DbaMode::New));
        assert_eq!(DbaMode::from_str("x"), None);
    }

    #[test]
    fn test_mode_is_writable() {
        assert!(!DbaMode::Read.is_writable());
        assert!(DbaMode::ReadWrite.is_writable());
        assert!(DbaMode::Create.is_writable());
        assert!(DbaMode::New.is_writable());
    }

    #[test]
    fn test_mode_as_str() {
        assert_eq!(DbaMode::Read.as_str(), "r");
        assert_eq!(DbaMode::ReadWrite.as_str(), "w");
        assert_eq!(DbaMode::Create.as_str(), "c");
        assert_eq!(DbaMode::New.as_str(), "n");
    }

    #[test]
    fn test_error_display() {
        let err = DbaError::new("File not found");
        assert_eq!(err.to_string(), "DBA error: File not found");
    }

    #[test]
    fn test_open_all_valid_handlers() {
        for handler in &["flatfile", "inifile", "db4", "gdbm"] {
            let result = dba_open("/tmp/test.db", "c", handler);
            assert!(result.is_ok(), "Handler '{}' should be valid", handler);
            assert_eq!(result.unwrap().handler_name, *handler);
        }
    }
}
