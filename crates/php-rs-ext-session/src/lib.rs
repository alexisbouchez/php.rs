//! Session extension for php.rs
//!
//! Implements PHP session handling with pluggable storage backends.
//! The default backend stores sessions as files on the filesystem.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// SessionValue — Typed value stored in a session
// ---------------------------------------------------------------------------

/// A value that can be stored in a PHP session.
///
/// Mirrors the types that PHP's session serializer supports.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<(String, SessionValue)>),
}

impl fmt::Display for SessionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionValue::Null => write!(f, "N;"),
            SessionValue::Bool(b) => write!(f, "b:{};", if *b { 1 } else { 0 }),
            SessionValue::Int(i) => write!(f, "i:{};", i),
            SessionValue::Float(v) => write!(f, "d:{};", v),
            SessionValue::Str(s) => write!(f, "s:{}:\"{}\";", s.len(), s),
            SessionValue::Array(entries) => {
                write!(f, "a:{}:{{", entries.len())?;
                for (key, val) in entries {
                    write!(f, "s:{}:\"{}\";", key.len(), key)?;
                    write!(f, "{}", val)?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionError
// ---------------------------------------------------------------------------

/// An error from the session subsystem.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionError {
    pub message: String,
}

impl SessionError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionError: {}", self.message)
    }
}

impl std::error::Error for SessionError {}

// ---------------------------------------------------------------------------
// SessionHandler trait — pluggable storage backend
// ---------------------------------------------------------------------------

/// A pluggable session storage handler, equivalent to PHP's SessionHandlerInterface.
pub trait SessionHandler: Send {
    /// Initialize the session handler.
    ///
    /// `save_path` is the directory or DSN for storage.
    /// `session_name` is the name of the session (e.g. "PHPSESSID").
    fn open(&mut self, save_path: &str, session_name: &str) -> bool;

    /// Close the session handler.
    fn close(&mut self) -> bool;

    /// Read session data for the given ID. Returns `None` if not found.
    fn read(&self, session_id: &str) -> Option<String>;

    /// Write session data for the given ID.
    fn write(&mut self, session_id: &str, data: &str) -> bool;

    /// Destroy the session with the given ID.
    fn destroy(&mut self, session_id: &str) -> bool;

    /// Garbage collect sessions older than `max_lifetime` seconds.
    ///
    /// Returns the number of sessions removed.
    fn gc(&mut self, max_lifetime: u64) -> u32;
}

// ---------------------------------------------------------------------------
// FileSessionHandler — File-based session storage
// ---------------------------------------------------------------------------

/// Stores sessions as individual files in a directory.
///
/// Files are named `sess_{session_id}` in the save path directory.
pub struct FileSessionHandler {
    save_path: PathBuf,
}

impl FileSessionHandler {
    /// Create a new FileSessionHandler.
    pub fn new() -> Self {
        Self {
            save_path: PathBuf::new(),
        }
    }

    fn session_file(&self, session_id: &str) -> PathBuf {
        self.save_path.join(format!("sess_{}", session_id))
    }
}

impl Default for FileSessionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionHandler for FileSessionHandler {
    fn open(&mut self, save_path: &str, _session_name: &str) -> bool {
        self.save_path = PathBuf::from(save_path);
        // Ensure the directory exists.
        if !self.save_path.exists() {
            if fs::create_dir_all(&self.save_path).is_err() {
                return false;
            }
        }
        true
    }

    fn close(&mut self) -> bool {
        true
    }

    fn read(&self, session_id: &str) -> Option<String> {
        let path = self.session_file(session_id);
        fs::read_to_string(path).ok()
    }

    fn write(&mut self, session_id: &str, data: &str) -> bool {
        let path = self.session_file(session_id);
        fs::write(path, data).is_ok()
    }

    fn destroy(&mut self, session_id: &str) -> bool {
        let path = self.session_file(session_id);
        if path.exists() {
            fs::remove_file(path).is_ok()
        } else {
            true
        }
    }

    fn gc(&mut self, max_lifetime: u64) -> u32 {
        let mut removed = 0u32;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entries = match fs::read_dir(&self.save_path) {
            Ok(e) => e,
            Err(_) => return 0,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("sess_") {
                continue;
            }
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let mod_secs = modified
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now.saturating_sub(mod_secs) > max_lifetime {
                        if fs::remove_file(entry.path()).is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
        }

        removed
    }
}

// ---------------------------------------------------------------------------
// Session ID generation
// ---------------------------------------------------------------------------

/// Generate a random session ID.
///
/// Produces a 26-character hex string using a simple PRNG seeded from the
/// system clock, combined with a counter. This is sufficient for the
/// non-cryptographic uniqueness requirement of session IDs in a development
/// context. A production implementation would use the OS CSPRNG.
pub fn generate_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos() as u64;
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Simple mixing: combine timestamp nanos with counter.
    let seed = nanos.wrapping_mul(6364136223846793005).wrapping_add(count);
    let a = seed
        .wrapping_mul(2862933555777941757)
        .wrapping_add(3037000493);
    let b = a
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);

    // Format as 26 hex characters (13 bytes worth, truncated from two u64s).
    let hex = format!("{:016x}{:016x}", a, b);
    hex[..26].to_string()
}

// ---------------------------------------------------------------------------
// Session serialization (PHP serialize format)
// ---------------------------------------------------------------------------

/// Serialize session data to the PHP session serialization format.
///
/// PHP's default session serializer uses the format:
/// `key|serialized_value` for each top-level entry.
pub fn serialize_session_data(data: &HashMap<String, SessionValue>) -> String {
    let mut result = String::new();
    // Sort keys for deterministic output in tests.
    let mut keys: Vec<&String> = data.keys().collect();
    keys.sort();
    for key in keys {
        let value = &data[key];
        result.push_str(key);
        result.push('|');
        result.push_str(&value.to_string());
    }
    result
}

/// Deserialize session data from the PHP session serialization format.
///
/// Parses the `key|serialized_value` format used by PHP's default session
/// serializer.
pub fn deserialize_session_data(data: &str) -> Result<HashMap<String, SessionValue>, SessionError> {
    let mut result = HashMap::new();
    if data.is_empty() {
        return Ok(result);
    }

    let mut remaining = data;
    while !remaining.is_empty() {
        // Find the key (everything up to '|')
        let pipe_pos = remaining
            .find('|')
            .ok_or_else(|| SessionError::new("Invalid session data: missing | separator"))?;
        let key = remaining[..pipe_pos].to_string();
        remaining = &remaining[pipe_pos + 1..];

        // Parse the serialized value
        let (value, rest) = parse_serialized_value(remaining)?;
        result.insert(key, value);
        remaining = rest;
    }

    Ok(result)
}

/// Parse a single PHP serialized value from the beginning of a string.
///
/// Returns the parsed value and the remaining unparsed string.
fn parse_serialized_value(input: &str) -> Result<(SessionValue, &str), SessionError> {
    if input.is_empty() {
        return Err(SessionError::new("Unexpected end of serialized data"));
    }

    let first = input.chars().next().unwrap();
    match first {
        'N' => {
            // N;
            if input.len() < 2 || &input[1..2] != ";" {
                return Err(SessionError::new("Invalid NULL serialization"));
            }
            Ok((SessionValue::Null, &input[2..]))
        }
        'b' => {
            // b:0; or b:1;
            if input.len() < 4 || &input[1..2] != ":" {
                return Err(SessionError::new("Invalid bool serialization"));
            }
            let semicolon = input[2..]
                .find(';')
                .ok_or_else(|| SessionError::new("Invalid bool serialization: missing ;"))?;
            let val_str = &input[2..2 + semicolon];
            let val = match val_str {
                "1" => true,
                "0" => false,
                _ => {
                    return Err(SessionError::new(&format!(
                        "Invalid bool value: {}",
                        val_str
                    )))
                }
            };
            Ok((SessionValue::Bool(val), &input[2 + semicolon + 1..]))
        }
        'i' => {
            // i:123;
            if input.len() < 4 || &input[1..2] != ":" {
                return Err(SessionError::new("Invalid int serialization"));
            }
            let semicolon = input[2..]
                .find(';')
                .ok_or_else(|| SessionError::new("Invalid int serialization: missing ;"))?;
            let val_str = &input[2..2 + semicolon];
            let val: i64 = val_str
                .parse()
                .map_err(|_| SessionError::new(&format!("Invalid int value: {}", val_str)))?;
            Ok((SessionValue::Int(val), &input[2 + semicolon + 1..]))
        }
        'd' => {
            // d:1.5;
            if input.len() < 4 || &input[1..2] != ":" {
                return Err(SessionError::new("Invalid float serialization"));
            }
            let semicolon = input[2..]
                .find(';')
                .ok_or_else(|| SessionError::new("Invalid float serialization: missing ;"))?;
            let val_str = &input[2..2 + semicolon];
            let val: f64 = val_str
                .parse()
                .map_err(|_| SessionError::new(&format!("Invalid float value: {}", val_str)))?;
            Ok((SessionValue::Float(val), &input[2 + semicolon + 1..]))
        }
        's' => {
            // s:5:"hello";
            if input.len() < 4 || &input[1..2] != ":" {
                return Err(SessionError::new("Invalid string serialization"));
            }
            let colon2 = input[2..]
                .find(':')
                .ok_or_else(|| SessionError::new("Invalid string serialization: missing :"))?;
            let len_str = &input[2..2 + colon2];
            let len: usize = len_str
                .parse()
                .map_err(|_| SessionError::new(&format!("Invalid string length: {}", len_str)))?;
            // After the second colon should be a quote.
            let quote_start = 2 + colon2 + 1;
            if input.len() < quote_start + 1 || &input[quote_start..quote_start + 1] != "\"" {
                return Err(SessionError::new(
                    "Invalid string serialization: missing opening quote",
                ));
            }
            let str_start = quote_start + 1;
            if input.len() < str_start + len {
                return Err(SessionError::new(
                    "Invalid string serialization: string too short",
                ));
            }
            let val = &input[str_start..str_start + len];
            let after_str = str_start + len;
            // Expect closing "; sequence.
            if input.len() < after_str + 2
                || &input[after_str..after_str + 1] != "\""
                || &input[after_str + 1..after_str + 2] != ";"
            {
                return Err(SessionError::new(
                    "Invalid string serialization: missing \";",
                ));
            }
            Ok((SessionValue::Str(val.to_string()), &input[after_str + 2..]))
        }
        'a' => {
            // a:2:{s:3:"key";s:5:"value";s:3:"foo";i:42;}
            if input.len() < 4 || &input[1..2] != ":" {
                return Err(SessionError::new("Invalid array serialization"));
            }
            let colon2 = input[2..]
                .find(':')
                .ok_or_else(|| SessionError::new("Invalid array serialization: missing :"))?;
            let len_str = &input[2..2 + colon2];
            let count: usize = len_str
                .parse()
                .map_err(|_| SessionError::new(&format!("Invalid array count: {}", len_str)))?;
            let brace_start = 2 + colon2 + 1;
            if input.len() < brace_start + 1 || &input[brace_start..brace_start + 1] != "{" {
                return Err(SessionError::new(
                    "Invalid array serialization: missing opening brace",
                ));
            }
            let mut remaining = &input[brace_start + 1..];
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                // Parse key (must be a string in this format).
                let (key_val, rest) = parse_serialized_value(remaining)?;
                let key = match key_val {
                    SessionValue::Str(s) => s,
                    SessionValue::Int(i) => i.to_string(),
                    _ => {
                        return Err(SessionError::new("Invalid array key type"));
                    }
                };
                remaining = rest;

                // Parse value.
                let (value, rest) = parse_serialized_value(remaining)?;
                remaining = rest;

                entries.push((key, value));
            }
            // Expect closing brace.
            if remaining.is_empty() || &remaining[..1] != "}" {
                return Err(SessionError::new(
                    "Invalid array serialization: missing closing brace",
                ));
            }
            Ok((SessionValue::Array(entries), &remaining[1..]))
        }
        _ => Err(SessionError::new(&format!(
            "Unknown serialization type: {}",
            first
        ))),
    }
}

// ---------------------------------------------------------------------------
// SessionData — Active session data
// ---------------------------------------------------------------------------

/// An active session's data.
pub struct SessionData {
    /// The session ID.
    pub id: String,
    /// The session data store.
    pub data: HashMap<String, SessionValue>,
}

impl SessionData {
    /// Create new empty session data with the given ID.
    pub fn new(id: String) -> Self {
        Self {
            id,
            data: HashMap::new(),
        }
    }

    /// Get a session value by key.
    pub fn get(&self, key: &str) -> Option<&SessionValue> {
        self.data.get(key)
    }

    /// Set a session value.
    pub fn set(&mut self, key: &str, value: SessionValue) {
        self.data.insert(key.to_string(), value);
    }

    /// Remove a session value.
    pub fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    /// Save the session data to storage using the given handler.
    pub fn save(&self, handler: &mut dyn SessionHandler) -> Result<(), SessionError> {
        let serialized = serialize_session_data(&self.data);
        if handler.write(&self.id, &serialized) {
            Ok(())
        } else {
            Err(SessionError::new("Failed to write session data"))
        }
    }
}

// ---------------------------------------------------------------------------
// SessionManager — High-level session management
// ---------------------------------------------------------------------------

/// Manages the lifecycle of PHP sessions.
pub struct SessionManager;

impl SessionManager {
    /// Start or resume a session.
    ///
    /// If `session_id` is provided, attempts to resume that session.
    /// Otherwise, generates a new session ID.
    pub fn start(
        handler: &mut dyn SessionHandler,
        save_path: &str,
        session_name: &str,
        session_id: Option<&str>,
    ) -> Result<SessionData, SessionError> {
        if !handler.open(save_path, session_name) {
            return Err(SessionError::new("Failed to open session handler"));
        }

        let id = session_id
            .map(|s| s.to_string())
            .unwrap_or_else(generate_session_id);

        let data = if let Some(serialized) = handler.read(&id) {
            if serialized.is_empty() {
                HashMap::new()
            } else {
                deserialize_session_data(&serialized)?
            }
        } else {
            HashMap::new()
        };

        Ok(SessionData { id, data })
    }

    /// Destroy a session.
    pub fn destroy(
        handler: &mut dyn SessionHandler,
        save_path: &str,
        session_name: &str,
        session_id: &str,
    ) -> Result<(), SessionError> {
        if !handler.open(save_path, session_name) {
            return Err(SessionError::new("Failed to open session handler"));
        }
        if handler.destroy(session_id) {
            Ok(())
        } else {
            Err(SessionError::new("Failed to destroy session"))
        }
    }

    /// Regenerate the session ID, optionally deleting the old session.
    ///
    /// Returns the new session ID.
    pub fn regenerate_id(
        handler: &mut dyn SessionHandler,
        save_path: &str,
        session_name: &str,
        old_id: &str,
        delete_old: bool,
    ) -> Result<String, SessionError> {
        if !handler.open(save_path, session_name) {
            return Err(SessionError::new("Failed to open session handler"));
        }

        let new_id = generate_session_id();

        // Copy old data to new ID.
        if let Some(data) = handler.read(old_id) {
            if !handler.write(&new_id, &data) {
                return Err(SessionError::new("Failed to write regenerated session"));
            }
        }

        if delete_old {
            handler.destroy(old_id);
        }

        Ok(new_id)
    }

    /// Run garbage collection on old sessions.
    ///
    /// Returns the number of sessions removed.
    pub fn gc(
        handler: &mut dyn SessionHandler,
        save_path: &str,
        session_name: &str,
        max_lifetime: u64,
    ) -> Result<u32, SessionError> {
        if !handler.open(save_path, session_name) {
            return Err(SessionError::new("Failed to open session handler"));
        }
        Ok(handler.gc(max_lifetime))
    }
}

// ---------------------------------------------------------------------------
// SessionSuperglobal — $_SESSION superglobal integration
// ---------------------------------------------------------------------------

/// Represents the `$_SESSION` superglobal in PHP.
///
/// Wraps a `HashMap<String, SessionValue>` and provides get/set/remove
/// operations that stay in sync with the active session. When a session is
/// started, the superglobal is populated from the session data. When values
/// are modified through the superglobal, the changes are reflected in the
/// underlying session data so they can be persisted on session close.
pub struct SessionSuperglobal {
    /// The backing data store — mirrors the active session's data.
    data: HashMap<String, SessionValue>,
    /// Whether there is an active session bound to this superglobal.
    active: bool,
    /// The session ID of the currently bound session, if any.
    session_id: Option<String>,
}

impl SessionSuperglobal {
    /// Create a new, empty `$_SESSION` superglobal with no active session.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            active: false,
            session_id: None,
        }
    }

    /// Bind this superglobal to an active session, populating it with the
    /// session's current data.
    ///
    /// This is called internally when `session_start()` succeeds.
    pub fn bind(&mut self, session: &SessionData) {
        self.data = session.data.clone();
        self.active = true;
        self.session_id = Some(session.id.clone());
    }

    /// Unbind this superglobal from the active session, clearing all data.
    ///
    /// This is called internally when `session_destroy()` or
    /// `session_write_close()` is invoked.
    pub fn unbind(&mut self) {
        self.data.clear();
        self.active = false;
        self.session_id = None;
    }

    /// Returns `true` if there is an active session bound.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the session ID of the bound session, or `None` if no session
    /// is active.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get a value from `$_SESSION` by key.
    ///
    /// Returns `None` if the key does not exist or no session is active.
    pub fn get(&self, key: &str) -> Option<&SessionValue> {
        if !self.active {
            return None;
        }
        self.data.get(key)
    }

    /// Set a value in `$_SESSION`.
    ///
    /// Returns `Err` if no session is active (mirrors PHP's warning when
    /// writing to `$_SESSION` without an active session).
    pub fn set(&mut self, key: &str, value: SessionValue) -> Result<(), SessionError> {
        if !self.active {
            return Err(SessionError::new(
                "Cannot set $_SESSION key: no active session",
            ));
        }
        self.data.insert(key.to_string(), value);
        Ok(())
    }

    /// Remove a value from `$_SESSION`.
    ///
    /// Returns the removed value, or `None` if the key was not present.
    /// Returns `Err` if no session is active.
    pub fn remove(&mut self, key: &str) -> Result<Option<SessionValue>, SessionError> {
        if !self.active {
            return Err(SessionError::new(
                "Cannot remove $_SESSION key: no active session",
            ));
        }
        Ok(self.data.remove(key))
    }

    /// Returns an iterator over all key-value pairs in `$_SESSION`.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SessionValue)> {
        self.data.iter()
    }

    /// Returns the number of entries in `$_SESSION`.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if `$_SESSION` contains no entries.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Check whether a key exists in `$_SESSION`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.active && self.data.contains_key(key)
    }

    /// Sync the superglobal's data back into a `SessionData` struct so it can
    /// be persisted via a `SessionHandler`.
    ///
    /// This is the inverse of `bind` — it writes the superglobal's possibly
    /// modified data back into the session.
    pub fn sync_to_session(&self, session: &mut SessionData) {
        session.data = self.data.clone();
    }
}

impl Default for SessionSuperglobal {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Helper to create a temp directory for session files.
    fn temp_session_dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("php_rs_session_test_{}", generate_session_id()));
        fs::create_dir_all(&dir).expect("Failed to create temp dir");
        dir
    }

    /// Cleanup helper.
    fn cleanup_dir(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // SessionValue serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_serialize_null() {
        assert_eq!(SessionValue::Null.to_string(), "N;");
    }

    #[test]
    fn test_serialize_bool() {
        assert_eq!(SessionValue::Bool(true).to_string(), "b:1;");
        assert_eq!(SessionValue::Bool(false).to_string(), "b:0;");
    }

    #[test]
    fn test_serialize_int() {
        assert_eq!(SessionValue::Int(42).to_string(), "i:42;");
        assert_eq!(SessionValue::Int(-7).to_string(), "i:-7;");
        assert_eq!(SessionValue::Int(0).to_string(), "i:0;");
    }

    #[test]
    fn test_serialize_float() {
        assert_eq!(SessionValue::Float(3.14).to_string(), "d:3.14;");
    }

    #[test]
    fn test_serialize_string() {
        assert_eq!(
            SessionValue::Str("hello".to_string()).to_string(),
            "s:5:\"hello\";"
        );
        assert_eq!(SessionValue::Str("".to_string()).to_string(), "s:0:\"\";");
    }

    #[test]
    fn test_serialize_array() {
        let arr = SessionValue::Array(vec![
            ("name".to_string(), SessionValue::Str("Alice".to_string())),
            ("age".to_string(), SessionValue::Int(30)),
        ]);
        assert_eq!(
            arr.to_string(),
            "a:2:{s:4:\"name\";s:5:\"Alice\";s:3:\"age\";i:30;}"
        );
    }

    #[test]
    fn test_deserialize_session_data() {
        let data = "name|s:5:\"Alice\";age|i:30;";
        let result = deserialize_session_data(data).expect("deserialization failed");
        assert_eq!(
            result.get("name"),
            Some(&SessionValue::Str("Alice".to_string()))
        );
        assert_eq!(result.get("age"), Some(&SessionValue::Int(30)));
    }

    #[test]
    fn test_deserialize_empty_data() {
        let result = deserialize_session_data("").expect("deserialization failed");
        assert!(result.is_empty());
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let mut data = HashMap::new();
        data.insert("user".to_string(), SessionValue::Str("Bob".to_string()));
        data.insert("count".to_string(), SessionValue::Int(42));
        data.insert("active".to_string(), SessionValue::Bool(true));

        let serialized = serialize_session_data(&data);
        let deserialized = deserialize_session_data(&serialized).expect("deserialization failed");

        assert_eq!(
            deserialized.get("user"),
            Some(&SessionValue::Str("Bob".to_string()))
        );
        assert_eq!(deserialized.get("count"), Some(&SessionValue::Int(42)));
        assert_eq!(deserialized.get("active"), Some(&SessionValue::Bool(true)));
    }

    #[test]
    fn test_roundtrip_nested_array() {
        let mut data = HashMap::new();
        data.insert(
            "prefs".to_string(),
            SessionValue::Array(vec![
                ("theme".to_string(), SessionValue::Str("dark".to_string())),
                ("lang".to_string(), SessionValue::Str("en".to_string())),
            ]),
        );

        let serialized = serialize_session_data(&data);
        let deserialized = deserialize_session_data(&serialized).expect("deserialization failed");

        if let Some(SessionValue::Array(entries)) = deserialized.get("prefs") {
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].0, "theme");
            assert_eq!(entries[0].1, SessionValue::Str("dark".to_string()));
        } else {
            panic!("Expected array for 'prefs'");
        }
    }

    // -----------------------------------------------------------------------
    // Session ID generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_session_id_length() {
        let id = generate_session_id();
        assert_eq!(id.len(), 26);
        // Should be all hex characters.
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_session_id_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| generate_session_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        // All 100 IDs should be unique.
        assert_eq!(unique.len(), 100);
    }

    // -----------------------------------------------------------------------
    // FileSessionHandler
    // -----------------------------------------------------------------------

    #[test]
    fn test_file_handler_write_read() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();
        assert!(handler.open(dir.to_str().unwrap(), "PHPSESSID"));

        assert!(handler.write("abc123", "name|s:5:\"Alice\";"));
        let data = handler.read("abc123");
        assert_eq!(data, Some("name|s:5:\"Alice\";".to_string()));

        cleanup_dir(&dir);
    }

    #[test]
    fn test_file_handler_read_nonexistent() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();
        handler.open(dir.to_str().unwrap(), "PHPSESSID");

        assert_eq!(handler.read("nonexistent"), None);

        cleanup_dir(&dir);
    }

    #[test]
    fn test_file_handler_destroy() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();
        handler.open(dir.to_str().unwrap(), "PHPSESSID");

        handler.write("to_delete", "data");
        assert!(handler.read("to_delete").is_some());

        assert!(handler.destroy("to_delete"));
        assert!(handler.read("to_delete").is_none());

        cleanup_dir(&dir);
    }

    #[test]
    fn test_file_handler_destroy_nonexistent() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();
        handler.open(dir.to_str().unwrap(), "PHPSESSID");

        // Destroying a non-existent session should succeed (idempotent).
        assert!(handler.destroy("does_not_exist"));

        cleanup_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // SessionManager — Full lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_start_new_session() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();

        let session = SessionManager::start(&mut handler, dir.to_str().unwrap(), "PHPSESSID", None)
            .expect("start failed");

        assert_eq!(session.id.len(), 26);
        assert!(session.data.is_empty());

        cleanup_dir(&dir);
    }

    #[test]
    fn test_start_set_save_reload() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();

        // Start a new session.
        let mut session =
            SessionManager::start(&mut handler, dir.to_str().unwrap(), "PHPSESSID", None)
                .expect("start failed");

        let session_id = session.id.clone();

        // Set some data.
        session.set("username", SessionValue::Str("Alice".to_string()));
        session.set("login_count", SessionValue::Int(5));

        // Save.
        session.save(&mut handler).expect("save failed");

        // Reload by resuming the same session ID.
        let reloaded = SessionManager::start(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            Some(&session_id),
        )
        .expect("reload failed");

        assert_eq!(reloaded.id, session_id);
        assert_eq!(
            reloaded.get("username"),
            Some(&SessionValue::Str("Alice".to_string()))
        );
        assert_eq!(reloaded.get("login_count"), Some(&SessionValue::Int(5)));

        cleanup_dir(&dir);
    }

    #[test]
    fn test_destroy_session() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();

        // Start and save a session.
        let mut session =
            SessionManager::start(&mut handler, dir.to_str().unwrap(), "PHPSESSID", None)
                .expect("start failed");
        let session_id = session.id.clone();
        session.set("key", SessionValue::Str("value".to_string()));
        session.save(&mut handler).expect("save failed");

        // Destroy.
        SessionManager::destroy(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            &session_id,
        )
        .expect("destroy failed");

        // Attempting to reload should yield empty data.
        let reloaded = SessionManager::start(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            Some(&session_id),
        )
        .expect("reload failed");
        assert!(reloaded.data.is_empty());

        cleanup_dir(&dir);
    }

    #[test]
    fn test_regenerate_id() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();

        // Start and save a session.
        let mut session =
            SessionManager::start(&mut handler, dir.to_str().unwrap(), "PHPSESSID", None)
                .expect("start failed");
        let old_id = session.id.clone();
        session.set("role", SessionValue::Str("admin".to_string()));
        session.save(&mut handler).expect("save failed");

        // Regenerate ID.
        let new_id = SessionManager::regenerate_id(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            &old_id,
            true,
        )
        .expect("regenerate failed");

        assert_ne!(new_id, old_id);
        assert_eq!(new_id.len(), 26);

        // New ID should have the old data.
        let reloaded = SessionManager::start(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            Some(&new_id),
        )
        .expect("reload failed");
        assert_eq!(
            reloaded.get("role"),
            Some(&SessionValue::Str("admin".to_string()))
        );

        // Old ID should be gone.
        let old_session = SessionManager::start(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            Some(&old_id),
        )
        .expect("reload failed");
        assert!(old_session.data.is_empty());

        cleanup_dir(&dir);
    }

    #[test]
    fn test_session_data_remove() {
        let mut session = SessionData::new("test123".to_string());
        session.set("a", SessionValue::Int(1));
        session.set("b", SessionValue::Int(2));

        assert_eq!(session.get("a"), Some(&SessionValue::Int(1)));
        session.remove("a");
        assert_eq!(session.get("a"), None);
        assert_eq!(session.get("b"), Some(&SessionValue::Int(2)));
    }

    #[test]
    fn test_session_data_overwrite() {
        let mut session = SessionData::new("test456".to_string());
        session.set("key", SessionValue::Int(1));
        assert_eq!(session.get("key"), Some(&SessionValue::Int(1)));

        session.set("key", SessionValue::Str("updated".to_string()));
        assert_eq!(
            session.get("key"),
            Some(&SessionValue::Str("updated".to_string()))
        );
    }

    #[test]
    fn test_deserialize_null_value() {
        let data = "empty|N;";
        let result = deserialize_session_data(data).expect("deserialization failed");
        assert_eq!(result.get("empty"), Some(&SessionValue::Null));
    }

    #[test]
    fn test_deserialize_float_value() {
        let data = "pi|d:3.14;";
        let result = deserialize_session_data(data).expect("deserialization failed");
        assert_eq!(result.get("pi"), Some(&SessionValue::Float(3.14)));
    }

    // -----------------------------------------------------------------------
    // SessionSuperglobal — $_SESSION integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_superglobal_new_is_inactive() {
        let sg = SessionSuperglobal::new();
        assert!(!sg.is_active());
        assert!(sg.session_id().is_none());
        assert!(sg.is_empty());
        assert_eq!(sg.len(), 0);
    }

    #[test]
    fn test_superglobal_get_without_active_session_returns_none() {
        let sg = SessionSuperglobal::new();
        assert_eq!(sg.get("anything"), None);
    }

    #[test]
    fn test_superglobal_set_without_active_session_returns_error() {
        let mut sg = SessionSuperglobal::new();
        let result = sg.set("key", SessionValue::Int(1));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().message,
            "Cannot set $_SESSION key: no active session"
        );
    }

    #[test]
    fn test_superglobal_remove_without_active_session_returns_error() {
        let mut sg = SessionSuperglobal::new();
        let result = sg.remove("key");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().message,
            "Cannot remove $_SESSION key: no active session"
        );
    }

    #[test]
    fn test_superglobal_bind_populates_from_session() {
        let mut session = SessionData::new("sess_abc".to_string());
        session.set("user", SessionValue::Str("Alice".to_string()));
        session.set("role", SessionValue::Str("admin".to_string()));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        assert!(sg.is_active());
        assert_eq!(sg.session_id(), Some("sess_abc"));
        assert_eq!(sg.len(), 2);
        assert_eq!(
            sg.get("user"),
            Some(&SessionValue::Str("Alice".to_string()))
        );
        assert_eq!(
            sg.get("role"),
            Some(&SessionValue::Str("admin".to_string()))
        );
    }

    #[test]
    fn test_superglobal_set_and_get() {
        let session = SessionData::new("sess_xyz".to_string());
        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        sg.set("counter", SessionValue::Int(42)).unwrap();
        assert_eq!(sg.get("counter"), Some(&SessionValue::Int(42)));
        assert_eq!(sg.len(), 1);
    }

    #[test]
    fn test_superglobal_remove() {
        let mut session = SessionData::new("sess_rm".to_string());
        session.set("a", SessionValue::Int(1));
        session.set("b", SessionValue::Int(2));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        let removed = sg.remove("a").unwrap();
        assert_eq!(removed, Some(SessionValue::Int(1)));
        assert_eq!(sg.get("a"), None);
        assert_eq!(sg.get("b"), Some(&SessionValue::Int(2)));
        assert_eq!(sg.len(), 1);
    }

    #[test]
    fn test_superglobal_remove_nonexistent_key() {
        let session = SessionData::new("sess_rn".to_string());
        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        let removed = sg.remove("nonexistent").unwrap();
        assert_eq!(removed, None);
    }

    #[test]
    fn test_superglobal_contains_key() {
        let mut session = SessionData::new("sess_ck".to_string());
        session.set("exists", SessionValue::Bool(true));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        assert!(sg.contains_key("exists"));
        assert!(!sg.contains_key("missing"));
    }

    #[test]
    fn test_superglobal_contains_key_inactive() {
        let sg = SessionSuperglobal::new();
        // Even if there were hypothetical data, contains_key returns false
        // when no session is active.
        assert!(!sg.contains_key("anything"));
    }

    #[test]
    fn test_superglobal_unbind_clears_state() {
        let mut session = SessionData::new("sess_ub".to_string());
        session.set("key", SessionValue::Int(1));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);
        assert!(sg.is_active());
        assert_eq!(sg.len(), 1);

        sg.unbind();
        assert!(!sg.is_active());
        assert!(sg.session_id().is_none());
        assert!(sg.is_empty());
        assert_eq!(sg.get("key"), None);
    }

    #[test]
    fn test_superglobal_sync_to_session() {
        let mut session = SessionData::new("sess_sync".to_string());
        session.set("original", SessionValue::Str("value".to_string()));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        // Modify through the superglobal.
        sg.set("new_key", SessionValue::Int(99)).unwrap();
        sg.remove("original").unwrap();

        // Sync back.
        sg.sync_to_session(&mut session);

        assert_eq!(session.get("original"), None);
        assert_eq!(session.get("new_key"), Some(&SessionValue::Int(99)));
    }

    #[test]
    fn test_superglobal_full_lifecycle_with_handler() {
        let dir = temp_session_dir();
        let mut handler = FileSessionHandler::new();

        // Start a session.
        let mut session =
            SessionManager::start(&mut handler, dir.to_str().unwrap(), "PHPSESSID", None)
                .expect("start failed");
        let session_id = session.id.clone();

        // Bind superglobal.
        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        // Modify via superglobal (like PHP code would).
        sg.set("username", SessionValue::Str("Bob".to_string()))
            .unwrap();
        sg.set("visits", SessionValue::Int(1)).unwrap();

        // Sync back and save.
        sg.sync_to_session(&mut session);
        session.save(&mut handler).expect("save failed");

        // Simulate a new request — reload the session.
        let reloaded = SessionManager::start(
            &mut handler,
            dir.to_str().unwrap(),
            "PHPSESSID",
            Some(&session_id),
        )
        .expect("reload failed");

        let mut sg2 = SessionSuperglobal::new();
        sg2.bind(&reloaded);

        assert_eq!(
            sg2.get("username"),
            Some(&SessionValue::Str("Bob".to_string()))
        );
        assert_eq!(sg2.get("visits"), Some(&SessionValue::Int(1)));

        cleanup_dir(&dir);
    }

    #[test]
    fn test_superglobal_iter() {
        let mut session = SessionData::new("sess_it".to_string());
        session.set("a", SessionValue::Int(1));
        session.set("b", SessionValue::Int(2));

        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        let mut entries: Vec<(String, SessionValue)> = sg
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("a".to_string(), SessionValue::Int(1)));
        assert_eq!(entries[1], ("b".to_string(), SessionValue::Int(2)));
    }

    #[test]
    fn test_superglobal_default() {
        let sg = SessionSuperglobal::default();
        assert!(!sg.is_active());
        assert!(sg.is_empty());
    }

    #[test]
    fn test_superglobal_overwrite_value() {
        let session = SessionData::new("sess_ow".to_string());
        let mut sg = SessionSuperglobal::new();
        sg.bind(&session);

        sg.set("key", SessionValue::Int(1)).unwrap();
        assert_eq!(sg.get("key"), Some(&SessionValue::Int(1)));

        sg.set("key", SessionValue::Str("updated".to_string()))
            .unwrap();
        assert_eq!(
            sg.get("key"),
            Some(&SessionValue::Str("updated".to_string()))
        );
        assert_eq!(sg.len(), 1);
    }
}
