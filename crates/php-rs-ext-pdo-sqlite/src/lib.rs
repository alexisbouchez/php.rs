//! PDO SQLite driver extension for php.rs
//!
//! Implements the PDO_sqlite driver, which provides SQLite-specific DSN parsing,
//! attributes, and connection configuration. Uses an in-memory or file-backed
//! SQLite database.
//! Reference: php-src/ext/pdo_sqlite/

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants — PDO SQLite attributes
// ---------------------------------------------------------------------------

/// Custom attribute: SQLite specific. Open the database as read-only.
pub const PDO_SQLITE_ATTR_OPEN_FLAGS: i32 = 1000;
/// Custom attribute: Set the SQLite busy timeout in milliseconds.
pub const PDO_SQLITE_ATTR_BUSY_TIMEOUT: i32 = 1001;
/// Custom attribute: Extended result codes.
pub const PDO_SQLITE_ATTR_EXTENDED_RESULT_CODES: i32 = 1002;

/// Open flag: read only.
pub const SQLITE3_OPEN_READONLY: i32 = 0x01;
/// Open flag: read/write.
pub const SQLITE3_OPEN_READWRITE: i32 = 0x02;
/// Open flag: create database if it doesn't exist.
pub const SQLITE3_OPEN_CREATE: i32 = 0x04;

// ---------------------------------------------------------------------------
// PdoSqliteError
// ---------------------------------------------------------------------------

/// An error from the PDO SQLite driver.
#[derive(Debug, Clone, PartialEq)]
pub struct PdoSqliteError {
    pub message: String,
    pub code: i32,
}

impl PdoSqliteError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            code: 0,
        }
    }

    pub fn with_code(mut self, code: i32) -> Self {
        self.code = code;
        self
    }
}

impl fmt::Display for PdoSqliteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO SQLite error: {}", self.message)
    }
}

impl std::error::Error for PdoSqliteError {}

// ---------------------------------------------------------------------------
// PdoSqliteConfig — DSN parsing result
// ---------------------------------------------------------------------------

/// Configuration parsed from a SQLite PDO DSN string.
///
/// DSN format: `sqlite:/path/to/database.db` or `sqlite::memory:`
#[derive(Debug, Clone, PartialEq)]
pub struct PdoSqliteConfig {
    /// Database file path, or ":memory:" for in-memory databases.
    pub path: String,
}

impl Default for PdoSqliteConfig {
    fn default() -> Self {
        Self {
            path: ":memory:".to_string(),
        }
    }
}

/// Parse a SQLite PDO DSN parameter string.
///
/// The input should be the part after `sqlite:`, e.g.:
/// `/path/to/database.db` or `:memory:`
pub fn parse_dsn(dsn: &str) -> Result<PdoSqliteConfig, PdoSqliteError> {
    let path = dsn.trim();
    if path.is_empty() {
        return Err(PdoSqliteError::new("No database path specified in DSN"));
    }
    Ok(PdoSqliteConfig {
        path: path.to_string(),
    })
}

// ---------------------------------------------------------------------------
// PdoSqliteDriver
// ---------------------------------------------------------------------------

/// The PDO SQLite driver.
#[derive(Debug)]
pub struct PdoSqliteDriver;

impl PdoSqliteDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str {
        "sqlite"
    }
}

impl Default for PdoSqliteDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PdoSqliteConnection — in-memory database
// ---------------------------------------------------------------------------

/// Represents a PDO SQLite connection backed by an in-memory key-value store.
/// This is a compatibility stub; for real SQLite access, use the `sqlite3` extension.
#[derive(Debug, Clone)]
pub struct PdoSqliteConnection {
    pub config: PdoSqliteConfig,
    pub connected: bool,
    /// In-memory tables: table_name → Vec<row>, where each row is a HashMap.
    pub tables: HashMap<String, Vec<HashMap<String, String>>>,
    /// Auto-increment counters per table.
    pub auto_increments: HashMap<String, i64>,
    /// Last insert rowid.
    pub last_insert_id: i64,
    /// Number of rows affected by last statement.
    pub affected_rows: i64,
}

impl PdoSqliteConnection {
    pub fn new(config: PdoSqliteConfig) -> Self {
        Self {
            config,
            connected: true,
            tables: HashMap::new(),
            auto_increments: HashMap::new(),
            last_insert_id: 0,
            affected_rows: 0,
        }
    }

    /// Create a table (simplified — just registers the name).
    pub fn create_table(&mut self, name: &str) {
        self.tables.entry(name.to_string()).or_default();
        self.auto_increments.entry(name.to_string()).or_insert(1);
    }

    /// Insert a row into a table.
    pub fn insert(
        &mut self,
        table: &str,
        row: HashMap<String, String>,
    ) -> Result<i64, PdoSqliteError> {
        let rows = self
            .tables
            .get_mut(table)
            .ok_or_else(|| PdoSqliteError::new(&format!("no such table: {}", table)))?;
        let id = *self.auto_increments.get(table).unwrap_or(&1);
        let mut row = row;
        row.entry("rowid".to_string())
            .or_insert_with(|| id.to_string());
        rows.push(row);
        *self.auto_increments.entry(table.to_string()).or_insert(1) = id + 1;
        self.last_insert_id = id;
        self.affected_rows = 1;
        Ok(id)
    }

    /// Query all rows from a table.
    pub fn query_all(&self, table: &str) -> Result<Vec<HashMap<String, String>>, PdoSqliteError> {
        self.tables
            .get(table)
            .cloned()
            .ok_or_else(|| PdoSqliteError::new(&format!("no such table: {}", table)))
    }

    /// Get the SQLite version string.
    pub fn sqlite_version(&self) -> &'static str {
        "3.45.0"
    }
}

// ---------------------------------------------------------------------------
// User-defined functions support
// ---------------------------------------------------------------------------

/// Represents a user-defined SQL function registered via
/// `PDO::sqliteCreateFunction()`.
#[derive(Debug, Clone)]
pub struct SqliteUserFunction {
    pub name: String,
    pub num_args: i32,
    pub callback: String, // PHP callback name
}

impl SqliteUserFunction {
    pub fn new(name: &str, num_args: i32, callback: &str) -> Self {
        Self {
            name: name.to_string(),
            num_args,
            callback: callback.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dsn_memory() {
        let config = parse_dsn(":memory:").unwrap();
        assert_eq!(config.path, ":memory:");
    }

    #[test]
    fn test_parse_dsn_file() {
        let config = parse_dsn("/var/data/mydb.sqlite").unwrap();
        assert_eq!(config.path, "/var/data/mydb.sqlite");
    }

    #[test]
    fn test_parse_dsn_empty() {
        assert!(parse_dsn("").is_err());
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoSqliteDriver::new();
        assert_eq!(driver.name(), "sqlite");
    }

    #[test]
    fn test_connection_create_and_insert() {
        let config = PdoSqliteConfig {
            path: ":memory:".to_string(),
        };
        let mut conn = PdoSqliteConnection::new(config);
        conn.create_table("users");

        let mut row = HashMap::new();
        row.insert("name".to_string(), "Alice".to_string());
        let id = conn.insert("users", row).unwrap();
        assert_eq!(id, 1);
        assert_eq!(conn.last_insert_id, 1);

        let mut row2 = HashMap::new();
        row2.insert("name".to_string(), "Bob".to_string());
        let id2 = conn.insert("users", row2).unwrap();
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_connection_query_all() {
        let config = PdoSqliteConfig::default();
        let mut conn = PdoSqliteConnection::new(config);
        conn.create_table("items");

        let mut r1 = HashMap::new();
        r1.insert("val".to_string(), "a".to_string());
        conn.insert("items", r1).unwrap();

        let mut r2 = HashMap::new();
        r2.insert("val".to_string(), "b".to_string());
        conn.insert("items", r2).unwrap();

        let rows = conn.query_all("items").unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn test_query_nonexistent_table() {
        let conn = PdoSqliteConnection::new(PdoSqliteConfig::default());
        assert!(conn.query_all("nosuchtable").is_err());
    }

    #[test]
    fn test_insert_nonexistent_table() {
        let mut conn = PdoSqliteConnection::new(PdoSqliteConfig::default());
        assert!(conn.insert("nosuchtable", HashMap::new()).is_err());
    }

    #[test]
    fn test_sqlite_version() {
        let conn = PdoSqliteConnection::new(PdoSqliteConfig::default());
        assert!(conn.sqlite_version().starts_with("3."));
    }

    #[test]
    fn test_user_function() {
        let f = SqliteUserFunction::new("my_upper", 1, "strtoupper");
        assert_eq!(f.name, "my_upper");
        assert_eq!(f.num_args, 1);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SQLITE3_OPEN_READONLY, 0x01);
        assert_eq!(SQLITE3_OPEN_READWRITE, 0x02);
        assert_eq!(SQLITE3_OPEN_CREATE, 0x04);
    }

    #[test]
    fn test_default_config() {
        let config = PdoSqliteConfig::default();
        assert_eq!(config.path, ":memory:");
    }
}
