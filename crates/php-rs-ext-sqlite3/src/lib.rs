//! SQLite3 direct API extension for php.rs
//!
//! Implements the SQLite3 class and related structures, providing a direct
//! procedural and OO interface to SQLite databases. This is the non-PDO
//! SQLite interface.
//!
//! This is a structural stub -- no actual SQLite database files are created.
//! The API surface matches PHP's SQLite3 extension for compatibility.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants — Open flags
// ---------------------------------------------------------------------------

/// Open database for reading only.
pub const SQLITE3_OPEN_READONLY: i32 = 1;
/// Open database for reading and writing.
pub const SQLITE3_OPEN_READWRITE: i32 = 2;
/// Create the database if it does not exist.
pub const SQLITE3_OPEN_CREATE: i32 = 4;

// ---------------------------------------------------------------------------
// Constants — Column types
// ---------------------------------------------------------------------------

/// Column contains an integer value.
pub const SQLITE3_INTEGER: i32 = 1;
/// Column contains a floating-point value.
pub const SQLITE3_FLOAT: i32 = 2;
/// Column contains a text string.
pub const SQLITE3_TEXT: i32 = 3;
/// Column contains a binary blob.
pub const SQLITE3_BLOB: i32 = 4;
/// Column contains NULL.
pub const SQLITE3_NULL: i32 = 5;

// ---------------------------------------------------------------------------
// Sqlite3Error
// ---------------------------------------------------------------------------

/// An error from the SQLite3 extension.
#[derive(Debug, Clone, PartialEq)]
pub struct Sqlite3Error {
    /// SQLite error code.
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
}

impl Sqlite3Error {
    pub fn new(code: i32, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    pub fn general(message: &str) -> Self {
        Self::new(1, message)
    }
}

impl fmt::Display for Sqlite3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SQLite3 error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for Sqlite3Error {}

// ---------------------------------------------------------------------------
// Sqlite3Value
// ---------------------------------------------------------------------------

/// A typed value from a SQLite3 result.
#[derive(Debug, Clone, PartialEq)]
pub enum Sqlite3Value {
    Null,
    Integer(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl fmt::Display for Sqlite3Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sqlite3Value::Null => write!(f, "NULL"),
            Sqlite3Value::Integer(v) => write!(f, "{}", v),
            Sqlite3Value::Float(v) => write!(f, "{}", v),
            Sqlite3Value::Text(v) => write!(f, "{}", v),
            Sqlite3Value::Blob(v) => write!(f, "<blob({} bytes)>", v.len()),
        }
    }
}

impl Sqlite3Value {
    /// Return the SQLite3 type constant for this value.
    pub fn type_id(&self) -> i32 {
        match self {
            Sqlite3Value::Null => SQLITE3_NULL,
            Sqlite3Value::Integer(_) => SQLITE3_INTEGER,
            Sqlite3Value::Float(_) => SQLITE3_FLOAT,
            Sqlite3Value::Text(_) => SQLITE3_TEXT,
            Sqlite3Value::Blob(_) => SQLITE3_BLOB,
        }
    }
}

// ---------------------------------------------------------------------------
// Sqlite3Result
// ---------------------------------------------------------------------------

/// A result set from a SQLite3 query.
#[derive(Debug, Clone)]
pub struct Sqlite3Result {
    /// Column names.
    pub columns: Vec<String>,
    /// All rows in the result set.
    pub rows: Vec<Vec<Sqlite3Value>>,
    /// Current row pointer for sequential fetch.
    pub current_row: usize,
}

impl Sqlite3Result {
    /// Create a new empty result set.
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            current_row: 0,
        }
    }

    /// Create a result set with columns and rows.
    pub fn from_data(columns: Vec<String>, rows: Vec<Vec<Sqlite3Value>>) -> Self {
        Self {
            columns,
            rows,
            current_row: 0,
        }
    }

    /// Fetch the next row as a vector of values.
    pub fn fetch_array(&mut self) -> Option<Vec<Sqlite3Value>> {
        if self.current_row >= self.rows.len() {
            return None;
        }
        let row = self.rows[self.current_row].clone();
        self.current_row += 1;
        Some(row)
    }

    /// Return the number of columns in the result set.
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Return the column name at the given index.
    pub fn column_name(&self, index: usize) -> Option<&str> {
        self.columns.get(index).map(|s| s.as_str())
    }

    /// Reset the row pointer to the beginning.
    pub fn reset(&mut self) {
        self.current_row = 0;
    }
}

impl Default for Sqlite3Result {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Sqlite3Stmt
// ---------------------------------------------------------------------------

/// A prepared statement handle for SQLite3.
#[derive(Debug, Clone)]
pub struct Sqlite3Stmt {
    /// The SQL query template.
    pub sql: String,
    /// Bound parameter values, keyed by parameter name or index.
    pub bound_params: HashMap<String, Sqlite3Value>,
    /// Whether the statement has been executed.
    pub executed: bool,
}

impl Sqlite3Stmt {
    /// Create a new prepared statement.
    pub fn new(sql: &str) -> Self {
        Self {
            sql: sql.to_string(),
            bound_params: HashMap::new(),
            executed: false,
        }
    }

    /// Bind a value to a parameter.
    ///
    /// `param` can be a named parameter (e.g. ":name") or a positional
    /// index as a string (e.g. "1").
    pub fn bind_value(&mut self, param: &str, value: Sqlite3Value) {
        self.bound_params.insert(param.to_string(), value);
    }

    /// Execute the prepared statement.
    ///
    /// Returns an empty result set (stub).
    pub fn execute(&mut self) -> Result<Sqlite3Result, Sqlite3Error> {
        self.executed = true;
        Ok(Sqlite3Result::new())
    }

    /// Clear all bound parameters.
    pub fn clear_bindings(&mut self) {
        self.bound_params.clear();
    }

    /// Reset the statement to allow re-execution.
    pub fn reset(&mut self) {
        self.executed = false;
    }

    /// Close the statement and free resources.
    pub fn close(&mut self) -> bool {
        self.bound_params.clear();
        self.executed = false;
        true
    }
}

// ---------------------------------------------------------------------------
// Sqlite3 — The main database handle
// ---------------------------------------------------------------------------

/// Represents an open SQLite3 database connection.
#[derive(Debug, Clone)]
pub struct Sqlite3 {
    /// The filename or ":memory:" for in-memory databases.
    pub filename: String,
    /// Whether the database is currently open.
    pub is_open: bool,
    /// Whether this is an in-memory database.
    pub in_memory: bool,
    /// Last insert rowid.
    pub last_insert_rowid: i64,
    /// Number of rows changed by the last operation.
    pub changes: i32,
    /// Last error code.
    pub last_error_code: i32,
    /// Last error message.
    pub last_error_msg: String,
}

/// Open a SQLite3 database.
///
/// Equivalent to PHP's `new SQLite3($filename)`.
pub fn sqlite3_open(filename: &str) -> Result<Sqlite3, Sqlite3Error> {
    if filename.is_empty() {
        return Err(Sqlite3Error::general("Filename cannot be empty"));
    }

    let in_memory = filename == ":memory:";

    Ok(Sqlite3 {
        filename: filename.to_string(),
        is_open: true,
        in_memory,
        last_insert_rowid: 0,
        changes: 0,
        last_error_code: 0,
        last_error_msg: String::new(),
    })
}

impl Sqlite3 {
    /// Execute a SQL statement without returning results.
    ///
    /// Equivalent to PHP's `SQLite3::exec()`.
    pub fn exec(&mut self, _sql: &str) -> Result<bool, Sqlite3Error> {
        if !self.is_open {
            return Err(Sqlite3Error::general("Database is not open"));
        }
        self.changes = 0;
        self.last_error_code = 0;
        self.last_error_msg.clear();
        Ok(true)
    }

    /// Prepare a SQL statement.
    ///
    /// Equivalent to PHP's `SQLite3::prepare()`.
    pub fn prepare(&self, sql: &str) -> Result<Sqlite3Stmt, Sqlite3Error> {
        if !self.is_open {
            return Err(Sqlite3Error::general("Database is not open"));
        }
        if sql.is_empty() {
            return Err(Sqlite3Error::general("SQL statement cannot be empty"));
        }
        Ok(Sqlite3Stmt::new(sql))
    }

    /// Return the last insert rowid.
    ///
    /// Equivalent to PHP's `SQLite3::lastInsertRowID()`.
    pub fn last_insert_rowid(&self) -> i64 {
        self.last_insert_rowid
    }

    /// Return the number of rows changed by the last operation.
    ///
    /// Equivalent to PHP's `SQLite3::changes()`.
    pub fn changes(&self) -> i32 {
        self.changes
    }

    /// Close the database.
    ///
    /// Equivalent to PHP's `SQLite3::close()`.
    pub fn close(&mut self) -> bool {
        if !self.is_open {
            return false;
        }
        self.is_open = false;
        true
    }

    /// Escape a string for safe use in a SQL query.
    ///
    /// Equivalent to PHP's `SQLite3::escapeString()`.
    /// Doubles single quotes: `'` becomes `''`.
    pub fn escape_string(value: &str) -> String {
        value.replace('\'', "''")
    }

    /// Return the SQLite3 library version string.
    ///
    /// Equivalent to PHP's `SQLite3::version()`.
    pub fn version() -> String {
        "3.45.0".to_string()
    }

    /// Return the last error code.
    pub fn last_error_code(&self) -> i32 {
        self.last_error_code
    }

    /// Return the last error message.
    pub fn last_error_msg(&self) -> &str {
        &self.last_error_msg
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory_database() {
        let db = sqlite3_open(":memory:").expect("open should succeed");
        assert!(db.is_open);
        assert!(db.in_memory);
        assert_eq!(db.filename, ":memory:");
    }

    #[test]
    fn test_open_file_database() {
        let db = sqlite3_open("/tmp/test.db").expect("open should succeed");
        assert!(db.is_open);
        assert!(!db.in_memory);
        assert_eq!(db.filename, "/tmp/test.db");
    }

    #[test]
    fn test_open_empty_filename_fails() {
        let result = sqlite3_open("");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("empty"));
    }

    #[test]
    fn test_close() {
        let mut db = sqlite3_open(":memory:").unwrap();
        assert!(db.is_open);
        assert!(db.close());
        assert!(!db.is_open);
        // Closing again should return false.
        assert!(!db.close());
    }

    #[test]
    fn test_exec_on_open_db() {
        let mut db = sqlite3_open(":memory:").unwrap();
        let result = db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY)");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_exec_on_closed_db() {
        let mut db = sqlite3_open(":memory:").unwrap();
        db.close();
        let result = db.exec("SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare() {
        let db = sqlite3_open(":memory:").unwrap();
        let stmt = db.prepare("SELECT * FROM users WHERE id = :id");
        assert!(stmt.is_ok());
        let stmt = stmt.unwrap();
        assert_eq!(stmt.sql, "SELECT * FROM users WHERE id = :id");
    }

    #[test]
    fn test_prepare_empty_sql() {
        let db = sqlite3_open(":memory:").unwrap();
        let result = db.prepare("");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_on_closed_db() {
        let mut db = sqlite3_open(":memory:").unwrap();
        db.close();
        let result = db.prepare("SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_stmt_bind_and_execute() {
        let db = sqlite3_open(":memory:").unwrap();
        let mut stmt = db
            .prepare("SELECT * FROM users WHERE name = :name")
            .unwrap();

        stmt.bind_value(":name", Sqlite3Value::Text("Alice".to_string()));
        assert_eq!(
            stmt.bound_params.get(":name"),
            Some(&Sqlite3Value::Text("Alice".to_string()))
        );

        let result = stmt.execute();
        assert!(result.is_ok());
        assert!(stmt.executed);
    }

    #[test]
    fn test_stmt_clear_bindings() {
        let db = sqlite3_open(":memory:").unwrap();
        let mut stmt = db.prepare("SELECT ?").unwrap();
        stmt.bind_value("1", Sqlite3Value::Integer(42));
        assert!(!stmt.bound_params.is_empty());

        stmt.clear_bindings();
        assert!(stmt.bound_params.is_empty());
    }

    #[test]
    fn test_stmt_reset() {
        let db = sqlite3_open(":memory:").unwrap();
        let mut stmt = db.prepare("SELECT 1").unwrap();
        stmt.execute().unwrap();
        assert!(stmt.executed);

        stmt.reset();
        assert!(!stmt.executed);
    }

    #[test]
    fn test_stmt_close() {
        let db = sqlite3_open(":memory:").unwrap();
        let mut stmt = db.prepare("SELECT 1").unwrap();
        stmt.bind_value("1", Sqlite3Value::Integer(1));
        stmt.execute().unwrap();

        assert!(stmt.close());
        assert!(!stmt.executed);
        assert!(stmt.bound_params.is_empty());
    }

    #[test]
    fn test_result_fetch_array() {
        let columns = vec!["id".to_string(), "name".to_string()];
        let rows = vec![
            vec![
                Sqlite3Value::Integer(1),
                Sqlite3Value::Text("Alice".to_string()),
            ],
            vec![
                Sqlite3Value::Integer(2),
                Sqlite3Value::Text("Bob".to_string()),
            ],
        ];
        let mut result = Sqlite3Result::from_data(columns, rows);

        let row1 = result.fetch_array().expect("should have row");
        assert_eq!(row1[0], Sqlite3Value::Integer(1));
        assert_eq!(row1[1], Sqlite3Value::Text("Alice".to_string()));

        let row2 = result.fetch_array().expect("should have row");
        assert_eq!(row2[0], Sqlite3Value::Integer(2));

        assert!(result.fetch_array().is_none());
    }

    #[test]
    fn test_result_num_columns() {
        let result = Sqlite3Result::from_data(
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            Vec::new(),
        );
        assert_eq!(result.num_columns(), 3);
    }

    #[test]
    fn test_result_column_name() {
        let result =
            Sqlite3Result::from_data(vec!["id".to_string(), "name".to_string()], Vec::new());
        assert_eq!(result.column_name(0), Some("id"));
        assert_eq!(result.column_name(1), Some("name"));
        assert_eq!(result.column_name(2), None);
    }

    #[test]
    fn test_result_reset() {
        let columns = vec!["val".to_string()];
        let rows = vec![vec![Sqlite3Value::Integer(1)]];
        let mut result = Sqlite3Result::from_data(columns, rows);

        result.fetch_array(); // consume the row
        assert!(result.fetch_array().is_none());

        result.reset();
        assert!(result.fetch_array().is_some());
    }

    #[test]
    fn test_escape_string() {
        assert_eq!(Sqlite3::escape_string("hello"), "hello");
        assert_eq!(Sqlite3::escape_string("it's"), "it''s");
        assert_eq!(Sqlite3::escape_string("O'Brien's"), "O''Brien''s");
        assert_eq!(Sqlite3::escape_string("no'quotes'here"), "no''quotes''here");
        assert_eq!(Sqlite3::escape_string(""), "");
    }

    #[test]
    fn test_version() {
        let version = Sqlite3::version();
        assert!(version.starts_with("3."));
    }

    #[test]
    fn test_last_insert_rowid_and_changes() {
        let mut db = sqlite3_open(":memory:").unwrap();
        assert_eq!(db.last_insert_rowid(), 0);
        assert_eq!(db.changes(), 0);

        // Simulate an insert.
        db.last_insert_rowid = 42;
        db.changes = 1;
        assert_eq!(db.last_insert_rowid(), 42);
        assert_eq!(db.changes(), 1);
    }

    #[test]
    fn test_value_type_ids() {
        assert_eq!(Sqlite3Value::Null.type_id(), SQLITE3_NULL);
        assert_eq!(Sqlite3Value::Integer(0).type_id(), SQLITE3_INTEGER);
        assert_eq!(Sqlite3Value::Float(0.0).type_id(), SQLITE3_FLOAT);
        assert_eq!(Sqlite3Value::Text(String::new()).type_id(), SQLITE3_TEXT);
        assert_eq!(Sqlite3Value::Blob(Vec::new()).type_id(), SQLITE3_BLOB);
    }

    #[test]
    fn test_value_display() {
        assert_eq!(Sqlite3Value::Null.to_string(), "NULL");
        assert_eq!(Sqlite3Value::Integer(42).to_string(), "42");
        assert_eq!(Sqlite3Value::Float(3.125).to_string(), "3.125");
        assert_eq!(Sqlite3Value::Text("hello".to_string()).to_string(), "hello");
        assert_eq!(
            Sqlite3Value::Blob(vec![1, 2, 3]).to_string(),
            "<blob(3 bytes)>"
        );
    }

    #[test]
    fn test_open_flags_constants() {
        assert_eq!(SQLITE3_OPEN_READONLY, 1);
        assert_eq!(SQLITE3_OPEN_READWRITE, 2);
        assert_eq!(SQLITE3_OPEN_CREATE, 4);
    }

    #[test]
    fn test_error_display() {
        let err = Sqlite3Error::new(5, "database is locked");
        assert_eq!(err.to_string(), "SQLite3 error 5: database is locked");
    }
}
