//! SQLite3 internal types for the VM.
//!
//! Only compiled when the `native-io` feature is enabled.

use rusqlite::types::{ToSql, ToSqlOutput, Value as RVal};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Sqlite3ParamValue — a bindable parameter value
// ---------------------------------------------------------------------------

/// A typed parameter value that can be bound to a prepared statement.
#[derive(Debug, Clone)]
pub enum Sqlite3ParamValue {
    Null,
    Integer(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl ToSql for Sqlite3ParamValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Sqlite3ParamValue::Null => Ok(ToSqlOutput::Owned(RVal::Null)),
            Sqlite3ParamValue::Integer(v) => Ok(ToSqlOutput::Owned(RVal::Integer(*v))),
            Sqlite3ParamValue::Float(v) => Ok(ToSqlOutput::Owned(RVal::Real(*v))),
            Sqlite3ParamValue::Text(v) => Ok(ToSqlOutput::Owned(RVal::Text(v.clone()))),
            Sqlite3ParamValue::Blob(v) => Ok(ToSqlOutput::Owned(RVal::Blob(v.clone()))),
        }
    }
}

// ---------------------------------------------------------------------------
// Sqlite3Connection — a live database connection
// ---------------------------------------------------------------------------

/// Wraps a live `rusqlite::Connection`.
pub struct Sqlite3Connection {
    pub conn: rusqlite::Connection,
    pub last_error_code: i32,
    pub last_error_msg: String,
}

impl Sqlite3Connection {
    /// Open (or create) a database at `path`.
    /// `flags` is the PHP-style bitmask (SQLITE3_OPEN_READONLY = 1,
    /// SQLITE3_OPEN_READWRITE = 2, SQLITE3_OPEN_CREATE = 4).
    pub fn open(path: &str, flags: i32) -> Result<Self, String> {
        let mut of = rusqlite::OpenFlags::empty();
        if flags & 1 != 0 {
            of |= rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
        }
        if flags & 2 != 0 {
            of |= rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        }
        if flags & 4 != 0 {
            of |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        // Default: READWRITE|CREATE if no flags given
        if of.is_empty() {
            of = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }

        let conn = if path == ":memory:" {
            rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?
        } else {
            rusqlite::Connection::open_with_flags(path, of).map_err(|e| e.to_string())?
        };

        Ok(Self {
            conn,
            last_error_code: 0,
            last_error_msg: String::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Sqlite3PreparedStmt — a prepared statement with bound parameters
// ---------------------------------------------------------------------------

/// Stores the SQL, owning DB connection id, and bound parameter values.
/// On `execute()`, the VM re-prepares the SQL on the connection and binds.
pub struct Sqlite3PreparedStmt {
    /// The SQL template.
    pub sql: String,
    /// Object-id of the owning `SQLite3` connection object.
    pub db_obj_id: u64,
    /// Named parameters, e.g. `":id"` → value.
    pub named_params: HashMap<String, Sqlite3ParamValue>,
    /// Positional parameters (1-indexed), e.g. `1` → value.
    pub positional_params: HashMap<usize, Sqlite3ParamValue>,
}

impl Sqlite3PreparedStmt {
    pub fn new(sql: &str, db_obj_id: u64) -> Self {
        Self {
            sql: sql.to_string(),
            db_obj_id,
            named_params: HashMap::new(),
            positional_params: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sqlite3ResultSet — eagerly-collected query results
// ---------------------------------------------------------------------------

/// Holds all rows returned by a query.
pub struct Sqlite3ResultSet {
    /// Column names in result order.
    pub columns: Vec<String>,
    /// All rows; each row is a `Vec` of `rusqlite::types::Value`.
    pub rows: Vec<Vec<rusqlite::types::Value>>,
    /// Current fetch position.
    pub current_row: usize,
}

impl Sqlite3ResultSet {
    pub fn new(columns: Vec<String>, rows: Vec<Vec<rusqlite::types::Value>>) -> Self {
        Self {
            columns,
            rows,
            current_row: 0,
        }
    }

    /// Map a `rusqlite::types::Value` to a PHP SQLite3 type constant.
    pub fn sqlite3_type_of(v: &rusqlite::types::Value) -> i64 {
        match v {
            rusqlite::types::Value::Integer(_) => 1, // SQLITE3_INTEGER
            rusqlite::types::Value::Real(_) => 2,    // SQLITE3_FLOAT
            rusqlite::types::Value::Text(_) => 3,    // SQLITE3_TEXT
            rusqlite::types::Value::Blob(_) => 4,    // SQLITE3_BLOB
            rusqlite::types::Value::Null => 5,       // SQLITE3_NULL
        }
    }
}
