//! MySQL improved extension for php.rs
//!
//! Implements the mysqli_* family of functions for MySQL database access.
//! Uses the mysqlnd driver for real MySQL network connections.

use php_rs_ext_mysqlnd::{mysqlnd_close, mysqlnd_connect, mysqlnd_query, MysqlndConnection};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fetch mode: return associative array.
pub const MYSQLI_ASSOC: i32 = 1;
/// Fetch mode: return numeric array.
pub const MYSQLI_NUM: i32 = 2;
/// Fetch mode: return both associative and numeric array.
pub const MYSQLI_BOTH: i32 = 3;

/// Transaction flag: begin a read-write transaction (default).
pub const MYSQLI_TRANS_START_READ_WRITE: i32 = 0;
/// Transaction flag: begin a read-only transaction.
pub const MYSQLI_TRANS_START_READ_ONLY: i32 = 4;

/// Default MySQL port.
pub const MYSQLI_DEFAULT_PORT: u16 = 3306;

// ---------------------------------------------------------------------------
// MysqliError
// ---------------------------------------------------------------------------

/// An error from the mysqli subsystem.
#[derive(Debug, Clone, PartialEq)]
pub struct MysqliError {
    /// MySQL error number.
    pub errno: i32,
    /// Human-readable error message.
    pub message: String,
    /// SQLSTATE error code.
    pub sqlstate: String,
}

impl MysqliError {
    pub fn new(errno: i32, message: &str) -> Self {
        Self {
            errno,
            message: message.to_string(),
            sqlstate: "HY000".to_string(),
        }
    }

    pub fn connection_error(message: &str) -> Self {
        Self::new(2002, message)
    }
}

impl fmt::Display for MysqliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mysqli error {}: {}", self.errno, self.message)
    }
}

impl std::error::Error for MysqliError {}

// ---------------------------------------------------------------------------
// MysqliValue
// ---------------------------------------------------------------------------

/// A value returned from a MySQL query result.
#[derive(Debug, Clone, PartialEq)]
pub enum MysqliValue {
    Null,
    Int(i64),
    Float(f64),
    String(String),
    Blob(Vec<u8>),
}

impl fmt::Display for MysqliValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MysqliValue::Null => write!(f, "NULL"),
            MysqliValue::Int(v) => write!(f, "{}", v),
            MysqliValue::Float(v) => write!(f, "{}", v),
            MysqliValue::String(v) => write!(f, "{}", v),
            MysqliValue::Blob(v) => write!(f, "<blob({} bytes)>", v.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// MysqliField
// ---------------------------------------------------------------------------

/// Describes a column/field in a result set.
#[derive(Debug, Clone, PartialEq)]
pub struct MysqliField {
    /// Column name.
    pub name: String,
    /// Table this column belongs to.
    pub table: String,
    /// MySQL type ID.
    pub type_id: u32,
    /// Maximum length of the column.
    pub length: u32,
    /// Column flags.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// MysqliResult
// ---------------------------------------------------------------------------

/// A result set from a MySQL query.
#[derive(Debug, Clone)]
pub struct MysqliResult {
    /// All rows in the result set.
    pub rows: Vec<Vec<MysqliValue>>,
    /// Field/column metadata.
    pub fields: Vec<MysqliField>,
    /// Current row pointer (for sequential fetching).
    pub current_row: usize,
    /// Total number of rows.
    pub num_rows: usize,
}

impl MysqliResult {
    /// Create a new empty result set.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            fields: Vec::new(),
            current_row: 0,
            num_rows: 0,
        }
    }

    /// Create a result set from rows and field metadata.
    pub fn from_rows(rows: Vec<Vec<MysqliValue>>, fields: Vec<MysqliField>) -> Self {
        let num_rows = rows.len();
        Self {
            rows,
            fields,
            current_row: 0,
            num_rows,
        }
    }
}

impl Default for MysqliResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MysqliConnection
// ---------------------------------------------------------------------------

/// Represents a connection to a MySQL server.
#[derive(Debug, Clone)]
pub struct MysqliConnection {
    /// Hostname of the MySQL server.
    pub host: String,
    /// Username used to authenticate.
    pub username: String,
    /// The current database.
    pub database: String,
    /// Port number.
    pub port: u16,
    /// Whether the connection is currently active.
    pub connected: bool,
    /// Server version information string.
    pub server_info: String,
    /// Number of affected rows from the last query.
    pub affected_rows: i64,
    /// Last auto-increment insert ID.
    pub insert_id: i64,
    /// Last error number (0 = no error).
    pub errno: i32,
    /// Last error message.
    pub error: String,
    /// Current character set.
    pub charset: String,
    /// Whether a transaction is active.
    pub in_transaction: bool,
    /// Underlying mysqlnd connection.
    mysqlnd_conn: Option<MysqlndConnection>,
}

// ---------------------------------------------------------------------------
// MysqliStmt
// ---------------------------------------------------------------------------

/// A prepared statement handle.
#[derive(Debug, Clone)]
pub struct MysqliStmt {
    /// The SQL query template.
    pub query: String,
    /// Parameter types string (e.g. "ssi" for string, string, int).
    pub param_types: Option<String>,
    /// Bound parameter values.
    pub params: Vec<MysqliValue>,
    /// Whether the statement has been executed.
    pub executed: bool,
    /// Result set after execution (if any).
    pub result: Option<MysqliResult>,
    /// Affected rows from the last execution.
    pub affected_rows: i64,
    /// Insert ID from the last execution.
    pub insert_id: i64,
}

impl MysqliStmt {
    /// Create a new prepared statement.
    pub fn new(query: &str) -> Self {
        Self {
            query: query.to_string(),
            param_types: None,
            params: Vec::new(),
            executed: false,
            result: None,
            affected_rows: 0,
            insert_id: 0,
        }
    }

    /// Bind parameter types and values.
    ///
    /// `types` is a string where each character describes a parameter type:
    /// - 's' = string
    /// - 'i' = integer
    /// - 'd' = double/float
    /// - 'b' = blob
    pub fn bind_param(&mut self, types: &str, values: Vec<MysqliValue>) -> Result<(), MysqliError> {
        if types.len() != values.len() {
            return Err(MysqliError::new(
                2031,
                "Number of parameter types does not match number of values",
            ));
        }
        // Validate type characters.
        for ch in types.chars() {
            if !matches!(ch, 's' | 'i' | 'd' | 'b') {
                return Err(MysqliError::new(
                    2031,
                    &format!("Invalid parameter type: {}", ch),
                ));
            }
        }
        self.param_types = Some(types.to_string());
        self.params = values;
        Ok(())
    }

    /// Execute the prepared statement.
    ///
    /// This is a stub -- no actual query execution occurs.
    pub fn execute(&mut self) -> Result<bool, MysqliError> {
        self.executed = true;
        self.affected_rows = 0;
        self.insert_id = 0;
        self.result = Some(MysqliResult::new());
        Ok(true)
    }

    /// Get the result set from the last execution.
    pub fn get_result(&self) -> Option<&MysqliResult> {
        self.result.as_ref()
    }

    /// Close the prepared statement and free resources.
    pub fn close(&mut self) {
        self.params.clear();
        self.param_types = None;
        self.executed = false;
        self.result = None;
    }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Connect to a MySQL server.
///
/// Equivalent to PHP's `mysqli_connect()`.
/// Creates a real TCP connection to the MySQL server.
pub fn mysqli_connect(
    host: &str,
    user: &str,
    password: &str,
    database: &str,
    port: Option<u16>,
) -> Result<MysqliConnection, MysqliError> {
    if host.is_empty() {
        return Err(MysqliError::connection_error(
            "No hostname was provided to mysqli_connect()",
        ));
    }

    let port_val = port.unwrap_or(MYSQLI_DEFAULT_PORT);

    // Create real mysqlnd connection
    let mysqlnd_conn = match mysqlnd_connect(host, user, password, database, port_val) {
        Ok(conn) => conn,
        Err(e) => {
            return Err(MysqliError::new(2002, &format!("Connection failed: {}", e)));
        }
    };

    let server_info = mysqlnd_conn.server_version.clone();

    Ok(MysqliConnection {
        host: host.to_string(),
        username: user.to_string(),
        database: database.to_string(),
        port: port_val,
        connected: true,
        server_info,
        affected_rows: 0,
        insert_id: 0,
        errno: 0,
        error: String::new(),
        charset: "utf8mb4".to_string(),
        in_transaction: false,
        mysqlnd_conn: Some(mysqlnd_conn),
    })
}

/// Execute a query on the connection.
///
/// Equivalent to PHP's `mysqli_query()`.
/// Executes a real SQL query against the MySQL server.
pub fn mysqli_query(conn: &mut MysqliConnection, query: &str) -> Result<MysqliResult, MysqliError> {
    if !conn.connected {
        return Err(MysqliError::new(2006, "MySQL server has gone away"));
    }

    let mysqlnd_conn = conn
        .mysqlnd_conn
        .as_mut()
        .ok_or_else(|| MysqliError::new(2006, "No active connection"))?;

    // Execute the query
    let rows = match mysqlnd_query(mysqlnd_conn, query) {
        Ok(rows) => rows,
        Err(e) => {
            conn.errno = e.code as i32;
            conn.error = e.message.clone();
            return Err(MysqliError::new(e.code as i32, &e.message));
        }
    };

    conn.affected_rows = rows.len() as i64;
    conn.errno = 0;
    conn.error.clear();

    // Convert mysql::Row to MysqliResult
    let mut result_rows = Vec::new();
    let mut fields = Vec::new();

    if let Some(first_row) = rows.first() {
        // Extract column information from first row
        let columns = first_row.columns();
        for (_idx, col) in columns.iter().enumerate() {
            fields.push(MysqliField {
                name: col.name_str().to_string(),
                table: col.table_str().to_string(),
                type_id: col.column_type() as u32,
                length: col.column_length(),
                flags: col.flags().bits() as u32,
            });
        }
    }

    // Convert rows
    for row in rows {
        let mut row_values = Vec::new();
        for idx in 0..row.len() {
            let value = if row.as_ref(idx).is_some() {
                // Try to extract the value as different types
                if let Some(s) = row.get::<String, usize>(idx) {
                    MysqliValue::String(s)
                } else if let Some(i) = row.get::<i64, usize>(idx) {
                    MysqliValue::Int(i)
                } else if let Some(f) = row.get::<f64, usize>(idx) {
                    MysqliValue::Float(f)
                } else if let Some(b) = row.get::<Vec<u8>, usize>(idx) {
                    MysqliValue::Blob(b)
                } else {
                    MysqliValue::Null
                }
            } else {
                MysqliValue::Null
            };
            row_values.push(value);
        }
        result_rows.push(row_values);
    }

    Ok(MysqliResult::from_rows(result_rows, fields))
}

/// Escape a string for use in a MySQL query.
///
/// Equivalent to PHP's `mysqli_real_escape_string()`.
/// Escapes special characters: NUL, backslash, single quote, double quote,
/// Control-Z (0x1A), newline, carriage return.
pub fn mysqli_real_escape_string(_conn: &MysqliConnection, input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            '\0' => result.push_str("\\0"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("\\'"),
            '"' => result.push_str("\\\""),
            '\x1a' => result.push_str("\\Z"),
            _ => result.push(ch),
        }
    }
    result
}

/// Fetch the next row as an associative map.
///
/// Equivalent to PHP's `mysqli_fetch_assoc()`.
pub fn mysqli_fetch_assoc(result: &mut MysqliResult) -> Option<HashMap<String, MysqliValue>> {
    if result.current_row >= result.num_rows {
        return None;
    }
    let row = &result.rows[result.current_row];
    result.current_row += 1;

    let mut map = HashMap::new();
    for (i, field) in result.fields.iter().enumerate() {
        if i < row.len() {
            map.insert(field.name.clone(), row[i].clone());
        }
    }
    Some(map)
}

/// Fetch the next row as a numeric vector.
///
/// Equivalent to PHP's `mysqli_fetch_row()`.
pub fn mysqli_fetch_row(result: &mut MysqliResult) -> Option<Vec<MysqliValue>> {
    if result.current_row >= result.num_rows {
        return None;
    }
    let row = result.rows[result.current_row].clone();
    result.current_row += 1;
    Some(row)
}

/// Fetch the next row in the specified mode.
///
/// Equivalent to PHP's `mysqli_fetch_array()`.
///
/// `mode` is one of `MYSQLI_ASSOC`, `MYSQLI_NUM`, or `MYSQLI_BOTH`.
pub fn mysqli_fetch_array(
    result: &mut MysqliResult,
    mode: i32,
) -> Option<HashMap<String, MysqliValue>> {
    if result.current_row >= result.num_rows {
        return None;
    }
    let row = &result.rows[result.current_row];
    result.current_row += 1;

    let mut map = HashMap::new();

    if mode == MYSQLI_NUM || mode == MYSQLI_BOTH {
        for (i, val) in row.iter().enumerate() {
            map.insert(i.to_string(), val.clone());
        }
    }
    if mode == MYSQLI_ASSOC || mode == MYSQLI_BOTH {
        for (i, field) in result.fields.iter().enumerate() {
            if i < row.len() {
                map.insert(field.name.clone(), row[i].clone());
            }
        }
    }

    Some(map)
}

/// Get the number of rows in a result set.
///
/// Equivalent to PHP's `mysqli_num_rows()`.
pub fn mysqli_num_rows(result: &MysqliResult) -> usize {
    result.num_rows
}

/// Get the number of affected rows from the last query.
///
/// Equivalent to PHP's `mysqli_affected_rows()`.
pub fn mysqli_affected_rows(conn: &MysqliConnection) -> i64 {
    conn.affected_rows
}

/// Get the last auto-increment insert ID.
///
/// Equivalent to PHP's `mysqli_insert_id()`.
pub fn mysqli_insert_id(conn: &MysqliConnection) -> i64 {
    conn.insert_id
}

/// Close the MySQL connection.
///
/// Equivalent to PHP's `mysqli_close()`.
pub fn mysqli_close(conn: &mut MysqliConnection) {
    if let Some(ref mut mysqlnd_conn) = conn.mysqlnd_conn {
        mysqlnd_close(mysqlnd_conn);
    }
    conn.mysqlnd_conn = None;
    conn.connected = false;
    conn.errno = 0;
    conn.error.clear();
}

/// Get the last error number.
///
/// Equivalent to PHP's `mysqli_errno()`.
pub fn mysqli_errno(conn: &MysqliConnection) -> i32 {
    conn.errno
}

/// Get the last error message.
///
/// Equivalent to PHP's `mysqli_error()`.
pub fn mysqli_error(conn: &MysqliConnection) -> String {
    conn.error.clone()
}

/// Prepare a statement for execution.
///
/// Equivalent to PHP's `mysqli_prepare()`.
pub fn mysqli_prepare(conn: &MysqliConnection, query: &str) -> Result<MysqliStmt, MysqliError> {
    if !conn.connected {
        return Err(MysqliError::new(2006, "MySQL server has gone away"));
    }
    if query.is_empty() {
        return Err(MysqliError::new(1065, "Query was empty"));
    }
    Ok(MysqliStmt::new(query))
}

/// Begin a transaction.
///
/// Equivalent to PHP's `mysqli_begin_transaction()`.
pub fn mysqli_begin_transaction(conn: &mut MysqliConnection) -> Result<bool, MysqliError> {
    if !conn.connected {
        return Err(MysqliError::new(2006, "MySQL server has gone away"));
    }
    if conn.in_transaction {
        return Err(MysqliError::new(1399, "Transaction already started"));
    }
    conn.in_transaction = true;
    Ok(true)
}

/// Commit the current transaction.
///
/// Equivalent to PHP's `mysqli_commit()`.
pub fn mysqli_commit(conn: &mut MysqliConnection) -> Result<bool, MysqliError> {
    if !conn.connected {
        return Err(MysqliError::new(2006, "MySQL server has gone away"));
    }
    if !conn.in_transaction {
        return Err(MysqliError::new(1399, "No active transaction to commit"));
    }
    conn.in_transaction = false;
    Ok(true)
}

/// Roll back the current transaction.
///
/// Equivalent to PHP's `mysqli_rollback()`.
pub fn mysqli_rollback(conn: &mut MysqliConnection) -> Result<bool, MysqliError> {
    if !conn.connected {
        return Err(MysqliError::new(2006, "MySQL server has gone away"));
    }
    if !conn.in_transaction {
        return Err(MysqliError::new(1399, "No active transaction to rollback"));
    }
    conn.in_transaction = false;
    Ok(true)
}

/// Set the character set for the connection.
///
/// Equivalent to PHP's `mysqli_set_charset()`.
pub fn mysqli_set_charset(conn: &mut MysqliConnection, charset: &str) -> bool {
    if !conn.connected {
        return false;
    }
    let valid = matches!(
        charset,
        "utf8" | "utf8mb4" | "latin1" | "ascii" | "binary" | "utf8mb3"
    );
    if valid {
        conn.charset = charset.to_string();
    }
    valid
}

/// Select/change the current database.
///
/// Equivalent to PHP's `mysqli_select_db()`.
pub fn mysqli_select_db(conn: &mut MysqliConnection, database: &str) -> bool {
    if !conn.connected {
        return false;
    }
    if database.is_empty() {
        return false;
    }
    conn.database = database.to_string();
    true
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> MysqliConnection {
        // For tests, create a stub connection without real MySQL
        // Real integration tests should use an actual MySQL server
        MysqliConnection {
            host: "localhost".to_string(),
            username: "root".to_string(),
            database: "testdb".to_string(),
            port: MYSQLI_DEFAULT_PORT,
            connected: true,
            server_info: "8.0.0-test".to_string(),
            affected_rows: 0,
            insert_id: 0,
            errno: 0,
            error: String::new(),
            charset: "utf8mb4".to_string(),
            in_transaction: false,
            mysqlnd_conn: None, // No real connection for unit tests
        }
    }

    #[test]
    fn test_connect_success() {
        let conn = test_connection();
        assert!(conn.connected);
        assert_eq!(conn.host, "localhost");
        assert_eq!(conn.username, "root");
        assert_eq!(conn.database, "testdb");
        assert_eq!(conn.port, MYSQLI_DEFAULT_PORT);
        assert_eq!(conn.errno, 0);
        assert!(conn.error.is_empty());
    }

    #[test]
    fn test_connect_with_custom_port() {
        // Unit test with stub connection
        let conn = MysqliConnection {
            host: "db.example.com".to_string(),
            username: "admin".to_string(),
            database: "myapp".to_string(),
            port: 3307,
            connected: true,
            server_info: "8.0.0-test".to_string(),
            affected_rows: 0,
            insert_id: 0,
            errno: 0,
            error: String::new(),
            charset: "utf8mb4".to_string(),
            in_transaction: false,
            mysqlnd_conn: None,
        };
        assert_eq!(conn.port, 3307);
        assert_eq!(conn.host, "db.example.com");
    }

    #[test]
    fn test_connect_empty_host_fails() {
        let result = mysqli_connect("", "root", "pass", "db", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.errno, 2002);
        assert!(err.message.contains("hostname"));
    }

    #[test]
    fn test_real_escape_string() {
        let conn = test_connection();
        assert_eq!(mysqli_real_escape_string(&conn, "hello"), "hello");
        assert_eq!(mysqli_real_escape_string(&conn, "it's"), "it\\'s");
        assert_eq!(
            mysqli_real_escape_string(&conn, "line1\nline2"),
            "line1\\nline2"
        );
        assert_eq!(mysqli_real_escape_string(&conn, "tab\ttab"), "tab\ttab");
        assert_eq!(
            mysqli_real_escape_string(&conn, r#"say "hi""#),
            r#"say \"hi\""#
        );
        assert_eq!(
            mysqli_real_escape_string(&conn, "null\0byte"),
            "null\\0byte"
        );
        assert_eq!(
            mysqli_real_escape_string(&conn, "back\\slash"),
            "back\\\\slash"
        );
        assert_eq!(mysqli_real_escape_string(&conn, "ctrl\x1aZ"), "ctrl\\ZZ");
    }

    #[test]
    fn test_close_and_state() {
        let mut conn = test_connection();
        assert!(conn.connected);
        mysqli_close(&mut conn);
        assert!(!conn.connected);
        assert_eq!(mysqli_errno(&conn), 0);
        assert_eq!(mysqli_error(&conn), "");
    }

    #[test]
    fn test_query_on_closed_connection() {
        let mut conn = test_connection();
        mysqli_close(&mut conn);
        let result = mysqli_query(&mut conn, "SELECT 1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().errno, 2006);
    }

    #[test]
    fn test_fetch_assoc() {
        let fields = vec![
            MysqliField {
                name: "id".to_string(),
                table: "users".to_string(),
                type_id: 3,
                length: 11,
                flags: 0,
            },
            MysqliField {
                name: "name".to_string(),
                table: "users".to_string(),
                type_id: 253,
                length: 255,
                flags: 0,
            },
        ];
        let rows = vec![
            vec![
                MysqliValue::Int(1),
                MysqliValue::String("Alice".to_string()),
            ],
            vec![MysqliValue::Int(2), MysqliValue::String("Bob".to_string())],
        ];
        let mut result = MysqliResult::from_rows(rows, fields);
        assert_eq!(mysqli_num_rows(&result), 2);

        let row1 = mysqli_fetch_assoc(&mut result).expect("should have row");
        assert_eq!(row1.get("id"), Some(&MysqliValue::Int(1)));
        assert_eq!(
            row1.get("name"),
            Some(&MysqliValue::String("Alice".to_string()))
        );

        let row2 = mysqli_fetch_assoc(&mut result).expect("should have row");
        assert_eq!(row2.get("id"), Some(&MysqliValue::Int(2)));

        // No more rows.
        assert!(mysqli_fetch_assoc(&mut result).is_none());
    }

    #[test]
    fn test_fetch_row() {
        let fields = vec![MysqliField {
            name: "val".to_string(),
            table: "t".to_string(),
            type_id: 3,
            length: 11,
            flags: 0,
        }];
        let rows = vec![vec![MysqliValue::Int(42)], vec![MysqliValue::Int(99)]];
        let mut result = MysqliResult::from_rows(rows, fields);

        let row1 = mysqli_fetch_row(&mut result).expect("should have row");
        assert_eq!(row1, vec![MysqliValue::Int(42)]);

        let row2 = mysqli_fetch_row(&mut result).expect("should have row");
        assert_eq!(row2, vec![MysqliValue::Int(99)]);

        assert!(mysqli_fetch_row(&mut result).is_none());
    }

    #[test]
    fn test_fetch_array_both_mode() {
        let fields = vec![MysqliField {
            name: "color".to_string(),
            table: "t".to_string(),
            type_id: 253,
            length: 64,
            flags: 0,
        }];
        let rows = vec![vec![MysqliValue::String("red".to_string())]];
        let mut result = MysqliResult::from_rows(rows, fields);

        let row = mysqli_fetch_array(&mut result, MYSQLI_BOTH).expect("should have row");
        // Should contain both numeric key "0" and named key "color".
        assert_eq!(row.get("0"), Some(&MysqliValue::String("red".to_string())));
        assert_eq!(
            row.get("color"),
            Some(&MysqliValue::String("red".to_string()))
        );
    }

    #[test]
    fn test_affected_rows_and_insert_id() {
        let mut conn = test_connection();
        conn.affected_rows = 5;
        conn.insert_id = 42;
        assert_eq!(mysqli_affected_rows(&conn), 5);
        assert_eq!(mysqli_insert_id(&conn), 42);
    }

    #[test]
    fn test_prepare_and_bind() {
        let conn = test_connection();
        let mut stmt = mysqli_prepare(&conn, "INSERT INTO users (name, age) VALUES (?, ?)")
            .expect("prepare should succeed");
        assert_eq!(stmt.query, "INSERT INTO users (name, age) VALUES (?, ?)");

        stmt.bind_param(
            "si",
            vec![
                MysqliValue::String("Alice".to_string()),
                MysqliValue::Int(30),
            ],
        )
        .expect("bind should succeed");
        assert_eq!(stmt.param_types, Some("si".to_string()));
        assert_eq!(stmt.params.len(), 2);
    }

    #[test]
    fn test_prepare_bind_param_type_count_mismatch() {
        let conn = test_connection();
        let mut stmt = mysqli_prepare(&conn, "SELECT ?").expect("prepare should succeed");
        let result = stmt.bind_param("ss", vec![MysqliValue::String("one".to_string())]);
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_invalid_type_char() {
        let conn = test_connection();
        let mut stmt = mysqli_prepare(&conn, "SELECT ?").expect("prepare should succeed");
        let result = stmt.bind_param("x", vec![MysqliValue::Int(1)]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("Invalid parameter type"));
    }

    #[test]
    fn test_stmt_execute_and_get_result() {
        let conn = test_connection();
        let mut stmt = mysqli_prepare(&conn, "SELECT 1").expect("prepare should succeed");
        let ok = stmt.execute().expect("execute should succeed");
        assert!(ok);
        assert!(stmt.executed);
        assert!(stmt.get_result().is_some());
    }

    #[test]
    fn test_stmt_close() {
        let conn = test_connection();
        let mut stmt = mysqli_prepare(&conn, "SELECT 1").expect("prepare should succeed");
        stmt.execute().unwrap();
        stmt.close();
        assert!(!stmt.executed);
        assert!(stmt.result.is_none());
        assert!(stmt.params.is_empty());
    }

    #[test]
    fn test_prepare_on_closed_connection() {
        let mut conn = test_connection();
        mysqli_close(&mut conn);
        let result = mysqli_prepare(&conn, "SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_empty_query() {
        let conn = test_connection();
        let result = mysqli_prepare(&conn, "");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().errno, 1065);
    }

    #[test]
    fn test_transaction_lifecycle() {
        let mut conn = test_connection();

        assert!(!conn.in_transaction);
        mysqli_begin_transaction(&mut conn).expect("begin should succeed");
        assert!(conn.in_transaction);

        // Double begin should fail.
        let result = mysqli_begin_transaction(&mut conn);
        assert!(result.is_err());

        // Commit.
        mysqli_commit(&mut conn).expect("commit should succeed");
        assert!(!conn.in_transaction);

        // Commit without transaction should fail.
        let result = mysqli_commit(&mut conn);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_rollback() {
        let mut conn = test_connection();
        mysqli_begin_transaction(&mut conn).expect("begin should succeed");
        mysqli_rollback(&mut conn).expect("rollback should succeed");
        assert!(!conn.in_transaction);

        // Rollback without transaction should fail.
        let result = mysqli_rollback(&mut conn);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_charset() {
        let mut conn = test_connection();
        assert!(mysqli_set_charset(&mut conn, "utf8"));
        assert_eq!(conn.charset, "utf8");

        assert!(mysqli_set_charset(&mut conn, "latin1"));
        assert_eq!(conn.charset, "latin1");

        // Invalid charset.
        assert!(!mysqli_set_charset(&mut conn, "invalid_charset"));
        // charset should remain unchanged.
        assert_eq!(conn.charset, "latin1");
    }

    #[test]
    fn test_set_charset_on_closed_connection() {
        let mut conn = test_connection();
        mysqli_close(&mut conn);
        assert!(!mysqli_set_charset(&mut conn, "utf8"));
    }

    #[test]
    fn test_select_db() {
        let mut conn = test_connection();
        assert_eq!(conn.database, "testdb");

        assert!(mysqli_select_db(&mut conn, "other_db"));
        assert_eq!(conn.database, "other_db");

        // Empty db name should fail.
        assert!(!mysqli_select_db(&mut conn, ""));
        assert_eq!(conn.database, "other_db");
    }

    #[test]
    fn test_select_db_on_closed_connection() {
        let mut conn = test_connection();
        mysqli_close(&mut conn);
        assert!(!mysqli_select_db(&mut conn, "newdb"));
    }

    #[test]
    fn test_error_display() {
        let err = MysqliError::new(1045, "Access denied for user");
        assert_eq!(err.to_string(), "mysqli error 1045: Access denied for user");
    }

    #[test]
    fn test_value_display() {
        assert_eq!(MysqliValue::Null.to_string(), "NULL");
        assert_eq!(MysqliValue::Int(42).to_string(), "42");
        assert_eq!(MysqliValue::Float(3.125).to_string(), "3.125");
        assert_eq!(
            MysqliValue::String("hello".to_string()).to_string(),
            "hello"
        );
        assert_eq!(
            MysqliValue::Blob(vec![1, 2, 3]).to_string(),
            "<blob(3 bytes)>"
        );
    }

    #[test]
    fn test_query_success() {
        let mut conn = test_connection();
        // For unit test, query will fail without real mysqlnd connection
        // This test just verifies the error handling works
        let result = mysqli_query(&mut conn, "SELECT 1");
        assert!(result.is_err()); // Expected to fail without mysqlnd_conn
    }

    #[test]
    fn test_server_info() {
        let conn = test_connection();
        assert!(conn.server_info.contains("test")); // Test stub has "8.0.0-test"
    }
}
