//! ODBC database access extension for php.rs
//!
//! Implements the odbc_* family of functions for database access via ODBC.
//! This is a structural stub -- no actual ODBC driver manager is used.
//! The full API surface is provided for PHP compatibility.

use std::fmt;

// ---------------------------------------------------------------------------
// OdbcError
// ---------------------------------------------------------------------------

/// An error from the ODBC subsystem.
#[derive(Debug, Clone, PartialEq)]
pub struct OdbcError {
    /// SQLSTATE error code (5 characters).
    pub sqlstate: String,
    /// Human-readable error message.
    pub message: String,
}

impl OdbcError {
    pub fn new(sqlstate: &str, message: &str) -> Self {
        Self {
            sqlstate: sqlstate.to_string(),
            message: message.to_string(),
        }
    }

    pub fn general(message: &str) -> Self {
        Self::new("HY000", message)
    }
}

impl fmt::Display for OdbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ODBC error [{}]: {}", self.sqlstate, self.message)
    }
}

impl std::error::Error for OdbcError {}

// ---------------------------------------------------------------------------
// OdbcColumn — Column metadata
// ---------------------------------------------------------------------------

/// Describes a column in an ODBC result set.
#[derive(Debug, Clone, PartialEq)]
pub struct OdbcColumn {
    /// Column name.
    pub name: String,
    /// Type name (e.g. "VARCHAR", "INTEGER").
    pub type_name: String,
    /// Column size in bytes.
    pub size: i32,
    /// Whether the column is nullable.
    pub nullable: bool,
}

// ---------------------------------------------------------------------------
// OdbcResult — A result set
// ---------------------------------------------------------------------------

/// A result set from an ODBC query.
#[derive(Debug, Clone)]
pub struct OdbcResult {
    /// Rows of string values (ODBC returns everything as strings).
    pub rows: Vec<Vec<Option<String>>>,
    /// Column definitions.
    pub columns: Vec<OdbcColumn>,
    /// Current row pointer for sequential fetching.
    pub current_row: usize,
}

impl OdbcResult {
    /// Create a new empty result set.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: Vec::new(),
            current_row: 0,
        }
    }

    /// Create a result set from column definitions and rows.
    pub fn from_data(columns: Vec<OdbcColumn>, rows: Vec<Vec<Option<String>>>) -> Self {
        Self {
            rows,
            columns,
            current_row: 0,
        }
    }
}

impl Default for OdbcResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OdbcConnection — Connection handle
// ---------------------------------------------------------------------------

/// Represents an open ODBC connection.
#[derive(Debug, Clone)]
pub struct OdbcConnection {
    /// The DSN used to connect.
    pub dsn: String,
    /// Whether the connection is active.
    pub connected: bool,
    /// Whether autocommit is enabled.
    pub auto_commit: bool,
    /// Last error SQLSTATE.
    pub last_error: String,
    /// Last error message.
    pub last_error_msg: String,
}

// ---------------------------------------------------------------------------
// OdbcStmt — Prepared statement
// ---------------------------------------------------------------------------

/// A prepared ODBC statement.
#[derive(Debug, Clone)]
pub struct OdbcStmt {
    /// The SQL query.
    pub query: String,
    /// Bound parameter values.
    pub params: Vec<Option<String>>,
    /// Whether the statement has been executed.
    pub executed: bool,
}

impl OdbcStmt {
    /// Create a new prepared statement.
    pub fn new(query: &str) -> Self {
        Self {
            query: query.to_string(),
            params: Vec::new(),
            executed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Open an ODBC connection.
///
/// Equivalent to PHP's `odbc_connect()`.
pub fn odbc_connect(dsn: &str, user: &str, _password: &str) -> Result<OdbcConnection, OdbcError> {
    if dsn.is_empty() {
        return Err(OdbcError::general("DSN cannot be empty"));
    }
    if user.is_empty() {
        return Err(OdbcError::general("Username cannot be empty"));
    }

    Ok(OdbcConnection {
        dsn: dsn.to_string(),
        connected: true,
        auto_commit: true,
        last_error: String::new(),
        last_error_msg: String::new(),
    })
}

/// Close an ODBC connection.
///
/// Equivalent to PHP's `odbc_close()`.
pub fn odbc_close(conn: &mut OdbcConnection) {
    conn.connected = false;
    conn.last_error.clear();
    conn.last_error_msg.clear();
}

/// Execute a SQL statement directly.
///
/// Equivalent to PHP's `odbc_exec()`.
pub fn odbc_exec(conn: &mut OdbcConnection, _query: &str) -> Result<OdbcResult, OdbcError> {
    if !conn.connected {
        return Err(OdbcError::general("Connection is not active"));
    }
    conn.last_error.clear();
    conn.last_error_msg.clear();
    Ok(OdbcResult::new())
}

/// Prepare a SQL statement for execution.
///
/// Equivalent to PHP's `odbc_prepare()`.
pub fn odbc_prepare(conn: &OdbcConnection, query: &str) -> Result<OdbcStmt, OdbcError> {
    if !conn.connected {
        return Err(OdbcError::general("Connection is not active"));
    }
    if query.is_empty() {
        return Err(OdbcError::general("Query cannot be empty"));
    }
    Ok(OdbcStmt::new(query))
}

/// Execute a prepared statement.
///
/// Equivalent to PHP's `odbc_execute()`.
pub fn odbc_execute(stmt: &mut OdbcStmt) -> Result<OdbcResult, OdbcError> {
    stmt.executed = true;
    Ok(OdbcResult::new())
}

/// Fetch the next row from a result set, advancing the cursor.
///
/// Equivalent to PHP's `odbc_fetch_row()`.
/// Returns true if a row was fetched, false if no more rows.
pub fn odbc_fetch_row(result: &mut OdbcResult) -> bool {
    if result.current_row < result.rows.len() {
        result.current_row += 1;
        true
    } else {
        false
    }
}

/// Get a single field value from the current row.
///
/// Equivalent to PHP's `odbc_result()`.
/// `field` is a 1-based column index or a column name.
pub fn odbc_result(result: &OdbcResult, field: &str) -> Option<String> {
    if result.current_row == 0 || result.current_row > result.rows.len() {
        return None;
    }
    let row_idx = result.current_row - 1;
    let row = &result.rows[row_idx];

    // Try to parse field as a 1-based numeric index.
    if let Ok(idx) = field.parse::<usize>() {
        if idx >= 1 && idx <= row.len() {
            return row[idx - 1].clone();
        }
    }

    // Try to find by column name.
    for (i, col) in result.columns.iter().enumerate() {
        if col.name.eq_ignore_ascii_case(field) && i < row.len() {
            return row[i].clone();
        }
    }

    None
}

/// Get the number of rows in a result set.
///
/// Equivalent to PHP's `odbc_num_rows()`.
/// Returns -1 if the row count is not known (e.g. for some ODBC drivers).
pub fn odbc_num_rows(result: &OdbcResult) -> i64 {
    result.rows.len() as i64
}

/// Get the number of fields (columns) in a result set.
///
/// Equivalent to PHP's `odbc_num_fields()`.
pub fn odbc_num_fields(result: &OdbcResult) -> i32 {
    result.columns.len() as i32
}

/// Get the name of a field by its 1-based index.
///
/// Equivalent to PHP's `odbc_field_name()`.
pub fn odbc_field_name(result: &OdbcResult, field_number: i32) -> Option<String> {
    let idx = (field_number - 1) as usize;
    result.columns.get(idx).map(|c| c.name.clone())
}

/// Get the type name of a field by its 1-based index.
///
/// Equivalent to PHP's `odbc_field_type()`.
pub fn odbc_field_type(result: &OdbcResult, field_number: i32) -> Option<String> {
    let idx = (field_number - 1) as usize;
    result.columns.get(idx).map(|c| c.type_name.clone())
}

/// Commit the current transaction.
///
/// Equivalent to PHP's `odbc_commit()`.
pub fn odbc_commit(conn: &mut OdbcConnection) -> bool {
    if !conn.connected {
        return false;
    }
    true
}

/// Roll back the current transaction.
///
/// Equivalent to PHP's `odbc_rollback()`.
pub fn odbc_rollback(conn: &mut OdbcConnection) -> bool {
    if !conn.connected {
        return false;
    }
    true
}

/// Set or get the autocommit mode.
///
/// Equivalent to PHP's `odbc_autocommit()`.
/// If `on_off` is `Some`, sets the autocommit mode and returns the new state.
/// If `on_off` is `None`, returns the current state.
pub fn odbc_autocommit(conn: &mut OdbcConnection, on_off: Option<bool>) -> bool {
    if !conn.connected {
        return false;
    }
    if let Some(value) = on_off {
        conn.auto_commit = value;
    }
    conn.auto_commit
}

/// Get the SQLSTATE error code for the last operation.
///
/// Equivalent to PHP's `odbc_error()`.
pub fn odbc_error(conn: &OdbcConnection) -> String {
    conn.last_error.clone()
}

/// Get the error message for the last operation.
///
/// Equivalent to PHP's `odbc_errormsg()`.
pub fn odbc_errormsg(conn: &OdbcConnection) -> String {
    conn.last_error_msg.clone()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> OdbcConnection {
        odbc_connect("DSN=TestDB", "user", "pass").expect("connect should succeed")
    }

    #[test]
    fn test_connect_success() {
        let conn = test_connection();
        assert!(conn.connected);
        assert_eq!(conn.dsn, "DSN=TestDB");
        assert!(conn.auto_commit);
    }

    #[test]
    fn test_connect_empty_dsn() {
        let result = odbc_connect("", "user", "pass");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("DSN"));
    }

    #[test]
    fn test_connect_empty_user() {
        let result = odbc_connect("DSN=Test", "", "pass");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Username"));
    }

    #[test]
    fn test_close() {
        let mut conn = test_connection();
        assert!(conn.connected);
        odbc_close(&mut conn);
        assert!(!conn.connected);
    }

    #[test]
    fn test_exec_on_active_connection() {
        let mut conn = test_connection();
        let result = odbc_exec(&mut conn, "SELECT 1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_exec_on_closed_connection() {
        let mut conn = test_connection();
        odbc_close(&mut conn);
        let result = odbc_exec(&mut conn, "SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_and_execute() {
        let conn = test_connection();
        let mut stmt = odbc_prepare(&conn, "SELECT * FROM users WHERE id = ?")
            .expect("prepare should succeed");
        assert_eq!(stmt.query, "SELECT * FROM users WHERE id = ?");
        assert!(!stmt.executed);

        let result = odbc_execute(&mut stmt);
        assert!(result.is_ok());
        assert!(stmt.executed);
    }

    #[test]
    fn test_prepare_empty_query() {
        let conn = test_connection();
        let result = odbc_prepare(&conn, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_on_closed_connection() {
        let mut conn = test_connection();
        odbc_close(&mut conn);
        let result = odbc_prepare(&conn, "SELECT 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_row_and_result() {
        let columns = vec![
            OdbcColumn {
                name: "id".to_string(),
                type_name: "INTEGER".to_string(),
                size: 4,
                nullable: false,
            },
            OdbcColumn {
                name: "name".to_string(),
                type_name: "VARCHAR".to_string(),
                size: 255,
                nullable: true,
            },
        ];
        let rows = vec![
            vec![Some("1".to_string()), Some("Alice".to_string())],
            vec![Some("2".to_string()), Some("Bob".to_string())],
        ];
        let mut result = OdbcResult::from_data(columns, rows);

        // Before fetch, current_row is 0.
        assert_eq!(odbc_num_rows(&result), 2);
        assert_eq!(odbc_num_fields(&result), 2);

        // Fetch first row.
        assert!(odbc_fetch_row(&mut result));
        assert_eq!(odbc_result(&result, "1"), Some("1".to_string()));
        assert_eq!(odbc_result(&result, "name"), Some("Alice".to_string()));
        assert_eq!(odbc_result(&result, "id"), Some("1".to_string()));

        // Fetch second row.
        assert!(odbc_fetch_row(&mut result));
        assert_eq!(odbc_result(&result, "2"), Some("Bob".to_string()));

        // No more rows.
        assert!(!odbc_fetch_row(&mut result));
    }

    #[test]
    fn test_result_before_fetch_returns_none() {
        let columns = vec![OdbcColumn {
            name: "val".to_string(),
            type_name: "INTEGER".to_string(),
            size: 4,
            nullable: false,
        }];
        let rows = vec![vec![Some("42".to_string())]];
        let result = OdbcResult::from_data(columns, rows);

        // current_row is 0 (no fetch called yet).
        assert_eq!(odbc_result(&result, "1"), None);
    }

    #[test]
    fn test_field_name_and_type() {
        let columns = vec![
            OdbcColumn {
                name: "id".to_string(),
                type_name: "INTEGER".to_string(),
                size: 4,
                nullable: false,
            },
            OdbcColumn {
                name: "email".to_string(),
                type_name: "VARCHAR".to_string(),
                size: 255,
                nullable: true,
            },
        ];
        let result = OdbcResult::from_data(columns, Vec::new());

        assert_eq!(odbc_field_name(&result, 1), Some("id".to_string()));
        assert_eq!(odbc_field_name(&result, 2), Some("email".to_string()));
        assert_eq!(odbc_field_name(&result, 3), None);

        assert_eq!(odbc_field_type(&result, 1), Some("INTEGER".to_string()));
        assert_eq!(odbc_field_type(&result, 2), Some("VARCHAR".to_string()));
        assert_eq!(odbc_field_type(&result, 3), None);
    }

    #[test]
    fn test_commit_and_rollback() {
        let mut conn = test_connection();
        assert!(odbc_commit(&mut conn));
        assert!(odbc_rollback(&mut conn));
    }

    #[test]
    fn test_commit_on_closed_connection() {
        let mut conn = test_connection();
        odbc_close(&mut conn);
        assert!(!odbc_commit(&mut conn));
        assert!(!odbc_rollback(&mut conn));
    }

    #[test]
    fn test_autocommit() {
        let mut conn = test_connection();
        assert!(odbc_autocommit(&mut conn, None)); // default is true

        odbc_autocommit(&mut conn, Some(false));
        assert!(!odbc_autocommit(&mut conn, None));

        odbc_autocommit(&mut conn, Some(true));
        assert!(odbc_autocommit(&mut conn, None));
    }

    #[test]
    fn test_autocommit_on_closed_connection() {
        let mut conn = test_connection();
        odbc_close(&mut conn);
        assert!(!odbc_autocommit(&mut conn, None));
    }

    #[test]
    fn test_error_functions() {
        let mut conn = test_connection();
        assert_eq!(odbc_error(&conn), "");
        assert_eq!(odbc_errormsg(&conn), "");

        // Simulate an error.
        conn.last_error = "42S02".to_string();
        conn.last_error_msg = "Table not found".to_string();
        assert_eq!(odbc_error(&conn), "42S02");
        assert_eq!(odbc_errormsg(&conn), "Table not found");
    }

    #[test]
    fn test_error_display() {
        let err = OdbcError::new("42S02", "Table not found");
        assert_eq!(err.to_string(), "ODBC error [42S02]: Table not found");
    }

    #[test]
    fn test_null_values_in_result() {
        let columns = vec![OdbcColumn {
            name: "val".to_string(),
            type_name: "VARCHAR".to_string(),
            size: 255,
            nullable: true,
        }];
        let rows = vec![vec![None], vec![Some("hello".to_string())]];
        let mut result = OdbcResult::from_data(columns, rows);

        assert!(odbc_fetch_row(&mut result));
        assert_eq!(odbc_result(&result, "1"), None); // NULL value

        assert!(odbc_fetch_row(&mut result));
        assert_eq!(odbc_result(&result, "1"), Some("hello".to_string()));
    }

    #[test]
    fn test_result_by_column_name_case_insensitive() {
        let columns = vec![OdbcColumn {
            name: "Name".to_string(),
            type_name: "VARCHAR".to_string(),
            size: 255,
            nullable: false,
        }];
        let rows = vec![vec![Some("Alice".to_string())]];
        let mut result = OdbcResult::from_data(columns, rows);

        assert!(odbc_fetch_row(&mut result));
        assert_eq!(odbc_result(&result, "name"), Some("Alice".to_string()));
        assert_eq!(odbc_result(&result, "NAME"), Some("Alice".to_string()));
        assert_eq!(odbc_result(&result, "Name"), Some("Alice".to_string()));
    }
}
