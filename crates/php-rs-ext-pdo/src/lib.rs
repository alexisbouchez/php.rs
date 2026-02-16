//! PDO (PHP Data Objects) extension for php.rs
//!
//! Provides a database abstraction layer with a driver-based architecture.
//! Currently implements the SQLite driver using rusqlite.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

type DriverFactory = Box<dyn Fn() -> Box<dyn PdoDriver> + Send + Sync>;

static DRIVER_REGISTRY: OnceLock<Mutex<HashMap<String, DriverFactory>>> = OnceLock::new();

/// Register a PDO driver factory.
///
/// This allows external crates to register their drivers with the PDO system.
/// The factory function will be called each time a connection is created.
pub fn register_pdo_driver<F>(name: &str, factory: F)
where
    F: Fn() -> Box<dyn PdoDriver> + Send + Sync + 'static,
{
    let registry = DRIVER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap();
    registry.insert(name.to_string(), Box::new(factory));
}

fn get_driver(name: &str) -> Option<Box<dyn PdoDriver>> {
    let registry = DRIVER_REGISTRY.get()?;
    let registry = registry.lock().unwrap();
    let factory = registry.get(name)?;
    Some(factory())
}

// ---------------------------------------------------------------------------
// PdoValue — Represents a typed value flowing through PDO
// ---------------------------------------------------------------------------

/// A value that can be bound to a prepared statement parameter or fetched from
/// a result row.
#[derive(Debug, Clone, PartialEq)]
pub enum PdoValue {
    Null,
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Blob(Vec<u8>),
}

impl fmt::Display for PdoValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdoValue::Null => write!(f, "NULL"),
            PdoValue::Int(v) => write!(f, "{}", v),
            PdoValue::Float(v) => write!(f, "{}", v),
            PdoValue::Str(v) => write!(f, "{}", v),
            PdoValue::Bool(v) => write!(f, "{}", if *v { "1" } else { "0" }),
            PdoValue::Blob(v) => write!(f, "<blob({} bytes)>", v.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// PdoParam — Identifies a parameter in a prepared statement
// ---------------------------------------------------------------------------

/// Identifies a bound parameter by name (`:name`) or position (1-based).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PdoParam {
    Named(String),
    Positional(usize),
}

// ---------------------------------------------------------------------------
// FetchMode — Controls how rows are returned
// ---------------------------------------------------------------------------

/// Controls the shape of rows returned by fetch / fetch_all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchMode {
    /// Associative array keyed by column name.
    Assoc,
    /// Numeric array keyed by column index (0-based).
    Num,
    /// Both associative and numeric keys (default in PHP).
    Both,
    /// Anonymous object with column names as properties.
    Obj,
    /// Single column value.
    Column,
}

// ---------------------------------------------------------------------------
// PdoRow — A single result row
// ---------------------------------------------------------------------------

/// A single result row with both named and indexed access.
#[derive(Debug, Clone, PartialEq)]
pub struct PdoRow {
    /// Column names in order.
    pub columns: Vec<String>,
    /// Values in column order.
    pub values: Vec<PdoValue>,
}

impl PdoRow {
    /// Get a value by column name.
    pub fn get_by_name(&self, name: &str) -> Option<&PdoValue> {
        self.columns
            .iter()
            .position(|c| c == name)
            .map(|i| &self.values[i])
    }

    /// Get a value by column index (0-based).
    pub fn get_by_index(&self, index: usize) -> Option<&PdoValue> {
        self.values.get(index)
    }

    /// Convert the row to an associative map.
    pub fn to_assoc(&self) -> HashMap<String, PdoValue> {
        self.columns
            .iter()
            .cloned()
            .zip(self.values.iter().cloned())
            .collect()
    }

    /// Convert the row to a numeric (index-keyed) map.
    pub fn to_num(&self) -> HashMap<usize, PdoValue> {
        self.values.iter().cloned().enumerate().collect()
    }
}

// ---------------------------------------------------------------------------
// PdoError
// ---------------------------------------------------------------------------

/// An error originating from PDO or a PDO driver.
#[derive(Debug, Clone, PartialEq)]
pub struct PdoError {
    /// SQLSTATE error code (5 characters), e.g. "HY000".
    pub sqlstate: String,
    /// Driver-specific error code.
    pub code: Option<String>,
    /// Human-readable error message.
    pub message: String,
}

impl PdoError {
    pub fn new(sqlstate: &str, code: Option<&str>, message: &str) -> Self {
        Self {
            sqlstate: sqlstate.to_string(),
            code: code.map(|c| c.to_string()),
            message: message.to_string(),
        }
    }

    /// Convenience constructor for a general error.
    pub fn general(message: &str) -> Self {
        Self::new("HY000", None, message)
    }
}

impl fmt::Display for PdoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SQLSTATE[{}]: {}", self.sqlstate, self.message)
    }
}

impl std::error::Error for PdoError {}

// ---------------------------------------------------------------------------
// PdoDriver trait
// ---------------------------------------------------------------------------

/// A PDO driver provides the low-level database operations.
pub trait PdoDriver: Send {
    /// Open a connection described by the DSN components.
    fn connect(
        &self,
        dsn_params: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Box<dyn PdoDriverConnection>, PdoError>;
}

/// A live connection through a driver.
pub trait PdoDriverConnection: Send {
    /// Prepare a SQL statement and return an opaque handle.
    fn prepare(&self, sql: &str) -> Result<Box<dyn PdoDriverStatement>, PdoError>;

    /// Execute a SQL statement directly and return the number of affected rows.
    fn exec(&self, sql: &str) -> Result<u64, PdoError>;

    /// Quote a string for safe embedding in a SQL literal.
    fn quote(&self, string: &str) -> String;

    /// Return the row ID of the last inserted row.
    fn last_insert_id(&self) -> String;

    /// Begin a transaction.
    fn begin_transaction(&self) -> Result<(), PdoError>;

    /// Commit the current transaction.
    fn commit(&self) -> Result<(), PdoError>;

    /// Roll back the current transaction.
    fn rollback(&self) -> Result<(), PdoError>;

    /// Whether a transaction is currently active.
    fn in_transaction(&self) -> bool;
}

/// A prepared statement through a driver.
pub trait PdoDriverStatement: Send {
    /// Bind a value to a parameter.
    fn bind_value(&mut self, param: &PdoParam, value: &PdoValue) -> Result<(), PdoError>;

    /// Execute the statement with optional positional parameters.
    fn execute(&mut self, params: Option<&[PdoValue]>) -> Result<bool, PdoError>;

    /// Fetch the next row.
    fn fetch(&mut self) -> Option<PdoRow>;

    /// Return the number of rows affected by the last execute.
    fn row_count(&self) -> u64;

    /// Return the number of columns in the result set.
    fn column_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// PdoStatement — User-facing prepared statement wrapper
// ---------------------------------------------------------------------------

/// A prepared statement, wrapping a driver-level statement.
pub struct PdoStatement {
    inner: Box<dyn PdoDriverStatement>,
}

impl PdoStatement {
    fn new(inner: Box<dyn PdoDriverStatement>) -> Self {
        Self { inner }
    }

    /// Bind a value to a named or positional parameter.
    pub fn bind_value(&mut self, param: PdoParam, value: PdoValue) -> Result<(), PdoError> {
        self.inner.bind_value(&param, &value)
    }

    /// Execute the prepared statement.
    ///
    /// If `params` is provided, they are bound positionally before execution.
    pub fn execute(&mut self, params: Option<&[PdoValue]>) -> Result<bool, PdoError> {
        self.inner.execute(params)
    }

    /// Fetch the next row according to the given fetch mode.
    pub fn fetch(&mut self, _mode: FetchMode) -> Option<PdoRow> {
        self.inner.fetch()
    }

    /// Fetch all remaining rows.
    pub fn fetch_all(&mut self, mode: FetchMode) -> Vec<PdoRow> {
        let mut rows = Vec::new();
        while let Some(row) = self.fetch(mode) {
            rows.push(row);
        }
        rows
    }

    /// Fetch a single column value from the next row.
    pub fn fetch_column(&mut self, column: usize) -> Option<PdoValue> {
        self.fetch(FetchMode::Num)
            .and_then(|row| row.get_by_index(column).cloned())
    }

    /// Return the number of rows affected by the last execute.
    pub fn row_count(&self) -> u64 {
        self.inner.row_count()
    }

    /// Return the number of columns in the result set.
    pub fn column_count(&self) -> usize {
        self.inner.column_count()
    }
}

// ---------------------------------------------------------------------------
// PdoConnection — The main PDO connection handle
// ---------------------------------------------------------------------------

/// The main PDO connection object.
///
/// Wraps a driver-level connection and tracks error state.
pub struct PdoConnection {
    conn: Box<dyn PdoDriverConnection>,
    last_error: Option<PdoError>,
}

impl PdoConnection {
    /// Create a new PDO connection from a DSN string.
    ///
    /// DSN format: `driver:params` e.g. `sqlite:/path/to/db` or `sqlite::memory:`
    pub fn new(
        dsn: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, PdoError> {
        let (driver_name, params) = dsn
            .split_once(':')
            .ok_or_else(|| PdoError::general("Invalid DSN: missing driver prefix"))?;

        let driver: Box<dyn PdoDriver> = if driver_name == "sqlite" {
            // Built-in SQLite driver
            Box::new(SqliteDriver)
        } else if let Some(driver) = get_driver(driver_name) {
            // Driver from registry (e.g., pgsql, mysql)
            driver
        } else {
            return Err(PdoError::new(
                "HY000",
                None,
                &format!("could not find driver: {}", driver_name),
            ));
        };

        let conn = driver.connect(params, username, password)?;

        Ok(Self {
            conn,
            last_error: None,
        })
    }

    /// Prepare a SQL statement for execution.
    pub fn prepare(&mut self, sql: &str) -> Result<PdoStatement, PdoError> {
        match self.conn.prepare(sql) {
            Ok(inner) => {
                self.last_error = None;
                Ok(PdoStatement::new(inner))
            }
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Prepare and execute a SQL query, returning a statement for fetching.
    pub fn query(&mut self, sql: &str) -> Result<PdoStatement, PdoError> {
        let mut stmt = self.prepare(sql)?;
        stmt.execute(None)?;
        Ok(stmt)
    }

    /// Execute a SQL statement and return the number of affected rows.
    pub fn exec(&mut self, sql: &str) -> Result<u64, PdoError> {
        match self.conn.exec(sql) {
            Ok(n) => {
                self.last_error = None;
                Ok(n)
            }
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Return the ID of the last inserted row.
    pub fn last_insert_id(&self) -> String {
        self.conn.last_insert_id()
    }

    /// Quote a string for safe use in a SQL statement.
    pub fn quote(&self, string: &str) -> String {
        self.conn.quote(string)
    }

    /// Begin a database transaction.
    pub fn begin_transaction(&mut self) -> Result<(), PdoError> {
        match self.conn.begin_transaction() {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Commit the current transaction.
    pub fn commit(&mut self) -> Result<(), PdoError> {
        match self.conn.commit() {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Roll back the current transaction.
    pub fn rollback(&mut self) -> Result<(), PdoError> {
        match self.conn.rollback() {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Whether a transaction is currently active.
    pub fn in_transaction(&self) -> bool {
        self.conn.in_transaction()
    }

    /// Return error information for the last operation.
    ///
    /// Returns `(sqlstate, driver_code, message)`.
    pub fn error_info(&self) -> (String, Option<String>, Option<String>) {
        match &self.last_error {
            Some(e) => (e.sqlstate.clone(), e.code.clone(), Some(e.message.clone())),
            None => ("00000".to_string(), None, None),
        }
    }
}

// ===========================================================================
// SQLite Driver
// ===========================================================================

use rusqlite::Connection as SqliteRawConnection;
use std::cell::RefCell;

/// The PDO SQLite driver.
pub struct SqliteDriver;

impl PdoDriver for SqliteDriver {
    fn connect(
        &self,
        dsn_params: &str,
        _username: Option<&str>,
        _password: Option<&str>,
    ) -> Result<Box<dyn PdoDriverConnection>, PdoError> {
        let conn = if dsn_params == ":memory:" || dsn_params.is_empty() {
            SqliteRawConnection::open_in_memory()
        } else {
            SqliteRawConnection::open(dsn_params)
        };

        match conn {
            Ok(c) => Ok(Box::new(SqliteConnection {
                conn: RefCell::new(c),
                in_transaction: RefCell::new(false),
            })),
            Err(e) => Err(PdoError::new(
                "HY000",
                None,
                &format!("SQLSTATE[HY000]: Unable to open database: {}", e),
            )),
        }
    }
}

struct SqliteConnection {
    conn: RefCell<SqliteRawConnection>,
    in_transaction: RefCell<bool>,
}

// SAFETY: rusqlite::Connection is Send (it uses SQLite in serialized threading
// mode by default), and we wrap access in RefCell for interior mutability
// within a single thread. The PdoDriverConnection trait requires Send because
// PDO connections may be held across await points in async server contexts,
// but actual access is always single-threaded per PHP request.
unsafe impl Send for SqliteConnection {}

impl PdoDriverConnection for SqliteConnection {
    fn prepare(&self, sql: &str) -> Result<Box<dyn PdoDriverStatement>, PdoError> {
        // We need to work around rusqlite's borrow semantics: the Statement
        // borrows the Connection. Instead, we store the SQL and parameters
        // and execute lazily.
        Ok(Box::new(SqliteStatement {
            sql: sql.to_string(),
            bound_params: HashMap::new(),
            // We clone a new connection handle internally since rusqlite
            // Statement borrows Connection and we cannot store both.
            // For an in-memory database this shares the same database via
            // the path-based open. For a real approach we would use a
            // connection pool or raw sqlite3 pointers. Here we take a
            // pragmatic approach: we prepare and execute in one step.
            conn_ptr: self as *const SqliteConnection,
            rows: Vec::new(),
            row_index: 0,
            affected_rows: 0,
            column_names: Vec::new(),
        }))
    }

    fn exec(&self, sql: &str) -> Result<u64, PdoError> {
        let conn = self.conn.borrow();
        conn.execute_batch(sql).map_err(|e| sqlite_error(&e))?;
        Ok(conn.changes())
    }

    fn quote(&self, string: &str) -> String {
        // SQLite quoting: wrap in single quotes, double any embedded single quotes.
        let escaped = string.replace('\'', "''");
        format!("'{}'", escaped)
    }

    fn last_insert_id(&self) -> String {
        let conn = self.conn.borrow();
        conn.last_insert_rowid().to_string()
    }

    fn begin_transaction(&self) -> Result<(), PdoError> {
        if *self.in_transaction.borrow() {
            return Err(PdoError::new(
                "HY000",
                None,
                "There is already an active transaction",
            ));
        }
        let conn = self.conn.borrow();
        conn.execute_batch("BEGIN").map_err(|e| sqlite_error(&e))?;
        *self.in_transaction.borrow_mut() = true;
        Ok(())
    }

    fn commit(&self) -> Result<(), PdoError> {
        if !*self.in_transaction.borrow() {
            return Err(PdoError::new(
                "HY000",
                None,
                "There is no active transaction",
            ));
        }
        let conn = self.conn.borrow();
        conn.execute_batch("COMMIT").map_err(|e| sqlite_error(&e))?;
        *self.in_transaction.borrow_mut() = false;
        Ok(())
    }

    fn rollback(&self) -> Result<(), PdoError> {
        if !*self.in_transaction.borrow() {
            return Err(PdoError::new(
                "HY000",
                None,
                "There is no active transaction",
            ));
        }
        let conn = self.conn.borrow();
        conn.execute_batch("ROLLBACK")
            .map_err(|e| sqlite_error(&e))?;
        *self.in_transaction.borrow_mut() = false;
        Ok(())
    }

    fn in_transaction(&self) -> bool {
        *self.in_transaction.borrow()
    }
}

/// Convert a rusqlite error to a PdoError.
fn sqlite_error(e: &rusqlite::Error) -> PdoError {
    PdoError::new("HY000", None, &e.to_string())
}

// ---------------------------------------------------------------------------
// SqliteStatement
// ---------------------------------------------------------------------------

struct SqliteStatement {
    sql: String,
    bound_params: HashMap<PdoParam, PdoValue>,
    conn_ptr: *const SqliteConnection,
    rows: Vec<PdoRow>,
    row_index: usize,
    affected_rows: u64,
    column_names: Vec<String>,
}

// SAFETY: SqliteStatement holds a raw pointer to SqliteConnection, which is
// pinned for the lifetime of the PdoConnection. The pointer is only
// dereferenced during execute(), which happens on the same thread that
// created the connection. Send is required by the trait bound.
unsafe impl Send for SqliteStatement {}

impl PdoDriverStatement for SqliteStatement {
    fn bind_value(&mut self, param: &PdoParam, value: &PdoValue) -> Result<(), PdoError> {
        self.bound_params.insert(param.clone(), value.clone());
        Ok(())
    }

    fn execute(&mut self, params: Option<&[PdoValue]>) -> Result<bool, PdoError> {
        self.rows.clear();
        self.row_index = 0;
        self.affected_rows = 0;
        self.column_names.clear();

        // SAFETY: The conn_ptr is valid for the lifetime of the PdoConnection
        // that created this statement. We copy the pointer to a local variable
        // to avoid borrowing `self` through get_conn(), which would conflict
        // with later mutable access to self.column_names, self.rows, etc.
        let sqlite_conn: &SqliteConnection = unsafe { &*self.conn_ptr };
        let conn = sqlite_conn.conn.borrow();

        let mut stmt = conn.prepare(&self.sql).map_err(|e| sqlite_error(&e))?;

        // Build parameter list: prefer explicit params arg, fall back to bound params.
        let effective_params: Vec<PdoValue> = if let Some(p) = params {
            p.to_vec()
        } else if !self.bound_params.is_empty() {
            // Collect positional parameters in order.
            let max_pos = self
                .bound_params
                .keys()
                .filter_map(|k| match k {
                    PdoParam::Positional(i) => Some(*i),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            let mut v = Vec::with_capacity(max_pos);
            for i in 1..=max_pos {
                v.push(
                    self.bound_params
                        .get(&PdoParam::Positional(i))
                        .cloned()
                        .unwrap_or(PdoValue::Null),
                );
            }
            // Handle named params: bind them directly via rusqlite named params.
            // For simplicity, we handle named params as a separate path.
            if self
                .bound_params
                .keys()
                .any(|k| matches!(k, PdoParam::Named(_)))
            {
                // Execute with named params.
                let named: Vec<(String, PdoValue)> = self
                    .bound_params
                    .iter()
                    .filter_map(|(k, v)| match k {
                        PdoParam::Named(name) => Some((name.clone(), v.clone())),
                        _ => None,
                    })
                    .collect();

                let col_count = stmt.column_count();
                self.column_names = (0..col_count)
                    .map(|i| stmt.column_name(i).unwrap_or("").to_string())
                    .collect();

                let named_refs: Vec<(&str, &dyn rusqlite::types::ToSql)> = named
                    .iter()
                    .map(|(name, val)| {
                        let sql_name: &str = name.as_str();
                        let sql_val: &dyn rusqlite::types::ToSql = match val {
                            PdoValue::Null => &rusqlite::types::Null,
                            PdoValue::Int(i) => i,
                            PdoValue::Float(f) => f,
                            PdoValue::Str(s) => s,
                            PdoValue::Bool(b) => b,
                            PdoValue::Blob(v) => v,
                        };
                        (sql_name, sql_val)
                    })
                    .collect();

                if col_count > 0 {
                    let mut query_rows = stmt
                        .query(named_refs.as_slice())
                        .map_err(|e| sqlite_error(&e))?;

                    while let Some(row) = query_rows.next().map_err(|e| sqlite_error(&e))? {
                        let mut values = Vec::with_capacity(col_count);
                        for i in 0..col_count {
                            values.push(sqlite_value_from_row(row, i));
                        }
                        self.rows.push(PdoRow {
                            columns: self.column_names.clone(),
                            values,
                        });
                    }
                } else {
                    stmt.execute(named_refs.as_slice())
                        .map_err(|e| sqlite_error(&e))?;
                }
                self.affected_rows = conn.changes();
                return Ok(true);
            }
            v
        } else {
            Vec::new()
        };

        // Convert PdoValue to rusqlite params.
        let sqlite_params: Vec<Box<dyn rusqlite::types::ToSql>> = effective_params
            .iter()
            .map(|v| pdo_value_to_sqlite(v))
            .collect();

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            sqlite_params.iter().map(|b| b.as_ref()).collect();

        let col_count = stmt.column_count();
        self.column_names = (0..col_count)
            .map(|i| stmt.column_name(i).unwrap_or("").to_string())
            .collect();

        if col_count > 0 {
            // This is a query that returns rows.
            let mut query_rows = stmt
                .query(param_refs.as_slice())
                .map_err(|e| sqlite_error(&e))?;

            while let Some(row) = query_rows.next().map_err(|e| sqlite_error(&e))? {
                let mut values = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    values.push(sqlite_value_from_row(row, i));
                }
                self.rows.push(PdoRow {
                    columns: self.column_names.clone(),
                    values,
                });
            }
        } else {
            // DML statement.
            stmt.execute(param_refs.as_slice())
                .map_err(|e| sqlite_error(&e))?;
        }

        self.affected_rows = conn.changes();
        Ok(true)
    }

    fn fetch(&mut self) -> Option<PdoRow> {
        if self.row_index < self.rows.len() {
            let row = self.rows[self.row_index].clone();
            self.row_index += 1;
            Some(row)
        } else {
            None
        }
    }

    fn row_count(&self) -> u64 {
        self.affected_rows
    }

    fn column_count(&self) -> usize {
        self.column_names.len()
    }
}

/// Convert a rusqlite row column to a PdoValue.
fn sqlite_value_from_row(row: &rusqlite::Row, index: usize) -> PdoValue {
    use rusqlite::types::ValueRef;
    match row.get_ref(index) {
        Ok(ValueRef::Null) => PdoValue::Null,
        Ok(ValueRef::Integer(i)) => PdoValue::Int(i),
        Ok(ValueRef::Real(f)) => PdoValue::Float(f),
        Ok(ValueRef::Text(t)) => PdoValue::Str(String::from_utf8_lossy(t).to_string()),
        Ok(ValueRef::Blob(b)) => PdoValue::Blob(b.to_vec()),
        Err(_) => PdoValue::Null,
    }
}

/// Convert a PdoValue to a boxed rusqlite ToSql.
fn pdo_value_to_sqlite(value: &PdoValue) -> Box<dyn rusqlite::types::ToSql> {
    match value {
        PdoValue::Null => Box::new(rusqlite::types::Null),
        PdoValue::Int(i) => Box::new(*i),
        PdoValue::Float(f) => Box::new(*f),
        PdoValue::Str(s) => Box::new(s.clone()),
        PdoValue::Bool(b) => Box::new(*b),
        PdoValue::Blob(v) => Box::new(v.clone()),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> PdoConnection {
        PdoConnection::new("sqlite::memory:", None, None).expect("Failed to open in-memory SQLite")
    }

    #[test]
    fn test_create_in_memory_database() {
        let db = memory_db();
        assert!(!db.in_transaction());
        let (state, code, msg) = db.error_info();
        assert_eq!(state, "00000");
        assert!(code.is_none());
        assert!(msg.is_none());
    }

    #[test]
    fn test_create_table_insert_query() {
        let mut db = memory_db();

        db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)")
            .expect("CREATE TABLE failed");

        db.exec("INSERT INTO users (name, age) VALUES ('Alice', 30)")
            .expect("INSERT failed");
        db.exec("INSERT INTO users (name, age) VALUES ('Bob', 25)")
            .expect("INSERT failed");

        let mut stmt = db
            .query("SELECT id, name, age FROM users ORDER BY id")
            .expect("SELECT failed");

        let rows = stmt.fetch_all(FetchMode::Assoc);
        assert_eq!(rows.len(), 2);

        assert_eq!(
            rows[0].get_by_name("name"),
            Some(&PdoValue::Str("Alice".to_string()))
        );
        assert_eq!(rows[0].get_by_name("age"), Some(&PdoValue::Int(30)));
        assert_eq!(
            rows[1].get_by_name("name"),
            Some(&PdoValue::Str("Bob".to_string()))
        );
        assert_eq!(rows[1].get_by_name("age"), Some(&PdoValue::Int(25)));
    }

    #[test]
    fn test_prepared_statement_positional_params() {
        let mut db = memory_db();

        db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
            .expect("CREATE TABLE failed");

        let mut stmt = db
            .prepare("INSERT INTO items (name, price) VALUES (?, ?)")
            .expect("prepare failed");

        stmt.execute(Some(&[
            PdoValue::Str("Widget".to_string()),
            PdoValue::Float(9.99),
        ]))
        .expect("execute failed");

        stmt.execute(Some(&[
            PdoValue::Str("Gadget".to_string()),
            PdoValue::Float(19.99),
        ]))
        .expect("execute failed");

        let mut query = db
            .query("SELECT name, price FROM items ORDER BY price")
            .expect("SELECT failed");

        let row = query.fetch(FetchMode::Num).expect("no row");
        assert_eq!(
            row.get_by_index(0),
            Some(&PdoValue::Str("Widget".to_string()))
        );
        assert_eq!(row.get_by_index(1), Some(&PdoValue::Float(9.99)));

        let row = query.fetch(FetchMode::Num).expect("no row");
        assert_eq!(
            row.get_by_index(0),
            Some(&PdoValue::Str("Gadget".to_string()))
        );
        assert_eq!(row.get_by_index(1), Some(&PdoValue::Float(19.99)));

        assert!(query.fetch(FetchMode::Num).is_none());
    }

    #[test]
    fn test_prepared_statement_bind_value() {
        let mut db = memory_db();

        db.exec("CREATE TABLE kv (key TEXT, value TEXT)")
            .expect("CREATE TABLE failed");

        let mut stmt = db
            .prepare("INSERT INTO kv (key, value) VALUES (?, ?)")
            .expect("prepare failed");
        stmt.bind_value(PdoParam::Positional(1), PdoValue::Str("color".to_string()))
            .expect("bind failed");
        stmt.bind_value(PdoParam::Positional(2), PdoValue::Str("blue".to_string()))
            .expect("bind failed");
        stmt.execute(None).expect("execute failed");

        let mut query = db
            .query("SELECT value FROM kv WHERE key = 'color'")
            .expect("query failed");
        let val = query.fetch_column(0).expect("no column");
        assert_eq!(val, PdoValue::Str("blue".to_string()));
    }

    #[test]
    fn test_transaction_commit() {
        let mut db = memory_db();

        db.exec("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO accounts (balance) VALUES (100)")
            .expect("INSERT failed");

        assert!(!db.in_transaction());
        db.begin_transaction().expect("begin failed");
        assert!(db.in_transaction());

        db.exec("UPDATE accounts SET balance = balance - 30 WHERE id = 1")
            .expect("UPDATE failed");

        db.commit().expect("commit failed");
        assert!(!db.in_transaction());

        let mut stmt = db
            .query("SELECT balance FROM accounts WHERE id = 1")
            .expect("SELECT failed");
        let val = stmt.fetch_column(0).expect("no value");
        assert_eq!(val, PdoValue::Int(70));
    }

    #[test]
    fn test_transaction_rollback() {
        let mut db = memory_db();

        db.exec("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO accounts (balance) VALUES (100)")
            .expect("INSERT failed");

        db.begin_transaction().expect("begin failed");
        db.exec("UPDATE accounts SET balance = 0 WHERE id = 1")
            .expect("UPDATE failed");

        // Rollback should undo the update.
        db.rollback().expect("rollback failed");
        assert!(!db.in_transaction());

        let mut stmt = db
            .query("SELECT balance FROM accounts WHERE id = 1")
            .expect("SELECT failed");
        let val = stmt.fetch_column(0).expect("no value");
        assert_eq!(val, PdoValue::Int(100));
    }

    #[test]
    fn test_fetch_modes_assoc_num_both() {
        let mut db = memory_db();

        db.exec("CREATE TABLE colors (id INTEGER PRIMARY KEY, name TEXT)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO colors (name) VALUES ('red')")
            .expect("INSERT failed");

        // Assoc
        let mut stmt = db
            .query("SELECT id, name FROM colors")
            .expect("query failed");
        let row = stmt.fetch(FetchMode::Assoc).expect("no row");
        assert_eq!(
            row.get_by_name("name"),
            Some(&PdoValue::Str("red".to_string()))
        );
        assert_eq!(row.get_by_name("id"), Some(&PdoValue::Int(1)));

        // Num
        let mut stmt = db
            .query("SELECT id, name FROM colors")
            .expect("query failed");
        let row = stmt.fetch(FetchMode::Num).expect("no row");
        assert_eq!(row.get_by_index(0), Some(&PdoValue::Int(1)));
        assert_eq!(row.get_by_index(1), Some(&PdoValue::Str("red".to_string())));

        // Both
        let mut stmt = db
            .query("SELECT id, name FROM colors")
            .expect("query failed");
        let row = stmt.fetch(FetchMode::Both).expect("no row");
        assert_eq!(row.get_by_name("id"), Some(&PdoValue::Int(1)));
        assert_eq!(row.get_by_index(1), Some(&PdoValue::Str("red".to_string())));
    }

    #[test]
    fn test_last_insert_id() {
        let mut db = memory_db();

        db.exec("CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, val TEXT)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO seq (val) VALUES ('first')")
            .expect("INSERT failed");

        let id = db.last_insert_id();
        assert_eq!(id, "1");

        db.exec("INSERT INTO seq (val) VALUES ('second')")
            .expect("INSERT failed");
        let id = db.last_insert_id();
        assert_eq!(id, "2");
    }

    #[test]
    fn test_quote() {
        let db = memory_db();

        assert_eq!(db.quote("hello"), "'hello'");
        assert_eq!(db.quote("it's"), "'it''s'");
        assert_eq!(db.quote(""), "''");
        assert_eq!(db.quote("O'Brien's"), "'O''Brien''s'");
    }

    #[test]
    fn test_error_info_after_error() {
        let mut db = memory_db();

        let result = db.exec("SELECT * FROM nonexistent_table");
        assert!(result.is_err());

        let (state, _code, msg) = db.error_info();
        assert_eq!(state, "HY000");
        assert!(msg.is_some());
        let msg_str = msg.unwrap();
        assert!(msg_str.contains("nonexistent_table") || msg_str.contains("no such table"));
    }

    #[test]
    fn test_null_values() {
        let mut db = memory_db();

        db.exec("CREATE TABLE nullable (id INTEGER PRIMARY KEY, val TEXT)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO nullable (val) VALUES (NULL)")
            .expect("INSERT failed");

        let mut stmt = db.query("SELECT val FROM nullable").expect("query failed");
        let val = stmt.fetch_column(0).expect("no value");
        assert_eq!(val, PdoValue::Null);
    }

    #[test]
    fn test_blob_values() {
        let mut db = memory_db();

        db.exec("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
            .expect("CREATE TABLE failed");

        let mut stmt = db
            .prepare("INSERT INTO blobs (data) VALUES (?)")
            .expect("prepare failed");
        stmt.execute(Some(&[PdoValue::Blob(vec![0x00, 0xFF, 0x42])]))
            .expect("execute failed");

        let mut query = db.query("SELECT data FROM blobs").expect("query failed");
        let val = query.fetch_column(0).expect("no value");
        assert_eq!(val, PdoValue::Blob(vec![0x00, 0xFF, 0x42]));
    }

    #[test]
    fn test_row_count() {
        let mut db = memory_db();

        db.exec("CREATE TABLE things (id INTEGER PRIMARY KEY, name TEXT)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO things (name) VALUES ('a')")
            .expect("INSERT failed");
        db.exec("INSERT INTO things (name) VALUES ('b')")
            .expect("INSERT failed");
        db.exec("INSERT INTO things (name) VALUES ('c')")
            .expect("INSERT failed");

        let mut stmt = db
            .prepare("DELETE FROM things WHERE name IN ('a', 'b')")
            .expect("prepare failed");
        stmt.execute(None).expect("execute failed");
        assert_eq!(stmt.row_count(), 2);
    }

    #[test]
    fn test_column_count() {
        let mut db = memory_db();

        db.exec("CREATE TABLE multi (a INT, b TEXT, c REAL)")
            .expect("CREATE TABLE failed");
        db.exec("INSERT INTO multi VALUES (1, 'x', 1.5)")
            .expect("INSERT failed");

        let mut stmt = db.query("SELECT a, b, c FROM multi").expect("query failed");
        assert_eq!(stmt.column_count(), 3);

        let _row = stmt.fetch(FetchMode::Num);
    }

    #[test]
    fn test_invalid_dsn() {
        let result = PdoConnection::new("invalid", None, None);
        assert!(result.is_err());
        match result {
            Err(err) => {
                assert!(
                    err.message.contains("Invalid DSN") || err.message.contains("missing driver")
                );
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_unknown_driver() {
        let result = PdoConnection::new("mysql:host=localhost", None, None);
        assert!(result.is_err());
        match result {
            Err(err) => {
                assert!(err.message.contains("could not find driver"));
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_double_begin_transaction_error() {
        let mut db = memory_db();
        db.begin_transaction().expect("first begin should succeed");
        let result = db.begin_transaction();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("already an active transaction"));
        // Clean up
        db.rollback().expect("rollback should succeed");
    }

    #[test]
    fn test_commit_without_transaction_error() {
        let mut db = memory_db();
        let result = db.commit();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("no active transaction"));
    }

    #[test]
    fn test_rollback_without_transaction_error() {
        let mut db = memory_db();
        let result = db.rollback();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("no active transaction"));
    }
}
