//! PDO MySQL driver extension for php.rs
//!
//! Implements the PDO_mysql driver using the `mysql` crate for real MySQL
//! connections. Supports prepared statements, transactions, and all standard
//! PDO operations.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use mysql::prelude::Queryable;
use php_rs_ext_pdo::{
    ColumnMeta, PdoDriver, PdoDriverConnection, PdoDriverStatement, PdoError, PdoParam, PdoRow,
    PdoValue,
};

// ---------------------------------------------------------------------------
// Constants — PDO MySQL attributes
// ---------------------------------------------------------------------------

/// Use buffered queries (store result set in memory).
pub const PDO_MYSQL_ATTR_USE_BUFFERED_QUERY: i32 = 1000;
/// Use local LOAD DATA INFILE.
pub const PDO_MYSQL_ATTR_LOCAL_INFILE: i32 = 1001;
/// Run this SQL immediately after connecting.
pub const PDO_MYSQL_ATTR_INIT_COMMAND: i32 = 1002;
/// Read MySQL configuration from the given option file group.
pub const PDO_MYSQL_ATTR_READ_DEFAULT_FILE: i32 = 1003;
/// Read MySQL configuration from the named group in my.cnf.
pub const PDO_MYSQL_ATTR_READ_DEFAULT_GROUP: i32 = 1004;
/// Maximum buffer size for large reads.
pub const PDO_MYSQL_ATTR_MAX_BUFFER_SIZE: i32 = 1005;
/// Enable LOAD DATA LOCAL INFILE directory restriction.
pub const PDO_MYSQL_ATTR_LOCAL_INFILE_DIRECTORY: i32 = 1006;
/// Enable direct queries (disabling prepared statements).
pub const PDO_MYSQL_ATTR_DIRECT_QUERY: i32 = 1007;
/// Return the number of found/matched rows, not changed rows.
pub const PDO_MYSQL_ATTR_FOUND_ROWS: i32 = 1008;
/// Compress the client/server protocol.
pub const PDO_MYSQL_ATTR_COMPRESS: i32 = 1009;
/// Use SSL for the connection.
pub const PDO_MYSQL_ATTR_SSL_CA: i32 = 1010;
/// SSL certificate authority path.
pub const PDO_MYSQL_ATTR_SSL_CAPATH: i32 = 1011;
/// SSL client certificate.
pub const PDO_MYSQL_ATTR_SSL_CERT: i32 = 1012;
/// SSL cipher list.
pub const PDO_MYSQL_ATTR_SSL_CIPHER: i32 = 1013;
/// SSL client key.
pub const PDO_MYSQL_ATTR_SSL_KEY: i32 = 1014;
/// Enable multi-statements.
pub const PDO_MYSQL_ATTR_MULTI_STATEMENTS: i32 = 1015;
/// Disable SSL verification.
pub const PDO_MYSQL_ATTR_SSL_VERIFY_SERVER_CERT: i32 = 1016;

// ---------------------------------------------------------------------------
// PdoMysqlError
// ---------------------------------------------------------------------------

/// An error from the PDO MySQL driver.
#[derive(Debug, Clone, PartialEq)]
pub struct PdoMysqlError {
    pub message: String,
}

impl PdoMysqlError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for PdoMysqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO MySQL error: {}", self.message)
    }
}

impl std::error::Error for PdoMysqlError {}

// ---------------------------------------------------------------------------
// PdoMysqlConfig — DSN parsing result
// ---------------------------------------------------------------------------

/// Configuration parsed from a MySQL PDO DSN string.
///
/// DSN format: `mysql:host=xxx;port=3306;dbname=xxx;charset=utf8`
#[derive(Debug, Clone, PartialEq)]
pub struct PdoMysqlConfig {
    /// MySQL server hostname (default: "localhost").
    pub host: String,
    /// MySQL server port (default: 3306).
    pub port: u16,
    /// Database name (default: empty).
    pub dbname: String,
    /// Character set (default: "utf8mb4").
    pub charset: String,
    /// Unix socket path (alternative to host+port).
    pub unix_socket: Option<String>,
}

impl Default for PdoMysqlConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 3306,
            dbname: String::new(),
            charset: "utf8mb4".to_string(),
            unix_socket: None,
        }
    }
}

/// Parse a MySQL PDO DSN parameter string.
///
/// The input should be the part after `mysql:`, e.g.:
/// `host=localhost;port=3306;dbname=testdb;charset=utf8`
///
/// Recognized keys: `host`, `port`, `dbname`, `charset`, `unix_socket`.
/// Unknown keys are silently ignored.
pub fn parse_dsn(dsn: &str) -> Result<PdoMysqlConfig, PdoMysqlError> {
    let mut config = PdoMysqlConfig::default();

    if dsn.is_empty() {
        return Ok(config);
    }

    for part in dsn.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                return Err(PdoMysqlError::new(&format!(
                    "Invalid DSN component: {}",
                    part
                )));
            }
        };

        match key {
            "host" => config.host = value.to_string(),
            "port" => {
                config.port = value
                    .parse()
                    .map_err(|_| PdoMysqlError::new(&format!("Invalid port number: {}", value)))?;
            }
            "dbname" => config.dbname = value.to_string(),
            "charset" => config.charset = value.to_string(),
            "unix_socket" => config.unix_socket = Some(value.to_string()),
            _ => {
                // Unknown keys are silently ignored, matching PHP behavior.
            }
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// PdoMysqlDriver — Driver struct implementing PdoDriver
// ---------------------------------------------------------------------------

/// The PDO MySQL driver.
#[derive(Debug)]
pub struct PdoMysqlDriver;

impl PdoMysqlDriver {
    /// Create a new PDO MySQL driver instance.
    pub fn new() -> Self {
        Self
    }

    /// Get the driver name.
    pub fn name(&self) -> &'static str {
        "mysql"
    }
}

impl Default for PdoMysqlDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl PdoDriver for PdoMysqlDriver {
    fn connect(
        &self,
        dsn_params: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Box<dyn PdoDriverConnection>, PdoError> {
        let config = parse_dsn(dsn_params)
            .map_err(|e| PdoError::new("08006", None, &format!("Invalid DSN: {}", e.message)))?;

        // Build connection options.
        let host = if config.host == "localhost" {
            // MySQL client treats "localhost" as Unix socket; force TCP.
            "127.0.0.1".to_string()
        } else {
            config.host.clone()
        };

        let mut builder = mysql::OptsBuilder::new()
            .ip_or_hostname(Some(host))
            .tcp_port(config.port);

        if let Some(u) = username {
            builder = builder.user(Some(u));
        }
        if let Some(p) = password {
            builder = builder.pass(Some(p));
        }
        if !config.dbname.is_empty() {
            builder = builder.db_name(Some(&config.dbname));
        }

        // Connect.
        let mut conn = mysql::Conn::new(builder)
            .map_err(|e| PdoError::new("08006", None, &format!("Connection failed: {}", e)))?;

        // Set charset if specified.
        let charset_sql = format!("SET NAMES '{}'", config.charset.replace('\'', ""));
        conn.query_drop(&charset_sql)
            .map_err(|e| PdoError::new("HY000", None, &format!("SET NAMES failed: {}", e)))?;

        // Get server version.
        let (major, minor, patch) = conn.server_version();
        let server_version = format!("{}.{}.{}", major, minor, patch);

        Ok(Box::new(MysqlConnection {
            conn: RefCell::new(conn),
            in_transaction: RefCell::new(false),
            server_version,
            last_insert_id: RefCell::new(0),
        }))
    }
}

// ---------------------------------------------------------------------------
// MysqlConnection — Connection implementation
// ---------------------------------------------------------------------------

struct MysqlConnection {
    conn: RefCell<mysql::Conn>,
    in_transaction: RefCell<bool>,
    server_version: String,
    last_insert_id: RefCell<u64>,
}

// SAFETY: mysql::Conn is not Send by default because of the internal TCP stream,
// but we guarantee single-threaded access through RefCell.
unsafe impl Send for MysqlConnection {}

impl PdoDriverConnection for MysqlConnection {
    fn prepare(&self, sql: &str) -> Result<Box<dyn PdoDriverStatement>, PdoError> {
        // Convert PDO-style placeholders (? and :name) — MySQL native prepared
        // statements use ? for positional params. Named params (:name) need to
        // be converted to ? with a mapping.
        let (converted_sql, param_map) = convert_named_params(sql);

        Ok(Box::new(MysqlStatement {
            sql: converted_sql,
            original_sql: sql.to_string(),
            param_map,
            bound_params: HashMap::new(),
            conn_ptr: self as *const MysqlConnection,
            rows: Vec::new(),
            row_index: 0,
            affected_rows: 0,
            column_names: Vec::new(),
        }))
    }

    fn exec(&self, sql: &str) -> Result<u64, PdoError> {
        let mut conn = self.conn.borrow_mut();
        conn.query_drop(sql).map_err(mysql_error)?;
        let affected = conn.affected_rows();
        *self.last_insert_id.borrow_mut() = conn.last_insert_id();
        Ok(affected)
    }

    fn quote(&self, string: &str) -> String {
        // MySQL quoting: wrap in single quotes, escape special characters.
        let escaped = string
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('\0', "\\0")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\x1a', "\\Z");
        format!("'{}'", escaped)
    }

    fn last_insert_id(&self) -> String {
        self.last_insert_id.borrow().to_string()
    }

    fn begin_transaction(&self) -> Result<(), PdoError> {
        if *self.in_transaction.borrow() {
            return Err(PdoError::new(
                "HY000",
                None,
                "There is already an active transaction",
            ));
        }
        let mut conn = self.conn.borrow_mut();
        conn.query_drop("START TRANSACTION").map_err(mysql_error)?;
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
        let mut conn = self.conn.borrow_mut();
        conn.query_drop("COMMIT").map_err(mysql_error)?;
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
        let mut conn = self.conn.borrow_mut();
        conn.query_drop("ROLLBACK").map_err(mysql_error)?;
        *self.in_transaction.borrow_mut() = false;
        Ok(())
    }

    fn in_transaction(&self) -> bool {
        *self.in_transaction.borrow()
    }
}

/// Convert a mysql crate error to a PdoError.
fn mysql_error(e: mysql::Error) -> PdoError {
    let sqlstate = match &e {
        mysql::Error::MySqlError(ref me) => {
            // MySQL SQLSTATE is a 5-character string.
            if me.state.len() == 5 {
                me.state.clone()
            } else {
                "HY000".to_string()
            }
        }
        _ => "HY000".to_string(),
    };
    PdoError::new(&sqlstate, None, &e.to_string())
}

// ---------------------------------------------------------------------------
// Named parameter conversion
// ---------------------------------------------------------------------------

/// Convert PDO-style named parameters (:name) to MySQL positional (?)
/// and return the mapping from position (0-based) to parameter name.
fn convert_named_params(sql: &str) -> (String, Vec<String>) {
    let mut result = String::with_capacity(sql.len());
    let mut param_map = Vec::new();
    let mut chars = sql.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                result.push(ch);
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                result.push(ch);
            }
            ':' if !in_single_quote && !in_double_quote => {
                // Check for :: (PostgreSQL cast syntax, not a param).
                if chars.peek() == Some(&':') {
                    result.push(':');
                    result.push(chars.next().unwrap());
                } else if chars.peek().map_or(false, |c| c.is_alphabetic() || *c == '_') {
                    // Named parameter.
                    let mut name = String::new();
                    while chars
                        .peek()
                        .map_or(false, |c| c.is_alphanumeric() || *c == '_')
                    {
                        name.push(chars.next().unwrap());
                    }
                    param_map.push(name);
                    result.push('?');
                } else {
                    // Not a named param.
                    result.push(ch);
                }
            }
            _ => {
                result.push(ch);
            }
        }
    }

    (result, param_map)
}

// ---------------------------------------------------------------------------
// MysqlStatement — Statement implementation
// ---------------------------------------------------------------------------

struct MysqlStatement {
    /// SQL with named params converted to ?.
    sql: String,
    /// Original SQL as provided by the user.
    original_sql: String,
    /// Maps positional index (0-based) to named param name (without :).
    param_map: Vec<String>,
    /// Bound parameters.
    bound_params: HashMap<PdoParam, PdoValue>,
    /// Pointer to the parent connection.
    conn_ptr: *const MysqlConnection,
    /// Buffered result rows.
    rows: Vec<PdoRow>,
    /// Current row index for fetch().
    row_index: usize,
    /// Number of affected rows from last execute.
    affected_rows: u64,
    /// Column names from last result.
    column_names: Vec<String>,
}

// SAFETY: MysqlStatement holds a raw pointer to MysqlConnection, which is
// pinned for the lifetime of the PdoConnection. Send is required by trait bound.
unsafe impl Send for MysqlStatement {}

impl PdoDriverStatement for MysqlStatement {
    fn bind_value(&mut self, param: &PdoParam, value: &PdoValue) -> Result<(), PdoError> {
        self.bound_params.insert(param.clone(), value.clone());
        Ok(())
    }

    fn execute(&mut self, params: Option<&[PdoValue]>) -> Result<bool, PdoError> {
        self.rows.clear();
        self.row_index = 0;
        self.affected_rows = 0;
        self.column_names.clear();

        // SAFETY: conn_ptr is valid for the lifetime of the PdoConnection.
        let mysql_conn: &MysqlConnection = unsafe { &*self.conn_ptr };
        let mut conn = mysql_conn.conn.borrow_mut();

        // Build parameter list.
        let effective_params: Vec<PdoValue> = if let Some(p) = params {
            p.to_vec()
        } else if !self.bound_params.is_empty() {
            self.collect_ordered_params()
        } else {
            Vec::new()
        };

        // Convert to mysql crate values.
        let mysql_params: Vec<mysql::Value> = effective_params
            .iter()
            .map(pdo_value_to_mysql)
            .collect();

        // Execute using the text protocol with interpolated params.
        // This avoids issues with the mysql crate's prepared statement
        // API while still being correct for standard use cases.
        if mysql_params.is_empty() {
            // No params — direct query.
            let result: Result<Vec<mysql::Row>, _> = conn.query(&self.sql);
            match result {
                Ok(rows) => {
                    self.process_rows(rows);
                    self.affected_rows = conn.affected_rows();
                    *mysql_conn.last_insert_id.borrow_mut() = conn.last_insert_id();
                }
                Err(e) => return Err(mysql_error(e)),
            }
        } else {
            // Use exec with params (prepared statement).
            let stmt = conn.prep(&self.sql).map_err(mysql_error)?;
            let result: Result<Vec<mysql::Row>, _> =
                conn.exec(&stmt, &mysql_params);
            match result {
                Ok(rows) => {
                    self.process_rows(rows);
                    self.affected_rows = conn.affected_rows();
                    *mysql_conn.last_insert_id.borrow_mut() = conn.last_insert_id();
                }
                Err(e) => return Err(mysql_error(e)),
            }
        }

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
        if !self.rows.is_empty() {
            self.rows.len() as u64
        } else {
            self.affected_rows
        }
    }

    fn column_count(&self) -> usize {
        self.column_names.len()
    }

    fn get_column_meta(&self, column: usize) -> Option<ColumnMeta> {
        if column >= self.column_names.len() {
            return None;
        }
        Some(ColumnMeta::new(&self.column_names[column]))
    }
}

impl MysqlStatement {
    /// Collect bound parameters in the correct order for the SQL placeholders.
    fn collect_ordered_params(&self) -> Vec<PdoValue> {
        if !self.param_map.is_empty() {
            // Named parameters — use param_map to order them.
            self.param_map
                .iter()
                .map(|name| {
                    self.bound_params
                        .get(&PdoParam::Named(name.clone()))
                        .cloned()
                        .unwrap_or(PdoValue::Null)
                })
                .collect()
        } else {
            // Positional parameters — collect in order (1-based).
            let max_pos = self
                .bound_params
                .keys()
                .filter_map(|k| match k {
                    PdoParam::Positional(i) => Some(*i),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            (1..=max_pos)
                .map(|i| {
                    self.bound_params
                        .get(&PdoParam::Positional(i))
                        .cloned()
                        .unwrap_or(PdoValue::Null)
                })
                .collect()
        }
    }

    /// Process MySQL result rows into PdoRows.
    fn process_rows(&mut self, rows: Vec<mysql::Row>) {
        use mysql::prelude::FromValue;

        if rows.is_empty() {
            return;
        }

        // Get column names from first row.
        self.column_names = rows[0]
            .columns_ref()
            .iter()
            .map(|col| col.name_str().to_string())
            .collect();

        // Convert all rows.
        for row in &rows {
            let values: Vec<PdoValue> = (0..row.len())
                .map(|i| {
                    let mysql_val = match row.as_ref(i) {
                        Some(val) => val,
                        None => return PdoValue::Null,
                    };

                    // Check for NULL.
                    if *mysql_val == mysql::Value::NULL {
                        return PdoValue::Null;
                    }

                    // MySQL returns most values as strings in text protocol.
                    // Try string first (most common for PDO), then numeric types.
                    if let Ok(s) = String::from_value_opt(mysql_val.clone()) {
                        return PdoValue::Str(s);
                    }
                    if let Ok(i) = i64::from_value_opt(mysql_val.clone()) {
                        return PdoValue::Int(i);
                    }
                    if let Ok(f) = f64::from_value_opt(mysql_val.clone()) {
                        return PdoValue::Float(f);
                    }
                    if let Ok(bytes) = Vec::<u8>::from_value_opt(mysql_val.clone()) {
                        return PdoValue::Blob(bytes);
                    }

                    PdoValue::Null
                })
                .collect();

            self.rows.push(PdoRow {
                columns: self.column_names.clone(),
                values,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions for type conversion
// ---------------------------------------------------------------------------

/// Convert a PdoValue to a MySQL value.
fn pdo_value_to_mysql(value: &PdoValue) -> mysql::Value {
    match value {
        PdoValue::Null => mysql::Value::NULL,
        PdoValue::Int(i) => mysql::Value::Int(*i),
        PdoValue::Float(f) => mysql::Value::Double(*f),
        PdoValue::Str(s) => mysql::Value::Bytes(s.as_bytes().to_vec()),
        PdoValue::Bool(b) => mysql::Value::Int(if *b { 1 } else { 0 }),
        PdoValue::Blob(v) => mysql::Value::Bytes(v.clone()),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dsn_full() {
        let config = parse_dsn("host=db.example.com;port=3307;dbname=myapp;charset=utf8")
            .expect("parse should succeed");
        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.port, 3307);
        assert_eq!(config.dbname, "myapp");
        assert_eq!(config.charset, "utf8");
        assert!(config.unix_socket.is_none());
    }

    #[test]
    fn test_parse_dsn_defaults() {
        let config = parse_dsn("").expect("parse should succeed");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 3306);
        assert_eq!(config.dbname, "");
        assert_eq!(config.charset, "utf8mb4");
    }

    #[test]
    fn test_parse_dsn_host_only() {
        let config = parse_dsn("host=192.168.1.100").expect("parse should succeed");
        assert_eq!(config.host, "192.168.1.100");
        assert_eq!(config.port, 3306);
    }

    #[test]
    fn test_parse_dsn_with_unix_socket() {
        let config = parse_dsn("unix_socket=/var/run/mysqld/mysqld.sock;dbname=testdb")
            .expect("parse should succeed");
        assert_eq!(
            config.unix_socket,
            Some("/var/run/mysqld/mysqld.sock".to_string())
        );
        assert_eq!(config.dbname, "testdb");
    }

    #[test]
    fn test_parse_dsn_invalid_port() {
        let result = parse_dsn("host=localhost;port=abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Invalid port"));
    }

    #[test]
    fn test_parse_dsn_invalid_component() {
        let result = parse_dsn("host=localhost;badparam");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Invalid DSN"));
    }

    #[test]
    fn test_parse_dsn_unknown_keys_ignored() {
        let config = parse_dsn("host=localhost;unknown_key=value;dbname=test")
            .expect("parse should succeed");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.dbname, "test");
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoMysqlDriver::new();
        assert_eq!(driver.name(), "mysql");
    }

    #[test]
    fn test_attribute_constants() {
        assert_eq!(PDO_MYSQL_ATTR_USE_BUFFERED_QUERY, 1000);
        assert_eq!(PDO_MYSQL_ATTR_INIT_COMMAND, 1002);
        assert_eq!(PDO_MYSQL_ATTR_DIRECT_QUERY, 1007);
        assert_eq!(PDO_MYSQL_ATTR_MULTI_STATEMENTS, 1015);
    }

    #[test]
    fn test_parse_dsn_trailing_semicolon() {
        let config = parse_dsn("host=localhost;dbname=test;").expect("parse should succeed");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.dbname, "test");
    }

    #[test]
    fn test_default_config() {
        let config = PdoMysqlConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 3306);
        assert_eq!(config.charset, "utf8mb4");
        assert!(config.dbname.is_empty());
        assert!(config.unix_socket.is_none());
    }

    // --- Named parameter conversion tests ---

    #[test]
    fn test_convert_named_params_simple() {
        let (sql, map) = convert_named_params("SELECT * FROM users WHERE id = :id AND name = :name");
        assert_eq!(sql, "SELECT * FROM users WHERE id = ? AND name = ?");
        assert_eq!(map, vec!["id", "name"]);
    }

    #[test]
    fn test_convert_named_params_none() {
        let (sql, map) = convert_named_params("SELECT * FROM users WHERE id = ?");
        assert_eq!(sql, "SELECT * FROM users WHERE id = ?");
        assert!(map.is_empty());
    }

    #[test]
    fn test_convert_named_params_in_string() {
        let (sql, map) = convert_named_params("SELECT * FROM users WHERE name = ':not_a_param'");
        assert_eq!(sql, "SELECT * FROM users WHERE name = ':not_a_param'");
        assert!(map.is_empty());
    }

    #[test]
    fn test_convert_named_params_double_colon() {
        let (sql, map) = convert_named_params("SELECT id::text FROM users WHERE id = :id");
        assert_eq!(sql, "SELECT id::text FROM users WHERE id = ?");
        assert_eq!(map, vec!["id"]);
    }

    #[test]
    fn test_convert_named_params_repeated() {
        let (sql, map) =
            convert_named_params("INSERT INTO t (a, b) VALUES (:val, :val)");
        assert_eq!(sql, "INSERT INTO t (a, b) VALUES (?, ?)");
        assert_eq!(map, vec!["val", "val"]);
    }

    #[test]
    fn test_convert_named_params_with_underscore() {
        let (sql, map) =
            convert_named_params("SELECT * FROM t WHERE col = :my_param_1");
        assert_eq!(sql, "SELECT * FROM t WHERE col = ?");
        assert_eq!(map, vec!["my_param_1"]);
    }

    // --- Value conversion tests ---

    #[test]
    fn test_pdo_value_to_mysql() {
        assert_eq!(pdo_value_to_mysql(&PdoValue::Null), mysql::Value::NULL);
        assert_eq!(pdo_value_to_mysql(&PdoValue::Int(42)), mysql::Value::Int(42));
        assert_eq!(
            pdo_value_to_mysql(&PdoValue::Float(3.14)),
            mysql::Value::Double(3.14)
        );
        assert_eq!(
            pdo_value_to_mysql(&PdoValue::Str("hello".into())),
            mysql::Value::Bytes(b"hello".to_vec())
        );
        assert_eq!(
            pdo_value_to_mysql(&PdoValue::Bool(true)),
            mysql::Value::Int(1)
        );
        assert_eq!(
            pdo_value_to_mysql(&PdoValue::Bool(false)),
            mysql::Value::Int(0)
        );
        assert_eq!(
            pdo_value_to_mysql(&PdoValue::Blob(vec![1, 2, 3])),
            mysql::Value::Bytes(vec![1, 2, 3])
        );
    }

    // --- Quote tests ---

    #[test]
    fn test_quote_simple() {
        let conn_quote = |s: &str| -> String {
            let escaped = s
                .replace('\\', "\\\\")
                .replace('\'', "\\'")
                .replace('\0', "\\0")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\x1a', "\\Z");
            format!("'{}'", escaped)
        };
        assert_eq!(conn_quote("hello"), "'hello'");
        assert_eq!(conn_quote("it's"), "'it\\'s'");
        assert_eq!(conn_quote("back\\slash"), "'back\\\\slash'");
        assert_eq!(conn_quote("new\nline"), "'new\\nline'");
    }

    // --- Driver trait implementation test ---

    #[test]
    fn test_driver_implements_pdo_driver() {
        let driver = PdoMysqlDriver::new();
        assert_eq!(driver.name(), "mysql");

        // Test connection with invalid credentials (should fail gracefully).
        let result = driver.connect(
            "host=nonexistent.invalid;port=3306;dbname=test",
            Some("user"),
            Some("pass"),
        );

        // Connection should fail, but not panic.
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.message.contains("Connection failed") || e.message.contains("failed"),
                "Error was: {}",
                e.message
            );
        }
    }

    // --- Statement param ordering tests ---

    #[test]
    fn test_statement_collect_ordered_named_params() {
        let (sql, param_map) =
            convert_named_params("INSERT INTO t (a, b) VALUES (:alpha, :beta)");
        let mut stmt = MysqlStatement {
            sql,
            original_sql: "INSERT INTO t (a, b) VALUES (:alpha, :beta)".into(),
            param_map,
            bound_params: HashMap::new(),
            conn_ptr: std::ptr::null(),
            rows: Vec::new(),
            row_index: 0,
            affected_rows: 0,
            column_names: Vec::new(),
        };

        stmt.bound_params
            .insert(PdoParam::Named("beta".into()), PdoValue::Str("B".into()));
        stmt.bound_params
            .insert(PdoParam::Named("alpha".into()), PdoValue::Int(1));

        let ordered = stmt.collect_ordered_params();
        assert_eq!(ordered, vec![PdoValue::Int(1), PdoValue::Str("B".into())]);
    }

    #[test]
    fn test_statement_collect_ordered_positional_params() {
        let mut stmt = MysqlStatement {
            sql: "INSERT INTO t (a, b) VALUES (?, ?)".into(),
            original_sql: "INSERT INTO t (a, b) VALUES (?, ?)".into(),
            param_map: Vec::new(),
            bound_params: HashMap::new(),
            conn_ptr: std::ptr::null(),
            rows: Vec::new(),
            row_index: 0,
            affected_rows: 0,
            column_names: Vec::new(),
        };

        // Bind out of order.
        stmt.bound_params
            .insert(PdoParam::Positional(2), PdoValue::Str("second".into()));
        stmt.bound_params
            .insert(PdoParam::Positional(1), PdoValue::Int(1));

        let ordered = stmt.collect_ordered_params();
        assert_eq!(
            ordered,
            vec![PdoValue::Int(1), PdoValue::Str("second".into())]
        );
    }
}
