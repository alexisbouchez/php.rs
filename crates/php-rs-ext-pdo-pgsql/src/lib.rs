//! PDO PostgreSQL driver extension for php.rs
//!
//! Implements the PDO_pgsql driver, which provides PostgreSQL-specific DSN
//! parsing, attributes, and connection configuration.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use php_rs_ext_pdo::{
    PdoDriver, PdoDriverConnection, PdoDriverStatement,
    PdoError, PdoValue, PdoRow, PdoParam,
};
use postgres::{Client, NoTls, Row};

// ---------------------------------------------------------------------------
// Constants — PDO PostgreSQL attributes
// ---------------------------------------------------------------------------

/// Disable server-side prepared statements.
pub const PDO_PGSQL_ATTR_DISABLE_PREPARES: i32 = 1000;
/// Disable native type casting (return all values as strings).
pub const PDO_PGSQL_ATTR_RESULT_MEMORY_SIZE: i32 = 1001;

// ---------------------------------------------------------------------------
// PdoPgsqlError
// ---------------------------------------------------------------------------

/// An error from the PDO PostgreSQL driver.
#[derive(Debug, Clone, PartialEq)]
pub struct PdoPgsqlError {
    pub message: String,
}

impl PdoPgsqlError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for PdoPgsqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO pgsql error: {}", self.message)
    }
}

impl std::error::Error for PdoPgsqlError {}

// ---------------------------------------------------------------------------
// PdoPgsqlConfig — DSN parsing result
// ---------------------------------------------------------------------------

/// Configuration parsed from a PostgreSQL PDO DSN string.
///
/// DSN format: `pgsql:host=xxx;port=5432;dbname=xxx`
#[derive(Debug, Clone, PartialEq)]
pub struct PdoPgsqlConfig {
    /// PostgreSQL server hostname (default: "localhost").
    pub host: String,
    /// PostgreSQL server port (default: 5432).
    pub port: u16,
    /// Database name (default: empty).
    pub dbname: String,
    /// Username for authentication (can also be passed via PDO constructor).
    pub user: Option<String>,
    /// Password for authentication (can also be passed via PDO constructor).
    pub password: Option<String>,
    /// SSL mode: disable, allow, prefer, require, verify-ca, verify-full.
    pub sslmode: Option<String>,
}

impl Default for PdoPgsqlConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            dbname: String::new(),
            user: None,
            password: None,
            sslmode: None,
        }
    }
}

/// Parse a PostgreSQL PDO DSN parameter string.
///
/// The input should be the part after `pgsql:`, e.g.:
/// `host=localhost;port=5432;dbname=testdb`
///
/// Recognized keys: `host`, `port`, `dbname`, `user`, `password`, `sslmode`.
/// Unknown keys are silently ignored.
pub fn parse_dsn(dsn: &str) -> Result<PdoPgsqlConfig, PdoPgsqlError> {
    let mut config = PdoPgsqlConfig::default();

    if dsn.is_empty() {
        return Ok(config);
    }

    // PostgreSQL DSN can use either semicolons or spaces as separators.
    // We support both formats.
    let separator = if dsn.contains(';') { ';' } else { ' ' };

    for part in dsn.split(separator) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                return Err(PdoPgsqlError::new(&format!(
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
                    .map_err(|_| PdoPgsqlError::new(&format!("Invalid port number: {}", value)))?;
            }
            "dbname" => config.dbname = value.to_string(),
            "user" => config.user = Some(value.to_string()),
            "password" => config.password = Some(value.to_string()),
            "sslmode" => config.sslmode = Some(value.to_string()),
            _ => {
                // Unknown keys are silently ignored.
            }
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// PdoPgsqlDriver — Driver struct
// ---------------------------------------------------------------------------

/// The PDO PostgreSQL driver.
#[derive(Debug)]
pub struct PdoPgsqlDriver;

impl PdoPgsqlDriver {
    /// Create a new PDO PostgreSQL driver instance.
    pub fn new() -> Self {
        Self
    }

    /// Get the driver name.
    pub fn name(&self) -> &'static str {
        "pgsql"
    }
}

impl Default for PdoPgsqlDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl PdoDriver for PdoPgsqlDriver {
    fn connect(
        &self,
        dsn_params: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Box<dyn PdoDriverConnection>, PdoError> {
        let mut config = parse_dsn(dsn_params).map_err(|e| {
            PdoError::new("08006", None, &format!("Invalid DSN: {}", e.message))
        })?;

        // Override config with explicit username/password if provided
        if let Some(u) = username {
            config.user = Some(u.to_string());
        }
        if let Some(p) = password {
            config.password = Some(p.to_string());
        }

        // Build PostgreSQL connection string
        let mut conn_params = Vec::new();
        conn_params.push(format!("host={}", config.host));
        conn_params.push(format!("port={}", config.port));
        if !config.dbname.is_empty() {
            conn_params.push(format!("dbname={}", config.dbname));
        }
        if let Some(ref user) = config.user {
            conn_params.push(format!("user={}", user));
        }
        if let Some(ref password) = config.password {
            conn_params.push(format!("password={}", password));
        }
        if let Some(ref sslmode) = config.sslmode {
            conn_params.push(format!("sslmode={}", sslmode));
        }

        let conn_string = conn_params.join(" ");

        // Connect to PostgreSQL
        let client = Client::connect(&conn_string, NoTls).map_err(|e| {
            PdoError::new("08006", None, &format!("Connection failed: {}", e))
        })?;

        Ok(Box::new(PgsqlConnection {
            client: RefCell::new(client),
            in_transaction: RefCell::new(false),
        }))
    }
}

// ---------------------------------------------------------------------------
// PgsqlConnection — Connection implementation
// ---------------------------------------------------------------------------

struct PgsqlConnection {
    client: RefCell<Client>,
    in_transaction: RefCell<bool>,
}

// SAFETY: postgres::Client is Send, and we wrap access in RefCell for interior
// mutability within a single thread.
unsafe impl Send for PgsqlConnection {}

impl PdoDriverConnection for PgsqlConnection {
    fn prepare(&self, sql: &str) -> Result<Box<dyn PdoDriverStatement>, PdoError> {
        Ok(Box::new(PgsqlStatement {
            sql: sql.to_string(),
            bound_params: HashMap::new(),
            conn_ptr: self as *const PgsqlConnection,
            rows: Vec::new(),
            row_index: 0,
            affected_rows: 0,
            column_names: Vec::new(),
        }))
    }

    fn exec(&self, sql: &str) -> Result<u64, PdoError> {
        let mut client = self.client.borrow_mut();
        let affected = client.execute(sql, &[]).map_err(pgsql_error)?;
        Ok(affected)
    }

    fn quote(&self, string: &str) -> String {
        // PostgreSQL quoting: wrap in single quotes, double any embedded single quotes
        let escaped = string.replace('\'', "''");
        format!("'{}'", escaped)
    }

    fn last_insert_id(&self) -> String {
        // PostgreSQL doesn't have a last_insert_id() like MySQL
        // We would need to use RETURNING clause or sequences
        // For now, return empty string (PHP PDO returns empty string by default)
        String::new()
    }

    fn begin_transaction(&self) -> Result<(), PdoError> {
        if *self.in_transaction.borrow() {
            return Err(PdoError::new(
                "HY000",
                None,
                "There is already an active transaction",
            ));
        }
        let mut client = self.client.borrow_mut();
        client.execute("BEGIN", &[]).map_err(pgsql_error)?;
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
        let mut client = self.client.borrow_mut();
        client.execute("COMMIT", &[]).map_err(pgsql_error)?;
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
        let mut client = self.client.borrow_mut();
        client.execute("ROLLBACK", &[]).map_err(pgsql_error)?;
        *self.in_transaction.borrow_mut() = false;
        Ok(())
    }

    fn in_transaction(&self) -> bool {
        *self.in_transaction.borrow()
    }
}

/// Convert a postgres error to a PdoError.
fn pgsql_error(e: postgres::Error) -> PdoError {
    // PostgreSQL errors include SQLSTATE codes
    let sqlstate = e
        .code()
        .map(|c| c.code().to_string())
        .unwrap_or_else(|| "HY000".to_string());
    PdoError::new(&sqlstate, None, &e.to_string())
}

// ---------------------------------------------------------------------------
// PgsqlStatement — Statement implementation
// ---------------------------------------------------------------------------

struct PgsqlStatement {
    sql: String,
    bound_params: HashMap<PdoParam, PdoValue>,
    conn_ptr: *const PgsqlConnection,
    rows: Vec<PdoRow>,
    row_index: usize,
    affected_rows: u64,
    column_names: Vec<String>,
}

// SAFETY: PgsqlStatement holds a raw pointer to PgsqlConnection, which is
// pinned for the lifetime of the PdoConnection. Send is required by trait bound.
unsafe impl Send for PgsqlStatement {}

impl PdoDriverStatement for PgsqlStatement {
    fn bind_value(&mut self, param: &PdoParam, value: &PdoValue) -> Result<(), PdoError> {
        self.bound_params.insert(param.clone(), value.clone());
        Ok(())
    }

    fn execute(&mut self, params: Option<&[PdoValue]>) -> Result<bool, PdoError> {
        self.rows.clear();
        self.row_index = 0;
        self.affected_rows = 0;
        self.column_names.clear();

        // SAFETY: conn_ptr is valid for the lifetime of the PdoConnection
        let pgsql_conn: &PgsqlConnection = unsafe { &*self.conn_ptr };
        let mut client = pgsql_conn.client.borrow_mut();

        // Build parameter list
        let effective_params: Vec<PdoValue> = if let Some(p) = params {
            p.to_vec()
        } else if !self.bound_params.is_empty() {
            // Collect positional parameters in order
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
            v
        } else {
            Vec::new()
        };

        // Convert PdoValue to postgres parameters
        // PostgreSQL uses $1, $2, etc. for placeholders
        let pg_params: Vec<Box<dyn postgres::types::ToSql + Sync>> = effective_params
            .iter()
            .map(|v| pdo_value_to_pgsql(v))
            .collect();

        let param_refs: Vec<&(dyn postgres::types::ToSql + Sync)> =
            pg_params.iter().map(|b| b.as_ref()).collect();

        // Execute query
        let result = if self.sql.trim().to_uppercase().starts_with("SELECT")
            || self.sql.trim().to_uppercase().starts_with("WITH")
            || self.sql.contains("RETURNING")
        {
            // Query that returns rows
            client.query(&self.sql, &param_refs).map_err(pgsql_error)?
        } else {
            // Non-query statement
            self.affected_rows = client
                .execute(&self.sql, &param_refs)
                .map_err(pgsql_error)?;
            return Ok(true);
        };

        // Process result rows
        if !result.is_empty() {
            // Get column names from first row
            let first_row = &result[0];
            self.column_names = first_row
                .columns()
                .iter()
                .map(|col| col.name().to_string())
                .collect();

            // Convert all rows
            for row in result {
                let values = (0..row.len())
                    .map(|i| pgsql_value_from_row(&row, i))
                    .collect();
                self.rows.push(PdoRow {
                    columns: self.column_names.clone(),
                    values,
                });
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
        self.affected_rows
    }

    fn column_count(&self) -> usize {
        self.column_names.len()
    }
}

// ---------------------------------------------------------------------------
// Helper functions for type conversion
// ---------------------------------------------------------------------------

/// Convert a PdoValue to a PostgreSQL parameter.
fn pdo_value_to_pgsql(value: &PdoValue) -> Box<dyn postgres::types::ToSql + Sync> {
    match value {
        PdoValue::Null => Box::new(None::<i32>),
        PdoValue::Int(i) => Box::new(*i),
        PdoValue::Float(f) => Box::new(*f),
        PdoValue::Str(s) => Box::new(s.clone()),
        PdoValue::Bool(b) => Box::new(*b),
        PdoValue::Blob(v) => Box::new(v.clone()),
    }
}

/// Extract a PdoValue from a PostgreSQL row column.
fn pgsql_value_from_row(row: &Row, index: usize) -> PdoValue {
    // Try different types in order
    if let Ok(val) = row.try_get::<_, Option<i64>>(index) {
        return match val {
            Some(i) => PdoValue::Int(i),
            None => PdoValue::Null,
        };
    }
    if let Ok(val) = row.try_get::<_, Option<i32>>(index) {
        return match val {
            Some(i) => PdoValue::Int(i as i64),
            None => PdoValue::Null,
        };
    }
    if let Ok(val) = row.try_get::<_, Option<f64>>(index) {
        return match val {
            Some(f) => PdoValue::Float(f),
            None => PdoValue::Null,
        };
    }
    if let Ok(val) = row.try_get::<_, Option<bool>>(index) {
        return match val {
            Some(b) => PdoValue::Bool(b),
            None => PdoValue::Null,
        };
    }
    if let Ok(val) = row.try_get::<_, Option<Vec<u8>>>(index) {
        return match val {
            Some(v) => PdoValue::Blob(v),
            None => PdoValue::Null,
        };
    }
    if let Ok(val) = row.try_get::<_, Option<String>>(index) {
        return match val {
            Some(s) => PdoValue::Str(s),
            None => PdoValue::Null,
        };
    }
    // Default to Null if type conversion fails
    PdoValue::Null
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dsn_full() {
        let config =
            parse_dsn("host=db.example.com;port=5433;dbname=myapp").expect("parse should succeed");
        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.port, 5433);
        assert_eq!(config.dbname, "myapp");
    }

    #[test]
    fn test_parse_dsn_defaults() {
        let config = parse_dsn("").expect("parse should succeed");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.dbname, "");
        assert!(config.user.is_none());
        assert!(config.password.is_none());
        assert!(config.sslmode.is_none());
    }

    #[test]
    fn test_parse_dsn_with_credentials() {
        let config = parse_dsn("host=pg.local;dbname=prod;user=admin;password=secret")
            .expect("parse should succeed");
        assert_eq!(config.host, "pg.local");
        assert_eq!(config.dbname, "prod");
        assert_eq!(config.user, Some("admin".to_string()));
        assert_eq!(config.password, Some("secret".to_string()));
    }

    #[test]
    fn test_parse_dsn_with_sslmode() {
        let config =
            parse_dsn("host=pg.local;dbname=secure;sslmode=require").expect("parse should succeed");
        assert_eq!(config.sslmode, Some("require".to_string()));
    }

    #[test]
    fn test_parse_dsn_space_separated() {
        let config =
            parse_dsn("host=pg.local port=5433 dbname=mydb").expect("parse should succeed");
        assert_eq!(config.host, "pg.local");
        assert_eq!(config.port, 5433);
        assert_eq!(config.dbname, "mydb");
    }

    #[test]
    fn test_parse_dsn_invalid_port() {
        let result = parse_dsn("host=localhost;port=xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Invalid port"));
    }

    #[test]
    fn test_parse_dsn_invalid_component() {
        let result = parse_dsn("host=localhost;noequals");
        assert!(result.is_err());
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoPgsqlDriver::new();
        assert_eq!(driver.name(), "pgsql");
    }

    #[test]
    fn test_connection_from_config() {
        // This test verifies the config structure is correct
        let config = PdoPgsqlConfig {
            host: "pghost".to_string(),
            port: 5432,
            dbname: "pgdb".to_string(),
            user: Some("pguser".to_string()),
            password: None,
            sslmode: Some("prefer".to_string()),
        };
        assert_eq!(config.host, "pghost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.dbname, "pgdb");
        assert_eq!(config.user, Some("pguser".to_string()));
        assert_eq!(config.sslmode, Some("prefer".to_string()));
    }

    #[test]
    fn test_attribute_constants() {
        assert_eq!(PDO_PGSQL_ATTR_DISABLE_PREPARES, 1000);
    }

    #[test]
    fn test_default_config() {
        let config = PdoPgsqlConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert!(config.dbname.is_empty());
    }

    #[test]
    fn test_parse_dsn_trailing_semicolon() {
        let config = parse_dsn("host=localhost;dbname=test;").expect("parse should succeed");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.dbname, "test");
    }

    #[test]
    fn test_driver_implementation() {
        use php_rs_ext_pdo::PdoDriver;

        // Test that the driver implements the PdoDriver trait
        let driver = PdoPgsqlDriver::new();
        assert_eq!(driver.name(), "pgsql");

        // Test connection with invalid credentials (should fail gracefully)
        let result = driver.connect(
            "host=nonexistent.invalid;port=5432;dbname=test",
            Some("user"),
            Some("pass"),
        );

        // Connection should fail, but not panic
        assert!(result.is_err());
        if let Err(e) = result {
            // Should contain connection error
            assert!(e.message.contains("Connection failed") || e.message.contains("failed"));
        }
    }

    #[test]
    fn test_pdo_value_conversions() {
        use php_rs_ext_pdo::PdoValue;

        // Test that we can create PdoValues of different types
        let null_val = PdoValue::Null;
        let int_val = PdoValue::Int(42);
        let float_val = PdoValue::Float(3.14);
        let str_val = PdoValue::Str("hello".to_string());
        let bool_val = PdoValue::Bool(true);
        let blob_val = PdoValue::Blob(vec![1, 2, 3, 4]);

        // Test Display implementations
        assert_eq!(null_val.to_string(), "NULL");
        assert_eq!(int_val.to_string(), "42");
        assert_eq!(float_val.to_string(), "3.14");
        assert_eq!(str_val.to_string(), "hello");
        assert_eq!(bool_val.to_string(), "1");
        assert!(blob_val.to_string().contains("blob"));
    }
}
