//! PHP pgsql extension — native PostgreSQL client functions.
//!
//! Implements `pg_connect`, `pg_query`, `pg_fetch_assoc`, `pg_num_rows`,
//! and other procedural PostgreSQL functions.
//! Reference: php-src/ext/pgsql/

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants — connection status
// ---------------------------------------------------------------------------

pub const PGSQL_CONNECT_FORCE_NEW: i32 = 2;
pub const PGSQL_CONNECT_ASYNC: i32 = 4;

/// Connection OK.
pub const PGSQL_CONNECTION_OK: i32 = 0;
/// Connection bad/failed.
pub const PGSQL_CONNECTION_BAD: i32 = 1;
/// Waiting for connection to be established.
pub const PGSQL_CONNECTION_STARTED: i32 = 2;

// ---------------------------------------------------------------------------
// Constants — result status
// ---------------------------------------------------------------------------

/// Successful completion of a command returning no data.
pub const PGSQL_COMMAND_OK: i32 = 1;
/// Successful completion of a command returning data.
pub const PGSQL_TUPLES_OK: i32 = 2;
/// Empty query string.
pub const PGSQL_EMPTY_QUERY: i32 = 0;
/// Bad response from server.
pub const PGSQL_BAD_RESPONSE: i32 = 5;
/// Fatal error.
pub const PGSQL_FATAL_ERROR: i32 = 7;

// ---------------------------------------------------------------------------
// Constants — fetch mode
// ---------------------------------------------------------------------------

pub const PGSQL_ASSOC: i32 = 1;
pub const PGSQL_NUM: i32 = 2;
pub const PGSQL_BOTH: i32 = 3;

// ---------------------------------------------------------------------------
// Constants — field types
// ---------------------------------------------------------------------------

pub const PGSQL_RESULT_BOOL: i32 = 16;
pub const PGSQL_RESULT_INT2: i32 = 21;
pub const PGSQL_RESULT_INT4: i32 = 23;
pub const PGSQL_RESULT_INT8: i32 = 20;
pub const PGSQL_RESULT_FLOAT4: i32 = 700;
pub const PGSQL_RESULT_FLOAT8: i32 = 701;
pub const PGSQL_RESULT_TEXT: i32 = 25;
pub const PGSQL_RESULT_VARCHAR: i32 = 1043;

// ---------------------------------------------------------------------------
// PgsqlError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PgsqlError {
    pub message: String,
    pub sqlstate: String,
}

impl PgsqlError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            sqlstate: "00000".to_string(),
        }
    }

    pub fn with_state(mut self, state: &str) -> Self {
        self.sqlstate = state.to_string();
        self
    }
}

impl fmt::Display for PgsqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pg error: {}", self.message)
    }
}

impl std::error::Error for PgsqlError {}

// ---------------------------------------------------------------------------
// PgsqlConnectionConfig
// ---------------------------------------------------------------------------

/// Configuration for a PostgreSQL connection.
#[derive(Debug, Clone, PartialEq)]
pub struct PgsqlConnectionConfig {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub user: String,
    pub password: String,
}

impl Default for PgsqlConnectionConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            dbname: String::new(),
            user: String::new(),
            password: String::new(),
        }
    }
}

/// Parse a PostgreSQL connection string.
/// Supports: `host=xx port=5432 dbname=xx user=xx password=xx`
pub fn parse_connection_string(connstr: &str) -> Result<PgsqlConnectionConfig, PgsqlError> {
    let mut config = PgsqlConnectionConfig::default();

    for token in connstr.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "host" | "hostaddr" => config.host = value.to_string(),
                "port" => {
                    config.port = value
                        .parse()
                        .map_err(|_| PgsqlError::new(&format!("Invalid port: {}", value)))?;
                }
                "dbname" => config.dbname = value.to_string(),
                "user" => config.user = value.to_string(),
                "password" => config.password = value.to_string(),
                _ => {} // Ignore unknown keys
            }
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// PgsqlConnection — in-memory stub
// ---------------------------------------------------------------------------

/// Represents a pgsql connection (in-memory stub for now).
#[derive(Debug, Clone)]
pub struct PgsqlConnection {
    pub config: PgsqlConnectionConfig,
    pub status: i32,
    /// In-memory tables for stub usage.
    pub tables: HashMap<String, Vec<Vec<(String, String)>>>,
    /// Server version string.
    pub server_version: String,
    /// Last error message.
    pub last_error: String,
}

impl PgsqlConnection {
    pub fn new(config: PgsqlConnectionConfig) -> Self {
        Self {
            config,
            status: PGSQL_CONNECTION_OK,
            tables: HashMap::new(),
            server_version: "16.0".to_string(),
            last_error: String::new(),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.status == PGSQL_CONNECTION_OK
    }

    pub fn close(&mut self) {
        self.status = PGSQL_CONNECTION_BAD;
    }
}

// ---------------------------------------------------------------------------
// PgsqlResult — query result
// ---------------------------------------------------------------------------

/// A query result set.
#[derive(Debug, Clone)]
pub struct PgsqlResult {
    /// Column names in order.
    pub fields: Vec<String>,
    /// Rows: each row is a Vec of string values in column order.
    pub rows: Vec<Vec<String>>,
    /// Current fetch position.
    pub position: usize,
    /// Result status.
    pub status: i32,
    /// Command tag (e.g., "SELECT 2", "INSERT 0 1").
    pub command_tag: String,
}

impl PgsqlResult {
    pub fn new(fields: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        Self {
            fields,
            rows,
            position: 0,
            status: PGSQL_TUPLES_OK,
            command_tag: String::new(),
        }
    }

    pub fn empty() -> Self {
        Self {
            fields: Vec::new(),
            rows: Vec::new(),
            position: 0,
            status: PGSQL_COMMAND_OK,
            command_tag: String::new(),
        }
    }

    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }

    pub fn num_fields(&self) -> usize {
        self.fields.len()
    }

    pub fn field_name(&self, index: usize) -> Option<&str> {
        self.fields.get(index).map(|s| s.as_str())
    }

    /// Fetch the next row as an associative map.
    pub fn fetch_assoc(&mut self) -> Option<HashMap<String, String>> {
        if self.position >= self.rows.len() {
            return None;
        }
        let row = &self.rows[self.position];
        self.position += 1;
        let mut map = HashMap::new();
        for (i, field) in self.fields.iter().enumerate() {
            if let Some(val) = row.get(i) {
                map.insert(field.clone(), val.clone());
            }
        }
        Some(map)
    }

    /// Fetch the next row as a numeric array.
    pub fn fetch_row(&mut self) -> Option<Vec<String>> {
        if self.position >= self.rows.len() {
            return None;
        }
        let row = self.rows[self.position].clone();
        self.position += 1;
        Some(row)
    }

    /// Fetch a specific row/field value.
    pub fn fetch_result(&self, row: usize, field: usize) -> Option<&str> {
        self.rows
            .get(row)
            .and_then(|r| r.get(field))
            .map(|s| s.as_str())
    }

    /// Reset the fetch position.
    pub fn data_seek(&mut self, row: usize) {
        self.position = row;
    }

    /// Number of rows affected by the last command.
    pub fn affected_rows(&self) -> usize {
        // For SELECT, this is the row count. For INSERT/UPDATE/DELETE,
        // the command tag contains the count.
        self.rows.len()
    }
}

// ---------------------------------------------------------------------------
// Escape functions
// ---------------------------------------------------------------------------

/// Escape a string for use in a PostgreSQL query.
/// Mimics `pg_escape_string()`.
pub fn pg_escape_string(input: &str) -> String {
    let mut output = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\'' => output.push_str("''"),
            '\\' => output.push_str("\\\\"),
            _ => output.push(ch),
        }
    }
    output
}

/// Escape a string literal for PostgreSQL (with E'' quoting).
/// Mimics `pg_escape_literal()`.
pub fn pg_escape_literal(input: &str) -> String {
    format!("'{}'", pg_escape_string(input))
}

/// Escape an identifier for PostgreSQL (double-quote wrapping).
/// Mimics `pg_escape_identifier()`.
pub fn pg_escape_identifier(input: &str) -> String {
    let escaped = input.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

/// Escape bytea data for insertion.
pub fn pg_escape_bytea(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for &byte in data {
        if byte == b'\\' {
            output.push_str("\\\\");
        } else if byte < 0x20 || byte > 0x7e {
            output.push_str(&format!("\\{:03o}", byte));
        } else {
            output.push(byte as char);
        }
    }
    output
}

/// Unescape bytea data from a query result.
pub fn pg_unescape_bytea(input: &str) -> Vec<u8> {
    // Handle hex format: \x...
    if input.starts_with("\\x") {
        let hex = &input[2..];
        let mut result = Vec::with_capacity(hex.len() / 2);
        let mut i = 0;
        let bytes = hex.as_bytes();
        while i + 1 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) {
                result.push(byte);
            }
            i += 2;
        }
        return result;
    }

    // Handle octal escape format: \\NNN
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'\\' {
                result.push(b'\\');
                i += 2;
            } else if i + 3 < bytes.len()
                && bytes[i + 1].is_ascii_digit()
                && bytes[i + 2].is_ascii_digit()
                && bytes[i + 3].is_ascii_digit()
            {
                let octal = &input[i + 1..i + 4];
                if let Ok(byte) = u8::from_str_radix(octal, 8) {
                    result.push(byte);
                }
                i += 4;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connection_string() {
        let config = parse_connection_string(
            "host=db.example.com port=5433 dbname=myapp user=admin password=secret",
        )
        .unwrap();
        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.port, 5433);
        assert_eq!(config.dbname, "myapp");
        assert_eq!(config.user, "admin");
        assert_eq!(config.password, "secret");
    }

    #[test]
    fn test_parse_connection_defaults() {
        let config = parse_connection_string("dbname=test").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
    }

    #[test]
    fn test_connection_status() {
        let config = PgsqlConnectionConfig::default();
        let mut conn = PgsqlConnection::new(config);
        assert!(conn.is_connected());
        conn.close();
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_result_fetch_assoc() {
        let fields = vec!["id".to_string(), "name".to_string()];
        let rows = vec![
            vec!["1".to_string(), "Alice".to_string()],
            vec!["2".to_string(), "Bob".to_string()],
        ];
        let mut result = PgsqlResult::new(fields, rows);
        assert_eq!(result.num_rows(), 2);
        assert_eq!(result.num_fields(), 2);

        let row1 = result.fetch_assoc().unwrap();
        assert_eq!(row1["id"], "1");
        assert_eq!(row1["name"], "Alice");

        let row2 = result.fetch_assoc().unwrap();
        assert_eq!(row2["name"], "Bob");

        assert!(result.fetch_assoc().is_none());
    }

    #[test]
    fn test_result_data_seek() {
        let fields = vec!["x".to_string()];
        let rows = vec![vec!["a".to_string()], vec!["b".to_string()]];
        let mut result = PgsqlResult::new(fields, rows);
        result.fetch_row();
        result.fetch_row();
        assert!(result.fetch_row().is_none());

        result.data_seek(0);
        assert_eq!(result.fetch_row().unwrap(), vec!["a"]);
    }

    #[test]
    fn test_result_fetch_result() {
        let fields = vec!["col".to_string()];
        let rows = vec![vec!["val".to_string()]];
        let result = PgsqlResult::new(fields, rows);
        assert_eq!(result.fetch_result(0, 0), Some("val"));
        assert_eq!(result.fetch_result(1, 0), None);
    }

    #[test]
    fn test_escape_string() {
        assert_eq!(pg_escape_string("it's"), "it''s");
        assert_eq!(pg_escape_string("a\\b"), "a\\\\b");
        assert_eq!(pg_escape_string("plain"), "plain");
    }

    #[test]
    fn test_escape_literal() {
        assert_eq!(pg_escape_literal("it's"), "'it''s'");
    }

    #[test]
    fn test_escape_identifier() {
        assert_eq!(pg_escape_identifier("my table"), "\"my table\"");
        assert_eq!(pg_escape_identifier("col\"name"), "\"col\"\"name\"");
    }

    #[test]
    fn test_escape_bytea() {
        assert_eq!(pg_escape_bytea(b"hello"), "hello");
        assert_eq!(pg_escape_bytea(b"\x00\x01"), "\\000\\001");
        assert_eq!(pg_escape_bytea(b"a\\b"), "a\\\\b");
    }

    #[test]
    fn test_unescape_bytea_hex() {
        assert_eq!(pg_unescape_bytea("\\x48656c6c6f"), b"Hello");
    }

    #[test]
    fn test_unescape_bytea_octal() {
        assert_eq!(pg_unescape_bytea("\\000\\001"), vec![0u8, 1u8]);
        assert_eq!(pg_unescape_bytea("\\\\"), vec![b'\\']);
    }

    #[test]
    fn test_field_name() {
        let result = PgsqlResult::new(vec!["a".into(), "b".into()], vec![]);
        assert_eq!(result.field_name(0), Some("a"));
        assert_eq!(result.field_name(1), Some("b"));
        assert_eq!(result.field_name(2), None);
    }

    #[test]
    fn test_empty_result() {
        let result = PgsqlResult::empty();
        assert_eq!(result.num_rows(), 0);
        assert_eq!(result.status, PGSQL_COMMAND_OK);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PGSQL_ASSOC, 1);
        assert_eq!(PGSQL_NUM, 2);
        assert_eq!(PGSQL_BOTH, 3);
        assert_eq!(PGSQL_CONNECTION_OK, 0);
    }
}
