//! PDO ODBC driver extension for php.rs
//!
//! Implements the PDO_odbc driver, which provides ODBC DSN parsing,
//! attributes, and connection configuration for ODBC-based database access.
//! Reference: php-src/ext/pdo_odbc/

use std::fmt;

// ---------------------------------------------------------------------------
// Constants — PDO ODBC attributes
// ---------------------------------------------------------------------------

/// Assume the ODBC driver is ANSI-only.
pub const PDO_ODBC_ATTR_USE_CURSOR_LIBRARY: i32 = 1000;
/// Assume the ODBC driver handles Unicode.
pub const PDO_ODBC_ATTR_ASSUME_UTF8: i32 = 1001;

/// SQL_CURSOR_FORWARD_ONLY.
pub const PDO_ODBC_SQL_USE_IF_NEEDED: i32 = 0;
/// Always use the cursor library.
pub const PDO_ODBC_SQL_USE_DRIVER: i32 = 2;
/// Never use the cursor library.
pub const PDO_ODBC_SQL_USE_ODBC: i32 = 1;

// ---------------------------------------------------------------------------
// SQL type constants used by ODBC
// ---------------------------------------------------------------------------

pub const SQL_CHAR: i32 = 1;
pub const SQL_VARCHAR: i32 = 12;
pub const SQL_LONGVARCHAR: i32 = -1;
pub const SQL_WCHAR: i32 = -8;
pub const SQL_WVARCHAR: i32 = -9;
pub const SQL_DECIMAL: i32 = 3;
pub const SQL_NUMERIC: i32 = 2;
pub const SQL_SMALLINT: i32 = 5;
pub const SQL_INTEGER: i32 = 4;
pub const SQL_REAL: i32 = 7;
pub const SQL_FLOAT: i32 = 6;
pub const SQL_DOUBLE: i32 = 8;
pub const SQL_BIT: i32 = -7;
pub const SQL_TINYINT: i32 = -6;
pub const SQL_BIGINT: i32 = -5;
pub const SQL_BINARY: i32 = -2;
pub const SQL_VARBINARY: i32 = -3;
pub const SQL_DATE: i32 = 9;
pub const SQL_TIME: i32 = 10;
pub const SQL_TIMESTAMP: i32 = 11;

// ---------------------------------------------------------------------------
// PdoOdbcError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PdoOdbcError {
    pub message: String,
    pub sqlstate: String,
    pub native_code: i32,
}

impl PdoOdbcError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            sqlstate: "00000".to_string(),
            native_code: 0,
        }
    }

    pub fn with_state(mut self, state: &str) -> Self {
        self.sqlstate = state.to_string();
        self
    }

    pub fn with_native(mut self, code: i32) -> Self {
        self.native_code = code;
        self
    }
}

impl fmt::Display for PdoOdbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO ODBC error [{}]: {}", self.sqlstate, self.message)
    }
}

impl std::error::Error for PdoOdbcError {}

// ---------------------------------------------------------------------------
// PdoOdbcConfig — DSN parsing
// ---------------------------------------------------------------------------

/// Configuration from an ODBC PDO DSN.
///
/// DSN formats:
/// - `odbc:DSN_NAME` — use a pre-configured system/user DSN
/// - `odbc:DRIVER={driver};SERVER=host;DATABASE=db;...` — connection string
#[derive(Debug, Clone, PartialEq)]
pub struct PdoOdbcConfig {
    /// The ODBC DSN name (if using a pre-configured DSN).
    pub dsn_name: Option<String>,
    /// Raw connection string (if using a connection string directly).
    pub connection_string: Option<String>,
    /// Whether to assume UTF-8 encoding for string data.
    pub assume_utf8: bool,
}

impl Default for PdoOdbcConfig {
    fn default() -> Self {
        Self {
            dsn_name: None,
            connection_string: None,
            assume_utf8: false,
        }
    }
}

/// Parse an ODBC PDO DSN parameter string.
///
/// If the string contains `=`, it's treated as a connection string.
/// Otherwise, it's treated as a DSN name.
pub fn parse_dsn(dsn: &str) -> Result<PdoOdbcConfig, PdoOdbcError> {
    let dsn = dsn.trim();
    if dsn.is_empty() {
        return Err(PdoOdbcError::new("Empty DSN"));
    }

    if dsn.contains('=') {
        // Connection string format
        Ok(PdoOdbcConfig {
            dsn_name: None,
            connection_string: Some(dsn.to_string()),
            assume_utf8: false,
        })
    } else {
        // Pre-configured DSN name
        Ok(PdoOdbcConfig {
            dsn_name: Some(dsn.to_string()),
            connection_string: None,
            assume_utf8: false,
        })
    }
}

/// Parse an ODBC connection string into key-value pairs.
/// Format: `KEY1=VALUE1;KEY2=VALUE2;...`
/// Values can be wrapped in `{}` to include semicolons.
pub fn parse_connection_string(connstr: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut i = 0;
    let bytes = connstr.as_bytes();

    while i < bytes.len() {
        // Skip whitespace
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }

        // Find '='
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b';' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }
        let key = connstr[key_start..i].trim().to_string();
        i += 1; // skip '='

        // Parse value (may be {}-enclosed)
        let value;
        if i < bytes.len() && bytes[i] == b'{' {
            i += 1;
            let val_start = i;
            while i < bytes.len() && bytes[i] != b'}' {
                i += 1;
            }
            value = connstr[val_start..i].to_string();
            if i < bytes.len() {
                i += 1; // skip '}'
            }
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            value = connstr[val_start..i].trim().to_string();
        }

        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
        }

        if !key.is_empty() {
            result.push((key, value));
        }
    }

    result
}

// ---------------------------------------------------------------------------
// PdoOdbcDriver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PdoOdbcDriver;

impl PdoOdbcDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str {
        "odbc"
    }
}

impl Default for PdoOdbcDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dsn_name() {
        let config = parse_dsn("MyDSN").unwrap();
        assert_eq!(config.dsn_name, Some("MyDSN".to_string()));
        assert!(config.connection_string.is_none());
    }

    #[test]
    fn test_parse_dsn_connection_string() {
        let config = parse_dsn("DRIVER={SQL Server};SERVER=localhost;DATABASE=test").unwrap();
        assert!(config.dsn_name.is_none());
        assert!(config.connection_string.is_some());
    }

    #[test]
    fn test_parse_dsn_empty() {
        assert!(parse_dsn("").is_err());
    }

    #[test]
    fn test_parse_connection_string() {
        let pairs = parse_connection_string("DRIVER={SQL Server};SERVER=localhost;DATABASE=test");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("DRIVER".into(), "SQL Server".into()));
        assert_eq!(pairs[1], ("SERVER".into(), "localhost".into()));
        assert_eq!(pairs[2], ("DATABASE".into(), "test".into()));
    }

    #[test]
    fn test_parse_connection_string_no_braces() {
        let pairs = parse_connection_string("SERVER=host;UID=sa;PWD=pass");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, "SERVER");
        assert_eq!(pairs[2].1, "pass");
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoOdbcDriver::new();
        assert_eq!(driver.name(), "odbc");
    }

    #[test]
    fn test_error_with_state() {
        let err = PdoOdbcError::new("connection failed")
            .with_state("08001")
            .with_native(17);
        assert_eq!(err.sqlstate, "08001");
        assert_eq!(err.native_code, 17);
        assert!(format!("{}", err).contains("08001"));
    }

    #[test]
    fn test_sql_type_constants() {
        assert_eq!(SQL_VARCHAR, 12);
        assert_eq!(SQL_INTEGER, 4);
        assert_eq!(SQL_BIGINT, -5);
    }

    #[test]
    fn test_default_config() {
        let config = PdoOdbcConfig::default();
        assert!(config.dsn_name.is_none());
        assert!(config.connection_string.is_none());
        assert!(!config.assume_utf8);
    }

    #[test]
    fn test_parse_connection_string_braces_with_semicolon() {
        let pairs = parse_connection_string("DRIVER={My;Driver};SERVER=host");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].1, "My;Driver");
    }
}
