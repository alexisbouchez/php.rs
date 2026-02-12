//! PDO Firebird driver extension for php.rs
//!
//! Implements the PDO_firebird driver, which provides Firebird/InterBase
//! DSN parsing, attributes, and connection configuration.
//! Reference: php-src/ext/pdo_firebird/

use std::fmt;

// ---------------------------------------------------------------------------
// Constants — PDO Firebird attributes
// ---------------------------------------------------------------------------

/// Firebird-specific: date format.
pub const PDO_FB_ATTR_DATE_FORMAT: i32 = 1000;
/// Firebird-specific: time format.
pub const PDO_FB_ATTR_TIME_FORMAT: i32 = 1001;
/// Firebird-specific: timestamp format.
pub const PDO_FB_ATTR_TIMESTAMP_FORMAT: i32 = 1002;

// ---------------------------------------------------------------------------
// Transaction isolation levels
// ---------------------------------------------------------------------------

pub const PDO_FB_TRANSACTION_ISOLATION_READ_COMMITTED: i32 = 0;
pub const PDO_FB_TRANSACTION_ISOLATION_REPEATABLE_READ: i32 = 1;
pub const PDO_FB_TRANSACTION_ISOLATION_SERIALIZABLE: i32 = 2;
pub const PDO_FB_TRANSACTION_ISOLATION_READ_COMMITTED_READ_ONLY: i32 = 3;

// ---------------------------------------------------------------------------
// PdoFirebirdError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PdoFirebirdError {
    pub message: String,
    pub isc_code: i64,
}

impl PdoFirebirdError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            isc_code: 0,
        }
    }

    pub fn with_code(mut self, code: i64) -> Self {
        self.isc_code = code;
        self
    }
}

impl fmt::Display for PdoFirebirdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO Firebird error: {}", self.message)
    }
}

impl std::error::Error for PdoFirebirdError {}

// ---------------------------------------------------------------------------
// PdoFirebirdConfig — DSN parsing
// ---------------------------------------------------------------------------

/// Configuration from a Firebird PDO DSN.
///
/// DSN format: `firebird:dbname=/path/to/database.fdb;charset=UTF8;role=xxx`
#[derive(Debug, Clone, PartialEq)]
pub struct PdoFirebirdConfig {
    /// Database path (can be local path or remote: `host:/path/to/db.fdb`).
    pub dbname: String,
    /// Character set for the connection.
    pub charset: String,
    /// SQL role for the connection.
    pub role: String,
    /// Dialect (1, 2, or 3; default 3).
    pub dialect: i32,
}

impl Default for PdoFirebirdConfig {
    fn default() -> Self {
        Self {
            dbname: String::new(),
            charset: "UTF8".to_string(),
            role: String::new(),
            dialect: 3,
        }
    }
}

/// Parse a Firebird PDO DSN parameter string.
pub fn parse_dsn(dsn: &str) -> Result<PdoFirebirdConfig, PdoFirebirdError> {
    let mut config = PdoFirebirdConfig::default();

    for part in dsn.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                // Plain dbname without key
                if config.dbname.is_empty() {
                    config.dbname = part.to_string();
                }
                continue;
            }
        };

        match key {
            "dbname" => config.dbname = value.to_string(),
            "charset" => config.charset = value.to_string(),
            "role" => config.role = value.to_string(),
            "dialect" => {
                config.dialect = value.parse().unwrap_or(3);
            }
            _ => {}
        }
    }

    if config.dbname.is_empty() {
        return Err(PdoFirebirdError::new("No database specified in DSN"));
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// PdoFirebirdDriver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PdoFirebirdDriver;

impl PdoFirebirdDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str {
        "firebird"
    }
}

impl Default for PdoFirebirdDriver {
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
    fn test_parse_dsn_basic() {
        let config = parse_dsn("dbname=/var/data/test.fdb").unwrap();
        assert_eq!(config.dbname, "/var/data/test.fdb");
        assert_eq!(config.charset, "UTF8");
        assert_eq!(config.dialect, 3);
    }

    #[test]
    fn test_parse_dsn_remote() {
        let config = parse_dsn("dbname=server:/var/data/test.fdb;charset=NONE").unwrap();
        assert_eq!(config.dbname, "server:/var/data/test.fdb");
        assert_eq!(config.charset, "NONE");
    }

    #[test]
    fn test_parse_dsn_with_role() {
        let config = parse_dsn("dbname=test.fdb;role=ADMIN;dialect=1").unwrap();
        assert_eq!(config.role, "ADMIN");
        assert_eq!(config.dialect, 1);
    }

    #[test]
    fn test_parse_dsn_no_dbname() {
        assert!(parse_dsn("charset=UTF8").is_err());
    }

    #[test]
    fn test_parse_dsn_empty() {
        assert!(parse_dsn("").is_err());
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoFirebirdDriver::new();
        assert_eq!(driver.name(), "firebird");
    }

    #[test]
    fn test_error_with_code() {
        let err = PdoFirebirdError::new("table not found").with_code(335544345);
        assert_eq!(err.isc_code, 335544345);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PDO_FB_ATTR_DATE_FORMAT, 1000);
        assert_eq!(PDO_FB_TRANSACTION_ISOLATION_SERIALIZABLE, 2);
    }

    #[test]
    fn test_default_config() {
        let config = PdoFirebirdConfig::default();
        assert_eq!(config.dialect, 3);
        assert_eq!(config.charset, "UTF8");
        assert!(config.dbname.is_empty());
    }
}
