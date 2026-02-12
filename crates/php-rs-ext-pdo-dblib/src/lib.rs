//! PDO DBLIB (MS SQL Server / Sybase) driver extension for php.rs
//!
//! Implements the PDO_dblib driver, which provides DSN parsing, attributes,
//! and connection configuration for FreeTDS-based SQL Server access.
//! Reference: php-src/ext/pdo_dblib/

use std::fmt;

// ---------------------------------------------------------------------------
// Constants — PDO DBLIB attributes
// ---------------------------------------------------------------------------

/// Use version-specific date formatting.
pub const PDO_DBLIB_ATTR_CONNECTION_TIMEOUT: i32 = 1000;
/// Query timeout in seconds.
pub const PDO_DBLIB_ATTR_QUERY_TIMEOUT: i32 = 1001;
/// Version of the TDS protocol to use.
pub const PDO_DBLIB_ATTR_TDS_VERSION: i32 = 1002;
/// Skip empty rowsets in multi-result queries.
pub const PDO_DBLIB_ATTR_SKIP_EMPTY_ROWSETS: i32 = 1003;
/// Stringify uniqueidentifier fields.
pub const PDO_DBLIB_ATTR_STRINGIFY_UNIQUEIDENTIFIER: i32 = 1004;
/// Convert datetime to string.
pub const PDO_DBLIB_ATTR_DATETIME_CONVERT: i32 = 1005;

// ---------------------------------------------------------------------------
// PdoDblibError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PdoDblibError {
    pub message: String,
}

impl PdoDblibError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for PdoDblibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDO dblib error: {}", self.message)
    }
}

impl std::error::Error for PdoDblibError {}

// ---------------------------------------------------------------------------
// PdoDblibConfig — DSN parsing
// ---------------------------------------------------------------------------

/// Configuration from a dblib PDO DSN.
///
/// DSN format: `dblib:host=xxx;dbname=xxx;charset=xxx;appname=xxx`
#[derive(Debug, Clone, PartialEq)]
pub struct PdoDblibConfig {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub charset: String,
    pub appname: String,
    pub tds_version: String,
}

impl Default for PdoDblibConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 1433,
            dbname: String::new(),
            charset: "UTF-8".to_string(),
            appname: String::new(),
            tds_version: "7.4".to_string(),
        }
    }
}

/// Parse a dblib PDO DSN parameter string.
pub fn parse_dsn(dsn: &str) -> Result<PdoDblibConfig, PdoDblibError> {
    let mut config = PdoDblibConfig::default();

    for part in dsn.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        match key {
            "host" | "server" => {
                // host can include port: host:port or host\instance
                if let Some((h, p)) = value.split_once(':') {
                    config.host = h.to_string();
                    if let Ok(port) = p.parse() {
                        config.port = port;
                    }
                } else if let Some((h, _instance)) = value.split_once('\\') {
                    config.host = h.to_string();
                } else {
                    config.host = value.to_string();
                }
            }
            "dbname" => config.dbname = value.to_string(),
            "charset" => config.charset = value.to_string(),
            "appname" => config.appname = value.to_string(),
            "version" | "tds_version" => config.tds_version = value.to_string(),
            _ => {}
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// PdoDblibDriver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PdoDblibDriver;

impl PdoDblibDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str {
        "dblib"
    }
}

impl Default for PdoDblibDriver {
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
        let config = parse_dsn("host=sqlserver.local;dbname=mydb").unwrap();
        assert_eq!(config.host, "sqlserver.local");
        assert_eq!(config.port, 1433);
        assert_eq!(config.dbname, "mydb");
    }

    #[test]
    fn test_parse_dsn_with_port() {
        let config = parse_dsn("host=server:1434;dbname=test").unwrap();
        assert_eq!(config.host, "server");
        assert_eq!(config.port, 1434);
    }

    #[test]
    fn test_parse_dsn_with_instance() {
        let config = parse_dsn("host=server\\SQLEXPRESS;dbname=test").unwrap();
        assert_eq!(config.host, "server");
    }

    #[test]
    fn test_parse_dsn_with_charset() {
        let config = parse_dsn("host=localhost;dbname=db;charset=ISO-8859-1").unwrap();
        assert_eq!(config.charset, "ISO-8859-1");
    }

    #[test]
    fn test_parse_dsn_empty() {
        let config = parse_dsn("").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 1433);
    }

    #[test]
    fn test_driver_name() {
        let driver = PdoDblibDriver::new();
        assert_eq!(driver.name(), "dblib");
    }

    #[test]
    fn test_constants() {
        assert_eq!(PDO_DBLIB_ATTR_CONNECTION_TIMEOUT, 1000);
        assert_eq!(PDO_DBLIB_ATTR_QUERY_TIMEOUT, 1001);
    }

    #[test]
    fn test_parse_dsn_server_alias() {
        let config = parse_dsn("server=myhost;dbname=db").unwrap();
        assert_eq!(config.host, "myhost");
    }

    #[test]
    fn test_default_config() {
        let config = PdoDblibConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 1433);
        assert_eq!(config.tds_version, "7.4");
        assert_eq!(config.charset, "UTF-8");
    }
}
