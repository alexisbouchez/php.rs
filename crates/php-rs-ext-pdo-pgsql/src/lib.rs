//! PDO PostgreSQL driver extension for php.rs
//!
//! Implements the PDO_pgsql driver, which provides PostgreSQL-specific DSN
//! parsing, attributes, and connection configuration.

use std::fmt;

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

// ---------------------------------------------------------------------------
// PdoPgsqlConnection — Connection struct
// ---------------------------------------------------------------------------

/// Represents a PDO PostgreSQL connection.
#[derive(Debug, Clone)]
pub struct PdoPgsqlConnection {
    /// The configuration used to create this connection.
    pub config: PdoPgsqlConfig,
    /// Whether the connection is active.
    pub connected: bool,
    /// Server version string.
    pub server_version: String,
    /// Whether prepared statements are disabled.
    pub disable_prepares: bool,
}

impl PdoPgsqlConnection {
    /// Create a new connection from a config.
    pub fn new(config: PdoPgsqlConfig) -> Self {
        Self {
            config,
            connected: true,
            server_version: "16.0-php-rs-stub".to_string(),
            disable_prepares: false,
        }
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
        let config = PdoPgsqlConfig {
            host: "pghost".to_string(),
            port: 5432,
            dbname: "pgdb".to_string(),
            user: Some("pguser".to_string()),
            password: None,
            sslmode: Some("prefer".to_string()),
        };
        let conn = PdoPgsqlConnection::new(config);
        assert!(conn.connected);
        assert_eq!(conn.config.host, "pghost");
        assert_eq!(conn.config.dbname, "pgdb");
        assert!(!conn.disable_prepares);
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
}
