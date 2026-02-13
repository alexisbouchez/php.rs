//! PDO MySQL driver extension for php.rs
//!
//! Implements the PDO_mysql driver, which provides MySQL-specific DSN parsing,
//! attributes, and connection configuration. This sits on top of the PDO
//! abstraction layer and the mysqlnd native driver.

use std::fmt;

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
// PdoMysqlDriver — Driver struct
// ---------------------------------------------------------------------------

/// The PDO MySQL driver.
///
/// In the full implementation, this would implement the `PdoDriver` trait
/// from the `php-rs-ext-pdo` crate.
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

// ---------------------------------------------------------------------------
// PdoMysqlConnection — Connection struct
// ---------------------------------------------------------------------------

/// Represents a PDO MySQL connection.
#[derive(Debug, Clone)]
pub struct PdoMysqlConnection {
    /// The configuration used to create this connection.
    pub config: PdoMysqlConfig,
    /// Whether the connection is active.
    pub connected: bool,
    /// Server version string.
    pub server_version: String,
    /// Whether buffered queries are enabled.
    pub buffered_queries: bool,
    /// Init command to run on connect.
    pub init_command: Option<String>,
}

impl PdoMysqlConnection {
    /// Create a new connection from a config.
    pub fn new(config: PdoMysqlConfig) -> Self {
        Self {
            config,
            connected: true,
            server_version: "8.0.0-php-rs-stub".to_string(),
            buffered_queries: true,
            init_command: None,
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
    fn test_connection_from_config() {
        let config = PdoMysqlConfig {
            host: "myhost".to_string(),
            port: 3308,
            dbname: "mydb".to_string(),
            charset: "latin1".to_string(),
            unix_socket: None,
        };
        let conn = PdoMysqlConnection::new(config.clone());
        assert!(conn.connected);
        assert_eq!(conn.config.host, "myhost");
        assert_eq!(conn.config.port, 3308);
        assert!(conn.buffered_queries);
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
}
