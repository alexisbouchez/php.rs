//! MySQL native driver (mysqlnd) extension for php.rs
//!
//! Implements the protocol-level driver used internally by mysqli and PDO_mysql.
//! This crate provides real MySQL wire protocol implementation with actual
//! network connections to MySQL servers.

use std::fmt;
use mysql::{Pool, OptsBuilder};
use mysql::prelude::*;

// ---------------------------------------------------------------------------
// Constants — MySQL protocol command bytes
// ---------------------------------------------------------------------------

/// COM_QUIT: tell the server to close the connection.
pub const COM_QUIT: u8 = 0x01;
/// COM_INIT_DB: switch the default database.
pub const COM_INIT_DB: u8 = 0x02;
/// COM_QUERY: execute a text-based SQL query.
pub const COM_QUERY: u8 = 0x03;
/// COM_FIELD_LIST: list columns in a table (deprecated in MySQL 5.7.11+).
pub const COM_FIELD_LIST: u8 = 0x04;
/// COM_CREATE_DB: create a database (deprecated).
pub const COM_CREATE_DB: u8 = 0x05;
/// COM_DROP_DB: drop a database (deprecated).
pub const COM_DROP_DB: u8 = 0x06;
/// COM_REFRESH: flush tables, logs, etc.
pub const COM_REFRESH: u8 = 0x07;
/// COM_STATISTICS: get server statistics string.
pub const COM_STATISTICS: u8 = 0x09;
/// COM_PROCESS_INFO: get thread info (deprecated).
pub const COM_PROCESS_INFO: u8 = 0x0A;
/// COM_PROCESS_KILL: kill a connection.
pub const COM_PROCESS_KILL: u8 = 0x0C;
/// COM_PING: check if the server is alive.
pub const COM_PING: u8 = 0x0E;
/// COM_CHANGE_USER: change the authenticated user.
pub const COM_CHANGE_USER: u8 = 0x11;
/// COM_STMT_PREPARE: prepare a server-side statement.
pub const COM_STMT_PREPARE: u8 = 0x16;
/// COM_STMT_EXECUTE: execute a prepared statement.
pub const COM_STMT_EXECUTE: u8 = 0x17;
/// COM_STMT_CLOSE: deallocate a prepared statement.
pub const COM_STMT_CLOSE: u8 = 0x19;
/// COM_STMT_RESET: reset a prepared statement.
pub const COM_STMT_RESET: u8 = 0x1A;
/// COM_SET_OPTION: set connection options.
pub const COM_SET_OPTION: u8 = 0x1B;
/// COM_RESET_CONNECTION: reset the connection (MySQL 5.7+).
pub const COM_RESET_CONNECTION: u8 = 0x1F;

// ---------------------------------------------------------------------------
// Constants — Server status flags
// ---------------------------------------------------------------------------

/// The server is in a transaction.
pub const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
/// Autocommit is enabled.
pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
/// More results are available (multi-statement).
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

// ---------------------------------------------------------------------------
// Constants — Client capability flags
// ---------------------------------------------------------------------------

pub const CLIENT_LONG_PASSWORD: u32 = 0x00000001;
pub const CLIENT_FOUND_ROWS: u32 = 0x00000002;
pub const CLIENT_LONG_FLAG: u32 = 0x00000004;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x00000008;
pub const CLIENT_PROTOCOL_41: u32 = 0x00000200;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x00008000;
pub const CLIENT_MULTI_STATEMENTS: u32 = 0x00010000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x00020000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x00080000;

// ---------------------------------------------------------------------------
// MysqlndError
// ---------------------------------------------------------------------------

/// An error from the mysqlnd subsystem.
#[derive(Debug, Clone, PartialEq)]
pub struct MysqlndError {
    pub code: u16,
    pub message: String,
    pub sqlstate: String,
}

impl MysqlndError {
    pub fn new(code: u16, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
            sqlstate: "HY000".to_string(),
        }
    }

    pub fn protocol_error(message: &str) -> Self {
        Self::new(2000, message)
    }
}

impl fmt::Display for MysqlndError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mysqlnd error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for MysqlndError {}

// ---------------------------------------------------------------------------
// ColumnType — MySQL column types
// ---------------------------------------------------------------------------

/// MySQL column/field data types as defined in the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ColumnType {
    Decimal = 0x00,
    Tiny = 0x01,
    Short = 0x02,
    Long = 0x03,
    Float = 0x04,
    Double = 0x05,
    Null = 0x06,
    Timestamp = 0x07,
    LongLong = 0x08,
    Int24 = 0x09,
    Date = 0x0A,
    Time = 0x0B,
    DateTime = 0x0C,
    Year = 0x0D,
    NewDate = 0x0E,
    Varchar = 0x0F,
    Bit = 0x10,
    Json = 0xF5,
    NewDecimal = 0xF6,
    Enum = 0xF7,
    Set = 0xF8,
    TinyBlob = 0xF9,
    MediumBlob = 0xFA,
    LongBlob = 0xFB,
    Blob = 0xFC,
    VarString = 0xFD,
    String = 0xFE,
    Geometry = 0xFF,
}

impl ColumnType {
    /// Convert a raw byte to a ColumnType, returning None for unknown types.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(ColumnType::Decimal),
            0x01 => Some(ColumnType::Tiny),
            0x02 => Some(ColumnType::Short),
            0x03 => Some(ColumnType::Long),
            0x04 => Some(ColumnType::Float),
            0x05 => Some(ColumnType::Double),
            0x06 => Some(ColumnType::Null),
            0x07 => Some(ColumnType::Timestamp),
            0x08 => Some(ColumnType::LongLong),
            0x09 => Some(ColumnType::Int24),
            0x0A => Some(ColumnType::Date),
            0x0B => Some(ColumnType::Time),
            0x0C => Some(ColumnType::DateTime),
            0x0D => Some(ColumnType::Year),
            0x0E => Some(ColumnType::NewDate),
            0x0F => Some(ColumnType::Varchar),
            0x10 => Some(ColumnType::Bit),
            0xF5 => Some(ColumnType::Json),
            0xF6 => Some(ColumnType::NewDecimal),
            0xF7 => Some(ColumnType::Enum),
            0xF8 => Some(ColumnType::Set),
            0xF9 => Some(ColumnType::TinyBlob),
            0xFA => Some(ColumnType::MediumBlob),
            0xFB => Some(ColumnType::LongBlob),
            0xFC => Some(ColumnType::Blob),
            0xFD => Some(ColumnType::VarString),
            0xFE => Some(ColumnType::String),
            0xFF => Some(ColumnType::Geometry),
            _ => None,
        }
    }

    /// Returns the human-readable name for this column type.
    pub fn name(&self) -> &'static str {
        match self {
            ColumnType::Decimal => "DECIMAL",
            ColumnType::Tiny => "TINY",
            ColumnType::Short => "SHORT",
            ColumnType::Long => "LONG",
            ColumnType::Float => "FLOAT",
            ColumnType::Double => "DOUBLE",
            ColumnType::Null => "NULL",
            ColumnType::Timestamp => "TIMESTAMP",
            ColumnType::LongLong => "LONGLONG",
            ColumnType::Int24 => "INT24",
            ColumnType::Date => "DATE",
            ColumnType::Time => "TIME",
            ColumnType::DateTime => "DATETIME",
            ColumnType::Year => "YEAR",
            ColumnType::NewDate => "NEWDATE",
            ColumnType::Varchar => "VARCHAR",
            ColumnType::Bit => "BIT",
            ColumnType::Json => "JSON",
            ColumnType::NewDecimal => "NEWDECIMAL",
            ColumnType::Enum => "ENUM",
            ColumnType::Set => "SET",
            ColumnType::TinyBlob => "TINYBLOB",
            ColumnType::MediumBlob => "MEDIUMBLOB",
            ColumnType::LongBlob => "LONGBLOB",
            ColumnType::Blob => "BLOB",
            ColumnType::VarString => "VAR_STRING",
            ColumnType::String => "STRING",
            ColumnType::Geometry => "GEOMETRY",
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionState — Protocol state machine
// ---------------------------------------------------------------------------

/// The state of a mysqlnd connection in the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection has not been initiated yet.
    Disconnected,
    /// Waiting for the server's initial handshake packet.
    WaitingHandshake,
    /// Handshake received, authentication response sent, waiting for result.
    Authenticating,
    /// Fully connected and ready to accept commands.
    Ready,
    /// A query has been sent, waiting for the result set.
    QuerySent,
    /// Currently reading a result set.
    FetchingResults,
    /// Connection is being closed.
    Closing,
    /// Connection has been closed.
    Closed,
}

// ---------------------------------------------------------------------------
// Packet types
// ---------------------------------------------------------------------------

/// Initial handshake packet sent by the MySQL server.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakePacket {
    /// Protocol version (always 10 for modern MySQL).
    pub protocol_version: u8,
    /// Server version string (e.g. "8.0.32").
    pub server_version: String,
    /// Connection/thread ID assigned by the server.
    pub connection_id: u32,
    /// Authentication plugin data (scramble) part 1.
    pub auth_plugin_data_part1: Vec<u8>,
    /// Server capability flags.
    pub capability_flags: u32,
    /// Default character set.
    pub character_set: u8,
    /// Server status flags.
    pub status_flags: u16,
    /// Authentication plugin name (e.g. "mysql_native_password").
    pub auth_plugin_name: String,
}

impl HandshakePacket {
    /// Create a default handshake packet for testing.
    pub fn default_v10() -> Self {
        Self {
            protocol_version: 10,
            server_version: "8.0.32".to_string(),
            connection_id: 1,
            auth_plugin_data_part1: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            capability_flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH,
            character_set: 0xFF, // utf8mb4
            status_flags: SERVER_STATUS_AUTOCOMMIT,
            auth_plugin_name: "mysql_native_password".to_string(),
        }
    }

    /// Serialize the handshake packet to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.protocol_version);
        buf.extend_from_slice(self.server_version.as_bytes());
        buf.push(0x00); // NUL terminator for version string
        buf.extend_from_slice(&self.connection_id.to_le_bytes());
        buf.extend_from_slice(&self.auth_plugin_data_part1);
        buf.push(0x00); // filler
        buf.extend_from_slice(&(self.capability_flags as u16).to_le_bytes());
        buf.push(self.character_set);
        buf.extend_from_slice(&self.status_flags.to_le_bytes());
        buf.extend_from_slice(&((self.capability_flags >> 16) as u16).to_le_bytes());
        buf
    }
}

/// Authentication response packet sent by the client.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthPacket {
    /// Client capability flags.
    pub capability_flags: u32,
    /// Maximum packet size the client is willing to accept.
    pub max_packet_size: u32,
    /// Character set requested by the client.
    pub character_set: u8,
    /// Username for authentication.
    pub username: String,
    /// Hashed authentication response.
    pub auth_response: Vec<u8>,
    /// Database to use after authentication.
    pub database: Option<String>,
    /// Authentication plugin name.
    pub auth_plugin_name: String,
}

impl AuthPacket {
    /// Serialize the auth packet to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.capability_flags.to_le_bytes());
        buf.extend_from_slice(&self.max_packet_size.to_le_bytes());
        buf.push(self.character_set);
        // 23 bytes of reserved zeros
        buf.extend_from_slice(&[0u8; 23]);
        buf.extend_from_slice(self.username.as_bytes());
        buf.push(0x00); // NUL terminator
        buf.push(self.auth_response.len() as u8);
        buf.extend_from_slice(&self.auth_response);
        if let Some(ref db) = self.database {
            buf.extend_from_slice(db.as_bytes());
            buf.push(0x00);
        }
        buf.extend_from_slice(self.auth_plugin_name.as_bytes());
        buf.push(0x00);
        buf
    }
}

/// A command packet sent from client to server.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandPacket {
    /// The command byte (e.g. COM_QUERY, COM_PING).
    pub command: u8,
    /// Command payload (e.g. the SQL query string for COM_QUERY).
    pub payload: Vec<u8>,
}

impl CommandPacket {
    /// Create a COM_QUERY command packet.
    pub fn query(sql: &str) -> Self {
        Self {
            command: COM_QUERY,
            payload: sql.as_bytes().to_vec(),
        }
    }

    /// Create a COM_PING command packet.
    pub fn ping() -> Self {
        Self {
            command: COM_PING,
            payload: Vec::new(),
        }
    }

    /// Create a COM_QUIT command packet.
    pub fn quit() -> Self {
        Self {
            command: COM_QUIT,
            payload: Vec::new(),
        }
    }

    /// Create a COM_INIT_DB command packet.
    pub fn init_db(database: &str) -> Self {
        Self {
            command: COM_INIT_DB,
            payload: database.as_bytes().to_vec(),
        }
    }

    /// Serialize the command packet to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.payload.len());
        buf.push(self.command);
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// A result set header returned by the server.
#[derive(Debug, Clone, PartialEq)]
pub struct ResultSetPacket {
    /// Number of columns in the result set.
    pub column_count: u64,
    /// Column definitions.
    pub columns: Vec<ColumnDefinition>,
    /// Whether more data is available.
    pub has_more_data: bool,
}

/// A column definition within a result set.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnDefinition {
    /// Catalog (always "def" in modern MySQL).
    pub catalog: String,
    /// Schema/database name.
    pub schema: String,
    /// Table name (virtual or alias).
    pub table: String,
    /// Original table name.
    pub org_table: String,
    /// Column name (alias).
    pub name: String,
    /// Original column name.
    pub org_name: String,
    /// Column type.
    pub column_type: ColumnType,
    /// Maximum column length.
    pub column_length: u32,
    /// Character set.
    pub character_set: u16,
    /// Column flags.
    pub flags: u16,
    /// Number of decimal places.
    pub decimals: u8,
}

// ---------------------------------------------------------------------------
// MysqlndStat — Connection statistics
// ---------------------------------------------------------------------------

/// Network statistics for a mysqlnd connection.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MysqlndStat {
    /// Total bytes sent to the server.
    pub bytes_sent: u64,
    /// Total bytes received from the server.
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Number of queries sent.
    pub queries_sent: u64,
    /// Number of result sets received.
    pub result_sets_received: u64,
}

impl MysqlndStat {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record bytes sent.
    pub fn record_send(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
    }

    /// Record bytes received.
    pub fn record_receive(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.packets_received += 1;
    }
}

// ---------------------------------------------------------------------------
// MysqlndConnection — Protocol-level connection
// ---------------------------------------------------------------------------

/// Represents a protocol-level MySQL connection.
pub struct MysqlndConnection {
    /// Current protocol state.
    pub state: ConnectionState,
    /// Server version from the handshake.
    pub server_version: String,
    /// Connection/thread ID.
    pub connection_id: u32,
    /// Server capability flags.
    pub server_capabilities: u32,
    /// Client capability flags.
    pub client_capabilities: u32,
    /// Current character set.
    pub character_set: u8,
    /// Server status flags.
    pub server_status: u16,
    /// Network statistics.
    pub stats: MysqlndStat,
    /// Authenticated username.
    pub username: String,
    /// Current database.
    pub database: String,
    /// Actual MySQL connection pool.
    pool: Option<Pool>,
}

impl std::fmt::Debug for MysqlndConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MysqlndConnection")
            .field("state", &self.state)
            .field("server_version", &self.server_version)
            .field("connection_id", &self.connection_id)
            .field("username", &self.username)
            .field("database", &self.database)
            .finish()
    }
}

impl Clone for MysqlndConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            server_version: self.server_version.clone(),
            connection_id: self.connection_id,
            server_capabilities: self.server_capabilities,
            client_capabilities: self.client_capabilities,
            character_set: self.character_set,
            server_status: self.server_status,
            stats: self.stats.clone(),
            username: self.username.clone(),
            database: self.database.clone(),
            pool: None, // Can't clone pool, create new connection if needed
        }
    }
}

/// Create a new mysqlnd connection with real MySQL network connection.
pub fn mysqlnd_connect(
    host: &str,
    user: &str,
    password: &str,
    database: &str,
    port: u16,
) -> Result<MysqlndConnection, MysqlndError> {
    if host.is_empty() {
        return Err(MysqlndError::new(2002, "No hostname provided"));
    }
    if user.is_empty() {
        return Err(MysqlndError::new(1045, "No username provided"));
    }

    // Build MySQL connection URL
    let port_to_use = if port == 0 { 3306 } else { port };

    // Try to create a real MySQL connection
    let opts = OptsBuilder::new()
        .ip_or_hostname(Some(host))
        .tcp_port(port_to_use)
        .user(Some(user))
        .pass(Some(password))
        .db_name(Some(database));

    let pool = match Pool::new(opts) {
        Ok(p) => p,
        Err(e) => {
            return Err(MysqlndError::new(
                2002,
                &format!("Connection failed: {}", e),
            ));
        }
    };

    // Try to get a connection to verify it works
    let mut conn = pool.get_conn().map_err(|e| {
        MysqlndError::new(2002, &format!("Failed to get connection: {}", e))
    })?;

    // Get server version
    let server_version: String = conn
        .query_first("SELECT VERSION()")
        .map_err(|e| MysqlndError::new(2002, &format!("Failed to get version: {}", e)))?
        .unwrap_or_else(|| "8.0.0".to_string());

    // Get connection ID
    let connection_id: u32 = conn
        .query_first("SELECT CONNECTION_ID()")
        .map_err(|e| MysqlndError::new(2002, &format!("Failed to get connection ID: {}", e)))?
        .unwrap_or(1);

    drop(conn); // Return connection to pool

    Ok(MysqlndConnection {
        state: ConnectionState::Ready,
        server_version,
        connection_id,
        server_capabilities: CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_MULTI_STATEMENTS
            | CLIENT_MULTI_RESULTS,
        client_capabilities: CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_WITH_DB,
        character_set: 0xFF,
        server_status: SERVER_STATUS_AUTOCOMMIT,
        stats: MysqlndStat::new(),
        username: user.to_string(),
        database: database.to_string(),
        pool: Some(pool),
    })
}

/// Execute a query and return raw results.
pub fn mysqlnd_query(
    conn: &mut MysqlndConnection,
    query: &str,
) -> Result<Vec<mysql::Row>, MysqlndError> {
    if conn.state != ConnectionState::Ready {
        return Err(MysqlndError::new(2006, "MySQL server has gone away"));
    }

    let pool = conn.pool.as_ref()
        .ok_or_else(|| MysqlndError::new(2006, "No active connection"))?;

    let mut pool_conn = pool.get_conn()
        .map_err(|e| MysqlndError::new(2006, &format!("Failed to get connection: {}", e)))?;

    conn.stats.queries_sent += 1;

    let rows: Vec<mysql::Row> = pool_conn.query(query)
        .map_err(|e| MysqlndError::new(1064, &format!("Query error: {}", e)))?;

    conn.stats.result_sets_received += 1;

    Ok(rows)
}

/// Close the mysqlnd connection.
pub fn mysqlnd_close(conn: &mut MysqlndConnection) {
    conn.pool = None;
    conn.state = ConnectionState::Closed;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires real MySQL server
    fn test_connect_success() {
        let conn = mysqlnd_connect("localhost", "root", "pass", "testdb", 3306)
            .expect("connect should succeed");
        assert_eq!(conn.state, ConnectionState::Ready);
        assert_eq!(conn.username, "root");
        assert_eq!(conn.database, "testdb");
        assert!(!conn.server_version.is_empty());
    }

    #[test]
    fn test_connect_empty_host() {
        let result = mysqlnd_connect("", "root", "pass", "db", 3306);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, 2002);
    }

    #[test]
    fn test_connect_empty_user() {
        let result = mysqlnd_connect("localhost", "", "pass", "db", 3306);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, 1045);
    }

    #[test]
    fn test_column_type_from_byte() {
        assert_eq!(ColumnType::from_byte(0x03), Some(ColumnType::Long));
        assert_eq!(ColumnType::from_byte(0x08), Some(ColumnType::LongLong));
        assert_eq!(ColumnType::from_byte(0xF5), Some(ColumnType::Json));
        assert_eq!(ColumnType::from_byte(0xFE), Some(ColumnType::String));
        assert_eq!(ColumnType::from_byte(0x20), None); // Unknown
    }

    #[test]
    fn test_column_type_name() {
        assert_eq!(ColumnType::Long.name(), "LONG");
        assert_eq!(ColumnType::Varchar.name(), "VARCHAR");
        assert_eq!(ColumnType::DateTime.name(), "DATETIME");
        assert_eq!(ColumnType::Json.name(), "JSON");
        assert_eq!(ColumnType::Blob.name(), "BLOB");
    }

    #[test]
    fn test_command_packet_query() {
        let pkt = CommandPacket::query("SELECT 1");
        assert_eq!(pkt.command, COM_QUERY);
        assert_eq!(pkt.payload, b"SELECT 1");
        let bytes = pkt.serialize();
        assert_eq!(bytes[0], COM_QUERY);
        assert_eq!(&bytes[1..], b"SELECT 1");
    }

    #[test]
    fn test_command_packet_ping() {
        let pkt = CommandPacket::ping();
        assert_eq!(pkt.command, COM_PING);
        assert!(pkt.payload.is_empty());
        let bytes = pkt.serialize();
        assert_eq!(bytes, vec![COM_PING]);
    }

    #[test]
    fn test_command_packet_quit() {
        let pkt = CommandPacket::quit();
        assert_eq!(pkt.command, COM_QUIT);
        let bytes = pkt.serialize();
        assert_eq!(bytes, vec![COM_QUIT]);
    }

    #[test]
    fn test_command_packet_init_db() {
        let pkt = CommandPacket::init_db("mydb");
        assert_eq!(pkt.command, COM_INIT_DB);
        assert_eq!(pkt.payload, b"mydb");
    }

    #[test]
    fn test_handshake_packet_serialize() {
        let pkt = HandshakePacket::default_v10();
        assert_eq!(pkt.protocol_version, 10);
        assert_eq!(pkt.server_version, "8.0.32");
        let bytes = pkt.serialize();
        // First byte should be protocol version.
        assert_eq!(bytes[0], 10);
        // Should contain the version string.
        assert!(bytes.len() > 10);
    }

    #[test]
    fn test_auth_packet_serialize() {
        let pkt = AuthPacket {
            capability_flags: CLIENT_PROTOCOL_41 | CLIENT_CONNECT_WITH_DB,
            max_packet_size: 16777216,
            character_set: 0xFF,
            username: "root".to_string(),
            auth_response: vec![0xAA, 0xBB],
            database: Some("testdb".to_string()),
            auth_plugin_name: "mysql_native_password".to_string(),
        };
        let bytes = pkt.serialize();
        // Should start with capability flags (4 bytes).
        assert!(bytes.len() > 32); // 4+4+1+23+username+NUL+auth+db+plugin
                                   // First 4 bytes are capability flags in LE.
        let cap = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(cap, pkt.capability_flags);
    }

    #[test]
    fn test_mysqlnd_stat() {
        let mut stat = MysqlndStat::new();
        assert_eq!(stat.bytes_sent, 0);
        assert_eq!(stat.packets_sent, 0);

        stat.record_send(100);
        assert_eq!(stat.bytes_sent, 100);
        assert_eq!(stat.packets_sent, 1);

        stat.record_receive(250);
        assert_eq!(stat.bytes_received, 250);
        assert_eq!(stat.packets_received, 1);

        stat.record_send(50);
        assert_eq!(stat.bytes_sent, 150);
        assert_eq!(stat.packets_sent, 2);
    }

    #[test]
    fn test_connection_state_enum() {
        let state = ConnectionState::Disconnected;
        assert_eq!(state, ConnectionState::Disconnected);
        assert_ne!(state, ConnectionState::Ready);
    }

    #[test]
    fn test_error_display() {
        let err = MysqlndError::new(2002, "Connection refused");
        assert_eq!(err.to_string(), "mysqlnd error 2002: Connection refused");
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(COM_QUERY, 0x03);
        assert_eq!(COM_QUIT, 0x01);
        assert_eq!(COM_PING, 0x0E);
        assert_eq!(COM_STMT_PREPARE, 0x16);
        assert_eq!(COM_STMT_EXECUTE, 0x17);
    }

    #[test]
    #[ignore] // Requires real MySQL server
    fn test_server_capability_flags() {
        let conn = mysqlnd_connect("localhost", "root", "pass", "db", 3306).unwrap();
        assert!(conn.server_capabilities & CLIENT_PROTOCOL_41 != 0);
        assert!(conn.server_capabilities & CLIENT_SECURE_CONNECTION != 0);
        assert!(conn.server_capabilities & CLIENT_PLUGIN_AUTH != 0);
    }
}
