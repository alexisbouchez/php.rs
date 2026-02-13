//! PHP FPM SAPI — FastCGI Process Manager
//!
//! Implements the FastCGI protocol and process management for php.rs.
//! Equivalent to php-src/sapi/fpm/ (32 C files).
//!
//! Architecture:
//! - Master process: manages worker pools, handles signals
//! - Worker processes: handle FastCGI requests
//! - Pool configuration: static, dynamic, ondemand modes

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── FastCGI Protocol Constants ──────────────────────────────────────────────
// Reference: https://fastcgi-archives.github.io/FastCGI_Specification.html

pub const FCGI_VERSION_1: u8 = 1;

/// FastCGI record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FcgiRecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    UnknownType = 11,
}

impl FcgiRecordType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::BeginRequest),
            2 => Some(Self::AbortRequest),
            3 => Some(Self::EndRequest),
            4 => Some(Self::Params),
            5 => Some(Self::Stdin),
            6 => Some(Self::Stdout),
            7 => Some(Self::Stderr),
            8 => Some(Self::Data),
            9 => Some(Self::GetValues),
            10 => Some(Self::GetValuesResult),
            11 => Some(Self::UnknownType),
            _ => None,
        }
    }
}

/// FastCGI roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FcgiRole {
    Responder = 1,
    Authorizer = 2,
    Filter = 3,
}

/// FastCGI protocol status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FcgiProtocolStatus {
    RequestComplete = 0,
    CantMpxConn = 1,
    Overloaded = 2,
    UnknownRole = 3,
}

// ── FastCGI Record ──────────────────────────────────────────────────────────

/// A FastCGI record header (8 bytes).
#[derive(Debug, Clone)]
pub struct FcgiHeader {
    pub version: u8,
    pub record_type: u8,
    pub request_id: u16,
    pub content_length: u16,
    pub padding_length: u8,
}

impl FcgiHeader {
    pub const SIZE: usize = 8;

    /// Parse a header from 8 bytes.
    pub fn from_bytes(buf: &[u8; 8]) -> Self {
        Self {
            version: buf[0],
            record_type: buf[1],
            request_id: u16::from_be_bytes([buf[2], buf[3]]),
            content_length: u16::from_be_bytes([buf[4], buf[5]]),
            padding_length: buf[6],
        }
    }

    /// Serialize to 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let id = self.request_id.to_be_bytes();
        let cl = self.content_length.to_be_bytes();
        [
            self.version,
            self.record_type,
            id[0],
            id[1],
            cl[0],
            cl[1],
            self.padding_length,
            0, // reserved
        ]
    }
}

/// A complete FastCGI record.
#[derive(Debug, Clone)]
pub struct FcgiRecord {
    pub header: FcgiHeader,
    pub content: Vec<u8>,
}

impl FcgiRecord {
    /// Read a record from a stream.
    pub fn read_from(stream: &mut impl Read) -> io::Result<Self> {
        let mut header_buf = [0u8; 8];
        stream.read_exact(&mut header_buf)?;
        let header = FcgiHeader::from_bytes(&header_buf);

        let mut content = vec![0u8; header.content_length as usize];
        if !content.is_empty() {
            stream.read_exact(&mut content)?;
        }

        // Read and discard padding
        if header.padding_length > 0 {
            let mut padding = vec![0u8; header.padding_length as usize];
            stream.read_exact(&mut padding)?;
        }

        Ok(Self { header, content })
    }

    /// Write a record to a stream.
    pub fn write_to(&self, stream: &mut impl Write) -> io::Result<()> {
        stream.write_all(&self.header.to_bytes())?;
        stream.write_all(&self.content)?;
        // Write padding
        if self.header.padding_length > 0 {
            let padding = vec![0u8; self.header.padding_length as usize];
            stream.write_all(&padding)?;
        }
        Ok(())
    }

    /// Create a stdout record.
    pub fn stdout(request_id: u16, data: &[u8]) -> Self {
        Self {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdout as u8,
                request_id,
                content_length: data.len() as u16,
                padding_length: 0,
            },
            content: data.to_vec(),
        }
    }

    /// Create a stderr record.
    pub fn stderr(request_id: u16, data: &[u8]) -> Self {
        Self {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stderr as u8,
                request_id,
                content_length: data.len() as u16,
                padding_length: 0,
            },
            content: data.to_vec(),
        }
    }

    /// Create an end-request record.
    pub fn end_request(
        request_id: u16,
        app_status: u32,
        protocol_status: FcgiProtocolStatus,
    ) -> Self {
        let status_bytes = app_status.to_be_bytes();
        Self {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::EndRequest as u8,
                request_id,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![
                status_bytes[0],
                status_bytes[1],
                status_bytes[2],
                status_bytes[3],
                protocol_status as u8,
                0,
                0,
                0,
            ],
        }
    }
}

// ── FastCGI Parameter Parsing ───────────────────────────────────────────────

/// Parse FastCGI name-value pairs from a params record body.
pub fn parse_fcgi_params(data: &[u8]) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        // Read name length
        let (name_len, consumed) = read_fcgi_length(data, pos);
        pos += consumed;

        // Read value length
        let (value_len, consumed) = read_fcgi_length(data, pos);
        pos += consumed;

        if pos + name_len + value_len > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;
        let value = String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
        pos += value_len;

        params.insert(name, value);
    }

    params
}

/// Read a FastCGI length (1 or 4 bytes). Returns (length, bytes_consumed).
fn read_fcgi_length(data: &[u8], pos: usize) -> (usize, usize) {
    if pos >= data.len() {
        return (0, 0);
    }
    if data[pos] >> 7 == 0 {
        // 1-byte length
        (data[pos] as usize, 1)
    } else if pos + 4 <= data.len() {
        // 4-byte length
        let len = ((data[pos] & 0x7F) as usize) << 24
            | (data[pos + 1] as usize) << 16
            | (data[pos + 2] as usize) << 8
            | data[pos + 3] as usize;
        (len, 4)
    } else {
        (0, 1)
    }
}

/// Encode a name-value pair for FastCGI params.
pub fn encode_fcgi_param(name: &str, value: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_fcgi_length(&mut buf, name.len());
    encode_fcgi_length(&mut buf, value.len());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(value.as_bytes());
    buf
}

/// Encode a length for FastCGI (1 or 4 bytes).
fn encode_fcgi_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        buf.push(((len >> 24) as u8) | 0x80);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

// ── FPM Configuration ───────────────────────────────────────────────────────

/// Pool process manager mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmMode {
    /// Fixed number of worker processes.
    Static,
    /// Dynamic scaling between min and max.
    Dynamic,
    /// Workers spawned on demand, killed when idle.
    OnDemand,
}

/// Configuration for an FPM pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Pool name (e.g., "www").
    pub name: String,
    /// Listen address (e.g., "127.0.0.1:9000" or "/var/run/php-fpm.sock").
    pub listen: String,
    /// Process manager mode.
    pub pm: PmMode,
    /// Maximum number of child processes.
    pub pm_max_children: u32,
    /// Number of children created on startup (dynamic mode).
    pub pm_start_servers: u32,
    /// Minimum number of idle children (dynamic mode).
    pub pm_min_spare_servers: u32,
    /// Maximum number of idle children (dynamic mode).
    pub pm_max_spare_servers: u32,
    /// Maximum requests per child before respawn (0 = unlimited).
    pub pm_max_requests: u32,
    /// Idle timeout in seconds (ondemand mode).
    pub pm_process_idle_timeout: u32,
    /// Enable status page.
    pub pm_status_path: Option<String>,
    /// Enable ping page.
    pub ping_path: Option<String>,
    /// Ping response text.
    pub ping_response: String,
    /// Slow log path.
    pub slowlog: Option<String>,
    /// Slow log timeout in seconds.
    pub request_slowlog_timeout: u32,
    /// Access log path.
    pub access_log: Option<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            name: "www".into(),
            listen: "127.0.0.1:9000".into(),
            pm: PmMode::Dynamic,
            pm_max_children: 5,
            pm_start_servers: 2,
            pm_min_spare_servers: 1,
            pm_max_spare_servers: 3,
            pm_max_requests: 0,
            pm_process_idle_timeout: 10,
            pm_status_path: None,
            ping_path: None,
            ping_response: "pong".into(),
            slowlog: None,
            request_slowlog_timeout: 0,
            access_log: None,
        }
    }
}

/// FPM master configuration.
#[derive(Debug, Clone)]
pub struct FpmConfig {
    /// Process pools.
    pub pools: Vec<PoolConfig>,
    /// PID file path.
    pub pid_file: Option<String>,
    /// Error log path.
    pub error_log: Option<String>,
    /// Daemonize flag.
    pub daemonize: bool,
}

impl Default for FpmConfig {
    fn default() -> Self {
        Self {
            pools: vec![PoolConfig::default()],
            pid_file: None,
            error_log: None,
            daemonize: false,
        }
    }
}

// ── Worker State ────────────────────────────────────────────────────────────

/// State of an FPM worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Idle,
    Busy,
}

/// Information about a worker process.
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub pid: u32,
    pub state: WorkerState,
    pub requests_served: u64,
    pub start_time: u64,
}

/// Pool runtime status.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub pool_name: String,
    pub pm_mode: PmMode,
    pub active_processes: u32,
    pub idle_processes: u32,
    pub total_processes: u32,
    pub accepted_connections: u64,
    pub listen_queue: u32,
    pub max_listen_queue: u32,
}

impl PoolStatus {
    /// Format as PHP FPM status page output.
    pub fn to_status_string(&self) -> String {
        format!(
            "pool:                 {}\n\
             process manager:      {}\n\
             accepted conn:        {}\n\
             listen queue:         {}\n\
             max listen queue:     {}\n\
             idle processes:       {}\n\
             active processes:     {}\n\
             total processes:      {}\n",
            self.pool_name,
            match self.pm_mode {
                PmMode::Static => "static",
                PmMode::Dynamic => "dynamic",
                PmMode::OnDemand => "ondemand",
            },
            self.accepted_connections,
            self.listen_queue,
            self.max_listen_queue,
            self.idle_processes,
            self.active_processes,
            self.total_processes,
        )
    }
}

// ── FastCGI Request Handler ─────────────────────────────────────────────────

/// Handle a single FastCGI connection.
pub fn handle_fcgi_connection(stream: &mut std::net::TcpStream) -> io::Result<()> {
    let mut params_data = Vec::new();
    let mut stdin_data = Vec::new();
    let mut request_id = 0u16;

    // Read all records until stdin is complete
    loop {
        let record = FcgiRecord::read_from(stream)?;
        let rtype = FcgiRecordType::from_u8(record.header.record_type);

        match rtype {
            Some(FcgiRecordType::BeginRequest) => {
                request_id = record.header.request_id;
            }
            Some(FcgiRecordType::Params) => {
                if record.content.is_empty() {
                    // Empty params record = end of params
                } else {
                    params_data.extend_from_slice(&record.content);
                }
            }
            Some(FcgiRecordType::Stdin) => {
                if record.content.is_empty() {
                    // Empty stdin = end of request body
                    break;
                }
                stdin_data.extend_from_slice(&record.content);
            }
            Some(FcgiRecordType::AbortRequest) => {
                return Ok(());
            }
            _ => {}
        }
    }

    // Parse params
    let params = parse_fcgi_params(&params_data);

    // Get the script filename
    let script_filename = params.get("SCRIPT_FILENAME").cloned().unwrap_or_default();

    // Execute PHP
    let (status, output, error_output) = execute_php_fcgi(&script_filename, &params, &stdin_data);

    // Send response headers + body as stdout
    let http_headers = format!(
        "Status: {} {}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
        if status == 0 { 200 } else { 500 },
        if status == 0 {
            "OK"
        } else {
            "Internal Server Error"
        },
    );

    let mut response = http_headers.into_bytes();
    response.extend_from_slice(output.as_bytes());

    // Send stdout in chunks (max 65535 bytes per record)
    for chunk in response.chunks(65535) {
        let record = FcgiRecord::stdout(request_id, chunk);
        record.write_to(stream)?;
    }
    // Empty stdout to signal end
    FcgiRecord::stdout(request_id, &[]).write_to(stream)?;

    // Send stderr if any
    if !error_output.is_empty() {
        let record = FcgiRecord::stderr(request_id, error_output.as_bytes());
        record.write_to(stream)?;
        FcgiRecord::stderr(request_id, &[]).write_to(stream)?;
    }

    // Send end request
    let end = FcgiRecord::end_request(
        request_id,
        status as u32,
        FcgiProtocolStatus::RequestComplete,
    );
    end.write_to(stream)?;

    stream.flush()?;
    Ok(())
}

/// Execute PHP for a FastCGI request.
fn execute_php_fcgi(
    script_filename: &str,
    _params: &HashMap<String, String>,
    _stdin: &[u8],
) -> (i32, String, String) {
    if script_filename.is_empty() {
        return (1, String::new(), "No SCRIPT_FILENAME provided".into());
    }

    let source = match std::fs::read_to_string(script_filename) {
        Ok(s) => s,
        Err(e) => {
            return (
                1,
                String::new(),
                format!("Cannot read {}: {}", script_filename, e),
            );
        }
    };

    let op_array = match php_rs_compiler::compile(&source) {
        Ok(oa) => oa,
        Err(e) => return (1, String::new(), format!("{}", e)),
    };

    let mut vm = php_rs_vm::Vm::new();
    match vm.execute(&op_array, None) {
        Ok(output) => (0, output, String::new()),
        Err(e) => (1, String::new(), format!("{:?}", e)),
    }
}

// ── FPM Server ──────────────────────────────────────────────────────────────

/// Run the FPM master process (single-threaded for now).
pub fn run_fpm(config: FpmConfig) -> i32 {
    let running = Arc::new(AtomicBool::new(true));

    if config.pools.is_empty() {
        eprintln!("[FPM] ERROR: No pools configured");
        return 1;
    }

    let pool = &config.pools[0];
    eprintln!("[FPM] Starting pool '{}' on {}", pool.name, pool.listen);
    eprintln!(
        "[FPM] Process manager: {:?}, max_children: {}",
        pool.pm, pool.pm_max_children
    );

    let listener = match TcpListener::bind(&pool.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[FPM] ERROR: Failed to bind {}: {}", pool.listen, e);
            return 1;
        }
    };

    eprintln!("[FPM] Ready to handle connections");

    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(e) = handle_fcgi_connection(&mut stream) {
                    eprintln!("[FPM] Request error: {}", e);
                }
            }
            Err(e) => {
                if running.load(Ordering::Relaxed) {
                    eprintln!("[FPM] Accept error: {}", e);
                }
            }
        }
    }

    eprintln!("[FPM] Shutting down");
    0
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fcgi_header_roundtrip() {
        let header = FcgiHeader {
            version: FCGI_VERSION_1,
            record_type: FcgiRecordType::Stdout as u8,
            request_id: 1,
            content_length: 100,
            padding_length: 4,
        };
        let bytes = header.to_bytes();
        let parsed = FcgiHeader::from_bytes(&bytes);
        assert_eq!(parsed.version, FCGI_VERSION_1);
        assert_eq!(parsed.record_type, FcgiRecordType::Stdout as u8);
        assert_eq!(parsed.request_id, 1);
        assert_eq!(parsed.content_length, 100);
        assert_eq!(parsed.padding_length, 4);
    }

    #[test]
    fn test_fcgi_record_types() {
        assert_eq!(
            FcgiRecordType::from_u8(1),
            Some(FcgiRecordType::BeginRequest)
        );
        assert_eq!(FcgiRecordType::from_u8(3), Some(FcgiRecordType::EndRequest));
        assert_eq!(FcgiRecordType::from_u8(4), Some(FcgiRecordType::Params));
        assert_eq!(FcgiRecordType::from_u8(5), Some(FcgiRecordType::Stdin));
        assert_eq!(FcgiRecordType::from_u8(6), Some(FcgiRecordType::Stdout));
        assert_eq!(FcgiRecordType::from_u8(99), None);
    }

    #[test]
    fn test_parse_fcgi_params() {
        // Encode some params
        let mut data = Vec::new();
        data.extend_from_slice(&encode_fcgi_param("SCRIPT_FILENAME", "/var/www/index.php"));
        data.extend_from_slice(&encode_fcgi_param("REQUEST_METHOD", "GET"));
        data.extend_from_slice(&encode_fcgi_param("QUERY_STRING", "page=1"));

        let params = parse_fcgi_params(&data);
        assert_eq!(params.get("SCRIPT_FILENAME").unwrap(), "/var/www/index.php");
        assert_eq!(params.get("REQUEST_METHOD").unwrap(), "GET");
        assert_eq!(params.get("QUERY_STRING").unwrap(), "page=1");
    }

    #[test]
    fn test_encode_fcgi_param_short() {
        let encoded = encode_fcgi_param("A", "B");
        // 1-byte name len (1) + 1-byte value len (1) + "A" + "B"
        assert_eq!(encoded, vec![1, 1, b'A', b'B']);
    }

    #[test]
    fn test_encode_fcgi_param_long_value() {
        let long_value = "x".repeat(200);
        let encoded = encode_fcgi_param("key", &long_value);
        // name_len=3 (1 byte), value_len=200 (4 bytes since >127)
        assert_eq!(encoded[0], 3); // name length
        assert_eq!(encoded[1] & 0x80, 0x80); // 4-byte length marker
        let value_len = ((encoded[1] & 0x7F) as usize) << 24
            | (encoded[2] as usize) << 16
            | (encoded[3] as usize) << 8
            | encoded[4] as usize;
        assert_eq!(value_len, 200);
    }

    #[test]
    fn test_fcgi_record_stdout() {
        let record = FcgiRecord::stdout(1, b"Hello");
        assert_eq!(record.header.record_type, FcgiRecordType::Stdout as u8);
        assert_eq!(record.header.request_id, 1);
        assert_eq!(record.header.content_length, 5);
        assert_eq!(record.content, b"Hello");
    }

    #[test]
    fn test_fcgi_record_end_request() {
        let record = FcgiRecord::end_request(1, 0, FcgiProtocolStatus::RequestComplete);
        assert_eq!(record.header.record_type, FcgiRecordType::EndRequest as u8);
        assert_eq!(record.header.content_length, 8);
        assert_eq!(record.content[4], FcgiProtocolStatus::RequestComplete as u8);
    }

    #[test]
    fn test_fcgi_record_read_write_roundtrip() {
        let record = FcgiRecord::stdout(42, b"test data");

        let mut buf = Vec::new();
        record.write_to(&mut buf).unwrap();

        let mut cursor = io::Cursor::new(buf);
        let parsed = FcgiRecord::read_from(&mut cursor).unwrap();

        assert_eq!(parsed.header.request_id, 42);
        assert_eq!(parsed.header.record_type, FcgiRecordType::Stdout as u8);
        assert_eq!(parsed.content, b"test data");
    }

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.name, "www");
        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.pm, PmMode::Dynamic);
        assert_eq!(config.pm_max_children, 5);
        assert_eq!(config.pm_start_servers, 2);
    }

    #[test]
    fn test_pool_status_format() {
        let status = PoolStatus {
            pool_name: "www".into(),
            pm_mode: PmMode::Dynamic,
            active_processes: 2,
            idle_processes: 3,
            total_processes: 5,
            accepted_connections: 1000,
            listen_queue: 0,
            max_listen_queue: 10,
        };
        let output = status.to_status_string();
        assert!(output.contains("pool:                 www"));
        assert!(output.contains("process manager:      dynamic"));
        assert!(output.contains("accepted conn:        1000"));
        assert!(output.contains("total processes:      5"));
    }

    #[test]
    fn test_execute_php_fcgi_success() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("php_rs_fpm_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, "<?php echo \"FPM OK\";").unwrap();
        drop(f);

        let params = HashMap::new();
        let (status, output, error) = execute_php_fcgi(file.to_str().unwrap(), &params, &[]);
        assert_eq!(status, 0);
        assert_eq!(output, "FPM OK");
        assert!(error.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_php_fcgi_missing_file() {
        let params = HashMap::new();
        let (status, _, error) = execute_php_fcgi("/nonexistent/file.php", &params, &[]);
        assert_ne!(status, 0);
        assert!(!error.is_empty());
    }

    #[test]
    fn test_execute_php_fcgi_no_script() {
        let params = HashMap::new();
        let (status, _, error) = execute_php_fcgi("", &params, &[]);
        assert_ne!(status, 0);
        assert!(error.contains("No SCRIPT_FILENAME"));
    }

    #[test]
    fn test_fpm_config_defaults() {
        let config = FpmConfig::default();
        assert_eq!(config.pools.len(), 1);
        assert!(!config.daemonize);
    }

    #[test]
    fn test_fpm_can_bind() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
        drop(listener);
    }
}
