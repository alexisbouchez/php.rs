//! PHP FPM SAPI — FastCGI Process Manager
//!
//! Implements the FastCGI protocol and process management for php.rs.
//! Equivalent to php-src/sapi/fpm/ (32 C files).
//!
//! Architecture:
//! - Master process: manages worker pools, handles signals
//! - Worker threads: handle FastCGI requests via thread pool
//! - Pool configuration: static, dynamic, ondemand modes
//!
//! Features:
//! - Full FastCGI request/response with superglobal injection (10B.01)
//! - Pool mode support: static, dynamic, ondemand (10B.02)
//! - Worker thread management with respawn (10B.03)
//! - Status page at pm.status_path (10B.04)
//! - Slow log for long-running requests (10B.05)
//! - php-fpm.conf INI-style config parsing (10B.06)

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use php_rs_vm::{PhpArray, Value};

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
    /// Log level (alert=1, error=3, warning=4, notice=5, debug=7).
    pub log_level: u8,
}

impl Default for FpmConfig {
    fn default() -> Self {
        Self {
            pools: vec![PoolConfig::default()],
            pid_file: None,
            error_log: None,
            daemonize: false,
            log_level: 5,
        }
    }
}

// ── 10B.06: php-fpm.conf Parsing ────────────────────────────────────────────

/// Parse a php-fpm.conf file into an FpmConfig.
pub fn parse_fpm_config(content: &str) -> Result<FpmConfig, String> {
    let mut config = FpmConfig {
        pools: Vec::new(),
        pid_file: None,
        error_log: None,
        daemonize: false,
        log_level: 5,
    };

    let mut current_section: Option<String> = None;
    let mut current_pool: Option<PoolConfig> = None;

    for (line_num, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        // Section header: [global] or [pool-name]
        if line.starts_with('[') && line.ends_with(']') {
            // Save previous pool if any
            if let Some(pool) = current_pool.take() {
                config.pools.push(pool);
            }

            let section_name = &line[1..line.len() - 1];
            if section_name == "global" {
                current_section = Some("global".into());
            } else {
                current_section = Some(section_name.to_string());
                let mut pool = PoolConfig::default();
                pool.name = section_name.to_string();
                current_pool = Some(pool);
            }
            continue;
        }

        // Key = value
        let (key, value) = match line.find('=') {
            Some(eq) => (line[..eq].trim(), line[eq + 1..].trim()),
            None => {
                return Err(format!("Line {}: invalid syntax: {}", line_num + 1, line));
            }
        };

        match current_section.as_deref() {
            Some("global") => match key {
                "pid" => config.pid_file = Some(value.to_string()),
                "error_log" => config.error_log = Some(value.to_string()),
                "daemonize" => config.daemonize = parse_bool(value),
                "log_level" => {
                    config.log_level = match value {
                        "alert" => 1,
                        "error" => 3,
                        "warning" => 4,
                        "notice" => 5,
                        "debug" => 7,
                        _ => value.parse().unwrap_or(5),
                    };
                }
                _ => {} // Ignore unknown global directives
            },
            Some(_) => {
                if let Some(ref mut pool) = current_pool {
                    apply_pool_directive(pool, key, value)?;
                }
            }
            None => {
                // Directives before any section — treat as global
                match key {
                    "pid" => config.pid_file = Some(value.to_string()),
                    "error_log" => config.error_log = Some(value.to_string()),
                    "daemonize" => config.daemonize = parse_bool(value),
                    _ => {}
                }
            }
        }
    }

    // Save last pool
    if let Some(pool) = current_pool {
        config.pools.push(pool);
    }

    // If no pools defined, use default
    if config.pools.is_empty() {
        config.pools.push(PoolConfig::default());
    }

    Ok(config)
}

/// Parse a boolean value from an FPM config (yes/no/true/false/1/0).
fn parse_bool(value: &str) -> bool {
    matches!(value.to_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// Apply a pool-level directive to a PoolConfig.
fn apply_pool_directive(pool: &mut PoolConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "listen" => pool.listen = value.to_string(),
        "pm" => {
            pool.pm = match value {
                "static" => PmMode::Static,
                "dynamic" => PmMode::Dynamic,
                "ondemand" => PmMode::OnDemand,
                _ => return Err(format!("Unknown pm mode: {}", value)),
            };
        }
        "pm.max_children" => {
            pool.pm_max_children = value
                .parse()
                .map_err(|_| format!("Invalid pm.max_children: {}", value))?;
        }
        "pm.start_servers" => {
            pool.pm_start_servers = value
                .parse()
                .map_err(|_| format!("Invalid pm.start_servers: {}", value))?;
        }
        "pm.min_spare_servers" => {
            pool.pm_min_spare_servers = value
                .parse()
                .map_err(|_| format!("Invalid pm.min_spare_servers: {}", value))?;
        }
        "pm.max_spare_servers" => {
            pool.pm_max_spare_servers = value
                .parse()
                .map_err(|_| format!("Invalid pm.max_spare_servers: {}", value))?;
        }
        "pm.max_requests" => {
            pool.pm_max_requests = value
                .parse()
                .map_err(|_| format!("Invalid pm.max_requests: {}", value))?;
        }
        "pm.process_idle_timeout" => {
            // May end with "s" suffix
            let v = value.trim_end_matches('s');
            pool.pm_process_idle_timeout = v
                .parse()
                .map_err(|_| format!("Invalid pm.process_idle_timeout: {}", value))?;
        }
        "pm.status_path" => pool.pm_status_path = Some(value.to_string()),
        "ping.path" => pool.ping_path = Some(value.to_string()),
        "ping.response" => pool.ping_response = value.to_string(),
        "slowlog" => pool.slowlog = Some(value.to_string()),
        "request_slowlog_timeout" => {
            let v = value.trim_end_matches('s');
            pool.request_slowlog_timeout = v
                .parse()
                .map_err(|_| format!("Invalid request_slowlog_timeout: {}", value))?;
        }
        "access.log" => pool.access_log = Some(value.to_string()),
        _ => {} // Ignore unknown pool directives
    }
    Ok(())
}

/// Load and parse a php-fpm.conf file from disk.
pub fn load_fpm_config(path: &str) -> Result<FpmConfig, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
    parse_fpm_config(&content)
}

// ── Worker State ────────────────────────────────────────────────────────────

/// State of an FPM worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Idle,
    Busy,
}

/// Information about a worker thread.
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub id: u32,
    pub state: WorkerState,
    pub requests_served: u64,
    pub start_time: u64,
    pub last_request_time: u64,
}

/// Pool runtime status (shared between workers and master).
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
    pub start_time: u64,
    pub max_active_processes: u32,
    pub slow_requests: u64,
}

impl PoolStatus {
    /// Format as PHP FPM status page output (plain text).
    pub fn to_status_string(&self) -> String {
        format!(
            "pool:                 {}\n\
             process manager:      {}\n\
             start time:           {}\n\
             accepted conn:        {}\n\
             listen queue:         {}\n\
             max listen queue:     {}\n\
             idle processes:       {}\n\
             active processes:     {}\n\
             total processes:      {}\n\
             max active processes: {}\n\
             slow requests:        {}\n",
            self.pool_name,
            match self.pm_mode {
                PmMode::Static => "static",
                PmMode::Dynamic => "dynamic",
                PmMode::OnDemand => "ondemand",
            },
            self.start_time,
            self.accepted_connections,
            self.listen_queue,
            self.max_listen_queue,
            self.idle_processes,
            self.active_processes,
            self.total_processes,
            self.max_active_processes,
            self.slow_requests,
        )
    }

    /// Format as JSON for status page ?json query.
    pub fn to_status_json(&self) -> String {
        format!(
            r#"{{"pool":"{}","process manager":"{}","start time":{},"accepted conn":{},"listen queue":{},"max listen queue":{},"idle processes":{},"active processes":{},"total processes":{},"max active processes":{},"slow requests":{}}}"#,
            self.pool_name,
            match self.pm_mode {
                PmMode::Static => "static",
                PmMode::Dynamic => "dynamic",
                PmMode::OnDemand => "ondemand",
            },
            self.start_time,
            self.accepted_connections,
            self.listen_queue,
            self.max_listen_queue,
            self.idle_processes,
            self.active_processes,
            self.total_processes,
            self.max_active_processes,
            self.slow_requests,
        )
    }
}

// ── Shared Pool State ───────────────────────────────────────────────────────

/// Thread-safe shared state for a pool.
pub struct SharedPoolState {
    accepted_connections: AtomicU64,
    active_workers: AtomicU64,
    max_active_workers: AtomicU64,
    slow_requests: AtomicU64,
    start_time: u64,
    workers: Mutex<Vec<WorkerInfo>>,
}

impl SharedPoolState {
    fn new(start_time: u64) -> Self {
        Self {
            accepted_connections: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            max_active_workers: AtomicU64::new(0),
            slow_requests: AtomicU64::new(0),
            start_time,
            workers: Mutex::new(Vec::new()),
        }
    }

    fn get_status(&self, pool_name: &str, pm_mode: PmMode) -> PoolStatus {
        let active = self.active_workers.load(Ordering::Relaxed) as u32;
        let workers = self.workers.lock().unwrap();
        let total = workers.len() as u32;
        let idle = total.saturating_sub(active);

        PoolStatus {
            pool_name: pool_name.to_string(),
            pm_mode,
            active_processes: active,
            idle_processes: idle,
            total_processes: total,
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            listen_queue: 0,
            max_listen_queue: 0,
            start_time: self.start_time,
            max_active_processes: self.max_active_workers.load(Ordering::Relaxed) as u32,
            slow_requests: self.slow_requests.load(Ordering::Relaxed),
        }
    }
}

// ── 10B.01: Full FastCGI Request Handler with Superglobals ──────────────────

/// Handle a single FastCGI connection with full superglobal injection.
pub fn handle_fcgi_connection(stream: &mut std::net::TcpStream) -> io::Result<()> {
    handle_fcgi_connection_with_config(stream, None, None)
}

/// Handle a FastCGI connection with pool config for status/ping pages.
pub fn handle_fcgi_connection_with_config(
    stream: &mut std::net::TcpStream,
    pool_config: Option<&PoolConfig>,
    pool_state: Option<&SharedPoolState>,
) -> io::Result<()> {
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
                if !record.content.is_empty() {
                    params_data.extend_from_slice(&record.content);
                }
            }
            Some(FcgiRecordType::Stdin) => {
                if record.content.is_empty() {
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

    let params = parse_fcgi_params(&params_data);

    // 10B.04: Check for status page request
    if let (Some(cfg), Some(state)) = (pool_config, pool_state) {
        let request_uri = params.get("REQUEST_URI").cloned().unwrap_or_default();

        // Status page
        if let Some(ref status_path) = cfg.pm_status_path {
            let (uri_path, query) = match request_uri.find('?') {
                Some(q) => (&request_uri[..q], &request_uri[q + 1..]),
                None => (request_uri.as_str(), ""),
            };
            if uri_path == status_path {
                let status = state.get_status(&cfg.name, cfg.pm);
                let (content_type, body) = if query.contains("json") {
                    ("application/json", status.to_status_json())
                } else {
                    ("text/plain", status.to_status_string())
                };
                let response = format!(
                    "Status: 200 OK\r\nContent-Type: {}\r\n\r\n{}",
                    content_type, body
                );
                send_fcgi_response(stream, request_id, &response, "")?;
                return Ok(());
            }
        }

        // Ping page
        if let Some(ref ping_path) = cfg.ping_path {
            let uri_path = match request_uri.find('?') {
                Some(q) => &request_uri[..q],
                None => &request_uri,
            };
            if uri_path == ping_path {
                let response = format!(
                    "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n{}",
                    cfg.ping_response
                );
                send_fcgi_response(stream, request_id, &response, "")?;
                return Ok(());
            }
        }
    }

    let script_filename = params.get("SCRIPT_FILENAME").cloned().unwrap_or_default();

    // 10B.05: Track request timing for slow log
    let start = Instant::now();

    let (status, output, error_output, vm_headers, vm_status) =
        execute_php_fcgi(&script_filename, &params, &stdin_data);

    let elapsed = start.elapsed();

    // Check slow log threshold
    if let Some(cfg) = pool_config {
        if cfg.request_slowlog_timeout > 0
            && elapsed.as_secs() >= cfg.request_slowlog_timeout as u64
        {
            if let Some(state) = pool_state {
                state.slow_requests.fetch_add(1, Ordering::Relaxed);
            }
            write_slow_log(cfg, &script_filename, elapsed.as_secs_f64());
        }
    }

    // Build HTTP response from VM output
    let http_status = vm_status.unwrap_or(if status == 0 { 200 } else { 500 });
    let http_status_text = match http_status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };

    let mut response_headers = format!("Status: {} {}\r\n", http_status, http_status_text);

    // Add VM-set headers
    let mut has_content_type = false;
    for h in &vm_headers {
        response_headers.push_str(h);
        response_headers.push_str("\r\n");
        if h.to_lowercase().starts_with("content-type:") {
            has_content_type = true;
        }
    }
    if !has_content_type {
        response_headers.push_str("Content-Type: text/html; charset=UTF-8\r\n");
    }
    response_headers.push_str("\r\n");

    let mut full_response = response_headers.into_bytes();
    full_response.extend_from_slice(output.as_bytes());

    send_fcgi_response_bytes(stream, request_id, &full_response, error_output.as_bytes())?;

    Ok(())
}

/// Send a FastCGI response (stdout + optional stderr + end request).
fn send_fcgi_response(
    stream: &mut impl Write,
    request_id: u16,
    stdout: &str,
    stderr: &str,
) -> io::Result<()> {
    send_fcgi_response_bytes(stream, request_id, stdout.as_bytes(), stderr.as_bytes())
}

/// Send a FastCGI response as raw bytes.
fn send_fcgi_response_bytes(
    stream: &mut impl Write,
    request_id: u16,
    stdout: &[u8],
    stderr: &[u8],
) -> io::Result<()> {
    // Send stdout in chunks (max 65535 bytes per record)
    for chunk in stdout.chunks(65535) {
        FcgiRecord::stdout(request_id, chunk).write_to(stream)?;
    }
    FcgiRecord::stdout(request_id, &[]).write_to(stream)?;

    // Send stderr if any
    if !stderr.is_empty() {
        for chunk in stderr.chunks(65535) {
            FcgiRecord::stderr(request_id, chunk).write_to(stream)?;
        }
        FcgiRecord::stderr(request_id, &[]).write_to(stream)?;
    }

    // End request
    FcgiRecord::end_request(request_id, 0, FcgiProtocolStatus::RequestComplete).write_to(stream)?;

    stream.flush()?;
    Ok(())
}

/// Execute PHP for a FastCGI request with full superglobal injection.
fn execute_php_fcgi(
    script_filename: &str,
    params: &HashMap<String, String>,
    stdin: &[u8],
) -> (i32, String, String, Vec<String>, Option<u16>) {
    if script_filename.is_empty() {
        return (
            1,
            String::new(),
            "No SCRIPT_FILENAME provided".into(),
            Vec::new(),
            None,
        );
    }

    let source = match std::fs::read_to_string(script_filename) {
        Ok(s) => s,
        Err(e) => {
            return (
                1,
                String::new(),
                format!("Cannot read {}: {}", script_filename, e),
                Vec::new(),
                None,
            );
        }
    };

    let op_array = match php_rs_compiler::compile_file(
        &source,
        &std::path::Path::new(script_filename)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(script_filename))
            .to_string_lossy(),
    ) {
        Ok(oa) => oa,
        Err(e) => return (1, String::new(), format!("{}", e), Vec::new(), None),
    };

    let mut vm = php_rs_vm::Vm::new();

    // Build superglobals from FCGI params
    let mut server_vars: HashMap<String, String> = HashMap::new();
    let mut get_vars: HashMap<String, String> = HashMap::new();
    let mut post_vars: HashMap<String, String> = HashMap::new();
    let mut cookie_vars: HashMap<String, String> = HashMap::new();

    // Copy all FCGI params into $_SERVER
    for (k, v) in params {
        server_vars.insert(k.clone(), v.clone());
    }

    // Parse $_GET from QUERY_STRING
    if let Some(qs) = params.get("QUERY_STRING") {
        get_vars = parse_query_string(qs);
    }

    // Parse $_POST from stdin if Content-Type is form-urlencoded
    if let Some(ct) = params.get("CONTENT_TYPE") {
        if ct.starts_with("application/x-www-form-urlencoded") && !stdin.is_empty() {
            let body_str = String::from_utf8_lossy(stdin);
            post_vars = parse_query_string(&body_str);
        }
    }

    // Parse $_COOKIE from HTTP_COOKIE
    if let Some(cookie_header) = params.get("HTTP_COOKIE") {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some(eq) = pair.find('=') {
                cookie_vars.insert(
                    pair[..eq].trim().to_string(),
                    pair[eq + 1..].trim().to_string(),
                );
            }
        }
    }

    // Build $_REQUEST (GET + POST + COOKIE, POST wins on conflicts)
    let mut request_vars = get_vars.clone();
    for (k, v) in &post_vars {
        request_vars.insert(k.clone(), v.clone());
    }
    for (k, v) in &cookie_vars {
        request_vars.insert(k.clone(), v.clone());
    }

    // Build $_ENV from process environment
    let env_vars: HashMap<String, String> = std::env::vars().collect();

    // Inject all superglobals
    let mut superglobals: HashMap<String, Value> = HashMap::new();
    superglobals.insert(
        "_SERVER".into(),
        Value::Array(PhpArray::from_string_map(&server_vars)),
    );
    superglobals.insert(
        "_GET".into(),
        Value::Array(PhpArray::from_string_map(&get_vars)),
    );
    superglobals.insert(
        "_POST".into(),
        Value::Array(PhpArray::from_string_map(&post_vars)),
    );
    superglobals.insert(
        "_COOKIE".into(),
        Value::Array(PhpArray::from_string_map(&cookie_vars)),
    );
    superglobals.insert(
        "_ENV".into(),
        Value::Array(PhpArray::from_string_map(&env_vars)),
    );
    superglobals.insert(
        "_REQUEST".into(),
        Value::Array(PhpArray::from_string_map(&request_vars)),
    );
    superglobals.insert("_FILES".into(), Value::Array(PhpArray::new()));

    // Set raw request body for php://input
    if !stdin.is_empty() {
        let raw_body = String::from_utf8_lossy(stdin).to_string();
        vm.set_raw_input_body(raw_body);
    }

    match vm.execute(&op_array, Some(&superglobals)) {
        Ok(output) => {
            let status_code = vm.response_code();
            let headers = vm.response_headers().to_vec();
            (0, output, String::new(), headers, status_code)
        }
        Err(php_rs_vm::VmError::Exit(_)) => {
            let output = vm.output_so_far();
            let status_code = vm.response_code();
            let headers = vm.response_headers().to_vec();
            (0, output, String::new(), headers, status_code)
        }
        Err(e) => (1, String::new(), format!("{:?}", e), Vec::new(), None),
    }
}

/// Parse a URL query string into key-value pairs.
fn parse_query_string(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if qs.is_empty() {
        return map;
    }
    for pair in qs.split('&') {
        if let Some(eq) = pair.find('=') {
            let key = url_decode(&pair[..eq]);
            let value = url_decode(&pair[eq + 1..]);
            map.insert(key, value);
        } else if !pair.is_empty() {
            map.insert(url_decode(pair), String::new());
        }
    }
    map
}

/// Simple URL decoding (percent-decoding + '+' to space).
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                result.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    result.push(byte as char);
                    i += 3;
                } else {
                    result.push('%');
                    i += 1;
                }
            }
            _ => {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    result
}

// ── 10B.05: Slow Log ────────────────────────────────────────────────────────

/// Write a slow log entry.
fn write_slow_log(config: &PoolConfig, script: &str, elapsed_secs: f64) {
    let message = format!(
        "[pool {}] [slow] script_filename={} elapsed={:.3}s\n",
        config.name, script, elapsed_secs,
    );

    if let Some(ref path) = config.slowlog {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(message.as_bytes());
            return;
        }
    }

    // Fallback to stderr
    eprint!("{}", message);
}

// ── 10B.02 + 10B.03: Worker Pool Manager ────────────────────────────────────

/// Manages a pool of worker threads for handling FastCGI requests.
pub struct PoolManager {
    config: PoolConfig,
    state: Arc<SharedPoolState>,
    running: Arc<AtomicBool>,
}

impl PoolManager {
    /// Create a new pool manager.
    pub fn new(config: PoolConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            config,
            state: Arc::new(SharedPoolState::new(now)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get the current pool status.
    pub fn status(&self) -> PoolStatus {
        self.state.get_status(&self.config.name, self.config.pm)
    }

    /// Stop the pool manager.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Calculate how many workers to start initially based on PM mode.
    fn initial_workers(&self) -> u32 {
        match self.config.pm {
            PmMode::Static => self.config.pm_max_children,
            PmMode::Dynamic => self.config.pm_start_servers,
            PmMode::OnDemand => 0,
        }
    }

    /// Run the pool: spawn workers and accept connections.
    pub fn run(&self, listener: TcpListener) {
        let initial = self.initial_workers();

        eprintln!(
            "[pool {}] {} mode, spawning {} initial workers (max {})",
            self.config.name,
            match self.config.pm {
                PmMode::Static => "static",
                PmMode::Dynamic => "dynamic",
                PmMode::OnDemand => "ondemand",
            },
            initial,
            self.config.pm_max_children,
        );

        // Use a channel to distribute connections to worker threads
        let (tx, rx) = std::sync::mpsc::channel::<std::net::TcpStream>();
        let rx = Arc::new(Mutex::new(rx));

        // Spawn initial worker threads
        let mut handles = Vec::new();
        for id in 0..initial {
            let handle = self.spawn_worker(id, Arc::clone(&rx));
            handles.push(handle);
        }

        // Register workers in shared state
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut workers = self.state.workers.lock().unwrap();
            for id in 0..initial {
                workers.push(WorkerInfo {
                    id,
                    state: WorkerState::Idle,
                    requests_served: 0,
                    start_time: now,
                    last_request_time: 0,
                });
            }
        }

        // Set non-blocking on listener for clean shutdown
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|e| eprintln!("[pool {}] set_nonblocking: {}", self.config.name, e));

        // Master loop: accept connections and dispatch to workers
        while self.running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    self.state
                        .accepted_connections
                        .fetch_add(1, Ordering::Relaxed);

                    // For ondemand mode, spawn workers when needed
                    if self.config.pm == PmMode::OnDemand {
                        let workers = self.state.workers.lock().unwrap();
                        if workers.len() < self.config.pm_max_children as usize {
                            drop(workers);
                            let next_id = handles.len() as u32;
                            let handle = self.spawn_worker(next_id, Arc::clone(&rx));
                            handles.push(handle);
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let mut workers = self.state.workers.lock().unwrap();
                            workers.push(WorkerInfo {
                                id: next_id,
                                state: WorkerState::Idle,
                                requests_served: 0,
                                start_time: now,
                                last_request_time: 0,
                            });
                        }
                    }

                    // Dynamic mode: scale up if needed
                    if self.config.pm == PmMode::Dynamic {
                        let active = self.state.active_workers.load(Ordering::Relaxed) as u32;
                        let workers_count = {
                            let workers = self.state.workers.lock().unwrap();
                            workers.len() as u32
                        };
                        let idle = workers_count.saturating_sub(active);

                        if idle < self.config.pm_min_spare_servers
                            && workers_count < self.config.pm_max_children
                        {
                            let next_id = handles.len() as u32;
                            let handle = self.spawn_worker(next_id, Arc::clone(&rx));
                            handles.push(handle);
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let mut workers = self.state.workers.lock().unwrap();
                            workers.push(WorkerInfo {
                                id: next_id,
                                state: WorkerState::Idle,
                                requests_served: 0,
                                start_time: now,
                                last_request_time: 0,
                            });
                        }
                    }

                    let _ = tx.send(stream);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    if self.running.load(Ordering::Relaxed) {
                        eprintln!("[pool {}] accept error: {}", self.config.name, e);
                    }
                }
            }
        }

        // Signal workers to stop
        drop(tx);
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Spawn a single worker thread.
    fn spawn_worker(
        &self,
        id: u32,
        rx: Arc<Mutex<std::sync::mpsc::Receiver<std::net::TcpStream>>>,
    ) -> std::thread::JoinHandle<()> {
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let max_requests = self.config.pm_max_requests;

        std::thread::spawn(move || {
            let mut requests_served = 0u64;

            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                // Try to receive a connection (with timeout for clean shutdown)
                let stream = {
                    let receiver = rx.lock().unwrap();
                    receiver.recv_timeout(std::time::Duration::from_millis(100))
                };

                let mut stream = match stream {
                    Ok(s) => s,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                };

                // Mark worker as busy
                state.active_workers.fetch_add(1, Ordering::Relaxed);
                let active = state.active_workers.load(Ordering::Relaxed);
                let prev_max = state.max_active_workers.load(Ordering::Relaxed);
                if active > prev_max {
                    state.max_active_workers.store(active, Ordering::Relaxed);
                }

                // Update worker state
                {
                    let mut workers = state.workers.lock().unwrap();
                    if let Some(w) = workers.iter_mut().find(|w| w.id == id) {
                        w.state = WorkerState::Busy;
                    }
                }

                // Handle the request
                let _ =
                    handle_fcgi_connection_with_config(&mut stream, Some(&config), Some(&state));

                // Mark worker as idle
                state.active_workers.fetch_sub(1, Ordering::Relaxed);
                requests_served += 1;

                {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut workers = state.workers.lock().unwrap();
                    if let Some(w) = workers.iter_mut().find(|w| w.id == id) {
                        w.state = WorkerState::Idle;
                        w.requests_served = requests_served;
                        w.last_request_time = now;
                    }
                }

                // Respawn check: if max_requests reached, exit this worker
                if max_requests > 0 && requests_served >= max_requests as u64 {
                    break;
                }
            }
        })
    }
}

// ── FPM Server ──────────────────────────────────────────────────────────────

/// Run the FPM master process with full pool management.
pub fn run_fpm(config: FpmConfig) -> i32 {
    if config.pools.is_empty() {
        eprintln!("[FPM] ERROR: No pools configured");
        return 1;
    }

    let running = Arc::new(AtomicBool::new(true));

    // Write PID file if configured
    if let Some(ref pid_file) = config.pid_file {
        let pid = std::process::id();
        if let Err(e) = std::fs::write(pid_file, format!("{}", pid)) {
            eprintln!("[FPM] WARNING: Cannot write PID file {}: {}", pid_file, e);
        }
    }

    eprintln!("[FPM] Starting php-rs FPM");

    // Start a pool manager for each configured pool
    let mut pool_handles = Vec::new();

    for pool_config in &config.pools {
        eprintln!(
            "[FPM] Starting pool '{}' on {}",
            pool_config.name, pool_config.listen
        );
        eprintln!(
            "[FPM] Pool '{}': pm={:?}, max_children={}",
            pool_config.name, pool_config.pm, pool_config.pm_max_children
        );

        let listener = match TcpListener::bind(&pool_config.listen) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[FPM] ERROR: Failed to bind {}: {}", pool_config.listen, e);
                return 1;
            }
        };

        let manager = PoolManager::new(pool_config.clone());
        let pool_running = Arc::clone(&running);

        let handle = std::thread::spawn(move || {
            manager.run(listener);
            drop(pool_running);
        });

        pool_handles.push(handle);
    }

    eprintln!("[FPM] Ready to handle connections");

    // Wait for shutdown signal
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    eprintln!("[FPM] Shutting down");

    // Clean up PID file
    if let Some(ref pid_file) = config.pid_file {
        let _ = std::fs::remove_file(pid_file);
    }

    for handle in pool_handles {
        let _ = handle.join();
    }

    0
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FastCGI Protocol Tests ──────────────────────────────────────────

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
        assert_eq!(encoded, vec![1, 1, b'A', b'B']);
    }

    #[test]
    fn test_encode_fcgi_param_long_value() {
        let long_value = "x".repeat(200);
        let encoded = encode_fcgi_param("key", &long_value);
        assert_eq!(encoded[0], 3);
        assert_eq!(encoded[1] & 0x80, 0x80);
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

    // ── Config Tests ────────────────────────────────────────────────────

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
    fn test_fpm_config_defaults() {
        let config = FpmConfig::default();
        assert_eq!(config.pools.len(), 1);
        assert!(!config.daemonize);
        assert_eq!(config.log_level, 5);
    }

    // ── 10B.06: Config Parsing Tests ────────────────────────────────────

    #[test]
    fn test_parse_fpm_config_global_section() {
        let config_str = r#"
[global]
pid = /run/php-fpm.pid
error_log = /var/log/php-fpm.log
daemonize = yes
log_level = error
"#;
        let config = parse_fpm_config(config_str).unwrap();
        assert_eq!(config.pid_file.as_deref(), Some("/run/php-fpm.pid"));
        assert_eq!(config.error_log.as_deref(), Some("/var/log/php-fpm.log"));
        assert!(config.daemonize);
        assert_eq!(config.log_level, 3);
    }

    #[test]
    fn test_parse_fpm_config_pool_section() {
        let config_str = r#"
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 10
pm.max_requests = 500
pm.status_path = /status
ping.path = /ping
ping.response = pong
slowlog = /var/log/php-fpm.slow
request_slowlog_timeout = 5s
access.log = /var/log/php-fpm.access
"#;
        let config = parse_fpm_config(config_str).unwrap();
        assert_eq!(config.pools.len(), 1);
        let pool = &config.pools[0];
        assert_eq!(pool.name, "www");
        assert_eq!(pool.listen, "127.0.0.1:9000");
        assert_eq!(pool.pm, PmMode::Static);
        assert_eq!(pool.pm_max_children, 10);
        assert_eq!(pool.pm_max_requests, 500);
        assert_eq!(pool.pm_status_path.as_deref(), Some("/status"));
        assert_eq!(pool.ping_path.as_deref(), Some("/ping"));
        assert_eq!(pool.ping_response, "pong");
        assert_eq!(pool.slowlog.as_deref(), Some("/var/log/php-fpm.slow"));
        assert_eq!(pool.request_slowlog_timeout, 5);
        assert_eq!(pool.access_log.as_deref(), Some("/var/log/php-fpm.access"));
    }

    #[test]
    fn test_parse_fpm_config_multiple_pools() {
        let config_str = r#"
[global]
pid = /run/php-fpm.pid

[www]
listen = 127.0.0.1:9000
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

[api]
listen = 127.0.0.1:9001
pm = static
pm.max_children = 10
"#;
        let config = parse_fpm_config(config_str).unwrap();
        assert_eq!(config.pools.len(), 2);
        assert_eq!(config.pools[0].name, "www");
        assert_eq!(config.pools[0].pm, PmMode::Dynamic);
        assert_eq!(config.pools[0].pm_start_servers, 2);
        assert_eq!(config.pools[1].name, "api");
        assert_eq!(config.pools[1].listen, "127.0.0.1:9001");
        assert_eq!(config.pools[1].pm, PmMode::Static);
        assert_eq!(config.pools[1].pm_max_children, 10);
    }

    #[test]
    fn test_parse_fpm_config_ondemand_pool() {
        let config_str = r#"
[workers]
listen = 127.0.0.1:9002
pm = ondemand
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 1000
"#;
        let config = parse_fpm_config(config_str).unwrap();
        assert_eq!(config.pools.len(), 1);
        let pool = &config.pools[0];
        assert_eq!(pool.name, "workers");
        assert_eq!(pool.pm, PmMode::OnDemand);
        assert_eq!(pool.pm_max_children, 20);
        assert_eq!(pool.pm_process_idle_timeout, 30);
        assert_eq!(pool.pm_max_requests, 1000);
    }

    #[test]
    fn test_parse_fpm_config_comments_and_empty_lines() {
        let config_str = r#"
; This is a comment
# This is also a comment

[global]
; PID file path
pid = /run/php-fpm.pid

[www]
; Pool configuration
listen = 127.0.0.1:9000
pm = static
pm.max_children = 3
"#;
        let config = parse_fpm_config(config_str).unwrap();
        assert_eq!(config.pid_file.as_deref(), Some("/run/php-fpm.pid"));
        assert_eq!(config.pools[0].pm_max_children, 3);
    }

    #[test]
    fn test_parse_fpm_config_invalid_pm_mode() {
        let config_str = r#"
[www]
pm = invalid_mode
"#;
        let result = parse_fpm_config(config_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown pm mode"));
    }

    #[test]
    fn test_parse_fpm_config_empty_defaults_to_pool() {
        let config = parse_fpm_config("").unwrap();
        assert_eq!(config.pools.len(), 1);
        assert_eq!(config.pools[0].name, "www");
    }

    #[test]
    fn test_parse_fpm_config_bool_values() {
        assert!(parse_bool("yes"));
        assert!(parse_bool("true"));
        assert!(parse_bool("1"));
        assert!(parse_bool("on"));
        assert!(!parse_bool("no"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool("0"));
        assert!(!parse_bool("off"));
    }

    // ── Pool Status Tests ───────────────────────────────────────────────

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
            start_time: 1700000000,
            max_active_processes: 4,
            slow_requests: 2,
        };
        let output = status.to_status_string();
        assert!(output.contains("pool:                 www"));
        assert!(output.contains("process manager:      dynamic"));
        assert!(output.contains("accepted conn:        1000"));
        assert!(output.contains("total processes:      5"));
        assert!(output.contains("max active processes: 4"));
        assert!(output.contains("slow requests:        2"));
    }

    #[test]
    fn test_pool_status_json() {
        let status = PoolStatus {
            pool_name: "api".into(),
            pm_mode: PmMode::Static,
            active_processes: 1,
            idle_processes: 4,
            total_processes: 5,
            accepted_connections: 500,
            listen_queue: 0,
            max_listen_queue: 5,
            start_time: 1700000000,
            max_active_processes: 3,
            slow_requests: 0,
        };
        let json = status.to_status_json();
        assert!(json.contains(r#""pool":"api""#));
        assert!(json.contains(r#""process manager":"static""#));
        assert!(json.contains(r#""accepted conn":500"#));
        assert!(json.contains(r#""slow requests":0"#));
    }

    #[test]
    fn test_pool_status_ondemand() {
        let status = PoolStatus {
            pool_name: "workers".into(),
            pm_mode: PmMode::OnDemand,
            active_processes: 0,
            idle_processes: 0,
            total_processes: 0,
            accepted_connections: 0,
            listen_queue: 0,
            max_listen_queue: 0,
            start_time: 1700000000,
            max_active_processes: 0,
            slow_requests: 0,
        };
        let output = status.to_status_string();
        assert!(output.contains("process manager:      ondemand"));
        assert!(output.contains("total processes:      0"));
    }

    // ── 10B.01: Full Request/Response Cycle Tests ───────────────────────

    #[test]
    fn test_execute_php_fcgi_with_superglobals() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("php_rs_fpm_sg_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test_sg.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(
            f,
            r#"<?php echo $_SERVER['REQUEST_METHOD'] . " " . $_GET['name'];"#
        )
        .unwrap();
        drop(f);

        let mut params = HashMap::new();
        params.insert("SCRIPT_FILENAME".into(), file.to_str().unwrap().to_string());
        params.insert("REQUEST_METHOD".into(), "GET".into());
        params.insert("QUERY_STRING".into(), "name=world".into());

        let (status, output, error, _headers, _code) =
            execute_php_fcgi(file.to_str().unwrap(), &params, &[]);
        assert_eq!(status, 0, "error: {}", error);
        assert_eq!(output, "GET world");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_php_fcgi_post_body() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("php_rs_fpm_post_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("post.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, r#"<?php echo $_POST['user'] . ":" . $_POST['pass'];"#).unwrap();
        drop(f);

        let mut params = HashMap::new();
        params.insert("SCRIPT_FILENAME".into(), file.to_str().unwrap().to_string());
        params.insert("REQUEST_METHOD".into(), "POST".into());
        params.insert(
            "CONTENT_TYPE".into(),
            "application/x-www-form-urlencoded".into(),
        );

        let body = b"user=admin&pass=secret";
        let (status, output, error, _, _) = execute_php_fcgi(file.to_str().unwrap(), &params, body);
        assert_eq!(status, 0, "error: {}", error);
        assert_eq!(output, "admin:secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_php_fcgi_cookies() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("php_rs_fpm_cookie_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("cookie.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, r#"<?php echo $_COOKIE['sid'];"#).unwrap();
        drop(f);

        let mut params = HashMap::new();
        params.insert("SCRIPT_FILENAME".into(), file.to_str().unwrap().to_string());
        params.insert("HTTP_COOKIE".into(), "sid=abc123; theme=dark".into());

        let (status, output, error, _, _) = execute_php_fcgi(file.to_str().unwrap(), &params, &[]);
        assert_eq!(status, 0, "error: {}", error);
        assert_eq!(output, "abc123");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_php_fcgi_full_cycle_via_stream() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("php_rs_fpm_cycle_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("hello.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, "<?php echo \"Hello FPM!\";").unwrap();
        drop(f);

        // Build a complete FCGI request in a buffer
        let mut request_buf = Vec::new();

        // BeginRequest record
        let begin = FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::BeginRequest as u8,
                request_id: 1,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![0, 1, 0, 0, 0, 0, 0, 0], // role=Responder, flags=0
        };
        begin.write_to(&mut request_buf).unwrap();

        // Params record
        let mut params_data = Vec::new();
        params_data.extend_from_slice(&encode_fcgi_param(
            "SCRIPT_FILENAME",
            file.to_str().unwrap(),
        ));
        params_data.extend_from_slice(&encode_fcgi_param("REQUEST_METHOD", "GET"));
        params_data.extend_from_slice(&encode_fcgi_param("QUERY_STRING", ""));
        let params_record = FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: params_data.len() as u16,
                padding_length: 0,
            },
            content: params_data,
        };
        params_record.write_to(&mut request_buf).unwrap();

        // Empty params (end of params)
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        // Empty stdin (end of request)
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdin as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        // Create a mock TCP connection using a listener on localhost
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(&request_buf).unwrap();
            client.flush().unwrap();

            // Read response
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });

        let (mut stream, _) = listener.accept().unwrap();
        handle_fcgi_connection(&mut stream).unwrap();
        drop(stream);

        let response_data = client_thread.join().unwrap();

        // Parse response records
        let mut cursor = io::Cursor::new(&response_data);
        let mut stdout_data = Vec::new();
        while (cursor.position() as usize) < response_data.len() {
            if let Ok(record) = FcgiRecord::read_from(&mut cursor) {
                if record.header.record_type == FcgiRecordType::Stdout as u8
                    && !record.content.is_empty()
                {
                    stdout_data.extend_from_slice(&record.content);
                }
            } else {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&stdout_data);
        assert!(response_str.contains("Hello FPM!"));
        assert!(response_str.contains("Status: 200"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_php_fcgi_missing_file() {
        let params = HashMap::new();
        let (status, _, error, _, _) = execute_php_fcgi("/nonexistent/file.php", &params, &[]);
        assert_ne!(status, 0);
        assert!(!error.is_empty());
    }

    #[test]
    fn test_execute_php_fcgi_no_script() {
        let params = HashMap::new();
        let (status, _, error, _, _) = execute_php_fcgi("", &params, &[]);
        assert_ne!(status, 0);
        assert!(error.contains("No SCRIPT_FILENAME"));
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
        let (status, output, error, _, _) = execute_php_fcgi(file.to_str().unwrap(), &params, &[]);
        assert_eq!(status, 0);
        assert_eq!(output, "FPM OK");
        assert!(error.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 10B.02: Pool Mode Tests ─────────────────────────────────────────

    #[test]
    fn test_pool_manager_initial_workers_static() {
        let mut config = PoolConfig::default();
        config.pm = PmMode::Static;
        config.pm_max_children = 8;
        let manager = PoolManager::new(config);
        assert_eq!(manager.initial_workers(), 8);
    }

    #[test]
    fn test_pool_manager_initial_workers_dynamic() {
        let mut config = PoolConfig::default();
        config.pm = PmMode::Dynamic;
        config.pm_start_servers = 3;
        let manager = PoolManager::new(config);
        assert_eq!(manager.initial_workers(), 3);
    }

    #[test]
    fn test_pool_manager_initial_workers_ondemand() {
        let mut config = PoolConfig::default();
        config.pm = PmMode::OnDemand;
        let manager = PoolManager::new(config);
        assert_eq!(manager.initial_workers(), 0);
    }

    // ── 10B.03: Worker Management Tests ─────────────────────────────────

    #[test]
    fn test_pool_manager_status_initial() {
        let config = PoolConfig::default();
        let manager = PoolManager::new(config);
        let status = manager.status();
        assert_eq!(status.pool_name, "www");
        assert_eq!(status.pm_mode, PmMode::Dynamic);
        assert_eq!(status.total_processes, 0);
        assert_eq!(status.accepted_connections, 0);
    }

    #[test]
    fn test_pool_manager_stop() {
        let config = PoolConfig::default();
        let manager = PoolManager::new(config);
        assert!(manager.running.load(Ordering::Relaxed));
        manager.stop();
        assert!(!manager.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_worker_info_creation() {
        let info = WorkerInfo {
            id: 1,
            state: WorkerState::Idle,
            requests_served: 0,
            start_time: 1700000000,
            last_request_time: 0,
        };
        assert_eq!(info.id, 1);
        assert_eq!(info.state, WorkerState::Idle);
        assert_eq!(info.requests_served, 0);
    }

    #[test]
    fn test_shared_pool_state() {
        let state = SharedPoolState::new(1700000000);
        state.accepted_connections.fetch_add(5, Ordering::Relaxed);
        state.active_workers.store(2, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut workers = state.workers.lock().unwrap();
            workers.push(WorkerInfo {
                id: 0,
                state: WorkerState::Busy,
                requests_served: 3,
                start_time: now,
                last_request_time: now,
            });
            workers.push(WorkerInfo {
                id: 1,
                state: WorkerState::Idle,
                requests_served: 2,
                start_time: now,
                last_request_time: now,
            });
        }

        let status = state.get_status("test", PmMode::Dynamic);
        assert_eq!(status.active_processes, 2);
        assert_eq!(status.total_processes, 2);
        assert_eq!(status.accepted_connections, 5);
    }

    // ── 10B.04: Status Page Tests ───────────────────────────────────────

    #[test]
    fn test_status_page_via_fcgi() {
        // Simulate a status page request via the FCGI handler
        let mut config = PoolConfig::default();
        config.pm_status_path = Some("/status".into());

        let state = SharedPoolState::new(1700000000);
        state.accepted_connections.store(42, Ordering::Relaxed);

        // Build FCGI request for /status
        let mut request_buf = Vec::new();
        let begin = FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::BeginRequest as u8,
                request_id: 1,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![0, 1, 0, 0, 0, 0, 0, 0],
        };
        begin.write_to(&mut request_buf).unwrap();

        let mut params_data = Vec::new();
        params_data.extend_from_slice(&encode_fcgi_param("REQUEST_URI", "/status"));
        let params_record = FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: params_data.len() as u16,
                padding_length: 0,
            },
            content: params_data,
        };
        params_record.write_to(&mut request_buf).unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdin as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        // Use TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(&request_buf).unwrap();
            client.flush().unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });

        let (mut stream, _) = listener.accept().unwrap();
        handle_fcgi_connection_with_config(&mut stream, Some(&config), Some(&state)).unwrap();
        drop(stream);

        let response_data = client_thread.join().unwrap();
        let mut cursor = io::Cursor::new(&response_data);
        let mut stdout_data = Vec::new();
        while (cursor.position() as usize) < response_data.len() {
            if let Ok(record) = FcgiRecord::read_from(&mut cursor) {
                if record.header.record_type == FcgiRecordType::Stdout as u8
                    && !record.content.is_empty()
                {
                    stdout_data.extend_from_slice(&record.content);
                }
            } else {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&stdout_data);
        assert!(response_str.contains("pool:                 www"));
        assert!(response_str.contains("accepted conn:        42"));
    }

    #[test]
    fn test_status_page_json() {
        let mut config = PoolConfig::default();
        config.pm_status_path = Some("/status".into());

        let state = SharedPoolState::new(1700000000);
        state.accepted_connections.store(99, Ordering::Relaxed);

        // Build request for /status?json
        let mut request_buf = Vec::new();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::BeginRequest as u8,
                request_id: 1,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![0, 1, 0, 0, 0, 0, 0, 0],
        }
        .write_to(&mut request_buf)
        .unwrap();

        let mut params_data = Vec::new();
        params_data.extend_from_slice(&encode_fcgi_param("REQUEST_URI", "/status?json"));
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: params_data.len() as u16,
                padding_length: 0,
            },
            content: params_data,
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdin as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(&request_buf).unwrap();
            client.flush().unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });

        let (mut stream, _) = listener.accept().unwrap();
        handle_fcgi_connection_with_config(&mut stream, Some(&config), Some(&state)).unwrap();
        drop(stream);

        let response_data = client_thread.join().unwrap();
        let mut cursor = io::Cursor::new(&response_data);
        let mut stdout_data = Vec::new();
        while (cursor.position() as usize) < response_data.len() {
            if let Ok(record) = FcgiRecord::read_from(&mut cursor) {
                if record.header.record_type == FcgiRecordType::Stdout as u8
                    && !record.content.is_empty()
                {
                    stdout_data.extend_from_slice(&record.content);
                }
            } else {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&stdout_data);
        assert!(response_str.contains(r#""pool":"www""#));
        assert!(response_str.contains(r#""accepted conn":99"#));
    }

    #[test]
    fn test_ping_page_via_fcgi() {
        let mut config = PoolConfig::default();
        config.ping_path = Some("/ping".into());
        config.ping_response = "pong".into();

        let state = SharedPoolState::new(1700000000);

        let mut request_buf = Vec::new();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::BeginRequest as u8,
                request_id: 1,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![0, 1, 0, 0, 0, 0, 0, 0],
        }
        .write_to(&mut request_buf)
        .unwrap();

        let mut params_data = Vec::new();
        params_data.extend_from_slice(&encode_fcgi_param("REQUEST_URI", "/ping"));
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: params_data.len() as u16,
                padding_length: 0,
            },
            content: params_data,
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdin as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(&request_buf).unwrap();
            client.flush().unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });

        let (mut stream, _) = listener.accept().unwrap();
        handle_fcgi_connection_with_config(&mut stream, Some(&config), Some(&state)).unwrap();
        drop(stream);

        let response_data = client_thread.join().unwrap();
        let mut cursor = io::Cursor::new(&response_data);
        let mut stdout_data = Vec::new();
        while (cursor.position() as usize) < response_data.len() {
            if let Ok(record) = FcgiRecord::read_from(&mut cursor) {
                if record.header.record_type == FcgiRecordType::Stdout as u8
                    && !record.content.is_empty()
                {
                    stdout_data.extend_from_slice(&record.content);
                }
            } else {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&stdout_data);
        assert!(response_str.contains("pong"));
    }

    // ── 10B.05: Slow Log Tests ──────────────────────────────────────────

    #[test]
    fn test_slow_log_writes_to_file() {
        let dir = std::env::temp_dir().join("php_rs_fpm_slowlog_test");
        let _ = std::fs::create_dir_all(&dir);
        let slowlog_path = dir.join("slow.log");

        let mut config = PoolConfig::default();
        config.slowlog = Some(slowlog_path.to_str().unwrap().to_string());

        write_slow_log(&config, "/var/www/slow.php", 5.123);

        let contents = std::fs::read_to_string(&slowlog_path).unwrap();
        assert!(contents.contains("[pool www]"));
        assert!(contents.contains("[slow]"));
        assert!(contents.contains("/var/www/slow.php"));
        assert!(contents.contains("5.123s"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── URL Decode Tests ────────────────────────────────────────────────

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("a%3Db%26c"), "a=b&c");
    }

    #[test]
    fn test_parse_query_string() {
        let qs = parse_query_string("foo=bar&baz=123&empty=");
        assert_eq!(qs.get("foo").unwrap(), "bar");
        assert_eq!(qs.get("baz").unwrap(), "123");
        assert_eq!(qs.get("empty").unwrap(), "");
    }

    #[test]
    fn test_fpm_can_bind() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
        drop(listener);
    }

    // ── 10B.03: Worker Pool Integration Test ────────────────────────────

    #[test]
    fn test_pool_manager_handles_requests() {
        use std::io::Write as _;

        // Create a PHP file
        let dir = std::env::temp_dir().join("php_rs_pool_mgr_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("pool_test.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, "<?php echo \"pool ok\";").unwrap();
        drop(f);

        // Start pool manager on random port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut config = PoolConfig::default();
        config.pm = PmMode::Static;
        config.pm_max_children = 2;
        config.listen = addr.to_string();

        let manager = PoolManager::new(config);
        let running = Arc::clone(&manager.running);

        let pool_thread = std::thread::spawn(move || {
            manager.run(listener);
        });

        // Give pool time to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Send a request
        let file_path = file.to_str().unwrap().to_string();
        let mut request_buf = Vec::new();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::BeginRequest as u8,
                request_id: 1,
                content_length: 8,
                padding_length: 0,
            },
            content: vec![0, 1, 0, 0, 0, 0, 0, 0],
        }
        .write_to(&mut request_buf)
        .unwrap();

        let mut params_data = Vec::new();
        params_data.extend_from_slice(&encode_fcgi_param("SCRIPT_FILENAME", &file_path));
        params_data.extend_from_slice(&encode_fcgi_param("REQUEST_METHOD", "GET"));
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: params_data.len() as u16,
                padding_length: 0,
            },
            content: params_data,
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Params as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();
        FcgiRecord {
            header: FcgiHeader {
                version: FCGI_VERSION_1,
                record_type: FcgiRecordType::Stdin as u8,
                request_id: 1,
                content_length: 0,
                padding_length: 0,
            },
            content: Vec::new(),
        }
        .write_to(&mut request_buf)
        .unwrap();

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        client.write_all(&request_buf).unwrap();
        client.flush().unwrap();

        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);

        // Parse stdout from response
        let mut cursor = io::Cursor::new(&response);
        let mut stdout_data = Vec::new();
        while (cursor.position() as usize) < response.len() {
            if let Ok(record) = FcgiRecord::read_from(&mut cursor) {
                if record.header.record_type == FcgiRecordType::Stdout as u8
                    && !record.content.is_empty()
                {
                    stdout_data.extend_from_slice(&record.content);
                }
            } else {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&stdout_data);
        assert!(
            response_str.contains("pool ok"),
            "Response was: {}",
            response_str
        );

        // Cleanup
        running.store(false, Ordering::Relaxed);
        let _ = pool_thread.join();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
