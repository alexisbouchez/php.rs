//! Built-in HTTP server for php.rs
//!
//! Equivalent to php-src/sapi/cli/php_cli_server.c
//! Usage: php-rs -S localhost:8080 [-t docroot] [router.php]
//!
//! Features:
//! - Router script support with false-return fallthrough (10C.01)
//! - Concurrent request handling via thread pool (10C.03)
//! - Access logging with timestamps, status codes, response times (10C.04)

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use php_rs_runtime::superglobals::Superglobals;
use php_rs_vm::{PhpArray, Value};

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the built-in server.
pub struct ServerConfig {
    /// Listen address (e.g., "localhost:8080").
    pub listen: String,
    /// Document root directory.
    pub docroot: PathBuf,
    /// Optional router script.
    pub router: Option<PathBuf>,
}

// ── Dashboard State ─────────────────────────────────────────────────────────

const DASHBOARD_RING_SIZE: usize = 1000;

struct RequestRecord {
    id: u64,
    timestamp: String,
    method: String,
    uri: String,
    status: u16,
    elapsed_ms: u128,
    content_length: usize,
    remote_addr: String,
    content_type: String,
    events: Vec<(String, String, u128)>, // (kind, detail, elapsed_us)
}

impl RequestRecord {
    fn to_json(&self) -> String {
        let mut ev_json = String::from("[");
        for (i, (kind, detail, us)) in self.events.iter().enumerate() {
            if i > 0 { ev_json.push(','); }
            let d = detail.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            ev_json.push_str(&format!(r#"{{"k":"{}","d":"{}","us":{}}}"#, kind, d, us));
        }
        ev_json.push(']');
        format!(
            r#"{{"id":{},"ts":"{}","method":"{}","uri":"{}","status":{},"ms":{},"len":{},"addr":"{}","ct":"{}","ev":{}}}"#,
            self.id,
            self.timestamp.replace('\\', "\\\\").replace('"', "\\\""),
            self.method.replace('\\', "\\\\").replace('"', "\\\""),
            self.uri.replace('\\', "\\\\").replace('"', "\\\""),
            self.status,
            self.elapsed_ms,
            self.content_length,
            self.remote_addr.replace('\\', "\\\\").replace('"', "\\\""),
            self.content_type.replace('\\', "\\\\").replace('"', "\\\""),
            ev_json,
        )
    }
}

struct DashboardState {
    next_id: AtomicU64,
    entries: Mutex<VecDeque<RequestRecord>>,
    total_requests: AtomicU64,
    total_errors: AtomicU64,
}

impl DashboardState {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(VecDeque::with_capacity(DASHBOARD_RING_SIZE)),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
        }
    }

    fn push(&self, method: String, uri: String, status: u16, elapsed_ms: u128, content_length: usize, remote_addr: String, content_type: String, events: Vec<(String, String, u128)>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if status >= 400 {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
        }
        let record = RequestRecord {
            id,
            timestamp: format_timestamp(),
            method,
            uri,
            status,
            elapsed_ms,
            content_length,
            remote_addr,
            content_type,
            events,
        };
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= DASHBOARD_RING_SIZE {
            entries.pop_front();
        }
        entries.push_back(record);
    }

    fn entries_since(&self, last_id: u64) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|r| r.id > last_id)
            .map(|r| format!("id: {}\ndata: {}\n", r.id, r.to_json()))
            .collect()
    }
}

// ── HTTP Request ────────────────────────────────────────────────────────────

/// A parsed HTTP request.
struct HttpRequest {
    method: String,
    uri: String,
    path: String,
    query_string: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    /// Remote address (client IP:port).
    remote_addr: String,
}

// ── MIME Types ──────────────────────────────────────────────────────────────

/// MIME types for static file serving.
fn mime_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=UTF-8",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "xhtml" => "application/xhtml+xml",
        "rss" => "application/rss+xml",
        "atom" => "application/atom+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "svg" | "svgz" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "txt" | "text" | "log" => "text/plain; charset=UTF-8",
        "csv" => "text/csv; charset=UTF-8",
        "tsv" => "text/tab-separated-values; charset=UTF-8",
        "md" | "markdown" => "text/markdown; charset=UTF-8",
        "yaml" | "yml" => "text/yaml; charset=UTF-8",
        "php" => "text/html; charset=UTF-8",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "ogg" => "audio/ogg",
        "ogv" => "video/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "wasm" => "application/wasm",
        "map" => "application/json",
        "swf" => "application/x-shockwave-flash",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "rtf" => "application/rtf",
        _ => "application/octet-stream",
    }
}

// ── HTTP Parsing ────────────────────────────────────────────────────────────

/// Parse an HTTP request from a buffered reader.
fn parse_request(
    reader: &mut BufReader<&mut std::net::TcpStream>,
    remote_addr: String,
) -> Option<HttpRequest> {
    // Read request line
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let uri = parts[1].to_string();

    // Split path and query string
    let (path, query_string) = if let Some(q) = uri.find('?') {
        (uri[..q].to_string(), uri[q + 1..].to_string())
    } else {
        (uri.clone(), String::new())
    };

    // Read headers
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end().to_string();
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    // Read body if Content-Length is present
    let body = if let Some(len_str) = headers.get("content-length") {
        if let Ok(len) = len_str.parse::<usize>() {
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).ok()?;
            body
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Some(HttpRequest {
        method,
        uri,
        path,
        query_string,
        headers,
        body,
        remote_addr,
    })
}

// ── Server Variables ────────────────────────────────────────────────────────

/// Build $_SERVER variables from an HTTP request.
fn build_server_vars(req: &HttpRequest, config: &ServerConfig) -> HashMap<String, String> {
    let mut server = HashMap::new();

    // Extract host and port from listen address
    let (host, port) = if let Some(colon) = config.listen.rfind(':') {
        (
            config.listen[..colon].to_string(),
            config.listen[colon + 1..].to_string(),
        )
    } else {
        (config.listen.clone(), "80".to_string())
    };

    server.insert("SERVER_SOFTWARE".into(), "php.rs built-in server".into());
    server.insert("SERVER_NAME".into(), host.clone());
    server.insert("SERVER_PORT".into(), port);
    server.insert("SERVER_PROTOCOL".into(), "HTTP/1.1".into());
    server.insert("GATEWAY_INTERFACE".into(), "CGI/1.1".into());
    server.insert("REQUEST_METHOD".into(), req.method.clone());
    server.insert("REQUEST_URI".into(), req.uri.clone());
    server.insert("SCRIPT_NAME".into(), req.path.clone());
    server.insert("QUERY_STRING".into(), req.query_string.clone());
    server.insert("DOCUMENT_ROOT".into(), config.docroot.display().to_string());
    server.insert("SERVER_ADDR".into(), host);
    server.insert("REMOTE_ADDR".into(), req.remote_addr.clone());

    // Map HTTP headers to $_SERVER format
    if let Some(ct) = req.headers.get("content-type") {
        server.insert("CONTENT_TYPE".into(), ct.clone());
    }
    if let Some(cl) = req.headers.get("content-length") {
        server.insert("CONTENT_LENGTH".into(), cl.clone());
    }
    if let Some(host) = req.headers.get("host") {
        server.insert("HTTP_HOST".into(), host.clone());
    }
    if let Some(ua) = req.headers.get("user-agent") {
        server.insert("HTTP_USER_AGENT".into(), ua.clone());
    }
    if let Some(accept) = req.headers.get("accept") {
        server.insert("HTTP_ACCEPT".into(), accept.clone());
    }
    if let Some(cookie) = req.headers.get("cookie") {
        server.insert("HTTP_COOKIE".into(), cookie.clone());
    }

    // Script filename
    let script_path = config.docroot.join(req.path.trim_start_matches('/'));
    server.insert("SCRIPT_FILENAME".into(), script_path.display().to_string());

    server
}

// ── HTTP Response Helpers ───────────────────────────────────────────────────

/// Get the standard status text for an HTTP status code.
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Send an HTTP response.
fn send_response(
    stream: &mut std::net::TcpStream,
    status: u16,
    status_text: &str,
    content_type: &str,
    extra_headers: &[String],
    body: &[u8],
) {
    let mut header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        status_text,
        content_type,
        body.len()
    );
    for h in extra_headers {
        // Skip Content-Type and Content-Length (already set above) to avoid duplicates
        if let Some(colon) = h.find(':') {
            let name = h[..colon].trim();
            if name.eq_ignore_ascii_case("content-type")
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
        }
        header.push_str(h);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Send a 404 response.
fn send_404(stream: &mut std::net::TcpStream, path: &str) {
    let body = format!(
        "<html><head><title>404 Not Found</title></head>\
         <body><h1>Not Found</h1><p>The requested URL {} was not found on this server.</p>\
         <hr><address>php.rs built-in server</address></body></html>",
        path
    );
    send_response(
        stream,
        404,
        "Not Found",
        "text/html; charset=UTF-8",
        &[],
        body.as_bytes(),
    );
}

/// Send a 500 response.
fn send_500(stream: &mut std::net::TcpStream, message: &str) {
    let body = format!(
        "<html><head><title>500 Internal Server Error</title></head>\
         <body><h1>Internal Server Error</h1><p>{}</p>\
         <hr><address>php.rs built-in server</address></body></html>",
        message
    );
    send_response(
        stream,
        500,
        "Internal Server Error",
        "text/html; charset=UTF-8",
        &[],
        body.as_bytes(),
    );
}

// ── PHP Execution ───────────────────────────────────────────────────────────

/// Result of a PHP router script execution.
enum RouterResult {
    /// Router handled the request — send this response.
    /// Fields: status, content_type, extra_headers, body, events
    Handled(u16, String, Vec<String>, Vec<u8>, Vec<(String, String, u128)>),
    /// Router returned false — fall through to static file serving.
    Fallthrough,
    /// Router script error.
    Error(String),
}

/// Execute a PHP router script, checking for false return (fallthrough).
///
/// In PHP's built-in server, if a router script returns `false`, the server
/// falls through to serve the requested file directly (static or PHP).
fn execute_router_script(
    script_path: &Path,
    req: &HttpRequest,
    config: &ServerConfig,
) -> RouterResult {
    let source = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            return RouterResult::Error(format!("Failed to read {}: {}", script_path.display(), e))
        }
    };

    let abs_path = script_path
        .canonicalize()
        .unwrap_or_else(|_| script_path.to_path_buf());
    let filename = abs_path.to_string_lossy();
    let op_array = match php_rs_compiler::compile_file(&source, &filename) {
        Ok(oa) => oa,
        Err(e) => return RouterResult::Error(format!("{}", e)),
    };

    let mut vm = php_rs_vm::Vm::new();
    let superglobals = build_superglobals(req, config);

    let raw_body = String::from_utf8_lossy(&req.body).to_string();
    vm.set_raw_input_body(raw_body);

    match vm.execute(&op_array, Some(&superglobals)) {
        Ok(output) => {
            // Check if the script returned false (fallthrough)
            let last_return = vm.last_return_value();
            if is_false_return(&last_return) && output.is_empty() {
                return RouterResult::Fallthrough;
            }

            let status = vm.response_code().unwrap_or(200);
            let content_type = extract_content_type(&vm);
            let body = php_output_to_bytes(&output, &content_type);
            let extra_headers = vm.response_headers().to_vec();
            let events = take_vm_events(&mut vm);
            RouterResult::Handled(status, content_type, extra_headers, body, events)
        }
        Err(php_rs_vm::VmError::Exit(_)) => {
            // exit() means the script handled the request — never fallthrough.
            let output = vm.output_so_far();
            let status = vm.response_code().unwrap_or(200);
            let content_type = extract_content_type(&vm);
            let body = php_output_to_bytes(&output, &content_type);
            let extra_headers = vm.response_headers().to_vec();
            let events = take_vm_events(&mut vm);
            RouterResult::Handled(status, content_type, extra_headers, body, events)
        }
        Err(e) => RouterResult::Error(format!("{:?}", e)),
    }
}

/// Convert PHP output to response bytes, using the Content-Type to decide encoding.
/// Text content (HTML, JSON, XML, etc.) uses UTF-8 (into_bytes).
/// Binary content (images, octet-stream, etc.) uses Latin-1 (byte-per-char).
fn php_output_to_bytes(s: &str, content_type: &str) -> Vec<u8> {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("text/")
        || ct.starts_with("application/json")
        || ct.starts_with("application/xml")
        || ct.starts_with("application/xhtml")
        || ct.starts_with("application/rss")
        || ct.starts_with("application/atom")
    {
        s.as_bytes().to_vec()
    } else {
        // Binary content: each char is one byte (Latin-1 mapping)
        s.chars().map(|c| c as u8).collect()
    }
}

fn is_false_return(value: &Option<Value>) -> bool {
    match value {
        Some(Value::Bool(false)) => true,
        None => false,
        _ => false,
    }
}

/// Extract Content-Type from VM response headers.
fn extract_content_type(vm: &php_rs_vm::Vm) -> String {
    for h in vm.response_headers() {
        if let Some(colon) = h.find(':') {
            if h[..colon].trim().eq_ignore_ascii_case("content-type") {
                return h[colon + 1..].trim().to_string();
            }
        }
    }
    "text/html; charset=UTF-8".to_string()
}

/// Execute a PHP script for an HTTP request.
/// Returns (status, content_type, extra_headers, body, events).
fn execute_php_request(
    script_path: &Path,
    req: &HttpRequest,
    config: &ServerConfig,
) -> Result<(u16, String, Vec<String>, Vec<u8>, Vec<(String, String, u128)>), String> {
    let source = std::fs::read_to_string(script_path)
        .map_err(|e| format!("Failed to read {}: {}", script_path.display(), e))?;

    let abs_path = script_path
        .canonicalize()
        .unwrap_or_else(|_| script_path.to_path_buf());
    let filename = abs_path.to_string_lossy();
    let op_array =
        php_rs_compiler::compile_file(&source, &filename).map_err(|e| format!("{}", e))?;

    let mut vm = php_rs_vm::Vm::new();
    let superglobals = build_superglobals(req, config);

    let raw_body = String::from_utf8_lossy(&req.body).to_string();
    vm.set_raw_input_body(raw_body);

    match vm.execute(&op_array, Some(&superglobals)) {
        Ok(output) => {
            let status = vm.response_code().unwrap_or(200);
            let content_type = extract_content_type(&vm);
            let body = php_output_to_bytes(&output, &content_type);
            let extra_headers = vm.response_headers().to_vec();
            let events = take_vm_events(&mut vm);
            Ok((status, content_type, extra_headers, body, events))
        }
        Err(php_rs_vm::VmError::Exit(_)) => {
            let status = vm.response_code().unwrap_or(200);
            let output = vm.output_so_far();
            let content_type = extract_content_type(&vm);
            let body = php_output_to_bytes(&output, &content_type);
            let extra_headers = vm.response_headers().to_vec();
            let events = take_vm_events(&mut vm);
            Ok((status, content_type, extra_headers, body, events))
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}

/// Extract VM events as (kind, detail, elapsed_us) tuples.
fn take_vm_events(vm: &mut php_rs_vm::Vm) -> Vec<(String, String, u128)> {
    vm.take_events().into_iter().map(|e| (e.kind.to_string(), e.detail, e.elapsed_us)).collect()
}

/// Build all superglobals for a request.
fn build_superglobals(req: &HttpRequest, config: &ServerConfig) -> HashMap<String, Value> {
    let server_vars = build_server_vars(req, config);
    let get_vars = parse_query_string(&req.query_string);
    let mut multipart_files: Option<HashMap<String, String>> = None;
    let post_vars = if req.method == "POST" {
        if let Some(ct) = req.headers.get("content-type") {
            if ct.starts_with("application/x-www-form-urlencoded") {
                let body_str = String::from_utf8_lossy(&req.body);
                parse_query_string(&body_str)
            } else if ct.starts_with("multipart/form-data") {
                if let Some(boundary) = Superglobals::extract_boundary(ct) {
                    let mut sg = Superglobals::new();
                    let _ = sg.parse_multipart(
                        &req.body,
                        &boundary,
                        2 * 1024 * 1024,  // 2 MB max file size
                        8 * 1024 * 1024,  // 8 MB max post size
                    );
                    multipart_files = Some(sg.files);
                    sg.post
                } else {
                    HashMap::new()
                }
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    // Build $_REQUEST (merged GET + POST, POST wins on conflicts)
    let mut request_vars = get_vars.clone();
    for (k, v) in &post_vars {
        request_vars.insert(k.clone(), v.clone());
    }

    // Parse $_COOKIE from Cookie header
    let cookie_vars: HashMap<String, String> =
        if let Some(cookie_header) = req.headers.get("cookie") {
            let mut cookies = HashMap::new();
            for pair in cookie_header.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                if let Some(eq) = pair.find('=') {
                    cookies.insert(
                        pair[..eq].trim().to_string(),
                        pair[eq + 1..].trim().to_string(),
                    );
                }
            }
            cookies
        } else {
            HashMap::new()
        };

    // Add cookies to $_REQUEST
    for (k, v) in &cookie_vars {
        request_vars.insert(k.clone(), v.clone());
    }

    // Build $_ENV from process environment
    let env_vars: HashMap<String, String> = std::env::vars().collect();

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
    // Build $_FILES from multipart data (flat keys like "image[name]" → nested arrays)
    let files_array = if let Some(flat_files) = multipart_files {
        flat_files_to_php_array(&flat_files)
    } else {
        PhpArray::new()
    };
    superglobals.insert("_FILES".into(), Value::Array(files_array));

    superglobals
}

/// Convert flat $_FILES keys (e.g. "image[name]", "image[type]") into nested PhpArrays.
///
/// PHP expects `$_FILES['image']` to be an array with keys: name, type, tmp_name, error, size.
/// The Superglobals parser stores them as flat keys like `image[name]`, `image[type]`, etc.
fn flat_files_to_php_array(flat: &HashMap<String, String>) -> PhpArray {
    let mut files = PhpArray::new();

    // Group by field name
    let mut grouped: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (key, value) in flat {
        // Parse "fieldname[subkey]" format
        if let Some(bracket) = key.find('[') {
            if key.ends_with(']') {
                let field = &key[..bracket];
                let subkey = &key[bracket + 1..key.len() - 1];
                grouped
                    .entry(field.to_string())
                    .or_default()
                    .insert(subkey.to_string(), value.clone());
            }
        }
    }

    for (field_name, subkeys) in grouped {
        let mut entry = PhpArray::new();
        for (subkey, value) in subkeys {
            let v = match subkey.as_str() {
                "error" | "size" => {
                    Value::Long(value.parse::<i64>().unwrap_or(0))
                }
                _ => Value::String(value),
            };
            entry.set_string(subkey, v);
        }
        files.set_string(field_name, Value::Array(entry));
    }

    files
}

// ── URL Parsing ─────────────────────────────────────────────────────────────

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

// ── 10C.04: Access Logging ──────────────────────────────────────────────────

/// Format a timestamp for access logging (ISO 8601 UTC).
fn format_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Calculate UTC date and time from epoch seconds
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute year/month/day from days since epoch
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Log an access entry to stderr (matches PHP built-in server format).
fn log_access(
    remote_addr: &str,
    listen: &str,
    status: u16,
    method: &str,
    uri: &str,
    elapsed_ms: u128,
) {
    let timestamp = format_timestamp();
    eprintln!(
        "[{}] {}:{} [{}]: {} {} ({}ms)",
        timestamp, remote_addr, listen, status, method, uri, elapsed_ms
    );
}

// ── Dashboard SSE & HTML ────────────────────────────────────────────────────

/// Handle an SSE stream on a dedicated thread (frees pool worker).
fn handle_sse_stream(mut stream: std::net::TcpStream, state: Arc<DashboardState>, mut last_id: u64) {
    // Set write timeout so dead connections don't hang threads
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

    let header = "HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Cache-Control: no-cache\r\n\
                  Connection: keep-alive\r\n\
                  X-Accel-Buffering: no\r\n\
                  \r\n";
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();

    let mut idle_ticks: u32 = 0;
    loop {
        let events = state.entries_since(last_id);
        if events.is_empty() {
            idle_ticks += 1;
            // Send keepalive comment every ~3s (30 * 100ms)
            if idle_ticks >= 30 {
                if stream.write_all(b": keepalive\n\n").is_err() {
                    break;
                }
                let _ = stream.flush();
                idle_ticks = 0;
            }
        } else {
            idle_ticks = 0;
            for event in &events {
                if stream.write_all(event.as_bytes()).is_err() {
                    return;
                }
                if stream.write_all(b"\n").is_err() {
                    return;
                }
            }
            let _ = stream.flush();
            // Update last_id from the last event we sent
            // The event format is "id: N\ndata: ...\n"
            if let Some(last_event) = events.last() {
                if let Some(id_line) = last_event.lines().next() {
                    if let Some(id_str) = id_line.strip_prefix("id: ") {
                        if let Ok(id) = id_str.parse::<u64>() {
                            last_id = id;
                        }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Generate the self-contained dashboard HTML page.
fn dashboard_html(listen: &str) -> String {
    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>php.rs dashboard</title>
<link rel="preconnect" href="https://fonts.bunny.net">
<link href="https://fonts.bunny.net/css?family=iosevka:400,700" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{color-scheme:light;--bg:oklch(.98 .005 260);--surface:oklch(.95 .005 260);--border:oklch(.88 .01 260);--fg:oklch(.2 .02 260);--fg2:oklch(.5 .02 260);--ok:oklch(.45 .2 145);--warn:oklch(.5 .17 80);--err:oklch(.5 .22 25);--accent:oklch(.5 .15 250)}}
html{{block-size:100dvh}}
body{{font:400 14px/1.5 Iosevka,ui-monospace,monospace;background:var(--bg);color:var(--fg);display:grid;grid-template-rows:auto 1fr;block-size:100dvh}}
header{{position:sticky;inset-block-start:0;z-index:1;background:var(--surface);border-block-end:1px solid var(--border);padding-block:.75rem;padding-inline:1.25rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}}
header h1{{font-size:1rem;font-weight:700;letter-spacing:.04em}}
.dot{{inline-size:8px;block-size:8px;border-radius:50%;background:var(--ok);animation:pulse 2s ease-in-out infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.dot.dead{{background:var(--err);animation:none}}
.stats{{margin-inline-start:auto;display:flex;gap:1.5rem;color:var(--fg2);font-size:.85rem}}
.stats b{{color:var(--fg)}}
.wrap{{overflow-y:auto;overflow-anchor:auto}}
table{{inline-size:100%;border-collapse:collapse}}
thead{{position:sticky;inset-block-start:0;background:var(--surface)}}
th{{text-align:start;padding:.5rem 1rem;color:var(--fg2);font-weight:400;font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;border-block-end:1px solid var(--border)}}
td{{padding:.35rem 1rem;border-block-end:1px solid var(--border);white-space:nowrap}}
tr.req{{cursor:pointer}}
tr.req:hover td{{background:oklch(.92 .005 260)}}
tr.detail{{display:none}}
tr.detail.open{{display:table-row}}
tr.detail td{{padding:.5rem 1rem;background:var(--surface);color:var(--fg2);white-space:pre-wrap;font-size:.85rem}}
tr.detail dl{{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1rem}}
tr.detail dt{{color:var(--fg2);text-transform:uppercase;font-size:.75rem;letter-spacing:.06em}}
tr.detail dd{{color:var(--fg)}}
.s2{{color:var(--ok)}}.s3{{color:var(--accent)}}.s4{{color:var(--warn)}}.s5{{color:var(--err)}}
.ms{{color:var(--fg2)}}
.anchor{{overflow-anchor:auto;block-size:1px}}
.empty{{padding:3rem;text-align:center;color:var(--fg2)}}
.ev-table{{inline-size:100%;border-collapse:collapse;margin-block-start:.5rem}}
.ev-table th{{text-align:start;padding:.25rem .5rem;color:var(--fg2);font-weight:400;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;border-block-end:1px solid var(--border)}}
.ev-table td{{padding:.2rem .5rem;border-block-end:1px solid var(--border);font-size:.8rem;white-space:nowrap}}
.ev-table td.ev-detail{{white-space:pre-wrap;word-break:break-all;max-inline-size:60ch;overflow:hidden;text-overflow:ellipsis}}
.badge{{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.7rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}}
.badge-sql{{background:oklch(.92 .08 250);color:oklch(.35 .15 250)}}
.badge-include{{background:oklch(.92 .02 260);color:oklch(.35 .02 260)}}
.badge-error{{background:oklch(.92 .1 25);color:oklch(.4 .2 25)}}
.badge-warning{{background:oklch(.92 .1 80);color:oklch(.4 .17 80)}}
.badge-notice{{background:oklch(.92 .1 90);color:oklch(.45 .15 90)}}
.no-events{{color:var(--fg2);font-size:.8rem;font-style:italic}}
</style>
</head>
<body>
<header>
  <span class="dot" id="dot"></span>
  <h1>php.rs &mdash; {listen}</h1>
  <div class="stats">
    <span>reqs <b id="cnt">0</b></span>
    <span>errs <b id="ecnt">0</b></span>
  </div>
</header>
<div class="wrap">
  <table>
    <thead><tr><th>time</th><th>method</th><th>uri</th><th>status</th><th>ms</th><th>size</th></tr></thead>
    <tbody id="tb"></tbody>
  </table>
  <div class="anchor"></div>
  <div class="empty" id="empty">Waiting for requests&hellip;</div>
</div>
<script>
(function(){{
  const tb=document.getElementById("tb"),dot=document.getElementById("dot");
  const cnt=document.getElementById("cnt"),ecnt=document.getElementById("ecnt");
  const empty=document.getElementById("empty");
  let reqs=0,errs=0;
  const es=new EventSource("/_php-rs/events");
  function fmt(n){{if(n<1024)return n+"B";if(n<1048576)return(n/1024).toFixed(1)+"K";return(n/1048576).toFixed(1)+"M"}}
  function esc(s){{const d=document.createElement("span");d.textContent=s;return d.innerHTML}}
  function badgeClass(k){{if(k==="sql")return"badge-sql";if(k==="include")return"badge-include";if(k==="error")return"badge-error";if(k==="warning")return"badge-warning";if(k==="notice")return"badge-notice";return"badge-include"}}
  function evRows(ev){{
    if(!ev||!ev.length)return"<span class=\"no-events\">no internal events</span>";
    let h="<table class=\"ev-table\"><thead><tr><th>type</th><th>detail</th><th>at</th></tr></thead><tbody>";
    for(let i=0;i<ev.length;i++){{
      const e=ev[i];
      const ms=(e.us/1000).toFixed(1);
      const detail=e.d.length>120?esc(e.d.slice(0,120))+"&hellip;":esc(e.d);
      h+="<tr><td><span class=\"badge "+badgeClass(e.k)+"\">"+esc(e.k)+"</span></td><td class=\"ev-detail\">"+detail+"</td><td class=\"ms\">"+ms+" ms</td></tr>";
    }}
    h+="</tbody></table>";
    return h;
  }}
  es.onmessage=function(e){{
    const d=JSON.parse(e.data);
    const tr=document.createElement("tr");
    tr.className="req";
    const sc=d.status<300?"s2":d.status<400?"s3":d.status<500?"s4":"s5";
    const evCount=d.ev&&d.ev.length?d.ev.length:0;
    tr.innerHTML="<td class=\"ms\">"+d.ts.slice(11)+"</td><td>"+esc(d.method)+"</td><td>"+esc(d.uri)+"</td><td class=\""+sc+"\">"+d.status+"</td><td class=\"ms\">"+d.ms+"</td><td class=\"ms\">"+fmt(d.len)+"</td>";
    const dr=document.createElement("tr");
    dr.className="detail";
    dr.innerHTML="<td colspan=\"6\"><dl><dt>id</dt><dd>"+d.id+"</dd><dt>timestamp</dt><dd>"+esc(d.ts)+"</dd><dt>method</dt><dd>"+esc(d.method)+"</dd><dt>uri</dt><dd>"+esc(d.uri)+"</dd><dt>status</dt><dd class=\""+sc+"\">"+d.status+"</dd><dt>elapsed</dt><dd>"+d.ms+" ms</dd><dt>size</dt><dd>"+fmt(d.len)+"</dd><dt>client</dt><dd>"+esc(d.addr)+"</dd><dt>content-type</dt><dd>"+esc(d.ct)+"</dd><dt>events ("+evCount+")</dt><dd>"+evRows(d.ev)+"</dd></dl></td>";
    tr.addEventListener("click",function(){{dr.classList.toggle("open")}});
    tb.appendChild(tr);
    tb.appendChild(dr);
    reqs++;if(d.status>=400)errs++;
    cnt.textContent=reqs;ecnt.textContent=errs;
    if(empty)empty.style.display="none";
  }};
  es.onerror=function(){{dot.classList.add("dead")}};
  es.onopen=function(){{dot.classList.remove("dead")}};
}})();
</script>
</body>
</html>"##, listen = listen)
}

// ── Connection Handling ─────────────────────────────────────────────────────

/// Handle a single HTTP connection.
/// Returns (status_code, method, uri) for access logging.
fn handle_connection(
    stream: &mut std::net::TcpStream,
    config: &ServerConfig,
    remote_addr: &str,
    dashboard: &Arc<DashboardState>,
) -> Option<(u16, String, String)> {
    let start = Instant::now();

    let mut reader = BufReader::new(stream);
    let req = match parse_request(&mut reader, remote_addr.to_string()) {
        Some(r) => r,
        None => return None,
    };

    let method = req.method.clone();
    let uri = req.uri.clone();
    let stream = reader.into_inner();

    // Dashboard routes — intercept before router script (not logged)
    let path_trimmed = req.path.trim_end_matches('/');
    if path_trimmed == "/_php-rs" {
        let html = dashboard_html(&config.listen);
        send_response(
            stream,
            200,
            "OK",
            "text/html; charset=UTF-8",
            &["Cache-Control: no-store".into()],
            html.as_bytes(),
        );
        return None; // don't log dashboard requests
    }
    if req.path == "/_php-rs/events" {
        let last_id = req
            .headers
            .get("last-event-id")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if let Ok(cloned) = stream.try_clone() {
            let dash = Arc::clone(dashboard);
            std::thread::spawn(move || {
                handle_sse_stream(cloned, dash, last_id);
            });
        }
        return None; // SSE handled on dedicated thread, don't log
    }

    // 10C.01: Router script with false-return fallthrough
    if let Some(ref router) = config.router {
        if router.exists() {
            match execute_router_script(router, &req, config) {
                RouterResult::Handled(status, content_type, extra_headers, body, events) => {
                    let len = body.len();
                    send_response(stream, status, status_text(status), &content_type, &extra_headers, &body);
                    let elapsed = start.elapsed().as_millis();
                    log_access(remote_addr, &config.listen, status, &method, &uri, elapsed);
                    dashboard.push(method.clone(), uri.clone(), status, elapsed, len, remote_addr.to_string(), content_type, events);
                    return Some((status, method, uri));
                }
                RouterResult::Fallthrough => {
                    // Fall through to normal file serving below
                }
                RouterResult::Error(msg) => {
                    let len = msg.len();
                    send_500(stream, &msg);
                    let elapsed = start.elapsed().as_millis();
                    log_access(remote_addr, &config.listen, 500, &method, &uri, elapsed);
                    dashboard.push(method.clone(), uri.clone(), 500, elapsed, len, remote_addr.to_string(), "text/html".into(), vec![]);
                    return Some((500, method, uri));
                }
            }
        }
    }

    // Resolve the file path
    let mut file_path = config.docroot.join(req.path.trim_start_matches('/'));

    // If path is a directory, look for index files (PHP priority, then HTML)
    if file_path.is_dir() {
        let candidates = ["index.php", "index.html", "index.htm"];
        let mut found = false;
        for name in &candidates {
            let candidate = file_path.join(name);
            if candidate.exists() {
                file_path = candidate;
                found = true;
                break;
            }
        }
        if !found {
            send_404(stream, &req.path);
            let elapsed = start.elapsed().as_millis();
            log_access(remote_addr, &config.listen, 404, &method, &uri, elapsed);
            dashboard.push(method.clone(), uri.clone(), 404, elapsed, 0, remote_addr.to_string(), "text/html".into(), vec![]);
            return Some((404, method, uri));
        }
    }

    if !file_path.exists() {
        send_404(stream, &req.path);
        let elapsed = start.elapsed().as_millis();
        log_access(remote_addr, &config.listen, 404, &method, &uri, elapsed);
        dashboard.push(method.clone(), uri.clone(), 404, elapsed, 0, remote_addr.to_string(), "text/html".into(), vec![]);
        return Some((404, method, uri));
    }

    // Check if it's a PHP file
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let (status, content_len, ct_str, php_events) = if ext == "php" {
        match execute_php_request(&file_path, &req, config) {
            Ok((status, content_type, extra_headers, body, events)) => {
                let len = body.len();
                send_response(stream, status, status_text(status), &content_type, &extra_headers, &body);
                (status, len, content_type, events)
            }
            Err(msg) => {
                let len = msg.len();
                send_500(stream, &msg);
                (500, len, "text/html".to_string(), vec![])
            }
        }
    } else {
        // Serve static file
        match std::fs::read(&file_path) {
            Ok(contents) => {
                let len = contents.len();
                let ct = mime_type(file_path.to_str().unwrap_or(""));
                send_response(stream, 200, "OK", ct, &[], &contents);
                (200, len, ct.to_string(), vec![])
            }
            Err(_) => {
                send_404(stream, &req.path);
                (404, 0, "text/html".to_string(), vec![])
            }
        }
    };

    let elapsed = start.elapsed().as_millis();
    log_access(remote_addr, &config.listen, status, &method, &uri, elapsed);
    dashboard.push(method.clone(), uri.clone(), status, elapsed, content_len, remote_addr.to_string(), ct_str, php_events);
    Some((status, method, uri))
}

// ── 10C.03: Concurrent Request Handling (Thread Pool) ───────────────────────

/// A simple thread pool for handling concurrent connections.
struct ThreadPool {
    workers: Vec<std::thread::JoinHandle<()>>,
    sender: std::sync::mpsc::Sender<Job>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    /// Create a new thread pool with the given number of worker threads.
    fn new(size: usize) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel::<Job>();
        let receiver = Arc::new(std::sync::Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);
        for _ in 0..size {
            let rx = Arc::clone(&receiver);
            let handle = std::thread::spawn(move || loop {
                let job = {
                    let lock = rx.lock().unwrap();
                    lock.recv()
                };
                match job {
                    Ok(job) => job(),
                    Err(_) => break, // Channel closed, exit
                }
            });
            workers.push(handle);
        }

        Self { workers, sender }
    }

    /// Submit a job to the thread pool.
    fn execute<F: FnOnce() + Send + 'static>(&self, f: F) {
        let _ = self.sender.send(Box::new(f));
    }

    /// Shut down the thread pool, waiting for all workers to finish.
    fn shutdown(self) {
        drop(self.sender);
        for handle in self.workers {
            let _ = handle.join();
        }
    }
}

// ── Server Entry Point ──────────────────────────────────────────────────────

/// Number of worker threads for the built-in server.
const DEFAULT_THREAD_POOL_SIZE: usize = 4;

/// Start the built-in HTTP server with concurrent request handling.
pub fn run_server(config: ServerConfig) -> i32 {
    eprintln!(
        "php.rs Development Server (http://{}) started",
        config.listen
    );
    eprintln!(
        "Document root is {}",
        config
            .docroot
            .canonicalize()
            .unwrap_or(config.docroot.clone())
            .display()
    );
    if let Some(ref router) = config.router {
        eprintln!("Router script is {}", router.display());
    }
    eprintln!(
        "Dashboard at http://{}/_php-rs",
        config.listen
    );
    eprintln!("Press Ctrl+C to quit.");

    let listener = match TcpListener::bind(&config.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to listen on {}: {}", config.listen, e);
            return 1;
        }
    };

    // 10C.03: Use thread pool for concurrent handling
    let pool = ThreadPool::new(DEFAULT_THREAD_POOL_SIZE);
    let config = Arc::new(config);
    let dashboard = Arc::new(DashboardState::new());

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let config = Arc::clone(&config);
                let dashboard = Arc::clone(&dashboard);
                let remote_addr = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".into());
                pool.execute(move || {
                    handle_connection(&mut stream, &config, &remote_addr, &dashboard);
                });
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }

    pool.shutdown();
    0
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_type() {
        assert_eq!(mime_type("index.html"), "text/html; charset=UTF-8");
        assert_eq!(mime_type("style.css"), "text/css");
        assert_eq!(mime_type("app.js"), "application/javascript");
        assert_eq!(mime_type("data.json"), "application/json");
        assert_eq!(mime_type("image.png"), "image/png");
        assert_eq!(mime_type("script.php"), "text/html; charset=UTF-8");
        assert_eq!(mime_type("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("a%3Db%26c"), "a=b&c");
        assert_eq!(url_decode("plain"), "plain");
    }

    #[test]
    fn test_parse_query_string() {
        let qs = parse_query_string("foo=bar&baz=123&empty=");
        assert_eq!(qs.get("foo").unwrap(), "bar");
        assert_eq!(qs.get("baz").unwrap(), "123");
        assert_eq!(qs.get("empty").unwrap(), "");
    }

    #[test]
    fn test_parse_query_string_empty() {
        let qs = parse_query_string("");
        assert!(qs.is_empty());
    }

    #[test]
    fn test_parse_query_string_encoded() {
        let qs = parse_query_string("name=John+Doe&city=New%20York");
        assert_eq!(qs.get("name").unwrap(), "John Doe");
        assert_eq!(qs.get("city").unwrap(), "New York");
    }

    #[test]
    fn test_build_server_vars() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/index.php?page=1".into(),
            path: "/index.php".into(),
            query_string: "page=1".into(),
            headers: {
                let mut h = HashMap::new();
                h.insert("host".into(), "localhost:8080".into());
                h.insert("user-agent".into(), "TestAgent/1.0".into());
                h
            },
            body: Vec::new(),
            remote_addr: "127.0.0.1:54321".into(),
        };
        let config = ServerConfig {
            listen: "localhost:8080".into(),
            docroot: PathBuf::from("/var/www"),
            router: None,
        };
        let vars = build_server_vars(&req, &config);
        assert_eq!(vars.get("REQUEST_METHOD").unwrap(), "GET");
        assert_eq!(vars.get("REQUEST_URI").unwrap(), "/index.php?page=1");
        assert_eq!(vars.get("QUERY_STRING").unwrap(), "page=1");
        assert_eq!(vars.get("SCRIPT_NAME").unwrap(), "/index.php");
        assert_eq!(vars.get("SERVER_PORT").unwrap(), "8080");
        assert_eq!(vars.get("HTTP_HOST").unwrap(), "localhost:8080");
        assert_eq!(vars.get("HTTP_USER_AGENT").unwrap(), "TestAgent/1.0");
        assert_eq!(vars.get("DOCUMENT_ROOT").unwrap(), "/var/www");
        assert_eq!(vars.get("REMOTE_ADDR").unwrap(), "127.0.0.1:54321");
    }

    #[test]
    fn test_build_server_vars_post() {
        let req = HttpRequest {
            method: "POST".into(),
            uri: "/submit".into(),
            path: "/submit".into(),
            query_string: String::new(),
            headers: {
                let mut h = HashMap::new();
                h.insert(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                );
                h.insert("content-length".into(), "11".into());
                h
            },
            body: b"name=foobar".to_vec(),
            remote_addr: "127.0.0.1:12345".into(),
        };
        let config = ServerConfig {
            listen: "0.0.0.0:9000".into(),
            docroot: PathBuf::from("/tmp"),
            router: None,
        };
        let vars = build_server_vars(&req, &config);
        assert_eq!(vars.get("REQUEST_METHOD").unwrap(), "POST");
        assert_eq!(
            vars.get("CONTENT_TYPE").unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(vars.get("CONTENT_LENGTH").unwrap(), "11");
    }

    #[test]
    fn test_server_serves_php() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_server_test");
        let _ = std::fs::create_dir_all(&dir);
        let php_file = dir.join("hello.php");
        let mut f = std::fs::File::create(&php_file).unwrap();
        write!(f, "<?php echo \"Hello from server!\";").unwrap();
        drop(f);

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/hello.php".into(),
            path: "/hello.php".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _ct, _hdrs, body, _) = execute_php_request(&php_file, &req, &config).unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body), "Hello from server!");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_server_static_file() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_static_test");
        let _ = std::fs::create_dir_all(&dir);
        let html_file = dir.join("page.html");
        let mut f = std::fs::File::create(&html_file).unwrap();
        write!(f, "<h1>Static</h1>").unwrap();
        drop(f);

        assert_eq!(mime_type("page.html"), "text/html; charset=UTF-8");
        let contents = std::fs::read_to_string(&html_file).unwrap();
        assert_eq!(contents, "<h1>Static</h1>");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_server_index_resolution() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_index_test");
        let _ = std::fs::create_dir_all(&dir);

        let index = dir.join("index.php");
        let mut f = std::fs::File::create(&index).unwrap();
        write!(f, "<?php echo \"Index!\";").unwrap();
        drop(f);

        assert!(dir.is_dir());
        let index_php = dir.join("index.php");
        assert!(index_php.exists());

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/".into(),
            path: "/".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _, _, body, _) = execute_php_request(&index_php, &req, &config).unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body), "Index!");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_server_post_parsing() {
        let body = "username=admin&password=secret";
        let vars = parse_query_string(body);
        assert_eq!(vars.get("username").unwrap(), "admin");
        assert_eq!(vars.get("password").unwrap(), "secret");
    }

    #[test]
    fn test_server_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
        drop(listener);
    }

    #[test]
    fn test_superglobals_injected() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_superglobal_test");
        let _ = std::fs::create_dir_all(&dir);
        let php_file = dir.join("test.php");
        let mut f = std::fs::File::create(&php_file).unwrap();
        write!(
            f,
            r#"<?php echo $_SERVER['REQUEST_METHOD'] . " " . $_GET['name'] . " " . $_SERVER['QUERY_STRING'];"#
        )
        .unwrap();
        drop(f);

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/test.php?name=world".into(),
            path: "/test.php".into(),
            query_string: "name=world".into(),
            headers: {
                let mut h = HashMap::new();
                h.insert("host".into(), "localhost:8080".into());
                h
            },
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:8080".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _, _, body, _) = execute_php_request(&php_file, &req, &config).unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body), "GET world name=world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_post_superglobals_injected() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_post_superglobal_test");
        let _ = std::fs::create_dir_all(&dir);
        let php_file = dir.join("post.php");
        let mut f = std::fs::File::create(&php_file).unwrap();
        write!(
            f,
            r#"<?php echo $_POST['username'] . ":" . $_POST['password'];"#
        )
        .unwrap();
        drop(f);

        let req = HttpRequest {
            method: "POST".into(),
            uri: "/post.php".into(),
            path: "/post.php".into(),
            query_string: String::new(),
            headers: {
                let mut h = HashMap::new();
                h.insert(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                );
                h.insert("content-length".into(), "29".into());
                h
            },
            body: b"username=admin&password=s3cr3t".to_vec(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:8080".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _, _, body, _) = execute_php_request(&php_file, &req, &config).unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body), "admin:s3cr3t");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 10C.01: Router Script Tests ─────────────────────────────────────

    #[test]
    fn test_router_script_handles_request() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_router_handle_test");
        let _ = std::fs::create_dir_all(&dir);
        let router = dir.join("router.php");
        let mut f = std::fs::File::create(&router).unwrap();
        write!(f, "<?php echo \"Routed!\";").unwrap();
        drop(f);

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/anything".into(),
            path: "/anything".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };

        match execute_router_script(&router, &req, &config) {
            RouterResult::Handled(status, _, _, body, _) => {
                assert_eq!(status, 200);
                assert_eq!(String::from_utf8_lossy(&body), "Routed!");
            }
            RouterResult::Fallthrough => panic!("Expected Handled, got Fallthrough"),
            RouterResult::Error(e) => panic!("Expected Handled, got Error: {}", e),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_router_script_fallthrough() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_router_fallthrough_test");
        let _ = std::fs::create_dir_all(&dir);
        let router = dir.join("router.php");
        let mut f = std::fs::File::create(&router).unwrap();
        write!(f, "<?php return false;").unwrap();
        drop(f);

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/style.css".into(),
            path: "/style.css".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };

        match execute_router_script(&router, &req, &config) {
            RouterResult::Fallthrough => {} // Expected
            RouterResult::Handled(_, _, _, body, _) => {
                panic!(
                    "Expected Fallthrough, got Handled with body: {}",
                    String::from_utf8_lossy(&body)
                );
            }
            RouterResult::Error(e) => panic!("Expected Fallthrough, got Error: {}", e),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_router_with_output_not_fallthrough() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_router_output_test");
        let _ = std::fs::create_dir_all(&dir);
        let router = dir.join("router.php");
        let mut f = std::fs::File::create(&router).unwrap();
        // Router that outputs something should NOT fallthrough even with false return
        write!(f, "<?php echo \"handled\"; return false;").unwrap();
        drop(f);

        let req = HttpRequest {
            method: "GET".into(),
            uri: "/test".into(),
            path: "/test".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:0".into(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };

        match execute_router_script(&router, &req, &config) {
            RouterResult::Handled(_, _, _, body, _) => {
                assert_eq!(String::from_utf8_lossy(&body), "handled");
            }
            _ => panic!("Expected Handled (output present)"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 10C.04: Access Logging Tests ────────────────────────────────────

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp();
        // Should be YYYY-MM-DD HH:MM:SS format
        assert_eq!(ts.len(), 19);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 = 19723 days since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_leap_year() {
        // 2024-02-29 = 19723 + 31 + 28 = 19782 (2024 is leap year)
        let (y, m, d) = days_to_ymd(19782);
        assert_eq!(y, 2024);
        assert_eq!(m, 2);
        assert_eq!(d, 29);
    }

    // ── 10C.03: Thread Pool Tests ───────────────────────────────────────

    #[test]
    fn test_thread_pool_executes_jobs() {
        let pool = ThreadPool::new(2);
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));

        for _ in 0..10 {
            let c = Arc::clone(&counter);
            pool.execute(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }

        pool.shutdown();
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            10,
            "All 10 jobs should have executed"
        );
    }

    #[test]
    fn test_thread_pool_concurrent_execution() {
        let pool = ThreadPool::new(4);
        let start = Instant::now();
        let barrier = Arc::new(std::sync::Barrier::new(4));

        for _ in 0..4 {
            let b = Arc::clone(&barrier);
            pool.execute(move || {
                b.wait();
                std::thread::sleep(std::time::Duration::from_millis(50));
            });
        }

        pool.shutdown();
        let elapsed = start.elapsed();
        // If truly concurrent, 4 sleeps of 50ms should complete in ~50-100ms, not 200ms
        assert!(
            elapsed.as_millis() < 200,
            "Should be concurrent, took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_is_false_return() {
        assert!(is_false_return(&Some(Value::Bool(false))));
        assert!(!is_false_return(&Some(Value::Bool(true))));
        assert!(!is_false_return(&Some(Value::Null)));
        assert!(!is_false_return(&None));
        assert!(!is_false_return(&Some(Value::Long(0))));
    }

    // ── Concurrent Server Integration Test ──────────────────────────────

    #[test]
    fn test_concurrent_server_handles_multiple_requests() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("php_rs_concurrent_test");
        let _ = std::fs::create_dir_all(&dir);
        let html_file = dir.join("test.html");
        let mut f = std::fs::File::create(&html_file).unwrap();
        write!(f, "OK").unwrap();
        drop(f);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig {
            listen: addr.to_string(),
            docroot: dir.clone(),
            router: None,
        });

        // Start server in a thread
        let server_config = Arc::clone(&config);
        let server_thread = std::thread::spawn(move || {
            let pool = ThreadPool::new(2);
            let dashboard = Arc::new(DashboardState::new());
            // Accept 3 connections then stop
            for _ in 0..3 {
                if let Ok(mut stream) = listener.accept() {
                    let sc = Arc::clone(&server_config);
                    let dash = Arc::clone(&dashboard);
                    let remote = stream
                        .0
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    pool.execute(move || {
                        handle_connection(&mut stream.0, &sc, &remote, &dash);
                    });
                }
            }
            pool.shutdown();
        });

        // Send 3 requests concurrently
        let mut client_handles = Vec::new();
        for _ in 0..3 {
            let a = addr;
            let handle = std::thread::spawn(move || {
                let mut client = std::net::TcpStream::connect(a).unwrap();
                client
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                write!(client, "GET /test.html HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
                client.flush().unwrap();

                let mut response = String::new();
                let _ = client.read_to_string(&mut response);
                response
            });
            client_handles.push(handle);
        }

        for handle in client_handles {
            let response = handle.join().unwrap();
            assert!(response.contains("200 OK"), "Response: {}", response);
            assert!(response.contains("OK"));
        }

        server_thread.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
