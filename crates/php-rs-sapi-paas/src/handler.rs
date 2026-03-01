//! HTTP request handling — parse requests, route to PHP or static files,
//! build responses.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use php_rs_vm::vm::{Vm, VmConfig, VmError};

use crate::config::AppConfig;
use crate::logging::{self, Logger};
use crate::metrics::Metrics;
use crate::mime;
use crate::superglobals;

/// A parsed HTTP request.
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub path: String,
    pub query_string: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub remote_addr: String,
}

/// Handle a single TCP connection.
pub fn handle_connection(
    mut stream: TcpStream,
    vm: &mut Vm,
    config: &AppConfig,
    metrics: &Metrics,
    logger: &Logger,
    ready: &AtomicBool,
) {
    let remote_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let start = Instant::now();
    let request_id = logging::next_request_id();

    let req = {
        let mut reader = BufReader::new(&mut stream);
        match parse_request(&mut reader, remote_addr) {
            Some(req) => req,
            None => return,
        }
    };

    let method = req.method.clone();
    let path = req.path.clone();

    // Platform endpoints — bypass PHP entirely.
    if req.path == config.health_path {
        send_response(&mut stream, 200, "text/plain", &[], b"ok");
        log_request(logger, metrics, &method, &path, 200, start, 2, &request_id);
        return;
    }
    if req.path == config.ready_path {
        let status = if ready.load(Ordering::Relaxed) { 200 } else { 503 };
        let body = if status == 200 { b"ready" as &[u8] } else { b"not ready" };
        send_response(&mut stream, status, "text/plain", &[], body);
        log_request(logger, metrics, &method, &path, status, start, body.len(), &request_id);
        return;
    }
    if req.path == config.metrics_path {
        let body = metrics.render();
        send_response(&mut stream, 200, "text/plain; version=0.0.4", &[], body.as_bytes());
        log_request(logger, metrics, &method, &path, 200, start, body.len(), &request_id);
        return;
    }

    // Static file check — serve directly if the path maps to a static asset.
    let docroot = config.document_root_path();
    let relative_path = req.path.trim_start_matches('/');
    let static_path = docroot.join(relative_path);
    if let Some(ext) = static_path.extension().and_then(|e| e.to_str()) {
        if config.is_static_extension(ext) && static_path.is_file() {
            serve_static_file(&mut stream, &static_path, logger, metrics, &method, &path, start, &request_id);
            return;
        }
    }

    // PHP execution — all other requests go through the entry script.
    let entry_path = config.entry_script_path();
    if !entry_path.exists() {
        let body = format!(
            "<h1>500 Internal Server Error</h1><p>Entry script not found: {}</p>",
            entry_path.display()
        );
        send_response(&mut stream, 500, "text/html; charset=UTF-8", &[], body.as_bytes());
        log_request(logger, metrics, &method, &path, 500, start, body.len(), &request_id);
        metrics.record_php_error();
        return;
    }

    execute_php(&mut stream, vm, &req, config, metrics, logger, start, &request_id);
}

/// Execute PHP for a request using the worker's warm VM.
fn execute_php(
    stream: &mut TcpStream,
    vm: &mut Vm,
    req: &HttpRequest,
    config: &AppConfig,
    metrics: &Metrics,
    logger: &Logger,
    start: Instant,
    request_id: &str,
) {
    let entry_path = config.entry_script_path();
    let abs_path = entry_path
        .canonicalize()
        .unwrap_or_else(|_| entry_path.clone());
    let filename = abs_path.to_string_lossy().to_string();

    // Compile with opcode caching — the VM caches compiled op arrays keyed by
    // file path + mtime, so repeated requests skip parsing and compilation.
    let op_array = match vm.compile_cached(&filename) {
        Ok(oa) => oa,
        Err(e) => {
            let msg = format_vm_error(&e);
            let body = format!("<h1>500 Internal Server Error</h1><p>{}</p>", msg);
            send_response(stream, 500, "text/html; charset=UTF-8", &[], body.as_bytes());
            log_request(logger, metrics, &req.method, &req.path, 500, start, body.len(), request_id);
            metrics.record_php_error();
            return;
        }
    };

    // Apply config to VM.
    let mut vm_config = VmConfig {
        memory_limit: config.memory_limit_bytes(),
        max_execution_time: config.max_execution_time,
        ..VmConfig::default()
    };

    // Apply security settings.
    if !config.disable_functions.is_empty() {
        vm_config.set_disabled_functions(&config.disable_functions);
    }
    let open_basedir = config.open_basedir();
    if !open_basedir.is_empty() {
        vm_config.set_open_basedir(&open_basedir);
    }
    vm.apply_config(vm_config);

    // Apply INI overrides.
    for (key, value) in &config.ini_overrides {
        vm.ini_force_set(key, value);
    }

    // Security INI defaults for PaaS.
    if config.sandbox_enabled {
        vm.ini_force_set("allow_url_include", "0");
        vm.ini_force_set("enable_dl", "0");
    }

    // Set php://input body.
    let raw_body = String::from_utf8_lossy(&req.body).to_string();
    vm.set_raw_input_body(raw_body);

    // Build superglobals and execute.
    let sg = superglobals::build_superglobals(req, config);

    let (output, _had_error) = match vm.execute(&op_array, Some(&sg)) {
        Ok(output) => (output, false),
        Err(VmError::Exit(_)) => {
            // exit()/die() — collect any partial output.
            (vm.output_so_far(), false)
        }
        Err(e) => {
            metrics.record_php_error();
            let partial = vm.output_so_far();
            let error_msg = format_vm_error(&e);

            if partial.is_empty() {
                let body = format!("<h1>500 Internal Server Error</h1><p>{}</p>", error_msg);
                send_response(stream, 500, "text/html; charset=UTF-8", &[], body.as_bytes());
                log_request(logger, metrics, &req.method, &req.path, 500, start, body.len(), request_id);
                return;
            } else {
                // Partial output exists — send what we have.
                (partial, true)
            }
        }
    };

    // Collect response metadata from the VM.
    let status = vm.take_response_code().unwrap_or(200);
    let php_headers = vm.take_response_headers();

    // Determine content type from PHP headers, or default.
    let content_type = php_headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("content-type:"))
        .map(|h| h[13..].trim().to_string())
        .unwrap_or_else(|| "text/html; charset=UTF-8".to_string());

    // Build extra headers (filter out content-type since we set it explicitly).
    let extra_headers: Vec<String> = php_headers
        .iter()
        .filter(|h| !h.to_lowercase().starts_with("content-type:"))
        .cloned()
        .collect();

    let body = output.as_bytes();
    send_response(stream, status, &content_type, &extra_headers, body);
    log_request(logger, metrics, &req.method, &req.path, status, start, body.len(), request_id);
}

/// Serve a static file directly.
fn serve_static_file(
    stream: &mut TcpStream,
    path: &Path,
    logger: &Logger,
    metrics: &Metrics,
    method: &str,
    req_path: &str,
    start: Instant,
    request_id: &str,
) {
    match std::fs::read(path) {
        Ok(contents) => {
            let content_type = mime::mime_type(&path.to_string_lossy());
            send_response(stream, 200, content_type, &[], &contents);
            metrics.record_static();
            log_request(logger, metrics, method, req_path, 200, start, contents.len(), request_id);
        }
        Err(_) => {
            send_response(stream, 404, "text/plain", &[], b"Not Found");
            log_request(logger, metrics, method, req_path, 404, start, 9, request_id);
        }
    }
}

// ── HTTP Parsing ────────────────────────────────────────────────────────────

/// Parse an HTTP request from a buffered reader.
pub fn parse_request(
    reader: &mut BufReader<&mut TcpStream>,
    remote_addr: String,
) -> Option<HttpRequest> {
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

    let (path, query_string) = if let Some(q) = uri.find('?') {
        (uri[..q].to_string(), uri[q + 1..].to_string())
    } else {
        (uri.clone(), String::new())
    };

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

// ── HTTP Response ───────────────────────────────────────────────────────────

/// Send an HTTP response.
fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    extra_headers: &[String],
    body: &[u8],
) {
    let mut header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        status_text(status),
        content_type,
        body.len(),
    );
    for h in extra_headers {
        if let Some(colon) = h.find(':') {
            let name = h[..colon].trim();
            if name.eq_ignore_ascii_case("content-type")
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
        }
        header.push_str(h);
        if !h.ends_with("\r\n") {
            header.push_str("\r\n");
        }
    }
    header.push_str("\r\n");
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

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
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

fn format_vm_error(e: &VmError) -> String {
    match e {
        VmError::FatalError(msg) => format!("Fatal error: {}", msg),
        VmError::TypeError(msg) => format!("TypeError: {}", msg),
        VmError::DivisionByZero => "Division by zero".to_string(),
        VmError::UndefinedVariable(name) => format!("Undefined variable ${}", name),
        VmError::UndefinedFunction(name) => format!("Call to undefined function {}()", name),
        VmError::UndefinedClass(name) => format!("Class \"{}\" not found", name),
        VmError::UndefinedMethod(c, m) => format!("Call to undefined method {}::{}()", c, m),
        VmError::UndefinedProperty(c, p) => format!("Undefined property: {}::${}", c, p),
        VmError::UndefinedClassConstant(c, n) => format!("Undefined class constant {}::{}", c, n),
        VmError::MatchError => "Unhandled match case".to_string(),
        VmError::Thrown(val) => format!("Uncaught exception: {:?}", val),
        VmError::InternalError(msg) => format!("Internal error: {}", msg),
        VmError::Exit(code) => format!("exit({})", code),
        VmError::MemoryLimitExceeded(msg) => format!("Memory limit exceeded: {}", msg),
        VmError::TimeLimitExceeded(msg) => format!("Maximum execution time exceeded: {}", msg),
        VmError::DisabledFunction(name) => format!("Call to disabled function {}()", name),
    }
}

// ── Logging Helper ──────────────────────────────────────────────────────────

fn log_request(
    logger: &Logger,
    metrics: &Metrics,
    method: &str,
    path: &str,
    status: u16,
    start: Instant,
    bytes: usize,
    request_id: &str,
) {
    let duration = start.elapsed();
    let duration_ms = duration.as_millis();
    let duration_us = duration.as_micros() as u64;
    metrics.record_request(status, duration_us);
    logger.request(method, path, status, duration_ms, bytes, request_id);
}
