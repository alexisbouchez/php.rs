//! L7 reverse proxy — routes incoming HTTP requests to app processes by Host header.
//!
//! The router listens on port 80 (or configured port) and forwards requests
//! to the appropriate `php-rs-app` process based on the `Host` header.
//!
//! Routing modes:
//! - Default subdomain: `{app-name}.phprs.local` → app process
//! - Custom domain: `myapp.com` → app process (configured per app)
//!
//! The router reads the current state file on each request to discover
//! app→port mappings. In future, this will be replaced with a shared
//! in-memory routing table with hot reload.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rustls;

use crate::state::PlatformState;

/// A single backend instance for an app.
#[derive(Debug, Clone)]
pub struct BackendInstance {
    pub port: u16,
    pub healthy: bool,
}

/// A routing table entry — maps a domain to one or more backend instances.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub app_name: String,
    pub backend_port: u16,
    /// All backend instances for this app (for load balancing).
    pub backends: Vec<BackendInstance>,
    /// Whether sticky sessions are enabled for this app.
    pub sticky_sessions: bool,
}

impl RouteEntry {
    /// Select a backend using round-robin, skipping unhealthy instances.
    pub fn select_backend(&self, counter: u64) -> Option<u16> {
        let healthy: Vec<u16> = self.backends.iter()
            .filter(|b| b.healthy)
            .map(|b| b.port)
            .collect();
        if healthy.is_empty() {
            // Fallback to primary port.
            return Some(self.backend_port);
        }
        let idx = (counter as usize) % healthy.len();
        Some(healthy[idx])
    }

    /// Select a backend by sticky session hash.
    pub fn select_sticky(&self, session_id: &str) -> u16 {
        let healthy: Vec<u16> = self.backends.iter()
            .filter(|b| b.healthy)
            .map(|b| b.port)
            .collect();
        if healthy.is_empty() {
            return self.backend_port;
        }
        // Simple hash: sum of bytes modulo backend count.
        let hash: usize = session_id.bytes().map(|b| b as usize).sum();
        healthy[hash % healthy.len()]
    }
}

// ── Rate Limiting ──────────────────────────────────────────────────

/// Token bucket rate limiter.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Rate limiter with per-app and per-IP buckets.
pub struct RateLimiter {
    /// Per-app rate limit (requests per minute).
    per_app: Mutex<HashMap<String, TokenBucket>>,
    /// Per-IP rate limit (requests per minute).
    per_ip: Mutex<HashMap<IpAddr, TokenBucket>>,
    /// Default per-app requests per minute.
    pub app_rpm: f64,
    /// Default per-IP requests per minute.
    pub ip_rpm: f64,
    /// Maximum request body size in bytes (0 = unlimited).
    pub max_body_size: usize,
    /// Maximum header size in bytes.
    pub max_header_size: usize,
}

impl RateLimiter {
    pub fn new(app_rpm: f64, ip_rpm: f64) -> Self {
        Self {
            per_app: Mutex::new(HashMap::new()),
            per_ip: Mutex::new(HashMap::new()),
            app_rpm,
            ip_rpm,
            max_body_size: 10 * 1024 * 1024, // 10 MB default
            max_header_size: 16 * 1024, // 16 KB default
        }
    }

    /// Check if a request is allowed for the given app and IP.
    pub fn check(&self, app_name: &str, ip: IpAddr) -> RateLimitResult {
        // Check per-IP limit.
        {
            let mut buckets = self.per_ip.lock().unwrap();
            let bucket = buckets.entry(ip).or_insert_with(|| {
                TokenBucket::new(self.ip_rpm, self.ip_rpm / 60.0)
            });
            if !bucket.try_consume() {
                return RateLimitResult::IpLimited;
            }
        }

        // Check per-app limit.
        {
            let mut buckets = self.per_app.lock().unwrap();
            let bucket = buckets.entry(app_name.to_string()).or_insert_with(|| {
                TokenBucket::new(self.app_rpm, self.app_rpm / 60.0)
            });
            if !bucket.try_consume() {
                return RateLimitResult::AppLimited;
            }
        }

        RateLimitResult::Allowed
    }

    /// Clean up stale entries (called periodically).
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
        {
            let mut buckets = self.per_ip.lock().unwrap();
            buckets.retain(|_, b| b.last_refill > cutoff);
        }
        {
            let mut buckets = self.per_app.lock().unwrap();
            buckets.retain(|_, b| b.last_refill > cutoff);
        }
    }
}

pub enum RateLimitResult {
    Allowed,
    IpLimited,
    AppLimited,
}

// ── Middleware ──────────────────────────────────────────────────────

/// Generate a unique request ID (timestamp + counter).
pub fn generate_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:04x}", ts, seq & 0xFFFF)
}

/// Build response middleware headers to inject into backend responses.
pub fn middleware_response_headers(request_id: &str) -> String {
    format!(
        "X-Request-Id: {}\r\nX-Powered-By: php.rs\r\nX-Frame-Options: SAMEORIGIN\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n",
        request_id
    )
}

/// The routing table — thread-safe, hot-reloadable.
pub struct RoutingTable {
    /// Domain → RouteEntry mapping.
    routes: RwLock<HashMap<String, RouteEntry>>,
    /// Platform domain suffix (e.g. "phprs.local").
    platform_domain: String,
}

impl RoutingTable {
    pub fn new(platform_domain: &str) -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            platform_domain: platform_domain.to_string(),
        }
    }

    /// Reload routes from the current platform state.
    pub fn reload_from_state(&self, state: &PlatformState) {
        let mut routes = HashMap::new();

        for (name, app) in &state.apps {
            // Only route to running apps.
            if app.pid.is_none() || !app.is_running() {
                continue;
            }

            // Primary instance.
            let mut backends = vec![BackendInstance {
                port: app.port,
                healthy: true,
            }];

            // Additional scaled instances.
            for instance in &app.instances {
                if let Some(pid) = instance.pid {
                    if crate::state::process_alive(pid) {
                        backends.push(BackendInstance {
                            port: instance.port,
                            healthy: true,
                        });
                    }
                }
            }

            let sticky = app.env.get("APP_STICKY_SESSIONS")
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);

            let entry = RouteEntry {
                app_name: name.clone(),
                backend_port: app.port,
                backends,
                sticky_sessions: sticky,
            };

            // Default subdomain: {app-name}.{platform-domain}
            let default_domain = format!("{}.{}", name, self.platform_domain);
            routes.insert(default_domain, entry.clone());

            // Custom domains from app env.
            if let Some(domains) = app.env.get("APP_DOMAINS") {
                for domain in domains.split(',') {
                    let domain = domain.trim().to_lowercase();
                    if !domain.is_empty() {
                        routes.insert(domain, entry.clone());
                    }
                }
            }
        }

        let mut table = self.routes.write().unwrap();
        *table = routes;
    }

    /// Look up a route by Host header value.
    pub fn lookup(&self, host: &str) -> Option<RouteEntry> {
        let host = host.split(':').next().unwrap_or(host).to_lowercase();
        let routes = self.routes.read().unwrap();
        routes.get(&host).cloned()
    }

    /// Get all current routes (for status display).
    pub fn all_routes(&self) -> HashMap<String, RouteEntry> {
        self.routes.read().unwrap().clone()
    }
}

/// Configuration for the router.
pub struct RouterConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub platform_domain: String,
    pub reload_interval_secs: u64,
    /// Enable TLS on an additional port.
    pub tls_port: Option<u16>,
    /// Path to the TLS certificates directory.
    pub tls_certs_dir: Option<String>,
    /// Per-app rate limit (requests per minute, 0 = unlimited).
    pub rate_limit_app_rpm: f64,
    /// Per-IP rate limit (requests per minute, 0 = unlimited).
    pub rate_limit_ip_rpm: f64,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
    /// Connection read timeout in seconds (slowloris protection).
    pub read_timeout_secs: u64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            listen_host: "0.0.0.0".into(),
            listen_port: 80,
            platform_domain: "phprs.local".into(),
            reload_interval_secs: 5,
            tls_port: None,
            tls_certs_dir: None,
            rate_limit_app_rpm: 6000.0, // 100 req/sec default
            rate_limit_ip_rpm: 600.0,   // 10 req/sec per IP
            max_body_size: 10 * 1024 * 1024, // 10 MB
            read_timeout_secs: 30,
        }
    }
}

impl RouterConfig {
    pub fn from_env() -> Self {
        Self {
            listen_host: std::env::var("ROUTER_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            listen_port: std::env::var("ROUTER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80),
            platform_domain: std::env::var("ROUTER_DOMAIN")
                .unwrap_or_else(|_| "phprs.local".into()),
            reload_interval_secs: std::env::var("ROUTER_RELOAD_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            tls_port: std::env::var("ROUTER_TLS_PORT")
                .ok()
                .and_then(|s| s.parse().ok()),
            tls_certs_dir: std::env::var("ROUTER_TLS_CERTS_DIR").ok(),
            rate_limit_app_rpm: std::env::var("ROUTER_RATE_LIMIT_APP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(6000.0),
            rate_limit_ip_rpm: std::env::var("ROUTER_RATE_LIMIT_IP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600.0),
            max_body_size: std::env::var("ROUTER_MAX_BODY_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10 * 1024 * 1024),
            read_timeout_secs: std::env::var("ROUTER_READ_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }
}

/// Run the reverse proxy router (blocking).
pub fn run_router(config: RouterConfig, shutdown: Arc<AtomicBool>) {
    let listener = match TcpListener::bind(format!("{}:{}", config.listen_host, config.listen_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Router: cannot bind {}:{}: {}", config.listen_host, config.listen_port, e);
            return;
        }
    };

    listener.set_nonblocking(true).unwrap_or_default();

    eprintln!("Router: listening on {}:{} (HTTP)", config.listen_host, config.listen_port);
    eprintln!("Router: platform domain: *.{}", config.platform_domain);

    let table = Arc::new(RoutingTable::new(&config.platform_domain));
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_app_rpm, config.rate_limit_ip_rpm));
    let lb_counter = Arc::new(AtomicU64::new(0));
    let read_timeout = Duration::from_secs(config.read_timeout_secs);
    let max_body_size = config.max_body_size;

    // Set up TLS cert store (shared between ACME challenge handler and TLS listener).
    let cert_store = if let Some(ref certs_dir) = config.tls_certs_dir {
        let store = Arc::new(crate::tls::CertStore::new(std::path::Path::new(certs_dir)));
        Some(store)
    } else {
        None
    };

    // Initial route load.
    let state = PlatformState::load();
    table.reload_from_state(&state);

    // Background reload thread — periodically refresh routes from state.
    let table_reload = table.clone();
    let shutdown_reload = shutdown.clone();
    let reload_interval = config.reload_interval_secs;
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(reload_interval));
            if shutdown_reload.load(Ordering::Relaxed) {
                break;
            }
            let state = PlatformState::load();
            table_reload.reload_from_state(&state);
        }
    });

    // Rate limiter cleanup thread — evict stale buckets every 60 seconds.
    let rl_cleanup = rate_limiter.clone();
    let shutdown_rl = shutdown.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(60));
            if shutdown_rl.load(Ordering::Relaxed) {
                break;
            }
            rl_cleanup.cleanup();
        }
    });

    // Spawn TLS listener thread if configured.
    if let (Some(tls_port), Some(ref store)) = (config.tls_port, &cert_store) {
        let tls_addr = format!("{}:{}", config.listen_host, tls_port);
        match TcpListener::bind(&tls_addr) {
            Ok(tls_listener) => {
                tls_listener.set_nonblocking(true).unwrap_or_default();
                eprintln!("Router: listening on {} (HTTPS)", tls_addr);

                let tls_config = match store.build_tls_config() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Router: TLS config failed: {}", e);
                        return;
                    }
                };

                let table_tls = table.clone();
                let shutdown_tls = shutdown.clone();
                let tls_config = tls_config.clone();
                let tls_rate_limiter = rate_limiter.clone();
                let tls_lb_counter = lb_counter.clone();
                std::thread::spawn(move || {
                    loop {
                        if shutdown_tls.load(Ordering::Relaxed) {
                            break;
                        }
                        match tls_listener.accept() {
                            Ok((stream, _)) => {
                                let table = table_tls.clone();
                                let tls_config = tls_config.clone();
                                let rl = tls_rate_limiter.clone();
                                let lbc = tls_lb_counter.clone();
                                std::thread::spawn(move || {
                                    match crate::tls::tls_accept(stream, &tls_config) {
                                        Ok(mut tls_stream) => {
                                            handle_proxy_tls_connection(&mut tls_stream, &table, &rl, &lbc);
                                        }
                                        Err(e) => {
                                            eprintln!("Router: TLS handshake failed: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(e) => {
                                eprintln!("Router: TLS accept error: {}", e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Router: cannot bind TLS on {}: {}", tls_addr, e);
            }
        }
    }

    // HTTP accept loop.
    let acme_store = cert_store.clone();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let table = table.clone();
                let acme_store = acme_store.clone();
                let rate_limiter = rate_limiter.clone();
                let lb_counter = lb_counter.clone();
                std::thread::spawn(move || {
                    handle_proxy_connection(
                        stream, &table, acme_store.as_deref(),
                        &rate_limiter, &lb_counter, read_timeout, max_body_size,
                    );
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Router: accept error: {}", e);
            }
        }
    }
}

/// Handle a single proxied HTTP connection.
fn handle_proxy_connection(
    mut client: TcpStream,
    table: &RoutingTable,
    cert_store: Option<&crate::tls::CertStore>,
    rate_limiter: &RateLimiter,
    lb_counter: &AtomicU64,
    read_timeout: Duration,
    max_body_size: usize,
) {
    client.set_read_timeout(Some(read_timeout)).ok();
    client.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let client_ip = client.peer_addr().ok().map(|a| a.ip());
    let request_id = generate_request_id();

    // Read the request (headers only, to extract Host).
    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }

    let mut headers = Vec::new();
    let mut host: Option<String> = None;
    let mut content_length: usize = 0;
    let mut header_bytes: usize = request_line.len();
    let mut cookie_header: Option<String> = None;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        header_bytes += line.len();
        // Slowloris/header size protection.
        if header_bytes > rate_limiter.max_header_size {
            send_error_response(&mut client, 431, "Request headers too large");
            return;
        }
        let trimmed = line.trim_end().to_string();
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().to_lowercase();
            let value = trimmed[colon + 1..].trim().to_string();
            if key == "host" {
                host = Some(value.clone());
            }
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            if key == "cookie" {
                cookie_header = Some(value.clone());
            }
        }
        headers.push(line);
    }

    // Check body size limit.
    if max_body_size > 0 && content_length > max_body_size {
        send_error_response(&mut client, 413, "Request body too large");
        return;
    }

    // Handle ACME HTTP-01 challenges: GET /.well-known/acme-challenge/{token}
    if let Some(store) = cert_store {
        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            if let Some(response) = store.get_acme_challenge(token) {
                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(), response
                );
                let _ = client.write_all(http_response.as_bytes());
                let _ = client.flush();
                return;
            }
        }
    }

    let host = match host {
        Some(h) => h,
        None => {
            send_error_response(&mut client, 400, "Missing Host header");
            return;
        }
    };

    // Look up the route.
    let route = match table.lookup(&host) {
        Some(r) => r,
        None => {
            send_error_response(&mut client, 404, &format!(
                "No app found for host: {}. Available apps use *.phprs.local subdomains.", host
            ));
            return;
        }
    };

    // Rate limiting.
    if let Some(ip) = client_ip {
        match rate_limiter.check(&route.app_name, ip) {
            RateLimitResult::Allowed => {}
            RateLimitResult::IpLimited => {
                send_error_response(&mut client, 429, "Rate limit exceeded (per-IP)");
                return;
            }
            RateLimitResult::AppLimited => {
                send_error_response(&mut client, 429, "Rate limit exceeded (per-app)");
                return;
            }
        }
    }

    // Load balancing: select backend.
    let backend_port = if route.sticky_sessions {
        // Sticky sessions: extract session cookie and hash to backend.
        let session_id = cookie_header
            .as_deref()
            .and_then(|c| extract_session_cookie(c))
            .unwrap_or_default();
        if session_id.is_empty() {
            let counter = lb_counter.fetch_add(1, Ordering::Relaxed);
            route.select_backend(counter).unwrap_or(route.backend_port)
        } else {
            route.select_sticky(&session_id)
        }
    } else {
        let counter = lb_counter.fetch_add(1, Ordering::Relaxed);
        route.select_backend(counter).unwrap_or(route.backend_port)
    };

    // Read body if present.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        if reader.read_exact(&mut body).is_err() {
            send_error_response(&mut client, 400, "Failed to read request body");
            return;
        }
    }

    // Connect to backend and proxy.
    proxy_to_backend(
        &mut client,
        &request_line,
        &headers,
        &body,
        content_length,
        &route,
        "http",
        backend_port,
        &request_id,
    );
}

/// Extract PHPSESSID or PHPRS_SESSION from a Cookie header.
fn extract_session_cookie(cookie: &str) -> Option<String> {
    for part in cookie.split(';') {
        let part = part.trim();
        for prefix in &["PHPSESSID=", "PHPRS_SESSION=", "phprs_sticky="] {
            if let Some(val) = part.strip_prefix(prefix) {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Handle a single proxied HTTPS/TLS connection.
fn handle_proxy_tls_connection(
    tls_stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    table: &RoutingTable,
    rate_limiter: &RateLimiter,
    lb_counter: &AtomicU64,
) {
    let client_ip = tls_stream.get_ref().peer_addr().ok().map(|a| a.ip());
    let request_id = generate_request_id();

    let mut request_line = String::new();
    let mut reader = BufReader::new(&mut *tls_stream);
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }

    let mut headers = Vec::new();
    let mut host: Option<String> = None;
    let mut content_length: usize = 0;
    let mut cookie_header: Option<String> = None;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end().to_string();
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().to_lowercase();
            let value = trimmed[colon + 1..].trim().to_string();
            if key == "host" {
                host = Some(value.clone());
            }
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            if key == "cookie" {
                cookie_header = Some(value.clone());
            }
        }
        headers.push(line);
    }

    let host = match host {
        Some(h) => h,
        None => {
            let _ = tls_stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };

    let route = match table.lookup(&host) {
        Some(r) => r,
        None => {
            let body = format!("No app found for host: {}", host);
            let response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = tls_stream.write_all(response.as_bytes());
            return;
        }
    };

    // Rate limiting.
    if let Some(ip) = client_ip {
        match rate_limiter.check(&route.app_name, ip) {
            RateLimitResult::Allowed => {}
            _ => {
                let _ = tls_stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        }
    }

    // Load balancing.
    let backend_port = if route.sticky_sessions {
        let session_id = cookie_header
            .as_deref()
            .and_then(|c| extract_session_cookie(c))
            .unwrap_or_default();
        if session_id.is_empty() {
            let counter = lb_counter.fetch_add(1, Ordering::Relaxed);
            route.select_backend(counter).unwrap_or(route.backend_port)
        } else {
            route.select_sticky(&session_id)
        }
    } else {
        let counter = lb_counter.fetch_add(1, Ordering::Relaxed);
        route.select_backend(counter).unwrap_or(route.backend_port)
    };

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        if reader.read_exact(&mut body).is_err() {
            return;
        }
    }

    // Proxy to backend.
    proxy_to_backend_tls(
        tls_stream,
        &request_line,
        &headers,
        &body,
        content_length,
        &route,
        backend_port,
        &request_id,
    );
}

/// Proxy request to a backend app process (HTTP client side).
fn proxy_to_backend(
    client: &mut TcpStream,
    request_line: &str,
    headers: &[String],
    body: &[u8],
    content_length: usize,
    route: &RouteEntry,
    proto: &str,
    backend_port: u16,
    request_id: &str,
) {
    let backend_addr = format!("127.0.0.1:{}", backend_port);
    let mut backend = match TcpStream::connect_timeout(
        &backend_addr.parse().unwrap(),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => {
            send_error_response(client, 502, &format!(
                "Cannot connect to backend ({}, port {}): {}",
                route.app_name, backend_port, e
            ));
            return;
        }
    };

    backend.set_read_timeout(Some(Duration::from_secs(60))).ok();
    backend.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let _ = backend.write_all(request_line.as_bytes());
    for header in headers {
        let _ = backend.write_all(header.as_bytes());
    }
    if let Ok(peer) = client.peer_addr() {
        let xff = format!("X-Forwarded-For: {}\r\n", peer.ip());
        let _ = backend.write_all(xff.as_bytes());
    }
    let xfp = format!("X-Forwarded-Proto: {}\r\n", proto);
    let _ = backend.write_all(xfp.as_bytes());
    let xrid = format!("X-Request-Id: {}\r\n", request_id);
    let _ = backend.write_all(xrid.as_bytes());
    let _ = backend.write_all(b"\r\n");
    if content_length > 0 {
        let _ = backend.write_all(body);
    }
    let _ = backend.flush();

    let mut response = Vec::new();
    let _ = backend.read_to_end(&mut response);

    // Inject middleware headers into the response.
    let middleware_headers = middleware_response_headers(request_id);
    let response = inject_response_headers(&response, &middleware_headers);
    let _ = client.write_all(&response);
    let _ = client.flush();
}

/// Inject headers into an HTTP response (after the status line).
fn inject_response_headers(response: &[u8], headers: &str) -> Vec<u8> {
    // Find the end of the status line (\r\n).
    if let Some(pos) = response.windows(2).position(|w| w == b"\r\n") {
        let mut result = Vec::with_capacity(response.len() + headers.len());
        result.extend_from_slice(&response[..pos + 2]); // Status line + \r\n
        result.extend_from_slice(headers.as_bytes());    // Injected headers
        result.extend_from_slice(&response[pos + 2..]);  // Rest of response
        result
    } else {
        response.to_vec()
    }
}

/// Proxy request from TLS stream to backend.
fn proxy_to_backend_tls(
    tls_stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    request_line: &str,
    headers: &[String],
    body: &[u8],
    content_length: usize,
    _route: &RouteEntry,
    backend_port: u16,
    request_id: &str,
) {
    let backend_addr = format!("127.0.0.1:{}", backend_port);
    let mut backend = match TcpStream::connect_timeout(
        &backend_addr.parse().unwrap(),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(_) => {
            let _ = tls_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };

    backend.set_read_timeout(Some(Duration::from_secs(60))).ok();
    backend.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let _ = backend.write_all(request_line.as_bytes());
    for header in headers {
        let _ = backend.write_all(header.as_bytes());
    }
    if let Ok(peer) = tls_stream.get_ref().peer_addr() {
        let xff = format!("X-Forwarded-For: {}\r\n", peer.ip());
        let _ = backend.write_all(xff.as_bytes());
    }
    let _ = backend.write_all(b"X-Forwarded-Proto: https\r\n");
    let xrid = format!("X-Request-Id: {}\r\n", request_id);
    let _ = backend.write_all(xrid.as_bytes());
    let _ = backend.write_all(b"\r\n");
    if content_length > 0 {
        let _ = backend.write_all(body);
    }
    let _ = backend.flush();

    let mut response = Vec::new();
    let _ = backend.read_to_end(&mut response);

    // Inject middleware headers (including HSTS for TLS).
    let mut mw_headers = middleware_response_headers(request_id);
    mw_headers.push_str("Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n");
    let response = inject_response_headers(&response, &mw_headers);
    let _ = tls_stream.write_all(&response);
    let _ = tls_stream.flush();
}

/// Send an error response directly to the client.
fn send_error_response(stream: &mut TcpStream, status: u16, message: &str) {
    let status_text = match status {
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let body = format!(
        "<html><body><h1>{} {}</h1><p>{}</p><hr><small>php-rs router</small></body></html>",
        status, status_text, message
    );
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_route(name: &str, port: u16) -> RouteEntry {
        RouteEntry {
            app_name: name.into(),
            backend_port: port,
            backends: vec![BackendInstance { port, healthy: true }],
            sticky_sessions: false,
        }
    }

    fn test_route_multi(name: &str, ports: &[u16]) -> RouteEntry {
        RouteEntry {
            app_name: name.into(),
            backend_port: ports[0],
            backends: ports.iter().map(|&p| BackendInstance { port: p, healthy: true }).collect(),
            sticky_sessions: false,
        }
    }

    #[test]
    fn test_routing_table_empty() {
        let table = RoutingTable::new("phprs.local");
        assert!(table.lookup("myapp.phprs.local").is_none());
    }

    #[test]
    fn test_routing_table_default_domain() {
        let table = RoutingTable::new("phprs.local");
        {
            let mut routes = table.routes.write().unwrap();
            routes.insert("myapp.phprs.local".into(), test_route("myapp", 8001));
        }

        let route = table.lookup("myapp.phprs.local").unwrap();
        assert_eq!(route.app_name, "myapp");
        assert_eq!(route.backend_port, 8001);
    }

    #[test]
    fn test_routing_table_strips_port() {
        let table = RoutingTable::new("phprs.local");
        {
            let mut routes = table.routes.write().unwrap();
            routes.insert("myapp.phprs.local".into(), test_route("myapp", 8001));
        }

        let route = table.lookup("myapp.phprs.local:80").unwrap();
        assert_eq!(route.app_name, "myapp");
    }

    #[test]
    fn test_routing_table_case_insensitive() {
        let table = RoutingTable::new("phprs.local");
        {
            let mut routes = table.routes.write().unwrap();
            routes.insert("myapp.phprs.local".into(), test_route("myapp", 8001));
        }

        assert!(table.lookup("MyApp.PHPRS.local").is_some());
    }

    #[test]
    fn test_routing_table_reload() {
        use crate::state::AppState;

        let table = RoutingTable::new("test.local");
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp".into(),
        };

        let current_pid = std::process::id();
        state.apps.insert("webapp".into(), AppState {
            name: "webapp".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8042,
            pid: Some(current_pid),
            env: HashMap::from([
                ("APP_DOMAINS".into(), "example.com, www.example.com".into()),
            ]),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });

        table.reload_from_state(&state);

        let route = table.lookup("webapp.test.local").unwrap();
        assert_eq!(route.backend_port, 8042);

        let route = table.lookup("example.com").unwrap();
        assert_eq!(route.app_name, "webapp");

        let route = table.lookup("www.example.com").unwrap();
        assert_eq!(route.app_name, "webapp");
    }

    #[test]
    fn test_routing_table_skips_stopped_apps() {
        use crate::state::AppState;

        let table = RoutingTable::new("test.local");
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp".into(),
        };

        state.apps.insert("stopped".into(), AppState {
            name: "stopped".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8099,
            pid: None,
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });

        table.reload_from_state(&state);
        assert!(table.lookup("stopped.test.local").is_none());
    }

    #[test]
    fn test_all_routes() {
        let table = RoutingTable::new("phprs.local");
        {
            let mut routes = table.routes.write().unwrap();
            routes.insert("a.phprs.local".into(), test_route("a", 8001));
            routes.insert("b.phprs.local".into(), test_route("b", 8002));
        }

        let all = table.all_routes();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_error_response_format() {
        let body = format!(
            "<html><body><h1>{} {}</h1><p>{}</p><hr><small>php-rs router</small></body></html>",
            404, "Not Found", "No app found"
        );
        assert!(body.contains("404 Not Found"));
        assert!(body.contains("No app found"));
    }

    // ── Load Balancing Tests ──

    #[test]
    fn test_round_robin_backend_selection() {
        let route = test_route_multi("app", &[8001, 8002, 8003]);
        assert_eq!(route.select_backend(0), Some(8001));
        assert_eq!(route.select_backend(1), Some(8002));
        assert_eq!(route.select_backend(2), Some(8003));
        assert_eq!(route.select_backend(3), Some(8001)); // Wraps around.
    }

    #[test]
    fn test_round_robin_skips_unhealthy() {
        let route = RouteEntry {
            app_name: "app".into(),
            backend_port: 8001,
            backends: vec![
                BackendInstance { port: 8001, healthy: true },
                BackendInstance { port: 8002, healthy: false },
                BackendInstance { port: 8003, healthy: true },
            ],
            sticky_sessions: false,
        };
        assert_eq!(route.select_backend(0), Some(8001));
        assert_eq!(route.select_backend(1), Some(8003));
        assert_eq!(route.select_backend(2), Some(8001));
    }

    #[test]
    fn test_round_robin_all_unhealthy_falls_back() {
        let route = RouteEntry {
            app_name: "app".into(),
            backend_port: 8001,
            backends: vec![
                BackendInstance { port: 8001, healthy: false },
                BackendInstance { port: 8002, healthy: false },
            ],
            sticky_sessions: false,
        };
        // Falls back to primary port.
        assert_eq!(route.select_backend(0), Some(8001));
    }

    #[test]
    fn test_sticky_session_consistent() {
        let route = test_route_multi("app", &[8001, 8002, 8003]);
        let port1 = route.select_sticky("session-abc");
        let port2 = route.select_sticky("session-abc");
        assert_eq!(port1, port2); // Same session → same backend.
    }

    #[test]
    fn test_sticky_session_distributes() {
        let route = test_route_multi("app", &[8001, 8002, 8003]);
        let mut ports_seen = std::collections::HashSet::new();
        for i in 0..100 {
            let port = route.select_sticky(&format!("session-{}", i));
            ports_seen.insert(port);
        }
        // Should have hit multiple backends.
        assert!(ports_seen.len() > 1);
    }

    // ── Rate Limiter Tests ──

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(100.0, 100.0);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        match limiter.check("myapp", ip) {
            RateLimitResult::Allowed => {}
            _ => panic!("Should be allowed"),
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_ip_limit() {
        let limiter = RateLimiter::new(10000.0, 2.0); // 2 RPM per IP
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // First 2 should pass (bucket starts full at capacity).
        assert!(matches!(limiter.check("app", ip), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("app", ip), RateLimitResult::Allowed));
        // Third should be blocked.
        assert!(matches!(limiter.check("app", ip), RateLimitResult::IpLimited));
    }

    #[test]
    fn test_rate_limiter_blocks_over_app_limit() {
        let limiter = RateLimiter::new(2.0, 10000.0); // 2 RPM per app
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(matches!(limiter.check("app", ip1), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("app", ip2), RateLimitResult::Allowed));
        // Third request to same app from different IP should be blocked.
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(matches!(limiter.check("app", ip3), RateLimitResult::AppLimited));
    }

    #[test]
    fn test_rate_limiter_different_apps_independent() {
        let limiter = RateLimiter::new(2.0, 10000.0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches!(limiter.check("app1", ip), RateLimitResult::Allowed));
        assert!(matches!(limiter.check("app1", ip), RateLimitResult::Allowed));
        // app2 should have its own limit.
        assert!(matches!(limiter.check("app2", ip), RateLimitResult::Allowed));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(100.0, 100.0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.check("app", ip);
        limiter.cleanup(); // Should not panic.
    }

    // ── Middleware Tests ──

    #[test]
    fn test_generate_request_id() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert_ne!(id1, id2);
        assert!(id1.contains('-'));
    }

    #[test]
    fn test_middleware_response_headers() {
        let headers = middleware_response_headers("test-123");
        assert!(headers.contains("X-Request-Id: test-123"));
        assert!(headers.contains("X-Powered-By: php.rs"));
        assert!(headers.contains("X-Frame-Options: SAMEORIGIN"));
        assert!(headers.contains("X-Content-Type-Options: nosniff"));
        assert!(headers.contains("Referrer-Policy: strict-origin-when-cross-origin"));
    }

    #[test]
    fn test_inject_response_headers() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello";
        let injected = inject_response_headers(response, "X-Test: value\r\n");
        let result = String::from_utf8(injected).unwrap();
        assert!(result.starts_with("HTTP/1.1 200 OK\r\nX-Test: value\r\n"));
        assert!(result.contains("Content-Type: text/html"));
        assert!(result.ends_with("hello"));
    }

    #[test]
    fn test_inject_response_headers_empty_response() {
        let response = b"";
        let injected = inject_response_headers(response, "X-Test: value\r\n");
        assert!(injected.is_empty());
    }

    // ── Session Cookie Tests ──

    #[test]
    fn test_extract_session_cookie() {
        assert_eq!(
            extract_session_cookie("PHPSESSID=abc123; other=value"),
            Some("abc123".into())
        );
        assert_eq!(
            extract_session_cookie("foo=bar; PHPRS_SESSION=xyz; baz=qux"),
            Some("xyz".into())
        );
        assert_eq!(
            extract_session_cookie("foo=bar; phprs_sticky=s1"),
            Some("s1".into())
        );
        assert_eq!(extract_session_cookie("foo=bar; baz=qux"), None);
    }
}
