//! REST API server — programmatic interface for managing the PaaS.
//!
//! Endpoints:
//!   GET    /api/apps                 — list apps
//!   POST   /api/apps                 — create app
//!   GET    /api/apps/{name}          — app details
//!   DELETE /api/apps/{name}          — destroy app
//!   POST   /api/apps/{name}/restart  — restart app
//!   POST   /api/apps/{name}/start    — start app
//!   POST   /api/apps/{name}/stop     — stop app
//!   GET    /api/apps/{name}/config   — get config
//!   PUT    /api/apps/{name}/config   — set config
//!   GET    /api/apps/{name}/services — list services
//!   GET    /api/health               — API health check
//!
//! Auth: Bearer token via Authorization header or API_TOKEN env var.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::process;
use crate::services;
use crate::state::{self, AppState, PlatformState};

/// API server configuration.
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    /// Bearer token for API authentication. Empty = no auth.
    pub api_token: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 9090,
            api_token: String::new(),
        }
    }
}

impl ApiConfig {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("API_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(9090),
            api_token: std::env::var("API_TOKEN").unwrap_or_default(),
        }
    }
}

/// A parsed API request.
struct ApiRequest {
    method: String,
    path: String,
    #[allow(dead_code)]
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Run the API server (blocking).
pub fn run_api(config: ApiConfig, shutdown: Arc<AtomicBool>) {
    let listener = match TcpListener::bind(format!("{}:{}", config.host, config.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("API: cannot bind {}:{}: {}", config.host, config.port, e);
            return;
        }
    };

    listener.set_nonblocking(true).unwrap_or_default();
    eprintln!("API: listening on {}:{}", config.host, config.port);

    let config = Arc::new(config);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let config = config.clone();
                std::thread::spawn(move || {
                    handle_api_connection(stream, &config);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("API: accept error: {}", e);
            }
        }
    }
}

fn handle_api_connection(mut stream: TcpStream, config: &ApiConfig) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let req = {
        let mut reader = BufReader::new(&mut stream);
        match parse_api_request(&mut reader) {
            Some(r) => r,
            None => return,
        }
    };

    let raw_path = req.path.clone();
    let path = raw_path.trim_end_matches('/').to_string();

    // Dashboard routes — serve HTML.
    if raw_path == "/dashboard" || raw_path.starts_with("/dashboard/") {
        let auth_header = req.headers.get("authorization").map(|s| s.as_str());
        let cookie_header = req.headers.get("cookie").map(|s| s.as_str());
        let user_store = crate::auth::UserStore::load();
        let user_id = user_store.authenticate(auth_header, cookie_header);

        let dash_path = if path.is_empty() { "/dashboard" } else { &path };
        let (status, content_type, body) = crate::dashboard::render_dashboard(
            dash_path,
            user_id,
            &req.headers,
        );
        send_html(&mut stream, status, content_type, &body);
        return;
    }

    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Public API endpoints (no auth required).
    let is_public = matches!(
        (req.method.as_str(), parts.as_slice()),
        ("GET", ["api", "health"])
            | ("POST", ["api", "auth", "register"])
            | ("POST", ["api", "auth", "login"])
    );

    if !is_public {
        // Authenticate via user store or legacy API_TOKEN.
        let auth_header = req.headers.get("authorization").map(|s| s.as_str());
        let cookie_header = req.headers.get("cookie").map(|s| s.as_str());
        let user_store = crate::auth::UserStore::load();

        let authenticated = if let Some(uid) = user_store.authenticate(auth_header, cookie_header) {
            let _ = uid;
            true
        } else if !config.api_token.is_empty() {
            let auth = req.headers.get("authorization").cloned().unwrap_or_default();
            auth == format!("Bearer {}", config.api_token)
        } else {
            user_store.users.is_empty()
        };

        if !authenticated {
            send_json(&mut stream, 401, &serde_json::json!({"error": "Unauthorized"}));
            return;
        }
    }

    // Route the API request.
    let (status, body) = route_request(&req);

    // For login, attach session cookie to response.
    if let Some(session_token) = body.get("_session_token").and_then(|v| v.as_str()) {
        let cookie = format!("phprs_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400", session_token);
        send_json_with_headers(&mut stream, status, &body, &[("Set-Cookie", &cookie)]);
    } else {
        send_json(&mut stream, status, &body);
    }
}

fn route_request(req: &ApiRequest) -> (u16, serde_json::Value) {
    let path = req.path.trim_end_matches('/');
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (req.method.as_str(), parts.as_slice()) {
        // Public endpoints.
        ("GET", ["api", "health"]) => api_health(),
        ("POST", ["api", "auth", "register"]) => api_auth_register(req),
        ("POST", ["api", "auth", "login"]) => api_auth_login(req),
        ("POST", ["api", "auth", "logout"]) => api_auth_logout(req),
        ("POST", ["api", "auth", "token"]) => api_auth_create_token(req),
        ("GET", ["api", "auth", "me"]) => api_auth_me(req),
        // App endpoints.
        ("GET", ["api", "apps"]) => api_list_apps(),
        ("POST", ["api", "apps"]) => api_create_app(req),
        ("GET", ["api", "apps", name]) => api_get_app(name),
        ("DELETE", ["api", "apps", name]) => api_destroy_app(name),
        ("POST", ["api", "apps", name, "start"]) => api_start_app(name),
        ("POST", ["api", "apps", name, "stop"]) => api_stop_app(name),
        ("POST", ["api", "apps", name, "restart"]) => api_restart_app(name),
        ("GET", ["api", "apps", name, "config"]) => api_get_config(name),
        ("PUT", ["api", "apps", name, "config"]) => api_set_config(name, req),
        ("GET", ["api", "apps", name, "services"]) => api_list_services(name),
        _ => (404, serde_json::json!({"error": "Not found"})),
    }
}

// ── API Handlers ───────────────────────────────────────────────────────────

fn api_health() -> (u16, serde_json::Value) {
    (200, serde_json::json!({"status": "ok"}))
}

// ── Auth Handlers ─────────────────────────────────────────────────────────

fn api_auth_register(req: &ApiRequest) -> (u16, serde_json::Value) {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return (400, serde_json::json!({"error": "Invalid JSON body"})),
    };

    let username = match body.get("username").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'username'"})),
    };
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'password'"})),
    };
    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) => e.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'email'"})),
    };

    if password.len() < 8 {
        return (400, serde_json::json!({"error": "Password must be at least 8 characters"}));
    }

    let mut store = crate::auth::UserStore::load();
    match store.register(&username, &password, &email) {
        Ok(id) => {
            if let Err(e) = store.save() {
                return (500, serde_json::json!({"error": format!("Failed to save: {}", e)}));
            }
            (201, serde_json::json!({
                "id": id,
                "username": username,
                "email": email,
            }))
        }
        Err(e) => (409, serde_json::json!({"error": e})),
    }
}

fn api_auth_login(req: &ApiRequest) -> (u16, serde_json::Value) {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return (400, serde_json::json!({"error": "Invalid JSON body"})),
    };

    let username = match body.get("username").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'username'"})),
    };
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'password'"})),
    };

    let mut store = crate::auth::UserStore::load();
    match store.login(&username, &password) {
        Ok(uid) => {
            // Create session token.
            match store.create_session(uid, 24) {
                Ok(session_token) => {
                    if let Err(e) = store.save() {
                        return (500, serde_json::json!({"error": format!("Save failed: {}", e)}));
                    }
                    (200, serde_json::json!({
                        "user_id": uid,
                        "username": username,
                        "_session_token": session_token,
                    }))
                }
                Err(e) => (500, serde_json::json!({"error": e})),
            }
        }
        Err(e) => (401, serde_json::json!({"error": e})),
    }
}

fn api_auth_logout(req: &ApiRequest) -> (u16, serde_json::Value) {
    if let Some(cookies) = req.headers.get("cookie") {
        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            if let Some(token) = cookie.strip_prefix("phprs_session=") {
                let mut store = crate::auth::UserStore::load();
                store.logout(token.trim());
                let _ = store.save();
            }
        }
    }
    (200, serde_json::json!({"status": "logged_out"}))
}

fn api_auth_create_token(req: &ApiRequest) -> (u16, serde_json::Value) {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return (400, serde_json::json!({"error": "Invalid JSON body"})),
    };

    // Get current user from auth header/cookie.
    let auth_header = req.headers.get("authorization").map(|s| s.as_str());
    let cookie_header = req.headers.get("cookie").map(|s| s.as_str());
    let mut store = crate::auth::UserStore::load();

    let uid = match store.authenticate(auth_header, cookie_header) {
        Some(uid) => uid,
        None => return (401, serde_json::json!({"error": "Not authenticated"})),
    };

    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("api-token")
        .to_string();
    let expires_days = body.get("expires_days").and_then(|v| v.as_u64());

    match store.create_api_token(uid, &name, expires_days) {
        Ok(token) => {
            if let Err(e) = store.save() {
                return (500, serde_json::json!({"error": format!("Save failed: {}", e)}));
            }
            (201, serde_json::json!({
                "token": token,
                "name": name,
            }))
        }
        Err(e) => (500, serde_json::json!({"error": e})),
    }
}

fn api_auth_me(req: &ApiRequest) -> (u16, serde_json::Value) {
    let auth_header = req.headers.get("authorization").map(|s| s.as_str());
    let cookie_header = req.headers.get("cookie").map(|s| s.as_str());
    let store = crate::auth::UserStore::load();

    match store.authenticate(auth_header, cookie_header) {
        Some(uid) => {
            if let Some(user) = store.get_user(uid) {
                (200, serde_json::json!({
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                    "tokens": user.tokens.iter().map(|t| serde_json::json!({
                        "name": t.name,
                        "created_at": t.created_at,
                    })).collect::<Vec<_>>(),
                    "created_at": user.created_at,
                }))
            } else {
                (404, serde_json::json!({"error": "User not found"}))
            }
        }
        None => (401, serde_json::json!({"error": "Not authenticated"})),
    }
}

// ── App Handlers ──────────────────────────────────────────────────────────

fn api_list_apps() -> (u16, serde_json::Value) {
    let state = PlatformState::load();
    let apps: Vec<serde_json::Value> = state
        .apps
        .values()
        .map(|app| app_to_json(app))
        .collect();
    (200, serde_json::json!({"apps": apps}))
}

fn api_create_app(req: &ApiRequest) -> (u16, serde_json::Value) {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return (400, serde_json::json!({"error": "Invalid JSON body"})),
    };

    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return (400, serde_json::json!({"error": "Missing 'name' field"})),
    };

    let root = body.get("root").and_then(|v| v.as_str()).unwrap_or(".").to_string();
    let entry = body.get("entry").and_then(|v| v.as_str()).unwrap_or("public/index.php").to_string();
    let docroot = body.get("docroot").and_then(|v| v.as_str()).unwrap_or("public").to_string();
    let workers = body.get("workers").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

    let root_path = std::path::Path::new(&root);
    let abs_root = root_path
        .canonicalize()
        .unwrap_or_else(|_| root_path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let mut state = PlatformState::load();

    if state.apps.contains_key(&name) {
        return (409, serde_json::json!({"error": format!("App '{}' already exists", name)}));
    }

    let port = state.allocate_port();
    let app = AppState {
        name: name.clone(),
        root: abs_root,
        entry,
        docroot,
        port,
        pid: None,
        env: HashMap::new(),
        workers,
        created_at: state::now_iso8601(),
        releases: vec![],
        current_release: None,
    scaling: Default::default(),
    instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
    };

    let json = app_to_json(&app);
    state.apps.insert(name, app);

    if let Err(e) = state.save() {
        return (500, serde_json::json!({"error": format!("Cannot save state: {}", e)}));
    }

    (201, json)
}

fn api_get_app(name: &str) -> (u16, serde_json::Value) {
    let state = PlatformState::load();
    match state.get_app(name) {
        Some(app) => {
            let mut json = app_to_json(app);
            // Add health status if running.
            if app.is_running() {
                let health = match process::health_check(app) {
                    Ok(true) => "healthy",
                    Ok(false) => "unhealthy",
                    Err(_) => "unknown",
                };
                json.as_object_mut().unwrap().insert("health".into(), health.into());
            }
            (200, json)
        }
        None => (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    }
}

fn api_destroy_app(name: &str) -> (u16, serde_json::Value) {
    let mut state = PlatformState::load();
    match state.apps.remove(name) {
        Some(app) => {
            if app.is_running() {
                process::stop_app(&app, Duration::from_secs(10));
            }
            if let Err(e) = state.save() {
                return (500, serde_json::json!({"error": format!("Cannot save state: {}", e)}));
            }
            (200, serde_json::json!({"status": "destroyed", "name": name}))
        }
        None => (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    }
}

fn api_start_app(name: &str) -> (u16, serde_json::Value) {
    let mut state = PlatformState::load();
    let app = match state.get_app(name) {
        Some(a) => a.clone(),
        None => return (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    };

    match process::start_app(&app) {
        process::StartResult::Started(pid) => {
            state.get_app_mut(name).unwrap().pid = Some(pid);
            let _ = state.save();
            (200, serde_json::json!({"status": "started", "pid": pid}))
        }
        process::StartResult::AlreadyRunning(pid) => {
            (200, serde_json::json!({"status": "already_running", "pid": pid}))
        }
        process::StartResult::Failed(e) => {
            (500, serde_json::json!({"error": e}))
        }
    }
}

fn api_stop_app(name: &str) -> (u16, serde_json::Value) {
    let mut state = PlatformState::load();
    let app = match state.get_app(name) {
        Some(a) => a.clone(),
        None => return (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    };

    match process::stop_app(&app, Duration::from_secs(10)) {
        process::StopResult::Stopped | process::StopResult::Killed => {
            state.get_app_mut(name).unwrap().pid = None;
            let _ = state.save();
            (200, serde_json::json!({"status": "stopped"}))
        }
        process::StopResult::NotRunning => {
            state.get_app_mut(name).unwrap().pid = None;
            let _ = state.save();
            (200, serde_json::json!({"status": "not_running"}))
        }
        process::StopResult::Failed(e) => {
            (500, serde_json::json!({"error": e}))
        }
    }
}

fn api_restart_app(name: &str) -> (u16, serde_json::Value) {
    let (status1, _) = api_stop_app(name);
    if status1 == 404 {
        return (404, serde_json::json!({"error": format!("App '{}' not found", name)}));
    }
    api_start_app(name)
}

fn api_get_config(name: &str) -> (u16, serde_json::Value) {
    let state = PlatformState::load();
    match state.get_app(name) {
        Some(app) => {
            let config: serde_json::Map<String, serde_json::Value> = app
                .env
                .iter()
                .filter(|(k, _)| !k.starts_with("_PHPRS_"))
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            (200, serde_json::json!({"config": config}))
        }
        None => (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    }
}

fn api_set_config(name: &str, req: &ApiRequest) -> (u16, serde_json::Value) {
    let body: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return (400, serde_json::json!({"error": "Invalid JSON body"})),
    };

    let config = match body.get("config").and_then(|v| v.as_object()) {
        Some(c) => c,
        None => return (400, serde_json::json!({"error": "Missing 'config' object"})),
    };

    let mut state = PlatformState::load();
    let app = match state.get_app_mut(name) {
        Some(a) => a,
        None => return (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    };

    for (key, value) in config {
        if let Some(v) = value.as_str() {
            app.env.insert(key.clone(), v.to_string());
        } else if value.is_null() {
            app.env.remove(key);
        }
    }

    if let Err(e) = state.save() {
        return (500, serde_json::json!({"error": format!("Cannot save state: {}", e)}));
    }

    (200, serde_json::json!({"status": "updated"}))
}

fn api_list_services(name: &str) -> (u16, serde_json::Value) {
    let state = PlatformState::load();
    match state.get_app(name) {
        Some(app) => {
            let svcs = services::list_app_services(&app.env);
            let services: Vec<serde_json::Value> = svcs
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "type": s.service_type,
                        "name": s.name,
                        "host": s.host,
                        "port": s.port,
                        "url": s.url,
                        "env_var": s.env_var,
                        "created_at": s.created_at,
                    })
                })
                .collect();
            (200, serde_json::json!({"services": services}))
        }
        None => (404, serde_json::json!({"error": format!("App '{}' not found", name)})),
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn app_to_json(app: &AppState) -> serde_json::Value {
    let status = if app.is_running() {
        "running"
    } else if app.pid.is_some() {
        "crashed"
    } else {
        "stopped"
    };

    serde_json::json!({
        "name": app.name,
        "status": status,
        "port": app.port,
        "pid": app.pid,
        "root": app.root,
        "entry": app.entry,
        "docroot": app.docroot,
        "workers": app.workers,
        "created_at": app.created_at,
    })
}

fn parse_api_request(reader: &mut BufReader<&mut TcpStream>) -> Option<ApiRequest> {
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

    let (path, query) = if let Some(q) = uri.find('?') {
        (uri[..q].to_string(), uri[q + 1..].to_string())
    } else {
        (uri, String::new())
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

    Some(ApiRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn send_html(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let status_text = match status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        _ => "OK",
    };
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        status, status_text, content_type, body.len()
    );
    if status == 302 {
        // Extract redirect URL from meta refresh (simple approach).
        if let Some(start) = body.find("url=") {
            if let Some(end) = body[start + 4..].find('"') {
                let url = &body[start + 4..start + 4 + end];
                response.push_str(&format!("Location: {}\r\n", url));
            }
        }
    }
    response.push_str(&format!("\r\n{}", body));
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn send_json(stream: &mut TcpStream, status: u16, body: &serde_json::Value) {
    send_json_with_headers(stream, status, body, &[]);
}

fn send_json_with_headers(
    stream: &mut TcpStream,
    status: u16,
    body: &serde_json::Value,
    extra_headers: &[(&str, &str)],
) {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        status, status_text, body_str.len()
    );
    for (k, v) in extra_headers {
        response.push_str(&format!("{}: {}\r\n", k, v));
    }
    response.push_str(&format!("\r\n{}", body_str));
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_to_json() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8001,
            pid: None,
            env: HashMap::new(),
            workers: 2,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };

        let json = app_to_json(&app);
        assert_eq!(json["name"], "test");
        assert_eq!(json["status"], "stopped");
        assert_eq!(json["port"], 8001);
        assert_eq!(json["workers"], 2);
    }

    #[test]
    fn test_app_to_json_running() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8001,
            pid: Some(std::process::id()), // Current process — is_running() returns true.
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };

        let json = app_to_json(&app);
        assert_eq!(json["status"], "running");
    }

    #[test]
    fn test_route_health() {
        let req = ApiRequest {
            method: "GET".into(),
            path: "/api/health".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let (status, body) = route_request(&req);
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ok");
    }

    #[test]
    fn test_route_not_found() {
        let req = ApiRequest {
            method: "GET".into(),
            path: "/api/nonexistent".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let (status, _) = route_request(&req);
        assert_eq!(status, 404);
    }

    #[test]
    fn test_route_list_apps() {
        let req = ApiRequest {
            method: "GET".into(),
            path: "/api/apps".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let (status, body) = route_request(&req);
        assert_eq!(status, 200);
        assert!(body["apps"].is_array());
    }

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 9090);
        assert!(config.api_token.is_empty());
    }

    #[test]
    fn test_route_get_app_not_found() {
        let req = ApiRequest {
            method: "GET".into(),
            path: "/api/apps/nonexistent".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let (status, body) = route_request(&req);
        assert_eq!(status, 404);
        assert!(body["error"].as_str().unwrap().contains("not found"));
    }

    #[test]
    fn test_route_trailing_slash() {
        let req = ApiRequest {
            method: "GET".into(),
            path: "/api/health/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let (status, _) = route_request(&req);
        assert_eq!(status, 200);
    }
}
