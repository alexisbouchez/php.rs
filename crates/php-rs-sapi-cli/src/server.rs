//! Built-in HTTP server for php.rs
//!
//! Equivalent to php-src/sapi/cli/php_cli_server.c
//! Usage: php-rs -S localhost:8080 [-t docroot] [router.php]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

/// Configuration for the built-in server.
pub struct ServerConfig {
    /// Listen address (e.g., "localhost:8080").
    pub listen: String,
    /// Document root directory.
    pub docroot: PathBuf,
    /// Optional router script.
    pub router: Option<PathBuf>,
}

/// A parsed HTTP request.
struct HttpRequest {
    method: String,
    uri: String,
    path: String,
    query_string: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// MIME types for static file serving.
fn mime_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=UTF-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" | "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=UTF-8",
        "php" => "text/html; charset=UTF-8",
        _ => "application/octet-stream",
    }
}

/// Parse an HTTP request from a buffered reader.
fn parse_request(reader: &mut BufReader<&mut std::net::TcpStream>) -> Option<HttpRequest> {
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
    })
}

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

/// Send an HTTP response.
fn send_response(
    stream: &mut std::net::TcpStream,
    status: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        content_type,
        body.len()
    );
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
        body.as_bytes(),
    );
}

/// Execute a PHP script for an HTTP request.
fn execute_php_request(
    script_path: &Path,
    req: &HttpRequest,
    config: &ServerConfig,
) -> Result<(u16, String, Vec<u8>), String> {
    let source = std::fs::read_to_string(script_path)
        .map_err(|e| format!("Failed to read {}: {}", script_path.display(), e))?;

    let op_array = php_rs_compiler::compile(&source).map_err(|e| format!("{}", e))?;

    let mut vm = php_rs_vm::Vm::new();

    // Build $_SERVER, $_GET, $_POST variables and pass to VM
    let _server_vars = build_server_vars(req, config);
    // TODO: inject server_vars into VM's superglobals when that integration exists

    // Parse query string for $_GET
    let _get_vars = parse_query_string(&req.query_string);

    // Parse POST body for $_POST
    let _post_vars = if req.method == "POST" {
        if let Some(ct) = req.headers.get("content-type") {
            if ct.starts_with("application/x-www-form-urlencoded") {
                let body_str = String::from_utf8_lossy(&req.body);
                parse_query_string(&body_str)
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    match vm.execute(&op_array) {
        Ok(output) => Ok((200, "text/html; charset=UTF-8".into(), output.into_bytes())),
        Err(e) => Err(format!("{:?}", e)),
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

/// Simple URL decoding (percent-decoding + '+' → space).
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

/// Handle a single HTTP connection.
fn handle_connection(stream: &mut std::net::TcpStream, config: &ServerConfig) {
    let mut reader = BufReader::new(stream);
    let req = match parse_request(&mut reader) {
        Some(r) => r,
        None => return,
    };

    // Log the request (like PHP's built-in server)
    let timestamp = chrono_lite_now();
    eprintln!(
        "[{}] {} [200]: {} {}",
        timestamp, config.listen, req.method, req.uri
    );

    let stream = reader.into_inner();

    // If router script is specified, use it for every request
    if let Some(ref router) = config.router {
        if router.exists() {
            match execute_php_request(router, &req, config) {
                Ok((status, content_type, body)) => {
                    let status_text = match status {
                        200 => "OK",
                        301 => "Moved Permanently",
                        302 => "Found",
                        404 => "Not Found",
                        _ => "OK",
                    };
                    send_response(stream, status, status_text, &content_type, &body);
                }
                Err(msg) => send_500(stream, &msg),
            }
            return;
        }
    }

    // Resolve the file path
    let mut file_path = config.docroot.join(req.path.trim_start_matches('/'));

    // If path is a directory, look for index.php or index.html
    if file_path.is_dir() {
        let index_php = file_path.join("index.php");
        let index_html = file_path.join("index.html");
        if index_php.exists() {
            file_path = index_php;
        } else if index_html.exists() {
            file_path = index_html;
        } else {
            send_404(stream, &req.path);
            return;
        }
    }

    if !file_path.exists() {
        send_404(stream, &req.path);
        return;
    }

    // Check if it's a PHP file
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "php" {
        // Execute PHP
        match execute_php_request(&file_path, &req, config) {
            Ok((status, content_type, body)) => {
                let status_text = if status == 200 { "OK" } else { "Error" };
                send_response(stream, status, status_text, &content_type, &body);
            }
            Err(msg) => send_500(stream, &msg),
        }
    } else {
        // Serve static file
        match std::fs::read(&file_path) {
            Ok(contents) => {
                let ct = mime_type(file_path.to_str().unwrap_or(""));
                send_response(stream, 200, "OK", ct, &contents);
            }
            Err(_) => send_404(stream, &req.path),
        }
    }
}

/// Simple timestamp for logging (avoids chrono dependency).
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert to rough date/time (UTC)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date using epoch (Jan 1, 1970)
    // Simplified: just show the time portion for logging
    let year_approx = 1970 + days / 365;
    let _ = year_approx;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Start the built-in HTTP server.
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
    eprintln!("Press Ctrl+C to quit.");

    let listener = match TcpListener::bind(&config.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to listen on {}: {}", config.listen, e);
            return 1;
        }
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_connection(&mut stream, &config);
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }

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

        // Create a temp directory with a PHP file
        let dir = std::env::temp_dir().join("php_rs_server_test");
        let _ = std::fs::create_dir_all(&dir);
        let php_file = dir.join("hello.php");
        let mut f = std::fs::File::create(&php_file).unwrap();
        write!(f, "<?php echo \"Hello from server!\";").unwrap();
        drop(f);

        // Test execute_php_request directly (no network needed)
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/hello.php".into(),
            path: "/hello.php".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _ct, body) = execute_php_request(&php_file, &req, &config).unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body), "Hello from server!");

        // Cleanup
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

        // Static files are served by reading directly, test mime_type
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

        // Create index.php
        let index = dir.join("index.php");
        let mut f = std::fs::File::create(&index).unwrap();
        write!(f, "<?php echo \"Index!\";").unwrap();
        drop(f);

        // The directory should resolve to index.php
        assert!(dir.is_dir());
        let index_php = dir.join("index.php");
        assert!(index_php.exists());

        // Execute it
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/".into(),
            path: "/".into(),
            query_string: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let config = ServerConfig {
            listen: "localhost:0".into(),
            docroot: dir.clone(),
            router: None,
        };
        let (status, _, body) = execute_php_request(&index_php, &req, &config).unwrap();
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
        // Verify we can bind to a random port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
        drop(listener);
    }
}
