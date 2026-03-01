//! Build PHP superglobals ($_SERVER, $_GET, $_POST, etc.) from HTTP requests.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use php_rs_runtime::superglobals::Superglobals;
use php_rs_vm::value::{PhpArray, Value};

use crate::config::AppConfig;
use crate::handler::HttpRequest;

/// Build the superglobals HashMap for the VM from an HTTP request.
pub fn build_superglobals(req: &HttpRequest, config: &AppConfig) -> HashMap<String, Value> {
    let server_vars = build_server_vars(req, config);
    let get_vars = parse_query_string(&req.query_string);

    let mut multipart_files: Option<HashMap<String, String>> = None;
    let post_vars = if req.method == "POST" || req.method == "PUT" || req.method == "PATCH" {
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

    // Build $_REQUEST (merged GET + POST, POST wins).
    let mut request_vars = get_vars.clone();
    for (k, v) in &post_vars {
        request_vars.insert(k.clone(), v.clone());
    }

    // Parse $_COOKIE from Cookie header.
    let cookie_vars = if let Some(cookie_header) = req.headers.get("cookie") {
        parse_cookies(cookie_header)
    } else {
        HashMap::new()
    };
    for (k, v) in &cookie_vars {
        request_vars.insert(k.clone(), v.clone());
    }

    // Build $_ENV from process environment.
    let env_vars: HashMap<String, String> = std::env::vars().collect();

    let mut superglobals: HashMap<String, Value> = HashMap::new();
    superglobals.insert("_SERVER".into(), Value::Array(PhpArray::from_string_map(&server_vars)));
    superglobals.insert("_GET".into(), Value::Array(PhpArray::from_string_map(&get_vars)));
    superglobals.insert("_POST".into(), Value::Array(PhpArray::from_string_map(&post_vars)));
    superglobals.insert("_COOKIE".into(), Value::Array(PhpArray::from_string_map(&cookie_vars)));
    superglobals.insert("_ENV".into(), Value::Array(PhpArray::from_string_map(&env_vars)));
    superglobals.insert("_REQUEST".into(), Value::Array(PhpArray::from_string_map(&request_vars)));
    superglobals.insert("_SESSION".into(), Value::Array(PhpArray::new()));

    // Build $_FILES from multipart data.
    let files_array = if let Some(flat_files) = multipart_files {
        flat_files_to_php_array(&flat_files)
    } else {
        PhpArray::new()
    };
    superglobals.insert("_FILES".into(), Value::Array(files_array));

    superglobals
}

fn build_server_vars(req: &HttpRequest, config: &AppConfig) -> HashMap<String, String> {
    let mut server = HashMap::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    server.insert("SERVER_SOFTWARE".into(), "php.rs/paas".into());
    server.insert("SERVER_NAME".into(), req.headers.get("host").cloned().unwrap_or_else(|| config.host.clone()));
    server.insert("SERVER_PORT".into(), config.port.to_string());
    server.insert("SERVER_PROTOCOL".into(), "HTTP/1.1".into());
    server.insert("GATEWAY_INTERFACE".into(), "CGI/1.1".into());
    server.insert("REQUEST_METHOD".into(), req.method.clone());
    server.insert("REQUEST_URI".into(), req.uri.clone());
    server.insert("SCRIPT_NAME".into(), format!("/{}", config.entry_script.trim_start_matches('/')));
    server.insert("QUERY_STRING".into(), req.query_string.clone());
    server.insert("DOCUMENT_ROOT".into(), config.document_root_path().display().to_string());
    server.insert("REMOTE_ADDR".into(), req.remote_addr.clone());
    server.insert("REQUEST_TIME".into(), now.as_secs().to_string());
    server.insert("REQUEST_TIME_FLOAT".into(), format!("{}.{:03}", now.as_secs(), now.subsec_millis()));
    server.insert("PHP_SELF".into(), req.path.clone());
    server.insert("SCRIPT_FILENAME".into(), config.entry_script_path().display().to_string());

    // Map HTTP headers to $_SERVER["HTTP_*"] format.
    for (key, value) in &req.headers {
        match key.as_str() {
            "content-type" => { server.insert("CONTENT_TYPE".into(), value.clone()); }
            "content-length" => { server.insert("CONTENT_LENGTH".into(), value.clone()); }
            _ => {
                let http_key = format!("HTTP_{}", key.to_uppercase().replace('-', "_"));
                server.insert(http_key, value.clone());
            }
        }
    }

    // Include APP_ENV as a server var.
    server.insert("APP_ENV".into(), config.app_env.clone());

    server
}

fn parse_query_string(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if qs.is_empty() {
        return map;
    }
    for pair in qs.split('&') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some(eq) = pair.find('=') {
            let key = url_decode(&pair[..eq]);
            let value = url_decode(&pair[eq + 1..]);
            map.insert(key, value);
        } else {
            map.insert(url_decode(pair), String::new());
        }
    }
    map
}

fn parse_cookies(header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in header.split(';') {
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
}

fn url_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use php_rs_vm::value::ArrayKey;

    fn sk(s: &str) -> ArrayKey {
        ArrayKey::String(s.to_string())
    }

    #[test]
    fn test_parse_query_string_basic() {
        let qs = parse_query_string("foo=bar&baz=42");
        assert_eq!(qs.get("foo").unwrap(), "bar");
        assert_eq!(qs.get("baz").unwrap(), "42");
    }

    #[test]
    fn test_parse_query_string_empty() {
        let qs = parse_query_string("");
        assert!(qs.is_empty());
    }

    #[test]
    fn test_parse_query_string_url_encoded() {
        let qs = parse_query_string("name=hello+world&path=%2Ffoo%2Fbar");
        assert_eq!(qs.get("name").unwrap(), "hello world");
        assert_eq!(qs.get("path").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_parse_cookies() {
        let cookies = parse_cookies("session=abc123; user=test; theme=dark");
        assert_eq!(cookies.get("session").unwrap(), "abc123");
        assert_eq!(cookies.get("user").unwrap(), "test");
        assert_eq!(cookies.get("theme").unwrap(), "dark");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("%2Ffoo%2Fbar"), "/foo/bar");
        assert_eq!(url_decode("no%20encoding%21"), "no encoding!");
        assert_eq!(url_decode("plain"), "plain");
    }

    #[test]
    fn test_build_superglobals_has_required_keys() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/test?q=1".into(),
            path: "/test".into(),
            query_string: "q=1".into(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "127.0.0.1:12345".into(),
        };
        let config = AppConfig::from_env();
        let sg = build_superglobals(&req, &config);

        assert!(sg.contains_key("_SERVER"));
        assert!(sg.contains_key("_GET"));
        assert!(sg.contains_key("_POST"));
        assert!(sg.contains_key("_COOKIE"));
        assert!(sg.contains_key("_ENV"));
        assert!(sg.contains_key("_REQUEST"));
        assert!(sg.contains_key("_FILES"));
        assert!(sg.contains_key("_SESSION"));
    }

    #[test]
    fn test_build_superglobals_get_params() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/api?name=John&age=30".into(),
            path: "/api".into(),
            query_string: "name=John&age=30".into(),
            headers: HashMap::new(),
            body: Vec::new(),
            remote_addr: "10.0.0.1:8080".into(),
        };
        let config = AppConfig::from_env();
        let sg = build_superglobals(&req, &config);

        if let Value::Array(get) = &sg["_GET"] {
            assert_eq!(
                get.get_by_key(&sk("name")),
                Some(&Value::String("John".into()))
            );
            assert_eq!(
                get.get_by_key(&sk("age")),
                Some(&Value::String("30".into()))
            );
        } else {
            panic!("_GET is not an array");
        }
    }

    #[test]
    fn test_build_superglobals_server_vars() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), "example.com".into());
        headers.insert("user-agent".into(), "TestAgent/1.0".into());

        let req = HttpRequest {
            method: "POST".into(),
            uri: "/submit".into(),
            path: "/submit".into(),
            query_string: String::new(),
            headers,
            body: Vec::new(),
            remote_addr: "192.168.1.1:5000".into(),
        };
        let config = AppConfig::from_env();
        let sg = build_superglobals(&req, &config);

        if let Value::Array(server) = &sg["_SERVER"] {
            assert_eq!(
                server.get_by_key(&sk("REQUEST_METHOD")),
                Some(&Value::String("POST".into()))
            );
            assert_eq!(
                server.get_by_key(&sk("REQUEST_URI")),
                Some(&Value::String("/submit".into()))
            );
            assert_eq!(
                server.get_by_key(&sk("REMOTE_ADDR")),
                Some(&Value::String("192.168.1.1:5000".into()))
            );
            assert_eq!(
                server.get_by_key(&sk("HTTP_HOST")),
                Some(&Value::String("example.com".into()))
            );
            assert_eq!(
                server.get_by_key(&sk("HTTP_USER_AGENT")),
                Some(&Value::String("TestAgent/1.0".into()))
            );
            assert_eq!(
                server.get_by_key(&sk("SERVER_SOFTWARE")),
                Some(&Value::String("php.rs/paas".into()))
            );
        } else {
            panic!("_SERVER is not an array");
        }
    }
}

/// Convert flat $_FILES keys (e.g. "image[name]") into nested PhpArrays.
fn flat_files_to_php_array(flat: &HashMap<String, String>) -> PhpArray {
    let mut files = PhpArray::new();
    let mut grouped: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (key, value) in flat {
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
    for (field, subkeys) in &grouped {
        let mut file_entry = PhpArray::new();
        for (subkey, value) in subkeys {
            match subkey.as_str() {
                "size" | "error" => {
                    let n = value.parse::<i64>().unwrap_or(0);
                    file_entry.set_string(subkey.clone(), Value::Long(n));
                }
                _ => {
                    file_entry.set_string(subkey.clone(), Value::String(value.clone()));
                }
            }
        }
        files.set_string(field.clone(), Value::Array(file_entry));
    }
    files
}
