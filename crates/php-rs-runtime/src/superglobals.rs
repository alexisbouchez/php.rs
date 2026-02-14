//! PHP superglobal variables.
//!
//! Implements $_SERVER, $_ENV, $_GET, $_POST, $_COOKIE, $_FILES,
//! $_REQUEST, $_SESSION, and $GLOBALS.
//!
//! Reference: php-src/main/php_variables.c

use std::collections::HashMap;

/// A single superglobal variable — essentially a string→string map.
///
/// In real PHP these are arrays of ZVals, but for the runtime service
/// layer we model them as string maps. The VM layer will convert them
/// to ZArray when needed.
pub type SuperglobalMap = HashMap<String, String>;

/// All PHP superglobal variables.
pub struct Superglobals {
    /// $_SERVER — server and execution environment information.
    pub server: SuperglobalMap,
    /// $_ENV — environment variables.
    pub env: SuperglobalMap,
    /// $_GET — URL query parameters.
    pub get: SuperglobalMap,
    /// $_POST — POST body parameters.
    pub post: SuperglobalMap,
    /// $_COOKIE — HTTP cookies.
    pub cookie: SuperglobalMap,
    /// $_FILES — uploaded file information.
    /// (Simplified: real PHP uses nested arrays per file.)
    pub files: SuperglobalMap,
    /// $_REQUEST — merged GET + POST + COOKIE (per request_order INI).
    pub request: SuperglobalMap,
    /// $_SESSION — session data.
    pub session: SuperglobalMap,
}

impl Superglobals {
    /// Create empty superglobals.
    pub fn new() -> Self {
        Self {
            server: HashMap::new(),
            env: HashMap::new(),
            get: HashMap::new(),
            post: HashMap::new(),
            cookie: HashMap::new(),
            files: HashMap::new(),
            request: HashMap::new(),
            session: HashMap::new(),
        }
    }

    /// Populate $_ENV from the process environment.
    pub fn populate_env(&mut self) {
        for (key, value) in std::env::vars() {
            self.env.insert(key, value);
        }
    }

    /// Populate $_SERVER with standard CLI values.
    pub fn populate_server_cli(&mut self, script_filename: &str, argv: &[String]) {
        self.server
            .insert("PHP_SELF".to_string(), script_filename.to_string());
        self.server
            .insert("SCRIPT_NAME".to_string(), script_filename.to_string());
        self.server
            .insert("SCRIPT_FILENAME".to_string(), script_filename.to_string());
        self.server
            .insert("DOCUMENT_ROOT".to_string(), String::new());
        self.server
            .insert("REQUEST_TIME".to_string(), current_timestamp().to_string());
        self.server.insert(
            "REQUEST_TIME_FLOAT".to_string(),
            current_timestamp_float().to_string(),
        );
        self.server.insert("argv".to_string(), argv.join(" "));
        self.server
            .insert("argc".to_string(), argv.len().to_string());
        self.server
            .insert("GATEWAY_INTERFACE".to_string(), String::new());
        self.server
            .insert("SERVER_PROTOCOL".to_string(), String::new());
        self.server
            .insert("REQUEST_METHOD".to_string(), String::new());
        self.server
            .insert("SERVER_SOFTWARE".to_string(), "php.rs".to_string());

        // Copy relevant env vars to $_SERVER
        for key in &[
            "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "TMPDIR", "HOSTNAME",
        ] {
            if let Ok(val) = std::env::var(key) {
                self.server.insert(key.to_string(), val);
            }
        }
    }

    /// Populate $_SERVER for an HTTP request (used by built-in web server / FPM).
    pub fn populate_server_http(
        &mut self,
        method: &str,
        uri: &str,
        host: &str,
        remote_addr: &str,
        content_type: &str,
        content_length: usize,
    ) {
        self.server
            .insert("REQUEST_METHOD".to_string(), method.to_string());
        self.server
            .insert("REQUEST_URI".to_string(), uri.to_string());
        self.server
            .insert("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string());
        self.server
            .insert("HTTP_HOST".to_string(), host.to_string());
        self.server
            .insert("REMOTE_ADDR".to_string(), remote_addr.to_string());
        self.server
            .insert("CONTENT_TYPE".to_string(), content_type.to_string());
        self.server
            .insert("CONTENT_LENGTH".to_string(), content_length.to_string());
        self.server
            .insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        self.server
            .insert("REQUEST_TIME".to_string(), current_timestamp().to_string());
        self.server.insert(
            "REQUEST_TIME_FLOAT".to_string(),
            current_timestamp_float().to_string(),
        );
        self.server
            .insert("SERVER_SOFTWARE".to_string(), "php.rs".to_string());

        // Parse query string from URI
        if let Some(q) = uri.find('?') {
            let query = &uri[q + 1..];
            self.server
                .insert("QUERY_STRING".to_string(), query.to_string());
            let path = &uri[..q];
            self.server
                .insert("SCRIPT_NAME".to_string(), path.to_string());
            self.server.insert("PHP_SELF".to_string(), path.to_string());
            self.parse_query_string(query);
        } else {
            self.server
                .insert("QUERY_STRING".to_string(), String::new());
            self.server
                .insert("SCRIPT_NAME".to_string(), uri.to_string());
            self.server.insert("PHP_SELF".to_string(), uri.to_string());
        }
    }

    /// Parse an application/x-www-form-urlencoded POST body into $_POST.
    pub fn parse_post_body(&mut self, body: &str) {
        for pair in body.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = if let Some(eq) = pair.find('=') {
                (url_decode(&pair[..eq]), url_decode(&pair[eq + 1..]))
            } else {
                (url_decode(pair), String::new())
            };
            self.post.insert(key, value);
        }
    }

    /// Parse a multipart/form-data body, populating $_POST and $_FILES.
    ///
    /// `boundary` is the boundary string from the Content-Type header.
    /// `max_file_size` is the upload_max_filesize INI limit in bytes (0 = unlimited).
    /// `max_post_size` is the post_max_size INI limit in bytes (0 = unlimited).
    ///
    /// Returns Ok(()) or an error string if limits are exceeded.
    pub fn parse_multipart(
        &mut self,
        body: &[u8],
        boundary: &str,
        max_file_size: usize,
        max_post_size: usize,
    ) -> Result<(), String> {
        // Check post_max_size
        if max_post_size > 0 && body.len() > max_post_size {
            return Err(format!(
                "POST Content-Length of {} bytes exceeds the limit of {} bytes",
                body.len(),
                max_post_size
            ));
        }

        let delimiter = format!("--{}", boundary);
        let body_str = String::from_utf8_lossy(body);

        // Split on boundary
        let parts: Vec<&str> = body_str.split(&delimiter).collect();

        for part in parts.iter().skip(1) {
            // Skip the final closing delimiter
            if part.starts_with("--") {
                continue;
            }

            // Split headers from body at the double newline
            let (headers_section, content) = if let Some(pos) = part.find("\r\n\r\n") {
                (&part[..pos], &part[pos + 4..])
            } else if let Some(pos) = part.find("\n\n") {
                (&part[..pos], &part[pos + 2..])
            } else {
                continue;
            };

            // Strip trailing \r\n from content
            let content = content.trim_end_matches("\r\n").trim_end_matches('\n');

            // Parse Content-Disposition
            let mut field_name = None;
            let mut filename = None;
            let mut content_type_val = "application/octet-stream".to_string();

            for line in headers_section.lines() {
                let line = line.trim();
                let lower = line.to_lowercase();
                if lower.starts_with("content-disposition:") {
                    // Extract name="..."
                    if let Some(npos) = line.find("name=\"") {
                        let rest = &line[npos + 6..];
                        if let Some(end) = rest.find('"') {
                            field_name = Some(rest[..end].to_string());
                        }
                    }
                    // Extract filename="..."
                    if let Some(fpos) = line.find("filename=\"") {
                        let rest = &line[fpos + 10..];
                        if let Some(end) = rest.find('"') {
                            filename = Some(rest[..end].to_string());
                        }
                    }
                } else if lower.starts_with("content-type:") {
                    content_type_val = line["content-type:".len()..].trim().to_string();
                }
            }

            let field_name = match field_name {
                Some(n) => n,
                None => continue,
            };

            if let Some(fname) = filename {
                // File upload
                let size = content.len();

                if max_file_size > 0 && size > max_file_size {
                    // PHP sets error code 1 (UPLOAD_ERR_INI_SIZE)
                    self.files.insert(format!("{}[name]", field_name), fname);
                    self.files
                        .insert(format!("{}[error]", field_name), "1".to_string());
                    self.files
                        .insert(format!("{}[size]", field_name), "0".to_string());
                    continue;
                }

                // Write to temp file
                let tmp_dir = std::env::temp_dir();
                let tmp_name = format!(
                    "php_rs_upload_{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                );
                let tmp_path = tmp_dir.join(&tmp_name);
                if let Err(e) = std::fs::write(&tmp_path, content.as_bytes()) {
                    self.files.insert(
                        format!("{}[error]", field_name),
                        format!("7"), // UPLOAD_ERR_CANT_WRITE
                    );
                    self.files.insert(format!("{}[name]", field_name), fname);
                    let _ = e;
                    continue;
                }

                // Populate $_FILES entries (PHP's nested array structure flattened)
                self.files.insert(format!("{}[name]", field_name), fname);
                self.files
                    .insert(format!("{}[type]", field_name), content_type_val);
                self.files.insert(
                    format!("{}[tmp_name]", field_name),
                    tmp_path.to_string_lossy().to_string(),
                );
                self.files
                    .insert(format!("{}[error]", field_name), "0".to_string());
                self.files
                    .insert(format!("{}[size]", field_name), size.to_string());
            } else {
                // Regular form field → $_POST
                self.post.insert(field_name, content.to_string());
            }
        }

        Ok(())
    }

    /// Extract the boundary from a Content-Type header value.
    /// e.g. "multipart/form-data; boundary=----WebKitFormBoundary" → "----WebKitFormBoundary"
    pub fn extract_boundary(content_type: &str) -> Option<String> {
        for part in content_type.split(';') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix("boundary=") {
                return Some(val.trim_matches('"').to_string());
            }
        }
        None
    }

    /// Parse a query string into $_GET (e.g., "foo=bar&baz=qux").
    pub fn parse_query_string(&mut self, query: &str) {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = if let Some(eq) = pair.find('=') {
                (url_decode(&pair[..eq]), url_decode(&pair[eq + 1..]))
            } else {
                (url_decode(pair), String::new())
            };
            self.get.insert(key, value);
        }
    }

    /// Build $_REQUEST from $_GET, $_POST, $_COOKIE according to request_order.
    ///
    /// The `order` parameter follows PHP's `request_order` INI (default "GP"):
    /// - G = $_GET
    /// - P = $_POST
    /// - C = $_COOKIE
    ///
    /// Later values override earlier ones.
    pub fn build_request(&mut self, order: &str) {
        self.request.clear();
        for ch in order.chars() {
            let source = match ch {
                'G' | 'g' => &self.get,
                'P' | 'p' => &self.post,
                'C' | 'c' => &self.cookie,
                _ => continue,
            };
            for (k, v) in source {
                self.request.insert(k.clone(), v.clone());
            }
        }
    }

    /// Reset all superglobals (for request end).
    pub fn reset(&mut self) {
        self.server.clear();
        self.env.clear();
        self.get.clear();
        self.post.clear();
        self.cookie.clear();
        self.files.clear();
        self.request.clear();
        self.session.clear();
    }
}

impl Default for Superglobals {
    fn default() -> Self {
        Self::new()
    }
}

/// Basic URL decoding (percent-decoding + '+' → space).
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();

    while let Some(b) = chars.next() {
        match b {
            b'+' => result.push(' '),
            b'%' => {
                let hi = chars.next().and_then(hex_val);
                let lo = chars.next().and_then(hex_val);
                if let (Some(h), Some(l)) = (hi, lo) {
                    result.push((h << 4 | l) as char);
                } else {
                    result.push('%');
                }
            }
            _ => result.push(b as char),
        }
    }

    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn current_timestamp_float() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superglobals_new_empty() {
        let sg = Superglobals::new();
        assert!(sg.server.is_empty());
        assert!(sg.env.is_empty());
        assert!(sg.get.is_empty());
        assert!(sg.post.is_empty());
        assert!(sg.cookie.is_empty());
        assert!(sg.request.is_empty());
    }

    #[test]
    fn test_populate_env() {
        let mut sg = Superglobals::new();
        // Set a known env var for testing
        std::env::set_var("PHP_RS_TEST_VAR", "hello");
        sg.populate_env();
        assert_eq!(sg.env.get("PHP_RS_TEST_VAR"), Some(&"hello".to_string()));
        std::env::remove_var("PHP_RS_TEST_VAR");
    }

    #[test]
    fn test_populate_server_cli() {
        let mut sg = Superglobals::new();
        sg.populate_server_cli("test.php", &["test.php".to_string(), "--flag".to_string()]);
        assert_eq!(
            sg.server.get("SCRIPT_FILENAME"),
            Some(&"test.php".to_string())
        );
        assert_eq!(sg.server.get("argc"), Some(&"2".to_string()));
        assert_eq!(
            sg.server.get("SERVER_SOFTWARE"),
            Some(&"php.rs".to_string())
        );
    }

    #[test]
    fn test_parse_query_string() {
        let mut sg = Superglobals::new();
        sg.parse_query_string("foo=bar&baz=qux&empty=&flag");
        assert_eq!(sg.get.get("foo"), Some(&"bar".to_string()));
        assert_eq!(sg.get.get("baz"), Some(&"qux".to_string()));
        assert_eq!(sg.get.get("empty"), Some(&String::new()));
        assert_eq!(sg.get.get("flag"), Some(&String::new()));
    }

    #[test]
    fn test_parse_query_string_url_encoded() {
        let mut sg = Superglobals::new();
        sg.parse_query_string("name=John+Doe&path=%2Ftmp%2Ftest");
        assert_eq!(sg.get.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(sg.get.get("path"), Some(&"/tmp/test".to_string()));
    }

    #[test]
    fn test_build_request_gp() {
        let mut sg = Superglobals::new();
        sg.get.insert("a".to_string(), "from_get".to_string());
        sg.get.insert("shared".to_string(), "get_val".to_string());
        sg.post.insert("b".to_string(), "from_post".to_string());
        sg.post.insert("shared".to_string(), "post_val".to_string());

        sg.build_request("GP");
        assert_eq!(sg.request.get("a"), Some(&"from_get".to_string()));
        assert_eq!(sg.request.get("b"), Some(&"from_post".to_string()));
        // POST overrides GET for shared keys (P comes after G)
        assert_eq!(sg.request.get("shared"), Some(&"post_val".to_string()));
    }

    #[test]
    fn test_build_request_pg() {
        let mut sg = Superglobals::new();
        sg.get.insert("shared".to_string(), "get_val".to_string());
        sg.post.insert("shared".to_string(), "post_val".to_string());

        sg.build_request("PG");
        // GET overrides POST for shared keys (G comes after P)
        assert_eq!(sg.request.get("shared"), Some(&"get_val".to_string()));
    }

    #[test]
    fn test_build_request_with_cookie() {
        let mut sg = Superglobals::new();
        sg.get.insert("a".to_string(), "1".to_string());
        sg.cookie.insert("session".to_string(), "abc".to_string());

        sg.build_request("GPC");
        assert_eq!(sg.request.get("a"), Some(&"1".to_string()));
        assert_eq!(sg.request.get("session"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_reset() {
        let mut sg = Superglobals::new();
        sg.get.insert("a".to_string(), "1".to_string());
        sg.server.insert("b".to_string(), "2".to_string());
        sg.reset();
        assert!(sg.get.is_empty());
        assert!(sg.server.is_empty());
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("foo%20bar"), "foo bar");
        assert_eq!(url_decode("%2F"), "/");
        assert_eq!(url_decode("plain"), "plain");
        assert_eq!(url_decode(""), "");
    }

    #[test]
    fn test_parse_post_body() {
        let mut sg = Superglobals::new();
        sg.parse_post_body("name=John+Doe&age=30&city=New+York");
        assert_eq!(sg.post.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(sg.post.get("age"), Some(&"30".to_string()));
        assert_eq!(sg.post.get("city"), Some(&"New York".to_string()));
    }

    #[test]
    fn test_parse_multipart_form_fields() {
        let mut sg = Superglobals::new();
        let boundary = "----boundary123";
        let body = format!(
            "------boundary123\r\n\
             Content-Disposition: form-data; name=\"field1\"\r\n\
             \r\n\
             value1\r\n\
             ------boundary123\r\n\
             Content-Disposition: form-data; name=\"field2\"\r\n\
             \r\n\
             value2\r\n\
             ------boundary123--\r\n"
        );
        sg.parse_multipart(body.as_bytes(), boundary, 0, 0).unwrap();
        assert_eq!(sg.post.get("field1"), Some(&"value1".to_string()));
        assert_eq!(sg.post.get("field2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_parse_multipart_file_upload() {
        let mut sg = Superglobals::new();
        let boundary = "----boundary456";
        let body = format!(
            "------boundary456\r\n\
             Content-Disposition: form-data; name=\"myfile\"; filename=\"test.txt\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             Hello file content\r\n\
             ------boundary456--\r\n"
        );
        sg.parse_multipart(body.as_bytes(), boundary, 0, 0).unwrap();
        assert_eq!(sg.files.get("myfile[name]"), Some(&"test.txt".to_string()));
        assert_eq!(
            sg.files.get("myfile[type]"),
            Some(&"text/plain".to_string())
        );
        assert_eq!(sg.files.get("myfile[error]"), Some(&"0".to_string()));
        assert!(sg.files.get("myfile[tmp_name]").is_some());
        // Clean up temp file
        if let Some(tmp) = sg.files.get("myfile[tmp_name]") {
            let _ = std::fs::remove_file(tmp);
        }
    }

    #[test]
    fn test_parse_multipart_exceeds_file_size() {
        let mut sg = Superglobals::new();
        let boundary = "----boundary789";
        let body = format!(
            "------boundary789\r\n\
             Content-Disposition: form-data; name=\"bigfile\"; filename=\"big.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             This content is too large for the limit\r\n\
             ------boundary789--\r\n"
        );
        // Set max file size to 10 bytes — content is larger
        sg.parse_multipart(body.as_bytes(), boundary, 10, 0)
            .unwrap();
        // Should have error = 1 (UPLOAD_ERR_INI_SIZE)
        assert_eq!(sg.files.get("bigfile[error]"), Some(&"1".to_string()));
    }

    #[test]
    fn test_parse_multipart_exceeds_post_size() {
        let mut sg = Superglobals::new();
        let boundary = "----boundary000";
        let body = b"------boundary000\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\ndata\r\n------boundary000--\r\n";
        let result = sg.parse_multipart(body, boundary, 0, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds the limit"));
    }

    #[test]
    fn test_extract_boundary() {
        assert_eq!(
            Superglobals::extract_boundary("multipart/form-data; boundary=----WebKit123"),
            Some("----WebKit123".to_string())
        );
        assert_eq!(
            Superglobals::extract_boundary("multipart/form-data; boundary=\"quoted-bound\""),
            Some("quoted-bound".to_string())
        );
        assert_eq!(Superglobals::extract_boundary("application/json"), None);
    }

    #[test]
    fn test_populate_server_http() {
        let mut sg = Superglobals::new();
        sg.populate_server_http(
            "POST",
            "/api/upload?token=abc",
            "example.com",
            "127.0.0.1",
            "application/json",
            42,
        );
        assert_eq!(sg.server.get("REQUEST_METHOD"), Some(&"POST".to_string()));
        assert_eq!(sg.server.get("HTTP_HOST"), Some(&"example.com".to_string()));
        assert_eq!(
            sg.server.get("QUERY_STRING"),
            Some(&"token=abc".to_string())
        );
        assert_eq!(
            sg.server.get("SCRIPT_NAME"),
            Some(&"/api/upload".to_string())
        );
        assert_eq!(sg.get.get("token"), Some(&"abc".to_string()));
    }
}
