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
}
