//! PHP miscellaneous standard functions.
//!
//! Reference: php-src/ext/standard/basic_functions.c, info.c, type.c

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── 8.6.1: Constants ─────────────────────────────────────────────────────────

/// A simple constants store.
pub struct ConstantStore {
    constants: HashMap<String, ConstValue>,
}

/// A PHP constant value.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl ConstValue {
    pub fn as_str(&self) -> String {
        match self {
            ConstValue::Null => String::new(),
            ConstValue::Bool(true) => "1".to_string(),
            ConstValue::Bool(false) => String::new(),
            ConstValue::Int(n) => n.to_string(),
            ConstValue::Float(f) => format!("{}", f),
            ConstValue::Str(s) => s.clone(),
        }
    }
}

impl ConstantStore {
    pub fn new() -> Self {
        let mut store = Self {
            constants: HashMap::new(),
        };
        // Pre-register PHP constants
        store.register_defaults();
        store
    }

    fn register_defaults(&mut self) {
        self.constants
            .insert("PHP_EOL".to_string(), ConstValue::Str("\n".to_string()));
        self.constants
            .insert("PHP_INT_MAX".to_string(), ConstValue::Int(i64::MAX));
        self.constants
            .insert("PHP_INT_MIN".to_string(), ConstValue::Int(i64::MIN));
        self.constants
            .insert("PHP_INT_SIZE".to_string(), ConstValue::Int(8));
        self.constants
            .insert("PHP_FLOAT_MAX".to_string(), ConstValue::Float(f64::MAX));
        self.constants.insert(
            "PHP_FLOAT_MIN".to_string(),
            ConstValue::Float(f64::MIN_POSITIVE),
        );
        self.constants.insert(
            "PHP_FLOAT_EPSILON".to_string(),
            ConstValue::Float(f64::EPSILON),
        );
        self.constants
            .insert("PHP_FLOAT_DIG".to_string(), ConstValue::Int(15));
        self.constants
            .insert("PHP_MAJOR_VERSION".to_string(), ConstValue::Int(8));
        self.constants
            .insert("PHP_MINOR_VERSION".to_string(), ConstValue::Int(6));
        self.constants
            .insert("PHP_RELEASE_VERSION".to_string(), ConstValue::Int(0));
        self.constants.insert(
            "PHP_VERSION".to_string(),
            ConstValue::Str("8.6.0-php.rs".to_string()),
        );
        self.constants
            .insert("PHP_VERSION_ID".to_string(), ConstValue::Int(80600));
        self.constants.insert(
            "PHP_OS".to_string(),
            ConstValue::Str(std::env::consts::OS.to_string()),
        );
        self.constants.insert(
            "PHP_OS_FAMILY".to_string(),
            ConstValue::Str(os_family().to_string()),
        );
        self.constants
            .insert("PHP_SAPI".to_string(), ConstValue::Str("cli".to_string()));
        self.constants
            .insert("PHP_MAXPATHLEN".to_string(), ConstValue::Int(1024));
        self.constants.insert(
            "PHP_PREFIX".to_string(),
            ConstValue::Str("/usr/local".to_string()),
        );
        self.constants.insert(
            "DIRECTORY_SEPARATOR".to_string(),
            ConstValue::Str(std::path::MAIN_SEPARATOR.to_string()),
        );
        self.constants.insert(
            "PATH_SEPARATOR".to_string(),
            ConstValue::Str(if cfg!(windows) { ";" } else { ":" }.to_string()),
        );
        self.constants
            .insert("TRUE".to_string(), ConstValue::Bool(true));
        self.constants
            .insert("FALSE".to_string(), ConstValue::Bool(false));
        self.constants.insert("NULL".to_string(), ConstValue::Null);
        self.constants
            .insert("STDIN".to_string(), ConstValue::Int(0));
        self.constants
            .insert("STDOUT".to_string(), ConstValue::Int(1));
        self.constants
            .insert("STDERR".to_string(), ConstValue::Int(2));

        // Error level constants
        self.constants
            .insert("E_ERROR".to_string(), ConstValue::Int(1));
        self.constants
            .insert("E_WARNING".to_string(), ConstValue::Int(2));
        self.constants
            .insert("E_PARSE".to_string(), ConstValue::Int(4));
        self.constants
            .insert("E_NOTICE".to_string(), ConstValue::Int(8));
        self.constants
            .insert("E_CORE_ERROR".to_string(), ConstValue::Int(16));
        self.constants
            .insert("E_CORE_WARNING".to_string(), ConstValue::Int(32));
        self.constants
            .insert("E_COMPILE_ERROR".to_string(), ConstValue::Int(64));
        self.constants
            .insert("E_COMPILE_WARNING".to_string(), ConstValue::Int(128));
        self.constants
            .insert("E_USER_ERROR".to_string(), ConstValue::Int(256));
        self.constants
            .insert("E_USER_WARNING".to_string(), ConstValue::Int(512));
        self.constants
            .insert("E_USER_NOTICE".to_string(), ConstValue::Int(1024));
        self.constants
            .insert("E_STRICT".to_string(), ConstValue::Int(2048));
        self.constants
            .insert("E_RECOVERABLE_ERROR".to_string(), ConstValue::Int(4096));
        self.constants
            .insert("E_DEPRECATED".to_string(), ConstValue::Int(8192));
        self.constants
            .insert("E_USER_DEPRECATED".to_string(), ConstValue::Int(16384));
        self.constants
            .insert("E_ALL".to_string(), ConstValue::Int(32767));

        // Sort flags
        self.constants
            .insert("SORT_REGULAR".to_string(), ConstValue::Int(0));
        self.constants
            .insert("SORT_NUMERIC".to_string(), ConstValue::Int(1));
        self.constants
            .insert("SORT_STRING".to_string(), ConstValue::Int(2));
        self.constants
            .insert("SORT_LOCALE_STRING".to_string(), ConstValue::Int(5));
        self.constants
            .insert("SORT_NATURAL".to_string(), ConstValue::Int(6));
        self.constants
            .insert("SORT_FLAG_CASE".to_string(), ConstValue::Int(8));

        // Array flags
        self.constants
            .insert("ARRAY_FILTER_USE_BOTH".to_string(), ConstValue::Int(1));
        self.constants
            .insert("ARRAY_FILTER_USE_KEY".to_string(), ConstValue::Int(2));

        // STR_PAD
        self.constants
            .insert("STR_PAD_RIGHT".to_string(), ConstValue::Int(1));
        self.constants
            .insert("STR_PAD_LEFT".to_string(), ConstValue::Int(0));
        self.constants
            .insert("STR_PAD_BOTH".to_string(), ConstValue::Int(2));
    }

    /// define() — Defines a named constant.
    pub fn define(&mut self, name: &str, value: ConstValue) -> bool {
        if self.constants.contains_key(name) {
            return false;
        }
        self.constants.insert(name.to_string(), value);
        true
    }

    /// constant() — Returns the value of a constant.
    pub fn constant(&self, name: &str) -> Option<&ConstValue> {
        self.constants.get(name)
    }

    /// defined() — Checks whether a given named constant exists.
    pub fn defined(&self, name: &str) -> bool {
        self.constants.contains_key(name)
    }
}

impl Default for ConstantStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── 8.6.2-8.6.3: Reflection-like functions ──────────────────────────────────

/// function_exists() — Return true if the given function has been defined.
/// (Requires a function registry; we provide the signature here.)
pub fn php_function_exists(name: &str, registry: &[&str]) -> bool {
    registry.contains(&name)
}

// ── 8.6.6: Timing ───────────────────────────────────────────────────────────

/// sleep() — Delay execution (in seconds).
pub fn php_sleep(seconds: u64) {
    std::thread::sleep(std::time::Duration::from_secs(seconds));
}

/// usleep() — Delay execution in microseconds.
pub fn php_usleep(microseconds: u64) {
    std::thread::sleep(std::time::Duration::from_micros(microseconds));
}

// ── 8.6.7: Time functions ────────────────────────────────────────────────────

/// microtime() — Return current Unix timestamp with microseconds.
pub fn php_microtime(as_float: bool) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    if as_float {
        format!("{}.{:06}", now.as_secs(), now.subsec_micros())
    } else {
        // PHP format: "0.MICROSECONDS SECONDS"
        format!("0.{:06}00 {}", now.subsec_micros(), now.as_secs())
    }
}

/// time() — Return current Unix timestamp.
pub fn php_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// hrtime() — Get the system's high resolution time (nanoseconds).
pub fn php_hrtime(as_number: bool) -> (u64, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if as_number {
        (now.as_nanos() as u64, 0)
    } else {
        (now.as_secs(), now.subsec_nanos() as u64)
    }
}

// ── 8.6.8: Environment ──────────────────────────────────────────────────────

/// getenv() — Gets the value of an environment variable.
pub fn php_getenv(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// putenv() — Sets the value of an environment variable.
pub fn php_putenv(setting: &str) -> bool {
    if let Some(eq) = setting.find('=') {
        let key = &setting[..eq];
        let value = &setting[eq + 1..];
        std::env::set_var(key, value);
        true
    } else {
        std::env::remove_var(setting);
        true
    }
}

// ── 8.6.12: PHP info ────────────────────────────────────────────────────────

/// phpversion() — Gets the current PHP version.
pub fn php_phpversion() -> &'static str {
    "8.6.0-php.rs"
}

/// php_uname() — Returns information about the operating system.
pub fn php_uname(mode: char) -> String {
    match mode {
        's' => std::env::consts::OS.to_string(),
        'r' => "unknown".to_string(), // Would need uname() syscall
        'v' => "unknown".to_string(),
        'm' => std::env::consts::ARCH.to_string(),
        'n' => hostname(),
        _ => {
            format!(
                "{} {} {} {} {}",
                std::env::consts::OS,
                hostname(),
                "unknown",
                "unknown",
                std::env::consts::ARCH,
            )
        }
    }
}

/// php_sapi_name() — Returns the type of interface between web server and PHP.
pub fn php_sapi_name() -> &'static str {
    "cli"
}

// ── 8.6.3: Class introspection ────────────────────────────────────────────────

/// get_parent_class() — Retrieves the parent class name.
/// The actual class lookup happens in the VM; this is the signature.
pub fn php_get_parent_class(
    class_name: &str,
    parent_lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    parent_lookup(class_name)
}

/// is_a() — Checks if the object is of this class or has this class as one of its parents.
pub fn php_is_a(
    class_name: &str,
    target_class: &str,
    inheritance_check: impl Fn(&str, &str) -> bool,
) -> bool {
    if class_name.eq_ignore_ascii_case(target_class) {
        return true;
    }
    inheritance_check(class_name, target_class)
}

/// is_subclass_of() — Checks if the object has this class as one of its parents (excluding self).
pub fn php_is_subclass_of(
    class_name: &str,
    target_class: &str,
    inheritance_check: impl Fn(&str, &str) -> bool,
) -> bool {
    if class_name.eq_ignore_ascii_case(target_class) {
        return false;
    }
    inheritance_check(class_name, target_class)
}

// ── 8.6.5: HTTP headers ──────────────────────────────────────────────────────

/// HTTP header manager for the SAPI layer.
#[derive(Debug, Clone, Default)]
pub struct HeaderStore {
    headers: Vec<(String, String)>,
    http_response_code: u16,
    headers_sent: bool,
}

impl HeaderStore {
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            http_response_code: 200,
            headers_sent: false,
        }
    }

    /// header() — Send a raw HTTP header.
    pub fn header(&mut self, header_str: &str, replace: bool) {
        if self.headers_sent {
            return;
        }

        // Check for HTTP/ status line
        if header_str.starts_with("HTTP/") {
            // Extract response code
            if let Some(code) = header_str
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
            {
                self.http_response_code = code;
            }
            return;
        }

        if let Some(colon_pos) = header_str.find(':') {
            let name = header_str[..colon_pos].trim().to_string();
            let value = header_str[colon_pos + 1..].trim().to_string();

            if replace {
                self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
            }
            self.headers.push((name, value));
        }
    }

    /// header_remove() — Remove previously set headers.
    pub fn header_remove(&mut self, name: Option<&str>) {
        match name {
            Some(n) => self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(n)),
            None => self.headers.clear(),
        }
    }

    /// headers_sent() — Checks if or where headers have been sent.
    pub fn headers_sent(&self) -> bool {
        self.headers_sent
    }

    /// http_response_code() — Get or Set the HTTP response code.
    pub fn http_response_code(&mut self, code: Option<u16>) -> u16 {
        if let Some(c) = code {
            let old = self.http_response_code;
            self.http_response_code = c;
            old
        } else {
            self.http_response_code
        }
    }

    /// Mark headers as sent (called when first output occurs).
    pub fn mark_sent(&mut self) {
        self.headers_sent = true;
    }

    /// Get all headers.
    pub fn get_headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

// ── 8.6.9: exit / die ────────────────────────────────────────────────────────
// exit() and die() are language constructs handled by the compiler/VM.
// They produce a special ExitStatus that the SAPI layer handles.

/// Represents the result of exit()/die().
#[derive(Debug, Clone, PartialEq)]
pub enum ExitStatus {
    /// exit(0) or exit() — success
    Code(i32),
    /// exit("message") — print message and exit with 0
    Message(String),
}

impl ExitStatus {
    pub fn code(&self) -> i32 {
        match self {
            ExitStatus::Code(c) => *c,
            ExitStatus::Message(_) => 0,
        }
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            ExitStatus::Message(m) => Some(m),
            _ => None,
        }
    }
}

// ── 8.6.10: Shutdown functions ───────────────────────────────────────────────

/// Shutdown function registry.
#[derive(Debug, Default)]
pub struct ShutdownFunctionRegistry {
    functions: Vec<String>,
}

impl ShutdownFunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    /// register_shutdown_function() — Register a function for execution on shutdown.
    pub fn register(&mut self, func_name: String) {
        self.functions.push(func_name);
    }

    /// Get all registered shutdown functions (in order of registration).
    pub fn functions(&self) -> &[String] {
        &self.functions
    }

    /// Clear all registered functions (for testing).
    pub fn clear(&mut self) {
        self.functions.clear();
    }
}

// ── 8.6.11: Execution limits ─────────────────────────────────────────────────

/// set_time_limit() — Limits the maximum execution time.
///
/// In our implementation, we store the limit but actual enforcement
/// happens in the VM's dispatch loop.
pub fn php_set_time_limit(seconds: u64) -> u64 {
    // Returns the previous limit; actual enforcement is VM-level
    seconds
}

/// ignore_user_abort() — Set whether client disconnection should abort script execution.
pub fn php_ignore_user_abort(setting: Option<bool>, current: bool) -> bool {
    match setting {
        Some(_) => current, // Return previous value
        None => current,    // Return current value
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string())
}

fn os_family() -> &'static str {
    if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "freebsd") {
        "BSD"
    } else {
        "Unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_store_defaults() {
        let store = ConstantStore::new();
        assert!(store.defined("PHP_EOL"));
        assert!(store.defined("PHP_INT_MAX"));
        assert!(store.defined("TRUE"));
        assert!(store.defined("E_ALL"));
        assert_eq!(
            store.constant("PHP_INT_MAX"),
            Some(&ConstValue::Int(i64::MAX))
        );
        assert_eq!(
            store.constant("PHP_VERSION"),
            Some(&ConstValue::Str("8.6.0-php.rs".to_string()))
        );
    }

    #[test]
    fn test_define() {
        let mut store = ConstantStore::new();
        assert!(store.define("MY_CONST", ConstValue::Int(42)));
        assert!(store.defined("MY_CONST"));
        assert_eq!(store.constant("MY_CONST"), Some(&ConstValue::Int(42)));

        // Cannot redefine
        assert!(!store.define("MY_CONST", ConstValue::Int(99)));
        assert_eq!(store.constant("MY_CONST"), Some(&ConstValue::Int(42)));
    }

    #[test]
    fn test_function_exists() {
        let registry = vec!["strlen", "substr", "array_map"];
        assert!(php_function_exists("strlen", &registry));
        assert!(!php_function_exists("nonexistent", &registry));
    }

    #[test]
    fn test_time() {
        let t = php_time();
        assert!(t > 1700000000); // After Nov 2023
    }

    #[test]
    fn test_microtime() {
        let mt = php_microtime(true);
        assert!(mt.contains('.'));

        let mt = php_microtime(false);
        assert!(mt.starts_with("0."));
    }

    #[test]
    fn test_getenv_putenv() {
        php_putenv("PHP_RS_TEST_MISC=hello");
        assert_eq!(php_getenv("PHP_RS_TEST_MISC"), Some("hello".to_string()));
        assert_eq!(php_getenv("NONEXISTENT_VAR_12345"), None);
        std::env::remove_var("PHP_RS_TEST_MISC");
    }

    #[test]
    fn test_phpversion() {
        assert_eq!(php_phpversion(), "8.6.0-php.rs");
    }

    #[test]
    fn test_php_sapi_name() {
        assert_eq!(php_sapi_name(), "cli");
    }

    #[test]
    fn test_php_uname() {
        let os = php_uname('s');
        assert!(!os.is_empty());

        let arch = php_uname('m');
        assert!(!arch.is_empty());
    }

    // ── Class introspection ──
    #[test]
    fn test_is_a() {
        // Same class
        assert!(php_is_a("Foo", "Foo", |_, _| false));
        assert!(php_is_a("Foo", "foo", |_, _| false)); // Case-insensitive
                                                       // Parent class
        assert!(php_is_a("Child", "Parent", |cls, target| {
            cls == "Child" && target == "Parent"
        }));
        assert!(!php_is_a("Child", "Other", |_, _| false));
    }

    #[test]
    fn test_is_subclass_of() {
        // Same class is NOT a subclass
        assert!(!php_is_subclass_of("Foo", "Foo", |_, _| true));
        // Parent class IS a subclass
        assert!(php_is_subclass_of("Child", "Parent", |cls, target| {
            cls == "Child" && target == "Parent"
        }));
    }

    // ── Header store ──
    #[test]
    fn test_header_store() {
        let mut store = HeaderStore::new();
        assert_eq!(store.http_response_code(None), 200);
        assert!(!store.headers_sent());

        store.header("Content-Type: text/html", true);
        assert_eq!(store.get_headers().len(), 1);

        store.header("X-Custom: value1", false);
        store.header("X-Custom: value2", false);
        assert_eq!(store.get_headers().len(), 3);

        store.header_remove(Some("X-Custom"));
        assert_eq!(store.get_headers().len(), 1);

        store.http_response_code(Some(404));
        assert_eq!(store.http_response_code(None), 404);
    }

    #[test]
    fn test_header_http_status_line() {
        let mut store = HeaderStore::new();
        store.header("HTTP/1.1 301 Moved Permanently", true);
        assert_eq!(store.http_response_code(None), 301);
    }

    // ── Exit status ──
    #[test]
    fn test_exit_status() {
        let exit_code = ExitStatus::Code(1);
        assert_eq!(exit_code.code(), 1);
        assert_eq!(exit_code.message(), None);

        let exit_msg = ExitStatus::Message("Goodbye".to_string());
        assert_eq!(exit_msg.code(), 0);
        assert_eq!(exit_msg.message(), Some("Goodbye"));
    }

    // ── Shutdown functions ──
    #[test]
    fn test_shutdown_functions() {
        let mut registry = ShutdownFunctionRegistry::new();
        assert_eq!(registry.functions().len(), 0);

        registry.register("cleanup".to_string());
        registry.register("log_shutdown".to_string());
        assert_eq!(registry.functions().len(), 2);
        assert_eq!(registry.functions()[0], "cleanup");
        assert_eq!(registry.functions()[1], "log_shutdown");

        registry.clear();
        assert_eq!(registry.functions().len(), 0);
    }

    #[test]
    fn test_const_value_as_str() {
        assert_eq!(ConstValue::Int(42).as_str(), "42");
        assert_eq!(ConstValue::Bool(true).as_str(), "1");
        assert_eq!(ConstValue::Null.as_str(), "");
        assert_eq!(ConstValue::Str("hello".to_string()).as_str(), "hello");
    }
}
