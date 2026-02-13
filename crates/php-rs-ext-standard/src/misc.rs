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

    #[test]
    fn test_const_value_as_str() {
        assert_eq!(ConstValue::Int(42).as_str(), "42");
        assert_eq!(ConstValue::Bool(true).as_str(), "1");
        assert_eq!(ConstValue::Null.as_str(), "");
        assert_eq!(ConstValue::Str("hello".to_string()).as_str(), "hello");
    }
}
