//! PHP Embed SAPI — embeddable PHP interpreter for Rust applications.
//!
//! Equivalent to php-src/sapi/embed/
//!
//! Provides a simple API to:
//! - Initialize/shutdown the PHP runtime
//! - Execute PHP code strings
//! - Execute PHP files
//! - Exchange values between Rust and PHP

use std::collections::HashMap;

// ── PHP Embed Value Type ────────────────────────────────────────────────────

/// A PHP value that can be exchanged between Rust and PHP.
#[derive(Debug, Clone, PartialEq)]
pub enum PhpValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<(PhpValue, PhpValue)>),
}

impl PhpValue {
    /// Convert to a PHP expression string.
    pub fn to_php_literal(&self) -> String {
        match self {
            PhpValue::Null => "null".into(),
            PhpValue::Bool(true) => "true".into(),
            PhpValue::Bool(false) => "false".into(),
            PhpValue::Int(n) => n.to_string(),
            PhpValue::Float(f) => {
                let s = f.to_string();
                if s.contains('.') {
                    s
                } else {
                    format!("{}.0", s)
                }
            }
            PhpValue::String(s) => {
                // Escape for PHP single-quoted string
                let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
                format!("'{}'", escaped)
            }
            PhpValue::Array(entries) => {
                let items: Vec<String> = entries
                    .iter()
                    .map(|(k, v)| format!("{} => {}", k.to_php_literal(), v.to_php_literal()))
                    .collect();
                format!("[{}]", items.join(", "))
            }
        }
    }

    /// Check if the value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, PhpValue::Null)
    }

    /// Try to get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PhpValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get as integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            PhpValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Try to get as float.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            PhpValue::Float(f) => Some(*f),
            PhpValue::Int(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// Try to get as string reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PhpValue::String(s) => Some(s),
            _ => None,
        }
    }
}

impl std::fmt::Display for PhpValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhpValue::Null => write!(f, ""),
            PhpValue::Bool(true) => write!(f, "1"),
            PhpValue::Bool(false) => write!(f, ""),
            PhpValue::Int(n) => write!(f, "{}", n),
            PhpValue::Float(v) => write!(f, "{}", v),
            PhpValue::String(s) => write!(f, "{}", s),
            PhpValue::Array(_) => write!(f, "Array"),
        }
    }
}

// ── PHP Embed Error ─────────────────────────────────────────────────────────

/// Errors from the embed SAPI.
#[derive(Debug, Clone)]
pub enum EmbedError {
    /// Parse error in PHP code.
    ParseError(String),
    /// Runtime error during execution.
    RuntimeError(String),
    /// File not found.
    FileNotFound(String),
    /// IO error.
    IoError(String),
    /// Not initialized.
    NotInitialized,
}

impl std::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbedError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            EmbedError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
            EmbedError::FileNotFound(path) => write!(f, "File not found: {}", path),
            EmbedError::IoError(msg) => write!(f, "IO error: {}", msg),
            EmbedError::NotInitialized => write!(f, "PHP runtime not initialized"),
        }
    }
}

impl std::error::Error for EmbedError {}

pub type EmbedResult<T> = Result<T, EmbedError>;

// ── PHP Embed Runtime ───────────────────────────────────────────────────────

/// The embeddable PHP runtime.
///
/// Usage:
/// ```no_run
/// use php_rs_sapi_embed::PhpEmbed;
///
/// let mut php = PhpEmbed::new();
/// php.init().unwrap();
///
/// let output = php.eval_string("echo 'Hello!';").unwrap();
/// assert_eq!(output, "Hello!");
///
/// php.shutdown();
/// ```
pub struct PhpEmbed {
    initialized: bool,
    /// INI overrides.
    ini_overrides: HashMap<String, String>,
    /// Variables to inject into the PHP scope.
    variables: HashMap<String, PhpValue>,
}

impl PhpEmbed {
    /// Create a new embed instance (not yet initialized).
    pub fn new() -> Self {
        Self {
            initialized: false,
            ini_overrides: HashMap::new(),
            variables: HashMap::new(),
        }
    }

    /// Set an INI directive before initialization.
    pub fn set_ini(&mut self, key: &str, value: &str) {
        self.ini_overrides
            .insert(key.to_string(), value.to_string());
    }

    /// Set a variable that will be available in PHP scope.
    pub fn set_variable(&mut self, name: &str, value: PhpValue) {
        self.variables.insert(name.to_string(), value);
    }

    /// Initialize the PHP runtime.
    pub fn init(&mut self) -> EmbedResult<()> {
        // In a full implementation, this would init the Zend engine,
        // register extensions, apply INI, etc.
        self.initialized = true;
        Ok(())
    }

    /// Shut down the PHP runtime.
    pub fn shutdown(&mut self) {
        self.initialized = false;
        self.variables.clear();
    }

    /// Check if the runtime is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Evaluate a PHP code string and return the output.
    ///
    /// The code should NOT include `<?php` tags — they are added automatically.
    pub fn eval_string(&mut self, code: &str) -> EmbedResult<String> {
        if !self.initialized {
            return Err(EmbedError::NotInitialized);
        }

        // Build the source with variable injection
        let mut source = String::from("<?php\n");

        // Inject variables as PHP assignments
        for (name, value) in &self.variables {
            source.push_str(&format!("${} = {};\n", name, value.to_php_literal()));
        }

        source.push_str(code);

        self.execute_source(&source)
    }

    /// Execute a PHP file and return the output.
    pub fn execute_file(&mut self, path: &str) -> EmbedResult<String> {
        if !self.initialized {
            return Err(EmbedError::NotInitialized);
        }

        let source = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                EmbedError::FileNotFound(path.to_string())
            } else {
                EmbedError::IoError(e.to_string())
            }
        })?;

        self.execute_source(&source)
    }

    /// Internal: compile and execute PHP source.
    fn execute_source(&self, source: &str) -> EmbedResult<String> {
        let op_array =
            php_rs_compiler::compile(source).map_err(|e| EmbedError::ParseError(e.to_string()))?;

        let mut vm = php_rs_vm::Vm::new();
        vm.execute(&op_array, None)
            .map_err(|e| EmbedError::RuntimeError(format!("{:?}", e)))
    }
}

impl Default for PhpEmbed {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PhpEmbed {
    fn drop(&mut self) {
        if self.initialized {
            self.shutdown();
        }
    }
}

// ── Convenience Functions ───────────────────────────────────────────────────

/// Quick eval: initialize, run code, shutdown.
pub fn php_eval(code: &str) -> EmbedResult<String> {
    let mut php = PhpEmbed::new();
    php.init()?;
    let result = php.eval_string(code);
    php.shutdown();
    result
}

/// Quick file execution: initialize, run file, shutdown.
pub fn php_exec_file(path: &str) -> EmbedResult<String> {
    let mut php = PhpEmbed::new();
    php.init()?;
    let result = php.execute_file(path);
    php.shutdown();
    result
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embed_init_shutdown() {
        let mut php = PhpEmbed::new();
        assert!(!php.is_initialized());
        php.init().unwrap();
        assert!(php.is_initialized());
        php.shutdown();
        assert!(!php.is_initialized());
    }

    #[test]
    fn test_embed_eval_string() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let output = php.eval_string("echo 'Hello!';").unwrap();
        assert_eq!(output, "Hello!");
        php.shutdown();
    }

    #[test]
    fn test_embed_eval_arithmetic() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let output = php.eval_string("echo 2 + 3;").unwrap();
        assert_eq!(output, "5");
        php.shutdown();
    }

    #[test]
    fn test_embed_not_initialized() {
        let mut php = PhpEmbed::new();
        let result = php.eval_string("echo 1;");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EmbedError::NotInitialized));
    }

    #[test]
    fn test_embed_parse_error() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let result = php.eval_string("echo (;");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EmbedError::ParseError(_)));
        php.shutdown();
    }

    #[test]
    fn test_embed_execute_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("php_rs_embed_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, "<?php echo 'From file!';").unwrap();
        drop(f);

        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let output = php.execute_file(file.to_str().unwrap()).unwrap();
        assert_eq!(output, "From file!");
        php.shutdown();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_embed_file_not_found() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let result = php.execute_file("/nonexistent/file.php");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EmbedError::FileNotFound(_)));
        php.shutdown();
    }

    #[test]
    fn test_embed_set_variable() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        php.set_variable("name", PhpValue::String("World".into()));
        let output = php.eval_string("echo 'Hello, ' . $name . '!';").unwrap();
        assert_eq!(output, "Hello, World!");
        php.shutdown();
    }

    #[test]
    fn test_embed_set_int_variable() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        php.set_variable("x", PhpValue::Int(42));
        let output = php.eval_string("echo $x * 2;").unwrap();
        assert_eq!(output, "84");
        php.shutdown();
    }

    #[test]
    fn test_embed_quick_eval() {
        let output = php_eval("echo 'quick!';").unwrap();
        assert_eq!(output, "quick!");
    }

    #[test]
    fn test_embed_quick_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("php_rs_embed_quick");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("quick.php");
        let mut f = std::fs::File::create(&file).unwrap();
        write!(f, "<?php echo 42;").unwrap();
        drop(f);

        let output = php_exec_file(file.to_str().unwrap()).unwrap();
        assert_eq!(output, "42");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_embed_drop_shuts_down() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        assert!(php.is_initialized());
        drop(php);
        // No panic = success
    }

    #[test]
    fn test_php_value_to_php_literal() {
        assert_eq!(PhpValue::Null.to_php_literal(), "null");
        assert_eq!(PhpValue::Bool(true).to_php_literal(), "true");
        assert_eq!(PhpValue::Bool(false).to_php_literal(), "false");
        assert_eq!(PhpValue::Int(42).to_php_literal(), "42");
        assert_eq!(PhpValue::Float(1.5).to_php_literal(), "1.5");
        assert_eq!(PhpValue::String("hello".into()).to_php_literal(), "'hello'");
        assert_eq!(PhpValue::String("it's".into()).to_php_literal(), "'it\\'s'");
    }

    #[test]
    fn test_php_value_display() {
        assert_eq!(format!("{}", PhpValue::Null), "");
        assert_eq!(format!("{}", PhpValue::Bool(true)), "1");
        assert_eq!(format!("{}", PhpValue::Bool(false)), "");
        assert_eq!(format!("{}", PhpValue::Int(42)), "42");
        assert_eq!(format!("{}", PhpValue::String("hello".into())), "hello");
        assert_eq!(format!("{}", PhpValue::Array(vec![])), "Array");
    }

    #[test]
    fn test_php_value_accessors() {
        assert!(PhpValue::Null.is_null());
        assert!(!PhpValue::Int(1).is_null());
        assert_eq!(PhpValue::Bool(true).as_bool(), Some(true));
        assert_eq!(PhpValue::Int(42).as_int(), Some(42));
        assert_eq!(PhpValue::Float(1.5).as_float(), Some(1.5));
        assert_eq!(PhpValue::Int(42).as_float(), Some(42.0));
        assert_eq!(PhpValue::String("hi".into()).as_str(), Some("hi"));
    }

    #[test]
    fn test_embed_ini_override() {
        let mut php = PhpEmbed::new();
        php.set_ini("display_errors", "Off");
        php.init().unwrap();
        assert!(php.is_initialized());
        php.shutdown();
    }

    #[test]
    fn test_embed_multiple_evals() {
        let mut php = PhpEmbed::new();
        php.init().unwrap();
        let out1 = php.eval_string("echo 1;").unwrap();
        let out2 = php.eval_string("echo 2;").unwrap();
        assert_eq!(out1, "1");
        assert_eq!(out2, "2");
        php.shutdown();
    }
}
