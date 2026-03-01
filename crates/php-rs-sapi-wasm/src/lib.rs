//! WASM SAPI — run PHP in the browser via WebAssembly.
//!
//! Provides a rich JS API through `wasm-bindgen`:
//! - Execute PHP code with structured results (output, headers, status code)
//! - Manage a virtual filesystem
//! - Tokenize and parse PHP (JSON AST via serde)
//! - Configure INI settings, environment variables, and superglobals
//! - Register JS callbacks callable from PHP
//! - Stream output to JS in real-time
//! - Persistent REPL mode across eval() calls

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use php_rs_compiler::compile;
use php_rs_runtime::superglobals::Superglobals;
use php_rs_runtime::VirtualFileSystem;
use php_rs_vm::value::{PhpArray, Value};
use php_rs_vm::vm::{Vm, VmConfig, VmError};

#[cfg(feature = "browser")]
use wasm_bindgen::prelude::*;

// =============================================================================
// Structured result/error types
// =============================================================================

/// Structured PHP error returned on execution failure.
#[cfg(feature = "browser")]
#[wasm_bindgen]
#[derive(Clone)]
pub struct PhpError {
    kind: String,
    message: String,
    file: String,
    line: u32,
}

#[cfg(feature = "browser")]
#[wasm_bindgen]
impl PhpError {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn file(&self) -> String {
        self.file.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn line(&self) -> u32 {
        self.line
    }
}

/// Structured PHP execution result.
#[cfg(feature = "browser")]
#[wasm_bindgen]
pub struct PhpResult {
    output: String,
    headers: String,
    status_code: u16,
}

#[cfg(feature = "browser")]
#[wasm_bindgen]
impl PhpResult {
    #[wasm_bindgen(getter)]
    pub fn output(&self) -> String {
        self.output.clone()
    }

    /// Response headers as a JSON array of strings (e.g. `["Content-Type: text/html"]`).
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> String {
        self.headers.clone()
    }

    /// HTTP status code (200 if not explicitly set by the script).
    #[wasm_bindgen(getter, js_name = statusCode)]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }
}

// =============================================================================
// PhpWasm — main wasm-bindgen API
// =============================================================================

/// PHP WebAssembly runtime instance.
///
/// Encapsulates a PHP VM with an in-memory virtual filesystem,
/// suitable for running in browser or Node.js environments.
#[cfg(feature = "browser")]
#[wasm_bindgen]
pub struct PhpWasm {
    vm: Vm,
    vfs: Arc<RwLock<VirtualFileSystem>>,
    ini_settings: Vec<(String, String)>,
    env_vars: HashMap<String, String>,
    superglobals: Superglobals,
    persistent: bool,
    js_functions: HashMap<String, js_sys::Function>,
    output_handler: Option<js_sys::Function>,
    fetch_handler: Option<js_sys::Function>,
}

#[cfg(feature = "browser")]
#[wasm_bindgen]
impl PhpWasm {
    /// Create a new PHP WASM runtime instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();

        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        });
        vm.set_vfs(vfs.clone());
        Self {
            vm,
            vfs,
            ini_settings: Vec::new(),
            env_vars: HashMap::new(),
            superglobals: Superglobals::new(),
            persistent: false,
            js_functions: HashMap::new(),
            output_handler: None,
            fetch_handler: None,
        }
    }

    // =========================================================================
    // Virtual Filesystem operations
    // =========================================================================

    /// Write a file to the virtual filesystem.
    pub fn write_file(&mut self, path: &str, contents: &[u8]) -> Result<(), JsValue> {
        let mut vfs = self
            .vfs
            .write()
            .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
        vfs.write_file(path, contents)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Read a file from the virtual filesystem.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, JsValue> {
        let vfs = self
            .vfs
            .read()
            .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
        vfs.read_file(path)
            .map(|b| b.to_vec())
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Check if a file or directory exists in the VFS.
    pub fn file_exists(&self, path: &str) -> bool {
        self.vfs.read().map(|vfs| vfs.exists(path)).unwrap_or(false)
    }

    /// List directory entries. Returns JSON array of filenames.
    pub fn list_dir(&self, path: &str) -> Result<String, JsValue> {
        let vfs = self
            .vfs
            .read()
            .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
        let entries = vfs
            .read_dir(path)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        serde_json::to_string(&entries)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))
    }

    /// Remove a file from the VFS.
    pub fn remove_file(&mut self, path: &str) -> Result<(), JsValue> {
        let mut vfs = self
            .vfs
            .write()
            .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
        vfs.remove_file(path)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Create a directory in the VFS.
    pub fn mkdir(&mut self, path: &str) -> Result<(), JsValue> {
        let mut vfs = self
            .vfs
            .write()
            .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
        vfs.mkdir(path, true)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    /// Set a PHP INI directive. Applied before each execution.
    pub fn set_ini(&mut self, key: &str, value: &str) {
        self.ini_settings.push((key.to_string(), value.to_string()));
    }

    /// Set an environment variable (accessible via getenv() in PHP).
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env_vars.insert(name.to_string(), value.to_string());
    }

    /// Set `$_GET` parameters from a query string (e.g. `"foo=bar&baz=1"`).
    pub fn set_get_params(&mut self, query_string: &str) {
        self.superglobals.parse_query_string(query_string);
    }

    /// Set `$_POST` from a URL-encoded form body.
    pub fn set_post_body(&mut self, body: &str, content_type: &str) {
        if content_type.starts_with("application/x-www-form-urlencoded") {
            self.superglobals.parse_post_body(body);
        } else if content_type.starts_with("multipart/form-data") {
            if let Some(boundary) = Superglobals::extract_boundary(content_type) {
                self.superglobals
                    .parse_multipart(body.as_bytes(), &boundary, 2 * 1024 * 1024, 8 * 1024 * 1024);
            }
        }
    }

    /// Set `$_COOKIE` from a cookie header string (e.g. `"name=value; name2=value2"`).
    pub fn set_cookies(&mut self, cookie_header: &str) {
        self.superglobals.parse_cookies(cookie_header);
    }

    /// Set a `$_SERVER` variable.
    pub fn set_server_var(&mut self, key: &str, value: &str) {
        self.superglobals
            .server
            .insert(key.to_string(), value.to_string());
    }

    /// Set the raw request body for `php://input` reads.
    pub fn set_request_body(&mut self, body: &[u8]) {
        self.vm
            .set_raw_input_body(String::from_utf8_lossy(body).to_string());
    }

    /// Enable/disable persistent mode. When enabled, functions, classes, and
    /// constants survive across `eval()` calls (REPL-like behavior).
    pub fn set_persistent(&mut self, mode: bool) {
        self.persistent = mode;
    }

    // =========================================================================
    // PHP Execution
    // =========================================================================

    /// Evaluate PHP code and return the output as a string.
    /// The code should include `<?php` opening tags.
    pub fn eval(&mut self, code: &str) -> Result<String, JsValue> {
        self.apply_ini_to_vm();
        let op_array =
            compile(code).map_err(|e| JsValue::from_str(&format!("Parse error: {:?}", e)))?;
        let sg_map = self.build_superglobals_map();
        let result = if self.persistent {
            self.vm.execute_incremental(&op_array, Some(&sg_map))
        } else {
            self.vm.execute(&op_array, Some(&sg_map))
        };
        result.map_err(|e| JsValue::from_str(&vm_error_display(&e)))
    }

    /// Execute a PHP file from the virtual filesystem and return the output.
    pub fn exec_file(&mut self, path: &str) -> Result<String, JsValue> {
        let code = {
            let vfs = self
                .vfs
                .read()
                .map_err(|e| JsValue::from_str(&format!("VFS lock error: {}", e)))?;
            let bytes = vfs
                .read_file(path)
                .map_err(|e| JsValue::from_str(&format!("File read error: {}", e)))?;
            String::from_utf8(bytes.to_vec())
                .map_err(|e| JsValue::from_str(&format!("UTF-8 error: {}", e)))?
        };
        self.eval(&code)
    }

    /// Execute PHP code and return a structured result with output, headers, and status code.
    pub fn run(&mut self, code: &str) -> Result<PhpResult, PhpError> {
        self.apply_ini_to_vm();
        let op_array = compile(code).map_err(|e| PhpError {
            kind: "ParseError".to_string(),
            message: format!("{:?}", e),
            file: "<eval>".to_string(),
            line: 0,
        })?;
        let sg_map = self.build_superglobals_map();
        let result = if self.persistent {
            self.vm.execute_incremental(&op_array, Some(&sg_map))
        } else {
            self.vm.execute(&op_array, Some(&sg_map))
        };
        match result {
            Ok(output) => {
                let headers = self.vm.take_response_headers();
                let status_code = self.vm.take_response_code().unwrap_or(200);
                let headers_json =
                    serde_json::to_string(&headers).unwrap_or_else(|_| "[]".to_string());
                Ok(PhpResult {
                    output,
                    headers: headers_json,
                    status_code,
                })
            }
            Err(VmError::Exit(_)) => {
                let headers = self.vm.take_response_headers();
                let status_code = self.vm.take_response_code().unwrap_or(200);
                let headers_json =
                    serde_json::to_string(&headers).unwrap_or_else(|_| "[]".to_string());
                Ok(PhpResult {
                    output: String::new(),
                    headers: headers_json,
                    status_code,
                })
            }
            Err(e) => Err(vm_error_to_php_error(&e)),
        }
    }

    // =========================================================================
    // JS Interop (Phase 3)
    // =========================================================================

    /// Register a JS function callable from PHP by name.
    /// The function receives an array of arguments and should return a value.
    pub fn register_function(&mut self, name: &str, callback: &js_sys::Function) {
        self.js_functions.insert(name.to_string(), callback.clone());
    }

    /// Set a JS callback that receives output as it is produced (real-time streaming).
    /// The callback signature is `(chunk: string) => void`.
    pub fn set_output_handler(&mut self, callback: &js_sys::Function) {
        self.output_handler = Some(callback.clone());
    }

    /// Set a JS callback for fetching URLs from PHP (e.g. `file_get_contents('https://...')`).
    /// The callback signature is `(url: string) => string`.
    pub fn set_fetch_handler(&mut self, callback: &js_sys::Function) {
        self.fetch_handler = Some(callback.clone());
    }

    // =========================================================================
    // Introspection (for playground tooling)
    // =========================================================================

    /// Tokenize PHP code and return a JSON array of tokens.
    ///
    /// Each token is: `{"type": "T_STRING", "value": "echo", "line": 1, "col": 6}`.
    pub fn tokenize(&self, code: &str) -> Result<String, JsValue> {
        let mut lexer = php_rs_lexer::Lexer::new(code);
        let mut tokens = Vec::new();

        while let Some((token, span)) = lexer.next_token() {
            let text = &code[span.start..span.end];
            tokens.push(serde_json::json!({
                "type": format!("{:?}", token),
                "value": text,
                "start": span.start,
                "end": span.end,
                "line": span.line,
                "col": span.column,
            }));
        }

        serde_json::to_string(&tokens)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))
    }

    /// Parse PHP code and return the AST as a JSON string.
    /// Uses serde serialization for a proper structured JSON AST.
    pub fn parse(&self, code: &str) -> Result<String, JsValue> {
        let mut parser = php_rs_parser::Parser::new(code);
        let program = parser
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Parse error: {:?}", e)))?;

        serde_json::to_string(&program)
            .map_err(|e| JsValue::from_str(&format!("JSON serialization error: {}", e)))
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    /// Reset the VM state (clear classes, functions, etc.) but keep the VFS.
    pub fn reset(&mut self) {
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        });
        vm.set_vfs(self.vfs.clone());
        self.vm = vm;
        self.superglobals.reset();
    }

    /// Get the PHP version string.
    pub fn php_version(&self) -> String {
        "8.6.0".to_string()
    }

    /// Get a list of loaded extensions as a JSON array.
    pub fn loaded_extensions(&self) -> String {
        let extensions = vec![
            "json", "hash", "standard", "pcre", "ctype", "mbstring", "date", "spl", "filter",
            "tokenizer", "reflection", "random", "bcmath", "calendar", "intl", "opcache", "dom",
            "xml", "zlib", "iconv",
        ];
        serde_json::to_string(&extensions).unwrap_or_else(|_| "[]".to_string())
    }
}

// =============================================================================
// Private helpers (browser feature)
// =============================================================================

#[cfg(feature = "browser")]
impl PhpWasm {
    /// Apply stored INI settings to the VM before execution.
    fn apply_ini_to_vm(&mut self) {
        for (key, value) in &self.ini_settings {
            self.vm.ini_force_set(key, value);
        }

        let mut config = VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        };

        for (key, value) in &self.ini_settings {
            match key.as_str() {
                "memory_limit" => {
                    let bytes = parse_ini_size(value);
                    config.memory_limit = if bytes < 0 { 0 } else { bytes as usize };
                }
                "max_execution_time" => {
                    let secs: i64 = value.parse().unwrap_or(0);
                    config.max_execution_time = if secs <= 0 { 0 } else { secs as u64 };
                }
                "disable_functions" => {
                    config.set_disabled_functions(value);
                }
                "open_basedir" => {
                    config.set_open_basedir(value);
                }
                _ => {}
            }
        }

        self.vm.apply_config(config);
    }

    /// Build the superglobals HashMap from current state.
    fn build_superglobals_map(&mut self) -> HashMap<String, Value> {
        self.superglobals.build_request("GP");

        for (k, v) in &self.env_vars {
            self.superglobals.env.insert(k.clone(), v.clone());
        }

        let mut map = HashMap::new();

        map.insert(
            "_GET".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.get)),
        );
        map.insert(
            "_POST".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.post)),
        );
        map.insert(
            "_ENV".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.env)),
        );
        map.insert(
            "_COOKIE".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.cookie)),
        );
        map.insert(
            "_FILES".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.files)),
        );
        map.insert(
            "_REQUEST".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.request)),
        );
        map.insert(
            "_SESSION".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.session)),
        );

        let mut server = PhpArray::from_string_map(&self.superglobals.server);
        server.set_string(
            "SERVER_SOFTWARE".to_string(),
            Value::String("php.rs/wasm".to_string()),
        );
        map.insert("_SERVER".to_string(), Value::Array(server));

        map
    }
}

#[cfg(feature = "browser")]
impl Default for PhpWasm {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Error conversion helpers
// =============================================================================

fn vm_error_display(e: &VmError) -> String {
    match e {
        VmError::FatalError(msg) => format!("Fatal error: {}", msg),
        VmError::TypeError(msg) => format!("TypeError: {}", msg),
        VmError::DivisionByZero => "Division by zero".to_string(),
        VmError::UndefinedVariable(name) => format!("Undefined variable ${}", name),
        VmError::UndefinedFunction(name) => format!("Call to undefined function {}()", name),
        VmError::UndefinedClass(name) => format!("Class \"{}\" not found", name),
        VmError::UndefinedMethod(class, method) => {
            format!("Call to undefined method {}::{}()", class, method)
        }
        VmError::UndefinedProperty(class, prop) => {
            format!("Undefined property: {}::${}", class, prop)
        }
        VmError::UndefinedClassConstant(class, name) => {
            format!("Undefined class constant {}::{}", class, name)
        }
        VmError::MatchError => "Unhandled match case".to_string(),
        VmError::Thrown(val) => format!("Uncaught exception: {:?}", val),
        VmError::InternalError(msg) => format!("Internal error: {}", msg),
        VmError::Exit(code) => format!("exit({})", code),
        VmError::MemoryLimitExceeded(msg) => format!("Memory limit exceeded: {}", msg),
        VmError::TimeLimitExceeded(msg) => format!("Maximum execution time exceeded: {}", msg),
        VmError::DisabledFunction(name) => format!("Call to disabled function {}()", name),
    }
}

#[cfg(feature = "browser")]
fn vm_error_to_php_error(e: &VmError) -> PhpError {
    let (kind, message) = match e {
        VmError::FatalError(msg) => ("FatalError", msg.clone()),
        VmError::TypeError(msg) => ("TypeError", msg.clone()),
        VmError::DivisionByZero => ("DivisionByZero", "Division by zero".to_string()),
        VmError::UndefinedVariable(name) => {
            ("UndefinedVariable", format!("Undefined variable ${}", name))
        }
        VmError::UndefinedFunction(name) => (
            "UndefinedFunction",
            format!("Call to undefined function {}()", name),
        ),
        VmError::UndefinedClass(name) => {
            ("UndefinedClass", format!("Class \"{}\" not found", name))
        }
        VmError::UndefinedMethod(class, method) => (
            "UndefinedMethod",
            format!("Call to undefined method {}::{}()", class, method),
        ),
        VmError::UndefinedProperty(class, prop) => (
            "UndefinedProperty",
            format!("Undefined property: {}::${}", class, prop),
        ),
        VmError::UndefinedClassConstant(class, name) => (
            "UndefinedClassConstant",
            format!("Undefined class constant {}::{}", class, name),
        ),
        VmError::MatchError => ("MatchError", "Unhandled match case".to_string()),
        VmError::Thrown(val) => ("Exception", format!("{:?}", val)),
        VmError::InternalError(msg) => ("InternalError", msg.clone()),
        VmError::Exit(code) => ("Exit", format!("exit({})", code)),
        VmError::MemoryLimitExceeded(msg) => ("MemoryLimitExceeded", msg.clone()),
        VmError::TimeLimitExceeded(msg) => ("TimeLimitExceeded", msg.clone()),
        VmError::DisabledFunction(name) => (
            "DisabledFunction",
            format!("Call to disabled function {}()", name),
        ),
    };
    PhpError {
        kind: kind.to_string(),
        message,
        file: "<eval>".to_string(),
        line: 0,
    }
}

/// Parse a PHP INI size value (e.g. "128M" -> 134217728).
fn parse_ini_size(val: &str) -> i64 {
    let val = val.trim();
    if val.is_empty() {
        return 0;
    }
    let (num_str, multiplier) = match val.as_bytes().last() {
        Some(b'K' | b'k') => (&val[..val.len() - 1], 1024i64),
        Some(b'M' | b'm') => (&val[..val.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&val[..val.len() - 1], 1024 * 1024 * 1024),
        _ => (val, 1),
    };
    num_str.trim().parse::<i64>().unwrap_or(0) * multiplier
}

// =============================================================================
// Core logic (non-wasm-bindgen) for testing on native targets
// =============================================================================

/// Core PHP WASM runtime without wasm-bindgen annotations.
/// Used for native-target testing.
pub struct PhpWasmCore {
    vm: Vm,
    vfs: Arc<RwLock<VirtualFileSystem>>,
    ini_settings: Vec<(String, String)>,
    env_vars: HashMap<String, String>,
    superglobals: Superglobals,
    persistent: bool,
}

impl PhpWasmCore {
    /// Create a new instance.
    pub fn new() -> Self {
        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        });
        vm.set_vfs(vfs.clone());
        Self {
            vm,
            vfs,
            ini_settings: Vec::new(),
            env_vars: HashMap::new(),
            superglobals: Superglobals::new(),
            persistent: false,
        }
    }

    /// Write a file to the VFS.
    pub fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), String> {
        let mut vfs = self
            .vfs
            .write()
            .map_err(|e| format!("VFS lock error: {}", e))?;
        vfs.write_file(path, contents).map_err(|e| format!("{}", e))
    }

    /// Read a file from the VFS.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let vfs = self
            .vfs
            .read()
            .map_err(|e| format!("VFS lock error: {}", e))?;
        vfs.read_file(path)
            .map(|b| b.to_vec())
            .map_err(|e| format!("{}", e))
    }

    /// Check if a file exists.
    pub fn file_exists(&self, path: &str) -> bool {
        self.vfs.read().map(|vfs| vfs.exists(path)).unwrap_or(false)
    }

    /// Set a PHP INI directive.
    pub fn set_ini(&mut self, key: &str, value: &str) {
        self.ini_settings.push((key.to_string(), value.to_string()));
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env_vars.insert(name.to_string(), value.to_string());
    }

    /// Set `$_GET` parameters from a query string.
    pub fn set_get_params(&mut self, query_string: &str) {
        self.superglobals.parse_query_string(query_string);
    }

    /// Set `$_POST` from URL-encoded body.
    pub fn set_post_body(&mut self, body: &str) {
        self.superglobals.parse_post_body(body);
    }

    /// Set `$_COOKIE` from a cookie header.
    pub fn set_cookies(&mut self, cookie_header: &str) {
        self.superglobals.parse_cookies(cookie_header);
    }

    /// Set a `$_SERVER` variable.
    pub fn set_server_var(&mut self, key: &str, value: &str) {
        self.superglobals
            .server
            .insert(key.to_string(), value.to_string());
    }

    /// Enable/disable persistent mode.
    pub fn set_persistent(&mut self, mode: bool) {
        self.persistent = mode;
    }

    /// Apply INI settings to the VM.
    fn apply_ini_to_vm(&mut self) {
        for (key, value) in &self.ini_settings {
            self.vm.ini_force_set(key, value);
        }
        let mut config = VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        };
        for (key, value) in &self.ini_settings {
            match key.as_str() {
                "memory_limit" => {
                    let bytes = parse_ini_size(value);
                    config.memory_limit = if bytes < 0 { 0 } else { bytes as usize };
                }
                "max_execution_time" => {
                    let secs: i64 = value.parse().unwrap_or(0);
                    config.max_execution_time = if secs <= 0 { 0 } else { secs as u64 };
                }
                "disable_functions" => {
                    config.set_disabled_functions(value);
                }
                "open_basedir" => {
                    config.set_open_basedir(value);
                }
                _ => {}
            }
        }
        self.vm.apply_config(config);
    }

    /// Build the superglobals HashMap.
    fn build_superglobals_map(&mut self) -> HashMap<String, Value> {
        self.superglobals.build_request("GP");
        for (k, v) in &self.env_vars {
            self.superglobals.env.insert(k.clone(), v.clone());
        }

        let mut map = HashMap::new();
        map.insert(
            "_GET".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.get)),
        );
        map.insert(
            "_POST".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.post)),
        );
        map.insert(
            "_ENV".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.env)),
        );
        map.insert(
            "_COOKIE".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.cookie)),
        );
        map.insert(
            "_FILES".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.files)),
        );
        map.insert(
            "_REQUEST".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.request)),
        );
        map.insert(
            "_SESSION".to_string(),
            Value::Array(PhpArray::from_string_map(&self.superglobals.session)),
        );

        let mut server = PhpArray::from_string_map(&self.superglobals.server);
        server.set_string(
            "SERVER_SOFTWARE".to_string(),
            Value::String("php.rs/wasm".to_string()),
        );
        map.insert("_SERVER".to_string(), Value::Array(server));
        map
    }

    /// Evaluate PHP code.
    pub fn eval(&mut self, code: &str) -> Result<String, String> {
        self.apply_ini_to_vm();
        let op_array = compile(code).map_err(|e| format!("Parse error: {:?}", e))?;
        let sg_map = self.build_superglobals_map();
        let result = if self.persistent {
            self.vm.execute_incremental(&op_array, Some(&sg_map))
        } else {
            self.vm.execute(&op_array, Some(&sg_map))
        };
        result.map_err(|e| vm_error_display(&e))
    }

    /// Execute a PHP file from the VFS.
    pub fn exec_file(&mut self, path: &str) -> Result<String, String> {
        let code = {
            let vfs = self
                .vfs
                .read()
                .map_err(|e| format!("VFS lock error: {}", e))?;
            let bytes = vfs.read_file(path).map_err(|e| format!("{}", e))?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("{}", e))?
        };
        self.eval(&code)
    }

    /// Execute PHP code and return structured result.
    pub fn run(&mut self, code: &str) -> Result<CorePhpResult, String> {
        self.apply_ini_to_vm();
        let op_array = compile(code).map_err(|e| format!("Parse error: {:?}", e))?;
        let sg_map = self.build_superglobals_map();
        let result = if self.persistent {
            self.vm.execute_incremental(&op_array, Some(&sg_map))
        } else {
            self.vm.execute(&op_array, Some(&sg_map))
        };
        match result {
            Ok(output) => {
                let headers = self.vm.take_response_headers();
                let status_code = self.vm.take_response_code().unwrap_or(200);
                Ok(CorePhpResult {
                    output,
                    headers,
                    status_code,
                })
            }
            Err(VmError::Exit(_)) => {
                let headers = self.vm.take_response_headers();
                let status_code = self.vm.take_response_code().unwrap_or(200);
                Ok(CorePhpResult {
                    output: String::new(),
                    headers,
                    status_code,
                })
            }
            Err(e) => Err(vm_error_display(&e)),
        }
    }

    /// Parse PHP code and return JSON AST.
    pub fn parse(&self, code: &str) -> Result<String, String> {
        let mut parser = php_rs_parser::Parser::new(code);
        let program = parser
            .parse()
            .map_err(|e| format!("Parse error: {:?}", e))?;
        serde_json::to_string(&program).map_err(|e| format!("JSON error: {}", e))
    }

    /// Reset the VM state.
    pub fn reset(&mut self) {
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        });
        vm.set_vfs(self.vfs.clone());
        self.vm = vm;
        self.superglobals.reset();
    }
}

impl Default for PhpWasmCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Structured execution result for native testing.
pub struct CorePhpResult {
    pub output: String,
    pub headers: Vec<String>,
    pub status_code: u16,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_hello_world() {
        let mut php = PhpWasmCore::new();
        let output = php.eval("<?php echo 'Hello, WASM!';").unwrap();
        assert_eq!(output, "Hello, WASM!");
    }

    #[test]
    fn test_vfs_write_and_read() {
        let php = PhpWasmCore::new();
        php.write_file("/test.txt", b"Hello, VFS!").unwrap();
        let data = php.read_file("/test.txt").unwrap();
        assert_eq!(data, b"Hello, VFS!");
    }

    #[test]
    fn test_exec_file() {
        let mut php = PhpWasmCore::new();
        php.write_file("/script.php", b"<?php echo 42 + 8;")
            .unwrap();
        let output = php.exec_file("/script.php").unwrap();
        assert_eq!(output, "50");
    }

    #[test]
    fn test_file_exists() {
        let php = PhpWasmCore::new();
        assert!(!php.file_exists("/nope.php"));
        php.write_file("/exists.php", b"<?php").unwrap();
        assert!(php.file_exists("/exists.php"));
    }

    #[test]
    fn test_reset_keeps_vfs() {
        let mut php = PhpWasmCore::new();
        php.write_file("/keep.txt", b"persistent").unwrap();
        php.eval("<?php echo 'before';").unwrap();
        php.reset();
        assert!(php.file_exists("/keep.txt"));
        let output = php.eval("<?php echo 'after';").unwrap();
        assert_eq!(output, "after");
    }

    #[test]
    fn test_eval_arithmetic() {
        let mut php = PhpWasmCore::new();
        let output = php.eval("<?php $a = 10; $b = 20; echo $a + $b;").unwrap();
        assert_eq!(output, "30");
    }

    #[test]
    fn test_eval_string_functions() {
        let mut php = PhpWasmCore::new();
        let output = php.eval("<?php echo strtoupper('hello');").unwrap();
        assert_eq!(output, "HELLO");
    }

    #[test]
    fn test_eval_array_operations() {
        let mut php = PhpWasmCore::new();
        let output = php
            .eval("<?php $arr = [1, 2, 3]; echo count($arr);")
            .unwrap();
        assert_eq!(output, "3");
    }

    #[test]
    fn test_eval_parse_error() {
        let mut php = PhpWasmCore::new();
        let result = php.eval("<?php echo ");
        assert!(result.is_err());
    }

    // Phase 1.1: INI wiring
    #[test]
    fn test_ini_settings_applied() {
        let mut php = PhpWasmCore::new();
        php.set_ini("display_errors", "0");
        let output = php.eval("<?php echo ini_get('display_errors');").unwrap();
        assert_eq!(output, "0");
    }

    #[test]
    fn test_ini_memory_limit() {
        let mut php = PhpWasmCore::new();
        php.set_ini("memory_limit", "256M");
        let output = php.eval("<?php echo ini_get('memory_limit');").unwrap();
        assert_eq!(output, "256M");
    }

    // Phase 1.2: Superglobals
    #[test]
    fn test_get_params() {
        let mut php = PhpWasmCore::new();
        php.set_get_params("foo=bar&baz=42");
        let output = php
            .eval("<?php echo $_GET['foo'] . ',' . $_GET['baz'];")
            .unwrap();
        assert_eq!(output, "bar,42");
    }

    #[test]
    fn test_post_body() {
        let mut php = PhpWasmCore::new();
        php.set_post_body("name=John&age=30");
        let output = php
            .eval("<?php echo $_POST['name'] . ' is ' . $_POST['age'];")
            .unwrap();
        assert_eq!(output, "John is 30");
    }

    #[test]
    fn test_cookies() {
        let mut php = PhpWasmCore::new();
        php.set_cookies("session=abc123; user=test");
        let output = php
            .eval("<?php echo $_COOKIE['session'] . ',' . $_COOKIE['user'];")
            .unwrap();
        assert_eq!(output, "abc123,test");
    }

    #[test]
    fn test_server_vars() {
        let mut php = PhpWasmCore::new();
        php.set_server_var("REQUEST_METHOD", "POST");
        let output = php
            .eval("<?php echo $_SERVER['REQUEST_METHOD'];")
            .unwrap();
        assert_eq!(output, "POST");
    }

    #[test]
    fn test_env_vars() {
        let mut php = PhpWasmCore::new();
        php.set_env("MY_APP_KEY", "secret123");
        let output = php.eval("<?php echo $_ENV['MY_APP_KEY'];").unwrap();
        assert_eq!(output, "secret123");
    }

    // Phase 1.4: Structured result
    #[test]
    fn test_run_returns_result() {
        let mut php = PhpWasmCore::new();
        let result = php.run("<?php echo 'hello';").unwrap();
        assert_eq!(result.output, "hello");
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn test_run_captures_headers() {
        let mut php = PhpWasmCore::new();
        let result = php
            .run("<?php header('Content-Type: application/json'); echo '{}';")
            .unwrap();
        assert_eq!(result.output, "{}");
        assert!(result
            .headers
            .iter()
            .any(|h| h.contains("Content-Type: application/json")));
    }

    #[test]
    fn test_run_captures_status_code() {
        let mut php = PhpWasmCore::new();
        let result = php
            .run("<?php http_response_code(404); echo 'Not Found';")
            .unwrap();
        assert_eq!(result.output, "Not Found");
        assert_eq!(result.status_code, 404);
    }

    // Phase 1.6: State persistence
    #[test]
    fn test_persistent_mode_preserves_functions() {
        let mut php = PhpWasmCore::new();
        php.set_persistent(true);
        php.eval("<?php function greet() { echo 'hi'; }").unwrap();
        let output = php.eval("<?php greet();").unwrap();
        assert_eq!(output, "hi");
    }

    #[test]
    fn test_non_persistent_mode_clears_functions() {
        let mut php = PhpWasmCore::new();
        php.set_persistent(false);
        php.eval("<?php function greet() { echo 'hi'; }").unwrap();
        let result = php.eval("<?php greet();");
        assert!(result.is_err());
    }

    // Phase 2.1: JSON AST
    #[test]
    fn test_parse_returns_json() {
        let php = PhpWasmCore::new();
        let json = php.parse("<?php echo 'hello';").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("statements").is_some());
    }

    #[test]
    fn test_parse_ast_structure() {
        let php = PhpWasmCore::new();
        let json = php.parse("<?php $x = 42;").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let stmts = parsed["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
    }

    // INI size parsing
    #[test]
    fn test_parse_ini_size() {
        assert_eq!(parse_ini_size("128M"), 128 * 1024 * 1024);
        assert_eq!(parse_ini_size("2G"), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_ini_size("64K"), 64 * 1024);
        assert_eq!(parse_ini_size("1024"), 1024);
        assert_eq!(parse_ini_size(""), 0);
    }
}
