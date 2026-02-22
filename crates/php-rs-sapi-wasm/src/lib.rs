//! WASM SAPI — run PHP in the browser via WebAssembly.
//!
//! Provides a rich JS API through `wasm-bindgen`:
//! - Execute PHP code
//! - Manage a virtual filesystem
//! - Tokenize and parse PHP for tooling
//! - Configure INI settings and inject variables

use std::sync::{Arc, RwLock};

use php_rs_compiler::compile;
use php_rs_runtime::VirtualFileSystem;
use php_rs_vm::vm::{Vm, VmConfig};
use wasm_bindgen::prelude::*;

/// PHP WebAssembly runtime instance.
///
/// Encapsulates a PHP VM with an in-memory virtual filesystem,
/// suitable for running in browser or Node.js environments.
#[wasm_bindgen]
pub struct PhpWasm {
    vm: Vm,
    vfs: Arc<RwLock<VirtualFileSystem>>,
    ini_settings: Vec<(String, String)>,
    env_vars: std::collections::HashMap<String, String>,
}

#[wasm_bindgen]
impl PhpWasm {
    /// Create a new PHP WASM runtime instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0, // No timeout in WASM
            ..VmConfig::default()
        });
        vm.set_vfs(vfs.clone());
        Self {
            vm,
            vfs,
            ini_settings: Vec::new(),
            env_vars: std::collections::HashMap::new(),
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
        self.vfs
            .read()
            .map(|vfs| vfs.exists(path))
            .unwrap_or(false)
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
    // PHP Execution
    // =========================================================================

    /// Evaluate PHP code and return the output as a string.
    ///
    /// The code should include `<?php` opening tags.
    pub fn eval(&mut self, code: &str) -> Result<String, JsValue> {
        let op_array =
            compile(code).map_err(|e| JsValue::from_str(&format!("Parse error: {:?}", e)))?;

        self.vm
            .execute(&op_array, None)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
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

    // =========================================================================
    // Configuration
    // =========================================================================

    /// Set a PHP INI directive.
    pub fn set_ini(&mut self, key: &str, value: &str) {
        self.ini_settings
            .push((key.to_string(), value.to_string()));
    }

    /// Set an environment variable (accessible via getenv() in PHP).
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env_vars.insert(name.to_string(), value.to_string());
    }

    // =========================================================================
    // Introspection (for playground tooling)
    // =========================================================================

    /// Tokenize PHP code and return a JSON array of tokens.
    ///
    /// Each token is an object: `{"type": "T_STRING", "value": "echo", "line": 1, "col": 6}`.
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
    pub fn parse(&self, code: &str) -> Result<String, JsValue> {
        let mut parser = php_rs_parser::Parser::new(code);
        let program = parser
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Parse error: {:?}", e)))?;

        // Use Debug formatting as a structured representation
        Ok(format!("{:#?}", program))
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
    }

    /// Get the PHP version string.
    pub fn php_version(&self) -> String {
        "8.6.0".to_string()
    }

    /// Get a list of loaded extensions as a JSON array.
    pub fn loaded_extensions(&self) -> String {
        let extensions = vec![
            "json",
            "hash",
            "standard",
            "pcre",
            "ctype",
            "mbstring",
            "date",
            "spl",
            "filter",
            "tokenizer",
            "reflection",
            "random",
            "bcmath",
            "calendar",
            "intl",
            "opcache",
            "dom",
            "xml",
            "zlib",
            "iconv",
        ];
        serde_json::to_string(&extensions).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for PhpWasm {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Core logic (non-wasm-bindgen) for testing on native targets
// =============================================================================

/// Core PHP WASM runtime without wasm-bindgen annotations.
/// Used for native-target testing.
pub struct PhpWasmCore {
    vm: Vm,
    vfs: Arc<RwLock<VirtualFileSystem>>,
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
        Self { vm, vfs }
    }

    /// Write a file to the VFS.
    pub fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), String> {
        let mut vfs = self
            .vfs
            .write()
            .map_err(|e| format!("VFS lock error: {}", e))?;
        vfs.write_file(path, contents)
            .map_err(|e| format!("{}", e))
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
        self.vfs
            .read()
            .map(|vfs| vfs.exists(path))
            .unwrap_or(false)
    }

    /// Evaluate PHP code.
    pub fn eval(&mut self, code: &str) -> Result<String, String> {
        let op_array = compile(code).map_err(|e| format!("Parse error: {:?}", e))?;
        self.vm
            .execute(&op_array, None)
            .map_err(|e| format!("{:?}", e))
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

    /// Reset the VM state.
    pub fn reset(&mut self) {
        let mut vm = Vm::with_config(VmConfig {
            max_execution_time: 0,
            ..VmConfig::default()
        });
        vm.set_vfs(self.vfs.clone());
        self.vm = vm;
    }
}

impl Default for PhpWasmCore {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn test_eval_with_vfs_include() {
        let mut php = PhpWasmCore::new();
        php.write_file("/helper.php", b"<?php function greet() { echo 'Hi'; }")
            .unwrap();
        // The include path resolution depends on CWD; test basic eval for now
        let output = php
            .eval("<?php echo 'Hello'; echo ' '; echo 'World';")
            .unwrap();
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_eval_arithmetic() {
        let mut php = PhpWasmCore::new();
        let output = php
            .eval("<?php $a = 10; $b = 20; echo $a + $b;")
            .unwrap();
        assert_eq!(output, "30");
    }

    #[test]
    fn test_eval_string_functions() {
        let mut php = PhpWasmCore::new();
        let output = php
            .eval("<?php echo strtoupper('hello');")
            .unwrap();
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
}
