//! WASI entry point — run PHP scripts via `wasm32-wasi` runtimes
//! (Wasmtime, WasmEdge, Wasmer, etc.).
//!
//! Usage:
//!   cargo build --target wasm32-wasi -p php-rs-sapi-wasm --features wasi --no-default-features
//!   wasmtime target/wasm32-wasi/release/php-rs-wasi.wasm -- script.php
//!   echo '<?php echo "hi";' | wasmtime target/wasm32-wasi/release/php-rs-wasi.wasm -- -

use std::env;
use std::io::{self, Read};

use php_rs_compiler::compile;
use php_rs_vm::vm::{Vm, VmConfig};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: php-rs-wasi <file.php | -r 'code' | ->");
        eprintln!("  file.php    Execute a PHP file");
        eprintln!("  -r 'code'  Run inline PHP code");
        eprintln!("  -          Read PHP from stdin");
        std::process::exit(1);
    }

    let code = match args[1].as_str() {
        "-r" => {
            if args.len() < 3 {
                eprintln!("Error: -r requires a code argument");
                std::process::exit(1);
            }
            // -r mode: wrap in <?php
            format!("<?php {}", args[2])
        }
        "-" => {
            // Read from stdin
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .expect("Failed to read stdin");
            buf
        }
        path => {
            // Read from WASI filesystem
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {}", path, e);
                std::process::exit(1);
            })
        }
    };

    let op_array = match compile(&code) {
        Ok(ops) => ops,
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            std::process::exit(255);
        }
    };

    let mut vm = Vm::with_config(VmConfig {
        max_execution_time: 0,
        ..VmConfig::default()
    });

    match vm.execute(&op_array, None) {
        Ok(output) => {
            print!("{}", output);
        }
        Err(e) => {
            eprintln!("{}", super_display(&e));
            std::process::exit(255);
        }
    }
}

fn super_display(e: &php_rs_vm::vm::VmError) -> String {
    use php_rs_vm::vm::VmError;
    match e {
        VmError::FatalError(msg) => format!("Fatal error: {}", msg),
        VmError::TypeError(msg) => format!("TypeError: {}", msg),
        VmError::DivisionByZero => "Division by zero".to_string(),
        VmError::UndefinedVariable(name) => format!("Undefined variable ${}", name),
        VmError::UndefinedFunction(name) => format!("Call to undefined function {}()", name),
        VmError::UndefinedClass(name) => format!("Class \"{}\" not found", name),
        VmError::UndefinedMethod(c, m) => format!("Call to undefined method {}::{}()", c, m),
        VmError::UndefinedProperty(c, p) => format!("Undefined property: {}::${}", c, p),
        VmError::UndefinedClassConstant(c, n) => {
            format!("Undefined class constant {}::{}", c, n)
        }
        VmError::MatchError => "Unhandled match case".to_string(),
        VmError::Thrown(val) => format!("Uncaught exception: {:?}", val),
        VmError::InternalError(msg) => format!("Internal error: {}", msg),
        VmError::Exit(code) => std::process::exit(*code as i32),
        VmError::MemoryLimitExceeded(msg) => format!("Memory limit exceeded: {}", msg),
        VmError::TimeLimitExceeded(msg) => format!("Maximum execution time exceeded: {}", msg),
        VmError::DisabledFunction(name) => format!("Call to disabled function {}()", name),
    }
}
