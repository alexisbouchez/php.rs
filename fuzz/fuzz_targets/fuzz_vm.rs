#![no_main]
//! Fuzz target for the full pipeline: lex → parse → compile → execute.
//!
//! Compiles arbitrary PHP and executes it in the VM with tight limits to
//! prevent infinite loops and OOM. The VM must never panic.
//!
//! Run: cargo +nightly fuzz run fuzz_vm

use libfuzzer_sys::fuzz_target;
use php_rs_vm::{Vm, VmConfig};

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let source = format!("<?php {}", input);
        if let Ok(op_array) = php_rs_compiler::compile(&source) {
            // Run with tight limits to avoid hangs
            let mut config = VmConfig::default();
            config.max_execution_time = 1; // 1 second timeout
            config.memory_limit = 4 * 1024 * 1024; // 4 MB limit

            let mut vm = Vm::with_config(config);
            // Execution may succeed, error, or hit limits — all fine, just don't panic.
            let _ = vm.execute(&op_array, None);
        }
    }
});
