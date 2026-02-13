#![no_main]
//! Fuzz target for the full compilation pipeline (lex → parse → compile).
//!
//! The compiler must never panic on any syntactically valid or invalid input.
//!
//! Run: cargo +nightly fuzz run fuzz_compiler

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let source = format!("<?php {}", input);
        let _ = php_rs_compiler::compile(&source);
    }
});
