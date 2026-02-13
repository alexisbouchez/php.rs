#![no_main]
//! Fuzz target for the PHP parser.
//!
//! Parses arbitrary PHP input. The parser must never panic — it should either
//! produce an AST or return a parse error.
//!
//! Run: cargo +nightly fuzz run fuzz_parser

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let source = format!("<?php {}", input);
        let mut parser = php_rs_parser::Parser::new(&source);
        // Parsing must not panic
        let _ = parser.parse();
    }
});
