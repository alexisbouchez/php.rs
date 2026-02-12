#![no_main]
//! Fuzz target for the PHP lexer.
//!
//! Feeds arbitrary byte sequences to the tokenizer. The lexer must never panic
//! or enter an infinite loop — it should either produce tokens or return errors.
//!
//! Run: cargo +nightly fuzz run fuzz_lexer

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let source = format!("<?php {}", input);
        let mut lexer = php_rs_lexer::Lexer::new(&source);
        // Drain all tokens — lexer must not panic
        while let Some((_token, _span)) = lexer.next_token() {}
    }
});
