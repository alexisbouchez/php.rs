//! Integration test: parse --FILE-- sections from php-src/tests/lang/*.phpt
//!
//! This test validates that our parser can handle all language constructs
//! found in the PHP reference test suite.

use php_rs_parser::Parser;
use std::fs;
use std::path::Path;

/// Extract the --FILE-- section from a .phpt file
fn extract_file_section(content: &str) -> Option<String> {
    let mut in_file_section = false;
    let mut file_content = String::new();

    for line in content.lines() {
        if line.starts_with("--FILE--") {
            in_file_section = true;
            continue;
        }
        if in_file_section && line.starts_with("--") && line.ends_with("--") {
            // Hit the next section
            break;
        }
        if in_file_section {
            if !file_content.is_empty() {
                file_content.push('\n');
            }
            file_content.push_str(line);
        }
    }

    if file_content.is_empty() {
        None
    } else {
        Some(file_content)
    }
}

/// Files known to use constructs we intentionally don't parse yet,
/// or that contain intentional parse errors for testing PHP error handling.
fn is_known_skip(filename: &str) -> bool {
    matches!(
        filename,
        // Cross-tag brace interleaving: <?php if (1) { ?>#<?php } ?>
        // Requires tracking brace depth across PHP/HTML transitions
        "bug44654.phpt"
        // Invalid octal literal: $x = 08; (lexer returns two tokens for "0" and "8")
        | "invalid_octal.phpt"
    )
}

#[test]
fn test_parse_all_phpt_lang_file_sections() {
    let lang_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("php-src/tests/lang");

    if !lang_dir.exists() {
        eprintln!(
            "Skipping test: php-src/tests/lang/ not found at {:?}",
            lang_dir
        );
        return;
    }

    let mut total = 0;
    let mut passed = 0;
    let mut skipped = 0;
    let mut failures: Vec<(String, String)> = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(&lang_dir)
        .expect("Failed to read lang directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "phpt"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        total += 1;

        if is_known_skip(&filename) {
            skipped += 1;
            continue;
        }

        let content = fs::read_to_string(&path).expect("Failed to read phpt file");
        let file_section = match extract_file_section(&content) {
            Some(s) => s,
            None => {
                skipped += 1;
                continue;
            }
        };

        let mut parser = Parser::new(&file_section);
        match parser.parse() {
            Ok(_) => {
                passed += 1;
            }
            Err(e) => {
                failures.push((filename, format!("{:?}", e)));
            }
        }
    }

    let failed = failures.len();

    eprintln!("\n=== PHPT Lang Parse Results ===");
    eprintln!("Total:   {}", total);
    eprintln!("Passed:  {}", passed);
    eprintln!("Failed:  {}", failed);
    eprintln!("Skipped: {}", skipped);

    if !failures.is_empty() {
        eprintln!("\n--- Failures ---");
        for (file, err) in &failures {
            eprintln!("  FAIL: {} -> {}", file, err);
        }
    }

    // Calculate pass rate
    let testable = total - skipped;
    let pass_rate = if testable > 0 {
        (passed as f64 / testable as f64) * 100.0
    } else {
        100.0
    };
    eprintln!("\nPass rate: {:.1}% ({}/{})", pass_rate, passed, testable);

    // All non-skipped files must pass
    assert!(
        failures.is_empty(),
        "\n{} of {} phpt --FILE-- sections failed to parse.\nFirst failure: {} -> {}",
        failed,
        testable,
        failures[0].0,
        failures[0].1
    );
}
