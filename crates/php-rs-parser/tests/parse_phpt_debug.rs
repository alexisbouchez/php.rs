//! Debug test: parse all php-src/tests/lang/*.phpt --FILE-- sections

use php_rs_parser::Parser;
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn extract_file_section(content: &str) -> Option<String> {
    let mut in_file_section = false;
    let mut file_content = String::new();
    for line in content.lines() {
        if line.starts_with("--FILE--") {
            in_file_section = true;
            continue;
        }
        if in_file_section && line.starts_with("--") && line.ends_with("--") {
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

#[test]
fn scan_all_phpt_files() {
    let lang_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("php-src/tests/lang");

    if !lang_dir.exists() {
        return;
    }

    let mut entries: Vec<_> = fs::read_dir(&lang_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "phpt"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut total = 0;
    let mut passed = 0;
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut hangs: Vec<String> = Vec::new();

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        let content = fs::read_to_string(&path).unwrap();
        let file_section = match extract_file_section(&content) {
            Some(s) => s,
            None => continue,
        };
        total += 1;

        eprint!("  Parsing {}... ", filename);

        let source = file_section.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut parser = Parser::new(&source);
            let result = parser.parse();
            let _ = tx.send(result.map(|_| ()).map_err(|e| format!("{:?}", e)));
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                eprintln!("OK");
                passed += 1;
            }
            Ok(Err(e)) => {
                eprintln!("FAIL: {}", e);
                failures.push((filename, e));
            }
            Err(_) => {
                eprintln!("HANG (>5s)");
                hangs.push(filename);
            }
        }
    }

    let failed = failures.len();
    let hung = hangs.len();
    eprintln!("\n=== PHPT Parse Results ===");
    eprintln!(
        "Total: {}, Passed: {}, Failed: {}, Hung: {}",
        total, passed, failed, hung
    );
    eprintln!("Pass rate: {:.1}%", (passed as f64 / total as f64) * 100.0);

    if !hangs.is_empty() {
        eprintln!("\n--- Hangs (>5s) ---");
        for file in &hangs {
            eprintln!("  HANG: {}", file);
        }
    }

    if !failures.is_empty() {
        eprintln!("\n--- First 30 failures ---");
        for (file, err) in failures.iter().take(30) {
            eprintln!("  {}: {}", file, err);
        }
    }
}
