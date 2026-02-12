use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Parse php-src/ext/*_arginfo.h and Zend/*_arginfo.h for function entries.
/// Returns a map of extension_name -> set of function names.
fn parse_php_src(project_root: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let mut extensions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // Scan ext/ directories
    let php_src_ext = project_root.join("php-src/ext");
    if let Ok(entries) = fs::read_dir(&php_src_ext) {
        for entry in entries.flatten() {
            let ext_path = entry.path();
            if !ext_path.is_dir() {
                continue;
            }
            let ext_name = entry.file_name().to_string_lossy().to_string();
            if matches!(
                ext_name.as_str(),
                "skeleton" | "dl_test" | "zend_test" | "lexbor"
            ) {
                continue;
            }

            let mut funcs = BTreeSet::new();
            collect_functions_from_dir(&ext_path, &mut funcs);
            if !funcs.is_empty() {
                extensions.insert(ext_name, funcs);
            }
        }
    }

    // Scan Zend/ for core built-in functions (strlen, get_class, exit, etc.)
    let zend_dir = project_root.join("php-src/Zend");
    let mut zend_funcs = BTreeSet::new();
    collect_functions_from_dir(&zend_dir, &mut zend_funcs);
    if !zend_funcs.is_empty() {
        extensions.insert("zend_core".to_string(), zend_funcs);
    }

    extensions
}

fn collect_functions_from_dir(dir: &Path, funcs: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_functions_from_dir(&path, funcs);
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.ends_with("_arginfo.h") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        parse_arginfo(&content, funcs);
    }
}

fn parse_arginfo(content: &str, funcs: &mut BTreeSet<String>) {
    // Track whether we're inside a function entry array vs a method entry array.
    // Method arrays are named like `class_Foo_methods[]` while function arrays
    // are named like `ext_functions[]` or `php_foo_functions[]`.
    let mut in_method_array = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect array declarations to track context
        if trimmed.contains("zend_function_entry") && trimmed.contains('[') {
            // class_*_methods[] → method array, skip entries
            // anything else → function array
            in_method_array = trimmed.contains("class_") && trimmed.contains("_methods");
        }

        // ZEND_FE_END resets context
        if trimmed.starts_with("ZEND_FE_END") {
            in_method_array = false;
            continue;
        }

        // Skip ZEND_ME / ZEND_ABSTRACT_ME / ZEND_MALIAS / ZEND_DEP_ME (always methods)
        if trimmed.starts_with("ZEND_ME(")
            || trimmed.starts_with("ZEND_ABSTRACT_ME(")
            || trimmed.starts_with("ZEND_MALIAS(")
            || trimmed.starts_with("ZEND_DEP_ME(")
        {
            continue;
        }

        // ZEND_FE(name, arginfo) or ZEND_DEP_FE(name, arginfo)
        if let Some(rest) = trimmed
            .strip_prefix("ZEND_FE(")
            .or_else(|| trimmed.strip_prefix("ZEND_DEP_FE("))
        {
            if !in_method_array {
                if let Some(name) = rest.split(',').next() {
                    let name = name.trim();
                    if is_valid_func_name(name) {
                        funcs.insert(name.to_string());
                    }
                }
            }
            continue;
        }

        // ZEND_FALIAS(alias, original, arginfo)
        if let Some(rest) = trimmed.strip_prefix("ZEND_FALIAS(") {
            if !in_method_array {
                if let Some(name) = rest.split(',').next() {
                    let name = name.trim();
                    if is_valid_func_name(name) {
                        funcs.insert(name.to_string());
                    }
                }
            }
            continue;
        }

        // ZEND_RAW_FENTRY("name", handler, ...)
        if let Some(rest) = trimmed.strip_prefix("ZEND_RAW_FENTRY(") {
            if let Some(name) = extract_quoted_string(rest) {
                // Find handler after the closing quote + comma
                let after_name = &rest[rest.find('"').unwrap() + name.len() + 2..];
                let after_comma =
                    after_name.trim_start_matches(|c: char| c == ',' || c.is_whitespace());

                // Skip entries that are clearly methods:
                // - handler starts with zim_ (class method implementation)
                // - handler is NULL (abstract method)
                // - we're inside a class methods array
                if after_comma.starts_with("zim_") || after_comma.starts_with("NULL") {
                    continue;
                }

                if in_method_array {
                    // Inside a method array — even with zif_ handler, these are methods
                    continue;
                }

                // Top-level function with zif_ or php_if_ handler
                if after_comma.starts_with("zif_") || after_comma.starts_with("php_if_") {
                    funcs.insert(name);
                }
            }
            continue;
        }

        // ZEND_NS_FE("ns", name, arginfo) or ZEND_NS_DEP_FE
        if let Some(rest) = trimmed
            .strip_prefix("ZEND_NS_FE(")
            .or_else(|| trimmed.strip_prefix("ZEND_NS_DEP_FE("))
        {
            if !in_method_array {
                let parts: Vec<&str> = rest.splitn(3, ',').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim();
                    if is_valid_func_name(name) {
                        funcs.insert(name.to_string());
                    }
                }
            }
            continue;
        }

        // ZEND_NS_FALIAS("ns", alias, original, arginfo)
        if let Some(rest) = trimmed.strip_prefix("ZEND_NS_FALIAS(") {
            if !in_method_array {
                let parts: Vec<&str> = rest.splitn(4, ',').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim();
                    if is_valid_func_name(name) {
                        funcs.insert(name.to_string());
                    }
                }
            }
            continue;
        }
    }
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    if !s.starts_with('"') {
        return None;
    }
    let end = s[1..].find('"')?;
    Some(s[1..1 + end].to_string())
}

fn is_valid_func_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

/// Parse php-rs vm.rs call_builtin match arms for implemented function names.
fn parse_php_rs(vm_path: &Path) -> BTreeSet<String> {
    let mut funcs = BTreeSet::new();

    let Ok(content) = fs::read_to_string(vm_path) else {
        eprintln!("Cannot read {}", vm_path.display());
        return funcs;
    };

    let mut in_call_builtin = false;
    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.contains("fn call_builtin") {
            in_call_builtin = true;
            continue;
        }

        if !in_call_builtin {
            continue;
        }

        // End of call_builtin: next method at same indent level (4 spaces + fn)
        // Skip nested fn definitions inside match arms
        if trimmed.starts_with("fn ") && !trimmed.contains("call_builtin") {
            // Check if this is a top-level method (indented 4 spaces) vs nested fn
            let indent = line.len() - line.trim_start().len();
            if indent <= 4 {
                break;
            }
            // Otherwise it's a nested fn inside a match arm - skip
            continue;
        }

        // Match arms: "name" => or "name" | "name2" =>
        // Also handles multi-line arms where continuation lines start with |
        // Accumulate names from lines containing quoted strings (match patterns)
        if trimmed.starts_with('"') || (trimmed.starts_with("| \"") && !trimmed.contains("//")) {
            // Extract all quoted strings from this line
            let scan = if trimmed.contains("=>") {
                trimmed.split("=>").next().unwrap()
            } else {
                trimmed
            };
            let mut pos = 0;
            let bytes = scan.as_bytes();
            while pos < bytes.len() {
                if bytes[pos] == b'"' {
                    if let Some(end) = scan[pos + 1..].find('"') {
                        let name = &scan[pos + 1..pos + 1 + end];
                        if is_valid_func_name(name) {
                            funcs.insert(name.to_string());
                        }
                        pos = pos + 1 + end + 1;
                    } else {
                        break;
                    }
                } else {
                    pos += 1;
                }
            }
        }
    }

    funcs
}

/// Map a php-rs function name to the php-src extension that defines it.
fn classify_function(name: &str, php_src: &BTreeMap<String, BTreeSet<String>>) -> Option<String> {
    for (ext, funcs) in php_src {
        if funcs.contains(name) {
            return Some(ext.clone());
        }
    }
    None
}

fn main() {
    let project_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vm_path = project_root.join("crates/php-rs-vm/src/vm.rs");

    let php_src_funcs = parse_php_src(project_root);
    let php_rs_funcs = parse_php_rs(&vm_path);

    println!("=== PHP Standard Library Coverage: php-rs vs php-src ===\n");

    let mut total_php_src = 0usize;
    let mut total_implemented = 0usize;
    let mut ext_stats: Vec<(String, usize, usize)> = Vec::new();

    let mut implemented_by_ext: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unclassified = BTreeSet::new();

    for func in &php_rs_funcs {
        if let Some(ext) = classify_function(func, &php_src_funcs) {
            implemented_by_ext
                .entry(ext)
                .or_default()
                .insert(func.clone());
        } else {
            unclassified.insert(func.clone());
        }
    }

    for (ext, funcs) in &php_src_funcs {
        let implemented = implemented_by_ext.get(ext).cloned().unwrap_or_default();
        let impl_count = implemented.len();
        let total = funcs.len();
        total_php_src += total;
        total_implemented += impl_count;
        ext_stats.push((ext.clone(), impl_count, total));

        if impl_count == 0 && total < 3 {
            continue;
        }

        let pct = if total > 0 {
            100.0 * impl_count as f64 / total as f64
        } else {
            0.0
        };

        println!(
            "Extension: {} ({}/{} = {:.1}%)",
            ext, impl_count, total, pct
        );

        for f in &implemented {
            println!("  [x] {}", f);
        }
        let missing: Vec<_> = funcs.difference(&implemented).collect();
        let show_missing = 20;
        for (i, f) in missing.iter().enumerate() {
            if i >= show_missing && missing.len() > show_missing + 2 {
                println!("  ... and {} more missing", missing.len() - show_missing);
                break;
            }
            println!("  [ ] {}", f);
        }
        println!();
    }

    if !unclassified.is_empty() {
        println!("Unclassified (in php-rs, not found in php-src):");
        for f in &unclassified {
            println!("  [?] {}", f);
        }
        println!();
    }

    println!("=== Summary ===");
    let pct = if total_php_src > 0 {
        100.0 * total_implemented as f64 / total_php_src as f64
    } else {
        0.0
    };
    println!(
        "Total: {}/{} functions ({:.1}%)",
        total_implemented, total_php_src, pct
    );
    println!(
        "Implemented in php-rs: {} (including {} not in php-src)",
        php_rs_funcs.len(),
        unclassified.len()
    );

    let fully_covered: Vec<_> = ext_stats
        .iter()
        .filter(|(_, imp, tot)| *imp > 0 && *imp == *tot)
        .collect();
    if !fully_covered.is_empty() {
        print!("Fully covered:");
        for (ext, imp, _) in &fully_covered {
            print!(" {} ({}/{})", ext, imp, imp);
        }
        println!();
    }

    println!("\nBest opportunities (most missing):");
    let mut by_missing: Vec<_> = ext_stats
        .iter()
        .map(|(ext, imp, tot)| (ext, tot - imp, *tot))
        .filter(|(_, missing, _)| *missing > 0)
        .collect();
    by_missing.sort_by(|a, b| b.1.cmp(&a.1));
    for (ext, missing, total) in by_missing.iter().take(10) {
        println!("  {} ({} missing of {})", ext, missing, total);
    }
}
