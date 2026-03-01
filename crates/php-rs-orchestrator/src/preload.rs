//! Framework preloading — auto-detect and generate preload scripts.
//!
//! Detects the PHP framework in a project directory and generates a
//! preload script that pre-includes core framework files for faster boot.

use std::path::Path;

/// Detected PHP framework.
#[derive(Debug, Clone, PartialEq)]
pub enum Framework {
    Laravel,
    Symfony,
    WordPress,
    Unknown,
}

/// Detect which PHP framework is used in a project directory.
pub fn detect_framework(project_dir: &Path) -> Framework {
    // Laravel: has artisan file and composer.json with laravel/framework.
    if project_dir.join("artisan").exists() {
        if let Ok(composer) = std::fs::read_to_string(project_dir.join("composer.json")) {
            if composer.contains("laravel/framework") {
                return Framework::Laravel;
            }
        }
        return Framework::Laravel; // artisan file strongly suggests Laravel.
    }

    // Symfony: has bin/console and symfony packages.
    if project_dir.join("bin/console").exists() {
        if let Ok(composer) = std::fs::read_to_string(project_dir.join("composer.json")) {
            if composer.contains("symfony/framework-bundle") || composer.contains("symfony/symfony") {
                return Framework::Symfony;
            }
        }
    }

    // WordPress: has wp-config.php or wp-includes/.
    if project_dir.join("wp-config.php").exists()
        || project_dir.join("wp-includes").is_dir()
    {
        return Framework::WordPress;
    }

    Framework::Unknown
}

/// Generate a preload script for the detected framework.
/// Returns the script contents or None if no preloading is useful.
pub fn generate_preload_script(framework: &Framework, project_dir: &Path) -> Option<String> {
    match framework {
        Framework::Laravel => Some(generate_laravel_preload(project_dir)),
        Framework::Symfony => Some(generate_symfony_preload(project_dir)),
        Framework::WordPress => None, // WordPress doesn't benefit much from preloading.
        Framework::Unknown => None,
    }
}

/// Suggested preload file path for a framework.
pub fn preload_file_path(framework: &Framework) -> Option<&'static str> {
    match framework {
        Framework::Laravel => Some("preload.php"),
        Framework::Symfony => Some("preload.php"),
        _ => None,
    }
}

fn generate_laravel_preload(project_dir: &Path) -> String {
    let vendor = project_dir.join("vendor");
    let mut files = Vec::new();

    // Core Laravel files to preload.
    let laravel_dirs = [
        "laravel/framework/src/Illuminate/Support",
        "laravel/framework/src/Illuminate/Container",
        "laravel/framework/src/Illuminate/Contracts",
        "laravel/framework/src/Illuminate/Http",
        "laravel/framework/src/Illuminate/Routing",
        "laravel/framework/src/Illuminate/Foundation",
        "laravel/framework/src/Illuminate/Pipeline",
    ];

    for dir in &laravel_dirs {
        let full_path = vendor.join(dir);
        if full_path.is_dir() {
            collect_php_files(&full_path, &mut files);
        }
    }

    // Also include autoloader.
    let autoload = vendor.join("autoload.php");
    if autoload.exists() {
        files.insert(0, autoload.to_string_lossy().to_string());
    }

    generate_preload_php(&files)
}

fn generate_symfony_preload(project_dir: &Path) -> String {
    let vendor = project_dir.join("vendor");
    let mut files = Vec::new();

    let symfony_dirs = [
        "symfony/http-foundation",
        "symfony/http-kernel",
        "symfony/routing",
        "symfony/dependency-injection",
        "symfony/event-dispatcher",
    ];

    for dir in &symfony_dirs {
        let full_path = vendor.join(dir);
        if full_path.is_dir() {
            collect_php_files(&full_path, &mut files);
        }
    }

    let autoload = vendor.join("autoload.php");
    if autoload.exists() {
        files.insert(0, autoload.to_string_lossy().to_string());
    }

    generate_preload_php(&files)
}

/// Recursively collect .php files from a directory.
fn collect_php_files(dir: &Path, files: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_php_files(&path, files);
            } else if path.extension().map_or(false, |e| e == "php") {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }
}

/// Generate a PHP preload script that requires all the given files.
fn generate_preload_php(files: &[String]) -> String {
    let mut script = String::from("<?php\n// Auto-generated preload script by php-rs PaaS\n// Pre-includes framework files to warm opcode cache.\n\n");

    for file in files {
        // Use require_once to avoid duplicate includes.
        script.push_str(&format!("require_once '{}';\n", file.replace('\'', "\\'")));
    }

    script.push_str(&format!(
        "\n// Preloaded {} files.\n",
        files.len()
    ));
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_framework_laravel() {
        let dir = std::env::temp_dir().join(format!("phprs-fw-test-laravel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Create artisan file + composer.json.
        std::fs::write(dir.join("artisan"), "#!/usr/bin/env php\n").unwrap();
        std::fs::write(
            dir.join("composer.json"),
            r#"{"require": {"laravel/framework": "^11.0"}}"#,
        )
        .unwrap();

        assert_eq!(detect_framework(&dir), Framework::Laravel);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_framework_symfony() {
        let dir = std::env::temp_dir().join(format!("phprs-fw-test-symfony-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();

        std::fs::write(dir.join("bin/console"), "#!/usr/bin/env php\n").unwrap();
        std::fs::write(
            dir.join("composer.json"),
            r#"{"require": {"symfony/framework-bundle": "^7.0"}}"#,
        )
        .unwrap();

        assert_eq!(detect_framework(&dir), Framework::Symfony);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_framework_wordpress() {
        let dir = std::env::temp_dir().join(format!("phprs-fw-test-wp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("wp-config.php"), "<?php\n").unwrap();

        assert_eq!(detect_framework(&dir), Framework::WordPress);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_framework_unknown() {
        let dir = std::env::temp_dir().join(format!("phprs-fw-test-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("index.php"), "<?php echo 'hello';\n").unwrap();

        assert_eq!(detect_framework(&dir), Framework::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_preload_php() {
        let files = vec![
            "/app/vendor/autoload.php".to_string(),
            "/app/vendor/laravel/framework/src/Support/Str.php".to_string(),
        ];
        let script = generate_preload_php(&files);
        assert!(script.starts_with("<?php"));
        assert!(script.contains("require_once"));
        assert!(script.contains("autoload.php"));
        assert!(script.contains("Str.php"));
        assert!(script.contains("2 files"));
    }

    #[test]
    fn test_preload_file_path() {
        assert_eq!(preload_file_path(&Framework::Laravel), Some("preload.php"));
        assert_eq!(preload_file_path(&Framework::Symfony), Some("preload.php"));
        assert_eq!(preload_file_path(&Framework::WordPress), None);
        assert_eq!(preload_file_path(&Framework::Unknown), None);
    }

    #[test]
    fn test_no_preload_for_wordpress() {
        let dir = std::env::temp_dir().join(format!("phprs-fw-test-wp2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(generate_preload_script(&Framework::WordPress, &dir).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
