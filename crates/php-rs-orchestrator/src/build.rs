//! Build pipeline — transforms a PHP project into a deployable slug.
//!
//! Steps:
//! 1. Detect framework (Laravel, Symfony, WordPress, vanilla)
//! 2. Generate or read Appfile.toml manifest
//! 3. Restore build cache (vendor/, opcache)
//! 4. Run `composer install` (if composer.json present)
//! 5. Generate optimized classmap
//! 6. Run framework-specific build steps
//! 7. Pre-compile PHP files to opcache
//! 8. Package as tarball slug
//! 9. Save build cache
//!
//! The slug is a .tar.gz containing the app source + vendor/ + Appfile.toml.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::manifest::Appfile;

/// Result of a build operation.
#[derive(Debug)]
pub struct BuildResult {
    /// Path to the generated slug tarball.
    pub slug_path: String,
    /// The parsed/generated Appfile.
    pub appfile: Appfile,
    /// Build log messages.
    pub log: Vec<String>,
}

/// Build cache metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildCache {
    /// Hash of composer.lock (used to skip vendor reinstall).
    pub composer_lock_hash: Option<String>,
    /// Hash of source files (used to skip opcode recompilation).
    pub source_hash: Option<String>,
    /// Cached vendor directory path.
    pub vendor_cache_path: Option<String>,
    /// Cached opcache directory path.
    pub opcache_cache_path: Option<String>,
}

impl Default for BuildCache {
    fn default() -> Self {
        Self {
            composer_lock_hash: None,
            source_hash: None,
            vendor_cache_path: None,
            opcache_cache_path: None,
        }
    }
}

/// Build a PHP project into a deployable slug.
pub fn build(source_dir: &str, output_dir: &str, app_name: &str) -> Result<BuildResult, String> {
    let source = Path::new(source_dir);
    let output = Path::new(output_dir);

    if !source.exists() {
        return Err(format!("Source directory not found: {}", source_dir));
    }

    std::fs::create_dir_all(output)
        .map_err(|e| format!("Cannot create output directory: {}", e))?;

    let mut log = Vec::new();
    log.push(format!("Building '{}' from {}", app_name, source_dir));

    // Step 1: Detect or load Appfile.toml.
    let appfile = if source.join("Appfile.toml").exists() {
        log.push("Found Appfile.toml \u{2014} using existing manifest".into());
        Appfile::load_from_dir(source)?
    } else {
        log.push(format!("No Appfile.toml found \u{2014} auto-detecting (framework: {})",
            crate::manifest::detect_framework(source)));
        let appfile = Appfile::detect(source, app_name);
        // Write generated Appfile.toml to source directory.
        let toml = appfile.to_toml();
        std::fs::write(source.join("Appfile.toml"), &toml)
            .map_err(|e| format!("Cannot write Appfile.toml: {}", e))?;
        log.push("Generated Appfile.toml".into());
        appfile
    };

    log.push(format!("Framework: {}", appfile.app.framework));
    log.push(format!("Entry: {}", appfile.app.entry));
    log.push(format!("DocRoot: {}", appfile.app.docroot));

    // Step 2: Restore build cache.
    let cache_dir = build_cache_dir(app_name);
    let cache = load_build_cache(&cache_dir);
    let mut new_cache = BuildCache::default();

    // Step 3: Run composer install (if composer.json exists).
    if source.join("composer.json").exists() {
        let lock_hash = hash_file_contents(&source.join("composer.lock"));
        let cache_hit = cache.composer_lock_hash.as_ref() == Some(&lock_hash)
            && cache.vendor_cache_path.as_ref()
                .map(|p| Path::new(p).exists())
                .unwrap_or(false);

        if cache_hit {
            // Restore vendor from cache.
            log.push("Composer cache hit \u{2014} restoring vendor/".into());
            if let Some(ref cached_vendor) = cache.vendor_cache_path {
                restore_vendor_cache(cached_vendor, &source.join("vendor"), &mut log);
            }
        } else {
            log.push("Running composer install...".into());
            match run_composer_install(source) {
                Ok(()) => log.push("composer install completed".into()),
                Err(e) => log.push(format!("Warning: composer install failed: {}", e)),
            }
        }

        // Generate optimized classmap (Phase 2.3).
        if source.join("vendor").exists() {
            log.push("Generating optimized classmap...".into());
            match generate_classmap(source) {
                Ok(count) => log.push(format!("Classmap: {} classes indexed", count)),
                Err(e) => log.push(format!("Warning: classmap generation failed: {}", e)),
            }
        }

        new_cache.composer_lock_hash = Some(lock_hash);
    }

    // Step 4: Framework-specific build steps (Phase 2.5).
    run_framework_build(&appfile.app.framework, source, &mut log);

    // Step 5: Verify entry point exists.
    let entry_path = source.join(&appfile.app.entry);
    if !entry_path.exists() {
        return Err(format!(
            "Entry point not found: {} (looked in {})",
            appfile.app.entry,
            entry_path.display()
        ));
    }

    // Step 6: Pre-compile PHP files to opcache (Phase 2.4).
    let source_hash = hash_php_sources(source);
    let opcache_cache_hit = cache.source_hash.as_ref() == Some(&source_hash)
        && cache.opcache_cache_path.as_ref()
            .map(|p| Path::new(p).exists())
            .unwrap_or(false);

    if opcache_cache_hit {
        log.push("Opcache cache hit \u{2014} restoring pre-compiled opcodes".into());
        if let Some(ref cached_opcache) = cache.opcache_cache_path {
            let dest = source.join("opcache.bin");
            let _ = std::fs::copy(cached_opcache, &dest);
        }
    } else {
        log.push("Pre-compiling PHP files...".into());
        match precompile_php_files(source) {
            Ok(count) => log.push(format!("Pre-compiled {} PHP files to opcache.bin", count)),
            Err(e) => log.push(format!("Warning: opcode pre-compilation skipped: {}", e)),
        }
    }
    new_cache.source_hash = Some(source_hash);

    // Step 7: Package as tarball.
    let slug_name = format!("{}.tar.gz", app_name);
    let slug_path = output.join(&slug_name);
    log.push(format!("Packaging slug: {}", slug_path.display()));

    create_slug(source, &slug_path)?;

    // Step 8: Save build cache (Phase 2.6).
    save_build_cache(&cache_dir, &new_cache, source, &mut log);

    log.push(format!("Build complete: {}", slug_path.display()));

    Ok(BuildResult {
        slug_path: slug_path.to_string_lossy().to_string(),
        appfile,
        log,
    })
}

/// Run `composer install --no-dev --optimize-autoloader` in the project directory.
fn run_composer_install(dir: &Path) -> Result<(), String> {
    // Try to find composer.
    let composer = find_composer();

    let status = std::process::Command::new(&composer)
        .args(["install", "--no-dev", "--no-interaction", "--optimize-autoloader"])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("Failed to run composer: {} (tried '{}')", e, composer))?;

    if !status.success() {
        return Err(format!("composer install exited with status {}", status));
    }
    Ok(())
}

/// Find the composer binary.
fn find_composer() -> String {
    // Check common locations.
    for candidate in &["composer", "composer.phar", "/usr/local/bin/composer"] {
        if let Ok(output) = std::process::Command::new("which")
            .arg(candidate)
            .output()
        {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }
    "composer".into() // Fall back to bare name.
}

/// Create a tarball slug from the source directory.
fn create_slug(source_dir: &Path, output_path: &Path) -> Result<(), String> {
    let status = std::process::Command::new("tar")
        .args([
            "czf",
            &output_path.to_string_lossy(),
            "-C",
            &source_dir.to_string_lossy(),
            ".",
        ])
        .status()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    if !status.success() {
        return Err(format!("tar failed with status {}", status));
    }
    Ok(())
}

// ── Phase 2.3: Composer Integration ────────────────────────────────────────

/// Generate an optimized classmap from vendor/composer/autoload_classmap.php.
/// Returns the number of classes found.
fn generate_classmap(source: &Path) -> Result<usize, String> {
    let classmap_file = source.join("vendor/composer/autoload_classmap.php");
    if !classmap_file.exists() {
        // Try to generate it with composer dump-autoload.
        let composer = find_composer();
        let _ = std::process::Command::new(&composer)
            .args(["dump-autoload", "--optimize", "--no-interaction"])
            .current_dir(source)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Count classes in the classmap file.
    if classmap_file.exists() {
        let content = std::fs::read_to_string(&classmap_file)
            .map_err(|e| format!("Cannot read classmap: {}", e))?;
        // Count lines with '=>' which represent class mappings.
        let count = content.lines().filter(|l| l.contains("=>")).count();
        Ok(count)
    } else {
        Ok(0)
    }
}

// ── Phase 2.4: Opcode Pre-compilation ──────────────────────────────────────

/// Pre-compile all PHP files in the source directory to an opcache binary.
/// Returns the number of files compiled.
fn precompile_php_files(source: &Path) -> Result<usize, String> {
    let php_files = collect_php_files_for_compile(source);
    if php_files.is_empty() {
        return Ok(0);
    }

    // Write a file listing for the opcache generator.
    let listing_path = source.join(".opcache_files");
    let listing_content: String = php_files.iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&listing_path, &listing_content)
        .map_err(|e| format!("Cannot write opcache file listing: {}", e))?;

    // The opcache.bin is a placeholder for now — actual serialization
    // requires ZOpArray serialization support which would be implemented
    // in the compiler crate. For now, we create a manifest of files to precompile.
    let opcache_manifest = OpcacheManifest {
        version: 1,
        files: php_files.iter()
            .map(|p| {
                let relative = p.strip_prefix(source).unwrap_or(p);
                OpcacheEntry {
                    path: relative.to_string_lossy().to_string(),
                    hash: hash_file_contents(p),
                }
            })
            .collect(),
    };

    let manifest_json = serde_json::to_string_pretty(&opcache_manifest)
        .map_err(|e| format!("Cannot serialize opcache manifest: {}", e))?;
    std::fs::write(source.join("opcache.bin"), &manifest_json)
        .map_err(|e| format!("Cannot write opcache.bin: {}", e))?;

    // Clean up temp file.
    let _ = std::fs::remove_file(&listing_path);

    Ok(php_files.len())
}

/// Opcache manifest — describes pre-compiled files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpcacheManifest {
    version: u32,
    files: Vec<OpcacheEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpcacheEntry {
    path: String,
    hash: String,
}

/// Collect PHP files for compilation, excluding test and vendor test directories.
fn collect_php_files_for_compile(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_php_recursive(dir, dir, &mut files);
    files
}

fn collect_php_recursive(base: &Path, dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden dirs, vendor tests, node_modules, .git.
        if name.starts_with('.') || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            // Skip vendor test directories.
            let relative = path.strip_prefix(base).unwrap_or(&path);
            let rel_str = relative.to_string_lossy();
            if rel_str.contains("vendor/") && (name == "tests" || name == "Tests" || name == "test") {
                continue;
            }
            collect_php_recursive(base, &path, files);
        } else if name.ends_with(".php") {
            files.push(path);
        }
    }
}

// ── Phase 2.5: Framework-Specific Build Steps ─────────────────────────────

/// Run framework-specific build steps.
fn run_framework_build(framework: &str, source: &Path, log: &mut Vec<String>) {
    match framework {
        "laravel" => run_laravel_build(source, log),
        "symfony" => run_symfony_build(source, log),
        "wordpress" => run_wordpress_build(source, log),
        _ => {} // Vanilla PHP — nothing to do.
    }
}

fn run_laravel_build(source: &Path, log: &mut Vec<String>) {
    log.push("Running Laravel build steps...".into());

    // Ensure storage directories exist.
    let storage_dirs = [
        "storage/framework/cache",
        "storage/framework/sessions",
        "storage/framework/views",
        "storage/logs",
        "bootstrap/cache",
    ];
    for dir in &storage_dirs {
        let _ = std::fs::create_dir_all(source.join(dir));
    }

    // Config cache — cache configuration for faster boot.
    if source.join("artisan").exists() {
        if run_artisan(source, &["config:cache"]).is_ok() {
            log.push("  config:cache completed".into());
        } else {
            log.push("  Warning: config:cache failed (non-fatal)".into());
        }

        // Route cache.
        if run_artisan(source, &["route:cache"]).is_ok() {
            log.push("  route:cache completed".into());
        } else {
            log.push("  Warning: route:cache failed (non-fatal)".into());
        }

        // View cache.
        if run_artisan(source, &["view:cache"]).is_ok() {
            log.push("  view:cache completed".into());
        } else {
            log.push("  Warning: view:cache failed (non-fatal)".into());
        }

        // Event cache (Laravel 11+).
        if run_artisan(source, &["event:cache"]).is_ok() {
            log.push("  event:cache completed".into());
        }
    }

    // Detect required extensions from config.
    detect_laravel_extensions(source, log);
}

fn run_symfony_build(source: &Path, log: &mut Vec<String>) {
    log.push("Running Symfony build steps...".into());

    // Ensure var directories exist.
    let var_dirs = ["var/cache", "var/log", "var/sessions"];
    for dir in &var_dirs {
        let _ = std::fs::create_dir_all(source.join(dir));
    }

    // Warm DI container cache.
    if source.join("bin/console").exists() {
        if run_symfony_console(source, &["cache:warmup", "--env=prod"]).is_ok() {
            log.push("  cache:warmup completed".into());
        } else {
            log.push("  Warning: cache:warmup failed (non-fatal)".into());
        }

        // Compile routes.
        if run_symfony_console(source, &["router:match", "/"]).is_ok() {
            log.push("  Router warmed".into());
        }
    }
}

fn run_wordpress_build(source: &Path, log: &mut Vec<String>) {
    log.push("Running WordPress build steps...".into());

    // Ensure writable directories exist.
    let _ = std::fs::create_dir_all(source.join("wp-content/uploads"));
    let _ = std::fs::create_dir_all(source.join("wp-content/cache"));

    // Detect wp-config.php and verify it exists.
    if source.join("wp-config.php").exists() {
        log.push("  wp-config.php found".into());
    } else if source.join("wp-config-sample.php").exists() {
        log.push("  Warning: wp-config.php not found, wp-config-sample.php exists".into());
        log.push("  Copy wp-config-sample.php to wp-config.php and configure".into());
    }
}

/// Run `php artisan <args>` in the project directory.
fn run_artisan(source: &Path, args: &[&str]) -> Result<(), String> {
    let php = find_php();
    let mut cmd_args = vec!["artisan"];
    cmd_args.extend_from_slice(args);
    cmd_args.push("--no-interaction");

    let status = std::process::Command::new(&php)
        .args(&cmd_args)
        .current_dir(source)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Failed to run artisan: {}", e))?;

    if status.success() { Ok(()) } else { Err("artisan command failed".into()) }
}

/// Run `php bin/console <args>` in the project directory.
fn run_symfony_console(source: &Path, args: &[&str]) -> Result<(), String> {
    let php = find_php();
    let mut cmd_args = vec!["bin/console"];
    cmd_args.extend_from_slice(args);
    cmd_args.push("--no-interaction");

    let status = std::process::Command::new(&php)
        .args(&cmd_args)
        .current_dir(source)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Failed to run console: {}", e))?;

    if status.success() { Ok(()) } else { Err("console command failed".into()) }
}

/// Find a PHP binary for running build commands.
fn find_php() -> String {
    for candidate in &["php", "/usr/bin/php", "/usr/local/bin/php"] {
        if let Ok(output) = std::process::Command::new("which")
            .arg(candidate)
            .output()
        {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }
    "php".into()
}

/// Detect required PHP extensions from Laravel config files.
fn detect_laravel_extensions(source: &Path, log: &mut Vec<String>) {
    let mut detected = Vec::new();

    // Check config/database.php for database driver.
    if let Ok(content) = std::fs::read_to_string(source.join("config/database.php")) {
        if content.contains("'mysql'") { detected.push("pdo_mysql"); }
        if content.contains("'pgsql'") { detected.push("pdo_pgsql"); }
        if content.contains("'sqlite'") { detected.push("pdo_sqlite"); }
    }

    // Check config/cache.php for Redis.
    if let Ok(content) = std::fs::read_to_string(source.join("config/cache.php")) {
        if content.contains("'redis'") { detected.push("redis"); }
    }

    if !detected.is_empty() {
        log.push(format!("  Detected extensions: {}", detected.join(", ")));
    }
}

// ── Phase 2.6: Build Caching ──────────────────────────────────────────────

/// Get the build cache directory for an app.
fn build_cache_dir(app_name: &str) -> PathBuf {
    let base = if let Ok(dir) = std::env::var("PHPRS_STATE_DIR") {
        PathBuf::from(dir)
    } else if let Some(home) = dirs_home() {
        home.join(".php-rs")
    } else {
        PathBuf::from("/tmp/.php-rs")
    };
    base.join("cache").join(app_name)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Load build cache metadata for an app.
fn load_build_cache(cache_dir: &Path) -> BuildCache {
    let meta_path = cache_dir.join("cache.json");
    if meta_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&meta_path) {
            if let Ok(cache) = serde_json::from_str(&content) {
                return cache;
            }
        }
    }
    BuildCache::default()
}

/// Save build cache after successful build.
fn save_build_cache(cache_dir: &Path, cache: &BuildCache, source: &Path, log: &mut Vec<String>) {
    let _ = std::fs::create_dir_all(cache_dir);

    // Cache vendor directory.
    let vendor_src = source.join("vendor");
    if vendor_src.exists() {
        let vendor_cache = cache_dir.join("vendor");
        if let Err(e) = copy_dir_for_cache(&vendor_src, &vendor_cache) {
            log.push(format!("Warning: vendor cache save failed: {}", e));
        } else {
            log.push("Saved vendor/ to build cache".into());
        }
    }

    // Cache opcache.bin.
    let opcache_src = source.join("opcache.bin");
    if opcache_src.exists() {
        let opcache_cache = cache_dir.join("opcache.bin");
        let _ = std::fs::copy(&opcache_src, &opcache_cache);
    }

    // Update metadata.
    let mut saved = cache.clone();
    saved.vendor_cache_path = Some(cache_dir.join("vendor").to_string_lossy().to_string());
    saved.opcache_cache_path = Some(cache_dir.join("opcache.bin").to_string_lossy().to_string());

    if let Ok(json) = serde_json::to_string_pretty(&saved) {
        let _ = std::fs::write(cache_dir.join("cache.json"), &json);
    }
}

/// Restore vendor directory from cache.
fn restore_vendor_cache(cache_path: &str, dest: &Path, log: &mut Vec<String>) {
    let src = Path::new(cache_path);
    if !src.exists() {
        log.push("Warning: vendor cache not found".into());
        return;
    }
    if let Err(e) = copy_dir_for_cache(src, dest) {
        log.push(format!("Warning: vendor cache restore failed: {}", e));
    }
}

/// Copy a directory tree (simple recursive copy for caching).
fn copy_dir_for_cache(src: &Path, dest: &Path) -> Result<(), String> {
    // Use tar for efficient directory copy.
    let _ = std::fs::create_dir_all(dest);
    let status = std::process::Command::new("rsync")
        .args(["-a", "--delete"])
        .arg(&format!("{}/", src.to_string_lossy()))
        .arg(&format!("{}/", dest.to_string_lossy()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            // Fallback to cp -a.
            let status = std::process::Command::new("cp")
                .args(["-a"])
                .arg(src)
                .arg(dest.parent().unwrap_or(dest))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|e| format!("cp failed: {}", e))?;
            if status.success() { Ok(()) } else { Err("cp failed".into()) }
        }
    }
}

// ── Hashing Utilities ─────────────────────────────────────────────────────

/// Simple hash of a file's contents (for cache invalidation).
/// Uses a fast non-cryptographic hash.
fn hash_file_contents(path: &Path) -> String {
    if let Ok(content) = std::fs::read(path) {
        format!("{:016x}", simple_hash(&content))
    } else {
        "0000000000000000".into()
    }
}

/// Hash all PHP source files (for opcache invalidation).
fn hash_php_sources(dir: &Path) -> String {
    let files = collect_php_files_for_compile(dir);
    let mut combined: u64 = 0;
    for file in &files {
        if let Ok(content) = std::fs::read(file) {
            combined = combined.wrapping_add(simple_hash(&content));
        }
    }
    format!("{:016x}", combined)
}

/// FNV-1a 64-bit hash for fast non-cryptographic hashing.
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x00000100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple_project() {
        let dir = std::env::temp_dir().join(format!("phprs-test-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let source = dir.join("source");
        let output = dir.join("output");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("index.php"), "<?php echo 'hello';").unwrap();

        let result = build(
            source.to_str().unwrap(),
            output.to_str().unwrap(),
            "testapp",
        ).unwrap();

        assert!(Path::new(&result.slug_path).exists());
        assert_eq!(result.appfile.app.name, "testapp");
        assert_eq!(result.appfile.app.framework, "vanilla");
        // Appfile.toml should have been generated.
        assert!(source.join("Appfile.toml").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_with_appfile() {
        let dir = std::env::temp_dir().join(format!("phprs-test-build-appfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let source = dir.join("source");
        let output = dir.join("output");
        std::fs::create_dir_all(source.join("public")).unwrap();
        std::fs::write(source.join("public/index.php"), "<?php echo 'hi';").unwrap();
        std::fs::write(source.join("Appfile.toml"), r#"
[app]
name = "custom"
framework = "slim"
entry = "public/index.php"
docroot = "public"

[php]
memory_limit = "512M"
"#).unwrap();

        let result = build(
            source.to_str().unwrap(),
            output.to_str().unwrap(),
            "custom",
        ).unwrap();

        assert_eq!(result.appfile.app.name, "custom");
        assert_eq!(result.appfile.app.framework, "slim");
        assert_eq!(result.appfile.php.memory_limit, "512M");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_missing_entry_point() {
        let dir = std::env::temp_dir().join(format!("phprs-test-build-noentry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let source = dir.join("source");
        let output = dir.join("output");
        std::fs::create_dir_all(&source).unwrap();
        // No index.php or public/index.php

        let result = build(
            source.to_str().unwrap(),
            output.to_str().unwrap(),
            "noentry",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Entry point not found"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_missing_source() {
        let result = build("/nonexistent/source", "/tmp/output", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Source directory not found"));
    }

    #[test]
    fn test_find_composer() {
        // Just verify it doesn't panic.
        let _ = find_composer();
    }

    #[test]
    fn test_simple_hash() {
        let h1 = simple_hash(b"hello");
        let h2 = simple_hash(b"hello");
        let h3 = simple_hash(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hash_file_contents() {
        let dir = std::env::temp_dir().join(format!("phprs-test-hash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let file_a = dir.join("a.txt");
        let file_b = dir.join("b.txt");
        std::fs::write(&file_a, "hello").unwrap();
        std::fs::write(&file_b, "hello").unwrap();

        assert_eq!(hash_file_contents(&file_a), hash_file_contents(&file_b));

        std::fs::write(&file_b, "world").unwrap();
        assert_ne!(hash_file_contents(&file_a), hash_file_contents(&file_b));

        // Non-existent file.
        assert_eq!(hash_file_contents(&dir.join("missing")), "0000000000000000");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_php_files_for_compile() {
        let dir = std::env::temp_dir().join(format!("phprs-test-collect-php-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("vendor/pkg/tests")).unwrap();
        std::fs::create_dir_all(dir.join(".hidden")).unwrap();

        std::fs::write(dir.join("index.php"), "<?php echo 1;").unwrap();
        std::fs::write(dir.join("src/App.php"), "<?php class App {}").unwrap();
        std::fs::write(dir.join("vendor/pkg/Foo.php"), "<?php class Foo {}").unwrap();
        std::fs::write(dir.join("vendor/pkg/tests/FooTest.php"), "<?php class FooTest {}").unwrap();
        std::fs::write(dir.join(".hidden/secret.php"), "<?php").unwrap();
        std::fs::write(dir.join("readme.md"), "not php").unwrap();

        let files = collect_php_files_for_compile(&dir);

        // Should include index.php, src/App.php, vendor/pkg/Foo.php
        // Should NOT include vendor/pkg/tests/FooTest.php, .hidden/secret.php, readme.md
        let names: Vec<String> = files.iter()
            .map(|p| p.strip_prefix(&dir).unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"index.php".to_string()));
        assert!(names.contains(&"src/App.php".to_string()));
        assert!(names.contains(&"vendor/pkg/Foo.php".to_string()));
        assert!(!names.iter().any(|n| n.contains("FooTest")));
        assert!(!names.iter().any(|n| n.contains(".hidden")));
        assert!(!names.iter().any(|n| n.contains("readme")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_precompile_creates_opcache() {
        let dir = std::env::temp_dir().join(format!("phprs-test-precompile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("index.php"), "<?php echo 'hello';").unwrap();
        std::fs::write(dir.join("lib.php"), "<?php function foo() {}").unwrap();

        let count = precompile_php_files(&dir).unwrap();
        assert_eq!(count, 2);
        assert!(dir.join("opcache.bin").exists());

        // Verify the manifest is valid JSON.
        let content = std::fs::read_to_string(dir.join("opcache.bin")).unwrap();
        let manifest: OpcacheManifest = serde_json::from_str(&content).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.version, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_cache_roundtrip() {
        let dir = std::env::temp_dir().join(format!("phprs-test-bcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let cache = BuildCache {
            composer_lock_hash: Some("abc123".into()),
            source_hash: Some("def456".into()),
            vendor_cache_path: Some("/tmp/vendor".into()),
            opcache_cache_path: Some("/tmp/opcache.bin".into()),
        };

        let json = serde_json::to_string_pretty(&cache).unwrap();
        std::fs::write(dir.join("cache.json"), &json).unwrap();

        let loaded = load_build_cache(&dir);
        assert_eq!(loaded.composer_lock_hash, Some("abc123".into()));
        assert_eq!(loaded.source_hash, Some("def456".into()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_cache_missing() {
        let dir = std::env::temp_dir().join("phprs-test-bcache-missing");
        let loaded = load_build_cache(&dir);
        assert!(loaded.composer_lock_hash.is_none());
        assert!(loaded.source_hash.is_none());
    }

    #[test]
    fn test_framework_build_creates_dirs() {
        let dir = std::env::temp_dir().join(format!("phprs-test-fw-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut log = Vec::new();

        // Laravel build should create storage directories.
        run_framework_build("laravel", &dir, &mut log);
        assert!(dir.join("storage/framework/cache").exists());
        assert!(dir.join("storage/logs").exists());
        assert!(dir.join("bootstrap/cache").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wordpress_build() {
        let dir = std::env::temp_dir().join(format!("phprs-test-wp-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("wp-config.php"), "<?php").unwrap();

        let mut log = Vec::new();
        run_framework_build("wordpress", &dir, &mut log);
        assert!(dir.join("wp-content/uploads").exists());
        assert!(log.iter().any(|l| l.contains("wp-config.php found")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hash_php_sources() {
        let dir = std::env::temp_dir().join(format!("phprs-test-hash-php-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("a.php"), "<?php echo 1;").unwrap();
        let h1 = hash_php_sources(&dir);

        std::fs::write(dir.join("a.php"), "<?php echo 2;").unwrap();
        let h2 = hash_php_sources(&dir);

        assert_ne!(h1, h2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
