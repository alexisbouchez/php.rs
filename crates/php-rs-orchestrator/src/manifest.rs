//! Appfile.toml — application manifest for PaaS deployments.
//!
//! Auto-generated during build, or manually provided by the user.
//! Describes the app's configuration, runtime requirements, and services.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The application manifest (Appfile.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appfile {
    pub app: AppSection,
    #[serde(default)]
    pub php: PhpSection,
    #[serde(default)]
    pub resources: ResourcesSection,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub services: ServicesSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSection {
    pub name: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default = "default_entry")]
    pub entry: String,
    #[serde(default = "default_docroot")]
    pub docroot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhpSection {
    #[serde(default = "default_memory_limit")]
    pub memory_limit: String,
    #[serde(default = "default_max_execution_time")]
    pub max_execution_time: u64,
    #[serde(default)]
    pub preload: Option<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub ini: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesSection {
    #[serde(default)]
    pub workers: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServicesSection {
    #[serde(default)]
    pub mysql: bool,
    #[serde(default)]
    pub postgres: bool,
    #[serde(default)]
    pub redis: bool,
}

fn default_entry() -> String { "public/index.php".into() }
fn default_docroot() -> String { "public".into() }
fn default_memory_limit() -> String { "128M".into() }
fn default_max_execution_time() -> u64 { 30 }

impl Default for ResourcesSection {
    fn default() -> Self {
        Self { workers: 0 }
    }
}

impl Appfile {
    /// Load an Appfile.toml from a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self, String> {
        let path = dir.join("Appfile.toml");
        if !path.exists() {
            return Err(format!("No Appfile.toml found in {}", dir.display()));
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        Self::parse(&content)
    }

    /// Parse an Appfile from TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, String> {
        // Simple TOML parser — handles the subset we need.
        parse_appfile_toml(toml_str)
    }

    /// Generate an Appfile by auto-detecting the project.
    pub fn detect(dir: &Path, app_name: &str) -> Self {
        let framework = detect_framework(dir);
        let entry = detect_entry_point(dir, &framework);
        let docroot = detect_docroot(dir, &framework);
        let extensions = detect_extensions(dir);
        let services = detect_services(dir);

        Appfile {
            app: AppSection {
                name: app_name.to_string(),
                framework: framework.clone(),
                entry,
                docroot,
            },
            php: PhpSection {
                memory_limit: "128M".into(),
                max_execution_time: 30,
                preload: None,
                extensions,
                ini: HashMap::new(),
            },
            resources: ResourcesSection::default(),
            env: HashMap::new(),
            services,
        }
    }

    /// Serialize to TOML format.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("[app]\n");
        out.push_str(&format!("name = \"{}\"\n", self.app.name));
        if !self.app.framework.is_empty() {
            out.push_str(&format!("framework = \"{}\"\n", self.app.framework));
        }
        out.push_str(&format!("entry = \"{}\"\n", self.app.entry));
        out.push_str(&format!("docroot = \"{}\"\n", self.app.docroot));

        out.push_str("\n[php]\n");
        out.push_str(&format!("memory_limit = \"{}\"\n", self.php.memory_limit));
        out.push_str(&format!("max_execution_time = {}\n", self.php.max_execution_time));
        if let Some(preload) = &self.php.preload {
            out.push_str(&format!("preload = \"{}\"\n", preload));
        }
        if !self.php.extensions.is_empty() {
            out.push_str(&format!(
                "extensions = [{}]\n",
                self.php.extensions.iter().map(|e| format!("\"{}\"", e)).collect::<Vec<_>>().join(", ")
            ));
        }

        if self.resources.workers > 0 {
            out.push_str("\n[resources]\n");
            out.push_str(&format!("workers = {}\n", self.resources.workers));
        }

        if !self.env.is_empty() {
            out.push_str("\n[env]\n");
            let mut keys: Vec<&String> = self.env.keys().collect();
            keys.sort();
            for key in keys {
                out.push_str(&format!("{} = \"{}\"\n", key, self.env[key]));
            }
        }

        if self.services.mysql || self.services.postgres || self.services.redis {
            out.push_str("\n[services]\n");
            if self.services.mysql { out.push_str("mysql = true\n"); }
            if self.services.postgres { out.push_str("postgres = true\n"); }
            if self.services.redis { out.push_str("redis = true\n"); }
        }

        out
    }
}

// ── Framework Detection ─────────────────────────────────────────────────────

/// Detect the PHP framework from project files.
pub fn detect_framework(dir: &Path) -> String {
    // Laravel: has artisan file + composer.json with laravel/framework
    if dir.join("artisan").exists() {
        if let Ok(composer) = std::fs::read_to_string(dir.join("composer.json")) {
            if composer.contains("laravel/framework") {
                return "laravel".into();
            }
        }
        return "laravel".into(); // artisan present = likely Laravel
    }

    // Symfony: has bin/console + composer.json with symfony/framework-bundle
    if dir.join("bin/console").exists() {
        if let Ok(composer) = std::fs::read_to_string(dir.join("composer.json")) {
            if composer.contains("symfony/framework-bundle") {
                return "symfony".into();
            }
        }
    }

    // WordPress: has wp-config.php or wp-load.php
    if dir.join("wp-config.php").exists() || dir.join("wp-load.php").exists() {
        return "wordpress".into();
    }

    // Slim: composer.json with slim/slim
    if let Ok(composer) = std::fs::read_to_string(dir.join("composer.json")) {
        if composer.contains("slim/slim") { return "slim".into(); }
        if composer.contains("cakephp/cakephp") { return "cakephp".into(); }
        if composer.contains("codeigniter4/framework") { return "codeigniter".into(); }
        if composer.contains("yiisoft/yii2") { return "yii2".into(); }
    }

    // Default: vanilla PHP
    "vanilla".into()
}

/// Detect the entry point for the app.
fn detect_entry_point(dir: &Path, framework: &str) -> String {
    match framework {
        "laravel" | "symfony" | "slim" => {
            if dir.join("public/index.php").exists() {
                "public/index.php".into()
            } else {
                "index.php".into()
            }
        }
        "wordpress" => "index.php".into(),
        _ => {
            if dir.join("public/index.php").exists() {
                "public/index.php".into()
            } else if dir.join("web/index.php").exists() {
                "web/index.php".into()
            } else {
                "index.php".into()
            }
        }
    }
}

/// Detect the document root.
fn detect_docroot(dir: &Path, framework: &str) -> String {
    match framework {
        "laravel" | "slim" => "public".into(),
        "symfony" => {
            if dir.join("public").exists() { "public".into() }
            else { "web".into() }
        }
        "wordpress" => ".".into(),
        _ => {
            if dir.join("public").exists() { "public".into() }
            else if dir.join("web").exists() { "web".into() }
            else { ".".into() }
        }
    }
}

/// Detect required PHP extensions from composer.json.
fn detect_extensions(dir: &Path) -> Vec<String> {
    let mut extensions = Vec::new();
    if let Ok(composer) = std::fs::read_to_string(dir.join("composer.json")) {
        // Simple detection from require keys.
        let ext_names = [
            "pdo_mysql", "pdo_pgsql", "pdo_sqlite", "redis", "gd",
            "mbstring", "json", "xml", "curl", "openssl", "bcmath",
            "intl", "zip", "fileinfo", "exif", "iconv",
        ];
        for ext in &ext_names {
            let key = format!("\"ext-{}\"", ext);
            if composer.contains(&key) {
                extensions.push(ext.to_string());
            }
        }
    }
    extensions
}

/// Detect required backing services from project configuration.
fn detect_services(dir: &Path) -> ServicesSection {
    let mut services = ServicesSection::default();

    if let Ok(composer) = std::fs::read_to_string(dir.join("composer.json")) {
        if composer.contains("pdo_mysql") || composer.contains("doctrine/dbal")
            || composer.contains("illuminate/database") {
            services.mysql = true;
        }
        if composer.contains("pdo_pgsql") {
            services.postgres = true;
        }
        if composer.contains("predis/predis") || composer.contains("ext-redis") {
            services.redis = true;
        }
    }

    // Check .env for database configuration hints.
    if let Ok(env_content) = std::fs::read_to_string(dir.join(".env")) {
        if env_content.contains("DB_CONNECTION=mysql") {
            services.mysql = true;
        }
        if env_content.contains("DB_CONNECTION=pgsql") {
            services.postgres = true;
        }
        if env_content.contains("REDIS_HOST") || env_content.contains("REDIS_URL") {
            services.redis = true;
        }
    }

    services
}

// ── Simple TOML Parser ──────────────────────────────────────────────────────

/// Parse a simple Appfile.toml. Handles the subset we need:
/// sections, string values, integer values, boolean values, string arrays.
fn parse_appfile_toml(input: &str) -> Result<Appfile, String> {
    let mut app_name = String::new();
    let mut app_framework = String::new();
    let mut app_entry = default_entry();
    let mut app_docroot = default_docroot();
    let mut php_memory = default_memory_limit();
    let mut php_max_time = default_max_execution_time();
    let mut php_preload: Option<String> = None;
    let mut php_extensions: Vec<String> = Vec::new();
    let mut php_ini: HashMap<String, String> = HashMap::new();
    let mut workers: u16 = 0;
    let mut env: HashMap<String, String> = HashMap::new();
    let mut services = ServicesSection::default();

    let mut current_section = "";

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim();
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim();
            let value = line[eq + 1..].trim();
            let value_unquoted = value.trim_matches('"').trim_matches('\'');

            match current_section {
                "app" => match key {
                    "name" => app_name = value_unquoted.to_string(),
                    "framework" => app_framework = value_unquoted.to_string(),
                    "entry" => app_entry = value_unquoted.to_string(),
                    "docroot" | "root" => app_docroot = value_unquoted.to_string(),
                    _ => {}
                },
                "php" => match key {
                    "memory_limit" => php_memory = value_unquoted.to_string(),
                    "max_execution_time" => php_max_time = value_unquoted.parse().unwrap_or(30),
                    "preload" => php_preload = Some(value_unquoted.to_string()),
                    "extensions" => {
                        // Parse simple array: ["a", "b", "c"]
                        let trimmed = value.trim_start_matches('[').trim_end_matches(']');
                        php_extensions = trimmed
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    _ => { php_ini.insert(key.to_string(), value_unquoted.to_string()); }
                },
                "resources" => match key {
                    "workers" => workers = value_unquoted.parse().unwrap_or(0),
                    _ => {}
                },
                "env" => {
                    env.insert(key.to_string(), value_unquoted.to_string());
                }
                "services" => match key {
                    "mysql" => services.mysql = value_unquoted == "true",
                    "postgres" | "postgresql" => services.postgres = value_unquoted == "true",
                    "redis" => services.redis = value_unquoted == "true",
                    _ => {}
                },
                _ => {}
            }
        }
    }

    if app_name.is_empty() {
        return Err("Missing [app] name in Appfile.toml".into());
    }

    Ok(Appfile {
        app: AppSection {
            name: app_name,
            framework: app_framework,
            entry: app_entry,
            docroot: app_docroot,
        },
        php: PhpSection {
            memory_limit: php_memory,
            max_execution_time: php_max_time,
            preload: php_preload,
            extensions: php_extensions,
            ini: php_ini,
        },
        resources: ResourcesSection { workers },
        env,
        services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vanilla() {
        let dir = std::env::temp_dir().join("phprs-test-detect-vanilla");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.php"), "<?php echo 'hi';").unwrap();

        assert_eq!(detect_framework(&dir), "vanilla");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_laravel() {
        let dir = std::env::temp_dir().join("phprs-test-detect-laravel");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("public")).unwrap();
        std::fs::write(dir.join("artisan"), "#!/usr/bin/env php").unwrap();
        std::fs::write(dir.join("composer.json"), r#"{"require":{"laravel/framework":"^11.0"}}"#).unwrap();
        std::fs::write(dir.join("public/index.php"), "<?php").unwrap();

        assert_eq!(detect_framework(&dir), "laravel");

        let appfile = Appfile::detect(&dir, "mylaravel");
        assert_eq!(appfile.app.framework, "laravel");
        assert_eq!(appfile.app.entry, "public/index.php");
        assert_eq!(appfile.app.docroot, "public");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_wordpress() {
        let dir = std::env::temp_dir().join("phprs-test-detect-wp");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("wp-config.php"), "<?php").unwrap();
        std::fs::write(dir.join("index.php"), "<?php").unwrap();

        assert_eq!(detect_framework(&dir), "wordpress");

        let appfile = Appfile::detect(&dir, "myblog");
        assert_eq!(appfile.app.entry, "index.php");
        assert_eq!(appfile.app.docroot, ".");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_appfile_toml() {
        let toml = r#"
[app]
name = "myapp"
framework = "laravel"
entry = "public/index.php"
docroot = "public"

[php]
memory_limit = "256M"
max_execution_time = 60
extensions = ["pdo_mysql", "redis"]

[resources]
workers = 4

[env]
APP_ENV = "production"
APP_KEY = "base64:abc"

[services]
mysql = true
redis = true
"#;

        let appfile = Appfile::parse(toml).unwrap();
        assert_eq!(appfile.app.name, "myapp");
        assert_eq!(appfile.app.framework, "laravel");
        assert_eq!(appfile.php.memory_limit, "256M");
        assert_eq!(appfile.php.max_execution_time, 60);
        assert_eq!(appfile.php.extensions, vec!["pdo_mysql", "redis"]);
        assert_eq!(appfile.resources.workers, 4);
        assert_eq!(appfile.env.get("APP_ENV").unwrap(), "production");
        assert!(appfile.services.mysql);
        assert!(appfile.services.redis);
        assert!(!appfile.services.postgres);
    }

    #[test]
    fn test_parse_appfile_minimal() {
        let toml = r#"
[app]
name = "simple"
"#;

        let appfile = Appfile::parse(toml).unwrap();
        assert_eq!(appfile.app.name, "simple");
        assert_eq!(appfile.app.entry, "public/index.php");
        assert_eq!(appfile.php.memory_limit, "128M");
    }

    #[test]
    fn test_parse_appfile_missing_name() {
        let toml = r#"
[app]
framework = "laravel"
"#;
        assert!(Appfile::parse(toml).is_err());
    }

    #[test]
    fn test_to_toml_roundtrip() {
        let appfile = Appfile {
            app: AppSection {
                name: "testapp".into(),
                framework: "laravel".into(),
                entry: "public/index.php".into(),
                docroot: "public".into(),
            },
            php: PhpSection {
                memory_limit: "256M".into(),
                max_execution_time: 60,
                preload: Some("preload.php".into()),
                extensions: vec!["pdo_mysql".into()],
                ini: HashMap::new(),
            },
            resources: ResourcesSection { workers: 4 },
            env: HashMap::from([("APP_ENV".into(), "production".into())]),
            services: ServicesSection { mysql: true, postgres: false, redis: true },
        };

        let toml = appfile.to_toml();
        assert!(toml.contains("name = \"testapp\""));
        assert!(toml.contains("framework = \"laravel\""));
        assert!(toml.contains("memory_limit = \"256M\""));
        assert!(toml.contains("workers = 4"));
        assert!(toml.contains("mysql = true"));
        assert!(toml.contains("redis = true"));
        assert!(toml.contains("preload = \"preload.php\""));

        // Re-parse and verify.
        let reparsed = Appfile::parse(&toml).unwrap();
        assert_eq!(reparsed.app.name, "testapp");
        assert_eq!(reparsed.php.max_execution_time, 60);
        assert_eq!(reparsed.resources.workers, 4);
    }

    #[test]
    fn test_detect_extensions_from_composer() {
        let dir = std::env::temp_dir().join("phprs-test-detect-ext");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("composer.json"),
            r#"{"require":{"ext-pdo_mysql":"*","ext-redis":"*","ext-gd":"*"}}"#,
        ).unwrap();

        let exts = detect_extensions(&dir);
        assert!(exts.contains(&"pdo_mysql".to_string()));
        assert!(exts.contains(&"redis".to_string()));
        assert!(exts.contains(&"gd".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
