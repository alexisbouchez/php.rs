use std::path::{Path, PathBuf};

/// Composer configuration, loaded from composer.json "config" section
/// and global ~/.composer/config.json.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory for installed packages (default: "vendor")
    pub vendor_dir: String,
    /// Cache directory (default: ~/.cache/composer or ~/.composer/cache)
    pub cache_dir: PathBuf,
    /// Minimum stability for packages (default: "stable")
    pub minimum_stability: String,
    /// Whether to prefer stable versions (default: true)
    pub prefer_stable: bool,
    /// Whether to prefer dist (archive) over source (VCS)
    pub prefer_dist: bool,
    /// Whether to prefer source over dist
    pub prefer_source: bool,
    /// Sort packages alphabetically in require/require-dev
    pub sort_packages: bool,
    /// Working directory
    pub working_dir: PathBuf,
}

impl Config {
    pub fn new(working_dir: &Path) -> Self {
        let cache_dir = dirs_cache_dir();
        Config {
            vendor_dir: "vendor".to_string(),
            cache_dir,
            minimum_stability: "stable".to_string(),
            prefer_stable: true,
            prefer_dist: true,
            prefer_source: false,
            sort_packages: false,
            working_dir: working_dir.to_path_buf(),
        }
    }

    /// Get the absolute path to the vendor directory.
    pub fn vendor_path(&self) -> PathBuf {
        if Path::new(&self.vendor_dir).is_absolute() {
            PathBuf::from(&self.vendor_dir)
        } else {
            self.working_dir.join(&self.vendor_dir)
        }
    }

    /// Get the path to composer.json in the working directory.
    pub fn composer_json_path(&self) -> PathBuf {
        self.working_dir.join("composer.json")
    }

    /// Get the path to composer.lock in the working directory.
    pub fn composer_lock_path(&self) -> PathBuf {
        self.working_dir.join("composer.lock")
    }

    /// Load config overrides from a composer.json "config" section.
    pub fn merge_json(&mut self, config: &serde_json::Value) {
        if let Some(obj) = config.as_object() {
            if let Some(v) = obj.get("vendor-dir").and_then(|v| v.as_str()) {
                self.vendor_dir = v.to_string();
            }
            if let Some(v) = obj.get("cache-dir").and_then(|v| v.as_str()) {
                self.cache_dir = PathBuf::from(v);
            }
            if let Some(v) = obj.get("sort-packages").and_then(|v| v.as_bool()) {
                self.sort_packages = v;
            }
            if let Some(v) = obj.get("prefer-stable").and_then(|v| v.as_bool()) {
                self.prefer_stable = v;
            }
        }
    }
}

fn dirs_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("COMPOSER_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = home_dir() {
        let composer_cache = home.join(".composer").join("cache");
        if composer_cache.exists() {
            return composer_cache;
        }
        // XDG on Linux
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(xdg).join("composer");
        }
        #[cfg(target_os = "macos")]
        {
            return home.join("Library").join("Caches").join("composer");
        }
        #[cfg(not(target_os = "macos"))]
        {
            return home.join(".cache").join("composer");
        }
    }
    PathBuf::from("/tmp/composer-cache")
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

/// Authentication configuration read from ~/.composer/auth.json.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Token-based auth: hostname → token
    pub bearer: std::collections::HashMap<String, String>,
    /// HTTP basic auth: hostname → (username, password)
    pub http_basic: std::collections::HashMap<String, (String, String)>,
    /// GitHub OAuth tokens
    pub github_oauth: std::collections::HashMap<String, String>,
    /// GitLab tokens
    pub gitlab_token: std::collections::HashMap<String, String>,
}

impl AuthConfig {
    /// Load auth config from ~/.composer/auth.json.
    pub fn load() -> Self {
        let mut config = AuthConfig::default();

        let path = match home_dir() {
            Some(home) => home.join(".composer").join("auth.json"),
            None => return config,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return config,
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return config,
        };

        if let Some(obj) = json.as_object() {
            // GitHub OAuth
            if let Some(gh) = obj.get("github-oauth").and_then(|v| v.as_object()) {
                for (host, token) in gh {
                    if let Some(t) = token.as_str() {
                        config.github_oauth.insert(host.clone(), t.to_string());
                    }
                }
            }

            // GitLab tokens
            if let Some(gl) = obj.get("gitlab-token").and_then(|v| v.as_object()) {
                for (host, token) in gl {
                    if let Some(t) = token.as_str() {
                        config.gitlab_token.insert(host.clone(), t.to_string());
                    }
                }
            }

            // HTTP basic auth
            if let Some(basic) = obj.get("http-basic").and_then(|v| v.as_object()) {
                for (host, creds) in basic {
                    if let Some(creds_obj) = creds.as_object() {
                        let username = creds_obj
                            .get("username")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let password = creds_obj
                            .get("password")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        config.http_basic.insert(host.clone(), (username, password));
                    }
                }
            }

            // Bearer tokens
            if let Some(bearer) = obj.get("bearer").and_then(|v| v.as_object()) {
                for (host, token) in bearer {
                    if let Some(t) = token.as_str() {
                        config.bearer.insert(host.clone(), t.to_string());
                    }
                }
            }
        }

        config
    }

    /// Get a token for a given hostname (checks GitHub OAuth, bearer, etc.).
    pub fn token_for_host(&self, host: &str) -> Option<&str> {
        if let Some(t) = self.github_oauth.get(host) {
            return Some(t);
        }
        if let Some(t) = self.gitlab_token.get(host) {
            return Some(t);
        }
        if let Some(t) = self.bearer.get(host) {
            return Some(t);
        }
        None
    }
}

impl Config {
    /// Get the global composer home directory (~/.composer).
    pub fn global_home() -> PathBuf {
        if let Ok(dir) = std::env::var("COMPOSER_HOME") {
            return PathBuf::from(dir);
        }
        home_dir()
            .map(|h| h.join(".composer"))
            .unwrap_or_else(|| PathBuf::from("/tmp/.composer"))
    }

    /// Get the global vendor directory (~/.composer/vendor).
    pub fn global_vendor_path() -> PathBuf {
        Self::global_home().join("vendor")
    }
}
