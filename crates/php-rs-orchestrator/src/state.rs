//! Persistent state for the orchestrator — app registry, port allocation.
//!
//! State is stored as JSON at `~/.php-rs/state.json`. All mutations go through
//! `PlatformState` which handles load/save atomically.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The root state object persisted to disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformState {
    /// All registered applications keyed by name.
    pub apps: HashMap<String, AppState>,
    /// Next port to assign to a new app.
    pub next_port: u16,
    /// Base directory for app deployments (default: ~/.php-rs/apps/).
    pub apps_dir: String,
}

/// Per-application state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub name: String,
    /// Application root directory (where source lives).
    pub root: String,
    /// Entry script relative to root (e.g. "public/index.php").
    pub entry: String,
    /// Document root relative to app root (e.g. "public").
    pub docroot: String,
    /// Assigned port for this app's HTTP server.
    pub port: u16,
    /// PID of the running php-rs-app process, if any.
    pub pid: Option<u32>,
    /// Environment variables injected into the app process.
    pub env: HashMap<String, String>,
    /// Worker count (0 = auto/CPU cores).
    pub workers: u16,
    /// ISO-8601 timestamp when the app was created.
    pub created_at: String,
    /// List of deployed releases.
    pub releases: Vec<Release>,
    /// Currently active release version, if any.
    pub current_release: Option<u64>,
    /// Scaling configuration.
    #[serde(default)]
    pub scaling: ScalingConfig,
    /// Additional instance PIDs/ports for scaled apps.
    #[serde(default)]
    pub instances: Vec<AppInstance>,
    /// Cron jobs for this app.
    #[serde(default)]
    pub cron_jobs: Vec<crate::cron::CronJob>,
    /// Worker process configurations.
    #[serde(default)]
    pub worker_configs: Vec<crate::workers::WorkerConfig>,
}

/// Scaling configuration for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingConfig {
    /// Minimum number of instances (default: 1).
    pub min_instances: u16,
    /// Maximum number of instances (default: 1 = no auto-scaling).
    pub max_instances: u16,
    /// Target response time in milliseconds (triggers scale-up if exceeded).
    pub target_response_ms: u64,
    /// Cooldown in seconds before scaling down an idle instance.
    pub cooldown_secs: u64,
}

impl Default for ScalingConfig {
    fn default() -> Self {
        Self {
            min_instances: 1,
            max_instances: 1,
            target_response_ms: 500,
            cooldown_secs: 300,
        }
    }
}

/// An additional instance of an app (for scaling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInstance {
    pub port: u16,
    pub pid: Option<u32>,
}

/// A single deployment release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    /// Monotonically increasing version number.
    pub version: u64,
    /// Absolute path to the extracted release directory.
    pub path: String,
    /// ISO-8601 timestamp of deployment.
    pub deployed_at: String,
}

impl PlatformState {
    /// Load state from disk, or create a new empty state.
    pub fn load() -> Self {
        Self::load_from(&state_file_path())
    }

    /// Load state from a specific path.
    pub fn load_from(path: &Path) -> Self {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(json) => match serde_json::from_str(&json) {
                    Ok(state) => return state,
                    Err(e) => {
                        eprintln!("Warning: corrupt state file {}: {}", path.display(), e);
                    }
                },
                Err(e) => {
                    eprintln!("Warning: cannot read state file {}: {}", path.display(), e);
                }
            }
        }
        let dir = path.parent()
            .map(|p| p.join("apps"))
            .unwrap_or_else(|| PathBuf::from("apps"));
        Self {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: dir.to_string_lossy().to_string(),
        }
    }

    /// Create a fresh empty state (used by `load()` when no state file exists).
    #[allow(dead_code)]
    fn new() -> Self {
        let apps_dir = state_dir().join("apps");
        Self {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: apps_dir.to_string_lossy().to_string(),
        }
    }

    /// Save state to disk atomically (write to temp file, then rename).
    pub fn save(&self) -> Result<(), String> {
        self.save_to(&state_file_path())
    }

    /// Save state to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Cannot create state directory {}: {}", dir.display(), e))?;

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Cannot serialize state: {}", e))?;

        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| format!("Cannot write {}: {}", tmp_path.display(), e))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("Cannot rename {}: {}", tmp_path.display(), e))?;

        Ok(())
    }

    /// Allocate the next available port and increment the counter.
    pub fn allocate_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port += 1;
        // Skip well-known ports and wrap around if needed.
        if self.next_port < 8001 {
            self.next_port = 8001;
        }
        port
    }

    /// Get an app by name.
    pub fn get_app(&self, name: &str) -> Option<&AppState> {
        self.apps.get(name)
    }

    /// Get a mutable reference to an app by name.
    pub fn get_app_mut(&mut self, name: &str) -> Option<&mut AppState> {
        self.apps.get_mut(name)
    }

    /// Directory where releases are stored for an app.
    pub fn app_releases_dir(&self, app_name: &str) -> PathBuf {
        Path::new(&self.apps_dir).join(app_name).join("releases")
    }

    /// Symlink path for the "current" release of an app.
    pub fn app_current_link(&self, app_name: &str) -> PathBuf {
        Path::new(&self.apps_dir).join(app_name).join("current")
    }
}

impl AppState {
    /// Check if the app process is currently running (by checking if PID exists).
    pub fn is_running(&self) -> bool {
        if let Some(pid) = self.pid {
            process_alive(pid)
        } else {
            false
        }
    }

    /// Get the effective app root — either from a deployed release or the static root.
    #[allow(dead_code)]
    pub fn effective_root(&self) -> &str {
        &self.root
    }

    /// Build environment variables for spawning the app process.
    /// Decrypts any encrypted values (ENC: prefix) using the platform master key.
    pub fn build_process_env(&self) -> HashMap<String, String> {
        // Decrypt env vars using the secret store.
        let mut env = match crate::secrets::SecretStore::new().decrypt_env(&self.env) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                eprintln!("Warning: failed to decrypt env vars for '{}': {}", self.name, e);
                self.env.clone()
            }
        };
        env.insert("APP_PORT".into(), self.port.to_string());
        env.insert("APP_ROOT".into(), self.root.clone());
        env.insert("APP_ENTRY".into(), self.entry.clone());
        env.insert("APP_DOCROOT".into(), self.docroot.clone());
        if self.workers > 0 {
            env.insert("APP_WORKERS".into(), self.workers.to_string());
        }
        env.insert("APP_NAME".into(), self.name.clone());
        env
    }
}

/// Check if a process with the given PID is still alive.
pub fn process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks existence without sending a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Get the state directory (~/.php-rs/).
fn state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PHPRS_STATE_DIR") {
        PathBuf::from(dir)
    } else if let Some(home) = home_dir() {
        home.join(".php-rs")
    } else {
        PathBuf::from("/tmp/.php-rs")
    }
}

/// Get the state file path (~/.php-rs/state.json).
fn state_file_path() -> PathBuf {
    state_dir().join("state.json")
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
}

/// Get current timestamp as ISO-8601 string.
pub fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple UTC timestamp without chrono dependency.
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since epoch to Y-M-D (simplified).
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Public wrapper for days_to_ymd (used by cron module).
pub fn days_to_ymd_pub(days: u64) -> (u64, u64, u64) {
    days_to_ymd(days)
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant.
    let z = days_since_epoch as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_state_new() {
        let nonexistent = std::env::temp_dir().join("phprs-never-exists-12345/state.json");
        let state = PlatformState::load_from(&nonexistent);
        assert_eq!(state.next_port, 8001);
        assert!(state.apps.is_empty());
    }

    #[test]
    fn test_allocate_port() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test-apps".into(),
        };
        assert_eq!(state.allocate_port(), 8001);
        assert_eq!(state.allocate_port(), 8002);
        assert_eq!(state.allocate_port(), 8003);
    }

    #[test]
    fn test_app_state_build_env() {
        let app = AppState {
            name: "myapp".into(),
            root: "/apps/myapp".into(),
            entry: "public/index.php".into(),
            docroot: "public".into(),
            port: 8001,
            pid: None,
            env: HashMap::from([("DATABASE_URL".into(), "mysql://localhost/myapp".into())]),
            workers: 4,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };
        let env = app.build_process_env();
        assert_eq!(env.get("APP_PORT").unwrap(), "8001");
        assert_eq!(env.get("APP_ROOT").unwrap(), "/apps/myapp");
        assert_eq!(env.get("APP_ENTRY").unwrap(), "public/index.php");
        assert_eq!(env.get("APP_NAME").unwrap(), "myapp");
        assert_eq!(env.get("DATABASE_URL").unwrap(), "mysql://localhost/myapp");
        assert_eq!(env.get("APP_WORKERS").unwrap(), "4");
    }

    #[test]
    fn test_app_state_not_running() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 9999,
            pid: None,
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };
        assert!(!app.is_running());
    }

    #[test]
    fn test_app_state_dead_pid() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 9999,
            pid: Some(999999999), // Very unlikely to exist.
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };
        assert!(!app.is_running());
    }

    #[test]
    fn test_now_iso8601_format() {
        let ts = now_iso8601();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn test_days_to_ymd() {
        // 2024-01-01 = 19723 days since 1970-01-01
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));

        // 1970-01-01 = day 0
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_state_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("phprs-test-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("state.json");

        let mut state = PlatformState::load_from(&state_path);
        let port = state.allocate_port();
        state.apps.insert("testapp".into(), AppState {
            name: "testapp".into(),
            root: "/apps/testapp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port,
            pid: None,
            env: HashMap::new(),
            workers: 2,
            created_at: now_iso8601(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });
        state.save_to(&state_path).unwrap();

        let loaded = PlatformState::load_from(&state_path);
        assert!(loaded.apps.contains_key("testapp"));
        assert_eq!(loaded.apps["testapp"].port, 8001);
        assert_eq!(loaded.next_port, 8002);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
