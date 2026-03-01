//! Process management — spawn, stop, and monitor `php-rs-app` processes.
//!
//! Features:
//! - Process spawning with isolation (rlimits, uid/gid, cgroups, network)
//! - Graceful shutdown (SIGTERM → wait → SIGKILL)
//! - Health checking (/_health, /_ready endpoints)
//! - Crash detection with automatic restart and exponential backoff
//! - Crash counter per app (suspend after repeated failures)
//! - OOM detection via cgroup memory events and dmesg

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::isolation::IsolationConfig;
use crate::state::{self, AppState, PlatformState};

/// Maximum consecutive crashes before an app is suspended.
const MAX_CRASH_COUNT: u32 = 5;

/// Crash tracking state for the watchdog.
#[derive(Debug, Clone)]
pub struct CrashTracker {
    /// Per-app crash counters and last crash times.
    apps: HashMap<String, CrashState>,
}

/// Per-app crash tracking.
#[derive(Debug, Clone)]
struct CrashState {
    /// Number of consecutive crashes (resets on successful health check).
    crash_count: u32,
    /// When the last crash was detected.
    last_crash: Option<Instant>,
    /// Whether the app is suspended due to repeated crashes.
    suspended: bool,
}

impl Default for CrashState {
    fn default() -> Self {
        Self {
            crash_count: 0,
            last_crash: None,
            suspended: false,
        }
    }
}

impl CrashTracker {
    /// Create a new crash tracker.
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
        }
    }

    /// Record a crash for an app. Returns the crash count and whether the app
    /// should be suspended.
    pub fn record_crash(&mut self, app_name: &str) -> (u32, bool) {
        let state = self.apps.entry(app_name.to_string()).or_default();
        state.crash_count += 1;
        state.last_crash = Some(Instant::now());

        if state.crash_count >= MAX_CRASH_COUNT {
            state.suspended = true;
        }

        (state.crash_count, state.suspended)
    }

    /// Get the backoff duration for the next restart attempt.
    /// Uses exponential backoff: 1s, 2s, 4s, 8s, 16s (capped at 30s).
    pub fn backoff_duration(&self, app_name: &str) -> Duration {
        let count = self.apps
            .get(app_name)
            .map(|s| s.crash_count)
            .unwrap_or(0);
        let secs = (1u64 << count.min(4)).min(30); // 1, 2, 4, 8, 16, capped at 30
        Duration::from_secs(secs)
    }

    /// Check if an app is suspended due to repeated crashes.
    pub fn is_suspended(&self, app_name: &str) -> bool {
        self.apps
            .get(app_name)
            .map(|s| s.suspended)
            .unwrap_or(false)
    }

    /// Reset crash counter for an app (e.g., after a successful health check
    /// or manual restart).
    pub fn reset(&mut self, app_name: &str) {
        if let Some(state) = self.apps.get_mut(app_name) {
            state.crash_count = 0;
            state.suspended = false;
            state.last_crash = None;
        }
    }

    /// Unsuspend an app (manual override).
    pub fn unsuspend(&mut self, app_name: &str) {
        if let Some(state) = self.apps.get_mut(app_name) {
            state.suspended = false;
            state.crash_count = 0;
            state.last_crash = None;
        }
    }

    /// Get the crash count for an app.
    pub fn crash_count(&self, app_name: &str) -> u32 {
        self.apps
            .get(app_name)
            .map(|s| s.crash_count)
            .unwrap_or(0)
    }

    /// Check if enough time has passed since the last crash to attempt restart
    /// (respecting backoff).
    pub fn can_restart(&self, app_name: &str) -> bool {
        if self.is_suspended(app_name) {
            return false;
        }
        let state = match self.apps.get(app_name) {
            Some(s) => s,
            None => return true,
        };
        match state.last_crash {
            Some(last) => last.elapsed() >= self.backoff_duration(app_name),
            None => true,
        }
    }
}

/// Result of starting an app process.
pub enum StartResult {
    /// Process started successfully with the given PID.
    Started(u32),
    /// App is already running.
    AlreadyRunning(u32),
    /// Failed to start.
    Failed(String),
}

/// Result of stopping an app process.
pub enum StopResult {
    /// Process stopped gracefully.
    Stopped,
    /// App was not running.
    NotRunning,
    /// Failed to stop (had to SIGKILL).
    Killed,
    /// Failed completely.
    Failed(String),
}

/// Find the `php-rs-app` binary path (public API for scaling module).
pub fn find_app_binary_pub() -> Result<String, String> {
    find_app_binary()
}

/// Find the `php-rs-app` binary path.
/// Searches in order: same directory as `php-rs-ctl`, PATH, cargo target directory.
fn find_app_binary() -> Result<String, String> {
    // 1. Check alongside the current binary.
    if let Ok(self_path) = std::env::current_exe() {
        if let Some(dir) = self_path.parent() {
            let candidate = dir.join("php-rs-app");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
    }

    // 2. Check if it's in PATH.
    if let Ok(output) = Command::new("which").arg("php-rs-app").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    Err("Cannot find php-rs-app binary. Build it with: cargo build -p php-rs-sapi-paas".into())
}

/// Start an app process. Returns the child PID.
pub fn start_app(app: &AppState) -> StartResult {
    // Check if already running.
    if app.is_running() {
        return StartResult::AlreadyRunning(app.pid.unwrap());
    }

    let binary = match find_app_binary() {
        Ok(b) => b,
        Err(e) => return StartResult::Failed(e),
    };

    let env = app.build_process_env();
    let isolation = IsolationConfig::from_env(&env);

    // Create per-app temp directory.
    if let Some(tmpdir) = env.get("TMPDIR") {
        if let Err(e) = std::fs::create_dir_all(tmpdir) {
            eprintln!("Warning: cannot create temp dir {}: {}", tmpdir, e);
        }
    }

    // Spawn the process with stdout/stderr piped for log capture.
    let logs_dir = crate::logs::default_logs_dir();
    let mut cmd = Command::new(&binary);
    cmd.envs(&env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Apply pre-exec isolation (rlimits, uid/gid) if configured.
    if isolation.has_settings() {
        let iso = isolation.clone();
        // SAFETY: pre_exec runs after fork but before exec. We only call
        // async-signal-safe operations (setrlimit, setuid, setgid).
        unsafe {
            cmd.pre_exec(move || {
                iso.apply().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
        }
    }

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();

            // Apply cgroup limits (Linux only, from parent process).
            #[cfg(target_os = "linux")]
            if isolation.cgroup_path.is_some() {
                if let Err(e) = isolation.setup_cgroup(pid) {
                    eprintln!("Warning: cgroup setup failed for '{}': {}", app.name, e);
                }
            }

            // Apply network isolation rules (Linux only, requires iptables + root).
            #[cfg(target_os = "linux")]
            if isolation.network.enabled {
                if let Some(uid) = isolation.uid {
                    if let Err(e) = crate::isolation::apply_network_rules(&isolation.network, uid) {
                        eprintln!("Warning: network isolation failed for '{}': {}", app.name, e);
                    }
                } else {
                    eprintln!(
                        "Warning: network isolation requires APP_UID for '{}' (skipped)",
                        app.name
                    );
                }
            }

            // Start log capture threads for stdout/stderr.
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                crate::logs::start_log_capture(
                    app.name.clone(),
                    logs_dir,
                    stdout,
                    stderr,
                );
            }

            // Detach the child — let it run independently.
            // We just track the PID and check health.
            std::mem::forget(child);
            StartResult::Started(pid)
        }
        Err(e) => StartResult::Failed(format!("Failed to spawn {}: {}", binary, e)),
    }
}

/// Stop an app process gracefully (SIGTERM, then SIGKILL after timeout).
pub fn stop_app(app: &AppState, timeout: Duration) -> StopResult {
    let pid = match app.pid {
        Some(pid) if state::process_alive(pid) => pid,
        _ => return StopResult::NotRunning,
    };

    // Clean up network isolation rules before stopping.
    #[cfg(target_os = "linux")]
    {
        let isolation = IsolationConfig::from_env(&app.env);
        if isolation.network.enabled {
            if let Some(uid) = isolation.uid {
                if let Err(e) = crate::isolation::remove_network_rules(&isolation.network, uid) {
                    eprintln!("Warning: network rule cleanup failed for '{}': {}", app.name, e);
                }
            }
        }
    }

    // Send SIGTERM for graceful shutdown.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    // Wait for process to exit.
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !state::process_alive(pid) {
            return StopResult::Stopped;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Process didn't exit in time — SIGKILL.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }

    // Wait briefly for SIGKILL to take effect.
    std::thread::sleep(Duration::from_millis(200));
    if !state::process_alive(pid) {
        StopResult::Killed
    } else {
        StopResult::Failed(format!("Process {} did not respond to SIGKILL", pid))
    }
}

/// Restart an app: stop the old process, start a new one.
#[allow(dead_code)]
pub fn restart_app(app: &mut AppState, timeout: Duration) -> StartResult {
    if app.is_running() {
        stop_app(app, timeout);
    }
    app.pid = None;

    match start_app(app) {
        StartResult::Started(pid) => {
            app.pid = Some(pid);
            StartResult::Started(pid)
        }
        other => other,
    }
}

/// Check if an app is healthy by sending a GET to /_health.
pub fn health_check(app: &AppState) -> Result<bool, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{}", app.port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Bad address: {}", e))?,
        Duration::from_secs(2),
    )
    .map_err(|e| format!("Cannot connect to {}: {}", addr, e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();

    let request = "GET /_health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    // Check for "200" in the response status line.
    Ok(response.starts_with("HTTP/1.1 200"))
}

/// Wait for an app to become ready (poll /_ready until 200 or timeout).
pub fn wait_for_ready(app: &AppState, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(true) = health_check_ready(app) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Check the /_ready endpoint.
fn health_check_ready(app: &AppState) -> Result<bool, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{}", app.port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Bad address: {}", e))?,
        Duration::from_secs(2),
    )
    .map_err(|e| format!("Cannot connect: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let request = "GET /_ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    Ok(response.starts_with("HTTP/1.1 200"))
}

/// Monitor all apps — restart crashed processes with backoff and check disk quotas.
/// Returns a list of (app_name, action_taken) for logging.
pub fn monitor_apps(state: &mut PlatformState) -> Vec<(String, String)> {
    monitor_apps_with_tracker(state, &mut CrashTracker::new())
}

/// Monitor all apps using a provided crash tracker for backoff/suspension.
/// This variant allows the tracker to persist across monitoring cycles.
pub fn monitor_apps_with_tracker(
    state: &mut PlatformState,
    tracker: &mut CrashTracker,
) -> Vec<(String, String)> {
    let mut actions = Vec::new();

    let app_names: Vec<String> = state.apps.keys().cloned().collect();
    for name in app_names {
        let app = &state.apps[&name];

        // Check for crashed processes.
        if app.pid.is_some() && !app.is_running() {
            let crash_reason = detect_crash_reason(app);
            let (crash_count, suspended) = tracker.record_crash(&name);

            if suspended {
                state.apps.get_mut(&name).unwrap().pid = None;
                actions.push((
                    name.clone(),
                    format!(
                        "{} — SUSPENDED after {} consecutive crashes (manual restart required)",
                        crash_reason, crash_count
                    ),
                ));
                continue;
            }

            if !tracker.can_restart(&name) {
                let backoff = tracker.backoff_duration(&name);
                actions.push((
                    name.clone(),
                    format!(
                        "{} — waiting {}s before restart (crash #{}/{})",
                        crash_reason,
                        backoff.as_secs(),
                        crash_count,
                        MAX_CRASH_COUNT
                    ),
                ));
                continue;
            }

            actions.push((
                name.clone(),
                format!("{} — restarting (crash #{}/{})", crash_reason, crash_count, MAX_CRASH_COUNT),
            ));

            let app = state.apps.get(&name).unwrap().clone();
            match start_app(&app) {
                StartResult::Started(pid) => {
                    state.apps.get_mut(&name).unwrap().pid = Some(pid);
                    actions.push((name, format!("restarted with PID {}", pid)));
                }
                StartResult::Failed(e) => {
                    state.apps.get_mut(&name).unwrap().pid = None;
                    actions.push((name, format!("restart failed: {}", e)));
                }
                _ => {}
            }
            continue;
        }

        // If app is running and healthy, reset crash counter.
        if app.is_running() {
            if tracker.crash_count(&name) > 0 {
                // App recovered — reset crash counter.
                tracker.reset(&name);
            }

            // Check disk quota if configured.
            let isolation = IsolationConfig::from_env(&app.env);
            if let Some(quota) = isolation.disk_quota {
                let app_dir = std::path::Path::new(&app.root);
                let (current, _, over) = crate::isolation::check_disk_quota(app_dir, quota);
                if over {
                    actions.push((
                        name.clone(),
                        format!(
                            "DISK QUOTA EXCEEDED: {} MB / {} MB",
                            current / (1024 * 1024),
                            quota / (1024 * 1024)
                        ),
                    ));
                }
            }
        }
    }

    actions
}

/// Try to determine why a process crashed.
fn detect_crash_reason(app: &AppState) -> String {
    #[cfg(target_os = "linux")]
    {
        // Check cgroup memory events for OOM.
        if let Some(uid) = app.env.get("APP_UID").and_then(|v| v.parse::<u32>().ok()) {
            let events_path = format!("/sys/fs/cgroup/phprs/app-{}/memory.events", uid);
            if let Ok(events) = std::fs::read_to_string(&events_path) {
                for line in events.lines() {
                    if line.starts_with("oom_kill ") {
                        let count: u64 = line
                            .strip_prefix("oom_kill ")
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if count > 0 {
                            return format!("OOM killed (cgroup, {} events)", count);
                        }
                    }
                }
            }
        }

        // Fallback: check dmesg for OOM kills of this PID.
        if let Some(pid) = app.pid {
            if let Ok(output) = std::process::Command::new("dmesg")
                .args(["--time-format", "reltime", "-l", "err"])
                .output()
            {
                let dmesg = String::from_utf8_lossy(&output.stdout);
                if dmesg.contains(&format!("Killed process {}", pid))
                    || dmesg.contains("oom-kill")
                {
                    return "OOM killed".into();
                }
            }
        }
    }
    let _ = app; // suppress unused warning on non-Linux
    "crashed".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_find_app_binary_returns_error_gracefully() {
        // In test environment, the binary may or may not exist.
        // Just verify it doesn't panic.
        let _ = find_app_binary();
    }

    #[test]
    fn test_stop_not_running() {
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
        match stop_app(&app, Duration::from_secs(5)) {
            StopResult::NotRunning => {} // expected
            _ => panic!("Expected NotRunning"),
        }
    }

    #[test]
    fn test_stop_dead_pid() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 9999,
            pid: Some(999999999), // Not a real process.
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
        match stop_app(&app, Duration::from_secs(1)) {
            StopResult::NotRunning => {} // expected — pid doesn't exist
            _ => panic!("Expected NotRunning for dead PID"),
        }
    }

    #[test]
    fn test_health_check_unreachable() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 59999, // Nothing should be listening here.
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
        assert!(health_check(&app).is_err());
    }

    // --- CrashTracker tests ---

    #[test]
    fn test_crash_tracker_new() {
        let tracker = CrashTracker::new();
        assert_eq!(tracker.crash_count("myapp"), 0);
        assert!(!tracker.is_suspended("myapp"));
        assert!(tracker.can_restart("myapp"));
    }

    #[test]
    fn test_crash_tracker_record_crash() {
        let mut tracker = CrashTracker::new();

        let (count, suspended) = tracker.record_crash("myapp");
        assert_eq!(count, 1);
        assert!(!suspended);

        let (count, suspended) = tracker.record_crash("myapp");
        assert_eq!(count, 2);
        assert!(!suspended);

        assert_eq!(tracker.crash_count("myapp"), 2);
    }

    #[test]
    fn test_crash_tracker_suspension_at_max() {
        let mut tracker = CrashTracker::new();

        for i in 1..MAX_CRASH_COUNT {
            let (count, suspended) = tracker.record_crash("myapp");
            assert_eq!(count, i);
            assert!(!suspended);
        }

        // The MAX_CRASH_COUNT-th crash should trigger suspension.
        let (count, suspended) = tracker.record_crash("myapp");
        assert_eq!(count, MAX_CRASH_COUNT);
        assert!(suspended);
        assert!(tracker.is_suspended("myapp"));
        assert!(!tracker.can_restart("myapp"));
    }

    #[test]
    fn test_crash_tracker_reset() {
        let mut tracker = CrashTracker::new();

        tracker.record_crash("myapp");
        tracker.record_crash("myapp");
        assert_eq!(tracker.crash_count("myapp"), 2);

        tracker.reset("myapp");
        assert_eq!(tracker.crash_count("myapp"), 0);
        assert!(!tracker.is_suspended("myapp"));
        assert!(tracker.can_restart("myapp"));
    }

    #[test]
    fn test_crash_tracker_unsuspend() {
        let mut tracker = CrashTracker::new();

        // Trigger suspension.
        for _ in 0..MAX_CRASH_COUNT {
            tracker.record_crash("myapp");
        }
        assert!(tracker.is_suspended("myapp"));

        // Unsuspend.
        tracker.unsuspend("myapp");
        assert!(!tracker.is_suspended("myapp"));
        assert_eq!(tracker.crash_count("myapp"), 0);
        assert!(tracker.can_restart("myapp"));
    }

    #[test]
    fn test_crash_tracker_backoff_duration() {
        let mut tracker = CrashTracker::new();

        // No crashes — 1s (2^0).
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(1));

        tracker.record_crash("myapp"); // crash 1 → 2^1 = 2s
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(2));

        tracker.record_crash("myapp"); // crash 2 → 2^2 = 4s
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(4));

        tracker.record_crash("myapp"); // crash 3 → 2^3 = 8s
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(8));

        tracker.record_crash("myapp"); // crash 4 → 2^4 = 16s
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(16));

        tracker.record_crash("myapp"); // crash 5 → min(5,4)=4, 2^4 = 16s (capped)
        assert_eq!(tracker.backoff_duration("myapp"), Duration::from_secs(16));
    }

    #[test]
    fn test_crash_tracker_independent_apps() {
        let mut tracker = CrashTracker::new();

        tracker.record_crash("app1");
        tracker.record_crash("app1");
        tracker.record_crash("app2");

        assert_eq!(tracker.crash_count("app1"), 2);
        assert_eq!(tracker.crash_count("app2"), 1);

        tracker.reset("app1");
        assert_eq!(tracker.crash_count("app1"), 0);
        assert_eq!(tracker.crash_count("app2"), 1); // unaffected
    }

    #[test]
    fn test_crash_tracker_can_restart_respects_backoff() {
        let mut tracker = CrashTracker::new();

        // Record crash with a timestamp in the past (simulate waiting).
        tracker.record_crash("myapp");

        // Immediately after crash, backoff hasn't elapsed yet.
        // With crash_count=1, backoff is 2s — so can_restart should be false.
        assert!(!tracker.can_restart("myapp"));

        // Manually set last_crash to the past to simulate elapsed time.
        if let Some(state) = tracker.apps.get_mut("myapp") {
            state.last_crash = Some(Instant::now() - Duration::from_secs(10));
        }
        assert!(tracker.can_restart("myapp"));
    }

    #[test]
    fn test_monitor_apps_with_tracker_detects_dead_process() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/phprs-test-monitor".into(),
            next_uid: 10000,
        };
        state.apps.insert("deadapp".into(), AppState {
            name: "deadapp".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8001,
            pid: Some(999999999), // Dead PID.
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
        });

        let mut tracker = CrashTracker::new();
        let actions = monitor_apps_with_tracker(&mut state, &mut tracker);

        // Should detect the crash and record it.
        assert!(!actions.is_empty());
        assert_eq!(tracker.crash_count("deadapp"), 1);
    }

    #[test]
    fn test_monitor_apps_suspends_after_repeated_crashes() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/phprs-test-monitor-suspend".into(),
            next_uid: 10000,
        };
        state.apps.insert("crasher".into(), AppState {
            name: "crasher".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8002,
            pid: Some(999999999), // Dead PID.
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
        });

        let mut tracker = CrashTracker::new();

        // Pre-fill crash count to just below suspension threshold.
        for _ in 0..(MAX_CRASH_COUNT - 1) {
            tracker.record_crash("crasher");
        }

        // This monitor call should trigger the suspension.
        let actions = monitor_apps_with_tracker(&mut state, &mut tracker);

        assert!(tracker.is_suspended("crasher"));
        // Should have a SUSPENDED action.
        let has_suspended = actions.iter().any(|(_, msg)| msg.contains("SUSPENDED"));
        assert!(has_suspended, "Expected SUSPENDED action, got: {:?}", actions);
    }

    #[test]
    fn test_detect_crash_reason_default() {
        let app = AppState {
            name: "test".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 9999,
            pid: Some(99999),
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
        let reason = detect_crash_reason(&app);
        // On non-Linux, should return "crashed".
        // On Linux without cgroup, should also return "crashed".
        assert!(!reason.is_empty());
    }
}
