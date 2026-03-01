//! Process management — spawn, stop, and monitor `php-rs-app` processes.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::isolation::IsolationConfig;
use crate::state::{self, AppState, PlatformState};

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
    let isolation = IsolationConfig::from_env(&app.env);

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

/// Monitor all apps — restart crashed processes and check disk quotas.
/// Returns a list of (app_name, action_taken) for logging.
pub fn monitor_apps(state: &mut PlatformState) -> Vec<(String, String)> {
    let mut actions = Vec::new();

    let app_names: Vec<String> = state.apps.keys().cloned().collect();
    for name in app_names {
        let app = &state.apps[&name];

        // Check for crashed processes.
        if app.pid.is_some() && !app.is_running() {
            // Detect likely OOM kill on Linux.
            let crash_reason = detect_crash_reason(app);
            actions.push((name.clone(), format!("{} — restarting", crash_reason)));
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

        // Check disk quota if configured and app is running.
        if app.is_running() {
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
        // On Linux, check dmesg for OOM kills of this PID.
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
}
