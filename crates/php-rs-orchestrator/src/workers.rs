//! Worker processes (queues) — long-running PHP processes for background work.
//!
//! Workers are separate from HTTP instances: they run continuously processing
//! queue jobs (e.g. `php artisan queue:work`). The orchestrator monitors them
//! and restarts on crash.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::state::{self, AppState, PlatformState};

/// A configured worker process for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Unique ID (auto-incremented).
    pub id: u64,
    /// Command to run (e.g. "php artisan queue:work").
    pub command: String,
    /// Number of processes to run for this worker type.
    #[serde(default = "default_one")]
    pub count: u16,
    /// Whether this worker is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// PIDs of running worker processes.
    #[serde(default)]
    pub pids: Vec<u32>,
}

fn default_one() -> u16 {
    1
}

fn default_true() -> bool {
    true
}

/// Start all configured workers for an app.
/// Returns actions taken.
pub fn start_workers(app: &AppState) -> Vec<(String, String)> {
    let mut actions = Vec::new();

    for worker in &app.worker_configs {
        if !worker.enabled {
            continue;
        }

        let running = worker
            .pids
            .iter()
            .filter(|&&pid| state::process_alive(pid))
            .count();

        let to_start = (worker.count as usize).saturating_sub(running);
        for _ in 0..to_start {
            match spawn_worker(app, worker) {
                Ok(pid) => {
                    actions.push((
                        app.name.clone(),
                        format!(
                            "worker #{}: started '{}' (PID {})",
                            worker.id, worker.command, pid
                        ),
                    ));
                }
                Err(e) => {
                    actions.push((
                        app.name.clone(),
                        format!("worker #{}: failed to start: {}", worker.id, e),
                    ));
                }
            }
        }
    }

    actions
}

/// Spawn a single worker process.
fn spawn_worker(app: &AppState, worker: &WorkerConfig) -> Result<u32, String> {
    let binary = crate::process::find_app_binary_pub()?;

    let mut env = app.build_process_env();
    env.insert("APP_WORKER_ID".into(), worker.id.to_string());
    env.insert("APP_WORKER_COMMAND".into(), worker.command.clone());
    env.insert("APP_MODE".into(), "worker".into());

    // Override entry point based on the worker command.
    if worker.command.starts_with("php ") {
        let cmd = &worker.command[4..];
        env.insert("APP_ENTRY".into(), cmd.to_string());
    }

    let mut cmd = Command::new(&binary);
    cmd.envs(&env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();

            // Capture output.
            let logs_dir = crate::logs::default_logs_dir();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                crate::logs::start_log_capture(
                    format!("{}:worker:{}", app.name, worker.id),
                    logs_dir,
                    stdout,
                    stderr,
                );
            }

            std::mem::forget(child);
            Ok(pid)
        }
        Err(e) => Err(format!("Failed to spawn worker: {}", e)),
    }
}

/// Stop all workers for an app.
pub fn stop_workers(app: &AppState) -> Vec<(String, String)> {
    let mut actions = Vec::new();

    for worker in &app.worker_configs {
        for &pid in &worker.pids {
            if state::process_alive(pid) {
                stop_worker_pid(pid);
                actions.push((
                    app.name.clone(),
                    format!("worker #{}: stopped PID {}", worker.id, pid),
                ));
            }
        }
    }

    actions
}

/// Stop a single worker process (public API for CLI).
pub fn stop_worker_pid_pub(pid: u32) {
    stop_worker_pid(pid);
}

/// Stop a single worker process (SIGTERM → SIGKILL).
fn stop_worker_pid(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    while start.elapsed() < timeout {
        if !state::process_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Force kill.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

/// Monitor workers: restart crashed ones, start missing ones.
/// Returns actions taken.
pub fn monitor_workers(state: &mut PlatformState) -> Vec<(String, String)> {
    let mut actions = Vec::new();
    let app_names: Vec<String> = state.apps.keys().cloned().collect();

    for name in app_names {
        let app = state.apps[&name].clone();

        if !app.is_running() {
            continue; // Skip apps that aren't running.
        }

        for (wi, worker) in app.worker_configs.iter().enumerate() {
            if !worker.enabled {
                continue;
            }

            // Check which PIDs are still alive.
            let mut alive_pids: Vec<u32> = worker
                .pids
                .iter()
                .copied()
                .filter(|&pid| state::process_alive(pid))
                .collect();

            let dead_count = worker.pids.len() - alive_pids.len();
            if dead_count > 0 {
                actions.push((
                    name.clone(),
                    format!("worker #{}: {} process(es) died", worker.id, dead_count),
                ));
            }

            // Start any missing processes.
            let needed = (worker.count as usize).saturating_sub(alive_pids.len());
            for _ in 0..needed {
                match spawn_worker(&app, worker) {
                    Ok(pid) => {
                        alive_pids.push(pid);
                        actions.push((
                            name.clone(),
                            format!(
                                "worker #{}: restarted '{}' (PID {})",
                                worker.id, worker.command, pid
                            ),
                        ));
                    }
                    Err(e) => {
                        actions.push((
                            name.clone(),
                            format!("worker #{}: restart failed: {}", worker.id, e),
                        ));
                    }
                }
            }

            // Update PIDs in state.
            state.apps.get_mut(&name).unwrap().worker_configs[wi].pids = alive_pids;
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_app() -> AppState {
        AppState {
            name: "testapp".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8001,
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
        }
    }

    #[test]
    fn test_worker_config_serialize() {
        let wc = WorkerConfig {
            id: 1,
            command: "php artisan queue:work".into(),
            count: 2,
            enabled: true,
            pids: vec![],
        };
        let json = serde_json::to_string(&wc).unwrap();
        assert!(json.contains("queue:work"));

        let parsed: WorkerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.count, 2);
        assert!(parsed.enabled);
    }

    #[test]
    fn test_worker_config_defaults() {
        let json = r#"{"id":1,"command":"test"}"#;
        let wc: WorkerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(wc.count, 1);
        assert!(wc.enabled);
        assert!(wc.pids.is_empty());
    }

    #[test]
    fn test_start_workers_no_workers() {
        let app = test_app();
        let actions = start_workers(&app);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_start_workers_disabled() {
        let mut app = test_app();
        app.worker_configs.push(WorkerConfig {
            id: 1,
            command: "php artisan queue:work".into(),
            count: 1,
            enabled: false,
            pids: vec![],
        });
        let actions = start_workers(&app);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_stop_workers_no_workers() {
        let app = test_app();
        let actions = stop_workers(&app);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_stop_workers_dead_pids() {
        let mut app = test_app();
        app.worker_configs.push(WorkerConfig {
            id: 1,
            command: "php artisan queue:work".into(),
            count: 1,
            enabled: true,
            pids: vec![99999999], // Not a real PID.
        });
        let actions = stop_workers(&app);
        // Dead PID, so stop is a no-op.
        assert!(actions.is_empty());
    }

    #[test]
    fn test_monitor_workers_no_apps() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test".into(),
            next_uid: 10000,
        };
        let actions = monitor_workers(&mut state);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_monitor_workers_app_not_running() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test".into(),
            next_uid: 10000,
        };
        let mut app = test_app();
        app.worker_configs.push(WorkerConfig {
            id: 1,
            command: "php artisan queue:work".into(),
            count: 1,
            enabled: true,
            pids: vec![],
        });
        state.apps.insert("testapp".into(), app);

        let actions = monitor_workers(&mut state);
        // App isn't running, so workers aren't monitored.
        assert!(actions.is_empty());
    }
}
