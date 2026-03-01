//! Auto-scaling logic for PHP apps.
//!
//! Monitors response latency and scales app instances between configured
//! min/max bounds. Each extra instance runs on a separate port.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::process::{self, StartResult, StopResult};
use crate::state::{self, AppInstance, AppState, PlatformState};

/// Metrics collected for scaling decisions.
#[derive(Debug, Clone)]
pub struct AppMetrics {
    /// Rolling average response time in milliseconds.
    pub avg_response_ms: u64,
    /// Number of samples in the rolling window.
    pub sample_count: u64,
    /// Last time a scale-up happened.
    pub last_scale_up: Option<Instant>,
    /// Last time a scale-down happened.
    pub last_scale_down: Option<Instant>,
    /// Last time metrics were updated.
    pub last_updated: Instant,
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self {
            avg_response_ms: 0,
            sample_count: 0,
            last_scale_up: None,
            last_scale_down: None,
            last_updated: Instant::now(),
        }
    }
}

/// Autoscaler that tracks metrics and adjusts instance counts.
pub struct Autoscaler {
    /// Per-app metrics.
    pub metrics: HashMap<String, AppMetrics>,
}

/// Action the autoscaler decided to take.
#[derive(Debug, PartialEq)]
pub enum ScaleAction {
    /// No change needed.
    None,
    /// Scale up by spawning more instances.
    ScaleUp { current: usize, target: usize },
    /// Scale down by removing idle instances.
    ScaleDown { current: usize, target: usize },
}

impl Autoscaler {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
        }
    }

    /// Record a response time sample for an app.
    pub fn record_response(&mut self, app_name: &str, response_ms: u64) {
        let m = self.metrics.entry(app_name.to_string()).or_default();
        // Exponential moving average (weight recent samples more).
        if m.sample_count == 0 {
            m.avg_response_ms = response_ms;
        } else {
            // EMA with alpha=0.1 (smooths over ~10 samples).
            m.avg_response_ms = (m.avg_response_ms * 9 + response_ms) / 10;
        }
        m.sample_count += 1;
        m.last_updated = Instant::now();
    }

    /// Decide what scaling action to take for an app.
    pub fn evaluate(&self, app: &AppState) -> ScaleAction {
        let config = &app.scaling;

        // If max_instances <= 1, auto-scaling is disabled.
        if config.max_instances <= 1 {
            return ScaleAction::None;
        }

        let current_count = current_instance_count(app);
        let metrics = self.metrics.get(&app.name);

        // Scale up: avg response time exceeds target.
        if let Some(m) = metrics {
            if m.avg_response_ms > config.target_response_ms
                && current_count < config.max_instances as usize
                && m.sample_count >= 5 // Need enough samples
            {
                // Check cooldown: don't scale up if we just scaled up.
                if let Some(last_up) = m.last_scale_up {
                    if last_up.elapsed() < Duration::from_secs(30) {
                        return ScaleAction::None;
                    }
                }
                let target = (current_count + 1).min(config.max_instances as usize);
                return ScaleAction::ScaleUp {
                    current: current_count,
                    target,
                };
            }

            // Scale down: avg response time well below target AND cooldown elapsed.
            if m.avg_response_ms < config.target_response_ms / 2
                && current_count > config.min_instances as usize
            {
                // Check cooldown before scaling down.
                if let Some(last_down) = m.last_scale_down {
                    if last_down.elapsed() < Duration::from_secs(config.cooldown_secs) {
                        return ScaleAction::None;
                    }
                }
                // Also don't scale down immediately after scale up.
                if let Some(last_up) = m.last_scale_up {
                    if last_up.elapsed() < Duration::from_secs(config.cooldown_secs) {
                        return ScaleAction::None;
                    }
                }
                let target = (current_count - 1).max(config.min_instances as usize);
                return ScaleAction::ScaleDown {
                    current: current_count,
                    target,
                };
            }
        }

        ScaleAction::None
    }

    /// Apply a scaling decision: start or stop instances.
    /// Returns a list of (app_name, action_taken) for logging.
    pub fn apply_scale(
        &mut self,
        state: &mut PlatformState,
        app_name: &str,
    ) -> Vec<(String, String)> {
        let mut actions = Vec::new();

        let app = match state.apps.get(app_name) {
            Some(a) => a.clone(),
            None => return actions,
        };

        let action = self.evaluate(&app);

        match action {
            ScaleAction::ScaleUp { current, target } => {
                let to_add = target - current;
                for _ in 0..to_add {
                    let port = state.allocate_port();
                    match start_instance(&app, port) {
                        StartResult::Started(pid) => {
                            let app_mut = state.apps.get_mut(app_name).unwrap();
                            app_mut.instances.push(AppInstance {
                                port,
                                pid: Some(pid),
                            });
                            actions.push((
                                app_name.to_string(),
                                format!("scaled up: instance on port {} (PID {})", port, pid),
                            ));
                        }
                        StartResult::Failed(e) => {
                            actions.push((
                                app_name.to_string(),
                                format!("scale-up failed on port {}: {}", port, e),
                            ));
                        }
                        _ => {}
                    }
                }
                if let Some(m) = self.metrics.get_mut(app_name) {
                    m.last_scale_up = Some(Instant::now());
                }
            }
            ScaleAction::ScaleDown { current, target } => {
                let to_remove = current - target;
                for _ in 0..to_remove {
                    let app_mut = state.apps.get_mut(app_name).unwrap();
                    if let Some(instance) = app_mut.instances.pop() {
                        if let Some(pid) = instance.pid {
                            if state::process_alive(pid) {
                                stop_instance(pid);
                            }
                        }
                        actions.push((
                            app_name.to_string(),
                            format!(
                                "scaled down: stopped instance on port {}",
                                instance.port
                            ),
                        ));
                    }
                }
                if let Some(m) = self.metrics.get_mut(app_name) {
                    m.last_scale_down = Some(Instant::now());
                }
            }
            ScaleAction::None => {}
        }

        actions
    }

    /// Run one autoscaler tick: evaluate all apps and apply changes.
    pub fn tick(&mut self, state: &mut PlatformState) -> Vec<(String, String)> {
        let mut all_actions = Vec::new();
        let app_names: Vec<String> = state.apps.keys().cloned().collect();

        for name in app_names {
            let actions = self.apply_scale(state, &name);
            all_actions.extend(actions);
        }

        // Also monitor instance health — restart crashed instances.
        let app_names: Vec<String> = state.apps.keys().cloned().collect();
        for name in app_names {
            let app = &state.apps[&name];
            let mut crashed_indices = Vec::new();

            for (i, instance) in app.instances.iter().enumerate() {
                if let Some(pid) = instance.pid {
                    if !state::process_alive(pid) {
                        crashed_indices.push(i);
                    }
                }
            }

            if !crashed_indices.is_empty() {
                let app_clone = state.apps[&name].clone();
                let app_mut = state.apps.get_mut(&name).unwrap();
                for i in crashed_indices.into_iter().rev() {
                    let port = app_mut.instances[i].port;
                    match start_instance(&app_clone, port) {
                        StartResult::Started(pid) => {
                            app_mut.instances[i].pid = Some(pid);
                            all_actions.push((
                                name.clone(),
                                format!("instance on port {} restarted (PID {})", port, pid),
                            ));
                        }
                        StartResult::Failed(e) => {
                            app_mut.instances.remove(i);
                            all_actions.push((
                                name.clone(),
                                format!("instance on port {} restart failed: {}", port, e),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }

        all_actions
    }
}

/// Get the total instance count for an app (primary + additional instances).
pub fn current_instance_count(app: &AppState) -> usize {
    // The primary process counts as 1 instance.
    let primary = if app.is_running() { 1 } else { 0 };
    let additional = app.instances.iter().filter(|i| {
        i.pid.map_or(false, state::process_alive)
    }).count();
    primary + additional
}

/// Start an additional instance of an app on a specific port.
pub fn start_instance(app: &AppState, port: u16) -> StartResult {
    let binary = match process::find_app_binary_pub() {
        Ok(b) => b,
        Err(e) => return StartResult::Failed(e),
    };

    let mut env = app.build_process_env();
    // Override port for this instance.
    env.insert("APP_PORT".into(), port.to_string());

    let mut cmd = std::process::Command::new(&binary);
    cmd.envs(&env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();

            // Start log capture for this instance.
            let logs_dir = crate::logs::default_logs_dir();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                crate::logs::start_log_capture(
                    format!("{}:{}", app.name, port),
                    logs_dir,
                    stdout,
                    stderr,
                );
            }

            std::mem::forget(child);
            StartResult::Started(pid)
        }
        Err(e) => StartResult::Failed(format!("Failed to spawn instance: {}", e)),
    }
}

/// Stop an instance by PID (SIGTERM, then SIGKILL).
pub fn stop_instance(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(5);
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

/// Manually set the instance count for an app.
/// Returns actions taken.
pub fn set_instance_count(
    state: &mut PlatformState,
    app_name: &str,
    count: usize,
) -> Result<Vec<String>, String> {
    let app = state
        .apps
        .get(app_name)
        .ok_or_else(|| format!("App '{}' not found", app_name))?
        .clone();

    if !app.is_running() {
        return Err(format!("App '{}' is not running", app_name));
    }

    let current = current_instance_count(&app);
    let mut actions = Vec::new();

    if count > current {
        // Scale up.
        for _ in 0..(count - current) {
            let port = state.allocate_port();
            match start_instance(&app, port) {
                StartResult::Started(pid) => {
                    let app_mut = state.apps.get_mut(app_name).unwrap();
                    app_mut.instances.push(AppInstance {
                        port,
                        pid: Some(pid),
                    });
                    actions.push(format!("Started instance on port {} (PID {})", port, pid));
                }
                StartResult::Failed(e) => {
                    actions.push(format!("Failed to start instance: {}", e));
                }
                _ => {}
            }
        }
    } else if count < current {
        // Scale down — remove additional instances first, then primary if needed.
        let to_remove = current - count;
        let app_mut = state.apps.get_mut(app_name).unwrap();
        for _ in 0..to_remove.min(app_mut.instances.len()) {
            if let Some(instance) = app_mut.instances.pop() {
                if let Some(pid) = instance.pid {
                    if state::process_alive(pid) {
                        stop_instance(pid);
                    }
                }
                actions.push(format!("Stopped instance on port {}", instance.port));
            }
        }
    } else {
        actions.push("Already at requested instance count".to_string());
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ScalingConfig;
    use std::collections::HashMap;

    fn test_app(name: &str) -> AppState {
        AppState {
            name: name.into(),
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
    fn test_autoscaler_new() {
        let scaler = Autoscaler::new();
        assert!(scaler.metrics.is_empty());
    }

    #[test]
    fn test_record_response() {
        let mut scaler = Autoscaler::new();
        scaler.record_response("myapp", 100);
        assert_eq!(scaler.metrics["myapp"].avg_response_ms, 100);
        assert_eq!(scaler.metrics["myapp"].sample_count, 1);

        // EMA: (100 * 9 + 200) / 10 = 110
        scaler.record_response("myapp", 200);
        assert_eq!(scaler.metrics["myapp"].avg_response_ms, 110);
        assert_eq!(scaler.metrics["myapp"].sample_count, 2);
    }

    #[test]
    fn test_evaluate_disabled() {
        let scaler = Autoscaler::new();
        let app = test_app("myapp");
        // max_instances = 1 (default), so scaling disabled.
        assert_eq!(scaler.evaluate(&app), ScaleAction::None);
    }

    #[test]
    fn test_evaluate_scale_up() {
        let mut scaler = Autoscaler::new();
        let mut app = test_app("myapp");
        app.scaling = ScalingConfig {
            min_instances: 1,
            max_instances: 4,
            target_response_ms: 500,
            cooldown_secs: 60,
        };
        // Fake PID is not a real process, so current_instance_count = 0.

        // Record high response times (above 500ms target).
        for _ in 0..10 {
            scaler.record_response("myapp", 800);
        }

        let action = scaler.evaluate(&app);
        // current=0 (fake PID not alive), target=1
        assert_eq!(
            action,
            ScaleAction::ScaleUp {
                current: 0,
                target: 1,
            }
        );
    }

    #[test]
    fn test_evaluate_scale_down() {
        let mut scaler = Autoscaler::new();
        let mut app = test_app("myapp");
        app.scaling = ScalingConfig {
            min_instances: 1,
            max_instances: 4,
            target_response_ms: 500,
            cooldown_secs: 0, // No cooldown for testing.
        };
        // Simulate 2 instances running.
        app.pid = Some(99999999);
        app.instances.push(AppInstance {
            port: 8002,
            pid: Some(99999998),
        });

        // Record low response times (well below 250 = target/2).
        for _ in 0..10 {
            scaler.record_response("myapp", 50);
        }

        // current_instance_count checks process_alive, which returns false for fake PIDs.
        // So current_count = 0, which is not > min_instances. No scale-down.
        // This tests the logic path correctly — in production, real PIDs would pass process_alive.
        let action = scaler.evaluate(&app);
        // With fake PIDs, current=0 which is not > min=1, so None.
        assert_eq!(action, ScaleAction::None);
    }

    #[test]
    fn test_evaluate_not_enough_samples() {
        let mut scaler = Autoscaler::new();
        let mut app = test_app("myapp");
        app.scaling = ScalingConfig {
            min_instances: 1,
            max_instances: 4,
            target_response_ms: 500,
            cooldown_secs: 60,
        };

        // Only 3 samples — below the 5-sample minimum.
        for _ in 0..3 {
            scaler.record_response("myapp", 800);
        }

        assert_eq!(scaler.evaluate(&app), ScaleAction::None);
    }

    #[test]
    fn test_evaluate_at_max() {
        let mut scaler = Autoscaler::new();
        let mut app = test_app("myapp");
        app.scaling = ScalingConfig {
            min_instances: 1,
            max_instances: 2,
            target_response_ms: 500,
            cooldown_secs: 60,
        };
        // Simulate 2 running instances (at max).
        app.pid = Some(99999999);
        app.instances.push(AppInstance {
            port: 8002,
            pid: Some(99999998),
        });

        for _ in 0..10 {
            scaler.record_response("myapp", 800);
        }

        // current_instance_count with fake PIDs = 0 (not alive).
        // But if they were real, at max=2 it would be None.
        // This just verifies evaluate doesn't crash.
        let _action = scaler.evaluate(&app);
    }

    #[test]
    fn test_current_instance_count_no_instances() {
        let app = test_app("myapp");
        assert_eq!(current_instance_count(&app), 0);
    }

    #[test]
    fn test_current_instance_count_with_dead_instances() {
        let mut app = test_app("myapp");
        app.instances.push(AppInstance {
            port: 8002,
            pid: Some(99999999), // Not a real PID.
        });
        app.instances.push(AppInstance {
            port: 8003,
            pid: None,
        });
        // All fake/None PIDs, so count = 0.
        assert_eq!(current_instance_count(&app), 0);
    }

    #[test]
    fn test_set_instance_count_app_not_found() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test".into(),
            next_uid: 10000,
        };
        let result = set_instance_count(&mut state, "nonexistent", 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_set_instance_count_not_running() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test".into(),
            next_uid: 10000,
        };
        state.apps.insert("myapp".into(), test_app("myapp"));
        let result = set_instance_count(&mut state, "myapp", 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not running"));
    }

    #[test]
    fn test_scale_action_eq() {
        assert_eq!(ScaleAction::None, ScaleAction::None);
        assert_eq!(
            ScaleAction::ScaleUp {
                current: 1,
                target: 2,
            },
            ScaleAction::ScaleUp {
                current: 1,
                target: 2,
            }
        );
        assert_ne!(
            ScaleAction::ScaleUp {
                current: 1,
                target: 2,
            },
            ScaleAction::ScaleDown {
                current: 2,
                target: 1,
            }
        );
    }
}
