//! Cron / scheduled tasks for PHP apps.
//!
//! Run PHP scripts on a schedule via one-off processes.
//! Uses standard cron expression syntax (minute hour dom month dow).

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::state::{AppState, PlatformState};

/// A scheduled cron job for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// Unique ID (auto-incremented).
    pub id: u64,
    /// Cron schedule expression: "minute hour dom month dow"
    /// Supports: numbers, ranges (1-5), lists (1,3,5), steps (*/5), wildcard (*).
    pub schedule: String,
    /// Command to run (e.g. "php artisan schedule:run").
    pub command: String,
    /// Whether to prevent overlapping runs.
    #[serde(default = "default_true")]
    pub no_overlap: bool,
    /// Whether the job is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// PID of the currently running instance, if any (for no_overlap).
    #[serde(skip)]
    pub running_pid: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// Parsed cron schedule fields.
#[derive(Debug, Clone, PartialEq)]
pub struct CronSchedule {
    pub minutes: Vec<u8>,  // 0-59
    pub hours: Vec<u8>,    // 0-23
    pub doms: Vec<u8>,     // 1-31 (day of month)
    pub months: Vec<u8>,   // 1-12
    pub dows: Vec<u8>,     // 0-7 (0 and 7 = Sunday)
}

/// Parse a cron expression into its component fields.
/// Format: "minute hour dom month dow"
pub fn parse_schedule(expr: &str) -> Result<CronSchedule, String> {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(format!(
            "Invalid cron expression '{}': expected 5 fields (minute hour dom month dow)",
            expr
        ));
    }

    Ok(CronSchedule {
        minutes: parse_field(parts[0], 0, 59)?,
        hours: parse_field(parts[1], 0, 23)?,
        doms: parse_field(parts[2], 1, 31)?,
        months: parse_field(parts[3], 1, 12)?,
        dows: parse_field(parts[4], 0, 7)?,
    })
}

/// Parse a single cron field (e.g. "*/5", "1,3,5", "1-5", "*", "3").
fn parse_field(field: &str, min: u8, max: u8) -> Result<Vec<u8>, String> {
    let mut values = Vec::new();

    for part in field.split(',') {
        if part == "*" {
            // Wildcard: all values.
            values.extend(min..=max);
        } else if let Some(step_str) = part.strip_prefix("*/") {
            // Step: */N
            let step: u8 = step_str
                .parse()
                .map_err(|_| format!("Invalid step value: {}", step_str))?;
            if step == 0 {
                return Err("Step value cannot be zero".into());
            }
            let mut v = min;
            while v <= max {
                values.push(v);
                v = v.saturating_add(step);
            }
        } else if part.contains('-') {
            // Range: N-M or N-M/S
            let (range_part, step) = if part.contains('/') {
                let rs: Vec<&str> = part.split('/').collect();
                let s: u8 = rs[1]
                    .parse()
                    .map_err(|_| format!("Invalid step: {}", rs[1]))?;
                (rs[0], s)
            } else {
                (part, 1)
            };

            let bounds: Vec<&str> = range_part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }
            let lo: u8 = bounds[0]
                .parse()
                .map_err(|_| format!("Invalid range start: {}", bounds[0]))?;
            let hi: u8 = bounds[1]
                .parse()
                .map_err(|_| format!("Invalid range end: {}", bounds[1]))?;

            if lo < min || hi > max || lo > hi {
                return Err(format!("Range {}-{} out of bounds ({}-{})", lo, hi, min, max));
            }

            let mut v = lo;
            while v <= hi {
                values.push(v);
                v = v.saturating_add(step);
            }
        } else {
            // Single value.
            let v: u8 = part
                .parse()
                .map_err(|_| format!("Invalid value: {}", part))?;
            if v < min || v > max {
                return Err(format!("Value {} out of bounds ({}-{})", v, min, max));
            }
            values.push(v);
        }
    }

    values.sort_unstable();
    values.dedup();
    Ok(values)
}

impl CronSchedule {
    /// Check if the schedule matches the given time.
    pub fn matches(&self, minute: u8, hour: u8, dom: u8, month: u8, dow: u8) -> bool {
        self.minutes.contains(&minute)
            && self.hours.contains(&hour)
            && self.doms.contains(&dom)
            && self.months.contains(&month)
            && (self.dows.contains(&dow) || self.dows.contains(&(dow % 7)))
    }

    /// Check if the schedule matches the current time.
    pub fn matches_now(&self) -> bool {
        let (minute, hour, dom, month, dow) = current_time_fields();
        self.matches(minute, hour, dom, month, dow)
    }
}

/// Get current UTC time as (minute, hour, day_of_month, month, day_of_week).
fn current_time_fields() -> (u8, u8, u8, u8, u8) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let day_secs = (secs % 86400) as u32;
    let hour = (day_secs / 3600) as u8;
    let minute = ((day_secs % 3600) / 60) as u8;

    // Days since epoch to Y-M-D.
    let days = secs / 86400;
    let (_, month, dom) = crate::state::days_to_ymd_pub(days);

    // Day of week: 1970-01-01 was Thursday (4), 0=Sunday.
    let dow = ((days + 4) % 7) as u8;

    (minute, hour, dom as u8, month as u8, dow)
}

/// Runner that checks and executes cron jobs.
pub struct CronRunner {
    /// Track which jobs are currently running (job_key → PID).
    running: HashMap<String, u32>,
    /// Last execution check time (to avoid running twice in same minute).
    last_check_minute: Option<(u8, u8)>,
}

impl CronRunner {
    pub fn new() -> Self {
        Self {
            running: HashMap::new(),
            last_check_minute: None,
        }
    }

    /// Run one tick: check all apps' cron jobs and execute any that are due.
    /// Returns a list of (app_name, action) for logging.
    pub fn tick(&mut self, state: &PlatformState) -> Vec<(String, String)> {
        let (minute, hour, dom, month, dow) = current_time_fields();
        let mut actions = Vec::new();

        // Only check once per minute.
        let current_hm = (hour, minute);
        if self.last_check_minute == Some(current_hm) {
            // Clean up finished processes.
            self.cleanup_finished(&mut actions);
            return actions;
        }
        self.last_check_minute = Some(current_hm);

        // Clean up any finished processes first.
        self.cleanup_finished(&mut actions);

        for (app_name, app) in &state.apps {
            for job in &app.cron_jobs {
                if !job.enabled {
                    continue;
                }

                let schedule = match parse_schedule(&job.schedule) {
                    Ok(s) => s,
                    Err(e) => {
                        actions.push((
                            app_name.clone(),
                            format!("cron #{}: invalid schedule '{}': {}", job.id, job.schedule, e),
                        ));
                        continue;
                    }
                };

                if !schedule.matches(minute, hour, dom, month, dow) {
                    continue;
                }

                let job_key = format!("{}:{}", app_name, job.id);

                // Check for overlap.
                if job.no_overlap {
                    if let Some(&pid) = self.running.get(&job_key) {
                        if crate::state::process_alive(pid) {
                            actions.push((
                                app_name.clone(),
                                format!(
                                    "cron #{}: skipping (previous run PID {} still running)",
                                    job.id, pid
                                ),
                            ));
                            continue;
                        }
                    }
                }

                // Execute the cron job.
                match run_cron_job(app, job) {
                    Ok(pid) => {
                        self.running.insert(job_key, pid);
                        actions.push((
                            app_name.clone(),
                            format!("cron #{}: started '{}' (PID {})", job.id, job.command, pid),
                        ));
                    }
                    Err(e) => {
                        actions.push((
                            app_name.clone(),
                            format!("cron #{}: failed to start: {}", job.id, e),
                        ));
                    }
                }
            }
        }

        actions
    }

    /// Clean up entries for finished processes.
    fn cleanup_finished(&mut self, actions: &mut Vec<(String, String)>) {
        let mut finished = Vec::new();
        for (key, &pid) in &self.running {
            if !crate::state::process_alive(pid) {
                finished.push(key.clone());
            }
        }
        for key in finished {
            self.running.remove(&key);
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() == 2 {
                actions.push((
                    parts[0].to_string(),
                    format!("cron #{}: completed", parts[1]),
                ));
            }
        }
    }
}

/// Execute a cron job as a one-off process.
fn run_cron_job(app: &AppState, job: &CronJob) -> Result<u32, String> {
    let binary = crate::process::find_app_binary_pub()?;

    let mut env = app.build_process_env();
    // Mark this as a one-off cron process.
    env.insert("APP_CRON_JOB".into(), job.id.to_string());
    env.insert("APP_CRON_COMMAND".into(), job.command.clone());

    // Use the app's entry as -r script if the command starts with "php ".
    // Otherwise, set the command as the entry.
    let (entry_override, extra_args) = if job.command.starts_with("php ") {
        // Strip "php " and use remaining as args to the PHP runtime.
        let cmd = &job.command[4..];
        if cmd.starts_with("artisan ") || cmd.starts_with("-r ") {
            (None, Some(cmd.to_string()))
        } else {
            // It's a PHP file path.
            (Some(cmd.to_string()), None)
        }
    } else {
        // Treat as a PHP script path.
        (Some(job.command.clone()), None)
    };

    if let Some(entry) = entry_override {
        env.insert("APP_ENTRY".into(), entry);
    }

    let mut cmd = Command::new(&binary);
    cmd.envs(&env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(args) = extra_args {
        cmd.env("APP_ARGS", args);
    }

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();

            // Capture output.
            let logs_dir = crate::logs::default_logs_dir();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                crate::logs::start_log_capture(
                    format!("{}:cron:{}", app.name, job.id),
                    logs_dir,
                    stdout,
                    stderr,
                );
            }

            std::mem::forget(child);
            Ok(pid)
        }
        Err(e) => Err(format!("Failed to spawn cron job: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wildcard() {
        let s = parse_schedule("* * * * *").unwrap();
        assert_eq!(s.minutes.len(), 60); // 0-59
        assert_eq!(s.hours.len(), 24);   // 0-23
        assert_eq!(s.doms.len(), 31);    // 1-31
        assert_eq!(s.months.len(), 12);  // 1-12
        assert_eq!(s.dows.len(), 8);     // 0-7
    }

    #[test]
    fn test_parse_specific() {
        let s = parse_schedule("30 2 15 6 3").unwrap();
        assert_eq!(s.minutes, vec![30]);
        assert_eq!(s.hours, vec![2]);
        assert_eq!(s.doms, vec![15]);
        assert_eq!(s.months, vec![6]);
        assert_eq!(s.dows, vec![3]);
    }

    #[test]
    fn test_parse_step() {
        let s = parse_schedule("*/5 * * * *").unwrap();
        assert_eq!(s.minutes, vec![0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55]);
    }

    #[test]
    fn test_parse_range() {
        let s = parse_schedule("0 9-17 * * *").unwrap();
        assert_eq!(s.hours, vec![9, 10, 11, 12, 13, 14, 15, 16, 17]);
    }

    #[test]
    fn test_parse_list() {
        let s = parse_schedule("0 0 1,15 * *").unwrap();
        assert_eq!(s.doms, vec![1, 15]);
    }

    #[test]
    fn test_parse_range_with_step() {
        let s = parse_schedule("0 0 1-30/5 * *").unwrap();
        assert_eq!(s.doms, vec![1, 6, 11, 16, 21, 26]);
    }

    #[test]
    fn test_parse_invalid_too_few_fields() {
        assert!(parse_schedule("* * *").is_err());
    }

    #[test]
    fn test_parse_invalid_value() {
        assert!(parse_schedule("60 * * * *").is_err()); // minute > 59
    }

    #[test]
    fn test_parse_invalid_range() {
        assert!(parse_schedule("0 25 * * *").is_err()); // hour > 23
    }

    #[test]
    fn test_parse_zero_step() {
        assert!(parse_schedule("*/0 * * * *").is_err());
    }

    #[test]
    fn test_matches() {
        let s = parse_schedule("30 14 * * 1-5").unwrap();
        // 2:30 PM on a Monday (dow=1)
        assert!(s.matches(30, 14, 15, 6, 1));
        // Wrong minute
        assert!(!s.matches(0, 14, 15, 6, 1));
        // Saturday (dow=6)
        assert!(!s.matches(30, 14, 15, 6, 6));
    }

    #[test]
    fn test_matches_sunday() {
        // Both 0 and 7 mean Sunday.
        let s = parse_schedule("0 0 * * 0").unwrap();
        assert!(s.matches(0, 0, 1, 1, 0)); // dow=0 (Sunday)
        assert!(s.matches(0, 0, 1, 1, 7)); // dow=7 (also Sunday)
    }

    #[test]
    fn test_every_five_minutes() {
        let s = parse_schedule("*/5 * * * *").unwrap();
        assert!(s.matches(0, 10, 1, 1, 3));
        assert!(s.matches(5, 10, 1, 1, 3));
        assert!(s.matches(10, 10, 1, 1, 3));
        assert!(!s.matches(3, 10, 1, 1, 3));
        assert!(!s.matches(7, 10, 1, 1, 3));
    }

    #[test]
    fn test_cron_runner_new() {
        let runner = CronRunner::new();
        assert!(runner.running.is_empty());
        assert!(runner.last_check_minute.is_none());
    }

    #[test]
    fn test_cron_job_serialize() {
        let job = CronJob {
            id: 1,
            schedule: "*/5 * * * *".into(),
            command: "php artisan schedule:run".into(),
            no_overlap: true,
            enabled: true,
            running_pid: None,
        };
        let json = serde_json::to_string(&job).unwrap();
        assert!(json.contains("schedule"));
        assert!(json.contains("*/5"));

        let parsed: CronJob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.schedule, "*/5 * * * *");
        assert!(parsed.no_overlap);
    }
}
