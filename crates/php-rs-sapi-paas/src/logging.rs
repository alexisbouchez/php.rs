//! Structured JSON logging to stdout (12-factor app style).
//!
//! Each log line is a JSON object with standard fields:
//! `{"ts":"...","level":"info","app":"myapp","component":"boot","msg":"..."}`
//!
//! Request logs include additional fields: method, path, status, duration_ms,
//! bytes, request_id.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique request ID for tracing.
pub fn next_request_id() -> String {
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    format!("{:x}-{:04x}", ts, count & 0xFFFF)
}

/// Structured logger that writes JSON to stdout.
#[derive(Clone)]
pub struct Logger {
    app_name: String,
}

impl Logger {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
        }
    }

    pub fn info(&self, component: &str, msg: &str) {
        self.log("info", component, msg);
    }

    pub fn warn(&self, component: &str, msg: &str) {
        self.log("warn", component, msg);
    }

    pub fn error(&self, component: &str, msg: &str) {
        self.log("error", component, msg);
    }

    /// Log a completed HTTP request.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        status: u16,
        duration_ms: u128,
        bytes: usize,
        request_id: &str,
    ) {
        let ts = format_timestamp();
        let msg = escape_json(&format!("{} {} {} {}ms {}B", method, path, status, duration_ms, bytes));
        let line = format!(
            r#"{{"ts":"{}","level":"info","app":"{}","component":"request","msg":"{}","method":"{}","path":"{}","status":{},"duration_ms":{},"bytes":{},"request_id":"{}"}}"#,
            ts,
            escape_json(&self.app_name),
            msg,
            escape_json(method),
            escape_json(path),
            status,
            duration_ms,
            bytes,
            escape_json(request_id),
        );
        println!("{}", line);
    }

    fn log(&self, level: &str, component: &str, msg: &str) {
        let ts = format_timestamp();
        let line = format!(
            r#"{{"ts":"{}","level":"{}","app":"{}","component":"{}","msg":"{}"}}"#,
            ts,
            level,
            escape_json(&self.app_name),
            escape_json(component),
            escape_json(msg),
        );
        println!("{}", line);
    }
}

fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Simple ISO-8601 timestamp without pulling in chrono.
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch → year/month/day (simplified).
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified date conversion from days since Unix epoch.
    let mut y = 1970;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let months = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for days_in_month in &months {
        if remaining < *days_in_month {
            break;
        }
        remaining -= days_in_month;
        m += 1;
    }
    (y, m + 1, remaining + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
