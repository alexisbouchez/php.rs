//! Prometheus-compatible metrics.
//!
//! Exposed at `/_metrics` in Prometheus text exposition format.

use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe metrics counters.
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_ok: AtomicU64,
    pub requests_4xx: AtomicU64,
    pub requests_5xx: AtomicU64,
    pub php_errors: AtomicU64,
    pub static_files_served: AtomicU64,
    /// Cumulative request duration in microseconds (for computing averages).
    pub duration_us_total: AtomicU64,
    /// Cumulative PHP memory usage in bytes. Populated when arena tracking is added.
    #[allow(dead_code)]
    pub php_memory_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_ok: AtomicU64::new(0),
            requests_4xx: AtomicU64::new(0),
            requests_5xx: AtomicU64::new(0),
            php_errors: AtomicU64::new(0),
            static_files_served: AtomicU64::new(0),
            duration_us_total: AtomicU64::new(0),
            php_memory_total: AtomicU64::new(0),
        }
    }

    /// Record a completed request.
    pub fn record_request(&self, status: u16, duration_us: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.duration_us_total.fetch_add(duration_us, Ordering::Relaxed);
        match status {
            200..=399 => { self.requests_ok.fetch_add(1, Ordering::Relaxed); }
            400..=499 => { self.requests_4xx.fetch_add(1, Ordering::Relaxed); }
            _ => { self.requests_5xx.fetch_add(1, Ordering::Relaxed); }
        }
    }

    /// Record a static file served.
    pub fn record_static(&self) {
        self.static_files_served.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a PHP error/exception.
    pub fn record_php_error(&self) {
        self.php_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let ok = self.requests_ok.load(Ordering::Relaxed);
        let client_err = self.requests_4xx.load(Ordering::Relaxed);
        let server_err = self.requests_5xx.load(Ordering::Relaxed);
        let php_err = self.php_errors.load(Ordering::Relaxed);
        let statics = self.static_files_served.load(Ordering::Relaxed);
        let duration_us = self.duration_us_total.load(Ordering::Relaxed);
        let duration_s = duration_us as f64 / 1_000_000.0;
        let avg_ms = if total > 0 {
            (duration_us as f64 / total as f64) / 1000.0
        } else {
            0.0
        };

        format!(
            "# HELP phprs_requests_total Total HTTP requests handled.\n\
             # TYPE phprs_requests_total counter\n\
             phprs_requests_total {}\n\
             # HELP phprs_requests_ok Total 2xx/3xx responses.\n\
             # TYPE phprs_requests_ok counter\n\
             phprs_requests_ok {}\n\
             # HELP phprs_requests_4xx Total 4xx responses.\n\
             # TYPE phprs_requests_4xx counter\n\
             phprs_requests_4xx {}\n\
             # HELP phprs_requests_5xx Total 5xx responses.\n\
             # TYPE phprs_requests_5xx counter\n\
             phprs_requests_5xx {}\n\
             # HELP phprs_php_errors_total Total PHP errors/exceptions.\n\
             # TYPE phprs_php_errors_total counter\n\
             phprs_php_errors_total {}\n\
             # HELP phprs_static_files_total Static files served (no PHP).\n\
             # TYPE phprs_static_files_total counter\n\
             phprs_static_files_total {}\n\
             # HELP phprs_request_duration_seconds_total Cumulative request duration.\n\
             # TYPE phprs_request_duration_seconds_total counter\n\
             phprs_request_duration_seconds_total {:.6}\n\
             # HELP phprs_request_duration_avg_ms Average request duration in ms.\n\
             # TYPE phprs_request_duration_avg_ms gauge\n\
             phprs_request_duration_avg_ms {:.3}\n",
            total, ok, client_err, server_err, php_err, statics, duration_s, avg_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_request_2xx() {
        let m = Metrics::new();
        m.record_request(200, 1000);
        m.record_request(301, 500);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.requests_ok.load(Ordering::Relaxed), 2);
        assert_eq!(m.requests_4xx.load(Ordering::Relaxed), 0);
        assert_eq!(m.requests_5xx.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_request_4xx() {
        let m = Metrics::new();
        m.record_request(404, 100);
        m.record_request(403, 100);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.requests_4xx.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_request_5xx() {
        let m = Metrics::new();
        m.record_request(500, 100);
        m.record_request(503, 100);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.requests_5xx.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_php_error() {
        let m = Metrics::new();
        m.record_php_error();
        m.record_php_error();
        assert_eq!(m.php_errors.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_static() {
        let m = Metrics::new();
        m.record_static();
        assert_eq!(m.static_files_served.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_render_prometheus_format() {
        let m = Metrics::new();
        m.record_request(200, 5000);  // 5ms
        m.record_request(404, 1000);  // 1ms
        m.record_php_error();
        m.record_static();

        let output = m.render();
        assert!(output.contains("phprs_requests_total 2"));
        assert!(output.contains("phprs_requests_ok 1"));
        assert!(output.contains("phprs_requests_4xx 1"));
        assert!(output.contains("phprs_php_errors_total 1"));
        assert!(output.contains("phprs_static_files_total 1"));
        assert!(output.contains("# TYPE phprs_requests_total counter"));
    }

    #[test]
    fn test_render_empty_metrics() {
        let m = Metrics::new();
        let output = m.render();
        assert!(output.contains("phprs_requests_total 0"));
        assert!(output.contains("phprs_request_duration_avg_ms 0.000"));
    }
}
