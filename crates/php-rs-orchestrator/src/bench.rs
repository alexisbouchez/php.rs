//! Benchmark utilities for measuring PaaS performance.
//!
//! Measures: cold start time, warm request time, throughput, memory usage.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Benchmark results.
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    /// Time to first response after process start (ms).
    pub cold_start_ms: Option<f64>,
    /// Average request time on warm VM (ms).
    pub avg_request_ms: f64,
    /// Minimum request time (ms).
    pub min_request_ms: f64,
    /// Maximum request time (ms).
    pub max_request_ms: f64,
    /// P50 latency (ms).
    pub p50_ms: f64,
    /// P95 latency (ms).
    pub p95_ms: f64,
    /// P99 latency (ms).
    pub p99_ms: f64,
    /// Requests per second.
    pub requests_per_sec: f64,
    /// Total requests completed.
    pub total_requests: usize,
    /// Failed requests.
    pub failed_requests: usize,
    /// RSS memory in KB (if available).
    pub memory_rss_kb: Option<u64>,
}

/// Run a benchmark against a running app.
/// Sends `total_requests` sequential HTTP GET requests to the given port.
pub fn bench_app(port: u16, path: &str, total_requests: usize) -> BenchmarkResults {
    let addr = format!("127.0.0.1:{}", port);
    let mut latencies: Vec<f64> = Vec::with_capacity(total_requests);
    let mut failed = 0;

    let overall_start = Instant::now();

    for _ in 0..total_requests {
        match send_request(&addr, path) {
            Ok(latency_ms) => latencies.push(latency_ms),
            Err(_) => failed += 1,
        }
    }

    let overall_elapsed = overall_start.elapsed().as_secs_f64();

    if latencies.is_empty() {
        return BenchmarkResults {
            cold_start_ms: None,
            avg_request_ms: 0.0,
            min_request_ms: 0.0,
            max_request_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            requests_per_sec: 0.0,
            total_requests,
            failed_requests: failed,
            memory_rss_kb: None,
        };
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let min = latencies[0];
    let max = latencies[latencies.len() - 1];
    let p50 = percentile(&latencies, 50.0);
    let p95 = percentile(&latencies, 95.0);
    let p99 = percentile(&latencies, 99.0);
    let rps = latencies.len() as f64 / overall_elapsed;

    BenchmarkResults {
        cold_start_ms: None,
        avg_request_ms: avg,
        min_request_ms: min,
        max_request_ms: max,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        requests_per_sec: rps,
        total_requests,
        failed_requests: failed,
        memory_rss_kb: get_process_rss(port),
    }
}

/// Run a concurrent benchmark with `concurrency` threads.
pub fn bench_concurrent(
    port: u16,
    path: &str,
    total_requests: usize,
    concurrency: usize,
) -> BenchmarkResults {
    use std::sync::{Arc, Mutex};

    let addr = format!("127.0.0.1:{}", port);
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(total_requests)));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(total_requests));

    let overall_start = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let addr = addr.clone();
        let path = path.to_string();
        let latencies = latencies.clone();
        let failed = failed.clone();
        let remaining = remaining.clone();

        handles.push(std::thread::spawn(move || {
            loop {
                let prev = remaining.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                if prev == 0 {
                    remaining.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                match send_request(&addr, &path) {
                    Ok(latency_ms) => {
                        latencies.lock().unwrap().push(latency_ms);
                    }
                    Err(_) => {
                        failed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let overall_elapsed = overall_start.elapsed().as_secs_f64();
    let mut latencies = latencies.lock().unwrap().clone();
    let failed = failed.load(std::sync::atomic::Ordering::SeqCst);

    if latencies.is_empty() {
        return BenchmarkResults {
            cold_start_ms: None,
            avg_request_ms: 0.0,
            min_request_ms: 0.0,
            max_request_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            requests_per_sec: 0.0,
            total_requests,
            failed_requests: failed,
            memory_rss_kb: None,
        };
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let min = latencies[0];
    let max = latencies[latencies.len() - 1];
    let p50 = percentile(&latencies, 50.0);
    let p95 = percentile(&latencies, 95.0);
    let p99 = percentile(&latencies, 99.0);
    let rps = latencies.len() as f64 / overall_elapsed;

    BenchmarkResults {
        cold_start_ms: None,
        avg_request_ms: avg,
        min_request_ms: min,
        max_request_ms: max,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        requests_per_sec: rps,
        total_requests,
        failed_requests: failed,
        memory_rss_kb: get_process_rss(port),
    }
}

/// Send a single HTTP GET request and return latency in milliseconds.
fn send_request(addr: &str, path: &str) -> Result<f64, String> {
    let start = Instant::now();

    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("{}", e))?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("Connect: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write: {}", e))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("Read: {}", e))?;

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    // Check for HTTP 200.
    let resp_str = String::from_utf8_lossy(&response);
    if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
        return Err(format!("Non-200 response: {}", &resp_str[..resp_str.len().min(40)]));
    }

    Ok(elapsed)
}

/// Get the Nth percentile from a sorted list.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Try to get the RSS of the process listening on the given port.
fn get_process_rss(_port: u16) -> Option<u64> {
    // On macOS, use `ps` to get RSS.
    // On Linux, read /proc/<pid>/status.
    // This is best-effort.
    None
}

/// Format benchmark results for display.
pub fn format_results(results: &BenchmarkResults) -> String {
    let mut out = String::new();
    out.push_str("Benchmark Results:\n");
    out.push_str(&format!("  Total requests:     {}\n", results.total_requests));
    out.push_str(&format!("  Failed requests:    {}\n", results.failed_requests));
    out.push_str(&format!("  Requests/sec:       {:.1}\n", results.requests_per_sec));
    out.push_str(&format!("  Avg latency:        {:.2} ms\n", results.avg_request_ms));
    out.push_str(&format!("  Min latency:        {:.2} ms\n", results.min_request_ms));
    out.push_str(&format!("  Max latency:        {:.2} ms\n", results.max_request_ms));
    out.push_str(&format!("  P50 latency:        {:.2} ms\n", results.p50_ms));
    out.push_str(&format!("  P95 latency:        {:.2} ms\n", results.p95_ms));
    out.push_str(&format!("  P99 latency:        {:.2} ms\n", results.p99_ms));
    if let Some(rss) = results.memory_rss_kb {
        out.push_str(&format!("  Memory RSS:         {} KB ({:.1} MB)\n", rss, rss as f64 / 1024.0));
    }
    if let Some(cold) = results.cold_start_ms {
        out.push_str(&format!("  Cold start:         {:.1} ms\n", cold));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(percentile(&data, 50.0), 6.0);
        assert_eq!(percentile(&data, 0.0), 1.0);
        assert_eq!(percentile(&data, 100.0), 10.0);
    }

    #[test]
    fn test_percentile_empty() {
        assert_eq!(percentile(&[], 50.0), 0.0);
    }

    #[test]
    fn test_percentile_single() {
        assert_eq!(percentile(&[5.0], 50.0), 5.0);
        assert_eq!(percentile(&[5.0], 99.0), 5.0);
    }

    #[test]
    fn test_format_results() {
        let results = BenchmarkResults {
            cold_start_ms: Some(15.5),
            avg_request_ms: 2.5,
            min_request_ms: 1.0,
            max_request_ms: 10.0,
            p50_ms: 2.0,
            p95_ms: 5.0,
            p99_ms: 8.0,
            requests_per_sec: 5000.0,
            total_requests: 1000,
            failed_requests: 0,
            memory_rss_kb: Some(8192),
        };
        let output = format_results(&results);
        assert!(output.contains("5000.0"));
        assert!(output.contains("1000"));
        assert!(output.contains("2.50 ms"));
        assert!(output.contains("8192 KB"));
        assert!(output.contains("15.5 ms"));
    }

    #[test]
    fn test_bench_unreachable() {
        // Bench against a port nothing is listening on.
        let results = bench_app(59998, "/", 5);
        assert_eq!(results.failed_requests, 5);
        assert_eq!(results.total_requests, 5);
    }

    #[test]
    fn test_bench_concurrent_unreachable() {
        let results = bench_concurrent(59997, "/", 10, 2);
        assert_eq!(results.failed_requests, 10);
    }
}
