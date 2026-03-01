//! PaaS SAPI — managed PHP application hosting runtime.
//!
//! A long-running HTTP server that executes PHP scripts with a warm VM worker
//! pool. Designed for multi-tenant PaaS deployment: one `php-rs-app` process
//! per tenant application.
//!
//! Features:
//! - Warm VM pool: VMs persist across requests (opcode cache stays warm)
//! - Environment-driven configuration (12-factor app style)
//! - Structured JSON logging to stdout
//! - Prometheus-compatible metrics endpoint
//! - Health/readiness probes for orchestrators
//! - Static file serving with MIME detection
//! - Graceful shutdown on SIGTERM

mod config;
mod handler;
mod logging;
mod metrics;
mod mime;
mod superglobals;
mod worker;

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use config::AppConfig;
use logging::Logger;
use metrics::Metrics;
use worker::WorkerPool;

fn main() {
    let config = AppConfig::from_env();

    let logger = Logger::new(&config.app_name);
    logger.info("boot", &format!(
        "php-rs-app starting: {}:{} workers={} root={} entry={}",
        config.host, config.port, config.workers, config.app_root, config.entry_script,
    ));

    let listener = match TcpListener::bind(format!("{}:{}", config.host, config.port)) {
        Ok(l) => l,
        Err(e) => {
            logger.error("boot", &format!("Failed to bind {}:{}: {}", config.host, config.port, e));
            std::process::exit(1);
        }
    };

    logger.info("boot", &format!("Listening on {}:{}", config.host, config.port));

    let shutdown = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Metrics::new());

    // Install SIGTERM/SIGINT handlers for graceful shutdown.
    unsafe {
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
    }
    SHUTDOWN_FLAG.store(0, Ordering::SeqCst);

    // Spawn shutdown monitor thread.
    let shutdown_clone = shutdown.clone();
    let logger_sig = logger.clone();
    std::thread::spawn(move || {
        loop {
            if SHUTDOWN_FLAG.load(Ordering::SeqCst) != 0 {
                logger_sig.info("shutdown", "Signal received, initiating graceful shutdown");
                shutdown_clone.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    // Create worker pool with warm VMs.
    // opcache: loads pre-compiled opcodes from disk (skips parse+compile).
    // preload: executes a PHP script to warm framework classes and routes.
    let preload_path = config.preload.as_ref().map(|p| {
        let root = std::path::Path::new(&config.app_root);
        let abs = root.join(p);
        if abs.exists() {
            abs.to_string_lossy().to_string()
        } else {
            p.clone()
        }
    });
    if let Some(ref path) = preload_path {
        logger.info("boot", &format!("Preload script: {}", path));
    }
    let pool = WorkerPool::with_preload(
        config.workers,
        config.opcache_path.clone(),
        preload_path,
    );

    // Mark as ready.
    ready.store(true, Ordering::Relaxed);
    logger.info("boot", "Application ready");

    // Accept loop — use non-blocking accept with short timeout so we can
    // check the shutdown flag promptly when SIGTERM arrives.
    listener.set_nonblocking(true).unwrap_or_default();
    let config = Arc::new(config);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            logger.info("shutdown", "Draining — no longer accepting connections");
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let config = config.clone();
                let metrics = metrics.clone();
                let logger = logger.clone();
                let ready = ready.clone();
                pool.execute(move |vm| {
                    handler::handle_connection(stream, vm, &config, &metrics, &logger, &ready);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connections — sleep briefly and check shutdown flag.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                logger.warn("accept", &format!("Connection error: {}", e));
            }
        }
    }

    // Graceful shutdown: wait for in-flight requests.
    logger.info("shutdown", "Waiting for in-flight requests to complete...");
    drop(pool);
    logger.info("shutdown", "Shutdown complete");
}

static SHUTDOWN_FLAG: AtomicU64 = AtomicU64::new(0);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN_FLAG.store(1, Ordering::SeqCst);
}
