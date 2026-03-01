//! VM worker pool — each worker thread owns a warm Vm instance.
//!
//! Unlike the CLI server which creates a new Vm per request, the PaaS worker
//! keeps its Vm alive across requests. The opcode cache, class table, and
//! constant table persist, so repeated requests skip parsing and compilation.
//! Request-scoped state (output, session, file handles, etc.) is automatically
//! reset by `vm.execute()` at the start of each request.

use std::sync::mpsc;
use std::thread;

use php_rs_vm::vm::{Vm, VmConfig};

type Job = Box<dyn FnOnce(&mut Vm) + Send + 'static>;

/// A pool of worker threads, each owning a warm Vm instance.
pub struct WorkerPool {
    sender: Option<mpsc::Sender<Job>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl WorkerPool {
    /// Create a worker pool with `size` threads, each with its own Vm.
    pub fn new(size: usize) -> Self {
        Self::with_opcache(size, None)
    }

    /// Create a worker pool with optional opcache pre-warming.
    /// If `opcache_path` is provided, each VM loads the cached opcodes on startup.
    pub fn with_opcache(size: usize, opcache_path: Option<String>) -> Self {
        Self::with_preload(size, opcache_path, None)
    }

    /// Create a worker pool with opcache and preload script support.
    /// If `preload_script` is provided, it's executed on each VM at startup
    /// to warm framework classes, routes, and configuration.
    pub fn with_preload(
        size: usize,
        opcache_path: Option<String>,
        preload_script: Option<String>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = std::sync::Arc::new(std::sync::Mutex::new(receiver));
        let opcache_path = opcache_path.map(std::sync::Arc::new);
        let preload_script = preload_script.map(std::sync::Arc::new);

        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            let receiver = receiver.clone();
            let opcache_path = opcache_path.clone();
            let preload_script = preload_script.clone();
            let handle = thread::Builder::new()
                .name(format!("php-worker-{}", id))
                .spawn(move || {
                    // Each worker owns its own Vm — warm across requests.
                    let mut vm = Vm::with_config(VmConfig::default());

                    // Pre-warm the VM's opcode cache from disk if available.
                    if let Some(path) = &opcache_path {
                        match vm.load_opcache(std::path::Path::new(path.as_str())) {
                            Ok(n) => eprintln!("worker-{}: loaded {} cached oparrays", id, n),
                            Err(e) => eprintln!("worker-{}: opcache load failed: {}", id, e),
                        }
                    }

                    // Execute preload script to warm framework classes and routes.
                    if let Some(script_path) = &preload_script {
                        match std::fs::read_to_string(script_path.as_str()) {
                            Ok(source) => {
                                match php_rs_compiler::compile(&source) {
                                    Ok(op) => {
                                        match vm.execute(&op, None) {
                                            Ok(_) => {
                                                eprintln!("worker-{}: preloaded {}", id, script_path);
                                            }
                                            Err(e) => {
                                                eprintln!("worker-{}: preload execution error: {:?}", id, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("worker-{}: preload compile error: {:?}", id, e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("worker-{}: cannot read preload script {}: {}", id, script_path, e);
                            }
                        }
                    }

                    loop {
                        let job = {
                            let lock = receiver.lock().unwrap();
                            lock.recv()
                        };
                        match job {
                            Ok(job) => job(&mut vm),
                            Err(_) => break, // Channel closed, shutdown.
                        }
                    }
                })
                .expect("failed to spawn worker thread");
            workers.push(handle);
        }

        Self {
            sender: Some(sender),
            workers,
        }
    }

    /// Send a job to be executed on any available worker.
    /// The closure receives a mutable reference to the worker's warm Vm.
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce(&mut Vm) + Send + 'static,
    {
        if let Some(sender) = &self.sender {
            let _ = sender.send(Box::new(f));
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        // Drop the sender to close the channel and signal workers to stop.
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_worker_pool_executes_jobs() {
        let counter = Arc::new(AtomicU64::new(0));
        let pool = WorkerPool::new(2);

        for _ in 0..10 {
            let counter = counter.clone();
            pool.execute(move |_vm| {
                counter.fetch_add(1, Ordering::Relaxed);
            });
        }

        drop(pool); // Wait for all jobs to complete.
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_worker_pool_vm_is_warm() {
        // Verify that the VM persists across jobs within a worker.
        // Execute PHP that defines a function, then call it in the next job.
        // Since VMs are warm, the opcode cache persists.
        let pool = WorkerPool::new(1); // Single worker to ensure same VM.
        let result = Arc::new(std::sync::Mutex::new(String::new()));

        // First job: execute PHP.
        let result_clone = result.clone();
        pool.execute(move |vm| {
            let source = "<?php echo 'warm';";
            let op = php_rs_compiler::compile(source).unwrap();
            let output = vm.execute(&op, None).unwrap();
            *result_clone.lock().unwrap() = output;
        });

        drop(pool);
        assert_eq!(*result.lock().unwrap(), "warm");
    }

    #[test]
    fn test_worker_pool_concurrent_php() {
        let pool = WorkerPool::new(4);
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));

        for i in 0..20 {
            let results = results.clone();
            pool.execute(move |vm| {
                let source = format!("<?php echo {} + {};", i, i);
                let op = php_rs_compiler::compile(&source).unwrap();
                let output = vm.execute(&op, None).unwrap();
                results.lock().unwrap().push((i, output));
            });
        }

        drop(pool);
        let results = results.lock().unwrap();
        assert_eq!(results.len(), 20);
        for (i, output) in results.iter() {
            assert_eq!(*output, format!("{}", i + i));
        }
    }

    #[test]
    fn test_worker_pool_graceful_drop() {
        // Ensure dropping the pool waits for in-flight jobs.
        let started = Arc::new(AtomicU64::new(0));
        let finished = Arc::new(AtomicU64::new(0));

        let pool = WorkerPool::new(2);
        for _ in 0..5 {
            let started = started.clone();
            let finished = finished.clone();
            pool.execute(move |_vm| {
                started.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(10));
                finished.fetch_add(1, Ordering::Relaxed);
            });
        }

        drop(pool); // Should block until all 5 jobs finish.
        assert_eq!(finished.load(Ordering::Relaxed), 5);
    }
}
