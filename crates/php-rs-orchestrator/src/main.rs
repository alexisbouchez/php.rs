//! `php-rs-ctl` — CLI for managing PHP apps on the PaaS platform.
//!
//! Commands:
//!   app create <name> [--root <path>] [--entry <script>] [--workers <n>]
//!   app list
//!   app start <name>
//!   app stop <name>
//!   app restart <name>
//!   app status <name>
//!   app destroy <name>
//!   app config <name> set KEY=VALUE [KEY=VALUE...]
//!   app config <name> get
//!   deploy <name> --tar <path>
//!   deploy <name> --dir <path>
//!   monitor                      (foreground health monitor daemon)

mod api;
mod auth;
mod bench;
mod build;
mod cluster;
mod cron;
mod dashboard;
mod deploy;
mod gitdeploy;
mod isolation;
mod logs;
mod manifest;
mod preload;
mod process;
mod router;
mod scaling;
mod secrets;
mod services;
mod state;
mod tls;
mod workers;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use state::{AppState, PlatformState};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        std::process::exit(1);
    }

    let result = match args[0].as_str() {
        "api" => handle_api(&args[1..]),
        "app" => handle_app(&args[1..]),
        "bench" => handle_bench(&args[1..]),
        "build" => handle_build(&args[1..]),
        "cluster" => handle_cluster(&args[1..]),
        "cron" => handle_cron(&args[1..]),
        "db" => handle_db(&args[1..]),
        "deploy" => handle_deploy(&args[1..]),
        "dev" => handle_dev(&args[1..]),
        "exec" | "ssh" => handle_exec(&args[1..]),
        "git" => handle_git(&args[1..]),
        "init" => handle_init(&args[1..]),
        "logs" => handle_logs(&args[1..]),
        "monitor" => handle_monitor(),
        "preview" => handle_preview(&args[1..]),
        "redis" => handle_redis(&args[1..]),
        "run" => handle_run(&args[1..]),
        "storage" => handle_storage(&args[1..]),
        "worker" => handle_worker(&args[1..]),
        "router" => handle_router(&args[1..]),
        "routes" => handle_routes(),
        "tls" => handle_tls(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "version" | "--version" | "-v" => {
            println!("php-rs-ctl 0.1.0");
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[0]);
            print_usage();
            Err(1)
        }
    };

    if let Err(code) = result {
        std::process::exit(code);
    }
}

fn print_usage() {
    eprintln!(
        "php-rs-ctl — PaaS process manager for php.rs

USAGE:
    php-rs-ctl <command> [options]

COMMANDS:
    api [--port <port>] [--host <host>] [--token <token>]
    app create <name> [--root <path>] [--entry <script>] [--docroot <dir>] [--workers <n>]
    app list
    app start <name>
    app stop <name>
    app restart <name>
    app status [<name>]
    app destroy <name>
    app config <name> set KEY=VALUE [...]
    app config <name> get
    app scale <name> [<count>] [--min <n>] [--max <n>] [--target-ms <n>] [--cooldown <n>]
    bench <app> [--requests <n>] [--concurrency <n>] [--path <path>]
    build <source-dir>
    cluster status                    (show cluster state)
    cluster nodes                     (list nodes)
    cluster join <host:port>          (register this node)
    cluster drain <node-id>           (drain a node)
    cluster cordon <node-id>          (cordon a node)
    cluster uncordon <node-id>        (uncordon a node)
    cron <app> add \"<schedule>\" \"<command>\"
    cron <app> remove <id>
    cron <app> list [--name <name>] [--output <dir>]
    db create <app> <mysql|postgres>
    db destroy <app> <mysql|postgres>
    db info <app>
    deploy <name> --tar <path>
    deploy <name> --dir <path>
    dev [--dir <path>] [--port <port>]    (local dev mode)
    exec <app> [<command>]                (exec shell / command in app context)
    git init <app>               (create bare repo for git push deploy)
    git remove <app>
    git list
    git info <app>
    init [--dir <path>] [--name <name>]   (detect framework, generate Appfile.toml)
    logs <app> [-f] [-n <lines>] [--clear]
    redis create <app>
    redis destroy <app>
    redis info <app>
    run <app> \"<command>\"               (run one-off command in app context)
    storage create <app>              (provision S3-compatible bucket)
    storage destroy <app>
    storage info <app>
    worker <app> add \"<command>\" [--count <n>]
    worker <app> remove <id>
    worker <app> list
    worker <app> start
    worker <app> stop
    monitor
    preview <app> create [--branch <branch>]  (create preview deployment)
    preview <app> destroy                     (destroy preview deployment)
    preview <app> list
    router [--port <port>] [--domain <suffix>]
    routes
    tls generate <domain>         (generate self-signed cert)
    tls add <domain> --cert <path> --key <path>
    tls remove <domain>
    tls list
    help
    version

ENVIRONMENT:
    PHPRS_STATE_DIR    Override state directory (default: ~/.php-rs/)"
    );
}

// ── App Commands ────────────────────────────────────────────────────────────

fn handle_app(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl app <create|list|start|stop|restart|status|destroy|config>");
        return Err(1);
    }

    match args[0].as_str() {
        "create" => app_create(&args[1..]),
        "list" | "ls" => app_list(),
        "start" => app_start(&args[1..]),
        "stop" => app_stop(&args[1..]),
        "restart" => app_restart(&args[1..]),
        "status" => app_status(&args[1..]),
        "destroy" | "rm" | "delete" => app_destroy(&args[1..]),
        "config" => app_config(&args[1..]),
        "domains" => app_domains(&args[1..]),
        "scale" => app_scale(&args[1..]),
        _ => {
            eprintln!("Unknown app command: {}", args[0]);
            Err(1)
        }
    }
}

fn app_create(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl app create <name> [--root <path>] [--entry <script>] [--workers <n>]");
        return Err(1);
    }

    let name = &args[0];
    let mut root = ".".to_string();
    let mut entry = "public/index.php".to_string();
    let mut docroot = "public".to_string();
    let mut workers: u16 = 0;
    let mut env = HashMap::new();

    // Parse optional flags.
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" | "-r" => {
                i += 1;
                if i < args.len() { root = args[i].clone(); }
            }
            "--entry" | "-e" => {
                i += 1;
                if i < args.len() { entry = args[i].clone(); }
            }
            "--docroot" | "-d" => {
                i += 1;
                if i < args.len() { docroot = args[i].clone(); }
            }
            "--workers" | "-w" => {
                i += 1;
                if i < args.len() { workers = args[i].parse().unwrap_or(0); }
            }
            arg if arg.contains('=') => {
                // KEY=VALUE env var.
                if let Some(eq) = arg.find('=') {
                    env.insert(arg[..eq].to_string(), arg[eq + 1..].to_string());
                }
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    // Resolve root to absolute path.
    let root_path = std::path::Path::new(&root);
    let abs_root = root_path
        .canonicalize()
        .unwrap_or_else(|_| root_path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let mut state = PlatformState::load();

    if state.apps.contains_key(name.as_str()) {
        eprintln!("Error: app '{}' already exists", name);
        return Err(1);
    }

    let port = state.allocate_port();
    let app = AppState {
        name: name.clone(),
        root: abs_root,
        entry,
        docroot,
        port,
        pid: None,
        env,
        workers,
        created_at: state::now_iso8601(),
        releases: vec![],
        current_release: None,
    scaling: Default::default(),
    instances: vec![],
    cron_jobs: vec![],
    worker_configs: vec![],
    };

    println!("Created app '{}' on port {}", name, port);
    println!("  Root:    {}", app.root);
    println!("  Entry:   {}", app.entry);
    println!("  DocRoot: {}", app.docroot);

    state.apps.insert(name.clone(), app);
    save_or_exit(&state);

    Ok(())
}

fn app_list() -> Result<(), i32> {
    let state = PlatformState::load();

    if state.apps.is_empty() {
        println!("No apps registered.");
        return Ok(());
    }

    println!("{:<20} {:<8} {:<10} {:<10} {}", "NAME", "PORT", "STATUS", "PID", "ROOT");
    println!("{}", "-".repeat(80));

    let mut apps: Vec<&AppState> = state.apps.values().collect();
    apps.sort_by_key(|a| &a.name);

    for app in apps {
        let status = if app.is_running() { "running" } else if app.pid.is_some() { "crashed" } else { "stopped" };
        let pid = app.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        println!("{:<20} {:<8} {:<10} {:<10} {}", app.name, app.port, status, pid, app.root);
    }

    Ok(())
}

fn app_start(args: &[String]) -> Result<(), i32> {
    let name = require_name(args, "start")?;
    let mut state = PlatformState::load();

    let app = match state.get_app(&name) {
        Some(a) => a.clone(),
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    match process::start_app(&app) {
        process::StartResult::Started(pid) => {
            println!("Started '{}' (PID {}) on port {}", name, pid, app.port);
            state.get_app_mut(&name).unwrap().pid = Some(pid);
            save_or_exit(&state);
        }
        process::StartResult::AlreadyRunning(pid) => {
            println!("App '{}' is already running (PID {})", name, pid);
        }
        process::StartResult::Failed(e) => {
            eprintln!("Error starting '{}': {}", name, e);
            return Err(1);
        }
    }

    Ok(())
}

fn app_stop(args: &[String]) -> Result<(), i32> {
    let name = require_name(args, "stop")?;
    let mut state = PlatformState::load();

    let app = match state.get_app(&name) {
        Some(a) => a.clone(),
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    // Stop workers first.
    workers::stop_workers(&app);

    // Stop additional instances.
    for instance in &app.instances {
        if let Some(pid) = instance.pid {
            if state::process_alive(pid) {
                scaling::stop_instance(pid);
            }
        }
    }

    match process::stop_app(&app, Duration::from_secs(10)) {
        process::StopResult::Stopped => {
            println!("Stopped '{}'", name);
            let app_mut = state.get_app_mut(&name).unwrap();
            app_mut.pid = None;
            app_mut.instances.clear();
            for wc in &mut app_mut.worker_configs {
                wc.pids.clear();
            }
            save_or_exit(&state);
        }
        process::StopResult::Killed => {
            println!("Killed '{}' (did not stop gracefully)", name);
            let app_mut = state.get_app_mut(&name).unwrap();
            app_mut.pid = None;
            app_mut.instances.clear();
            for wc in &mut app_mut.worker_configs {
                wc.pids.clear();
            }
            save_or_exit(&state);
        }
        process::StopResult::NotRunning => {
            println!("App '{}' is not running", name);
            let app_mut = state.get_app_mut(&name).unwrap();
            app_mut.pid = None;
            app_mut.instances.clear();
            for wc in &mut app_mut.worker_configs {
                wc.pids.clear();
            }
            save_or_exit(&state);
        }
        process::StopResult::Failed(e) => {
            eprintln!("Error stopping '{}': {}", name, e);
            return Err(1);
        }
    }

    Ok(())
}

fn app_restart(args: &[String]) -> Result<(), i32> {
    let name = require_name(args, "restart")?;
    let mut state = PlatformState::load();

    let app = match state.get_app(&name) {
        Some(a) => a.clone(),
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    // Stop if running.
    if app.is_running() {
        print!("Stopping... ");
        process::stop_app(&app, Duration::from_secs(10));
        println!("done.");
    }
    state.get_app_mut(&name).unwrap().pid = None;

    // Start.
    let app = state.get_app(&name).unwrap().clone();
    match process::start_app(&app) {
        process::StartResult::Started(pid) => {
            println!("Started '{}' (PID {}) on port {}", name, pid, app.port);
            state.get_app_mut(&name).unwrap().pid = Some(pid);
            save_or_exit(&state);
        }
        process::StartResult::Failed(e) => {
            eprintln!("Error starting '{}': {}", name, e);
            return Err(1);
        }
        _ => {}
    }

    Ok(())
}

fn app_status(args: &[String]) -> Result<(), i32> {
    let state = PlatformState::load();

    if args.is_empty() {
        // Show all apps.
        return app_list();
    }

    let name = &args[0];
    let app = match state.get_app(name) {
        Some(a) => a,
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    let status = if app.is_running() {
        "running"
    } else if app.pid.is_some() {
        "crashed"
    } else {
        "stopped"
    };

    println!("App:      {}", app.name);
    println!("Status:   {}", status);
    println!("Port:     {}", app.port);
    println!("PID:      {}", app.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()));
    println!("Root:     {}", app.root);
    println!("Entry:    {}", app.entry);
    println!("DocRoot:  {}", app.docroot);
    println!("Workers:  {}", if app.workers == 0 { "auto".into() } else { app.workers.to_string() });
    println!("Created:  {}", app.created_at);

    if !app.env.is_empty() {
        println!("Env:");
        let mut keys: Vec<&String> = app.env.keys().collect();
        keys.sort();
        for key in keys {
            let val = &app.env[key];
            if secrets::is_encrypted(val) {
                println!("  {}=[encrypted]", key);
            } else {
                println!("  {}={}", key, val);
            }
        }
    }

    if !app.releases.is_empty() {
        println!("Releases: {} total (current: v{})",
            app.releases.len(),
            app.current_release.unwrap_or(0));
        for r in app.releases.iter().rev().take(5) {
            let marker = if Some(r.version) == app.current_release { " ← current" } else { "" };
            println!("  v{}: {} {}{}", r.version, r.path, r.deployed_at, marker);
        }
    }

    // Show isolation settings.
    let iso = isolation::IsolationConfig::from_env(&app.env);
    let desc = iso.describe();
    if !desc.is_empty() {
        println!("Isolation:");
        for d in &desc {
            println!("  {}", d);
        }
    }

    // Show scaling info.
    let total = scaling::current_instance_count(app);
    println!("Instances: {} (min: {}, max: {})",
        total, app.scaling.min_instances, app.scaling.max_instances);
    if !app.instances.is_empty() {
        for inst in &app.instances {
            let status = inst.pid.map_or("stopped".to_string(), |pid| {
                if state::process_alive(pid) {
                    format!("running (PID {})", pid)
                } else {
                    "dead".to_string()
                }
            });
            println!("  port {} — {}", inst.port, status);
        }
    }

    // Try health check if running.
    if app.is_running() {
        match process::health_check(app) {
            Ok(true) => println!("Health:   healthy"),
            Ok(false) => println!("Health:   unhealthy (non-200 response)"),
            Err(e) => println!("Health:   unknown ({})", e),
        }
    }

    Ok(())
}

fn app_destroy(args: &[String]) -> Result<(), i32> {
    let name = require_name(args, "destroy")?;
    let mut state = PlatformState::load();

    let app = match state.apps.remove(&name) {
        Some(a) => a,
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    // Stop workers first.
    workers::stop_workers(&app);

    // Stop additional instances.
    for instance in &app.instances {
        if let Some(pid) = instance.pid {
            if state::process_alive(pid) {
                scaling::stop_instance(pid);
            }
        }
    }

    // Stop primary process if running.
    if app.is_running() {
        print!("Stopping process... ");
        process::stop_app(&app, Duration::from_secs(10));
        println!("done.");
    }

    // Clean up app directory.
    let app_dir = std::path::Path::new(&state.apps_dir).join(&name);
    if app_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&app_dir) {
            eprintln!("Warning: cannot remove app directory {}: {}", app_dir.display(), e);
        }
    }

    println!("Destroyed app '{}'", name);
    save_or_exit(&state);

    Ok(())
}

fn app_config(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl app config <name> <set|get>");
        return Err(1);
    }

    let name = &args[0];
    let action = &args[1];

    let mut state = PlatformState::load();

    let mut secret_store = secrets::SecretStore::new();

    match action.as_str() {
        "set" => {
            let app = match state.get_app_mut(name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", name);
                    return Err(1);
                }
            };
            for kv in &args[2..] {
                if let Some(eq) = kv.find('=') {
                    let key = kv[..eq].to_string();
                    let value = kv[eq + 1..].to_string();
                    // Encrypt the value at rest.
                    let stored = match secret_store.encrypt(&value) {
                        Ok(enc) => {
                            println!("  {} = [encrypted]", key);
                            enc
                        }
                        Err(e) => {
                            eprintln!("Warning: encryption failed ({}), storing plaintext", e);
                            println!("  {} = {}", key, value);
                            value
                        }
                    };
                    app.env.insert(key, stored);
                } else {
                    eprintln!("Invalid format (use KEY=VALUE): {}", kv);
                    return Err(1);
                }
            }
            save_or_exit(&state);
            println!("Config updated for '{}'. Restart the app for changes to take effect.", name);
        }
        "get" => {
            let app = match state.get_app(name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", name);
                    return Err(1);
                }
            };
            if app.env.is_empty() {
                println!("No custom environment variables set for '{}'.", name);
            } else {
                let mut keys: Vec<&String> = app.env.keys().collect();
                keys.sort();
                for key in keys {
                    let val = &app.env[key];
                    if secrets::is_encrypted(val) {
                        // Never show encrypted values in plain text.
                        println!("{}=[encrypted]", key);
                    } else {
                        println!("{}={}", key, val);
                    }
                }
            }
        }
        "import" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl app config {} import <.env-file>", name);
                return Err(1);
            }
            let env_file = &args[2];
            let content = std::fs::read_to_string(env_file).map_err(|e| {
                eprintln!("Error reading {}: {}", env_file, e);
                1
            })?;
            let vars = logs::parse_dotenv(&content);
            let app = match state.get_app_mut(name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", name);
                    return Err(1);
                }
            };
            for (key, value) in &vars {
                let stored = match secret_store.encrypt(value) {
                    Ok(enc) => {
                        println!("  {} = [encrypted]", key);
                        enc
                    }
                    Err(_) => {
                        println!("  {} = {}", key, value);
                        value.clone()
                    }
                };
                app.env.insert(key.clone(), stored);
            }
            save_or_exit(&state);
            println!("Imported {} variables from {}. Restart the app for changes to take effect.", vars.len(), env_file);
        }
        _ => {
            eprintln!("Unknown config action: {} (use 'set', 'get', or 'import')", action);
            return Err(1);
        }
    }

    Ok(())
}

fn app_domains(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl app domains <name> <add|remove|list> [domain]");
        return Err(1);
    }

    let name = &args[0];
    let action = &args[1];

    let mut state = PlatformState::load();

    let app = match state.get_app_mut(name) {
        Some(a) => a,
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    let domains_str = app.env.get("APP_DOMAINS").cloned().unwrap_or_default();
    let mut domains: Vec<String> = domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match action.as_str() {
        "add" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl app domains {} add <domain>", name);
                return Err(1);
            }
            let domain = args[2].to_lowercase();
            if domains.contains(&domain) {
                println!("Domain '{}' already configured for '{}'", domain, name);
            } else {
                domains.push(domain.clone());
                app.env.insert("APP_DOMAINS".into(), domains.join(","));
                save_or_exit(&state);
                println!("Added domain '{}' to '{}'", domain, name);
                println!("Point your DNS to this server and restart the router.");
            }
        }
        "remove" | "rm" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl app domains {} remove <domain>", name);
                return Err(1);
            }
            let domain = args[2].to_lowercase();
            if let Some(pos) = domains.iter().position(|d| d == &domain) {
                domains.remove(pos);
                if domains.is_empty() {
                    app.env.remove("APP_DOMAINS");
                } else {
                    app.env.insert("APP_DOMAINS".into(), domains.join(","));
                }
                save_or_exit(&state);
                println!("Removed domain '{}' from '{}'", domain, name);
            } else {
                println!("Domain '{}' not found for '{}'", domain, name);
            }
        }
        "list" | "ls" => {
            let platform_domain = std::env::var("ROUTER_DOMAIN")
                .unwrap_or_else(|_| "phprs.local".into());
            println!("Domains for '{}':", name);
            println!("  {}.{} (default)", name, platform_domain);
            for domain in &domains {
                println!("  {}", domain);
            }
        }
        _ => {
            eprintln!("Unknown domains action: {} (use add, remove, or list)", action);
            return Err(1);
        }
    }

    Ok(())
}

// ── Cron Command ────────────────────────────────────────────────────────────

fn handle_cron(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl cron <app> <add|remove|list|enable|disable> [options]");
        eprintln!("  add <schedule> <command>   Add a cron job");
        eprintln!("  remove <id>                Remove a cron job");
        eprintln!("  list                       List cron jobs");
        eprintln!("  enable <id>                Enable a cron job");
        eprintln!("  disable <id>               Disable a cron job");
        return Err(1);
    }

    let app_name = &args[0];
    let action = &args[1];
    let mut state = PlatformState::load();

    match action.as_str() {
        "add" => {
            if args.len() < 4 {
                eprintln!("Usage: php-rs-ctl cron {} add \"<schedule>\" \"<command>\"", app_name);
                eprintln!("  Schedule: standard cron (minute hour dom month dow)");
                eprintln!("  Example:  php-rs-ctl cron myapp add \"*/5 * * * *\" \"php artisan schedule:run\"");
                return Err(1);
            }

            let schedule = &args[2];
            let command = args[3..].join(" ");

            // Validate schedule.
            if let Err(e) = cron::parse_schedule(schedule) {
                eprintln!("Error: invalid schedule: {}", e);
                return Err(1);
            }

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let next_id = app.cron_jobs.iter().map(|j| j.id).max().unwrap_or(0) + 1;
            let job = cron::CronJob {
                id: next_id,
                schedule: schedule.clone(),
                command: command.clone(),
                no_overlap: true,
                enabled: true,
                running_pid: None,
            };
            app.cron_jobs.push(job);
            save_or_exit(&state);
            println!("Added cron job #{} for '{}':", next_id, app_name);
            println!("  Schedule: {}", schedule);
            println!("  Command:  {}", command);
        }
        "remove" | "rm" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl cron {} remove <id>", app_name);
                return Err(1);
            }
            let id: u64 = args[2].parse().map_err(|_| {
                eprintln!("Invalid job ID: {}", args[2]);
                1
            })?;

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if let Some(pos) = app.cron_jobs.iter().position(|j| j.id == id) {
                app.cron_jobs.remove(pos);
                save_or_exit(&state);
                println!("Removed cron job #{} from '{}'", id, app_name);
            } else {
                eprintln!("Error: cron job #{} not found", id);
                return Err(1);
            }
        }
        "list" | "ls" => {
            let app = match state.get_app(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if app.cron_jobs.is_empty() {
                println!("No cron jobs for '{}'", app_name);
            } else {
                println!("Cron jobs for '{}':", app_name);
                for job in &app.cron_jobs {
                    let status = if job.enabled { "enabled" } else { "disabled" };
                    let overlap = if job.no_overlap { "no-overlap" } else { "allow-overlap" };
                    println!(
                        "  #{}: {} | {} [{}] [{}]",
                        job.id, job.schedule, job.command, status, overlap
                    );
                }
            }
        }
        "enable" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl cron {} enable <id>", app_name);
                return Err(1);
            }
            let id: u64 = args[2].parse().map_err(|_| {
                eprintln!("Invalid job ID: {}", args[2]);
                1
            })?;

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if let Some(job) = app.cron_jobs.iter_mut().find(|j| j.id == id) {
                job.enabled = true;
                save_or_exit(&state);
                println!("Enabled cron job #{}", id);
            } else {
                eprintln!("Error: cron job #{} not found", id);
                return Err(1);
            }
        }
        "disable" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl cron {} disable <id>", app_name);
                return Err(1);
            }
            let id: u64 = args[2].parse().map_err(|_| {
                eprintln!("Invalid job ID: {}", args[2]);
                1
            })?;

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if let Some(job) = app.cron_jobs.iter_mut().find(|j| j.id == id) {
                job.enabled = false;
                save_or_exit(&state);
                println!("Disabled cron job #{}", id);
            } else {
                eprintln!("Error: cron job #{} not found", id);
                return Err(1);
            }
        }
        _ => {
            eprintln!("Unknown cron action: {} (use add, remove, list, enable, disable)", action);
            return Err(1);
        }
    }

    Ok(())
}

// ── Worker Command ──────────────────────────────────────────────────────────

fn handle_worker(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl worker <app> <add|remove|list|start|stop> [options]");
        eprintln!("  add \"<command>\" [--count <n>]    Add a worker type");
        eprintln!("  remove <id>                       Remove a worker type");
        eprintln!("  list                              List worker types");
        eprintln!("  start                             Start all workers");
        eprintln!("  stop                              Stop all workers");
        return Err(1);
    }

    let app_name = &args[0];
    let action = &args[1];
    let mut state = PlatformState::load();

    match action.as_str() {
        "add" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl worker {} add \"<command>\" [--count <n>]", app_name);
                return Err(1);
            }

            let command = &args[2];
            let mut count: u16 = 1;

            let mut i = 3;
            while i < args.len() {
                if args[i] == "--count" || args[i] == "-n" {
                    i += 1;
                    if i < args.len() {
                        count = args[i].parse().unwrap_or(1);
                    }
                }
                i += 1;
            }

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let next_id = app
                .worker_configs
                .iter()
                .map(|w| w.id)
                .max()
                .unwrap_or(0)
                + 1;
            let wc = workers::WorkerConfig {
                id: next_id,
                command: command.clone(),
                count,
                enabled: true,
                pids: vec![],
            };
            app.worker_configs.push(wc);
            save_or_exit(&state);
            println!(
                "Added worker #{} for '{}': {} (count: {})",
                next_id, app_name, command, count
            );
        }
        "remove" | "rm" => {
            if args.len() < 3 {
                eprintln!("Usage: php-rs-ctl worker {} remove <id>", app_name);
                return Err(1);
            }
            let id: u64 = args[2].parse().map_err(|_| {
                eprintln!("Invalid worker ID: {}", args[2]);
                1
            })?;

            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if let Some(pos) = app.worker_configs.iter().position(|w| w.id == id) {
                let wc = app.worker_configs.remove(pos);
                // Stop any running processes.
                for &pid in &wc.pids {
                    if state::process_alive(pid) {
                        workers::stop_worker_pid_pub(pid);
                    }
                }
                save_or_exit(&state);
                println!("Removed worker #{} from '{}'", id, app_name);
            } else {
                eprintln!("Error: worker #{} not found", id);
                return Err(1);
            }
        }
        "list" | "ls" => {
            let app = match state.get_app(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            if app.worker_configs.is_empty() {
                println!("No workers for '{}'", app_name);
            } else {
                println!("Workers for '{}':", app_name);
                for wc in &app.worker_configs {
                    let running = wc.pids.iter().filter(|&&p| state::process_alive(p)).count();
                    let status = if wc.enabled { "enabled" } else { "disabled" };
                    println!(
                        "  #{}: {} (count: {}, running: {}) [{}]",
                        wc.id, wc.command, wc.count, running, status
                    );
                    for &pid in &wc.pids {
                        let alive = if state::process_alive(pid) { "running" } else { "dead" };
                        println!("    PID {} — {}", pid, alive);
                    }
                }
            }
        }
        "start" => {
            let app = match state.get_app(app_name) {
                Some(a) => a.clone(),
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let actions = workers::start_workers(&app);
            if actions.is_empty() {
                println!("No workers to start for '{}'", app_name);
            }
            for (_, action) in &actions {
                println!("{}", action);
            }

            // Update PIDs in state (need to extract from actions).
            // For simplicity, run monitor_workers to sync state.
            workers::monitor_workers(&mut state);
            save_or_exit(&state);
        }
        "stop" => {
            let app = match state.get_app(app_name) {
                Some(a) => a.clone(),
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let actions = workers::stop_workers(&app);
            if actions.is_empty() {
                println!("No workers running for '{}'", app_name);
            }
            for (_, action) in &actions {
                println!("{}", action);
            }

            // Clear PIDs.
            let app_mut = state.get_app_mut(app_name).unwrap();
            for wc in &mut app_mut.worker_configs {
                wc.pids.clear();
            }
            save_or_exit(&state);
        }
        _ => {
            eprintln!(
                "Unknown worker action: {} (use add, remove, list, start, stop)",
                action
            );
            return Err(1);
        }
    }

    Ok(())
}

// ── Scale Command ───────────────────────────────────────────────────────────

fn app_scale(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl app scale <name> <count>");
        eprintln!("       php-rs-ctl app scale <name> --min <n> --max <n> [--target-ms <n>] [--cooldown <n>]");
        return Err(1);
    }

    let name = &args[0];
    let mut state = PlatformState::load();

    let app = match state.get_app_mut(name) {
        Some(a) => a,
        None => {
            eprintln!("Error: app '{}' not found", name);
            return Err(1);
        }
    };

    // Parse flags.
    if args.len() >= 2 {
        let mut i = 1;
        let mut has_config = false;

        while i < args.len() {
            match args[i].as_str() {
                "--min" => {
                    i += 1;
                    if i < args.len() {
                        app.scaling.min_instances = args[i].parse().unwrap_or(1);
                        has_config = true;
                    }
                }
                "--max" => {
                    i += 1;
                    if i < args.len() {
                        app.scaling.max_instances = args[i].parse().unwrap_or(1);
                        has_config = true;
                    }
                }
                "--target-ms" => {
                    i += 1;
                    if i < args.len() {
                        app.scaling.target_response_ms = args[i].parse().unwrap_or(500);
                        has_config = true;
                    }
                }
                "--cooldown" => {
                    i += 1;
                    if i < args.len() {
                        app.scaling.cooldown_secs = args[i].parse().unwrap_or(300);
                        has_config = true;
                    }
                }
                n if n.parse::<usize>().is_ok() => {
                    // Direct instance count: `app scale myapp 3`
                    let count: usize = n.parse().unwrap();
                    save_or_exit(&state);
                    match scaling::set_instance_count(&mut state, name, count) {
                        Ok(actions) => {
                            for action in &actions {
                                println!("{}", action);
                            }
                            save_or_exit(&state);
                            let total = scaling::current_instance_count(
                                state.get_app(name).unwrap(),
                            );
                            println!("'{}' now running {} instance(s)", name, total);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            return Err(1);
                        }
                    }
                    return Ok(());
                }
                _ => {
                    eprintln!("Unknown scale flag: {}", args[i]);
                    return Err(1);
                }
            }
            i += 1;
        }

        if has_config {
            let scaling = app.scaling.clone();
            save_or_exit(&state);
            println!("Scaling config for '{}':", name);
            println!("  Min instances:      {}", scaling.min_instances);
            println!("  Max instances:      {}", scaling.max_instances);
            println!("  Target response:    {} ms", scaling.target_response_ms);
            println!("  Cooldown:           {} s", scaling.cooldown_secs);
            if scaling.max_instances > 1 {
                println!("  Auto-scaling:       enabled");
            } else {
                println!("  Auto-scaling:       disabled (max_instances = 1)");
            }
            return Ok(());
        }
    }

    // No arguments beyond name — show current status.
    let app = state.get_app(name).unwrap();
    let total = scaling::current_instance_count(app);
    println!("'{}' scaling status:", name);
    println!("  Running instances:  {}", total);
    println!("  Min instances:      {}", app.scaling.min_instances);
    println!("  Max instances:      {}", app.scaling.max_instances);
    println!("  Target response:    {} ms", app.scaling.target_response_ms);
    println!("  Cooldown:           {} s", app.scaling.cooldown_secs);
    if !app.instances.is_empty() {
        println!("  Additional instances:");
        for inst in &app.instances {
            let status = inst.pid.map_or("stopped".to_string(), |pid| {
                if state::process_alive(pid) {
                    format!("running (PID {})", pid)
                } else {
                    "dead".to_string()
                }
            });
            println!("    port {} — {}", inst.port, status);
        }
    }

    Ok(())
}

// ── Deploy Command ──────────────────────────────────────────────────────────

fn handle_deploy(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl deploy <name> --tar <path> | --dir <path>");
        return Err(1);
    }

    let name = &args[0];
    let mut tarball: Option<String> = None;
    let mut dir: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tar" | "-t" => {
                i += 1;
                if i < args.len() { tarball = Some(args[i].clone()); }
            }
            "--dir" | "-d" => {
                i += 1;
                if i < args.len() { dir = Some(args[i].clone()); }
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    let mut state = PlatformState::load();

    if !state.apps.contains_key(name.as_str()) {
        eprintln!("Error: app '{}' not found. Create it first with: php-rs-ctl app create {}", name, name);
        return Err(1);
    }

    if let Some(tarball) = tarball {
        println!("Deploying '{}' from tarball: {}", name, tarball);
        match deploy::deploy(&mut state, name, &tarball, Duration::from_secs(30)) {
            Ok(version) => {
                println!("Deployed '{}' v{} successfully!", name, version);
            }
            Err(e) => {
                eprintln!("Deploy failed: {}", e);
                return Err(1);
            }
        }
    } else if let Some(dir) = dir {
        println!("Deploying '{}' from directory: {}", name, dir);
        match deploy::deploy_local(&mut state, name, &dir) {
            Ok(()) => {
                println!("Updated app root for '{}'. Restart the app for changes to take effect.", name);
            }
            Err(e) => {
                eprintln!("Deploy failed: {}", e);
                return Err(1);
            }
        }
    } else {
        eprintln!("Error: specify --tar <path> or --dir <path>");
        return Err(1);
    }

    Ok(())
}

// ── API Command ─────────────────────────────────────────────────────────

fn handle_api(args: &[String]) -> Result<(), i32> {
    let mut config = api::ApiConfig::from_env();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    config.port = args[i].parse().unwrap_or(9090);
                }
            }
            "--host" | "-h" => {
                i += 1;
                if i < args.len() {
                    config.host = args[i].clone();
                }
            }
            "--token" | "-t" => {
                i += 1;
                if i < args.len() {
                    config.api_token = args[i].clone();
                }
            }
            _ => {
                eprintln!("Unknown api flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    api::run_api(config, shutdown);
    Ok(())
}

// ── Build Command ───────────────────────────────────────────────────────

fn handle_build(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl build <source-dir> [--name <name>] [--output <dir>]");
        return Err(1);
    }

    let source_dir = &args[0];
    let mut name = std::path::Path::new(source_dir)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "app".into());
    let mut output_dir = ".".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "-n" => {
                i += 1;
                if i < args.len() { name = args[i].clone(); }
            }
            "--output" | "-o" => {
                i += 1;
                if i < args.len() { output_dir = args[i].clone(); }
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    println!("Building '{}' from {}", name, source_dir);
    match build::build(source_dir, &output_dir, &name) {
        Ok(result) => {
            for line in &result.log {
                println!("  {}", line);
            }
            println!("\nSlug: {}", result.slug_path);
            println!("Framework: {}", result.appfile.app.framework);
            println!("Entry: {}", result.appfile.app.entry);
        }
        Err(e) => {
            eprintln!("Build failed: {}", e);
            return Err(1);
        }
    }

    Ok(())
}

// ── Cluster Command (Phase 10) ──────────────────────────────────────────────

fn handle_cluster(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl cluster <status|nodes|join|drain|cordon|uncordon>");
        return Err(1);
    }

    let cluster_path = cluster_state_path();
    let mut state = load_cluster_state(&cluster_path);

    match args[0].as_str() {
        "status" => {
            // Check heartbeats first.
            let failed = state.check_heartbeats();
            if !failed.is_empty() {
                save_cluster_state(&cluster_path, &state);
            }

            let total = state.nodes.len();
            let ready = state.ready_nodes().len();
            let apps: usize = state.placements.values().map(|v| v.len()).sum();

            println!("Cluster Status:");
            println!("  Nodes:     {} total, {} ready", total, ready);
            println!("  App placements: {}", apps);
            println!("  Heartbeat timeout: {}s", state.heartbeat_timeout_secs);

            if !failed.is_empty() {
                println!("\n  Failed nodes:");
                for id in &failed {
                    println!("    - {} (heartbeat timeout)", id);
                }
            }

            // Check for failover actions.
            let ha = cluster::HAConfig::default();
            let actions = cluster::check_failover(&state, &ha);
            if !actions.is_empty() {
                println!("\n  Failover actions needed:");
                for action in &actions {
                    println!("    - {} on {}: {:?} ({})",
                        action.app_name, action.failed_node, action.action, action.reason);
                }
            }
        }
        "nodes" | "ls" => {
            state.check_heartbeats();

            if state.nodes.is_empty() {
                println!("No nodes registered.");
                return Ok(());
            }

            println!("{:<20} {:<15} {:<10} {:<10} {:<10} {:<10}",
                "ID", "HOST", "STATUS", "APPS", "CPU%", "MEM(MB)");
            println!("{}", "-".repeat(75));

            let mut nodes: Vec<_> = state.nodes.values().collect();
            nodes.sort_by_key(|n| &n.id);
            for node in nodes {
                let status = match node.status {
                    cluster::NodeStatus::Ready => "Ready",
                    cluster::NodeStatus::NotReady => "NotReady",
                    cluster::NodeStatus::Draining => "Draining",
                    cluster::NodeStatus::Cordoned => "Cordoned",
                };
                println!("{:<20} {:<15} {:<10} {:<10} {:<10.1} {:<10}",
                    node.id, node.host, status,
                    node.usage.running_apps,
                    node.usage.cpu_percent,
                    node.usage.memory_used_mb);
            }
        }
        "join" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl cluster join <host:port>");
                return Err(1);
            }

            let addr = &args[1];
            let (host, port) = if let Some(colon) = addr.rfind(':') {
                let h = addr[..colon].to_string();
                let p: u16 = addr[colon + 1..].parse().unwrap_or(8080);
                (h, p)
            } else {
                (addr.clone(), 8080)
            };

            let node_id = cluster::generate_node_id();
            let node = cluster::ClusterNode {
                id: node_id.clone(),
                host: host.clone(),
                api_port: port,
                status: cluster::NodeStatus::Ready,
                capacity: cluster::NodeCapacity::default(),
                usage: cluster::NodeUsage::default(),
                apps: Vec::new(),
                last_heartbeat: crate::state::now_iso8601(),
                labels: HashMap::new(),
                registered_at: crate::state::now_iso8601(),
            };

            state.register_node(node);
            save_cluster_state(&cluster_path, &state);

            println!("Node '{}' joined cluster at {}:{}", node_id, host, port);
        }
        "drain" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl cluster drain <node-id>");
                return Err(1);
            }
            if state.drain_node(&args[1]) {
                save_cluster_state(&cluster_path, &state);
                println!("Node '{}' is now draining.", args[1]);
            } else {
                eprintln!("Node '{}' not found.", args[1]);
                return Err(1);
            }
        }
        "cordon" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl cluster cordon <node-id>");
                return Err(1);
            }
            if state.cordon_node(&args[1]) {
                save_cluster_state(&cluster_path, &state);
                println!("Node '{}' cordoned.", args[1]);
            } else {
                eprintln!("Node '{}' not found.", args[1]);
                return Err(1);
            }
        }
        "uncordon" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl cluster uncordon <node-id>");
                return Err(1);
            }
            if state.uncordon_node(&args[1]) {
                save_cluster_state(&cluster_path, &state);
                println!("Node '{}' uncordoned.", args[1]);
            } else {
                eprintln!("Node '{}' not found or not cordoned.", args[1]);
                return Err(1);
            }
        }
        _ => {
            eprintln!("Unknown cluster command: {}", args[0]);
            return Err(1);
        }
    }

    Ok(())
}

fn cluster_state_path() -> std::path::PathBuf {
    let base = if let Ok(dir) = std::env::var("PHPRS_STATE_DIR") {
        std::path::PathBuf::from(dir)
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".php-rs")
    } else {
        std::path::PathBuf::from("/tmp/.php-rs")
    };
    base.join("cluster.json")
}

fn load_cluster_state(path: &std::path::Path) -> cluster::ClusterState {
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(state) = serde_json::from_str(&content) {
                return state;
            }
        }
    }
    cluster::ClusterState::default()
}

fn save_cluster_state(path: &std::path::Path, state: &cluster::ClusterState) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(path, &json);
    }
}

// ── Bench Command ───────────────────────────────────────────────────────────

fn handle_bench(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl bench <app> [--requests <n>] [--concurrency <n>] [--path <path>]");
        return Err(1);
    }

    let app_name = &args[0];
    let mut total_requests: usize = 100;
    let mut concurrency: usize = 1;
    let mut path = "/".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--requests" | "-n" => {
                i += 1;
                if i < args.len() {
                    total_requests = args[i].parse().unwrap_or(100);
                }
            }
            "--concurrency" | "-c" => {
                i += 1;
                if i < args.len() {
                    concurrency = args[i].parse().unwrap_or(1);
                }
            }
            "--path" | "-p" => {
                i += 1;
                if i < args.len() {
                    path = args[i].clone();
                }
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    // Look up app to get its port.
    let platform = PlatformState::load();
    let app = match platform.apps.get(app_name) {
        Some(a) => a,
        None => {
            eprintln!("App '{}' not found.", app_name);
            return Err(1);
        }
    };

    if !app.is_running() {
        eprintln!("App '{}' is not running.", app_name);
        return Err(1);
    }

    println!(
        "Benchmarking '{}' on port {} \u{2014} {} requests, concurrency {}",
        app_name, app.port, total_requests, concurrency
    );
    println!("Path: {}", path);
    println!();

    let results = if concurrency <= 1 {
        bench::bench_app(app.port, &path, total_requests)
    } else {
        bench::bench_concurrent(app.port, &path, total_requests, concurrency)
    };

    print!("{}", bench::format_results(&results));
    Ok(())
}

// ── Monitor Command ─────────────────────────────────────────────────────────

fn handle_monitor() -> Result<(), i32> {
    println!("php-rs-ctl monitor — watching app processes...");
    println!("Press Ctrl-C to stop.");

    let mut autoscaler = scaling::Autoscaler::new();
    let mut cron_runner = cron::CronRunner::new();

    loop {
        let mut state = PlatformState::load();

        // Monitor crashed processes and resource limits.
        let actions = process::monitor_apps(&mut state);

        // Run autoscaler tick (evaluate and apply scaling decisions).
        let scale_actions = autoscaler.tick(&mut state);

        // Run cron scheduler tick.
        let cron_actions = cron_runner.tick(&state);

        // Monitor worker processes (restart crashed workers).
        let worker_actions = workers::monitor_workers(&mut state);

        let all_actions: Vec<_> = actions
            .into_iter()
            .chain(scale_actions)
            .chain(cron_actions)
            .chain(worker_actions)
            .collect();

        if !all_actions.is_empty() {
            for (name, action) in &all_actions {
                println!("[{}] {}: {}", state::now_iso8601(), name, action);
            }
            if let Err(e) = state.save() {
                eprintln!("Warning: cannot save state: {}", e);
            }
        }

        std::thread::sleep(Duration::from_secs(5));
    }
}

// ── Router Command ──────────────────────────────────────────────────────────

fn handle_router(args: &[String]) -> Result<(), i32> {
    let mut config = router::RouterConfig::from_env();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    config.listen_port = args[i].parse().unwrap_or(80);
                }
            }
            "--domain" | "-d" => {
                i += 1;
                if i < args.len() {
                    config.platform_domain = args[i].clone();
                }
            }
            "--host" | "-h" => {
                i += 1;
                if i < args.len() {
                    config.listen_host = args[i].clone();
                }
            }
            _ => {
                eprintln!("Unknown router flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    router::run_router(config, shutdown);
    Ok(())
}

fn handle_routes() -> Result<(), i32> {
    let state = PlatformState::load();
    let table = router::RoutingTable::new(
        &std::env::var("ROUTER_DOMAIN").unwrap_or_else(|_| "phprs.local".into()),
    );
    table.reload_from_state(&state);

    let routes = table.all_routes();
    if routes.is_empty() {
        println!("No active routes (no running apps).");
        return Ok(());
    }

    println!("{:<40} {:<20} {:<8}", "DOMAIN", "APP", "PORT");
    println!("{}", "-".repeat(70));

    let mut domains: Vec<(&String, &router::RouteEntry)> = routes.iter().collect();
    domains.sort_by_key(|(d, _)| d.to_string());

    for (domain, entry) in domains {
        println!("{:<40} {:<20} {:<8}", domain, entry.app_name, entry.backend_port);
    }

    Ok(())
}

// ── Logs Command ────────────────────────────────────────────────────────────

fn handle_logs(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl logs <app> [-f] [-n <lines>] [--clear]");
        return Err(1);
    }

    let app_name = &args[0];
    let mut follow = false;
    let mut num_lines: usize = 100;
    let mut clear = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--follow" => follow = true,
            "--clear" => clear = true,
            "-n" | "--lines" => {
                i += 1;
                if i < args.len() {
                    num_lines = args[i].parse().unwrap_or(100);
                }
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                return Err(1);
            }
        }
        i += 1;
    }

    // Verify app exists.
    let state = PlatformState::load();
    if state.get_app(app_name).is_none() {
        eprintln!("Error: app '{}' not found", app_name);
        return Err(1);
    }

    let logs_dir = logs::default_logs_dir();

    if clear {
        logs::clear_logs(app_name, &logs_dir);
        println!("Logs cleared for '{}'.", app_name);
        return Ok(());
    }

    if follow {
        println!("Following logs for '{}' (Ctrl-C to stop)...", app_name);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        logs::follow_logs(app_name, &logs_dir, &shutdown);
    } else {
        let lines = logs::read_logs(app_name, &logs_dir, num_lines);
        if lines.is_empty() {
            println!("No logs for '{}'.", app_name);
        } else {
            for line in &lines {
                println!("{}", line);
            }
        }
    }

    Ok(())
}

// ── Git Command ─────────────────────────────────────────────────────────────

fn handle_git(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl git <init|remove|list|info> [app]");
        return Err(1);
    }

    let repos_dir = gitdeploy::default_repos_dir();

    match args[0].as_str() {
        "init" | "setup" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl git init <app>");
                return Err(1);
            }
            let app_name = &args[1];

            // Verify the app exists.
            let state = PlatformState::load();
            if state.get_app(app_name).is_none() {
                eprintln!("Error: app '{}' not found. Create it first.", app_name);
                return Err(1);
            }

            match gitdeploy::init_repo(app_name, &repos_dir) {
                Ok(repo_path) => {
                    println!("Git repo initialized for '{}'.", app_name);
                    println!("  Repo: {}", repo_path.display());
                    println!();
                    println!("Add as a remote:");
                    println!("  git remote add phprs {}", repo_path.display());
                    println!();
                    println!("Deploy with:");
                    println!("  git push phprs main");
                    println!();
                    println!("For SSH deployment from another machine:");
                    if let Ok(hostname) = std::env::var("HOSTNAME") {
                        println!(
                            "  git remote add phprs ssh://user@{}/{}",
                            hostname,
                            repo_path.display()
                        );
                    } else {
                        println!(
                            "  git remote add phprs ssh://user@<host>/{}",
                            repo_path.display()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "remove" | "rm" | "delete" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl git remove <app>");
                return Err(1);
            }
            let app_name = &args[1];
            match gitdeploy::remove_repo(app_name, &repos_dir) {
                Ok(()) => println!("Git repo removed for '{}'.", app_name),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "list" | "ls" => {
            let repos = gitdeploy::list_repos(&repos_dir);
            if repos.is_empty() {
                println!("No git repos configured.");
                println!("Set one up with: php-rs-ctl git init <app>");
            } else {
                println!("{:<20} {}", "APP", "REPO PATH");
                println!("{}", "-".repeat(60));
                for name in &repos {
                    let path = gitdeploy::repo_path(name, &repos_dir);
                    println!("{:<20} {}", name, path.display());
                }
            }
        }
        "info" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl git info <app>");
                return Err(1);
            }
            let app_name = &args[1];
            if !gitdeploy::repo_exists(app_name, &repos_dir) {
                println!("No git repo for '{}'.", app_name);
                println!("Set one up with: php-rs-ctl git init {}", app_name);
                return Ok(());
            }
            let path = gitdeploy::repo_path(app_name, &repos_dir);
            println!("Git repo for '{}':", app_name);
            println!("  Path: {}", path.display());
            println!("  Local remote:");
            println!("    git remote add phprs {}", path.display());
            println!("  SSH remote:");
            println!(
                "    git remote add phprs ssh://user@<host>/{}",
                path.display()
            );
        }
        _ => {
            eprintln!("Unknown git command: {} (use init, remove, list, or info)", args[0]);
            return Err(1);
        }
    }

    Ok(())
}

// ── Database Command ────────────────────────────────────────────────────────

fn handle_db(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl db <create|destroy|info> <app> [mysql|postgres]");
        return Err(1);
    }

    let action = &args[0];
    let app_name = &args[1];
    let db_type = args.get(2).map(|s| s.as_str()).unwrap_or("mysql");

    let mut state = PlatformState::load();
    let svc_config = services::ServiceConfig::from_env();

    match action.as_str() {
        "create" => {
            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            // Check if a DB service already exists.
            let existing = services::list_app_services(&app.env);
            if existing.iter().any(|s| s.service_type == db_type) {
                eprintln!("Error: {} service already provisioned for '{}'", db_type, app_name);
                return Err(1);
            }

            println!("Provisioning {} database for '{}'...", db_type, app_name);
            let instance = match db_type {
                "mysql" => services::mysql_create(app_name, &svc_config),
                "postgres" | "postgresql" | "pg" => services::postgres_create(app_name, &svc_config),
                _ => {
                    eprintln!("Unknown database type: {} (use 'mysql' or 'postgres')", db_type);
                    return Err(1);
                }
            };

            match instance {
                Ok(svc) => {
                    println!("Database created:");
                    println!("  Type:     {}", svc.service_type);
                    println!("  Name:     {}", svc.name);
                    println!("  Host:     {}:{}", svc.host, svc.port);
                    println!("  User:     {}", svc.username);
                    println!("  URL:      {}", svc.url);
                    println!("  Env var:  {}", svc.env_var);

                    let mut svcs = existing;
                    svcs.push(svc);
                    services::save_app_services(&mut app.env, &svcs);
                    save_or_exit(&state);
                    println!("\nRestart the app for the DATABASE_URL to take effect.");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "destroy" | "rm" | "delete" => {
            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let existing = services::list_app_services(&app.env);
            let (to_destroy, remaining): (Vec<_>, Vec<_>) = existing
                .into_iter()
                .partition(|s| s.service_type == db_type);

            if to_destroy.is_empty() {
                eprintln!("No {} service found for '{}'", db_type, app_name);
                return Err(1);
            }

            for svc in &to_destroy {
                println!("Destroying {} database '{}'...", svc.service_type, svc.name);
                match db_type {
                    "mysql" => { let _ = services::mysql_destroy(svc, &svc_config); }
                    "postgres" | "postgresql" | "pg" => { let _ = services::postgres_destroy(svc, &svc_config); }
                    _ => {}
                }
            }

            services::save_app_services(&mut app.env, &remaining);
            app.env.remove("DATABASE_URL");
            save_or_exit(&state);
            println!("Database destroyed. Restart the app to apply changes.");
        }
        "info" => {
            let app = match state.get_app(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let svcs = services::list_app_services(&app.env);
            let db_svcs: Vec<_> = svcs.iter().filter(|s| s.service_type == "mysql" || s.service_type == "postgres").collect();

            if db_svcs.is_empty() {
                println!("No database services provisioned for '{}'.", app_name);
                println!("Create one with: php-rs-ctl db create {} <mysql|postgres>", app_name);
            } else {
                for svc in db_svcs {
                    println!("Database:");
                    println!("  Type:     {}", svc.service_type);
                    println!("  Name:     {}", svc.name);
                    println!("  Host:     {}:{}", svc.host, svc.port);
                    println!("  User:     {}", svc.username);
                    println!("  URL:      {}", svc.url);
                    println!("  Created:  {}", svc.created_at);
                }
            }
        }
        _ => {
            eprintln!("Unknown db action: {} (use 'create', 'destroy', or 'info')", action);
            return Err(1);
        }
    }

    Ok(())
}

// ── Redis Command ───────────────────────────────────────────────────────────

fn handle_redis(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl redis <create|destroy|info> <app>");
        return Err(1);
    }

    let action = &args[0];
    let app_name = &args[1];

    let mut state = PlatformState::load();
    let svc_config = services::ServiceConfig::from_env();

    match action.as_str() {
        "create" => {
            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let existing = services::list_app_services(&app.env);
            if existing.iter().any(|s| s.service_type == "redis") {
                eprintln!("Error: Redis service already provisioned for '{}'", app_name);
                return Err(1);
            }

            println!("Provisioning Redis for '{}'...", app_name);
            match services::redis_create(app_name, &svc_config) {
                Ok(svc) => {
                    println!("Redis provisioned:");
                    println!("  Host:     {}:{}", svc.host, svc.port);
                    println!("  Prefix:   {}:", svc.name);
                    println!("  URL:      {}", svc.url);
                    println!("  Env var:  {}", svc.env_var);

                    let mut svcs = existing;
                    svcs.push(svc);
                    services::save_app_services(&mut app.env, &svcs);
                    save_or_exit(&state);
                    println!("\nRestart the app for REDIS_URL to take effect.");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "destroy" | "rm" | "delete" => {
            let app = match state.get_app_mut(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let existing = services::list_app_services(&app.env);
            let (to_destroy, remaining): (Vec<_>, Vec<_>) = existing
                .into_iter()
                .partition(|s| s.service_type == "redis");

            if to_destroy.is_empty() {
                eprintln!("No Redis service found for '{}'", app_name);
                return Err(1);
            }

            for svc in &to_destroy {
                let _ = services::redis_destroy(svc, &svc_config);
            }

            services::save_app_services(&mut app.env, &remaining);
            app.env.remove("REDIS_URL");
            save_or_exit(&state);
            println!("Redis service destroyed for '{}'.", app_name);
        }
        "info" => {
            let app = match state.get_app(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let svcs = services::list_app_services(&app.env);
            let redis_svcs: Vec<_> = svcs.iter().filter(|s| s.service_type == "redis").collect();

            if redis_svcs.is_empty() {
                println!("No Redis service provisioned for '{}'.", app_name);
                println!("Create one with: php-rs-ctl redis create {}", app_name);
            } else {
                for svc in redis_svcs {
                    println!("Redis:");
                    println!("  Host:     {}:{}", svc.host, svc.port);
                    println!("  Prefix:   {}:", svc.name);
                    println!("  URL:      {}", svc.url);
                    println!("  Created:  {}", svc.created_at);
                }
            }
        }
        _ => {
            eprintln!("Unknown redis action: {} (use 'create', 'destroy', or 'info')", action);
            return Err(1);
        }
    }

    Ok(())
}

// ── Storage Command (Phase 6.4) ─────────────────────────────────────────────

fn handle_storage(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl storage <create|destroy|info> <app>");
        return Err(1);
    }

    let action = &args[0];
    let app_name = &args[1];

    let mut state = PlatformState::load();
    let storage_config = services::StorageConfig::from_env();

    match action.as_str() {
        "create" => {
            if state.get_app(app_name).is_none() {
                eprintln!("Error: app '{}' not found", app_name);
                return Err(1);
            }

            match services::storage_create(app_name, &storage_config) {
                Ok(instance) => {
                    let app = state.get_app_mut(app_name).unwrap();
                    // Add S3 env vars.
                    let s3_vars = services::storage_env_vars(&instance, &storage_config);
                    for (k, v) in &s3_vars {
                        app.env.insert(k.clone(), v.clone());
                    }

                    // Save instance in services list.
                    let mut existing = services::list_app_services(&app.env);
                    existing.push(instance);
                    services::save_app_services(&mut app.env, &existing);

                    let bucket = app.env.get("S3_BUCKET").cloned().unwrap_or_default();
                    let endpoint = app.env.get("S3_ENDPOINT").cloned().unwrap_or_default();
                    let access_key = app.env.get("S3_ACCESS_KEY").cloned().unwrap_or_default();
                    drop(app);

                    save_or_exit(&state);

                    println!("S3 storage created for '{}'.", app_name);
                    println!("  Bucket:     {}", bucket);
                    println!("  Endpoint:   {}", endpoint);
                    println!("  Access Key: {}", access_key);
                }
                Err(e) => {
                    eprintln!("Failed to create storage: {}", e);
                    return Err(1);
                }
            }
        }
        "destroy" => {
            {
                let app = match state.get_app(app_name) {
                    Some(a) => a,
                    None => {
                        eprintln!("Error: app '{}' not found", app_name);
                        return Err(1);
                    }
                };

                let existing = services::list_app_services(&app.env);
                let (to_destroy, _): (Vec<_>, Vec<_>) = existing
                    .into_iter()
                    .partition(|s| s.service_type == "s3");

                if to_destroy.is_empty() {
                    eprintln!("No storage service found for '{}'", app_name);
                    return Err(1);
                }

                for svc in &to_destroy {
                    let _ = services::storage_destroy(svc, &storage_config);
                }
            }

            let app = state.get_app_mut(app_name).unwrap();
            let existing = services::list_app_services(&app.env);
            let remaining: Vec<_> = existing.into_iter().filter(|s| s.service_type != "s3").collect();
            services::save_app_services(&mut app.env, &remaining);
            // Clean up S3-specific env vars.
            for key in &["S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY",
                         "S3_SECRET_KEY", "S3_BUCKET_URL", "S3_USE_PATH_STYLE",
                         "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                         "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "FILESYSTEM_DISK"] {
                app.env.remove(*key);
            }
            drop(app);
            save_or_exit(&state);
            println!("Storage destroyed for '{}'.", app_name);
        }
        "info" => {
            let app = match state.get_app(app_name) {
                Some(a) => a,
                None => {
                    eprintln!("Error: app '{}' not found", app_name);
                    return Err(1);
                }
            };

            let svcs = services::list_app_services(&app.env);
            let s3_svcs: Vec<_> = svcs.iter().filter(|s| s.service_type == "s3").collect();
            if s3_svcs.is_empty() {
                println!("No storage service for '{}'.", app_name);
            } else {
                for svc in &s3_svcs {
                    println!("Storage for '{}':", app_name);
                    println!("  Bucket:     {}", svc.name);
                    println!("  Endpoint:   {}", svc.host);
                    println!("  Access Key: {}", svc.username);
                    println!("  URL:        {}", svc.url);
                    println!("  Created:    {}", svc.created_at);
                }
            }
        }
        _ => {
            eprintln!("Unknown storage action: {} (use 'create', 'destroy', or 'info')", action);
            return Err(1);
        }
    }

    Ok(())
}

// ── TLS Command ─────────────────────────────────────────────────────────────

fn handle_tls(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl tls <generate|add|remove|list>");
        return Err(1);
    }

    let certs_dir = tls_certs_dir();
    let store = tls::CertStore::new(&certs_dir);

    match args[0].as_str() {
        "generate" | "gen" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl tls generate <domain>");
                return Err(1);
            }
            let domain = &args[1];
            println!("Generating self-signed certificate for '{}'...", domain);
            match store.generate_self_signed(domain) {
                Ok(()) => {
                    println!("Certificate generated and stored.");
                    println!("  Cert: {}/{}/cert.pem", certs_dir.display(), domain);
                    println!("  Key:  {}/{}/privkey.pem", certs_dir.display(), domain);
                    println!("\nNote: Self-signed certs will show browser warnings.");
                    println!("For production, use 'php-rs-ctl tls add' with a real certificate.");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "add" | "import" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl tls add <domain> --cert <path> --key <path>");
                return Err(1);
            }
            let domain = &args[1];
            let mut cert_path: Option<String> = None;
            let mut key_path: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--cert" | "-c" => {
                        i += 1;
                        if i < args.len() { cert_path = Some(args[i].clone()); }
                    }
                    "--key" | "-k" => {
                        i += 1;
                        if i < args.len() { key_path = Some(args[i].clone()); }
                    }
                    _ => {
                        eprintln!("Unknown flag: {}", args[i]);
                        return Err(1);
                    }
                }
                i += 1;
            }

            let cert_path = match cert_path {
                Some(p) => p,
                None => {
                    eprintln!("Error: --cert <path> is required");
                    return Err(1);
                }
            };
            let key_path = match key_path {
                Some(p) => p,
                None => {
                    eprintln!("Error: --key <path> is required");
                    return Err(1);
                }
            };

            let cert_pem = std::fs::read_to_string(&cert_path)
                .map_err(|e| {
                    eprintln!("Error reading cert file: {}", e);
                    1
                })?;
            let key_pem = std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    eprintln!("Error reading key file: {}", e);
                    1
                })?;

            let meta = tls::CertMeta {
                domain: domain.to_string(),
                issuer: "imported".to_string(),
                not_before: crate::state::now_iso8601(),
                not_after: "unknown".to_string(),
                self_signed: false,
                auto_renew: false,
            };

            match store.store_cert(domain, &cert_pem, &key_pem, &meta) {
                Ok(()) => {
                    println!("Certificate imported for '{}'.", domain);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "remove" | "rm" | "delete" => {
            if args.len() < 2 {
                eprintln!("Usage: php-rs-ctl tls remove <domain>");
                return Err(1);
            }
            let domain = &args[1];
            match store.remove_cert(domain) {
                Ok(()) => println!("Certificate removed for '{}'.", domain),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Err(1);
                }
            }
        }
        "list" | "ls" => {
            let domains = store.list_domains();
            if domains.is_empty() {
                println!("No TLS certificates stored.");
                println!("Generate one with: php-rs-ctl tls generate <domain>");
                return Ok(());
            }

            println!("{:<30} {:<15} {:<10} {}", "DOMAIN", "ISSUER", "TYPE", "EXPIRES");
            println!("{}", "-".repeat(75));

            for meta in &domains {
                let cert_type = if meta.self_signed { "self-signed" } else { "imported" };
                println!(
                    "{:<30} {:<15} {:<10} {}",
                    meta.domain, meta.issuer, cert_type, meta.not_after
                );
            }
        }
        _ => {
            eprintln!("Unknown tls command: {}", args[0]);
            return Err(1);
        }
    }

    Ok(())
}

fn tls_certs_dir() -> std::path::PathBuf {
    let state_dir = std::env::var("PHPRS_STATE_DIR")
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{}/.php-rs", home)
        });
    let dir = std::path::Path::new(&state_dir).join("certs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn require_name(args: &[String], cmd: &str) -> Result<String, i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl app {} <name>", cmd);
        return Err(1);
    }
    Ok(args[0].clone())
}

fn save_or_exit(state: &PlatformState) {
    if let Err(e) = state.save() {
        eprintln!("Error: cannot save state: {}", e);
        std::process::exit(1);
    }
}

// ── Init Command (Phase 9.1) ────────────────────────────────────────────────

fn handle_init(args: &[String]) -> Result<(), i32> {
    let mut dir = ".".to_string();
    let mut name: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" | "-d" => {
                i += 1;
                if i < args.len() { dir = args[i].clone(); }
            }
            "--name" | "-n" => {
                i += 1;
                if i < args.len() { name = Some(args[i].clone()); }
            }
            _ => {
                // Treat first positional arg as dir.
                dir = args[i].clone();
            }
        }
        i += 1;
    }

    let dir_path = std::path::Path::new(&dir);
    if !dir_path.exists() {
        eprintln!("Directory '{}' does not exist.", dir);
        return Err(1);
    }

    // Check for existing Appfile.toml.
    if dir_path.join("Appfile.toml").exists() {
        eprintln!("Appfile.toml already exists in {}. Use --dir to specify a different directory.", dir);
        return Err(1);
    }

    // Derive name from directory name if not provided.
    let app_name = name.unwrap_or_else(|| {
        dir_path
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-app".into())
    });

    // Detect and generate.
    let framework = manifest::detect_framework(dir_path);
    println!("Detected framework: {}", if framework.is_empty() { "vanilla PHP" } else { &framework });

    let appfile = manifest::Appfile::detect(dir_path, &app_name);

    // Show what we found.
    println!("  Name:       {}", appfile.app.name);
    println!("  Entry:      {}", appfile.app.entry);
    println!("  Docroot:    {}", appfile.app.docroot);
    if !appfile.php.extensions.is_empty() {
        println!("  Extensions: {}", appfile.php.extensions.join(", "));
    }
    if appfile.services.mysql { println!("  Service:    MySQL"); }
    if appfile.services.postgres { println!("  Service:    PostgreSQL"); }
    if appfile.services.redis { println!("  Service:    Redis"); }

    // Write Appfile.toml.
    let toml_content = appfile.to_toml();
    let toml_path = dir_path.join("Appfile.toml");
    std::fs::write(&toml_path, &toml_content)
        .map_err(|e| { eprintln!("Failed to write Appfile.toml: {}", e); 1 })?;
    println!("\nCreated {}", toml_path.display());

    // Generate .php-rs-ignore file.
    let ignore_path = dir_path.join(".php-rs-ignore");
    if !ignore_path.exists() {
        let ignore_content = generate_ignore_file(&framework);
        std::fs::write(&ignore_path, &ignore_content)
            .map_err(|e| { eprintln!("Failed to write .php-rs-ignore: {}", e); 1 })?;
        println!("Created {}", ignore_path.display());
    }

    println!("\nProject initialized. Deploy with:");
    println!("  php-rs-ctl app create {} --root {}", app_name, dir);
    println!("  php-rs-ctl app start {}", app_name);

    Ok(())
}

fn generate_ignore_file(framework: &str) -> String {
    let mut lines = vec![
        "# php-rs-ignore — files excluded from deployment slugs",
        ".git/",
        ".github/",
        ".env",
        ".env.local",
        ".env.*.local",
        "node_modules/",
        "tests/",
        "phpunit.xml",
        ".phpunit.result.cache",
        ".idea/",
        ".vscode/",
        "*.log",
        "docker-compose.yml",
        "Dockerfile",
    ];

    match framework {
        "laravel" => {
            lines.push("storage/logs/*");
            lines.push("storage/framework/cache/*");
            lines.push("storage/framework/sessions/*");
            lines.push("storage/framework/views/*");
            lines.push("bootstrap/cache/*");
        }
        "symfony" => {
            lines.push("var/cache/*");
            lines.push("var/log/*");
            lines.push("var/sessions/*");
        }
        "wordpress" => {
            lines.push("wp-content/uploads/*");
            lines.push("wp-content/cache/*");
        }
        _ => {}
    }

    lines.join("\n") + "\n"
}

// ── Dev Command (Phase 9.2) ────────────────────────────────────────────────

fn handle_dev(args: &[String]) -> Result<(), i32> {
    let mut dir = ".".to_string();
    let mut port: u16 = 8080;
    let mut workers: u16 = 2;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" | "-d" => {
                i += 1;
                if i < args.len() { dir = args[i].clone(); }
            }
            "--port" | "-p" => {
                i += 1;
                if i < args.len() { port = args[i].parse().unwrap_or(8080); }
            }
            "--workers" | "-w" => {
                i += 1;
                if i < args.len() { workers = args[i].parse().unwrap_or(2); }
            }
            _ => {
                dir = args[i].clone();
            }
        }
        i += 1;
    }

    let dir_path = std::path::Path::new(&dir);
    if !dir_path.exists() {
        eprintln!("Directory '{}' does not exist.", dir);
        return Err(1);
    }

    // Load Appfile.toml if available, otherwise auto-detect.
    let appfile = if dir_path.join("Appfile.toml").exists() {
        match manifest::Appfile::load_from_dir(dir_path) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Error loading Appfile.toml: {}", e);
                return Err(1);
            }
        }
    } else {
        let name = dir_path
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "dev-app".into());
        manifest::Appfile::detect(dir_path, &name)
    };

    // Load .env file if present.
    let mut env_vars: HashMap<String, String> = HashMap::new();
    let env_file = dir_path.join(".env");
    if env_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&env_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim().to_string();
                    let val = line[eq + 1..].trim().trim_matches('"').trim_matches('\'').to_string();
                    env_vars.insert(key, val);
                }
            }
        }
    }

    // Merge Appfile env.
    for (k, v) in &appfile.env {
        env_vars.entry(k.clone()).or_insert_with(|| v.clone());
    }

    println!("php-rs dev server");
    println!("  App:       {}", appfile.app.name);
    println!("  Framework: {}", if appfile.app.framework.is_empty() { "vanilla" } else { &appfile.app.framework });
    println!("  Root:      {}", dir_path.canonicalize().unwrap_or_else(|_| dir_path.to_path_buf()).display());
    println!("  Entry:     {}", appfile.app.entry);
    println!("  Port:      {}", port);
    println!("  Workers:   {}", workers);
    if !env_vars.is_empty() {
        println!("  Env vars:  {} loaded", env_vars.len());
    }
    println!();
    println!("Serving at http://127.0.0.1:{}", port);
    println!("Press Ctrl-C to stop.\n");

    // Find the php-rs-app binary.
    let binary = match process::find_app_binary_pub() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Cannot find php-rs-app binary: {}", e);
            return Err(1);
        }
    };

    // Build environment for the child process.
    let abs_root = dir_path.canonicalize().unwrap_or_else(|_| dir_path.to_path_buf());
    let mut child_env: Vec<(String, String)> = vec![
        ("APP_ROOT".into(), abs_root.to_string_lossy().to_string()),
        ("APP_ENTRY".into(), appfile.app.entry.clone()),
        ("APP_DOCROOT".into(), appfile.app.docroot.clone()),
        ("APP_PORT".into(), port.to_string()),
        ("APP_WORKERS".into(), workers.to_string()),
        ("APP_NAME".into(), appfile.app.name.clone()),
        ("APP_ENV".into(), "development".into()),
    ];
    for (k, v) in &env_vars {
        child_env.push((k.clone(), v.clone()));
    }

    // Spawn and wait.
    let mut cmd = std::process::Command::new(&binary);
    cmd.envs(child_env);
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                eprintln!("\nDev server exited with status: {}", status);
                return Err(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("Failed to start dev server (binary: {}): {}", binary, e);
            return Err(1);
        }
    }

    Ok(())
}

// ── Run Command (Phase 9.3) ────────────────────────────────────────────────

fn handle_run(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl run <app> \"<command>\"");
        return Err(1);
    }

    let app_name = &args[0];
    let command = args[1..].join(" ");

    let platform = PlatformState::load();
    let app = match platform.apps.get(app_name) {
        Some(a) => a,
        None => {
            eprintln!("App '{}' not found.", app_name);
            return Err(1);
        }
    };

    println!("Running in '{}' context: {}", app_name, command);

    // Build the environment like the app process would have.
    let env_vars = app.build_process_env();
    let binary = match process::find_app_binary_pub() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Cannot find php-rs-app binary: {}", e);
            return Err(1);
        }
    };

    // Parse the command to determine if it's a PHP script or artisan command.
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        eprintln!("Empty command.");
        return Err(1);
    }

    // If the command starts with "php", strip it since we're running via php-rs.
    let (script, script_args) = if parts[0] == "php" && parts.len() > 1 {
        (parts[1], &parts[2..])
    } else {
        (parts[0], &parts[1..])
    };

    // Build the one-off command: run php-rs-sapi-cli with the script in the app's root.
    let abs_root = std::path::Path::new(&app.root)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&app.root));
    let script_path = abs_root.join(script);

    let mut cmd = std::process::Command::new(&binary);
    // Use cli mode: pass script as argument.
    // For one-off commands, we run the CLI SAPI instead of the app SAPI.
    // Actually, we use the same binary but with ONE_OFF=1 to signal single execution mode.
    cmd.env("APP_ROOT", abs_root.to_string_lossy().to_string());
    cmd.env("APP_ENTRY", script_path.to_string_lossy().to_string());
    cmd.env("ONE_OFF", "1");
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }
    for arg in script_args {
        cmd.arg(arg);
    }
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    cmd.current_dir(&abs_root);

    let timeout_secs: u64 = 300; // 5 minute timeout for one-off commands.

    match cmd.spawn() {
        Ok(mut child) => {
            // Spawn a watchdog thread for timeout.
            let child_id = child.id();
            let watchdog = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(timeout_secs));
                // If we get here, the child is still running — kill it.
                unsafe { libc::kill(child_id as i32, libc::SIGKILL); }
            });

            match child.wait() {
                Ok(status) => {
                    drop(watchdog); // Watchdog thread will end when process dies.
                    if !status.success() {
                        return Err(status.code().unwrap_or(1));
                    }
                }
                Err(e) => {
                    eprintln!("Error waiting for command: {}", e);
                    return Err(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to run command: {}", e);
            return Err(1);
        }
    }

    Ok(())
}

// ── Exec / SSH Command (Phase 9.4) ────────────────────────────────────────

fn handle_exec(args: &[String]) -> Result<(), i32> {
    if args.is_empty() {
        eprintln!("Usage: php-rs-ctl exec <app> [<command>]");
        eprintln!("       php-rs-ctl ssh <app>");
        return Err(1);
    }

    let app_name = &args[0];
    let command = if args.len() > 1 {
        Some(args[1..].join(" "))
    } else {
        None
    };

    let platform = PlatformState::load();
    let app = match platform.apps.get(app_name) {
        Some(a) => a,
        None => {
            eprintln!("App '{}' not found.", app_name);
            return Err(1);
        }
    };

    let abs_root = std::path::Path::new(&app.root)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&app.root));

    let env_vars = app.build_process_env();

    match command {
        Some(cmd_str) => {
            // Run a specific command in the app context.
            println!("Executing in '{}': {}", app_name, cmd_str);
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(&cmd_str);
            cmd.current_dir(&abs_root);
            for (k, v) in &env_vars {
                cmd.env(k, v);
            }
            cmd.stdout(std::process::Stdio::inherit());
            cmd.stderr(std::process::Stdio::inherit());
            cmd.stdin(std::process::Stdio::inherit());

            match cmd.status() {
                Ok(status) => {
                    if !status.success() {
                        return Err(status.code().unwrap_or(1));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute: {}", e);
                    return Err(1);
                }
            }
        }
        None => {
            // Interactive shell in app context.
            println!("Opening shell in '{}' context (exit to leave).", app_name);
            println!("Working directory: {}\n", abs_root.display());

            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            let mut cmd = std::process::Command::new(&shell);
            cmd.current_dir(&abs_root);
            for (k, v) in &env_vars {
                cmd.env(k, v);
            }
            cmd.env("PS1", format!("[php-rs:{}] \\w $ ", app_name));
            cmd.stdout(std::process::Stdio::inherit());
            cmd.stderr(std::process::Stdio::inherit());
            cmd.stdin(std::process::Stdio::inherit());

            match cmd.status() {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to start shell: {}", e);
                    return Err(1);
                }
            }
        }
    }

    Ok(())
}

// ── Preview Command (Phase 9.5) ────────────────────────────────────────────

fn handle_preview(args: &[String]) -> Result<(), i32> {
    if args.len() < 2 {
        eprintln!("Usage: php-rs-ctl preview <app> <create|destroy|list> [--branch <branch>]");
        return Err(1);
    }

    let app_name = &args[0];
    let action = &args[1];

    match action.as_str() {
        "create" => preview_create(app_name, &args[2..]),
        "destroy" => preview_destroy(app_name),
        "list" | "ls" => preview_list(app_name),
        _ => {
            eprintln!("Unknown preview action: {}", action);
            Err(1)
        }
    }
}

fn preview_create(base_app: &str, args: &[String]) -> Result<(), i32> {
    let mut branch = "preview".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--branch" | "-b" => {
                i += 1;
                if i < args.len() { branch = args[i].clone(); }
            }
            _ => {
                branch = args[i].clone();
            }
        }
        i += 1;
    }

    let mut platform = PlatformState::load();

    let base = match platform.apps.get(base_app) {
        Some(a) => a.clone(),
        None => {
            eprintln!("Base app '{}' not found.", base_app);
            return Err(1);
        }
    };

    // Generate preview name: base-preview-branch.
    let safe_branch = branch.replace('/', "-").replace(' ', "-");
    let preview_name = format!("{}-preview-{}", base_app, safe_branch);

    if platform.apps.contains_key(&preview_name) {
        eprintln!("Preview '{}' already exists. Destroy it first.", preview_name);
        return Err(1);
    }

    // Allocate port.
    let port = platform.next_port;
    platform.next_port += 1;

    // Create preview app state based on the base app.
    let preview = AppState {
        name: preview_name.clone(),
        root: base.root.clone(),
        entry: base.entry.clone(),
        docroot: base.docroot.clone(),
        port,
        pid: None,
        env: {
            let mut env = base.env.clone();
            env.insert("APP_ENV".into(), "preview".into());
            env.insert("PREVIEW_BRANCH".into(), branch.clone());
            env.insert("PREVIEW_BASE_APP".into(), base_app.into());
            env
        },
        workers: 1, // Previews use minimal resources.
        created_at: state::now_iso8601(),
        releases: vec![],
        current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
    };

    platform.apps.insert(preview_name.clone(), preview);
    save_or_exit(&platform);

    println!("Preview '{}' created.", preview_name);
    println!("  Port:   {}", port);
    println!("  Branch: {}", branch);
    println!("  Based on: {}", base_app);
    println!("\nStart with: php-rs-ctl app start {}", preview_name);

    Ok(())
}

fn preview_destroy(base_app: &str) -> Result<(), i32> {
    let mut platform = PlatformState::load();

    // Find all previews for this app.
    let preview_prefix = format!("{}-preview-", base_app);
    let preview_names: Vec<String> = platform.apps.keys()
        .filter(|k| k.starts_with(&preview_prefix))
        .cloned()
        .collect();

    if preview_names.is_empty() {
        eprintln!("No previews found for '{}'.", base_app);
        return Err(1);
    }

    for name in &preview_names {
        // Stop if running.
        if let Some(app) = platform.apps.get(name) {
            if app.is_running() {
                println!("Stopping preview '{}'...", name);
                process::stop_app(app, Duration::from_secs(10));
            }
        }
        platform.apps.remove(name);
        println!("Destroyed preview '{}'.", name);
    }

    save_or_exit(&platform);
    Ok(())
}

fn preview_list(base_app: &str) -> Result<(), i32> {
    let platform = PlatformState::load();

    let preview_prefix = format!("{}-preview-", base_app);
    let previews: Vec<(&String, &AppState)> = platform.apps.iter()
        .filter(|(k, _)| k.starts_with(&preview_prefix))
        .collect();

    if previews.is_empty() {
        println!("No previews for '{}'.", base_app);
        return Ok(());
    }

    println!("Previews for '{}':", base_app);
    for (name, app) in &previews {
        let status = if app.is_running() { "running" } else { "stopped" };
        let branch = app.env.get("PREVIEW_BRANCH").map(|s| s.as_str()).unwrap_or("?");
        println!("  {} (port {}, branch {}, {})", name, app.port, branch, status);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Each test gets its own unique state directory.
    fn unique_test_dir(label: &str) -> std::path::PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("phprs-cli-{}-{}-{}", std::process::id(), n, label));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_require_name_empty() {
        assert!(require_name(&[], "start").is_err());
    }

    #[test]
    fn test_require_name_present() {
        let args = vec!["myapp".to_string()];
        assert_eq!(require_name(&args, "start").unwrap(), "myapp");
    }

    #[test]
    fn test_state_create_app() {
        let dir = unique_test_dir("create");

        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: dir.join("apps").to_string_lossy().to_string(),
            next_uid: 10000,
        };

        let port = state.allocate_port();
        assert_eq!(port, 8001);

        let app = AppState {
            name: "myapp".into(),
            root: "/tmp".into(),
            entry: "public/index.php".into(),
            docroot: "public".into(),
            port,
            pid: None,
            env: HashMap::from([("APP_ENV".into(), "production".into())]),
            workers: 4,
            created_at: state::now_iso8601(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        };
        state.apps.insert("myapp".into(), app);

        assert_eq!(state.apps.len(), 1);
        assert_eq!(state.apps["myapp"].port, 8001);
        assert_eq!(state.next_port, 8002);

        // Verify duplicate detection.
        assert!(state.apps.contains_key("myapp"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_state_destroy_app() {
        let dir = unique_test_dir("destroy");

        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: dir.join("apps").to_string_lossy().to_string(),
            next_uid: 10000,
        };

        let port = state.allocate_port();
        state.apps.insert("destroyable".into(), AppState {
            name: "destroyable".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port,
            pid: None,
            env: HashMap::new(),
            workers: 0,
            created_at: state::now_iso8601(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });

        assert!(state.apps.contains_key("destroyable"));
        state.apps.remove("destroyable");
        assert!(!state.apps.contains_key("destroyable"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_state_config_env() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp".into(),
            next_uid: 10000,
        };

        state.apps.insert("configapp".into(), AppState {
            name: "configapp".into(),
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
        });

        // Set env var.
        let app = state.get_app_mut("configapp").unwrap();
        app.env.insert("DATABASE_URL".into(), "mysql://localhost".into());

        assert_eq!(
            state.get_app("configapp").unwrap().env.get("DATABASE_URL").unwrap(),
            "mysql://localhost"
        );

        // Build process env should include it.
        let env = state.get_app("configapp").unwrap().build_process_env();
        assert_eq!(env.get("DATABASE_URL").unwrap(), "mysql://localhost");
    }

    #[test]
    fn test_stop_not_found_returns_error() {
        let state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp".into(),
            next_uid: 10000,
        };

        assert!(state.get_app("nonexistent").is_none());
    }

    #[test]
    fn test_multiple_apps_different_ports() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: "/tmp/test-apps".into(),
            next_uid: 10000,
        };

        for i in 0..5 {
            let port = state.allocate_port();
            let name = format!("app{}", i);
            state.apps.insert(name.clone(), AppState {
                name,
                root: "/tmp".into(),
                entry: "index.php".into(),
                docroot: ".".into(),
                port,
                pid: None,
                env: HashMap::new(),
                workers: 0,
                created_at: state::now_iso8601(),
                releases: vec![],
                current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
            });
        }

        assert_eq!(state.apps.len(), 5);
        // Each app should have a unique port.
        let ports: Vec<u16> = state.apps.values().map(|a| a.port).collect();
        let mut sorted = ports.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
        assert_eq!(sorted, vec![8001, 8002, 8003, 8004, 8005]);
    }

    // ── Phase 9 tests ──────────────────────────────────────────────────────

    #[test]
    fn test_generate_ignore_file_laravel() {
        let content = generate_ignore_file("laravel");
        assert!(content.contains(".git/"));
        assert!(content.contains("node_modules/"));
        assert!(content.contains("storage/logs/*"));
        assert!(content.contains("bootstrap/cache/*"));
        assert!(!content.contains("var/cache/*")); // Symfony-only.
    }

    #[test]
    fn test_generate_ignore_file_symfony() {
        let content = generate_ignore_file("symfony");
        assert!(content.contains(".git/"));
        assert!(content.contains("var/cache/*"));
        assert!(content.contains("var/log/*"));
        assert!(!content.contains("storage/logs/*")); // Laravel-only.
    }

    #[test]
    fn test_generate_ignore_file_vanilla() {
        let content = generate_ignore_file("vanilla");
        assert!(content.contains(".git/"));
        assert!(content.contains("node_modules/"));
        assert!(!content.contains("storage/logs/*"));
        assert!(!content.contains("var/cache/*"));
    }

    #[test]
    fn test_init_creates_appfile() {
        let dir = std::env::temp_dir().join(format!("phprs-test-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.php"), "<?php echo 'hello';").unwrap();

        let dir_str = dir.to_string_lossy().to_string();
        let result = handle_init(&[dir_str.clone(), "--name".into(), "test-init-app".into()]);
        assert!(result.is_ok());

        // Appfile.toml should exist.
        assert!(dir.join("Appfile.toml").exists());
        let content = std::fs::read_to_string(dir.join("Appfile.toml")).unwrap();
        assert!(content.contains("test-init-app"));

        // .php-rs-ignore should exist.
        assert!(dir.join(".php-rs-ignore").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_init_already_exists() {
        let dir = std::env::temp_dir().join(format!("phprs-test-init-exists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Appfile.toml"), "[app]\nname = \"existing\"\n").unwrap();

        let dir_str = dir.to_string_lossy().to_string();
        let result = handle_init(&[dir_str]);
        assert!(result.is_err()); // Should fail because Appfile.toml exists.

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_preview_create_and_destroy() {
        // Test preview create by directly building state (avoids env var races).
        let base_app = AppState {
            name: "myapp".into(),
            root: "/tmp/myapp".into(),
            entry: "public/index.php".into(),
            docroot: "public".into(),
            port: 9001,
            pid: None,
            env: HashMap::new(),
            workers: 2,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
        };

        // Simulate what preview_create does internally.
        let branch = "feature-login";
        let safe_branch = branch.replace('/', "-");
        let preview_name = format!("myapp-preview-{}", safe_branch);

        let preview = AppState {
            name: preview_name.clone(),
            root: base_app.root.clone(),
            entry: base_app.entry.clone(),
            docroot: base_app.docroot.clone(),
            port: 9002,
            pid: None,
            env: {
                let mut env = base_app.env.clone();
                env.insert("APP_ENV".into(), "preview".into());
                env.insert("PREVIEW_BRANCH".into(), branch.into());
                env.insert("PREVIEW_BASE_APP".into(), "myapp".into());
                env
            },
            workers: 1,
            created_at: state::now_iso8601(),
            releases: vec![],
            current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
        };

        assert_eq!(preview.name, "myapp-preview-feature-login");
        assert_eq!(preview.env.get("PREVIEW_BRANCH").unwrap(), "feature-login");
        assert_eq!(preview.env.get("APP_ENV").unwrap(), "preview");
        assert_eq!(preview.workers, 1);
        assert_eq!(preview.port, 9002);

        // Test that preview names with slashes are sanitized.
        let branch2 = "feature/complex-name";
        let safe2 = branch2.replace('/', "-");
        assert_eq!(safe2, "feature-complex-name");
    }

    #[test]
    fn test_preview_list_empty() {
        // Create a platform with no previews, verify filtering works.
        let mut platform = PlatformState {
            apps: HashMap::new(),
            next_port: 9001,
            apps_dir: "/tmp".into(),
            next_uid: 10000,
        };
        platform.apps.insert("myapp".into(), AppState {
            name: "myapp".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 9001,
            pid: None,
            env: HashMap::new(),
            workers: 2,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: vec![],
            current_release: None,
            scaling: Default::default(),
            instances: vec![],
            cron_jobs: vec![],
            worker_configs: vec![],
        });

        let prefix = format!("{}-preview-", "myapp");
        let previews: Vec<&String> = platform.apps.keys()
            .filter(|k| k.starts_with(&prefix))
            .collect();
        assert!(previews.is_empty());
    }

    #[test]
    fn test_run_no_args() {
        let result = handle_run(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_exec_no_args() {
        let result = handle_exec(&[]);
        assert!(result.is_err());
    }
}
