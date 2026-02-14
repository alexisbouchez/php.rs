use crate::config::Config;
use crate::json::JsonFile;

/// Execute a named script from composer.json "scripts" section.
///
/// Supports:
/// - Shell commands (run via `sh -c`)
/// - `@php <args>` — runs php-rs with the given arguments
/// - `@composer <args>` — runs php-rs composer with the given arguments
/// - `@putenv VAR=val` — sets an environment variable
/// - `Composer\Config::disableProcessTimeout` — ignored (no-op)
/// - PHP callbacks like `Vendor\Class::method` — logged as unsupported
pub fn execute(config: &Config, script_name: &str, extra_args: &[String]) -> Result<(), String> {
    let json_path = config.composer_json_path();
    let json_file = JsonFile::new(&json_path);
    let root = json_file
        .read()
        .map_err(|e| format!("Could not open composer.json: {}", e))?;

    let scripts = root
        .get("scripts")
        .ok_or_else(|| format!("No \"scripts\" section found in composer.json"))?;

    let script_entries = scripts.get(script_name).ok_or_else(|| {
        format!(
            "Script \"{}\" is not defined in this package's composer.json.",
            script_name
        )
    })?;

    let commands: Vec<String> = match script_entries {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => return Err(format!("Script \"{}\" has an invalid format.", script_name)),
    };

    println!("> {}", script_name);

    for cmd in &commands {
        run_single_script(cmd, config, extra_args)?;
    }

    Ok(())
}

fn run_single_script(script: &str, config: &Config, extra_args: &[String]) -> Result<(), String> {
    let script = script.trim();

    // Composer\Config::disableProcessTimeout — just ignore it
    if script.contains("Composer\\Config::disableProcessTimeout") {
        return Ok(());
    }

    // @putenv VAR=value
    if let Some(rest) = script.strip_prefix("@putenv ") {
        let rest = rest.trim();
        if let Some((var, val)) = rest.split_once('=') {
            std::env::set_var(var.trim(), val.trim());
        }
        return Ok(());
    }

    // @php <args> — run via php-rs binary
    if let Some(rest) = script.strip_prefix("@php ") {
        let mut full_cmd = rest.to_string();
        for arg in extra_args {
            full_cmd.push(' ');
            full_cmd.push_str(arg);
        }
        println!("  > @php {}", full_cmd);

        // Find our own binary to run as php
        let exe =
            std::env::current_exe().map_err(|e| format!("Cannot find php-rs binary: {}", e))?;

        let status = std::process::Command::new(&exe)
            .args(full_cmd.split_whitespace())
            .current_dir(&config.working_dir)
            .status()
            .map_err(|e| format!("Failed to run '@php {}': {}", full_cmd, e))?;

        if !status.success() {
            return Err(format!(
                "Script '@php {}' returned with error code {}",
                full_cmd,
                status.code().unwrap_or(-1)
            ));
        }
        return Ok(());
    }

    // @composer <args> — run a composer subcommand
    if let Some(rest) = script.strip_prefix("@composer ") {
        let mut full_cmd = rest.to_string();
        for arg in extra_args {
            full_cmd.push(' ');
            full_cmd.push_str(arg);
        }
        println!("  > @composer {}", full_cmd);

        let exe =
            std::env::current_exe().map_err(|e| format!("Cannot find php-rs binary: {}", e))?;

        let status = std::process::Command::new(&exe)
            .arg("composer")
            .args(full_cmd.split_whitespace())
            .current_dir(&config.working_dir)
            .status()
            .map_err(|e| format!("Failed to run '@composer {}': {}", full_cmd, e))?;

        if !status.success() {
            return Err(format!(
                "Script '@composer {}' returned with error code {}",
                full_cmd,
                status.code().unwrap_or(-1)
            ));
        }
        return Ok(());
    }

    // @ reference to another script — skip for now
    if script.starts_with('@') {
        println!("  > {} (script reference - skipped)", script);
        return Ok(());
    }

    // PHP class callback (contains ::) — not executable without VM
    if script.contains("::") && !script.contains(' ') {
        println!("  > {} (PHP callback - requires php-rs VM)", script);
        return Ok(());
    }

    // Shell command
    let mut full_cmd = script.to_string();
    for arg in extra_args {
        full_cmd.push(' ');
        full_cmd.push_str(arg);
    }
    println!("  > {}", full_cmd);

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .current_dir(&config.working_dir)
        .status()
        .map_err(|e| format!("Failed to run script '{}': {}", full_cmd, e))?;

    if !status.success() {
        return Err(format!(
            "Script '{}' returned with error code {}",
            full_cmd,
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

/// List all available scripts from composer.json.
pub fn list_scripts(config: &Config) -> Result<(), String> {
    let json_path = config.composer_json_path();
    let json_file = JsonFile::new(&json_path);
    let root = json_file
        .read()
        .map_err(|e| format!("Could not open composer.json: {}", e))?;

    let scripts = match root.get("scripts") {
        Some(s) => s,
        None => {
            println!("No scripts defined in composer.json");
            return Ok(());
        }
    };

    let obj = match scripts.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };

    println!("Available scripts:");
    for (name, value) in obj {
        let desc = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => {
                let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                parts.join(", ")
            }
            _ => continue,
        };
        println!("  {} - {}", name, desc);
    }

    Ok(())
}
