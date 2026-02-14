use crate::package::Package;

/// Script event types that Composer supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEvent {
    PreInstallCmd,
    PostInstallCmd,
    PreUpdateCmd,
    PostUpdateCmd,
    PostAutoloadDump,
    PreAutoloadDump,
    PostRootPackageInstall,
    PostCreateProjectCmd,
}

impl ScriptEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreInstallCmd => "pre-install-cmd",
            Self::PostInstallCmd => "post-install-cmd",
            Self::PreUpdateCmd => "pre-update-cmd",
            Self::PostUpdateCmd => "post-update-cmd",
            Self::PostAutoloadDump => "post-autoload-dump",
            Self::PreAutoloadDump => "pre-autoload-dump",
            Self::PostRootPackageInstall => "post-root-package-install",
            Self::PostCreateProjectCmd => "post-create-project-cmd",
        }
    }
}

/// Script runner that dispatches Composer script events.
///
/// Scripts are defined in composer.json under the "scripts" key and can be:
/// - PHP class method calls: "Vendor\\Class::method"
/// - Shell commands: "@php script.php" or "echo hello"
/// - References to other scripts: "@composer install"
pub struct ScriptRunner;

impl ScriptRunner {
    /// Get the scripts defined for a given event in the root package.
    pub fn get_scripts(root_package: &Package, event: &ScriptEvent) -> Vec<String> {
        let scripts = match &root_package.scripts {
            Some(s) => s,
            None => return Vec::new(),
        };

        let event_scripts = match scripts.get(event.as_str()) {
            Some(s) => s,
            None => return Vec::new(),
        };

        match event_scripts {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Run scripts for an event. Currently logs them; full execution requires
    /// the php-rs VM to be available as a dependency.
    pub fn run_event(root_package: &Package, event: &ScriptEvent) -> Result<(), String> {
        let scripts = Self::get_scripts(root_package, event);
        if scripts.is_empty() {
            return Ok(());
        }

        println!("> {}", event.as_str());
        for script in &scripts {
            if script.starts_with('@') {
                // Reference to another script or composer command
                println!("  > {}", script);
            } else if script.contains("::") {
                // PHP class callback - would need php-rs VM to execute
                println!("  > {} (PHP callback - requires php-rs VM)", script);
            } else {
                // Shell command
                println!("  > {}", script);
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .status()
                    .map_err(|e| format!("Failed to run script '{}': {}", script, e))?;

                if !status.success() {
                    return Err(format!(
                        "Script '{}' returned with error code {}",
                        script,
                        status.code().unwrap_or(-1)
                    ));
                }
            }
        }

        Ok(())
    }
}
