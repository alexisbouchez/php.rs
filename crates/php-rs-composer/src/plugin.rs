use crate::package::Package;

/// Plugin capability markers.
///
/// Composer plugins are packages of type "composer-plugin" that implement
/// the `PluginInterface`. They can modify Composer behavior by subscribing
/// to events.
///
/// In php-rs, plugin support is limited since plugins are PHP code that
/// would need the php-rs VM to execute. This module provides the data
/// structures for plugin detection and configuration.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Whether plugins are allowed to run.
    pub allow_plugins: PluginPermission,
}

/// Permission level for plugin execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginPermission {
    /// All plugins are allowed.
    AllAllowed,
    /// No plugins are allowed.
    NoneAllowed,
    /// Only specific plugins are allowed (by package name).
    Specific(Vec<String>),
}

impl Default for PluginConfig {
    fn default() -> Self {
        PluginConfig {
            allow_plugins: PluginPermission::AllAllowed,
        }
    }
}

impl PluginConfig {
    /// Load plugin configuration from composer.json "config.allow-plugins".
    pub fn from_json(config: &serde_json::Value) -> Self {
        let allow_plugins = config.get("config").and_then(|c| c.get("allow-plugins"));

        let permission = match allow_plugins {
            Some(serde_json::Value::Bool(true)) => PluginPermission::AllAllowed,
            Some(serde_json::Value::Bool(false)) => PluginPermission::NoneAllowed,
            Some(serde_json::Value::Object(map)) => {
                let allowed: Vec<String> = map
                    .iter()
                    .filter(|(_, v)| v.as_bool().unwrap_or(false))
                    .map(|(k, _)| k.clone())
                    .collect();
                PluginPermission::Specific(allowed)
            }
            _ => PluginPermission::AllAllowed,
        };

        PluginConfig {
            allow_plugins: permission,
        }
    }

    /// Check if a specific plugin package is allowed to run.
    pub fn is_plugin_allowed(&self, package_name: &str) -> bool {
        match &self.allow_plugins {
            PluginPermission::AllAllowed => true,
            PluginPermission::NoneAllowed => false,
            PluginPermission::Specific(names) => names.iter().any(|n| n == package_name),
        }
    }

    /// Detect composer-plugin packages from a list of installed packages.
    pub fn detect_plugins(packages: &[Package]) -> Vec<&Package> {
        packages
            .iter()
            .filter(|p| p.package_type == "composer-plugin")
            .collect()
    }
}
