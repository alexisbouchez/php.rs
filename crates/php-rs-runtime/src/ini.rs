//! PHP INI system.
//!
//! Implements php.ini parsing, ini_get(), ini_set(), and permission levels.
//!
//! Reference: php-src/main/php_ini.c, php-src/Zend/zend_ini.h

use std::collections::HashMap;

/// INI entry permission levels.
///
/// Controls when an INI directive can be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IniPermission {
    /// Can only be set in php.ini or httpd.conf.
    System = 1, // INI_SYSTEM
    /// Can be set in php.ini, .htaccess, or httpd.conf.
    PerDir = 2, // INI_PERDIR
    /// Can be set at runtime via ini_set().
    User = 4, // INI_USER
    /// Can be set anywhere (System | PerDir | User).
    All = 7, // INI_ALL
}

impl IniPermission {
    /// Check if this permission allows runtime modification (via ini_set).
    pub fn allows_user_change(self) -> bool {
        (self as u8) & (IniPermission::User as u8) != 0
    }
}

/// A single INI entry.
#[derive(Debug, Clone)]
pub struct IniEntry {
    /// The directive name (e.g., "error_reporting").
    pub name: String,
    /// Current value.
    pub value: String,
    /// Default value (from php.ini or registration).
    pub default_value: String,
    /// Permission level.
    pub permission: IniPermission,
    /// Whether this entry has been modified at runtime.
    pub modified: bool,
}

impl IniEntry {
    /// Create a new INI entry.
    pub fn new(
        name: impl Into<String>,
        default: impl Into<String>,
        permission: IniPermission,
    ) -> Self {
        let default = default.into();
        Self {
            name: name.into(),
            value: default.clone(),
            default_value: default,
            permission,
            modified: false,
        }
    }
}

/// The INI system — manages all PHP configuration directives.
pub struct IniSystem {
    /// All registered INI entries.
    entries: HashMap<String, IniEntry>,
}

impl IniSystem {
    /// Create a new INI system with core directives pre-registered.
    pub fn new() -> Self {
        let mut sys = Self {
            entries: HashMap::new(),
        };
        sys.register_core_directives();
        sys
    }

    /// Register the core PHP INI directives.
    fn register_core_directives(&mut self) {
        let directives = [
            ("error_reporting", "32767", IniPermission::All), // E_ALL
            ("display_errors", "1", IniPermission::All),
            ("display_startup_errors", "1", IniPermission::All),
            ("log_errors", "0", IniPermission::All),
            ("error_log", "", IniPermission::All),
            ("memory_limit", "128M", IniPermission::All),
            ("max_execution_time", "30", IniPermission::All),
            ("max_input_time", "60", IniPermission::All),
            ("post_max_size", "8M", IniPermission::PerDir),
            ("upload_max_filesize", "2M", IniPermission::PerDir),
            ("max_file_uploads", "20", IniPermission::System),
            ("default_charset", "UTF-8", IniPermission::All),
            ("default_mimetype", "text/html", IniPermission::All),
            ("date.timezone", "", IniPermission::All),
            ("short_open_tag", "1", IniPermission::PerDir),
            ("precision", "14", IniPermission::All),
            ("serialize_precision", "-1", IniPermission::All),
            ("output_buffering", "0", IniPermission::PerDir),
            ("implicit_flush", "0", IniPermission::All),
            ("open_basedir", "", IniPermission::System),
            ("disable_functions", "", IniPermission::System),
            ("disable_classes", "", IniPermission::System),
            ("include_path", ".", IniPermission::All),
            ("extension_dir", "", IniPermission::System),
            ("file_uploads", "1", IniPermission::System),
            ("allow_url_fopen", "1", IniPermission::System),
            ("allow_url_include", "0", IniPermission::System),
            ("variables_order", "EGPCS", IniPermission::PerDir),
            ("request_order", "GP", IniPermission::PerDir),
            ("auto_prepend_file", "", IniPermission::PerDir),
            ("auto_append_file", "", IniPermission::PerDir),
            ("session.save_handler", "files", IniPermission::All),
            ("session.save_path", "", IniPermission::All),
            ("session.name", "PHPSESSID", IniPermission::All),
            ("session.gc_maxlifetime", "1440", IniPermission::All),
        ];

        for (name, default, perm) in directives {
            self.entries
                .insert(name.to_string(), IniEntry::new(name, default, perm));
        }
    }

    /// Register a custom INI directive.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        default: impl Into<String>,
        permission: IniPermission,
    ) {
        let name = name.into();
        self.entries
            .insert(name.clone(), IniEntry::new(name, default, permission));
    }

    /// Get the value of an INI directive. Returns empty string if not found.
    pub fn get(&self, name: &str) -> &str {
        self.entries
            .get(name)
            .map(|e| e.value.as_str())
            .unwrap_or("")
    }

    /// Get the full INI entry (if it exists).
    pub fn get_entry(&self, name: &str) -> Option<&IniEntry> {
        self.entries.get(name)
    }

    /// Set an INI directive at runtime (ini_set).
    ///
    /// Returns the old value, or None if the directive doesn't exist or
    /// the change is not permitted.
    pub fn set(&mut self, name: &str, value: impl Into<String>) -> Option<String> {
        let entry = self.entries.get_mut(name)?;
        if !entry.permission.allows_user_change() {
            return None;
        }
        let old = std::mem::replace(&mut entry.value, value.into());
        entry.modified = true;
        Some(old)
    }

    /// Restore an INI directive to its default value (ini_restore).
    pub fn restore(&mut self, name: &str) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.value = entry.default_value.clone();
            entry.modified = false;
        }
    }

    /// Parse a php.ini format string and apply the settings.
    pub fn parse_ini_string(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            // Skip section headers [section]
            if line.starts_with('[') && line.ends_with(']') {
                continue;
            }

            // Parse key = value
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let mut value = line[eq_pos + 1..].trim();

                // Strip inline comments
                if let Some(comment_pos) = value.find(';') {
                    // Only if preceded by whitespace (not in a quoted string)
                    if !value.starts_with('"') && !value.starts_with('\'') {
                        value = value[..comment_pos].trim();
                    }
                }

                // Strip quotes
                if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value = &value[1..value.len() - 1];
                }

                // Apply setting (INI_SYSTEM level — allowed for all directives)
                if let Some(entry) = self.entries.get_mut(key) {
                    entry.value = value.to_string();
                } else {
                    // Register unknown directives too
                    self.entries.insert(
                        key.to_string(),
                        IniEntry::new(key, value, IniPermission::All),
                    );
                }
            }
        }
    }

    /// Get an INI value as a boolean (handles "On", "Off", "1", "0", etc.).
    pub fn get_bool(&self, name: &str) -> bool {
        let val = self.get(name);
        matches!(val.to_lowercase().as_str(), "1" | "on" | "yes" | "true")
    }

    /// Get an INI value as an integer.
    pub fn get_long(&self, name: &str) -> i64 {
        let val = self.get(name);
        // Handle PHP shorthand: 128M, 8G, 1K
        parse_ini_size(val)
    }

    /// Get all directive names.
    pub fn directives(&self) -> Vec<&str> {
        self.entries.keys().map(|k| k.as_str()).collect()
    }

    /// Reset all modified entries to defaults.
    pub fn reset(&mut self) {
        for entry in self.entries.values_mut() {
            if entry.modified {
                entry.value = entry.default_value.clone();
                entry.modified = false;
            }
        }
    }
}

impl Default for IniSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a PHP INI size value (e.g., "128M" → 134217728).
fn parse_ini_size(val: &str) -> i64 {
    let val = val.trim();
    if val.is_empty() {
        return 0;
    }

    let (num_str, multiplier) = match val.as_bytes().last() {
        Some(b'K' | b'k') => (&val[..val.len() - 1], 1024i64),
        Some(b'M' | b'm') => (&val[..val.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&val[..val.len() - 1], 1024 * 1024 * 1024),
        _ => (val, 1),
    };

    num_str.trim().parse::<i64>().unwrap_or(0) * multiplier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ini_system_defaults() {
        let ini = IniSystem::new();
        assert_eq!(ini.get("error_reporting"), "32767");
        assert_eq!(ini.get("display_errors"), "1");
        assert_eq!(ini.get("memory_limit"), "128M");
        assert_eq!(ini.get("default_charset"), "UTF-8");
    }

    #[test]
    fn test_ini_get_nonexistent() {
        let ini = IniSystem::new();
        assert_eq!(ini.get("nonexistent"), "");
    }

    #[test]
    fn test_ini_set_user() {
        let mut ini = IniSystem::new();
        let old = ini.set("error_reporting", "0");
        assert_eq!(old, Some("32767".to_string()));
        assert_eq!(ini.get("error_reporting"), "0");
    }

    #[test]
    fn test_ini_set_system_only() {
        let mut ini = IniSystem::new();
        // open_basedir is INI_SYSTEM — cannot be changed at runtime
        let result = ini.set("open_basedir", "/tmp");
        assert!(result.is_none());
        assert_eq!(ini.get("open_basedir"), "");
    }

    #[test]
    fn test_ini_restore() {
        let mut ini = IniSystem::new();
        ini.set("display_errors", "0");
        assert_eq!(ini.get("display_errors"), "0");

        ini.restore("display_errors");
        assert_eq!(ini.get("display_errors"), "1");
    }

    #[test]
    fn test_ini_parse_string() {
        let mut ini = IniSystem::new();
        ini.parse_ini_string(
            r#"
; This is a comment
error_reporting = 0
display_errors = Off
memory_limit = 256M
custom_setting = "hello world"

[section]
date.timezone = "America/New_York"
"#,
        );

        assert_eq!(ini.get("error_reporting"), "0");
        assert_eq!(ini.get("display_errors"), "Off");
        assert_eq!(ini.get("memory_limit"), "256M");
        assert_eq!(ini.get("custom_setting"), "hello world");
        assert_eq!(ini.get("date.timezone"), "America/New_York");
    }

    #[test]
    fn test_ini_get_bool() {
        let mut ini = IniSystem::new();
        assert!(ini.get_bool("display_errors")); // "1"

        ini.set("display_errors", "Off");
        assert!(!ini.get_bool("display_errors"));

        ini.set("display_errors", "On");
        assert!(ini.get_bool("display_errors"));

        ini.set("display_errors", "yes");
        assert!(ini.get_bool("display_errors"));
    }

    #[test]
    fn test_ini_get_long() {
        let ini = IniSystem::new();
        assert_eq!(ini.get_long("memory_limit"), 128 * 1024 * 1024);
        assert_eq!(ini.get_long("max_execution_time"), 30);
    }

    #[test]
    fn test_parse_ini_size() {
        assert_eq!(parse_ini_size("128M"), 128 * 1024 * 1024);
        assert_eq!(parse_ini_size("2G"), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_ini_size("64K"), 64 * 1024);
        assert_eq!(parse_ini_size("1024"), 1024);
        assert_eq!(parse_ini_size(""), 0);
    }

    #[test]
    fn test_ini_permission_allows_user_change() {
        assert!(IniPermission::User.allows_user_change());
        assert!(IniPermission::All.allows_user_change());
        assert!(!IniPermission::System.allows_user_change());
        assert!(!IniPermission::PerDir.allows_user_change());
    }

    #[test]
    fn test_ini_register_custom() {
        let mut ini = IniSystem::new();
        ini.register("my_extension.debug", "0", IniPermission::All);
        assert_eq!(ini.get("my_extension.debug"), "0");

        ini.set("my_extension.debug", "1");
        assert_eq!(ini.get("my_extension.debug"), "1");
    }

    #[test]
    fn test_ini_reset() {
        let mut ini = IniSystem::new();
        ini.set("error_reporting", "0");
        ini.set("display_errors", "0");
        assert_eq!(ini.get("error_reporting"), "0");
        assert_eq!(ini.get("display_errors"), "0");

        ini.reset();
        assert_eq!(ini.get("error_reporting"), "32767");
        assert_eq!(ini.get("display_errors"), "1");
    }
}
