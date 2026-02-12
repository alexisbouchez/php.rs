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
    /// Covers ~200 standard PHP directives across all core modules.
    fn register_core_directives(&mut self) {
        let directives = [
            // ── Core / Zend Engine ──
            ("error_reporting", "32767", IniPermission::All), // E_ALL
            ("display_errors", "1", IniPermission::All),
            ("display_startup_errors", "1", IniPermission::All),
            ("log_errors", "0", IniPermission::All),
            ("log_errors_max_len", "1024", IniPermission::All),
            ("error_log", "", IniPermission::All),
            ("error_prepend_string", "", IniPermission::All),
            ("error_append_string", "", IniPermission::All),
            ("html_errors", "1", IniPermission::All),
            ("xmlrpc_errors", "0", IniPermission::System),
            ("xmlrpc_error_number", "0", IniPermission::All),
            ("docref_root", "", IniPermission::All),
            ("docref_ext", "", IniPermission::All),
            ("report_memleaks", "1", IniPermission::System),
            ("track_errors", "0", IniPermission::All),
            ("ignore_repeated_errors", "0", IniPermission::All),
            ("ignore_repeated_source", "0", IniPermission::All),
            ("memory_limit", "128M", IniPermission::All),
            ("max_execution_time", "30", IniPermission::All),
            ("max_input_time", "60", IniPermission::All),
            ("max_input_nesting_level", "64", IniPermission::PerDir),
            ("max_input_vars", "1000", IniPermission::PerDir),
            // ── Output / Buffering ──
            ("output_buffering", "0", IniPermission::PerDir),
            ("output_handler", "", IniPermission::PerDir),
            ("implicit_flush", "0", IniPermission::All),
            ("output_encoding", "", IniPermission::All),
            // ── Charset / Locale ──
            ("default_charset", "UTF-8", IniPermission::All),
            ("default_mimetype", "text/html", IniPermission::All),
            ("internal_encoding", "", IniPermission::All),
            ("input_encoding", "", IniPermission::All),
            // ── Paths & Directories ──
            ("include_path", ".", IniPermission::All),
            ("extension_dir", "", IniPermission::System),
            ("open_basedir", "", IniPermission::System),
            ("doc_root", "", IniPermission::System),
            ("user_dir", "", IniPermission::System),
            ("sys_temp_dir", "", IniPermission::System),
            // ── File Uploads ──
            ("file_uploads", "1", IniPermission::System),
            ("upload_tmp_dir", "", IniPermission::System),
            ("upload_max_filesize", "2M", IniPermission::PerDir),
            ("post_max_size", "8M", IniPermission::PerDir),
            ("max_file_uploads", "20", IniPermission::System),
            // ── URL / Network ──
            ("allow_url_fopen", "1", IniPermission::System),
            ("allow_url_include", "0", IniPermission::System),
            ("default_socket_timeout", "60", IniPermission::All),
            ("from", "", IniPermission::All),
            ("user_agent", "", IniPermission::All),
            ("auto_detect_line_endings", "0", IniPermission::All),
            // ── Disable ──
            ("disable_functions", "", IniPermission::System),
            ("disable_classes", "", IniPermission::System),
            // ── Request / Variables ──
            ("variables_order", "EGPCS", IniPermission::PerDir),
            ("request_order", "GP", IniPermission::PerDir),
            ("register_argc_argv", "1", IniPermission::PerDir),
            ("auto_globals_jit", "1", IniPermission::PerDir),
            ("auto_prepend_file", "", IniPermission::PerDir),
            ("auto_append_file", "", IniPermission::PerDir),
            ("arg_separator.input", "&", IniPermission::PerDir),
            ("arg_separator.output", "&", IniPermission::All),
            // ── PHP Tags ──
            ("short_open_tag", "1", IniPermission::PerDir),
            ("asp_tags", "0", IniPermission::PerDir),
            // ── Numeric ──
            ("precision", "14", IniPermission::All),
            ("serialize_precision", "-1", IniPermission::All),
            // ── Zend Engine ──
            ("zend.assertions", "1", IniPermission::All),
            ("zend.enable_gc", "1", IniPermission::All),
            ("zend.multibyte", "0", IniPermission::PerDir),
            ("zend.script_encoding", "", IniPermission::All),
            ("zend.detect_unicode", "1", IniPermission::All),
            ("zend.signal_check", "0", IniPermission::System),
            ("zend.exception_ignore_args", "0", IniPermission::All),
            (
                "zend.exception_string_param_max_len",
                "0",
                IniPermission::All,
            ),
            // ── Date ──
            ("date.timezone", "", IniPermission::All),
            ("date.default_latitude", "31.7667", IniPermission::All),
            ("date.default_longitude", "35.2333", IniPermission::All),
            ("date.sunrise_zenith", "90.833333", IniPermission::All),
            ("date.sunset_zenith", "90.833333", IniPermission::All),
            // ── PCRE ──
            ("pcre.backtrack_limit", "1000000", IniPermission::All),
            ("pcre.recursion_limit", "100000", IniPermission::All),
            ("pcre.jit", "1", IniPermission::All),
            // ── Session ──
            ("session.save_handler", "files", IniPermission::All),
            ("session.save_path", "", IniPermission::All),
            ("session.name", "PHPSESSID", IniPermission::All),
            ("session.auto_start", "0", IniPermission::PerDir),
            ("session.gc_probability", "1", IniPermission::All),
            ("session.gc_divisor", "100", IniPermission::All),
            ("session.gc_maxlifetime", "1440", IniPermission::All),
            ("session.serialize_handler", "php", IniPermission::All),
            ("session.cookie_lifetime", "0", IniPermission::All),
            ("session.cookie_path", "/", IniPermission::All),
            ("session.cookie_domain", "", IniPermission::All),
            ("session.cookie_secure", "0", IniPermission::All),
            ("session.cookie_httponly", "0", IniPermission::All),
            ("session.cookie_samesite", "", IniPermission::All),
            ("session.use_strict_mode", "0", IniPermission::All),
            ("session.use_cookies", "1", IniPermission::All),
            ("session.use_only_cookies", "1", IniPermission::All),
            ("session.use_trans_sid", "0", IniPermission::All),
            (
                "session.trans_sid_tags",
                "a=href,area=href,frame=src,form=",
                IniPermission::All,
            ),
            ("session.trans_sid_hosts", "", IniPermission::All),
            ("session.sid_length", "32", IniPermission::All),
            ("session.sid_bits_per_character", "5", IniPermission::All),
            ("session.cache_limiter", "nocache", IniPermission::All),
            ("session.cache_expire", "180", IniPermission::All),
            ("session.lazy_write", "1", IniPermission::All),
            (
                "session.upload_progress.enabled",
                "1",
                IniPermission::PerDir,
            ),
            (
                "session.upload_progress.cleanup",
                "1",
                IniPermission::PerDir,
            ),
            (
                "session.upload_progress.prefix",
                "upload_progress_",
                IniPermission::PerDir,
            ),
            (
                "session.upload_progress.name",
                "PHP_SESSION_UPLOAD_PROGRESS",
                IniPermission::PerDir,
            ),
            ("session.upload_progress.freq", "1%", IniPermission::PerDir),
            (
                "session.upload_progress.min_freq",
                "1",
                IniPermission::PerDir,
            ),
            // ── mbstring ──
            ("mbstring.language", "neutral", IniPermission::All),
            ("mbstring.internal_encoding", "", IniPermission::All),
            ("mbstring.http_input", "", IniPermission::All),
            ("mbstring.http_output", "", IniPermission::All),
            ("mbstring.encoding_translation", "0", IniPermission::PerDir),
            ("mbstring.detect_order", "", IniPermission::All),
            ("mbstring.substitute_character", "", IniPermission::All),
            ("mbstring.func_overload", "0", IniPermission::System),
            ("mbstring.strict_detection", "0", IniPermission::All),
            ("mbstring.regex_stack_limit", "100000", IniPermission::All),
            ("mbstring.regex_retry_limit", "1000000", IniPermission::All),
            // ── Filter ──
            ("filter.default", "unsafe_raw", IniPermission::PerDir),
            ("filter.default_flags", "", IniPermission::PerDir),
            // ── Assert ──
            ("assert.active", "1", IniPermission::All),
            ("assert.bail", "0", IniPermission::All),
            ("assert.warning", "1", IniPermission::All),
            ("assert.callback", "", IniPermission::All),
            ("assert.exception", "1", IniPermission::All),
            // ── Bcmath ──
            ("bcmath.scale", "0", IniPermission::All),
            // ── Mail ──
            ("SMTP", "localhost", IniPermission::All),
            ("smtp_port", "25", IniPermission::All),
            ("sendmail_from", "", IniPermission::All),
            ("sendmail_path", "", IniPermission::System),
            ("mail.add_x_header", "0", IniPermission::PerDir),
            ("mail.mixed_lf_and_crlf", "0", IniPermission::System),
            ("mail.log", "", IniPermission::PerDir),
            // ── Opcache (stub directives, recognised but not enforced) ──
            ("opcache.enable", "1", IniPermission::System),
            ("opcache.enable_cli", "0", IniPermission::System),
            ("opcache.memory_consumption", "128", IniPermission::System),
            (
                "opcache.interned_strings_buffer",
                "8",
                IniPermission::System,
            ),
            (
                "opcache.max_accelerated_files",
                "10000",
                IniPermission::System,
            ),
            ("opcache.revalidate_freq", "2", IniPermission::All),
            ("opcache.validate_timestamps", "1", IniPermission::All),
            ("opcache.save_comments", "1", IniPermission::System),
            ("opcache.jit", "tracing", IniPermission::All),
            ("opcache.jit_buffer_size", "0", IniPermission::System),
            // ── cURL ──
            ("curl.cainfo", "", IniPermission::System),
            // ── OpenSSL ──
            ("openssl.cafile", "", IniPermission::PerDir),
            ("openssl.capath", "", IniPermission::PerDir),
            // ── MySQLi ──
            ("mysqli.default_host", "", IniPermission::All),
            ("mysqli.default_user", "", IniPermission::All),
            ("mysqli.default_pw", "", IniPermission::All),
            ("mysqli.default_port", "3306", IniPermission::All),
            ("mysqli.default_socket", "", IniPermission::All),
            ("mysqli.reconnect", "0", IniPermission::System),
            ("mysqli.allow_local_infile", "0", IniPermission::System),
            // ── PDO ──
            ("pdo_mysql.default_socket", "", IniPermission::System),
            // ── SPL ──
            ("spl.autoload_extensions", ".php,.inc", IniPermission::All),
            // ── Tidy ──
            ("tidy.clean_output", "0", IniPermission::User),
            ("tidy.default_config", "", IniPermission::System),
            // ── SOAP ──
            ("soap.wsdl_cache_enabled", "1", IniPermission::All),
            ("soap.wsdl_cache_dir", "/tmp", IniPermission::All),
            ("soap.wsdl_cache_ttl", "86400", IniPermission::All),
            ("soap.wsdl_cache_limit", "5", IniPermission::All),
            // ── JSON ──
            ("json.encode_max_depth", "512", IniPermission::All),
            // ── iconv ──
            ("iconv.input_encoding", "", IniPermission::All),
            ("iconv.output_encoding", "", IniPermission::All),
            ("iconv.internal_encoding", "", IniPermission::All),
            // ── Intl ──
            ("intl.default_locale", "", IniPermission::All),
            ("intl.error_level", "0", IniPermission::All),
            ("intl.use_exceptions", "0", IniPermission::All),
            // ── GD ──
            ("gd.jpeg_ignore_warning", "1", IniPermission::All),
            // ── Exif ──
            ("exif.encode_unicode", "ISO-8859-15", IniPermission::All),
            (
                "exif.decode_unicode_motorola",
                "UCS-2BE",
                IniPermission::All,
            ),
            ("exif.decode_unicode_intel", "UCS-2LE", IniPermission::All),
            ("exif.encode_jis", "", IniPermission::All),
            ("exif.decode_jis_motorola", "JIS", IniPermission::All),
            ("exif.decode_jis_intel", "JIS", IniPermission::All),
            // ── Readline ──
            ("cli.pager", "", IniPermission::All),
            ("cli.prompt", "\\b \\> ", IniPermission::All),
            // ── Fileinfo ──
            ("mime_magic.magicfile", "", IniPermission::System),
            // ── Syslog ──
            ("syslog.facility", "LOG_USER", IniPermission::System),
            ("syslog.ident", "php", IniPermission::System),
            ("syslog.filter", "no-ctrl", IniPermission::All),
            // ── Misc ──
            ("expose_php", "1", IniPermission::System),
            ("zlib.output_compression", "0", IniPermission::All),
            ("zlib.output_compression_level", "-1", IniPermission::All),
            ("zlib.output_handler", "", IniPermission::All),
            ("url_rewriter.tags", "", IniPermission::All),
            ("url_rewriter.hosts", "", IniPermission::All),
            ("unserialize_callback_func", "", IniPermission::All),
            ("unserialize_max_depth", "4096", IniPermission::All),
            ("realpath_cache_size", "4096K", IniPermission::System),
            ("realpath_cache_ttl", "120", IniPermission::System),
            ("user_ini_filename", ".user.ini", IniPermission::System),
            ("user_ini_cache_ttl", "300", IniPermission::System),
            ("hard_timeout", "2", IniPermission::System),
            ("sys_temp_dir", "", IniPermission::System),
            ("enable_dl", "0", IniPermission::System),
            ("enable_post_data_reading", "1", IniPermission::PerDir),
            ("cgi.rfc2616_headers", "0", IniPermission::All),
            ("cgi.nph", "0", IniPermission::All),
            ("cgi.force_redirect", "1", IniPermission::System),
            ("cgi.redirect_status_env", "", IniPermission::System),
            ("cgi.fix_pathinfo", "1", IniPermission::System),
            ("fastcgi.impersonate", "0", IniPermission::System),
            ("fastcgi.logging", "1", IniPermission::System),
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

    /// Force-set an INI directive bypassing permission checks.
    /// Used for SAPI-level overrides like CLI `-d` flags and php.ini loading.
    pub fn force_set(&mut self, name: &str, value: impl Into<String>) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.value = value.into();
            entry.modified = true;
        } else {
            self.entries.insert(
                name.to_string(),
                IniEntry::new(name, value, IniPermission::All),
            );
        }
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

    /// Get all entries (for ini_get_all).
    pub fn all_entries(&self) -> &HashMap<String, IniEntry> {
        &self.entries
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

    /// Load php.ini from the given path.
    /// Returns true if the file was successfully loaded.
    pub fn load_ini_file(&mut self, path: &str) -> bool {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                self.parse_ini_string(&content);
                true
            }
            Err(_) => false,
        }
    }

    /// Search default paths for php.ini and load it.
    /// Returns the path of the loaded file, or None if no php.ini was found.
    ///
    /// Search order matches PHP:
    /// 1. $PHPRC environment variable (file or directory)
    /// 2. /etc/php/{major}.{minor}/cli/php.ini (Debian/Ubuntu)
    /// 3. /etc/php.ini (RHEL/CentOS/Fedora)
    /// 4. /usr/local/lib/php.ini
    /// 5. /usr/local/etc/php.ini (FreeBSD)
    pub fn load_default_ini(&mut self) -> Option<String> {
        let search_paths = build_ini_search_paths();

        for path in &search_paths {
            if std::path::Path::new(path).is_file() {
                if self.load_ini_file(path) {
                    return Some(path.clone());
                }
            }
        }

        None
    }

    /// Load .user.ini overrides for a given directory.
    /// Applies INI_USER and INI_PERDIR directives from .user.ini.
    /// Returns true if a .user.ini was found and loaded.
    pub fn load_user_ini(&mut self, dir: &str) -> bool {
        let filename = self.get("user_ini_filename");
        let filename = if filename.is_empty() {
            ".user.ini"
        } else {
            filename
        };
        let user_ini_path = std::path::Path::new(dir).join(filename);

        match std::fs::read_to_string(&user_ini_path) {
            Ok(content) => {
                self.parse_user_ini_string(&content);
                true
            }
            Err(_) => false,
        }
    }

    /// Parse a .user.ini format string — only applies directives that allow
    /// per-directory or user-level changes (not INI_SYSTEM-only).
    pub fn parse_user_ini_string(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                continue;
            }

            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let mut value = line[eq_pos + 1..].trim();

                // Strip inline comments
                if let Some(comment_pos) = value.find(';') {
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

                // Only apply if existing entry allows per-dir or user changes,
                // or if it's an unknown directive (treated as All).
                if let Some(entry) = self.entries.get_mut(key) {
                    let perm = entry.permission as u8;
                    // Allow if PerDir (2) or User (4) or All (7)
                    if perm & (IniPermission::PerDir as u8 | IniPermission::User as u8) != 0 {
                        entry.value = value.to_string();
                        entry.modified = true;
                    }
                    // INI_SYSTEM-only entries are silently skipped (matching PHP behavior)
                } else {
                    // Unknown directive: register and allow
                    self.entries.insert(
                        key.to_string(),
                        IniEntry::new(key, value, IniPermission::All),
                    );
                }
            }
        }
    }
}

impl Default for IniSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the list of default search paths for php.ini.
fn build_ini_search_paths() -> Vec<String> {
    let mut paths = Vec::new();

    // 1. $PHPRC environment variable
    if let Ok(phprc) = std::env::var("PHPRC") {
        let p = std::path::Path::new(&phprc);
        if p.is_file() {
            paths.push(phprc.clone());
        } else if p.is_dir() {
            paths.push(format!("{}/php.ini", phprc));
        }
    }

    // 2. Debian/Ubuntu per-version path
    paths.push("/etc/php/8.6/cli/php.ini".to_string());
    paths.push("/etc/php/8.4/cli/php.ini".to_string());
    paths.push("/etc/php/8.3/cli/php.ini".to_string());

    // 3. RHEL/CentOS/Fedora
    paths.push("/etc/php.ini".to_string());

    // 4. Generic Unix
    paths.push("/usr/local/lib/php.ini".to_string());

    // 5. FreeBSD
    paths.push("/usr/local/etc/php.ini".to_string());

    // 6. macOS Homebrew
    paths.push("/opt/homebrew/etc/php/8.6/php.ini".to_string());
    paths.push("/opt/homebrew/etc/php/8.4/php.ini".to_string());
    paths.push("/usr/local/etc/php/8.6/php.ini".to_string());

    paths
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

    #[test]
    fn test_ini_has_standard_directives() {
        // Verify that ~200 standard directives are registered
        let ini = IniSystem::new();
        let directives = ini.directives();
        assert!(
            directives.len() >= 180,
            "Expected >=180 directives, got {}",
            directives.len()
        );

        // Spot-check directives from various modules
        assert_eq!(ini.get("pcre.backtrack_limit"), "1000000");
        assert_eq!(ini.get("session.cookie_path"), "/");
        assert_eq!(ini.get("mbstring.language"), "neutral");
        assert_eq!(ini.get("bcmath.scale"), "0");
        assert_eq!(ini.get("filter.default"), "unsafe_raw");
        assert_eq!(ini.get("zend.assertions"), "1");
        assert_eq!(ini.get("date.timezone"), "");
        assert_eq!(ini.get("mysqli.default_port"), "3306");
        assert_eq!(ini.get("opcache.enable"), "1");
        assert_eq!(ini.get("spl.autoload_extensions"), ".php,.inc");
        assert_eq!(ini.get("user_ini_filename"), ".user.ini");
        assert_eq!(ini.get("expose_php"), "1");
    }

    #[test]
    fn test_ini_search_paths() {
        let paths = super::build_ini_search_paths();
        // Should have multiple search paths
        assert!(paths.len() >= 5);
        // Should include standard paths
        assert!(paths.contains(&"/etc/php.ini".to_string()));
        assert!(paths.contains(&"/usr/local/lib/php.ini".to_string()));
    }

    #[test]
    fn test_user_ini_respects_permissions() {
        let mut ini = IniSystem::new();
        // open_basedir is INI_SYSTEM — .user.ini cannot override it
        ini.parse_user_ini_string(
            r#"
display_errors = 0
open_basedir = /tmp
custom_user_val = hello
"#,
        );

        // display_errors is INI_ALL — should be changed
        assert_eq!(ini.get("display_errors"), "0");
        // open_basedir is INI_SYSTEM — should NOT be changed
        assert_eq!(ini.get("open_basedir"), "");
        // Custom directive should be added
        assert_eq!(ini.get("custom_user_val"), "hello");
    }

    #[test]
    fn test_load_ini_file_nonexistent() {
        let mut ini = IniSystem::new();
        assert!(!ini.load_ini_file("/nonexistent/path/php.ini"));
    }

    #[test]
    fn test_all_entries() {
        let ini = IniSystem::new();
        let entries = ini.all_entries();
        assert!(entries.len() >= 180);
        let entry = entries.get("error_reporting").unwrap();
        assert_eq!(entry.default_value, "32767");
        assert_eq!(entry.permission as u8, IniPermission::All as u8);
    }
}
