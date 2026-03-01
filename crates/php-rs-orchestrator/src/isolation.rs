//! Process isolation and resource limits for multi-tenant security.
//!
//! Applies OS-level restrictions to app processes:
//! - Resource limits via setrlimit (cross-platform Unix)
//! - UID/GID dropping (run as unprivileged user)
//! - Linux cgroups v2 for memory/CPU limits
//! - File descriptor and process count limits
//! - Network isolation via iptables (Linux) owner-based filtering

/// Network policy for an app process.
///
/// Controls which outbound connections the app is allowed to make.
/// Enforced via iptables on Linux using the owner module to match
/// traffic by UID. Requires the app to run as its own OS user (APP_UID).
#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    /// Whether network isolation is enabled.
    pub enabled: bool,
    /// The app's assigned listen port (always allowed for bind + listen).
    pub app_port: u16,
    /// Allowed outbound TCP ports (default: 80, 443 for HTTP/HTTPS).
    pub allowed_outbound_ports: Vec<u16>,
    /// Allowed outbound destinations as "ip:port" or "cidr:port" pairs.
    /// Used for backing services (e.g. "10.0.1.5:3306" for MySQL).
    pub allowed_outbound_destinations: Vec<String>,
    /// Whether to allow outbound DNS (UDP port 53). Default: true.
    pub allow_dns: bool,
    /// Whether to allow loopback traffic (127.0.0.0/8). Default: true.
    /// Set to false to block inter-app communication on the same host.
    pub allow_loopback: bool,
    /// Ports on loopback that are blocked even if allow_loopback is true.
    /// Used to prevent connecting to other apps' ports.
    pub blocked_loopback_ports: Vec<u16>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            app_port: 0,
            allowed_outbound_ports: vec![80, 443],
            allowed_outbound_destinations: Vec::new(),
            allow_dns: true,
            allow_loopback: true,
            blocked_loopback_ports: Vec::new(),
        }
    }
}

impl NetworkPolicy {
    /// Build from app environment variables.
    pub fn from_env(env: &std::collections::HashMap<String, String>) -> Self {
        let mut policy = Self::default();

        // Enable network isolation if APP_NET_ISOLATE=1|true|yes.
        if let Some(val) = env.get("APP_NET_ISOLATE") {
            policy.enabled = matches!(val.as_str(), "1" | "true" | "yes");
        }

        // App port (always allowed).
        if let Some(port) = env.get("APP_PORT").and_then(|v| v.parse().ok()) {
            policy.app_port = port;
        }

        // Allowed outbound ports (comma-separated).
        // e.g. APP_NET_ALLOW_PORTS=80,443,8080
        if let Some(ports) = env.get("APP_NET_ALLOW_PORTS") {
            policy.allowed_outbound_ports = ports
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
        }

        // Allowed outbound destinations (comma-separated "ip:port" pairs).
        // e.g. APP_NET_ALLOW_DEST=10.0.1.5:3306,10.0.1.6:6379
        if let Some(dests) = env.get("APP_NET_ALLOW_DEST") {
            policy.allowed_outbound_destinations = dests
                .split(',')
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .collect();
        }

        // DNS override.
        if let Some(val) = env.get("APP_NET_ALLOW_DNS") {
            policy.allow_dns = !matches!(val.as_str(), "0" | "false" | "no");
        }

        // Loopback override.
        if let Some(val) = env.get("APP_NET_ALLOW_LOOPBACK") {
            policy.allow_loopback = !matches!(val.as_str(), "0" | "false" | "no");
        }

        // Blocked loopback ports (other apps' ports, comma-separated).
        // e.g. APP_NET_BLOCK_PORTS=8081,8082,8083
        if let Some(ports) = env.get("APP_NET_BLOCK_PORTS") {
            policy.blocked_loopback_ports = ports
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
        }

        policy
    }

    /// Generate iptables rules for this policy.
    /// Returns a list of iptables commands to execute (without the `iptables` prefix).
    /// Requires APP_UID to be set for owner-based matching.
    pub fn generate_iptables_rules(&self, uid: u32) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let mut rules = Vec::new();
        let chain = format!("PHPRS_APP_{}", uid);

        // Create a dedicated chain for this app.
        rules.push(format!("-N {}", chain));

        // Allow established/related connections (response traffic).
        rules.push(format!(
            "-A {} -m state --state ESTABLISHED,RELATED -j ACCEPT",
            chain
        ));

        // Allow the app to listen on its own port.
        if self.app_port > 0 {
            rules.push(format!(
                "-A {} -p tcp --sport {} -j ACCEPT",
                chain, self.app_port
            ));
        }

        // Allow DNS if enabled.
        if self.allow_dns {
            rules.push(format!("-A {} -p udp --dport 53 -j ACCEPT", chain));
            rules.push(format!("-A {} -p tcp --dport 53 -j ACCEPT", chain));
        }

        // Block specific loopback ports (other apps) before allowing loopback.
        for port in &self.blocked_loopback_ports {
            rules.push(format!(
                "-A {} -d 127.0.0.0/8 -p tcp --dport {} -j DROP",
                chain, port
            ));
        }

        // Allow loopback traffic (after blocked ports).
        if self.allow_loopback {
            rules.push(format!("-A {} -d 127.0.0.0/8 -j ACCEPT", chain));
        }

        // Allow specific outbound destinations (backing services).
        for dest in &self.allowed_outbound_destinations {
            if let Some((ip, port)) = dest.rsplit_once(':') {
                rules.push(format!(
                    "-A {} -d {} -p tcp --dport {} -j ACCEPT",
                    chain, ip, port
                ));
            }
        }

        // Allow general outbound ports (HTTP, HTTPS, etc.).
        for port in &self.allowed_outbound_ports {
            rules.push(format!(
                "-A {} -p tcp --dport {} -j ACCEPT",
                chain, port
            ));
        }

        // Default: drop all other outbound traffic.
        rules.push(format!("-A {} -j DROP", chain));

        // Hook into the OUTPUT chain — match by UID.
        rules.push(format!(
            "-A OUTPUT -m owner --uid-owner {} -j {}",
            uid, chain
        ));

        rules
    }

    /// Generate iptables cleanup commands to remove rules for this app.
    pub fn generate_iptables_cleanup(&self, uid: u32) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let chain = format!("PHPRS_APP_{}", uid);
        vec![
            // Remove the jump rule from OUTPUT.
            format!("-D OUTPUT -m owner --uid-owner {} -j {}", uid, chain),
            // Flush and delete the chain.
            format!("-F {}", chain),
            format!("-X {}", chain),
        ]
    }

    /// Describe the active network policy (for status display).
    pub fn describe(&self) -> Vec<String> {
        if !self.enabled {
            return vec!["Network isolation: disabled".into()];
        }
        let mut desc = vec!["Network isolation: enabled".into()];
        if self.app_port > 0 {
            desc.push(format!("  Listen port: {}", self.app_port));
        }
        if !self.allowed_outbound_ports.is_empty() {
            desc.push(format!(
                "  Allowed outbound ports: {:?}",
                self.allowed_outbound_ports
            ));
        }
        if !self.allowed_outbound_destinations.is_empty() {
            desc.push(format!(
                "  Allowed destinations: {:?}",
                self.allowed_outbound_destinations
            ));
        }
        desc.push(format!("  DNS: {}", if self.allow_dns { "allowed" } else { "blocked" }));
        desc.push(format!(
            "  Loopback: {}",
            if self.allow_loopback { "allowed" } else { "blocked" }
        ));
        if !self.blocked_loopback_ports.is_empty() {
            desc.push(format!(
                "  Blocked loopback ports: {:?}",
                self.blocked_loopback_ports
            ));
        }
        desc
    }
}

/// Apply iptables rules for network isolation.
/// Must be called from parent process AFTER spawning the child.
/// Requires root privileges.
#[cfg(target_os = "linux")]
pub fn apply_network_rules(policy: &NetworkPolicy, uid: u32) -> Result<(), String> {
    if !policy.enabled {
        return Ok(());
    }

    let rules = policy.generate_iptables_rules(uid);
    for rule in &rules {
        let output = std::process::Command::new("iptables")
            .args(rule.split_whitespace())
            .output()
            .map_err(|e| format!("iptables failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("iptables {} failed: {}", rule, stderr.trim()));
        }
    }
    Ok(())
}

/// Remove iptables rules for network isolation.
#[cfg(target_os = "linux")]
pub fn remove_network_rules(policy: &NetworkPolicy, uid: u32) -> Result<(), String> {
    if !policy.enabled {
        return Ok(());
    }

    let rules = policy.generate_iptables_cleanup(uid);
    for rule in &rules {
        let output = std::process::Command::new("iptables")
            .args(rule.split_whitespace())
            .output()
            .map_err(|e| format!("iptables cleanup failed: {}", e))?;

        if !output.status.success() {
            // Non-fatal — rule may already be removed.
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("iptables cleanup warning: {}: {}", rule, stderr.trim());
        }
    }
    Ok(())
}

/// Isolation and resource limit configuration for an app process.
#[derive(Debug, Clone, Default)]
pub struct IsolationConfig {
    /// OS user ID to run the process as.
    pub uid: Option<u32>,
    /// OS group ID to run the process as.
    pub gid: Option<u32>,
    /// Memory limit in bytes (RLIMIT_AS — virtual address space).
    pub memory_limit_bytes: Option<u64>,
    /// Max open file descriptors (RLIMIT_NOFILE).
    pub max_fds: Option<u64>,
    /// Max child processes (RLIMIT_NPROC).
    pub max_procs: Option<u64>,
    /// CPU time limit in seconds (RLIMIT_CPU).
    pub cpu_time_limit: Option<u64>,
    /// Max file size in bytes (RLIMIT_FSIZE).
    pub max_file_size: Option<u64>,
    /// Max core dump size in bytes (RLIMIT_CORE, 0 = disable core dumps).
    pub core_size: Option<u64>,
    /// Disk quota in bytes for the app directory.
    pub disk_quota: Option<u64>,
    /// Network isolation policy.
    pub network: NetworkPolicy,
    /// Linux cgroup path for this app (e.g. /sys/fs/cgroup/phprs/myapp).
    #[cfg(target_os = "linux")]
    pub cgroup_path: Option<String>,
    /// Cgroup memory.max in bytes.
    #[cfg(target_os = "linux")]
    pub cgroup_memory_max: Option<u64>,
    /// Cgroup cpu.max (microseconds per period, e.g. "50000 100000" = 50% of 1 core).
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_max: Option<String>,
}

impl IsolationConfig {
    /// Build from an app's environment variables.
    /// Reads APP_UID, APP_GID, APP_RLIMIT_*, APP_NET_* env vars from the app's config.
    pub fn from_env(env: &std::collections::HashMap<String, String>) -> Self {
        let mut config = Self::default();

        if let Some(uid) = env.get("APP_UID").and_then(|v| v.parse().ok()) {
            config.uid = Some(uid);
        }
        if let Some(gid) = env.get("APP_GID").and_then(|v| v.parse().ok()) {
            config.gid = Some(gid);
        }
        if let Some(mem) = env.get("APP_RLIMIT_MEMORY").and_then(|v| parse_size(v)) {
            config.memory_limit_bytes = Some(mem);
        }
        if let Some(fds) = env.get("APP_RLIMIT_NOFILE").and_then(|v| v.parse().ok()) {
            config.max_fds = Some(fds);
        }
        if let Some(nproc) = env.get("APP_RLIMIT_NPROC").and_then(|v| v.parse().ok()) {
            config.max_procs = Some(nproc);
        }
        if let Some(cpu) = env.get("APP_RLIMIT_CPU").and_then(|v| v.parse().ok()) {
            config.cpu_time_limit = Some(cpu);
        }
        if let Some(fsize) = env.get("APP_RLIMIT_FSIZE").and_then(|v| parse_size(v)) {
            config.max_file_size = Some(fsize);
        }

        // Disable core dumps by default in PaaS.
        config.core_size = Some(
            env.get("APP_RLIMIT_CORE")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        );

        // Disk quota.
        if let Some(quota) = env.get("APP_DISK_QUOTA").and_then(|v| parse_size(v)) {
            config.disk_quota = Some(quota);
        }

        // Network isolation policy.
        config.network = NetworkPolicy::from_env(env);

        #[cfg(target_os = "linux")]
        {
            config.cgroup_path = env.get("APP_CGROUP_PATH").cloned();
            if let Some(mem) = env.get("APP_CGROUP_MEMORY").and_then(|v| parse_size(v)) {
                config.cgroup_memory_max = Some(mem);
            }
            config.cgroup_cpu_max = env.get("APP_CGROUP_CPU").cloned();
        }

        config
    }

    /// Apply resource limits to the current process (call from pre_exec).
    ///
    /// # Safety
    /// Must be called in a pre_exec context (after fork, before exec).
    pub unsafe fn apply(&self) -> Result<(), String> {
        self.apply_rlimits()?;
        self.drop_privileges()?;
        Ok(())
    }

    /// Set resource limits via setrlimit.
    unsafe fn apply_rlimits(&self) -> Result<(), String> {
        if let Some(mem) = self.memory_limit_bytes {
            set_rlimit(libc::RLIMIT_AS, mem)?;
        }
        if let Some(fds) = self.max_fds {
            set_rlimit(libc::RLIMIT_NOFILE, fds)?;
        }
        if let Some(nproc) = self.max_procs {
            set_rlimit(libc::RLIMIT_NPROC, nproc)?;
        }
        if let Some(cpu) = self.cpu_time_limit {
            set_rlimit(libc::RLIMIT_CPU, cpu)?;
        }
        if let Some(fsize) = self.max_file_size {
            set_rlimit(libc::RLIMIT_FSIZE, fsize)?;
        }
        if let Some(core) = self.core_size {
            set_rlimit(libc::RLIMIT_CORE, core)?;
        }
        Ok(())
    }

    /// Drop privileges to the configured UID/GID.
    unsafe fn drop_privileges(&self) -> Result<(), String> {
        // Set GID first (requires root), then UID.
        if let Some(gid) = self.gid {
            if libc::setgid(gid) != 0 {
                return Err(format!(
                    "setgid({}) failed: {}",
                    gid,
                    std::io::Error::last_os_error()
                ));
            }
            // Also set supplementary groups to just this GID.
            if libc::setgroups(1, &gid as *const u32 as *const libc::gid_t) != 0 {
                // Non-fatal — setgroups may fail without root.
            }
        }
        if let Some(uid) = self.uid {
            if libc::setuid(uid) != 0 {
                return Err(format!(
                    "setuid({}) failed: {}",
                    uid,
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    /// Set up Linux cgroups v2 for this app's process.
    /// Must be called BEFORE spawning the process (from the parent).
    #[cfg(target_os = "linux")]
    pub fn setup_cgroup(&self, pid: u32) -> Result<(), String> {
        let cgroup_path = match &self.cgroup_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let cgroup = std::path::Path::new(&cgroup_path);

        // Create the cgroup directory if it doesn't exist.
        std::fs::create_dir_all(cgroup)
            .map_err(|e| format!("Cannot create cgroup {}: {}", cgroup_path, e))?;

        // Set memory limit.
        if let Some(mem) = self.cgroup_memory_max {
            std::fs::write(cgroup.join("memory.max"), mem.to_string())
                .map_err(|e| format!("Cannot set memory.max: {}", e))?;
        }

        // Set CPU limit.
        if let Some(ref cpu) = self.cgroup_cpu_max {
            std::fs::write(cgroup.join("cpu.max"), cpu)
                .map_err(|e| format!("Cannot set cpu.max: {}", e))?;
        }

        // Add the process to the cgroup.
        std::fs::write(cgroup.join("cgroup.procs"), pid.to_string())
            .map_err(|e| format!("Cannot add PID {} to cgroup: {}", pid, e))?;

        Ok(())
    }

    /// Check if any isolation settings are configured.
    pub fn has_settings(&self) -> bool {
        self.uid.is_some()
            || self.gid.is_some()
            || self.memory_limit_bytes.is_some()
            || self.max_fds.is_some()
            || self.max_procs.is_some()
            || self.cpu_time_limit.is_some()
            || self.max_file_size.is_some()
            || self.core_size.is_some()
            || self.disk_quota.is_some()
            || self.network.enabled
    }

    /// Describe the active isolation settings (for status display).
    pub fn describe(&self) -> Vec<String> {
        let mut desc = Vec::new();
        if let Some(uid) = self.uid {
            desc.push(format!("UID: {}", uid));
        }
        if let Some(gid) = self.gid {
            desc.push(format!("GID: {}", gid));
        }
        if let Some(mem) = self.memory_limit_bytes {
            desc.push(format!("Memory limit: {} MB", mem / (1024 * 1024)));
        }
        if let Some(fds) = self.max_fds {
            desc.push(format!("Max FDs: {}", fds));
        }
        if let Some(nproc) = self.max_procs {
            desc.push(format!("Max procs: {}", nproc));
        }
        if let Some(cpu) = self.cpu_time_limit {
            desc.push(format!("CPU time limit: {}s", cpu));
        }
        if let Some(fsize) = self.max_file_size {
            desc.push(format!("Max file size: {} MB", fsize / (1024 * 1024)));
        }
        if let Some(core) = self.core_size {
            if core == 0 {
                desc.push("Core dumps: disabled".into());
            }
        }
        if let Some(quota) = self.disk_quota {
            desc.push(format!("Disk quota: {} MB", quota / (1024 * 1024)));
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(ref path) = self.cgroup_path {
                desc.push(format!("Cgroup: {}", path));
            }
            if let Some(mem) = self.cgroup_memory_max {
                desc.push(format!("Cgroup memory.max: {} MB", mem / (1024 * 1024)));
            }
            if let Some(ref cpu) = self.cgroup_cpu_max {
                desc.push(format!("Cgroup cpu.max: {}", cpu));
            }
        }
        // Network isolation.
        desc.extend(self.network.describe());
        desc
    }
}

/// Set a resource limit (both soft and hard).
unsafe fn set_rlimit(resource: libc::c_int, value: u64) -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    if libc::setrlimit(resource, &limit) != 0 {
        let name = rlimit_name(resource);
        return Err(format!(
            "setrlimit({}, {}) failed: {}",
            name,
            value,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Get the name of a resource limit for error messages.
fn rlimit_name(resource: libc::c_int) -> &'static str {
    match resource {
        libc::RLIMIT_AS => "RLIMIT_AS",
        libc::RLIMIT_NOFILE => "RLIMIT_NOFILE",
        libc::RLIMIT_NPROC => "RLIMIT_NPROC",
        libc::RLIMIT_CPU => "RLIMIT_CPU",
        libc::RLIMIT_FSIZE => "RLIMIT_FSIZE",
        libc::RLIMIT_CORE => "RLIMIT_CORE",
        _ => "RLIMIT_UNKNOWN",
    }
}

/// Parse a size string like "512M", "2G", "1024K", or plain bytes.
fn parse_size(val: &str) -> Option<u64> {
    let val = val.trim();
    if val.is_empty() {
        return None;
    }
    let (num_str, multiplier) = match val.as_bytes().last() {
        Some(b'K' | b'k') => (&val[..val.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&val[..val.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&val[..val.len() - 1], 1024 * 1024 * 1024),
        _ => (val, 1),
    };
    num_str.trim().parse::<u64>().ok().map(|n| n * multiplier)
}

/// Calculate the total size of a directory tree (in bytes).
pub fn dir_size(path: &std::path::Path) -> u64 {
    if !path.is_dir() {
        return 0;
    }
    let mut total: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                total += dir_size(&entry_path);
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Check if an app exceeds its disk quota.
/// Returns (current_size, quota, over_quota).
pub fn check_disk_quota(app_dir: &std::path::Path, quota_bytes: u64) -> (u64, u64, bool) {
    let current = dir_size(app_dir);
    (current, quota_bytes, current > quota_bytes)
}

/// Query current resource limits for diagnostic purposes.
#[allow(dead_code)]
pub fn get_current_limits() -> Vec<(String, u64, u64)> {
    let mut limits = Vec::new();
    let resources = [
        (libc::RLIMIT_AS, "RLIMIT_AS (virtual memory)"),
        (libc::RLIMIT_NOFILE, "RLIMIT_NOFILE (open files)"),
        (libc::RLIMIT_NPROC, "RLIMIT_NPROC (processes)"),
        (libc::RLIMIT_CPU, "RLIMIT_CPU (cpu seconds)"),
        (libc::RLIMIT_FSIZE, "RLIMIT_FSIZE (file size)"),
        (libc::RLIMIT_CORE, "RLIMIT_CORE (core dump)"),
    ];
    for (resource, name) in &resources {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::getrlimit(*resource, &mut limit) == 0 {
                limits.push((name.to_string(), limit.rlim_cur as u64, limit.rlim_max as u64));
            }
        }
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("64K"), Some(64 * 1024));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn test_isolation_config_default() {
        let config = IsolationConfig::default();
        assert!(config.uid.is_none());
        assert!(config.gid.is_none());
        assert!(config.memory_limit_bytes.is_none());
        assert!(!config.has_settings());
    }

    #[test]
    fn test_isolation_config_from_env() {
        let mut env = HashMap::new();
        env.insert("APP_UID".into(), "1000".into());
        env.insert("APP_GID".into(), "1000".into());
        env.insert("APP_RLIMIT_MEMORY".into(), "512M".into());
        env.insert("APP_RLIMIT_NOFILE".into(), "1024".into());
        env.insert("APP_RLIMIT_NPROC".into(), "64".into());
        env.insert("APP_RLIMIT_CPU".into(), "300".into());
        env.insert("APP_RLIMIT_FSIZE".into(), "1G".into());

        let config = IsolationConfig::from_env(&env);
        assert_eq!(config.uid, Some(1000));
        assert_eq!(config.gid, Some(1000));
        assert_eq!(config.memory_limit_bytes, Some(512 * 1024 * 1024));
        assert_eq!(config.max_fds, Some(1024));
        assert_eq!(config.max_procs, Some(64));
        assert_eq!(config.cpu_time_limit, Some(300));
        assert_eq!(config.max_file_size, Some(1024 * 1024 * 1024));
        assert_eq!(config.core_size, Some(0)); // default: disabled
        assert!(config.has_settings());
    }

    #[test]
    fn test_isolation_config_core_size_override() {
        let mut env = HashMap::new();
        env.insert("APP_RLIMIT_CORE".into(), "1048576".into());
        let config = IsolationConfig::from_env(&env);
        assert_eq!(config.core_size, Some(1048576));
    }

    #[test]
    fn test_isolation_config_describe() {
        let config = IsolationConfig {
            uid: Some(1000),
            gid: Some(1000),
            memory_limit_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1024),
            core_size: Some(0),
            ..Default::default()
        };
        let desc = config.describe();
        assert!(desc.iter().any(|d| d.contains("UID: 1000")));
        assert!(desc.iter().any(|d| d.contains("GID: 1000")));
        assert!(desc.iter().any(|d| d.contains("Memory limit: 512 MB")));
        assert!(desc.iter().any(|d| d.contains("Max FDs: 1024")));
        assert!(desc.iter().any(|d| d.contains("Core dumps: disabled")));
    }

    #[test]
    fn test_get_current_limits() {
        let limits = get_current_limits();
        // Should have entries for the 6 resource types we query.
        assert!(!limits.is_empty());
        // Each entry should have (name, soft, hard).
        for (name, soft, _hard) in &limits {
            assert!(!name.is_empty());
            // Soft limit should be non-negative (it's u64, so always >= 0).
            let _ = soft; // just verify it's accessible
        }
    }

    #[test]
    fn test_isolation_config_from_empty_env() {
        let env = HashMap::new();
        let config = IsolationConfig::from_env(&env);
        assert!(config.uid.is_none());
        assert!(config.gid.is_none());
        assert!(config.memory_limit_bytes.is_none());
        // Core is always set to 0 by default.
        assert_eq!(config.core_size, Some(0));
    }

    #[test]
    fn test_rlimit_name() {
        assert_eq!(rlimit_name(libc::RLIMIT_AS), "RLIMIT_AS");
        assert_eq!(rlimit_name(libc::RLIMIT_NOFILE), "RLIMIT_NOFILE");
        assert_eq!(rlimit_name(libc::RLIMIT_NPROC), "RLIMIT_NPROC");
        assert_eq!(rlimit_name(libc::RLIMIT_CPU), "RLIMIT_CPU");
        assert_eq!(rlimit_name(libc::RLIMIT_FSIZE), "RLIMIT_FSIZE");
        assert_eq!(rlimit_name(libc::RLIMIT_CORE), "RLIMIT_CORE");
        assert_eq!(rlimit_name(999), "RLIMIT_UNKNOWN");
    }

    // --- Network policy tests ---

    #[test]
    fn test_network_policy_default() {
        let policy = NetworkPolicy::default();
        assert!(!policy.enabled);
        assert_eq!(policy.app_port, 0);
        assert_eq!(policy.allowed_outbound_ports, vec![80, 443]);
        assert!(policy.allowed_outbound_destinations.is_empty());
        assert!(policy.allow_dns);
        assert!(policy.allow_loopback);
        assert!(policy.blocked_loopback_ports.is_empty());
    }

    #[test]
    fn test_network_policy_from_env() {
        let mut env = HashMap::new();
        env.insert("APP_NET_ISOLATE".into(), "true".into());
        env.insert("APP_PORT".into(), "8080".into());
        env.insert("APP_NET_ALLOW_PORTS".into(), "80,443,8443".into());
        env.insert("APP_NET_ALLOW_DEST".into(), "10.0.1.5:3306,10.0.1.6:6379".into());
        env.insert("APP_NET_ALLOW_DNS".into(), "true".into());
        env.insert("APP_NET_ALLOW_LOOPBACK".into(), "false".into());
        env.insert("APP_NET_BLOCK_PORTS".into(), "8081,8082".into());

        let policy = NetworkPolicy::from_env(&env);
        assert!(policy.enabled);
        assert_eq!(policy.app_port, 8080);
        assert_eq!(policy.allowed_outbound_ports, vec![80, 443, 8443]);
        assert_eq!(
            policy.allowed_outbound_destinations,
            vec!["10.0.1.5:3306", "10.0.1.6:6379"]
        );
        assert!(policy.allow_dns);
        assert!(!policy.allow_loopback);
        assert_eq!(policy.blocked_loopback_ports, vec![8081, 8082]);
    }

    #[test]
    fn test_network_policy_from_env_disabled() {
        let env = HashMap::new();
        let policy = NetworkPolicy::from_env(&env);
        assert!(!policy.enabled);
    }

    #[test]
    fn test_network_policy_enable_values() {
        for val in &["1", "true", "yes"] {
            let mut env = HashMap::new();
            env.insert("APP_NET_ISOLATE".into(), val.to_string());
            assert!(NetworkPolicy::from_env(&env).enabled, "should enable for {}", val);
        }
        for val in &["0", "false", "no", ""] {
            let mut env = HashMap::new();
            env.insert("APP_NET_ISOLATE".into(), val.to_string());
            assert!(!NetworkPolicy::from_env(&env).enabled, "should not enable for '{}'", val);
        }
    }

    #[test]
    fn test_network_policy_iptables_rules_disabled() {
        let policy = NetworkPolicy::default();
        assert!(policy.generate_iptables_rules(1000).is_empty());
        assert!(policy.generate_iptables_cleanup(1000).is_empty());
    }

    #[test]
    fn test_network_policy_iptables_rules_enabled() {
        let policy = NetworkPolicy {
            enabled: true,
            app_port: 8080,
            allowed_outbound_ports: vec![80, 443],
            allowed_outbound_destinations: vec!["10.0.1.5:3306".into()],
            allow_dns: true,
            allow_loopback: true,
            blocked_loopback_ports: vec![8081],
        };
        let rules = policy.generate_iptables_rules(1000);

        // Should create a chain.
        assert!(rules.iter().any(|r| r.contains("-N PHPRS_APP_1000")));
        // Should allow established connections.
        assert!(rules.iter().any(|r| r.contains("ESTABLISHED,RELATED")));
        // Should allow app port.
        assert!(rules.iter().any(|r| r.contains("--sport 8080")));
        // Should allow DNS.
        assert!(rules.iter().any(|r| r.contains("--dport 53")));
        // Should block specific loopback port.
        assert!(rules.iter().any(|r| r.contains("127.0.0.0/8") && r.contains("--dport 8081") && r.contains("DROP")));
        // Should allow loopback.
        assert!(rules.iter().any(|r| r.contains("127.0.0.0/8") && r.contains("ACCEPT") && !r.contains("--dport")));
        // Should allow backing service destination.
        assert!(rules.iter().any(|r| r.contains("10.0.1.5") && r.contains("--dport 3306")));
        // Should allow HTTP/HTTPS.
        assert!(rules.iter().any(|r| r.contains("--dport 80") && r.contains("ACCEPT")));
        assert!(rules.iter().any(|r| r.contains("--dport 443") && r.contains("ACCEPT")));
        // Should have default DROP.
        assert!(rules.iter().any(|r| r == "-A PHPRS_APP_1000 -j DROP"));
        // Should hook into OUTPUT chain.
        assert!(rules.iter().any(|r| r.contains("OUTPUT") && r.contains("--uid-owner 1000")));
    }

    #[test]
    fn test_network_policy_iptables_cleanup() {
        let policy = NetworkPolicy {
            enabled: true,
            ..Default::default()
        };
        let rules = policy.generate_iptables_cleanup(1000);
        assert_eq!(rules.len(), 3);
        // Should remove OUTPUT jump, flush chain, delete chain.
        assert!(rules[0].contains("-D OUTPUT"));
        assert!(rules[1].contains("-F PHPRS_APP_1000"));
        assert!(rules[2].contains("-X PHPRS_APP_1000"));
    }

    #[test]
    fn test_network_policy_no_loopback() {
        let policy = NetworkPolicy {
            enabled: true,
            app_port: 8080,
            allow_loopback: false,
            ..Default::default()
        };
        let rules = policy.generate_iptables_rules(1000);
        // Should NOT have loopback ACCEPT rule.
        assert!(!rules.iter().any(|r| r.contains("127.0.0.0/8") && r.contains("ACCEPT")));
    }

    #[test]
    fn test_network_policy_no_dns() {
        let policy = NetworkPolicy {
            enabled: true,
            app_port: 8080,
            allow_dns: false,
            ..Default::default()
        };
        let rules = policy.generate_iptables_rules(1000);
        // Should NOT have DNS rules.
        assert!(!rules.iter().any(|r| r.contains("--dport 53")));
    }

    #[test]
    fn test_network_policy_describe_disabled() {
        let policy = NetworkPolicy::default();
        let desc = policy.describe();
        assert_eq!(desc.len(), 1);
        assert!(desc[0].contains("disabled"));
    }

    #[test]
    fn test_network_policy_describe_enabled() {
        let policy = NetworkPolicy {
            enabled: true,
            app_port: 8080,
            allowed_outbound_ports: vec![80, 443],
            allowed_outbound_destinations: vec!["10.0.1.5:3306".into()],
            allow_dns: true,
            allow_loopback: true,
            blocked_loopback_ports: vec![8081],
        };
        let desc = policy.describe();
        assert!(desc.iter().any(|d| d.contains("enabled")));
        assert!(desc.iter().any(|d| d.contains("8080")));
        assert!(desc.iter().any(|d| d.contains("[80, 443]")));
        assert!(desc.iter().any(|d| d.contains("10.0.1.5:3306")));
        assert!(desc.iter().any(|d| d.contains("DNS: allowed")));
        assert!(desc.iter().any(|d| d.contains("Loopback: allowed")));
        assert!(desc.iter().any(|d| d.contains("[8081]")));
    }

    #[test]
    fn test_isolation_config_with_network() {
        let mut env = HashMap::new();
        env.insert("APP_UID".into(), "1000".into());
        env.insert("APP_NET_ISOLATE".into(), "1".into());
        env.insert("APP_PORT".into(), "8080".into());

        let config = IsolationConfig::from_env(&env);
        assert!(config.has_settings());
        assert!(config.network.enabled);
        assert_eq!(config.network.app_port, 8080);
    }

    #[test]
    fn test_disk_quota_from_env() {
        let mut env = HashMap::new();
        env.insert("APP_DISK_QUOTA".into(), "1G".into());
        let config = IsolationConfig::from_env(&env);
        assert_eq!(config.disk_quota, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn test_disk_quota_in_describe() {
        let config = IsolationConfig {
            disk_quota: Some(512 * 1024 * 1024),
            ..Default::default()
        };
        let desc = config.describe();
        assert!(desc.iter().any(|d| d.contains("Disk quota: 512 MB")));
    }

    #[test]
    fn test_dir_size() {
        let dir = std::env::temp_dir().join(format!("phprs-dir-size-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        std::fs::write(dir.join("b.txt"), "world!").unwrap();

        let size = dir_size(&dir);
        assert_eq!(size, 11); // 5 + 6 bytes

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_disk_quota_under() {
        let dir = std::env::temp_dir().join(format!("phprs-quota-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("test.txt"), "data").unwrap();

        let (current, quota, over) = check_disk_quota(&dir, 1024 * 1024);
        assert_eq!(current, 4);
        assert_eq!(quota, 1024 * 1024);
        assert!(!over);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_disk_quota_over() {
        let dir = std::env::temp_dir().join(format!("phprs-quota-over-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("big.txt"), "a".repeat(100)).unwrap();

        let (_, _, over) = check_disk_quota(&dir, 50); // 50 byte quota
        assert!(over);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_isolation_config_network_in_describe() {
        let config = IsolationConfig {
            uid: Some(1000),
            network: NetworkPolicy {
                enabled: true,
                app_port: 8080,
                ..Default::default()
            },
            ..Default::default()
        };
        let desc = config.describe();
        assert!(desc.iter().any(|d| d.contains("Network isolation: enabled")));
    }
}
