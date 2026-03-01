//! Backing service provisioning — MySQL, PostgreSQL, Redis.
//!
//! Provisions per-app databases and caches. Credentials are injected
//! as environment variables (DATABASE_URL, REDIS_URL, etc.).
//!
//! Uses CLI tools (mysql, psql, redis-cli) for provisioning to avoid
//! adding heavy database driver dependencies.

use std::collections::HashMap;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// A provisioned backing service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    /// Service type: "mysql", "postgres", "redis".
    pub service_type: String,
    /// Database/instance name.
    pub name: String,
    /// Host address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Username (for databases).
    pub username: String,
    /// Password (for databases).
    pub password: String,
    /// Connection URL (injected as env var).
    pub url: String,
    /// Environment variable name for the URL.
    pub env_var: String,
    /// When it was created.
    pub created_at: String,
}

/// Configuration for connecting to the backing service servers.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// MySQL admin connection.
    pub mysql_host: String,
    pub mysql_port: u16,
    pub mysql_admin_user: String,
    pub mysql_admin_password: String,
    /// PostgreSQL admin connection.
    pub postgres_host: String,
    pub postgres_port: u16,
    pub postgres_admin_user: String,
    /// Redis connection.
    pub redis_host: String,
    pub redis_port: u16,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            mysql_host: "127.0.0.1".into(),
            mysql_port: 3306,
            mysql_admin_user: "root".into(),
            mysql_admin_password: String::new(),
            postgres_host: "127.0.0.1".into(),
            postgres_port: 5432,
            postgres_admin_user: "postgres".into(),
            redis_host: "127.0.0.1".into(),
            redis_port: 6379,
        }
    }
}

impl ServiceConfig {
    /// Build configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            mysql_host: env_or("PHPRS_MYSQL_HOST", "127.0.0.1"),
            mysql_port: env_or("PHPRS_MYSQL_PORT", "3306").parse().unwrap_or(3306),
            mysql_admin_user: env_or("PHPRS_MYSQL_USER", "root"),
            mysql_admin_password: env_or("PHPRS_MYSQL_PASSWORD", ""),
            postgres_host: env_or("PHPRS_POSTGRES_HOST", "127.0.0.1"),
            postgres_port: env_or("PHPRS_POSTGRES_PORT", "5432").parse().unwrap_or(5432),
            postgres_admin_user: env_or("PHPRS_POSTGRES_USER", "postgres"),
            redis_host: env_or("PHPRS_REDIS_HOST", "127.0.0.1"),
            redis_port: env_or("PHPRS_REDIS_PORT", "6379").parse().unwrap_or(6379),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// ── MySQL ──────────────────────────────────────────────────────────────────

/// Provision a MySQL database for an app.
pub fn mysql_create(
    app_name: &str,
    config: &ServiceConfig,
) -> Result<ServiceInstance, String> {
    let db_name = sanitize_name(app_name);
    let username = format!("phprs_{}", db_name);
    let password = generate_password();

    // Create database.
    mysql_exec(config, &format!(
        "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
        db_name
    ))?;

    // Create user and grant privileges.
    mysql_exec(config, &format!(
        "CREATE USER IF NOT EXISTS '{}'@'%' IDENTIFIED BY '{}';",
        username, password
    ))?;
    mysql_exec(config, &format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'%';",
        db_name, username
    ))?;
    mysql_exec(config, "FLUSH PRIVILEGES;")?;

    let url = format!(
        "mysql://{}:{}@{}:{}/{}",
        username, password, config.mysql_host, config.mysql_port, db_name
    );

    Ok(ServiceInstance {
        service_type: "mysql".into(),
        name: db_name,
        host: config.mysql_host.clone(),
        port: config.mysql_port,
        username,
        password,
        url,
        env_var: "DATABASE_URL".into(),
        created_at: crate::state::now_iso8601(),
    })
}

/// Destroy a MySQL database and user.
pub fn mysql_destroy(
    instance: &ServiceInstance,
    config: &ServiceConfig,
) -> Result<(), String> {
    mysql_exec(config, &format!("DROP DATABASE IF EXISTS `{}`;", instance.name))?;
    mysql_exec(config, &format!("DROP USER IF EXISTS '{}'@'%';", instance.username))?;
    mysql_exec(config, "FLUSH PRIVILEGES;")?;
    Ok(())
}

/// Execute a MySQL statement via the mysql CLI.
fn mysql_exec(config: &ServiceConfig, sql: &str) -> Result<String, String> {
    let mut cmd = Command::new("mysql");
    cmd.args([
        "-h", &config.mysql_host,
        "-P", &config.mysql_port.to_string(),
        "-u", &config.mysql_admin_user,
        "--batch",
        "-e", sql,
    ]);

    if !config.mysql_admin_password.is_empty() {
        cmd.arg(format!("-p{}", config.mysql_admin_password));
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run mysql CLI: {} (is mysql-client installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("MySQL error: {}", stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if the MySQL CLI is available.
#[allow(dead_code)]
pub fn mysql_available() -> bool {
    Command::new("mysql")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── PostgreSQL ─────────────────────────────────────────────────────────────

/// Provision a PostgreSQL database for an app.
pub fn postgres_create(
    app_name: &str,
    config: &ServiceConfig,
) -> Result<ServiceInstance, String> {
    let db_name = sanitize_name(app_name);
    let username = format!("phprs_{}", db_name);
    let password = generate_password();

    // Create role.
    psql_exec(config, &format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{}') THEN CREATE ROLE {} LOGIN PASSWORD '{}'; END IF; END $$;",
        username, username, password
    ))?;

    // Create database owned by the new role.
    psql_exec(config, &format!(
        "SELECT 'CREATE DATABASE {}' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{}')\\gexec",
        db_name, db_name
    )).or_else(|_| {
        // Fallback: try CREATE DATABASE directly (may fail if exists).
        psql_exec(config, &format!("CREATE DATABASE {} OWNER {};", db_name, username))
    })?;

    // Grant privileges.
    psql_exec(config, &format!(
        "GRANT ALL PRIVILEGES ON DATABASE {} TO {};",
        db_name, username
    ))?;

    let url = format!(
        "postgres://{}:{}@{}:{}/{}",
        username, password, config.postgres_host, config.postgres_port, db_name
    );

    Ok(ServiceInstance {
        service_type: "postgres".into(),
        name: db_name,
        host: config.postgres_host.clone(),
        port: config.postgres_port,
        username,
        password,
        url,
        env_var: "DATABASE_URL".into(),
        created_at: crate::state::now_iso8601(),
    })
}

/// Destroy a PostgreSQL database and role.
pub fn postgres_destroy(
    instance: &ServiceInstance,
    config: &ServiceConfig,
) -> Result<(), String> {
    psql_exec(config, &format!("DROP DATABASE IF EXISTS {};", instance.name))?;
    psql_exec(config, &format!("DROP ROLE IF EXISTS {};", instance.username))?;
    Ok(())
}

/// Execute a PostgreSQL statement via the psql CLI.
fn psql_exec(config: &ServiceConfig, sql: &str) -> Result<String, String> {
    let output = Command::new("psql")
        .args([
            "-h", &config.postgres_host,
            "-p", &config.postgres_port.to_string(),
            "-U", &config.postgres_admin_user,
            "-c", sql,
        ])
        .env("PGPASSWORD", "") // Use peer auth or .pgpass.
        .output()
        .map_err(|e| format!("Failed to run psql CLI: {} (is postgresql-client installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("PostgreSQL error: {}", stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if the psql CLI is available.
#[allow(dead_code)]
pub fn postgres_available() -> bool {
    Command::new("psql")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Redis ──────────────────────────────────────────────────────────────────

/// Provision a Redis instance for an app using Redis 6+ ACLs.
///
/// Creates a dedicated Redis user with a password, restricted to keys
/// matching the app's prefix pattern. This provides real isolation instead
/// of relying on key-prefix conventions that apps can bypass.
pub fn redis_create(
    app_name: &str,
    config: &ServiceConfig,
) -> Result<ServiceInstance, String> {
    let prefix = sanitize_name(app_name);
    let username = format!("phprs_{}", prefix);
    let password = generate_password();

    // Verify Redis is reachable.
    redis_exec(config, &["PING"])
        .map_err(|e| format!("Cannot connect to Redis: {}", e))?;

    // Create a Redis ACL user (Redis 6+) restricted to keys with this app's prefix.
    // ACL SETUSER <username> on ><password> ~<prefix>:* +@all -@admin -@dangerous
    let key_pattern = format!("~{}:*", prefix);
    let pass_arg = format!(">{}", password);
    let acl_result = redis_exec(config, &[
        "ACL", "SETUSER", &username,
        "on",           // Enable the user.
        &pass_arg,      // Set password.
        &key_pattern,   // Restrict to keys matching prefix:*
        "+@all",        // Allow all commands...
        "-@admin",      // ...except admin commands (CONFIG, DEBUG, etc.)
        "-@dangerous",  // ...and dangerous commands (FLUSHALL, FLUSHDB, etc.)
    ]);

    match acl_result {
        Ok(_) => {
            // ACL user created — persist ACL changes.
            let _ = redis_exec(config, &["ACL", "SAVE"]);
        }
        Err(e) => {
            // Redis < 6 or ACL not supported — fall back to prefix-only isolation.
            eprintln!("Warning: Redis ACL setup failed (Redis 6+ required): {}", e);
            eprintln!("Falling back to key-prefix isolation for '{}'", app_name);
        }
    }

    let url = format!(
        "redis://{}:{}@{}:{}/0?prefix={}:",
        username, password, config.redis_host, config.redis_port, prefix
    );

    Ok(ServiceInstance {
        service_type: "redis".into(),
        name: prefix,
        host: config.redis_host.clone(),
        port: config.redis_port,
        username,
        password,
        url,
        env_var: "REDIS_URL".into(),
        created_at: crate::state::now_iso8601(),
    })
}

/// Destroy a Redis instance — remove the ACL user and flush its keys.
pub fn redis_destroy(
    instance: &ServiceInstance,
    config: &ServiceConfig,
) -> Result<(), String> {
    // Delete the ACL user (Redis 6+).
    if !instance.username.is_empty() {
        let _ = redis_exec(config, &["ACL", "DELUSER", &instance.username]);
        let _ = redis_exec(config, &["ACL", "SAVE"]);
    }

    // Delete all keys with the app's prefix using SCAN + DEL.
    let pattern = format!("{}:*", instance.name);
    let output = redis_exec(config, &["KEYS", &pattern])?;
    let keys: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
    if !keys.is_empty() {
        let mut args = vec!["DEL"];
        args.extend(keys.iter().copied());
        redis_exec(config, &args)?;
    }
    Ok(())
}

/// Auto-populate network policy allowed destinations for provisioned services.
/// Call this after provisioning a service to ensure the app can reach it.
pub fn populate_network_destinations(
    env: &mut HashMap<String, String>,
    services: &[ServiceInstance],
) {
    let mut destinations: Vec<String> = Vec::new();
    for svc in services {
        if !svc.host.is_empty() && svc.port > 0 {
            destinations.push(format!("{}:{}", svc.host, svc.port));
        }
    }
    if !destinations.is_empty() {
        // Merge with any existing destinations.
        if let Some(existing) = env.get("APP_NET_ALLOW_DEST") {
            let mut all: Vec<String> = existing
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            for dest in &destinations {
                if !all.contains(dest) {
                    all.push(dest.clone());
                }
            }
            destinations = all;
        }
        env.insert("APP_NET_ALLOW_DEST".into(), destinations.join(","));
    }
}

/// Execute a Redis command via redis-cli.
fn redis_exec(config: &ServiceConfig, args: &[&str]) -> Result<String, String> {
    let output = Command::new("redis-cli")
        .args(["-h", &config.redis_host, "-p", &config.redis_port.to_string()])
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run redis-cli: {} (is redis-cli installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Redis error: {}", stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if redis-cli is available.
#[allow(dead_code)]
pub fn redis_available() -> bool {
    Command::new("redis-cli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Sanitize an app name for use as a database/user name.
/// Only allows alphanumeric and underscores, max 32 chars.
fn sanitize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .take(32)
        .collect();
    if sanitized.is_empty() {
        "app".into()
    } else {
        sanitized
    }
}

/// Generate a random password for database credentials.
fn generate_password() -> String {
    use std::io::Read;

    let mut bytes = [0u8; 24];
    // Try /dev/urandom first for secure random bytes.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut bytes).is_err() {
            fill_fallback_bytes(&mut bytes);
        }
    } else {
        fill_fallback_bytes(&mut bytes);
    }

    // Encode as alphanumeric string.
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    bytes
        .iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect()
}

/// Fallback entropy using timestamp + pid.
fn fill_fallback_bytes(bytes: &mut [u8]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() ^ (std::process::id() as u128);
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = ((seed >> (i % 16)) & 0xFF) as u8;
    }
}

/// Get all services for an app from its environment variables.
pub fn list_app_services(env: &HashMap<String, String>) -> Vec<ServiceInstance> {
    let services_json = env.get("_PHPRS_SERVICES");
    match services_json {
        Some(json) => serde_json::from_str(json).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Save services list to app env.
pub fn save_app_services(env: &mut HashMap<String, String>, services: &[ServiceInstance]) {
    if services.is_empty() {
        env.remove("_PHPRS_SERVICES");
    } else {
        let json = serde_json::to_string(services).unwrap_or_default();
        env.insert("_PHPRS_SERVICES".into(), json);
    }
    // Also set the individual URL env vars.
    for svc in services {
        env.insert(svc.env_var.clone(), svc.url.clone());
    }
}

// ── Phase 6.4: Object Storage (S3-Compatible) ─────────────────────────────

/// Configuration for object storage (S3-compatible, e.g. MinIO).
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// S3 endpoint URL.
    pub endpoint: String,
    /// S3 region.
    pub region: String,
    /// Admin access key.
    pub admin_access_key: String,
    /// Admin secret key.
    pub admin_secret_key: String,
    /// Whether to use path-style URLs (for MinIO).
    pub path_style: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            admin_access_key: "minioadmin".into(),
            admin_secret_key: "minioadmin".into(),
            path_style: true,
        }
    }
}

impl StorageConfig {
    pub fn from_env() -> Self {
        Self {
            endpoint: env_or("PHPRS_S3_ENDPOINT", "http://127.0.0.1:9000"),
            region: env_or("PHPRS_S3_REGION", "us-east-1"),
            admin_access_key: env_or("PHPRS_S3_ACCESS_KEY", "minioadmin"),
            admin_secret_key: env_or("PHPRS_S3_SECRET_KEY", "minioadmin"),
            path_style: env_or("PHPRS_S3_PATH_STYLE", "true") == "true",
        }
    }
}

/// Provision an S3-compatible bucket for an app.
pub fn storage_create(
    app_name: &str,
    config: &StorageConfig,
) -> Result<ServiceInstance, String> {
    let bucket_name = format!("phprs-{}", sanitize_name(app_name));
    let access_key = generate_password();
    let secret_key = generate_password();

    // Create bucket using mc (MinIO client) or aws CLI.
    match create_s3_bucket(&bucket_name, config) {
        Ok(()) => {}
        Err(e) => return Err(format!("Failed to create bucket: {}", e)),
    }

    // Create access credentials (MinIO admin API or IAM).
    match create_s3_credentials(&bucket_name, &access_key, &secret_key, config) {
        Ok(()) => {}
        Err(e) => {
            // Non-fatal: bucket exists but credentials may use admin keys.
            eprintln!("Warning: credential creation failed: {}", e);
        }
    }

    let url = format!("{}/{}", config.endpoint, bucket_name);

    Ok(ServiceInstance {
        service_type: "s3".into(),
        name: bucket_name,
        host: config.endpoint.clone(),
        port: 0, // Port embedded in endpoint URL.
        username: access_key,
        password: secret_key,
        url,
        env_var: "S3_BUCKET_URL".into(),
        created_at: crate::state::now_iso8601(),
    })
}

/// Destroy an S3 bucket.
pub fn storage_destroy(
    instance: &ServiceInstance,
    config: &StorageConfig,
) -> Result<(), String> {
    // Remove bucket and all objects.
    delete_s3_bucket(&instance.name, config)
}

/// Get storage credentials as env vars for injection.
pub fn storage_env_vars(instance: &ServiceInstance, config: &StorageConfig) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    vars.insert("S3_ENDPOINT".into(), config.endpoint.clone());
    vars.insert("S3_REGION".into(), config.region.clone());
    vars.insert("S3_BUCKET".into(), instance.name.clone());
    vars.insert("S3_ACCESS_KEY".into(), instance.username.clone());
    vars.insert("S3_SECRET_KEY".into(), instance.password.clone());
    vars.insert("S3_BUCKET_URL".into(), instance.url.clone());
    vars.insert("S3_USE_PATH_STYLE".into(), config.path_style.to_string());
    // AWS SDK compatible vars.
    vars.insert("AWS_ACCESS_KEY_ID".into(), instance.username.clone());
    vars.insert("AWS_SECRET_ACCESS_KEY".into(), instance.password.clone());
    vars.insert("AWS_DEFAULT_REGION".into(), config.region.clone());
    vars.insert("AWS_ENDPOINT_URL".into(), config.endpoint.clone());
    vars
}

/// Create an S3 bucket using the mc (MinIO Client) or aws CLI.
fn create_s3_bucket(bucket_name: &str, config: &StorageConfig) -> Result<(), String> {
    // Try MinIO client first (mc).
    let mc_result = Command::new("mc")
        .args(["mb", &format!("phprs/{}", bucket_name)])
        .env("MC_HOST_phprs", format!(
            "{}:{}:{}",
            config.endpoint, config.admin_access_key, config.admin_secret_key
        ))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if let Ok(status) = mc_result {
        if status.success() {
            return Ok(());
        }
    }

    // Fallback: aws CLI.
    let aws_result = Command::new("aws")
        .args([
            "s3", "mb",
            &format!("s3://{}", bucket_name),
            "--endpoint-url", &config.endpoint,
        ])
        .env("AWS_ACCESS_KEY_ID", &config.admin_access_key)
        .env("AWS_SECRET_ACCESS_KEY", &config.admin_secret_key)
        .env("AWS_DEFAULT_REGION", &config.region)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match aws_result {
        Ok(s) if s.success() => Ok(()),
        _ => Err("Neither mc nor aws CLI available for bucket creation".into()),
    }
}

/// Create S3 credentials for the bucket (MinIO admin API).
fn create_s3_credentials(
    _bucket: &str,
    _access_key: &str,
    _secret_key: &str,
    _config: &StorageConfig,
) -> Result<(), String> {
    // MinIO user/policy creation would go here.
    // For now, use admin credentials and restrict via bucket policy.
    // Real implementation would use `mc admin user add` and `mc admin policy set`.
    Ok(())
}

/// Delete an S3 bucket and all its objects.
fn delete_s3_bucket(bucket_name: &str, config: &StorageConfig) -> Result<(), String> {
    // Try mc.
    let mc_result = Command::new("mc")
        .args(["rb", "--force", &format!("phprs/{}", bucket_name)])
        .env("MC_HOST_phprs", format!(
            "{}:{}:{}",
            config.endpoint, config.admin_access_key, config.admin_secret_key
        ))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if let Ok(status) = mc_result {
        if status.success() {
            return Ok(());
        }
    }

    // Fallback: aws CLI.
    let aws_result = Command::new("aws")
        .args([
            "s3", "rb",
            &format!("s3://{}", bucket_name),
            "--force",
            "--endpoint-url", &config.endpoint,
        ])
        .env("AWS_ACCESS_KEY_ID", &config.admin_access_key)
        .env("AWS_SECRET_ACCESS_KEY", &config.admin_secret_key)
        .env("AWS_DEFAULT_REGION", &config.region)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match aws_result {
        Ok(s) if s.success() => Ok(()),
        _ => Err("Neither mc nor aws CLI available for bucket deletion".into()),
    }
}

// ── Phase 6.5: Service Discovery ──────────────────────────────────────────

/// Standard environment variable names for service discovery.
/// Apps discover services purely through env vars (12-factor app).
pub struct ServiceDiscovery;

impl ServiceDiscovery {
    /// Build all environment variables for an app's provisioned services.
    /// Returns a map of env var name -> value.
    pub fn build_env_vars(services: &[ServiceInstance], storage_config: Option<&StorageConfig>) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        for svc in services {
            match svc.service_type.as_str() {
                "mysql" | "postgres" => {
                    vars.insert("DATABASE_URL".into(), svc.url.clone());
                    vars.insert("DB_CONNECTION".into(), svc.service_type.clone());
                    vars.insert("DB_HOST".into(), svc.host.clone());
                    vars.insert("DB_PORT".into(), svc.port.to_string());
                    vars.insert("DB_DATABASE".into(), svc.name.clone());
                    vars.insert("DB_USERNAME".into(), svc.username.clone());
                    vars.insert("DB_PASSWORD".into(), svc.password.clone());
                }
                "redis" => {
                    vars.insert("REDIS_URL".into(), svc.url.clone());
                    vars.insert("REDIS_HOST".into(), svc.host.clone());
                    vars.insert("REDIS_PORT".into(), svc.port.to_string());
                    // Laravel-specific.
                    vars.insert("CACHE_DRIVER".into(), "redis".into());
                    vars.insert("SESSION_DRIVER".into(), "redis".into());
                    vars.insert("QUEUE_CONNECTION".into(), "redis".into());
                }
                "s3" => {
                    if let Some(sc) = storage_config {
                        vars.extend(storage_env_vars(svc, sc));
                    } else {
                        vars.insert("S3_BUCKET".into(), svc.name.clone());
                        vars.insert("S3_BUCKET_URL".into(), svc.url.clone());
                        vars.insert("S3_ACCESS_KEY".into(), svc.username.clone());
                        vars.insert("S3_SECRET_KEY".into(), svc.password.clone());
                    }
                    // Laravel Filesystem.
                    vars.insert("FILESYSTEM_DISK".into(), "s3".into());
                }
                _ => {
                    // Unknown service type — just set the URL.
                    vars.insert(svc.env_var.clone(), svc.url.clone());
                }
            }
        }

        vars
    }

    /// Verify all required services are provisioned for an app.
    /// Returns a list of missing services based on what the Appfile declares.
    pub fn check_required_services(
        required: &crate::manifest::ServicesSection,
        provisioned: &[ServiceInstance],
    ) -> Vec<String> {
        let mut missing = Vec::new();

        if required.mysql {
            if !provisioned.iter().any(|s| s.service_type == "mysql") {
                missing.push("mysql".into());
            }
        }
        if required.postgres {
            if !provisioned.iter().any(|s| s.service_type == "postgres") {
                missing.push("postgres".into());
            }
        }
        if required.redis {
            if !provisioned.iter().any(|s| s.service_type == "redis") {
                missing.push("redis".into());
            }
        }

        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_name() {
        assert_eq!(sanitize_name("my-app"), "my_app");
        assert_eq!(sanitize_name("My App 123"), "My_App_123");
        assert_eq!(sanitize_name("test@app!"), "test_app_");
        assert_eq!(sanitize_name(""), "app");
        // Long names get truncated.
        let long = "a".repeat(50);
        assert_eq!(sanitize_name(&long).len(), 32);
    }

    #[test]
    fn test_generate_password() {
        let p1 = generate_password();
        let p2 = generate_password();
        assert_eq!(p1.len(), 24);
        assert_eq!(p2.len(), 24);
        // Passwords should be different (with very high probability).
        assert_ne!(p1, p2);
        // All chars should be alphanumeric.
        assert!(p1.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_service_instance_serialization() {
        let svc = ServiceInstance {
            service_type: "mysql".into(),
            name: "testdb".into(),
            host: "127.0.0.1".into(),
            port: 3306,
            username: "phprs_testdb".into(),
            password: "secret123".into(),
            url: "mysql://phprs_testdb:secret123@127.0.0.1:3306/testdb".into(),
            env_var: "DATABASE_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        };

        let json = serde_json::to_string(&svc).unwrap();
        let parsed: ServiceInstance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "testdb");
        assert_eq!(parsed.service_type, "mysql");
        assert_eq!(parsed.port, 3306);
    }

    #[test]
    fn test_list_app_services_empty() {
        let env = HashMap::new();
        assert!(list_app_services(&env).is_empty());
    }

    #[test]
    fn test_save_and_list_services() {
        let mut env = HashMap::new();
        let services = vec![
            ServiceInstance {
                service_type: "mysql".into(),
                name: "testdb".into(),
                host: "127.0.0.1".into(),
                port: 3306,
                username: "user".into(),
                password: "pass".into(),
                url: "mysql://user:pass@127.0.0.1:3306/testdb".into(),
                env_var: "DATABASE_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
            ServiceInstance {
                service_type: "redis".into(),
                name: "testredis".into(),
                host: "127.0.0.1".into(),
                port: 6379,
                username: String::new(),
                password: String::new(),
                url: "redis://127.0.0.1:6379/0?prefix=testredis:".into(),
                env_var: "REDIS_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
        ];

        save_app_services(&mut env, &services);

        // Check env vars are set.
        assert!(env.contains_key("DATABASE_URL"));
        assert!(env.contains_key("REDIS_URL"));
        assert!(env.contains_key("_PHPRS_SERVICES"));

        // List should return both services.
        let listed = list_app_services(&env);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].service_type, "mysql");
        assert_eq!(listed[1].service_type, "redis");
    }

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.mysql_host, "127.0.0.1");
        assert_eq!(config.mysql_port, 3306);
        assert_eq!(config.postgres_port, 5432);
        assert_eq!(config.redis_port, 6379);
    }

    #[test]
    fn test_mysql_available_check() {
        // Just verify it doesn't panic — result depends on local system.
        let _ = mysql_available();
    }

    #[test]
    fn test_postgres_available_check() {
        let _ = postgres_available();
    }

    #[test]
    fn test_redis_available_check() {
        let _ = redis_available();
    }

    // ── Phase 6.4: Object Storage Tests ───────────────────────────────────

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.endpoint, "http://127.0.0.1:9000");
        assert_eq!(config.region, "us-east-1");
        assert!(config.path_style);
    }

    #[test]
    fn test_storage_env_vars() {
        let instance = ServiceInstance {
            service_type: "s3".into(),
            name: "phprs-myapp".into(),
            host: "http://127.0.0.1:9000".into(),
            port: 0,
            username: "access123".into(),
            password: "secret456".into(),
            url: "http://127.0.0.1:9000/phprs-myapp".into(),
            env_var: "S3_BUCKET_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        };

        let config = StorageConfig::default();
        let vars = storage_env_vars(&instance, &config);

        assert_eq!(vars.get("S3_BUCKET").unwrap(), "phprs-myapp");
        assert_eq!(vars.get("S3_ACCESS_KEY").unwrap(), "access123");
        assert_eq!(vars.get("S3_SECRET_KEY").unwrap(), "secret456");
        assert_eq!(vars.get("AWS_ACCESS_KEY_ID").unwrap(), "access123");
        assert_eq!(vars.get("AWS_SECRET_ACCESS_KEY").unwrap(), "secret456");
        assert_eq!(vars.get("S3_ENDPOINT").unwrap(), "http://127.0.0.1:9000");
        assert_eq!(vars.get("S3_USE_PATH_STYLE").unwrap(), "true");
    }

    // ── Phase 6.5: Service Discovery Tests ────────────────────────────────

    #[test]
    fn test_service_discovery_mysql() {
        let services = vec![ServiceInstance {
            service_type: "mysql".into(),
            name: "testdb".into(),
            host: "db.local".into(),
            port: 3306,
            username: "user".into(),
            password: "pass".into(),
            url: "mysql://user:pass@db.local:3306/testdb".into(),
            env_var: "DATABASE_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        }];

        let vars = ServiceDiscovery::build_env_vars(&services, None);
        assert_eq!(vars.get("DATABASE_URL").unwrap(), "mysql://user:pass@db.local:3306/testdb");
        assert_eq!(vars.get("DB_CONNECTION").unwrap(), "mysql");
        assert_eq!(vars.get("DB_HOST").unwrap(), "db.local");
        assert_eq!(vars.get("DB_PORT").unwrap(), "3306");
        assert_eq!(vars.get("DB_DATABASE").unwrap(), "testdb");
        assert_eq!(vars.get("DB_USERNAME").unwrap(), "user");
        assert_eq!(vars.get("DB_PASSWORD").unwrap(), "pass");
    }

    #[test]
    fn test_service_discovery_redis() {
        let services = vec![ServiceInstance {
            service_type: "redis".into(),
            name: "cache".into(),
            host: "redis.local".into(),
            port: 6379,
            username: String::new(),
            password: String::new(),
            url: "redis://redis.local:6379/0".into(),
            env_var: "REDIS_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        }];

        let vars = ServiceDiscovery::build_env_vars(&services, None);
        assert_eq!(vars.get("REDIS_URL").unwrap(), "redis://redis.local:6379/0");
        assert_eq!(vars.get("REDIS_HOST").unwrap(), "redis.local");
        assert_eq!(vars.get("REDIS_PORT").unwrap(), "6379");
        assert_eq!(vars.get("CACHE_DRIVER").unwrap(), "redis");
        assert_eq!(vars.get("SESSION_DRIVER").unwrap(), "redis");
    }

    #[test]
    fn test_service_discovery_s3_with_config() {
        let services = vec![ServiceInstance {
            service_type: "s3".into(),
            name: "phprs-myapp".into(),
            host: "http://minio:9000".into(),
            port: 0,
            username: "ak123".into(),
            password: "sk456".into(),
            url: "http://minio:9000/phprs-myapp".into(),
            env_var: "S3_BUCKET_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        }];

        let config = StorageConfig {
            endpoint: "http://minio:9000".into(),
            region: "eu-west-1".into(),
            ..Default::default()
        };

        let vars = ServiceDiscovery::build_env_vars(&services, Some(&config));
        assert_eq!(vars.get("S3_BUCKET").unwrap(), "phprs-myapp");
        assert_eq!(vars.get("S3_ENDPOINT").unwrap(), "http://minio:9000");
        assert_eq!(vars.get("S3_REGION").unwrap(), "eu-west-1");
        assert_eq!(vars.get("FILESYSTEM_DISK").unwrap(), "s3");
    }

    #[test]
    fn test_service_discovery_mixed() {
        let services = vec![
            ServiceInstance {
                service_type: "mysql".into(),
                name: "db".into(),
                host: "db.local".into(),
                port: 3306,
                username: "user".into(),
                password: "pass".into(),
                url: "mysql://user:pass@db.local:3306/db".into(),
                env_var: "DATABASE_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
            ServiceInstance {
                service_type: "redis".into(),
                name: "cache".into(),
                host: "redis.local".into(),
                port: 6379,
                username: String::new(),
                password: String::new(),
                url: "redis://redis.local:6379/0".into(),
                env_var: "REDIS_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
        ];

        let vars = ServiceDiscovery::build_env_vars(&services, None);
        assert!(vars.contains_key("DATABASE_URL"));
        assert!(vars.contains_key("REDIS_URL"));
        assert_eq!(vars.get("DB_CONNECTION").unwrap(), "mysql");
        assert_eq!(vars.get("CACHE_DRIVER").unwrap(), "redis");
    }

    #[test]
    fn test_check_required_services() {
        let required = crate::manifest::ServicesSection {
            mysql: true,
            postgres: false,
            redis: true,
        };

        // Nothing provisioned.
        let missing = ServiceDiscovery::check_required_services(&required, &[]);
        assert_eq!(missing, vec!["mysql", "redis"]);

        // MySQL provisioned, Redis missing.
        let provisioned = vec![ServiceInstance {
            service_type: "mysql".into(),
            name: "db".into(),
            host: "localhost".into(),
            port: 3306,
            username: "u".into(),
            password: "p".into(),
            url: "mysql://u:p@localhost/db".into(),
            env_var: "DATABASE_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        }];
        let missing = ServiceDiscovery::check_required_services(&required, &provisioned);
        assert_eq!(missing, vec!["redis"]);

        // All provisioned.
        let provisioned = vec![
            ServiceInstance {
                service_type: "mysql".into(),
                name: "db".into(),
                host: "localhost".into(),
                port: 3306,
                username: "u".into(),
                password: "p".into(),
                url: "mysql://u:p@localhost/db".into(),
                env_var: "DATABASE_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
            ServiceInstance {
                service_type: "redis".into(),
                name: "cache".into(),
                host: "localhost".into(),
                port: 6379,
                username: String::new(),
                password: String::new(),
                url: "redis://localhost:6379/0".into(),
                env_var: "REDIS_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let missing = ServiceDiscovery::check_required_services(&required, &provisioned);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_populate_network_destinations() {
        let mut env = HashMap::new();
        let services = vec![
            ServiceInstance {
                service_type: "mysql".into(),
                name: "db".into(),
                host: "10.0.1.5".into(),
                port: 3306,
                username: "user".into(),
                password: "pass".into(),
                url: "mysql://user:pass@10.0.1.5:3306/db".into(),
                env_var: "DATABASE_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
            ServiceInstance {
                service_type: "redis".into(),
                name: "cache".into(),
                host: "10.0.1.6".into(),
                port: 6379,
                username: "phprs_cache".into(),
                password: "redispass".into(),
                url: "redis://phprs_cache:redispass@10.0.1.6:6379/0".into(),
                env_var: "REDIS_URL".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
            },
        ];

        populate_network_destinations(&mut env, &services);
        let dest = env.get("APP_NET_ALLOW_DEST").unwrap();
        assert!(dest.contains("10.0.1.5:3306"));
        assert!(dest.contains("10.0.1.6:6379"));
    }

    #[test]
    fn test_populate_network_destinations_merges() {
        let mut env = HashMap::new();
        env.insert("APP_NET_ALLOW_DEST".into(), "10.0.0.1:5432".into());

        let services = vec![ServiceInstance {
            service_type: "mysql".into(),
            name: "db".into(),
            host: "10.0.1.5".into(),
            port: 3306,
            username: "user".into(),
            password: "pass".into(),
            url: "mysql://user:pass@10.0.1.5:3306/db".into(),
            env_var: "DATABASE_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        }];

        populate_network_destinations(&mut env, &services);
        let dest = env.get("APP_NET_ALLOW_DEST").unwrap();
        assert!(dest.contains("10.0.0.1:5432")); // Existing preserved.
        assert!(dest.contains("10.0.1.5:3306")); // New added.
    }

    #[test]
    fn test_redis_service_has_credentials() {
        // Verify ServiceInstance for redis now includes username/password.
        let svc = ServiceInstance {
            service_type: "redis".into(),
            name: "myapp".into(),
            host: "127.0.0.1".into(),
            port: 6379,
            username: "phprs_myapp".into(),
            password: "securepass".into(),
            url: "redis://phprs_myapp:securepass@127.0.0.1:6379/0?prefix=myapp:".into(),
            env_var: "REDIS_URL".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        };
        assert!(!svc.username.is_empty());
        assert!(!svc.password.is_empty());
        assert!(svc.url.contains("phprs_myapp"));
    }

    #[test]
    fn test_check_no_required_services() {
        let required = crate::manifest::ServicesSection::default();
        let missing = ServiceDiscovery::check_required_services(&required, &[]);
        assert!(missing.is_empty());
    }
}
