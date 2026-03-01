//! Authentication & authorization for the PaaS.
//!
//! Users authenticate via:
//! - API token (Bearer header) — for CLI and programmatic access
//! - Session cookie — for the web dashboard
//!
//! User data and tokens stored in a JSON file at ~/.php-rs/users.json.
//!
//! Security features:
//! - bcrypt password hashing (cost=12)
//! - Cryptographically secure token generation via ring::rand::SystemRandom
//! - Legacy SHA-256 hash support with automatic upgrade on login
//! - IP-based rate limiting on login (token bucket, 10 attempts/minute)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// bcrypt cost factor (12 = ~250ms per hash on modern hardware).
const BCRYPT_COST: u32 = 12;

/// A registered user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u64,
    pub username: String,
    /// Bcrypt-hashed password (or legacy "sha256:salt:hash" format).
    pub password_hash: String,
    pub email: String,
    /// API tokens for this user.
    pub tokens: Vec<ApiToken>,
    /// Active sessions (cookie → expiry timestamp).
    #[serde(default)]
    pub sessions: HashMap<String, u64>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Whether this user is an admin.
    #[serde(default)]
    pub is_admin: bool,
}

/// An API token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    /// The token value (hex string).
    pub token: String,
    /// Human-readable name for this token.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Optional expiry timestamp (epoch seconds). None = never expires.
    pub expires_at: Option<u64>,
}

/// User database stored on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserStore {
    pub users: Vec<User>,
    pub next_id: u64,
}

impl Default for UserStore {
    fn default() -> Self {
        Self {
            users: vec![],
            next_id: 1,
        }
    }
}

impl UserStore {
    /// Load user store from disk.
    pub fn load() -> Self {
        Self::load_from(&users_file_path())
    }

    /// Load from a specific path.
    pub fn load_from(path: &Path) -> Self {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(json) => match serde_json::from_str(&json) {
                    Ok(store) => return store,
                    Err(e) => {
                        eprintln!("Warning: corrupt users file: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Warning: cannot read users file: {}", e);
                }
            }
        }
        Self::default()
    }

    /// Save to disk.
    pub fn save(&self) -> Result<(), String> {
        self.save_to(&users_file_path())
    }

    /// Save to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let dir = path
            .parent()
            .ok_or_else(|| "No parent directory".to_string())?;
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Cannot create directory: {}", e))?;

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Cannot serialize: {}", e))?;

        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| format!("Cannot write: {}", e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("Cannot rename: {}", e))?;

        Ok(())
    }

    /// Register a new user. Returns the user ID.
    pub fn register(
        &mut self,
        username: &str,
        password: &str,
        email: &str,
    ) -> Result<u64, String> {
        // Check for duplicate username.
        if self.users.iter().any(|u| u.username == username) {
            return Err(format!("Username '{}' already taken", username));
        }

        // Check for duplicate email.
        if self.users.iter().any(|u| u.email == email) {
            return Err(format!("Email '{}' already registered", email));
        }

        let password_hash = hash_password(password)?;
        let id = self.next_id;
        self.next_id += 1;

        let user = User {
            id,
            username: username.to_string(),
            password_hash,
            email: email.to_string(),
            tokens: vec![],
            sessions: HashMap::new(),
            created_at: crate::state::now_iso8601(),
            is_admin: self.users.is_empty(), // First user is admin.
        };

        self.users.push(user);
        Ok(id)
    }

    /// Authenticate with username + password. Returns user ID on success.
    /// Automatically upgrades legacy SHA-256 hashes to bcrypt.
    pub fn login(&mut self, username: &str, password: &str) -> Result<u64, String> {
        let user = self
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| "Invalid username or password".to_string())?;

        if verify_password(password, &user.password_hash)? {
            let user_id = user.id;

            // Auto-upgrade legacy SHA-256 hashes to bcrypt on successful login.
            if user.password_hash.starts_with("sha256:") {
                if let Ok(new_hash) = hash_password(password) {
                    if let Some(u) = self.users.iter_mut().find(|u| u.id == user_id) {
                        u.password_hash = new_hash;
                    }
                }
            }

            Ok(user_id)
        } else {
            Err("Invalid username or password".into())
        }
    }

    /// Create a new session for a user. Returns the session token.
    pub fn create_session(&mut self, user_id: u64, ttl_hours: u64) -> Result<String, String> {
        let user = self
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| "User not found".to_string())?;

        let token = generate_token();
        let expiry = epoch_secs() + (ttl_hours * 3600);
        user.sessions.insert(token.clone(), expiry);

        // Clean up expired sessions.
        let now = epoch_secs();
        user.sessions.retain(|_, &mut exp| exp > now);

        Ok(token)
    }

    /// Validate a session token. Returns user ID if valid.
    pub fn validate_session(&self, session_token: &str) -> Option<u64> {
        let now = epoch_secs();
        for user in &self.users {
            if let Some(&expiry) = user.sessions.get(session_token) {
                if expiry > now {
                    return Some(user.id);
                }
            }
        }
        None
    }

    /// Create a new API token for a user. Returns the token string.
    pub fn create_api_token(
        &mut self,
        user_id: u64,
        name: &str,
        expires_days: Option<u64>,
    ) -> Result<String, String> {
        let user = self
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| "User not found".to_string())?;

        let token = generate_token();
        let expires_at = expires_days.map(|d| epoch_secs() + (d * 86400));

        user.tokens.push(ApiToken {
            token: token.clone(),
            name: name.to_string(),
            created_at: crate::state::now_iso8601(),
            expires_at,
        });

        Ok(token)
    }

    /// Validate an API token. Returns user ID if valid.
    pub fn validate_token(&self, token: &str) -> Option<u64> {
        let now = epoch_secs();
        for user in &self.users {
            for t in &user.tokens {
                if t.token == token {
                    if let Some(exp) = t.expires_at {
                        if exp <= now {
                            return None; // Expired.
                        }
                    }
                    return Some(user.id);
                }
            }
        }
        None
    }

    /// Revoke an API token.
    pub fn revoke_token(&mut self, user_id: u64, token: &str) -> bool {
        if let Some(user) = self.users.iter_mut().find(|u| u.id == user_id) {
            if let Some(pos) = user.tokens.iter().position(|t| t.token == token) {
                user.tokens.remove(pos);
                return true;
            }
        }
        false
    }

    /// Get a user by ID.
    pub fn get_user(&self, user_id: u64) -> Option<&User> {
        self.users.iter().find(|u| u.id == user_id)
    }

    /// Get a user by username.
    pub fn get_user_by_name(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }

    /// Logout: remove a session.
    pub fn logout(&mut self, session_token: &str) {
        for user in &mut self.users {
            user.sessions.remove(session_token);
        }
    }

    /// Authenticate a request. Checks Bearer token, then session cookie.
    /// Returns user ID on success.
    pub fn authenticate(&self, auth_header: Option<&str>, cookie_header: Option<&str>) -> Option<u64> {
        // 1. Check Bearer token.
        if let Some(auth) = auth_header {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if let Some(uid) = self.validate_token(token.trim()) {
                    return Some(uid);
                }
            }
        }

        // 2. Check session cookie.
        if let Some(cookies) = cookie_header {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("phprs_session=") {
                    if let Some(uid) = self.validate_session(token.trim()) {
                        return Some(uid);
                    }
                }
            }
        }

        None
    }
}

// ── Password Hashing ────────────────────────────────────────────────────────

/// Hash a password using bcrypt with cost factor 12.
fn hash_password(password: &str) -> Result<String, String> {
    bcrypt::hash(password, BCRYPT_COST)
        .map_err(|e| format!("bcrypt hash failed: {}", e))
}

/// Verify a password against a stored hash.
/// Supports both bcrypt and legacy "sha256:salt:hash" format.
fn verify_password(password: &str, stored: &str) -> Result<bool, String> {
    if stored.starts_with("sha256:") {
        // Legacy SHA-256 format: "sha256:{salt}:{hash}"
        verify_password_sha256_legacy(password, stored)
    } else {
        // bcrypt format (starts with "$2b$" or "$2a$" or "$2y$")
        bcrypt::verify(password, stored)
            .map_err(|e| format!("bcrypt verify failed: {}", e))
    }
}

/// Verify a legacy SHA-256 password hash.
fn verify_password_sha256_legacy(password: &str, stored: &str) -> Result<bool, String> {
    let parts: Vec<&str> = stored.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "sha256" {
        return Err("Invalid hash format".into());
    }
    let salt = parts[1];
    let expected_hash = parts[2];
    let computed = sha256_hex(&format!("{}{}", salt, password));
    Ok(computed == expected_hash)
}

// ── Token Generation ────────────────────────────────────────────────────────

/// Generate a cryptographically secure random hex token (32 bytes = 64 hex chars).
/// Uses ring::rand::SystemRandom for secure random bytes.
fn generate_token() -> String {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut bytes)
        .expect("SystemRandom fill failed");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Rate Limiting ───────────────────────────────────────────────────────────

/// Token-bucket rate limiter for login attempts.
/// Allows `max_attempts` per `window_secs` per IP address.
pub struct RateLimiter {
    /// Map of IP address → list of attempt timestamps (epoch seconds).
    attempts: std::sync::Mutex<HashMap<String, Vec<u64>>>,
    /// Maximum attempts allowed per window.
    max_attempts: u64,
    /// Window size in seconds.
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_attempts: u64, window_secs: u64) -> Self {
        Self {
            attempts: std::sync::Mutex::new(HashMap::new()),
            max_attempts,
            window_secs,
        }
    }

    /// Create a default login rate limiter (10 attempts per 60 seconds).
    pub fn login_default() -> Self {
        Self::new(10, 60)
    }

    /// Check if an IP is rate limited. Returns Ok(()) if allowed,
    /// Err(seconds_until_retry) if rate limited.
    pub fn check(&self, ip: &str) -> Result<(), u64> {
        let now = epoch_secs();
        let mut attempts = self.attempts.lock().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();

        // Remove expired attempts outside the window.
        let cutoff = now.saturating_sub(self.window_secs);
        entry.retain(|&t| t > cutoff);

        if entry.len() as u64 >= self.max_attempts {
            // Rate limited — calculate seconds until the oldest attempt expires.
            let oldest = entry.first().copied().unwrap_or(now);
            let retry_after = (oldest + self.window_secs).saturating_sub(now);
            Err(retry_after)
        } else {
            Ok(())
        }
    }

    /// Record a login attempt for an IP.
    pub fn record_attempt(&self, ip: &str) {
        let now = epoch_secs();
        let mut attempts = self.attempts.lock().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();

        // Clean up old entries while we're here.
        let cutoff = now.saturating_sub(self.window_secs);
        entry.retain(|&t| t > cutoff);

        entry.push(now);
    }

    /// Reset rate limit for an IP (e.g. after successful login).
    pub fn reset(&self, ip: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(ip);
    }

    /// Clean up stale entries (call periodically).
    pub fn cleanup(&self) {
        let now = epoch_secs();
        let cutoff = now.saturating_sub(self.window_secs);
        let mut attempts = self.attempts.lock().unwrap();
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// SHA-256 hash for legacy password verification (using ring).
fn sha256_hex(input: &str) -> String {
    sha256_bytes(input.as_bytes())
}

fn sha256_bytes(data: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA256, data);
    d.as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn users_file_path() -> PathBuf {
    if let Ok(dir) = std::env::var("PHPRS_STATE_DIR") {
        PathBuf::from(dir).join("users.json")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".php-rs").join("users.json")
    } else {
        PathBuf::from("/tmp/.php-rs/users.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_store_path() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "phprs-auth-test-{}-{}/users.json",
            std::process::id(),
            n
        ))
    }

    #[test]
    fn test_register_and_login() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let id = store.register("testuser", "password123", "test@example.com").unwrap();
        assert_eq!(id, 1);
        assert!(store.users[0].is_admin); // First user is admin.

        // Login with correct password.
        let login_id = store.login("testuser", "password123").unwrap();
        assert_eq!(login_id, 1);

        // Login with wrong password.
        assert!(store.login("testuser", "wrongpass").is_err());

        // Login with wrong username.
        assert!(store.login("nouser", "password123").is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_bcrypt_hash_format() {
        let hash = hash_password("testpass").unwrap();
        // bcrypt hashes start with "$2b$"
        assert!(hash.starts_with("$2b$"), "Hash should be bcrypt format, got: {}", hash);
        assert!(verify_password("testpass", &hash).unwrap());
        assert!(!verify_password("wrongpass", &hash).unwrap());
    }

    #[test]
    fn test_legacy_sha256_verification() {
        // Manually create a legacy SHA-256 hash.
        let salt = "abcdef0123456789";
        let password = "legacypass";
        let hash = sha256_hex(&format!("{}{}", salt, password));
        let stored = format!("sha256:{}:{}", salt, hash);

        // Should still verify correctly.
        assert!(verify_password(password, &stored).unwrap());
        assert!(!verify_password("wrongpass", &stored).unwrap());
    }

    #[test]
    fn test_legacy_hash_auto_upgrade() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        // Register a user (will use bcrypt).
        store.register("upgradeuser", "mypass", "up@test.com").unwrap();

        // Manually set a legacy SHA-256 hash to simulate migration.
        let salt = "deadbeef01234567";
        let hash = sha256_hex(&format!("{}{}", salt, "mypass"));
        store.users[0].password_hash = format!("sha256:{}:{}", salt, hash);
        assert!(store.users[0].password_hash.starts_with("sha256:"));

        // Login should succeed and upgrade the hash.
        let uid = store.login("upgradeuser", "mypass").unwrap();
        assert_eq!(uid, 1);

        // Hash should now be bcrypt.
        assert!(store.users[0].password_hash.starts_with("$2b$"),
            "Hash should be upgraded to bcrypt, got: {}", store.users[0].password_hash);

        // Login should still work with the new bcrypt hash.
        let uid2 = store.login("upgradeuser", "mypass").unwrap();
        assert_eq!(uid2, 1);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_secure_token_generation() {
        let t1 = generate_token();
        let t2 = generate_token();

        // Should be 64 hex chars (32 bytes).
        assert_eq!(t1.len(), 64);
        assert_eq!(t2.len(), 64);

        // Should be valid hex.
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(t2.chars().all(|c| c.is_ascii_hexdigit()));

        // Should be different (cryptographically random).
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_duplicate_username() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        store.register("user1", "pass1", "a@b.com").unwrap();
        assert!(store.register("user1", "pass2", "c@d.com").is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_duplicate_email() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        store.register("user1", "pass1", "same@email.com").unwrap();
        assert!(store.register("user2", "pass2", "same@email.com").is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_api_token() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let uid = store.register("user1", "pass1", "user@test.com").unwrap();
        let token = store.create_api_token(uid, "my-token", None).unwrap();

        // Validate token.
        assert_eq!(store.validate_token(&token), Some(uid));

        // Invalid token.
        assert_eq!(store.validate_token("invalid"), None);

        // Revoke token.
        assert!(store.revoke_token(uid, &token));
        assert_eq!(store.validate_token(&token), None);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_session() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let uid = store.register("user1", "pass1", "user@test.com").unwrap();
        let session = store.create_session(uid, 24).unwrap();

        // Validate session.
        assert_eq!(store.validate_session(&session), Some(uid));

        // Invalid session.
        assert_eq!(store.validate_session("invalid"), None);

        // Logout.
        store.logout(&session);
        assert_eq!(store.validate_session(&session), None);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_save_and_load() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        store.register("user1", "pass1", "user@test.com").unwrap();
        store.save_to(&path).unwrap();

        let mut loaded = UserStore::load_from(&path);
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].username, "user1");
        assert_eq!(loaded.next_id, 2);

        // Can still login after reload.
        assert!(loaded.login("user1", "pass1").is_ok());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_authenticate_bearer() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let uid = store.register("user1", "pass1", "user@test.com").unwrap();
        let token = store.create_api_token(uid, "test", None).unwrap();

        let auth_header = format!("Bearer {}", token);
        assert_eq!(
            store.authenticate(Some(&auth_header), None),
            Some(uid)
        );

        // Wrong token.
        assert_eq!(
            store.authenticate(Some("Bearer invalid"), None),
            None
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_authenticate_session_cookie() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let uid = store.register("user1", "pass1", "user@test.com").unwrap();
        let session = store.create_session(uid, 24).unwrap();

        let cookie = format!("phprs_session={}", session);
        assert_eq!(
            store.authenticate(None, Some(&cookie)),
            Some(uid)
        );

        // With other cookies too.
        let cookie = format!("foo=bar; phprs_session={}; baz=qux", session);
        assert_eq!(
            store.authenticate(None, Some(&cookie)),
            Some(uid)
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_second_user_not_admin() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        store.register("admin", "pass1", "admin@test.com").unwrap();
        store.register("user2", "pass2", "user2@test.com").unwrap();

        assert!(store.users[0].is_admin);
        assert!(!store.users[1].is_admin);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_password_hash_verify() {
        let hash = hash_password("testpassword").unwrap();
        assert!(hash.starts_with("$2b$"));
        assert!(verify_password("testpassword", &hash).unwrap());
        assert!(!verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_get_user() {
        let path = test_store_path();
        let mut store = UserStore::load_from(&path);

        let uid = store.register("user1", "pass1", "user@test.com").unwrap();

        assert!(store.get_user(uid).is_some());
        assert_eq!(store.get_user(uid).unwrap().username, "user1");
        assert!(store.get_user(999).is_none());

        assert!(store.get_user_by_name("user1").is_some());
        assert!(store.get_user_by_name("nouser").is_none());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ── Rate Limiter Tests ──────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(3, 60);
        let ip = "192.168.1.1";

        // First 3 attempts should be allowed.
        for _ in 0..3 {
            assert!(limiter.check(ip).is_ok());
            limiter.record_attempt(ip);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        let ip = "192.168.1.2";

        // Record 3 attempts.
        for _ in 0..3 {
            limiter.record_attempt(ip);
        }

        // 4th check should be rate limited.
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_different_ips_independent() {
        let limiter = RateLimiter::new(2, 60);

        // Fill up IP 1.
        limiter.record_attempt("10.0.0.1");
        limiter.record_attempt("10.0.0.1");
        assert!(limiter.check("10.0.0.1").is_err());

        // IP 2 should still be allowed.
        assert!(limiter.check("10.0.0.2").is_ok());
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(2, 60);
        let ip = "10.0.0.3";

        limiter.record_attempt(ip);
        limiter.record_attempt(ip);
        assert!(limiter.check(ip).is_err());

        // Reset should clear the limit.
        limiter.reset(ip);
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(10, 60);
        limiter.record_attempt("stale-ip");
        limiter.cleanup();
        // Should not panic, stale entries will be cleaned on next window expiry.
    }

    #[test]
    fn test_rate_limiter_login_default() {
        let limiter = RateLimiter::login_default();
        let ip = "1.2.3.4";

        // Should allow 10 attempts.
        for _ in 0..10 {
            assert!(limiter.check(ip).is_ok());
            limiter.record_attempt(ip);
        }

        // 11th should be blocked.
        assert!(limiter.check(ip).is_err());
    }
}
