//! Authentication & authorization for the PaaS.
//!
//! Users authenticate via:
//! - API token (Bearer header) — for CLI and programmatic access
//! - Session cookie — for the web dashboard
//!
//! User data and tokens stored in a JSON file at ~/.php-rs/users.json.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A registered user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u64,
    pub username: String,
    /// Bcrypt-hashed password.
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
    pub fn login(&self, username: &str, password: &str) -> Result<u64, String> {
        let user = self
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| "Invalid username or password".to_string())?;

        if verify_password(password, &user.password_hash)? {
            Ok(user.id)
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

/// Hash a password using SHA-256 + salt (simple, no bcrypt dependency).
/// Format: "sha256:{salt}:{hash}"
fn hash_password(password: &str) -> Result<String, String> {
    let salt = generate_salt();
    let hash = sha256_hex(&format!("{}{}", salt, password));
    Ok(format!("sha256:{}:{}", salt, hash))
}

/// Verify a password against a stored hash.
fn verify_password(password: &str, stored: &str) -> Result<bool, String> {
    let parts: Vec<&str> = stored.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "sha256" {
        return Err("Invalid hash format".into());
    }
    let salt = parts[1];
    let expected_hash = parts[2];
    let computed = sha256_hex(&format!("{}{}", salt, password));
    Ok(computed == expected_hash)
}

/// Generate a random hex token (32 bytes = 64 hex chars).
fn generate_token() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    epoch_nanos().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    (h1 ^ 0xdeadbeef).hash(&mut hasher2);
    epoch_nanos().hash(&mut hasher2);
    let h2 = hasher2.finish();

    format!("{:016x}{:016x}", h1, h2)
}

/// Generate a random salt (16 hex chars).
fn generate_salt() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    epoch_nanos().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Simple SHA-256 (manual implementation for no extra dependencies).
fn sha256_hex(input: &str) -> String {
    sha256_bytes(input.as_bytes())
}

fn sha256_bytes(data: &[u8]) -> String {
    // Use ring for SHA-256 since we already depend on it.
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

fn epoch_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
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

        let loaded = UserStore::load_from(&path);
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
        assert!(hash.starts_with("sha256:"));
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
}
