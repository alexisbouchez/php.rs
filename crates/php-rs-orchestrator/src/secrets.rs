//! Secrets management — AES-256-GCM encryption for environment variables at rest.
//!
//! Env vars in state.json are stored encrypted with a platform master key.
//! The master key lives at `~/.php-rs/master.key` (256-bit random, chmod 600).
//! Encrypted values are prefixed with `ENC:` followed by base64-encoded
//! nonce + ciphertext + tag.
//!
//! Decryption happens only when building the process environment for a running
//! app — secrets never appear in logs, error messages, or API responses.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

const ENCRYPTED_PREFIX: &str = "ENC:";
const KEY_SIZE: usize = 32; // AES-256
const NONCE_SIZE: usize = 12; // 96-bit nonce for AES-GCM

/// Secrets manager handling encryption and decryption of environment variables.
pub struct SecretStore {
    /// Path to the master key file.
    key_path: PathBuf,
    /// Cached sealing key (loaded lazily).
    key_bytes: Option<Vec<u8>>,
}

impl SecretStore {
    /// Create a new SecretStore using the default key location (~/.php-rs/master.key).
    pub fn new() -> Self {
        Self::with_key_path(default_key_path())
    }

    /// Create a SecretStore with a custom key path.
    pub fn with_key_path(key_path: PathBuf) -> Self {
        Self {
            key_path,
            key_bytes: None,
        }
    }

    /// Load or create the master key. Creates a new random key if none exists.
    pub fn ensure_key(&mut self) -> Result<(), String> {
        if self.key_bytes.is_some() {
            return Ok(());
        }

        if self.key_path.exists() {
            let bytes = std::fs::read(&self.key_path)
                .map_err(|e| format!("Cannot read master key {}: {}", self.key_path.display(), e))?;
            if bytes.len() != KEY_SIZE {
                return Err(format!(
                    "Master key {} has wrong size ({} bytes, expected {})",
                    self.key_path.display(),
                    bytes.len(),
                    KEY_SIZE
                ));
            }
            self.key_bytes = Some(bytes);
        } else {
            // Generate a new random key.
            let key = generate_key()?;

            // Write to disk with restrictive permissions.
            if let Some(dir) = self.key_path.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("Cannot create key directory: {}", e))?;
            }
            std::fs::write(&self.key_path, &key)
                .map_err(|e| format!("Cannot write master key: {}", e))?;

            // Set permissions to 600 (owner read/write only).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&self.key_path, perms)
                    .map_err(|e| format!("Cannot set key permissions: {}", e))?;
            }

            self.key_bytes = Some(key);
        }
        Ok(())
    }

    /// Encrypt a plaintext value. Returns a string prefixed with "ENC:".
    pub fn encrypt(&mut self, plaintext: &str) -> Result<String, String> {
        self.ensure_key()?;
        let key_bytes = self.key_bytes.as_ref().unwrap();
        let ciphertext = encrypt_value(key_bytes, plaintext.as_bytes())?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        Ok(format!("{}{}", ENCRYPTED_PREFIX, encoded))
    }

    /// Decrypt an encrypted value (must start with "ENC:").
    pub fn decrypt(&mut self, encrypted: &str) -> Result<String, String> {
        if !encrypted.starts_with(ENCRYPTED_PREFIX) {
            return Err("Value is not encrypted (missing ENC: prefix)".into());
        }
        self.ensure_key()?;
        let key_bytes = self.key_bytes.as_ref().unwrap();
        let encoded = &encrypted[ENCRYPTED_PREFIX.len()..];
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Invalid base64: {}", e))?;
        let plaintext = decrypt_value(key_bytes, &ciphertext)?;
        String::from_utf8(plaintext).map_err(|e| format!("Decrypted value is not valid UTF-8: {}", e))
    }

    /// Encrypt all values in a HashMap. Already-encrypted values are skipped.
    pub fn encrypt_env(&mut self, env: &mut HashMap<String, String>) -> Result<(), String> {
        let keys: Vec<String> = env.keys().cloned().collect();
        for key in keys {
            let val = &env[&key];
            if !is_encrypted(val) {
                let encrypted = self.encrypt(val)?;
                env.insert(key, encrypted);
            }
        }
        Ok(())
    }

    /// Decrypt all encrypted values in a HashMap. Non-encrypted values are unchanged.
    pub fn decrypt_env(&mut self, env: &HashMap<String, String>) -> Result<HashMap<String, String>, String> {
        let mut result = HashMap::with_capacity(env.len());
        for (key, val) in env {
            if is_encrypted(val) {
                result.insert(key.clone(), self.decrypt(val)?);
            } else {
                result.insert(key.clone(), val.clone());
            }
        }
        Ok(result)
    }

    /// Re-encrypt all values with a new key. Used for key rotation.
    /// 1. Decrypt all values with the current key
    /// 2. Generate a new key
    /// 3. Encrypt all values with the new key
    pub fn rotate_key(&mut self, env: &mut HashMap<String, String>) -> Result<(), String> {
        // Decrypt all values with the current key.
        let decrypted = self.decrypt_env(env)?;

        // Generate a new key and replace the old one.
        let new_key = generate_key()?;
        std::fs::write(&self.key_path, &new_key)
            .map_err(|e| format!("Cannot write new master key: {}", e))?;
        self.key_bytes = Some(new_key);

        // Re-encrypt all values with the new key.
        *env = decrypted;
        self.encrypt_env(env)
    }

    /// Get the key file path.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
}

/// Check if a value is encrypted (starts with "ENC:").
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX)
}

/// Generate a random 256-bit key.
fn generate_key() -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut key = vec![0u8; KEY_SIZE];
    rng.fill(&mut key)
        .map_err(|_| "Failed to generate random key".to_string())?;
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext || tag.
fn encrypt_value(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| "Invalid encryption key")?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "Failed to generate nonce")?;

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Encryption failed")?;

    // Prepend nonce to ciphertext+tag.
    let mut result = Vec::with_capacity(NONCE_SIZE + in_out.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// Decrypt ciphertext with AES-256-GCM. Input is nonce || ciphertext || tag.
fn decrypt_value(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_SIZE + aead::AES_256_GCM.tag_len() {
        return Err("Ciphertext too short".into());
    }

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| "Invalid decryption key")?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "Invalid nonce")?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed — wrong key or corrupted data")?;

    Ok(plaintext.to_vec())
}

/// Get the default master key path (~/.php-rs/master.key).
fn default_key_path() -> PathBuf {
    if let Ok(dir) = std::env::var("PHPRS_STATE_DIR") {
        PathBuf::from(dir).join("master.key")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".php-rs").join("master.key")
    } else {
        PathBuf::from("/tmp/.php-rs/master.key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_key_path() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "phprs-secrets-test-{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("master.key")
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);

        // Keys should be random (different each time).
        let key2 = generate_key().unwrap();
        assert_ne!(key, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key().unwrap();
        let plaintext = b"my-secret-database-password";

        let ciphertext = encrypt_value(&key, plaintext).unwrap();
        assert_ne!(&ciphertext[NONCE_SIZE..], plaintext); // Should be encrypted.

        let decrypted = decrypt_value(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = generate_key().unwrap();
        let ciphertext = encrypt_value(&key, b"").unwrap();
        let decrypted = decrypt_value(&key, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = generate_key().unwrap();
        let key2 = generate_key().unwrap();

        let ciphertext = encrypt_value(&key1, b"secret").unwrap();
        assert!(decrypt_value(&key2, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = generate_key().unwrap();
        let mut ciphertext = encrypt_value(&key, b"secret").unwrap();

        // Corrupt a byte.
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_value(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = generate_key().unwrap();
        assert!(decrypt_value(&key, b"short").is_err());
    }

    #[test]
    fn test_secret_store_encrypt_decrypt() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let encrypted = store.encrypt("my-password-123").unwrap();
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        assert!(is_encrypted(&encrypted));

        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "my-password-123");

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_key_persistence() {
        let key_path = temp_key_path();

        // First store: creates the key.
        let encrypted = {
            let mut store = SecretStore::with_key_path(key_path.clone());
            store.encrypt("persistent-secret").unwrap()
        };

        // Second store: loads the same key.
        {
            let mut store = SecretStore::with_key_path(key_path.clone());
            let decrypted = store.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, "persistent-secret");
        }

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_encrypt_env() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let mut env = HashMap::new();
        env.insert("DB_PASSWORD".into(), "secret123".into());
        env.insert("API_KEY".into(), "abc-def-ghi".into());

        store.encrypt_env(&mut env).unwrap();

        // All values should now be encrypted.
        assert!(is_encrypted(&env["DB_PASSWORD"]));
        assert!(is_encrypted(&env["API_KEY"]));

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_decrypt_env() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let mut env = HashMap::new();
        env.insert("DB_PASSWORD".into(), "secret123".into());
        env.insert("PLAIN_VAR".into(), "not-a-secret".into());

        // Encrypt only DB_PASSWORD.
        let encrypted = store.encrypt("secret123").unwrap();
        env.insert("DB_PASSWORD".into(), encrypted);

        // Decrypt — PLAIN_VAR should pass through unchanged.
        let decrypted = store.decrypt_env(&env).unwrap();
        assert_eq!(decrypted["DB_PASSWORD"], "secret123");
        assert_eq!(decrypted["PLAIN_VAR"], "not-a-secret");

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_encrypt_skips_already_encrypted() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let mut env = HashMap::new();
        let already_encrypted = store.encrypt("value1").unwrap();
        env.insert("KEY1".into(), already_encrypted.clone());
        env.insert("KEY2".into(), "plaintext".into());

        store.encrypt_env(&mut env).unwrap();

        // KEY1 should be unchanged (already encrypted).
        assert_eq!(env["KEY1"], already_encrypted);
        // KEY2 should now be encrypted.
        assert!(is_encrypted(&env["KEY2"]));

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_key_rotation() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        // Encrypt some values.
        let mut env = HashMap::new();
        env.insert("SECRET1".into(), "password1".into());
        env.insert("SECRET2".into(), "password2".into());
        store.encrypt_env(&mut env).unwrap();

        let old_encrypted = env.clone();

        // Rotate the key.
        store.rotate_key(&mut env).unwrap();

        // Values should still be encrypted, but with different ciphertext.
        assert!(is_encrypted(&env["SECRET1"]));
        assert!(is_encrypted(&env["SECRET2"]));
        assert_ne!(env["SECRET1"], old_encrypted["SECRET1"]);
        assert_ne!(env["SECRET2"], old_encrypted["SECRET2"]);

        // Decryption with the new key should work.
        let decrypted = store.decrypt_env(&env).unwrap();
        assert_eq!(decrypted["SECRET1"], "password1");
        assert_eq!(decrypted["SECRET2"], "password2");

        cleanup(&key_path);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(is_encrypted("ENC:abc123"));
        assert!(!is_encrypted("plain-value"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("enc:lowercase"));
    }

    #[test]
    fn test_secret_store_special_characters() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let special = "p@ss=w0rd!#$%^&*(){}[]|\\:\";<>,.?/~`";
        let encrypted = store.encrypt(special).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, special);

        cleanup(&key_path);
    }

    #[test]
    fn test_secret_store_unicode() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());

        let unicode = "密码🔐motdepasse";
        let encrypted = store.encrypt(unicode).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, unicode);

        cleanup(&key_path);
    }

    #[test]
    fn test_decrypt_non_encrypted_errors() {
        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());
        store.ensure_key().unwrap();

        assert!(store.decrypt("not-encrypted").is_err());

        cleanup(&key_path);
    }

    #[test]
    #[cfg(unix)]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let key_path = temp_key_path();
        let mut store = SecretStore::with_key_path(key_path.clone());
        store.ensure_key().unwrap();

        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        cleanup(&key_path);
    }
}
