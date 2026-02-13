//! PHP openssl extension implementation for php.rs
//!
//! Provides openssl_* functions for encryption, decryption, signing, and key management.
//! This is a pure Rust implementation using basic crypto primitives where possible,
//! with stubs for operations that require full OpenSSL functionality.

/// OpenSSL-related constants matching PHP's values.
pub mod constants {
    /// Raw output (binary).
    pub const OPENSSL_RAW_DATA: u32 = 1;
    /// Zero-pad data.
    pub const OPENSSL_ZERO_PADDING: u32 = 2;
    /// Don't base64 encode (same as raw).
    pub const OPENSSL_DONT_ZERO_PAD_KEY: u32 = 4;

    pub const OPENSSL_KEYTYPE_RSA: u32 = 0;
    pub const OPENSSL_KEYTYPE_DSA: u32 = 1;
    pub const OPENSSL_KEYTYPE_DH: u32 = 2;
    pub const OPENSSL_KEYTYPE_EC: u32 = 3;
}

/// Key types supported by the openssl extension.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    RSA,
    DSA,
    DH,
    EC,
}

impl KeyType {
    /// Convert from a PHP OPENSSL_KEYTYPE_* constant.
    pub fn from_constant(c: u32) -> Option<KeyType> {
        match c {
            constants::OPENSSL_KEYTYPE_RSA => Some(KeyType::RSA),
            constants::OPENSSL_KEYTYPE_DSA => Some(KeyType::DSA),
            constants::OPENSSL_KEYTYPE_DH => Some(KeyType::DH),
            constants::OPENSSL_KEYTYPE_EC => Some(KeyType::EC),
            _ => None,
        }
    }
}

/// Configuration for key generation.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub key_type: KeyType,
    pub bits: u32,
    pub curve_name: Option<String>,
}

impl Default for KeyConfig {
    fn default() -> Self {
        KeyConfig {
            key_type: KeyType::RSA,
            bits: 2048,
            curve_name: None,
        }
    }
}

/// An OpenSSL key, representing either a public or private key (or both).
#[derive(Debug, Clone)]
pub struct OpensslKey {
    pub key_type: KeyType,
    pub bits: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Encrypt data using a symmetric cipher.
///
/// Equivalent to PHP's `openssl_encrypt(string $data, string $cipher_algo, string $passphrase,
/// int $options = 0, string $iv = "", ...): string|false`.
///
/// Currently supports "aes-128-cbc", "aes-256-cbc", and "aes-256-ecb" as stubs
/// that perform XOR-based obfuscation for API surface testing.
pub fn openssl_encrypt(
    data: &str,
    method: &str,
    key: &str,
    options: u32,
    iv: &str,
) -> Result<String, String> {
    let method_lower = method.to_lowercase();

    if !is_supported_cipher(&method_lower) {
        return Err(format!("Unknown cipher algorithm: {}", method));
    }

    // Validate IV length for modes that require it
    if method_lower.contains("cbc") || method_lower.contains("cfb") || method_lower.contains("ofb")
    {
        if method_lower.contains("128") && iv.len() != 16 {
            return Err(format!(
                "openssl_encrypt(): IV passed is {} bytes long which is longer than the {} expected by selected cipher",
                iv.len(),
                16
            ));
        }
        if method_lower.contains("256") && iv.len() != 16 {
            return Err(format!(
                "openssl_encrypt(): IV passed is {} bytes long which is longer than the {} expected by selected cipher",
                iv.len(),
                16
            ));
        }
    }

    // Stub encryption: XOR data with key bytes for API compatibility
    let data_bytes = data.as_bytes();
    let key_bytes = key.as_bytes();
    let iv_bytes = iv.as_bytes();

    let mut encrypted = Vec::with_capacity(data_bytes.len());
    for (i, &b) in data_bytes.iter().enumerate() {
        let k = if !key_bytes.is_empty() {
            key_bytes[i % key_bytes.len()]
        } else {
            0
        };
        let v = if !iv_bytes.is_empty() {
            iv_bytes[i % iv_bytes.len()]
        } else {
            0
        };
        encrypted.push(b ^ k ^ v);
    }

    let raw_output = (options & constants::OPENSSL_RAW_DATA) != 0;
    if raw_output {
        // In PHP, raw output returns binary bytes. Since Rust strings are UTF-8,
        // we hex-encode raw bytes to preserve them losslessly in the stub.
        Ok(hex_encode(&encrypted))
    } else {
        Ok(base64_encode(&encrypted))
    }
}

/// Decrypt data using a symmetric cipher.
///
/// Equivalent to PHP's `openssl_decrypt(string $data, string $cipher_algo, string $passphrase,
/// int $options = 0, string $iv = "", ...): string|false`.
pub fn openssl_decrypt(
    data: &str,
    method: &str,
    key: &str,
    options: u32,
    iv: &str,
) -> Result<String, String> {
    let method_lower = method.to_lowercase();

    if !is_supported_cipher(&method_lower) {
        return Err(format!("Unknown cipher algorithm: {}", method));
    }

    let raw_input = (options & constants::OPENSSL_RAW_DATA) != 0;
    let cipher_bytes = if raw_input {
        // Raw mode uses hex encoding in our stub (matching encrypt)
        hex_decode(data)?
    } else {
        base64_decode(data)?
    };

    let key_bytes = key.as_bytes();
    let iv_bytes = iv.as_bytes();

    // Stub decryption: XOR reversal (same as encrypt for XOR)
    let mut decrypted = Vec::with_capacity(cipher_bytes.len());
    for (i, &b) in cipher_bytes.iter().enumerate() {
        let k = if !key_bytes.is_empty() {
            key_bytes[i % key_bytes.len()]
        } else {
            0
        };
        let v = if !iv_bytes.is_empty() {
            iv_bytes[i % iv_bytes.len()]
        } else {
            0
        };
        decrypted.push(b ^ k ^ v);
    }

    String::from_utf8(decrypted).map_err(|e| format!("Decryption produced invalid UTF-8: {}", e))
}

/// Sign data using a private key.
///
/// Equivalent to PHP's `openssl_sign(string $data, string &$signature, OpenSSLAsymmetricKey $private_key,
/// string|int $algorithm = OPENSSL_ALGO_SHA1): bool`.
///
/// Stub implementation: generates a deterministic signature based on key and data.
pub fn openssl_sign(data: &str, key: &OpensslKey, _algorithm: &str) -> Result<Vec<u8>, String> {
    if key.private_key.is_empty() {
        return Err("openssl_sign(): supplied key param cannot be used for signing".to_string());
    }

    // Stub: produce a deterministic "signature" by XOR-mixing data with private key
    let data_bytes = data.as_bytes();
    let mut signature = Vec::with_capacity(64);
    for i in 0..64 {
        let d = if !data_bytes.is_empty() {
            data_bytes[i % data_bytes.len()]
        } else {
            0
        };
        let k = if !key.private_key.is_empty() {
            key.private_key[i % key.private_key.len()]
        } else {
            0
        };
        signature.push(d ^ k);
    }
    Ok(signature)
}

/// Verify a signature against data using a public key.
///
/// Equivalent to PHP's `openssl_verify(string $data, string $signature,
/// OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $public_key,
/// string|int $algorithm = OPENSSL_ALGO_SHA1): int|false`.
///
/// Returns: 1 if valid, 0 if invalid, or error.
/// Stub: always returns 1 (valid) when key has a public key component.
pub fn openssl_verify(
    _data: &str,
    _signature: &[u8],
    key: &OpensslKey,
    _algorithm: &str,
) -> Result<i32, String> {
    if key.public_key.is_empty() {
        return Err(
            "openssl_verify(): supplied key param cannot be used for verifying".to_string(),
        );
    }
    // Stub: always report valid
    Ok(1)
}

/// Generate pseudo-random bytes.
///
/// Equivalent to PHP's `openssl_random_pseudo_bytes(int $length, bool &$strong_result = null): string`.
///
/// Uses a simple random byte generator. Not cryptographically secure in this stub.
pub fn openssl_random_pseudo_bytes(length: usize) -> Vec<u8> {
    // Use a simple deterministic approach for testability,
    // but in practice this would use a CSPRNG.
    let mut bytes = Vec::with_capacity(length);
    // Simple LCG for stub purposes
    let mut state: u64 = 0x12345678_9ABCDEF0;
    for _ in 0..length {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        bytes.push((state >> 33) as u8);
    }
    bytes
}

/// Get a list of available cipher methods.
///
/// Equivalent to PHP's `openssl_get_cipher_methods(bool $aliases = false): array`.
pub fn openssl_get_cipher_methods() -> Vec<String> {
    vec![
        "aes-128-cbc".to_string(),
        "aes-128-cfb".to_string(),
        "aes-128-ecb".to_string(),
        "aes-128-gcm".to_string(),
        "aes-128-ofb".to_string(),
        "aes-192-cbc".to_string(),
        "aes-192-cfb".to_string(),
        "aes-192-ecb".to_string(),
        "aes-192-gcm".to_string(),
        "aes-192-ofb".to_string(),
        "aes-256-cbc".to_string(),
        "aes-256-cfb".to_string(),
        "aes-256-ecb".to_string(),
        "aes-256-gcm".to_string(),
        "aes-256-ofb".to_string(),
        "bf-cbc".to_string(),
        "bf-cfb".to_string(),
        "bf-ecb".to_string(),
        "bf-ofb".to_string(),
        "camellia-128-cbc".to_string(),
        "camellia-256-cbc".to_string(),
        "chacha20".to_string(),
        "chacha20-poly1305".to_string(),
        "des-cbc".to_string(),
        "des-ecb".to_string(),
        "des-ede3-cbc".to_string(),
        "rc4".to_string(),
    ]
}

/// Get a list of available digest methods.
///
/// Equivalent to PHP's `openssl_get_md_methods(bool $aliases = false): array`.
pub fn openssl_get_md_methods() -> Vec<String> {
    vec![
        "md5".to_string(),
        "sha1".to_string(),
        "sha224".to_string(),
        "sha256".to_string(),
        "sha384".to_string(),
        "sha512".to_string(),
        "sha3-256".to_string(),
        "sha3-384".to_string(),
        "sha3-512".to_string(),
        "ripemd160".to_string(),
        "whirlpool".to_string(),
    ]
}

/// Compute a digest (hash) of data.
///
/// Equivalent to PHP's `openssl_digest(string $data, string $digest_algo,
/// bool $binary = false): string|false`.
///
/// Stub: uses a simple hash function for API compatibility.
pub fn openssl_digest(data: &str, method: &str, raw_output: bool) -> Result<String, String> {
    let method_lower = method.to_lowercase();

    let digest_len = match method_lower.as_str() {
        "md5" => 16,
        "sha1" => 20,
        "sha224" => 28,
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        "sha3-256" => 32,
        "sha3-384" => 48,
        "sha3-512" => 64,
        "ripemd160" => 20,
        _ => return Err(format!("Unknown digest algorithm: {}", method)),
    };

    // Stub hash: simple DJB2-like mixing to produce the right number of bytes
    let data_bytes = data.as_bytes();
    let mut hash = vec![0u8; digest_len];
    let mut state: u64 = 5381;
    for (i, &b) in data_bytes.iter().enumerate() {
        state = state.wrapping_mul(33).wrapping_add(b as u64);
        hash[i % digest_len] ^= (state >> (i % 8)) as u8;
    }
    // Mix further
    for (i, byte) in hash.iter_mut().enumerate() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(i as u64);
        *byte = byte.wrapping_add((state >> 33) as u8);
    }

    if raw_output {
        // In PHP, raw output returns binary bytes. Since Rust strings are UTF-8,
        // we hex-encode raw bytes in the stub for lossless representation.
        // The output length will be 2x the digest length (hex-encoded).
        Ok(hex_encode(&hash))
    } else {
        Ok(hex_encode(&hash))
    }
}

/// Generate a new asymmetric key pair.
///
/// Equivalent to PHP's `openssl_pkey_new(?array $options = null): OpenSSLAsymmetricKey|false`.
///
/// Stub: generates random-looking key material.
pub fn openssl_pkey_new(config: Option<KeyConfig>) -> Result<OpensslKey, String> {
    let config = config.unwrap_or_default();

    let key_size = match config.key_type {
        KeyType::RSA => config.bits as usize / 8,
        KeyType::DSA => config.bits as usize / 8,
        KeyType::DH => config.bits as usize / 8,
        KeyType::EC => 32, // Simplified for EC
    };

    // Stub: generate deterministic-looking key bytes
    let mut public_key = Vec::with_capacity(key_size);
    let mut private_key = Vec::with_capacity(key_size);
    let mut state: u64 = 0xDEADBEEF_CAFEBABE;

    for _ in 0..key_size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        public_key.push((state >> 33) as u8);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(3);
        private_key.push((state >> 33) as u8);
    }

    Ok(OpensslKey {
        key_type: config.key_type,
        bits: config.bits,
        public_key,
        private_key,
    })
}

/// Load a public key from PEM-encoded data.
///
/// Equivalent to PHP's `openssl_pkey_get_public(OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $public_key): OpenSSLAsymmetricKey|false`.
///
/// Stub: extracts key bytes from between PEM markers.
pub fn openssl_pkey_get_public(pem: &str) -> Result<OpensslKey, String> {
    if !pem.contains("-----BEGIN") {
        return Err("openssl_pkey_get_public(): PEM format expected".to_string());
    }

    // Stub: create a key with the PEM data as public key bytes
    let key_data: Vec<u8> = pem.bytes().collect();
    Ok(OpensslKey {
        key_type: KeyType::RSA,
        bits: 2048,
        public_key: key_data,
        private_key: Vec::new(),
    })
}

/// Load a private key from PEM-encoded data.
///
/// Equivalent to PHP's `openssl_pkey_get_private(OpenSSLAsymmetricKey|string $private_key,
/// ?string $passphrase = null): OpenSSLAsymmetricKey|false`.
///
/// Stub: extracts key bytes from between PEM markers.
pub fn openssl_pkey_get_private(
    pem: &str,
    _passphrase: Option<&str>,
) -> Result<OpensslKey, String> {
    if !pem.contains("-----BEGIN") {
        return Err("openssl_pkey_get_private(): PEM format expected".to_string());
    }

    // Stub: create a key with the PEM data as private key bytes
    let key_data: Vec<u8> = pem.bytes().collect();
    Ok(OpensslKey {
        key_type: KeyType::RSA,
        bits: 2048,
        public_key: Vec::new(),
        private_key: key_data,
    })
}

// --- Internal helpers ---

fn is_supported_cipher(method: &str) -> bool {
    let methods = openssl_get_cipher_methods();
    methods.iter().any(|m| m == method)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }
    result
}

fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let chars: Vec<u8> = data.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    if !chars.len().is_multiple_of(4) {
        return Err("Invalid base64 input length".to_string());
    }

    let mut i = 0;
    while i < chars.len() {
        let sextet = |c: u8| -> Result<u32, String> {
            match c {
                b'A'..=b'Z' => Ok((c - b'A') as u32),
                b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
                b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
                b'+' => Ok(62),
                b'/' => Ok(63),
                b'=' => Ok(0),
                _ => Err(format!("Invalid base64 character: {}", c as char)),
            }
        };

        let a = sextet(chars[i])?;
        let b = sextet(chars[i + 1])?;
        let c = sextet(chars[i + 2])?;
        let d = sextet(chars[i + 3])?;

        let triple = (a << 18) | (b << 12) | (c << 6) | d;

        result.push((triple >> 16) as u8);
        if chars[i + 2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chars[i + 3] != b'=' {
            result.push(triple as u8);
        }

        i += 4;
    }
    Ok(result)
}

fn hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

fn hex_decode(data: &str) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(2) {
        return Err("Invalid hex string length".to_string());
    }
    let mut result = Vec::with_capacity(data.len() / 2);
    let bytes = data.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let high = hex_char_val(bytes[i])?;
        let low = hex_char_val(bytes[i + 1])?;
        result.push((high << 4) | low);
        i += 2;
    }
    Ok(result)
}

fn hex_char_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("Invalid hex character: {}", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Encrypt / Decrypt ---

    #[test]
    fn test_openssl_encrypt_basic() {
        let result = openssl_encrypt(
            "Hello, World!",
            "aes-256-cbc",
            "my-secret-key-00",
            0,
            "1234567890123456",
        );
        assert!(result.is_ok());
        // Should return base64 by default
        let encrypted = result.unwrap();
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_openssl_encrypt_raw_output() {
        let result = openssl_encrypt(
            "Hello",
            "aes-128-cbc",
            "my-secret-key-00",
            constants::OPENSSL_RAW_DATA,
            "1234567890123456",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_openssl_encrypt_unknown_cipher() {
        let result = openssl_encrypt("data", "unknown-cipher", "key", 0, "iv");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown cipher algorithm"));
    }

    #[test]
    fn test_openssl_decrypt_basic() {
        let key = "my-secret-key-00";
        let iv = "1234567890123456";
        let plaintext = "Hello, World!";

        let encrypted = openssl_encrypt(plaintext, "aes-256-cbc", key, 0, iv).unwrap();
        let decrypted = openssl_decrypt(&encrypted, "aes-256-cbc", key, 0, iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_decrypt_raw() {
        let key = "my-secret-key-00";
        let iv = "1234567890123456";
        let plaintext = "Test data";

        let encrypted = openssl_encrypt(
            plaintext,
            "aes-128-cbc",
            key,
            constants::OPENSSL_RAW_DATA,
            iv,
        )
        .unwrap();
        let decrypted = openssl_decrypt(
            &encrypted,
            "aes-128-cbc",
            key,
            constants::OPENSSL_RAW_DATA,
            iv,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_decrypt_unknown_cipher() {
        let result = openssl_decrypt("data", "unknown", "key", 0, "iv");
        assert!(result.is_err());
    }

    #[test]
    fn test_openssl_encrypt_ecb_mode() {
        let result = openssl_encrypt("data", "aes-256-ecb", "key", 0, "");
        assert!(result.is_ok());
    }

    // --- Sign / Verify ---

    #[test]
    fn test_openssl_sign_basic() {
        let key = openssl_pkey_new(None).unwrap();
        let result = openssl_sign("Test data to sign", &key, "sha256");
        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_openssl_sign_no_private_key() {
        let key = OpensslKey {
            key_type: KeyType::RSA,
            bits: 2048,
            public_key: vec![1, 2, 3],
            private_key: Vec::new(),
        };
        let result = openssl_sign("data", &key, "sha256");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be used for signing"));
    }

    #[test]
    fn test_openssl_verify_basic() {
        let key = openssl_pkey_new(None).unwrap();
        let signature = openssl_sign("data", &key, "sha256").unwrap();
        let result = openssl_verify("data", &signature, &key, "sha256");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_openssl_verify_no_public_key() {
        let key = OpensslKey {
            key_type: KeyType::RSA,
            bits: 2048,
            public_key: Vec::new(),
            private_key: vec![1, 2, 3],
        };
        let result = openssl_verify("data", &[0u8; 64], &key, "sha256");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be used for verifying"));
    }

    // --- Random bytes ---

    #[test]
    fn test_openssl_random_pseudo_bytes() {
        let bytes = openssl_random_pseudo_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_openssl_random_pseudo_bytes_zero() {
        let bytes = openssl_random_pseudo_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_openssl_random_pseudo_bytes_large() {
        let bytes = openssl_random_pseudo_bytes(1024);
        assert_eq!(bytes.len(), 1024);
    }

    // --- Cipher methods ---

    #[test]
    fn test_openssl_get_cipher_methods() {
        let methods = openssl_get_cipher_methods();
        assert!(!methods.is_empty());
        assert!(methods.contains(&"aes-128-cbc".to_string()));
        assert!(methods.contains(&"aes-256-cbc".to_string()));
        assert!(methods.contains(&"aes-256-gcm".to_string()));
        assert!(methods.contains(&"chacha20-poly1305".to_string()));
    }

    // --- Digest methods ---

    #[test]
    fn test_openssl_get_md_methods() {
        let methods = openssl_get_md_methods();
        assert!(!methods.is_empty());
        assert!(methods.contains(&"md5".to_string()));
        assert!(methods.contains(&"sha1".to_string()));
        assert!(methods.contains(&"sha256".to_string()));
        assert!(methods.contains(&"sha512".to_string()));
    }

    // --- Digest ---

    #[test]
    fn test_openssl_digest_sha256() {
        let result = openssl_digest("Hello", "sha256", false);
        assert!(result.is_ok());
        let hex = result.unwrap();
        // SHA-256 hex output is 64 chars
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_openssl_digest_md5() {
        let result = openssl_digest("Hello", "md5", false);
        assert!(result.is_ok());
        let hex = result.unwrap();
        // MD5 hex output is 32 chars
        assert_eq!(hex.len(), 32);
    }

    #[test]
    fn test_openssl_digest_sha512() {
        let result = openssl_digest("data", "sha512", false);
        assert!(result.is_ok());
        let hex = result.unwrap();
        assert_eq!(hex.len(), 128);
    }

    #[test]
    fn test_openssl_digest_raw_output() {
        // In this stub, raw_output also returns hex-encoded data since Rust strings
        // cannot hold arbitrary binary data losslessly. A real implementation would
        // return Vec<u8> for raw mode.
        let result = openssl_digest("data", "sha256", true);
        assert!(result.is_ok());
        let raw = result.unwrap();
        // SHA-256 produces 32 bytes, hex-encoded = 64 chars
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn test_openssl_digest_unknown_method() {
        let result = openssl_digest("data", "unknown", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown digest algorithm"));
    }

    // --- Key generation ---

    #[test]
    fn test_openssl_pkey_new_default() {
        let key = openssl_pkey_new(None);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.key_type, KeyType::RSA);
        assert_eq!(key.bits, 2048);
        assert_eq!(key.public_key.len(), 256); // 2048 / 8
        assert_eq!(key.private_key.len(), 256);
    }

    #[test]
    fn test_openssl_pkey_new_rsa_4096() {
        let config = KeyConfig {
            key_type: KeyType::RSA,
            bits: 4096,
            curve_name: None,
        };
        let key = openssl_pkey_new(Some(config)).unwrap();
        assert_eq!(key.bits, 4096);
        assert_eq!(key.public_key.len(), 512); // 4096 / 8
    }

    #[test]
    fn test_openssl_pkey_new_ec() {
        let config = KeyConfig {
            key_type: KeyType::EC,
            bits: 256,
            curve_name: Some("prime256v1".to_string()),
        };
        let key = openssl_pkey_new(Some(config)).unwrap();
        assert_eq!(key.key_type, KeyType::EC);
        assert_eq!(key.public_key.len(), 32);
    }

    // --- PEM loading ---

    #[test]
    fn test_openssl_pkey_get_public() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----";
        let result = openssl_pkey_get_public(pem);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert!(!key.public_key.is_empty());
        assert!(key.private_key.is_empty());
    }

    #[test]
    fn test_openssl_pkey_get_public_invalid() {
        let result = openssl_pkey_get_public("not a pem string");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PEM format expected"));
    }

    #[test]
    fn test_openssl_pkey_get_private() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PRIVATE KEY-----";
        let result = openssl_pkey_get_private(pem, None);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert!(!key.private_key.is_empty());
        assert!(key.public_key.is_empty());
    }

    #[test]
    fn test_openssl_pkey_get_private_with_passphrase() {
        let pem =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\ndata\n-----END ENCRYPTED PRIVATE KEY-----";
        let result = openssl_pkey_get_private(pem, Some("password"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_openssl_pkey_get_private_invalid() {
        let result = openssl_pkey_get_private("not a pem", None);
        assert!(result.is_err());
    }

    // --- Key type conversion ---

    #[test]
    fn test_key_type_from_constant() {
        assert_eq!(
            KeyType::from_constant(constants::OPENSSL_KEYTYPE_RSA),
            Some(KeyType::RSA)
        );
        assert_eq!(
            KeyType::from_constant(constants::OPENSSL_KEYTYPE_DSA),
            Some(KeyType::DSA)
        );
        assert_eq!(
            KeyType::from_constant(constants::OPENSSL_KEYTYPE_DH),
            Some(KeyType::DH)
        );
        assert_eq!(
            KeyType::from_constant(constants::OPENSSL_KEYTYPE_EC),
            Some(KeyType::EC)
        );
        assert_eq!(KeyType::from_constant(999), None);
    }

    // --- Base64 helpers ---

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        let encoded = base64_encode(b"");
        assert_eq!(encoded, "");
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    // --- Hex helpers ---

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }

    // --- Key config default ---

    #[test]
    fn test_key_config_default() {
        let config = KeyConfig::default();
        assert_eq!(config.key_type, KeyType::RSA);
        assert_eq!(config.bits, 2048);
        assert!(config.curve_name.is_none());
    }
}
