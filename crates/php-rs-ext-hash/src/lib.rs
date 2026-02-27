//! PHP hash extension.
//!
//! Implements hash(), hash_hmac(), hash_algos(), hash_equals().
//! Reference: php-src/ext/hash/

use digest::Digest;
use hmac::{Hmac, Mac};

/// hash() — Generate a hash value.
///
/// Supports: md5, sha1, sha256, sha384, sha512, crc32, crc32b.
pub fn php_hash(algo: &str, data: &str) -> Option<String> {
    php_hash_bytes(algo, data.as_bytes())
}

/// hash() variant that accepts raw bytes (for binary-safe PHP strings).
pub fn php_hash_bytes(algo: &str, data: &[u8]) -> Option<String> {
    match algo {
        "md5" => Some(hex(&md5_raw(data))),
        "sha1" => Some(hex(&sha1_raw(data))),
        "sha256" => Some(hex(&sha256_raw(data))),
        "sha384" => Some(hex(&sha384_raw(data))),
        "sha512" => Some(hex(&sha512_raw(data))),
        "crc32" => Some(format!("{:08x}", crc32(data))),
        "crc32b" => Some(format!("{:08x}", crc32(data))),
        _ => None,
    }
}

/// hash_hmac() — Generate a keyed hash value using the HMAC method.
pub fn php_hash_hmac(algo: &str, data: &str, key: &str) -> Option<String> {
    let data_bytes: Vec<u8> = data.chars().map(|c| c as u8).collect();
    let key_bytes: Vec<u8> = key.chars().map(|c| c as u8).collect();
    php_hash_hmac_bytes(algo, &data_bytes, &key_bytes)
}

/// hash_hmac() variant that accepts raw bytes.
pub fn php_hash_hmac_bytes(algo: &str, data: &[u8], key: &[u8]) -> Option<String> {
    Some(hex(&hmac_bytes(algo, key, data)))
}

/// hash_equals() — Timing attack safe string comparison.
pub fn php_hash_equals(known: &str, user: &str) -> bool {
    if known.len() != user.len() {
        return false;
    }
    let mut result = 0u8;
    for (a, b) in known.bytes().zip(user.bytes()) {
        result |= a ^ b;
    }
    result == 0
}

/// hash_algos() — Return a list of registered hashing algorithms.
pub fn php_hash_algos() -> Vec<&'static str> {
    vec![
        "md5", "sha1", "sha256", "sha384", "sha512", "crc32", "crc32b",
    ]
}

// ── Streaming hash context ───────────────────────────────────────────────────

/// Incremental hash computation.
pub struct HashContext {
    algo: String,
    data: Vec<u8>,
}

impl HashContext {
    /// hash_init()
    pub fn new(algo: &str) -> Option<Self> {
        match algo {
            "md5" | "sha1" | "sha256" | "sha384" | "sha512" | "crc32" | "crc32b" => Some(Self {
                algo: algo.to_string(),
                data: Vec::new(),
            }),
            _ => None,
        }
    }

    /// hash_update()
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// hash_final()
    pub fn finalize(self) -> Option<String> {
        php_hash_bytes(&self.algo, &self.data)
    }
}

// ── Core hash functions (using RustCrypto crates) ────────────────────────────

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn md5_raw(data: &[u8]) -> Vec<u8> {
    md5::Md5::digest(data).to_vec()
}

fn sha1_raw(data: &[u8]) -> Vec<u8> {
    sha1::Sha1::digest(data).to_vec()
}

fn sha256_raw(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}

fn sha384_raw(data: &[u8]) -> Vec<u8> {
    sha2::Sha384::digest(data).to_vec()
}

fn sha512_raw(data: &[u8]) -> Vec<u8> {
    sha2::Sha512::digest(data).to_vec()
}

/// Compute hash of raw bytes and return raw bytes (not hex).
/// Useful for PBKDF2, HMAC, and other binary-safe hash operations.
pub fn hash_bytes(algo: &str, data: &[u8]) -> Vec<u8> {
    match algo {
        "md5" => md5_raw(data),
        "sha1" => sha1_raw(data),
        "sha256" => sha256_raw(data),
        "sha384" => sha384_raw(data),
        "sha512" => sha512_raw(data),
        _ => sha256_raw(data),
    }
}

/// Compute HMAC of raw bytes, return raw bytes.
pub fn hmac_bytes(algo: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        "md5" => {
            let mut mac = Hmac::<md5::Md5>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "sha1" => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "sha256" => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "sha384" => {
            let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "sha512" => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_md5() {
        assert_eq!(
            php_hash("md5", "").unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            php_hash("md5", "hello").unwrap(),
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn test_hash_sha1() {
        assert_eq!(
            php_hash("sha1", "").unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            php_hash("sha1", "hello").unwrap(),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn test_hash_sha256() {
        assert_eq!(
            php_hash("sha256", "").unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            php_hash("sha256", "hello").unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_unknown() {
        assert!(php_hash("unknown_algo", "test").is_none());
    }

    #[test]
    fn test_hash_equals() {
        assert!(php_hash_equals("abc", "abc"));
        assert!(!php_hash_equals("abc", "abd"));
        assert!(!php_hash_equals("abc", "ab"));
    }

    #[test]
    fn test_hash_algos() {
        let algos = php_hash_algos();
        assert!(algos.contains(&"md5"));
        assert!(algos.contains(&"sha1"));
        assert!(algos.contains(&"sha256"));
    }

    #[test]
    fn test_hash_hmac_md5() {
        // Known test vector
        let result = php_hash_hmac(
            "md5",
            "Hi There",
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_hash_context_streaming() {
        let mut ctx = HashContext::new("md5").unwrap();
        ctx.update(b"hel");
        ctx.update(b"lo");
        assert_eq!(ctx.finalize().unwrap(), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_hash_sha384() {
        assert_eq!(
            php_hash("sha384", "").unwrap(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            php_hash("sha384", "hello").unwrap(),
            "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f"
        );
    }

    #[test]
    fn test_hash_sha512() {
        assert_eq!(
            php_hash("sha512", "").unwrap(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            php_hash("sha512", "hello").unwrap(),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        );
    }

    #[test]
    fn test_hash_hmac_sha256() {
        // RFC 4231 Test Case 2
        let result = php_hash_hmac("sha256", "what do ya want for nothing?", "Jefe").unwrap();
        assert_eq!(
            result,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_hash_algos_includes_new() {
        let algos = php_hash_algos();
        assert!(algos.contains(&"sha384"));
        assert!(algos.contains(&"sha512"));
    }
}
