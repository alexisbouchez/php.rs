//! PHP sodium extension implementation for php.rs
//!
//! Provides sodium_* functions for modern cryptographic operations.
//! Uses real cryptographic implementations via `crypto_secretbox`, `crypto_box`,
//! `ed25519-dalek`, and `argon2` crates.

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;

/// Sodium constants matching PHP's ext/sodium values.
pub mod constants {
    /// Key size for crypto_secretbox (XSalsa20-Poly1305).
    pub const SODIUM_CRYPTO_SECRETBOX_KEYBYTES: usize = 32;
    /// Nonce size for crypto_secretbox.
    pub const SODIUM_CRYPTO_SECRETBOX_NONCEBYTES: usize = 24;
    /// MAC size for crypto_secretbox.
    pub const SODIUM_CRYPTO_SECRETBOX_MACBYTES: usize = 16;

    /// Key size for crypto_box (Curve25519-XSalsa20-Poly1305).
    pub const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES: usize = 32;
    pub const SODIUM_CRYPTO_BOX_SECRETKEYBYTES: usize = 32;
    pub const SODIUM_CRYPTO_BOX_KEYPAIRBYTES: usize = 64;
    pub const SODIUM_CRYPTO_BOX_NONCEBYTES: usize = 24;
    pub const SODIUM_CRYPTO_BOX_MACBYTES: usize = 16;

    /// Key size for crypto_sign (Ed25519).
    pub const SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES: usize = 32;
    pub const SODIUM_CRYPTO_SIGN_SECRETKEYBYTES: usize = 64;
    pub const SODIUM_CRYPTO_SIGN_KEYPAIRBYTES: usize = 96;
    pub const SODIUM_CRYPTO_SIGN_BYTES: usize = 64;
    /// Ed25519 seed bytes (first 32 bytes of secret key).
    pub const SODIUM_CRYPTO_SIGN_SEEDBYTES: usize = 32;

    /// Constants for crypto_pwhash (Argon2id).
    pub const SODIUM_CRYPTO_PWHASH_SALTBYTES: usize = 16;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE: u64 = 2;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE: u64 = 3;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: u64 = 4;
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE: usize = 67108864; // 64 MB
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE: usize = 268435456; // 256 MB
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: usize = 1073741824; // 1 GB
    pub const SODIUM_CRYPTO_PWHASH_STRBYTES: usize = 128;

    /// Constants for crypto_aead_chacha20poly1305_ietf.
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES: usize = 32;
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES: usize = 12;
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES: usize = 16;
}

// ============================================================
// crypto_secretbox — XSalsa20-Poly1305
// ============================================================

/// Encrypt a message using a secret key and nonce (XSalsa20-Poly1305).
///
/// Equivalent to PHP's `sodium_crypto_secretbox(string $message, string $nonce, string $key): string`.
///
/// Returns MAC(16 bytes) || ciphertext.
pub fn sodium_crypto_secretbox(
    message: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES {
        return Err(format!(
            "sodium_crypto_secretbox(): key must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            key.len()
        ));
    }
    if nonce.len() != constants::SODIUM_CRYPTO_SECRETBOX_NONCEBYTES {
        return Err(format!(
            "sodium_crypto_secretbox(): nonce must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
            nonce.len()
        ));
    }

    let cipher = XSalsa20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), message)
        .map_err(|e| format!("sodium_crypto_secretbox(): encryption failed: {}", e))
}

/// Decrypt a message using a secret key and nonce (XSalsa20-Poly1305).
///
/// Equivalent to PHP's `sodium_crypto_secretbox_open(string $ciphertext, string $nonce, string $key): string|false`.
pub fn sodium_crypto_secretbox_open(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES {
        return Err(format!(
            "sodium_crypto_secretbox_open(): key must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            key.len()
        ));
    }
    if nonce.len() != constants::SODIUM_CRYPTO_SECRETBOX_NONCEBYTES {
        return Err(format!(
            "sodium_crypto_secretbox_open(): nonce must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
            nonce.len()
        ));
    }
    if ciphertext.len() < constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES {
        return Err("sodium_crypto_secretbox_open(): ciphertext too short".to_string());
    }

    let cipher = XSalsa20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| "sodium_crypto_secretbox_open(): decryption failed".to_string())
}

/// Generate a random key for crypto_secretbox.
pub fn sodium_crypto_secretbox_keygen() -> Vec<u8> {
    random_bytes(constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
}

// ============================================================
// crypto_box — Curve25519-XSalsa20-Poly1305
// ============================================================

/// Generate a key pair for crypto_box (Curve25519).
///
/// Returns (secret_key(32) || public_key(32)) as a single 64-byte keypair,
/// matching PHP's convention.
pub fn sodium_crypto_box_keypair() -> Vec<u8> {
    use crypto_box::aead::OsRng;
    let secret = crypto_box::SecretKey::generate(&mut OsRng);
    let public = secret.public_key();

    let mut keypair = Vec::with_capacity(constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES);
    keypair.extend_from_slice(&secret.to_bytes());
    keypair.extend_from_slice(public.as_bytes());
    keypair
}

/// Extract the public key from a crypto_box keypair.
pub fn sodium_crypto_box_publickey(keypair: &[u8]) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_box_publickey(): keypair must be {} bytes",
            constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES
        ));
    }
    Ok(keypair[32..64].to_vec())
}

/// Extract the secret key from a crypto_box keypair.
pub fn sodium_crypto_box_secretkey(keypair: &[u8]) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_box_secretkey(): keypair must be {} bytes",
            constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES
        ));
    }
    Ok(keypair[0..32].to_vec())
}

/// Derive a public key from a secret key.
pub fn sodium_crypto_box_publickey_from_secretkey(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES {
        return Err(format!(
            "sodium_crypto_box_publickey_from_secretkey(): secret_key must be {} bytes",
            constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES
        ));
    }
    let sk_bytes: [u8; 32] = secret_key.try_into().unwrap();
    let secret = crypto_box::SecretKey::from(sk_bytes);
    let public = secret.public_key();
    Ok(public.as_bytes().to_vec())
}

/// Build a keypair from separate secret and public keys.
pub fn sodium_crypto_box_keypair_from_secretkey_and_publickey(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES {
        return Err(
            "sodium_crypto_box_keypair_from_secretkey_and_publickey(): invalid secret key length"
                .to_string(),
        );
    }
    if public_key.len() != constants::SODIUM_CRYPTO_BOX_PUBLICKEYBYTES {
        return Err(
            "sodium_crypto_box_keypair_from_secretkey_and_publickey(): invalid public key length"
                .to_string(),
        );
    }
    let mut keypair = Vec::with_capacity(constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES);
    keypair.extend_from_slice(secret_key);
    keypair.extend_from_slice(public_key);
    Ok(keypair)
}

/// Encrypt a message using public-key cryptography (Curve25519-XSalsa20-Poly1305).
///
/// The keypair parameter is: sender_secret_key(32) || recipient_public_key(32).
pub fn sodium_crypto_box(message: &[u8], nonce: &[u8], keypair: &[u8]) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_box(): keypair must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES,
            keypair.len()
        ));
    }
    if nonce.len() != constants::SODIUM_CRYPTO_BOX_NONCEBYTES {
        return Err(format!(
            "sodium_crypto_box(): nonce must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_BOX_NONCEBYTES,
            nonce.len()
        ));
    }

    let sk_bytes: [u8; 32] = keypair[0..32].try_into().unwrap();
    let pk_bytes: [u8; 32] = keypair[32..64].try_into().unwrap();

    let secret_key = crypto_box::SecretKey::from(sk_bytes);
    let public_key = crypto_box::PublicKey::from(pk_bytes);
    let salsa_box = crypto_box::SalsaBox::new(&public_key, &secret_key);

    salsa_box
        .encrypt(nonce.into(), message)
        .map_err(|e| format!("sodium_crypto_box(): encryption failed: {}", e))
}

/// Decrypt a message using public-key cryptography.
///
/// The keypair parameter is: recipient_secret_key(32) || sender_public_key(32).
pub fn sodium_crypto_box_open(
    ciphertext: &[u8],
    nonce: &[u8],
    keypair: &[u8],
) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_box_open(): keypair must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES,
            keypair.len()
        ));
    }
    if nonce.len() != constants::SODIUM_CRYPTO_BOX_NONCEBYTES {
        return Err(format!(
            "sodium_crypto_box_open(): nonce must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_BOX_NONCEBYTES,
            nonce.len()
        ));
    }
    if ciphertext.len() < constants::SODIUM_CRYPTO_BOX_MACBYTES {
        return Err("sodium_crypto_box_open(): ciphertext too short".to_string());
    }

    let sk_bytes: [u8; 32] = keypair[0..32].try_into().unwrap();
    let pk_bytes: [u8; 32] = keypair[32..64].try_into().unwrap();

    let secret_key = crypto_box::SecretKey::from(sk_bytes);
    let public_key = crypto_box::PublicKey::from(pk_bytes);
    let salsa_box = crypto_box::SalsaBox::new(&public_key, &secret_key);

    salsa_box
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| "sodium_crypto_box_open(): decryption failed".to_string())
}

// ============================================================
// crypto_sign — Ed25519
// ============================================================

/// Generate a key pair for crypto_sign (Ed25519).
///
/// Returns concatenated keypair: secret_key(64) || public_key(32) = 96 bytes.
/// The secret_key is seed(32) || public_key(32) per NaCl convention.
pub fn sodium_crypto_sign_keypair() -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // PHP/NaCl convention: secret_key = seed(32) || public_key(32) = 64 bytes
    let mut keypair = Vec::with_capacity(constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES);
    // Secret key: signing key bytes (seed) + verifying key bytes
    keypair.extend_from_slice(signing_key.as_bytes());
    keypair.extend_from_slice(verifying_key.as_bytes());
    // Then public key
    keypair.extend_from_slice(verifying_key.as_bytes());
    keypair
}

/// Generate an Ed25519 keypair from a seed.
pub fn sodium_crypto_sign_seed_keypair(seed: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != constants::SODIUM_CRYPTO_SIGN_SEEDBYTES {
        return Err(format!(
            "sodium_crypto_sign_seed_keypair(): seed must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_SEEDBYTES
        ));
    }
    use ed25519_dalek::SigningKey;
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed_arr);
    let verifying_key = signing_key.verifying_key();

    let mut keypair = Vec::with_capacity(constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES);
    keypair.extend_from_slice(signing_key.as_bytes());
    keypair.extend_from_slice(verifying_key.as_bytes());
    keypair.extend_from_slice(verifying_key.as_bytes());
    Ok(keypair)
}

/// Extract the public key from a crypto_sign keypair.
pub fn sodium_crypto_sign_publickey(keypair: &[u8]) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_sign_publickey(): keypair must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES
        ));
    }
    // Public key is the last 32 bytes
    Ok(keypair[64..96].to_vec())
}

/// Extract the secret key from a crypto_sign keypair.
pub fn sodium_crypto_sign_secretkey(keypair: &[u8]) -> Result<Vec<u8>, String> {
    if keypair.len() != constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES {
        return Err(format!(
            "sodium_crypto_sign_secretkey(): keypair must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES
        ));
    }
    // Secret key is the first 64 bytes (seed + public)
    Ok(keypair[0..64].to_vec())
}

/// Derive the public key from a secret key.
pub fn sodium_crypto_sign_publickey_from_secretkey(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign_publickey_from_secretkey(): secret_key must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
        ));
    }
    // The seed is the first 32 bytes of the secret key
    let seed: [u8; 32] = secret_key[0..32].try_into().unwrap();
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key().as_bytes().to_vec())
}

/// Build a sign keypair from secret key and public key.
pub fn sodium_crypto_sign_keypair_from_secretkey_and_publickey(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES {
        return Err(
            "sodium_crypto_sign_keypair_from_secretkey_and_publickey(): invalid secret key length"
                .to_string(),
        );
    }
    if public_key.len() != constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES {
        return Err(
            "sodium_crypto_sign_keypair_from_secretkey_and_publickey(): invalid public key length"
                .to_string(),
        );
    }
    let mut keypair = Vec::with_capacity(constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES);
    keypair.extend_from_slice(secret_key);
    keypair.extend_from_slice(public_key);
    Ok(keypair)
}

/// Sign a message using Ed25519.
///
/// Returns signature(64) || message.
pub fn sodium_crypto_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign(): secret_key must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES,
            secret_key.len()
        ));
    }

    use ed25519_dalek::{Signer, SigningKey};
    // First 32 bytes = seed
    let seed: [u8; 32] = secret_key[0..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message);

    let mut output = Vec::with_capacity(constants::SODIUM_CRYPTO_SIGN_BYTES + message.len());
    output.extend_from_slice(&signature.to_bytes());
    output.extend_from_slice(message);
    Ok(output)
}

/// Verify and extract a message from a signed message.
///
/// Returns the original message if the signature is valid.
pub fn sodium_crypto_sign_open(
    signed_message: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    if public_key.len() != constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign_open(): public_key must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,
            public_key.len()
        ));
    }
    if signed_message.len() < constants::SODIUM_CRYPTO_SIGN_BYTES {
        return Err("sodium_crypto_sign_open(): signed message too short".to_string());
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = public_key.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("sodium_crypto_sign_open(): invalid public key: {}", e))?;

    let sig_bytes: [u8; 64] = signed_message[0..64].try_into().unwrap();
    let signature = Signature::from_bytes(&sig_bytes);
    let message = &signed_message[64..];

    verifying_key
        .verify(message, &signature)
        .map_err(|_| "sodium_crypto_sign_open(): signature verification failed".to_string())?;

    Ok(message.to_vec())
}

/// Create a detached signature for a message.
pub fn sodium_crypto_sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign_detached(): secret_key must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
        ));
    }

    use ed25519_dalek::{Signer, SigningKey};
    let seed: [u8; 32] = secret_key[0..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a detached signature.
pub fn sodium_crypto_sign_verify_detached(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> Result<bool, String> {
    if public_key.len() != constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign_verify_detached(): public_key must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
        ));
    }
    if signature.len() != constants::SODIUM_CRYPTO_SIGN_BYTES {
        return Err(format!(
            "sodium_crypto_sign_verify_detached(): signature must be {} bytes",
            constants::SODIUM_CRYPTO_SIGN_BYTES
        ));
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = public_key.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
        format!(
            "sodium_crypto_sign_verify_detached(): invalid public key: {}",
            e
        )
    })?;

    let sig_bytes: [u8; 64] = signature.try_into().unwrap();
    let sig = Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

// ============================================================
// crypto_pwhash — Argon2id
// ============================================================

/// Derive a key from a password using Argon2id.
///
/// Equivalent to PHP's `sodium_crypto_pwhash()`.
pub fn sodium_crypto_pwhash(
    length: usize,
    password: &str,
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> Result<Vec<u8>, String> {
    if salt.len() != constants::SODIUM_CRYPTO_PWHASH_SALTBYTES {
        return Err(format!(
            "sodium_crypto_pwhash(): salt must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_PWHASH_SALTBYTES,
            salt.len()
        ));
    }
    if length == 0 {
        return Err("sodium_crypto_pwhash(): length must be greater than 0".to_string());
    }

    use argon2::{Algorithm, Argon2, Params, Version};
    let mem_kib = (memlimit / 1024) as u32;
    let params = Params::new(mem_kib, opslimit as u32, 1, Some(length))
        .map_err(|e| format!("sodium_crypto_pwhash(): invalid params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; length];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("sodium_crypto_pwhash(): hashing failed: {}", e))?;
    Ok(output)
}

/// Hash a password to a string using Argon2id.
///
/// Equivalent to PHP's `sodium_crypto_pwhash_str()`.
pub fn sodium_crypto_pwhash_str(
    password: &str,
    opslimit: u64,
    memlimit: usize,
) -> Result<String, String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Algorithm, Argon2, Params, Version,
    };
    let mem_kib = (memlimit / 1024) as u32;
    let params = Params::new(mem_kib, opslimit as u32, 1, None)
        .map_err(|e| format!("sodium_crypto_pwhash_str(): invalid params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("sodium_crypto_pwhash_str(): hashing failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a hash string.
///
/// Equivalent to PHP's `sodium_crypto_pwhash_str_verify()`.
pub fn sodium_crypto_pwhash_str_verify(hash: &str, password: &str) -> Result<bool, String> {
    use argon2::{password_hash::PasswordVerifier, Argon2};
    let parsed = argon2::password_hash::PasswordHash::new(hash)
        .map_err(|e| format!("sodium_crypto_pwhash_str_verify(): invalid hash: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ============================================================
// AEAD — ChaCha20-Poly1305 IETF keygen
// ============================================================

/// Generate a random key for AEAD ChaCha20-Poly1305 IETF.
pub fn sodium_crypto_aead_chacha20poly1305_ietf_keygen() -> Vec<u8> {
    random_bytes(constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES)
}

// ============================================================
// Utility functions
// ============================================================

/// Convert binary data to a hexadecimal string.
pub fn sodium_bin2hex(bin: &[u8]) -> String {
    let mut hex = String::with_capacity(bin.len() * 2);
    for &byte in bin {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Convert a hexadecimal string to binary data.
pub fn sodium_hex2bin(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("sodium_hex2bin(): hex string must have even length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let Some(high) = chars.next() {
        let low = chars
            .next()
            .ok_or_else(|| "sodium_hex2bin(): unexpected end of hex string".to_string())?;
        let high_val = hex_char_value(high)?;
        let low_val = hex_char_value(low)?;
        bytes.push((high_val << 4) | low_val);
    }
    Ok(bytes)
}

/// Zero out a buffer's contents securely.
pub fn sodium_memzero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// Compare two buffers in constant time.
///
/// Returns 0 if equal, -1 otherwise.
pub fn sodium_memcmp(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return -1;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    if result == 0 {
        0
    } else {
        -1
    }
}

/// Increment a byte buffer (treated as a little-endian unsigned integer) by 1.
pub fn sodium_increment(buf: &mut [u8]) {
    let mut carry: u16 = 1;
    for byte in buf.iter_mut() {
        let sum = *byte as u16 + carry;
        *byte = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
}

/// Pad a message to a multiple of the block size.
pub fn sodium_pad(message: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 {
        return Err("sodium_pad(): block_size must be greater than 0".to_string());
    }
    let pad_len = block_size - (message.len() % block_size);
    let mut padded = Vec::with_capacity(message.len() + pad_len);
    padded.extend_from_slice(message);
    // ISO 7816-4 style padding: 0x80 followed by zeros
    padded.push(0x80);
    padded.extend(std::iter::repeat_n(0x00, pad_len - 1));
    Ok(padded)
}

/// Remove padding from a message.
pub fn sodium_unpad(padded: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 {
        return Err("sodium_unpad(): block_size must be greater than 0".to_string());
    }
    if padded.is_empty() || padded.len() % block_size != 0 {
        return Err("sodium_unpad(): invalid padding".to_string());
    }

    // Find the 0x80 padding marker from the end
    let mut pos = padded.len() - 1;
    while pos > 0 && padded[pos] == 0x00 {
        pos -= 1;
    }
    if padded[pos] != 0x80 {
        return Err("sodium_unpad(): invalid padding".to_string());
    }
    Ok(padded[..pos].to_vec())
}

// --- Internal helpers ---

/// Generate cryptographically secure random bytes.
fn random_bytes(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex_char_value(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(format!("sodium_hex2bin(): invalid hex character: {}", c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constants ---

    #[test]
    fn test_secretbox_constants() {
        assert_eq!(constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 32);
        assert_eq!(constants::SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, 24);
        assert_eq!(constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES, 16);
    }

    #[test]
    fn test_box_constants() {
        assert_eq!(constants::SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 32);
        assert_eq!(constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 32);
        assert_eq!(constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES, 64);
        assert_eq!(constants::SODIUM_CRYPTO_BOX_NONCEBYTES, 24);
        assert_eq!(constants::SODIUM_CRYPTO_BOX_MACBYTES, 16);
    }

    #[test]
    fn test_sign_constants() {
        assert_eq!(constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 32);
        assert_eq!(constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 64);
        assert_eq!(constants::SODIUM_CRYPTO_SIGN_BYTES, 64);
    }

    #[test]
    fn test_pwhash_constants() {
        assert_eq!(constants::SODIUM_CRYPTO_PWHASH_SALTBYTES, 16);
        assert_eq!(constants::SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, 2);
        assert_eq!(
            constants::SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            67108864
        );
    }

    #[test]
    fn test_aead_constants() {
        assert_eq!(
            constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
            32
        );
        assert_eq!(
            constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
            12
        );
        assert_eq!(
            constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
            16
        );
    }

    // --- Secretbox ---

    #[test]
    fn test_secretbox_encrypt_decrypt() {
        let key = sodium_crypto_secretbox_keygen();
        let nonce = random_bytes(24);
        let message = b"Hello, sodium!";

        let ciphertext = sodium_crypto_secretbox(message, &nonce, &key).unwrap();
        assert_eq!(
            ciphertext.len(),
            constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES + message.len()
        );

        let plaintext = sodium_crypto_secretbox_open(&ciphertext, &nonce, &key).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_secretbox_tamper_detection() {
        let key = sodium_crypto_secretbox_keygen();
        let nonce = random_bytes(24);
        let message = b"Hello, sodium!";

        let mut ciphertext = sodium_crypto_secretbox(message, &nonce, &key).unwrap();
        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        let result = sodium_crypto_secretbox_open(&ciphertext, &nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_wrong_key_length() {
        let result = sodium_crypto_secretbox(b"msg", &[0u8; 24], &[0u8; 16]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("key must be 32 bytes"));
    }

    #[test]
    fn test_secretbox_wrong_nonce_length() {
        let result = sodium_crypto_secretbox(b"msg", &[0u8; 12], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonce must be 24 bytes"));
    }

    #[test]
    fn test_secretbox_open_too_short() {
        let result = sodium_crypto_secretbox_open(&[0u8; 5], &[0u8; 24], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ciphertext too short"));
    }

    #[test]
    fn test_secretbox_empty_message() {
        let key = sodium_crypto_secretbox_keygen();
        let nonce = random_bytes(24);
        let message = b"";

        let ciphertext = sodium_crypto_secretbox(message, &nonce, &key).unwrap();
        assert_eq!(
            ciphertext.len(),
            constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES
        );

        let plaintext = sodium_crypto_secretbox_open(&ciphertext, &nonce, &key).unwrap();
        assert!(plaintext.is_empty());
    }

    // --- Secretbox keygen ---

    #[test]
    fn test_secretbox_keygen() {
        let key = sodium_crypto_secretbox_keygen();
        assert_eq!(key.len(), constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    #[test]
    fn test_secretbox_keygen_nondeterministic() {
        let key1 = sodium_crypto_secretbox_keygen();
        let key2 = sodium_crypto_secretbox_keygen();
        assert_ne!(key1, key2);
    }

    // --- Box ---

    #[test]
    fn test_box_keypair() {
        let keypair = sodium_crypto_box_keypair();
        assert_eq!(keypair.len(), constants::SODIUM_CRYPTO_BOX_KEYPAIRBYTES);
    }

    #[test]
    fn test_box_encrypt_decrypt() {
        // Generate two keypairs (sender and recipient)
        let sender_keypair = sodium_crypto_box_keypair();
        let recipient_keypair = sodium_crypto_box_keypair();

        let sender_sk = &sender_keypair[0..32];
        let sender_pk = &sender_keypair[32..64];
        let recipient_sk = &recipient_keypair[0..32];
        let recipient_pk = &recipient_keypair[32..64];

        let nonce = random_bytes(24);
        let message = b"Public-key crypto!";

        // Encrypt: sender's SK + recipient's PK
        let mut encrypt_keypair = Vec::new();
        encrypt_keypair.extend_from_slice(sender_sk);
        encrypt_keypair.extend_from_slice(recipient_pk);

        let ciphertext = sodium_crypto_box(message, &nonce, &encrypt_keypair).unwrap();
        assert_eq!(
            ciphertext.len(),
            constants::SODIUM_CRYPTO_BOX_MACBYTES + message.len()
        );

        // Decrypt: recipient's SK + sender's PK
        let mut decrypt_keypair = Vec::new();
        decrypt_keypair.extend_from_slice(recipient_sk);
        decrypt_keypair.extend_from_slice(sender_pk);

        let plaintext = sodium_crypto_box_open(&ciphertext, &nonce, &decrypt_keypair).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_box_wrong_keypair_length() {
        let result = sodium_crypto_box(b"msg", &[0u8; 24], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("keypair must be 64 bytes"));
    }

    #[test]
    fn test_box_wrong_nonce_length() {
        let result = sodium_crypto_box(b"msg", &[0u8; 12], &[0u8; 64]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonce must be 24 bytes"));
    }

    #[test]
    fn test_box_open_too_short() {
        let result = sodium_crypto_box_open(&[0u8; 5], &[0u8; 24], &[0u8; 64]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ciphertext too short"));
    }

    #[test]
    fn test_box_publickey_from_secretkey() {
        let keypair = sodium_crypto_box_keypair();
        let sk = &keypair[0..32];
        let pk = &keypair[32..64];

        let derived_pk = sodium_crypto_box_publickey_from_secretkey(sk).unwrap();
        assert_eq!(derived_pk, pk);
    }

    // --- Sign ---

    #[test]
    fn test_sign_keypair() {
        let keypair = sodium_crypto_sign_keypair();
        assert_eq!(keypair.len(), constants::SODIUM_CRYPTO_SIGN_KEYPAIRBYTES);
    }

    #[test]
    fn test_sign_and_open() {
        let keypair = sodium_crypto_sign_keypair();
        let sk = &keypair[0..64];
        let pk = &keypair[64..96];
        let message = b"Sign this message";

        let signed = sodium_crypto_sign(message, sk).unwrap();
        assert_eq!(
            signed.len(),
            constants::SODIUM_CRYPTO_SIGN_BYTES + message.len()
        );

        let opened = sodium_crypto_sign_open(&signed, pk).unwrap();
        assert_eq!(opened, message);
    }

    #[test]
    fn test_sign_detached_verify() {
        let keypair = sodium_crypto_sign_keypair();
        let sk = &keypair[0..64];
        let pk = &keypair[64..96];
        let message = b"Detached signature test";

        let signature = sodium_crypto_sign_detached(message, sk).unwrap();
        assert_eq!(signature.len(), constants::SODIUM_CRYPTO_SIGN_BYTES);

        let valid = sodium_crypto_sign_verify_detached(&signature, message, pk).unwrap();
        assert!(valid);

        // Wrong message should fail
        let invalid = sodium_crypto_sign_verify_detached(&signature, b"wrong", pk).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_sign_wrong_key_length() {
        let result = sodium_crypto_sign(b"msg", &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("secret_key must be 64 bytes"));
    }

    #[test]
    fn test_sign_open_wrong_key_length() {
        let signed = vec![0u8; 128]; // 64 sig + some message
        let result = sodium_crypto_sign_open(&signed, &[0u8; 16]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("public_key must be 32 bytes"));
    }

    #[test]
    fn test_sign_open_too_short() {
        let result = sodium_crypto_sign_open(&[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signed message too short"));
    }

    #[test]
    fn test_sign_open_invalid_signature() {
        let keypair = sodium_crypto_sign_keypair();
        let pk = &keypair[64..96];

        // Forge a signed message with garbage signature
        let mut forged = vec![0xFFu8; 64]; // garbage signature
        forged.extend_from_slice(b"forged message");

        let result = sodium_crypto_sign_open(&forged, pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_publickey_from_secretkey() {
        let keypair = sodium_crypto_sign_keypair();
        let sk = &keypair[0..64];
        let pk = &keypair[64..96];

        let derived_pk = sodium_crypto_sign_publickey_from_secretkey(sk).unwrap();
        assert_eq!(derived_pk, pk);
    }

    // --- Password hashing ---

    #[test]
    fn test_pwhash_basic() {
        let salt = random_bytes(16);
        let result = sodium_crypto_pwhash(
            32,
            "password",
            &salt,
            constants::SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            constants::SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_pwhash_wrong_salt_length() {
        let result = sodium_crypto_pwhash(32, "password", &[0u8; 8], 2, 67108864);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("salt must be 16 bytes"));
    }

    #[test]
    fn test_pwhash_zero_length() {
        let result = sodium_crypto_pwhash(0, "password", &[0u8; 16], 2, 67108864);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("length must be greater than 0"));
    }

    #[test]
    fn test_pwhash_deterministic() {
        let salt = [0x42u8; 16];
        let r1 = sodium_crypto_pwhash(
            32,
            "test",
            &salt,
            constants::SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            constants::SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let r2 = sodium_crypto_pwhash(
            32,
            "test",
            &salt,
            constants::SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            constants::SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_pwhash_str_and_verify() {
        let hash = sodium_crypto_pwhash_str(
            "my_password",
            constants::SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            constants::SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        // Contains argon2id identifier
        assert!(hash.contains("argon2id"));

        // Correct password verifies
        assert!(sodium_crypto_pwhash_str_verify(&hash, "my_password").unwrap());

        // Wrong password doesn't verify
        assert!(!sodium_crypto_pwhash_str_verify(&hash, "wrong_password").unwrap());
    }

    // --- Hex conversion ---

    #[test]
    fn test_bin2hex_empty() {
        assert_eq!(sodium_bin2hex(&[]), "");
    }

    #[test]
    fn test_bin2hex_basic() {
        assert_eq!(sodium_bin2hex(&[0x00, 0xff, 0xab, 0x12]), "00ffab12");
    }

    #[test]
    fn test_bin2hex_all_bytes() {
        let bytes: Vec<u8> = (0..=255).collect();
        let hex = sodium_bin2hex(&bytes);
        assert_eq!(hex.len(), 512);
        assert!(hex.starts_with("000102"));
        assert!(hex.ends_with("fdfeff"));
    }

    #[test]
    fn test_hex2bin_empty() {
        let result = sodium_hex2bin("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_hex2bin_basic() {
        let result = sodium_hex2bin("00ffab12").unwrap();
        assert_eq!(result, vec![0x00, 0xff, 0xab, 0x12]);
    }

    #[test]
    fn test_hex2bin_uppercase() {
        let result = sodium_hex2bin("DEADBEEF").unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex2bin_odd_length() {
        let result = sodium_hex2bin("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("even length"));
    }

    #[test]
    fn test_hex2bin_invalid_char() {
        let result = sodium_hex2bin("zz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid hex character"));
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let hex = sodium_bin2hex(&original);
        let decoded = sodium_hex2bin(&hex).unwrap();
        assert_eq!(decoded, original);
    }

    // --- Memzero ---

    #[test]
    fn test_memzero() {
        let mut buf = vec![0xFF, 0xAB, 0x42, 0x01];
        sodium_memzero(&mut buf);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_memzero_empty() {
        let mut buf: Vec<u8> = Vec::new();
        sodium_memzero(&mut buf);
        assert!(buf.is_empty());
    }

    // --- Memcmp ---

    #[test]
    fn test_memcmp_equal() {
        assert_eq!(sodium_memcmp(&[1, 2, 3], &[1, 2, 3]), 0);
    }

    #[test]
    fn test_memcmp_not_equal() {
        assert_eq!(sodium_memcmp(&[1, 2, 3], &[1, 2, 4]), -1);
    }

    #[test]
    fn test_memcmp_different_length() {
        assert_eq!(sodium_memcmp(&[1, 2], &[1, 2, 3]), -1);
    }

    #[test]
    fn test_memcmp_empty() {
        assert_eq!(sodium_memcmp(&[], &[]), 0);
    }

    // --- Increment ---

    #[test]
    fn test_increment_basic() {
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        sodium_increment(&mut buf);
        assert_eq!(buf, vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_increment_carry() {
        let mut buf = vec![0xFF, 0x00, 0x00, 0x00];
        sodium_increment(&mut buf);
        assert_eq!(buf, vec![0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_increment_overflow() {
        let mut buf = vec![0xFF, 0xFF, 0xFF, 0xFF];
        sodium_increment(&mut buf);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_increment_single_byte() {
        let mut buf = vec![0x41];
        sodium_increment(&mut buf);
        assert_eq!(buf, vec![0x42]);
    }

    // --- Pad / Unpad ---

    #[test]
    fn test_pad_basic() {
        let padded = sodium_pad(b"hello", 16).unwrap();
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..5], b"hello");
        assert_eq!(padded[5], 0x80);
        for byte in &padded[6..] {
            assert_eq!(*byte, 0x00);
        }
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let message = b"Hello, padding!";
        let padded = sodium_pad(message, 16).unwrap();
        let unpadded = sodium_unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, message);
    }

    #[test]
    fn test_pad_zero_block_size() {
        let result = sodium_pad(b"hello", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_zero_block_size() {
        let result = sodium_unpad(b"hello", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_invalid_padding() {
        // 16 bytes of zeros -- no 0x80 marker
        let result = sodium_unpad(&[0u8; 16], 16);
        assert!(result.is_err());
    }

    // --- AEAD keygen ---

    #[test]
    fn test_aead_keygen() {
        let key = sodium_crypto_aead_chacha20poly1305_ietf_keygen();
        assert_eq!(
            key.len(),
            constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES
        );
    }
}
