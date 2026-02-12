//! PHP openssl extension implementation for php.rs
//!
//! Provides openssl_* functions for encryption, decryption, signing, and key management.
//! Uses real cryptographic implementations via the `aes`, `cbc`, `rsa`, and `getrandom` crates.

use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use ecb::{Decryptor as EcbDecryptor, Encryptor as EcbEncryptor};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};

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

/// An OpenSSL key, wrapping real RSA key material.
#[derive(Debug, Clone)]
pub struct OpensslKey {
    pub key_type: KeyType,
    pub bits: u32,
    /// DER-encoded public key (PKCS#1)
    pub public_key: Vec<u8>,
    /// DER-encoded private key (PKCS#1)
    pub private_key: Vec<u8>,
}

impl OpensslKey {
    /// Get the RSA private key if available.
    pub fn rsa_private_key(&self) -> Option<RsaPrivateKey> {
        if self.private_key.is_empty() {
            return None;
        }
        use rsa::pkcs1::DecodeRsaPrivateKey;
        RsaPrivateKey::from_pkcs1_der(&self.private_key).ok()
    }

    /// Get the RSA public key if available.
    pub fn rsa_public_key(&self) -> Option<RsaPublicKey> {
        if !self.public_key.is_empty() {
            use rsa::pkcs1::DecodeRsaPublicKey;
            if let Ok(pk) = RsaPublicKey::from_pkcs1_der(&self.public_key) {
                return Some(pk);
            }
        }
        // Try deriving from private key
        self.rsa_private_key().map(|sk| sk.to_public_key())
    }
}

/// Encrypt data using a symmetric cipher.
///
/// Equivalent to PHP's `openssl_encrypt(string $data, string $cipher_algo, string $passphrase,
/// int $options = 0, string $iv = "", ...): string|false`.
///
/// Supports AES-128/192/256 in CBC and ECB modes with PKCS7 padding.
pub fn openssl_encrypt(
    data: &str,
    method: &str,
    key: &str,
    options: u32,
    iv: &str,
) -> Result<String, String> {
    let encrypted_bytes = openssl_encrypt_bytes(
        data.as_bytes(),
        method,
        key.as_bytes(),
        options,
        iv.as_bytes(),
    )?;
    let raw_output = (options & constants::OPENSSL_RAW_DATA) != 0;
    if raw_output {
        // Return raw binary bytes as a string (PHP strings are binary-safe)
        Ok(String::from_utf8_lossy(&encrypted_bytes).to_string())
    } else {
        Ok(base64_encode(&encrypted_bytes))
    }
}

/// Encrypt raw bytes using a symmetric cipher. Returns raw ciphertext bytes.
pub fn openssl_encrypt_bytes(
    data: &[u8],
    method: &str,
    key: &[u8],
    options: u32,
    iv: &[u8],
) -> Result<Vec<u8>, String> {
    let method_lower = method.to_lowercase();

    if !is_supported_cipher(&method_lower) {
        return Err(format!("Unknown cipher algorithm: {}", method));
    }

    let (key_len, mode) = parse_cipher_method(&method_lower)?;

    // Zero-pad or truncate key to required length
    let mut padded_key = vec![0u8; key_len];
    let copy_len = key.len().min(key_len);
    padded_key[..copy_len].copy_from_slice(&key[..copy_len]);

    let zero_padding = (options & constants::OPENSSL_ZERO_PADDING) != 0;

    match mode {
        CipherMode::CBC => {
            // IV must be exactly 16 bytes for AES-CBC
            if iv.len() != 16 {
                return Err(format!(
                    "openssl_encrypt(): IV passed is {} bytes long which is longer than the {} expected by selected cipher",
                    iv.len(),
                    16
                ));
            }
            encrypt_aes_cbc(data, &padded_key, iv, zero_padding)
        }
        CipherMode::ECB => encrypt_aes_ecb(data, &padded_key, zero_padding),
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
    let raw_input = (options & constants::OPENSSL_RAW_DATA) != 0;
    let cipher_bytes = if raw_input {
        data.as_bytes().to_vec()
    } else {
        base64_decode(data)?
    };

    let decrypted = openssl_decrypt_bytes(
        &cipher_bytes,
        method,
        key.as_bytes(),
        options,
        iv.as_bytes(),
    )?;
    String::from_utf8(decrypted).map_err(|e| format!("Decryption produced invalid UTF-8: {}", e))
}

/// Decrypt raw bytes using a symmetric cipher. Returns raw plaintext bytes.
pub fn openssl_decrypt_bytes(
    data: &[u8],
    method: &str,
    key: &[u8],
    options: u32,
    iv: &[u8],
) -> Result<Vec<u8>, String> {
    let method_lower = method.to_lowercase();

    if !is_supported_cipher(&method_lower) {
        return Err(format!("Unknown cipher algorithm: {}", method));
    }

    let (key_len, mode) = parse_cipher_method(&method_lower)?;

    // Zero-pad or truncate key to required length
    let mut padded_key = vec![0u8; key_len];
    let copy_len = key.len().min(key_len);
    padded_key[..copy_len].copy_from_slice(&key[..copy_len]);

    let zero_padding = (options & constants::OPENSSL_ZERO_PADDING) != 0;

    match mode {
        CipherMode::CBC => {
            if iv.len() != 16 {
                return Err(format!(
                    "openssl_decrypt(): IV passed is {} bytes long which is longer than the {} expected by selected cipher",
                    iv.len(),
                    16
                ));
            }
            decrypt_aes_cbc(data, &padded_key, iv, zero_padding)
        }
        CipherMode::ECB => decrypt_aes_ecb(data, &padded_key, zero_padding),
    }
}

/// Sign data using a private key.
///
/// Equivalent to PHP's `openssl_sign(string $data, string &$signature, OpenSSLAsymmetricKey $private_key,
/// string|int $algorithm = OPENSSL_ALGO_SHA1): bool`.
///
/// Uses real RSA PKCS#1 v1.5 signing with SHA-256.
pub fn openssl_sign(data: &str, key: &OpensslKey, _algorithm: &str) -> Result<Vec<u8>, String> {
    let private_key = key.rsa_private_key().ok_or_else(|| {
        "openssl_sign(): supplied key param cannot be used for signing".to_string()
    })?;

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(data.as_bytes());
    Ok(signature.to_vec())
}

/// Verify a signature against data using a public key.
///
/// Equivalent to PHP's `openssl_verify(string $data, string $signature,
/// OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $public_key,
/// string|int $algorithm = OPENSSL_ALGO_SHA1): int|false`.
///
/// Returns: 1 if valid, 0 if invalid, or error.
pub fn openssl_verify(
    data: &str,
    signature: &[u8],
    key: &OpensslKey,
    _algorithm: &str,
) -> Result<i32, String> {
    let public_key = key.rsa_public_key().ok_or_else(|| {
        "openssl_verify(): supplied key param cannot be used for verifying".to_string()
    })?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    match verifying_key.verify(data.as_bytes(), &sig) {
        Ok(()) => Ok(1),
        Err(_) => Ok(0),
    }
}

/// Generate cryptographically secure pseudo-random bytes.
///
/// Equivalent to PHP's `openssl_random_pseudo_bytes(int $length, bool &$strong_result = null): string`.
///
/// Uses `getrandom` for OS-level CSPRNG.
pub fn openssl_random_pseudo_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    if length > 0 {
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
    }
    bytes
}

/// Get a list of available cipher methods.
///
/// Equivalent to PHP's `openssl_get_cipher_methods(bool $aliases = false): array`.
pub fn openssl_get_cipher_methods() -> Vec<String> {
    vec![
        "aes-128-cbc".to_string(),
        "aes-128-ecb".to_string(),
        "aes-192-cbc".to_string(),
        "aes-192-ecb".to_string(),
        "aes-256-cbc".to_string(),
        "aes-256-ecb".to_string(),
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
    ]
}

/// Compute a digest (hash) of data.
///
/// Equivalent to PHP's `openssl_digest(string $data, string $digest_algo,
/// bool $binary = false): string|false`.
pub fn openssl_digest(data: &str, method: &str, raw_output: bool) -> Result<String, String> {
    use sha2::{Digest, Sha224, Sha384, Sha512};

    let method_lower = method.to_lowercase();
    let hash_bytes: Vec<u8> = match method_lower.as_str() {
        "sha256" => Sha256::digest(data.as_bytes()).to_vec(),
        "sha224" => Sha224::digest(data.as_bytes()).to_vec(),
        "sha384" => Sha384::digest(data.as_bytes()).to_vec(),
        "sha512" => Sha512::digest(data.as_bytes()).to_vec(),
        _ => return Err(format!("Unknown digest algorithm: {}", method)),
    };

    if raw_output {
        Ok(String::from_utf8_lossy(&hash_bytes).to_string())
    } else {
        Ok(hex_encode(&hash_bytes))
    }
}

/// Generate a new asymmetric key pair.
///
/// Equivalent to PHP's `openssl_pkey_new(?array $options = null): OpenSSLAsymmetricKey|false`.
///
/// Generates a real RSA key pair.
pub fn openssl_pkey_new(config: Option<KeyConfig>) -> Result<OpensslKey, String> {
    let config = config.unwrap_or_default();

    match config.key_type {
        KeyType::RSA => {
            let mut rng = rand::rngs::OsRng;
            let bits = config.bits as usize;
            let private_key = RsaPrivateKey::new(&mut rng, bits)
                .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
            let public_key = private_key.to_public_key();

            use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
            let private_der = private_key
                .to_pkcs1_der()
                .map_err(|e| format!("Failed to encode private key: {}", e))?;
            let public_der = public_key
                .to_pkcs1_der()
                .map_err(|e| format!("Failed to encode public key: {}", e))?;

            Ok(OpensslKey {
                key_type: KeyType::RSA,
                bits: config.bits,
                public_key: public_der.as_bytes().to_vec(),
                private_key: private_der.as_bytes().to_vec(),
            })
        }
        _ => Err(format!(
            "openssl_pkey_new(): key type {:?} not yet supported",
            config.key_type
        )),
    }
}

/// Load a public key from PEM-encoded data.
pub fn openssl_pkey_get_public(pem: &str) -> Result<OpensslKey, String> {
    if !pem.contains("-----BEGIN") {
        return Err("openssl_pkey_get_public(): PEM format expected".to_string());
    }

    // Try PKCS#8 format first, then PKCS#1
    use pkcs8::DecodePublicKey;
    if let Ok(pk) = RsaPublicKey::from_public_key_pem(pem) {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let der = pk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?;
        return Ok(OpensslKey {
            key_type: KeyType::RSA,
            bits: pk.n().bits() as u32,
            public_key: der.as_bytes().to_vec(),
            private_key: Vec::new(),
        });
    }

    // Try PKCS#1 PEM
    use rsa::pkcs1::DecodeRsaPublicKey;
    if let Ok(pk) = RsaPublicKey::from_pkcs1_pem(pem) {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let der = pk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?;
        return Ok(OpensslKey {
            key_type: KeyType::RSA,
            bits: pk.n().bits() as u32,
            public_key: der.as_bytes().to_vec(),
            private_key: Vec::new(),
        });
    }

    Err("openssl_pkey_get_public(): failed to parse public key PEM".to_string())
}

/// Load a private key from PEM-encoded data.
pub fn openssl_pkey_get_private(
    pem: &str,
    _passphrase: Option<&str>,
) -> Result<OpensslKey, String> {
    if !pem.contains("-----BEGIN") {
        return Err("openssl_pkey_get_private(): PEM format expected".to_string());
    }

    // Try PKCS#8 format first
    use pkcs8::DecodePrivateKey;
    if let Ok(sk) = RsaPrivateKey::from_pkcs8_pem(pem) {
        let pk = sk.to_public_key();
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let private_der = sk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode private key: {}", e))?;
        let public_der = pk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?;
        return Ok(OpensslKey {
            key_type: KeyType::RSA,
            bits: pk.n().bits() as u32,
            public_key: public_der.as_bytes().to_vec(),
            private_key: private_der.as_bytes().to_vec(),
        });
    }

    // Try PKCS#1 PEM
    use rsa::pkcs1::DecodeRsaPrivateKey;
    if let Ok(sk) = RsaPrivateKey::from_pkcs1_pem(pem) {
        let pk = sk.to_public_key();
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let private_der = sk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode private key: {}", e))?;
        let public_der = pk
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?;
        return Ok(OpensslKey {
            key_type: KeyType::RSA,
            bits: pk.n().bits() as u32,
            public_key: public_der.as_bytes().to_vec(),
            private_key: private_der.as_bytes().to_vec(),
        });
    }

    Err("openssl_pkey_get_private(): failed to parse private key PEM".to_string())
}

/// Encrypt data with a public key using PKCS#1 v1.5 padding.
///
/// Equivalent to PHP's `openssl_public_encrypt(string $data, string &$encrypted,
/// OpenSSLAsymmetricKey|string $public_key, int $padding = OPENSSL_PKCS1_PADDING): bool`.
pub fn openssl_public_encrypt(data: &[u8], key: &OpensslKey) -> Result<Vec<u8>, String> {
    let public_key = key.rsa_public_key().ok_or_else(|| {
        "openssl_public_encrypt(): supplied key is not a valid public key".to_string()
    })?;
    let mut rng = rand::rngs::OsRng;
    public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, data)
        .map_err(|e| format!("openssl_public_encrypt(): encryption failed: {}", e))
}

/// Decrypt data with a private key using PKCS#1 v1.5 padding.
///
/// Equivalent to PHP's `openssl_private_decrypt(string $data, string &$decrypted,
/// OpenSSLAsymmetricKey|string $private_key, int $padding = OPENSSL_PKCS1_PADDING): bool`.
pub fn openssl_private_decrypt(data: &[u8], key: &OpensslKey) -> Result<Vec<u8>, String> {
    let private_key = key.rsa_private_key().ok_or_else(|| {
        "openssl_private_decrypt(): supplied key is not a valid private key".to_string()
    })?;
    private_key
        .decrypt(rsa::Pkcs1v15Encrypt, data)
        .map_err(|e| format!("openssl_private_decrypt(): decryption failed: {}", e))
}

/// Encrypt data with a private key (PKCS#1 v1.5 type 1 / signature padding).
///
/// Equivalent to PHP's `openssl_private_encrypt(string $data, string &$encrypted,
/// OpenSSLAsymmetricKey|string $private_key, int $padding = OPENSSL_PKCS1_PADDING): bool`.
///
/// This applies PKCS#1 v1.5 type 1 padding then the RSA private key operation.
pub fn openssl_private_encrypt(data: &[u8], key: &OpensslKey) -> Result<Vec<u8>, String> {
    use num_bigint_dig::BigUint;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    let private_key = key.rsa_private_key().ok_or_else(|| {
        "openssl_private_encrypt(): supplied key is not a valid private key".to_string()
    })?;

    let k = private_key.size(); // modulus length in bytes
    if data.len() > k - 11 {
        return Err("openssl_private_encrypt(): data too large for key size".to_string());
    }

    // Build PKCS#1 v1.5 type 1 encoded message: 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || M
    let ps_len = k - data.len() - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat(0xFF).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(data);

    // Raw RSA private key operation: c = m^d mod n
    let m = BigUint::from_bytes_be(&em);
    let c = m.modpow(private_key.d(), private_key.n());
    let mut result = c.to_bytes_be();
    // Pad with leading zeros to key size
    while result.len() < k {
        result.insert(0, 0);
    }
    Ok(result)
}

/// Decrypt data with a public key (reverse of openssl_private_encrypt).
///
/// Equivalent to PHP's `openssl_public_decrypt(string $data, string &$decrypted,
/// OpenSSLAsymmetricKey|string $public_key, int $padding = OPENSSL_PKCS1_PADDING): bool`.
///
/// This applies the RSA public key operation then strips PKCS#1 v1.5 type 1 padding.
pub fn openssl_public_decrypt(data: &[u8], key: &OpensslKey) -> Result<Vec<u8>, String> {
    use num_bigint_dig::BigUint;
    use rsa::traits::PublicKeyParts;

    let public_key = key.rsa_public_key().ok_or_else(|| {
        "openssl_public_decrypt(): supplied key is not a valid public key".to_string()
    })?;

    let k = public_key.size();

    // Raw RSA public key operation: m = c^e mod n
    let c = BigUint::from_bytes_be(data);
    let m = c.modpow(public_key.e(), public_key.n());
    let mut em = m.to_bytes_be();
    // Pad with leading zeros to key size
    while em.len() < k {
        em.insert(0, 0);
    }

    // Strip PKCS#1 v1.5 type 1 padding: 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || M
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return Err("openssl_public_decrypt(): decryption error".to_string());
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    if i >= em.len() || em[i] != 0x00 {
        return Err("openssl_public_decrypt(): decryption error".to_string());
    }
    i += 1; // skip the 0x00 separator

    Ok(em[i..].to_vec())
}

// --- Internal helpers ---

#[derive(Debug, Clone, Copy)]
enum CipherMode {
    CBC,
    ECB,
}

fn parse_cipher_method(method: &str) -> Result<(usize, CipherMode), String> {
    let key_len = if method.contains("128") {
        16
    } else if method.contains("192") {
        24
    } else if method.contains("256") {
        32
    } else {
        return Err(format!(
            "Cannot determine key length for cipher: {}",
            method
        ));
    };

    let mode = if method.contains("ecb") {
        CipherMode::ECB
    } else if method.contains("cbc") {
        CipherMode::CBC
    } else {
        return Err(format!("Unsupported cipher mode in: {}", method));
    };

    Ok((key_len, mode))
}

fn encrypt_aes_cbc(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    zero_padding: bool,
) -> Result<Vec<u8>, String> {
    if zero_padding {
        // OPENSSL_ZERO_PADDING: no padding, data must be a multiple of block size
        if data.len() % 16 != 0 {
            return Err(
                "openssl_encrypt(): data length is not a multiple of the block size".to_string(),
            );
        }
    }

    match key.len() {
        16 => {
            if zero_padding {
                let ct = CbcEncryptor::<Aes128>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data);
                Ok(ct)
            } else {
                let ct = CbcEncryptor::<Aes128>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(data);
                Ok(ct)
            }
        }
        24 => {
            if zero_padding {
                let ct = CbcEncryptor::<Aes192>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data);
                Ok(ct)
            } else {
                let ct = CbcEncryptor::<Aes192>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(data);
                Ok(ct)
            }
        }
        32 => {
            if zero_padding {
                let ct = CbcEncryptor::<Aes256>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data);
                Ok(ct)
            } else {
                let ct = CbcEncryptor::<Aes256>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(data);
                Ok(ct)
            }
        }
        _ => Err(format!("Invalid AES key length: {}", key.len())),
    }
}

fn decrypt_aes_cbc(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    zero_padding: bool,
) -> Result<Vec<u8>, String> {
    match key.len() {
        16 => {
            if zero_padding {
                CbcDecryptor::<Aes128>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                CbcDecryptor::<Aes128>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        24 => {
            if zero_padding {
                CbcDecryptor::<Aes192>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                CbcDecryptor::<Aes192>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        32 => {
            if zero_padding {
                CbcDecryptor::<Aes256>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                CbcDecryptor::<Aes256>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        _ => Err(format!("Invalid AES key length: {}", key.len())),
    }
}

fn encrypt_aes_ecb(data: &[u8], key: &[u8], zero_padding: bool) -> Result<Vec<u8>, String> {
    if zero_padding && data.len() % 16 != 0 {
        return Err(
            "openssl_encrypt(): data length is not a multiple of the block size".to_string(),
        );
    }

    match key.len() {
        16 => {
            if zero_padding {
                Ok(EcbEncryptor::<Aes128>::new(key.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data))
            } else {
                Ok(EcbEncryptor::<Aes128>::new(key.into()).encrypt_padded_vec_mut::<Pkcs7>(data))
            }
        }
        24 => {
            if zero_padding {
                Ok(EcbEncryptor::<Aes192>::new(key.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data))
            } else {
                Ok(EcbEncryptor::<Aes192>::new(key.into()).encrypt_padded_vec_mut::<Pkcs7>(data))
            }
        }
        32 => {
            if zero_padding {
                Ok(EcbEncryptor::<Aes256>::new(key.into())
                    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data))
            } else {
                Ok(EcbEncryptor::<Aes256>::new(key.into()).encrypt_padded_vec_mut::<Pkcs7>(data))
            }
        }
        _ => Err(format!("Invalid AES key length: {}", key.len())),
    }
}

fn decrypt_aes_ecb(data: &[u8], key: &[u8], zero_padding: bool) -> Result<Vec<u8>, String> {
    match key.len() {
        16 => {
            if zero_padding {
                EcbDecryptor::<Aes128>::new(key.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                EcbDecryptor::<Aes128>::new(key.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        24 => {
            if zero_padding {
                EcbDecryptor::<Aes192>::new(key.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                EcbDecryptor::<Aes192>::new(key.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        32 => {
            if zero_padding {
                EcbDecryptor::<Aes256>::new(key.into())
                    .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            } else {
                EcbDecryptor::<Aes256>::new(key.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
        }
        _ => Err(format!("Invalid AES key length: {}", key.len())),
    }
}

fn is_supported_cipher(method: &str) -> bool {
    matches!(
        method,
        "aes-128-cbc"
            | "aes-192-cbc"
            | "aes-256-cbc"
            | "aes-128-ecb"
            | "aes-192-ecb"
            | "aes-256-ecb"
    )
}

pub fn base64_encode(data: &[u8]) -> String {
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

pub fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let chars: Vec<u8> = data.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    if chars.is_empty() {
        return Ok(result);
    }

    if chars.len() % 4 != 0 {
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

pub fn hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

fn hex_decode(data: &str) -> Result<Vec<u8>, String> {
    if data.len() % 2 != 0 {
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
    fn test_openssl_encrypt_decrypt_aes_256_cbc() {
        let key = "k".repeat(32); // 32-byte key for AES-256
        let iv = "i".repeat(16); // 16-byte IV
        let plaintext = "Hello, World!";

        let encrypted = openssl_encrypt(plaintext, "aes-256-cbc", &key, 0, &iv).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted = openssl_decrypt(&encrypted, "aes-256-cbc", &key, 0, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_encrypt_decrypt_aes_128_cbc() {
        let key = "k".repeat(16);
        let iv = "i".repeat(16);
        let plaintext = "Test data for AES-128";

        let encrypted = openssl_encrypt(plaintext, "aes-128-cbc", &key, 0, &iv).unwrap();
        let decrypted = openssl_decrypt(&encrypted, "aes-128-cbc", &key, 0, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_encrypt_decrypt_aes_192_cbc() {
        let key = "k".repeat(24);
        let iv = "i".repeat(16);
        let plaintext = "AES-192 test";

        let encrypted = openssl_encrypt(plaintext, "aes-192-cbc", &key, 0, &iv).unwrap();
        let decrypted = openssl_decrypt(&encrypted, "aes-192-cbc", &key, 0, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_encrypt_decrypt_ecb() {
        let key = "k".repeat(32);
        let plaintext = "ECB mode test!!!"; // exactly 16 bytes for convenience

        let encrypted = openssl_encrypt(plaintext, "aes-256-ecb", &key, 0, "").unwrap();
        let decrypted = openssl_decrypt(&encrypted, "aes-256-ecb", &key, 0, "").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_openssl_encrypt_raw_output() {
        let key = b"k".repeat(32);
        let iv = b"i".repeat(16);
        let plaintext = b"Hello";

        // Raw bytes roundtrip (bypasses String lossy conversion)
        let encrypted = openssl_encrypt_bytes(plaintext, "aes-256-cbc", &key, 0, &iv).unwrap();
        let decrypted = openssl_decrypt_bytes(&encrypted, "aes-256-cbc", &key, 0, &iv).unwrap();
        assert_eq!(decrypted, plaintext);

        // Base64 mode roundtrip via string API
        let encrypted_b64 =
            openssl_encrypt("Hello", "aes-256-cbc", &"k".repeat(32), 0, &"i".repeat(16)).unwrap();
        let decrypted_b64 = openssl_decrypt(
            &encrypted_b64,
            "aes-256-cbc",
            &"k".repeat(32),
            0,
            &"i".repeat(16),
        )
        .unwrap();
        assert_eq!(decrypted_b64, "Hello");
    }

    #[test]
    fn test_openssl_encrypt_unknown_cipher() {
        let result = openssl_encrypt("data", "unknown-cipher", "key", 0, "iv");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown cipher algorithm"));
    }

    #[test]
    fn test_openssl_encrypt_key_padding() {
        // Short key should be zero-padded
        let key_short = "short";
        let iv = "i".repeat(16);
        let plaintext = "test";

        let encrypted = openssl_encrypt(plaintext, "aes-256-cbc", key_short, 0, &iv).unwrap();
        let decrypted = openssl_decrypt(&encrypted, "aes-256-cbc", key_short, 0, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // --- Sign / Verify ---

    #[test]
    fn test_openssl_sign_verify_roundtrip() {
        // Generate a real RSA key (use small size for speed in tests)
        let config = KeyConfig {
            key_type: KeyType::RSA,
            bits: 2048,
            curve_name: None,
        };
        let key = openssl_pkey_new(Some(config)).unwrap();

        let data = "Test data to sign";
        let signature = openssl_sign(data, &key, "sha256").unwrap();
        assert!(!signature.is_empty());

        // Verify with correct data
        let result = openssl_verify(data, &signature, &key, "sha256").unwrap();
        assert_eq!(result, 1);

        // Verify with wrong data should fail
        let result = openssl_verify("wrong data", &signature, &key, "sha256").unwrap();
        assert_eq!(result, 0);
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
    fn test_openssl_verify_no_public_key() {
        let key = OpensslKey {
            key_type: KeyType::RSA,
            bits: 2048,
            public_key: Vec::new(),
            private_key: Vec::new(),
        };
        let result = openssl_verify("data", &[0u8; 64], &key, "sha256");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be used for verifying"));
    }

    // --- Random bytes ---

    #[test]
    fn test_openssl_random_pseudo_bytes_length() {
        let bytes = openssl_random_pseudo_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_openssl_random_pseudo_bytes_zero() {
        let bytes = openssl_random_pseudo_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_openssl_random_pseudo_bytes_nondeterministic() {
        let bytes1 = openssl_random_pseudo_bytes(32);
        let bytes2 = openssl_random_pseudo_bytes(32);
        assert_ne!(bytes1, bytes2);
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
    }

    // --- Digest methods ---

    #[test]
    fn test_openssl_get_md_methods() {
        let methods = openssl_get_md_methods();
        assert!(!methods.is_empty());
        assert!(methods.contains(&"sha256".to_string()));
    }

    // --- Digest ---

    #[test]
    fn test_openssl_digest_sha256() {
        let result = openssl_digest("Hello", "sha256", false);
        assert!(result.is_ok());
        let hex = result.unwrap();
        assert_eq!(hex.len(), 64);
        // Known SHA-256 of "Hello"
        assert_eq!(
            hex,
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
        );
    }

    #[test]
    fn test_openssl_digest_sha512() {
        let result = openssl_digest("data", "sha512", false);
        assert!(result.is_ok());
        let hex = result.unwrap();
        assert_eq!(hex.len(), 128);
    }

    #[test]
    fn test_openssl_digest_unknown_method() {
        let result = openssl_digest("data", "unknown", false);
        assert!(result.is_err());
    }

    // --- Key generation ---

    #[test]
    fn test_openssl_pkey_new_default() {
        let key = openssl_pkey_new(None);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.key_type, KeyType::RSA);
        assert_eq!(key.bits, 2048);
        assert!(!key.public_key.is_empty());
        assert!(!key.private_key.is_empty());
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
