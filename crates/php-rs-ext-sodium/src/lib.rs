//! PHP sodium extension implementation for php.rs
//!
//! Provides sodium_* functions for modern cryptographic operations.
//! This is a pure Rust stub implementation that implements the full API surface
//! for compatibility. The stub uses XOR-based operations instead of real
//! NaCl/libsodium primitives. Real crypto will be added via a proper library.

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

    /// Constants for crypto_pwhash (Argon2id).
    pub const SODIUM_CRYPTO_PWHASH_SALTBYTES: usize = 16;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE: u64 = 2;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE: u64 = 3;
    pub const SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: u64 = 4;
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE: usize = 67108864; // 64 MB
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE: usize = 268435456; // 256 MB
    pub const SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: usize = 1073741824; // 1 GB

    /// Constants for crypto_aead_chacha20poly1305_ietf.
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES: usize = 32;
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES: usize = 12;
    pub const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES: usize = 16;
}

/// Encrypt a message using a secret key and nonce (XSalsa20-Poly1305).
///
/// Equivalent to PHP's `sodium_crypto_secretbox(string $message, string $nonce, string $key): string`.
///
/// Stub: XOR-based encryption with a simulated MAC prefix.
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

    // Stub: create a MAC (simulated) + XOR-encrypted ciphertext
    let mut mac = vec![0u8; constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES];
    // Generate deterministic MAC from key, nonce, and message
    let mut state: u64 = 0;
    for &b in key.iter().chain(nonce.iter()).chain(message.iter()) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(b as u64);
    }
    for byte in mac.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }

    // XOR message with key and nonce
    let mut ciphertext = Vec::with_capacity(message.len());
    for (i, &b) in message.iter().enumerate() {
        let k = key[i % key.len()];
        let n = nonce[i % nonce.len()];
        ciphertext.push(b ^ k ^ n);
    }

    // Output = MAC || ciphertext
    let mut output = mac;
    output.extend_from_slice(&ciphertext);
    Ok(output)
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

    // Skip the MAC prefix
    let encrypted = &ciphertext[constants::SODIUM_CRYPTO_SECRETBOX_MACBYTES..];

    // XOR to decrypt (reverse of encrypt)
    let mut plaintext = Vec::with_capacity(encrypted.len());
    for (i, &b) in encrypted.iter().enumerate() {
        let k = key[i % key.len()];
        let n = nonce[i % nonce.len()];
        plaintext.push(b ^ k ^ n);
    }

    Ok(plaintext)
}

/// Generate a random key for crypto_secretbox.
///
/// Equivalent to PHP's `sodium_crypto_secretbox_keygen(): string`.
pub fn sodium_crypto_secretbox_keygen() -> Vec<u8> {
    random_bytes(constants::SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
}

/// Generate a key pair for crypto_box (Curve25519).
///
/// Equivalent to PHP's `sodium_crypto_box_keypair(): string`.
///
/// Returns (public_key, secret_key).
pub fn sodium_crypto_box_keypair() -> (Vec<u8>, Vec<u8>) {
    let public_key = random_bytes(constants::SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
    let secret_key = random_bytes(constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
    (public_key, secret_key)
}

/// Encrypt a message using public-key cryptography (Curve25519-XSalsa20-Poly1305).
///
/// Equivalent to PHP's `sodium_crypto_box(string $message, string $nonce, string $keypair): string`.
///
/// The keypair parameter should be 64 bytes: secret_key || public_key (as per PHP convention).
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

    // Stub: MAC + XOR encryption using keypair bytes
    let mut mac = vec![0u8; constants::SODIUM_CRYPTO_BOX_MACBYTES];
    let mut state: u64 = 0;
    for &b in keypair.iter().chain(nonce.iter()).chain(message.iter()) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(b as u64);
    }
    for byte in mac.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }

    let mut ciphertext = Vec::with_capacity(message.len());
    for (i, &b) in message.iter().enumerate() {
        let k = keypair[i % keypair.len()];
        let n = nonce[i % nonce.len()];
        ciphertext.push(b ^ k ^ n);
    }

    let mut output = mac;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a message using public-key cryptography.
///
/// Equivalent to PHP's `sodium_crypto_box_open(string $ciphertext, string $nonce, string $keypair): string|false`.
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

    let encrypted = &ciphertext[constants::SODIUM_CRYPTO_BOX_MACBYTES..];

    let mut plaintext = Vec::with_capacity(encrypted.len());
    for (i, &b) in encrypted.iter().enumerate() {
        let k = keypair[i % keypair.len()];
        let n = nonce[i % nonce.len()];
        plaintext.push(b ^ k ^ n);
    }

    Ok(plaintext)
}

/// Generate a key pair for crypto_sign (Ed25519).
///
/// Equivalent to PHP's `sodium_crypto_sign_keypair(): string`.
///
/// Returns (public_key, secret_key).
pub fn sodium_crypto_sign_keypair() -> (Vec<u8>, Vec<u8>) {
    let public_key = random_bytes(constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
    let secret_key = random_bytes(constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
    (public_key, secret_key)
}

/// Sign a message using Ed25519.
///
/// Equivalent to PHP's `sodium_crypto_sign(string $message, string $secret_key): string`.
///
/// Returns signature || message.
pub fn sodium_crypto_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES {
        return Err(format!(
            "sodium_crypto_sign(): secret_key must be {} bytes, {} given",
            constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES,
            secret_key.len()
        ));
    }

    // Stub: generate a deterministic 64-byte signature
    let mut signature = vec![0u8; constants::SODIUM_CRYPTO_SIGN_BYTES];
    let mut state: u64 = 0;
    for &b in secret_key.iter().chain(message.iter()) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(b as u64);
    }
    for byte in signature.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }

    // Output = signature || message
    let mut output = signature;
    output.extend_from_slice(message);
    Ok(output)
}

/// Verify and extract a message from a signed message.
///
/// Equivalent to PHP's `sodium_crypto_sign_open(string $signed_message, string $public_key): string|false`.
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

    // Stub: always accept the signature and return the message portion
    let message = signed_message[constants::SODIUM_CRYPTO_SIGN_BYTES..].to_vec();
    Ok(message)
}

/// Derive a key from a password using Argon2id.
///
/// Equivalent to PHP's `sodium_crypto_pwhash(int $length, string $password, string $salt,
/// int $opslimit, int $memlimit, ?int $algo = null): string`.
///
/// Stub: produces deterministic output derived from password and salt.
pub fn sodium_crypto_pwhash(
    length: usize,
    password: &str,
    salt: &[u8],
    _opslimit: u64,
    _memlimit: usize,
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

    // Stub: derive bytes from password and salt using simple mixing
    let password_bytes = password.as_bytes();
    let mut output = Vec::with_capacity(length);
    let mut state: u64 = 0xCAFEBABE;
    for &b in salt.iter().chain(password_bytes.iter()) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(b as u64);
    }
    for _ in 0..length {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        output.push((state >> 33) as u8);
    }

    Ok(output)
}

/// Generate a random key for crypto_secretbox.
///
/// Helper that generates the correct number of random bytes.
pub fn sodium_crypto_aead_chacha20poly1305_ietf_keygen() -> Vec<u8> {
    random_bytes(constants::SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES)
}

/// Convert binary data to a hexadecimal string.
///
/// Equivalent to PHP's `sodium_bin2hex(string $string): string`.
pub fn sodium_bin2hex(bin: &[u8]) -> String {
    let mut hex = String::with_capacity(bin.len() * 2);
    for &byte in bin {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Convert a hexadecimal string to binary data.
///
/// Equivalent to PHP's `sodium_hex2bin(string $string, ?string $ignore = null): string`.
pub fn sodium_hex2bin(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
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
///
/// Equivalent to PHP's `sodium_memzero(string &$string): void`.
pub fn sodium_memzero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    // In a real implementation, we would use a volatile write or
    // std::ptr::write_volatile to prevent the compiler from optimizing this away.
}

/// Compare two buffers in constant time.
///
/// Equivalent to PHP's `sodium_memcmp(string $string1, string $string2): int`.
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
///
/// Equivalent to PHP's `sodium_increment(string &$string): void`.
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
///
/// Equivalent to PHP's `sodium_pad(string $string, int $block_size): string`.
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
///
/// Equivalent to PHP's `sodium_unpad(string $string, int $block_size): string`.
pub fn sodium_unpad(padded: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 {
        return Err("sodium_unpad(): block_size must be greater than 0".to_string());
    }
    if padded.is_empty() || !padded.len().is_multiple_of(block_size) {
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

/// Generate random bytes using a simple LCG (stub, not cryptographically secure).
fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    // Use a different seed each call by incorporating the length
    // In a real implementation, this would use OsRng or equivalent.
    let mut state: u64 = 0xFEEDFACE_DEADBEEF_u64.wrapping_add(length as u64);
    // Mix in a timestamp-like value for variety
    state = state.wrapping_mul(6364136223846793005).wrapping_add(0x1234);
    for _ in 0..length {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        bytes.push((state >> 33) as u8);
    }
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
        let key = vec![0x42u8; 32];
        let nonce = vec![0x01u8; 24];
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
        let key = vec![0x42u8; 32];
        let nonce = vec![0x01u8; 24];
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

    // --- Box ---

    #[test]
    fn test_box_keypair() {
        let (pk, sk) = sodium_crypto_box_keypair();
        assert_eq!(pk.len(), constants::SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
        assert_eq!(sk.len(), constants::SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
    }

    #[test]
    fn test_box_encrypt_decrypt() {
        let keypair = vec![0x42u8; 64];
        let nonce = vec![0x01u8; 24];
        let message = b"Public-key crypto!";

        let ciphertext = sodium_crypto_box(message, &nonce, &keypair).unwrap();
        assert_eq!(
            ciphertext.len(),
            constants::SODIUM_CRYPTO_BOX_MACBYTES + message.len()
        );

        let plaintext = sodium_crypto_box_open(&ciphertext, &nonce, &keypair).unwrap();
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

    // --- Sign ---

    #[test]
    fn test_sign_keypair() {
        let (pk, sk) = sodium_crypto_sign_keypair();
        assert_eq!(pk.len(), constants::SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        assert_eq!(sk.len(), constants::SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
    }

    #[test]
    fn test_sign_and_open() {
        let (pk, sk) = sodium_crypto_sign_keypair();
        let message = b"Sign this message";

        let signed = sodium_crypto_sign(message, &sk).unwrap();
        assert_eq!(
            signed.len(),
            constants::SODIUM_CRYPTO_SIGN_BYTES + message.len()
        );

        let opened = sodium_crypto_sign_open(&signed, &pk).unwrap();
        assert_eq!(opened, message);
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

    // --- Password hashing ---

    #[test]
    fn test_pwhash_basic() {
        let salt = vec![0x01u8; 16];
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
        let salt = vec![0x42u8; 16];
        let r1 = sodium_crypto_pwhash(32, "test", &salt, 2, 67108864).unwrap();
        let r2 = sodium_crypto_pwhash(32, "test", &salt, 2, 67108864).unwrap();
        assert_eq!(r1, r2);
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
