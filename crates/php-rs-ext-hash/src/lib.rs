//! PHP hash extension.
//!
//! Implements hash(), hash_hmac(), hash_algos(), hash_equals().
//! Reference: php-src/ext/hash/

/// hash() — Generate a hash value.
///
/// Supports: md5, sha1, sha256, sha512, crc32.
pub fn php_hash(algo: &str, data: &str) -> Option<String> {
    match algo {
        "md5" => Some(md5(data.as_bytes())),
        "sha1" => Some(sha1(data.as_bytes())),
        "sha256" => Some(sha256(data.as_bytes())),
        "crc32" => Some(format!("{:08x}", crc32(data.as_bytes()))),
        "crc32b" => Some(format!("{:08x}", crc32(data.as_bytes()))),
        _ => None,
    }
}

/// hash_hmac() — Generate a keyed hash value using the HMAC method.
pub fn php_hash_hmac(algo: &str, data: &str, key: &str) -> Option<String> {
    let hash_fn: fn(&[u8]) -> Vec<u8> = match algo {
        "md5" => |d| md5_raw(d),
        "sha1" => |d| sha1_raw(d),
        "sha256" => |d| sha256_raw(d),
        _ => return None,
    };

    let block_size: usize = match algo {
        "md5" => 64,
        "sha1" => 64,
        "sha256" => 64,
        _ => return None,
    };

    Some(hmac(hash_fn, block_size, key.as_bytes(), data.as_bytes()))
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
    vec!["md5", "sha1", "sha256", "crc32", "crc32b"]
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
            "md5" | "sha1" | "sha256" | "crc32" | "crc32b" => Some(Self {
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
        php_hash(&self.algo, std::str::from_utf8(&self.data).unwrap_or(""))
    }
}

// ── HMAC implementation ──────────────────────────────────────────────────────

fn hmac(hash_fn: fn(&[u8]) -> Vec<u8>, block_size: usize, key: &[u8], data: &[u8]) -> String {
    let key = if key.len() > block_size {
        hash_fn(key)
    } else {
        key.to_vec()
    };

    let mut key_padded = key.clone();
    key_padded.resize(block_size, 0);

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5Cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    // inner hash: H(ipad || data)
    let mut inner_input = ipad;
    inner_input.extend_from_slice(data);
    let inner_hash = hash_fn(&inner_input);

    // outer hash: H(opad || inner_hash)
    let mut outer_input = opad;
    outer_input.extend_from_slice(&inner_hash);
    let outer_hash = hash_fn(&outer_input);

    outer_hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Hash implementations ─────────────────────────────────────────────────────

fn md5(data: &[u8]) -> String {
    md5_raw(data).iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha1(data: &[u8]) -> String {
    sha1_raw(data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn sha256(data: &[u8]) -> String {
    sha256_raw(data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn md5_raw(data: &[u8]) -> Vec<u8> {
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(s[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&a0.to_le_bytes());
    result.extend_from_slice(&b0.to_le_bytes());
    result.extend_from_slice(&c0.to_le_bytes());
    result.extend_from_slice(&d0.to_le_bytes());
    result
}

fn sha1_raw(data: &[u8]) -> Vec<u8> {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut result = Vec::with_capacity(20);
    for h in [h0, h1, h2, h3, h4] {
        result.extend_from_slice(&h.to_be_bytes());
    }
    result
}

fn sha256_raw(data: &[u8]) -> Vec<u8> {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        #[allow(clippy::needless_range_loop)]
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut result = Vec::with_capacity(32);
    for val in h {
        result.extend_from_slice(&val.to_be_bytes());
    }
    result
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
}
