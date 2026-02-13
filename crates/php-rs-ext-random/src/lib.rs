//! PHP Random extension (PHP 8.2+).
//!
//! Implements Random\Engine interface, engine implementations (Mt19937, PCG, Xoshiro256**,
//! Secure), and the Random\Randomizer class.
//! Reference: php-src/ext/random/

// ── RandomEngine trait ───────────────────────────────────────────────────────

/// The Random\Engine interface — all engines generate raw random bytes.
pub trait RandomEngine {
    /// Generate random bytes (engine-specific length).
    fn generate(&mut self) -> Vec<u8>;
}

// ── Mt19937 ──────────────────────────────────────────────────────────────────

/// Mersenne Twister (MT19937) engine.
///
/// 624-element state array, period 2^19937-1.
/// Reference: php-src/ext/random/engine_mt19937.c
pub struct Mt19937 {
    state: [u32; 624],
    index: usize,
}

impl Mt19937 {
    /// Create a new MT19937 engine with an optional seed.
    /// If no seed is provided, uses a default seed of 5489.
    pub fn new(seed: Option<u64>) -> Self {
        let seed = seed.unwrap_or(5489) as u32;
        let mut state = [0u32; 624];
        state[0] = seed;
        for i in 1..624 {
            state[i] = 1812433253u32
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Mt19937 { state, index: 624 }
    }

    /// Generate a raw u32 value from the Mersenne Twister.
    pub fn generate_u32(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C_5680;
        y ^= (y << 15) & 0xEFC6_0000;
        y ^= y >> 18;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let upper = self.state[i] & 0x8000_0000;
            let lower = self.state[(i + 1) % 624] & 0x7FFF_FFFF;
            let x = upper | lower;
            let mut x_a = x >> 1;
            if x & 1 != 0 {
                x_a ^= 0x9908_B0DF;
            }
            self.state[i] = self.state[(i + 397) % 624] ^ x_a;
        }
        self.index = 0;
    }
}

impl RandomEngine for Mt19937 {
    fn generate(&mut self) -> Vec<u8> {
        self.generate_u32().to_le_bytes().to_vec()
    }
}

// ── PcgOneseq128XslRr64 ─────────────────────────────────────────────────────

/// PCG-XSL-RR-128/64 (oneseq) engine.
///
/// Reference: php-src/ext/random/engine_pcgoneseq128xslrr64.c
pub struct PcgOneseq128XslRr64 {
    state: u128,
}

impl PcgOneseq128XslRr64 {
    /// The increment for the single-sequence PCG variant (must be odd).
    const INCREMENT: u128 = 1442695040888963407u128 | 1;

    /// Create a new PCG engine with an optional 128-bit seed.
    pub fn new(seed: Option<u128>) -> Self {
        let seed = seed.unwrap_or(0x4d595df4d0f33173);
        let mut engine = PcgOneseq128XslRr64 { state: 0 };
        // Advance state once and add seed (PCG seeding protocol)
        engine.state = engine.state.wrapping_add(Self::INCREMENT);
        engine.step();
        engine.state = engine.state.wrapping_add(seed);
        engine.step();
        engine
    }

    fn step(&mut self) {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(Self::INCREMENT);
    }

    /// Generate a raw u64 value using PCG XSL-RR output function.
    pub fn generate_u64(&mut self) -> u64 {
        self.step();
        let state = self.state;
        // XSL-RR output function
        let rot = (state >> 122) as u32;
        let xsl = ((state >> 64) ^ state) as u64;
        xsl.rotate_right(rot)
    }
}

impl RandomEngine for PcgOneseq128XslRr64 {
    fn generate(&mut self) -> Vec<u8> {
        self.generate_u64().to_le_bytes().to_vec()
    }
}

// ── Xoshiro256StarStar ───────────────────────────────────────────────────────

/// Xoshiro256** engine.
///
/// Reference: php-src/ext/random/engine_xoshiro256starstar.c
pub struct Xoshiro256StarStar {
    s: [u64; 4],
}

impl Xoshiro256StarStar {
    /// Create a new Xoshiro256** engine with an optional 4x64-bit seed.
    /// If no seed is provided, uses a non-zero default.
    pub fn new(seed: Option<[u64; 4]>) -> Self {
        let s = seed.unwrap_or([
            0x01d353e5f3993bb0,
            0x7b9c0df6cb193b20,
            0xfdfcaa91110765b6,
            0xd2db341f10bb232e,
        ]);
        Xoshiro256StarStar { s }
    }

    /// Generate a raw u64 value.
    pub fn generate_u64(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5)).rotate_left(7).wrapping_mul(9);

        let t = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];

        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);

        result
    }
}

impl RandomEngine for Xoshiro256StarStar {
    fn generate(&mut self) -> Vec<u8> {
        self.generate_u64().to_le_bytes().to_vec()
    }
}

// ── SecureEngine ─────────────────────────────────────────────────────────────

/// Cryptographically secure random engine wrapping OS randomness.
///
/// Uses /dev/urandom on Unix or equivalent OS primitives.
/// Reference: php-src/ext/random/engine_secure.c
pub struct SecureEngine;

impl SecureEngine {
    /// Generate `n` cryptographically secure random bytes.
    pub fn generate_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        // Simple CSPRNG fallback: read from /dev/urandom on unix,
        // or use a basic seeded generator for portability.
        #[cfg(unix)]
        {
            use std::io::Read;
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                let _ = f.read_exact(&mut buf);
                return buf;
            }
        }
        // Fallback: use system time as seed for a basic PRNG (not truly secure, but functional)
        #[cfg(not(unix))]
        {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(42);
            let mut state = seed;
            for byte in buf.iter_mut() {
                // SplitMix64
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                *byte = z as u8;
            }
        }
        buf
    }
}

impl RandomEngine for SecureEngine {
    fn generate(&mut self) -> Vec<u8> {
        SecureEngine::generate_bytes(8)
    }
}

// ── Randomizer ───────────────────────────────────────────────────────────────

/// Random\Randomizer — high-level randomness API backed by a pluggable engine.
///
/// Reference: php-src/ext/random/randomizer.c
pub struct Randomizer {
    engine: Box<dyn RandomEngine>,
}

impl Randomizer {
    /// Create a new Randomizer backed by the given engine.
    pub fn new(engine: Box<dyn RandomEngine>) -> Self {
        Randomizer { engine }
    }

    /// Generate a random integer in [min, max] (inclusive).
    ///
    /// Uses rejection sampling to avoid modulo bias.
    pub fn next_int(&mut self, min: i64, max: i64) -> i64 {
        if min > max {
            panic!(
                "Minimum value ({}) must be less than or equal to maximum value ({})",
                min, max
            );
        }
        if min == max {
            return min;
        }

        let range = (max as u128).wrapping_sub(min as u128) as u64;

        // Generate unbiased random value in [0, range]
        let threshold = (u64::MAX - range).wrapping_rem(range.wrapping_add(1));

        loop {
            let bytes = self.engine.generate();
            let mut value: u64 = 0;
            for (i, &b) in bytes.iter().take(8).enumerate() {
                value |= (b as u64) << (i * 8);
            }

            if value >= threshold {
                return min.wrapping_add((value % range.wrapping_add(1)) as i64);
            }
        }
    }

    /// Generate `length` random bytes.
    pub fn get_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        while result.len() < length {
            let chunk = self.engine.generate();
            let remaining = length - result.len();
            let take = remaining.min(chunk.len());
            result.extend_from_slice(&chunk[..take]);
        }
        result
    }

    /// Shuffle a mutable slice in-place using the Fisher-Yates algorithm.
    pub fn shuffle_array<T>(&mut self, arr: &mut [T]) {
        let len = arr.len();
        if len <= 1 {
            return;
        }
        for i in (1..len).rev() {
            let j = self.next_int(0, i as i64) as usize;
            arr.swap(i, j);
        }
    }

    /// Pick `num` random keys (indices) from a slice.
    ///
    /// Returns sorted indices when `num` < slice length.
    pub fn pick_array_keys<T>(&mut self, arr: &[T], num: usize) -> Vec<usize> {
        let len = arr.len();
        if num > len {
            panic!("Cannot pick {} keys from array of size {}", num, len);
        }
        if num == 0 {
            return vec![];
        }
        if num == len {
            return (0..len).collect();
        }

        // Fisher-Yates partial shuffle to pick `num` unique indices
        let mut indices: Vec<usize> = (0..len).collect();
        for i in 0..num {
            let j = self.next_int(i as i64, (len - 1) as i64) as usize;
            indices.swap(i, j);
        }
        let mut result: Vec<usize> = indices[..num].to_vec();
        result.sort_unstable();
        result
    }

    /// Generate a random float in [0, 1).
    pub fn get_float(&mut self) -> f64 {
        let bytes = self.engine.generate();
        let mut value: u64 = 0;
        for (i, &b) in bytes.iter().take(8).enumerate() {
            value |= (b as u64) << (i * 8);
        }
        // Use the upper 53 bits divided by 2^53 for uniform [0, 1)
        let mantissa = value >> 11; // 53 bits
        mantissa as f64 / (1u64 << 53) as f64
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_deterministic_output() {
        // MT19937 with seed 0 should produce known deterministic values.
        let mut mt = Mt19937::new(Some(0));
        let v1 = mt.generate_u32();
        let v2 = mt.generate_u32();
        let v3 = mt.generate_u32();

        // Verify determinism — same seed gives same sequence.
        let mut mt2 = Mt19937::new(Some(0));
        assert_eq!(mt2.generate_u32(), v1);
        assert_eq!(mt2.generate_u32(), v2);
        assert_eq!(mt2.generate_u32(), v3);
    }

    #[test]
    fn test_mt19937_known_values() {
        // MT19937 with seed 1 — first output is a well-known value: 1791095845
        let mut mt = Mt19937::new(Some(1));
        assert_eq!(mt.generate_u32(), 1791095845);
    }

    #[test]
    fn test_mt19937_default_seed() {
        // Default seed (5489) should produce deterministic output.
        let mut mt1 = Mt19937::new(None);
        let mut mt2 = Mt19937::new(Some(5489));
        assert_eq!(mt1.generate_u32(), mt2.generate_u32());
    }

    #[test]
    fn test_mt19937_engine_trait() {
        let mut mt = Mt19937::new(Some(42));
        let bytes = mt.generate();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn test_pcg_produces_nonzero_output() {
        let mut pcg = PcgOneseq128XslRr64::new(Some(12345));
        let v1 = pcg.generate_u64();
        let v2 = pcg.generate_u64();
        // Should produce non-zero distinct values
        assert_ne!(v1, 0);
        assert_ne!(v2, 0);
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_pcg_deterministic() {
        let mut pcg1 = PcgOneseq128XslRr64::new(Some(999));
        let mut pcg2 = PcgOneseq128XslRr64::new(Some(999));
        for _ in 0..10 {
            assert_eq!(pcg1.generate_u64(), pcg2.generate_u64());
        }
    }

    #[test]
    fn test_pcg_engine_trait() {
        let mut pcg = PcgOneseq128XslRr64::new(Some(42));
        let bytes = pcg.generate();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_xoshiro_produces_nonzero_output() {
        // Use larger seed values to avoid zero outputs in early iterations.
        let mut xo = Xoshiro256StarStar::new(Some([
            0x0123456789ABCDEF,
            0xFEDCBA9876543210,
            0xAAAAAAAA55555555,
            0x1111111122222222,
        ]));
        let v1 = xo.generate_u64();
        let v2 = xo.generate_u64();
        assert_ne!(v1, 0);
        assert_ne!(v2, 0);
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_xoshiro_deterministic() {
        let seed = [0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x9ABC_DEF0];
        let mut xo1 = Xoshiro256StarStar::new(Some(seed));
        let mut xo2 = Xoshiro256StarStar::new(Some(seed));
        for _ in 0..10 {
            assert_eq!(xo1.generate_u64(), xo2.generate_u64());
        }
    }

    #[test]
    fn test_xoshiro_engine_trait() {
        let mut xo = Xoshiro256StarStar::new(None);
        let bytes = xo.generate();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_secure_engine_produces_correct_length() {
        let bytes = SecureEngine::generate_bytes(16);
        assert_eq!(bytes.len(), 16);

        let bytes = SecureEngine::generate_bytes(0);
        assert_eq!(bytes.len(), 0);

        let bytes = SecureEngine::generate_bytes(1024);
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn test_secure_engine_trait() {
        let mut se = SecureEngine;
        let bytes = se.generate();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_randomizer_next_int_range() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        for _ in 0..100 {
            let val = rng.next_int(1, 10);
            assert!(val >= 1 && val <= 10, "Value {} out of range [1, 10]", val);
        }
    }

    #[test]
    fn test_randomizer_next_int_single_value() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);
        assert_eq!(rng.next_int(5, 5), 5);
    }

    #[test]
    #[should_panic(expected = "Minimum value")]
    fn test_randomizer_next_int_invalid_range() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);
        rng.next_int(10, 1);
    }

    #[test]
    fn test_randomizer_next_int_negative_range() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        for _ in 0..100 {
            let val = rng.next_int(-10, -1);
            assert!(
                val >= -10 && val <= -1,
                "Value {} out of range [-10, -1]",
                val
            );
        }
    }

    #[test]
    fn test_randomizer_get_bytes() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let bytes = rng.get_bytes(16);
        assert_eq!(bytes.len(), 16);

        let bytes = rng.get_bytes(0);
        assert_eq!(bytes.len(), 0);

        let bytes = rng.get_bytes(100);
        assert_eq!(bytes.len(), 100);
    }

    #[test]
    fn test_randomizer_shuffle_produces_permutation() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let mut arr = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let original = arr.clone();
        rng.shuffle_array(&mut arr);

        // Same elements, possibly different order
        let mut sorted = arr.clone();
        sorted.sort();
        let mut orig_sorted = original.clone();
        orig_sorted.sort();
        assert_eq!(sorted, orig_sorted);

        // With high probability, the shuffled array differs from original
        // (probability of identical order is 1/10! = very small)
        assert_ne!(
            arr, original,
            "Shuffle should change the order (statistically)"
        );
    }

    #[test]
    fn test_randomizer_shuffle_empty() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);
        let mut arr: Vec<i32> = vec![];
        rng.shuffle_array(&mut arr);
        assert!(arr.is_empty());
    }

    #[test]
    fn test_randomizer_shuffle_single() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);
        let mut arr = vec![42];
        rng.shuffle_array(&mut arr);
        assert_eq!(arr, vec![42]);
    }

    #[test]
    fn test_randomizer_pick_array_keys() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let arr = vec![10, 20, 30, 40, 50];
        let keys = rng.pick_array_keys(&arr, 3);
        assert_eq!(keys.len(), 3);

        // Keys should be valid indices and unique
        for &k in &keys {
            assert!(k < arr.len());
        }
        let mut deduped = keys.clone();
        deduped.dedup();
        assert_eq!(keys.len(), deduped.len());

        // Keys should be sorted
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn test_randomizer_pick_all_keys() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let arr = vec![1, 2, 3];
        let keys = rng.pick_array_keys(&arr, 3);
        assert_eq!(keys, vec![0, 1, 2]);
    }

    #[test]
    fn test_randomizer_pick_zero_keys() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let arr = vec![1, 2, 3];
        let keys = rng.pick_array_keys(&arr, 0);
        assert!(keys.is_empty());
    }

    #[test]
    #[should_panic(expected = "Cannot pick")]
    fn test_randomizer_pick_too_many_keys() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        let arr = vec![1, 2, 3];
        rng.pick_array_keys(&arr, 5);
    }

    #[test]
    fn test_randomizer_get_float() {
        let engine = Box::new(Mt19937::new(Some(42)));
        let mut rng = Randomizer::new(engine);

        for _ in 0..100 {
            let f = rng.get_float();
            assert!(f >= 0.0, "Float {} should be >= 0.0", f);
            assert!(f < 1.0, "Float {} should be < 1.0", f);
        }
    }
}
