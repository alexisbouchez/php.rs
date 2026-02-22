//! PHP math functions.
//!
//! Reference: php-src/ext/standard/math.c

use std::f64::consts;

// ── 8.4.1: Rounding ─────────────────────────────────────────────────────────

/// abs() — Absolute value.
pub fn php_abs_int(n: i64) -> i64 {
    n.abs()
}

pub fn php_abs_float(n: f64) -> f64 {
    n.abs()
}

/// ceil() — Round fractions up.
pub fn php_ceil(n: f64) -> f64 {
    n.ceil()
}

/// floor() — Round fractions down.
pub fn php_floor(n: f64) -> f64 {
    n.floor()
}

/// round() — Rounds a float.
pub fn php_round(n: f64, precision: i32) -> f64 {
    if precision >= 0 {
        let factor = 10f64.powi(precision);
        (n * factor).round() / factor
    } else {
        let factor = 10f64.powi(-precision);
        (n / factor).round() * factor
    }
}

/// fmod() — Floating point modulo.
pub fn php_fmod(x: f64, y: f64) -> f64 {
    x % y
}

/// intdiv() — Integer division.
pub fn php_intdiv(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        None
    } else {
        Some(a / b)
    }
}

// ── 8.4.2: Min / max ────────────────────────────────────────────────────────

/// max() — Find highest value.
pub fn php_max_int(values: &[i64]) -> Option<i64> {
    values.iter().copied().max()
}

pub fn php_max_float(values: &[f64]) -> Option<f64> {
    values
        .iter()
        .copied()
        .reduce(|a, b| if a >= b { a } else { b })
}

/// min() — Find lowest value.
pub fn php_min_int(values: &[i64]) -> Option<i64> {
    values.iter().copied().min()
}

pub fn php_min_float(values: &[f64]) -> Option<f64> {
    values
        .iter()
        .copied()
        .reduce(|a, b| if a <= b { a } else { b })
}

// ── 8.4.3: Exponential / logarithmic ────────────────────────────────────────

pub fn php_pow(base: f64, exp: f64) -> f64 {
    base.powf(exp)
}

pub fn php_sqrt(n: f64) -> f64 {
    n.sqrt()
}

pub fn php_log(n: f64) -> f64 {
    n.ln()
}

pub fn php_log2(n: f64) -> f64 {
    n.log2()
}

pub fn php_log10(n: f64) -> f64 {
    n.log10()
}

pub fn php_exp(n: f64) -> f64 {
    n.exp()
}

// ── 8.4.4: Trigonometric ─────────────────────────────────────────────────────

pub fn php_sin(n: f64) -> f64 {
    n.sin()
}
pub fn php_cos(n: f64) -> f64 {
    n.cos()
}
pub fn php_tan(n: f64) -> f64 {
    n.tan()
}
pub fn php_asin(n: f64) -> f64 {
    n.asin()
}
pub fn php_acos(n: f64) -> f64 {
    n.acos()
}
pub fn php_atan(n: f64) -> f64 {
    n.atan()
}
pub fn php_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

// ── 8.4.5: Constants ─────────────────────────────────────────────────────────

pub const PHP_M_PI: f64 = consts::PI;
pub const PHP_M_E: f64 = consts::E;
pub const PHP_M_LOG2E: f64 = consts::LOG2_E;
pub const PHP_M_LOG10E: f64 = consts::LOG10_E;
pub const PHP_M_LN2: f64 = consts::LN_2;
pub const PHP_M_LN10: f64 = consts::LN_10;
pub const PHP_M_SQRT2: f64 = consts::SQRT_2;
pub const PHP_INF: f64 = f64::INFINITY;
pub const PHP_NAN: f64 = f64::NAN;
pub const PHP_INT_MAX: i64 = i64::MAX;
pub const PHP_INT_MIN: i64 = i64::MIN;
pub const PHP_INT_SIZE: i64 = 8;
pub const PHP_FLOAT_MAX: f64 = f64::MAX;
pub const PHP_FLOAT_MIN: f64 = f64::MIN_POSITIVE;
pub const PHP_FLOAT_EPSILON: f64 = f64::EPSILON;

/// pi() — Get value of pi.
pub fn php_pi() -> f64 {
    PHP_M_PI
}

// ── 8.4.6: Random ────────────────────────────────────────────────────────────

/// rand() / mt_rand() — Generate a random integer.
///
/// Uses a simple LCG for now; production would use proper CSPRNG for random_int.
pub fn php_rand(min: i64, max: i64) -> i64 {
    if min >= max {
        return min;
    }
    // Simple random using system entropy
    let mut buf = [0u8; 8];
    #[cfg(all(target_os = "macos", feature = "native-io"))]
    {
        unsafe {
            libc::arc4random_buf(buf.as_mut_ptr() as *mut libc::c_void, 8);
        }
    }
    #[cfg(not(all(target_os = "macos", feature = "native-io")))]
    {
        use std::time::SystemTime;
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        buf = seed.to_le_bytes();
    }
    let raw = u64::from_le_bytes(buf);
    let range = (max - min + 1) as u64;
    min + (raw % range) as i64
}

// ── 8.4.7: Base conversion ───────────────────────────────────────────────────

/// base_convert() — Convert a number between arbitrary bases.
pub fn php_base_convert(number: &str, from_base: u32, to_base: u32) -> Option<String> {
    if !(2..=36).contains(&from_base) || !(2..=36).contains(&to_base) {
        return None;
    }
    let n = u64::from_str_radix(number, from_base).ok()?;
    Some(format_radix(n, to_base))
}

/// bindec() — Binary to decimal.
pub fn php_bindec(binary: &str) -> i64 {
    i64::from_str_radix(binary, 2).unwrap_or(0)
}

/// octdec() — Octal to decimal.
pub fn php_octdec(octal: &str) -> i64 {
    i64::from_str_radix(octal, 8).unwrap_or(0)
}

/// hexdec() — Hexadecimal to decimal.
pub fn php_hexdec(hex: &str) -> i64 {
    i64::from_str_radix(hex, 16).unwrap_or(0)
}

/// decbin() — Decimal to binary.
pub fn php_decbin(n: i64) -> String {
    format!("{:b}", n)
}

/// decoct() — Decimal to octal.
pub fn php_decoct(n: i64) -> String {
    format!("{:o}", n)
}

/// dechex() — Decimal to hexadecimal.
pub fn php_dechex(n: i64) -> String {
    format!("{:x}", n)
}

fn format_radix(mut n: u64, radix: u32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::new();
    while n > 0 {
        result.push(digits[(n % radix as u64) as usize]);
        n /= radix as u64;
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abs() {
        assert_eq!(php_abs_int(-42), 42);
        assert_eq!(php_abs_int(42), 42);
        assert_eq!(php_abs_float(-2.75), 2.75);
    }

    #[test]
    fn test_ceil_floor() {
        assert_eq!(php_ceil(4.3), 5.0);
        assert_eq!(php_ceil(9.999), 10.0);
        assert_eq!(php_ceil(-2.75), -2.0);
        assert_eq!(php_floor(4.9), 4.0);
        assert_eq!(php_floor(-2.75), -3.0);
    }

    #[test]
    fn test_round() {
        assert_eq!(php_round(3.4, 0), 3.0);
        assert_eq!(php_round(3.5, 0), 4.0);
        assert_eq!(php_round(5.67891, 2), 5.68);
        assert_eq!(php_round(1234.0, -2), 1200.0);
    }

    #[test]
    fn test_fmod() {
        assert!((php_fmod(10.0, 3.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_intdiv() {
        assert_eq!(php_intdiv(7, 2), Some(3));
        assert_eq!(php_intdiv(7, 0), None);
    }

    #[test]
    fn test_max_min() {
        assert_eq!(php_max_int(&[1, 5, 3, 7, 2]), Some(7));
        assert_eq!(php_min_int(&[1, 5, 3, 7, 2]), Some(1));
        assert_eq!(php_max_float(&[1.5, 9.99, 2.7]), Some(9.99));
        assert_eq!(php_min_float(&[1.5, 9.99, 2.7]), Some(1.5));
    }

    #[test]
    fn test_pow_sqrt() {
        assert_eq!(php_pow(2.0, 10.0), 1024.0);
        assert_eq!(php_sqrt(144.0), 12.0);
        assert!(php_sqrt(-1.0).is_nan());
    }

    #[test]
    fn test_log() {
        assert!((php_log(consts::E) - 1.0).abs() < 1e-10);
        assert!((php_log2(8.0) - 3.0).abs() < 1e-10);
        assert!((php_log10(1000.0) - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_trig() {
        assert!((php_sin(0.0)).abs() < 1e-10);
        assert!((php_cos(0.0) - 1.0).abs() < 1e-10);
        assert!((php_tan(0.0)).abs() < 1e-10);
        assert!((php_asin(1.0) - consts::FRAC_PI_2).abs() < 1e-10);
    }

    #[test]
    fn test_pi() {
        assert_eq!(php_pi(), consts::PI);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PHP_INT_MAX, i64::MAX);
        assert_eq!(PHP_INT_MIN, i64::MIN);
        assert!(PHP_INF.is_infinite());
        assert!(PHP_NAN.is_nan());
    }

    #[test]
    fn test_rand() {
        let r = php_rand(1, 100);
        assert!((1..=100).contains(&r));
    }

    #[test]
    fn test_base_convert() {
        assert_eq!(php_base_convert("ff", 16, 10), Some("255".to_string()));
        assert_eq!(php_base_convert("255", 10, 16), Some("ff".to_string()));
        assert_eq!(php_base_convert("1010", 2, 10), Some("10".to_string()));
    }

    #[test]
    fn test_bindec_octdec_hexdec() {
        assert_eq!(php_bindec("1010"), 10);
        assert_eq!(php_octdec("77"), 63);
        assert_eq!(php_hexdec("ff"), 255);
    }

    #[test]
    fn test_decbin_decoct_dechex() {
        assert_eq!(php_decbin(10), "1010");
        assert_eq!(php_decoct(63), "77");
        assert_eq!(php_dechex(255), "ff");
    }
}
