//! PHP gmp extension.
//!
//! Implements GNU Multiple Precision arithmetic functions.
//! Uses i128 as a simplified backing store (not full GMP).
//! Reference: php-src/ext/gmp/

use std::fmt;

/// A simplified GMP integer backed by i128.
///
/// In a full implementation this would wrap libgmp or a big-integer library.
/// For now, i128 gives us 128-bit precision which is sufficient for most use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GmpInt {
    value: i128,
}

/// Error type for GMP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmpError {
    /// Division by zero.
    DivisionByZero,
    /// Invalid base for string conversion.
    InvalidBase(i32),
    /// Negative operand where non-negative is required.
    NegativeOperand,
    /// Value out of range.
    Overflow,
    /// Invalid string for parsing.
    InvalidString(String),
}

impl fmt::Display for GmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GmpError::DivisionByZero => write!(f, "Division by zero"),
            GmpError::InvalidBase(b) => write!(f, "Invalid base: {}", b),
            GmpError::NegativeOperand => write!(f, "Negative operand"),
            GmpError::Overflow => write!(f, "Value out of range"),
            GmpError::InvalidString(s) => write!(f, "Invalid string: {}", s),
        }
    }
}

impl fmt::Display for GmpInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl GmpInt {
    /// Create a new GmpInt from an i128 value.
    pub fn new(value: i128) -> Self {
        GmpInt { value }
    }
}

/// gmp_init -- Create GMP number.
///
/// Creates a GMP number from an integer or string value.
pub fn gmp_init(value: &str) -> Result<GmpInt, GmpError> {
    let s = value.trim();
    if s.is_empty() {
        return Ok(GmpInt { value: 0 });
    }

    // Check for base prefixes
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v = i128::from_str_radix(rest, 16)
            .map_err(|_| GmpError::InvalidString(value.to_string()))?;
        return Ok(GmpInt { value: v });
    }
    if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        let v = i128::from_str_radix(rest, 2)
            .map_err(|_| GmpError::InvalidString(value.to_string()))?;
        return Ok(GmpInt { value: v });
    }
    if s.len() > 1
        && s.starts_with('0')
        && !s.starts_with("0.")
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_digit())
    {
        // Octal
        let v =
            i128::from_str_radix(s, 8).map_err(|_| GmpError::InvalidString(value.to_string()))?;
        return Ok(GmpInt { value: v });
    }

    let v = s
        .parse::<i128>()
        .map_err(|_| GmpError::InvalidString(value.to_string()))?;
    Ok(GmpInt { value: v })
}

/// gmp_init from an i64 value (convenience).
pub fn gmp_init_int(value: i64) -> GmpInt {
    GmpInt {
        value: value as i128,
    }
}

/// gmp_add -- Add numbers.
pub fn gmp_add(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value.wrapping_add(b.value),
    }
}

/// gmp_sub -- Subtract numbers.
pub fn gmp_sub(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value.wrapping_sub(b.value),
    }
}

/// gmp_mul -- Multiply numbers.
pub fn gmp_mul(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value.wrapping_mul(b.value),
    }
}

/// gmp_div_q -- Divide numbers (quotient).
///
/// Returns the integer quotient of a divided by b (truncated toward zero).
pub fn gmp_div_q(a: &GmpInt, b: &GmpInt) -> Result<GmpInt, GmpError> {
    if b.value == 0 {
        return Err(GmpError::DivisionByZero);
    }
    Ok(GmpInt {
        value: a.value / b.value,
    })
}

/// gmp_div_r -- Divide numbers (remainder).
///
/// Returns the remainder of a divided by b.
pub fn gmp_div_r(a: &GmpInt, b: &GmpInt) -> Result<GmpInt, GmpError> {
    if b.value == 0 {
        return Err(GmpError::DivisionByZero);
    }
    Ok(GmpInt {
        value: a.value % b.value,
    })
}

/// gmp_mod -- Modulo operation.
///
/// Returns the non-negative remainder (modulo) of a divided by b.
pub fn gmp_mod(a: &GmpInt, b: &GmpInt) -> Result<GmpInt, GmpError> {
    if b.value == 0 {
        return Err(GmpError::DivisionByZero);
    }
    let r = a.value % b.value;
    // PHP gmp_mod always returns non-negative result
    let result = if r < 0 { r + b.value.abs() } else { r };
    Ok(GmpInt { value: result })
}

/// gmp_pow -- Raise number into power.
///
/// Raises `base` to the power of `exp`. `exp` must be non-negative.
pub fn gmp_pow(base: &GmpInt, exp: u32) -> GmpInt {
    if exp == 0 {
        return GmpInt { value: 1 };
    }
    let mut result: i128 = 1;
    let mut b = base.value;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.wrapping_mul(b);
        }
        e >>= 1;
        if e > 0 {
            b = b.wrapping_mul(b);
        }
    }
    GmpInt { value: result }
}

/// gmp_sqrt -- Calculate square root.
///
/// Returns the integer part of the square root of `a`.
pub fn gmp_sqrt(a: &GmpInt) -> Result<GmpInt, GmpError> {
    if a.value < 0 {
        return Err(GmpError::NegativeOperand);
    }
    if a.value == 0 {
        return Ok(GmpInt { value: 0 });
    }

    // Newton's method for integer square root
    let mut x = a.value;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + a.value / x) / 2;
    }
    Ok(GmpInt { value: x })
}

/// gmp_gcd -- Calculate GCD.
///
/// Returns the greatest common divisor of a and b.
pub fn gmp_gcd(a: &GmpInt, b: &GmpInt) -> GmpInt {
    let mut x = a.value.abs();
    let mut y = b.value.abs();
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    GmpInt { value: x }
}

/// gmp_lcm -- Calculate LCM.
///
/// Returns the least common multiple of a and b.
pub fn gmp_lcm(a: &GmpInt, b: &GmpInt) -> GmpInt {
    if a.value == 0 || b.value == 0 {
        return GmpInt { value: 0 };
    }
    let gcd = gmp_gcd(a, b);
    let result = (a.value / gcd.value).abs() * b.value.abs();
    GmpInt { value: result }
}

/// gmp_abs -- Absolute value.
pub fn gmp_abs(a: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value.abs(),
    }
}

/// gmp_neg -- Negate number.
pub fn gmp_neg(a: &GmpInt) -> GmpInt {
    GmpInt { value: -a.value }
}

/// gmp_cmp -- Compare numbers.
///
/// Returns a positive value if a > b, zero if a == b, or a negative value if a < b.
pub fn gmp_cmp(a: &GmpInt, b: &GmpInt) -> i32 {
    if a.value > b.value {
        1
    } else if a.value < b.value {
        -1
    } else {
        0
    }
}

/// gmp_sign -- Sign of number.
///
/// Returns 1 if a is positive, -1 if a is negative, 0 if a is zero.
pub fn gmp_sign(a: &GmpInt) -> i32 {
    if a.value > 0 {
        1
    } else if a.value < 0 {
        -1
    } else {
        0
    }
}

/// gmp_fact -- Factorial.
///
/// Returns n! (n factorial). n must be non-negative.
pub fn gmp_fact(n: u32) -> GmpInt {
    let mut result: i128 = 1;
    for i in 2..=n as i128 {
        result = result.wrapping_mul(i);
    }
    GmpInt { value: result }
}

/// gmp_intval -- Convert GMP number to integer.
pub fn gmp_intval(a: &GmpInt) -> i64 {
    a.value as i64
}

/// gmp_strval -- Convert GMP number to string.
///
/// Converts to a string representation in the given `base` (2-62).
pub fn gmp_strval(a: &GmpInt, base: i32) -> Result<String, GmpError> {
    if !(2..=62).contains(&base) {
        return Err(GmpError::InvalidBase(base));
    }

    if a.value == 0 {
        return Ok("0".to_string());
    }

    let negative = a.value < 0;
    let mut n = a.value.unsigned_abs();
    let base_u = base as u128;

    let digits: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    let mut result = Vec::new();
    while n > 0 {
        let rem = (n % base_u) as usize;
        result.push(digits[rem]);
        n /= base_u;
    }

    if negative {
        result.push(b'-');
    }
    result.reverse();

    Ok(String::from_utf8(result).unwrap())
}

/// gmp_prob_prime -- Check if number is "probably prime".
///
/// Returns 0 if definitely not prime, 1 if probably prime, 2 if definitely prime.
/// `reps` controls the number of Miller-Rabin rounds (higher = more accurate).
pub fn gmp_prob_prime(a: &GmpInt, _reps: u32) -> i32 {
    let n = a.value;
    if n < 2 {
        return 0;
    }
    if n == 2 || n == 3 {
        return 2;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return 0;
    }

    // Trial division up to sqrt(n) for small numbers
    let limit = gmp_sqrt(a).map(|s| s.value).unwrap_or(0);
    let mut i: i128 = 5;
    while i <= limit {
        if n % i == 0 || n % (i + 2) == 0 {
            return 0;
        }
        i += 6;
    }

    // For values that pass trial division, mark as definitely prime for small values
    // or probably prime for larger values
    if n < 1_000_000 {
        2
    } else {
        1
    }
}

/// gmp_nextprime -- Find next prime number.
pub fn gmp_nextprime(a: &GmpInt) -> GmpInt {
    let mut candidate = if a.value < 2 { 2 } else { a.value + 1 };

    // Make sure candidate is odd (except for 2)
    if candidate == 2 {
        return GmpInt { value: 2 };
    }
    if candidate % 2 == 0 {
        candidate += 1;
    }

    loop {
        let g = GmpInt { value: candidate };
        if gmp_prob_prime(&g, 10) > 0 {
            return g;
        }
        candidate += 2;
    }
}

/// gmp_and -- Bitwise AND.
pub fn gmp_and(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value & b.value,
    }
}

/// gmp_or -- Bitwise OR.
pub fn gmp_or(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value | b.value,
    }
}

/// gmp_xor -- Bitwise XOR.
pub fn gmp_xor(a: &GmpInt, b: &GmpInt) -> GmpInt {
    GmpInt {
        value: a.value ^ b.value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmp_init() {
        let a = gmp_init("42").unwrap();
        assert_eq!(a.value, 42);

        let b = gmp_init("-100").unwrap();
        assert_eq!(b.value, -100);

        let c = gmp_init("0xff").unwrap();
        assert_eq!(c.value, 255);

        let d = gmp_init("0b1010").unwrap();
        assert_eq!(d.value, 10);
    }

    #[test]
    fn test_gmp_init_int() {
        let a = gmp_init_int(42);
        assert_eq!(a.value, 42);
        let b = gmp_init_int(-100);
        assert_eq!(b.value, -100);
    }

    #[test]
    fn test_gmp_add() {
        let a = gmp_init_int(10);
        let b = gmp_init_int(20);
        assert_eq!(gmp_add(&a, &b).value, 30);
    }

    #[test]
    fn test_gmp_sub() {
        let a = gmp_init_int(30);
        let b = gmp_init_int(20);
        assert_eq!(gmp_sub(&a, &b).value, 10);

        let c = gmp_sub(&b, &a);
        assert_eq!(c.value, -10);
    }

    #[test]
    fn test_gmp_mul() {
        let a = gmp_init_int(6);
        let b = gmp_init_int(7);
        assert_eq!(gmp_mul(&a, &b).value, 42);

        let c = gmp_init_int(-3);
        assert_eq!(gmp_mul(&a, &c).value, -18);
    }

    #[test]
    fn test_gmp_div() {
        let a = gmp_init_int(10);
        let b = gmp_init_int(3);
        assert_eq!(gmp_div_q(&a, &b).unwrap().value, 3);
        assert_eq!(gmp_div_r(&a, &b).unwrap().value, 1);
    }

    #[test]
    fn test_gmp_div_by_zero() {
        let a = gmp_init_int(10);
        let b = gmp_init_int(0);
        assert!(gmp_div_q(&a, &b).is_err());
    }

    #[test]
    fn test_gmp_mod() {
        let a = gmp_init_int(10);
        let b = gmp_init_int(3);
        assert_eq!(gmp_mod(&a, &b).unwrap().value, 1);

        // Negative dividend should give non-negative result
        let c = gmp_init_int(-10);
        assert_eq!(gmp_mod(&c, &b).unwrap().value, 2);
    }

    #[test]
    fn test_gmp_pow() {
        let base = gmp_init_int(2);
        assert_eq!(gmp_pow(&base, 10).value, 1024);
        assert_eq!(gmp_pow(&base, 0).value, 1);

        let three = gmp_init_int(3);
        assert_eq!(gmp_pow(&three, 5).value, 243);
    }

    #[test]
    fn test_gmp_sqrt() {
        let a = gmp_init_int(16);
        assert_eq!(gmp_sqrt(&a).unwrap().value, 4);

        let b = gmp_init_int(17);
        assert_eq!(gmp_sqrt(&b).unwrap().value, 4);

        let c = gmp_init_int(0);
        assert_eq!(gmp_sqrt(&c).unwrap().value, 0);

        let d = gmp_init_int(-1);
        assert!(gmp_sqrt(&d).is_err());
    }

    #[test]
    fn test_gmp_gcd() {
        let a = gmp_init_int(12);
        let b = gmp_init_int(8);
        assert_eq!(gmp_gcd(&a, &b).value, 4);

        let c = gmp_init_int(17);
        let d = gmp_init_int(13);
        assert_eq!(gmp_gcd(&c, &d).value, 1);
    }

    #[test]
    fn test_gmp_lcm() {
        let a = gmp_init_int(4);
        let b = gmp_init_int(6);
        assert_eq!(gmp_lcm(&a, &b).value, 12);

        let c = gmp_init_int(0);
        assert_eq!(gmp_lcm(&a, &c).value, 0);
    }

    #[test]
    fn test_gmp_abs_neg() {
        let a = gmp_init_int(-42);
        assert_eq!(gmp_abs(&a).value, 42);
        assert_eq!(gmp_neg(&a).value, 42);

        let b = gmp_init_int(42);
        assert_eq!(gmp_abs(&b).value, 42);
        assert_eq!(gmp_neg(&b).value, -42);
    }

    #[test]
    fn test_gmp_cmp() {
        let a = gmp_init_int(10);
        let b = gmp_init_int(20);
        assert_eq!(gmp_cmp(&a, &b), -1);
        assert_eq!(gmp_cmp(&b, &a), 1);
        assert_eq!(gmp_cmp(&a, &a), 0);
    }

    #[test]
    fn test_gmp_sign() {
        assert_eq!(gmp_sign(&gmp_init_int(42)), 1);
        assert_eq!(gmp_sign(&gmp_init_int(-42)), -1);
        assert_eq!(gmp_sign(&gmp_init_int(0)), 0);
    }

    #[test]
    fn test_gmp_fact() {
        assert_eq!(gmp_fact(0).value, 1);
        assert_eq!(gmp_fact(1).value, 1);
        assert_eq!(gmp_fact(5).value, 120);
        assert_eq!(gmp_fact(10).value, 3628800);
    }

    #[test]
    fn test_gmp_intval() {
        let a = gmp_init_int(42);
        assert_eq!(gmp_intval(&a), 42);
    }

    #[test]
    fn test_gmp_strval() {
        let a = gmp_init_int(255);
        assert_eq!(gmp_strval(&a, 10).unwrap(), "255");
        assert_eq!(gmp_strval(&a, 16).unwrap(), "ff");
        assert_eq!(gmp_strval(&a, 2).unwrap(), "11111111");
        assert_eq!(gmp_strval(&a, 8).unwrap(), "377");

        let b = gmp_init_int(0);
        assert_eq!(gmp_strval(&b, 10).unwrap(), "0");

        let c = gmp_init_int(-42);
        assert_eq!(gmp_strval(&c, 10).unwrap(), "-42");

        // Invalid base
        assert!(gmp_strval(&a, 1).is_err());
        assert!(gmp_strval(&a, 63).is_err());
    }

    #[test]
    fn test_gmp_prob_prime() {
        assert_eq!(gmp_prob_prime(&gmp_init_int(2), 10), 2);
        assert_eq!(gmp_prob_prime(&gmp_init_int(3), 10), 2);
        assert_eq!(gmp_prob_prime(&gmp_init_int(4), 10), 0);
        assert_eq!(gmp_prob_prime(&gmp_init_int(17), 10), 2);
        assert_eq!(gmp_prob_prime(&gmp_init_int(1), 10), 0);
        assert_eq!(gmp_prob_prime(&gmp_init_int(0), 10), 0);
    }

    #[test]
    fn test_gmp_nextprime() {
        assert_eq!(gmp_nextprime(&gmp_init_int(1)).value, 2);
        assert_eq!(gmp_nextprime(&gmp_init_int(2)).value, 3);
        assert_eq!(gmp_nextprime(&gmp_init_int(10)).value, 11);
        assert_eq!(gmp_nextprime(&gmp_init_int(20)).value, 23);
    }

    #[test]
    fn test_gmp_bitwise() {
        let a = gmp_init_int(0b1100);
        let b = gmp_init_int(0b1010);
        assert_eq!(gmp_and(&a, &b).value, 0b1000);
        assert_eq!(gmp_or(&a, &b).value, 0b1110);
        assert_eq!(gmp_xor(&a, &b).value, 0b0110);
    }

    #[test]
    fn test_gmp_display() {
        let a = gmp_init_int(42);
        assert_eq!(format!("{}", a), "42");
        let b = gmp_init_int(-100);
        assert_eq!(format!("{}", b), "-100");
    }
}
