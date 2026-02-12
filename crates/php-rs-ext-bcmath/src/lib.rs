//! PHP bcmath extension.
//!
//! Implements arbitrary precision mathematics functions.
//! Reference: php-src/ext/bcmath/

use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;

thread_local! {
    static DEFAULT_SCALE: Cell<usize> = const { Cell::new(0) };
}

/// Error type for bcmath operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcMathError {
    /// Division by zero.
    DivisionByZero,
    /// Negative square root.
    NegativeSqrt,
    /// Negative exponent in bcpowmod.
    NegativeExponent,
    /// Modulus is zero in bcpowmod.
    ModulusZero,
    /// Invalid number string.
    InvalidNumber(String),
}

impl fmt::Display for BcMathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BcMathError::DivisionByZero => write!(f, "Division by zero"),
            BcMathError::NegativeSqrt => write!(f, "Square root of negative number"),
            BcMathError::NegativeExponent => write!(f, "Negative exponent"),
            BcMathError::ModulusZero => write!(f, "Modulus is zero"),
            BcMathError::InvalidNumber(s) => write!(f, "Invalid number: {}", s),
        }
    }
}

/// Internal representation of a BC number.
#[derive(Debug, Clone)]
struct BcNum {
    /// Sign: false = positive, true = negative.
    negative: bool,
    /// Integer digits (most significant first). Empty means 0.
    integer: Vec<u8>,
    /// Fractional digits (most significant first).
    fractional: Vec<u8>,
}

impl BcNum {
    fn zero() -> Self {
        BcNum {
            negative: false,
            integer: vec![0],
            fractional: vec![],
        }
    }

    fn is_zero(&self) -> bool {
        self.integer.iter().all(|&d| d == 0) && self.fractional.iter().all(|&d| d == 0)
    }

    /// Parse a string into a BcNum.
    fn parse(s: &str) -> Self {
        let s = s.trim();
        if s.is_empty() {
            return BcNum::zero();
        }

        let (negative, s) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix('+') {
            (false, rest)
        } else {
            (false, s)
        };

        let (int_part, frac_part) = if let Some(dot_pos) = s.find('.') {
            (&s[..dot_pos], &s[dot_pos + 1..])
        } else {
            (s, "")
        };

        let integer: Vec<u8> = if int_part.is_empty() {
            vec![0]
        } else {
            let digits: Vec<u8> = int_part
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .map(|b| b - b'0')
                .collect();
            if digits.is_empty() {
                vec![0]
            } else {
                // Remove leading zeros but keep at least one
                let start = digits
                    .iter()
                    .position(|&d| d != 0)
                    .unwrap_or(digits.len() - 1);
                digits[start..].to_vec()
            }
        };

        let fractional: Vec<u8> = frac_part
            .bytes()
            .filter(|b| b.is_ascii_digit())
            .map(|b| b - b'0')
            .collect();

        let mut num = BcNum {
            negative,
            integer,
            fractional,
        };

        // Zero is never negative
        if num.is_zero() {
            num.negative = false;
        }

        num
    }

    /// Format with the given scale (number of decimal places).
    fn format(&self, scale: usize) -> String {
        let mut result = String::new();

        if self.negative && !self.is_zero() {
            result.push('-');
        }

        // Integer part
        for &d in &self.integer {
            result.push((d + b'0') as char);
        }

        if scale > 0 {
            result.push('.');
            for i in 0..scale {
                if i < self.fractional.len() {
                    result.push((self.fractional[i] + b'0') as char);
                } else {
                    result.push('0');
                }
            }
        }

        result
    }

    /// Get all digits as a single vector (integer + fractional padded to frac_len).
    fn all_digits(&self, frac_len: usize) -> Vec<u8> {
        let mut digits = self.integer.clone();
        for i in 0..frac_len {
            if i < self.fractional.len() {
                digits.push(self.fractional[i]);
            } else {
                digits.push(0);
            }
        }
        digits
    }

    /// Compare absolute values.
    fn cmp_abs(&self, other: &BcNum) -> Ordering {
        // Compare integer parts by length first
        let self_int_len = self.integer.len();
        let other_int_len = other.integer.len();

        if self_int_len != other_int_len {
            return self_int_len.cmp(&other_int_len);
        }

        // Same integer length, compare digit by digit
        for (a, b) in self.integer.iter().zip(other.integer.iter()) {
            if a != b {
                return a.cmp(b);
            }
        }

        // Integer parts are equal, compare fractional parts
        let max_frac = self.fractional.len().max(other.fractional.len());
        for i in 0..max_frac {
            let a = if i < self.fractional.len() {
                self.fractional[i]
            } else {
                0
            };
            let b = if i < other.fractional.len() {
                other.fractional[i]
            } else {
                0
            };
            if a != b {
                return a.cmp(&b);
            }
        }

        Ordering::Equal
    }

    /// Add absolute values (ignoring signs).
    fn add_abs(a: &BcNum, b: &BcNum) -> BcNum {
        let max_frac = a.fractional.len().max(b.fractional.len());
        let a_digits = a.all_digits(max_frac);
        let b_digits = b.all_digits(max_frac);

        let max_len = a_digits.len().max(b_digits.len());
        let mut result = vec![0u8; max_len + 1];
        let mut carry = 0u8;

        for i in (0..max_len).rev() {
            let offset = max_len - a_digits.len();
            let ad = if i >= offset { a_digits[i - offset] } else { 0 };
            let offset_b = max_len - b_digits.len();
            let bd = if i >= offset_b {
                b_digits[i - offset_b]
            } else {
                0
            };
            let sum = ad + bd + carry;
            result[i + 1] = sum % 10;
            carry = sum / 10;
        }
        result[0] = carry;

        // Split back into integer and fractional
        let int_len = result.len() - max_frac;
        let integer_part = result[..int_len].to_vec();
        let frac_part = result[int_len..].to_vec();

        // Remove leading zeros from integer
        let start = integer_part
            .iter()
            .position(|&d| d != 0)
            .unwrap_or(integer_part.len().saturating_sub(1));

        BcNum {
            negative: false,
            integer: integer_part[start..].to_vec(),
            fractional: frac_part,
        }
    }

    /// Subtract absolute values (assumes a >= b in absolute value).
    fn sub_abs(a: &BcNum, b: &BcNum) -> BcNum {
        let max_frac = a.fractional.len().max(b.fractional.len());
        let a_digits = a.all_digits(max_frac);
        let b_digits = b.all_digits(max_frac);

        let max_len = a_digits.len().max(b_digits.len());
        let mut result = vec![0u8; max_len];
        let mut borrow: i8 = 0;

        for i in (0..max_len).rev() {
            let offset_a = max_len - a_digits.len();
            let ad = if i >= offset_a {
                a_digits[i - offset_a] as i8
            } else {
                0i8
            };
            let offset_b = max_len - b_digits.len();
            let bd = if i >= offset_b {
                b_digits[i - offset_b] as i8
            } else {
                0i8
            };
            let mut diff = ad - bd - borrow;
            if diff < 0 {
                diff += 10;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = diff as u8;
        }

        let int_len = result.len() - max_frac;
        let integer_part = result[..int_len].to_vec();
        let frac_part = result[int_len..].to_vec();

        let start = integer_part
            .iter()
            .position(|&d| d != 0)
            .unwrap_or(integer_part.len().saturating_sub(1));

        let integer = if start >= integer_part.len() {
            vec![0]
        } else {
            integer_part[start..].to_vec()
        };

        BcNum {
            negative: false,
            integer,
            fractional: frac_part,
        }
    }

    /// Add two BcNums with signs.
    fn add(a: &BcNum, b: &BcNum) -> BcNum {
        if a.negative == b.negative {
            // Same sign: add magnitudes, keep sign
            let mut result = BcNum::add_abs(a, b);
            result.negative = a.negative;
            if result.is_zero() {
                result.negative = false;
            }
            result
        } else {
            // Different signs: subtract smaller from larger
            match a.cmp_abs(b) {
                Ordering::Greater | Ordering::Equal => {
                    let mut result = BcNum::sub_abs(a, b);
                    result.negative = a.negative;
                    if result.is_zero() {
                        result.negative = false;
                    }
                    result
                }
                Ordering::Less => {
                    let mut result = BcNum::sub_abs(b, a);
                    result.negative = b.negative;
                    if result.is_zero() {
                        result.negative = false;
                    }
                    result
                }
            }
        }
    }

    /// Subtract: a - b.
    fn sub(a: &BcNum, b: &BcNum) -> BcNum {
        let mut neg_b = b.clone();
        neg_b.negative = !neg_b.negative;
        if neg_b.is_zero() {
            neg_b.negative = false;
        }
        BcNum::add(a, &neg_b)
    }

    /// Multiply two BcNums.
    fn mul(a: &BcNum, b: &BcNum) -> BcNum {
        let a_frac_len = a.fractional.len();
        let b_frac_len = b.fractional.len();
        let total_frac = a_frac_len + b_frac_len;

        let a_digits = a.all_digits(a_frac_len);
        let b_digits = b.all_digits(b_frac_len);

        if a_digits.is_empty() || b_digits.is_empty() {
            return BcNum::zero();
        }

        let result_len = a_digits.len() + b_digits.len();
        let mut result = vec![0u32; result_len];

        for (i, &ad) in a_digits.iter().enumerate().rev() {
            for (j, &bd) in b_digits.iter().enumerate().rev() {
                let mul = (ad as u32) * (bd as u32);
                let p1 = i + j;
                let p2 = i + j + 1;
                let sum = mul + result[p2];
                result[p2] = sum % 10;
                result[p1] += sum / 10;
            }
        }

        // Convert to u8
        let result: Vec<u8> = result.iter().map(|&d| d as u8).collect();

        // Split into integer and fractional
        let int_len = result.len() - total_frac;
        let integer_part = if int_len > 0 {
            result[..int_len].to_vec()
        } else {
            vec![0]
        };
        let frac_part = if total_frac > 0 && int_len < result.len() {
            result[int_len..].to_vec()
        } else {
            vec![]
        };

        let start = integer_part
            .iter()
            .position(|&d| d != 0)
            .unwrap_or(integer_part.len().saturating_sub(1));

        let integer = if start >= integer_part.len() {
            vec![0]
        } else {
            integer_part[start..].to_vec()
        };

        let neg = a.negative != b.negative;
        let mut num = BcNum {
            negative: neg,
            integer,
            fractional: frac_part,
        };
        if num.is_zero() {
            num.negative = false;
        }
        num
    }

    /// Divide a by b, returning quotient with `scale` decimal places.
    fn div(a: &BcNum, b: &BcNum, scale: usize) -> Result<BcNum, BcMathError> {
        if b.is_zero() {
            return Err(BcMathError::DivisionByZero);
        }

        let neg = a.negative != b.negative;

        // Convert both to integer representations by removing decimal points
        let a_frac_len = a.fractional.len();
        let b_frac_len = b.fractional.len();

        let mut dividend = a.all_digits(a_frac_len);
        let divisor = b.all_digits(b_frac_len);

        // We need to compute: (a_int) / (b_int) where both are scaled
        // Actually: real_result = (a_int / 10^a_frac) / (b_int / 10^b_frac)
        //                       = (a_int * 10^b_frac) / (b_int * 10^a_frac)
        // So we adjust the dividend: pad with b_frac_len zeros
        // Then the decimal point is at a_frac_len position from the right of dividend originally,
        // but after padding it's at a_frac_len position.
        // Actually, let's simplify: combine everything into one big division.

        // Pad dividend so that: dividend * 10^b_frac_len gives us the numerator
        dividend.resize(dividend.len() + b_frac_len, 0);

        // a has a_frac_len fractional digits, so a_int = a_value * 10^a_frac_len
        // b has b_frac_len fractional digits, so b_int = b_value * 10^b_frac_len
        // We want: a_value / b_value = (a_int / 10^a_frac_len) / (b_int / 10^b_frac_len)
        //        = (a_int * 10^b_frac_len) / (b_int * 10^a_frac_len)
        // We've already multiplied a_int by 10^b_frac_len (the padding above).
        // So now: dividend / divisor gives us the result * 10^a_frac_len
        // This means the fractional point starts a_frac_len digits from the right.

        // We want `scale` fractional digits, so we need to pad dividend with `scale` more zeros
        dividend.resize(dividend.len() + scale, 0);

        // Now perform long division
        let quotient_digits = long_division(&dividend, &divisor);

        // The integer part length:
        // quotient has (dividend.len() - divisor.len() + 1) or similar digits
        // The fractional point is at: quotient.len() - scale - a_frac_len ... hmm
        // Actually: total extra zeros we added = b_frac_len + scale
        // The raw division gives: (a_int * 10^(b_frac_len + scale)) / b_int
        // = (a_value * 10^a_frac_len * 10^(b_frac_len + scale)) / (b_value * 10^b_frac_len)
        // = (a_value / b_value) * 10^(a_frac_len + scale)
        // So the fractional part of the result has (a_frac_len + scale) digits from the right
        // But we only want `scale` fractional digits.

        // Actually, from the quotient, the last (a_frac_len + scale) digits are fractional,
        // but we only want `scale`. So the last a_frac_len digits are extra precision.

        // Simpler approach: result = quotient / 10^a_frac_len, and we want `scale` frac digits.
        // So we truncate the last a_frac_len digits (or reduce precision).

        let total_frac_digits = a_frac_len + scale;

        // The quotient represents result * 10^(a_frac_len + scale)
        // We want integer part and `scale` fractional digits.
        // So from quotient, take all but the last `total_frac_digits` as integer,
        // and the digits from position (len - total_frac_digits) to (len - a_frac_len) as fractional.

        let qlen = quotient_digits.len();
        let (integer, fractional) = if qlen <= total_frac_digits {
            // All digits are fractional or less
            let mut frac = vec![0u8; total_frac_digits - qlen];
            frac.extend_from_slice(&quotient_digits);
            // Take only `scale` digits
            let frac = if frac.len() > scale {
                frac[..scale].to_vec()
            } else {
                let mut f = frac;
                f.resize(scale, 0);
                f
            };
            (vec![0u8], frac)
        } else {
            let int_end = qlen - total_frac_digits;
            let int_part = quotient_digits[..int_end].to_vec();
            let frac_all = &quotient_digits[int_end..];
            let frac = if frac_all.len() >= scale {
                frac_all[..scale].to_vec()
            } else {
                let mut f = frac_all.to_vec();
                f.resize(scale, 0);
                f
            };
            let start = int_part
                .iter()
                .position(|&d| d != 0)
                .unwrap_or(int_part.len().saturating_sub(1));
            let integer = if start >= int_part.len() {
                vec![0]
            } else {
                int_part[start..].to_vec()
            };
            (integer, frac)
        };

        let mut num = BcNum {
            negative: neg,
            integer,
            fractional,
        };
        if num.is_zero() {
            num.negative = false;
        }
        Ok(num)
    }

    /// Truncate fractional part to `scale` digits.
    fn truncate(&mut self, scale: usize) {
        if self.fractional.len() > scale {
            self.fractional.truncate(scale);
        } else {
            self.fractional.resize(scale, 0);
        }
    }
}

/// Long division of two numbers represented as digit arrays.
/// Returns quotient digits.
fn long_division(dividend: &[u8], divisor: &[u8]) -> Vec<u8> {
    // Remove leading zeros from divisor
    let div_start = divisor
        .iter()
        .position(|&d| d != 0)
        .unwrap_or(divisor.len());
    let divisor = &divisor[div_start..];

    if divisor.is_empty() {
        return vec![0];
    }

    // Simple schoolbook long division using trial quotient
    let mut remainder: Vec<u8> = Vec::new();
    let mut quotient: Vec<u8> = Vec::new();

    for &digit in dividend {
        remainder.push(digit);
        // Remove leading zeros from remainder
        while remainder.len() > 1 && remainder[0] == 0 {
            remainder.remove(0);
        }

        // Binary search for the quotient digit (0-9)
        let q = find_quotient_digit(&remainder, divisor);

        // Subtract q * divisor from remainder
        if q > 0 {
            let product = multiply_digit_array(divisor, q);
            remainder = subtract_digit_arrays_right_aligned(&remainder, &product);
            // Remove leading zeros
            while remainder.len() > 1 && remainder[0] == 0 {
                remainder.remove(0);
            }
        }
        quotient.push(q);
    }

    if quotient.is_empty() {
        vec![0]
    } else {
        quotient
    }
}

/// Find the largest digit q (0-9) such that q * divisor <= remainder.
fn find_quotient_digit(remainder: &[u8], divisor: &[u8]) -> u8 {
    // Quick check: if remainder is shorter than divisor, q = 0
    let rem_stripped = strip_leading_zeros(remainder);
    let div_stripped = strip_leading_zeros(divisor);

    if rem_stripped.len() < div_stripped.len() {
        return 0;
    }

    // Binary search for q in [0, 9]
    let mut lo: u8 = 0;
    let mut hi: u8 = 9;
    let mut best: u8 = 0;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let product = multiply_digit_array(divisor, mid);
        if compare_digit_arrays(remainder, &product) != Ordering::Less {
            best = mid;
            if mid == 9 {
                break;
            }
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    best
}

/// Multiply a digit array by a single digit (0-9).
fn multiply_digit_array(a: &[u8], d: u8) -> Vec<u8> {
    if d == 0 {
        return vec![0];
    }
    let mut result = vec![0u8; a.len() + 1];
    let mut carry: u16 = 0;
    for i in (0..a.len()).rev() {
        let prod = (a[i] as u16) * (d as u16) + carry;
        result[i + 1] = (prod % 10) as u8;
        carry = prod / 10;
    }
    result[0] = carry as u8;

    // Strip leading zeros
    let start = result
        .iter()
        .position(|&x| x != 0)
        .unwrap_or(result.len() - 1);
    result[start..].to_vec()
}

/// Strip leading zeros from a digit array, keeping at least one digit.
fn strip_leading_zeros(a: &[u8]) -> &[u8] {
    let start = a
        .iter()
        .position(|&d| d != 0)
        .unwrap_or(a.len().saturating_sub(1));
    if start >= a.len() {
        &a[a.len() - 1..]
    } else {
        &a[start..]
    }
}

/// Compare two digit arrays as unsigned integers.
fn compare_digit_arrays(a: &[u8], b: &[u8]) -> Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);

    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return x.cmp(y);
        }
    }
    Ordering::Equal
}

/// Subtract digit array b from a (a >= b assumed), right-aligned.
fn subtract_digit_arrays_right_aligned(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u8; max_len];
    let mut borrow: i16 = 0;

    for k in 0..max_len {
        let ai = if k < a.len() {
            a[a.len() - 1 - k] as i16
        } else {
            0
        };
        let bi = if k < b.len() {
            b[b.len() - 1 - k] as i16
        } else {
            0
        };
        let mut diff = ai - bi - borrow;
        if diff < 0 {
            diff += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[max_len - 1 - k] = diff as u8;
    }

    result
}

/// bcadd -- Add two arbitrary precision numbers.
///
/// Returns the sum of `left` and `right` with `scale` decimal places.
pub fn bcadd(left: &str, right: &str, scale: Option<usize>) -> String {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let a = BcNum::parse(left);
    let b = BcNum::parse(right);
    let mut result = BcNum::add(&a, &b);
    result.truncate(scale);
    result.format(scale)
}

/// bcsub -- Subtract one arbitrary precision number from another.
///
/// Returns the difference of `left` and `right` with `scale` decimal places.
pub fn bcsub(left: &str, right: &str, scale: Option<usize>) -> String {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let a = BcNum::parse(left);
    let b = BcNum::parse(right);
    let mut result = BcNum::sub(&a, &b);
    result.truncate(scale);
    result.format(scale)
}

/// bcmul -- Multiply two arbitrary precision numbers.
///
/// Returns the product of `left` and `right` with `scale` decimal places.
pub fn bcmul(left: &str, right: &str, scale: Option<usize>) -> String {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let a = BcNum::parse(left);
    let b = BcNum::parse(right);
    let mut result = BcNum::mul(&a, &b);
    result.truncate(scale);
    result.format(scale)
}

/// bcdiv -- Divide two arbitrary precision numbers.
///
/// Returns the quotient of `left` and `right` with `scale` decimal places.
pub fn bcdiv(left: &str, right: &str, scale: Option<usize>) -> Result<String, BcMathError> {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let a = BcNum::parse(left);
    let b = BcNum::parse(right);
    let result = BcNum::div(&a, &b, scale)?;
    Ok(result.format(scale))
}

/// bcmod -- Get modulus of an arbitrary precision number.
///
/// Returns the modulus of `left` divided by `right` with `scale` decimal places.
pub fn bcmod(left: &str, right: &str, scale: Option<usize>) -> Result<String, BcMathError> {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let a = BcNum::parse(left);
    let b = BcNum::parse(right);

    if b.is_zero() {
        return Err(BcMathError::DivisionByZero);
    }

    // mod = a - (a/b)*b (truncated division)
    let quotient = BcNum::div(&a, &b, 0)?;
    let product = BcNum::mul(&quotient, &b);
    let mut remainder = BcNum::sub(&a, &product);
    remainder.truncate(scale);
    if remainder.is_zero() {
        remainder.negative = false;
    }
    Ok(remainder.format(scale))
}

/// bcpow -- Raise an arbitrary precision number to another.
///
/// Returns `base` raised to the power `exponent` with `scale` decimal places.
/// The exponent must be a non-negative integer (fractional part is ignored).
pub fn bcpow(base: &str, exponent: &str, scale: Option<usize>) -> String {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let b = BcNum::parse(base);
    let e = BcNum::parse(exponent);

    // Convert exponent to integer
    let mut exp_val: i64 = 0;
    for &d in &e.integer {
        exp_val = exp_val * 10 + d as i64;
    }
    if e.negative {
        exp_val = -exp_val;
    }

    if exp_val == 0 {
        let one = BcNum {
            negative: false,
            integer: vec![1],
            fractional: vec![0; scale],
        };
        return one.format(scale);
    }

    let is_neg_exp = exp_val < 0;
    let exp_val = exp_val.unsigned_abs();

    // Binary exponentiation
    let mut result = BcNum {
        negative: false,
        integer: vec![1],
        fractional: vec![],
    };
    let mut base_pow = b.clone();
    let mut exp = exp_val;

    // We need extra precision during computation
    let work_scale = scale + base_pow.fractional.len() * (exp_val as usize);

    while exp > 0 {
        if exp & 1 == 1 {
            result = BcNum::mul(&result, &base_pow);
        }
        exp >>= 1;
        if exp > 0 {
            base_pow = BcNum::mul(&base_pow, &base_pow);
        }
    }

    if is_neg_exp {
        let one = BcNum {
            negative: false,
            integer: vec![1],
            fractional: vec![],
        };
        result = BcNum::div(&one, &result, work_scale).unwrap_or(BcNum::zero());
    }

    result.truncate(scale);
    result.format(scale)
}

/// bccomp -- Compare two arbitrary precision numbers.
///
/// Returns 0 if the two operands are equal, 1 if `left` is larger, -1 if `right` is larger.
pub fn bccomp(left: &str, right: &str, scale: Option<usize>) -> i32 {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let mut a = BcNum::parse(left);
    let mut b = BcNum::parse(right);
    a.truncate(scale);
    b.truncate(scale);

    if a.is_zero() && b.is_zero() {
        return 0;
    }

    // Different signs
    if a.negative && !b.negative {
        return -1;
    }
    if !a.negative && b.negative {
        return 1;
    }

    // Same sign
    let cmp = a.cmp_abs(&b);
    if a.negative {
        // Both negative: larger absolute value is smaller
        match cmp {
            Ordering::Greater => -1,
            Ordering::Less => 1,
            Ordering::Equal => 0,
        }
    } else {
        match cmp {
            Ordering::Greater => 1,
            Ordering::Less => -1,
            Ordering::Equal => 0,
        }
    }
}

/// bcsqrt -- Get the square root of an arbitrary precision number.
///
/// Returns the square root of `operand` with `scale` decimal places.
pub fn bcsqrt(operand: &str, scale: Option<usize>) -> Result<String, BcMathError> {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let num = BcNum::parse(operand);

    if num.negative {
        return Err(BcMathError::NegativeSqrt);
    }

    if num.is_zero() {
        let zero = BcNum::zero();
        return Ok(zero.format(scale));
    }

    // Newton's method: x_{n+1} = (x_n + operand/x_n) / 2
    let work_scale = scale + 2;

    // Initial guess: use the integer part length to estimate
    let mut guess = BcNum {
        negative: false,
        integer: vec![1],
        fractional: vec![],
    };

    // Better initial guess based on number of digits
    let n_digits = num.integer.len();
    if n_digits > 1 {
        let half_digits = n_digits.div_ceil(2);
        guess.integer = vec![0; half_digits];
        guess.integer[0] = 1;
    }

    let two = BcNum::parse("2");

    for _ in 0..100 {
        // new_guess = (guess + num/guess) / 2
        let div_result = BcNum::div(&num, &guess, work_scale)?;
        let sum = BcNum::add(&guess, &div_result);
        let new_guess = BcNum::div(&sum, &two, work_scale)?;

        // Check convergence
        let diff = BcNum::sub(&new_guess, &guess);
        let mut diff_check = diff.clone();
        diff_check.negative = false;
        diff_check.truncate(work_scale);

        guess = new_guess;

        // If difference is all zeros at the required scale, we've converged
        let all_zero = diff_check.integer.iter().all(|&d| d == 0)
            && diff_check
                .fractional
                .iter()
                .take(scale + 1)
                .all(|&d| d == 0);
        if all_zero {
            break;
        }
    }

    guess.truncate(scale);
    Ok(guess.format(scale))
}

/// bcpowmod -- Raise an arbitrary precision number to another, reduced by a specified modulus.
///
/// Returns (`base` ^ `exponent`) mod `modulus` with `scale` decimal places.
pub fn bcpowmod(
    base: &str,
    exponent: &str,
    modulus: &str,
    scale: Option<usize>,
) -> Result<String, BcMathError> {
    let scale = scale.unwrap_or_else(|| DEFAULT_SCALE.with(|s| s.get()));
    let b = BcNum::parse(base);
    let e = BcNum::parse(exponent);
    let m = BcNum::parse(modulus);

    if m.is_zero() {
        return Err(BcMathError::ModulusZero);
    }
    if e.negative {
        return Err(BcMathError::NegativeExponent);
    }

    // Convert exponent to integer
    let mut exp_val: u64 = 0;
    for &d in &e.integer {
        exp_val = exp_val * 10 + d as u64;
    }

    if exp_val == 0 {
        // base^0 mod m = 1 mod m
        let one = BcNum::parse("1");
        let result_str = bcmod(&one.format(0), &m.format(0), Some(scale))?;
        return Ok(result_str);
    }

    // Modular exponentiation using binary method
    let m_str = m.format(m.fractional.len());
    let mut result = BcNum::parse("1");
    let mut base_pow = b.clone();

    // Reduce base mod m first
    let base_mod = bcmod(&base_pow.format(base_pow.fractional.len()), &m_str, Some(0))?;
    base_pow = BcNum::parse(&base_mod);

    while exp_val > 0 {
        if exp_val & 1 == 1 {
            result = BcNum::mul(&result, &base_pow);
            let r_str = bcmod(&result.format(result.fractional.len()), &m_str, Some(0))?;
            result = BcNum::parse(&r_str);
        }
        exp_val >>= 1;
        if exp_val > 0 {
            base_pow = BcNum::mul(&base_pow, &base_pow);
            let bp_str = bcmod(&base_pow.format(base_pow.fractional.len()), &m_str, Some(0))?;
            base_pow = BcNum::parse(&bp_str);
        }
    }

    result.truncate(scale);
    Ok(result.format(scale))
}

/// bcscale -- Set or get default scale parameter for all bc math functions.
///
/// If `scale` is `Some`, sets the default scale and returns the old value.
/// If `scale` is `None`, returns the current default scale.
pub fn bcscale(scale: Option<usize>) -> usize {
    DEFAULT_SCALE.with(|s| {
        let old = s.get();
        if let Some(new_scale) = scale {
            s.set(new_scale);
        }
        old
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcadd_integers() {
        // PHP bcadd("1", "2", 0) returns "3"
        assert_eq!(bcadd("1", "2", Some(0)), "3");
        assert_eq!(bcadd("0", "0", Some(0)), "0");
    }

    #[test]
    fn test_bcadd_basic() {
        assert_eq!(bcadd("1", "2", Some(0)), "3");
        assert_eq!(bcadd("100", "200", Some(0)), "300");
        assert_eq!(bcadd("-1", "2", Some(0)), "1");
        assert_eq!(bcadd("1", "-2", Some(0)), "-1");
    }

    #[test]
    fn test_bcadd_with_scale() {
        assert_eq!(bcadd("1.5", "2.3", Some(1)), "3.8");
        assert_eq!(bcadd("1.5", "2.3", Some(2)), "3.80");
        assert_eq!(bcadd("1.5", "2.3", Some(0)), "3");
    }

    #[test]
    fn test_bcsub_basic() {
        assert_eq!(bcsub("5", "3", Some(0)), "2");
        assert_eq!(bcsub("3", "5", Some(0)), "-2");
        assert_eq!(bcsub("10", "10", Some(0)), "0");
        assert_eq!(bcsub("-5", "-3", Some(0)), "-2");
    }

    #[test]
    fn test_bcsub_with_scale() {
        assert_eq!(bcsub("5.5", "2.3", Some(1)), "3.2");
        assert_eq!(bcsub("1.0", "0.5", Some(1)), "0.5");
    }

    #[test]
    fn test_bcmul_basic() {
        assert_eq!(bcmul("3", "4", Some(0)), "12");
        assert_eq!(bcmul("-3", "4", Some(0)), "-12");
        assert_eq!(bcmul("-3", "-4", Some(0)), "12");
        assert_eq!(bcmul("0", "100", Some(0)), "0");
    }

    #[test]
    fn test_bcmul_with_scale() {
        assert_eq!(bcmul("1.5", "2.0", Some(1)), "3.0");
        assert_eq!(bcmul("2.5", "4.0", Some(2)), "10.00");
    }

    #[test]
    fn test_bcdiv_basic() {
        assert_eq!(bcdiv("10", "3", Some(0)).unwrap(), "3");
        assert_eq!(bcdiv("10", "3", Some(2)).unwrap(), "3.33");
        assert_eq!(bcdiv("10", "3", Some(5)).unwrap(), "3.33333");
        assert_eq!(bcdiv("100", "10", Some(0)).unwrap(), "10");
    }

    #[test]
    fn test_bcdiv_by_zero() {
        assert_eq!(bcdiv("10", "0", Some(0)), Err(BcMathError::DivisionByZero));
    }

    #[test]
    fn test_bcmod_basic() {
        assert_eq!(bcmod("10", "3", Some(0)).unwrap(), "1");
        assert_eq!(bcmod("10", "5", Some(0)).unwrap(), "0");
        assert_eq!(bcmod("7", "4", Some(0)).unwrap(), "3");
    }

    #[test]
    fn test_bcmod_by_zero() {
        assert_eq!(bcmod("10", "0", Some(0)), Err(BcMathError::DivisionByZero));
    }

    #[test]
    fn test_bcpow_basic() {
        assert_eq!(bcpow("2", "3", Some(0)), "8");
        assert_eq!(bcpow("2", "10", Some(0)), "1024");
        assert_eq!(bcpow("5", "0", Some(0)), "1");
        assert_eq!(bcpow("10", "2", Some(0)), "100");
    }

    #[test]
    fn test_bccomp_basic() {
        assert_eq!(bccomp("1", "2", Some(0)), -1);
        assert_eq!(bccomp("2", "1", Some(0)), 1);
        assert_eq!(bccomp("1", "1", Some(0)), 0);
        assert_eq!(bccomp("-1", "1", Some(0)), -1);
        assert_eq!(bccomp("1", "-1", Some(0)), 1);
    }

    #[test]
    fn test_bccomp_with_scale() {
        assert_eq!(bccomp("1.00001", "1.00002", Some(5)), -1);
        assert_eq!(bccomp("1.00001", "1.00002", Some(3)), 0);
    }

    #[test]
    fn test_bcsqrt_basic() {
        assert_eq!(bcsqrt("4", Some(0)).unwrap(), "2");
        assert_eq!(bcsqrt("9", Some(0)).unwrap(), "3");
        assert_eq!(bcsqrt("2", Some(4)).unwrap(), "1.4142");
        assert_eq!(bcsqrt("0", Some(2)).unwrap(), "0.00");
    }

    #[test]
    fn test_bcsqrt_negative() {
        assert_eq!(bcsqrt("-1", Some(0)), Err(BcMathError::NegativeSqrt));
    }

    #[test]
    fn test_bcpowmod_basic() {
        assert_eq!(bcpowmod("2", "10", "7", Some(0)).unwrap(), "2");
        assert_eq!(bcpowmod("3", "3", "5", Some(0)).unwrap(), "2");
    }

    #[test]
    fn test_bcpowmod_errors() {
        assert_eq!(
            bcpowmod("2", "3", "0", Some(0)),
            Err(BcMathError::ModulusZero)
        );
        assert_eq!(
            bcpowmod("2", "-1", "5", Some(0)),
            Err(BcMathError::NegativeExponent)
        );
    }

    #[test]
    fn test_bcscale_get_set() {
        // Save and restore
        let old = bcscale(Some(5));
        assert_eq!(bcscale(None), 5);
        bcscale(Some(old));
    }

    #[test]
    fn test_bcadd_large_numbers() {
        assert_eq!(
            bcadd("99999999999999999999", "1", Some(0)),
            "100000000000000000000"
        );
    }

    #[test]
    fn test_bcnum_parse_edge_cases() {
        let num = BcNum::parse("");
        assert!(num.is_zero());

        let num = BcNum::parse("0");
        assert!(num.is_zero());

        let num = BcNum::parse("-0");
        assert!(num.is_zero());
        assert!(!num.negative);

        let num = BcNum::parse("00123");
        assert_eq!(num.integer, vec![1, 2, 3]);
    }

    #[test]
    fn test_bcdiv_with_decimals() {
        assert_eq!(bcdiv("1", "3", Some(10)).unwrap(), "0.3333333333");
        assert_eq!(bcdiv("22", "7", Some(6)).unwrap(), "3.142857");
    }

    #[test]
    fn test_bcmul_large() {
        assert_eq!(bcmul("999", "999", Some(0)), "998001");
    }
}
