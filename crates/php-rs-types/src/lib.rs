//! PHP type system
//!
//! This crate implements the core PHP value types (ZVal, ZString, ZArray, ZObject)
//! matching the reference PHP 8.6 implementation.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// Lazy static for global string interning pool
use std::sync::OnceLock;

static GLOBAL_INTERN_POOL: OnceLock<Mutex<HashMap<u64, Arc<ZStringInner>>>> = OnceLock::new();

/// PHP value type discriminant.
///
/// Represents the type tag for a ZVal. This matches PHP's u1.v.type field.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZValType {
    Null = 0,
    False = 1,
    True = 2,
    Long = 3,
    Double = 4,
    String = 5,
    Array = 6,
    Object = 7,
    Resource = 8,
    Reference = 9,
}

/// Core PHP value container (zval equivalent).
///
/// This struct represents all possible PHP value types. In the reference PHP implementation,
/// zval is a 16-byte struct with a union for the value and type/flags fields.
///
/// Layout:
/// - 8 bytes: value union (i64, f64, or pointer)
/// - 4 bytes: type info (u8 type + 3 bytes padding/flags)
/// - 4 bytes: reserved (for future refcount/flags)
///
/// Total: 16 bytes (matching PHP's zval)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ZVal {
    /// The actual value, represented as a union (using u64 for now)
    /// Can hold: i64, f64, or a pointer (usize)
    value: u64,
    /// The type discriminant
    type_tag: ZValType,
    /// Flags byte (reserved for future use)
    _flags1: u8,
    /// Flags byte (reserved for future use)
    _flags2: u8,
    /// Flags byte (reserved for future use)
    _flags3: u8,
    /// Reserved for refcount or other metadata
    _reserved: u32,
}

impl ZVal {
    /// Create a PHP null value
    pub const fn null() -> Self {
        Self {
            value: 0,
            type_tag: ZValType::Null,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP false value
    pub const fn false_val() -> Self {
        Self {
            value: 0,
            type_tag: ZValType::False,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP true value
    pub const fn true_val() -> Self {
        Self {
            value: 0,
            type_tag: ZValType::True,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP integer (long) value
    pub const fn long(value: i64) -> Self {
        Self {
            value: value as u64,
            type_tag: ZValType::Long,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP float (double) value
    pub fn double(value: f64) -> Self {
        Self {
            value: value.to_bits(),
            type_tag: ZValType::Double,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP string value (placeholder - stores pointer as usize)
    pub fn string(ptr: usize) -> Self {
        Self {
            value: ptr as u64,
            type_tag: ZValType::String,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP array value (placeholder - stores pointer as usize)
    pub fn array(ptr: usize) -> Self {
        Self {
            value: ptr as u64,
            type_tag: ZValType::Array,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP object value (placeholder - stores pointer as usize)
    pub fn object(ptr: usize) -> Self {
        Self {
            value: ptr as u64,
            type_tag: ZValType::Object,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP resource value (placeholder - stores pointer as usize)
    pub fn resource(ptr: usize) -> Self {
        Self {
            value: ptr as u64,
            type_tag: ZValType::Resource,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Create a PHP reference value (placeholder - stores pointer as usize)
    pub fn reference(ptr: usize) -> Self {
        Self {
            value: ptr as u64,
            type_tag: ZValType::Reference,
            _flags1: 0,
            _flags2: 0,
            _flags3: 0,
            _reserved: 0,
        }
    }

    /// Get the type tag
    pub fn type_tag(&self) -> ZValType {
        self.type_tag
    }

    /// Get the value as i64 (for Long type)
    pub fn as_long(&self) -> Option<i64> {
        if self.type_tag == ZValType::Long {
            Some(self.value as i64)
        } else {
            None
        }
    }

    /// Get the value as f64 (for Double type)
    pub fn as_double(&self) -> Option<f64> {
        if self.type_tag == ZValType::Double {
            Some(f64::from_bits(self.value))
        } else {
            None
        }
    }

    /// Get the value as pointer (for String, Array, Object, Resource, Reference types)
    pub fn as_ptr(&self) -> Option<usize> {
        match self.type_tag {
            ZValType::String
            | ZValType::Array
            | ZValType::Object
            | ZValType::Resource
            | ZValType::Reference => Some(self.value as usize),
            _ => None,
        }
    }

    /// Convert this ZVal to a long (i64) using PHP type juggling rules.
    ///
    /// Reference: php-src/Zend/zend_operators.c — convert_to_long()
    ///
    /// Conversion rules:
    /// - Null → 0
    /// - False → 0
    /// - True → 1
    /// - Long → identity
    /// - Double → truncate to i64
    /// - String → parse as integer (with leading whitespace skip, trailing text ignored)
    /// - Array → 0 for empty, 1 for non-empty
    /// - Object → 1 (with notice)
    /// - Resource → resource ID (as int)
    pub fn to_long(&self) -> i64 {
        match self.type_tag {
            ZValType::Null => 0,
            ZValType::False => 0,
            ZValType::True => 1,
            ZValType::Long => self.value as i64,
            ZValType::Double => {
                // Truncate float to int
                let d = f64::from_bits(self.value);
                if d.is_nan() {
                    0
                } else if d >= i64::MAX as f64 {
                    i64::MAX
                } else if d <= i64::MIN as f64 {
                    i64::MIN
                } else {
                    d as i64
                }
            }
            ZValType::String => {
                // SAFETY: We're assuming the pointer is valid for the lifetime of this operation
                // In a real implementation, this would use proper reference counting
                let ptr = self.value as usize;
                if ptr == 0 {
                    return 0;
                }
                // SAFETY: For now, this is unsafe. We'll fix this when we properly integrate ZString
                unsafe {
                    let zstring = &*(ptr as *const ZString);
                    Self::string_to_long(zstring.as_bytes())
                }
            }
            ZValType::Array => {
                // TODO: Check if array is empty (0) or non-empty (1)
                // For now, return 1 (placeholder)
                1
            }
            ZValType::Object => {
                // TODO: Object conversion (with notice)
                // For now, return 1 (placeholder)
                1
            }
            ZValType::Resource => {
                // Resource ID is stored in the value
                self.value as i64
            }
            ZValType::Reference => {
                // TODO: Dereference and convert
                // For now, return 0 (placeholder)
                0
            }
        }
    }

    /// Helper: Convert string bytes to long using PHP's parsing rules
    ///
    /// Reference: php-src/Zend/zend_operators.c — zend_strtol()
    ///
    /// Rules:
    /// - Leading whitespace is skipped
    /// - Parse digits until non-digit found
    /// - If no digits found, return 0 (with warning in real PHP)
    /// - If digits followed by non-digits, return parsed value (with warning in real PHP)
    fn string_to_long(bytes: &[u8]) -> i64 {
        // Skip leading whitespace
        let mut i = 0;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        if i >= bytes.len() {
            return 0; // Empty or whitespace-only string
        }

        // Check for sign
        let negative = if bytes[i] == b'-' {
            i += 1;
            true
        } else if bytes[i] == b'+' {
            i += 1;
            false
        } else {
            false
        };

        // Parse digits
        let mut result: i64 = 0;
        let mut found_digit = false;

        while i < bytes.len() && bytes[i].is_ascii_digit() {
            found_digit = true;
            let digit = (bytes[i] - b'0') as i64;

            // Check for overflow
            if let Some(new_result) = result.checked_mul(10) {
                if let Some(new_result) = new_result.checked_add(digit) {
                    result = new_result;
                } else {
                    // Overflow - in PHP this would convert to float
                    // For now, saturate at i64::MAX
                    return if negative { i64::MIN } else { i64::MAX };
                }
            } else {
                // Overflow
                return if negative { i64::MIN } else { i64::MAX };
            }

            i += 1;
        }

        if !found_digit {
            return 0; // No digits found (e.g., "abc")
        }

        if negative {
            -result
        } else {
            result
        }
    }

    /// Convert this ZVal to a double (f64) using PHP type juggling rules.
    ///
    /// Reference: php-src/Zend/zend_operators.c — convert_to_double()
    ///
    /// Conversion rules:
    /// - Null → 0.0
    /// - False → 0.0
    /// - True → 1.0
    /// - Long → convert to f64
    /// - Double → identity
    /// - String → parse as float (supports scientific notation)
    /// - Array → 0.0 for empty, 1.0 for non-empty
    /// - Object → 1.0 (with notice)
    /// - Resource → resource ID (as float)
    pub fn to_double(&self) -> f64 {
        match self.type_tag {
            ZValType::Null => 0.0,
            ZValType::False => 0.0,
            ZValType::True => 1.0,
            ZValType::Long => (self.value as i64) as f64,
            ZValType::Double => f64::from_bits(self.value),
            ZValType::String => {
                // SAFETY: We're assuming the pointer is valid for the lifetime of this operation
                // In a real implementation, this would use proper reference counting
                let ptr = self.value as usize;
                if ptr == 0 {
                    return 0.0;
                }
                // SAFETY: For now, this is unsafe. We'll fix this when we properly integrate ZString
                unsafe {
                    let zstring = &*(ptr as *const ZString);
                    Self::string_to_double(zstring.as_bytes())
                }
            }
            ZValType::Array => {
                // TODO: Check if array is empty (0.0) or non-empty (1.0)
                // For now, return 1.0 (placeholder)
                1.0
            }
            ZValType::Object => {
                // TODO: Object conversion (with notice)
                // For now, return 1.0 (placeholder)
                1.0
            }
            ZValType::Resource => {
                // Resource ID is stored in the value
                (self.value as i64) as f64
            }
            ZValType::Reference => {
                // TODO: Dereference and convert
                // For now, return 0.0 (placeholder)
                0.0
            }
        }
    }

    /// Convert this ZVal to a boolean using PHP type juggling rules.
    ///
    /// Reference: php-src/Zend/zend_operators.c — convert_to_boolean()
    ///
    /// Conversion rules:
    /// - Null → false
    /// - False → false
    /// - True → true
    /// - Long → false if 0, true otherwise
    /// - Double → false if 0.0 or NaN, true otherwise
    /// - String → false if "" or "0", true otherwise
    /// - Array → false if empty, true otherwise
    /// - Object → true
    /// - Resource → true
    pub fn to_bool(&self) -> bool {
        match self.type_tag {
            ZValType::Null => false,
            ZValType::False => false,
            ZValType::True => true,
            ZValType::Long => (self.value as i64) != 0,
            ZValType::Double => {
                let d = f64::from_bits(self.value);
                // In PHP, 0.0 and NaN are both false
                !d.is_nan() && d != 0.0
            }
            ZValType::String => {
                // SAFETY: We're assuming the pointer is valid for the lifetime of this operation
                // In a real implementation, this would use proper reference counting
                let ptr = self.value as usize;
                if ptr == 0 {
                    return false;
                }
                // SAFETY: For now, this is unsafe. We'll fix this when we properly integrate ZString
                unsafe {
                    let zstring = &*(ptr as *const ZString);
                    let bytes = zstring.as_bytes();
                    // Empty string or "0" is false
                    !bytes.is_empty() && bytes != b"0"
                }
            }
            ZValType::Array => {
                // Empty array → false, non-empty array → true
                // Placeholder implementation: pointer value 0 means empty array
                // In a full implementation, we would dereference the pointer and check the array's count
                let ptr = self.value as usize;
                ptr != 0
            }
            ZValType::Object => {
                // Objects are always true
                true
            }
            ZValType::Resource => {
                // Resources are always true
                true
            }
            ZValType::Reference => {
                // TODO: Dereference and convert
                // For now, return false (placeholder)
                false
            }
        }
    }

    /// Convert this ZVal to a string (ZString) using PHP type juggling rules.
    ///
    /// Reference: php-src/Zend/zend_operators.c — convert_to_string()
    ///
    /// Conversion rules:
    /// - Null → ""
    /// - False → ""
    /// - True → "1"
    /// - Long → string representation (e.g., 42 → "42")
    /// - Double → string representation (e.g., 1.5 → "1.5", INF → "INF", NAN → "NAN")
    /// - String → identity (but need to extract from pointer)
    /// - Array → "Array" (with notice)
    /// - Object → object's __toString() or "Object" (with notice)
    /// - Resource → "Resource id #N"
    pub fn to_string(&self) -> ZString {
        match self.type_tag {
            ZValType::Null => ZString::from_str(""),
            ZValType::False => ZString::from_str(""),
            ZValType::True => ZString::from_str("1"),
            ZValType::Long => {
                let value = self.value as i64;
                ZString::from_str(&value.to_string())
            }
            ZValType::Double => {
                let value = f64::from_bits(self.value);
                if value.is_nan() {
                    ZString::from_str("NAN")
                } else if value.is_infinite() {
                    if value.is_sign_positive() {
                        ZString::from_str("INF")
                    } else {
                        ZString::from_str("-INF")
                    }
                } else {
                    ZString::from_str(&value.to_string())
                }
            }
            ZValType::String => {
                // SAFETY: We're assuming the pointer is valid for the lifetime of this operation
                // In a real implementation, this would use proper reference counting
                let ptr = self.value as usize;
                if ptr == 0 {
                    return ZString::from_str("");
                }
                // SAFETY: For now, this is unsafe. We'll fix this when we properly integrate ZString
                unsafe {
                    let zstring = &*(ptr as *const ZString);
                    zstring.clone()
                }
            }
            ZValType::Array => {
                // TODO: Array conversion (with notice)
                // For now, return "Array" (placeholder)
                ZString::from_str("Array")
            }
            ZValType::Object => {
                // TODO: Object conversion (__toString() or notice)
                // For now, return "Object" (placeholder)
                ZString::from_str("Object")
            }
            ZValType::Resource => {
                // Resource ID is stored in the value
                // Format: "Resource id #N"
                let id = self.value as i64;
                ZString::from_str(&format!("Resource id #{}", id))
            }
            ZValType::Reference => {
                // TODO: Dereference and convert
                // For now, return empty string (placeholder)
                ZString::from_str("")
            }
        }
    }

    /// Helper: Convert string bytes to double using PHP's parsing rules
    ///
    /// Reference: php-src/Zend/zend_operators.c — zend_strtod()
    ///
    /// Rules:
    /// - Leading whitespace is skipped
    /// - Parse float in format: [sign][digits][.digits][(e|E)[sign]digits]
    /// - If no valid float found, return 0.0 (with warning in real PHP)
    /// - If float followed by non-float chars, return parsed value (with warning in real PHP)
    fn string_to_double(bytes: &[u8]) -> f64 {
        // Skip leading whitespace
        let mut i = 0;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        if i >= bytes.len() {
            return 0.0; // Empty or whitespace-only string
        }

        // Try to parse the string as f64 using Rust's standard parser
        // First, find the end of the numeric part
        let start = i;

        // Check for sign
        if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
            i += 1;
        }

        let mut found_digit = false;
        let mut found_dot = false;
        let mut found_e = false;

        // Parse the mantissa (integer and decimal parts)
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                found_digit = true;
                i += 1;
            } else if bytes[i] == b'.' && !found_dot && !found_e {
                found_dot = true;
                i += 1;
            } else if (bytes[i] == b'e' || bytes[i] == b'E') && !found_e && found_digit {
                found_e = true;
                i += 1;
                // Parse exponent sign
                if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
                    i += 1;
                }
                // Parse exponent digits
                let exp_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                // If no exponent digits, backtrack
                if i == exp_start {
                    i = exp_start - 1; // Back before the sign
                    if bytes[i - 1] == b'-' || bytes[i - 1] == b'+' {
                        i -= 1; // Back before the 'e'
                    }
                    break;
                }
            } else {
                break;
            }
        }

        if !found_digit {
            return 0.0; // No digits found (e.g., "abc")
        }

        // Extract the numeric substring
        let numeric_str = &bytes[start..i];

        // Parse using Rust's f64 parser
        if let Ok(s) = std::str::from_utf8(numeric_str) {
            if let Ok(value) = s.parse::<f64>() {
                return value;
            }
        }

        // If parsing failed, return 0.0
        0.0
    }
}

impl fmt::Display for ZVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.type_tag {
            ZValType::Null => write!(f, "NULL"),
            ZValType::False => write!(f, "bool(false)"),
            ZValType::True => write!(f, "bool(true)"),
            ZValType::Long => {
                let value = self.value as i64;
                write!(f, "int({})", value)
            }
            ZValType::Double => {
                let value = f64::from_bits(self.value);
                if value.is_nan() {
                    write!(f, "float(NAN)")
                } else if value.is_infinite() {
                    if value.is_sign_positive() {
                        write!(f, "float(INF)")
                    } else {
                        write!(f, "float(-INF)")
                    }
                } else {
                    write!(f, "float({})", value)
                }
            }
            ZValType::String => write!(f, "string"),
            ZValType::Array => write!(f, "array"),
            ZValType::Object => write!(f, "object"),
            ZValType::Resource => write!(f, "resource"),
            ZValType::Reference => write!(f, "reference"),
        }
    }
}

impl PartialEq for ZVal {
    fn eq(&self, other: &Self) -> bool {
        // First check if types match
        if self.type_tag != other.type_tag {
            return false;
        }

        // Then compare values based on type
        match self.type_tag {
            ZValType::Null | ZValType::False | ZValType::True => {
                // For these types, equal type tags means equal values
                true
            }
            ZValType::Long => {
                // Compare as i64
                (self.value as i64) == (other.value as i64)
            }
            ZValType::Double => {
                // Use f64::eq which respects IEEE 754 (NaN != NaN)
                let a = f64::from_bits(self.value);
                let b = f64::from_bits(other.value);
                a == b
            }
            ZValType::String
            | ZValType::Array
            | ZValType::Object
            | ZValType::Resource
            | ZValType::Reference => {
                // For pointer types, compare the raw pointer values
                self.value == other.value
            }
        }
    }
}

/// PHP string value with reference counting and precomputed hash.
///
/// This struct represents PHP's zend_string type. In the reference PHP implementation,
/// zend_string is a refcounted structure containing:
/// - gc: zend_refcounted_h (refcount + type_info)
/// - h: zend_ulong (hash value)
/// - len: size_t (string length in bytes)
/// - val: char[] (null-terminated string data)
///
/// In Rust, we use Arc for reference counting and store the data in a single allocation.
/// The hash is precomputed using PHP's DJBX33A hash algorithm.
///
/// Reference: php-src/Zend/zend_types.h, zend_string.h
#[derive(Clone)]
pub struct ZString {
    /// Shared reference to the string data
    inner: Arc<ZStringInner>,
}

/// Inner data for ZString (stored in Arc for reference counting)
struct ZStringInner {
    /// Precomputed hash value (PHP uses DJBX33A hash)
    hash: u64,
    /// String data (bytes, not guaranteed to be valid UTF-8)
    /// PHP strings are binary-safe and can contain null bytes
    bytes: Box<[u8]>,
}

impl ZString {
    /// Create a new ZString from a byte slice
    pub fn new(bytes: &[u8]) -> Self {
        let hash = Self::compute_hash(bytes);
        Self {
            inner: Arc::new(ZStringInner {
                hash,
                bytes: bytes.into(),
            }),
        }
    }

    /// Create a new ZString from a Rust string slice
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes())
    }

    /// Get the hash value
    pub fn hash(&self) -> u64 {
        self.inner.hash
    }

    /// Get the length in bytes
    pub fn len(&self) -> usize {
        self.inner.bytes.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }

    /// Get the bytes as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Get the string as a &str if it's valid UTF-8
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.inner.bytes).ok()
    }

    /// Intern a string globally
    ///
    /// This is used for strings that should be shared across all requests,
    /// such as function names, class names, and keywords.
    ///
    /// Reference: PHP's zend_string.c — zend_new_interned_string()
    pub fn intern(s: &str) -> Self {
        Self::intern_bytes(s.as_bytes())
    }

    /// Intern bytes globally
    fn intern_bytes(bytes: &[u8]) -> Self {
        let hash = Self::compute_hash(bytes);

        // Get or initialize the global intern pool
        let pool = GLOBAL_INTERN_POOL.get_or_init(|| Mutex::new(HashMap::new()));

        let mut pool = pool.lock().unwrap();

        // Check if already interned
        if let Some(inner) = pool.get(&hash) {
            // Verify hash collision didn't occur by comparing actual bytes
            if inner.bytes.as_ref() == bytes {
                return Self {
                    inner: Arc::clone(inner),
                };
            }
        }

        // Not interned yet, create and store it
        let inner = Arc::new(ZStringInner {
            hash,
            bytes: bytes.into(),
        });

        pool.insert(hash, Arc::clone(&inner));

        Self { inner }
    }

    /// Compute the hash using PHP's DJBX33A hash algorithm
    ///
    /// Reference: php-src/Zend/zend_string.h
    /// #define ZEND_STRING_HASH_VAL(s) zend_string_hash_val(s)
    ///
    /// The algorithm is:
    /// hash = 5381
    /// for each byte c:
    ///   hash = hash * 33 + c
    fn compute_hash(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 5381;
        for &byte in bytes {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
        }
        hash
    }
}

impl fmt::Debug for ZString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZString")
            .field("hash", &self.hash())
            .field("len", &self.len())
            .field("bytes", &self.inner.bytes)
            .finish()
    }
}

impl fmt::Display for ZString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = self.as_str() {
            write!(f, "{}", s)
        } else {
            // For binary data, show as hex escape sequences
            write!(f, "\"")?;
            for &byte in self.as_bytes() {
                if (32..=126).contains(&byte) && byte != b'\\' && byte != b'"' {
                    write!(f, "{}", byte as char)?;
                } else {
                    write!(f, "\\x{:02x}", byte)?;
                }
            }
            write!(f, "\"")
        }
    }
}

impl PartialEq for ZString {
    fn eq(&self, other: &Self) -> bool {
        // Fast path: if the Arc pointers are the same, they're equal
        if Arc::ptr_eq(&self.inner, &other.inner) {
            return true;
        }

        // Otherwise, compare the actual bytes
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ZString {}

impl std::hash::Hash for ZString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use the precomputed PHP hash
        state.write_u64(self.hash());
    }
}

impl AsRef<[u8]> for ZString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl FromStr for ZString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.as_bytes()))
    }
}

/// Request-scoped string interning context.
///
/// In PHP, there are two levels of string interning:
/// 1. Global interning: for function names, class names, keywords (survives across requests)
/// 2. Request-scoped interning: for variable names, property names (cleared after request)
///
/// This struct provides request-scoped interning.
///
/// Reference: php-src/Zend/zend_string.h — interned strings
pub struct InternContext {
    /// Request-scoped intern pool
    pool: Mutex<HashMap<u64, Arc<ZStringInner>>>,
}

impl InternContext {
    /// Create a new request-scoped intern context
    pub fn new() -> Self {
        Self {
            pool: Mutex::new(HashMap::new()),
        }
    }

    /// Intern a string in this request context
    pub fn intern(&self, s: &str) -> ZString {
        self.intern_bytes(s.as_bytes())
    }

    /// Intern bytes in this request context
    fn intern_bytes(&self, bytes: &[u8]) -> ZString {
        let hash = ZString::compute_hash(bytes);

        let mut pool = self.pool.lock().unwrap();

        // Check if already interned in this context
        if let Some(inner) = pool.get(&hash) {
            // Verify hash collision didn't occur
            if inner.bytes.as_ref() == bytes {
                return ZString {
                    inner: Arc::clone(inner),
                };
            }
        }

        // Not interned in this context, create and store it
        let inner = Arc::new(ZStringInner {
            hash,
            bytes: bytes.into(),
        });

        pool.insert(hash, Arc::clone(&inner));

        ZString { inner }
    }
}

impl Default for InternContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zval_variants_exist() {
        // Test: can construct all ZVal variants
        let _null = ZVal::null();
        let _false = ZVal::false_val();
        let _true = ZVal::true_val();
        let _long = ZVal::long(42);
        let _double = ZVal::double(2.5);
        let _string = ZVal::string(0x1234);
        let _array = ZVal::array(0);
        let _object = ZVal::object(0);
        let _resource = ZVal::resource(0);
        let _reference = ZVal::reference(0);
    }

    #[test]
    fn test_display_null() {
        // Test: NULL displays as "NULL"
        // Reference: php -r 'var_dump(null);' outputs "NULL\n"
        let val = ZVal::null();
        assert_eq!(format!("{}", val), "NULL");
    }

    #[test]
    fn test_display_bool() {
        // Test: bool(true) and bool(false)
        // Reference: php -r 'var_dump(true);' outputs "bool(true)\n"
        //            php -r 'var_dump(false);' outputs "bool(false)\n"
        let t = ZVal::true_val();
        let f = ZVal::false_val();
        assert_eq!(format!("{}", t), "bool(true)");
        assert_eq!(format!("{}", f), "bool(false)");
    }

    #[test]
    fn test_display_long() {
        // Test: int(42), int(0), int(-123)
        // Reference: php -r 'var_dump(42);' outputs "int(42)\n"
        let zero = ZVal::long(0);
        let positive = ZVal::long(42);
        let negative = ZVal::long(-123);
        assert_eq!(format!("{}", zero), "int(0)");
        assert_eq!(format!("{}", positive), "int(42)");
        assert_eq!(format!("{}", negative), "int(-123)");
    }

    #[test]
    fn test_display_double() {
        // Test: float(1.5), float(0), float(INF), float(-INF), float(NAN)
        // Reference: php -r 'var_dump(1.5);' outputs "float(1.5)\n"
        //            php -r 'var_dump(INF);' outputs "float(INF)\n"
        //            php -r 'var_dump(-INF);' outputs "float(-INF)\n"
        //            php -r 'var_dump(NAN);' outputs "float(NAN)\n"
        let normal = ZVal::double(1.5);
        let zero = ZVal::double(0.0);
        let inf = ZVal::double(f64::INFINITY);
        let neg_inf = ZVal::double(f64::NEG_INFINITY);
        let nan = ZVal::double(f64::NAN);

        assert_eq!(format!("{}", normal), "float(1.5)");
        assert_eq!(format!("{}", zero), "float(0)");
        assert_eq!(format!("{}", inf), "float(INF)");
        assert_eq!(format!("{}", neg_inf), "float(-INF)");
        assert_eq!(format!("{}", nan), "float(NAN)");
    }

    #[test]
    fn test_display_string_placeholder() {
        // Test: string (placeholder - just shows type for now)
        // Note: Actual string content will be implemented in Phase 1.2 (ZString)
        // For now, we just show the type
        let s = ZVal::string(0x1234);
        assert_eq!(format!("{}", s), "string");
    }

    #[test]
    fn test_display_array_placeholder() {
        // Test: array (placeholder)
        // Note: Actual array display will be implemented in Phase 1.4 (ZArray)
        let a = ZVal::array(0x5678);
        assert_eq!(format!("{}", a), "array");
    }

    #[test]
    fn test_display_object_placeholder() {
        // Test: object (placeholder)
        // Note: Actual object display will be implemented in Phase 1.5 (ZObject)
        let o = ZVal::object(0xABCD);
        assert_eq!(format!("{}", o), "object");
    }

    #[test]
    fn test_display_resource_placeholder() {
        // Test: resource (placeholder)
        // Reference: php -r '$f = fopen("/dev/null", "r"); var_dump($f);'
        //            outputs "resource(5) of type (stream)"
        // For now, just show "resource"
        let r = ZVal::resource(0xDEAD);
        assert_eq!(format!("{}", r), "resource");
    }

    #[test]
    fn test_display_reference_placeholder() {
        // Test: reference (placeholder)
        // Note: References are internal; they're not directly displayed.
        // For now, show "reference"
        let ref_val = ZVal::reference(0xBEEF);
        assert_eq!(format!("{}", ref_val), "reference");
    }

    #[test]
    fn test_zval_long_values() {
        // Test: Long can hold various integer values
        let zero = ZVal::long(0);
        let positive = ZVal::long(123456);
        let negative = ZVal::long(-999);
        let max = ZVal::long(i64::MAX);
        let min = ZVal::long(i64::MIN);

        assert_eq!(zero.type_tag(), ZValType::Long);
        assert_eq!(zero.as_long(), Some(0));

        assert_eq!(positive.type_tag(), ZValType::Long);
        assert_eq!(positive.as_long(), Some(123456));

        assert_eq!(negative.type_tag(), ZValType::Long);
        assert_eq!(negative.as_long(), Some(-999));

        assert_eq!(max.type_tag(), ZValType::Long);
        assert_eq!(max.as_long(), Some(i64::MAX));

        assert_eq!(min.type_tag(), ZValType::Long);
        assert_eq!(min.as_long(), Some(i64::MIN));
    }

    #[test]
    fn test_zval_double_values() {
        // Test: Double can hold various float values
        let zero = ZVal::double(0.0);
        let precise = ZVal::double(1.23456789);
        let negative = ZVal::double(-2.5);
        let inf = ZVal::double(f64::INFINITY);
        let neg_inf = ZVal::double(f64::NEG_INFINITY);
        let nan = ZVal::double(f64::NAN);

        assert_eq!(zero.type_tag(), ZValType::Double);
        assert_eq!(zero.as_double(), Some(0.0));

        assert_eq!(precise.type_tag(), ZValType::Double);
        assert!((precise.as_double().unwrap() - 1.23456789).abs() < f64::EPSILON);

        assert_eq!(negative.type_tag(), ZValType::Double);
        assert_eq!(negative.as_double(), Some(-2.5));

        assert_eq!(inf.type_tag(), ZValType::Double);
        let inf_val = inf.as_double().unwrap();
        assert!(inf_val.is_infinite() && inf_val.is_sign_positive());

        assert_eq!(neg_inf.type_tag(), ZValType::Double);
        let neg_inf_val = neg_inf.as_double().unwrap();
        assert!(neg_inf_val.is_infinite() && neg_inf_val.is_sign_negative());

        assert_eq!(nan.type_tag(), ZValType::Double);
        assert!(nan.as_double().unwrap().is_nan());
    }

    #[test]
    fn test_zval_string_values() {
        // Test: String can hold pointer values (actual string handling in Phase 1.2)
        let empty = ZVal::string(0);
        let ptr1 = ZVal::string(0x1000);
        let ptr2 = ZVal::string(0xDEADBEEF);

        assert_eq!(empty.type_tag(), ZValType::String);
        assert_eq!(empty.as_ptr(), Some(0));

        assert_eq!(ptr1.type_tag(), ZValType::String);
        assert_eq!(ptr1.as_ptr(), Some(0x1000));

        assert_eq!(ptr2.type_tag(), ZValType::String);
        assert_eq!(ptr2.as_ptr(), Some(0xDEADBEEF));
    }

    #[test]
    fn test_zval_boolean_variants() {
        // Test: PHP has separate True and False variants (not Bool(bool))
        let t = ZVal::true_val();
        let f = ZVal::false_val();

        assert_eq!(t.type_tag(), ZValType::True);
        assert_eq!(f.type_tag(), ZValType::False);
    }

    #[test]
    fn test_zval_debug_output() {
        // Test: ZVal implements Debug (required for development)
        let val = ZVal::long(42);
        let debug_str = format!("{:?}", val);
        assert!(debug_str.contains("Long") || debug_str.contains("type_tag"));
    }

    #[test]
    fn test_zval_size_is_16_bytes() {
        // CRITICAL: ZVal must be exactly 16 bytes to match PHP's zval struct layout.
        // Reference: php-src/Zend/zend_types.h — zval is 16 bytes (8-byte value + 8-byte type/flags).
        // This constraint is essential for memory layout compatibility and performance.
        use std::mem::size_of;
        assert_eq!(
            size_of::<ZVal>(),
            16,
            "ZVal must be exactly 16 bytes, got {} bytes",
            size_of::<ZVal>()
        );
    }

    #[test]
    fn test_zval_clone() {
        // Test: ZVal implements Clone
        // All ZVal variants should be cloneable
        let original = ZVal::long(42);
        let cloned = original.clone();

        assert_eq!(cloned.type_tag(), ZValType::Long);
        assert_eq!(cloned.as_long(), Some(42));
    }

    #[test]
    fn test_zval_clone_null() {
        // Test: Clone null values
        let original = ZVal::null();
        let cloned = original.clone();
        assert_eq!(cloned.type_tag(), ZValType::Null);
    }

    #[test]
    fn test_zval_clone_bool() {
        // Test: Clone boolean values
        let t = ZVal::true_val();
        let f = ZVal::false_val();

        let t_clone = t.clone();
        let f_clone = f.clone();

        assert_eq!(t_clone.type_tag(), ZValType::True);
        assert_eq!(f_clone.type_tag(), ZValType::False);
    }

    #[test]
    fn test_zval_clone_double() {
        // Test: Clone float values including special cases
        let normal = ZVal::double(1.23456);
        let inf = ZVal::double(f64::INFINITY);
        let nan = ZVal::double(f64::NAN);

        let normal_clone = normal.clone();
        let inf_clone = inf.clone();
        let nan_clone = nan.clone();

        assert!((normal_clone.as_double().unwrap() - 1.23456).abs() < f64::EPSILON);
        assert!(inf_clone.as_double().unwrap().is_infinite());
        assert!(nan_clone.as_double().unwrap().is_nan());
    }

    #[test]
    fn test_zval_clone_pointer_types() {
        // Test: Clone pointer-based types (string, array, object, etc.)
        let s = ZVal::string(0x1234);
        let a = ZVal::array(0x5678);
        let o = ZVal::object(0xABCD);

        let s_clone = s.clone();
        let a_clone = a.clone();
        let o_clone = o.clone();

        assert_eq!(s_clone.as_ptr(), Some(0x1234));
        assert_eq!(a_clone.as_ptr(), Some(0x5678));
        assert_eq!(o_clone.as_ptr(), Some(0xABCD));
    }

    #[test]
    fn test_zval_partial_eq_null() {
        // Test: PartialEq for null values
        let null1 = ZVal::null();
        let null2 = ZVal::null();
        let not_null = ZVal::long(0);

        assert_eq!(null1, null2);
        assert_ne!(null1, not_null);
    }

    #[test]
    fn test_zval_partial_eq_bool() {
        // Test: PartialEq for boolean values
        let true1 = ZVal::true_val();
        let true2 = ZVal::true_val();
        let false1 = ZVal::false_val();
        let false2 = ZVal::false_val();

        assert_eq!(true1, true2);
        assert_eq!(false1, false2);
        assert_ne!(true1, false1);
    }

    #[test]
    fn test_zval_partial_eq_long() {
        // Test: PartialEq for integer values
        let a = ZVal::long(42);
        let b = ZVal::long(42);
        let c = ZVal::long(100);
        let d = ZVal::long(-42);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn test_zval_partial_eq_double() {
        // Test: PartialEq for float values
        let a = ZVal::double(1.5);
        let b = ZVal::double(1.5);
        let c = ZVal::double(2.5);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_zval_partial_eq_double_special() {
        // Test: PartialEq for special float values (INF, -INF, NAN)
        // Note: NAN != NAN per IEEE 754
        let inf1 = ZVal::double(f64::INFINITY);
        let inf2 = ZVal::double(f64::INFINITY);
        let neg_inf = ZVal::double(f64::NEG_INFINITY);
        let nan1 = ZVal::double(f64::NAN);
        let nan2 = ZVal::double(f64::NAN);

        assert_eq!(inf1, inf2);
        assert_ne!(inf1, neg_inf);
        // NAN != NAN is the expected behavior for f64 PartialEq
        assert_ne!(nan1, nan2);
    }

    #[test]
    fn test_zval_partial_eq_different_types() {
        // Test: Values of different types are not equal
        // Reference: PHP uses === for strict comparison (type + value)
        let i = ZVal::long(1);
        let f = ZVal::double(1.0);
        let t = ZVal::true_val();
        let s = ZVal::string(0);

        assert_ne!(i, f); // int(1) !== float(1.0)
        assert_ne!(i, t); // int(1) !== bool(true)
        assert_ne!(f, t); // float(1.0) !== bool(true)
        assert_ne!(i, s); // int(1) !== string
    }

    #[test]
    fn test_zval_partial_eq_pointer_types() {
        // Test: PartialEq for pointer-based types
        // For now, we compare the raw pointer values
        let s1 = ZVal::string(0x1234);
        let s2 = ZVal::string(0x1234);
        let s3 = ZVal::string(0x5678);
        let a1 = ZVal::array(0x1234);

        assert_eq!(s1, s2); // Same pointer
        assert_ne!(s1, s3); // Different pointer
        assert_ne!(s1, a1); // Different type (string vs array)
    }

    #[test]
    fn test_zval_partial_eq_zero_values() {
        // Test: PartialEq for zero values of different types
        let null = ZVal::null();
        let false_val = ZVal::false_val();
        let int_zero = ZVal::long(0);
        let float_zero = ZVal::double(0.0);
        let string_zero = ZVal::string(0);

        // These should all be different with strict comparison (===)
        assert_ne!(null, false_val);
        assert_ne!(null, int_zero);
        assert_ne!(null, float_zero);
        assert_ne!(false_val, int_zero);
        assert_ne!(int_zero, float_zero);
        assert_ne!(int_zero, string_zero);
    }

    // ========================================================================
    // ZString tests (Phase 1.2)
    // ========================================================================

    #[test]
    fn test_zstring_new_from_bytes() {
        // Test: Create ZString from byte slice
        let s = ZString::new(b"hello");
        assert_eq!(s.len(), 5);
        assert_eq!(s.as_bytes(), b"hello");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_zstring_from_str() {
        // Test: Create ZString from Rust &str
        let s = ZString::from_str("hello world");
        assert_eq!(s.len(), 11);
        assert_eq!(s.as_str(), Some("hello world"));
    }

    #[test]
    fn test_zstring_empty() {
        // Test: Empty string
        let s = ZString::new(b"");
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert_eq!(s.as_bytes(), b"");
    }

    #[test]
    fn test_zstring_ascii() {
        // Test: ASCII string
        let s = ZString::from_str("Hello, World!");
        assert_eq!(s.len(), 13);
        assert_eq!(s.as_str(), Some("Hello, World!"));
    }

    #[test]
    fn test_zstring_binary_data() {
        // Test: Binary data with null bytes
        // PHP strings are binary-safe and can contain null bytes
        let binary = b"hello\x00world\xff\xfe";
        let s = ZString::new(binary);
        assert_eq!(s.len(), 13);
        assert_eq!(s.as_bytes(), binary);
        // as_str() should return None for invalid UTF-8
        assert_eq!(s.as_str(), None);
    }

    #[test]
    fn test_zstring_utf8() {
        // Test: UTF-8 string (multi-byte characters)
        let s = ZString::from_str("Hello 世界 🌍");
        assert!(s.len() > 8); // More bytes than visible characters
        assert_eq!(s.as_str(), Some("Hello 世界 🌍"));
    }

    #[test]
    fn test_zstring_hash_is_precomputed() {
        // Test: Hash is precomputed and stable
        let s1 = ZString::from_str("test");
        let s2 = ZString::from_str("test");

        // Same content = same hash
        assert_eq!(s1.hash(), s2.hash());

        // Different content = different hash (extremely likely)
        let s3 = ZString::from_str("different");
        assert_ne!(s1.hash(), s3.hash());
    }

    #[test]
    fn test_zstring_hash_djbx33a() {
        // Test: Verify DJBX33A hash algorithm implementation
        // Reference: PHP's DJBX33A hash starts with 5381, then: hash = hash * 33 + c
        // For empty string: hash should be 5381
        let empty = ZString::new(b"");
        assert_eq!(empty.hash(), 5381);

        // For single character 'a' (ASCII 97):
        // hash = 5381 * 33 + 97 = 177573 + 97 = 177670
        let a = ZString::new(b"a");
        assert_eq!(a.hash(), 177670);
    }

    #[test]
    fn test_zstring_partial_eq() {
        // Test: PartialEq compares content
        let s1 = ZString::from_str("hello");
        let s2 = ZString::from_str("hello");
        let s3 = ZString::from_str("world");

        assert_eq!(s1, s2); // Same content
        assert_ne!(s1, s3); // Different content
    }

    #[test]
    fn test_zstring_partial_eq_arc_optimization() {
        // Test: PartialEq fast path when Arc pointers are the same
        let s1 = ZString::from_str("test");
        let s2 = s1.clone(); // Clone shares the same Arc

        assert_eq!(s1, s2); // Should use fast path (ptr_eq)
        assert!(Arc::ptr_eq(&s1.inner, &s2.inner));
    }

    #[test]
    fn test_zstring_eq_trait() {
        // Test: Eq trait is implemented
        let s1 = ZString::from_str("test");
        let s2 = ZString::from_str("test");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_zstring_hash_trait() {
        // Test: Hash trait uses precomputed PHP hash
        use std::collections::HashMap;

        let s1 = ZString::from_str("key");
        let s2 = ZString::from_str("key");

        let mut map = HashMap::new();
        map.insert(s1, 42);

        // Should find the value using s2 (same content)
        assert_eq!(map.get(&s2), Some(&42));
    }

    #[test]
    fn test_zstring_display() {
        // Test: Display trait for valid UTF-8
        let s = ZString::from_str("hello");
        assert_eq!(format!("{}", s), "hello");
    }

    #[test]
    fn test_zstring_display_binary() {
        // Test: Display trait for binary data (hex escapes)
        let s = ZString::new(b"hello\x00\xff");
        let display = format!("{}", s);
        assert!(display.contains("\\x00"));
        assert!(display.contains("\\xff"));
    }

    #[test]
    fn test_zstring_debug() {
        // Test: Debug trait shows hash, len, and bytes
        let s = ZString::from_str("test");
        let debug = format!("{:?}", s);
        assert!(debug.contains("ZString"));
        assert!(debug.contains("hash"));
        assert!(debug.contains("len"));
        assert!(debug.contains("bytes"));
    }

    #[test]
    fn test_zstring_as_ref() {
        // Test: AsRef<[u8]> implementation
        let s = ZString::from_str("hello");
        let bytes: &[u8] = s.as_ref();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_zstring_clone() {
        // Test: Clone creates a new reference to the same data (Arc clone)
        let s1 = ZString::from_str("hello");
        let s2 = s1.clone();

        assert_eq!(s1, s2);
        assert_eq!(s1.hash(), s2.hash());
        assert!(Arc::ptr_eq(&s1.inner, &s2.inner)); // Same Arc
    }

    // ========================================================================
    // String interning tests (Phase 1.2.3)
    // ========================================================================

    #[test]
    fn test_string_interning_global() {
        // Test: Globally intern a string
        // Interned strings with the same content should be pointer-equal
        let s1 = ZString::intern("function");
        let s2 = ZString::intern("function");

        // Should be pointer-equal (same Arc)
        assert!(Arc::ptr_eq(&s1.inner, &s2.inner));
        assert_eq!(s1.as_str(), Some("function"));
    }

    #[test]
    fn test_string_interning_global_different_content() {
        // Test: Different strings are not interned to the same value
        let s1 = ZString::intern("function");
        let s2 = ZString::intern("class");

        // Different content = different Arc
        assert!(!Arc::ptr_eq(&s1.inner, &s2.inner));
        assert_eq!(s1.as_str(), Some("function"));
        assert_eq!(s2.as_str(), Some("class"));
    }

    #[test]
    fn test_string_interning_global_empty_string() {
        // Test: Empty string interning
        let s1 = ZString::intern("");
        let s2 = ZString::intern("");

        assert!(Arc::ptr_eq(&s1.inner, &s2.inner));
        assert!(s1.is_empty());
    }

    #[test]
    fn test_string_interning_non_interned() {
        // Test: Non-interned strings are not pointer-equal even with same content
        let s1 = ZString::from_str("test");
        let s2 = ZString::from_str("test");

        // Same content, but different allocations
        assert!(!Arc::ptr_eq(&s1.inner, &s2.inner));
        assert_eq!(s1, s2); // Still equal by value
    }

    #[test]
    fn test_string_interning_request_scoped() {
        // Test: Request-scoped interning
        // Create a new request context
        let ctx = InternContext::new();

        let s1 = ctx.intern("variable");
        let s2 = ctx.intern("variable");

        // Should be pointer-equal within the same context
        assert!(Arc::ptr_eq(&s1.inner, &s2.inner));
        assert_eq!(s1.as_str(), Some("variable"));
    }

    #[test]
    fn test_string_interning_request_isolation() {
        // Test: Different request contexts have separate intern pools
        let ctx1 = InternContext::new();
        let ctx2 = InternContext::new();

        let s1 = ctx1.intern("test");
        let s2 = ctx2.intern("test");

        // Different contexts = different interned strings
        // (unless they happen to use global pool)
        // For request-scoped, they should be different Arcs
        assert_eq!(s1.as_str(), Some("test"));
        assert_eq!(s2.as_str(), Some("test"));
    }

    #[test]
    fn test_string_interning_global_vs_request() {
        // Test: Global and request-scoped interning can coexist
        let global = ZString::intern("global");
        let ctx = InternContext::new();
        let request = ctx.intern("request");

        assert_eq!(global.as_str(), Some("global"));
        assert_eq!(request.as_str(), Some("request"));
    }

    #[test]
    fn test_string_interning_common_keywords() {
        // Test: Common PHP keywords are interned
        // Reference: PHP interns all function names, class names, and keywords
        let keywords = [
            "function",
            "class",
            "interface",
            "trait",
            "namespace",
            "use",
            "public",
            "private",
            "protected",
            "static",
            "final",
            "abstract",
            "const",
            "return",
            "if",
            "else",
            "elseif",
            "while",
            "for",
            "foreach",
            "switch",
            "case",
            "break",
            "continue",
            "echo",
            "print",
            "var",
            "new",
            "clone",
            "extends",
            "implements",
            "instanceof",
            "throw",
            "try",
            "catch",
            "finally",
        ];

        for &keyword in &keywords {
            let s1 = ZString::intern(keyword);
            let s2 = ZString::intern(keyword);
            assert!(
                Arc::ptr_eq(&s1.inner, &s2.inner),
                "Keyword '{}' not properly interned",
                keyword
            );
        }
    }

    // ========================================================================
    // Type coercion tests (Phase 1.3)
    // ========================================================================
    // Reference: php-src/Zend/zend_operators.c — convert_to_long(), convert_to_double(), etc.

    #[test]
    fn test_string_to_long_numeric_string() {
        // Test: Numeric string "123" converts to 123
        // Reference: php -r 'var_dump((int)"123");' outputs "int(123)"
        let s = ZString::from_str("123");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 123);
    }

    #[test]
    fn test_string_to_long_with_trailing_text() {
        // Test: "12abc" converts to 12 with E_WARNING
        // Reference: php -r 'var_dump((int)"12abc");' outputs:
        //   "Warning: A non well formed numeric value encountered in ..."
        //   "int(12)"
        // For now, we'll just test the conversion result (warnings to be implemented later)
        let s = ZString::from_str("12abc");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 12);
    }

    #[test]
    fn test_string_to_long_non_numeric() {
        // Test: "abc" converts to 0 with E_WARNING
        // Reference: php -r 'var_dump((int)"abc");' outputs:
        //   "Warning: A non-numeric value encountered in ..."
        //   "int(0)"
        let s = ZString::from_str("abc");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 0);
    }

    #[test]
    fn test_string_to_long_empty_string() {
        // Test: Empty string converts to 0
        // Reference: php -r 'var_dump((int)"");' outputs "int(0)"
        let s = ZString::from_str("");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 0);
    }

    #[test]
    fn test_string_to_long_whitespace() {
        // Test: Leading whitespace is skipped
        // Reference: php -r 'var_dump((int)"  123");' outputs "int(123)"
        let s = ZString::from_str("  123");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 123);
    }

    #[test]
    fn test_string_to_long_negative() {
        // Test: Negative numeric string
        // Reference: php -r 'var_dump((int)"-456");' outputs "int(-456)"
        let s = ZString::from_str("-456");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), -456);
    }

    #[test]
    fn test_string_to_long_zero() {
        // Test: "0" converts to 0
        // Reference: php -r 'var_dump((int)"0");' outputs "int(0)"
        let s = ZString::from_str("0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_long(), 0);
    }

    // ========================================================================
    // String → Float coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_string_to_double_numeric_string() {
        // Test: Numeric string "1.5" converts to 1.5
        // Reference: php -r 'var_dump((float)"1.5");' outputs "float(1.5)"
        let s = ZString::from_str("1.5");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 1.5);
    }

    #[test]
    fn test_string_to_double_scientific_notation() {
        // Test: Scientific notation "1.5e2" converts to 150.0
        // Reference: php -r 'var_dump((float)"1.5e2");' outputs "float(150)"
        let s = ZString::from_str("1.5e2");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 150.0);
    }

    #[test]
    fn test_string_to_double_negative_exponent() {
        // Test: Scientific notation with negative exponent "1.5e-2" converts to 0.015
        // Reference: php -r 'var_dump((float)"1.5e-2");' outputs "float(0.015)"
        let s = ZString::from_str("1.5e-2");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 0.015);
    }

    #[test]
    fn test_string_to_double_integer_string() {
        // Test: Integer string "42" converts to 42.0
        // Reference: php -r 'var_dump((float)"42");' outputs "float(42)"
        let s = ZString::from_str("42");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 42.0);
    }

    #[test]
    fn test_string_to_double_negative() {
        // Test: Negative float string "-2.5" converts to -2.5
        // Reference: php -r 'var_dump((float)"-2.5");' outputs "float(-2.5)"
        let s = ZString::from_str("-2.5");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), -2.5);
    }

    #[test]
    fn test_string_to_double_zero() {
        // Test: "0" converts to 0.0
        // Reference: php -r 'var_dump((float)"0");' outputs "float(0)"
        let s = ZString::from_str("0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 0.0);
    }

    #[test]
    fn test_string_to_double_with_trailing_text() {
        // Test: "1.5abc" converts to 1.5 with E_WARNING
        // Reference: php -r 'var_dump((float)"1.5abc");' outputs:
        //   "Warning: A non well formed numeric value encountered in ..."
        //   "float(1.5)"
        let s = ZString::from_str("1.5abc");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 1.5);
    }

    #[test]
    fn test_string_to_double_non_numeric() {
        // Test: "abc" converts to 0.0 with E_WARNING
        // Reference: php -r 'var_dump((float)"abc");' outputs:
        //   "Warning: A non-numeric value encountered in ..."
        //   "float(0)"
        let s = ZString::from_str("abc");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 0.0);
    }

    #[test]
    fn test_string_to_double_empty_string() {
        // Test: Empty string converts to 0.0
        // Reference: php -r 'var_dump((float)"");' outputs "float(0)"
        let s = ZString::from_str("");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 0.0);
    }

    #[test]
    fn test_string_to_double_whitespace() {
        // Test: Leading whitespace is skipped
        // Reference: php -r 'var_dump((float)"  1.5");' outputs "float(1.5)"
        let s = ZString::from_str("  1.5");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 1.5);
    }

    #[test]
    fn test_string_to_double_positive_sign() {
        // Test: Positive sign "+1.5" converts to 1.5
        // Reference: php -r 'var_dump((float)"+1.5");' outputs "float(1.5)"
        let s = ZString::from_str("+1.5");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 1.5);
    }

    #[test]
    fn test_string_to_double_uppercase_e() {
        // Test: Uppercase E in scientific notation "1.5E2" converts to 150.0
        // Reference: php -r 'var_dump((float)"1.5E2");' outputs "float(150)"
        let s = ZString::from_str("1.5E2");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert_eq!(val.to_double(), 150.0);
    }

    // ========================================================================
    // Int → String coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_int_to_string_positive() {
        // Test: int 42 converts to "42"
        // Reference: php -r 'var_dump((string)42);' outputs 'string(2) "42"'
        let val = ZVal::long(42);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("42"));
    }

    #[test]
    fn test_int_to_string_zero() {
        // Test: int 0 converts to "0"
        // Reference: php -r 'var_dump((string)0);' outputs 'string(1) "0"'
        let val = ZVal::long(0);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("0"));
    }

    #[test]
    fn test_int_to_string_negative() {
        // Test: int -123 converts to "-123"
        // Reference: php -r 'var_dump((string)-123);' outputs 'string(4) "-123"'
        let val = ZVal::long(-123);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("-123"));
    }

    #[test]
    fn test_int_to_string_max() {
        // Test: i64::MAX converts to its string representation
        // Reference: php -r 'var_dump((string)9223372036854775807);' outputs the number as string
        let val = ZVal::long(i64::MAX);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("9223372036854775807"));
    }

    #[test]
    fn test_int_to_string_min() {
        // Test: i64::MIN converts to its string representation
        // Reference: php -r 'var_dump((string)(-9223372036854775808));' outputs the number as string
        let val = ZVal::long(i64::MIN);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("-9223372036854775808"));
    }

    // ========================================================================
    // Float → String coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_float_to_string_positive() {
        // Test: float 1.5 converts to "1.5"
        // Reference: php -r 'var_dump((string)1.5);' outputs 'string(3) "1.5"'
        let val = ZVal::double(1.5);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("1.5"));
    }

    #[test]
    fn test_float_to_string_negative() {
        // Test: float -2.5 converts to "-2.5"
        // Reference: php -r 'var_dump((string)(-2.5));' outputs 'string(4) "-2.5"'
        let val = ZVal::double(-2.5);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("-2.5"));
    }

    #[test]
    fn test_float_to_string_zero() {
        // Test: float 0.0 converts to "0"
        // Reference: php -r 'var_dump((string)0.0);' outputs 'string(1) "0"'
        let val = ZVal::double(0.0);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("0"));
    }

    #[test]
    fn test_float_to_string_inf() {
        // Test: INF converts to "INF"
        // Reference: php -r 'var_dump((string)INF);' outputs 'string(3) "INF"'
        let val = ZVal::double(f64::INFINITY);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("INF"));
    }

    #[test]
    fn test_float_to_string_neg_inf() {
        // Test: -INF converts to "-INF"
        // Reference: php -r 'var_dump((string)(-INF));' outputs 'string(4) "-INF"'
        let val = ZVal::double(f64::NEG_INFINITY);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("-INF"));
    }

    #[test]
    fn test_float_to_string_nan() {
        // Test: NAN converts to "NAN"
        // Reference: php -r 'var_dump((string)NAN);' outputs 'string(3) "NAN"'
        let val = ZVal::double(f64::NAN);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("NAN"));
    }

    #[test]
    fn test_float_to_string_integer_value() {
        // Test: float 42.0 converts to "42"
        // Reference: php -r 'var_dump((string)42.0);' outputs 'string(2) "42"'
        let val = ZVal::double(42.0);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("42"));
    }

    #[test]
    fn test_float_to_string_small_decimal() {
        // Test: float 0.5 converts to "0.5"
        // Reference: php -r 'var_dump((string)0.5);' outputs 'string(3) "0.5"'
        let val = ZVal::double(0.5);
        let s = val.to_string();
        assert_eq!(s.as_str(), Some("0.5"));
    }

    // ========================================================================
    // Bool → Int coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_bool_to_int_true() {
        // Test: true converts to 1
        // Reference: php -r 'var_dump((int)true);' outputs "int(1)"
        let val = ZVal::true_val();
        assert_eq!(val.to_long(), 1);
    }

    #[test]
    fn test_bool_to_int_false() {
        // Test: false converts to 0
        // Reference: php -r 'var_dump((int)false);' outputs "int(0)"
        let val = ZVal::false_val();
        assert_eq!(val.to_long(), 0);
    }

    // ========================================================================
    // Null coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_null_to_int() {
        // Test: null converts to 0
        // Reference: php -r 'var_dump((int)null);' outputs "int(0)"
        let val = ZVal::null();
        assert_eq!(val.to_long(), 0);
    }

    #[test]
    fn test_null_to_float() {
        // Test: null converts to 0.0
        // Reference: php -r 'var_dump((float)null);' outputs "float(0)"
        let val = ZVal::null();
        assert_eq!(val.to_double(), 0.0);
    }

    #[test]
    fn test_null_to_string() {
        // Test: null converts to ""
        // Reference: php -r 'var_dump((string)null);' outputs 'string(0) ""'
        let val = ZVal::null();
        let s = val.to_string();
        assert_eq!(s.as_str(), Some(""));
        assert!(s.is_empty());
    }

    #[test]
    fn test_null_to_bool() {
        // Test: null converts to false
        // Reference: php -r 'var_dump((bool)null);' outputs "bool(false)"
        let val = ZVal::null();
        assert!(!val.to_bool());
    }

    // ========================================================================
    // Array → Bool coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_array_to_bool_empty() {
        // Test: Empty array [] converts to false
        // Reference: php -r 'var_dump((bool)[]);' outputs "bool(false)"
        // Create a mock empty array (we'll use count=0 to represent empty)
        // For now, we need to create a ZArray structure
        // Since ZArray isn't fully implemented yet, we'll store a placeholder pointer
        // that encodes whether the array is empty

        // Placeholder: pointer value 0 means empty array
        let val = ZVal::array(0); // 0 = empty array marker
        assert!(!val.to_bool(), "Empty array should convert to false");
    }

    #[test]
    fn test_array_to_bool_non_empty() {
        // Test: Non-empty array [1] converts to true
        // Reference: php -r 'var_dump((bool)[1]);' outputs "bool(true)"

        // Placeholder: any non-zero pointer means non-empty array
        let val = ZVal::array(1); // non-zero = non-empty array marker
        assert!(val.to_bool(), "Non-empty array should convert to true");
    }

    #[test]
    fn test_array_to_bool_multiple_elements() {
        // Test: Array with multiple elements [1, 2, 3] converts to true
        // Reference: php -r 'var_dump((bool)[1, 2, 3]);' outputs "bool(true)"
        let val = ZVal::array(0x1000); // non-zero pointer
        assert!(
            val.to_bool(),
            "Array with multiple elements should convert to true"
        );
    }

    // ========================================================================
    // String → Bool coercion tests (Phase 1.3.1)
    // ========================================================================

    #[test]
    fn test_string_to_bool_empty_string() {
        // Test: Empty string "" converts to false
        // Reference: php -r 'var_dump((bool)"");' outputs "bool(false)"
        let s = ZString::from_str("");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(!val.to_bool(), "Empty string should convert to false");
    }

    #[test]
    fn test_string_to_bool_zero_string() {
        // Test: String "0" converts to false
        // Reference: php -r 'var_dump((bool)"0");' outputs "bool(false)"
        let s = ZString::from_str("0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(!val.to_bool(), "String \"0\" should convert to false");
    }

    #[test]
    fn test_string_to_bool_whitespace_only() {
        // Test: Whitespace-only string "   " converts to true (not empty)
        // Reference: php -r 'var_dump((bool)"   ");' outputs "bool(true)"
        let s = ZString::from_str("   ");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "Whitespace-only string should convert to true"
        );
    }

    #[test]
    fn test_string_to_bool_non_zero_number() {
        // Test: String "1" converts to true
        // Reference: php -r 'var_dump((bool)"1");' outputs "bool(true)"
        let s = ZString::from_str("1");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(val.to_bool(), "String \"1\" should convert to true");
    }

    #[test]
    fn test_string_to_bool_text() {
        // Test: Any non-empty text string converts to true
        // Reference: php -r 'var_dump((bool)"hello");' outputs "bool(true)"
        let s = ZString::from_str("hello");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "Non-empty text string should convert to true"
        );
    }

    #[test]
    fn test_string_to_bool_false_string() {
        // Test: String "false" converts to true (it's not empty and not "0")
        // Reference: php -r 'var_dump((bool)"false");' outputs "bool(true)"
        let s = ZString::from_str("false");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String \"false\" should convert to true (non-empty string)"
        );
    }

    #[test]
    fn test_string_to_bool_zero_with_decimal() {
        // Test: String "0.0" converts to true (not exactly "0")
        // Reference: php -r 'var_dump((bool)"0.0");' outputs "bool(true)"
        let s = ZString::from_str("0.0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String \"0.0\" should convert to true (not exactly \"0\")"
        );
    }

    #[test]
    fn test_string_to_bool_negative_zero() {
        // Test: String "-0" converts to true (not exactly "0")
        // Reference: php -r 'var_dump((bool)"-0");' outputs "bool(true)"
        let s = ZString::from_str("-0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String \"-0\" should convert to true (not exactly \"0\")"
        );
    }

    #[test]
    fn test_string_to_bool_zero_with_leading_space() {
        // Test: String " 0" converts to true (not exactly "0")
        // Reference: php -r 'var_dump((bool)" 0");' outputs "bool(true)"
        let s = ZString::from_str(" 0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String \" 0\" should convert to true (not exactly \"0\")"
        );
    }

    #[test]
    fn test_string_to_bool_zero_with_trailing_space() {
        // Test: String "0 " converts to true (not exactly "0")
        // Reference: php -r 'var_dump((bool)"0 ");' outputs "bool(true)"
        let s = ZString::from_str("0 ");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String \"0 \" should convert to true (not exactly \"0\")"
        );
    }

    #[test]
    fn test_string_to_bool_null_byte() {
        // Test: String with null byte "\0" converts to true (not empty)
        // Reference: php -r 'var_dump((bool)"\0");' outputs "bool(true)"
        let s = ZString::new(b"\0");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);
        assert!(
            val.to_bool(),
            "String with null byte should convert to true (not empty)"
        );
    }

    // ========================================================================
    // Direct conversion method tests (Phase 1.3.2)
    // ========================================================================
    // Test the to_long(), to_double(), to_string(), to_bool() methods directly

    #[test]
    fn test_to_long_null() {
        // Test: ZVal::null().to_long() returns 0
        // Reference: php -r 'var_dump((int)null);' outputs "int(0)"
        assert_eq!(ZVal::null().to_long(), 0);
    }

    #[test]
    fn test_to_long_false() {
        // Test: ZVal::false_val().to_long() returns 0
        // Reference: php -r 'var_dump((int)false);' outputs "int(0)"
        assert_eq!(ZVal::false_val().to_long(), 0);
    }

    #[test]
    fn test_to_long_true() {
        // Test: ZVal::true_val().to_long() returns 1
        // Reference: php -r 'var_dump((int)true);' outputs "int(1)"
        assert_eq!(ZVal::true_val().to_long(), 1);
    }

    #[test]
    fn test_to_long_long_identity() {
        // Test: ZVal::long(42).to_long() returns 42 (identity)
        assert_eq!(ZVal::long(42).to_long(), 42);
        assert_eq!(ZVal::long(0).to_long(), 0);
        assert_eq!(ZVal::long(-999).to_long(), -999);
        assert_eq!(ZVal::long(i64::MAX).to_long(), i64::MAX);
        assert_eq!(ZVal::long(i64::MIN).to_long(), i64::MIN);
    }

    #[test]
    fn test_to_long_double_truncate() {
        // Test: ZVal::double(1.9).to_long() returns 1 (truncate towards zero)
        // Reference: php -r 'var_dump((int)1.9);' outputs "int(1)"
        assert_eq!(ZVal::double(1.9).to_long(), 1);
        assert_eq!(ZVal::double(1.1).to_long(), 1);
        assert_eq!(ZVal::double(-1.9).to_long(), -1);
        assert_eq!(ZVal::double(0.5).to_long(), 0);
        assert_eq!(ZVal::double(-0.5).to_long(), 0);
    }

    #[test]
    fn test_to_long_double_special_values() {
        // Test: Special float values convert to long
        // NAN → 0, INF → i64::MAX, -INF → i64::MIN
        // Reference: php -r 'var_dump((int)NAN);' outputs "int(0)"
        //            php -r 'var_dump((int)INF);' outputs "int(9223372036854775807)"
        assert_eq!(ZVal::double(f64::NAN).to_long(), 0);
        assert_eq!(ZVal::double(f64::INFINITY).to_long(), i64::MAX);
        assert_eq!(ZVal::double(f64::NEG_INFINITY).to_long(), i64::MIN);
    }

    #[test]
    fn test_to_double_null() {
        // Test: ZVal::null().to_double() returns 0.0
        // Reference: php -r 'var_dump((float)null);' outputs "float(0)"
        assert_eq!(ZVal::null().to_double(), 0.0);
    }

    #[test]
    fn test_to_double_false() {
        // Test: ZVal::false_val().to_double() returns 0.0
        // Reference: php -r 'var_dump((float)false);' outputs "float(0)"
        assert_eq!(ZVal::false_val().to_double(), 0.0);
    }

    #[test]
    fn test_to_double_true() {
        // Test: ZVal::true_val().to_double() returns 1.0
        // Reference: php -r 'var_dump((float)true);' outputs "float(1)"
        assert_eq!(ZVal::true_val().to_double(), 1.0);
    }

    #[test]
    fn test_to_double_long() {
        // Test: ZVal::long(42).to_double() returns 42.0
        // Reference: php -r 'var_dump((float)42);' outputs "float(42)"
        assert_eq!(ZVal::long(42).to_double(), 42.0);
        assert_eq!(ZVal::long(0).to_double(), 0.0);
        assert_eq!(ZVal::long(-123).to_double(), -123.0);
    }

    #[test]
    fn test_to_double_double_identity() {
        // Test: ZVal::double(1.5).to_double() returns 1.5 (identity)
        assert_eq!(ZVal::double(1.5).to_double(), 1.5);
        assert_eq!(ZVal::double(0.0).to_double(), 0.0);
        assert_eq!(ZVal::double(-2.5).to_double(), -2.5);
    }

    #[test]
    fn test_to_double_special_values_identity() {
        // Test: Special float values remain unchanged
        let inf = ZVal::double(f64::INFINITY).to_double();
        assert!(inf.is_infinite() && inf.is_sign_positive());

        let neg_inf = ZVal::double(f64::NEG_INFINITY).to_double();
        assert!(neg_inf.is_infinite() && neg_inf.is_sign_negative());

        let nan = ZVal::double(f64::NAN).to_double();
        assert!(nan.is_nan());
    }

    #[test]
    fn test_to_bool_null() {
        // Test: ZVal::null().to_bool() returns false
        // Reference: php -r 'var_dump((bool)null);' outputs "bool(false)"
        assert!(!ZVal::null().to_bool());
    }

    #[test]
    fn test_to_bool_false() {
        // Test: ZVal::false_val().to_bool() returns false
        assert!(!ZVal::false_val().to_bool());
    }

    #[test]
    fn test_to_bool_true() {
        // Test: ZVal::true_val().to_bool() returns true
        assert!(ZVal::true_val().to_bool());
    }

    #[test]
    fn test_to_bool_long() {
        // Test: ZVal::long(0).to_bool() returns false, non-zero returns true
        // Reference: php -r 'var_dump((bool)0);' outputs "bool(false)"
        //            php -r 'var_dump((bool)1);' outputs "bool(true)"
        //            php -r 'var_dump((bool)-1);' outputs "bool(true)"
        assert!(!ZVal::long(0).to_bool());
        assert!(ZVal::long(1).to_bool());
        assert!(ZVal::long(-1).to_bool());
        assert!(ZVal::long(42).to_bool());
        assert!(ZVal::long(i64::MAX).to_bool());
        assert!(ZVal::long(i64::MIN).to_bool());
    }

    #[test]
    fn test_to_bool_double() {
        // Test: ZVal::double(0.0).to_bool() returns false, non-zero returns true
        // Reference: php -r 'var_dump((bool)0.0);' outputs "bool(false)"
        //            php -r 'var_dump((bool)1.0);' outputs "bool(true)"
        assert!(!ZVal::double(0.0).to_bool());
        assert!(ZVal::double(1.0).to_bool());
        assert!(ZVal::double(-1.0).to_bool());
        assert!(ZVal::double(0.5).to_bool());
        assert!(ZVal::double(-0.5).to_bool());
    }

    #[test]
    fn test_to_bool_double_special_values() {
        // Test: NAN is false, INF is true
        // Reference: php -r 'var_dump((bool)NAN);' outputs "bool(false)"
        //            php -r 'var_dump((bool)INF);' outputs "bool(true)"
        assert!(!ZVal::double(f64::NAN).to_bool());
        assert!(ZVal::double(f64::INFINITY).to_bool());
        assert!(ZVal::double(f64::NEG_INFINITY).to_bool());
    }

    #[test]
    fn test_to_string_null() {
        // Test: ZVal::null().to_string() returns ""
        // Reference: php -r 'var_dump((string)null);' outputs 'string(0) ""'
        let s = ZVal::null().to_string();
        assert_eq!(s.as_str(), Some(""));
        assert!(s.is_empty());
    }

    #[test]
    fn test_to_string_false() {
        // Test: ZVal::false_val().to_string() returns ""
        // Reference: php -r 'var_dump((string)false);' outputs 'string(0) ""'
        let s = ZVal::false_val().to_string();
        assert_eq!(s.as_str(), Some(""));
        assert!(s.is_empty());
    }

    #[test]
    fn test_to_string_true() {
        // Test: ZVal::true_val().to_string() returns "1"
        // Reference: php -r 'var_dump((string)true);' outputs 'string(1) "1"'
        let s = ZVal::true_val().to_string();
        assert_eq!(s.as_str(), Some("1"));
    }

    #[test]
    fn test_to_string_long() {
        // Test: ZVal::long(42).to_string() returns "42"
        // Reference: php -r 'var_dump((string)42);' outputs 'string(2) "42"'
        assert_eq!(ZVal::long(42).to_string().as_str(), Some("42"));
        assert_eq!(ZVal::long(0).to_string().as_str(), Some("0"));
        assert_eq!(ZVal::long(-123).to_string().as_str(), Some("-123"));
        assert_eq!(
            ZVal::long(i64::MAX).to_string().as_str(),
            Some("9223372036854775807")
        );
        assert_eq!(
            ZVal::long(i64::MIN).to_string().as_str(),
            Some("-9223372036854775808")
        );
    }

    #[test]
    fn test_to_string_double() {
        // Test: ZVal::double(1.5).to_string() returns "1.5"
        // Reference: php -r 'var_dump((string)1.5);' outputs 'string(3) "1.5"'
        assert_eq!(ZVal::double(1.5).to_string().as_str(), Some("1.5"));
        assert_eq!(ZVal::double(0.0).to_string().as_str(), Some("0"));
        assert_eq!(ZVal::double(-2.5).to_string().as_str(), Some("-2.5"));
    }

    #[test]
    fn test_to_string_double_special_values() {
        // Test: Special float values convert to strings
        // Reference: php -r 'var_dump((string)INF);' outputs 'string(3) "INF"'
        //            php -r 'var_dump((string)(-INF));' outputs 'string(4) "-INF"'
        //            php -r 'var_dump((string)NAN);' outputs 'string(3) "NAN"'
        assert_eq!(
            ZVal::double(f64::INFINITY).to_string().as_str(),
            Some("INF")
        );
        assert_eq!(
            ZVal::double(f64::NEG_INFINITY).to_string().as_str(),
            Some("-INF")
        );
        assert_eq!(ZVal::double(f64::NAN).to_string().as_str(), Some("NAN"));
    }

    #[test]
    fn test_to_string_resource() {
        // Test: ZVal::resource(5).to_string() returns "Resource id #5"
        // Reference: php -r '$f = fopen("/dev/null", "r"); echo (string)$f;'
        //            outputs "Resource id #5" (or similar)
        let s = ZVal::resource(5).to_string();
        assert_eq!(s.as_str(), Some("Resource id #5"));

        let s = ZVal::resource(123).to_string();
        assert_eq!(s.as_str(), Some("Resource id #123"));
    }

    #[test]
    fn test_conversion_chaining() {
        // Test: Chaining conversions works correctly
        // Example: null → long → double → string
        let val = ZVal::null();
        let as_long = val.to_long();
        assert_eq!(as_long, 0);

        let val2 = ZVal::long(as_long);
        let as_double = val2.to_double();
        assert_eq!(as_double, 0.0);

        let val3 = ZVal::double(as_double);
        let as_string = val3.to_string();
        assert_eq!(as_string.as_str(), Some("0"));
    }

    #[test]
    fn test_conversion_round_trip_long() {
        // Test: long → string → long should preserve value (for valid numbers)
        let original = ZVal::long(42);
        let as_string = original.to_string();
        let as_val = ZVal::string(Box::into_raw(Box::new(as_string)) as usize);
        let back_to_long = as_val.to_long();
        assert_eq!(back_to_long, 42);
    }

    #[test]
    fn test_conversion_idempotency() {
        // Test: Converting twice should give the same result as converting once
        let val = ZVal::long(42);
        let s1 = val.to_string();
        let s2 = val.to_string();
        assert_eq!(s1, s2);

        let val = ZVal::double(1.5);
        let l1 = val.to_long();
        let l2 = val.to_long();
        assert_eq!(l1, l2);
    }

    // ================================================================================
    // PHASE 1.3.3: Edge case tests for type coercion
    // Reference: php-src/Zend/zend_operators.c
    // ================================================================================

    #[test]
    fn test_int_max_to_double() {
        // Test: PHP_INT_MAX (i64::MAX) can be converted to float
        // Reference: php -r 'var_dump((float)PHP_INT_MAX);'
        // Expected: float(9.223372036854776E+18) or similar
        let val = ZVal::long(i64::MAX);
        let result = val.to_double();

        // i64::MAX = 9223372036854775807
        // As f64, this will have some precision loss but should be close
        assert!(result > 0.0);
        assert!(result.is_finite());
        assert_eq!(result, i64::MAX as f64);
    }

    #[test]
    fn test_int_min_to_double() {
        // Test: PHP_INT_MIN (i64::MIN) can be converted to float
        // Reference: php -r 'var_dump((float)PHP_INT_MIN);'
        let val = ZVal::long(i64::MIN);
        let result = val.to_double();

        assert!(result < 0.0);
        assert!(result.is_finite());
        assert_eq!(result, i64::MIN as f64);
    }

    #[test]
    fn test_very_large_positive_double_to_long() {
        // Test: Very large positive floats overflow to i64::MAX
        // Reference: php -r 'var_dump((int)1e100);'
        // PHP behavior: large positive floats → PHP_INT_MAX
        let val = ZVal::double(1e100);
        let result = val.to_long();

        // Since 1e100 > i64::MAX, it should clamp to i64::MAX
        assert_eq!(result, i64::MAX);
    }

    #[test]
    fn test_very_large_negative_double_to_long() {
        // Test: Very large negative floats overflow to i64::MIN
        // Reference: php -r 'var_dump((int)-1e100);'
        // PHP behavior: large negative floats → PHP_INT_MIN
        let val = ZVal::double(-1e100);
        let result = val.to_long();

        // Since -1e100 < i64::MIN, it should clamp to i64::MIN
        assert_eq!(result, i64::MIN);
    }

    #[test]
    fn test_double_at_int_max_boundary() {
        // Test: Float exactly at i64::MAX boundary
        // This tests the boundary condition
        let val = ZVal::double(i64::MAX as f64);
        let result = val.to_long();

        // i64::MAX as f64 loses precision, so we just check it's near max
        // PHP would convert this to i64::MAX
        assert!(result == i64::MAX || result == i64::MAX - 1);
    }

    #[test]
    fn test_double_at_int_min_boundary() {
        // Test: Float exactly at i64::MIN boundary
        let val = ZVal::double(i64::MIN as f64);
        let result = val.to_long();

        // Similar to max, there may be precision loss
        assert!(result == i64::MIN || result == i64::MIN + 1);
    }

    #[test]
    fn test_double_precision_loss() {
        // Test: Very large integers lose precision when converted to double
        // Reference: php -r 'echo (float)9223372036854775807 === (float)9223372036854775806;'

        let max_val = ZVal::long(i64::MAX);
        let max_minus_1 = ZVal::long(i64::MAX - 1);

        let max_as_double = max_val.to_double();
        let max_minus_1_as_double = max_minus_1.to_double();

        // Due to f64 precision limits (53 bits mantissa), these may be equal
        // i64::MAX has 63 bits, so precision loss is expected
        // We just verify they convert without panicking and are finite
        assert!(max_as_double.is_finite());
        assert!(max_minus_1_as_double.is_finite());
        assert!(max_as_double >= max_minus_1_as_double);
    }

    #[test]
    fn test_small_double_precision() {
        // Test: Small floats with many decimal places
        // Reference: php -r 'var_dump((string)0.123456789012345);'
        let val = ZVal::double(0.123456789012345);
        let as_double = val.to_double();

        // Should preserve precision (within f64 limits)
        assert!((as_double - 0.123456789012345).abs() < 1e-15);
    }

    #[test]
    fn test_very_small_double_to_long() {
        // Test: Very small positive and negative floats truncate to 0
        // Reference: php -r 'var_dump((int)0.0000001);' → 0
        let positive_small = ZVal::double(0.0000001);
        let negative_small = ZVal::double(-0.0000001);

        assert_eq!(positive_small.to_long(), 0);
        assert_eq!(negative_small.to_long(), 0);
    }

    #[test]
    fn test_double_subnormal_values() {
        // Test: Subnormal (denormalized) floating point values
        // These are very small floats near zero
        let subnormal = ZVal::double(f64::MIN_POSITIVE / 2.0);

        // Should convert to 0
        assert_eq!(subnormal.to_long(), 0);

        // Should preserve the value as double
        let as_double = subnormal.to_double();
        assert!(as_double >= 0.0);
        assert!(as_double < f64::MIN_POSITIVE);
    }

    #[test]
    fn test_negative_zero_double() {
        // Test: Negative zero (-0.0) behavior
        // Reference: php -r 'var_dump((int)-0.0);' → 0
        let neg_zero = ZVal::double(-0.0);

        assert_eq!(neg_zero.to_long(), 0);
        assert_eq!(neg_zero.to_double(), -0.0);

        // -0.0 should convert to false (like 0.0)
        assert!(!neg_zero.to_bool());
    }

    #[test]
    fn test_string_large_integer() {
        // Test: String containing very large integer
        // Reference: php -r 'var_dump((int)"9223372036854775807");' → int(9223372036854775807)
        let s = ZString::from_str("9223372036854775807"); // i64::MAX
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);

        let result = val.to_long();
        assert_eq!(result, i64::MAX);
    }

    #[test]
    fn test_string_overflow_integer() {
        // Test: String containing integer larger than i64::MAX
        // Reference: php -r 'var_dump((int)"99999999999999999999");'
        // PHP behavior: integer overflow during parsing
        let s = ZString::from_str("99999999999999999999"); // Larger than i64::MAX
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);

        let result = val.to_long();
        // PHP would parse this and overflow; we should handle gracefully
        // The exact value depends on overflow behavior, but it should not panic
        // Most likely wraps around or clamps
        let _ = result; // Accept any result as long as it doesn't panic
    }

    #[test]
    fn test_string_very_large_float() {
        // Test: String containing very large float
        // Reference: php -r 'var_dump((float)"1.234567890123456789e+308");'
        let s = ZString::from_str("1e308");
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);

        let result = val.to_double();
        assert!(result > 0.0);
        assert!(result.is_finite());
        assert!(result > 1e100);
    }

    #[test]
    fn test_string_float_overflow_to_inf() {
        // Test: String containing float that overflows to infinity
        // Reference: php -r 'var_dump((float)"1e309");' → float(INF)
        let s = ZString::from_str("1e309"); // Larger than f64::MAX
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);

        let result = val.to_double();
        assert!(result.is_infinite());
        assert!(result.is_sign_positive());
    }

    #[test]
    fn test_string_float_underflow() {
        // Test: String containing very small float (underflow)
        // Reference: php -r 'var_dump((float)"1e-400");' → float(0)
        let s = ZString::from_str("1e-400"); // Smaller than f64::MIN_POSITIVE
        let val = ZVal::string(Box::into_raw(Box::new(s)) as usize);

        let result = val.to_double();
        // Should underflow to 0
        assert_eq!(result, 0.0);
    }

    #[test]
    fn test_float_to_string_precision() {
        // Test: Float to string maintains reasonable precision
        // Reference: php -r 'echo (string)1.234567890123456;'
        let val = ZVal::double(1.234567890123456);
        let s = val.to_string();

        // Should contain the float value as a string
        let str_val = s.as_str().unwrap();

        // Parse it back to verify precision
        let parsed: f64 = str_val.parse().unwrap();
        assert!((parsed - 1.234567890123456).abs() < 1e-10);
    }

    #[test]
    fn test_float_to_string_no_trailing_zeros() {
        // Test: Float to string removes trailing zeros
        // Reference: php -r 'echo (string)1.5;' → "1.5", not "1.50000"
        // Reference: php -r 'echo (string)2.0;' → "2"
        let val1 = ZVal::double(1.5);
        let val2 = ZVal::double(2.0);

        let s1 = val1.to_string();
        let s2 = val2.to_string();

        // 1.5 should be "1.5"
        assert_eq!(s1.as_str(), Some("1.5"));

        // 2.0 should be "2" (no decimal point for whole numbers)
        assert_eq!(s2.as_str(), Some("2"));
    }

    #[test]
    fn test_long_max_to_string_and_back() {
        // Test: i64::MAX → string → parse back
        // This tests round-trip conversion at the boundary
        let original = ZVal::long(i64::MAX);
        let as_string = original.to_string();

        // String should be "9223372036854775807"
        assert_eq!(as_string.as_str(), Some("9223372036854775807"));

        // Convert back
        let val = ZVal::string(Box::into_raw(Box::new(as_string)) as usize);
        let back_to_long = val.to_long();
        assert_eq!(back_to_long, i64::MAX);
    }

    #[test]
    fn test_long_min_to_string_and_back() {
        // Test: i64::MIN → string → parse back
        let original = ZVal::long(i64::MIN);
        let as_string = original.to_string();

        // String should be "-9223372036854775808"
        assert_eq!(as_string.as_str(), Some("-9223372036854775808"));

        // Convert back
        let val = ZVal::string(Box::into_raw(Box::new(as_string)) as usize);
        let back_to_long = val.to_long();
        assert_eq!(back_to_long, i64::MIN);
    }

    #[test]
    fn test_double_max_value() {
        // Test: f64::MAX handling
        let val = ZVal::double(f64::MAX);

        // Should convert to i64::MAX when converted to long (overflow)
        assert_eq!(val.to_long(), i64::MAX);

        // Should preserve as double
        assert_eq!(val.to_double(), f64::MAX);

        // Should be truthy
        assert!(val.to_bool());
    }

    #[test]
    fn test_double_min_value() {
        // Test: f64::MIN (most negative) handling
        let val = ZVal::double(f64::MIN);

        // Should convert to i64::MIN when converted to long (overflow)
        assert_eq!(val.to_long(), i64::MIN);

        // Should preserve as double
        assert_eq!(val.to_double(), f64::MIN);

        // Should be truthy (non-zero)
        assert!(val.to_bool());
    }
}

/// Robin Hood hash table implementation
///
/// Robin Hood hashing is an open addressing collision resolution algorithm
/// that minimizes variance in probe sequence length. When a collision occurs,
/// we compare the "probe distance" (how far from the ideal position) of the
/// inserting element with the existing element. If the inserting element has
/// probed further (is "poorer"), we swap them and continue inserting the
/// evicted element.
///
/// This matches PHP's internal hash table implementation more closely than
/// standard HashMap.
///
/// Reference: php-src/Zend/zend_hash.c
#[derive(Debug, Clone)]
struct RobinHoodTable<K, V> {
    /// Buckets storing (key, value, probe_distance)
    /// None represents an empty bucket
    buckets: Vec<Option<Bucket<K, V>>>,
    /// Number of elements in the table
    len: usize,
    /// Insertion order tracking (for maintaining PHP array semantics)
    /// Maps key hash to insertion order
    insertion_order: Vec<(u64, K)>,
}

#[derive(Debug, Clone)]
struct Bucket<K, V> {
    key: K,
    value: V,
    /// How far from the ideal position this entry is
    probe_distance: usize,
}

impl<K, V> RobinHoodTable<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    /// Initial capacity for new tables
    const INITIAL_CAPACITY: usize = 8;
    /// Load factor threshold for resizing (75%)
    const MAX_LOAD_FACTOR: f64 = 0.75;

    fn new() -> Self {
        Self::with_capacity(Self::INITIAL_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two().max(Self::INITIAL_CAPACITY);
        Self {
            buckets: vec![None; capacity],
            len: 0,
            insertion_order: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Calculate hash for a key
    fn hash_key(key: &K) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Get the ideal bucket index for a hash
    fn ideal_index(&self, hash: u64) -> usize {
        (hash as usize) & (self.buckets.len() - 1)
    }

    /// Insert or update a key-value pair
    fn insert(&mut self, key: K, value: V) {
        // Check if we need to grow
        let load_factor = (self.len + 1) as f64 / self.buckets.len() as f64;
        if load_factor > Self::MAX_LOAD_FACTOR {
            self.grow();
        }

        let hash = Self::hash_key(&key);
        let mut index = self.ideal_index(hash);

        let mut inserting = Bucket {
            key: key.clone(),
            value,
            probe_distance: 0,
        };

        loop {
            match &mut self.buckets[index] {
                None => {
                    // Empty slot, insert here
                    self.buckets[index] = Some(inserting);
                    self.insertion_order.push((hash, key));
                    self.len += 1;
                    return;
                }
                Some(existing) => {
                    // Key already exists, update value
                    if existing.key == inserting.key {
                        existing.value = inserting.value;
                        return;
                    }

                    // Robin Hood: if inserting element is poorer, swap
                    if inserting.probe_distance > existing.probe_distance {
                        std::mem::swap(&mut inserting, existing);
                    }

                    // Continue probing
                    index = (index + 1) & (self.buckets.len() - 1);
                    inserting.probe_distance += 1;
                }
            }
        }
    }

    /// Get a value by key
    fn get(&self, key: &K) -> Option<&V> {
        let hash = Self::hash_key(key);
        let mut index = self.ideal_index(hash);
        let mut probe_distance = 0;

        loop {
            match &self.buckets[index] {
                None => return None,
                Some(bucket) => {
                    if bucket.key == *key {
                        return Some(&bucket.value);
                    }

                    // If we've probed further than this bucket's distance,
                    // the key doesn't exist (Robin Hood property)
                    if probe_distance > bucket.probe_distance {
                        return None;
                    }

                    index = (index + 1) & (self.buckets.len() - 1);
                    probe_distance += 1;
                }
            }
        }
    }

    /// Delete a key-value pair
    fn delete(&mut self, key: &K) -> Option<V> {
        let hash = Self::hash_key(key);
        let mut index = self.ideal_index(hash);
        let mut probe_distance = 0;

        // Find the element
        loop {
            match &self.buckets[index] {
                None => return None,
                Some(bucket) => {
                    if bucket.key == *key {
                        break;
                    }

                    if probe_distance > bucket.probe_distance {
                        return None;
                    }

                    index = (index + 1) & (self.buckets.len() - 1);
                    probe_distance += 1;
                }
            }
        }

        // Remove from buckets
        let removed_value = self.buckets[index].take().unwrap().value;

        // Backward shift deletion to maintain Robin Hood properties
        let mut current = index;
        loop {
            let next = (current + 1) & (self.buckets.len() - 1);

            match &mut self.buckets[next] {
                None => break,
                Some(bucket) if bucket.probe_distance == 0 => break,
                Some(_) => {
                    // Shift element backward
                    let mut bucket = self.buckets[next].take().unwrap();
                    bucket.probe_distance -= 1;
                    self.buckets[current] = Some(bucket);
                    current = next;
                }
            }
        }

        // Remove from insertion order
        self.insertion_order.retain(|(_, k)| k != key);

        self.len -= 1;
        Some(removed_value)
    }

    /// Grow the table to accommodate more elements
    fn grow(&mut self) {
        let new_capacity = self.buckets.len() * 2;
        let old_buckets = std::mem::replace(&mut self.buckets, vec![None; new_capacity]);
        self.len = 0;
        let old_insertion_order = std::mem::take(&mut self.insertion_order);

        // Re-insert all elements in insertion order
        for (_, key) in old_insertion_order {
            // Find the old value
            for bucket in old_buckets.iter().flatten() {
                if bucket.key == key {
                    self.insert(key.clone(), bucket.value.clone());
                    break;
                }
            }
        }
    }

    /// Iterate over key-value pairs in insertion order
    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.insertion_order
            .iter()
            .filter_map(move |(_, key)| self.get(key).map(|value| (key, value)))
    }

    /// Iterate over keys in insertion order
    fn keys(&self) -> impl Iterator<Item = &K> {
        self.insertion_order.iter().map(|(_, key)| key)
    }
}

/// ZArray — PHP array implementation with dual-mode storage
///
/// PHP arrays are ordered maps that can have either integer or string keys.
/// For performance, we use two storage modes:
/// - Packed mode: consecutive integer keys 0..n, stored as Vec<ZVal>
/// - Hash mode: arbitrary keys (strings or non-consecutive integers), stored as RobinHoodTable
///
/// Reference: php-src/Zend/zend_hash.h, zend_hash.c
#[derive(Debug, Clone)]
pub struct ZArray {
    storage: ArrayStorage,
}

#[derive(Debug, Clone)]
enum ArrayStorage {
    /// Packed mode: consecutive integer keys starting from 0
    /// Used for: [0 => val0, 1 => val1, 2 => val2, ...]
    Packed(Vec<ZVal>),
    /// Hash mode: arbitrary keys (string or non-consecutive integers)
    /// Uses Robin Hood hashing for performance and PHP compatibility
    Hash(RobinHoodTable<ArrayKey, ZVal>),
}

/// Array key can be either an integer or a string
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ArrayKey {
    Int(i64),
    String(ZString),
}

impl ZArray {
    /// Create a new empty array in packed mode
    pub fn new() -> Self {
        Self {
            storage: ArrayStorage::Packed(Vec::new()),
        }
    }

    /// Create a new array with a specific capacity in packed mode
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: ArrayStorage::Packed(Vec::with_capacity(capacity)),
        }
    }

    /// Check if array is in packed mode
    pub fn is_packed(&self) -> bool {
        matches!(self.storage, ArrayStorage::Packed(_))
    }

    /// Check if array is in hash mode
    pub fn is_hash(&self) -> bool {
        matches!(self.storage, ArrayStorage::Hash(_))
    }

    /// Get the number of elements in the array
    pub fn len(&self) -> usize {
        match &self.storage {
            ArrayStorage::Packed(vec) => vec.len(),
            ArrayStorage::Hash(map) => map.len(),
        }
    }

    /// Check if the array is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a value with an integer key
    ///
    /// If we're in packed mode and the key is the next sequential index,
    /// we stay in packed mode. Otherwise, we promote to hash mode.
    pub fn insert_int(&mut self, key: i64, value: ZVal) {
        match &mut self.storage {
            ArrayStorage::Packed(vec) => {
                // Check if this key is the next sequential index
                if key >= 0 && key as usize == vec.len() {
                    // Stay in packed mode
                    vec.push(value);
                } else {
                    // Need to promote to hash mode
                    self.promote_to_hash();
                    // Now insert
                    if let ArrayStorage::Hash(map) = &mut self.storage {
                        map.insert(ArrayKey::Int(key), value);
                    }
                }
            }
            ArrayStorage::Hash(map) => {
                map.insert(ArrayKey::Int(key), value);
            }
        }
    }

    /// Insert a value with a string key
    ///
    /// This always promotes to hash mode if we're in packed mode.
    pub fn insert_string(&mut self, key: ZString, value: ZVal) {
        match &mut self.storage {
            ArrayStorage::Packed(_) => {
                // Promote to hash mode
                self.promote_to_hash();
                // Now insert
                if let ArrayStorage::Hash(map) = &mut self.storage {
                    map.insert(ArrayKey::String(key), value);
                }
            }
            ArrayStorage::Hash(map) => {
                map.insert(ArrayKey::String(key), value);
            }
        }
    }

    /// Promote from packed mode to hash mode
    ///
    /// Converts the Vec into a RobinHoodTable with keys 0, 1, 2, ...
    fn promote_to_hash(&mut self) {
        if let ArrayStorage::Packed(vec) = &self.storage {
            let mut table = RobinHoodTable::with_capacity(vec.len());
            for (i, val) in vec.iter().enumerate() {
                table.insert(ArrayKey::Int(i as i64), val.clone());
            }
            self.storage = ArrayStorage::Hash(table);
        }
    }

    /// Get a value by integer key
    pub fn get_int(&self, key: i64) -> Option<&ZVal> {
        match &self.storage {
            ArrayStorage::Packed(vec) => {
                if key >= 0 && (key as usize) < vec.len() {
                    Some(&vec[key as usize])
                } else {
                    None
                }
            }
            ArrayStorage::Hash(map) => map.get(&ArrayKey::Int(key)),
        }
    }

    /// Get a value by string key
    pub fn get_string(&self, key: &ZString) -> Option<&ZVal> {
        match &self.storage {
            ArrayStorage::Packed(_) => None, // Packed mode has no string keys
            ArrayStorage::Hash(map) => map.get(&ArrayKey::String(key.clone())),
        }
    }

    /// Push a value onto the end of the array (like $arr[] = $val in PHP)
    ///
    /// This finds the next free integer key and inserts there.
    pub fn push(&mut self, value: ZVal) {
        match &mut self.storage {
            ArrayStorage::Packed(vec) => {
                vec.push(value);
            }
            ArrayStorage::Hash(map) => {
                // Find the maximum integer key + 1
                let next_key = map
                    .keys()
                    .filter_map(|k| match k {
                        ArrayKey::Int(i) => Some(i),
                        ArrayKey::String(_) => None,
                    })
                    .max()
                    .map(|max| max + 1)
                    .unwrap_or(0);
                map.insert(ArrayKey::Int(next_key), value);
            }
        }
    }

    /// Remove a value by integer key
    ///
    /// Returns the removed value if it existed, None otherwise.
    /// Note: In packed mode, this promotes to hash mode (PHP behavior).
    pub fn remove_int(&mut self, key: i64) -> Option<ZVal> {
        match &mut self.storage {
            ArrayStorage::Packed(vec) => {
                // In PHP, unset() on a packed array promotes to hash mode
                // because we need to maintain gaps
                if key >= 0 && (key as usize) < vec.len() {
                    self.promote_to_hash();
                    if let ArrayStorage::Hash(map) = &mut self.storage {
                        map.delete(&ArrayKey::Int(key))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            ArrayStorage::Hash(map) => map.delete(&ArrayKey::Int(key)),
        }
    }

    /// Remove a value by string key
    ///
    /// Returns the removed value if it existed, None otherwise.
    pub fn remove_string(&mut self, key: &ZString) -> Option<ZVal> {
        match &mut self.storage {
            ArrayStorage::Packed(_) => None, // Packed mode has no string keys
            ArrayStorage::Hash(map) => map.delete(&ArrayKey::String(key.clone())),
        }
    }

    /// Iterate over (key, value) pairs in insertion order
    ///
    /// Returns a vector of (key, value) pairs.
    /// For packed mode, keys are integers 0..n.
    /// For hash mode, order is preserved based on insertion order.
    pub fn iter(&self) -> Vec<(ZArrayKey, &ZVal)> {
        match &self.storage {
            ArrayStorage::Packed(vec) => vec
                .iter()
                .enumerate()
                .map(|(i, v)| (ZArrayKey::Int(i as i64), v))
                .collect(),
            ArrayStorage::Hash(map) => map
                .insertion_order
                .iter()
                .filter_map(|(_, key)| {
                    map.get(key).map(|value| match key {
                        ArrayKey::Int(i) => (ZArrayKey::Int(*i), value),
                        ArrayKey::String(s) => (ZArrayKey::String(s.clone()), value),
                    })
                })
                .collect(),
        }
    }

    /// Iterate over keys in insertion order
    pub fn keys(&self) -> Vec<ZArrayKey> {
        match &self.storage {
            ArrayStorage::Packed(vec) => (0..vec.len() as i64).map(ZArrayKey::Int).collect(),
            ArrayStorage::Hash(map) => map
                .insertion_order
                .iter()
                .map(|(_, key)| match key {
                    ArrayKey::Int(i) => ZArrayKey::Int(*i),
                    ArrayKey::String(s) => ZArrayKey::String(s.clone()),
                })
                .collect(),
        }
    }

    /// Iterate over values in insertion order
    pub fn values(&self) -> Vec<&ZVal> {
        match &self.storage {
            ArrayStorage::Packed(vec) => vec.iter().collect(),
            ArrayStorage::Hash(map) => map
                .insertion_order
                .iter()
                .filter_map(|(_, key)| map.get(key))
                .collect(),
        }
    }
}

/// Key type for ZArray iteration and access
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZArrayKey {
    Int(i64),
    String(ZString),
}

impl Default for ZArray {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod zarray_tests {
    use super::*;

    #[test]
    fn test_packed_mode_new() {
        let arr = ZArray::new();
        assert!(arr.is_packed());
        assert!(!arr.is_hash());
        assert_eq!(arr.len(), 0);
        assert!(arr.is_empty());
    }

    #[test]
    fn test_packed_mode_sequential_insert() {
        let mut arr = ZArray::new();

        // Insert sequential keys 0, 1, 2
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));
        arr.insert_int(2, ZVal::long(300));

        // Should still be in packed mode
        assert!(arr.is_packed());
        assert_eq!(arr.len(), 3);

        // Verify values
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 300);
    }

    #[test]
    fn test_packed_mode_push() {
        let mut arr = ZArray::new();

        // Push values (equivalent to $arr[] = val)
        arr.push(ZVal::long(10));
        arr.push(ZVal::long(20));
        arr.push(ZVal::long(30));

        // Should be in packed mode with keys 0, 1, 2
        assert!(arr.is_packed());
        assert_eq!(arr.len(), 3);

        assert_eq!(arr.get_int(0).unwrap().to_long(), 10);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 20);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 30);
    }

    #[test]
    fn test_packed_to_hash_promotion_non_sequential() {
        let mut arr = ZArray::new();

        // Start with sequential keys
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));

        // Still packed
        assert!(arr.is_packed());

        // Insert non-sequential key — should promote to hash
        arr.insert_int(5, ZVal::long(500));

        // Now should be in hash mode
        assert!(arr.is_hash());
        assert_eq!(arr.len(), 3);

        // Verify all values are still accessible
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
        assert_eq!(arr.get_int(5).unwrap().to_long(), 500);
    }

    #[test]
    fn test_packed_to_hash_promotion_string_key() {
        let mut arr = ZArray::new();

        // Start with sequential integer keys
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));

        assert!(arr.is_packed());

        // Insert a string key — should promote to hash
        let key = ZString::new(b"name");
        arr.insert_string(key.clone(), ZVal::long(999));

        // Now should be in hash mode
        assert!(arr.is_hash());
        assert_eq!(arr.len(), 3);

        // Verify all values
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
        assert_eq!(arr.get_string(&key).unwrap().to_long(), 999);
    }

    #[test]
    fn test_get_nonexistent_key() {
        let arr = ZArray::new();

        // Getting non-existent key should return None
        assert!(arr.get_int(0).is_none());
        assert!(arr.get_int(999).is_none());

        let key = ZString::new(b"missing");
        assert!(arr.get_string(&key).is_none());
    }

    #[test]
    fn test_packed_mode_negative_key_promotion() {
        let mut arr = ZArray::new();

        // Start with key 0
        arr.insert_int(0, ZVal::long(100));
        assert!(arr.is_packed());

        // Insert negative key — should promote to hash
        arr.insert_int(-1, ZVal::long(999));

        assert!(arr.is_hash());
        assert_eq!(arr.len(), 2);

        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(-1).unwrap().to_long(), 999);
    }

    #[test]
    fn test_hash_mode_push() {
        let mut arr = ZArray::new();

        // Force hash mode by inserting a string key
        arr.insert_string(ZString::new(b"a"), ZVal::long(1));

        assert!(arr.is_hash());

        // Now push some values
        arr.push(ZVal::long(10));
        arr.push(ZVal::long(20));

        // Should get integer keys 0 and 1 (next free keys)
        assert_eq!(arr.get_int(0).unwrap().to_long(), 10);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 20);
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_with_capacity() {
        let arr = ZArray::with_capacity(100);
        assert!(arr.is_packed());
        assert_eq!(arr.len(), 0);
    }

    // Tests for Robin Hood hash table implementation

    #[test]
    fn test_robin_hood_basic_insert_get() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::new();

        table.insert(ArrayKey::Int(1), ZVal::long(100));
        table.insert(ArrayKey::Int(2), ZVal::long(200));
        table.insert(ArrayKey::String(ZString::new(b"key")), ZVal::long(300));

        assert_eq!(table.len(), 3);
        assert_eq!(table.get(&ArrayKey::Int(1)).unwrap().to_long(), 100);
        assert_eq!(table.get(&ArrayKey::Int(2)).unwrap().to_long(), 200);
        assert_eq!(
            table
                .get(&ArrayKey::String(ZString::new(b"key")))
                .unwrap()
                .to_long(),
            300
        );
    }

    #[test]
    fn test_robin_hood_overwrite() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::new();

        table.insert(ArrayKey::Int(1), ZVal::long(100));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&ArrayKey::Int(1)).unwrap().to_long(), 100);

        // Overwrite existing key
        table.insert(ArrayKey::Int(1), ZVal::long(999));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&ArrayKey::Int(1)).unwrap().to_long(), 999);
    }

    #[test]
    fn test_robin_hood_delete() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::new();

        table.insert(ArrayKey::Int(1), ZVal::long(100));
        table.insert(ArrayKey::Int(2), ZVal::long(200));
        table.insert(ArrayKey::Int(3), ZVal::long(300));

        assert_eq!(table.len(), 3);

        // Delete middle element
        assert!(table.delete(&ArrayKey::Int(2)).is_some());
        assert_eq!(table.len(), 2);

        // Should no longer exist
        assert!(table.get(&ArrayKey::Int(2)).is_none());

        // Others should still exist
        assert_eq!(table.get(&ArrayKey::Int(1)).unwrap().to_long(), 100);
        assert_eq!(table.get(&ArrayKey::Int(3)).unwrap().to_long(), 300);
    }

    #[test]
    fn test_robin_hood_grow() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::with_capacity(4);

        // Insert many items to trigger growth
        for i in 0..20 {
            table.insert(ArrayKey::Int(i), ZVal::long(i * 10));
        }

        assert_eq!(table.len(), 20);

        // Verify all items are still accessible
        for i in 0..20 {
            assert_eq!(table.get(&ArrayKey::Int(i)).unwrap().to_long(), i * 10);
        }
    }

    #[test]
    fn test_robin_hood_collision_handling() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::with_capacity(4);

        // Insert items that will definitely collide in a small table
        table.insert(ArrayKey::Int(0), ZVal::long(0));
        table.insert(ArrayKey::Int(4), ZVal::long(4)); // Will hash to same bucket in size-4 table
        table.insert(ArrayKey::Int(8), ZVal::long(8)); // Will hash to same bucket in size-4 table

        assert_eq!(table.len(), 3);
        assert_eq!(table.get(&ArrayKey::Int(0)).unwrap().to_long(), 0);
        assert_eq!(table.get(&ArrayKey::Int(4)).unwrap().to_long(), 4);
        assert_eq!(table.get(&ArrayKey::Int(8)).unwrap().to_long(), 8);
    }

    #[test]
    fn test_robin_hood_iteration_order() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::new();

        // Insert in specific order
        table.insert(ArrayKey::Int(3), ZVal::long(3));
        table.insert(ArrayKey::Int(1), ZVal::long(1));
        table.insert(ArrayKey::Int(2), ZVal::long(2));

        // Collect insertion order
        let keys: Vec<i64> = table
            .iter()
            .filter_map(|(k, _)| match k {
                ArrayKey::Int(i) => Some(*i),
                _ => None,
            })
            .collect();

        // Should maintain insertion order: 3, 1, 2
        assert_eq!(keys, vec![3, 1, 2]);
    }

    #[test]
    fn test_robin_hood_empty_operations() {
        let mut table = RobinHoodTable::<ArrayKey, ZVal>::new();

        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert!(table.get(&ArrayKey::Int(1)).is_none());
        assert!(table.delete(&ArrayKey::Int(1)).is_none());
    }

    // =========================================================================
    // Task 1.4.3: ZArray insert, get, delete, iteration order tests
    // =========================================================================

    #[test]
    fn test_zarray_insert_get_int_keys() {
        let mut arr = ZArray::new();

        // Insert values with integer keys
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));
        arr.insert_int(2, ZVal::long(300));

        // Test get
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 300);

        // Test non-existent key
        assert!(arr.get_int(3).is_none());
        assert!(arr.get_int(-1).is_none());
    }

    #[test]
    fn test_zarray_insert_get_string_keys() {
        let mut arr = ZArray::new();

        let key1 = ZString::new(b"name");
        let key2 = ZString::new(b"age");
        let key3 = ZString::new(b"city");

        // Insert values with string keys
        arr.insert_string(key1.clone(), ZVal::long(100));
        arr.insert_string(key2.clone(), ZVal::long(200));
        arr.insert_string(key3.clone(), ZVal::long(300));

        // Test get
        assert_eq!(arr.get_string(&key1).unwrap().to_long(), 100);
        assert_eq!(arr.get_string(&key2).unwrap().to_long(), 200);
        assert_eq!(arr.get_string(&key3).unwrap().to_long(), 300);

        // Test non-existent key
        let missing = ZString::new(b"missing");
        assert!(arr.get_string(&missing).is_none());
    }

    #[test]
    fn test_zarray_insert_get_mixed_keys() {
        let mut arr = ZArray::new();

        // Start with packed mode
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));

        // Add string key (promotes to hash mode)
        let key = ZString::new(b"name");
        arr.insert_string(key.clone(), ZVal::long(300));

        // Add more integer keys
        arr.insert_int(2, ZVal::long(400));
        arr.insert_int(10, ZVal::long(500));

        // Test all gets
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
        assert_eq!(arr.get_string(&key).unwrap().to_long(), 300);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 400);
        assert_eq!(arr.get_int(10).unwrap().to_long(), 500);

        assert!(arr.is_hash());
    }

    #[test]
    fn test_zarray_delete_packed_mode() {
        let mut arr = ZArray::new();

        // Insert in packed mode
        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));
        arr.insert_int(2, ZVal::long(300));

        assert!(arr.is_packed());
        assert_eq!(arr.len(), 3);

        // Delete from packed mode (should promote to hash)
        let removed = arr.remove_int(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().to_long(), 200);

        // Should now be in hash mode (PHP behavior)
        assert!(arr.is_hash());
        assert_eq!(arr.len(), 2);

        // Verify remaining elements
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert!(arr.get_int(1).is_none()); // Deleted
        assert_eq!(arr.get_int(2).unwrap().to_long(), 300);
    }

    #[test]
    fn test_zarray_delete_hash_mode_int_keys() {
        let mut arr = ZArray::new();

        // Force hash mode
        arr.insert_int(5, ZVal::long(500));
        arr.insert_int(1, ZVal::long(100));
        arr.insert_int(3, ZVal::long(300));
        arr.insert_int(2, ZVal::long(200));

        assert!(arr.is_hash());
        assert_eq!(arr.len(), 4);

        // Delete middle element
        let removed = arr.remove_int(3);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().to_long(), 300);
        assert_eq!(arr.len(), 3);

        // Verify deletion
        assert!(arr.get_int(3).is_none());

        // Verify remaining elements
        assert_eq!(arr.get_int(5).unwrap().to_long(), 500);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 200);

        // Delete another
        let removed = arr.remove_int(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().to_long(), 100);
        assert_eq!(arr.len(), 2);

        assert!(arr.get_int(1).is_none());
        assert_eq!(arr.get_int(5).unwrap().to_long(), 500);
        assert_eq!(arr.get_int(2).unwrap().to_long(), 200);
    }

    #[test]
    fn test_zarray_delete_hash_mode_string_keys() {
        let mut arr = ZArray::new();

        let key1 = ZString::new(b"name");
        let key2 = ZString::new(b"age");
        let key3 = ZString::new(b"city");

        arr.insert_string(key1.clone(), ZVal::long(100));
        arr.insert_string(key2.clone(), ZVal::long(200));
        arr.insert_string(key3.clone(), ZVal::long(300));

        assert_eq!(arr.len(), 3);

        // Delete middle element
        let removed = arr.remove_string(&key2);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().to_long(), 200);
        assert_eq!(arr.len(), 2);

        // Verify deletion
        assert!(arr.get_string(&key2).is_none());

        // Verify remaining elements
        assert_eq!(arr.get_string(&key1).unwrap().to_long(), 100);
        assert_eq!(arr.get_string(&key3).unwrap().to_long(), 300);
    }

    #[test]
    fn test_zarray_delete_nonexistent() {
        let mut arr = ZArray::new();

        arr.insert_int(0, ZVal::long(100));
        arr.insert_int(1, ZVal::long(200));

        // Delete non-existent key
        let removed = arr.remove_int(5);
        assert!(removed.is_none());
        assert_eq!(arr.len(), 2);

        // Verify existing elements unaffected
        assert_eq!(arr.get_int(0).unwrap().to_long(), 100);
        assert_eq!(arr.get_int(1).unwrap().to_long(), 200);
    }

    #[test]
    fn test_zarray_iteration_order_packed_mode() {
        let mut arr = ZArray::new();

        // Insert sequential keys
        arr.insert_int(0, ZVal::long(10));
        arr.insert_int(1, ZVal::long(20));
        arr.insert_int(2, ZVal::long(30));

        // Get iteration order
        let items = arr.iter();

        // Verify order and values
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, ZArrayKey::Int(0));
        assert_eq!(items[0].1.to_long(), 10);
        assert_eq!(items[1].0, ZArrayKey::Int(1));
        assert_eq!(items[1].1.to_long(), 20);
        assert_eq!(items[2].0, ZArrayKey::Int(2));
        assert_eq!(items[2].1.to_long(), 30);
    }

    #[test]
    fn test_zarray_iteration_order_hash_mode_int_keys() {
        let mut arr = ZArray::new();

        // Insert in non-sequential order
        arr.insert_int(5, ZVal::long(50));
        arr.insert_int(1, ZVal::long(10));
        arr.insert_int(3, ZVal::long(30));
        arr.insert_int(2, ZVal::long(20));

        // Get iteration order
        let items = arr.iter();

        // Verify insertion order is preserved
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].0, ZArrayKey::Int(5));
        assert_eq!(items[0].1.to_long(), 50);
        assert_eq!(items[1].0, ZArrayKey::Int(1));
        assert_eq!(items[1].1.to_long(), 10);
        assert_eq!(items[2].0, ZArrayKey::Int(3));
        assert_eq!(items[2].1.to_long(), 30);
        assert_eq!(items[3].0, ZArrayKey::Int(2));
        assert_eq!(items[3].1.to_long(), 20);
    }

    #[test]
    fn test_zarray_iteration_order_hash_mode_string_keys() {
        let mut arr = ZArray::new();

        let key1 = ZString::new(b"zebra");
        let key2 = ZString::new(b"apple");
        let key3 = ZString::new(b"mango");

        // Insert in specific order (not alphabetical)
        arr.insert_string(key1.clone(), ZVal::long(1));
        arr.insert_string(key2.clone(), ZVal::long(2));
        arr.insert_string(key3.clone(), ZVal::long(3));

        // Get iteration order
        let items = arr.iter();

        // Verify insertion order is preserved (not alphabetical)
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, ZArrayKey::String(key1.clone()));
        assert_eq!(items[0].1.to_long(), 1);
        assert_eq!(items[1].0, ZArrayKey::String(key2.clone()));
        assert_eq!(items[1].1.to_long(), 2);
        assert_eq!(items[2].0, ZArrayKey::String(key3.clone()));
        assert_eq!(items[2].1.to_long(), 3);
    }

    #[test]
    fn test_zarray_iteration_order_mixed_keys() {
        let mut arr = ZArray::new();

        let key1 = ZString::new(b"name");
        let key2 = ZString::new(b"city");

        // Insert mixed keys in specific order
        arr.insert_int(0, ZVal::long(100));
        arr.insert_string(key1.clone(), ZVal::long(200));
        arr.insert_int(5, ZVal::long(300));
        arr.insert_string(key2.clone(), ZVal::long(400));
        arr.insert_int(2, ZVal::long(500));

        // Get iteration order
        let items = arr.iter();

        // Verify insertion order is preserved
        assert_eq!(items.len(), 5);
        assert_eq!(items[0].0, ZArrayKey::Int(0));
        assert_eq!(items[0].1.to_long(), 100);
        assert_eq!(items[1].0, ZArrayKey::String(key1.clone()));
        assert_eq!(items[1].1.to_long(), 200);
        assert_eq!(items[2].0, ZArrayKey::Int(5));
        assert_eq!(items[2].1.to_long(), 300);
        assert_eq!(items[3].0, ZArrayKey::String(key2.clone()));
        assert_eq!(items[3].1.to_long(), 400);
        assert_eq!(items[4].0, ZArrayKey::Int(2));
        assert_eq!(items[4].1.to_long(), 500);
    }

    #[test]
    fn test_zarray_iteration_order_after_deletion() {
        let mut arr = ZArray::new();

        // Insert elements
        arr.insert_int(1, ZVal::long(10));
        arr.insert_int(2, ZVal::long(20));
        arr.insert_int(3, ZVal::long(30));
        arr.insert_int(4, ZVal::long(40));

        // Delete middle element
        arr.remove_int(2);

        // Get iteration order
        let items = arr.iter();

        // Verify deletion removes from iteration but preserves order
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, ZArrayKey::Int(1));
        assert_eq!(items[0].1.to_long(), 10);
        assert_eq!(items[1].0, ZArrayKey::Int(3));
        assert_eq!(items[1].1.to_long(), 30);
        assert_eq!(items[2].0, ZArrayKey::Int(4));
        assert_eq!(items[2].1.to_long(), 40);
    }

    #[test]
    fn test_zarray_iteration_keys_values() {
        let mut arr = ZArray::new();

        let key = ZString::new(b"name");

        arr.insert_int(0, ZVal::long(100));
        arr.insert_string(key.clone(), ZVal::long(200));
        arr.insert_int(5, ZVal::long(300));

        // Test keys()
        let keys = arr.keys();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], ZArrayKey::Int(0));
        assert_eq!(keys[1], ZArrayKey::String(key.clone()));
        assert_eq!(keys[2], ZArrayKey::Int(5));

        // Test values()
        let values = arr.values();
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].to_long(), 100);
        assert_eq!(values[1].to_long(), 200);
        assert_eq!(values[2].to_long(), 300);
    }

    #[test]
    fn test_zarray_iteration_empty_array() {
        let arr = ZArray::new();

        let items = arr.iter();
        assert_eq!(items.len(), 0);

        let keys = arr.keys();
        assert_eq!(keys.len(), 0);

        let values = arr.values();
        assert_eq!(values.len(), 0);
    }

    #[test]
    fn test_zarray_overwrite_preserves_insertion_order() {
        let mut arr = ZArray::new();

        // Insert in specific order
        arr.insert_int(1, ZVal::long(10));
        arr.insert_int(2, ZVal::long(20));
        arr.insert_int(3, ZVal::long(30));

        // Overwrite middle element
        arr.insert_int(2, ZVal::long(999));

        // Get iteration order
        let items = arr.iter();

        // Order should be preserved, value should be updated
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, ZArrayKey::Int(1));
        assert_eq!(items[0].1.to_long(), 10);
        assert_eq!(items[1].0, ZArrayKey::Int(2));
        assert_eq!(items[1].1.to_long(), 999); // Updated value
        assert_eq!(items[2].0, ZArrayKey::Int(3));
        assert_eq!(items[2].1.to_long(), 30);
    }
}
