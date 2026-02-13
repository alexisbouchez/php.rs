//! PHP value type for VM execution.
//!
//! High-level representation for correctness-first development.
//! Can be optimized to use the 16-byte ZVal layout from php-rs-types later.

use std::collections::HashMap;
use std::fmt;

/// A PHP value used during VM execution.
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Long(i64),
    Double(f64),
    String(String),
    Array(PhpArray),
    Object(PhpObject),

    /// Internal: foreach iterator state (not a PHP type).
    _Iterator {
        array: PhpArray,
        index: usize,
    },
}

impl Default for Value {
    fn default() -> Self {
        Value::Null
    }
}

impl Value {
    // =========================================================================
    // Type coercion (PHP semantics)
    // =========================================================================

    /// Convert to PHP integer (matching PHP's type juggling).
    pub fn to_long(&self) -> i64 {
        match self {
            Value::Null => 0,
            Value::Bool(false) => 0,
            Value::Bool(true) => 1,
            Value::Long(n) => *n,
            Value::Double(f) => {
                if f.is_nan() {
                    0
                } else if *f >= i64::MAX as f64 {
                    i64::MAX
                } else if *f <= i64::MIN as f64 {
                    i64::MIN
                } else {
                    *f as i64
                }
            }
            Value::String(s) => string_to_long(s),
            Value::Array(a) => {
                if a.is_empty() {
                    0
                } else {
                    1
                }
            }
            Value::Object(_) => 1,
            Value::_Iterator { .. } => 0,
        }
    }

    /// Convert to PHP float.
    pub fn to_double(&self) -> f64 {
        match self {
            Value::Null => 0.0,
            Value::Bool(false) => 0.0,
            Value::Bool(true) => 1.0,
            Value::Long(n) => *n as f64,
            Value::Double(f) => *f,
            Value::String(s) => string_to_double(s),
            Value::Array(a) => {
                if a.is_empty() {
                    0.0
                } else {
                    1.0
                }
            }
            Value::Object(_) => 1.0,
            Value::_Iterator { .. } => 0.0,
        }
    }

    /// Convert to PHP boolean.
    pub fn to_bool(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Long(n) => *n != 0,
            Value::Double(f) => *f != 0.0 && !f.is_nan(),
            Value::String(s) => !s.is_empty() && s != "0",
            Value::Array(a) => !a.is_empty(),
            Value::Object(_) => true,
            Value::_Iterator { .. } => true,
        }
    }

    /// Convert to PHP string.
    pub fn to_php_string(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Bool(true) => "1".to_string(),
            Value::Bool(false) => String::new(),
            Value::Long(n) => n.to_string(),
            Value::Double(f) => {
                if f.is_nan() {
                    "NAN".to_string()
                } else if f.is_infinite() {
                    if *f > 0.0 {
                        "INF".to_string()
                    } else {
                        "-INF".to_string()
                    }
                } else {
                    // PHP uses %G-like formatting (up to 14 significant digits)
                    let s = format!("{}", f);
                    if s.contains('.') || s.contains('E') || s.contains('e') {
                        s
                    } else {
                        // Integers that happen to be floats still get no decimal point in PHP
                        // unless they're very large. For now, just return as-is.
                        s
                    }
                }
            }
            Value::String(s) => s.clone(),
            Value::Array(_) => "Array".to_string(),
            Value::Object(o) => {
                // PHP: if __toString is defined, call it; otherwise error
                // For now, return class name as placeholder
                format!("{} Object", o.class_name)
            }
            Value::_Iterator { .. } => String::new(),
        }
    }

    /// Check if the value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Check if the value is "truthy" in PHP.
    pub fn is_truthy(&self) -> bool {
        self.to_bool()
    }

    // =========================================================================
    // PHP comparison operators
    // =========================================================================

    /// Loose equality (==) using PHP type juggling rules.
    pub fn loose_eq(&self, other: &Value) -> bool {
        match (self, other) {
            // Same types
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a == b,
            (Value::String(a), Value::String(b)) => {
                // If both look like numbers, compare numerically
                if let (Some(na), Some(nb)) = (try_numeric(a), try_numeric(b)) {
                    numeric_eq(&na, &nb)
                } else {
                    a == b
                }
            }

            // null == false, null == ""
            (Value::Null, Value::Bool(false)) | (Value::Bool(false), Value::Null) => true,
            (Value::Null, Value::String(s)) | (Value::String(s), Value::Null) => s.is_empty(),
            (Value::Null, Value::Long(0)) | (Value::Long(0), Value::Null) => true,
            (Value::Null, Value::Double(f)) | (Value::Double(f), Value::Null) => *f == 0.0,
            (Value::Null, Value::Array(a)) | (Value::Array(a), Value::Null) => a.is_empty(),

            // Bool comparisons — convert the other side to bool
            (Value::Bool(a), other) | (other, Value::Bool(a)) => *a == other.to_bool(),

            // Int vs Float
            (Value::Long(a), Value::Double(b)) => (*a as f64) == *b,
            (Value::Double(a), Value::Long(b)) => *a == (*b as f64),

            // String vs Int/Float — convert string to number
            (Value::String(s), Value::Long(n)) | (Value::Long(n), Value::String(s)) => {
                if let Some(num) = try_numeric(s) {
                    match num {
                        NumericValue::Long(sn) => sn == *n,
                        NumericValue::Double(sf) => sf == *n as f64,
                    }
                } else {
                    0 == *n
                }
            }
            (Value::String(s), Value::Double(f)) | (Value::Double(f), Value::String(s)) => {
                string_to_double(s) == *f
            }

            _ => false,
        }
    }

    /// Strict equality (===).
    pub fn strict_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            _ => false,
        }
    }

    /// PHP spaceship operator (<=>).
    pub fn spaceship(&self, other: &Value) -> i64 {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) => {
                if a < b {
                    -1
                } else if a > b {
                    1
                } else {
                    0
                }
            }
            _ => {
                let a = self.to_double();
                let b = other.to_double();
                if a < b {
                    -1
                } else if a > b {
                    1
                } else {
                    0
                }
            }
        }
    }

    /// PHP less-than comparison.
    pub fn is_smaller(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) => a < b,
            (Value::Double(a), Value::Double(b)) => a < b,
            (Value::Long(a), Value::Double(b)) => (*a as f64) < *b,
            (Value::Double(a), Value::Long(b)) => *a < (*b as f64),
            _ => self.to_double() < other.to_double(),
        }
    }

    // =========================================================================
    // Arithmetic
    // =========================================================================

    pub fn add(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) => match a.checked_add(*b) {
                Some(r) => Value::Long(r),
                None => Value::Double(*a as f64 + *b as f64),
            },
            (Value::Double(a), Value::Double(b)) => Value::Double(a + b),
            (Value::Long(a), Value::Double(b)) => Value::Double(*a as f64 + b),
            (Value::Double(a), Value::Long(b)) => Value::Double(a + *b as f64),
            (Value::Array(a), Value::Array(b)) => Value::Array(a.array_add(b)),
            _ => {
                let a = coerce_numeric(self);
                let b = coerce_numeric(other);
                a.add(&b)
            }
        }
    }

    pub fn sub(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) => match a.checked_sub(*b) {
                Some(r) => Value::Long(r),
                None => Value::Double(*a as f64 - *b as f64),
            },
            (Value::Double(a), Value::Double(b)) => Value::Double(a - b),
            (Value::Long(a), Value::Double(b)) => Value::Double(*a as f64 - b),
            (Value::Double(a), Value::Long(b)) => Value::Double(a - *b as f64),
            _ => {
                let a = coerce_numeric(self);
                let b = coerce_numeric(other);
                a.sub(&b)
            }
        }
    }

    pub fn mul(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) => match a.checked_mul(*b) {
                Some(r) => Value::Long(r),
                None => Value::Double(*a as f64 * *b as f64),
            },
            (Value::Double(a), Value::Double(b)) => Value::Double(a * b),
            (Value::Long(a), Value::Double(b)) => Value::Double(*a as f64 * b),
            (Value::Double(a), Value::Long(b)) => Value::Double(a * *b as f64),
            _ => {
                let a = coerce_numeric(self);
                let b = coerce_numeric(other);
                a.mul(&b)
            }
        }
    }

    pub fn div(&self, other: &Value) -> Value {
        let b_val = match other {
            Value::Long(0) => return Value::Bool(false), // Division by zero
            Value::Double(f) if *f == 0.0 => return Value::Bool(false),
            _ => {}
        };
        let _ = b_val;

        match (self, other) {
            (Value::Long(a), Value::Long(b)) => {
                if *b != 0 && a % b == 0 {
                    Value::Long(a / b)
                } else if *b != 0 {
                    Value::Double(*a as f64 / *b as f64)
                } else {
                    Value::Bool(false)
                }
            }
            (Value::Double(a), Value::Double(b)) => Value::Double(a / b),
            (Value::Long(a), Value::Double(b)) => Value::Double(*a as f64 / b),
            (Value::Double(a), Value::Long(b)) => Value::Double(a / *b as f64),
            _ => {
                let a = coerce_numeric(self);
                let b = coerce_numeric(other);
                a.div(&b)
            }
        }
    }

    pub fn modulo(&self, other: &Value) -> Value {
        let a = self.to_long();
        let b = other.to_long();
        if b == 0 {
            Value::Bool(false) // Division by zero
        } else {
            Value::Long(a % b)
        }
    }

    pub fn pow(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Long(a), Value::Long(b)) if *b >= 0 => match a.checked_pow(*b as u32) {
                Some(r) => Value::Long(r),
                None => Value::Double((*a as f64).powf(*b as f64)),
            },
            _ => {
                let a = self.to_double();
                let b = other.to_double();
                Value::Double(a.powf(b))
            }
        }
    }

    pub fn concat(&self, other: &Value) -> Value {
        let mut s = self.to_php_string();
        s.push_str(&other.to_php_string());
        Value::String(s)
    }

    pub fn bw_and(&self, other: &Value) -> Value {
        Value::Long(self.to_long() & other.to_long())
    }

    pub fn bw_or(&self, other: &Value) -> Value {
        Value::Long(self.to_long() | other.to_long())
    }

    pub fn bw_xor(&self, other: &Value) -> Value {
        Value::Long(self.to_long() ^ other.to_long())
    }

    pub fn bw_not(&self) -> Value {
        Value::Long(!self.to_long())
    }

    pub fn shl(&self, other: &Value) -> Value {
        Value::Long(self.to_long() << other.to_long())
    }

    pub fn shr(&self, other: &Value) -> Value {
        Value::Long(self.to_long() >> other.to_long())
    }

    pub fn bool_not(&self) -> Value {
        Value::Bool(!self.to_bool())
    }

    pub fn bool_xor(&self, other: &Value) -> Value {
        Value::Bool(self.to_bool() ^ other.to_bool())
    }

    /// Increment (++$a).
    pub fn increment(&self) -> Value {
        match self {
            Value::Long(n) => match n.checked_add(1) {
                Some(r) => Value::Long(r),
                None => Value::Double(*n as f64 + 1.0),
            },
            Value::Double(f) => Value::Double(f + 1.0),
            Value::Null => Value::Long(1),
            Value::Bool(_) => self.clone(), // PHP: booleans are unaffected by ++
            Value::String(s) => {
                // PHP alphanumeric increment: "a" -> "b", "z" -> "aa"
                if s.is_empty() {
                    return Value::String("1".to_string());
                }
                if let Some(num) = try_numeric(s) {
                    match num {
                        NumericValue::Long(n) => Value::Long(n + 1),
                        NumericValue::Double(f) => Value::Double(f + 1.0),
                    }
                } else {
                    Value::String(php_increment_string(s))
                }
            }
            _ => self.clone(),
        }
    }

    /// Decrement (--$a).
    pub fn decrement(&self) -> Value {
        match self {
            Value::Long(n) => match n.checked_sub(1) {
                Some(r) => Value::Long(r),
                None => Value::Double(*n as f64 - 1.0),
            },
            Value::Double(f) => Value::Double(f - 1.0),
            Value::Null => Value::Null, // PHP: null is unaffected by --
            Value::Bool(_) => self.clone(),
            Value::String(s) => {
                if let Some(num) = try_numeric(s) {
                    match num {
                        NumericValue::Long(n) => Value::Long(n - 1),
                        NumericValue::Double(f) => Value::Double(f - 1.0),
                    }
                } else {
                    self.clone() // PHP: non-numeric strings unaffected by --
                }
            }
            _ => self.clone(),
        }
    }

    /// Cast to a specific PHP type.
    pub fn cast(&self, type_code: u32) -> Value {
        match type_code {
            4 => Value::Long(self.to_long()),         // IS_LONG
            5 => Value::Double(self.to_double()),     // IS_DOUBLE
            6 => Value::String(self.to_php_string()), // IS_STRING
            2 => Value::Bool(self.to_bool()),         // IS_FALSE/_IS_BOOL
            7 => {
                // Cast to array
                match self {
                    Value::Null => Value::Array(PhpArray::new()),
                    Value::Array(_) => self.clone(),
                    Value::Object(o) => {
                        let mut arr = PhpArray::new();
                        for (k, v) in &o.properties {
                            arr.set_string(k.clone(), v.clone());
                        }
                        Value::Array(arr)
                    }
                    _ => {
                        let mut arr = PhpArray::new();
                        arr.push(self.clone());
                        Value::Array(arr)
                    }
                }
            }
            8 => {
                // Cast to object
                match self {
                    Value::Object(_) => self.clone(),
                    Value::Array(a) => {
                        let mut obj = PhpObject::new("stdClass".to_string());
                        for (key, val) in a.entries() {
                            let key_str = match key {
                                ArrayKey::Int(n) => n.to_string(),
                                ArrayKey::String(s) => s.clone(),
                            };
                            obj.properties.insert(key_str, val.clone());
                        }
                        Value::Object(obj)
                    }
                    Value::Null => Value::Object(PhpObject::new("stdClass".to_string())),
                    _ => {
                        let mut obj = PhpObject::new("stdClass".to_string());
                        obj.properties.insert("scalar".to_string(), self.clone());
                        Value::Object(obj)
                    }
                }
            }
            1 => Value::Null, // IS_NULL (unset cast)
            _ => self.clone(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_php_string())
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.strict_eq(other)
    }
}

// =============================================================================
// PhpObject — simplified object for VM execution
// =============================================================================

/// A PHP object instance.
#[derive(Debug, Clone)]
pub struct PhpObject {
    /// The class name this object is an instance of.
    pub class_name: String,
    /// Instance properties (name → value).
    pub properties: HashMap<String, Value>,
    /// Object ID (unique per-request, monotonically increasing).
    pub object_id: u64,
}

impl PhpObject {
    pub fn new(class_name: String) -> Self {
        // Object IDs will be assigned by the VM when creating objects
        Self {
            class_name,
            properties: HashMap::new(),
            object_id: 0,
        }
    }

    pub fn get_property(&self, name: &str) -> Option<&Value> {
        self.properties.get(name)
    }

    pub fn set_property(&mut self, name: String, value: Value) {
        self.properties.insert(name, value);
    }
}

// =============================================================================
// PhpArray — simplified ordered map for VM execution
// =============================================================================

/// A PHP array: ordered map with integer and string keys.
#[derive(Debug, Clone)]
pub struct PhpArray {
    entries: Vec<(ArrayKey, Value)>,
    next_int_key: i64,
}

/// Key type for PHP arrays.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrayKey {
    Int(i64),
    String(String),
}

impl PhpArray {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_int_key: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Push a value with the next integer key.
    pub fn push(&mut self, value: Value) {
        let key = self.next_int_key;
        self.entries.push((ArrayKey::Int(key), value));
        self.next_int_key = key + 1;
    }

    /// Set a value by integer key.
    pub fn set_int(&mut self, key: i64, value: Value) {
        for entry in &mut self.entries {
            if entry.0 == ArrayKey::Int(key) {
                entry.1 = value;
                return;
            }
        }
        self.entries.push((ArrayKey::Int(key), value));
        if key >= self.next_int_key {
            self.next_int_key = key + 1;
        }
    }

    /// Set a value by string key.
    pub fn set_string(&mut self, key: String, value: Value) {
        for entry in &mut self.entries {
            if entry.0 == ArrayKey::String(key.clone()) {
                entry.1 = value;
                return;
            }
        }
        self.entries.push((ArrayKey::String(key), value));
    }

    /// Set by a Value key (coercing to int or string).
    pub fn set(&mut self, key: &Value, value: Value) {
        match key {
            Value::Long(n) => self.set_int(*n, value),
            Value::String(s) => {
                if let Ok(n) = s.parse::<i64>() {
                    self.set_int(n, value);
                } else {
                    self.set_string(s.clone(), value);
                }
            }
            Value::Double(f) => self.set_int(*f as i64, value),
            Value::Bool(true) => self.set_int(1, value),
            Value::Bool(false) => self.set_int(0, value),
            Value::Null => self.set_string(String::new(), value),
            _ => self.push(value),
        }
    }

    /// Get by integer key.
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        for entry in &self.entries {
            if entry.0 == ArrayKey::Int(key) {
                return Some(&entry.1);
            }
        }
        None
    }

    /// Get by string key.
    pub fn get_string(&self, key: &str) -> Option<&Value> {
        for entry in &self.entries {
            if let ArrayKey::String(ref k) = entry.0 {
                if k == key {
                    return Some(&entry.1);
                }
            }
        }
        None
    }

    /// Get by Value key.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::Long(n) => self.get_int(*n),
            Value::String(s) => {
                if let Ok(n) = s.parse::<i64>() {
                    self.get_int(n)
                } else {
                    self.get_string(s)
                }
            }
            Value::Double(f) => self.get_int(*f as i64),
            Value::Bool(true) => self.get_int(1),
            Value::Bool(false) => self.get_int(0),
            Value::Null => self.get_string(""),
            _ => None,
        }
    }

    /// Remove by Value key.
    pub fn unset(&mut self, key: &Value) {
        let target = match key {
            Value::Long(n) => ArrayKey::Int(*n),
            Value::String(s) => {
                if let Ok(n) = s.parse::<i64>() {
                    ArrayKey::Int(n)
                } else {
                    ArrayKey::String(s.clone())
                }
            }
            _ => return,
        };
        self.entries.retain(|e| e.0 != target);
    }

    /// Check if key exists.
    pub fn isset(&self, key: &Value) -> bool {
        self.get(key).is_some_and(|v| !v.is_null())
    }

    /// Get the entry at a given iteration index.
    pub fn entry_at(&self, index: usize) -> Option<(&ArrayKey, &Value)> {
        self.entries.get(index).map(|(k, v)| (k, v))
    }

    /// PHP array union: $a + $b (keeps existing keys from $a, adds new from $b).
    pub fn array_add(&self, other: &PhpArray) -> PhpArray {
        let mut result = self.clone();
        for (key, value) in &other.entries {
            let exists = result.entries.iter().any(|e| e.0 == *key);
            if !exists {
                result.entries.push((key.clone(), value.clone()));
            }
        }
        result
    }

    /// Get entries for iteration.
    pub fn entries(&self) -> &[(ArrayKey, Value)] {
        &self.entries
    }
}

impl Default for PhpArray {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper functions
// =============================================================================

enum NumericValue {
    Long(i64),
    Double(f64),
}

fn try_numeric(s: &str) -> Option<NumericValue> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(NumericValue::Long(n));
    }
    if let Ok(f) = s.parse::<f64>() {
        return Some(NumericValue::Double(f));
    }
    None
}

fn numeric_eq(a: &NumericValue, b: &NumericValue) -> bool {
    match (a, b) {
        (NumericValue::Long(a), NumericValue::Long(b)) => a == b,
        (NumericValue::Double(a), NumericValue::Double(b)) => a == b,
        (NumericValue::Long(a), NumericValue::Double(b)) => *a as f64 == *b,
        (NumericValue::Double(a), NumericValue::Long(b)) => *a == *b as f64,
    }
}

fn coerce_numeric(v: &Value) -> Value {
    match v {
        Value::Long(_) | Value::Double(_) => v.clone(),
        Value::String(s) => match try_numeric(s) {
            Some(NumericValue::Long(n)) => Value::Long(n),
            Some(NumericValue::Double(f)) => Value::Double(f),
            None => Value::Long(0),
        },
        _ => Value::Long(v.to_long()),
    }
}

fn string_to_long(s: &str) -> i64 {
    let s = s.trim_start();
    if s.is_empty() {
        return 0;
    }
    // Try full parse first
    if let Ok(n) = s.parse::<i64>() {
        return n;
    }
    // PHP parses leading digits
    let mut result: i64 = 0;
    let mut chars = s.chars();
    let mut negative = false;
    if let Some(first) = chars.next() {
        match first {
            '-' => negative = true,
            '+' => {}
            '0'..='9' => result = (first as u8 - b'0') as i64,
            _ => return 0,
        }
    }
    for ch in chars {
        if ch.is_ascii_digit() {
            result = result
                .wrapping_mul(10)
                .wrapping_add((ch as u8 - b'0') as i64);
        } else {
            break;
        }
    }
    if negative {
        -result
    } else {
        result
    }
}

fn string_to_double(s: &str) -> f64 {
    let s = s.trim_start();
    if s.is_empty() {
        return 0.0;
    }
    // Find the longest prefix that parses as a float
    for end in (1..=s.len()).rev() {
        if let Ok(f) = s[..end].parse::<f64>() {
            return f;
        }
    }
    0.0
}

/// PHP-style alphanumeric string increment.
fn php_increment_string(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    let mut carry = true;

    for i in (0..chars.len()).rev() {
        if !carry {
            break;
        }
        let ch = chars[i];
        match ch {
            'a'..='y' => {
                chars[i] = (ch as u8 + 1) as char;
                carry = false;
            }
            'z' => chars[i] = 'a',
            'A'..='Y' => {
                chars[i] = (ch as u8 + 1) as char;
                carry = false;
            }
            'Z' => chars[i] = 'A',
            '0'..='8' => {
                chars[i] = (ch as u8 + 1) as char;
                carry = false;
            }
            '9' => chars[i] = '0',
            _ => {
                carry = false;
            }
        }
    }

    if carry {
        // Prepend: "z" -> "aa", "Z" -> "AA", "9" -> "10"
        let first = chars[0];
        let prefix = match first {
            'a'..='z' => 'a',
            'A'..='Z' => 'A',
            '0'..='9' => '1',
            _ => '1',
        };
        chars.insert(0, prefix);
    }

    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_long() {
        assert_eq!(Value::Null.to_long(), 0);
        assert_eq!(Value::Bool(true).to_long(), 1);
        assert_eq!(Value::Bool(false).to_long(), 0);
        assert_eq!(Value::Long(42).to_long(), 42);
        assert_eq!(Value::Double(3.7).to_long(), 3);
        assert_eq!(Value::String("123".to_string()).to_long(), 123);
        assert_eq!(Value::String("12abc".to_string()).to_long(), 12);
        assert_eq!(Value::String("abc".to_string()).to_long(), 0);
    }

    #[test]
    fn test_to_double() {
        assert_eq!(Value::Long(42).to_double(), 42.0);
        assert_eq!(Value::String("1.5".to_string()).to_double(), 1.5);
    }

    #[test]
    fn test_to_bool() {
        assert!(!Value::Null.to_bool());
        assert!(!Value::Bool(false).to_bool());
        assert!(Value::Bool(true).to_bool());
        assert!(!Value::Long(0).to_bool());
        assert!(Value::Long(1).to_bool());
        assert!(!Value::String("".to_string()).to_bool());
        assert!(!Value::String("0".to_string()).to_bool());
        assert!(Value::String("1".to_string()).to_bool());
    }

    #[test]
    fn test_to_string() {
        assert_eq!(Value::Null.to_php_string(), "");
        assert_eq!(Value::Bool(true).to_php_string(), "1");
        assert_eq!(Value::Bool(false).to_php_string(), "");
        assert_eq!(Value::Long(42).to_php_string(), "42");
        assert_eq!(Value::Double(3.5).to_php_string(), "3.5");
    }

    #[test]
    fn test_loose_eq() {
        assert!(Value::Long(0).loose_eq(&Value::Bool(false)));
        assert!(Value::Long(1).loose_eq(&Value::Bool(true)));
        assert!(Value::String("1".to_string()).loose_eq(&Value::Long(1)));
        assert!(Value::Null.loose_eq(&Value::Bool(false)));
        assert!(Value::Null.loose_eq(&Value::String("".to_string())));
    }

    #[test]
    fn test_strict_eq() {
        assert!(!Value::Long(1).strict_eq(&Value::Double(1.0)));
        assert!(Value::Long(1).strict_eq(&Value::Long(1)));
        assert!(!Value::String("1".to_string()).strict_eq(&Value::Long(1)));
    }

    #[test]
    fn test_add() {
        assert_eq!(Value::Long(2).add(&Value::Long(3)), Value::Long(5));
        assert_eq!(Value::Double(1.5).add(&Value::Long(2)), Value::Double(3.5));
    }

    #[test]
    fn test_concat() {
        assert_eq!(
            Value::String("hello".to_string()).concat(&Value::String(" world".to_string())),
            Value::String("hello world".to_string())
        );
        assert_eq!(
            Value::Long(42).concat(&Value::String("!".to_string())),
            Value::String("42!".to_string())
        );
    }

    #[test]
    fn test_increment() {
        assert_eq!(Value::Long(5).increment(), Value::Long(6));
        assert_eq!(Value::Null.increment(), Value::Long(1));
    }

    #[test]
    fn test_array_basic() {
        let mut arr = PhpArray::new();
        arr.push(Value::Long(10));
        arr.push(Value::Long(20));
        assert_eq!(arr.len(), 2);
        assert_eq!(arr.get_int(0), Some(&Value::Long(10)));
        assert_eq!(arr.get_int(1), Some(&Value::Long(20)));
    }

    #[test]
    fn test_array_string_keys() {
        let mut arr = PhpArray::new();
        arr.set_string("name".to_string(), Value::String("PHP".to_string()));
        assert_eq!(
            arr.get_string("name"),
            Some(&Value::String("PHP".to_string()))
        );
    }
}
