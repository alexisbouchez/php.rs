//! PHP value types for VM execution.
//!
//! Defines [`Value`], [`PhpArray`], and [`PhpObject`] -- the high-level runtime
//! representations of PHP values used during opcode execution. These are designed
//! for correctness-first development and can be migrated to the compact 16-byte
//! `ZVal` layout from `php-rs-types` for performance later.
//!
//! All PHP type juggling rules (implicit conversions between int, float, string,
//! bool, null, array, and object) are implemented on [`Value`] following the
//! semantics defined in `php-src/Zend/zend_operators.c`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use php_rs_compiler::op::OperandType;

/// A PHP value used during VM execution.
///
/// This enum represents all PHP value types at runtime. It is the primary
/// type flowing through the VM's operand stack, compiled variable slots,
/// and temporary variable slots.
///
/// # PHP types
///
/// - `Null`, `Bool`, `Long`, `Double`, `String` -- scalar types
/// - `Array` -- ordered map (see [`PhpArray`])
/// - `Object` -- class instance (see [`PhpObject`])
/// - `Resource` -- opaque handle to an external resource (file, connection, etc.)
/// - `Reference` -- shared mutable cell implementing PHP's `&$var` semantics
///
/// # Type juggling
///
/// The [`to_long`](Value::to_long), [`to_double`](Value::to_double),
/// [`to_bool`](Value::to_bool), and [`to_php_string`](Value::to_php_string)
/// methods implement PHP's implicit type conversion rules.
///
/// # Internal variants
///
/// Variants prefixed with `_` (e.g., `_Iterator`, `_Rope`) are VM-internal
/// state holders and do not correspond to PHP-visible types.
#[derive(Debug, Clone)]
pub enum Value {
    /// PHP `null`.
    Null,
    /// PHP `bool` (`true` or `false`).
    Bool(bool),
    /// PHP `int` (64-bit signed integer).
    Long(i64),
    /// PHP `float` (64-bit IEEE 754 double).
    Double(f64),
    /// PHP `string` (UTF-8 in Rust, but PHP strings are binary-safe).
    String(String),
    /// PHP `array` -- ordered map with integer and string keys.
    Array(PhpArray),
    /// PHP `object` -- class instance with properties and internal state.
    Object(PhpObject),

    /// A PHP resource (resource_id, resource_type).
    Resource(i64, String),

    /// A PHP reference -- shared mutable cell (used for `&$param` and `$a = &$b`).
    /// Multiple variables may hold clones of the same `Rc`, sharing one underlying `Value`.
    Reference(Rc<RefCell<Value>>),

    /// Internal: foreach iterator state (not a PHP-visible type).
    _Iterator { array: PhpArray, index: usize },

    /// Internal: generator iterator state for foreach over generators.
    _GeneratorIterator {
        object_id: u64,
        /// Whether the generator needs to be advanced before reading.
        /// False on the first fetch (already positioned at first yield from FE_RESET).
        needs_advance: bool,
    },

    /// Internal: object iterator state for foreach over Iterator/IteratorAggregate objects.
    _ObjectIterator {
        /// The iterator object (implements Iterator interface).
        iterator: PhpObject,
        /// Whether this is the first fetch (rewind already called, don't advance).
        first: bool,
    },

    /// Internal: rope state for RopeInit/RopeAdd/RopeEnd string interpolation.
    _Rope(Vec<String>),
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

    /// Dereference: if this is a Reference, return a clone of the inner value.
    /// Otherwise, return a clone of self.
    #[inline]
    pub fn deref_value(&self) -> Value {
        match self {
            Value::Reference(rc) => {
                let inner = rc.borrow();
                // Recursive deref in case of nested references
                inner.deref_value()
            }
            other => other.clone(),
        }
    }

    /// Check if this value is a Reference.
    pub fn is_reference(&self) -> bool {
        matches!(self, Value::Reference(_))
    }

    /// Convert to PHP integer (matching PHP's type juggling).
    #[inline]
    pub fn to_long(&self) -> i64 {
        match self {
            Value::Reference(rc) => rc.borrow().to_long(),
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
            Value::Resource(id, _) => *id,
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => 0,
        }
    }

    /// Convert to PHP float.
    #[inline]
    pub fn to_double(&self) -> f64 {
        match self {
            Value::Reference(rc) => rc.borrow().to_double(),
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
            Value::Resource(id, _) => *id as f64,
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => 0.0,
        }
    }

    /// Convert to PHP boolean.
    #[inline]
    pub fn to_bool(&self) -> bool {
        match self {
            Value::Reference(rc) => rc.borrow().to_bool(),
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Long(n) => *n != 0,
            Value::Double(f) => *f != 0.0 && !f.is_nan(),
            Value::String(s) => !s.is_empty() && s != "0",
            Value::Array(a) => !a.is_empty(),
            Value::Object(_) => true,
            Value::Resource(_, _) => true,
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => true,
        }
    }

    /// Convert to PHP string.
    #[inline]
    pub fn to_php_string(&self) -> String {
        match self {
            Value::Reference(rc) => rc.borrow().to_php_string(),
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
                format!("{} Object", o.class_name())
            }
            Value::Resource(id, _) => format!("Resource id #{}", id),
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => String::new(),
        }
    }

    /// Extract resource ID: returns the ID for Resource values,
    /// falls back to to_long() for Long (backward compat).
    pub fn resource_id(&self) -> i64 {
        match self {
            Value::Reference(rc) => rc.borrow().resource_id(),
            Value::Resource(id, _) => *id,
            _ => self.to_long(),
        }
    }

    /// Check if the value is null.
    pub fn is_null(&self) -> bool {
        match self {
            Value::Reference(rc) => rc.borrow().is_null(),
            Value::Null => true,
            _ => false,
        }
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
        // Auto-deref references
        if let Value::Reference(rc) = self {
            return rc.borrow().loose_eq(other);
        }
        if let Value::Reference(rc) = other {
            return self.loose_eq(&rc.borrow());
        }
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

            // String vs Int/Float — PHP 8.0+: non-numeric strings never equal numbers
            (Value::String(s), Value::Long(n)) | (Value::Long(n), Value::String(s)) => {
                if let Some(num) = try_numeric(s) {
                    match num {
                        NumericValue::Long(sn) => sn == *n,
                        NumericValue::Double(sf) => sf == *n as f64,
                    }
                } else {
                    false // PHP 8.0+: "foo" == 0 is false
                }
            }
            (Value::String(s), Value::Double(f)) | (Value::Double(f), Value::String(s)) => {
                if let Some(num) = try_numeric(s) {
                    match num {
                        NumericValue::Long(sn) => sn as f64 == *f,
                        NumericValue::Double(sf) => sf == *f,
                    }
                } else {
                    false // PHP 8.0+: non-numeric strings never equal floats
                }
            }

            // Object == Object: same class, same properties (loose comparison)
            (Value::Object(a), Value::Object(b)) => {
                if a.class_name() != b.class_name() {
                    return false;
                }
                let props_a = a.properties();
                let props_b = b.properties();
                if props_a.len() != props_b.len() {
                    return false;
                }
                for (key, val_a) in &props_a {
                    match props_b.iter().find(|(k, _)| k == &key) {
                        Some((_, val_b)) => {
                            if !val_a.loose_eq(val_b) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                true
            }

            // Array == Array: same keys, same values (loose), order doesn't matter
            (Value::Array(a), Value::Array(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                for (key, val_a) in a.entries() {
                    match b.get_by_key(key) {
                        Some(val_b) => {
                            if !val_a.loose_eq(val_b) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                true
            }

            _ => false,
        }
    }

    /// Strict equality (===).
    pub fn strict_eq(&self, other: &Value) -> bool {
        // Auto-deref references
        if let Value::Reference(rc) = self {
            return rc.borrow().strict_eq(other);
        }
        if let Value::Reference(rc) = other {
            return self.strict_eq(&rc.borrow());
        }
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Resource(a, _), Value::Resource(b, _)) => a == b,
            (Value::Object(a), Value::Object(b)) => a.is_same_instance(b),
            (Value::Array(a), Value::Array(b)) => {
                // PHP strict equality for arrays: same keys, same values (===), same order
                if a.len() != b.len() {
                    return false;
                }
                let a_entries = a.entries();
                let b_entries = b.entries();
                for (i, (key_a, val_a)) in a_entries.iter().enumerate() {
                    let (key_b, val_b) = &b_entries[i];
                    if key_a != key_b || !val_a.strict_eq(val_b) {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// PHP spaceship operator (<=>).
    pub fn spaceship(&self, other: &Value) -> i64 {
        if let Value::Reference(rc) = self {
            return rc.borrow().spaceship(other);
        }
        if let Value::Reference(rc) = other {
            return self.spaceship(&rc.borrow());
        }
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
            (Value::Double(a), Value::Double(b)) => {
                if a < b {
                    -1
                } else if a > b {
                    1
                } else {
                    0
                }
            }
            (Value::Long(a), Value::Double(b)) => {
                let a = *a as f64;
                if a < *b {
                    -1
                } else if a > *b {
                    1
                } else {
                    0
                }
            }
            (Value::Double(a), Value::Long(b)) => {
                let b = *b as f64;
                if *a < b {
                    -1
                } else if *a > b {
                    1
                } else {
                    0
                }
            }
            // String <=> String: lexicographic comparison
            (Value::String(a), Value::String(b)) => {
                // If both are numeric strings, compare numerically
                if let (Some(na), Some(nb)) = (try_numeric(a), try_numeric(b)) {
                    let fa = match na {
                        NumericValue::Long(n) => n as f64,
                        NumericValue::Double(f) => f,
                    };
                    let fb = match nb {
                        NumericValue::Long(n) => n as f64,
                        NumericValue::Double(f) => f,
                    };
                    if fa < fb {
                        -1
                    } else if fa > fb {
                        1
                    } else {
                        0
                    }
                } else {
                    match a.cmp(b) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Greater => 1,
                        std::cmp::Ordering::Equal => 0,
                    }
                }
            }
            // Array <=> Array: compare by count first, then element-by-element
            (Value::Array(a), Value::Array(b)) => {
                if a.len() != b.len() {
                    return if a.len() < b.len() { -1 } else { 1 };
                }
                // Element-by-element comparison using the order of the left array
                for (key, val_a) in a.entries() {
                    match b.get_by_key(key) {
                        Some(val_b) => {
                            let cmp = val_a.spaceship(val_b);
                            if cmp != 0 {
                                return cmp;
                            }
                        }
                        None => return 1, // Key exists in a but not b → a is "greater"
                    }
                }
                0
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
        if let Value::Reference(rc) = self {
            return rc.borrow().is_smaller(other);
        }
        if let Value::Reference(rc) = other {
            return self.is_smaller(&rc.borrow());
        }
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

    #[inline]
    pub fn add(&self, other: &Value) -> Value {
        if let Value::Reference(rc) = self {
            return rc.borrow().add(other);
        }
        if let Value::Reference(rc) = other {
            return self.add(&rc.borrow());
        }
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

    #[inline]
    pub fn sub(&self, other: &Value) -> Value {
        if let Value::Reference(rc) = self {
            return rc.borrow().sub(other);
        }
        if let Value::Reference(rc) = other {
            return self.sub(&rc.borrow());
        }
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

    #[inline]
    pub fn mul(&self, other: &Value) -> Value {
        if let Value::Reference(rc) = self {
            return rc.borrow().mul(other);
        }
        if let Value::Reference(rc) = other {
            return self.mul(&rc.borrow());
        }
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

    #[inline]
    pub fn div(&self, other: &Value) -> Value {
        if let Value::Reference(rc) = self {
            return rc.borrow().div(other);
        }
        if let Value::Reference(rc) = other {
            return self.div(&rc.borrow());
        }
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
        if let Value::Reference(rc) = self {
            return rc.borrow().pow(other);
        }
        if let Value::Reference(rc) = other {
            return self.pow(&rc.borrow());
        }
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
        if let Value::Reference(rc) = self {
            return rc.borrow().increment();
        }
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
        if let Value::Reference(rc) = self {
            return rc.borrow().decrement();
        }
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
        if let Value::Reference(rc) = self {
            return rc.borrow().cast(type_code);
        }
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
                        for (k, v) in &o.properties() {
                            // PHP name mangling for (array) cast:
                            // Private props: "\0ClassName\0propName"
                            // Protected props: "\0*\0propName"
                            // Public props: "propName" (no mangling)
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
                        let obj = PhpObject::new("stdClass".to_string());
                        for (key, val) in a.entries() {
                            let key_str = match key {
                                ArrayKey::Int(n) => n.to_string(),
                                ArrayKey::String(s) => s.clone(),
                            };
                            obj.set_property(key_str, val.clone());
                        }
                        Value::Object(obj)
                    }
                    Value::Null => Value::Object(PhpObject::new("stdClass".to_string())),
                    _ => {
                        let obj = PhpObject::new("stdClass".to_string());
                        obj.set_property("scalar".to_string(), self.clone());
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
        if let Value::Reference(rc) = self {
            return write!(f, "{}", rc.borrow().to_php_string());
        }
        write!(f, "{}", self.to_php_string())
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.strict_eq(other)
    }
}

// =============================================================================
// Generator & Fiber state types
// =============================================================================

/// Internal state marker for objects that are generators, fibers, or reflection objects.
#[derive(Debug, Clone, PartialEq)]
pub enum InternalState {
    None,
    Generator,
    Fiber,
    ReflectionClass,
}

/// Status of a generator.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GeneratorStatus {
    Created,
    Running,
    Suspended,
    Closed,
}

/// Saved state for a generator.
#[derive(Debug, Clone)]
pub struct GeneratorState {
    /// Saved execution frame (None when running or closed).
    pub frame: Option<GeneratorFrame>,
    /// Which op_array this generator executes.
    pub op_array_idx: usize,
    /// Currently yielded value.
    pub value: Value,
    /// Currently yielded key.
    pub key: Value,
    /// Return value (set when generator returns).
    pub return_value: Option<Value>,
    /// Value sent via send() — written to the yield result slot on resume.
    pub send_value: Value,
    /// Auto-incrementing integer key for yield without explicit key.
    pub largest_int_key: i64,
    /// Generator status.
    pub status: GeneratorStatus,
    /// Where to write the send_value in the frame (result_type, slot).
    pub yield_result_slot: Option<(OperandType, u32)>,
    /// Active delegate for yield from (array elements or inner generator id).
    pub delegate: Option<GeneratorDelegate>,
}

/// Active delegate for yield from.
#[derive(Debug, Clone)]
pub enum GeneratorDelegate {
    /// Yielding from an array, tracking current index.
    Array {
        entries: Vec<(ArrayKey, Value)>,
        index: usize,
    },
    /// Yielding from an inner generator.
    Generator { inner_id: u64 },
}

/// A saved generator frame — stores the execution context.
#[derive(Debug, Clone)]
pub struct GeneratorFrame {
    pub op_array_idx: usize,
    pub ip: usize,
    pub cvs: Vec<Value>,
    pub temps: Vec<Value>,
    pub args: Vec<Value>,
}

/// Status of a fiber.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FiberStatus {
    Init,
    Running,
    Suspended,
    Terminated,
}

/// Saved state for a fiber.
#[derive(Debug, Clone)]
pub struct FiberState {
    /// Saved frames from the fiber's call stack.
    pub saved_frames: Vec<FiberFrame>,
    /// Fiber status.
    pub status: FiberStatus,
    /// Callable name to execute.
    pub callback_name: String,
    /// Value passed between suspend/resume.
    pub transfer_value: Value,
    /// Return value (set when fiber completes).
    pub return_value: Option<Value>,
    /// Call stack depth when fiber started (used for draining).
    pub start_depth: usize,
}

/// A saved fiber frame.
#[derive(Debug, Clone)]
pub struct FiberFrame {
    pub op_array_idx: usize,
    pub ip: usize,
    pub cvs: Vec<Value>,
    pub temps: Vec<Value>,
    pub args: Vec<Value>,
    pub return_value: Value,
    pub return_dest: Option<(OperandType, u32)>,
    pub this_write_back: Option<(OperandType, u32)>,
    pub is_constructor: bool,
}

// =============================================================================
// PhpObject — simplified object for VM execution
// =============================================================================

/// Internal data for a PHP object instance.
#[derive(Debug)]
struct PhpObjectData {
    /// The class name this object is an instance of.
    class_name: String,
    /// Instance properties (name → value).
    properties: HashMap<String, Value>,
    /// Object ID (unique per-request, monotonically increasing).
    object_id: u64,
    /// Internal state: marks whether this is a Generator or Fiber object.
    internal: InternalState,
}

/// A PHP object instance with reference semantics.
///
/// In PHP, objects are always passed by handle: assigning `$a = $b` when `$b` is
/// an object makes both variables point to the same underlying object. This is
/// implemented via `Rc<RefCell<PhpObjectData>>` -- cloning a `PhpObject` clones
/// the `Rc` (shared reference), so multiple variables share state.
///
/// Each object has:
/// - A **class name** (e.g., `"stdClass"`, `"DateTime"`)
/// - A **properties** map (`HashMap<String, Value>`)
/// - A unique **object ID** (monotonically increasing per request)
/// - Optional **internal state** for special objects (generators, fibers, closures)
#[derive(Debug, Clone)]
pub struct PhpObject {
    inner: Rc<RefCell<PhpObjectData>>,
}

impl PhpObject {
    pub fn new(class_name: String) -> Self {
        Self {
            inner: Rc::new(RefCell::new(PhpObjectData {
                class_name,
                properties: HashMap::new(),
                object_id: 0,
                internal: InternalState::None,
            })),
        }
    }

    /// Check if two PhpObjects are the same instance (same Rc pointer).
    pub fn is_same_instance(&self, other: &PhpObject) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn class_name(&self) -> String {
        self.inner.borrow().class_name.clone()
    }

    pub fn object_id(&self) -> u64 {
        self.inner.borrow().object_id
    }

    pub fn set_object_id(&self, id: u64) {
        self.inner.borrow_mut().object_id = id;
    }

    pub fn internal(&self) -> InternalState {
        self.inner.borrow().internal.clone()
    }

    pub fn set_internal(&self, state: InternalState) {
        self.inner.borrow_mut().internal = state;
    }

    pub fn get_property(&self, name: &str) -> Option<Value> {
        self.inner.borrow().properties.get(name).cloned()
    }

    pub fn set_property(&self, name: String, value: Value) {
        self.inner.borrow_mut().properties.insert(name, value);
    }

    pub fn has_property(&self, name: &str) -> bool {
        self.inner.borrow().properties.contains_key(name)
    }

    pub fn properties(&self) -> HashMap<String, Value> {
        self.inner.borrow().properties.clone()
    }

    pub fn properties_count(&self) -> usize {
        self.inner.borrow().properties.len()
    }

    pub fn remove_property(&self, name: &str) {
        self.inner.borrow_mut().properties.remove(name);
    }
}

// =============================================================================
// PhpArray — optimized ordered map with copy-on-write and packed mode
// =============================================================================

/// Key type for PHP arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArrayKey {
    Int(i64),
    String(String),
}

impl Hash for ArrayKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            ArrayKey::Int(i) => {
                0u8.hash(state);
                i.hash(state);
            }
            ArrayKey::String(s) => {
                1u8.hash(state);
                s.hash(state);
            }
        }
    }
}

/// Threshold for building hash index (below this, linear scan is faster due to cache locality).
const INDEX_THRESHOLD: usize = 16;

/// Internal storage for PhpArray, shared via Rc for copy-on-write semantics.
#[derive(Debug, Clone)]
struct PhpArrayInner {
    entries: Vec<(ArrayKey, Value)>,
    next_int_key: i64,
    /// True when all keys are sequential integers 0..n-1 (enables O(1) indexed access).
    is_packed: bool,
    /// Hash index for O(1) integer key lookup. Lazily built when len > INDEX_THRESHOLD.
    int_index: Option<HashMap<i64, usize>>,
    /// Hash index for O(1) string key lookup. Lazily built when len > INDEX_THRESHOLD.
    str_index: Option<HashMap<String, usize>>,
}

impl PhpArrayInner {
    /// Build hash indexes if the array is large enough and they haven't been built yet.
    fn ensure_index(&mut self) {
        if self.int_index.is_some() || self.entries.len() <= INDEX_THRESHOLD {
            return;
        }
        let mut int_idx = HashMap::with_capacity(self.entries.len());
        let mut str_idx = HashMap::new();
        for (i, (key, _)) in self.entries.iter().enumerate() {
            match key {
                ArrayKey::Int(n) => {
                    int_idx.insert(*n, i);
                }
                ArrayKey::String(s) => {
                    str_idx.insert(s.clone(), i);
                }
            }
        }
        self.int_index = Some(int_idx);
        if !str_idx.is_empty() {
            self.str_index = Some(str_idx);
        }
    }

    /// Invalidate hash indexes (call after removal/reorder operations).
    #[inline]
    fn invalidate_index(&mut self) {
        self.int_index = None;
        self.str_index = None;
    }
}

/// A PHP array -- ordered map with integer and string keys, used at VM runtime.
///
/// This is the VM's runtime representation of PHP arrays, stored as a vector of
/// `(ArrayKey, Value)` pairs in insertion order. It supports both integer and
/// string keys, and preserves PHP's array ordering semantics.
///
/// # Performance features
///
/// - **Copy-on-write**: Clone is O(1) via `Rc` reference counting. Data is cloned
///   lazily on first mutation (`Rc::make_mut`), matching PHP's CoW array semantics.
/// - **Packed mode**: When all keys are sequential integers starting from 0,
///   lookups use direct indexing for O(1) access.
/// - **Hash index**: Arrays with more than 16 entries automatically build
///   `HashMap` indexes for O(1) key lookup by integer or string.
///
/// # Difference from `ZArray`
///
/// `php_rs_types::ZArray` is the low-level 16-byte-zval-compatible array.
/// `PhpArray` is the high-level runtime array used by the VM for correctness-first
/// execution. They may be unified in the future.
pub struct PhpArray {
    inner: Rc<PhpArrayInner>,
}

impl Clone for PhpArray {
    /// Copy-on-write clone: only bumps reference count.
    /// Actual data is cloned lazily on first mutation via Rc::make_mut.
    #[inline]
    fn clone(&self) -> Self {
        PhpArray {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for PhpArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhpArray")
            .field("entries", &self.inner.entries)
            .field("next_int_key", &self.inner.next_int_key)
            .field("is_packed", &self.inner.is_packed)
            .finish()
    }
}

impl PhpArray {
    /// Get mutable access to inner data, cloning if shared (copy-on-write).
    #[inline]
    fn inner_mut(&mut self) -> &mut PhpArrayInner {
        Rc::make_mut(&mut self.inner)
    }

    pub fn new() -> Self {
        Self {
            inner: Rc::new(PhpArrayInner {
                entries: Vec::new(),
                next_int_key: 0,
                is_packed: true,
                int_index: None,
                str_index: None,
            }),
        }
    }

    /// Build a PhpArray from pre-built entries (preserves keys and order).
    pub fn from_entries(entries: Vec<(ArrayKey, Value)>) -> Self {
        let mut next_int_key = 0i64;
        let mut is_packed = true;
        for (i, (k, _)) in entries.iter().enumerate() {
            match k {
                ArrayKey::Int(n) => {
                    if *n >= next_int_key {
                        next_int_key = *n + 1;
                    }
                    if *n != i as i64 {
                        is_packed = false;
                    }
                }
                ArrayKey::String(_) => {
                    is_packed = false;
                }
            }
        }
        Self {
            inner: Rc::new(PhpArrayInner {
                entries,
                next_int_key,
                is_packed,
                int_index: None,
                str_index: None,
            }),
        }
    }

    /// Build a PhpArray from a string→string map (e.g. $_GET, $_ENV).
    pub fn from_string_map(map: &HashMap<String, String>) -> Self {
        let mut arr = Self::new();
        for (k, v) in map {
            arr.set_string(k.clone(), Value::String(v.clone()));
        }
        arr
    }

    pub fn len(&self) -> usize {
        self.inner.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.entries.is_empty()
    }

    /// Push a value with the next integer key.
    pub fn push(&mut self, value: Value) {
        let inner = self.inner_mut();
        let key = inner.next_int_key;
        let pos = inner.entries.len();
        // Push always maintains packed invariant (next_int_key == entries.len() for packed)
        if let Some(ref mut idx) = inner.int_index {
            idx.insert(key, pos);
        }
        inner.entries.push((ArrayKey::Int(key), value));
        inner.next_int_key = key + 1;
    }

    /// Find position of integer key.
    #[inline]
    fn find_int_position(&self, key: i64) -> Option<usize> {
        // Packed mode: direct O(1) indexed access
        if self.inner.is_packed && key >= 0 && (key as usize) < self.inner.entries.len() {
            return Some(key as usize);
        }
        if let Some(ref int_index) = self.inner.int_index {
            return int_index.get(&key).copied();
        }
        self.inner
            .entries
            .iter()
            .position(|(k, _)| matches!(k, ArrayKey::Int(n) if *n == key))
    }

    /// Find position of string key.
    #[inline]
    fn find_str_position(&self, key: &str) -> Option<usize> {
        if self.inner.is_packed {
            return None; // Packed arrays only have int keys
        }
        if let Some(ref str_index) = self.inner.str_index {
            return str_index.get(key).copied();
        }
        self.inner
            .entries
            .iter()
            .position(|(k, _)| matches!(k, ArrayKey::String(ref s) if s == key))
    }

    /// Set a value by integer key.
    pub fn set_int(&mut self, key: i64, value: Value) {
        let existing_pos = self.find_int_position(key);
        let inner = self.inner_mut();
        if let Some(pos) = existing_pos {
            inner.entries[pos].1 = value;
            return;
        }
        // New entry
        let new_pos = inner.entries.len();
        // Check if this breaks packed invariant
        if inner.is_packed && key != new_pos as i64 {
            inner.is_packed = false;
        }
        inner.entries.push((ArrayKey::Int(key), value));
        if key >= inner.next_int_key {
            inner.next_int_key = key + 1;
        }
        if let Some(ref mut idx) = inner.int_index {
            idx.insert(key, new_pos);
        }
        inner.ensure_index();
    }

    /// Set a value by string key.
    pub fn set_string(&mut self, key: String, value: Value) {
        let existing_pos = self.find_str_position(&key);
        let inner = self.inner_mut();
        if let Some(pos) = existing_pos {
            inner.entries[pos].1 = value;
            return;
        }
        let new_pos = inner.entries.len();
        inner.is_packed = false;
        if let Some(ref mut idx) = inner.str_index {
            idx.insert(key.clone(), new_pos);
        }
        inner.entries.push((ArrayKey::String(key), value));
        inner.ensure_index();
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

    /// Get by ArrayKey.
    pub fn get_by_key(&self, key: &ArrayKey) -> Option<&Value> {
        match key {
            ArrayKey::Int(i) => self.get_int(*i),
            ArrayKey::String(s) => self.get_string(s),
        }
    }

    /// Get by integer key.
    #[inline]
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        // Packed mode: direct O(1) indexed access
        if self.inner.is_packed && key >= 0 && (key as usize) < self.inner.entries.len() {
            return Some(&self.inner.entries[key as usize].1);
        }
        if let Some(ref int_index) = self.inner.int_index {
            return int_index.get(&key).map(|&pos| &self.inner.entries[pos].1);
        }
        // Linear scan for small arrays
        for entry in &self.inner.entries {
            if matches!(&entry.0, ArrayKey::Int(n) if *n == key) {
                return Some(&entry.1);
            }
        }
        None
    }

    /// Get by string key.
    pub fn get_string(&self, key: &str) -> Option<&Value> {
        if self.inner.is_packed {
            return None; // Packed arrays only have int keys
        }
        if let Some(ref str_index) = self.inner.str_index {
            return str_index.get(key).map(|&pos| &self.inner.entries[pos].1);
        }
        // Linear scan for small arrays
        for entry in &self.inner.entries {
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
        let inner = self.inner_mut();
        inner.entries.retain(|e| e.0 != target);
        inner.is_packed = false; // Removal may create gaps
        inner.invalidate_index();
    }

    /// Check if key exists.
    pub fn isset(&self, key: &Value) -> bool {
        self.get(key).is_some_and(|v| !v.is_null())
    }

    /// Get the entry at a given iteration index.
    pub fn entry_at(&self, index: usize) -> Option<(&ArrayKey, &Value)> {
        self.inner.entries.get(index).map(|(k, v)| (k, v))
    }

    /// PHP array union: $a + $b (keeps existing keys from $a, adds new from $b).
    pub fn array_add(&self, other: &PhpArray) -> PhpArray {
        let mut result = PhpArray {
            inner: Rc::new((*self.inner).clone()),
        };
        for (key, value) in &other.inner.entries {
            let exists = result.inner.entries.iter().any(|e| e.0 == *key);
            if !exists {
                let inner = result.inner_mut();
                inner.entries.push((key.clone(), value.clone()));
                inner.is_packed = false;
                inner.invalidate_index();
            }
        }
        result
    }

    /// Get entries for iteration.
    pub fn entries(&self) -> &[(ArrayKey, Value)] {
        &self.inner.entries
    }

    /// Remove and return the last entry's value (like array_pop).
    pub fn pop(&mut self) -> Value {
        let inner = self.inner_mut();
        match inner.entries.pop() {
            Some((ArrayKey::Int(k), v)) => {
                // Remove from int index if present
                if let Some(ref mut idx) = inner.int_index {
                    idx.remove(&k);
                }
                v
            }
            Some((ArrayKey::String(ref k), v)) => {
                if let Some(ref mut idx) = inner.str_index {
                    idx.remove(k);
                }
                v
            }
            None => Value::Null,
        }
    }

    /// Remove and return the first entry's value, reindexing integer keys (like array_shift).
    pub fn shift(&mut self) -> Value {
        if self.inner.entries.is_empty() {
            return Value::Null;
        }
        let inner = self.inner_mut();
        let (_, val) = inner.entries.remove(0);
        // Reindex integer keys starting from 0
        let mut next = 0i64;
        for entry in &mut inner.entries {
            if let ArrayKey::Int(_) = entry.0 {
                entry.0 = ArrayKey::Int(next);
                next += 1;
            }
        }
        inner.next_int_key = next;
        // After reindex, check if packed (all int keys in sequence)
        inner.is_packed = inner
            .entries
            .iter()
            .enumerate()
            .all(|(i, (k, _))| matches!(k, ArrayKey::Int(n) if *n == i as i64));
        inner.invalidate_index();
        val
    }

    /// Prepend a value at the beginning, reindexing integer keys (like array_unshift).
    pub fn unshift(&mut self, value: Value) {
        let inner = self.inner_mut();
        inner.entries.insert(0, (ArrayKey::Int(0), value));
        // Reindex integer keys
        let mut next = 0i64;
        for entry in &mut inner.entries {
            if let ArrayKey::Int(_) = entry.0 {
                entry.0 = ArrayKey::Int(next);
                next += 1;
            }
        }
        inner.next_int_key = next;
        inner.is_packed = inner
            .entries
            .iter()
            .enumerate()
            .all(|(i, (k, _))| matches!(k, ArrayKey::Int(n) if *n == i as i64));
        inner.invalidate_index();
    }

    /// Return the first key, or Null if empty (like array_key_first).
    pub fn key_first(&self) -> Value {
        match self.inner.entries.first() {
            Some((ArrayKey::Int(n), _)) => Value::Long(*n),
            Some((ArrayKey::String(s), _)) => Value::String(s.clone()),
            None => Value::Null,
        }
    }

    /// Return the last key, or Null if empty (like array_key_last).
    pub fn key_last(&self) -> Value {
        match self.inner.entries.last() {
            Some((ArrayKey::Int(n), _)) => Value::Long(*n),
            Some((ArrayKey::String(s), _)) => Value::String(s.clone()),
            None => Value::Null,
        }
    }

    /// Return the current value (first entry) like current().
    pub fn current(&self) -> Value {
        match self.inner.entries.first() {
            Some((_, v)) => v.clone(),
            None => Value::Bool(false),
        }
    }

    /// Check if the array is a list (sequential integer keys 0..n).
    pub fn is_list(&self) -> bool {
        if self.inner.is_packed {
            return true;
        }
        self.inner
            .entries
            .iter()
            .enumerate()
            .all(|(i, (k, _))| matches!(k, ArrayKey::Int(n) if *n == i as i64))
    }

    /// Get mutable entries. Invalidates optimization state since external mutations
    /// cannot be tracked. Triggers copy-on-write if array is shared.
    pub fn entries_mut(&mut self) -> &mut Vec<(ArrayKey, Value)> {
        let inner = self.inner_mut();
        inner.is_packed = false;
        inner.invalidate_index();
        &mut inner.entries
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
    // Handle hex prefix: 0x/0X
    if s.len() >= 2 {
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("0x") || lower.starts_with("+0x") || lower.starts_with("-0x") {
            let negative = s.starts_with('-');
            let hex_part = if negative || s.starts_with('+') {
                &lower[3..]
            } else {
                &lower[2..]
            };
            // Parse leading hex digits
            let mut result: i64 = 0;
            for ch in hex_part.chars() {
                if let Some(d) = ch.to_digit(16) {
                    result = result.wrapping_mul(16).wrapping_add(d as i64);
                } else {
                    break;
                }
            }
            return if negative { -result } else { result };
        }
        // Handle octal prefix: 0o/0O (PHP 8.1+)
        if lower.starts_with("0o") || lower.starts_with("+0o") || lower.starts_with("-0o") {
            let negative = s.starts_with('-');
            let oct_part = if negative || s.starts_with('+') {
                &lower[3..]
            } else {
                &lower[2..]
            };
            let mut result: i64 = 0;
            for ch in oct_part.chars() {
                if ch >= '0' && ch <= '7' {
                    result = result
                        .wrapping_mul(8)
                        .wrapping_add((ch as u8 - b'0') as i64);
                } else {
                    break;
                }
            }
            return if negative { -result } else { result };
        }
        // Handle binary prefix: 0b/0B
        if lower.starts_with("0b") || lower.starts_with("+0b") || lower.starts_with("-0b") {
            let negative = s.starts_with('-');
            let bin_part = if negative || s.starts_with('+') {
                &lower[3..]
            } else {
                &lower[2..]
            };
            let mut result: i64 = 0;
            for ch in bin_part.chars() {
                if ch == '0' || ch == '1' {
                    result = result
                        .wrapping_mul(2)
                        .wrapping_add((ch as u8 - b'0') as i64);
                } else {
                    break;
                }
            }
            return if negative { -result } else { result };
        }
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
pub fn php_increment_string(s: &str) -> String {
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

    // ── Performance-related tests (Phase 13) ──

    #[test]
    fn test_array_packed_mode() {
        // Sequential push creates a packed array
        let mut arr = PhpArray::new();
        arr.push(Value::Long(10));
        arr.push(Value::Long(20));
        arr.push(Value::Long(30));
        assert!(arr.is_list());
        // Packed mode gives O(1) indexed access
        assert_eq!(arr.get_int(0), Some(&Value::Long(10)));
        assert_eq!(arr.get_int(1), Some(&Value::Long(20)));
        assert_eq!(arr.get_int(2), Some(&Value::Long(30)));
        assert_eq!(arr.get_int(3), None);
    }

    #[test]
    fn test_array_packed_to_mixed_transition() {
        let mut arr = PhpArray::new();
        arr.push(Value::Long(10));
        arr.push(Value::Long(20));
        assert!(arr.is_list());
        // Adding a string key transitions to non-packed
        arr.set_string("key".to_string(), Value::Long(30));
        // Still finds all values
        assert_eq!(arr.get_int(0), Some(&Value::Long(10)));
        assert_eq!(arr.get_int(1), Some(&Value::Long(20)));
        assert_eq!(arr.get_string("key"), Some(&Value::Long(30)));
    }

    #[test]
    fn test_array_cow_clone() {
        // CoW: clone is cheap (Rc bump), mutation triggers deep copy
        let mut original = PhpArray::new();
        original.push(Value::Long(1));
        original.push(Value::Long(2));
        original.push(Value::Long(3));

        let mut clone = original.clone();
        // Mutation on clone doesn't affect original
        clone.push(Value::Long(4));
        assert_eq!(original.len(), 3);
        assert_eq!(clone.len(), 4);
        // Original values unchanged
        assert_eq!(original.get_int(0), Some(&Value::Long(1)));
        assert_eq!(clone.get_int(3), Some(&Value::Long(4)));
    }

    #[test]
    fn test_array_cow_shared_reads() {
        // Multiple readers share the same data (no deep copy)
        let mut arr = PhpArray::new();
        for i in 0..100 {
            arr.push(Value::Long(i));
        }
        let clone1 = arr.clone();
        let clone2 = arr.clone();
        // All clones read the same data
        assert_eq!(clone1.get_int(50), Some(&Value::Long(50)));
        assert_eq!(clone2.get_int(99), Some(&Value::Long(99)));
        assert_eq!(clone1.len(), 100);
        assert_eq!(clone2.len(), 100);
    }

    #[test]
    fn test_array_hash_index_large() {
        // Large arrays should build hash index for O(1) lookup
        let mut arr = PhpArray::new();
        for i in 0..100 {
            arr.set_string(format!("key_{}", i), Value::Long(i));
        }
        // Verify all entries are findable
        for i in 0..100 {
            assert_eq!(
                arr.get_string(&format!("key_{}", i)),
                Some(&Value::Long(i)),
                "Failed to find key_{}",
                i
            );
        }
        assert_eq!(arr.len(), 100);
    }

    #[test]
    fn test_array_from_entries_packed() {
        let entries = vec![
            (ArrayKey::Int(0), Value::Long(10)),
            (ArrayKey::Int(1), Value::Long(20)),
            (ArrayKey::Int(2), Value::Long(30)),
        ];
        let arr = PhpArray::from_entries(entries);
        assert!(arr.is_list());
        assert_eq!(arr.get_int(1), Some(&Value::Long(20)));
    }

    #[test]
    fn test_array_from_entries_not_packed() {
        let entries = vec![
            (ArrayKey::Int(0), Value::Long(10)),
            (ArrayKey::Int(5), Value::Long(50)),
        ];
        let arr = PhpArray::from_entries(entries);
        assert!(!arr.is_list());
        assert_eq!(arr.get_int(5), Some(&Value::Long(50)));
    }

    #[test]
    fn test_array_cow_set_int() {
        let mut original = PhpArray::new();
        original.push(Value::Long(1));
        let mut clone = original.clone();
        clone.set_int(0, Value::Long(99));
        // Original unaffected
        assert_eq!(original.get_int(0), Some(&Value::Long(1)));
        assert_eq!(clone.get_int(0), Some(&Value::Long(99)));
    }

    #[test]
    fn test_array_cow_unset() {
        let mut original = PhpArray::new();
        original.push(Value::Long(1));
        original.push(Value::Long(2));
        let mut clone = original.clone();
        clone.unset(&Value::Long(0));
        assert_eq!(original.len(), 2);
        assert_eq!(clone.len(), 1);
    }

    #[test]
    fn test_array_cow_shift() {
        let mut original = PhpArray::new();
        original.push(Value::Long(10));
        original.push(Value::Long(20));
        let mut clone = original.clone();
        let shifted = clone.shift();
        assert_eq!(shifted, Value::Long(10));
        assert_eq!(original.len(), 2);
        assert_eq!(clone.len(), 1);
    }

    #[test]
    fn test_array_cow_pop() {
        let mut original = PhpArray::new();
        original.push(Value::Long(10));
        original.push(Value::Long(20));
        let mut clone = original.clone();
        let popped = clone.pop();
        assert_eq!(popped, Value::Long(20));
        assert_eq!(original.len(), 2);
        assert_eq!(clone.len(), 1);
    }

    #[test]
    fn test_array_packed_negative_key() {
        // Negative keys break packed mode
        let mut arr = PhpArray::new();
        arr.push(Value::Long(1));
        arr.set_int(-1, Value::Long(99));
        assert_eq!(arr.get_int(-1), Some(&Value::Long(99)));
        assert_eq!(arr.get_int(0), Some(&Value::Long(1)));
    }

    #[test]
    fn test_array_entries_mut_cow() {
        let mut original = PhpArray::new();
        original.push(Value::Long(1));
        let mut clone = original.clone();
        // entries_mut triggers CoW
        clone.entries_mut().push((ArrayKey::Int(1), Value::Long(2)));
        assert_eq!(original.len(), 1);
        assert_eq!(clone.len(), 2);
    }
}
