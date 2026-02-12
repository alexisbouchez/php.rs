//! PHP type system
//!
//! This crate implements the core PHP value types (ZVal, ZString, ZArray, ZObject)
//! matching the reference PHP 8.6 implementation.

use std::fmt;

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
        let normal = ZVal::double(3.14159);
        let inf = ZVal::double(f64::INFINITY);
        let nan = ZVal::double(f64::NAN);

        let normal_clone = normal.clone();
        let inf_clone = inf.clone();
        let nan_clone = nan.clone();

        assert!((normal_clone.as_double().unwrap() - 3.14159).abs() < f64::EPSILON);
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
}
