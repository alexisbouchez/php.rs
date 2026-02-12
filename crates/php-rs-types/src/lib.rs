//! PHP type system
//!
//! This crate implements the core PHP value types (ZVal, ZString, ZArray, ZObject)
//! matching the reference PHP 8.6 implementation.

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
#[derive(Debug)]
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
}
