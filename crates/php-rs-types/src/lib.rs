//! PHP type system
//!
//! This crate implements the core PHP value types (ZVal, ZString, ZArray, ZObject)
//! matching the reference PHP 8.6 implementation.

/// Core PHP value container (zval equivalent).
///
/// This enum represents all possible PHP value types. In the reference PHP implementation,
/// zval is a 16-byte struct with a union for the value and type/flags fields.
/// We use a Rust enum which provides type safety while matching PHP's semantics.
#[derive(Debug)]
pub enum ZVal {
    /// PHP null type
    Null,
    /// PHP false (boolean false)
    False,
    /// PHP true (boolean true)
    True,
    /// PHP integer (long) - always i64
    Long(i64),
    /// PHP float (double) - always f64
    Double(f64),
    /// PHP string - placeholder for now, will be replaced with ZString
    String(String),
    /// PHP array - placeholder for now, will be replaced with ZArray
    Array,
    /// PHP object - placeholder for now, will be replaced with ZObject
    Object,
    /// PHP resource - placeholder for now, will be replaced with ZResource
    Resource,
    /// PHP reference - placeholder for now, will be replaced with ZReference
    Reference,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zval_variants_exist() {
        // Test: can construct all ZVal variants
        let _null = ZVal::Null;
        let _false = ZVal::False;
        let _true = ZVal::True;
        let _long = ZVal::Long(42);
        let _double = ZVal::Double(2.5);
        let _string = ZVal::String("hello".to_string());
        let _array = ZVal::Array;
        let _object = ZVal::Object;
        let _resource = ZVal::Resource;
        let _reference = ZVal::Reference;
    }

    #[test]
    fn test_zval_long_values() {
        // Test: Long can hold various integer values
        let zero = ZVal::Long(0);
        let positive = ZVal::Long(123456);
        let negative = ZVal::Long(-999);
        let max = ZVal::Long(i64::MAX);
        let min = ZVal::Long(i64::MIN);

        match zero {
            ZVal::Long(n) => assert_eq!(n, 0),
            _ => panic!("Expected Long variant"),
        }

        match positive {
            ZVal::Long(n) => assert_eq!(n, 123456),
            _ => panic!("Expected Long variant"),
        }

        match negative {
            ZVal::Long(n) => assert_eq!(n, -999),
            _ => panic!("Expected Long variant"),
        }

        match max {
            ZVal::Long(n) => assert_eq!(n, i64::MAX),
            _ => panic!("Expected Long variant"),
        }

        match min {
            ZVal::Long(n) => assert_eq!(n, i64::MIN),
            _ => panic!("Expected Long variant"),
        }
    }

    #[test]
    fn test_zval_double_values() {
        // Test: Double can hold various float values
        let zero = ZVal::Double(0.0);
        let precise = ZVal::Double(1.23456789);
        let negative = ZVal::Double(-2.5);
        let inf = ZVal::Double(f64::INFINITY);
        let neg_inf = ZVal::Double(f64::NEG_INFINITY);
        let nan = ZVal::Double(f64::NAN);

        match zero {
            ZVal::Double(f) => assert_eq!(f, 0.0),
            _ => panic!("Expected Double variant"),
        }

        match precise {
            ZVal::Double(f) => assert!((f - 1.23456789).abs() < f64::EPSILON),
            _ => panic!("Expected Double variant"),
        }

        match negative {
            ZVal::Double(f) => assert_eq!(f, -2.5),
            _ => panic!("Expected Double variant"),
        }

        match inf {
            ZVal::Double(f) => assert!(f.is_infinite() && f.is_sign_positive()),
            _ => panic!("Expected Double variant"),
        }

        match neg_inf {
            ZVal::Double(f) => assert!(f.is_infinite() && f.is_sign_negative()),
            _ => panic!("Expected Double variant"),
        }

        match nan {
            ZVal::Double(f) => assert!(f.is_nan()),
            _ => panic!("Expected Double variant"),
        }
    }

    #[test]
    fn test_zval_string_values() {
        // Test: String can hold various string values
        let empty = ZVal::String("".to_string());
        let ascii = ZVal::String("hello".to_string());
        let unicode = ZVal::String("你好世界🌍".to_string());
        let binary = ZVal::String("binary\0data".to_string());

        match empty {
            ZVal::String(ref s) => assert_eq!(s, ""),
            _ => panic!("Expected String variant"),
        }

        match ascii {
            ZVal::String(ref s) => assert_eq!(s, "hello"),
            _ => panic!("Expected String variant"),
        }

        match unicode {
            ZVal::String(ref s) => assert_eq!(s, "你好世界🌍"),
            _ => panic!("Expected String variant"),
        }

        match binary {
            ZVal::String(ref s) => assert_eq!(s, "binary\0data"),
            _ => panic!("Expected String variant"),
        }
    }

    #[test]
    fn test_zval_boolean_variants() {
        // Test: PHP has separate True and False variants (not Bool(bool))
        let t = ZVal::True;
        let f = ZVal::False;

        match t {
            ZVal::True => {}
            _ => panic!("Expected True variant"),
        }

        match f {
            ZVal::False => {}
            _ => panic!("Expected False variant"),
        }
    }

    #[test]
    fn test_zval_debug_output() {
        // Test: ZVal implements Debug (required for development)
        let val = ZVal::Long(42);
        let debug_str = format!("{:?}", val);
        assert!(debug_str.contains("Long"));
        assert!(debug_str.contains("42"));
    }
}
