//! PHP variable functions.
//!
//! Reference: php-src/ext/standard/var.c, type.c, basic_functions.c

/// PHP type names returned by gettype().
pub fn php_gettype(type_tag: u8) -> &'static str {
    match type_tag {
        0 => "NULL",
        1 => "boolean",
        2 => "integer",
        3 => "double",
        4 => "string",
        5 => "array",
        6 => "object",
        7 => "resource",
        _ => "unknown type",
    }
}

/// PHP 8.0+ get_debug_type() names.
pub fn php_get_debug_type(type_tag: u8, class_name: Option<&str>) -> String {
    match type_tag {
        0 => "null".to_string(),
        1 => "bool".to_string(),
        2 => "int".to_string(),
        3 => "float".to_string(),
        4 => "string".to_string(),
        5 => "array".to_string(),
        6 => class_name.unwrap_or("object").to_string(),
        7 => "resource".to_string(),
        _ => "unknown".to_string(),
    }
}

/// is_numeric() — Check if a string is numeric.
pub fn php_is_numeric(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // Try parsing as integer
    if s.parse::<i64>().is_ok() {
        return true;
    }
    // Try parsing as float (including scientific notation)
    if s.parse::<f64>().is_ok() {
        // Reject special float values
        let lower = s.to_lowercase();
        if lower == "inf" || lower == "-inf" || lower == "nan" || lower == "infinity" {
            return false;
        }
        return true;
    }
    false
}

/// intval() — Get the integer value of a variable.
pub fn php_intval(s: &str, base: u32) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    if base == 10 {
        // PHP behavior: parse until first non-numeric character
        let mut end = 0;
        let bytes = s.as_bytes();
        if !bytes.is_empty() && (bytes[0] == b'-' || bytes[0] == b'+') {
            end = 1;
        }
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
            return 0;
        }
        s[..end].parse::<i64>().unwrap_or(0)
    } else {
        // Strip 0x, 0b, 0o prefixes
        let s = if base == 16 {
            s.strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s)
        } else if base == 2 {
            s.strip_prefix("0b")
                .or_else(|| s.strip_prefix("0B"))
                .unwrap_or(s)
        } else if base == 8 {
            s.strip_prefix("0o")
                .or_else(|| s.strip_prefix("0O"))
                .unwrap_or(s)
        } else {
            s
        };
        i64::from_str_radix(s, base).unwrap_or(0)
    }
}

/// floatval() — Get float value of a variable.
pub fn php_floatval(s: &str) -> f64 {
    let s = s.trim();
    if s.is_empty() {
        return 0.0;
    }

    // Parse until first non-numeric character (including decimal point and e)
    let mut end = 0;
    let bytes = s.as_bytes();
    if !bytes.is_empty() && (bytes[0] == b'-' || bytes[0] == b'+') {
        end = 1;
    }
    let mut has_dot = false;
    let mut has_e = false;
    while end < bytes.len() {
        match bytes[end] {
            b'0'..=b'9' => end += 1,
            b'.' if !has_dot && !has_e => {
                has_dot = true;
                end += 1;
            }
            b'e' | b'E' if !has_e => {
                has_e = true;
                end += 1;
                if end < bytes.len() && (bytes[end] == b'-' || bytes[end] == b'+') {
                    end += 1;
                }
            }
            _ => break,
        }
    }

    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return 0.0;
    }

    s[..end].parse::<f64>().unwrap_or(0.0)
}

/// var_dump() — Dumps information about a variable (returns formatted string).
///
/// This is a simplified version; the real one integrates with ZVal types.
pub fn php_var_dump_string(type_tag: u8, value: &str) -> String {
    match type_tag {
        0 => "NULL\n".to_string(),
        1 => {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                "bool(true)\n".to_string()
            } else {
                "bool(false)\n".to_string()
            }
        }
        2 => format!("int({})\n", value),
        3 => {
            let f: f64 = value.parse().unwrap_or(0.0);
            format!("float({})\n", f)
        }
        4 => format!("string({}) \"{}\"\n", value.len(), value),
        _ => format!("unknown({})\n", value),
    }
}

/// print_r() — Prints human-readable information (returns formatted string).
pub fn php_print_r_string(type_tag: u8, value: &str) -> String {
    match type_tag {
        0 => String::new(),
        1 => {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                "1".to_string()
            } else {
                String::new()
            }
        }
        _ => value.to_string(),
    }
}

// ── 8.3.6: serialize / unserialize ────────────────────────────────────────────

/// Serializable PHP value for serialize/unserialize.
#[derive(Debug, Clone, PartialEq)]
pub enum SerializableValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<(SerializableValue, SerializableValue)>),
}

/// serialize() — Generates a storable representation of a value.
///
/// PHP serialization format:
///   N;           — NULL
///   b:0;  b:1;  — boolean
///   i:42;        — integer
///   d:3.14;      — float
///   s:5:"hello"; — string
///   a:2:{...}    — array
pub fn php_serialize(val: &SerializableValue) -> String {
    match val {
        SerializableValue::Null => "N;".to_string(),
        SerializableValue::Bool(b) => format!("b:{};", if *b { 1 } else { 0 }),
        SerializableValue::Int(n) => format!("i:{};", n),
        SerializableValue::Float(f) => {
            if f.is_infinite() {
                if f.is_sign_positive() {
                    "d:INF;".to_string()
                } else {
                    "d:-INF;".to_string()
                }
            } else if f.is_nan() {
                "d:NAN;".to_string()
            } else {
                format!("d:{};", f)
            }
        }
        SerializableValue::Str(s) => format!("s:{}:\"{}\";", s.len(), s),
        SerializableValue::Array(entries) => {
            let mut result = format!("a:{}:{{", entries.len());
            for (key, value) in entries {
                result.push_str(&php_serialize(key));
                result.push_str(&php_serialize(value));
            }
            result.push('}');
            result
        }
    }
}

/// unserialize() — Creates a PHP value from a stored representation.
pub fn php_unserialize(input: &str) -> Option<SerializableValue> {
    let bytes = input.as_bytes();
    let (val, _) = unserialize_value(bytes, 0)?;
    Some(val)
}

fn unserialize_value(data: &[u8], pos: usize) -> Option<(SerializableValue, usize)> {
    if pos >= data.len() {
        return None;
    }
    match data[pos] {
        b'N' => {
            // N;
            if pos + 1 < data.len() && data[pos + 1] == b';' {
                Some((SerializableValue::Null, pos + 2))
            } else {
                None
            }
        }
        b'b' => {
            // b:0; or b:1;
            if pos + 3 < data.len() && data[pos + 1] == b':' && data[pos + 3] == b';' {
                let val = data[pos + 2] != b'0';
                Some((SerializableValue::Bool(val), pos + 4))
            } else {
                None
            }
        }
        b'i' => {
            // i:NUM;
            if pos + 1 < data.len() && data[pos + 1] == b':' {
                let start = pos + 2;
                let end = memchr_byte(b';', data, start)?;
                let num_str = std::str::from_utf8(&data[start..end]).ok()?;
                let n: i64 = num_str.parse().ok()?;
                Some((SerializableValue::Int(n), end + 1))
            } else {
                None
            }
        }
        b'd' => {
            // d:NUM;
            if pos + 1 < data.len() && data[pos + 1] == b':' {
                let start = pos + 2;
                let end = memchr_byte(b';', data, start)?;
                let num_str = std::str::from_utf8(&data[start..end]).ok()?;
                let f: f64 = match num_str {
                    "INF" => f64::INFINITY,
                    "-INF" => f64::NEG_INFINITY,
                    "NAN" => f64::NAN,
                    _ => num_str.parse().ok()?,
                };
                Some((SerializableValue::Float(f), end + 1))
            } else {
                None
            }
        }
        b's' => {
            // s:LEN:"STRING";
            if pos + 1 < data.len() && data[pos + 1] == b':' {
                let start = pos + 2;
                let colon = memchr_byte(b':', data, start)?;
                let len_str = std::str::from_utf8(&data[start..colon]).ok()?;
                let len: usize = len_str.parse().ok()?;
                // Expect :"...", so colon+1 should be "
                if colon + 1 >= data.len() || data[colon + 1] != b'"' {
                    return None;
                }
                let str_start = colon + 2;
                let str_end = str_start + len;
                if str_end + 2 > data.len() || data[str_end] != b'"' || data[str_end + 1] != b';' {
                    return None;
                }
                let s = std::str::from_utf8(&data[str_start..str_end]).ok()?;
                Some((SerializableValue::Str(s.to_string()), str_end + 2))
            } else {
                None
            }
        }
        b'a' => {
            // a:COUNT:{...}
            if pos + 1 < data.len() && data[pos + 1] == b':' {
                let start = pos + 2;
                let colon = memchr_byte(b':', data, start)?;
                let count_str = std::str::from_utf8(&data[start..colon]).ok()?;
                let count: usize = count_str.parse().ok()?;
                // Expect :{
                if colon + 1 >= data.len() || data[colon + 1] != b'{' {
                    return None;
                }
                let mut cur = colon + 2;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let (key, next) = unserialize_value(data, cur)?;
                    let (value, next2) = unserialize_value(data, next)?;
                    entries.push((key, value));
                    cur = next2;
                }
                if cur >= data.len() || data[cur] != b'}' {
                    return None;
                }
                Some((SerializableValue::Array(entries), cur + 1))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn memchr_byte(needle: u8, data: &[u8], start: usize) -> Option<usize> {
    data[start..]
        .iter()
        .position(|&b| b == needle)
        .map(|p| p + start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gettype() {
        assert_eq!(php_gettype(0), "NULL");
        assert_eq!(php_gettype(1), "boolean");
        assert_eq!(php_gettype(2), "integer");
        assert_eq!(php_gettype(3), "double");
        assert_eq!(php_gettype(4), "string");
        assert_eq!(php_gettype(5), "array");
        assert_eq!(php_gettype(6), "object");
    }

    #[test]
    fn test_get_debug_type() {
        assert_eq!(php_get_debug_type(0, None), "null");
        assert_eq!(php_get_debug_type(2, None), "int");
        assert_eq!(php_get_debug_type(6, Some("DateTime")), "DateTime");
    }

    #[test]
    fn test_is_numeric() {
        assert!(php_is_numeric("123"));
        assert!(php_is_numeric("-123"));
        assert!(php_is_numeric("12.5"));
        assert!(php_is_numeric("1.5e2"));
        assert!(php_is_numeric("  42  "));
        assert!(!php_is_numeric("abc"));
        assert!(!php_is_numeric("12abc"));
        assert!(!php_is_numeric(""));
        assert!(!php_is_numeric("inf"));
    }

    #[test]
    fn test_intval() {
        assert_eq!(php_intval("42", 10), 42);
        assert_eq!(php_intval("-42", 10), -42);
        assert_eq!(php_intval("042", 8), 34);
        assert_eq!(php_intval("0x1A", 16), 26);
        assert_eq!(php_intval("0b1010", 2), 10);
        assert_eq!(php_intval("12abc", 10), 12);
        assert_eq!(php_intval("abc", 10), 0);
        assert_eq!(php_intval("", 10), 0);
    }

    #[test]
    fn test_floatval() {
        assert_eq!(php_floatval("1.5"), 1.5);
        assert_eq!(php_floatval("-2.75"), -2.75);
        assert_eq!(php_floatval("1.5e2"), 150.0);
        assert_eq!(php_floatval("12abc"), 12.0);
        assert_eq!(php_floatval("abc"), 0.0);
        assert_eq!(php_floatval(""), 0.0);
    }

    #[test]
    fn test_var_dump_string() {
        assert_eq!(php_var_dump_string(0, ""), "NULL\n");
        assert_eq!(php_var_dump_string(1, "1"), "bool(true)\n");
        assert_eq!(php_var_dump_string(1, ""), "bool(false)\n");
        assert_eq!(php_var_dump_string(2, "42"), "int(42)\n");
        assert_eq!(php_var_dump_string(4, "hello"), "string(5) \"hello\"\n");
    }

    // ── serialize / unserialize ──
    #[test]
    fn test_serialize_primitives() {
        assert_eq!(php_serialize(&SerializableValue::Null), "N;");
        assert_eq!(php_serialize(&SerializableValue::Bool(true)), "b:1;");
        assert_eq!(php_serialize(&SerializableValue::Bool(false)), "b:0;");
        assert_eq!(php_serialize(&SerializableValue::Int(42)), "i:42;");
        assert_eq!(php_serialize(&SerializableValue::Int(-7)), "i:-7;");
        assert_eq!(php_serialize(&SerializableValue::Float(3.14)), "d:3.14;");
        assert_eq!(
            php_serialize(&SerializableValue::Str("hello".to_string())),
            "s:5:\"hello\";"
        );
    }

    #[test]
    fn test_serialize_array() {
        let arr = SerializableValue::Array(vec![
            (
                SerializableValue::Int(0),
                SerializableValue::Str("a".to_string()),
            ),
            (
                SerializableValue::Int(1),
                SerializableValue::Str("b".to_string()),
            ),
        ]);
        assert_eq!(php_serialize(&arr), "a:2:{i:0;s:1:\"a\";i:1;s:1:\"b\";}");
    }

    #[test]
    fn test_unserialize_primitives() {
        assert_eq!(php_unserialize("N;"), Some(SerializableValue::Null));
        assert_eq!(php_unserialize("b:1;"), Some(SerializableValue::Bool(true)));
        assert_eq!(
            php_unserialize("b:0;"),
            Some(SerializableValue::Bool(false))
        );
        assert_eq!(php_unserialize("i:42;"), Some(SerializableValue::Int(42)));
        assert_eq!(
            php_unserialize("d:3.14;"),
            Some(SerializableValue::Float(3.14))
        );
        assert_eq!(
            php_unserialize("s:5:\"hello\";"),
            Some(SerializableValue::Str("hello".to_string()))
        );
    }

    #[test]
    fn test_unserialize_array() {
        let result = php_unserialize("a:2:{i:0;s:1:\"a\";i:1;s:1:\"b\";}");
        assert!(result.is_some());
        if let Some(SerializableValue::Array(entries)) = result {
            assert_eq!(entries.len(), 2);
        }
    }

    #[test]
    fn test_serialize_roundtrip() {
        let values = vec![
            SerializableValue::Null,
            SerializableValue::Bool(true),
            SerializableValue::Int(123),
            SerializableValue::Float(2.5),
            SerializableValue::Str("test".to_string()),
        ];
        for val in values {
            let serialized = php_serialize(&val);
            let deserialized = php_unserialize(&serialized).unwrap();
            assert_eq!(val, deserialized);
        }
    }

    #[test]
    fn test_print_r_string() {
        assert_eq!(php_print_r_string(0, ""), "");
        assert_eq!(php_print_r_string(1, "1"), "1");
        assert_eq!(php_print_r_string(1, ""), "");
        assert_eq!(php_print_r_string(2, "42"), "42");
    }
}
