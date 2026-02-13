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

    #[test]
    fn test_print_r_string() {
        assert_eq!(php_print_r_string(0, ""), "");
        assert_eq!(php_print_r_string(1, "1"), "1");
        assert_eq!(php_print_r_string(1, ""), "");
        assert_eq!(php_print_r_string(2, "42"), "42");
    }
}
