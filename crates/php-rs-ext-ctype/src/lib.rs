//! PHP ctype extension.
//!
//! Implements character type checking functions.
//! Reference: php-src/ext/ctype/

/// ctype_alpha() — Check for alphabetic character(s).
pub fn ctype_alpha(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphabetic())
}

/// ctype_digit() — Check for numeric character(s).
pub fn ctype_digit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// ctype_alnum() — Check for alphanumeric character(s).
pub fn ctype_alnum(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// ctype_space() — Check for whitespace character(s).
pub fn ctype_space(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_whitespace())
}

/// ctype_upper() — Check for uppercase character(s).
pub fn ctype_upper(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase())
}

/// ctype_lower() — Check for lowercase character(s).
pub fn ctype_lower(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase())
}

/// ctype_punct() — Check for any printable character that is not whitespace or alphanumeric.
pub fn ctype_punct(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_punctuation())
}

/// ctype_print() — Check for printable character(s).
pub fn ctype_print(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// ctype_graph() — Check for any printable character(s) except space.
pub fn ctype_graph(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// ctype_cntrl() — Check for control character(s).
pub fn ctype_cntrl(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b < 0x20 || b == 0x7F)
}

/// ctype_xdigit() — Check for character(s) representing a hexadecimal digit.
pub fn ctype_xdigit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctype_alpha() {
        assert!(ctype_alpha("Hello"));
        assert!(!ctype_alpha("Hello123"));
        assert!(!ctype_alpha(""));
        assert!(!ctype_alpha("123"));
    }

    #[test]
    fn test_ctype_digit() {
        assert!(ctype_digit("12345"));
        assert!(!ctype_digit("123abc"));
        assert!(!ctype_digit(""));
    }

    #[test]
    fn test_ctype_alnum() {
        assert!(ctype_alnum("Hello123"));
        assert!(!ctype_alnum("Hello 123"));
        assert!(!ctype_alnum(""));
    }

    #[test]
    fn test_ctype_space() {
        assert!(ctype_space(" \t\n"));
        assert!(!ctype_space("hello"));
        assert!(!ctype_space(""));
    }

    #[test]
    fn test_ctype_upper_lower() {
        assert!(ctype_upper("HELLO"));
        assert!(!ctype_upper("Hello"));
        assert!(ctype_lower("hello"));
        assert!(!ctype_lower("Hello"));
    }

    #[test]
    fn test_ctype_punct() {
        assert!(ctype_punct("!@#$%"));
        assert!(!ctype_punct("Hello!"));
    }

    #[test]
    fn test_ctype_print() {
        assert!(ctype_print("Hello World!"));
        assert!(!ctype_print("Hello\x00World"));
    }

    #[test]
    fn test_ctype_graph() {
        assert!(ctype_graph("Hello!"));
        assert!(!ctype_graph("Hello World")); // Space fails
    }

    #[test]
    fn test_ctype_cntrl() {
        assert!(ctype_cntrl("\x00\x01\x1F"));
        assert!(!ctype_cntrl("hello"));
    }

    #[test]
    fn test_ctype_xdigit() {
        assert!(ctype_xdigit("0123456789abcdefABCDEF"));
        assert!(!ctype_xdigit("xyz"));
    }
}
