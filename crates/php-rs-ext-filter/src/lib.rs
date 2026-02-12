//! PHP filter extension.
//!
//! Implements filter_var() with FILTER_VALIDATE_* and FILTER_SANITIZE_*.
//! Reference: php-src/ext/filter/

// ── Filter IDs ───────────────────────────────────────────────────────────────

pub const FILTER_VALIDATE_INT: u32 = 257;
pub const FILTER_VALIDATE_FLOAT: u32 = 259;
pub const FILTER_VALIDATE_EMAIL: u32 = 274;
pub const FILTER_VALIDATE_URL: u32 = 273;
pub const FILTER_VALIDATE_IP: u32 = 275;
pub const FILTER_VALIDATE_BOOLEAN: u32 = 258;
pub const FILTER_VALIDATE_DOMAIN: u32 = 277;

pub const FILTER_SANITIZE_STRING: u32 = 513;
pub const FILTER_SANITIZE_EMAIL: u32 = 517;
pub const FILTER_SANITIZE_URL: u32 = 518;
pub const FILTER_SANITIZE_NUMBER_INT: u32 = 519;
pub const FILTER_SANITIZE_NUMBER_FLOAT: u32 = 520;
pub const FILTER_SANITIZE_ENCODED: u32 = 514;
pub const FILTER_SANITIZE_SPECIAL_CHARS: u32 = 515;
pub const FILTER_SANITIZE_ADD_SLASHES: u32 = 523;

pub const FILTER_DEFAULT: u32 = 516;

// ── filter_var ───────────────────────────────────────────────────────────────

/// filter_var() — Filters a variable with a specified filter.
///
/// Returns Some(filtered_value) on success, None on failure.
pub fn filter_var(value: &str, filter: u32) -> Option<String> {
    match filter {
        FILTER_VALIDATE_INT => validate_int(value),
        FILTER_VALIDATE_FLOAT => validate_float(value),
        FILTER_VALIDATE_EMAIL => validate_email(value),
        FILTER_VALIDATE_URL => validate_url(value),
        FILTER_VALIDATE_IP => validate_ip(value),
        FILTER_VALIDATE_BOOLEAN => validate_boolean(value),
        FILTER_VALIDATE_DOMAIN => validate_domain(value),
        FILTER_SANITIZE_EMAIL => Some(sanitize_email(value)),
        FILTER_SANITIZE_URL => Some(sanitize_url(value)),
        FILTER_SANITIZE_NUMBER_INT => Some(sanitize_number_int(value)),
        FILTER_SANITIZE_NUMBER_FLOAT => Some(sanitize_number_float(value)),
        FILTER_SANITIZE_SPECIAL_CHARS => Some(sanitize_special_chars(value)),
        FILTER_SANITIZE_ADD_SLASHES => Some(sanitize_add_slashes(value)),
        FILTER_SANITIZE_ENCODED => Some(sanitize_encoded(value)),
        FILTER_DEFAULT | FILTER_SANITIZE_STRING => Some(value.to_string()),
        _ => None,
    }
}

// ── Validators ───────────────────────────────────────────────────────────────

fn validate_int(value: &str) -> Option<String> {
    let trimmed = value.trim();
    // Allow leading +
    let to_parse = trimmed.strip_prefix('+').unwrap_or(trimmed);
    to_parse.parse::<i64>().ok().map(|n| n.to_string())
}

fn validate_float(value: &str) -> Option<String> {
    let trimmed = value.trim();
    trimmed.parse::<f64>().ok().map(|f| f.to_string())
}

fn validate_email(value: &str) -> Option<String> {
    let value = value.trim();
    let at_pos = value.find('@')?;
    if at_pos == 0 || at_pos == value.len() - 1 {
        return None;
    }
    let local = &value[..at_pos];
    let domain = &value[at_pos + 1..];

    // Basic validation
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    if !domain.contains('.') {
        return None;
    }
    // Check for valid characters (simplified)
    if !local
        .chars()
        .all(|c| c.is_alphanumeric() || "._+-".contains(c))
    {
        return None;
    }
    if !domain
        .chars()
        .all(|c| c.is_alphanumeric() || ".-".contains(c))
    {
        return None;
    }
    Some(value.to_string())
}

fn validate_url(value: &str) -> Option<String> {
    let value = value.trim();
    // Must have a scheme
    if !value.contains("://") {
        return None;
    }
    let scheme_end = value.find("://")?;
    let scheme = &value[..scheme_end];
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    let rest = &value[scheme_end + 3..];
    if rest.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn validate_ip(value: &str) -> Option<String> {
    let value = value.trim();
    // Try IPv4
    if validate_ipv4(value) {
        return Some(value.to_string());
    }
    // Try IPv6 (simplified)
    if value.contains(':') && value.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return Some(value.to_string());
    }
    None
}

fn validate_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.parse::<u8>().is_ok() && (p.len() == 1 || !p.starts_with('0')))
}

fn validate_boolean(value: &str) -> Option<String> {
    match value.to_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some("1".to_string()),
        "false" | "off" | "no" | "0" | "" => Some("".to_string()),
        _ => None,
    }
}

fn validate_domain(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
        return None;
    }
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    if !value.contains('.') {
        return None;
    }
    Some(value.to_string())
}

// ── Sanitizers ───────────────────────────────────────────────────────────────

fn sanitize_email(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric() || "!#$%&'*+/=?^_`{|}~@.[]- ".contains(*c))
        .collect()
}

fn sanitize_url(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric() || ":/.?#[]@!$&'()*+,;=-_%~".contains(*c))
        .collect()
}

fn sanitize_number_int(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+' || *c == '-')
        .collect()
}

fn sanitize_number_float(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            c.is_ascii_digit() || *c == '+' || *c == '-' || *c == '.' || *c == 'e' || *c == 'E'
        })
        .collect()
}

fn sanitize_special_chars(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '<' => result.push_str("&#60;"),
            '>' => result.push_str("&#62;"),
            '&' => result.push_str("&#38;"),
            '"' => result.push_str("&#34;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(ch),
        }
    }
    result
}

fn sanitize_add_slashes(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\'' | '"' | '\\' => {
                result.push('\\');
                result.push(ch);
            }
            '\0' => result.push_str("\\0"),
            _ => result.push(ch),
        }
    }
    result
}

fn sanitize_encoded(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_int() {
        assert_eq!(
            filter_var("42", FILTER_VALIDATE_INT),
            Some("42".to_string())
        );
        assert_eq!(
            filter_var("-7", FILTER_VALIDATE_INT),
            Some("-7".to_string())
        );
        assert_eq!(
            filter_var("+10", FILTER_VALIDATE_INT),
            Some("10".to_string())
        );
        assert_eq!(filter_var("abc", FILTER_VALIDATE_INT), None);
        assert_eq!(filter_var("1.5", FILTER_VALIDATE_INT), None);
    }

    #[test]
    fn test_validate_float() {
        assert_eq!(
            filter_var("1.5", FILTER_VALIDATE_FLOAT),
            Some("1.5".to_string())
        );
        assert_eq!(
            filter_var("42", FILTER_VALIDATE_FLOAT),
            Some("42".to_string())
        );
        assert_eq!(filter_var("abc", FILTER_VALIDATE_FLOAT), None);
    }

    #[test]
    fn test_validate_email() {
        assert_eq!(
            filter_var("user@example.com", FILTER_VALIDATE_EMAIL),
            Some("user@example.com".to_string())
        );
        assert_eq!(filter_var("invalid", FILTER_VALIDATE_EMAIL), None);
        assert_eq!(filter_var("@example.com", FILTER_VALIDATE_EMAIL), None);
        assert_eq!(filter_var("user@", FILTER_VALIDATE_EMAIL), None);
    }

    #[test]
    fn test_validate_url() {
        assert_eq!(
            filter_var("https://example.com", FILTER_VALIDATE_URL),
            Some("https://example.com".to_string())
        );
        assert_eq!(filter_var("not a url", FILTER_VALIDATE_URL), None);
        assert_eq!(filter_var("://missing", FILTER_VALIDATE_URL), None);
    }

    #[test]
    fn test_validate_ip() {
        assert_eq!(
            filter_var("192.168.1.1", FILTER_VALIDATE_IP),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(filter_var("999.999.999.999", FILTER_VALIDATE_IP), None);
        assert_eq!(filter_var("not_an_ip", FILTER_VALIDATE_IP), None);
    }

    #[test]
    fn test_validate_boolean() {
        assert_eq!(
            filter_var("true", FILTER_VALIDATE_BOOLEAN),
            Some("1".to_string())
        );
        assert_eq!(
            filter_var("yes", FILTER_VALIDATE_BOOLEAN),
            Some("1".to_string())
        );
        assert_eq!(
            filter_var("false", FILTER_VALIDATE_BOOLEAN),
            Some("".to_string())
        );
        assert_eq!(filter_var("maybe", FILTER_VALIDATE_BOOLEAN), None);
    }

    #[test]
    fn test_validate_domain() {
        assert_eq!(
            filter_var("example.com", FILTER_VALIDATE_DOMAIN),
            Some("example.com".to_string())
        );
        assert_eq!(filter_var("invalid!", FILTER_VALIDATE_DOMAIN), None);
        assert_eq!(filter_var("nodot", FILTER_VALIDATE_DOMAIN), None);
    }

    #[test]
    fn test_sanitize_email() {
        assert_eq!(
            filter_var("user<>@example.com", FILTER_SANITIZE_EMAIL),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_number_int() {
        assert_eq!(
            filter_var("abc123def-456", FILTER_SANITIZE_NUMBER_INT),
            Some("123-456".to_string())
        );
    }

    #[test]
    fn test_sanitize_special_chars() {
        assert_eq!(
            filter_var(
                "<script>alert('xss')</script>",
                FILTER_SANITIZE_SPECIAL_CHARS
            ),
            Some("&#60;script&#62;alert(&#39;xss&#39;)&#60;/script&#62;".to_string())
        );
    }

    #[test]
    fn test_sanitize_add_slashes() {
        assert_eq!(
            filter_var("it's a \"test\"", FILTER_SANITIZE_ADD_SLASHES),
            Some("it\\'s a \\\"test\\\"".to_string())
        );
    }
}
