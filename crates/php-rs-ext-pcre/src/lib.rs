//! PHP PCRE extension.
//!
//! Implements preg_match, preg_match_all, preg_replace, preg_split, preg_quote.
//! Uses the Rust `regex` crate as backend.
//!
//! Reference: php-src/ext/pcre/

use regex::Regex;
use std::cell::Cell;

// ── Error codes ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PregError {
    NoError = 0,
    InternalError = 1,
    BacktrackLimitError = 2,
    RecursionLimitError = 3,
    BadUtf8Error = 4,
    BadUtf8OffsetError = 5,
    JitStacklimitError = 6,
}

thread_local! {
    static LAST_ERROR: Cell<PregError> = const { Cell::new(PregError::NoError) };
}

/// preg_last_error() — Returns the error code of the last PCRE regex execution.
pub fn preg_last_error() -> PregError {
    LAST_ERROR.with(|e| e.get())
}

/// preg_last_error_msg() — Returns the error message of the last PCRE regex execution.
pub fn preg_last_error_msg() -> &'static str {
    match preg_last_error() {
        PregError::NoError => "No error",
        PregError::InternalError => "Internal error",
        PregError::BacktrackLimitError => "Backtrack limit exhausted",
        PregError::RecursionLimitError => "Recursion limit exhausted",
        PregError::BadUtf8Error => "Malformed UTF-8 characters, possibly incorrectly encoded",
        PregError::BadUtf8OffsetError => {
            "The offset did not correspond to the beginning of a valid UTF-8 code point"
        }
        PregError::JitStacklimitError => "JIT stack limit exhausted",
    }
}

fn set_last_error(err: PregError) {
    LAST_ERROR.with(|e| e.set(err));
}

// ── Pattern parsing ──────────────────────────────────────────────────────────

/// Parse a PHP-style regex pattern (e.g., "/pattern/flags") into a Rust regex.
fn parse_php_pattern(pattern: &str) -> Option<(Regex, String)> {
    // PHP patterns are delimited: /pattern/flags or ~pattern~flags etc.
    if pattern.is_empty() {
        return None;
    }

    let delimiter = pattern.as_bytes()[0];
    let closing = match delimiter {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        d => d,
    };

    // Find closing delimiter (not escaped)
    let inner = &pattern[1..];
    let mut end = 0;
    let bytes = inner.as_bytes();
    while end < bytes.len() {
        if bytes[end] == closing && (end == 0 || bytes[end - 1] != b'\\') {
            break;
        }
        end += 1;
    }

    if end >= bytes.len() {
        return None;
    }

    let regex_body = &inner[..end];
    let flags = &inner[end + 1..];

    // Build Rust regex with flags
    let mut rust_pattern = String::new();
    if flags.contains('i') {
        rust_pattern.push_str("(?i)");
    }
    if flags.contains('s') {
        rust_pattern.push_str("(?s)");
    }
    if flags.contains('m') {
        rust_pattern.push_str("(?m)");
    }
    if flags.contains('x') {
        rust_pattern.push_str("(?x)");
    }
    rust_pattern.push_str(regex_body);

    match Regex::new(&rust_pattern) {
        Ok(re) => Some((re, flags.to_string())),
        Err(_) => {
            set_last_error(PregError::InternalError);
            None
        }
    }
}

// ── preg_match ───────────────────────────────────────────────────────────────

/// A single match result.
#[derive(Debug, Clone, PartialEq)]
pub struct PregMatch {
    /// Full match and capture groups.
    pub groups: Vec<Option<String>>,
}

/// preg_match() — Perform a regular expression match.
/// Returns 1 if matched, 0 if not, -1 on error.
pub fn preg_match(pattern: &str, subject: &str) -> (i32, Option<PregMatch>) {
    set_last_error(PregError::NoError);

    let (re, _flags) = match parse_php_pattern(pattern) {
        Some(p) => p,
        None => return (-1, None),
    };

    match re.captures(subject) {
        Some(caps) => {
            let groups: Vec<Option<String>> = (0..caps.len())
                .map(|i| caps.get(i).map(|m| m.as_str().to_string()))
                .collect();
            (1, Some(PregMatch { groups }))
        }
        None => (0, None),
    }
}

/// preg_match_all() — Perform a global regular expression match.
/// Returns number of matches.
pub fn preg_match_all(pattern: &str, subject: &str) -> (i32, Vec<PregMatch>) {
    set_last_error(PregError::NoError);

    let (re, _flags) = match parse_php_pattern(pattern) {
        Some(p) => p,
        None => return (-1, vec![]),
    };

    let mut matches = Vec::new();
    for caps in re.captures_iter(subject) {
        let groups: Vec<Option<String>> = (0..caps.len())
            .map(|i| caps.get(i).map(|m| m.as_str().to_string()))
            .collect();
        matches.push(PregMatch { groups });
    }

    (matches.len() as i32, matches)
}

// ── preg_replace ─────────────────────────────────────────────────────────────

/// preg_replace() — Perform a regular expression search and replace.
pub fn preg_replace(pattern: &str, replacement: &str, subject: &str) -> Option<String> {
    set_last_error(PregError::NoError);

    let (re, _flags) = parse_php_pattern(pattern)?;

    // Convert PHP-style backreferences ($1, \\1) to Rust regex ($1)
    let rust_replacement = replacement
        .replace("\\1", "$1")
        .replace("\\2", "$2")
        .replace("\\3", "$3")
        .replace("\\4", "$4")
        .replace("\\5", "$5")
        .replace("\\6", "$6")
        .replace("\\7", "$7")
        .replace("\\8", "$8")
        .replace("\\9", "$9");

    Some(
        re.replace_all(subject, rust_replacement.as_str())
            .to_string(),
    )
}

// ── preg_split ───────────────────────────────────────────────────────────────

/// preg_split() — Split string by a regular expression.
pub fn preg_split(pattern: &str, subject: &str, limit: Option<usize>) -> Option<Vec<String>> {
    set_last_error(PregError::NoError);

    let (re, _flags) = parse_php_pattern(pattern)?;

    let parts: Vec<String> = match limit {
        Some(n) if n > 0 => re.splitn(subject, n).map(String::from).collect(),
        _ => re.split(subject).map(String::from).collect(),
    };

    Some(parts)
}

// ── preg_quote ───────────────────────────────────────────────────────────────

/// preg_quote() — Quote regular expression characters.
pub fn preg_quote(str: &str, delimiter: Option<char>) -> String {
    let special = r"\.+*?[^$(){}=!<>|:-#";
    let mut result = String::with_capacity(str.len() * 2);

    for ch in str.chars() {
        if special.contains(ch) || delimiter == Some(ch) {
            result.push('\\');
        }
        result.push(ch);
    }

    result
}

// ── preg_grep ────────────────────────────────────────────────────────────────

/// preg_grep() — Return array entries that match the pattern.
pub fn preg_grep(pattern: &str, input: &[&str], invert: bool) -> Option<Vec<String>> {
    set_last_error(PregError::NoError);

    let (re, _flags) = parse_php_pattern(pattern)?;

    let result: Vec<String> = input
        .iter()
        .filter(|&&s| re.is_match(s) != invert)
        .map(|&s| s.to_string())
        .collect();

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preg_match_simple() {
        let (count, m) = preg_match("/world/", "hello world");
        assert_eq!(count, 1);
        assert_eq!(m.unwrap().groups[0], Some("world".to_string()));
    }

    #[test]
    fn test_preg_match_no_match() {
        let (count, m) = preg_match("/xyz/", "hello world");
        assert_eq!(count, 0);
        assert!(m.is_none());
    }

    #[test]
    fn test_preg_match_case_insensitive() {
        let (count, _) = preg_match("/hello/i", "HELLO WORLD");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_preg_match_groups() {
        let (count, m) = preg_match("/(\\w+)@(\\w+)/", "user@host");
        assert_eq!(count, 1);
        let m = m.unwrap();
        assert_eq!(m.groups[0], Some("user@host".to_string()));
        assert_eq!(m.groups[1], Some("user".to_string()));
        assert_eq!(m.groups[2], Some("host".to_string()));
    }

    #[test]
    fn test_preg_match_all() {
        let (count, matches) = preg_match_all("/\\d+/", "foo 123 bar 456 baz 789");
        assert_eq!(count, 3);
        assert_eq!(matches[0].groups[0], Some("123".to_string()));
        assert_eq!(matches[1].groups[0], Some("456".to_string()));
        assert_eq!(matches[2].groups[0], Some("789".to_string()));
    }

    #[test]
    fn test_preg_replace() {
        let result = preg_replace("/world/", "PHP", "hello world").unwrap();
        assert_eq!(result, "hello PHP");
    }

    #[test]
    fn test_preg_replace_backreference() {
        let result = preg_replace("/(\\w+)@(\\w+)/", "$2=$1", "user@host").unwrap();
        assert_eq!(result, "host=user");
    }

    #[test]
    fn test_preg_replace_global() {
        let result = preg_replace("/\\d+/", "X", "a1b2c3").unwrap();
        assert_eq!(result, "aXbXcX");
    }

    #[test]
    fn test_preg_split() {
        let result = preg_split("/[\\s,]+/", "one, two, three", None).unwrap();
        assert_eq!(result, vec!["one", "two", "three"]);
    }

    #[test]
    fn test_preg_split_limit() {
        let result = preg_split("/[\\s,]+/", "one, two, three", Some(2)).unwrap();
        assert_eq!(result, vec!["one", "two, three"]);
    }

    #[test]
    fn test_preg_quote() {
        assert_eq!(preg_quote("$10.00", None), "\\$10\\.00");
        assert_eq!(preg_quote("a/b", Some('/')), "a\\/b");
    }

    #[test]
    fn test_preg_grep() {
        let input = vec!["foo", "bar", "baz", "foobar"];
        let result = preg_grep("/foo/", &input, false).unwrap();
        assert_eq!(result, vec!["foo", "foobar"]);

        let result = preg_grep("/foo/", &input, true).unwrap();
        assert_eq!(result, vec!["bar", "baz"]);
    }

    #[test]
    fn test_preg_match_multiline() {
        let (count, _) = preg_match("/^world/m", "hello\nworld");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_preg_match_dotall() {
        let (count, _) = preg_match("/hello.world/s", "hello\nworld");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_invalid_pattern() {
        let (count, _) = preg_match("/[invalid/", "test");
        assert_eq!(count, -1);
    }

    #[test]
    fn test_different_delimiters() {
        let (count, _) = preg_match("~hello~", "hello world");
        assert_eq!(count, 1);

        let (count, _) = preg_match("#hello#i", "HELLO");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_preg_last_error() {
        preg_match("/valid/", "test");
        assert_eq!(preg_last_error(), PregError::NoError);
    }
}
