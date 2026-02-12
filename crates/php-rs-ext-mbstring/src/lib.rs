//! PHP mbstring extension.
//!
//! Implements multibyte string functions.
//! Reference: php-src/ext/mbstring/

use std::cell::RefCell;

thread_local! {
    static INTERNAL_ENCODING: RefCell<String> = RefCell::new("UTF-8".to_string());
}

/// mb_internal_encoding() — Set/Get internal character encoding.
pub fn mb_internal_encoding(encoding: Option<&str>) -> String {
    INTERNAL_ENCODING.with(|e| {
        if let Some(enc) = encoding {
            *e.borrow_mut() = enc.to_string();
        }
        e.borrow().clone()
    })
}

/// mb_strlen() — Get string length in characters (not bytes).
pub fn mb_strlen(s: &str, _encoding: Option<&str>) -> usize {
    s.chars().count()
}

/// mb_substr() — Get part of string (character-based).
pub fn mb_substr(s: &str, start: i64, length: Option<i64>, _encoding: Option<&str>) -> String {
    let char_count = s.chars().count() as i64;

    let start = if start < 0 {
        (char_count + start).max(0) as usize
    } else {
        (start as usize).min(char_count as usize)
    };

    let end = match length {
        Some(l) if l < 0 => ((char_count + l) as usize).max(start),
        Some(l) => (start + l as usize).min(char_count as usize),
        None => char_count as usize,
    };

    s.chars().skip(start).take(end - start).collect()
}

/// mb_strpos() — Find position of first occurrence (character-based).
pub fn mb_strpos(
    haystack: &str,
    needle: &str,
    offset: usize,
    _encoding: Option<&str>,
) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    // Convert character offset to byte offset
    let byte_offset: usize = haystack.chars().take(offset).map(|c| c.len_utf8()).sum();
    haystack[byte_offset..].find(needle).map(|byte_pos| {
        // Convert byte position back to character position
        haystack[..byte_offset + byte_pos].chars().count()
    })
}

/// mb_strrpos() — Find position of last occurrence (character-based).
pub fn mb_strrpos(haystack: &str, needle: &str, _encoding: Option<&str>) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .rfind(needle)
        .map(|byte_pos| haystack[..byte_pos].chars().count())
}

/// mb_strtolower() — Make a string lowercase (Unicode-aware).
pub fn mb_strtolower(s: &str, _encoding: Option<&str>) -> String {
    s.to_lowercase()
}

/// mb_strtoupper() — Make a string uppercase (Unicode-aware).
pub fn mb_strtoupper(s: &str, _encoding: Option<&str>) -> String {
    s.to_uppercase()
}

/// mb_detect_encoding() — Detect character encoding.
///
/// Simplified: checks for valid UTF-8, ASCII, etc.
pub fn mb_detect_encoding(s: &str, _encoding_list: Option<&[&str]>) -> &'static str {
    if s.is_ascii() {
        "ASCII"
    } else if std::str::from_utf8(s.as_bytes()).is_ok() {
        "UTF-8"
    } else {
        "ISO-8859-1"
    }
}

/// mb_convert_encoding() — Convert character encoding.
///
/// Simplified: only handles UTF-8 ↔ ASCII (real implementation needs iconv or encoding_rs).
pub fn mb_convert_encoding(s: &str, to_encoding: &str, _from_encoding: Option<&str>) -> String {
    match to_encoding.to_uppercase().as_str() {
        "UTF-8" => s.to_string(),
        "ASCII" => s
            .chars()
            .map(|c| if c.is_ascii() { c } else { '?' })
            .collect(),
        _ => s.to_string(),
    }
}

/// mb_str_split() — Split a multibyte string into an array of characters.
pub fn mb_str_split(s: &str, length: usize) -> Vec<String> {
    if length == 0 {
        return vec![s.to_string()];
    }
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(length)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// mb_substr_count() — Count the number of substring occurrences.
pub fn mb_substr_count(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mb_strlen() {
        assert_eq!(mb_strlen("hello", None), 5);
        assert_eq!(mb_strlen("héllo", None), 5); // é is one character
        assert_eq!(mb_strlen("日本語", None), 3);
        assert_eq!(mb_strlen("", None), 0);
    }

    #[test]
    fn test_mb_substr() {
        assert_eq!(mb_substr("日本語テスト", 0, Some(3), None), "日本語");
        assert_eq!(mb_substr("日本語テスト", 3, None, None), "テスト");
        assert_eq!(mb_substr("日本語テスト", -3, None, None), "テスト");
        assert_eq!(mb_substr("hello", 1, Some(3), None), "ell");
    }

    #[test]
    fn test_mb_strpos() {
        assert_eq!(mb_strpos("日本語テスト", "テ", 0, None), Some(3));
        assert_eq!(mb_strpos("hello world", "world", 0, None), Some(6));
        assert_eq!(mb_strpos("hello", "xyz", 0, None), None);
    }

    #[test]
    fn test_mb_strrpos() {
        assert_eq!(mb_strrpos("abcabc", "abc", None), Some(3));
        assert_eq!(mb_strrpos("日本語日本語", "日本", None), Some(3));
    }

    #[test]
    fn test_mb_strtolower_upper() {
        assert_eq!(mb_strtolower("HÉLLO", None), "héllo");
        assert_eq!(mb_strtoupper("héllo", None), "HÉLLO");
        // German ß → SS
        assert_eq!(mb_strtoupper("straße", None), "STRASSE");
    }

    #[test]
    fn test_mb_detect_encoding() {
        assert_eq!(mb_detect_encoding("hello", None), "ASCII");
        assert_eq!(mb_detect_encoding("héllo", None), "UTF-8");
    }

    #[test]
    fn test_mb_convert_encoding() {
        assert_eq!(mb_convert_encoding("héllo", "ASCII", None), "h?llo");
        assert_eq!(mb_convert_encoding("hello", "UTF-8", None), "hello");
    }

    #[test]
    fn test_mb_str_split() {
        assert_eq!(mb_str_split("日本語", 1), vec!["日", "本", "語"]);
        assert_eq!(
            mb_str_split("日本語テスト", 2),
            vec!["日本", "語テ", "スト"]
        );
    }

    #[test]
    fn test_mb_substr_count() {
        assert_eq!(mb_substr_count("hello world hello", "hello"), 2);
        assert_eq!(mb_substr_count("日本語日本語", "日本"), 2);
    }

    #[test]
    fn test_mb_internal_encoding() {
        let enc = mb_internal_encoding(None);
        assert_eq!(enc, "UTF-8");

        mb_internal_encoding(Some("ISO-8859-1"));
        assert_eq!(mb_internal_encoding(None), "ISO-8859-1");

        // Reset
        mb_internal_encoding(Some("UTF-8"));
    }
}
