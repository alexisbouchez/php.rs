//! PHP iconv extension.
//!
//! Implements character set conversion functions.
//! Reference: php-src/ext/iconv/
//!
//! Supported charsets: UTF-8, ASCII, ISO-8859-1. Other charsets return an error.

use std::cell::RefCell;
use std::fmt;

// ── Error Types ─────────────────────────────────────────────────────────────

/// Errors returned by iconv functions.
#[derive(Debug, Clone, PartialEq)]
pub enum IconvError {
    /// The requested character set is not supported.
    UnsupportedCharset(String),
    /// A character cannot be represented in the target charset.
    IllegalCharacter,
    /// The input sequence is malformed for the declared charset.
    InvalidSequence,
}

impl fmt::Display for IconvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IconvError::UnsupportedCharset(cs) => write!(
                f,
                "Wrong charset, conversion from \"{}\" is not supported",
                cs
            ),
            IconvError::IllegalCharacter => {
                write!(f, "Detected an illegal character in input string")
            }
            IconvError::InvalidSequence => write!(f, "Invalid multibyte sequence in input string"),
        }
    }
}

// ── Thread-local encoding defaults ──────────────────────────────────────────

thread_local! {
    static INPUT_ENCODING: RefCell<String> = RefCell::new("UTF-8".to_string());
    static OUTPUT_ENCODING: RefCell<String> = RefCell::new("UTF-8".to_string());
    static INTERNAL_ENCODING: RefCell<String> = RefCell::new("UTF-8".to_string());
}

// ── MIME Preferences ────────────────────────────────────────────────────────

/// Preferences for iconv_mime_encode.
#[derive(Debug, Clone)]
pub struct MimePreferences {
    /// The scheme: "B" for base64, "Q" for quoted-printable.
    pub scheme: String,
    /// The input charset.
    pub input_charset: String,
    /// The output charset.
    pub output_charset: String,
    /// Line length limit (default 76).
    pub line_length: usize,
    /// Line break characters (default "\r\n").
    pub line_break_chars: String,
}

impl Default for MimePreferences {
    fn default() -> Self {
        MimePreferences {
            scheme: "B".to_string(),
            input_charset: "UTF-8".to_string(),
            output_charset: "UTF-8".to_string(),
            line_length: 76,
            line_break_chars: "\r\n".to_string(),
        }
    }
}

// ── Charset normalization ───────────────────────────────────────────────────

/// Normalize a charset name to a canonical form.
fn normalize_charset(charset: &str) -> String {
    let upper = charset.to_uppercase().replace('-', "");
    match upper.as_str() {
        "UTF8" => "UTF-8".to_string(),
        "ASCII" | "USASCII" | "US" => "ASCII".to_string(),
        "ISO88591" | "LATIN1" => "ISO-8859-1".to_string(),
        _ => charset.to_uppercase(),
    }
}

/// Check whether a normalized charset name is supported.
fn is_supported(normalized: &str) -> bool {
    matches!(normalized, "UTF-8" | "ASCII" | "ISO-8859-1")
}

// ── Core conversion helpers ─────────────────────────────────────────────────

/// Convert bytes from ISO-8859-1 to a Rust String (UTF-8).
fn iso8859_1_to_utf8(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Convert a UTF-8 string to ISO-8859-1 bytes.
fn utf8_to_iso8859_1(s: &str) -> Result<Vec<u8>, IconvError> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let cp = ch as u32;
        if cp > 0xFF {
            return Err(IconvError::IllegalCharacter);
        }
        out.push(cp as u8);
    }
    Ok(out)
}

/// Convert a UTF-8 string to ASCII bytes.
fn utf8_to_ascii(s: &str) -> Result<Vec<u8>, IconvError> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        if !ch.is_ascii() {
            return Err(IconvError::IllegalCharacter);
        }
        out.push(ch as u8);
    }
    Ok(out)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// iconv() -- Convert a string from one charset to another.
///
/// Supports UTF-8, ASCII, and ISO-8859-1. Returns `IconvError::UnsupportedCharset`
/// for anything else.
pub fn iconv(in_charset: &str, out_charset: &str, input: &str) -> Result<String, IconvError> {
    let from = normalize_charset(in_charset);
    let to_raw = normalize_charset(out_charset);

    // Handle //TRANSLIT and //IGNORE suffixes
    let to = to_raw
        .replace("//TRANSLIT", "")
        .replace("//IGNORE", "")
        .trim()
        .to_string();

    if !is_supported(&from) {
        return Err(IconvError::UnsupportedCharset(in_charset.to_string()));
    }
    if !is_supported(&to) {
        return Err(IconvError::UnsupportedCharset(out_charset.to_string()));
    }

    // Step 1: decode input to an internal UTF-8 String
    let utf8_string = match from.as_str() {
        "UTF-8" => input.to_string(),
        "ASCII" => {
            // Validate that all bytes are ASCII
            for b in input.bytes() {
                if b > 0x7F {
                    return Err(IconvError::InvalidSequence);
                }
            }
            input.to_string()
        }
        "ISO-8859-1" => iso8859_1_to_utf8(input.as_bytes()),
        _ => unreachable!(),
    };

    // Step 2: encode from UTF-8 to target
    match to.as_str() {
        "UTF-8" => Ok(utf8_string),
        "ASCII" => {
            let bytes = utf8_to_ascii(&utf8_string)?;
            Ok(String::from_utf8(bytes).unwrap())
        }
        "ISO-8859-1" => {
            let bytes = utf8_to_iso8859_1(&utf8_string)?;
            // ISO-8859-1 bytes 0x00-0xFF map to Unicode code points directly
            Ok(bytes.iter().map(|&b| b as char).collect())
        }
        _ => unreachable!(),
    }
}

/// iconv_strlen() -- Returns the character count of a string in a given charset.
///
/// For UTF-8, returns the number of Unicode code points.
/// For ASCII/ISO-8859-1, returns the byte length.
pub fn iconv_strlen(input: &str, charset: &str) -> Result<usize, IconvError> {
    let cs = normalize_charset(charset);
    if !is_supported(&cs) {
        return Err(IconvError::UnsupportedCharset(charset.to_string()));
    }
    match cs.as_str() {
        "UTF-8" => Ok(input.chars().count()),
        "ASCII" | "ISO-8859-1" => Ok(input.len()),
        _ => unreachable!(),
    }
}

/// iconv_strpos() -- Finds the position of the first occurrence of needle in haystack.
pub fn iconv_strpos(
    haystack: &str,
    needle: &str,
    offset: usize,
    charset: &str,
) -> Result<Option<usize>, IconvError> {
    let cs = normalize_charset(charset);
    if !is_supported(&cs) {
        return Err(IconvError::UnsupportedCharset(charset.to_string()));
    }

    if needle.is_empty() {
        return Ok(None);
    }

    let chars: Vec<char> = haystack.chars().collect();
    let needle_chars: Vec<char> = needle.chars().collect();

    if offset >= chars.len() {
        return Ok(None);
    }

    let needle_len = needle_chars.len();
    for i in offset..chars.len() {
        if i + needle_len > chars.len() {
            break;
        }
        if chars[i..i + needle_len] == needle_chars[..] {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// iconv_strrpos() -- Finds the position of the last occurrence of needle in haystack.
pub fn iconv_strrpos(
    haystack: &str,
    needle: &str,
    charset: &str,
) -> Result<Option<usize>, IconvError> {
    let cs = normalize_charset(charset);
    if !is_supported(&cs) {
        return Err(IconvError::UnsupportedCharset(charset.to_string()));
    }

    if needle.is_empty() {
        return Ok(None);
    }

    let chars: Vec<char> = haystack.chars().collect();
    let needle_chars: Vec<char> = needle.chars().collect();

    let needle_len = needle_chars.len();
    let mut last_pos = None;
    for i in 0..chars.len() {
        if i + needle_len > chars.len() {
            break;
        }
        if chars[i..i + needle_len] == needle_chars[..] {
            last_pos = Some(i);
        }
    }
    Ok(last_pos)
}

/// iconv_substr() -- Returns part of a string.
///
/// `offset` may be negative (count from end). `length` if `None` means to end of string;
/// if negative, it stops that many characters from the end.
pub fn iconv_substr(
    input: &str,
    offset: i64,
    length: Option<i64>,
    charset: &str,
) -> Result<String, IconvError> {
    let cs = normalize_charset(charset);
    if !is_supported(&cs) {
        return Err(IconvError::UnsupportedCharset(charset.to_string()));
    }

    let chars: Vec<char> = input.chars().collect();
    let len = chars.len() as i64;

    let start = if offset < 0 {
        let s = len + offset;
        if s < 0 {
            0
        } else {
            s as usize
        }
    } else {
        offset as usize
    };

    if start >= chars.len() {
        return Ok(String::new());
    }

    let end = match length {
        None => chars.len(),
        Some(l) if l >= 0 => {
            let e = start + l as usize;
            if e > chars.len() {
                chars.len()
            } else {
                e
            }
        }
        Some(l) => {
            // negative length: stop l characters from end
            let e = len + l;
            if e < start as i64 {
                return Ok(String::new());
            }
            e as usize
        }
    };

    Ok(chars[start..end].iter().collect())
}

/// iconv_mime_encode() -- Composes a MIME header field value (RFC 2047).
pub fn iconv_mime_encode(
    field_name: &str,
    field_value: &str,
    preferences: &MimePreferences,
) -> Result<String, IconvError> {
    let charset = normalize_charset(&preferences.output_charset);
    if !is_supported(&charset) {
        return Err(IconvError::UnsupportedCharset(
            preferences.output_charset.clone(),
        ));
    }

    let encoded = match preferences.scheme.to_uppercase().as_str() {
        "B" => {
            // Base64 encode
            let b64 = simple_base64_encode(field_value.as_bytes());
            format!("=?{}?B?{}?=", charset, b64)
        }
        "Q" => {
            // Quoted-printable encode
            let qp = quoted_printable_encode(field_value);
            format!("=?{}?Q?{}?=", charset, qp)
        }
        _ => {
            let b64 = simple_base64_encode(field_value.as_bytes());
            format!("=?{}?B?{}?=", charset, b64)
        }
    };

    Ok(format!("{}: {}", field_name, encoded))
}

/// iconv_mime_decode() -- Decodes a MIME header field (RFC 2047).
pub fn iconv_mime_decode(
    encoded_string: &str,
    _mode: i32,
    charset: &str,
) -> Result<String, IconvError> {
    let cs = normalize_charset(charset);
    if !is_supported(&cs) {
        return Err(IconvError::UnsupportedCharset(charset.to_string()));
    }

    let mut result = String::new();
    let mut remaining = encoded_string;

    while let Some(start) = remaining.find("=?") {
        // Text before the encoded word
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 2..];

        // Find charset
        let Some(q1) = remaining.find('?') else {
            result.push_str("=?");
            continue;
        };
        let _enc_charset = &remaining[..q1];
        remaining = &remaining[q1 + 1..];

        // Find encoding type
        let Some(q2) = remaining.find('?') else {
            continue;
        };
        let encoding = &remaining[..q2];
        remaining = &remaining[q2 + 1..];

        // Find end of encoded text
        let Some(end) = remaining.find("?=") else {
            continue;
        };
        let encoded_text = &remaining[..end];
        remaining = &remaining[end + 2..];

        match encoding.to_uppercase().as_str() {
            "B" => {
                if let Ok(decoded) = simple_base64_decode(encoded_text) {
                    result.push_str(&String::from_utf8_lossy(&decoded));
                }
            }
            "Q" => {
                result.push_str(&quoted_printable_decode(encoded_text));
            }
            _ => {}
        }
    }
    result.push_str(remaining);
    Ok(result)
}

/// iconv_get_encoding() -- Retrieves the current value of an internal encoding setting.
///
/// `type_name` is one of: "input_encoding", "output_encoding", "internal_encoding", "all".
pub fn iconv_get_encoding(type_name: &str) -> String {
    match type_name {
        "input_encoding" => INPUT_ENCODING.with(|e| e.borrow().clone()),
        "output_encoding" => OUTPUT_ENCODING.with(|e| e.borrow().clone()),
        "internal_encoding" => INTERNAL_ENCODING.with(|e| e.borrow().clone()),
        _ => String::new(),
    }
}

/// iconv_set_encoding() -- Sets the current encoding for the specified type.
///
/// Returns true on success, false if the charset is unsupported.
pub fn iconv_set_encoding(type_name: &str, charset: &str) -> bool {
    let normalized = normalize_charset(charset);
    if !is_supported(&normalized) {
        return false;
    }
    match type_name {
        "input_encoding" => {
            INPUT_ENCODING.with(|e| *e.borrow_mut() = normalized);
            true
        }
        "output_encoding" => {
            OUTPUT_ENCODING.with(|e| *e.borrow_mut() = normalized);
            true
        }
        "internal_encoding" => {
            INTERNAL_ENCODING.with(|e| *e.borrow_mut() = normalized);
            true
        }
        _ => false,
    }
}

// ── Base64 helpers (no external deps) ───────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn simple_base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }
    result
}

fn base64_decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn simple_base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    let bytes: Vec<u8> = data
        .bytes()
        .filter(|&b| b != b'\r' && b != b'\n' && b != b' ')
        .collect();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let a = base64_decode_char(bytes[i]).ok_or(())? as u32;
        let b = if i + 1 < bytes.len() && bytes[i + 1] != b'=' {
            base64_decode_char(bytes[i + 1]).ok_or(())? as u32
        } else {
            0
        };
        let c = if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            base64_decode_char(bytes[i + 2]).ok_or(())? as u32
        } else {
            0
        };
        let d = if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            base64_decode_char(bytes[i + 3]).ok_or(())? as u32
        } else {
            0
        };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;

        result.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }

        i += 4;
    }
    Ok(result)
}

// ── Quoted-printable helpers ────────────────────────────────────────────────

fn quoted_printable_encode(input: &str) -> String {
    let mut result = String::new();
    for byte in input.bytes() {
        match byte {
            b' ' => result.push('_'),
            b'_' | b'?' | b'=' | 0..=0x1F | 0x7F..=0xFF => {
                result.push('=');
                result.push_str(&format!("{:02X}", byte));
            }
            _ => result.push(byte as char),
        }
    }
    result
}

fn quoted_printable_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'_' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iconv_utf8_to_ascii() {
        let result = iconv("UTF-8", "ASCII", "Hello").unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_iconv_utf8_to_ascii_fails_on_non_ascii() {
        let result = iconv("UTF-8", "ASCII", "caf\u{00e9}");
        assert_eq!(result, Err(IconvError::IllegalCharacter));
    }

    #[test]
    fn test_iconv_utf8_to_iso8859_1() {
        let result = iconv("UTF-8", "ISO-8859-1", "caf\u{00e9}").unwrap();
        assert_eq!(result, "caf\u{00e9}");
    }

    #[test]
    fn test_iconv_iso8859_1_to_utf8() {
        let result = iconv("ISO-8859-1", "UTF-8", "Hello").unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_iconv_unsupported_charset() {
        let result = iconv("UTF-8", "KOI8-R", "Hello");
        assert!(matches!(result, Err(IconvError::UnsupportedCharset(_))));
    }

    #[test]
    fn test_iconv_strlen_utf8() {
        // "cafe\u{0301}" has 5 chars, but "caf\u{00e9}" has 4
        assert_eq!(iconv_strlen("caf\u{00e9}", "UTF-8").unwrap(), 4);
        assert_eq!(iconv_strlen("Hello", "UTF-8").unwrap(), 5);
        assert_eq!(iconv_strlen("", "UTF-8").unwrap(), 0);
    }

    #[test]
    fn test_iconv_strpos() {
        assert_eq!(
            iconv_strpos("Hello World", "World", 0, "UTF-8").unwrap(),
            Some(6)
        );
        assert_eq!(
            iconv_strpos("Hello World", "World", 7, "UTF-8").unwrap(),
            None
        );
        assert_eq!(
            iconv_strpos("Hello World", "xyz", 0, "UTF-8").unwrap(),
            None
        );
    }

    #[test]
    fn test_iconv_strrpos() {
        assert_eq!(iconv_strrpos("abcabc", "abc", "UTF-8").unwrap(), Some(3));
        assert_eq!(iconv_strrpos("abcabc", "xyz", "UTF-8").unwrap(), None);
    }

    #[test]
    fn test_iconv_substr_basic() {
        assert_eq!(
            iconv_substr("Hello World", 6, None, "UTF-8").unwrap(),
            "World"
        );
        assert_eq!(
            iconv_substr("Hello World", 0, Some(5), "UTF-8").unwrap(),
            "Hello"
        );
    }

    #[test]
    fn test_iconv_substr_negative_offset() {
        assert_eq!(
            iconv_substr("Hello World", -5, None, "UTF-8").unwrap(),
            "World"
        );
    }

    #[test]
    fn test_iconv_substr_negative_length() {
        assert_eq!(
            iconv_substr("Hello World", 0, Some(-6), "UTF-8").unwrap(),
            "Hello"
        );
    }

    #[test]
    fn test_iconv_mime_encode_base64() {
        let prefs = MimePreferences::default();
        let result = iconv_mime_encode("Subject", "Hello", &prefs).unwrap();
        assert!(result.starts_with("Subject: =?UTF-8?B?"));
        assert!(result.ends_with("?="));
    }

    #[test]
    fn test_iconv_mime_encode_qp() {
        let prefs = MimePreferences {
            scheme: "Q".to_string(),
            ..MimePreferences::default()
        };
        let result = iconv_mime_encode("Subject", "Hello World", &prefs).unwrap();
        assert!(result.starts_with("Subject: =?UTF-8?Q?"));
        assert!(result.ends_with("?="));
    }

    #[test]
    fn test_iconv_mime_decode_base64() {
        let encoded = "=?UTF-8?B?SGVsbG8=?=";
        let result = iconv_mime_decode(encoded, 0, "UTF-8").unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_iconv_mime_decode_qp() {
        let encoded = "=?UTF-8?Q?Hello_World?=";
        let result = iconv_mime_decode(encoded, 0, "UTF-8").unwrap();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_iconv_get_set_encoding() {
        assert!(iconv_set_encoding("input_encoding", "ASCII"));
        assert_eq!(iconv_get_encoding("input_encoding"), "ASCII");

        assert!(iconv_set_encoding("output_encoding", "ISO-8859-1"));
        assert_eq!(iconv_get_encoding("output_encoding"), "ISO-8859-1");

        // Reset
        iconv_set_encoding("input_encoding", "UTF-8");
        iconv_set_encoding("output_encoding", "UTF-8");
    }

    #[test]
    fn test_iconv_set_encoding_unsupported() {
        assert!(!iconv_set_encoding("input_encoding", "KOI8-R"));
    }

    #[test]
    fn test_iconv_set_encoding_invalid_type() {
        assert!(!iconv_set_encoding("bogus_type", "UTF-8"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = simple_base64_encode(data);
        let decoded = simple_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_iconv_identity_conversion() {
        let result = iconv("UTF-8", "UTF-8", "test string").unwrap();
        assert_eq!(result, "test string");
    }
}
