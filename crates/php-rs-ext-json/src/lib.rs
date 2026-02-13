//! PHP JSON extension.
//!
//! Implements json_encode(), json_decode(), json_last_error().
//! Reference: php-src/ext/json/

use std::fmt::Write;

// ── JSON value type ──────────────────────────────────────────────────────────

/// A JSON value (mirrors PHP's internal JSON representation).
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

// ── Encode options (bitmask) ─────────────────────────────────────────────────

pub const JSON_PRETTY_PRINT: u32 = 128;
pub const JSON_UNESCAPED_SLASHES: u32 = 64;
pub const JSON_UNESCAPED_UNICODE: u32 = 256;
pub const JSON_FORCE_OBJECT: u32 = 16;
pub const JSON_NUMERIC_CHECK: u32 = 32;
pub const JSON_HEX_TAG: u32 = 1;
pub const JSON_HEX_AMP: u32 = 2;
pub const JSON_HEX_APOS: u32 = 4;
pub const JSON_HEX_QUOT: u32 = 8;
pub const JSON_THROW_ON_ERROR: u32 = 4194304;

// ── JsonSerializable interface ───────────────────────────────────────────────

/// PHP's JsonSerializable interface.
///
/// Objects implementing this trait can customize their JSON representation.
/// When `json_encode()` is called on an object implementing `JsonSerializable`,
/// the `json_serialize()` method is invoked to obtain the value that should be
/// serialized instead of the default object-to-JSON conversion.
///
/// Reference: php-src/ext/json/php_json.h — php_json_serializable_ce
///
/// PHP signature:
/// ```php
/// interface JsonSerializable {
///     public function jsonSerialize(): mixed;
/// }
/// ```
pub trait JsonSerializable {
    /// Specify data which should be serialized to JSON.
    ///
    /// Returns a `JsonValue` that represents the data this object should
    /// serialize to. The returned value is encoded as JSON in place of the
    /// object itself.
    fn json_serialize(&self) -> JsonValue;
}

/// Encode a `JsonSerializable` implementor to a JSON string.
///
/// This is a convenience wrapper that calls `json_serialize()` on the object
/// and then encodes the resulting `JsonValue` with the given options.
pub fn json_encode_serializable<T: JsonSerializable>(obj: &T, options: u32) -> Option<String> {
    let value = obj.json_serialize();
    json_encode(&value, options)
}

// ── JSON error codes ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JsonError {
    None = 0,
    Depth = 1,
    StateMismatch = 2,
    CtrlChar = 3,
    Syntax = 4,
    Utf8 = 5,
    Recursion = 6,
    InfOrNan = 7,
    UnsupportedType = 8,
    InvalidPropertyName = 9,
    Utf16 = 10,
}

impl JsonError {
    pub fn message(self) -> &'static str {
        match self {
            JsonError::None => "No error",
            JsonError::Depth => "Maximum stack depth exceeded",
            JsonError::StateMismatch => "Invalid or malformed JSON",
            JsonError::CtrlChar => "Unexpected control character found",
            JsonError::Syntax => "Syntax error",
            JsonError::Utf8 => "Malformed UTF-8 characters, possibly incorrectly encoded",
            JsonError::Recursion => "Recursion detected",
            JsonError::InfOrNan => "Inf and NaN cannot be JSON encoded",
            JsonError::UnsupportedType => "Type is not supported",
            JsonError::InvalidPropertyName => "The decoded property name is invalid",
            JsonError::Utf16 => "Single unpaired UTF-16 surrogate in unicode escape",
        }
    }
}

// ── Thread-local last error ──────────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: std::cell::Cell<JsonError> = const { std::cell::Cell::new(JsonError::None) };
}

/// json_last_error() — Returns the last error occurred.
pub fn json_last_error() -> JsonError {
    LAST_ERROR.with(|e| e.get())
}

/// json_last_error_msg() — Returns the error string of the last json_encode() or json_decode() call.
pub fn json_last_error_msg() -> &'static str {
    json_last_error().message()
}

fn set_last_error(err: JsonError) {
    LAST_ERROR.with(|e| e.set(err));
}

// ── json_encode ──────────────────────────────────────────────────────────────

/// json_encode() — Returns the JSON representation of a value.
pub fn json_encode(value: &JsonValue, options: u32) -> Option<String> {
    set_last_error(JsonError::None);
    let pretty = options & JSON_PRETTY_PRINT != 0;
    let unescape_slashes = options & JSON_UNESCAPED_SLASHES != 0;
    let force_object = options & JSON_FORCE_OBJECT != 0;

    let mut buf = String::new();
    if encode_value(
        &mut buf,
        value,
        options,
        0,
        pretty,
        unescape_slashes,
        force_object,
    ) {
        Some(buf)
    } else {
        None
    }
}

fn encode_value(
    buf: &mut String,
    value: &JsonValue,
    options: u32,
    depth: usize,
    pretty: bool,
    unescape_slashes: bool,
    force_object: bool,
) -> bool {
    match value {
        JsonValue::Null => buf.push_str("null"),
        JsonValue::Bool(true) => buf.push_str("true"),
        JsonValue::Bool(false) => buf.push_str("false"),
        JsonValue::Int(n) => write!(buf, "{}", n).unwrap(),
        JsonValue::Float(f) => {
            if f.is_infinite() || f.is_nan() {
                set_last_error(JsonError::InfOrNan);
                return false;
            }
            // PHP outputs floats with at least one decimal
            if *f == f.trunc() {
                write!(buf, "{:.1}", f).unwrap();
            } else {
                write!(buf, "{}", f).unwrap();
            }
        }
        JsonValue::Str(s) => {
            encode_string(buf, s, unescape_slashes);
        }
        JsonValue::Array(items) => {
            if force_object {
                return encode_array_as_object(
                    buf,
                    items,
                    options,
                    depth,
                    pretty,
                    unescape_slashes,
                    force_object,
                );
            }
            buf.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                if pretty {
                    buf.push('\n');
                    indent(buf, depth + 1);
                }
                if !encode_value(
                    buf,
                    item,
                    options,
                    depth + 1,
                    pretty,
                    unescape_slashes,
                    false,
                ) {
                    return false;
                }
            }
            if pretty && !items.is_empty() {
                buf.push('\n');
                indent(buf, depth);
            }
            buf.push(']');
        }
        JsonValue::Object(entries) => {
            buf.push('{');
            for (i, (key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                if pretty {
                    buf.push('\n');
                    indent(buf, depth + 1);
                }
                encode_string(buf, key, unescape_slashes);
                buf.push(':');
                if pretty {
                    buf.push(' ');
                }
                if !encode_value(
                    buf,
                    val,
                    options,
                    depth + 1,
                    pretty,
                    unescape_slashes,
                    false,
                ) {
                    return false;
                }
            }
            if pretty && !entries.is_empty() {
                buf.push('\n');
                indent(buf, depth);
            }
            buf.push('}');
        }
    }
    true
}

fn encode_array_as_object(
    buf: &mut String,
    items: &[JsonValue],
    options: u32,
    depth: usize,
    pretty: bool,
    unescape_slashes: bool,
    force_object: bool,
) -> bool {
    buf.push('{');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        if pretty {
            buf.push('\n');
            indent(buf, depth + 1);
        }
        write!(buf, "\"{}\":", i).unwrap();
        if pretty {
            buf.push(' ');
        }
        if !encode_value(
            buf,
            item,
            options,
            depth + 1,
            pretty,
            unescape_slashes,
            force_object,
        ) {
            return false;
        }
    }
    if pretty && !items.is_empty() {
        buf.push('\n');
        indent(buf, depth);
    }
    buf.push('}');
    true
}

fn encode_string(buf: &mut String, s: &str, unescape_slashes: bool) {
    buf.push('"');
    for ch in s.chars() {
        match ch {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '/' if !unescape_slashes => buf.push_str("\\/"),
            '/' => buf.push('/'),
            '\x08' => buf.push_str("\\b"),
            '\x0C' => buf.push_str("\\f"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if c < '\x20' => write!(buf, "\\u{:04x}", c as u32).unwrap(),
            c => buf.push(c),
        }
    }
    buf.push('"');
}

fn indent(buf: &mut String, depth: usize) {
    for _ in 0..depth {
        buf.push_str("    ");
    }
}

// ── json_decode ──────────────────────────────────────────────────────────────

/// json_decode() — Decodes a JSON string.
///
/// If `assoc` is true, objects are returned as ordered maps (Object variant).
/// Default depth limit is 512.
pub fn json_decode(json: &str, assoc: bool, depth: usize) -> Option<JsonValue> {
    set_last_error(JsonError::None);
    let json = json.trim();
    if json.is_empty() {
        set_last_error(JsonError::Syntax);
        return None;
    }
    let depth = if depth == 0 { 512 } else { depth };
    let mut parser = JsonParser::new(json, depth);
    let result = parser.parse_value(0);
    if result.is_none() && json_last_error() == JsonError::None {
        set_last_error(JsonError::Syntax);
    }
    // Ignore assoc for now — always returns Object variant for objects
    let _ = assoc;
    result
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str, max_depth: usize) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
            max_depth,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, ch: u8) -> bool {
        self.skip_whitespace();
        if self.peek() == Some(ch) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth > self.max_depth {
            set_last_error(JsonError::Depth);
            return None;
        }
        self.skip_whitespace();
        match self.peek()? {
            b'"' => self.parse_string().map(JsonValue::Str),
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => {
                set_last_error(JsonError::Syntax);
                None
            }
        }
    }

    fn parse_string(&mut self) -> Option<String> {
        if self.advance()? != b'"' {
            set_last_error(JsonError::Syntax);
            return None;
        }
        let mut s = String::new();
        loop {
            let b = self.advance()?;
            match b {
                b'"' => return Some(s),
                b'\\' => {
                    let esc = self.advance()?;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\x08'),
                        b'f' => s.push('\x0C'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if let Some(c) = char::from_u32(cp as u32) {
                                s.push(c);
                            } else {
                                set_last_error(JsonError::Utf16);
                                return None;
                            }
                        }
                        _ => {
                            set_last_error(JsonError::Syntax);
                            return None;
                        }
                    }
                }
                _ => s.push(b as char),
            }
        }
    }

    fn parse_hex4(&mut self) -> Option<u16> {
        let mut val = 0u16;
        for _ in 0..4 {
            let b = self.advance()?;
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => {
                    set_last_error(JsonError::Syntax);
                    return None;
                }
            };
            val = (val << 4) | digit as u16;
        }
        Some(val)
    }

    fn parse_number(&mut self) -> Option<JsonValue> {
        let start = self.pos;
        let mut is_float = false;

        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        // Integer part
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
            self.pos += 1;
        }

        // Fractional part
        if self.pos < self.input.len() && self.input[self.pos] == b'.' {
            is_float = true;
            self.pos += 1;
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        // Exponent
        if self.pos < self.input.len()
            && (self.input[self.pos] == b'e' || self.input[self.pos] == b'E')
        {
            is_float = true;
            self.pos += 1;
            if self.pos < self.input.len()
                && (self.input[self.pos] == b'+' || self.input[self.pos] == b'-')
            {
                self.pos += 1;
            }
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        let s = std::str::from_utf8(&self.input[start..self.pos]).ok()?;

        if is_float {
            s.parse::<f64>().ok().map(JsonValue::Float)
        } else {
            // Try integer first, fall back to float for large numbers
            s.parse::<i64>()
                .ok()
                .map(JsonValue::Int)
                .or_else(|| s.parse::<f64>().ok().map(JsonValue::Float))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // skip [
        self.skip_whitespace();
        let mut items = Vec::new();

        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(JsonValue::Array(items));
        }

        loop {
            let val = self.parse_value(depth + 1)?;
            items.push(val);
            self.skip_whitespace();
            if self.peek() == Some(b',') {
                self.pos += 1;
            } else {
                break;
            }
        }

        if !self.expect(b']') {
            set_last_error(JsonError::Syntax);
            return None;
        }
        Some(JsonValue::Array(items))
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // skip {
        self.skip_whitespace();
        let mut entries = Vec::new();

        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(JsonValue::Object(entries));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if !self.expect(b':') {
                set_last_error(JsonError::Syntax);
                return None;
            }
            let val = self.parse_value(depth + 1)?;
            entries.push((key, val));
            self.skip_whitespace();
            if self.peek() == Some(b',') {
                self.pos += 1;
            } else {
                break;
            }
        }

        if !self.expect(b'}') {
            set_last_error(JsonError::Syntax);
            return None;
        }
        Some(JsonValue::Object(entries))
    }

    fn parse_literal(&mut self, expected: &[u8], value: JsonValue) -> Option<JsonValue> {
        if self.pos + expected.len() > self.input.len() {
            set_last_error(JsonError::Syntax);
            return None;
        }
        if &self.input[self.pos..self.pos + expected.len()] == expected {
            self.pos += expected.len();
            Some(value)
        } else {
            set_last_error(JsonError::Syntax);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── json_encode tests ──

    #[test]
    fn test_encode_null() {
        assert_eq!(json_encode(&JsonValue::Null, 0), Some("null".to_string()));
    }

    #[test]
    fn test_encode_bool() {
        assert_eq!(
            json_encode(&JsonValue::Bool(true), 0),
            Some("true".to_string())
        );
        assert_eq!(
            json_encode(&JsonValue::Bool(false), 0),
            Some("false".to_string())
        );
    }

    #[test]
    fn test_encode_int() {
        assert_eq!(json_encode(&JsonValue::Int(42), 0), Some("42".to_string()));
        assert_eq!(json_encode(&JsonValue::Int(-1), 0), Some("-1".to_string()));
    }

    #[test]
    fn test_encode_float() {
        assert_eq!(
            json_encode(&JsonValue::Float(1.5), 0),
            Some("1.5".to_string())
        );
        assert_eq!(
            json_encode(&JsonValue::Float(2.0), 0),
            Some("2.0".to_string())
        );
    }

    #[test]
    fn test_encode_float_inf_nan() {
        assert_eq!(json_encode(&JsonValue::Float(f64::INFINITY), 0), None);
        assert_eq!(json_last_error(), JsonError::InfOrNan);
        assert_eq!(json_encode(&JsonValue::Float(f64::NAN), 0), None);
    }

    #[test]
    fn test_encode_string() {
        assert_eq!(
            json_encode(&JsonValue::Str("hello".to_string()), 0),
            Some("\"hello\"".to_string())
        );
    }

    #[test]
    fn test_encode_string_escapes() {
        assert_eq!(
            json_encode(&JsonValue::Str("a\"b\\c\n".to_string()), 0),
            Some("\"a\\\"b\\\\c\\n\"".to_string())
        );
    }

    #[test]
    fn test_encode_array() {
        let arr = JsonValue::Array(vec![
            JsonValue::Int(1),
            JsonValue::Int(2),
            JsonValue::Int(3),
        ]);
        assert_eq!(json_encode(&arr, 0), Some("[1,2,3]".to_string()));
    }

    #[test]
    fn test_encode_object() {
        let obj = JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str("PHP".to_string())),
            ("version".to_string(), JsonValue::Int(8)),
        ]);
        assert_eq!(
            json_encode(&obj, 0),
            Some("{\"name\":\"PHP\",\"version\":8}".to_string())
        );
    }

    #[test]
    fn test_encode_pretty_print() {
        let arr = JsonValue::Array(vec![JsonValue::Int(1), JsonValue::Int(2)]);
        let result = json_encode(&arr, JSON_PRETTY_PRINT).unwrap();
        assert!(result.contains('\n'));
        assert!(result.contains("    "));
    }

    #[test]
    fn test_encode_force_object() {
        let arr = JsonValue::Array(vec![JsonValue::Str("a".to_string())]);
        let result = json_encode(&arr, JSON_FORCE_OBJECT).unwrap();
        assert_eq!(result, "{\"0\":\"a\"}");
    }

    #[test]
    fn test_encode_unescaped_slashes() {
        let val = JsonValue::Str("a/b".to_string());
        assert_eq!(json_encode(&val, 0), Some("\"a\\/b\"".to_string()));
        assert_eq!(
            json_encode(&val, JSON_UNESCAPED_SLASHES),
            Some("\"a/b\"".to_string())
        );
    }

    #[test]
    fn test_encode_nested() {
        let val = JsonValue::Object(vec![(
            "data".to_string(),
            JsonValue::Array(vec![
                JsonValue::Int(1),
                JsonValue::Object(vec![("x".to_string(), JsonValue::Bool(true))]),
            ]),
        )]);
        assert_eq!(
            json_encode(&val, 0),
            Some("{\"data\":[1,{\"x\":true}]}".to_string())
        );
    }

    // ── json_decode tests ──

    #[test]
    fn test_decode_null() {
        assert_eq!(json_decode("null", false, 0), Some(JsonValue::Null));
    }

    #[test]
    fn test_decode_bool() {
        assert_eq!(json_decode("true", false, 0), Some(JsonValue::Bool(true)));
        assert_eq!(json_decode("false", false, 0), Some(JsonValue::Bool(false)));
    }

    #[test]
    fn test_decode_int() {
        assert_eq!(json_decode("42", false, 0), Some(JsonValue::Int(42)));
        assert_eq!(json_decode("-1", false, 0), Some(JsonValue::Int(-1)));
    }

    #[test]
    fn test_decode_float() {
        assert_eq!(json_decode("1.5", false, 0), Some(JsonValue::Float(1.5)));
        assert_eq!(json_decode("1e10", false, 0), Some(JsonValue::Float(1e10)));
    }

    #[test]
    fn test_decode_string() {
        assert_eq!(
            json_decode("\"hello\"", false, 0),
            Some(JsonValue::Str("hello".to_string()))
        );
    }

    #[test]
    fn test_decode_string_escapes() {
        assert_eq!(
            json_decode("\"a\\\"b\\\\c\\n\"", false, 0),
            Some(JsonValue::Str("a\"b\\c\n".to_string()))
        );
    }

    #[test]
    fn test_decode_array() {
        assert_eq!(
            json_decode("[1,2,3]", false, 0),
            Some(JsonValue::Array(vec![
                JsonValue::Int(1),
                JsonValue::Int(2),
                JsonValue::Int(3)
            ]))
        );
    }

    #[test]
    fn test_decode_empty_array() {
        assert_eq!(json_decode("[]", false, 0), Some(JsonValue::Array(vec![])));
    }

    #[test]
    fn test_decode_object() {
        let result = json_decode("{\"a\":1,\"b\":\"hello\"}", false, 0);
        assert_eq!(
            result,
            Some(JsonValue::Object(vec![
                ("a".to_string(), JsonValue::Int(1)),
                ("b".to_string(), JsonValue::Str("hello".to_string())),
            ]))
        );
    }

    #[test]
    fn test_decode_empty_object() {
        assert_eq!(json_decode("{}", false, 0), Some(JsonValue::Object(vec![])));
    }

    #[test]
    fn test_decode_nested() {
        let result = json_decode("{\"data\":[1,{\"x\":true}]}", false, 0).unwrap();
        match result {
            JsonValue::Object(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "data");
            }
            _ => panic!("Expected object"),
        }
    }

    #[test]
    fn test_decode_invalid() {
        assert_eq!(json_decode("{invalid}", false, 0), None);
        assert_eq!(json_last_error(), JsonError::Syntax);
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(json_decode("", false, 0), None);
        assert_eq!(json_last_error(), JsonError::Syntax);
    }

    #[test]
    fn test_decode_depth_limit() {
        assert_eq!(json_decode("[[[[[]]]]]", false, 3), None);
        assert_eq!(json_last_error(), JsonError::Depth);
    }

    // ── Round-trip tests ──

    #[test]
    fn test_roundtrip() {
        let val = JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str("test".to_string())),
            ("count".to_string(), JsonValue::Int(42)),
            ("active".to_string(), JsonValue::Bool(true)),
            (
                "tags".to_string(),
                JsonValue::Array(vec![
                    JsonValue::Str("a".to_string()),
                    JsonValue::Str("b".to_string()),
                ]),
            ),
        ]);
        let encoded = json_encode(&val, 0).unwrap();
        let decoded = json_decode(&encoded, false, 0).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_last_error_reset() {
        json_decode("{bad}", false, 0);
        assert_eq!(json_last_error(), JsonError::Syntax);

        json_decode("42", false, 0);
        assert_eq!(json_last_error(), JsonError::None);
    }

    // ── JsonSerializable tests ──

    /// A simple struct implementing JsonSerializable that returns an object.
    struct UserData {
        name: String,
        age: i64,
    }

    impl JsonSerializable for UserData {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Object(vec![
                ("name".to_string(), JsonValue::Str(self.name.clone())),
                ("age".to_string(), JsonValue::Int(self.age)),
            ])
        }
    }

    #[test]
    fn test_json_serializable_object_return() {
        let user = UserData {
            name: "Alice".to_string(),
            age: 30,
        };
        let result = json_encode_serializable(&user, 0);
        assert_eq!(result, Some("{\"name\":\"Alice\",\"age\":30}".to_string()));
    }

    /// A struct implementing JsonSerializable that returns a scalar value.
    struct ScalarWrapper {
        value: String,
    }

    impl JsonSerializable for ScalarWrapper {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Str(self.value.clone())
        }
    }

    #[test]
    fn test_json_serializable_scalar_return() {
        let wrapper = ScalarWrapper {
            value: "just a string".to_string(),
        };
        let result = json_encode_serializable(&wrapper, 0);
        assert_eq!(result, Some("\"just a string\"".to_string()));
    }

    /// A struct implementing JsonSerializable that returns null.
    struct NullSerializer;

    impl JsonSerializable for NullSerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Null
        }
    }

    #[test]
    fn test_json_serializable_null_return() {
        let ns = NullSerializer;
        let result = json_encode_serializable(&ns, 0);
        assert_eq!(result, Some("null".to_string()));
    }

    /// A struct implementing JsonSerializable that returns an array.
    struct ArraySerializer {
        items: Vec<i64>,
    }

    impl JsonSerializable for ArraySerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Array(self.items.iter().map(|n| JsonValue::Int(*n)).collect())
        }
    }

    #[test]
    fn test_json_serializable_array_return() {
        let a = ArraySerializer {
            items: vec![1, 2, 3],
        };
        let result = json_encode_serializable(&a, 0);
        assert_eq!(result, Some("[1,2,3]".to_string()));
    }

    #[test]
    fn test_json_serializable_with_options() {
        let user = UserData {
            name: "Bob".to_string(),
            age: 25,
        };
        let result = json_encode_serializable(&user, JSON_PRETTY_PRINT).unwrap();
        assert!(result.contains('\n'));
        assert!(result.contains("    "));
        assert!(result.contains("\"name\""));
        assert!(result.contains("\"Bob\""));
        assert!(result.contains("25"));
    }

    /// A struct implementing JsonSerializable that returns a nested structure.
    struct NestedSerializer;

    impl JsonSerializable for NestedSerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Object(vec![
                ("type".to_string(), JsonValue::Str("nested".to_string())),
                (
                    "data".to_string(),
                    JsonValue::Array(vec![
                        JsonValue::Int(1),
                        JsonValue::Object(vec![("inner".to_string(), JsonValue::Bool(true))]),
                    ]),
                ),
            ])
        }
    }

    #[test]
    fn test_json_serializable_nested_structure() {
        let ns = NestedSerializer;
        let result = json_encode_serializable(&ns, 0);
        assert_eq!(
            result,
            Some("{\"type\":\"nested\",\"data\":[1,{\"inner\":true}]}".to_string())
        );
    }

    /// A struct implementing JsonSerializable that returns a boolean.
    struct BoolSerializer(bool);

    impl JsonSerializable for BoolSerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Bool(self.0)
        }
    }

    #[test]
    fn test_json_serializable_bool_return() {
        assert_eq!(
            json_encode_serializable(&BoolSerializer(true), 0),
            Some("true".to_string())
        );
        assert_eq!(
            json_encode_serializable(&BoolSerializer(false), 0),
            Some("false".to_string())
        );
    }

    /// A struct implementing JsonSerializable that returns an integer.
    struct IntSerializer(i64);

    impl JsonSerializable for IntSerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Int(self.0)
        }
    }

    #[test]
    fn test_json_serializable_int_return() {
        assert_eq!(
            json_encode_serializable(&IntSerializer(42), 0),
            Some("42".to_string())
        );
        assert_eq!(
            json_encode_serializable(&IntSerializer(-100), 0),
            Some("-100".to_string())
        );
    }

    /// A struct implementing JsonSerializable that returns a float.
    struct FloatSerializer(f64);

    impl JsonSerializable for FloatSerializer {
        fn json_serialize(&self) -> JsonValue {
            JsonValue::Float(self.0)
        }
    }

    #[test]
    fn test_json_serializable_float_return() {
        assert_eq!(
            json_encode_serializable(&FloatSerializer(2.75), 0),
            Some("2.75".to_string())
        );
    }

    #[test]
    fn test_json_serializable_float_inf_returns_none() {
        // JsonSerializable returning INF should cause json_encode to fail
        let result = json_encode_serializable(&FloatSerializer(f64::INFINITY), 0);
        assert_eq!(result, None);
        assert_eq!(json_last_error(), JsonError::InfOrNan);
    }

    #[test]
    fn test_json_serializable_with_unescaped_slashes() {
        struct UrlSerializer;
        impl JsonSerializable for UrlSerializer {
            fn json_serialize(&self) -> JsonValue {
                JsonValue::Str("https://example.com/path".to_string())
            }
        }
        // Default: slashes are escaped
        assert_eq!(
            json_encode_serializable(&UrlSerializer, 0),
            Some("\"https:\\/\\/example.com\\/path\"".to_string())
        );
        // With JSON_UNESCAPED_SLASHES: slashes are not escaped
        assert_eq!(
            json_encode_serializable(&UrlSerializer, JSON_UNESCAPED_SLASHES),
            Some("\"https://example.com/path\"".to_string())
        );
    }

    #[test]
    fn test_json_serializable_with_force_object() {
        // JsonSerializable returning an array with JSON_FORCE_OBJECT should produce an object
        let a = ArraySerializer {
            items: vec![10, 20],
        };
        let result = json_encode_serializable(&a, JSON_FORCE_OBJECT);
        assert_eq!(result, Some("{\"0\":10,\"1\":20}".to_string()));
    }

    #[test]
    fn test_json_serializable_empty_object() {
        struct EmptyObjectSerializer;
        impl JsonSerializable for EmptyObjectSerializer {
            fn json_serialize(&self) -> JsonValue {
                JsonValue::Object(vec![])
            }
        }
        assert_eq!(
            json_encode_serializable(&EmptyObjectSerializer, 0),
            Some("{}".to_string())
        );
    }

    #[test]
    fn test_json_serializable_empty_array() {
        struct EmptyArraySerializer;
        impl JsonSerializable for EmptyArraySerializer {
            fn json_serialize(&self) -> JsonValue {
                JsonValue::Array(vec![])
            }
        }
        assert_eq!(
            json_encode_serializable(&EmptyArraySerializer, 0),
            Some("[]".to_string())
        );
    }
}
