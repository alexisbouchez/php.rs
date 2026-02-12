//! PHP string functions.
//!
//! Reference: php-src/ext/standard/string.c

use std::collections::HashMap;

// ── 8.1.1: Core string search & info ────────────────────────────────────────

/// strlen() — Get string length.
pub fn php_strlen(s: &str) -> i64 {
    s.len() as i64
}

/// substr() — Return part of a string.
pub fn php_substr(s: &str, start: i64, length: Option<i64>) -> String {
    let len = s.len() as i64;

    // Normalize negative start
    let start = if start < 0 {
        (len + start).max(0) as usize
    } else {
        (start as usize).min(s.len())
    };

    let end = match length {
        Some(l) if l < 0 => ((len + l) as usize).max(start),
        Some(l) => (start + l as usize).min(s.len()),
        None => s.len(),
    };

    if start >= s.len() || start >= end {
        return String::new();
    }

    s[start..end].to_string()
}

/// strpos() — Find the position of the first occurrence of a substring.
pub fn php_strpos(haystack: &str, needle: &str, offset: usize) -> Option<usize> {
    if needle.is_empty() || offset > haystack.len() {
        return None;
    }
    haystack[offset..].find(needle).map(|pos| pos + offset)
}

/// strrpos() — Find the position of the last occurrence of a substring.
pub fn php_strrpos(haystack: &str, needle: &str, offset: i64) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let start = if offset < 0 {
        let abs = (-offset) as usize;
        if abs > haystack.len() {
            return None;
        }
        0
    } else {
        offset as usize
    };

    let end = if offset < 0 {
        haystack.len() - ((-offset) as usize)
    } else {
        haystack.len()
    };

    if start > end || start > haystack.len() {
        return None;
    }

    haystack[start..end].rfind(needle).map(|pos| pos + start)
}

/// strstr() — Find the first occurrence of a string.
pub fn php_strstr(haystack: &str, needle: &str, before_needle: bool) -> Option<String> {
    haystack.find(needle).map(|pos| {
        if before_needle {
            haystack[..pos].to_string()
        } else {
            haystack[pos..].to_string()
        }
    })
}

/// str_contains() — Determine if a string contains a given substring (PHP 8.0+).
pub fn php_str_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.contains(needle)
}

/// str_starts_with() — Check if a string starts with a given substring (PHP 8.0+).
pub fn php_str_starts_with(haystack: &str, needle: &str) -> bool {
    haystack.starts_with(needle)
}

/// str_ends_with() — Check if a string ends with a given substring (PHP 8.0+).
pub fn php_str_ends_with(haystack: &str, needle: &str) -> bool {
    haystack.ends_with(needle)
}

// ── 8.1.2: String replacement & repetition ──────────────────────────────────

/// str_replace() — Replace all occurrences of the search string with the replacement.
pub fn php_str_replace(search: &str, replace: &str, subject: &str) -> (String, usize) {
    let mut count = 0usize;
    let mut result = String::with_capacity(subject.len());
    let mut remaining = subject;

    if search.is_empty() {
        return (subject.to_string(), 0);
    }

    while let Some(pos) = remaining.find(search) {
        result.push_str(&remaining[..pos]);
        result.push_str(replace);
        remaining = &remaining[pos + search.len()..];
        count += 1;
    }
    result.push_str(remaining);

    (result, count)
}

/// str_repeat() — Repeat a string.
pub fn php_str_repeat(s: &str, times: usize) -> String {
    s.repeat(times)
}

/// str_pad() — Pad a string to a certain length.
pub fn php_str_pad(input: &str, length: usize, pad_string: &str, pad_type: PadType) -> String {
    if input.len() >= length || pad_string.is_empty() {
        return input.to_string();
    }

    let pad_needed = length - input.len();

    let make_pad = |n: usize| -> String {
        let full_repeats = n / pad_string.len();
        let remainder = n % pad_string.len();
        let mut p = pad_string.repeat(full_repeats);
        p.push_str(&pad_string[..remainder]);
        p
    };

    match pad_type {
        PadType::Right => {
            let mut result = input.to_string();
            result.push_str(&make_pad(pad_needed));
            result
        }
        PadType::Left => {
            let mut result = make_pad(pad_needed);
            result.push_str(input);
            result
        }
        PadType::Both => {
            let left = pad_needed / 2;
            let right = pad_needed - left;
            let mut result = make_pad(left);
            result.push_str(input);
            result.push_str(&make_pad(right));
            result
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadType {
    Right, // STR_PAD_RIGHT (default)
    Left,  // STR_PAD_LEFT
    Both,  // STR_PAD_BOTH
}

// ── 8.1.3: Case conversion ──────────────────────────────────────────────────

/// strtolower() — Make a string lowercase.
pub fn php_strtolower(s: &str) -> String {
    s.to_lowercase()
}

/// strtoupper() — Make a string uppercase.
pub fn php_strtoupper(s: &str) -> String {
    s.to_uppercase()
}

/// ucfirst() — Make a string's first character uppercase.
pub fn php_ucfirst(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap().to_uppercase().to_string();
    first + chars.as_str()
}

/// lcfirst() — Make a string's first character lowercase.
pub fn php_lcfirst(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap().to_lowercase().to_string();
    first + chars.as_str()
}

/// ucwords() — Uppercase the first character of each word.
pub fn php_ucwords(s: &str, delimiters: &str) -> String {
    let delims: Vec<char> = if delimiters.is_empty() {
        vec![' ', '\t', '\r', '\n', '\x0B']
    } else {
        delimiters.chars().collect()
    };

    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = true;

    for ch in s.chars() {
        if delims.contains(&ch) {
            result.push(ch);
            capitalize_next = true;
        } else if capitalize_next {
            for uc in ch.to_uppercase() {
                result.push(uc);
            }
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }

    result
}

// ── 8.1.4: Trimming ─────────────────────────────────────────────────────────

/// trim() — Strip whitespace from both ends.
pub fn php_trim(s: &str, chars: Option<&str>) -> String {
    match chars {
        Some(c) => {
            let char_set: Vec<char> = c.chars().collect();
            s.trim_matches(|ch: char| char_set.contains(&ch))
                .to_string()
        }
        None => s.trim().to_string(),
    }
}

/// ltrim() — Strip whitespace from the beginning.
pub fn php_ltrim(s: &str, chars: Option<&str>) -> String {
    match chars {
        Some(c) => {
            let char_set: Vec<char> = c.chars().collect();
            s.trim_start_matches(|ch: char| char_set.contains(&ch))
                .to_string()
        }
        None => s.trim_start().to_string(),
    }
}

/// rtrim() — Strip whitespace from the end.
pub fn php_rtrim(s: &str, chars: Option<&str>) -> String {
    match chars {
        Some(c) => {
            let char_set: Vec<char> = c.chars().collect();
            s.trim_end_matches(|ch: char| char_set.contains(&ch))
                .to_string()
        }
        None => s.trim_end().to_string(),
    }
}

// ── 8.1.5: Split & join ─────────────────────────────────────────────────────

/// explode() — Split a string by a delimiter.
pub fn php_explode(delimiter: &str, string: &str, limit: Option<i64>) -> Vec<String> {
    if delimiter.is_empty() {
        return vec![]; // PHP returns false; we return empty vec
    }

    match limit {
        None | Some(0) => string.split(delimiter).map(String::from).collect(),
        Some(l) if l > 0 => string
            .splitn(l as usize, delimiter)
            .map(String::from)
            .collect(),
        Some(l) => {
            // Negative limit: remove last -l elements
            let parts: Vec<String> = string.split(delimiter).map(String::from).collect();
            let remove = (-l) as usize;
            if remove >= parts.len() {
                vec![]
            } else {
                parts[..parts.len() - remove].to_vec()
            }
        }
    }
}

/// implode() / join() — Join array elements with a string.
pub fn php_implode(glue: &str, pieces: &[String]) -> String {
    pieces.join(glue)
}

// ── 8.1.6: Formatted output ─────────────────────────────────────────────────

/// sprintf() — Return a formatted string.
///
/// Supports: %s, %d, %f, %b, %o, %x, %X, %e, %%, %c, and width/precision.
pub fn php_sprintf(format: &str, args: &[&str]) -> String {
    let mut result = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_idx = 0;

    while let Some(ch) = chars.next() {
        if ch != '%' {
            result.push(ch);
            continue;
        }

        // Check for %%
        if chars.peek() == Some(&'%') {
            chars.next();
            result.push('%');
            continue;
        }

        // Parse optional flags, width, precision
        let mut pad_char = ' ';
        let mut left_align = false;
        let mut show_sign = false;
        let mut width: Option<usize> = None;
        let mut precision: Option<usize> = None;

        // Flags
        loop {
            match chars.peek() {
                Some('-') => {
                    left_align = true;
                    chars.next();
                }
                Some('+') => {
                    show_sign = true;
                    chars.next();
                }
                Some('0') => {
                    pad_char = '0';
                    chars.next();
                }
                Some('\'') => {
                    chars.next();
                    if let Some(&c) = chars.peek() {
                        pad_char = c;
                        chars.next();
                    }
                }
                _ => break,
            }
        }

        // Width
        let mut w = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                w.push(c);
                chars.next();
            } else {
                break;
            }
        }
        if !w.is_empty() {
            width = w.parse().ok();
        }

        // Precision
        if chars.peek() == Some(&'.') {
            chars.next();
            let mut p = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    p.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            precision = if p.is_empty() {
                Some(0)
            } else {
                p.parse().ok()
            };
        }

        // Type specifier
        let spec = match chars.next() {
            Some(c) => c,
            None => break,
        };

        let arg = if arg_idx < args.len() {
            args[arg_idx]
        } else {
            ""
        };
        arg_idx += 1;

        let formatted = match spec {
            's' => {
                let mut s = arg.to_string();
                if let Some(p) = precision {
                    s.truncate(p);
                }
                s
            }
            'd' => {
                let n: i64 = arg.parse().unwrap_or(0);
                let s = if show_sign && n >= 0 {
                    format!("+{}", n)
                } else {
                    n.to_string()
                };
                s
            }
            'f' | 'F' => {
                let n: f64 = arg.parse().unwrap_or(0.0);
                let p = precision.unwrap_or(6);
                let s = if show_sign && n >= 0.0 {
                    format!("+{:.prec$}", n, prec = p)
                } else {
                    format!("{:.prec$}", n, prec = p)
                };
                s
            }
            'e' | 'E' => {
                let n: f64 = arg.parse().unwrap_or(0.0);
                let p = precision.unwrap_or(6);
                if spec == 'e' {
                    format!("{:.prec$e}", n, prec = p)
                } else {
                    format!("{:.prec$E}", n, prec = p)
                }
            }
            'b' => {
                let n: i64 = arg.parse().unwrap_or(0);
                format!("{:b}", n)
            }
            'o' => {
                let n: i64 = arg.parse().unwrap_or(0);
                format!("{:o}", n)
            }
            'x' => {
                let n: i64 = arg.parse().unwrap_or(0);
                format!("{:x}", n)
            }
            'X' => {
                let n: i64 = arg.parse().unwrap_or(0);
                format!("{:X}", n)
            }
            'c' => {
                let n: u32 = arg.parse().unwrap_or(0);
                char::from_u32(n).map(|c| c.to_string()).unwrap_or_default()
            }
            _ => format!("%{}", spec),
        };

        // Apply width padding
        if let Some(w) = width {
            if formatted.len() < w {
                let padding = w - formatted.len();
                if left_align {
                    result.push_str(&formatted);
                    for _ in 0..padding {
                        result.push(' ');
                    }
                } else {
                    for _ in 0..padding {
                        result.push(pad_char);
                    }
                    result.push_str(&formatted);
                }
            } else {
                result.push_str(&formatted);
            }
        } else {
            result.push_str(&formatted);
        }
    }

    result
}

// ── 8.1.7: Number formatting ────────────────────────────────────────────────

/// number_format() — Format a number with grouped thousands.
pub fn php_number_format(
    number: f64,
    decimals: usize,
    dec_point: &str,
    thousands_sep: &str,
) -> String {
    // Round to requested decimal places
    let multiplier = 10f64.powi(decimals as i32);
    let rounded = (number * multiplier).round() / multiplier;

    let is_negative = rounded < 0.0;
    let abs = rounded.abs();

    // Split into integer and fractional parts
    let int_part = abs.trunc() as u64;
    let frac_part = ((abs - abs.trunc()) * multiplier).round() as u64;

    // Format integer part with thousands separator
    let int_str = int_part.to_string();
    let mut grouped = String::new();
    for (i, ch) in int_str.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            // Insert separator in reverse
            grouped = format!("{}{}{}", ch, thousands_sep, grouped);
        } else if grouped.is_empty() {
            grouped.push(ch);
        } else {
            grouped = format!("{}{}", ch, grouped);
        }
    }

    let mut result = if is_negative {
        format!("-{}", grouped)
    } else {
        grouped
    };

    if decimals > 0 {
        result.push_str(dec_point);
        let frac_str = format!("{:0>width$}", frac_part, width = decimals);
        result.push_str(&frac_str);
    }

    result
}

// ── 8.1.8: Formatting helpers ───────────────────────────────────────────────

/// nl2br() — Insert HTML line breaks before all newlines.
pub fn php_nl2br(s: &str, is_xhtml: bool) -> String {
    let br = if is_xhtml { "<br />" } else { "<br>" };
    let mut result = String::with_capacity(s.len() * 2);

    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            result.push_str(br);
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                result.push_str("\r\n");
                i += 2;
            } else {
                result.push('\r');
                i += 1;
            }
        } else if bytes[i] == b'\n' {
            result.push_str(br);
            result.push('\n');
            i += 1;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// wordwrap() — Wraps a string to a given number of characters.
pub fn php_wordwrap(s: &str, width: usize, brk: &str, cut_long_words: bool) -> String {
    if s.is_empty() || width == 0 {
        return s.to_string();
    }

    let mut result = String::new();
    let mut current_line_len = 0;

    for word in s.split(' ') {
        if !result.is_empty() {
            if current_line_len + 1 + word.len() > width {
                result.push_str(brk);
                current_line_len = 0;
            } else {
                result.push(' ');
                current_line_len += 1;
            }
        }

        if cut_long_words && word.len() > width {
            for (i, ch) in word.chars().enumerate() {
                if current_line_len >= width {
                    result.push_str(brk);
                    current_line_len = 0;
                }
                result.push(ch);
                current_line_len += 1;
                // Check if this is the last char
                if i == word.len() - 1 {
                    break;
                }
            }
        } else {
            result.push_str(word);
            current_line_len += word.len();
        }
    }

    result
}

/// chunk_split() — Split a string into smaller chunks.
pub fn php_chunk_split(body: &str, chunklen: usize, end: &str) -> String {
    if chunklen == 0 || body.is_empty() {
        return body.to_string();
    }

    let mut result = String::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let chunk_end = (i + chunklen).min(bytes.len());
        result.push_str(&body[i..chunk_end]);
        result.push_str(end);
        i = chunk_end;
    }
    result
}

// ── 8.1.9: HTML encoding ────────────────────────────────────────────────────

/// htmlspecialchars() — Convert special characters to HTML entities.
pub fn php_htmlspecialchars(s: &str, flags: HtmlFlags) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '"' if flags.double_encode => result.push_str("&quot;"),
            '\'' if flags.single_encode => result.push_str("&#039;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(ch),
        }
    }
    result
}

/// htmlspecialchars_decode() — Convert HTML entities back to characters.
pub fn php_htmlspecialchars_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[derive(Debug, Clone, Copy)]
pub struct HtmlFlags {
    pub double_encode: bool,
    pub single_encode: bool,
}

impl Default for HtmlFlags {
    fn default() -> Self {
        Self {
            double_encode: true,
            single_encode: false,
        }
    }
}

// ── 8.1.10: URL encoding ────────────────────────────────────────────────────

/// urlencode() — URL-encodes string.
pub fn php_urlencode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// urldecode() — Decodes URL-encoded string.
pub fn php_urldecode(s: &str) -> String {
    let mut result = Vec::new();
    let mut bytes = s.bytes();

    while let Some(b) = bytes.next() {
        match b {
            b'+' => result.push(b' '),
            b'%' => {
                let hi = bytes.next().and_then(hex_val);
                let lo = bytes.next().and_then(hex_val);
                if let (Some(h), Some(l)) = (hi, lo) {
                    result.push((h << 4) | l);
                } else {
                    result.push(b'%');
                }
            }
            _ => result.push(b),
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

/// rawurlencode() — URL-encode according to RFC 3986.
pub fn php_rawurlencode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
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

/// rawurldecode() — Decode URL-encoded strings.
pub fn php_rawurldecode(s: &str) -> String {
    let mut result = Vec::new();
    let mut bytes = s.bytes();

    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes.next().and_then(hex_val);
                let lo = bytes.next().and_then(hex_val);
                if let (Some(h), Some(l)) = (hi, lo) {
                    result.push((h << 4) | l);
                } else {
                    result.push(b'%');
                }
            }
            _ => result.push(b),
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── 8.1.11: Base64 ──────────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64_encode() — Encodes data with MIME base64.
pub fn php_base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// base64_decode() — Decodes data encoded with MIME base64.
pub fn php_base64_decode(data: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let filtered: Vec<u8> = data.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let chunks = filtered.chunks(4);

    for chunk in chunks {
        if chunk.len() < 2 {
            return None;
        }

        let vals: Vec<Option<u8>> = chunk
            .iter()
            .map(|&b| {
                if b == b'=' {
                    Some(0)
                } else {
                    base64_char_val(b)
                }
            })
            .collect();

        if vals.iter().any(|v| v.is_none()) {
            return None;
        }

        let a = vals[0].unwrap() as u32;
        let b = vals[1].unwrap() as u32;
        let c = if chunk.len() > 2 {
            vals[2].unwrap() as u32
        } else {
            0
        };
        let d = if chunk.len() > 3 {
            vals[3].unwrap() as u32
        } else {
            0
        };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;

        result.push(((triple >> 16) & 0xFF) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }
    }

    Some(result)
}

fn base64_char_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// ── 8.1.12: Hashing (thin wrappers) ─────────────────────────────────────────

/// md5() — Calculate the md5 hash of a string.
///
/// Simple implementation; real one should use a proper MD5 library.
pub fn php_md5(s: &str) -> String {
    // Minimal MD5 implementation
    md5_hash(s.as_bytes())
}

/// sha1() — Calculate the sha1 hash of a string.
pub fn php_sha1(s: &str) -> String {
    sha1_hash(s.as_bytes())
}

// Minimal MD5 (RFC 1321) — production code should use a crate
fn md5_hash(data: &[u8]) -> String {
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: add padding
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Process each 512-bit chunk
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(s[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        a0 as u8, (a0 >> 8) as u8, (a0 >> 16) as u8, (a0 >> 24) as u8,
        b0 as u8, (b0 >> 8) as u8, (b0 >> 16) as u8, (b0 >> 24) as u8,
        c0 as u8, (c0 >> 8) as u8, (c0 >> 16) as u8, (c0 >> 24) as u8,
        d0 as u8, (d0 >> 8) as u8, (d0 >> 16) as u8, (d0 >> 24) as u8,
    )
}

// Minimal SHA-1 (RFC 3174)
fn sha1_hash(data: &[u8]) -> String {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    format!("{:08x}{:08x}{:08x}{:08x}{:08x}", h0, h1, h2, h3, h4)
}

// ── 8.1.13: CRC32 ───────────────────────────────────────────────────────────

/// crc32() — Calculates the crc32 polynomial of a string.
pub fn php_crc32(s: &str) -> i64 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in s.as_bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    // PHP returns this as a signed 32-bit integer
    (crc ^ 0xFFFFFFFF) as i32 as i64
}

// ── 8.1.14: String manipulation ──────────────────────────────────────────────

/// str_rot13() — Perform the ROT13 transform.
pub fn php_str_rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

/// str_word_count() — Count the number of words in a string.
pub fn php_str_word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

// ── 8.1.15: Character functions ──────────────────────────────────────────────

/// ord() — Convert the first byte of a string to a value between 0 and 255.
pub fn php_ord(s: &str) -> i64 {
    s.bytes().next().unwrap_or(0) as i64
}

/// chr() — Generate a single-byte string from a number.
pub fn php_chr(code: i64) -> String {
    let byte = (code & 0xFF) as u8;
    String::from(byte as char)
}

/// str_split() — Convert a string to an array.
pub fn php_str_split(s: &str, length: usize) -> Vec<String> {
    if length == 0 || s.is_empty() {
        return vec![s.to_string()];
    }
    s.as_bytes()
        .chunks(length)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}

/// count_chars() — Return information about characters used in a string.
/// Mode 1: returns array with byte-value as key and frequency as value (only for occurring bytes).
pub fn php_count_chars(s: &str) -> HashMap<u8, usize> {
    let mut counts = HashMap::new();
    for &byte in s.as_bytes() {
        *counts.entry(byte).or_insert(0) += 1;
    }
    counts
}

// ── 8.1.16: Quoted-Printable ─────────────────────────────────────────────────

/// quoted_printable_encode() — Convert a 8 bit string to a quoted-printable string.
///
/// Reference: RFC 2045 section 6.7
pub fn php_quoted_printable_encode(input: &[u8]) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for &byte in input {
        // Rule: printable ASCII (33-126) except '=' pass through
        // Space (32) and tab (9) are allowed unless at end of line
        let encoded = if byte == b'=' {
            format!("={:02X}", byte)
        } else if (byte >= 33 && byte <= 126) || byte == b'\t' || byte == b' ' {
            (byte as char).to_string()
        } else if byte == b'\r' || byte == b'\n' {
            // Pass through CRLF/LF as-is, reset line length
            line_len = 0;
            result.push(byte as char);
            continue;
        } else {
            format!("={:02X}", byte)
        };

        // Soft line break if line would exceed 76 chars
        if line_len + encoded.len() > 75 {
            result.push_str("=\r\n");
            line_len = 0;
        }

        result.push_str(&encoded);
        line_len += encoded.len();
    }

    result
}

/// quoted_printable_decode() — Convert a quoted-printable string to an 8 bit string.
pub fn php_quoted_printable_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len() {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    result.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
            // Soft line break: =\r\n or =\n
            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            // Invalid sequence, pass through
            result.push(bytes[i]);
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

// ── 8.1.17: Escaping ────────────────────────────────────────────────────────

/// addslashes() — Quote string with slashes.
pub fn php_addslashes(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("\\'"),
            '"' => result.push_str("\\\""),
            '\0' => result.push_str("\\0"),
            _ => result.push(ch),
        }
    }
    result
}

/// stripslashes() — Un-quotes a quoted string.
pub fn php_stripslashes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => result.push('\\'),
                Some('\'') => result.push('\''),
                Some('"') => result.push('"'),
                Some('0') => result.push('\0'),
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strlen / substr / strpos ──
    #[test]
    fn test_strlen() {
        assert_eq!(php_strlen(""), 0);
        assert_eq!(php_strlen("hello"), 5);
        assert_eq!(php_strlen("héllo"), 6); // UTF-8: é is 2 bytes
    }

    #[test]
    fn test_substr() {
        assert_eq!(php_substr("Hello", 1, None), "ello");
        assert_eq!(php_substr("Hello", 1, Some(3)), "ell");
        assert_eq!(php_substr("Hello", -3, None), "llo");
        assert_eq!(php_substr("Hello", 0, Some(-1)), "Hell");
        assert_eq!(php_substr("Hello", -3, Some(2)), "ll");
        assert_eq!(php_substr("", 0, None), "");
    }

    #[test]
    fn test_strpos() {
        assert_eq!(php_strpos("hello world", "world", 0), Some(6));
        assert_eq!(php_strpos("hello world", "xyz", 0), None);
        assert_eq!(php_strpos("abcabc", "abc", 1), Some(3));
        assert_eq!(php_strpos("hello", "", 0), None);
    }

    #[test]
    fn test_strrpos() {
        assert_eq!(php_strrpos("abcabc", "abc", 0), Some(3));
        assert_eq!(php_strrpos("abcabc", "abc", -3), Some(0));
        assert_eq!(php_strrpos("hello", "xyz", 0), None);
    }

    #[test]
    fn test_strstr() {
        assert_eq!(
            php_strstr("hello world", "world", false),
            Some("world".to_string())
        );
        assert_eq!(
            php_strstr("hello world", "world", true),
            Some("hello ".to_string())
        );
        assert_eq!(php_strstr("hello", "xyz", false), None);
    }

    #[test]
    fn test_str_contains_starts_ends() {
        assert!(php_str_contains("hello world", "world"));
        assert!(php_str_contains("hello", ""));
        assert!(!php_str_contains("hello", "xyz"));

        assert!(php_str_starts_with("hello world", "hello"));
        assert!(!php_str_starts_with("hello world", "world"));

        assert!(php_str_ends_with("hello world", "world"));
        assert!(!php_str_ends_with("hello world", "hello"));
    }

    // ── str_replace / str_repeat / str_pad ──
    #[test]
    fn test_str_replace() {
        let (result, count) = php_str_replace("world", "PHP", "hello world world");
        assert_eq!(result, "hello PHP PHP");
        assert_eq!(count, 2);

        let (result, _) = php_str_replace("", "x", "hello");
        assert_eq!(result, "hello"); // Empty search returns original
    }

    #[test]
    fn test_str_repeat() {
        assert_eq!(php_str_repeat("ab", 3), "ababab");
        assert_eq!(php_str_repeat("x", 0), "");
    }

    #[test]
    fn test_str_pad() {
        assert_eq!(php_str_pad("42", 5, " ", PadType::Left), "   42");
        assert_eq!(php_str_pad("42", 5, "0", PadType::Left), "00042");
        assert_eq!(php_str_pad("hi", 5, "-", PadType::Right), "hi---");
        assert_eq!(php_str_pad("hi", 8, "-+", PadType::Both), "-+-hi-+-");
        assert_eq!(php_str_pad("toolong", 3, " ", PadType::Right), "toolong");
    }

    // ── Case conversion ──
    #[test]
    fn test_case_conversion() {
        assert_eq!(php_strtolower("HELLO"), "hello");
        assert_eq!(php_strtoupper("hello"), "HELLO");
        assert_eq!(php_ucfirst("hello"), "Hello");
        assert_eq!(php_ucfirst(""), "");
        assert_eq!(php_lcfirst("Hello"), "hello");
        assert_eq!(php_ucwords("hello world foo", ""), "Hello World Foo");
    }

    // ── trim ──
    #[test]
    fn test_trim() {
        assert_eq!(php_trim("  hello  ", None), "hello");
        assert_eq!(php_ltrim("  hello  ", None), "hello  ");
        assert_eq!(php_rtrim("  hello  ", None), "  hello");
        assert_eq!(php_trim("xxhelloxx", Some("x")), "hello");
    }

    // ── explode / implode ──
    #[test]
    fn test_explode() {
        assert_eq!(php_explode(",", "a,b,c", None), vec!["a", "b", "c"]);
        assert_eq!(php_explode(",", "a,b,c", Some(2)), vec!["a", "b,c"]);
        assert_eq!(php_explode(",", "a,b,c", Some(-1)), vec!["a", "b"]);
    }

    #[test]
    fn test_implode() {
        let pieces: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(php_implode(", ", &pieces), "a, b, c");
        assert_eq!(php_implode("", &pieces), "abc");
    }

    // ── sprintf ──
    #[test]
    fn test_sprintf() {
        assert_eq!(php_sprintf("Hello %s!", &["world"]), "Hello world!");
        assert_eq!(php_sprintf("%d items", &["42"]), "42 items");
        assert_eq!(php_sprintf("%.2f", &["3.14159"]), "3.14");
        assert_eq!(php_sprintf("%05d", &["42"]), "00042");
        assert_eq!(php_sprintf("100%%", &[]), "100%");
        assert_eq!(php_sprintf("%x", &["255"]), "ff");
        assert_eq!(php_sprintf("%X", &["255"]), "FF");
        assert_eq!(php_sprintf("%b", &["10"]), "1010");
        assert_eq!(php_sprintf("%o", &["8"]), "10");
    }

    // ── number_format ──
    #[test]
    fn test_number_format() {
        assert_eq!(php_number_format(1234567.891, 2, ".", ","), "1,234,567.89");
        assert_eq!(php_number_format(1234.5, 0, ".", ","), "1,235");
        assert_eq!(php_number_format(1234567.891, 2, ",", "."), "1.234.567,89");
        assert_eq!(php_number_format(0.5, 0, ".", ","), "1");
    }

    // ── nl2br / wordwrap / chunk_split ──
    #[test]
    fn test_nl2br() {
        assert_eq!(php_nl2br("hello\nworld", true), "hello<br />\nworld");
        assert_eq!(php_nl2br("hello\r\nworld", false), "hello<br>\r\nworld");
    }

    #[test]
    fn test_chunk_split() {
        assert_eq!(php_chunk_split("abcdef", 2, "-"), "ab-cd-ef-");
    }

    // ── htmlspecialchars ──
    #[test]
    fn test_htmlspecialchars() {
        let flags = HtmlFlags::default();
        assert_eq!(
            php_htmlspecialchars("<p>\"Hello\" & 'World'</p>", flags),
            "&lt;p&gt;&quot;Hello&quot; &amp; 'World'&lt;/p&gt;"
        );
    }

    #[test]
    fn test_htmlspecialchars_decode() {
        assert_eq!(
            php_htmlspecialchars_decode("&lt;p&gt;&amp;&quot;&#039;&lt;/p&gt;"),
            "<p>&\"'</p>"
        );
    }

    // ── URL encoding ──
    #[test]
    fn test_urlencode() {
        assert_eq!(php_urlencode("hello world"), "hello+world");
        assert_eq!(php_urlencode("foo@bar.com"), "foo%40bar.com");
    }

    #[test]
    fn test_urldecode() {
        assert_eq!(php_urldecode("hello+world"), "hello world");
        assert_eq!(php_urldecode("foo%40bar"), "foo@bar");
    }

    #[test]
    fn test_rawurlencode() {
        assert_eq!(php_rawurlencode("hello world"), "hello%20world");
        assert_eq!(php_rawurlencode("foo~bar"), "foo~bar"); // ~ is not encoded
    }

    // ── Base64 ──
    #[test]
    fn test_base64_encode() {
        assert_eq!(php_base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(php_base64_encode(b""), "");
        assert_eq!(php_base64_encode(b"f"), "Zg==");
        assert_eq!(php_base64_encode(b"fo"), "Zm8=");
        assert_eq!(php_base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(php_base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(php_base64_decode("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(php_base64_decode(""), Some(vec![]));
    }

    // ── MD5 / SHA1 ──
    #[test]
    fn test_md5() {
        assert_eq!(php_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(php_md5("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha1() {
        assert_eq!(php_sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            php_sha1("hello"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    // ── CRC32 ──
    #[test]
    fn test_crc32() {
        // PHP: crc32("hello") returns 907060870
        assert_eq!(php_crc32("hello"), 907060870);
    }

    // ── str_rot13 ──
    #[test]
    fn test_str_rot13() {
        assert_eq!(php_str_rot13("Hello"), "Uryyb");
        assert_eq!(php_str_rot13("Uryyb"), "Hello");
        assert_eq!(php_str_rot13("123"), "123"); // Non-alpha unchanged
    }

    // ── ord / chr ──
    #[test]
    fn test_ord_chr() {
        assert_eq!(php_ord("A"), 65);
        assert_eq!(php_chr(65), "A");
        assert_eq!(php_ord(""), 0);
    }

    // ── str_split ──
    #[test]
    fn test_str_split() {
        assert_eq!(php_str_split("Hello", 2), vec!["He", "ll", "o"]);
        assert_eq!(php_str_split("abc", 1), vec!["a", "b", "c"]);
    }

    // ── addslashes / stripslashes ──
    #[test]
    fn test_addslashes() {
        assert_eq!(php_addslashes(r#"He said "hello""#), r#"He said \"hello\""#);
        assert_eq!(php_addslashes("it's"), "it\\'s");
        assert_eq!(php_addslashes("back\\slash"), "back\\\\slash");
    }

    // ── quoted_printable ──
    #[test]
    fn test_quoted_printable_encode() {
        // Basic ASCII passes through
        assert_eq!(php_quoted_printable_encode(b"Hello World"), "Hello World");
        // Equals sign is encoded
        assert_eq!(php_quoted_printable_encode(b"a=b"), "a=3Db");
        // High bytes are encoded
        assert_eq!(php_quoted_printable_encode(&[0xFF]), "=FF");
        assert_eq!(php_quoted_printable_encode(&[0x00]), "=00");
    }

    #[test]
    fn test_quoted_printable_decode() {
        assert_eq!(php_quoted_printable_decode("Hello World"), "Hello World");
        assert_eq!(php_quoted_printable_decode("a=3Db"), "a=b");
        // Soft line break removal
        assert_eq!(php_quoted_printable_decode("hello=\r\nworld"), "helloworld");
        assert_eq!(php_quoted_printable_decode("hello=\nworld"), "helloworld");
    }

    #[test]
    fn test_stripslashes() {
        assert_eq!(
            php_stripslashes(r#"He said \"hello\""#),
            r#"He said "hello""#
        );
        assert_eq!(php_stripslashes("it\\'s"), "it's");
    }
}
