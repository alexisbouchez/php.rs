#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{
    days_in_month, easter_days_calc, month_name, nat_cmp, session_serialize, session_unserialize,
    simple_fnmatch, timestamp_to_parts, weekday_name, Vm, VmError, VmResult,
};
use php_rs_compiler::op::OperandType;

/// Convert raw bytes to a PHP-compatible string, preserving all byte values.
/// Tries UTF-8 first; falls back to latin-1 (each byte → its code point) to
/// ensure binary data is not corrupted.
#[inline]
pub(crate) fn bytes_to_php_string(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

/// Convert a PHP string (which may contain latin-1 encoded binary data) back to raw bytes.
/// This is the inverse of bytes_to_php_string: chars ≤ 0xFF are stored as their byte value.
#[inline]
fn php_string_to_bytes(s: &str) -> Vec<u8> {
    // Fast path: if all bytes are ASCII or the string is valid UTF-8 with only
    // single-byte or latin-1 range chars, collect char values.
    s.chars().map(|c| c as u8).collect()
}

/// Apply a PHP filter to a value. Used by both filter_var() and filter_input().
fn apply_filter(val: Value, filter: i64) -> Value {
    match filter {
        257 => {
            // FILTER_VALIDATE_INT
            match &val {
                Value::Long(n) => Value::Long(*n),
                Value::String(s) => match s.trim().parse::<i64>() {
                    Ok(n) => Value::Long(n),
                    Err(_) => Value::Bool(false),
                },
                _ => Value::Bool(false),
            }
        }
        259 => {
            // FILTER_VALIDATE_FLOAT
            match &val {
                Value::Double(n) => Value::Double(*n),
                Value::Long(n) => Value::Double(*n as f64),
                Value::String(s) => match s.trim().parse::<f64>() {
                    Ok(n) => Value::Double(n),
                    Err(_) => Value::Bool(false),
                },
                _ => Value::Bool(false),
            }
        }
        274 => {
            // FILTER_VALIDATE_EMAIL
            let s = val.to_php_string();
            let valid =
                s.contains('@') && s.len() > 3 && !s.starts_with('@') && !s.ends_with('@');
            if valid { Value::String(s) } else { Value::Bool(false) }
        }
        273 => {
            // FILTER_VALIDATE_URL
            let s = val.to_php_string();
            let valid = s.starts_with("http://")
                || s.starts_with("https://")
                || s.starts_with("ftp://");
            if valid { Value::String(s) } else { Value::Bool(false) }
        }
        275 => {
            // FILTER_VALIDATE_IP
            let s = val.to_php_string();
            // Check IPv4
            let parts: Vec<&str> = s.split('.').collect();
            let ipv4_valid = parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok());
            // Check IPv6
            let ipv6_valid = s.contains(':') && s.split(':').count() >= 3
                && s.split(':').all(|p| p.is_empty() || (p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit())));
            if ipv4_valid || ipv6_valid { Value::String(s) } else { Value::Bool(false) }
        }
        258 => {
            // FILTER_VALIDATE_BOOLEAN
            match val.to_php_string().to_lowercase().as_str() {
                "true" | "on" | "yes" | "1" => Value::Bool(true),
                "false" | "off" | "no" | "0" | "" => Value::Bool(false),
                _ => Value::Null,
            }
        }
        513 => {
            // FILTER_SANITIZE_STRING (deprecated but common)
            let s = val.to_php_string();
            let cleaned: String = s.chars().filter(|c| *c != '<' && *c != '>').collect();
            Value::String(cleaned)
        }
        276 => {
            // FILTER_VALIDATE_DOMAIN
            let s = val.to_php_string();
            let valid = !s.is_empty()
                && s.len() <= 253
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.contains('.');
            if valid { Value::String(s) } else { Value::Bool(false) }
        }
        279 => {
            // FILTER_VALIDATE_MAC
            let s = val.to_php_string();
            let parts: Vec<&str> = if s.contains(':') {
                s.split(':').collect()
            } else if s.contains('-') {
                s.split('-').collect()
            } else {
                vec![]
            };
            let valid = parts.len() == 6
                && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
            if valid { Value::String(s) } else { Value::Bool(false) }
        }
        514 => {
            // FILTER_SANITIZE_ENCODED
            let s = val.to_php_string();
            let encoded: String = s
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "-._~".contains(c) {
                        c.to_string()
                    } else {
                        format!("%{:02X}", c as u32)
                    }
                })
                .collect();
            Value::String(encoded)
        }
        515 => {
            // FILTER_SANITIZE_SPECIAL_CHARS
            let s = val.to_php_string();
            let cleaned: String = s
                .chars()
                .map(|c| match c {
                    '&' => "&amp;".to_string(),
                    '"' => "&quot;".to_string(),
                    '\'' => "&#039;".to_string(),
                    '<' => "&lt;".to_string(),
                    '>' => "&gt;".to_string(),
                    _ => c.to_string(),
                })
                .collect();
            Value::String(cleaned)
        }
        517 => {
            // FILTER_SANITIZE_NUMBER_INT
            let s = val.to_php_string();
            let cleaned: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '+' || *c == '-').collect();
            Value::String(cleaned)
        }
        520 => {
            // FILTER_SANITIZE_NUMBER_FLOAT
            let s = val.to_php_string();
            let cleaned: String = s
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+' || *c == '-' || *c == '.' || *c == 'e' || *c == 'E')
                .collect();
            Value::String(cleaned)
        }
        522 => {
            // FILTER_SANITIZE_EMAIL
            let s = val.to_php_string();
            let cleaned: String = s
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~@.[]-.".contains(*c))
                .collect();
            Value::String(cleaned)
        }
        523 => {
            // FILTER_SANITIZE_URL
            let s = val.to_php_string();
            let cleaned: String = s
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "$-_.+!*'(),{}|\\^~[]`<>#%\";/?:@&=".contains(*c))
                .collect();
            Value::String(cleaned)
        }
        524 => {
            // FILTER_SANITIZE_ADD_SLASHES
            let s = val.to_php_string();
            let escaped: String = s
                .chars()
                .flat_map(|c| match c {
                    '\'' => vec!['\\', '\''],
                    '"' => vec!['\\', '"'],
                    '\\' => vec!['\\', '\\'],
                    '\0' => vec!['\\', '0'],
                    _ => vec![c],
                })
                .collect();
            Value::String(escaped)
        }
        _ => val, // FILTER_DEFAULT or unknown
    }
}

/// Get a value from a PHP superglobal array.
fn get_superglobal_value(vm: &Vm, sg_name: &str, key: &str) -> Option<Value> {
    // Check call stack first (runtime modifications take precedence)
    for frame in vm.call_stack.iter().rev() {
        let oa = &vm.op_arrays[frame.op_array_idx];
        if let Some(idx) = oa.vars.iter().position(|v| v == sg_name) {
            if idx < frame.cvs.len() {
                if let Value::Array(ref arr) = frame.cvs[idx] {
                    for (k, v) in arr.entries() {
                        let key_str = match k {
                            ArrayKey::String(s) => s.clone(),
                            ArrayKey::Int(n) => n.to_string(),
                        };
                        if key_str == key {
                            return Some(v.clone());
                        }
                    }
                }
            }
        }
    }

    // Fall back to VM's stored superglobals
    if let Some(sg_val) = vm.superglobals.get(sg_name) {
        if let Value::Array(ref arr) = sg_val {
            for (k, v) in arr.entries() {
                let key_str = match k {
                    ArrayKey::String(s) => s.clone(),
                    ArrayKey::Int(n) => n.to_string(),
                };
                if key_str == key {
                    return Some(v.clone());
                }
            }
        }
    }

    None
}

/// XMLWriter state machine for generating XML documents.
#[derive(Debug, Clone)]
pub struct XmlWriterState {
    /// The XML buffer being built
    buf: String,
    /// Stack of open element names (for closing tags)
    element_stack: Vec<String>,
    /// Whether indentation is enabled
    indent: bool,
    /// The indentation string (default: single space)
    indent_string: String,
    /// Current nesting depth
    depth: usize,
    /// Whether we're inside a start tag (haven't written '>' yet)
    in_start_tag: bool,
    /// Per-depth flag: whether the element at that depth has child elements
    has_child_elements: Vec<bool>,
}

impl XmlWriterState {
    fn new() -> Self {
        Self {
            buf: String::new(),
            element_stack: Vec::new(),
            indent: false,
            indent_string: " ".to_string(),
            depth: 0,
            in_start_tag: false,
            has_child_elements: Vec::new(),
        }
    }

    fn close_start_tag(&mut self) {
        if self.in_start_tag {
            self.buf.push('>');
            self.in_start_tag = false;
        }
    }

    fn write_indent(&mut self) {
        if self.indent {
            self.buf.push('\n');
            for _ in 0..self.depth {
                self.buf.push_str(&self.indent_string);
            }
        }
    }

    fn start_document(&mut self, version: &str, encoding: Option<&str>, standalone: Option<&str>) {
        self.buf.push_str("<?xml version=\"");
        self.buf.push_str(if version.is_empty() { "1.0" } else { version });
        self.buf.push('"');
        if let Some(enc) = encoding {
            if !enc.is_empty() {
                self.buf.push_str(" encoding=\"");
                self.buf.push_str(enc);
                self.buf.push('"');
            }
        }
        if let Some(sa) = standalone {
            if !sa.is_empty() {
                self.buf.push_str(" standalone=\"");
                self.buf.push_str(sa);
                self.buf.push('"');
            }
        }
        self.buf.push_str("?>");
    }

    fn end_document(&mut self) {
        self.close_start_tag();
        // Close any remaining open elements
        while let Some(name) = self.element_stack.pop() {
            self.depth = self.depth.saturating_sub(1);
            self.write_indent();
            self.buf.push_str("</");
            self.buf.push_str(&name);
            self.buf.push('>');
        }
    }

    fn start_element(&mut self, name: &str) {
        self.close_start_tag();
        // Mark parent as having child elements
        if let Some(last) = self.has_child_elements.last_mut() {
            *last = true;
        }
        self.write_indent();
        self.buf.push('<');
        self.buf.push_str(name);
        self.in_start_tag = true;
        self.element_stack.push(name.to_string());
        self.has_child_elements.push(false); // New element has no children yet
        self.depth += 1;
    }

    fn start_element_ns(&mut self, prefix: Option<&str>, name: &str, uri: Option<&str>) {
        self.close_start_tag();
        if let Some(last) = self.has_child_elements.last_mut() {
            *last = true;
        }
        self.write_indent();
        self.buf.push('<');
        let full_name = if let Some(p) = prefix {
            if !p.is_empty() {
                format!("{}:{}", p, name)
            } else {
                name.to_string()
            }
        } else {
            name.to_string()
        };
        self.buf.push_str(&full_name);
        self.in_start_tag = true;
        // Add namespace declaration
        if let Some(u) = uri {
            if !u.is_empty() {
                if let Some(p) = prefix {
                    if !p.is_empty() {
                        self.buf.push_str(&format!(" xmlns:{}=\"{}\"", p, xml_escape_attr(u)));
                    } else {
                        self.buf.push_str(&format!(" xmlns=\"{}\"", xml_escape_attr(u)));
                    }
                } else {
                    self.buf.push_str(&format!(" xmlns=\"{}\"", xml_escape_attr(u)));
                }
            }
        }
        self.element_stack.push(full_name);
        self.has_child_elements.push(false);
        self.depth += 1;
    }

    fn end_element(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        let had_children = self.has_child_elements.pop().unwrap_or(false);
        if self.in_start_tag {
            // Self-closing tag
            self.buf.push_str("/>");
            self.in_start_tag = false;
            self.element_stack.pop();
        } else {
            if let Some(name) = self.element_stack.pop() {
                if had_children {
                    self.write_indent();
                }
                self.buf.push_str("</");
                self.buf.push_str(&name);
                self.buf.push('>');
            }
        }
    }

    fn full_end_element(&mut self) {
        self.close_start_tag();
        self.depth = self.depth.saturating_sub(1);
        let had_children = self.has_child_elements.pop().unwrap_or(false);
        if let Some(name) = self.element_stack.pop() {
            if had_children {
                self.write_indent();
            }
            self.buf.push_str("</");
            self.buf.push_str(&name);
            self.buf.push('>');
        }
    }

    fn write_attribute(&mut self, name: &str, value: &str) {
        if self.in_start_tag {
            self.buf.push(' ');
            self.buf.push_str(name);
            self.buf.push_str("=\"");
            self.buf.push_str(&xml_escape_attr(value));
            self.buf.push('"');
        }
    }

    fn write_text(&mut self, text: &str) {
        self.close_start_tag();
        self.buf.push_str(&xml_escape_text(text));
        // has_text_only stays true — text doesn't require indented close
    }

    fn write_cdata(&mut self, text: &str) {
        self.close_start_tag();
        self.buf.push_str("<![CDATA[");
        self.buf.push_str(text);
        self.buf.push_str("]]>");
        // has_text_only stays true — CDATA doesn't require indented close
    }

    fn write_comment(&mut self, text: &str) {
        self.close_start_tag();
        self.write_indent();
        self.buf.push_str("<!-- ");
        self.buf.push_str(text);
        self.buf.push_str(" -->");
    }

    fn write_pi(&mut self, target: &str, content: &str) {
        self.close_start_tag();
        self.write_indent();
        self.buf.push_str("<?");
        self.buf.push_str(target);
        if !content.is_empty() {
            self.buf.push(' ');
            self.buf.push_str(content);
        }
        self.buf.push_str("?>");
    }

    fn write_raw(&mut self, raw: &str) {
        self.close_start_tag();
        self.buf.push_str(raw);
    }

    fn output_memory(&mut self, flush: bool) -> String {
        let result = self.buf.clone();
        if flush {
            self.buf.clear();
        }
        result
    }
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Dispatch remaining built-in function calls.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "php_sapi_name" => Ok(Some(Value::String("cli".to_string()))),
        "strcmp" => {
            let s1 = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let s2 = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(s1.cmp(&s2) as i64)))
        }
        "strncmp" => {
            let s1 = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let s2 = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let n = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            let a = &s1[..n.min(s1.len())];
            let b = &s2[..n.min(s2.len())];
            Ok(Some(Value::Long(a.cmp(b) as i64)))
        }
        "strcasecmp" => {
            let s1 = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let s2 = args
                .get(1)
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            Ok(Some(Value::Long(s1.cmp(&s2) as i64)))
        }
        "strncasecmp" => {
            let s1 = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let s2 = args
                .get(1)
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let n = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            let a = &s1[..n.min(s1.len())];
            let b = &s2[..n.min(s2.len())];
            Ok(Some(Value::Long(a.cmp(b) as i64)))
        }

        // ══════════════════════════════════════════════════════════════
        // TIER 2: Type/value functions
        // ══════════════════════════════════════════════════════════════
        "is_numeric_string" | "ctype_digit" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(!s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))))
        }
        "ctype_alpha" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_alphabetic()),
            )))
        }
        "ctype_alnum" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric()),
            )))
        }
        "ctype_lower" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase()),
            )))
        }
        "ctype_upper" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase()),
            )))
        }
        "ctype_space" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_whitespace()),
            )))
        }
        "ctype_punct" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_punctuation()),
            )))
        }
        "ctype_xdigit" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()),
            )))
        }
        "expm1" => {
            let n = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(n.exp_m1())))
        }
        "log1p" => {
            let n = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(n.ln_1p())))
        }
        "fpow" => {
            let base = args.first().map(|v| v.to_double()).unwrap_or(0.0);
            let exp = args.get(1).map(|v| v.to_double()).unwrap_or(0.0);
            Ok(Some(Value::Double(base.powf(exp))))
        }
        "clamp" => {
            let val = args.first().map(|v| v.to_long()).unwrap_or(0);
            let min = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let max = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            if min > max {
                return Err(VmError::FatalError(
                    "clamp(): Argument #2 ($min) cannot be greater than argument #3 ($max)".into(),
                ));
            }
            Ok(Some(Value::Long(val.clamp(min, max))))
        }
        "strrchr" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            if let Some(pos) = haystack.rfind(&needle[..1.min(needle.len())]) {
                Ok(Some(Value::String(haystack[pos..].to_string())))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "strpbrk" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let charlist = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let pos = haystack.find(|c: char| charlist.contains(c));
            match pos {
                Some(p) => Ok(Some(Value::String(haystack[p..].to_string()))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "strtr" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if args.len() == 2 {
                // strtr($str, $replacements_array)
                if let Some(Value::Array(ref arr)) = args.get(1) {
                    let mut result = s.clone();
                    for (key, val) in arr.entries() {
                        let from = match key {
                            ArrayKey::String(ref k) => k.clone(),
                            ArrayKey::Int(n) => n.to_string(),
                        };
                        let to = val.to_php_string();
                        result = result.replace(&from, &to);
                    }
                    Ok(Some(Value::String(result)))
                } else {
                    Ok(Some(Value::String(s)))
                }
            } else {
                // strtr($str, $from, $to)
                let from = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let to = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                let from_chars: Vec<char> = from.chars().collect();
                let to_chars: Vec<char> = to.chars().collect();
                let result: String = s
                    .chars()
                    .map(|c| {
                        if let Some(pos) = from_chars.iter().position(|&fc| fc == c) {
                            to_chars.get(pos).copied().unwrap_or(c)
                        } else {
                            c
                        }
                    })
                    .collect();
                Ok(Some(Value::String(result)))
            }
        }
        "strspn" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mask = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let len = args.get(3).map(|v| v.to_long() as usize);
            let substr = if offset < s.len() { &s[offset..] } else { "" };
            let substr = match len {
                Some(l) if l < substr.len() => &substr[..l],
                _ => substr,
            };
            let count = substr.chars().take_while(|c| mask.contains(*c)).count();
            Ok(Some(Value::Long(count as i64)))
        }
        "strcspn" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mask = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let len = args.get(3).map(|v| v.to_long() as usize);
            let substr = if offset < s.len() { &s[offset..] } else { "" };
            let substr = match len {
                Some(l) if l < substr.len() => &substr[..l],
                _ => substr,
            };
            let count = substr.chars().take_while(|c| !mask.contains(*c)).count();
            Ok(Some(Value::Long(count as i64)))
        }
        "strcoll" => {
            let s1 = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let s2 = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Long(s1.cmp(&s2) as i64)))
        }
        "strip_tags" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let allowed = args.get(1).map(|v| v.to_php_string());
            let allowed_tags: Vec<String> = match &allowed {
                Some(a) => {
                    let mut tags = Vec::new();
                    let mut i = 0;
                    let bytes = a.as_bytes();
                    while i < bytes.len() {
                        if bytes[i] == b'<' {
                            if let Some(end) = a[i + 1..].find('>') {
                                tags.push(a[i + 1..i + 1 + end].to_lowercase());
                                i = i + 1 + end + 1;
                            } else {
                                break;
                            }
                        } else {
                            i += 1;
                        }
                    }
                    tags
                }
                None => Vec::new(),
            };
            let mut result = String::new();
            let mut in_tag = false;
            let mut tag_name = String::new();
            let mut current_tag = String::new();
            let mut collecting_name = false;
            for ch in s.chars() {
                if ch == '<' {
                    in_tag = true;
                    tag_name.clear();
                    current_tag.clear();
                    current_tag.push(ch);
                    collecting_name = true;
                } else if in_tag {
                    current_tag.push(ch);
                    if ch == '>' {
                        in_tag = false;
                        let tn = tag_name.trim_start_matches('/').to_lowercase();
                        if allowed_tags.contains(&tn) {
                            result.push_str(&current_tag);
                        }
                    } else if collecting_name {
                        if ch.is_whitespace() || ch == '/' || ch == '>' {
                            collecting_name = false;
                        } else {
                            tag_name.push(ch);
                        }
                    }
                } else {
                    result.push(ch);
                }
            }
            Ok(Some(Value::String(result)))
        }
        "str_decrement" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if s.is_empty() {
                return Err(VmError::FatalError(
                    "str_decrement(): Argument #1 ($string) must not be empty".into(),
                ));
            }
            let mut chars: Vec<char> = s.chars().collect();
            let mut i = chars.len() - 1;
            loop {
                if chars[i].is_ascii_digit() && chars[i] > '0' {
                    chars[i] = (chars[i] as u8 - 1) as char;
                    break;
                } else if chars[i] == '0' {
                    chars[i] = '9';
                    if i == 0 {
                        if chars.len() > 1 {
                            chars.remove(0);
                        }
                        break;
                    }
                    i -= 1;
                } else if chars[i].is_ascii_lowercase() && chars[i] > 'a' {
                    chars[i] = (chars[i] as u8 - 1) as char;
                    break;
                } else if chars[i] == 'a' {
                    chars[i] = 'z';
                    if i == 0 {
                        if chars.len() > 1 {
                            chars.remove(0);
                        }
                        break;
                    }
                    i -= 1;
                } else if chars[i].is_ascii_uppercase() && chars[i] > 'A' {
                    chars[i] = (chars[i] as u8 - 1) as char;
                    break;
                } else if chars[i] == 'A' {
                    chars[i] = 'Z';
                    if i == 0 {
                        if chars.len() > 1 {
                            chars.remove(0);
                        }
                        break;
                    }
                    i -= 1;
                } else {
                    break;
                }
            }
            Ok(Some(Value::String(chars.into_iter().collect())))
        }
        "str_increment" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(crate::value::php_increment_string(&s))))
        }
        "hebrev" => {
            // Simplified: just reverse RTL text segments
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(s)))
        }

        // === Type/Inspection functions ===
        "is_scalar" => {
            let val = args.first().unwrap_or(&Value::Null);
            let result = matches!(
                val,
                Value::Bool(_) | Value::Long(_) | Value::Double(_) | Value::String(_)
            );
            Ok(Some(Value::Bool(result)))
        }
        "is_countable" => {
            let val = args.first().unwrap_or(&Value::Null);
            let result = match val {
                Value::Array(_) => true,
                Value::Object(obj) => {
                    // Check if object implements Countable
                    let class_name = obj.class_name();
                    vm.classes
                        .get(&class_name)
                        .map(|cd| cd.interfaces.iter().any(|i| i == "Countable"))
                        .unwrap_or(false)
                }
                _ => false,
            };
            Ok(Some(Value::Bool(result)))
        }
        "is_iterable" => {
            let val = args.first().unwrap_or(&Value::Null);
            let result = match val {
                Value::Array(_) => true,
                Value::Object(obj) => {
                    // Check if object implements Traversable, Iterator, or IteratorAggregate
                    let class_name = obj.class_name();
                    vm.classes
                        .get(&class_name)
                        .map(|cd| {
                            cd.interfaces.iter().any(|i| {
                                i == "Traversable" || i == "Iterator" || i == "IteratorAggregate"
                            })
                        })
                        .unwrap_or(false)
                }
                _ => false,
            };
            Ok(Some(Value::Bool(result)))
        }

        // === Finish ctype ===
        "ctype_print" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.bytes().all(|b| b >= 0x20 && b <= 0x7E),
            )))
        }
        "ctype_graph" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.bytes().all(|b| b > 0x20 && b <= 0x7E),
            )))
        }
        "ctype_cntrl" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Bool(
                !s.is_empty() && s.bytes().all(|b| b < 0x20 || b == 0x7F),
            )))
        }
        "lcg_value" => {
            let mut rng = php_rs_ext_random::Randomizer::new(Box::new(
                php_rs_ext_random::Mt19937::new(Some(vm.mt_rng.generate_u32() as u64)),
            ));
            Ok(Some(Value::Double(rng.get_float())))
        }
        "gethostname" => Ok(Some(Value::String("localhost".into()))),
        // intl extension — normalizer (wired to php-rs-ext-intl)
        "normalizer_is_normalized" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let form_int = args.get(1).map(|v| v.to_long()).unwrap_or(4); // 4 = NFC
            let form = match form_int {
                2 => php_rs_ext_intl::NormalizationForm::NFD,
                4 => php_rs_ext_intl::NormalizationForm::NFC,
                5 => php_rs_ext_intl::NormalizationForm::NFKC,
                6 => php_rs_ext_intl::NormalizationForm::NFKD,
                _ => php_rs_ext_intl::NormalizationForm::NFC,
            };
            Ok(Some(Value::Bool(
                php_rs_ext_intl::Normalizer::is_normalized(&s, form),
            )))
        }
        "normalizer_normalize" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let form_int = args.get(1).map(|v| v.to_long()).unwrap_or(4);
            let form = match form_int {
                2 => php_rs_ext_intl::NormalizationForm::NFD,
                4 => php_rs_ext_intl::NormalizationForm::NFC,
                5 => php_rs_ext_intl::NormalizationForm::NFKC,
                6 => php_rs_ext_intl::NormalizationForm::NFKD,
                _ => php_rs_ext_intl::NormalizationForm::NFC,
            };
            Ok(Some(Value::String(php_rs_ext_intl::Normalizer::normalize(
                &s, form,
            ))))
        }
        "mb_strstr" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let before = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
            match haystack.find(&needle) {
                Some(pos) => {
                    if before {
                        Ok(Some(Value::String(haystack[..pos].to_string())))
                    } else {
                        Ok(Some(Value::String(haystack[pos..].to_string())))
                    }
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_stristr" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let before = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
            let pos = haystack.to_lowercase().find(&needle.to_lowercase());
            match pos {
                Some(p) => {
                    if before {
                        Ok(Some(Value::String(haystack[..p].to_string())))
                    } else {
                        Ok(Some(Value::String(haystack[p..].to_string())))
                    }
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // === filter extension ===
        "filter_var" => {
            let val = args.first().cloned().unwrap_or(Value::Null);
            let filter = args.get(1).map(|v| v.to_long()).unwrap_or(516); // FILTER_DEFAULT
            Ok(Some(apply_filter(val, filter)))
        }
        "filter_input" => {
            let input_type = args.first().map(|v| v.to_long()).unwrap_or(0);
            let var_name = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let filter = args.get(2).map(|v| v.to_long()).unwrap_or(516); // FILTER_DEFAULT

            // Map INPUT_* constant to superglobal name
            let sg_name = match input_type {
                1 => "_GET",     // INPUT_GET
                2 => "_POST",    // INPUT_POST
                4 => "_COOKIE",  // INPUT_COOKIE
                16 => "_ENV",    // INPUT_ENV
                32 => "_SERVER", // INPUT_SERVER
                99 => "_REQUEST", // INPUT_REQUEST
                _ => return Ok(Some(Value::Null)),
            };

            // Look up value from superglobals stored on VM
            let val = get_superglobal_value(vm, sg_name, &var_name);
            match val {
                Some(v) => Ok(Some(apply_filter(v, filter))),
                None => Ok(Some(Value::Null)),
            }
        }
        "filter_has_var" => {
            let input_type = args.first().map(|v| v.to_long()).unwrap_or(0);
            let var_name = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let sg_name = match input_type {
                1 => "_GET",
                2 => "_POST",
                4 => "_COOKIE",
                16 => "_ENV",
                32 => "_SERVER",
                99 => "_REQUEST",
                _ => return Ok(Some(Value::Bool(false))),
            };
            let has = get_superglobal_value(vm, sg_name, &var_name).is_some();
            Ok(Some(Value::Bool(has)))
        }
        "filter_list" => {
            let mut arr = PhpArray::new();
            for name in &[
                "int",
                "boolean",
                "float",
                "validate_regexp",
                "validate_url",
                "validate_email",
                "validate_ip",
                "string",
                "stripped",
                "encoded",
                "special_chars",
                "unsafe_raw",
                "email",
                "url",
                "number_int",
                "number_float",
                "callback",
            ] {
                arr.push(Value::String(name.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "filter_id" => {
            let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let id = match name.as_str() {
                "int" => 257,
                "boolean" => 258,
                "float" => 259,
                "validate_url" => 273,
                "validate_email" => 274,
                "validate_ip" => 275,
                "string" | "stripped" => 513,
                _ => 0,
            };
            if id > 0 {
                Ok(Some(Value::Long(id)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // === spl extension ===
        "spl_autoload_register" => {
            // Register an autoloader callback
            let callback = args.first().cloned().unwrap_or(Value::Null);
            let _throw = args.get(1).map(|v| v.to_bool()).unwrap_or(true);
            let prepend = args.get(2).map(|v| v.to_bool()).unwrap_or(false);

            let (func_name, this_obj) = match &callback {
                Value::String(s) => (s.clone(), None),
                Value::Array(arr) => {
                    // [$object, 'method'] or ['ClassName', 'method'] style
                    let class_part = arr.get_int(0).unwrap_or(&Value::Null).clone();
                    let method_part = arr.get_int(1).unwrap_or(&Value::Null).to_php_string();
                    let (class_name, this_val) = match &class_part {
                        Value::Object(o) => (o.class_name(), Some(class_part.clone())),
                        Value::String(s) => (s.clone(), None),
                        _ => ("unknown".to_string(), None),
                    };
                    (format!("{}::{}", class_name, method_part), this_val)
                }
                Value::Null => ("spl_autoload".to_string(), None),
                Value::Object(ref o) if o.class_name() == "Closure" => {
                    (Vm::extract_closure_name(&callback), None)
                }
                _ => (callback.to_php_string(), None),
            };

            if !vm.autoload_callbacks.iter().any(|(n, _)| n == &func_name) {
                let entry = (func_name, this_obj);
                if prepend {
                    vm.autoload_callbacks.insert(0, entry);
                } else {
                    vm.autoload_callbacks.push(entry);
                }
            }
            Ok(Some(Value::Bool(true)))
        }
        "spl_autoload_unregister" => {
            let raw = args.first().cloned().unwrap_or(Value::Null);
            let callback_name = match &raw {
                Value::Array(arr) => {
                    // [ClassName, 'methodName'] or [$obj, 'methodName']
                    let class = arr
                        .get_int(0)
                        .map(|v: &Value| v.to_php_string())
                        .unwrap_or_default();
                    let method = arr
                        .get_int(1)
                        .map(|v: &Value| v.to_php_string())
                        .unwrap_or_default();
                    format!("{}::{}", class, method)
                }
                _ => raw.to_php_string(),
            };
            vm.autoload_callbacks.retain(|(n, _)| n != &callback_name);
            Ok(Some(Value::Bool(true)))
        }
        "spl_autoload_functions" => {
            let mut arr = PhpArray::new();
            for (name, _) in &vm.autoload_callbacks {
                arr.push(Value::String(name.clone()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "spl_object_id" => {
            // Return a unique identifier
            Ok(Some(Value::Long(0)))
        }
        "spl_object_hash" => Ok(Some(Value::String("0000000000000000".into()))),
        "iterator_to_array" => {
            let val = args.first().cloned().unwrap_or(Value::Null);
            let preserve_keys = args.get(1).map(|v| v.to_bool()).unwrap_or(true);
            if let Value::Array(a) = val {
                Ok(Some(Value::Array(a)))
            } else if let Value::Object(_) = val {
                // Check for IteratorAggregate — call getIterator() first
                let iter_val = if let Value::Object(ref o) = val {
                    let class_name = o.class_name();
                    if vm.resolve_method(&class_name, "getIterator").is_some() {
                        match vm.call_method_sync(&val, "getIterator") {
                            Ok(v @ Value::Object(_)) => v,
                            _ => val.clone(),
                        }
                    } else {
                        val.clone()
                    }
                } else {
                    val.clone()
                };
                let mut result = PhpArray::new();
                vm.call_method_sync(&iter_val, "rewind")?;
                for _ in 0..100000 {
                    let valid = vm.call_method_sync(&iter_val, "valid")?;
                    if !valid.to_bool() {
                        break;
                    }
                    let current = vm.call_method_sync(&iter_val, "current")?;
                    if preserve_keys {
                        let key = vm.call_method_sync(&iter_val, "key")?;
                        match key {
                            Value::Long(_) | Value::String(_) => result.set(&key, current),
                            _ => result.push(current),
                        }
                    } else {
                        result.push(current);
                    }
                    vm.call_method_sync(&iter_val, "next")?;
                }
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Array(PhpArray::new())))
            }
        }
        "iterator_count" => {
            let val = args.first().cloned().unwrap_or(Value::Null);
            if let Value::Array(ref a) = val {
                Ok(Some(Value::Long(a.len() as i64)))
            } else if let Value::Object(_) = val {
                // Handle IteratorAggregate
                let iter_val = if let Value::Object(ref o) = val {
                    let class_name = o.class_name();
                    if vm.resolve_method(&class_name, "getIterator").is_some() {
                        match vm.call_method_sync(&val, "getIterator") {
                            Ok(v @ Value::Object(_)) => v,
                            _ => val.clone(),
                        }
                    } else {
                        val.clone()
                    }
                } else {
                    val.clone()
                };
                let mut count = 0i64;
                vm.call_method_sync(&iter_val, "rewind")?;
                for _ in 0..100000 {
                    let valid = vm.call_method_sync(&iter_val, "valid")?;
                    if !valid.to_bool() {
                        break;
                    }
                    count += 1;
                    vm.call_method_sync(&iter_val, "next")?;
                }
                Ok(Some(Value::Long(count)))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "iterator_apply" => Ok(Some(Value::Long(0))),
        "fpassthru" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let chunks: Option<Vec<Vec<u8>>> = if let Some(handle) = vm.file_handles.get_mut(&id) {
                let mut chunks = Vec::new();
                loop {
                    match handle.read(8192) {
                        Ok(data) if !data.is_empty() => chunks.push(data),
                        _ => break,
                    }
                }
                Some(chunks)
            } else {
                None
            };
            if let Some(chunks) = chunks {
                let total: usize = chunks.iter().map(|c| c.len()).sum();
                for chunk in chunks {
                    vm.write_output(&String::from_utf8_lossy(&chunk));
                }
                Ok(Some(Value::Long(total as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fstat" => {
            // Stub: return basic stat array
            let mut arr = PhpArray::new();
            for key in &[
                "dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "atime", "mtime",
                "ctime", "blksize", "blocks",
            ] {
                arr.set_string(key.to_string(), Value::Long(0));
            }
            Ok(Some(Value::Array(arr)))
        }
        "fsync" | "fdatasync" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.flush() {
                    Ok(_) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "umask" => {
            if args.is_empty() {
                Ok(Some(Value::Long(0o022)))
            } else {
                Ok(Some(Value::Long(0o022)))
            }
        }
        "fnmatch" => {
            let pattern = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let string = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            // Simple glob-style matching
            Ok(Some(Value::Bool(simple_fnmatch(&pattern, &string))))
        }
        "dir" => {
            // Returns an object, stub as false
            Ok(Some(Value::Bool(false)))
        }
        "chroot" => Ok(Some(Value::Bool(false))),

        // === String functions ===
        "strnatcmp" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Long(nat_cmp(&a, &b) as i64)))
        }
        "strnatcasecmp" => {
            let a = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let b = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Long(
                nat_cmp(&a.to_lowercase(), &b.to_lowercase()) as i64,
            )))
        }
        "vfprintf" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let format = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let arr_args = if let Some(Value::Array(ref a)) = args.get(2) {
                a.entries()
                    .iter()
                    .map(|(_, v)| v.to_php_string())
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };
            let formatted = php_rs_ext_standard::strings::php_sprintf(
                &format,
                &arr_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            );
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.write(formatted.as_bytes()) {
                    Ok(n) => Ok(Some(Value::Long(n as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fscanf" => {
            // Simplified: read line and apply sscanf
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let format = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.gets() {
                    Ok(Some(line)) => {
                        let scan_args = vec![Value::String(line), Value::String(format)];
                        vm.call_builtin("sscanf", &scan_args, &[], &[])
                    }
                    _ => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "utf8_encode" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(s)))
        }
        "utf8_decode" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(s)))
        }
        "strptime" => {
            // Deprecated, stub
            Ok(Some(Value::Bool(false)))
        }

        // === Array callback functions (with user callback comparison) ===
        "array_diff_uassoc"
        | "array_diff_ukey"
        | "array_intersect_uassoc"
        | "array_intersect_ukey"
        | "array_udiff"
        | "array_udiff_assoc"
        | "array_udiff_uassoc"
        | "array_uintersect"
        | "array_uintersect_assoc"
        | "array_uintersect_uassoc" => {
            let func_name = name.to_string();
            let arr1 = args.first().cloned().unwrap_or(Value::Null);
            let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
            let is_diff = func_name.contains("diff");

            // Determine which callbacks to use:
            // *_uassoc variants: last 2 args are (value_cb, key_cb) for udiff_uassoc/uintersect_uassoc
            // Others: last arg is the callback
            let has_two_callbacks = func_name.ends_with("_uassoc");

            let (val_cb, key_cb) = if has_two_callbacks {
                // Last two args: second-to-last = value callback, last = key callback
                let val_cb_val = args
                    .get(args.len().saturating_sub(2))
                    .cloned()
                    .unwrap_or(Value::Null);
                let key_cb_val = args.last().cloned().unwrap_or(Value::Null);
                (
                    Some(Vm::extract_closure_name(&val_cb_val)),
                    Some(Vm::extract_closure_name(&key_cb_val)),
                )
            } else {
                let cb_val = args.last().cloned().unwrap_or(Value::Null);
                let cb = Vm::extract_closure_name(&cb_val);
                // Determine if this callback compares keys or values
                let compares_keys = func_name.contains("_ukey") || func_name.ends_with("_uassoc");
                let compares_values =
                    func_name.contains("udiff") || func_name.contains("uintersect");
                if compares_keys {
                    (None, Some(cb))
                } else if compares_values {
                    (Some(cb), None)
                } else {
                    (Some(cb), None)
                }
            };

            if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
                let entries1: Vec<_> = a1.entries().iter().cloned().collect();
                let entries2: Vec<_> = a2.entries().iter().cloned().collect();
                let mut result = PhpArray::new();

                for (key1, val1) in &entries1 {
                    let found = entries2.iter().any(|(key2, val2)| {
                        // Compare values
                        let vals_match = if let Some(ref vcb) = val_cb {
                            let r = vm.invoke_user_callback(vcb, vec![val1.clone(), val2.clone()]);
                            matches!(r, Ok(Value::Long(0)))
                        } else {
                            val1.loose_eq(val2)
                        };

                        // Compare keys
                        let keys_match = if let Some(ref kcb) = key_cb {
                            let k1 = match key1 {
                                ArrayKey::Int(n) => Value::Long(*n),
                                ArrayKey::String(s) => Value::String(s.clone()),
                            };
                            let k2 = match key2 {
                                ArrayKey::Int(n) => Value::Long(*n),
                                ArrayKey::String(s) => Value::String(s.clone()),
                            };
                            let r = vm.invoke_user_callback(kcb, vec![k1, k2]);
                            matches!(r, Ok(Value::Long(0)))
                        } else {
                            // Builtin key comparison
                            key1 == key2
                        };

                        // For *_ukey variants, only key comparison matters
                        // For *_udiff/*_uintersect, only value comparison matters
                        // For *_assoc variants, both must match
                        let needs_key = func_name.contains("ukey")
                            || func_name.contains("uassoc")
                            || func_name.contains("_assoc");
                        let needs_val = func_name.contains("udiff")
                            || func_name.contains("uintersect")
                            || !func_name.contains("ukey");

                        if needs_key && needs_val {
                            vals_match && keys_match
                        } else if needs_key {
                            keys_match
                        } else {
                            vals_match
                        }
                    });

                    if (is_diff && !found) || (!is_diff && found) {
                        match key1 {
                            ArrayKey::Int(n) => result.set_int(*n, val1.clone()),
                            ArrayKey::String(s) => result.set_string(s.clone(), val1.clone()),
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Array(PhpArray::new())))
            }
        }

        // === Output buffering ===
        "ob_start" => {
            // ob_start(?callable $callback = null, int $chunk_size = 0, int $flags = PHP_OUTPUT_HANDLER_STDFLAGS): bool
            let callback = args.first().and_then(|v| {
                if v.is_null() || (matches!(v, Value::Bool(false))) {
                    None
                } else {
                    Some(v.to_php_string())
                }
            });
            vm.ob_stack.push(String::new());
            vm.ob_callbacks.push(callback);
            Ok(Some(Value::Bool(true)))
        }
        "ob_get_contents" => match vm.ob_stack.last() {
            Some(buf) => Ok(Some(Value::String(buf.clone()))),
            None => Ok(Some(Value::Bool(false))),
        },
        "ob_get_length" => match vm.ob_stack.last() {
            Some(buf) => Ok(Some(Value::Long(buf.len() as i64))),
            None => Ok(Some(Value::Bool(false))),
        },
        "ob_get_level" => Ok(Some(Value::Long(vm.ob_stack.len() as i64))),
        "ob_end_clean" => {
            if vm.ob_stack.pop().is_some() {
                vm.ob_callbacks.pop();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_clean" => {
            if let Some(buf) = vm.ob_stack.last_mut() {
                buf.clear();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_end_flush" => {
            if let Some(buf) = vm.ob_stack.pop() {
                let callback = vm.ob_callbacks.pop().flatten();
                // If a callback is registered, invoke it with the buffer contents
                let output = if let Some(ref cb_name) = callback {
                    if let Some(&_func_idx) = vm.functions.get(cb_name.as_str()) {
                        // Call the callback synchronously via invoke_user_callback
                        match vm.invoke_user_callback(
                            cb_name,
                            vec![Value::String(buf.clone()), Value::Long(2)],
                        ) {
                            Ok(result) => result.to_php_string(),
                            Err(_) => buf,
                        }
                    } else {
                        buf
                    }
                } else {
                    buf
                };
                vm.write_output(&output);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_flush" => {
            // Flush active buffer contents to parent level but keep buffer open.
            let n = vm.ob_stack.len();
            if n > 0 {
                let content = std::mem::take(&mut vm.ob_stack[n - 1]);
                if n > 1 {
                    vm.ob_stack[n - 2].push_str(&content);
                } else {
                    vm.output.push_str(&content);
                }
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_get_clean" => {
            if let Some(buf) = vm.ob_stack.pop() {
                vm.ob_callbacks.pop();
                Ok(Some(Value::String(buf)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_get_flush" => {
            if let Some(buf) = vm.ob_stack.pop() {
                vm.ob_callbacks.pop();
                vm.write_output(&buf.clone());
                Ok(Some(Value::String(buf)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ob_get_status" => {
            let mut arr = PhpArray::new();
            if let Some(buf) = vm.ob_stack.last() {
                let mut entry = PhpArray::new();
                entry.set_string(
                    "name".to_string(),
                    Value::String("default output handler".to_string()),
                );
                entry.set_string("type".to_string(), Value::Long(0));
                entry.set_string("flags".to_string(), Value::Long(112));
                entry.set_string(
                    "level".to_string(),
                    Value::Long(vm.ob_stack.len() as i64 - 1),
                );
                entry.set_string("chunk_size".to_string(), Value::Long(0));
                entry.set_string("buffer_size".to_string(), Value::Long(16384));
                entry.set_string("buffer_used".to_string(), Value::Long(buf.len() as i64));
                arr.push(Value::Array(entry));
            }
            Ok(Some(Value::Array(arr)))
        }
        "ob_implicit_flush" => {
            let flag = args.first().map(|v| v.to_long()).unwrap_or(1);
            vm.ob_implicit_flush = flag != 0;
            Ok(Some(Value::Null))
        }
        "ob_list_handlers" => {
            let mut arr = PhpArray::new();
            for (i, _) in vm.ob_stack.iter().enumerate() {
                let handler_name = vm
                    .ob_callbacks
                    .get(i)
                    .and_then(|cb| cb.as_ref())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "default output handler".to_string());
                arr.push(Value::String(handler_name));
            }
            Ok(Some(Value::Array(arr)))
        }
        "output_add_rewrite_var" => Ok(Some(Value::Bool(true))),
        "output_reset_rewrite_vars" => Ok(Some(Value::Bool(true))),
        "flush" => Ok(Some(Value::Null)),
        "highlight_string" | "show_source" => {
            let code = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let return_mode = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
            let highlighted = php_highlight_string(&code);
            if return_mode {
                Ok(Some(Value::String(highlighted)))
            } else {
                vm.write_output(&highlighted);
                Ok(Some(Value::Bool(true)))
            }
        }
        "highlight_file" => {
            let file = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let return_mode = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
            #[cfg(not(target_arch = "wasm32"))]
            let code = std::fs::read_to_string(&file).unwrap_or_default();
            #[cfg(target_arch = "wasm32")]
            let code = String::new();
            let highlighted = php_highlight_string(&code);
            if return_mode {
                Ok(Some(Value::String(highlighted)))
            } else {
                vm.write_output(&highlighted);
                Ok(Some(Value::Bool(true)))
            }
        }
        "php_strip_whitespace" => {
            let file = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            #[cfg(not(target_arch = "wasm32"))]
            let code = std::fs::read_to_string(&file).unwrap_or_default();
            #[cfg(target_arch = "wasm32")]
            let code = String::new();
            let stripped = php_strip_whitespace_impl(&code);
            Ok(Some(Value::String(stripped)))
        }
        "stream_get_line" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.gets() {
                    Ok(Some(line)) => {
                        Ok(Some(Value::String(line.trim_end_matches('\n').to_string())))
                    }
                    _ => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_get_meta_data" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let mut arr = PhpArray::new();
            arr.set_string("timed_out".into(), Value::Bool(false));
            arr.set_string("blocked".into(), Value::Bool(true));
            // Determine eof from the file handle
            let is_eof = if let Some(handle) = vm.file_handles.get(&id) {
                handle.eof()
            } else {
                false
            };
            arr.set_string("eof".into(), Value::Bool(is_eof));
            // Determine stream type and mode
            let (stream_type, mode_str, seekable, uri) = match id {
                0 => ("STDIO", "r", false, "php://stdin"),
                1 => ("STDIO", "w", false, "php://stdout"),
                2 => ("STDIO", "w", false, "php://stderr"),
                _ => ("STDIO", "r+", true, ""),
            };
            arr.set_string("stream_type".into(), Value::String(stream_type.into()));
            arr.set_string("mode".into(), Value::String(mode_str.into()));
            arr.set_string("seekable".into(), Value::Bool(seekable));
            arr.set_string("unread_bytes".into(), Value::Long(0));
            arr.set_string("uri".into(), Value::String(uri.into()));
            arr.set_string("wrapper_type".into(), Value::String("plainfile".into()));
            Ok(Some(Value::Array(arr)))
        }
        "stream_copy_to_stream" => {
            let src_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let dst_id = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let max_length = args.get(2).map(|v| v.to_long()).unwrap_or(-1);
            let _offset = args.get(3).map(|v| v.to_long()).unwrap_or(0);
            // Read from source
            let data = if let Some(handle) = vm.file_handles.get_mut(&src_id) {
                let read_size = if max_length > 0 {
                    max_length as usize
                } else {
                    1024 * 1024
                };
                let mut buf = Vec::new();
                loop {
                    let remaining = if max_length > 0 {
                        read_size - buf.len()
                    } else {
                        8192
                    };
                    if remaining == 0 {
                        break;
                    }
                    match handle.read(remaining) {
                        Ok(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
                        _ => break,
                    }
                }
                buf
            } else {
                return Ok(Some(Value::Bool(false)));
            };
            let bytes_written = data.len();
            // Write to destination
            if dst_id == 1 {
                // stdout — write to VM output
                vm.write_output(&String::from_utf8_lossy(&data));
            } else if let Some(handle) = vm.file_handles.get_mut(&dst_id) {
                let _ = handle.write(&data);
            } else {
                return Ok(Some(Value::Bool(false)));
            }
            Ok(Some(Value::Long(bytes_written as i64)))
        }
        // stream_get_transports not yet in file.rs
        "stream_get_transports" => {
            let mut arr = PhpArray::new();
            for t in &[
                "tcp", "udp", "unix", "udg", "ssl", "tls", "tlsv1.0", "tlsv1.1", "tlsv1.2",
                "tlsv1.3",
            ] {
                arr.push(Value::String(t.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "stream_isatty" => Ok(Some(Value::Bool(false))),
        "stream_set_chunk_size" | "stream_set_read_buffer" | "stream_set_write_buffer" => {
            Ok(Some(Value::Long(0)))
        }
        "stream_bucket_append"
        | "stream_bucket_make_writeable"
        | "stream_bucket_new"
        | "stream_bucket_prepend" => Ok(Some(Value::Null)),

        // === Finish spl (4 missing) ===
        "spl_autoload" => {
            // Default autoload implementation - try to include file
            let _class = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Null))
        }
        "spl_autoload_call" => {
            let _class = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Null))
        }
        "spl_autoload_extensions" => {
            let extensions = args.first().map(|v| v.to_php_string());
            if extensions.is_some() {
                Ok(Some(Value::Null))
            } else {
                Ok(Some(Value::String(".inc,.php".to_string())))
            }
        }
        "spl_classes" => {
            let mut arr = PhpArray::new();
            for cls in &[
                "AppendIterator",
                "ArrayIterator",
                "ArrayObject",
                "CachingIterator",
                "CallbackFilterIterator",
                "DirectoryIterator",
                "EmptyIterator",
                "FilesystemIterator",
                "FilterIterator",
                "GlobIterator",
                "InfiniteIterator",
                "IteratorIterator",
                "LimitIterator",
                "MultipleIterator",
                "NoRewindIterator",
                "ParentIterator",
                "RecursiveArrayIterator",
                "RecursiveCachingIterator",
                "RecursiveCallbackFilterIterator",
                "RecursiveDirectoryIterator",
                "RecursiveFilterIterator",
                "RecursiveIteratorIterator",
                "RecursiveRegexIterator",
                "RecursiveTreeIterator",
                "RegexIterator",
                "SplDoublyLinkedList",
                "SplFileInfo",
                "SplFileObject",
                "SplFixedArray",
                "SplHeap",
                "SplMaxHeap",
                "SplMinHeap",
                "SplObjectStorage",
                "SplPriorityQueue",
                "SplQueue",
                "SplStack",
                "SplTempFileObject",
            ] {
                arr.set_string(cls.to_string(), Value::String(cls.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }

        // === Finish filter (2 missing) ===
        "filter_input_array" => {
            let input_type = args.first().map(|v| v.to_long()).unwrap_or(0);
            let sg_name = match input_type {
                1 => "_GET",
                2 => "_POST",
                4 => "_COOKIE",
                16 => "_ENV",
                32 => "_SERVER",
                99 => "_REQUEST",
                _ => return Ok(Some(Value::Bool(false))),
            };
            // Get the entire superglobal array
            let mut result = PhpArray::new();
            let sg_val = vm.superglobals.get(sg_name).cloned()
                .or_else(|| {
                    for frame in &vm.call_stack {
                        let oa = &vm.op_arrays[frame.op_array_idx];
                        if let Some(idx) = oa.vars.iter().position(|v| v == sg_name) {
                            if idx < frame.cvs.len() {
                                if let Value::Array(_) = &frame.cvs[idx] {
                                    return Some(frame.cvs[idx].clone());
                                }
                            }
                        }
                    }
                    None
                });
            if let Some(Value::Array(ref arr)) = sg_val {
                let filter = args.get(1).map(|v| v.to_long()).unwrap_or(516);
                for (key, val) in arr.entries() {
                    let filtered = apply_filter(val.clone(), filter);
                    match key {
                        ArrayKey::String(s) => result.set_string(s.clone(), filtered),
                        ArrayKey::Int(n) => result.set_int(*n, filtered),
                    }
                }
            }
            Ok(Some(Value::Array(result)))
        }
        "filter_var_array" => {
            // Filter each element - basic pass-through
            let data = args.first().cloned().unwrap_or(Value::Null);
            if let Value::Array(ref a) = data {
                let mut result = PhpArray::new();
                for (key, val) in a.entries() {
                    match key {
                        ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                        ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                    }
                }
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "hash_hmac_file" => {
            let algo = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let filename = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let key = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Ok(data) = vm.vm_read_to_string(&filename) {
                match php_rs_ext_hash::php_hash_hmac(&algo, &data, &key) {
                    Some(result) => Ok(Some(Value::String(result))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "hash_hmac_algos" => {
            let mut arr = PhpArray::new();
            for algo in php_rs_ext_hash::php_hash_algos() {
                arr.push(Value::String(algo.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }

        // === Gettext extension (10 functions) ===
        "gettext" | "_" | "dcgettext" | "dcngettext" | "dgettext" | "dngettext" | "ngettext" => {
            // Return the message itself (no translation)
            let msg = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(msg)))
        }

        // === Calendar extension — wired to php_rs_ext_calendar ===
        "cal_days_in_month" => {
            let cal = args.first().map(|v| v.to_long() as i32).unwrap_or(0);
            let month = args.get(1).map(|v| v.to_long() as i32).unwrap_or(1);
            let year = args.get(2).map(|v| v.to_long() as i32).unwrap_or(2000);
            match php_rs_ext_calendar::cal_days_in_month(cal, month, year) {
                Ok(days) => Ok(Some(Value::Long(days as i64))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "cal_info" => {
            let cal = args.first().map(|v| v.to_long() as i32).unwrap_or(-1);
            if cal == -1 {
                // No argument: return info for all calendars
                let mut all = PhpArray::new();
                for c in 0..=3 {
                    if let Ok(info) = php_rs_ext_calendar::cal_info(c) {
                        let mut arr = PhpArray::new();
                        let mut months = PhpArray::new();
                        let mut abbrev = PhpArray::new();
                        for (i, name) in info.long_months.iter().enumerate() {
                            if i > 0 && !name.is_empty() {
                                months.set_int(i as i64, Value::String(name.clone()));
                                if i < info.short_months.len() {
                                    abbrev.set_int(
                                        i as i64,
                                        Value::String(info.short_months[i].clone()),
                                    );
                                }
                            }
                        }
                        arr.set_string("months".into(), Value::Array(months));
                        arr.set_string("abbrevmonths".into(), Value::Array(abbrev));
                        arr.set_string(
                            "maxdaysinmonth".into(),
                            Value::Long(info.maxdaysinmonth as i64),
                        );
                        arr.set_string("calname".into(), Value::String(info.calname));
                        arr.set_string("calsymbol".into(), Value::String(info.calsymbol));
                        all.push(Value::Array(arr));
                    }
                }
                Ok(Some(Value::Array(all)))
            } else if let Ok(info) = php_rs_ext_calendar::cal_info(cal) {
                let mut arr = PhpArray::new();
                let mut months = PhpArray::new();
                let mut abbrev = PhpArray::new();
                for (i, name) in info.long_months.iter().enumerate() {
                    if i > 0 && !name.is_empty() {
                        months.set_int(i as i64, Value::String(name.clone()));
                        if i < info.short_months.len() {
                            abbrev.set_int(i as i64, Value::String(info.short_months[i].clone()));
                        }
                    }
                }
                arr.set_string("months".into(), Value::Array(months));
                arr.set_string("abbrevmonths".into(), Value::Array(abbrev));
                arr.set_string(
                    "maxdaysinmonth".into(),
                    Value::Long(info.maxdaysinmonth as i64),
                );
                arr.set_string("calname".into(), Value::String(info.calname));
                arr.set_string("calsymbol".into(), Value::String(info.calsymbol));
                Ok(Some(Value::Array(arr)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gregoriantojd" => {
            let month = args.first().map(|v| v.to_long() as i32).unwrap_or(1);
            let day = args.get(1).map(|v| v.to_long() as i32).unwrap_or(1);
            let year = args.get(2).map(|v| v.to_long() as i32).unwrap_or(2000);
            let jd = php_rs_ext_calendar::gregoriantojd(month, day, year);
            Ok(Some(Value::Long(jd)))
        }
        "jdtogregorian" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let (month, day, year) = php_rs_ext_calendar::jdtogregorian(jd);
            Ok(Some(Value::String(format!("{}/{}/{}", month, day, year))))
        }
        "juliantojd" => {
            let month = args.first().map(|v| v.to_long() as i32).unwrap_or(1);
            let day = args.get(1).map(|v| v.to_long() as i32).unwrap_or(1);
            let year = args.get(2).map(|v| v.to_long() as i32).unwrap_or(2000);
            let jd = php_rs_ext_calendar::juliantojd(month, day, year);
            Ok(Some(Value::Long(jd)))
        }
        "jdtojulian" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let (month, day, year) = php_rs_ext_calendar::jdtojulian(jd);
            Ok(Some(Value::String(format!("{}/{}/{}", month, day, year))))
        }
        "cal_to_jd" => {
            let cal = args.first().map(|v| v.to_long() as i32).unwrap_or(0);
            let month = args.get(1).map(|v| v.to_long() as i32).unwrap_or(1);
            let day = args.get(2).map(|v| v.to_long() as i32).unwrap_or(1);
            let year = args.get(3).map(|v| v.to_long() as i32).unwrap_or(2000);
            match php_rs_ext_calendar::cal_to_jd(cal, month, day, year) {
                Ok(jd) => Ok(Some(Value::Long(jd))),
                Err(_) => Ok(Some(Value::Long(0))),
            }
        }
        "cal_from_jd" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let cal = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
            match php_rs_ext_calendar::cal_from_jd(jd, cal) {
                Ok(info) => {
                    let mut arr = PhpArray::new();
                    arr.set_string(
                        "date".into(),
                        Value::String(format!("{}/{}/{}", info.month, info.day, info.year)),
                    );
                    arr.set_string("month".into(), Value::Long(info.month as i64));
                    arr.set_string("day".into(), Value::Long(info.day as i64));
                    arr.set_string("year".into(), Value::Long(info.year as i64));
                    arr.set_string("dow".into(), Value::Long(info.dow as i64));
                    arr.set_string("abbrevdayname".into(), Value::String(info.abbrevdayname));
                    arr.set_string("dayname".into(), Value::String(info.dayname));
                    arr.set_string("abbrevmonth".into(), Value::String(info.abbrevmonth));
                    arr.set_string("monthname".into(), Value::String(info.monthname));
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "jddayofweek" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let mode = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
            match php_rs_ext_calendar::jddayofweek(jd, mode) {
                php_rs_ext_calendar::DayOfWeekResult::Number(n) => Ok(Some(Value::Long(n as i64))),
                php_rs_ext_calendar::DayOfWeekResult::Name(s) => Ok(Some(Value::String(s))),
            }
        }
        "jdmonthname" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let mode = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
            let name = php_rs_ext_calendar::jdmonthname(jd, mode);
            Ok(Some(Value::String(name)))
        }
        "unixtojd" => {
            let ts = args.first().map(|v| v.to_long()).unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });
            let jd = php_rs_ext_calendar::unixtojd(ts);
            Ok(Some(Value::Long(jd)))
        }
        "jdtounix" => {
            let jd = args.first().map(|v| v.to_long()).unwrap_or(0);
            let ts = php_rs_ext_calendar::jdtounix(jd);
            Ok(Some(Value::Long(ts)))
        }
        "easter_date" => {
            let year = args.first().map(|v| v.to_long() as i32).unwrap_or_else(|| {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let (y, _, _, _, _, _, _, _) = timestamp_to_parts(ts);
                y as i32
            });
            let ts = php_rs_ext_calendar::easter_date(year);
            Ok(Some(Value::Long(ts)))
        }
        "easter_days" => {
            let year = args.first().map(|v| v.to_long() as i32).unwrap_or_else(|| {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let (y, _, _, _, _, _, _, _) = timestamp_to_parts(ts);
                y as i32
            });
            let method = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
            let days = php_rs_ext_calendar::easter_days(year, method);
            Ok(Some(Value::Long(days as i64)))
        }
        "frenchtojd" | "jewishtojd" => {
            // Stub — return 0
            Ok(Some(Value::Long(0)))
        }
        "jdtofrench" | "jdtojewish" => Ok(Some(Value::String("0/0/0".to_string()))),
        "mb_convert_kana" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "mb_convert_variables" => {
            let to_enc = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(to_enc)))
        }
        "mb_regex_set_options" => Ok(Some(Value::String("msr".into()))),
        "mb_str_pad" => {
            let input = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let length = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
            let pad = args
                .get(2)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| " ".to_string());
            let pad_type = args.get(3).map(|v| v.to_long()).unwrap_or(1); // STR_PAD_RIGHT
            let cur_len = input.chars().count();
            if cur_len >= length {
                return Ok(Some(Value::String(input)));
            }
            let diff = length - cur_len;
            let pad_chars: Vec<char> = pad.chars().collect();
            if pad_chars.is_empty() {
                return Ok(Some(Value::String(input)));
            }
            let pad_str: String = pad_chars.iter().cycle().take(diff).collect();
            match pad_type {
                0 => Ok(Some(Value::String(format!("{}{}", pad_str, input)))), // STR_PAD_LEFT (note: PHP constant is actually 0)
                2 => {
                    // STR_PAD_BOTH
                    let left = diff / 2;
                    let right = diff - left;
                    let left_str: String = pad_chars.iter().cycle().take(left).collect();
                    let right_str: String = pad_chars.iter().cycle().take(right).collect();
                    Ok(Some(Value::String(format!(
                        "{}{}{}",
                        left_str, input, right_str
                    ))))
                }
                _ => Ok(Some(Value::String(format!("{}{}", input, pad_str)))), // STR_PAD_RIGHT
            }
        }
        "mb_str_contains" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.contains(&needle))))
        }
        "mb_str_starts_with" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.starts_with(&needle))))
        }
        "mb_str_ends_with" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.ends_with(&needle))))
        }
        "mb_strrchr" | "mb_strrichr" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let before = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
            let h_lower = haystack.to_lowercase();
            let n_lower = needle.to_lowercase();
            let pos = if name.contains("rch") || name.contains("rstr") {
                h_lower.rfind(&n_lower)
            } else {
                h_lower.find(&n_lower)
            };
            match pos {
                Some(p) => {
                    if before {
                        Ok(Some(Value::String(haystack[..p].to_string())))
                    } else {
                        Ok(Some(Value::String(haystack[p..].to_string())))
                    }
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // === Session extension (23 functions) — stubs ===
        "session_start" => {
            if vm.session_started {
                // Already active.
                return Ok(Some(Value::Bool(true)));
            }
            // Get or generate session ID.
            // Check $_COOKIE['PHPSESSID'] in main frame.
            let sid_from_cookie: Option<String> = (|| {
                let frame = vm.call_stack.first()?;
                let oa = vm.op_arrays.first()?;
                let idx = oa.vars.iter().position(|v| v == "_COOKIE")?;
                match frame.cvs.get(idx) {
                    Some(Value::Array(a)) => {
                        for (key, val) in a.entries() {
                            if matches!(key, crate::value::ArrayKey::String(s) if s == "PHPSESSID")
                            {
                                return Some(val.to_php_string());
                            }
                        }
                        None
                    }
                    _ => None,
                }
            })();
            if let Some(sid) = sid_from_cookie {
                if !sid.is_empty() {
                    vm.session_id = sid;
                }
            }
            if vm.session_id.is_empty() {
                vm.session_id = Vm::generate_session_id();
            }

            // Use custom save handler if registered
            if let Some(ref handler) = vm.session_save_handler.clone() {
                // Call open(save_path, session_name)
                let _ = vm.invoke_user_callback(
                    &handler.open,
                    vec![
                        Value::String(vm.session_save_path.clone()),
                        Value::String("PHPSESSID".to_string()),
                    ],
                );
                // Call read(session_id)
                let session_data = match vm
                    .invoke_user_callback(&handler.read, vec![Value::String(vm.session_id.clone())])
                {
                    Ok(Value::String(s)) => session_unserialize(&s),
                    _ => crate::value::PhpArray::new(),
                };
                vm.set_session_cv(session_data);
            } else {
                // Default file-based handler
                let path = vm.session_file_path(&vm.session_id.clone());
                let session_data = if let Ok(data) = std::fs::read_to_string(&path) {
                    session_unserialize(&data)
                } else {
                    crate::value::PhpArray::new()
                };
                vm.set_session_cv(session_data);
            }

            vm.session_started = true;
            // Set Set-Cookie header if this is a new session.
            vm.response_headers
                .push(format!("Set-Cookie: PHPSESSID={}; Path=/", vm.session_id));
            Ok(Some(Value::Bool(true)))
        }
        "session_destroy" => {
            if !vm.session_started {
                return Ok(Some(Value::Bool(false)));
            }

            if let Some(ref handler) = vm.session_save_handler.clone() {
                // Call destroy(session_id)
                let _ = vm.invoke_user_callback(
                    &handler.destroy,
                    vec![Value::String(vm.session_id.clone())],
                );
                // Call close()
                let _ = vm.invoke_user_callback(&handler.close, vec![]);
            } else {
                let path = vm.session_file_path(&vm.session_id.clone());
                #[cfg(not(target_arch = "wasm32"))]
                let _ = std::fs::remove_file(&path);
            }

            vm.session_started = false;
            vm.session_id.clear();
            vm.set_session_cv(crate::value::PhpArray::new());
            Ok(Some(Value::Bool(true)))
        }
        "session_id" => {
            let old_id = vm.session_id.clone();
            if let Some(new_id) = args.first().map(|v| v.to_php_string()) {
                if !new_id.is_empty() {
                    vm.session_id = new_id;
                }
            }
            Ok(Some(Value::String(old_id)))
        }
        "session_name" => {
            // We always use PHPSESSID; setting is a no-op for now.
            Ok(Some(Value::String("PHPSESSID".into())))
        }
        "session_status" => {
            // PHP_SESSION_DISABLED=0, PHP_SESSION_NONE=1, PHP_SESSION_ACTIVE=2
            if vm.session_started {
                Ok(Some(Value::Long(2)))
            } else {
                Ok(Some(Value::Long(1)))
            }
        }
        "session_regenerate_id" => {
            let delete_old = args.first().map(|v| v.to_bool()).unwrap_or(false);
            if delete_old && !vm.session_id.is_empty() {
                let old_path = vm.session_file_path(&vm.session_id.clone());
                #[cfg(not(target_arch = "wasm32"))]
                let _ = std::fs::remove_file(&old_path);
            }
            vm.session_id = Vm::generate_session_id();
            if vm.session_started {
                vm.response_headers
                    .push(format!("Set-Cookie: PHPSESSID={}; Path=/", vm.session_id));
            }
            Ok(Some(Value::Bool(true)))
        }
        "session_encode" => {
            let data = vm.get_session_cv().unwrap_or_default();
            Ok(Some(Value::String(session_serialize(&data))))
        }
        "session_decode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let data = session_unserialize(&s);
            vm.set_session_cv(data);
            Ok(Some(Value::Bool(true)))
        }
        "session_unset" => {
            vm.set_session_cv(crate::value::PhpArray::new());
            Ok(Some(Value::Bool(true)))
        }
        "session_gc" => Ok(Some(Value::Long(0))),
        "session_create_id" => {
            let prefix = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let id = format!("{}{:032x}", prefix, ts);
            Ok(Some(Value::String(id)))
        }
        "session_cache_expire" => {
            let old = vm.session_cache_expire;
            if let Some(new_val) = args.first() {
                vm.session_cache_expire = new_val.to_long();
            }
            Ok(Some(Value::Long(old)))
        }
        "session_cache_limiter" => {
            let old = vm.session_cache_limiter.clone();
            if let Some(new_val) = args.first() {
                let s = new_val.to_php_string();
                if !s.is_empty() {
                    vm.session_cache_limiter = s;
                }
            }
            Ok(Some(Value::String(old)))
        }
        "session_save_path" => {
            let old_path = vm.session_save_path.clone();
            if let Some(path) = args.first().map(|v| v.to_php_string()) {
                if !path.is_empty() {
                    vm.session_save_path = path;
                }
            }
            Ok(Some(Value::String(old_path)))
        }
        "session_module_name" => Ok(Some(Value::String("files".into()))),
        "session_set_cookie_params" => {
            // Accepts either positional args or an options array
            if let Some(first) = args.first() {
                if let Value::Array(ref opts) = first {
                    // Array form: session_set_cookie_params([...])
                    if let Some(v) = opts.get_string("lifetime") {
                        vm.session_cookie_params.lifetime = v.to_long();
                    }
                    if let Some(v) = opts.get_string("path") {
                        vm.session_cookie_params.path = v.to_php_string();
                    }
                    if let Some(v) = opts.get_string("domain") {
                        vm.session_cookie_params.domain = v.to_php_string();
                    }
                    if let Some(v) = opts.get_string("secure") {
                        vm.session_cookie_params.secure = v.to_bool();
                    }
                    if let Some(v) = opts.get_string("httponly") {
                        vm.session_cookie_params.httponly = v.to_bool();
                    }
                    if let Some(v) = opts.get_string("samesite") {
                        vm.session_cookie_params.samesite = v.to_php_string();
                    }
                } else {
                    // Positional form: session_set_cookie_params(lifetime, path, domain, secure, httponly)
                    vm.session_cookie_params.lifetime = first.to_long();
                    if let Some(v) = args.get(1) {
                        vm.session_cookie_params.path = v.to_php_string();
                    }
                    if let Some(v) = args.get(2) {
                        vm.session_cookie_params.domain = v.to_php_string();
                    }
                    if let Some(v) = args.get(3) {
                        vm.session_cookie_params.secure = v.to_bool();
                    }
                    if let Some(v) = args.get(4) {
                        vm.session_cookie_params.httponly = v.to_bool();
                    }
                }
            }
            Ok(Some(Value::Bool(true)))
        }
        "session_get_cookie_params" => {
            let p = &vm.session_cookie_params;
            let mut arr = PhpArray::new();
            arr.set_string("lifetime".into(), Value::Long(p.lifetime));
            arr.set_string("path".into(), Value::String(p.path.clone()));
            arr.set_string("domain".into(), Value::String(p.domain.clone()));
            arr.set_string("secure".into(), Value::Bool(p.secure));
            arr.set_string("httponly".into(), Value::Bool(p.httponly));
            arr.set_string("samesite".into(), Value::String(p.samesite.clone()));
            Ok(Some(Value::Array(arr)))
        }
        "session_set_save_handler" => {
            // Two forms:
            // 1. session_set_save_handler(SessionHandlerInterface $handler, bool $register_shutdown = true)
            // 2. session_set_save_handler(callable $open, callable $close, callable $read,
            //        callable $write, callable $destroy, callable $gc,
            //        callable $create_sid = null, callable $validate_sid = null, callable $update_timestamp = null)
            if args.is_empty() {
                return Ok(Some(Value::Bool(false)));
            }
            match &args[0] {
                Value::Object(obj) => {
                    // Form 1: object implementing SessionHandlerInterface
                    let class_name = obj.class_name().to_string();
                    let handler = crate::vm::SessionSaveHandler {
                        open: format!("{}::open", class_name),
                        close: format!("{}::close", class_name),
                        read: format!("{}::read", class_name),
                        write: format!("{}::write", class_name),
                        destroy: format!("{}::destroy", class_name),
                        gc: format!("{}::gc", class_name),
                        create_sid: None,
                        validate_sid: None,
                        update_timestamp: None,
                    };
                    vm.session_save_handler = Some(handler);
                    Ok(Some(Value::Bool(true)))
                }
                _ => {
                    // Form 2: individual callables
                    let open = args.first().map(|v| v.to_php_string()).unwrap_or_default();
                    let close = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                    let read = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                    let write = args.get(3).map(|v| v.to_php_string()).unwrap_or_default();
                    let destroy = args.get(4).map(|v| v.to_php_string()).unwrap_or_default();
                    let gc = args.get(5).map(|v| v.to_php_string()).unwrap_or_default();
                    let create_sid = args.get(6).map(|v| v.to_php_string());
                    let validate_sid = args.get(7).map(|v| v.to_php_string());
                    let update_timestamp = args.get(8).map(|v| v.to_php_string());
                    let handler = crate::vm::SessionSaveHandler {
                        open,
                        close,
                        read,
                        write,
                        destroy,
                        gc,
                        create_sid,
                        validate_sid,
                        update_timestamp,
                    };
                    vm.session_save_handler = Some(handler);
                    Ok(Some(Value::Bool(true)))
                }
            }
        }
        "session_write_close" | "session_commit" => {
            if vm.session_started && !vm.session_id.is_empty() {
                let data = vm.get_session_cv().unwrap_or_default();
                let serialized = session_serialize(&data);

                if let Some(ref handler) = vm.session_save_handler.clone() {
                    // Call write(session_id, data)
                    let _ = vm.invoke_user_callback(
                        &handler.write,
                        vec![
                            Value::String(vm.session_id.clone()),
                            Value::String(serialized),
                        ],
                    );
                    // Call close()
                    let _ = vm.invoke_user_callback(&handler.close, vec![]);
                } else {
                    let path = vm.session_file_path(&vm.session_id.clone());
                    #[cfg(not(target_arch = "wasm32"))]
                    let _ = std::fs::write(&path, serialized);
                }
            }
            vm.session_started = false;
            Ok(Some(Value::Bool(true)))
        }
        "session_abort" => Ok(Some(Value::Bool(true))),
        "session_reset" => Ok(Some(Value::Bool(true))),
        "session_register_shutdown" => Ok(Some(Value::Null)),
        "pcntl_unshare" | "pcntl_setns" => Ok(Some(Value::Bool(false))),
        "pcntl_getcpu" | "pcntl_getcpuaffinity" => Ok(Some(Value::Bool(false))),
        "pcntl_setcpuaffinity" => Ok(Some(Value::Bool(false))),

        // === XML extension (22 functions) — stubs ===
        "xml_parser_create" | "xml_parser_create_ns" => Ok(Some(Value::Long(1))),
        "xml_parser_free"
        | "xml_parser_set_option"
        | "xml_set_element_handler"
        | "xml_set_character_data_handler"
        | "xml_set_processing_instruction_handler"
        | "xml_set_default_handler"
        | "xml_set_unparsed_entity_decl_handler"
        | "xml_set_notation_decl_handler"
        | "xml_set_external_entity_ref_handler"
        | "xml_set_start_namespace_decl_handler"
        | "xml_set_end_namespace_decl_handler"
        | "xml_set_object" => Ok(Some(Value::Bool(true))),
        "xml_parse" | "xml_parse_into_struct" => Ok(Some(Value::Long(1))),
        "xml_parser_get_option" => Ok(Some(Value::String(String::new()))),
        "xml_get_current_byte_index"
        | "xml_get_current_column_number"
        | "xml_get_current_line_number" => Ok(Some(Value::Long(0))),
        "xml_get_error_code" => Ok(Some(Value::Long(0))),
        "xml_error_string" => Ok(Some(Value::String("No error".into()))),

        // === libxml (8 functions) — stubs ===
        "libxml_use_internal_errors" => {
            let use_errors = args.first().map(|v| v.to_bool()).unwrap_or(false);
            Ok(Some(Value::Bool(use_errors)))
        }
        "libxml_get_errors" => Ok(Some(Value::Array(PhpArray::new()))),
        "libxml_clear_errors" => Ok(Some(Value::Null)),
        "libxml_get_last_error" => Ok(Some(Value::Bool(false))),
        "libxml_set_streams_context" => Ok(Some(Value::Null)),
        "libxml_set_external_entity_loader" => Ok(Some(Value::Bool(true))),
        "libxml_disable_entity_loader" => Ok(Some(Value::Bool(true))),
        "libxml_get_external_entity_loader" => Ok(Some(Value::Null)),

        // === XMLWriter ===
        "xmlwriter_open_memory" => {
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.xml_writers.insert(id, XmlWriterState::new());
            Ok(Some(Value::Long(id)))
        }
        "xmlwriter_open_uri" => {
            // For now, treat URI-based writers as memory writers
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.xml_writers.insert(id, XmlWriterState::new());
            Ok(Some(Value::Long(id)))
        }
        "xmlwriter_start_document" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                let version = args.get(1).map(|v| v.to_string()).unwrap_or_default();
                let encoding = args.get(2).map(|v| v.to_string());
                let standalone = args.get(3).map(|v| v.to_string());
                w.start_document(&version, encoding.as_deref(), standalone.as_deref());
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_document" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.end_document();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_element" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let name = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.start_element(&name);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_element_ns" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let prefix = args.get(1).map(|v| v.to_string());
            let name = args.get(2).map(|v| v.to_string()).unwrap_or_default();
            let uri = args.get(3).map(|v| v.to_string());
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.start_element_ns(prefix.as_deref(), &name, uri.as_deref());
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_element" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.end_element();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_full_end_element" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.full_end_element();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_element" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let name = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let content = args.get(2).map(|v| v.to_string());
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.start_element(&name);
                if let Some(text) = content {
                    w.write_text(&text);
                }
                w.end_element();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_element_ns" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let prefix = args.get(1).map(|v| v.to_string());
            let name = args.get(2).map(|v| v.to_string()).unwrap_or_default();
            let uri = args.get(3).map(|v| v.to_string());
            let content = args.get(4).map(|v| v.to_string());
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.start_element_ns(prefix.as_deref(), &name, uri.as_deref());
                if let Some(text) = content {
                    w.write_text(&text);
                }
                w.end_element();
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_attribute" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            // start_attribute just means the next text() will go into the attribute
            // For simplicity, we handle this as a no-op since write_attribute is the common path
            if vm.xml_writers.contains_key(&id) {
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_attribute" | "xmlwriter_start_attribute_ns" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if vm.xml_writers.contains_key(&id) {
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_attribute" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let name = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let value = args.get(2).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_attribute(&name, &value);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_attribute_ns" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let prefix = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let name = args.get(2).map(|v| v.to_string()).unwrap_or_default();
            let _uri = args.get(3).map(|v| v.to_string());
            let value = args.get(4).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                let attr_name = if prefix.is_empty() {
                    name
                } else {
                    format!("{}:{}", prefix, name)
                };
                w.write_attribute(&attr_name, &value);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_text" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let text = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_text(&text);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_raw" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let raw = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_raw(&raw);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_cdata" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.close_start_tag();
                w.buf.push_str("<![CDATA[");
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_cdata" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.buf.push_str("]]>");
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_cdata" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let text = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_cdata(&text);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_comment" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.close_start_tag();
                w.buf.push_str("<!-- ");
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_comment" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.buf.push_str(" -->");
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_comment" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let text = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_comment(&text);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_pi" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let target = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.close_start_tag();
                w.buf.push_str("<?");
                w.buf.push_str(&target);
                w.buf.push(' ');
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_end_pi" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.buf.push_str("?>");
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_write_pi" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let target = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            let content = args.get(2).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.write_pi(&target, &content);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_set_indent" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let enable = args.get(1).map(|v| v.is_truthy()).unwrap_or(false);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.indent = enable;
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_set_indent_string" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let s = args.get(1).map(|v| v.to_string()).unwrap_or_default();
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                w.indent_string = s;
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_output_memory" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let flush = args.get(1).map(|v| v.is_truthy()).unwrap_or(true);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                let output = w.output_memory(flush);
                Ok(Some(Value::String(output)))
            } else {
                Ok(Some(Value::String(String::new())))
            }
        }
        "xmlwriter_flush" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(w) = vm.xml_writers.get_mut(&id) {
                let output = w.output_memory(true);
                // For memory-based writers, flush returns the content
                Ok(Some(Value::String(output)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "xmlwriter_start_dtd" | "xmlwriter_end_dtd"
        | "xmlwriter_start_dtd_attlist" | "xmlwriter_end_dtd_attlist"
        | "xmlwriter_start_dtd_element" | "xmlwriter_end_dtd_element"
        | "xmlwriter_start_dtd_entity" | "xmlwriter_end_dtd_entity"
        | "xmlwriter_write_dtd" | "xmlwriter_write_dtd_attlist"
        | "xmlwriter_write_dtd_element" | "xmlwriter_write_dtd_entity" => {
            // DTD functions: stub for now (rarely used)
            Ok(Some(Value::Bool(true)))
        }

        // === readline (13 functions) — stubs ===
        "readline" => {
            let prompt = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if !prompt.is_empty() {
                vm.write_output(&prompt);
            }
            Ok(Some(Value::String(String::new())))
        }
        "readline_add_history"
        | "readline_clear_history"
        | "readline_write_history"
        | "readline_read_history" => Ok(Some(Value::Bool(true))),
        "readline_info" => Ok(Some(Value::String(String::new()))),
        "readline_completion_function" => Ok(Some(Value::Bool(true))),
        "readline_callback_handler_install"
        | "readline_callback_handler_remove"
        | "readline_callback_read_char"
        | "readline_on_new_line"
        | "readline_redisplay" => Ok(Some(Value::Bool(true))),
        "readline_list_history" => Ok(Some(Value::Array(PhpArray::new()))),

        // === zlib (30 functions) — stubs ===
        "gzcompress" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let level = args.get(1).map(|v| v.to_long() as i32).unwrap_or(-1);
            let compressed = php_rs_ext_zlib::gzcompress(data.as_bytes(), level);
            Ok(Some(Value::String(bytes_to_php_string(&compressed))))
        }
        "gzuncompress" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let bytes = php_string_to_bytes(&data);
            match php_rs_ext_zlib::gzuncompress(&bytes) {
                Ok(result) => Ok(Some(Value::String(bytes_to_php_string(&result)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "gzdecode" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let bytes = php_string_to_bytes(&data);
            match php_rs_ext_zlib::gzdecode(&bytes) {
                Ok(result) => Ok(Some(Value::String(bytes_to_php_string(&result)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "gzinflate" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let bytes = php_string_to_bytes(&data);
            match php_rs_ext_zlib::gzinflate(&bytes) {
                Ok(result) => Ok(Some(Value::String(bytes_to_php_string(&result)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "gzencode" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let level = args.get(1).map(|v| v.to_long() as i32).unwrap_or(-1);
            let encoded = php_rs_ext_zlib::gzencode(data.as_bytes(), level);
            Ok(Some(Value::String(bytes_to_php_string(&encoded))))
        }
        "gzdeflate" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let level = args.get(1).map(|v| v.to_long() as i32).unwrap_or(-1);
            let deflated = php_rs_ext_zlib::gzdeflate(data.as_bytes(), level);
            Ok(Some(Value::String(bytes_to_php_string(&deflated))))
        }
        "gzopen" => {
            let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mode = args.get(1).cloned().unwrap_or(Value::String("r".to_string())).to_php_string();
            let is_write = mode.starts_with('w');
            let level = if mode.len() > 1 {
                mode.chars().find(|c| c.is_ascii_digit())
                    .map(|c| c.to_digit(10).unwrap() as i32)
                    .unwrap_or(-1)
            } else {
                -1
            };

            if is_write {
                // Writing mode: create empty buffer, flush on close
                let gz = crate::vm::GzFileHandle {
                    data: Vec::new(),
                    pos: 0,
                    writable: true,
                    path: filename,
                    level,
                };
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.gz_handles.insert(id, gz);
                Ok(Some(Value::Resource(id, "stream".to_string())))
            } else {
                // Reading mode: read and decompress file
                match std::fs::read(&filename) {
                    Ok(compressed) => {
                        let decompressed = php_rs_ext_zlib::gzdecode(&compressed)
                            .unwrap_or_else(|_| compressed);
                        let gz = crate::vm::GzFileHandle {
                            data: decompressed,
                            pos: 0,
                            writable: false,
                            path: filename,
                            level,
                        };
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.gz_handles.insert(id, gz);
                        Ok(Some(Value::Resource(id, "stream".to_string())))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
        }
        "gzclose" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(gz) = vm.gz_handles.remove(&id) {
                if gz.writable && !gz.path.is_empty() {
                    let compressed = php_rs_ext_zlib::gzencode(&gz.data, gz.level);
                    let _ = std::fs::write(&gz.path, &compressed);
                }
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzeof" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(true))),
            };
            if let Some(gz) = vm.gz_handles.get(&id) {
                Ok(Some(Value::Bool(gz.pos >= gz.data.len())))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "gzrewind" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                gz.pos = 0;
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzread" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let length = args.get(1).map(|v| v.to_long() as usize).unwrap_or(4096);
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                let end = (gz.pos + length).min(gz.data.len());
                let chunk = &gz.data[gz.pos..end];
                let s = bytes_to_php_string(chunk);
                gz.pos = end;
                Ok(Some(Value::String(s)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzgets" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let max_len = args.get(1).map(|v| v.to_long() as usize).unwrap_or(1024);
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                if gz.pos >= gz.data.len() {
                    return Ok(Some(Value::Bool(false)));
                }
                let remaining = &gz.data[gz.pos..];
                let end = remaining.iter().position(|&b| b == b'\n')
                    .map(|p| (p + 1).min(max_len))
                    .unwrap_or_else(|| remaining.len().min(max_len));
                let chunk = &remaining[..end];
                let s = bytes_to_php_string(chunk);
                gz.pos += end;
                Ok(Some(Value::String(s)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzgetc" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                if gz.pos >= gz.data.len() {
                    return Ok(Some(Value::Bool(false)));
                }
                let ch = gz.data[gz.pos];
                gz.pos += 1;
                Ok(Some(Value::String(String::from(ch as char))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzpassthru" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let result = if let Some(gz) = vm.gz_handles.get_mut(&id) {
                let remaining = gz.data[gz.pos..].to_vec();
                let len = remaining.len() as i64;
                let s = bytes_to_php_string(&remaining);
                gz.pos = gz.data.len();
                Some((s, len))
            } else {
                None
            };
            if let Some((s, len)) = result {
                vm.write_output(&s);
                Ok(Some(Value::Long(len)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzwrite" | "gzputs" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let data = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let max_len = args.get(2).map(|v| v.to_long() as usize);
            let bytes = data.as_bytes();
            let to_write = match max_len {
                Some(n) => &bytes[..n.min(bytes.len())],
                None => bytes,
            };
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                gz.data.extend_from_slice(to_write);
                gz.pos = gz.data.len();
                Ok(Some(Value::Long(to_write.len() as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzseek" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Long(-1))),
            };
            let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let whence = args.get(2).map(|v| v.to_long()).unwrap_or(0); // SEEK_SET=0
            if let Some(gz) = vm.gz_handles.get_mut(&id) {
                let new_pos = match whence {
                    1 => gz.pos as i64 + offset, // SEEK_CUR
                    _ => offset,                 // SEEK_SET
                };
                if new_pos >= 0 {
                    gz.pos = new_pos as usize;
                    Ok(Some(Value::Long(0)))
                } else {
                    Ok(Some(Value::Long(-1)))
                }
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "gztell" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(gz) = vm.gz_handles.get(&id) {
                Ok(Some(Value::Long(gz.pos as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "gzfile" => {
            // Read entire gzip file into array of lines
            let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match std::fs::read(&filename) {
                Ok(compressed) => {
                    let decompressed = php_rs_ext_zlib::gzdecode(&compressed)
                        .unwrap_or_else(|_| compressed);
                    let text = String::from_utf8_lossy(&decompressed);
                    let mut arr = PhpArray::new();
                    for line in text.split('\n') {
                        // PHP gzfile includes the newline in each line
                        arr.push(Value::String(format!("{}\n", line)));
                    }
                    // Remove trailing empty line artifact
                    let len = arr.len();
                    if len > 0 {
                        if let Some(Value::String(s)) = arr.get(&Value::Long(len as i64 - 1)) {
                            if s == "\n" {
                                arr.pop();
                            }
                        }
                    }
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "deflate_init" => {
            let encoding = args.first().map(|v| v.to_long() as i32).unwrap_or(php_rs_ext_zlib::ZLIB_ENCODING_DEFLATE);
            let level = if let Some(Value::Array(ref opts)) = args.get(1) {
                opts.get(&Value::String("level".to_string()))
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(-1)
            } else {
                -1
            };
            let ctx = crate::vm::DeflateContext {
                buffer: Vec::new(),
                encoding,
                level,
            };
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.deflate_contexts.insert(id, ctx);
            Ok(Some(Value::Resource(id, "deflate".to_string())))
        }
        "deflate_add" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let data = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let flush = args.get(2).map(|v| v.to_long() as i32).unwrap_or(php_rs_ext_zlib::ZLIB_SYNC_FLUSH);
            if let Some(ctx) = vm.deflate_contexts.get_mut(&id) {
                // Compress the data chunk according to encoding
                let compressed = match ctx.encoding {
                    php_rs_ext_zlib::ZLIB_ENCODING_RAW => php_rs_ext_zlib::gzdeflate(data.as_bytes(), ctx.level),
                    php_rs_ext_zlib::ZLIB_ENCODING_GZIP => php_rs_ext_zlib::gzencode(data.as_bytes(), ctx.level),
                    _ => php_rs_ext_zlib::gzcompress(data.as_bytes(), ctx.level),
                };
                // For ZLIB_FINISH, return all compressed data
                // For SYNC_FLUSH, return compressed chunk
                let _ = flush; // flush mode is handled by the compression call
                Ok(Some(Value::String(bytes_to_php_string(&compressed))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "inflate_init" => {
            let encoding = args.first().map(|v| v.to_long() as i32).unwrap_or(php_rs_ext_zlib::ZLIB_ENCODING_DEFLATE);
            let ctx = crate::vm::InflateContext {
                buffer: Vec::new(),
                encoding,
                bytes_read: 0,
            };
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.inflate_contexts.insert(id, ctx);
            Ok(Some(Value::Resource(id, "inflate".to_string())))
        }
        "inflate_add" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let data_str = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let data_bytes = php_string_to_bytes(&data_str);
            if let Some(ctx) = vm.inflate_contexts.get_mut(&id) {
                ctx.bytes_read += data_bytes.len();
                let result = match ctx.encoding {
                    php_rs_ext_zlib::ZLIB_ENCODING_RAW => php_rs_ext_zlib::gzinflate(&data_bytes),
                    php_rs_ext_zlib::ZLIB_ENCODING_GZIP => php_rs_ext_zlib::gzdecode(&data_bytes),
                    _ => php_rs_ext_zlib::gzuncompress(&data_bytes),
                };
                match result {
                    Ok(decompressed) => Ok(Some(Value::String(bytes_to_php_string(&decompressed)))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "inflate_get_read_len" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(ctx) = vm.inflate_contexts.get(&id) {
                Ok(Some(Value::Long(ctx.bytes_read as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "inflate_get_status" => {
            Ok(Some(Value::Long(0))) // ZLIB_OK
        }
        "zlib_encode" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let encoding = args
                .get(1)
                .map(|v| v.to_long() as i32)
                .unwrap_or(php_rs_ext_zlib::ZLIB_ENCODING_DEFLATE);
            let level = args.get(2).map(|v| v.to_long() as i32).unwrap_or(-1);
            match php_rs_ext_zlib::zlib_encode(data.as_bytes(), encoding, level) {
                Ok(result) => Ok(Some(Value::String(bytes_to_php_string(&result)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "zlib_decode" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_zlib::zlib_decode(data.as_bytes()) {
                Ok(result) => Ok(Some(Value::String(bytes_to_php_string(&result)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "zlib_get_coding_type" => Ok(Some(Value::Bool(false))),
        "ob_gzhandler" => {
            // ob_gzhandler(string $data, int $flags): string|false
            // When used as an ob_start callback, it receives buffer data and mode flags.
            // Without a real zlib implementation, we pass through the data unchanged
            // but set the Content-Encoding header to indicate gzip support.
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            // PHP_OUTPUT_HANDLER_START = 1 — first call, set headers
            if flags & 1 != 0 {
                vm.response_headers
                    .push("Content-Encoding: identity".to_string());
                vm.response_headers
                    .push("Vary: Accept-Encoding".to_string());
            }
            Ok(Some(Value::String(data)))
        }

        // === zip (10 functions) — stubs ===
        "zip_open" | "zip_close" | "zip_read" | "zip_entry_open" | "zip_entry_close"
        | "zip_entry_read" => Ok(Some(Value::Bool(false))),
        "zip_entry_name" | "zip_entry_compressionmethod" => Ok(Some(Value::String(String::new()))),
        "zip_entry_filesize" | "zip_entry_compressedsize" => Ok(Some(Value::Long(0))),

        // (shmop/sysv stubs removed — now handled by real implementations below)

        // === tidy (24 functions) — stubs ===
        "tidy_access_count" | "tidy_config_count" | "tidy_error_count" | "tidy_warning_count" => {
            Ok(Some(Value::Long(0)))
        }
        "tidy_clean_repair" | "tidy_diagnose" | "tidy_is_xhtml" | "tidy_is_xml" => {
            Ok(Some(Value::Bool(false)))
        }
        "tidy_get_body" | "tidy_get_head" | "tidy_get_html" | "tidy_get_root" => {
            Ok(Some(Value::Null))
        }
        "tidy_get_output" | "tidy_get_error_buffer" => Ok(Some(Value::String(String::new()))),
        "tidy_get_html_ver" => Ok(Some(Value::Long(0))),
        "tidy_get_opt_doc" => Ok(Some(Value::String(String::new()))),
        "tidy_get_release" => Ok(Some(Value::String("0.0.0".into()))),
        "tidy_get_status" => Ok(Some(Value::Long(0))),
        "tidy_getopt" => Ok(Some(Value::Bool(false))),
        "tidy_parse_file" | "tidy_parse_string" | "tidy_repair_file" | "tidy_repair_string" => {
            Ok(Some(Value::Bool(false)))
        }
        "tidy_reset_config" | "tidy_save_config" => Ok(Some(Value::Bool(false))),
        "tidy_set_encoding" => Ok(Some(Value::Bool(true))),

        // (snmp/socket stubs removed — now handled by real implementations below)

        // === opcache (8 functions) — stubs ===
        "opcache_compile_file"
        | "opcache_invalidate"
        | "opcache_is_script_cached"
        | "opcache_is_script_cached_in_file_cache"
        | "opcache_reset" => Ok(Some(Value::Bool(true))),
        "opcache_jit_blacklist" => Ok(Some(Value::Bool(true))),
        "mb_get_info" => {
            let mut arr = PhpArray::new();
            arr.set_string("internal_encoding".into(), Value::String("UTF-8".into()));
            arr.set_string("http_input".into(), Value::String("pass".into()));
            arr.set_string("http_output".into(), Value::String("pass".into()));
            arr.set_string("language".into(), Value::String("neutral".into()));
            Ok(Some(Value::Array(arr)))
        }
        "mb_lcfirst" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            if s.is_empty() {
                return Ok(Some(Value::String(s)));
            }
            let mut chars = s.chars();
            let first = chars.next().unwrap().to_lowercase().to_string();
            Ok(Some(Value::String(format!("{}{}", first, chars.as_str()))))
        }
        "mb_ucfirst" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            if s.is_empty() {
                return Ok(Some(Value::String(s)));
            }
            let mut chars = s.chars();
            let first = chars.next().unwrap().to_uppercase().to_string();
            Ok(Some(Value::String(format!("{}{}", first, chars.as_str()))))
        }
        "mb_ltrim" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let chars = args.get(1).map(|v| v.to_php_string());
            match chars {
                Some(c) => {
                    let chars: Vec<char> = c.chars().collect();
                    Ok(Some(Value::String(
                        s.trim_start_matches(|ch: char| chars.contains(&ch))
                            .to_string(),
                    )))
                }
                None => Ok(Some(Value::String(s.trim_start().to_string()))),
            }
        }
        "mb_rtrim" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let chars = args.get(1).map(|v| v.to_php_string());
            match chars {
                Some(c) => {
                    let chars: Vec<char> = c.chars().collect();
                    Ok(Some(Value::String(
                        s.trim_end_matches(|ch: char| chars.contains(&ch))
                            .to_string(),
                    )))
                }
                None => Ok(Some(Value::String(s.trim_end().to_string()))),
            }
        }
        "mb_trim" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let chars = args.get(1).map(|v| v.to_php_string());
            match chars {
                Some(c) => {
                    let chars: Vec<char> = c.chars().collect();
                    Ok(Some(Value::String(
                        s.trim_matches(|ch: char| chars.contains(&ch)).to_string(),
                    )))
                }
                None => Ok(Some(Value::String(s.trim().to_string()))),
            }
        }
        "mb_split" => {
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let mut arr = PhpArray::new();
            for part in string.split(&pattern) {
                arr.push(Value::String(part.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }

        // === Finish tidy (1 missing) ===
        "tidy_get_config" => Ok(Some(Value::Array(PhpArray::new()))),

        // === Finish sockets (3 missing) ===
        "socket_wsaprotocol_info_export"
        | "socket_wsaprotocol_info_import"
        | "socket_wsaprotocol_info_release" => Ok(Some(Value::Bool(false))),

        // === bz2 extension (10 functions) ===
        "bzopen" => {
            let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mode = args.get(1).cloned().unwrap_or(Value::String("r".to_string())).to_php_string();
            let is_write = mode.starts_with('w');

            if is_write {
                let bz = crate::vm::BzFileHandle {
                    data: Vec::new(),
                    pos: 0,
                    writable: true,
                    path: filename,
                };
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.bz_handles.insert(id, bz);
                Ok(Some(Value::Resource(id, "stream".to_string())))
            } else {
                match std::fs::read(&filename) {
                    Ok(compressed) => {
                        let decompressed = php_rs_ext_bz2::bzdecompress(&compressed, false)
                            .unwrap_or_else(|_| compressed);
                        let bz = crate::vm::BzFileHandle {
                            data: decompressed,
                            pos: 0,
                            writable: false,
                            path: filename,
                        };
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.bz_handles.insert(id, bz);
                        Ok(Some(Value::Resource(id, "stream".to_string())))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
        }
        "bzclose" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            if let Some(bz) = vm.bz_handles.remove(&id) {
                if bz.writable && !bz.path.is_empty() {
                    let compressed = php_rs_ext_bz2::bzcompress(&bz.data, 4, 0);
                    let _ = std::fs::write(&bz.path, &compressed);
                }
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "bzflush" => Ok(Some(Value::Bool(true))),
        "bzread" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let length = args.get(1).map(|v| v.to_long() as usize).unwrap_or(1024);
            if let Some(bz) = vm.bz_handles.get_mut(&id) {
                let end = (bz.pos + length).min(bz.data.len());
                let chunk = &bz.data[bz.pos..end];
                let s = bytes_to_php_string(chunk);
                bz.pos = end;
                Ok(Some(Value::String(s)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "bzwrite" => {
            let id = match args.first() {
                Some(Value::Resource(id, _)) => *id,
                _ => return Ok(Some(Value::Bool(false))),
            };
            let data = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let max_len = args.get(2).map(|v| v.to_long() as usize);
            let bytes = data.as_bytes();
            let to_write = match max_len {
                Some(n) => &bytes[..n.min(bytes.len())],
                None => bytes,
            };
            if let Some(bz) = vm.bz_handles.get_mut(&id) {
                bz.data.extend_from_slice(to_write);
                bz.pos = bz.data.len();
                Ok(Some(Value::Long(to_write.len() as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "bzcompress" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let block_size = args.get(1).map(|v| v.to_long() as u32).unwrap_or(4);
            let work_factor = args.get(2).map(|v| v.to_long() as u32).unwrap_or(0);
            let compressed = php_rs_ext_bz2::bzcompress(data.as_bytes(), block_size, work_factor);
            Ok(Some(Value::String(bytes_to_php_string(&compressed))))
        }
        "bzdecompress" => {
            let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let bytes = php_string_to_bytes(&data);
            match php_rs_ext_bz2::bzdecompress(&bytes, false) {
                Ok(decompressed) => Ok(Some(Value::String(bytes_to_php_string(&decompressed)))),
                Err(_) => Ok(Some(Value::Long(-1))),
            }
        }
        "bzerrno" => Ok(Some(Value::Long(0))),
        "bzerror" => {
            let mut arr = PhpArray::new();
            arr.set_string("errno".into(), Value::Long(0));
            arr.set_string("errstr".into(), Value::String(String::new()));
            Ok(Some(Value::Array(arr)))
        }
        "bzerrstr" => Ok(Some(Value::String(String::new()))),
        "com_event_sink"
        | "com_get_active_object"
        | "com_load_typelib"
        | "com_message_pump"
        | "com_print_typeinfo" => Ok(Some(Value::Bool(false))),
        "variant_abs"
        | "variant_add"
        | "variant_and"
        | "variant_cast"
        | "variant_cat"
        | "variant_cmp"
        | "variant_date_from_timestamp"
        | "variant_date_to_timestamp"
        | "variant_div"
        | "variant_eqv"
        | "variant_fix"
        | "variant_get_type"
        | "variant_idiv"
        | "variant_imp"
        | "variant_int"
        | "variant_mod"
        | "variant_mul"
        | "variant_neg"
        | "variant_not"
        | "variant_or"
        | "variant_pow"
        | "variant_round"
        | "variant_set"
        | "variant_set_type"
        | "variant_sub"
        | "variant_xor" => Ok(Some(Value::Null)),

        // === OpenSSL (66 functions) — stubs ===
        "openssl_cipher_iv_length" => {
            let method = args
                .first()
                .map(|v| v.to_php_string())
                .unwrap_or_default()
                .to_lowercase();
            let len = match method.as_str() {
                m if m.contains("ecb") => 0,
                m if m.contains("128") || m.contains("aes-128") => 16,
                m if m.contains("192") || m.contains("aes-192") => 16,
                m if m.contains("256") || m.contains("aes-256") => 16,
                _ => 16,
            };
            Ok(Some(Value::Long(len)))
        }
        "openssl_cipher_key_length" => {
            let method = args
                .first()
                .map(|v| v.to_php_string())
                .unwrap_or_default()
                .to_lowercase();
            let len = if method.contains("256") {
                32
            } else if method.contains("192") {
                24
            } else {
                16
            };
            Ok(Some(Value::Long(len)))
        }
        #[cfg(feature = "native-io")]
        "openssl_encrypt" => {
            let data = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let method = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            let options = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            let iv = args.get(4).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_openssl::openssl_encrypt_bytes(
                data.as_bytes(),
                &method,
                key.as_bytes(),
                options,
                iv.as_bytes(),
            ) {
                Ok(encrypted) => {
                    if (options & php_rs_ext_openssl::constants::OPENSSL_RAW_DATA) != 0 {
                        Ok(Some(Value::String(
                            bytes_to_php_string(&encrypted),
                        )))
                    } else {
                        Ok(Some(Value::String(php_rs_ext_openssl::base64_encode(
                            &encrypted,
                        ))))
                    }
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "openssl_decrypt" => {
            let data = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let method = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            let options = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            let iv = args.get(4).map(|v| v.to_php_string()).unwrap_or_default();
            let cipher_bytes = if (options & php_rs_ext_openssl::constants::OPENSSL_RAW_DATA) != 0 {
                data.as_bytes().to_vec()
            } else {
                match php_rs_ext_openssl::base64_decode(&data) {
                    Ok(b) => b,
                    Err(_) => return Ok(Some(Value::Bool(false))),
                }
            };
            match php_rs_ext_openssl::openssl_decrypt_bytes(
                &cipher_bytes,
                &method,
                key.as_bytes(),
                options,
                iv.as_bytes(),
            ) {
                Ok(decrypted) => Ok(Some(Value::String(bytes_to_php_string(&decrypted)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(not(feature = "native-io"))]
        "openssl_decrypt" | "openssl_encrypt" => Ok(Some(Value::Bool(false))),
        "openssl_digest" => {
            // Implement using our hash functions
            let data = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let algo = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_default()
                .to_lowercase();
            let raw = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
            let hash = match algo.as_str() {
                "md5" => Some(php_rs_ext_hash::php_hash("md5", &data)),
                "sha1" => Some(php_rs_ext_hash::php_hash("sha1", &data)),
                "sha256" => Some(php_rs_ext_hash::php_hash("sha256", &data)),
                "sha384" => Some(php_rs_ext_hash::php_hash("sha384", &data)),
                "sha512" => Some(php_rs_ext_hash::php_hash("sha512", &data)),
                _ => None,
            };
            match hash {
                Some(Some(h)) => {
                    if raw {
                        // Decode hex to bytes
                        let bytes: Vec<u8> = h
                            .as_bytes()
                            .chunks(2)
                            .filter_map(|c| std::str::from_utf8(c).ok())
                            .filter_map(|s| u8::from_str_radix(s, 16).ok())
                            .collect();
                        Ok(Some(Value::String(
                            bytes_to_php_string(&bytes),
                        )))
                    } else {
                        Ok(Some(Value::String(h)))
                    }
                }
                _ => Ok(Some(Value::Bool(false))),
            }
        }
        "openssl_error_string" => Ok(Some(Value::String(String::new()))),
        "openssl_free_key" => Ok(Some(Value::Null)),
        "openssl_get_cipher_methods" | "openssl_get_md_methods" | "openssl_get_curve_names" => {
            Ok(Some(Value::Array(PhpArray::new())))
        }
        "openssl_get_cert_locations" => {
            let mut arr = PhpArray::new();
            arr.set_string(
                "default_cert_file".into(),
                Value::String("/etc/ssl/certs/ca-certificates.crt".into()),
            );
            arr.set_string(
                "default_cert_dir".into(),
                Value::String("/etc/ssl/certs".into()),
            );
            Ok(Some(Value::Array(arr)))
        }
        "openssl_open" | "openssl_seal" => Ok(Some(Value::Bool(false))),
        #[cfg(feature = "native-io")]
        "openssl_sign" => {
            // openssl_sign(data, &signature, private_key, algo)
            let data = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let key_resource_id = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            if let Some(key) = vm.openssl_keys.get(&key_resource_id).cloned() {
                match php_rs_ext_openssl::openssl_sign(&data, &key, "sha256") {
                    Ok(signature) => {
                        let sig_str = bytes_to_php_string(&signature);
                        vm.write_back_arg(1, Value::String(sig_str), ref_args, ref_prop_args);
                        Ok(Some(Value::Bool(true)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        #[cfg(feature = "native-io")]
        "openssl_verify" => {
            // openssl_verify(data, signature, public_key, algo)
            let data = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let signature = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let key_resource_id = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            let _algo = args
                .get(3)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "sha256".to_string());
            if let Some(key) = vm.openssl_keys.get(&key_resource_id) {
                match php_rs_ext_openssl::openssl_verify(&data, signature.as_bytes(), key, "sha256")
                {
                    Ok(result) => Ok(Some(Value::Long(result as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        #[cfg(not(feature = "native-io"))]
        "openssl_sign" | "openssl_verify" => Ok(Some(Value::Bool(false))),
        "openssl_pkey_derive" | "openssl_pkey_export" | "openssl_pkey_export_to_file" => {
            Ok(Some(Value::Bool(false)))
        }
        "openssl_pkey_free" => {
            #[cfg(feature = "native-io")]
            {
                let id = args.first().map(|v| v.to_long()).unwrap_or(0);
                vm.openssl_keys.remove(&id);
            }
            Ok(Some(Value::Null))
        }
        #[cfg(feature = "native-io")]
        "openssl_pkey_new" => match php_rs_ext_openssl::openssl_pkey_new(None) {
            Ok(key) => {
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.openssl_keys.insert(id, key);
                Ok(Some(Value::Resource(id, "OpenSSL key".to_string())))
            }
            Err(_) => Ok(Some(Value::Bool(false))),
        },
        #[cfg(feature = "native-io")]
        "openssl_pkey_get_public" => {
            let pem = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_openssl::openssl_pkey_get_public(&pem) {
                Ok(key) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.openssl_keys.insert(id, key);
                    Ok(Some(Value::Resource(id, "OpenSSL key".to_string())))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "openssl_pkey_get_private" => {
            let pem = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let passphrase = args.get(1).map(|v| v.to_php_string());
            match php_rs_ext_openssl::openssl_pkey_get_private(&pem, passphrase.as_deref()) {
                Ok(key) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.openssl_keys.insert(id, key);
                    Ok(Some(Value::Resource(id, "OpenSSL key".to_string())))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "openssl_pkey_get_details" => {
            let key_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(key) = vm.openssl_keys.get(&key_id) {
                let mut arr = PhpArray::new();
                arr.set_string("bits".into(), Value::Long(key.bits as i64));
                arr.set_string(
                    "type".into(),
                    Value::Long(match key.key_type {
                        php_rs_ext_openssl::KeyType::RSA => 0,
                        php_rs_ext_openssl::KeyType::DSA => 1,
                        php_rs_ext_openssl::KeyType::DH => 2,
                        php_rs_ext_openssl::KeyType::EC => 3,
                    }),
                );
                Ok(Some(Value::Array(arr)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        #[cfg(not(feature = "native-io"))]
        "openssl_pkey_get_details"
        | "openssl_pkey_get_private"
        | "openssl_pkey_get_public"
        | "openssl_pkey_new" => Ok(Some(Value::Bool(false))),
        "openssl_pkcs7_decrypt"
        | "openssl_pkcs7_encrypt"
        | "openssl_pkcs7_read"
        | "openssl_pkcs7_sign"
        | "openssl_pkcs7_verify" => Ok(Some(Value::Bool(false))),
        "openssl_pkcs12_export" | "openssl_pkcs12_export_to_file" | "openssl_pkcs12_read" => {
            Ok(Some(Value::Bool(false)))
        }
        "openssl_cms_decrypt"
        | "openssl_cms_encrypt"
        | "openssl_cms_read"
        | "openssl_cms_sign"
        | "openssl_cms_verify" => Ok(Some(Value::Bool(false))),
        "openssl_csr_export"
        | "openssl_csr_export_to_file"
        | "openssl_csr_get_public_key"
        | "openssl_csr_get_subject"
        | "openssl_csr_new"
        | "openssl_csr_sign" => Ok(Some(Value::Bool(false))),
        "openssl_dh_compute_key" => Ok(Some(Value::Bool(false))),
        "openssl_pbkdf2" => Ok(Some(Value::Bool(false))),
        "openssl_public_encrypt"
        | "openssl_private_decrypt"
        | "openssl_private_encrypt"
        | "openssl_public_decrypt" => {
            #[cfg(feature = "native-io")]
            {
                let data = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let key_id = args.get(2).map(|v| v.to_long()).unwrap_or(-1);
                if let Some(key) = vm.openssl_keys.get(&key_id) {
                    let result = match name {
                        "openssl_public_encrypt" => {
                            php_rs_ext_openssl::openssl_public_encrypt(data.as_bytes(), key)
                        }
                        "openssl_private_decrypt" => {
                            php_rs_ext_openssl::openssl_private_decrypt(data.as_bytes(), key)
                        }
                        "openssl_private_encrypt" => {
                            php_rs_ext_openssl::openssl_private_encrypt(data.as_bytes(), key)
                        }
                        "openssl_public_decrypt" => {
                            php_rs_ext_openssl::openssl_public_decrypt(data.as_bytes(), key)
                        }
                        _ => unreachable!(),
                    };
                    match result {
                        Ok(encrypted) => {
                            // Write back to the &$crypted arg (arg index 1)
                            vm.write_back_arg(
                                1,
                                Value::String(bytes_to_php_string(&encrypted)),
                                ref_args,
                                ref_prop_args,
                            );
                            Ok(Some(Value::Bool(true)))
                        }
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            #[cfg(not(feature = "native-io"))]
            Ok(Some(Value::Bool(false)))
        }
        "openssl_random_pseudo_bytes" => {
            let length = args.first().map(|v| v.to_long()).unwrap_or(16) as usize;
            #[cfg(feature = "native-io")]
            let bytes = php_rs_ext_openssl::openssl_random_pseudo_bytes(length);
            #[cfg(not(feature = "native-io"))]
            let bytes = {
                let mut b = vec![0u8; length];
                let mut rng = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u64;
                for byte in b.iter_mut() {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *byte = (rng >> 33) as u8;
                }
                b
            };
            Ok(Some(Value::String(
                bytes_to_php_string(&bytes),
            )))
        }
        "openssl_spki_export"
        | "openssl_spki_export_challenge"
        | "openssl_spki_new"
        | "openssl_spki_verify" => Ok(Some(Value::Bool(false))),
        "openssl_x509_check_private_key" | "openssl_x509_checkpurpose" => {
            Ok(Some(Value::Bool(false)))
        }
        "openssl_x509_export" | "openssl_x509_export_to_file" => Ok(Some(Value::Bool(false))),
        "openssl_x509_fingerprint" => Ok(Some(Value::String(String::new()))),
        "openssl_x509_free" => Ok(Some(Value::Null)),
        "openssl_x509_parse" | "openssl_x509_read" => Ok(Some(Value::Bool(false))),
        "openssl_x509_verify" => Ok(Some(Value::Long(-1))),
        "odbc_connection_string_is_quoted" | "odbc_connection_string_should_quote" => {
            Ok(Some(Value::Bool(false)))
        }

        // === GD (108 functions) ===
        "imagecreate" => {
            let w = args.first().map(|v| v.to_long()).unwrap_or(0) as u32;
            let h = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u32;
            let img = php_rs_ext_gd::imagecreate(w, h);
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.gd_images.insert(id, img);
            Ok(Some(Value::Long(id)))
        }
        "imagecreatetruecolor" => {
            let w = args.first().map(|v| v.to_long()).unwrap_or(0) as u32;
            let h = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u32;
            let img = php_rs_ext_gd::imagecreatetruecolor(w, h);
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.gd_images.insert(id, img);
            Ok(Some(Value::Long(id)))
        }
        "imagecreatefromstring" => {
            let data_str = args.first().map(|v| v.to_string()).unwrap_or_default();
            let data: Vec<u8> = data_str.chars().map(|c| c as u8).collect();
            match php_rs_ext_gd::imagecreatefromstring(&data) {
                Some(img) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.gd_images.insert(id, img);
                    Ok(Some(Value::Long(id)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "imagecreatefrompng" => {
            let filename = args.first().map(|v| v.to_string()).unwrap_or_default();
            match std::fs::read(&filename) {
                Ok(data) => match php_rs_ext_gd::imagecreatefrompng_data(&data) {
                    Some(img) => {
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.gd_images.insert(id, img);
                        Ok(Some(Value::Long(id)))
                    }
                    None => Ok(Some(Value::Bool(false))),
                },
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "imagecreatefromgif" => {
            let filename = args.first().map(|v| v.to_string()).unwrap_or_default();
            match std::fs::read(&filename) {
                Ok(data) => match php_rs_ext_gd::imagecreatefromgif_data(&data) {
                    Some(img) => {
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.gd_images.insert(id, img);
                        Ok(Some(Value::Long(id)))
                    }
                    None => Ok(Some(Value::Bool(false))),
                },
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "imagecreatefromjpeg"
        | "imagecreatefromwebp"
        | "imagecreatefromavif"
        | "imagecreatefrombmp"
        | "imagecreatefromgd"
        | "imagecreatefromgd2"
        | "imagecreatefromgd2part"
        | "imagecreatefromwbmp"
        | "imagecreatefromxbm"
        | "imagecreatefromxpm"
        | "imagecreatefromtga" => Ok(Some(Value::Bool(false))),
        "imagedestroy" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            vm.gd_images.remove(&id);
            Ok(Some(Value::Bool(true)))
        }
        "imagepng" | "imagejpeg" | "imagegif" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(img) = vm.gd_images.get(&id) {
                let data = match name {
                    "imagepng" => {
                        let quality = args.get(2).map(|v| v.to_long() as i32).unwrap_or(-1);
                        php_rs_ext_gd::imagepng_quality(img, quality)
                    }
                    "imagejpeg" => {
                        let quality = args.get(2).map(|v| v.to_long() as i32).unwrap_or(75);
                        php_rs_ext_gd::imagejpeg_quality(img, quality)
                    }
                    "imagegif" => php_rs_ext_gd::imagegif(img),
                    _ => Vec::new(),
                };
                if data.is_empty() {
                    return Ok(Some(Value::Bool(false)));
                }
                // Second arg: filename or null
                let filename = args.get(1).and_then(|v| match v {
                    Value::String(s) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                });
                if let Some(path) = filename {
                    // Write to file
                    match std::fs::write(&path, &data) {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    // Output to stdout (binary data as latin-1 string)
                    let output: String = data.iter().map(|&b| b as char).collect();
                    vm.write_output(&output);
                    Ok(Some(Value::Bool(true)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagewebp" | "imageavif" | "imagebmp" | "imagewbmp" | "imagegd" | "imagegd2"
        | "imagexbm" => Ok(Some(Value::Bool(false))),
        "imagesx" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(img) = vm.gd_images.get(&id) {
                Ok(Some(Value::Long(php_rs_ext_gd::imagesx(img) as i64)))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "imagesy" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(img) = vm.gd_images.get(&id) {
                Ok(Some(Value::Long(php_rs_ext_gd::imagesy(img) as i64)))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "imagecolorallocate" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let r = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u8;
            let g = args.get(2).map(|v| v.to_long()).unwrap_or(0) as u8;
            let b = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u8;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Long(
                    php_rs_ext_gd::imagecolorallocate(img, r, g, b) as i64,
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecolorallocatealpha" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let r = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u8;
            let g = args.get(2).map(|v| v.to_long()).unwrap_or(0) as u8;
            let b = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u8;
            let a = args.get(4).map(|v| v.to_long()).unwrap_or(0) as u8;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Long(
                    php_rs_ext_gd::imagecolorallocatealpha(img, r, g, b, a) as i64,
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecolorat" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            if let Some(img) = vm.gd_images.get(&id) {
                Ok(Some(Value::Long(
                    php_rs_ext_gd::imagecolorat(img, x, y) as i64
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecolordeallocate"
        | "imagecolorset"
        | "imagecolorsforindex"
        | "imagecolorclosest"
        | "imagecolorclosestalpha"
        | "imagecolorclosesthwb"
        | "imagecolorexact"
        | "imagecolorexactalpha"
        | "imagecolormatch"
        | "imagecolorresolve"
        | "imagecolorresolvealpha"
        | "imagecolorstotal"
        | "imagecolortransparent" => Ok(Some(Value::Long(0))),
        "imagesetpixel" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let color = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagesetpixel(
                    img, x, y, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imageline" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x1 = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y1 = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let x2 = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y2 = args.get(4).map(|v| v.to_long()).unwrap_or(0) as i32;
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imageline(
                    img, x1, y1, x2, y2, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagerectangle" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x1 = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y1 = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let x2 = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y2 = args.get(4).map(|v| v.to_long()).unwrap_or(0) as i32;
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagerectangle(
                    img, x1, y1, x2, y2, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagefilledrectangle" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x1 = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y1 = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let x2 = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y2 = args.get(4).map(|v| v.to_long()).unwrap_or(0) as i32;
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagefilledrectangle(
                    img, x1, y1, x2, y2, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imageellipse" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let cx = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let cy = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let w = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            let h = args.get(4).map(|v| v.to_long()).unwrap_or(0) as u32;
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imageellipse(
                    img, cx, cy, w, h, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagefilledellipse" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let cx = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let cy = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let w = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            let h = args.get(4).map(|v| v.to_long()).unwrap_or(0) as u32;
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagefilledellipse(
                    img, cx, cy, w, h, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagefill" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let x = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let color = args.get(3).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagefill(
                    img, x, y, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagedashedline" | "imagearc" | "imagefilledarc" | "imagefilledpolygon"
        | "imagepolygon" | "imageopenpolygon" | "imagefilltoborder" => Ok(Some(Value::Bool(true))),
        "imagestring" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let font = args.get(1).map(|v| v.to_long()).unwrap_or(1) as i32;
            let x = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let y = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let s = args.get(4).map(|v| v.to_php_string()).unwrap_or_default();
            let color = args.get(5).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_gd::imagestring(
                    img, font, x, y, &s, color,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagestringup" | "imagechar" | "imagecharup" => Ok(Some(Value::Bool(true))),
        "imagettftext" | "imagefttext" | "imagettfbbox" | "imageftbbox" => {
            Ok(Some(Value::Bool(false)))
        }
        "imagefontwidth" | "imagefontheight" => Ok(Some(Value::Long(8))),
        "imageloadfont" => Ok(Some(Value::Long(0))),
        "imagecopy" => {
            let dst_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let src_id = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
            let dst_x = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let dst_y = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let src_x = args.get(4).map(|v| v.to_long()).unwrap_or(0) as i32;
            let src_y = args.get(5).map(|v| v.to_long()).unwrap_or(0) as i32;
            let src_w = args.get(6).map(|v| v.to_long()).unwrap_or(0) as u32;
            let src_h = args.get(7).map(|v| v.to_long()).unwrap_or(0) as u32;
            // Clone src to avoid double borrow
            if let Some(src) = vm.gd_images.get(&src_id).cloned() {
                if let Some(dst) = vm.gd_images.get_mut(&dst_id) {
                    Ok(Some(Value::Bool(php_rs_ext_gd::imagecopy(
                        dst, &src, dst_x, dst_y, src_x, src_y, src_w, src_h,
                    ))))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecopyresized" => {
            let dst_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let src_id = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
            let dst_x = args.get(2).map(|v| v.to_long()).unwrap_or(0) as i32;
            let dst_y = args.get(3).map(|v| v.to_long()).unwrap_or(0) as i32;
            let src_x = args.get(4).map(|v| v.to_long()).unwrap_or(0) as i32;
            let src_y = args.get(5).map(|v| v.to_long()).unwrap_or(0) as i32;
            let dst_w = args.get(6).map(|v| v.to_long()).unwrap_or(0) as u32;
            let dst_h = args.get(7).map(|v| v.to_long()).unwrap_or(0) as u32;
            let src_w = args.get(8).map(|v| v.to_long()).unwrap_or(0) as u32;
            let src_h = args.get(9).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(src) = vm.gd_images.get(&src_id).cloned() {
                if let Some(dst) = vm.gd_images.get_mut(&dst_id) {
                    Ok(Some(Value::Bool(php_rs_ext_gd::imagecopyresized(
                        dst, &src, dst_x, dst_y, src_x, src_y, dst_w, dst_h, src_w, src_h,
                    ))))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecopymerge" | "imagecopymergegray" | "imagecopyresampled" => {
            Ok(Some(Value::Bool(true)))
        }
        "imagerotate" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let angle = args.get(1).map(|v| v.to_double()).unwrap_or(0.0);
            let bg_color = args.get(2).map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(img) = vm.gd_images.get(&id) {
                let rotated = php_rs_ext_gd::imagerotate(img, angle, bg_color);
                let new_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.gd_images.insert(new_id, rotated);
                Ok(Some(Value::Long(new_id)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagescale" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let new_w = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u32;
            let new_h = args
                .get(2)
                .map(|v| {
                    let h = v.to_long();
                    if h < 0 {
                        None
                    } else {
                        Some(h as u32)
                    }
                })
                .unwrap_or(None);
            if let Some(img) = vm.gd_images.get(&id) {
                let scaled = php_rs_ext_gd::imagescale(img, new_w, new_h);
                let new_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.gd_images.insert(new_id, scaled);
                Ok(Some(Value::Long(new_id)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecrop" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let rect_arr = args.get(1).cloned().unwrap_or(Value::Null);
            if let (Some(img), Value::Array(ref a)) = (vm.gd_images.get(&id), &rect_arr) {
                let x = a.get_string("x").map(|v| v.to_long()).unwrap_or(0) as i32;
                let y = a.get_string("y").map(|v| v.to_long()).unwrap_or(0) as i32;
                let width = a.get_string("width").map(|v| v.to_long()).unwrap_or(0) as u32;
                let height = a.get_string("height").map(|v| v.to_long()).unwrap_or(0) as u32;
                let rect = php_rs_ext_gd::GdRect {
                    x,
                    y,
                    width,
                    height,
                };
                let cropped = php_rs_ext_gd::imagecrop(img, &rect);
                let new_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.gd_images.insert(new_id, cropped);
                Ok(Some(Value::Long(new_id)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagecropauto" => Ok(Some(Value::Bool(false))),
        "imageflip" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let mode = args.get(1).map(|v| v.to_long()).unwrap_or(0) as i32;
            if let Some(img) = vm.gd_images.get_mut(&id) {
                php_rs_ext_gd::imageflip(img, mode);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "imagesetthickness"
        | "imagesetbrush"
        | "imagesetstyle"
        | "imagesettile"
        | "imagesetinterpolation"
        | "imagesetclip"
        | "imagegetclip"
        | "imagelayereffect"
        | "imageantialias"
        | "imageinterlace"
        | "imagetruecolortopalette"
        | "imagepalettetotruecolor"
        | "imagepalettecopy"
        | "imagecolorsettotal"
        | "imageresolution"
        | "imagegammacorrect"
        | "imageconvolution"
        | "imagefilter"
        | "imageaffine"
        | "imageaffinematrixconcat"
        | "imageaffinematrixget"
        | "imagealphablending"
        | "imagesavealpha"
        | "imageistruecolor" => Ok(Some(Value::Bool(false))),
        "imagetypes" => Ok(Some(Value::Long(
            php_rs_ext_gd::IMG_PNG as i64
                | php_rs_ext_gd::IMG_JPG as i64
                | php_rs_ext_gd::IMG_GIF as i64,
        ))),

        // === sodium (110 functions) — stubs ===
        "sodium_crypto_aead_aes256gcm_is_available" => Ok(Some(Value::Bool(false))),
        "sodium_bin2hex" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let hex: String = s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
            Ok(Some(Value::String(hex)))
        }
        "sodium_hex2bin" => {
            let hex = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex[i..i.min(hex.len()).max(i + 2)], 16).ok())
                .collect();
            Ok(Some(Value::String(
                bytes_to_php_string(&bytes),
            )))
        }
        "sodium_bin2base64" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_base64_encode(s.as_bytes()),
            )))
        }
        "sodium_base642bin" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_standard::strings::php_base64_decode(&s) {
                Some(bytes) => Ok(Some(Value::String(
                    bytes_to_php_string(&bytes),
                ))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "sodium_compare" | "sodium_memcmp" => {
            let a = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let b = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(a.cmp(&b) as i64)))
        }
        "sodium_memzero" | "sodium_increment" | "sodium_add" | "sodium_sub" => {
            Ok(Some(Value::Null))
        }
        "sodium_pad" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "sodium_unpad" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "sodium_crypto_aead_aes256gcm_decrypt"
        | "sodium_crypto_aead_aes256gcm_encrypt"
        | "sodium_crypto_aead_aes256gcm_keygen"
        | "sodium_crypto_aead_chacha20poly1305_decrypt"
        | "sodium_crypto_aead_chacha20poly1305_encrypt"
        | "sodium_crypto_aead_chacha20poly1305_keygen"
        | "sodium_crypto_aead_chacha20poly1305_ietf_decrypt"
        | "sodium_crypto_aead_chacha20poly1305_ietf_encrypt"
        | "sodium_crypto_aead_chacha20poly1305_ietf_keygen"
        | "sodium_crypto_aead_xchacha20poly1305_ietf_decrypt"
        | "sodium_crypto_aead_xchacha20poly1305_ietf_encrypt"
        | "sodium_crypto_aead_xchacha20poly1305_ietf_keygen" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_auth" | "sodium_crypto_auth_keygen" => {
            Ok(Some(Value::String(String::new())))
        }
        "sodium_crypto_auth_verify" => Ok(Some(Value::Bool(false))),
        #[cfg(feature = "native-io")]
        "sodium_crypto_box" => {
            let message = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let nonce = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let keypair = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box(
                message.as_bytes(),
                nonce.as_bytes(),
                keypair.as_bytes(),
            ) {
                Ok(ct) => Ok(Some(Value::String(
                    bytes_to_php_string(&ct),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_open" => {
            let ciphertext = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let nonce = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let keypair = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box_open(
                ciphertext.as_bytes(),
                nonce.as_bytes(),
                keypair.as_bytes(),
            ) {
                Ok(pt) => Ok(Some(Value::String(
                    bytes_to_php_string(&pt),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_keypair" => {
            let keypair = php_rs_ext_sodium::sodium_crypto_box_keypair();
            Ok(Some(Value::String(
                bytes_to_php_string(&keypair),
            )))
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_publickey" => {
            let keypair = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box_publickey(keypair.as_bytes()) {
                Ok(pk) => Ok(Some(Value::String(
                    bytes_to_php_string(&pk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_secretkey" => {
            let keypair = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box_secretkey(keypair.as_bytes()) {
                Ok(sk) => Ok(Some(Value::String(
                    bytes_to_php_string(&sk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_publickey_from_secretkey" => {
            let sk = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box_publickey_from_secretkey(sk.as_bytes()) {
                Ok(pk) => Ok(Some(Value::String(
                    bytes_to_php_string(&pk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_box_keypair_from_secretkey_and_publickey" => {
            let sk = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let pk = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_box_keypair_from_secretkey_and_publickey(
                sk.as_bytes(),
                pk.as_bytes(),
            ) {
                Ok(kp) => Ok(Some(Value::String(
                    bytes_to_php_string(&kp),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_box"
        | "sodium_crypto_box_open"
        | "sodium_crypto_box_keypair"
        | "sodium_crypto_box_publickey"
        | "sodium_crypto_box_secretkey"
        | "sodium_crypto_box_publickey_from_secretkey"
        | "sodium_crypto_box_keypair_from_secretkey_and_publickey" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_box_seed_keypair"
        | "sodium_crypto_box_seal"
        | "sodium_crypto_box_seal_open" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_core_ristretto255_add"
        | "sodium_crypto_core_ristretto255_from_hash"
        | "sodium_crypto_core_ristretto255_is_valid_point"
        | "sodium_crypto_core_ristretto255_random"
        | "sodium_crypto_core_ristretto255_scalar_add"
        | "sodium_crypto_core_ristretto255_scalar_complement"
        | "sodium_crypto_core_ristretto255_scalar_invert"
        | "sodium_crypto_core_ristretto255_scalar_negate"
        | "sodium_crypto_core_ristretto255_scalar_random"
        | "sodium_crypto_core_ristretto255_scalar_reduce"
        | "sodium_crypto_core_ristretto255_scalar_sub"
        | "sodium_crypto_core_ristretto255_sub"
        | "sodium_crypto_scalarmult_ristretto255"
        | "sodium_crypto_scalarmult_ristretto255_base" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_generichash"
        | "sodium_crypto_generichash_keygen"
        | "sodium_crypto_shorthash"
        | "sodium_crypto_shorthash_keygen" => Ok(Some(Value::String(String::new()))),
        "sodium_crypto_generichash_init"
        | "sodium_crypto_generichash_update"
        | "sodium_crypto_generichash_final" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_kdf_keygen" | "sodium_crypto_kdf_derive_from_key" => {
            Ok(Some(Value::String(String::new())))
        }
        "sodium_crypto_kx_keypair"
        | "sodium_crypto_kx_seed_keypair"
        | "sodium_crypto_kx_publickey"
        | "sodium_crypto_kx_secretkey"
        | "sodium_crypto_kx_client_session_keys"
        | "sodium_crypto_kx_server_session_keys" => Ok(Some(Value::Bool(false))),
        #[cfg(feature = "native-io")]
        "sodium_crypto_pwhash" => {
            let length = args.first().map(|v| v.to_long()).unwrap_or(32) as usize;
            let password = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let salt = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            let opslimit = args.get(3).map(|v| v.to_long()).unwrap_or(2) as u64;
            let memlimit = args.get(4).map(|v| v.to_long()).unwrap_or(67108864) as usize;
            match php_rs_ext_sodium::sodium_crypto_pwhash(
                length,
                &password,
                salt.as_bytes(),
                opslimit,
                memlimit,
            ) {
                Ok(hash) => Ok(Some(Value::String(
                    bytes_to_php_string(&hash),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_pwhash_str" => {
            let password = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let opslimit = args.get(1).map(|v| v.to_long()).unwrap_or(2) as u64;
            let memlimit = args.get(2).map(|v| v.to_long()).unwrap_or(67108864) as usize;
            match php_rs_ext_sodium::sodium_crypto_pwhash_str(&password, opslimit, memlimit) {
                Ok(hash) => Ok(Some(Value::String(hash))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_pwhash_str_verify" => {
            let hash = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let password = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_pwhash_str_verify(&hash, &password) {
                Ok(valid) => Ok(Some(Value::Bool(valid))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_pwhash" | "sodium_crypto_pwhash_str" => Ok(Some(Value::Bool(false))),
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_pwhash_str_verify" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_pwhash_str_needs_rehash" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_pwhash_scryptsalsa208sha256"
        | "sodium_crypto_pwhash_scryptsalsa208sha256_str"
        | "sodium_crypto_pwhash_scryptsalsa208sha256_str_verify" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_scalarmult" | "sodium_crypto_scalarmult_base" => {
            Ok(Some(Value::Bool(false)))
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_secretbox" => {
            let message = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let nonce = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_secretbox(
                message.as_bytes(),
                nonce.as_bytes(),
                key.as_bytes(),
            ) {
                Ok(ct) => Ok(Some(Value::String(
                    bytes_to_php_string(&ct),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_secretbox_open" => {
            let ciphertext = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let nonce = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_secretbox_open(
                ciphertext.as_bytes(),
                nonce.as_bytes(),
                key.as_bytes(),
            ) {
                Ok(pt) => Ok(Some(Value::String(
                    bytes_to_php_string(&pt),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_secretbox_keygen" => {
            let key = php_rs_ext_sodium::sodium_crypto_secretbox_keygen();
            Ok(Some(Value::String(
                bytes_to_php_string(&key),
            )))
        }
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_secretbox"
        | "sodium_crypto_secretbox_keygen"
        | "sodium_crypto_secretbox_open" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_secretstream_xchacha20poly1305_init_push"
        | "sodium_crypto_secretstream_xchacha20poly1305_push"
        | "sodium_crypto_secretstream_xchacha20poly1305_init_pull"
        | "sodium_crypto_secretstream_xchacha20poly1305_pull"
        | "sodium_crypto_secretstream_xchacha20poly1305_rekey"
        | "sodium_crypto_secretstream_xchacha20poly1305_keygen" => Ok(Some(Value::Bool(false))),
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign" => {
            let message = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let secret_key = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign(message.as_bytes(), secret_key.as_bytes()) {
                Ok(signed) => Ok(Some(Value::String(
                    bytes_to_php_string(&signed),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_open" => {
            let signed = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let public_key = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_open(
                signed.as_bytes(),
                public_key.as_bytes(),
            ) {
                Ok(msg) => Ok(Some(Value::String(
                    bytes_to_php_string(&msg),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_detached" => {
            let message = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let secret_key = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_detached(
                message.as_bytes(),
                secret_key.as_bytes(),
            ) {
                Ok(sig) => Ok(Some(Value::String(
                    bytes_to_php_string(&sig),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_verify_detached" => {
            let signature = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let message = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let public_key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_verify_detached(
                signature.as_bytes(),
                message.as_bytes(),
                public_key.as_bytes(),
            ) {
                Ok(valid) => Ok(Some(Value::Bool(valid))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_keypair" => {
            let keypair = php_rs_ext_sodium::sodium_crypto_sign_keypair();
            Ok(Some(Value::String(
                bytes_to_php_string(&keypair),
            )))
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_seed_keypair" => {
            let seed = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_seed_keypair(seed.as_bytes()) {
                Ok(kp) => Ok(Some(Value::String(
                    bytes_to_php_string(&kp),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_publickey" => {
            let keypair = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_publickey(keypair.as_bytes()) {
                Ok(pk) => Ok(Some(Value::String(
                    bytes_to_php_string(&pk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_secretkey" => {
            let keypair = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_secretkey(keypair.as_bytes()) {
                Ok(sk) => Ok(Some(Value::String(
                    bytes_to_php_string(&sk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_publickey_from_secretkey" => {
            let sk = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_publickey_from_secretkey(sk.as_bytes()) {
                Ok(pk) => Ok(Some(Value::String(
                    bytes_to_php_string(&pk),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_sign"
        | "sodium_crypto_sign_open"
        | "sodium_crypto_sign_detached"
        | "sodium_crypto_sign_verify_detached"
        | "sodium_crypto_sign_keypair"
        | "sodium_crypto_sign_seed_keypair"
        | "sodium_crypto_sign_publickey"
        | "sodium_crypto_sign_secretkey"
        | "sodium_crypto_sign_publickey_from_secretkey" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_sign_ed25519_pk_to_curve25519"
        | "sodium_crypto_sign_ed25519_sk_to_curve25519" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_stream"
        | "sodium_crypto_stream_keygen"
        | "sodium_crypto_stream_xor"
        | "sodium_crypto_stream_xchacha20"
        | "sodium_crypto_stream_xchacha20_keygen"
        | "sodium_crypto_stream_xchacha20_xor"
        | "sodium_crypto_stream_xchacha20_xor_ic" => Ok(Some(Value::Bool(false))),
        "gd_info" => {
            let mut arr = PhpArray::new();
            arr.set_string(
                "GD Version".into(),
                Value::String("bundled (2.1.0 compatible)".into()),
            );
            arr.set_string("FreeType Support".into(), Value::Bool(false));
            arr.set_string("GIF Read Support".into(), Value::Bool(true));
            arr.set_string("GIF Create Support".into(), Value::Bool(true));
            arr.set_string("JPEG Support".into(), Value::Bool(false));
            arr.set_string("PNG Support".into(), Value::Bool(false));
            arr.set_string("WBMP Support".into(), Value::Bool(false));
            arr.set_string("XPM Support".into(), Value::Bool(false));
            arr.set_string("XBM Support".into(), Value::Bool(false));
            arr.set_string("WebP Support".into(), Value::Bool(false));
            arr.set_string("BMP Support".into(), Value::Bool(false));
            arr.set_string("AVIF Support".into(), Value::Bool(false));
            arr.set_string("TGA Read Support".into(), Value::Bool(false));
            arr.set_string(
                "JIS-mapped Japanese Font Support".into(),
                Value::Bool(false),
            );
            Ok(Some(Value::Array(arr)))
        }
        "imagegetinterpolation" => Ok(Some(Value::Long(0))),
        "imagegrabscreen" | "imagegrabwindow" => Ok(Some(Value::Bool(false))),
        "openssl_get_privatekey" | "openssl_get_publickey" => Ok(Some(Value::Bool(false))),
        "openssl_password_hash" | "openssl_password_verify" => Ok(Some(Value::Bool(false))),
        // pgsql aliases
        "pg_clientencoding" => Ok(Some(Value::String("UTF8".into()))),
        // sodium extras
        "sodium_crypto_aead_aegis128l_decrypt"
        | "sodium_crypto_aead_aegis128l_encrypt"
        | "sodium_crypto_aead_aegis128l_keygen"
        | "sodium_crypto_aead_aegis256_decrypt"
        | "sodium_crypto_aead_aegis256_encrypt"
        | "sodium_crypto_aead_aegis256_keygen" => Ok(Some(Value::Bool(false))),
        "sodium_crypto_core_ristretto255_scalar_mul" => Ok(Some(Value::Bool(false))),
        #[cfg(feature = "native-io")]
        "sodium_crypto_sign_keypair_from_secretkey_and_publickey" => {
            let sk = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let pk = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            match php_rs_ext_sodium::sodium_crypto_sign_keypair_from_secretkey_and_publickey(
                sk.as_bytes(),
                pk.as_bytes(),
            ) {
                Ok(kp) => Ok(Some(Value::String(
                    bytes_to_php_string(&kp),
                ))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        #[cfg(not(feature = "native-io"))]
        "sodium_crypto_sign_keypair_from_secretkey_and_publickey" => Ok(Some(Value::Bool(false))),
        // zlib remaining
        "readgzfile" => Ok(Some(Value::Long(0))),

        // === intl extension (187 functions) ===
        "collator_create" => {
            let locale = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let collator = php_rs_ext_intl::Collator::new(&locale);
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.intl_collators.insert(id, collator);
            Ok(Some(Value::Long(id)))
        }
        "collator_compare" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let a = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let b = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(col) = vm.intl_collators.get(&id) {
                let ord = col.compare(&a, &b);
                Ok(Some(Value::Long(match ord {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                })))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "collator_sort" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let arr = args.get(1).cloned().unwrap_or(Value::Null);
            if let (Some(col), Value::Array(ref a)) = (vm.intl_collators.get(&id), &arr) {
                let mut strings: Vec<String> =
                    a.entries().iter().map(|(_, v)| v.to_php_string()).collect();
                col.sort(&mut strings);
                let mut result = PhpArray::new();
                for s in strings {
                    result.push(Value::String(s));
                }
                vm.write_back_arg(1, Value::Array(result), ref_args, ref_prop_args);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "collator_asort"
        | "collator_get_attribute"
        | "collator_get_error_code"
        | "collator_get_locale"
        | "collator_get_sort_key"
        | "collator_get_strength"
        | "collator_set_attribute"
        | "collator_set_strength"
        | "collator_sort_with_sort_keys" => Ok(Some(Value::Bool(false))),
        "collator_get_error_message" => Ok(Some(Value::String(String::new()))),
        "datefmt_create" => {
            let locale = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let date_type_int = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let time_type_int = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            let to_format_type = |n: i64| -> php_rs_ext_intl::FormatType {
                match n {
                    -1 => php_rs_ext_intl::FormatType::None,
                    0 => php_rs_ext_intl::FormatType::Full,
                    1 => php_rs_ext_intl::FormatType::Long,
                    2 => php_rs_ext_intl::FormatType::Medium,
                    3 => php_rs_ext_intl::FormatType::Short,
                    _ => php_rs_ext_intl::FormatType::None,
                }
            };
            let formatter = php_rs_ext_intl::DateFormatter::new(
                &locale,
                to_format_type(date_type_int),
                to_format_type(time_type_int),
            );
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.intl_date_formatters.insert(id, formatter);
            Ok(Some(Value::Long(id)))
        }
        "datefmt_format" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let timestamp = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            if let Some(fmt) = vm.intl_date_formatters.get(&id) {
                Ok(Some(Value::String(fmt.format(timestamp))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "datefmt_format_object"
        | "datefmt_get_calendar"
        | "datefmt_get_calendar_object"
        | "datefmt_get_datetype"
        | "datefmt_get_locale"
        | "datefmt_get_pattern"
        | "datefmt_get_timetype"
        | "datefmt_get_timezone"
        | "datefmt_get_timezone_id"
        | "datefmt_is_lenient"
        | "datefmt_localtime"
        | "datefmt_parse"
        | "datefmt_set_calendar"
        | "datefmt_set_lenient"
        | "datefmt_set_pattern"
        | "datefmt_set_timezone" => Ok(Some(Value::Bool(false))),
        "datefmt_get_error_code" => Ok(Some(Value::Long(0))),
        "datefmt_get_error_message" => Ok(Some(Value::String(String::new()))),
        "grapheme_strlen" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            // For ASCII/BMP text, grapheme count ≈ char count
            Ok(Some(Value::Long(s.chars().count() as i64)))
        }
        "grapheme_substr" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let start = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let length = args.get(2).map(|v| Some(v.to_long()));
            let chars: Vec<char> = s.chars().collect();
            let len = chars.len() as i64;
            let start_idx = if start < 0 {
                (len + start).max(0) as usize
            } else {
                start as usize
            };
            if start_idx >= chars.len() {
                return Ok(Some(Value::String(String::new())));
            }
            let end_idx = match length {
                Some(Some(l)) if l < 0 => (len + l).max(start_idx as i64) as usize,
                Some(Some(l)) => (start_idx + l as usize).min(chars.len()),
                _ => chars.len(),
            };
            let result: String = chars[start_idx..end_idx].iter().collect();
            Ok(Some(Value::String(result)))
        }
        "grapheme_strpos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long() as usize).unwrap_or(0);
            if let Some(byte_pos) = haystack[offset..].find(&needle) {
                let char_pos = haystack[..offset + byte_pos].chars().count();
                Ok(Some(Value::Long(char_pos as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "grapheme_extract" | "grapheme_stripos" | "grapheme_stristr" | "grapheme_strripos"
        | "grapheme_strrpos" | "grapheme_strstr" | "grapheme_str_split" => {
            Ok(Some(Value::Bool(false)))
        }
        "idn_to_ascii" | "idn_to_utf8" => {
            let domain = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(domain)))
        }
        "intl_error_name" => {
            let code = args.first().map(|v| v.to_long()).unwrap_or(0);
            Ok(Some(Value::String(format!("U_ERROR_{}", code))))
        }
        "intl_get_error_code" => Ok(Some(Value::Long(0))),
        "intl_get_error_message" => Ok(Some(Value::String("U_ZERO_ERROR".into()))),
        "intl_is_failure" => Ok(Some(Value::Bool(false))),
        "intlcal_add"
        | "intlcal_after"
        | "intlcal_before"
        | "intlcal_clear"
        | "intlcal_create_instance"
        | "intlcal_equals"
        | "intlcal_field_difference"
        | "intlcal_from_date_time"
        | "intlcal_get"
        | "intlcal_get_actual_maximum"
        | "intlcal_get_actual_minimum"
        | "intlcal_get_available_locales"
        | "intlcal_get_day_of_week_type"
        | "intlcal_get_error_code"
        | "intlcal_get_error_message"
        | "intlcal_get_first_day_of_week"
        | "intlcal_get_greatest_minimum"
        | "intlcal_get_keyword_values_for_locale"
        | "intlcal_get_least_maximum"
        | "intlcal_get_locale"
        | "intlcal_get_maximum"
        | "intlcal_get_minimal_days_in_first_week"
        | "intlcal_get_minimum"
        | "intlcal_get_now"
        | "intlcal_get_repeated_wall_time_option"
        | "intlcal_get_skipped_wall_time_option"
        | "intlcal_get_time"
        | "intlcal_get_time_zone"
        | "intlcal_get_type"
        | "intlcal_get_weekend_transition"
        | "intlcal_in_daylight_time"
        | "intlcal_is_equivalent_to"
        | "intlcal_is_lenient"
        | "intlcal_is_set"
        | "intlcal_is_weekend"
        | "intlcal_roll"
        | "intlcal_set"
        | "intlcal_set_first_day_of_week"
        | "intlcal_set_lenient"
        | "intlcal_set_minimal_days_in_first_week"
        | "intlcal_set_repeated_wall_time_option"
        | "intlcal_set_skipped_wall_time_option"
        | "intlcal_set_time"
        | "intlcal_set_time_zone"
        | "intlcal_to_date_time" => Ok(Some(Value::Bool(false))),
        "intlgregcal_create_instance"
        | "intlgregcal_get_gregorian_change"
        | "intlgregcal_is_leap_year"
        | "intlgregcal_set_gregorian_change" => Ok(Some(Value::Bool(false))),
        "intltz_count_equivalent_ids"
        | "intltz_create_default"
        | "intltz_create_enumeration"
        | "intltz_create_time_zone"
        | "intltz_create_time_zone_id_enumeration"
        | "intltz_from_date_time_zone"
        | "intltz_get_canonical_id"
        | "intltz_get_display_name"
        | "intltz_get_dst_savings"
        | "intltz_get_equivalent_id"
        | "intltz_get_error_code"
        | "intltz_get_error_message"
        | "intltz_get_gmt"
        | "intltz_get_id"
        | "intltz_get_id_for_windows_id"
        | "intltz_get_offset"
        | "intltz_get_raw_offset"
        | "intltz_get_region"
        | "intltz_get_tz_data_version"
        | "intltz_get_unknown"
        | "intltz_get_windows_id"
        | "intltz_has_same_rules"
        | "intltz_to_date_time_zone"
        | "intltz_use_daylight_time" => Ok(Some(Value::Bool(false))),
        "locale_accept_from_http"
        | "locale_canonicalize"
        | "locale_compose"
        | "locale_filter_matches"
        | "locale_get_all_variants"
        | "locale_get_default"
        | "locale_get_display_language"
        | "locale_get_display_name"
        | "locale_get_display_region"
        | "locale_get_display_script"
        | "locale_get_display_variant"
        | "locale_get_keywords"
        | "locale_get_primary_language"
        | "locale_get_region"
        | "locale_get_script"
        | "locale_lookup"
        | "locale_parse"
        | "locale_set_default" => Ok(Some(Value::Bool(false))),
        "msgfmt_create"
        | "msgfmt_format"
        | "msgfmt_format_message"
        | "msgfmt_get_error_code"
        | "msgfmt_get_error_message"
        | "msgfmt_get_locale"
        | "msgfmt_get_pattern"
        | "msgfmt_parse"
        | "msgfmt_parse_message"
        | "msgfmt_set_pattern" => Ok(Some(Value::Bool(false))),
        "normalizer_get_raw_decomposition" => Ok(Some(Value::Bool(false))),
        "numfmt_create" => {
            let locale = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let style_int = args.get(1).map(|v| v.to_long()).unwrap_or(1);
            let style = match style_int {
                1 => php_rs_ext_intl::NumberFormatStyle::Decimal,
                2 => php_rs_ext_intl::NumberFormatStyle::Currency,
                3 => php_rs_ext_intl::NumberFormatStyle::Percent,
                4 => php_rs_ext_intl::NumberFormatStyle::Scientific,
                5 => php_rs_ext_intl::NumberFormatStyle::SpellOut,
                _ => php_rs_ext_intl::NumberFormatStyle::Decimal,
            };
            let formatter = php_rs_ext_intl::NumberFormatter::new(&locale, style);
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.intl_number_formatters.insert(id, formatter);
            Ok(Some(Value::Long(id)))
        }
        "numfmt_format" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let value = args.get(1).cloned().unwrap_or(Value::Null);
            if let Some(fmt) = vm.intl_number_formatters.get(&id) {
                let result = match &value {
                    Value::Long(n) => fmt.format_int(*n),
                    Value::Double(f) => fmt.format_float(*f),
                    _ => fmt.format_int(value.to_long()),
                };
                Ok(Some(Value::String(result)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "numfmt_parse" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let s = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(fmt) = vm.intl_number_formatters.get(&id) {
                match fmt.parse(&s) {
                    Some(v) => Ok(Some(Value::Double(v))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "numfmt_set_attribute" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let attr_int = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let value = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            if let Some(fmt) = vm.intl_number_formatters.get_mut(&id) {
                let attr = match attr_int {
                    8 => php_rs_ext_intl::NumberFormatAttr::MinFractionDigits,
                    6 => php_rs_ext_intl::NumberFormatAttr::MaxFractionDigits,
                    _ => return Ok(Some(Value::Bool(false))),
                };
                fmt.set_attribute(attr, value);
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "numfmt_get_attribute" => Ok(Some(Value::Long(0))),
        "numfmt_get_error_code" => Ok(Some(Value::Long(0))),
        "numfmt_get_error_message" => Ok(Some(Value::String(String::new()))),
        "numfmt_format_currency"
        | "numfmt_get_locale"
        | "numfmt_get_pattern"
        | "numfmt_get_symbol"
        | "numfmt_get_text_attribute"
        | "numfmt_parse_currency"
        | "numfmt_set_pattern"
        | "numfmt_set_symbol"
        | "numfmt_set_text_attribute" => Ok(Some(Value::Bool(false))),
        "resourcebundle_count"
        | "resourcebundle_create"
        | "resourcebundle_get"
        | "resourcebundle_get_error_code"
        | "resourcebundle_get_error_message"
        | "resourcebundle_locales" => Ok(Some(Value::Bool(false))),
        "transliterator_transliterate" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let id_str = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            // PHP signature: transliterator_transliterate($transliterator, $string)
            // But often called as transliterator_transliterate("id", "string")
            // The first arg is the transliterator ID or object, second is the string
            Ok(Some(Value::String(
                php_rs_ext_intl::Transliterator::transliterate(&id_str, &s),
            )))
        }
        "transliterator_create"
        | "transliterator_create_from_rules"
        | "transliterator_create_inverse"
        | "transliterator_get_error_code"
        | "transliterator_get_error_message"
        | "transliterator_list_ids" => Ok(Some(Value::Bool(false))),

        // Last remaining: intl + pgsql
        "grapheme_levenshtein" => Ok(Some(Value::Long(0))),
        "intltz_get_iana_id" => Ok(Some(Value::Bool(false))),
        "locale_add_likely_subtags" | "locale_minimize_subtags" => {
            let locale = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(locale)))
        }
        "locale_is_right_to_left" => Ok(Some(Value::Bool(false))),

        // ══════════════════════════════════════════════════════════════
        // EXIF extension
        // ══════════════════════════════════════════════════════════════
        "exif_tagname" => {
            let tag_id = args.first().cloned().unwrap_or(Value::Long(0)).to_long() as u16;
            match php_rs_ext_exif::exif_tagname(tag_id) {
                Some(name) => Ok(Some(Value::String(name.to_string()))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "exif_imagetype" => {
            let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match std::fs::read(&filename) {
                Ok(data) => match php_rs_ext_exif::exif_imagetype(&data) {
                    Some(t) => Ok(Some(Value::Long(t as i64))),
                    None => Ok(Some(Value::Bool(false))),
                },
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "exif_read_data" => {
            let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match std::fs::read(&filename) {
                Ok(data) => match php_rs_ext_exif::exif_read_data(&data) {
                    Ok(exif) => {
                        let mut arr = PhpArray::new();
                        if let Some(ref v) = exif.make {
                            arr.set_string("Make".into(), Value::String(v.clone()));
                        }
                        if let Some(ref v) = exif.model {
                            arr.set_string("Model".into(), Value::String(v.clone()));
                        }
                        if let Some(v) = exif.orientation {
                            arr.set_string("Orientation".into(), Value::Long(v as i64));
                        }
                        if let Some(ref v) = exif.datetime {
                            arr.set_string("DateTime".into(), Value::String(v.clone()));
                        }
                        if let Some(ref v) = exif.software {
                            arr.set_string("Software".into(), Value::String(v.clone()));
                        }
                        if let Some(v) = exif.image_width {
                            arr.set_string("ImageWidth".into(), Value::Long(v as i64));
                        }
                        if let Some(v) = exif.image_height {
                            arr.set_string("ImageLength".into(), Value::Long(v as i64));
                        }
                        if let Some(ref v) = exif.exposure_time {
                            arr.set_string("ExposureTime".into(), Value::String(v.clone()));
                        }
                        if let Some(ref v) = exif.f_number {
                            arr.set_string("FNumber".into(), Value::String(v.clone()));
                        }
                        if let Some(v) = exif.iso_speed {
                            arr.set_string("ISOSpeedRatings".into(), Value::Long(v as i64));
                        }
                        if let Some(ref v) = exif.focal_length {
                            arr.set_string("FocalLength".into(), Value::String(v.clone()));
                        }
                        Ok(Some(Value::Array(arr)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                },
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }

        // ══════════════════════════════════════════════════════════════
        // Sockets extension
        // ══════════════════════════════════════════════════════════════
        "socket_create" => {
            let domain = args.first().cloned().unwrap_or(Value::Long(2)).to_long() as i32;
            let type_ = args.get(1).cloned().unwrap_or(Value::Long(1)).to_long() as i32;
            let protocol = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            match php_rs_ext_sockets::socket_create(domain, type_, protocol) {
                Ok(sock) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.sockets.insert(id, sock);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "socket_bind" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let addr = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let port = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as u16;
            if let Some(sock) = vm.sockets.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sockets::socket_bind(
                    sock, &addr, port,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_listen" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let backlog = args.get(1).cloned().unwrap_or(Value::Long(128)).to_long() as i32;
            if let Some(sock) = vm.sockets.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sockets::socket_listen(
                    sock, backlog,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_accept" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let sock_clone = vm.sockets.get(&id).cloned();
            if let Some(sock) = sock_clone {
                match php_rs_ext_sockets::socket_accept(&sock) {
                    Ok(new_sock) => {
                        let new_id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.sockets.insert(new_id, new_sock);
                        Ok(Some(Value::Long(new_id)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_connect" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let addr = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let port = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as u16;
            if let Some(sock) = vm.sockets.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sockets::socket_connect(
                    sock, &addr, port,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_read" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let length = args.get(1).cloned().unwrap_or(Value::Long(2048)).to_long() as usize;
            if let Some(sock) = vm.sockets.get(&id) {
                let data = php_rs_ext_sockets::socket_read(sock, length);
                Ok(Some(Value::String(
                    bytes_to_php_string(&data),
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_write" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let data = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(sock) = vm.sockets.get_mut(&id) {
                let written = php_rs_ext_sockets::socket_write(sock, data.as_bytes());
                Ok(Some(Value::Long(written as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_close" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(sock) = vm.sockets.get_mut(&id) {
                php_rs_ext_sockets::socket_close(sock);
            }
            Ok(Some(Value::Null))
        }
        "socket_set_option" | "socket_setopt" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let level = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            let optname = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            let optval = args.get(3).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            if let Some(sock) = vm.sockets.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sockets::socket_set_option(
                    sock, level, optname, optval,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_get_option" | "socket_getopt" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let level = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            let optname = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            if let Some(sock) = vm.sockets.get(&id) {
                Ok(Some(Value::Long(
                    php_rs_ext_sockets::socket_get_option(sock, level, optname) as i64,
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_last_error" => {
            let id = args.first().cloned().unwrap_or(Value::Null);
            if matches!(id, Value::Null) {
                Ok(Some(Value::Long(
                    php_rs_ext_sockets::socket_last_error(None) as i64,
                )))
            } else {
                let rid = id.to_long();
                if let Some(sock) = vm.sockets.get(&rid) {
                    Ok(Some(Value::Long(
                        php_rs_ext_sockets::socket_last_error(Some(sock)) as i64,
                    )))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }
        }
        "socket_strerror" => {
            let errno = args.first().cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            Ok(Some(Value::String(php_rs_ext_sockets::socket_strerror(
                errno,
            ))))
        }
        "socket_getpeername" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(sock) = vm.sockets.get(&id) {
                match php_rs_ext_sockets::socket_getpeername(sock) {
                    Some((addr, port)) => {
                        vm.write_back_arg(1, Value::String(addr), ref_args, ref_prop_args);
                        vm.write_back_arg(2, Value::Long(port as i64), ref_args, ref_prop_args);
                        Ok(Some(Value::Bool(true)))
                    }
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "socket_getsockname" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(sock) = vm.sockets.get(&id) {
                match php_rs_ext_sockets::socket_getsockname(sock) {
                    Some((addr, port)) => {
                        vm.write_back_arg(1, Value::String(addr), ref_args, ref_prop_args);
                        vm.write_back_arg(2, Value::Long(port as i64), ref_args, ref_prop_args);
                        Ok(Some(Value::Bool(true)))
                    }
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // SimpleXML extension
        // ══════════════════════════════════════════════════════════════
        "simplexml_load_string" => {
            let xml = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_simplexml::simplexml_load_string(&xml) {
                Some(elem) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.simplexml_elements.insert(id, elem);
                    Ok(Some(Value::Long(id)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "simplexml_load_file" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_simplexml::simplexml_load_file(&path) {
                Ok(elem) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.simplexml_elements.insert(id, elem);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "simplexml_import_dom" => Ok(Some(Value::Bool(false))),

        // ══════════════════════════════════════════════════════════════
        // XMLReader extension
        // ══════════════════════════════════════════════════════════════
        "xmlreader_open" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_xmlreader::xmlreader_open(&path) {
                Ok(reader) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.xml_readers.insert(id, reader);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }

        // ══════════════════════════════════════════════════════════════
        // Phar extension
        // ══════════════════════════════════════════════════════════════
        "phar_running" => Ok(Some(Value::String(php_rs_ext_phar::PharArchive::running()))),

        // ══════════════════════════════════════════════════════════════
        // SOAP extension
        // ══════════════════════════════════════════════════════════════
        "is_soap_fault" => {
            // Stub: checks if value looks like a SoapFault
            Ok(Some(Value::Bool(false)))
        }

        // ══════════════════════════════════════════════════════════════
        // LDAP extension
        // ══════════════════════════════════════════════════════════════
        "ldap_connect" => {
            let host = args
                .first()
                .cloned()
                .unwrap_or(Value::String("localhost".to_string()))
                .to_php_string();
            let port = args.get(1).cloned().unwrap_or(Value::Long(389)).to_long() as u16;
            match php_rs_ext_ldap::ldap_connect(&host, port) {
                Ok(conn) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.ldap_connections.insert(id, conn);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "ldap_bind" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dn = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String(String::new()))
                .to_php_string();
            let password = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String(String::new()))
                .to_php_string();
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_bind(
                    conn, &dn, &password,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_unbind" | "ldap_close" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_unbind(conn))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_search" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let base_dn = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let filter = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            let conn_clone = vm.ldap_connections.get(&id).cloned();
            if let Some(conn) = conn_clone {
                match php_rs_ext_ldap::ldap_search(&conn, &base_dn, &filter, &[]) {
                    Ok(result) => {
                        let rid = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.ldap_search_results.insert(rid, result);
                        Ok(Some(Value::Long(rid)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_count_entries" => {
            let _conn_id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let result_id = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(result) = vm.ldap_search_results.get(&result_id) {
                Ok(Some(Value::Long(result.count as i64)))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "ldap_set_option" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let option = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            let value = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_set_option(
                    conn, option, value,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_error" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ldap_connections.get(&id) {
                Ok(Some(Value::String(php_rs_ext_ldap::ldap_error(conn))))
            } else {
                Ok(Some(Value::String("Unknown error".to_string())))
            }
        }
        "ldap_errno" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ldap_connections.get(&id) {
                Ok(Some(Value::Long(php_rs_ext_ldap::ldap_errno(conn) as i64)))
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "ldap_escape" => {
            let value = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let ignore = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String(String::new()))
                .to_php_string();
            let flags = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            Ok(Some(Value::String(php_rs_ext_ldap::ldap_escape(
                &value, &ignore, flags,
            ))))
        }
        "ldap_add" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dn = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                let entry = std::collections::HashMap::new();
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_add(
                    conn, &dn, &entry,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_modify" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dn = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                let entry = std::collections::HashMap::new();
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_modify(
                    conn, &dn, &entry,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ldap_delete" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dn = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ldap_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_ldap::ldap_delete(conn, &dn))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // FTP extension
        // ══════════════════════════════════════════════════════════════
        "ftp_connect" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let port = args.get(1).cloned().unwrap_or(Value::Long(21)).to_long() as u16;
            let timeout = args.get(2).cloned().unwrap_or(Value::Long(90)).to_long() as u32;
            match php_rs_ext_ftp::ftp_connect(&host, port, timeout) {
                Ok(conn) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.ftp_connections.insert(id, conn);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "ftp_login" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let user = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let pass = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_login(conn, &user, &pass) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_pwd" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ftp_connections.get(&id) {
                match php_rs_ext_ftp::ftp_pwd(conn) {
                    Ok(path) => Ok(Some(Value::String(path))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_chdir" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dir = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_chdir(conn, &dir) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_mkdir" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dir = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_mkdir(conn, &dir) {
                    Ok(path) => Ok(Some(Value::String(path))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_rmdir" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dir = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_rmdir(conn, &dir) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_nlist" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dir = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String(".".to_string()))
                .to_php_string();
            if let Some(conn) = vm.ftp_connections.get(&id) {
                match php_rs_ext_ftp::ftp_nlist(conn, &dir) {
                    Ok(list) => {
                        let mut arr = PhpArray::new();
                        for item in list {
                            arr.push(Value::String(item));
                        }
                        Ok(Some(Value::Array(arr)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_rawlist" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let dir = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String(".".to_string()))
                .to_php_string();
            if let Some(conn) = vm.ftp_connections.get(&id) {
                match php_rs_ext_ftp::ftp_rawlist(conn, &dir) {
                    Ok(list) => {
                        let mut arr = PhpArray::new();
                        for item in list {
                            arr.push(Value::String(item));
                        }
                        Ok(Some(Value::Array(arr)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_delete" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let path = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_delete(conn, &path) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_rename" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let old = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let new_name = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_rename(conn, &old, &new_name) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_size" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let remote = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.ftp_connections.get(&id) {
                match php_rs_ext_ftp::ftp_size(conn, &remote) {
                    Ok(size) => Ok(Some(Value::Long(size))),
                    Err(_) => Ok(Some(Value::Long(-1))),
                }
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "ftp_close" | "ftp_quit" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_ftp::ftp_close(conn))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_pasv" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let pasv = args.get(1).cloned().unwrap_or(Value::Bool(true)).to_bool();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_pasv(conn, pasv) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_systype" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ftp_connections.get(&id) {
                match php_rs_ext_ftp::ftp_systype(conn) {
                    Ok(s) => Ok(Some(Value::String(s))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "ftp_cdup" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.ftp_connections.get_mut(&id) {
                match php_rs_ext_ftp::ftp_cdup(conn) {
                    Ok(v) => Ok(Some(Value::Bool(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // ODBC extension
        // ══════════════════════════════════════════════════════════════
        "odbc_connect" => {
            let dsn = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let user = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let pass = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_odbc::odbc_connect(&dsn, &user, &pass) {
                Ok(conn) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.odbc_connections.insert(id, conn);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "odbc_close" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.odbc_connections.get_mut(&id) {
                php_rs_ext_odbc::odbc_close(conn);
            }
            Ok(Some(Value::Bool(true)))
        }
        "odbc_exec" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let query = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(conn) = vm.odbc_connections.get_mut(&id) {
                match php_rs_ext_odbc::odbc_exec(conn, &query) {
                    Ok(result) => {
                        let rid = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.odbc_results.insert(rid, result);
                        Ok(Some(Value::Long(rid)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_prepare" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let query = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let conn_clone = vm.odbc_connections.get(&id).cloned();
            if let Some(conn) = conn_clone {
                match php_rs_ext_odbc::odbc_prepare(&conn, &query) {
                    Ok(stmt) => {
                        let sid = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.odbc_stmts.insert(sid, stmt);
                        Ok(Some(Value::Long(sid)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_execute" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(stmt) = vm.odbc_stmts.get_mut(&id) {
                match php_rs_ext_odbc::odbc_execute(stmt) {
                    Ok(result) => {
                        let rid = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.odbc_results.insert(rid, result);
                        Ok(Some(Value::Bool(true)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_fetch_row" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(result) = vm.odbc_results.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_odbc::odbc_fetch_row(result))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_result" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let field = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(result) = vm.odbc_results.get(&id) {
                match php_rs_ext_odbc::odbc_result(result, &field) {
                    Some(val) => Ok(Some(Value::String(val))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_num_rows" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(result) = vm.odbc_results.get(&id) {
                Ok(Some(Value::Long(php_rs_ext_odbc::odbc_num_rows(result))))
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "odbc_num_fields" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(result) = vm.odbc_results.get(&id) {
                Ok(Some(Value::Long(
                    php_rs_ext_odbc::odbc_num_fields(result) as i64
                )))
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "odbc_field_name" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let num = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            if let Some(result) = vm.odbc_results.get(&id) {
                match php_rs_ext_odbc::odbc_field_name(result, num) {
                    Some(name) => Ok(Some(Value::String(name))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_field_type" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let num = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as i32;
            if let Some(result) = vm.odbc_results.get(&id) {
                match php_rs_ext_odbc::odbc_field_type(result, num) {
                    Some(t) => Ok(Some(Value::String(t))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_commit" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.odbc_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_odbc::odbc_commit(conn))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_rollback" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.odbc_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_odbc::odbc_rollback(conn))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_autocommit" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let on_off = args.get(1).map(|v| v.to_bool());
            if let Some(conn) = vm.odbc_connections.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_odbc::odbc_autocommit(
                    conn, on_off,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "odbc_error" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.odbc_connections.get(&id) {
                Ok(Some(Value::String(php_rs_ext_odbc::odbc_error(conn))))
            } else {
                Ok(Some(Value::String(String::new())))
            }
        }
        "odbc_errormsg" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(conn) = vm.odbc_connections.get(&id) {
                Ok(Some(Value::String(php_rs_ext_odbc::odbc_errormsg(conn))))
            } else {
                Ok(Some(Value::String(String::new())))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // SNMP extension
        // ══════════════════════════════════════════════════════════════
        "snmpget" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmpget(&host, &community, &oid) {
                Ok(val) => Ok(Some(Value::String(val))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmpgetnext" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmpgetnext(&host, &community, &oid) {
                Ok(val) => Ok(Some(Value::String(val))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmpwalk" | "snmpwalkoid" | "snmprealwalk" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmpwalk(&host, &community, &oid) {
                Ok(vals) => {
                    let mut arr = PhpArray::new();
                    for v in vals {
                        arr.push(Value::String(v));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmpset" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            let type_ = args.get(3).cloned().unwrap_or(Value::Null).to_php_string();
            let value = args.get(4).cloned().unwrap_or(Value::Null).to_php_string();
            let t = type_.chars().next().unwrap_or('s');
            Ok(Some(Value::Bool(php_rs_ext_snmp::snmpset(
                &host, &community, &oid, t, &value,
            ))))
        }
        "snmp2_get" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmp2_get(&host, &community, &oid) {
                Ok(val) => Ok(Some(Value::String(val))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmp2_getnext" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmp2_getnext(&host, &community, &oid) {
                Ok(val) => Ok(Some(Value::String(val))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmp2_walk" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_snmp::snmp2_walk(&host, &community, &oid) {
                Ok(vals) => {
                    let mut arr = PhpArray::new();
                    for v in vals {
                        arr.push(Value::String(v));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "snmp2_set" => {
            let host = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let community = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let oid = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            let type_ = args.get(3).cloned().unwrap_or(Value::Null).to_php_string();
            let value = args.get(4).cloned().unwrap_or(Value::Null).to_php_string();
            let t = type_.chars().next().unwrap_or('s');
            Ok(Some(Value::Bool(php_rs_ext_snmp::snmp2_set(
                &host, &community, &oid, t, &value,
            ))))
        }
        "snmp_get_quick_print" => Ok(Some(Value::Bool(php_rs_ext_snmp::snmp_get_quick_print()))),
        "snmp_set_quick_print" => {
            let enable = args
                .first()
                .cloned()
                .unwrap_or(Value::Bool(false))
                .to_bool();
            php_rs_ext_snmp::snmp_set_quick_print(enable);
            Ok(Some(Value::Bool(true)))
        }

        // ══════════════════════════════════════════════════════════════
        // DBA extension
        // ══════════════════════════════════════════════════════════════
        "dba_open" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mode = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String("r".to_string()))
                .to_php_string();
            let handler = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String("flatfile".to_string()))
                .to_php_string();
            match php_rs_ext_dba::dba_open(&path, &mode, &handler) {
                Ok(handle) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.dba_handles.insert(id, handle);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "dba_close" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            vm.dba_handles.remove(&id);
            Ok(Some(Value::Null))
        }
        "dba_exists" => {
            let key = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let id = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_exists(&key, handle))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_fetch" => {
            let key = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let id = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get(&id) {
                match php_rs_ext_dba::dba_fetch(&key, handle) {
                    Some(val) => Ok(Some(Value::String(val))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_insert" => {
            let key = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let value = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let id = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_insert(
                    &key, &value, handle,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_replace" => {
            let key = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let value = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let id = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_replace(
                    &key, &value, handle,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_delete" => {
            let key = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let id = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_delete(&key, handle))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_firstkey" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get_mut(&id) {
                match php_rs_ext_dba::dba_firstkey(handle) {
                    Some(key) => Ok(Some(Value::String(key))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_nextkey" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get_mut(&id) {
                match php_rs_ext_dba::dba_nextkey(handle) {
                    Some(key) => Ok(Some(Value::String(key))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_list" => {
            // Return all open handles
            let mut arr = PhpArray::new();
            for (id, handle) in &vm.dba_handles {
                arr.set_string(id.to_string(), Value::String(handle.path.clone()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "dba_handlers" => {
            let handlers = php_rs_ext_dba::dba_handlers();
            let mut arr = PhpArray::new();
            for h in handlers {
                arr.push(Value::String(h));
            }
            Ok(Some(Value::Array(arr)))
        }
        "dba_sync" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_sync(handle))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "dba_optimize" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(handle) = vm.dba_handles.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_dba::dba_optimize(handle))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // Enchant extension
        // ══════════════════════════════════════════════════════════════
        "enchant_broker_init" => {
            let broker = php_rs_ext_enchant::enchant_broker_init();
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.enchant_brokers.insert(id, broker);
            Ok(Some(Value::Long(id)))
        }
        "enchant_broker_free" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(broker) = vm.enchant_brokers.get_mut(&id) {
                php_rs_ext_enchant::enchant_broker_free(broker);
            }
            Ok(Some(Value::Bool(true)))
        }
        "enchant_broker_dict_exists" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let tag = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(broker) = vm.enchant_brokers.get(&id) {
                Ok(Some(Value::Bool(
                    php_rs_ext_enchant::enchant_broker_dict_exists(broker, &tag),
                )))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "enchant_broker_request_dict" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let tag = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(broker) = vm.enchant_brokers.get_mut(&id) {
                match php_rs_ext_enchant::enchant_broker_request_dict(broker, &tag) {
                    Ok(_) => {
                        // Return broker id + tag as dict identifier
                        Ok(Some(Value::Long(id)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "enchant_broker_free_dict" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let tag = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(broker) = vm.enchant_brokers.get_mut(&id) {
                php_rs_ext_enchant::enchant_broker_free_dict(broker, &tag);
            }
            Ok(Some(Value::Bool(true)))
        }
        "enchant_broker_list_dicts" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(broker) = vm.enchant_brokers.get(&id) {
                let dicts = php_rs_ext_enchant::enchant_broker_list_dicts(broker);
                let mut arr = PhpArray::new();
                for d in dicts {
                    arr.push(Value::String(d));
                }
                Ok(Some(Value::Array(arr)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "enchant_dict_check" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let word = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            // Use default "en_US" dict from broker
            if let Some(broker) = vm.enchant_brokers.get(&id) {
                // Find first available dict
                let dicts = php_rs_ext_enchant::enchant_broker_list_dicts(broker);
                if let Some(tag) = dicts.first() {
                    if let Some(dict) = broker.dictionaries.get(tag.as_str()) {
                        Ok(Some(Value::Bool(php_rs_ext_enchant::enchant_dict_check(
                            dict, &word,
                        ))))
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "enchant_dict_suggest" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let word = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(broker) = vm.enchant_brokers.get(&id) {
                let dicts = php_rs_ext_enchant::enchant_broker_list_dicts(broker);
                if let Some(tag) = dicts.first() {
                    if let Some(dict) = broker.dictionaries.get(tag.as_str()) {
                        let suggestions = php_rs_ext_enchant::enchant_dict_suggest(dict, &word);
                        let mut arr = PhpArray::new();
                        for s in suggestions {
                            arr.push(Value::String(s));
                        }
                        Ok(Some(Value::Array(arr)))
                    } else {
                        Ok(Some(Value::Array(PhpArray::new())))
                    }
                } else {
                    Ok(Some(Value::Array(PhpArray::new())))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // System V Semaphore extension
        // ══════════════════════════════════════════════════════════════
        "sem_get" => {
            let key = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let max_acquire = args.get(1).cloned().unwrap_or(Value::Long(1)).to_long() as i32;
            let perms = args.get(2).cloned().unwrap_or(Value::Long(0o666)).to_long() as i32;
            let auto_release = args.get(3).cloned().unwrap_or(Value::Bool(true)).to_bool();
            match php_rs_ext_sysvsem::sem_get(key, max_acquire, perms, auto_release) {
                Ok(sem) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.sysv_semaphores.insert(id, sem);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "sem_acquire" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let non_blocking = args.get(1).cloned().unwrap_or(Value::Bool(false)).to_bool();
            if let Some(sem) = vm.sysv_semaphores.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvsem::sem_acquire(
                    sem,
                    non_blocking,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "sem_release" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(sem) = vm.sysv_semaphores.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvsem::sem_release(sem))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "sem_remove" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(sem) = vm.sysv_semaphores.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvsem::sem_remove(sem))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // System V Shared Memory extension
        // ══════════════════════════════════════════════════════════════
        "shm_attach" => {
            let key = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let memsize = args.get(1).cloned().unwrap_or(Value::Long(10000)).to_long() as usize;
            let perm = args.get(2).cloned().unwrap_or(Value::Long(0o666)).to_long() as i32;
            match php_rs_ext_sysvshm::shm_attach(key, memsize, perm) {
                Ok(shm) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.sysv_shm.insert(id, shm);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "shm_detach" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(shm) = vm.sysv_shm.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvshm::shm_detach(shm))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shm_remove" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(shm) = vm.sysv_shm.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvshm::shm_remove(shm))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shm_get_var" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let var_key = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(shm) = vm.sysv_shm.get(&id) {
                match php_rs_ext_sysvshm::shm_get_var(shm, var_key) {
                    Some(data) => Ok(Some(Value::String(
                        bytes_to_php_string(&data),
                    ))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shm_put_var" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let var_key = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            let value = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(shm) = vm.sysv_shm.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvshm::shm_put_var(
                    shm,
                    var_key,
                    value.as_bytes(),
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shm_has_var" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let var_key = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(shm) = vm.sysv_shm.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvshm::shm_has_var(
                    shm, var_key,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shm_remove_var" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let var_key = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(shm) = vm.sysv_shm.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvshm::shm_remove_var(
                    shm, var_key,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ══════════════════════════════════════════════════════════════
        // System V Message Queue extension
        // ══════════════════════════════════════════════════════════════
        "msg_get_queue" => {
            let key = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let perms = args.get(1).cloned().unwrap_or(Value::Long(0o666)).to_long() as i32;
            match php_rs_ext_sysvmsg::msg_get_queue(key, perms) {
                Ok(queue) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.sysv_msg_queues.insert(id, queue);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "msg_send" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let msgtype = args.get(1).cloned().unwrap_or(Value::Long(1)).to_long();
            let message = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(queue) = vm.sysv_msg_queues.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvmsg::msg_send(
                    queue,
                    msgtype,
                    message.as_bytes(),
                    false,
                    true,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "msg_receive" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let desired_type = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            let maxsize = args.get(3).cloned().unwrap_or(Value::Long(16384)).to_long() as usize;
            if let Some(queue) = vm.sysv_msg_queues.get_mut(&id) {
                let mut msgtype_out = 0i64;
                let mut message_out = Vec::new();
                let success = php_rs_ext_sysvmsg::msg_receive(
                    queue,
                    desired_type,
                    &mut msgtype_out,
                    maxsize,
                    &mut message_out,
                    false,
                    0,
                );
                if success {
                    // Write back msgtype (arg index 2 = 3rd parameter)
                    vm.write_back_arg(2, Value::Long(msgtype_out), ref_args, ref_prop_args);
                    // Write back message (arg index 4 = 5th parameter)
                    vm.write_back_arg(
                        4,
                        Value::String(bytes_to_php_string(&message_out)),
                        ref_args,
                        ref_prop_args,
                    );
                }
                Ok(Some(Value::Bool(success)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "msg_remove_queue" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(queue) = vm.sysv_msg_queues.get(&id) {
                Ok(Some(Value::Bool(php_rs_ext_sysvmsg::msg_remove_queue(
                    queue,
                ))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "msg_stat_queue" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(queue) = vm.sysv_msg_queues.get(&id) {
                let stat = php_rs_ext_sysvmsg::msg_stat_queue(queue);
                let mut arr = PhpArray::new();
                arr.set_string("msg_qnum".into(), Value::Long(stat.msg_qnum as i64));
                arr.set_string("msg_qbytes".into(), Value::Long(stat.msg_qbytes as i64));
                arr.set_string("msg_lspid".into(), Value::Long(stat.msg_lspid as i64));
                arr.set_string("msg_lrpid".into(), Value::Long(stat.msg_lrpid as i64));
                Ok(Some(Value::Array(arr)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "msg_queue_exists" => {
            let key = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            Ok(Some(Value::Bool(php_rs_ext_sysvmsg::msg_queue_exists(key))))
        }

        // ══════════════════════════════════════════════════════════════
        // Shared Memory (shmop) extension
        // ══════════════════════════════════════════════════════════════
        "shmop_open" => {
            let key = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let flags = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String("c".to_string()))
                .to_php_string();
            let mode = args.get(2).cloned().unwrap_or(Value::Long(0o644)).to_long() as i32;
            let size = args.get(3).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            match php_rs_ext_shmop::shmop_open(key, &flags, mode, size) {
                Ok(block) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.shmop_blocks.insert(id, block);
                    Ok(Some(Value::Long(id)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "shmop_read" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let start = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            let count = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            if let Some(block) = vm.shmop_blocks.get(&id) {
                match php_rs_ext_shmop::shmop_read(block, start, count) {
                    Ok(data) => Ok(Some(Value::String(
                        bytes_to_php_string(&data),
                    ))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shmop_write" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            let data = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            if let Some(block) = vm.shmop_blocks.get_mut(&id) {
                match php_rs_ext_shmop::shmop_write(block, data.as_bytes(), offset) {
                    Ok(n) => Ok(Some(Value::Long(n as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shmop_size" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(block) = vm.shmop_blocks.get(&id) {
                Ok(Some(
                    Value::Long(php_rs_ext_shmop::shmop_size(block) as i64),
                ))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "shmop_delete" => {
            let id = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            if let Some(block) = vm.shmop_blocks.get_mut(&id) {
                Ok(Some(Value::Bool(php_rs_ext_shmop::shmop_delete(block))))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "shmop_close" => {
            // Deprecated since PHP 8.0, no-op
            Ok(Some(Value::Null))
        }

        _ => Ok(None),
    }
}

/// Strip comments and whitespace from PHP source code.
/// Mimics the behavior of php_strip_whitespace().
fn php_strip_whitespace_impl(code: &str) -> String {
    let mut result = String::new();
    let mut in_single_line_comment = false;
    let mut in_multi_line_comment = false;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_heredoc = false;
    let mut prev_char = '\0';
    let chars: Vec<char> = code.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        if in_single_line_comment {
            if c == '\n' {
                in_single_line_comment = false;
                result.push('\n');
            }
            i += 1;
            continue;
        }

        if in_multi_line_comment {
            if c == '*' && i + 1 < len && chars[i + 1] == '/' {
                in_multi_line_comment = false;
                i += 2;
                // Add a space to prevent tokens from merging
                if !result.ends_with(' ') && !result.ends_with('\n') {
                    result.push(' ');
                }
                continue;
            }
            if c == '\n' {
                result.push('\n');
            }
            i += 1;
            continue;
        }

        if in_single_quote {
            result.push(c);
            if c == '\'' && prev_char != '\\' {
                in_single_quote = false;
            }
            prev_char = c;
            i += 1;
            continue;
        }

        if in_double_quote {
            result.push(c);
            if c == '"' && prev_char != '\\' {
                in_double_quote = false;
            }
            prev_char = c;
            i += 1;
            continue;
        }

        // Check for comments
        if c == '/' && i + 1 < len {
            if chars[i + 1] == '/' {
                in_single_line_comment = true;
                i += 2;
                continue;
            }
            if chars[i + 1] == '*' {
                in_multi_line_comment = true;
                i += 2;
                continue;
            }
        }
        if c == '#' && !in_single_quote && !in_double_quote {
            in_single_line_comment = true;
            i += 1;
            continue;
        }

        // Check for strings
        if c == '\'' {
            in_single_quote = true;
            result.push(c);
            prev_char = c;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double_quote = true;
            result.push(c);
            prev_char = c;
            i += 1;
            continue;
        }

        // Collapse whitespace
        if c.is_whitespace() {
            if !result.ends_with(' ') && !result.ends_with('\n') && !result.is_empty() {
                if c == '\n' {
                    result.push('\n');
                } else {
                    result.push(' ');
                }
            }
        } else {
            result.push(c);
        }

        prev_char = c;
        i += 1;
    }

    result
}

/// Produce HTML syntax-highlighted output for PHP code.
/// Mimics highlight_string() — wraps code in <pre><code> with <span> color tags.
fn php_highlight_string(code: &str) -> String {
    let mut result = String::from("<pre><code>");
    let mut in_single_line_comment = false;
    let mut in_multi_line_comment = false;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = '\0';
    let chars: Vec<char> = code.chars().collect();
    let len = chars.len();
    let mut i = 0;

    fn html_escape(c: char) -> String {
        match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            _ => c.to_string(),
        }
    }

    while i < len {
        let c = chars[i];

        if in_single_line_comment {
            if c == '\n' {
                in_single_line_comment = false;
                result.push_str("</span>\n");
            } else {
                result.push_str(&html_escape(c));
            }
            i += 1;
            continue;
        }

        if in_multi_line_comment {
            if c == '*' && i + 1 < len && chars[i + 1] == '/' {
                in_multi_line_comment = false;
                result.push_str("*/</span>");
                i += 2;
                continue;
            }
            result.push_str(&html_escape(c));
            i += 1;
            continue;
        }

        if in_single_quote {
            result.push_str(&html_escape(c));
            if c == '\'' && prev_char != '\\' {
                in_single_quote = false;
                result.push_str("</span>");
            }
            prev_char = c;
            i += 1;
            continue;
        }

        if in_double_quote {
            result.push_str(&html_escape(c));
            if c == '"' && prev_char != '\\' {
                in_double_quote = false;
                result.push_str("</span>");
            }
            prev_char = c;
            i += 1;
            continue;
        }

        // Check for comments
        if c == '/' && i + 1 < len {
            if chars[i + 1] == '/' {
                in_single_line_comment = true;
                result.push_str("<span style=\"color: #FF8000\">//");
                i += 2;
                continue;
            }
            if chars[i + 1] == '*' {
                in_multi_line_comment = true;
                result.push_str("<span style=\"color: #FF8000\">/*");
                i += 2;
                continue;
            }
        }
        if c == '#' {
            in_single_line_comment = true;
            result.push_str("<span style=\"color: #FF8000\">#");
            i += 1;
            continue;
        }

        // Strings
        if c == '\'' {
            in_single_quote = true;
            result.push_str("<span style=\"color: #DD0000\">'");
            prev_char = c;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double_quote = true;
            result.push_str("<span style=\"color: #DD0000\">\"");
            prev_char = c;
            i += 1;
            continue;
        }

        // Keywords
        if c == '$' {
            result.push_str("<span style=\"color: #0000BB\">$");
            i += 1;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                result.push_str(&html_escape(chars[i]));
                i += 1;
            }
            result.push_str("</span>");
            continue;
        }

        result.push_str(&html_escape(c));
        prev_char = c;
        i += 1;
    }

    // Close any open spans
    if in_single_line_comment || in_multi_line_comment || in_single_quote || in_double_quote {
        result.push_str("</span>");
    }

    result.push_str("</code></pre>");
    result
}
