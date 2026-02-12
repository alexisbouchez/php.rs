//! Helper free functions — extracted from vm.rs.
//!
//! Format helpers, regex, serialization, date math, etc.

use super::Vm;
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use php_rs_compiler::op_array::Literal;

/// Convert a `rusqlite::types::Value` to a PHP VM `Value`.
#[cfg(feature = "native-io")]
pub(crate) fn sqlite3_rusql_to_vm_value(v: rusqlite::types::Value) -> Value {
    match v {
        rusqlite::types::Value::Integer(i) => Value::Long(i),
        rusqlite::types::Value::Real(f) => Value::Double(f),
        rusqlite::types::Value::Text(s) => Value::String(s),
        rusqlite::types::Value::Blob(b) => Value::String(String::from_utf8_lossy(&b).into_owned()),
        rusqlite::types::Value::Null => Value::Null,
    }
}

/// Convert a PHP VM `Value` + SQLite3 type hint to a bindable `Sqlite3ParamValue`.
#[cfg(feature = "native-io")]
pub(crate) fn vm_value_to_sqlite3_param(
    val: Value,
    type_hint: i64,
) -> crate::sqlite3::Sqlite3ParamValue {
    use crate::sqlite3::Sqlite3ParamValue;
    match type_hint {
        1 => Sqlite3ParamValue::Integer(val.to_long()), // SQLITE3_INTEGER
        2 => Sqlite3ParamValue::Float(val.to_double()), // SQLITE3_FLOAT
        3 => Sqlite3ParamValue::Text(val.to_php_string()), // SQLITE3_TEXT
        4 => Sqlite3ParamValue::Blob(val.to_php_string().into_bytes()), // SQLITE3_BLOB
        5 => Sqlite3ParamValue::Null,                   // SQLITE3_NULL
        _ => match val {
            Value::Null => Sqlite3ParamValue::Null,
            Value::Long(n) => Sqlite3ParamValue::Integer(n),
            Value::Double(f) => Sqlite3ParamValue::Float(f),
            Value::Bool(b) => Sqlite3ParamValue::Integer(b as i64),
            v => Sqlite3ParamValue::Text(v.to_php_string()),
        },
    }
}

#[inline]
pub(crate) fn literal_to_value(lit: &Literal) -> Value {
    match lit {
        Literal::Null => Value::Null,
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Long(n) => Value::Long(*n),
        Literal::Double(f) => Value::Double(*f),
        Literal::String(s) => Value::String(s.clone()),
        Literal::ClassConst(_, _) => Value::Null, // Cannot resolve without VM context
        Literal::LongJumpTable(_) | Literal::StringJumpTable(_) => Value::Null,
    }
}

/// Apply a compound assignment operation.
#[inline]
pub(crate) fn apply_assign_op(op_code: u32, lhs: &Value, rhs: &Value) -> Value {
    match op_code {
        1 => lhs.add(rhs),     // ADD
        2 => lhs.sub(rhs),     // SUB
        3 => lhs.mul(rhs),     // MUL
        4 => lhs.div(rhs),     // DIV
        5 => lhs.modulo(rhs),  // MOD
        6 => lhs.shl(rhs),     // SL
        7 => lhs.shr(rhs),     // SR
        8 => lhs.concat(rhs),  // CONCAT
        9 => lhs.bw_or(rhs),   // BW_OR
        10 => lhs.bw_and(rhs), // BW_AND
        11 => lhs.bw_xor(rhs), // BW_XOR
        12 => lhs.pow(rhs),    // POW
        _ => lhs.add(rhs),     // fallback
    }
}

/// Format a float as PHP would.
pub(crate) fn format_php_float(f: f64) -> String {
    if f.is_nan() {
        "NAN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 {
            "INF".to_string()
        } else {
            "-INF".to_string()
        }
    } else {
        let s = format!("{}", f);
        s
    }
}

// ── Helper functions for built-in implementations ──

/// Parse a PHP-style regex pattern like /pattern/flags.
pub(crate) fn parse_php_regex(pattern: &str) -> Option<(String, String)> {
    if pattern.is_empty() {
        return None;
    }
    let delimiter = pattern.as_bytes()[0] as char;
    let (end_delim, is_paired) = match delimiter {
        '(' => (')', true),
        '[' => (']', true),
        '{' => ('}', true),
        '<' => ('>', true),
        c if c.is_alphanumeric() || c == '\\' => return None,
        c => (c, false),
    };
    // Find the closing delimiter (not escaped), tracking nesting for paired delimiters
    let body = &pattern[1..];
    let mut i = 0;
    let mut depth = 0i32;
    let bytes = body.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // Skip escaped char
        } else if is_paired && bytes[i] == delimiter as u8 {
            depth += 1;
            i += 1;
        } else if bytes[i] == end_delim as u8 {
            if depth > 0 && is_paired {
                depth -= 1;
                i += 1;
            } else {
                let re_pattern = &body[..i];
                let flags = &body[i + 1..];
                return Some((re_pattern.to_string(), flags.to_string()));
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Apply PHP regex modifier flags to a pattern string for Rust regex.
pub(crate) fn apply_regex_flags(pattern: &str, flags: &str) -> String {
    // Strip PCRE verbs that Rust regex doesn't support ((*UTF8), (*UCP), etc.)
    // Rust regex is UTF-8 by default and supports Unicode properties natively.
    let pattern = pattern
        .replace("(*UTF8)", "")
        .replace("(*UCP)", "")
        .replace("(*BSR_ANYCRLF)", "")
        .replace("(*ANYCRLF)", "");
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('s') {
        prefix.push_str("(?s)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    if flags.contains('x') {
        prefix.push_str("(?x)");
    }
    // 'U' flag = ungreedy — swap greedy/lazy meaning of quantifiers
    if flags.contains('U') {
        prefix.push_str("(?U)");
    }
    // 'u' flag = UTF-8 mode — Rust regex is UTF-8 by default, but we enable Unicode
    // (no-op for standard regex crate, but recognized for compatibility)
    // 'D' flag = dollar end only — $ matches only at end of string, not before trailing \n
    // Rust regex $ already only matches at end (no PCRE_DOLLAR_ENDONLY needed),
    // unless (?m) is set. In non-multiline mode this is default Rust behavior.
    // 'S' flag = study pattern — optimization hint, no-op in Rust
    // 'A' flag = anchored — prepend ^ to anchor at start position
    // (actual offset handling is done in the preg_match caller)
    if flags.contains('A') {
        format!("{}^{}", prefix, pattern)
    } else {
        format!("{}{}", prefix, pattern)
    }
}

/// Convert a VM Value to a SerializableValue for PHP serialize().
pub(crate) fn value_to_serializable(
    val: &Value,
) -> php_rs_ext_standard::variables::SerializableValue {
    use php_rs_ext_standard::variables::SerializableValue as SV;
    if let Value::Reference(rc) = val {
        return value_to_serializable(&rc.borrow());
    }
    match val {
        Value::Null => SV::Null,
        Value::Bool(b) => SV::Bool(*b),
        Value::Long(n) => SV::Int(*n),
        Value::Double(f) => SV::Float(*f),
        Value::String(s) => SV::Str(s.clone()),
        Value::Array(a) => {
            let entries: Vec<_> = a
                .entries()
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        crate::value::ArrayKey::Int(n) => SV::Int(*n),
                        crate::value::ArrayKey::String(s) => SV::Str(s.clone()),
                    };
                    (key, value_to_serializable(v))
                })
                .collect();
            SV::Array(entries)
        }
        Value::Object(o) => {
            let props: Vec<_> = o
                .properties()
                .iter()
                .map(|(k, v)| (SV::Str(k.clone()), value_to_serializable(v)))
                .collect();
            SV::Object(o.class_name().to_string(), props)
        }
        Value::Resource(id, _) => SV::Int(*id),
        Value::Reference(_) => unreachable!("Reference handled above"),
        Value::_Iterator { .. }
        | Value::_GeneratorIterator { .. }
        | Value::_ObjectIterator { .. }
        | Value::_Rope(_) => SV::Null,
    }
}

/// Convert a SerializableValue back to a VM Value for PHP unserialize().
pub(crate) fn serializable_to_value(
    sv: &php_rs_ext_standard::variables::SerializableValue,
) -> Value {
    use php_rs_ext_standard::variables::SerializableValue as SV;
    match sv {
        SV::Null => Value::Null,
        SV::Bool(b) => Value::Bool(*b),
        SV::Int(n) => Value::Long(*n),
        SV::Float(f) => Value::Double(*f),
        SV::Str(s) => Value::String(s.clone()),
        SV::Array(entries) => {
            let mut arr = PhpArray::new();
            for (k, v) in entries {
                let key = match k {
                    SV::Int(n) => Value::Long(*n),
                    SV::Str(s) => Value::String(s.clone()),
                    _ => Value::String(String::new()),
                };
                arr.set(&key, serializable_to_value(v));
            }
            Value::Array(arr)
        }
        SV::Object(class_name, props) => {
            let obj = PhpObject::new(class_name.clone());
            for (k, v) in props {
                let prop_name = match k {
                    SV::Str(s) => s.clone(),
                    SV::Int(n) => n.to_string(),
                    _ => String::new(),
                };
                obj.set_property(prop_name, serializable_to_value(v));
            }
            Value::Object(obj)
        }
    }
}

/// Parse INI-format string into a PhpArray
pub(crate) fn parse_ini_to_array(content: &str, process_sections: bool) -> PhpArray {
    let mut result = PhpArray::new();
    let mut sections: std::collections::HashMap<String, PhpArray> =
        std::collections::HashMap::new();
    let mut current_section = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            if process_sections {
                sections
                    .entry(current_section.clone())
                    .or_insert_with(PhpArray::new);
            }
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let val_str = trimmed[eq_pos + 1..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            let val = match val_str.to_lowercase().as_str() {
                "true" | "on" | "yes" => Value::String("1".into()),
                "false" | "off" | "no" | "none" | "" => Value::String(String::new()),
                "null" => Value::String(String::new()),
                _ => Value::String(val_str),
            };
            if process_sections && !current_section.is_empty() {
                sections
                    .entry(current_section.clone())
                    .or_insert_with(PhpArray::new)
                    .set_string(key, val);
            } else {
                result.set_string(key, val);
            }
        }
    }
    if process_sections {
        for (sec_name, sec_arr) in sections {
            result.set_string(sec_name, Value::Array(sec_arr));
        }
    }
    result
}

/// Calculate Easter days offset from March 21 (Anonymous Gregorian algorithm)
pub(crate) fn easter_days_calc(year: i64) -> i64 {
    let a = year % 19;
    let b = year / 100;
    let c = year % 100;
    let d = b / 4;
    let e = b % 4;
    let f = (b + 8) / 25;
    let g = (b - f + 1) / 3;
    let h = (19 * a + b - d - g + 15) % 30;
    let i = c / 4;
    let k = c % 4;
    let l = (32 + 2 * e + 2 * i - h - k) % 7;
    let m = (a + 11 * h + 22 * l) / 451;
    let n = (h + l - 7 * m + 114) / 31; // month (3=March, 4=April)
    let p = (h + l - 7 * m + 114) % 31 + 1; // day
                                            // Days from March 21
    if n == 3 {
        p - 21
    } else {
        p + 31 - 21
    }
}

/// Simple glob-style pattern matching (for fnmatch)
pub(crate) fn simple_fnmatch(pattern: &str, string: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = string.chars().collect();
    fn matches(p: &[char], s: &[char]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        if p[0] == '*' {
            // Try matching rest of pattern at each position
            for i in 0..=s.len() {
                if matches(&p[1..], &s[i..]) {
                    return true;
                }
            }
            return false;
        }
        if s.is_empty() {
            return false;
        }
        if p[0] == '?' || p[0] == s[0] {
            return matches(&p[1..], &s[1..]);
        }
        false
    }
    matches(&p, &s)
}

/// Natural order string comparison (like PHP's strnatcmp)
pub(crate) fn nat_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut ai = 0;
    let mut bi = 0;
    while ai < a_chars.len() && bi < b_chars.len() {
        let ac = a_chars[ai];
        let bc = b_chars[bi];
        if ac.is_ascii_digit() && bc.is_ascii_digit() {
            // Compare numeric segments
            let mut a_num = String::new();
            while ai < a_chars.len() && a_chars[ai].is_ascii_digit() {
                a_num.push(a_chars[ai]);
                ai += 1;
            }
            let mut b_num = String::new();
            while bi < b_chars.len() && b_chars[bi].is_ascii_digit() {
                b_num.push(b_chars[bi]);
                bi += 1;
            }
            let an: u64 = a_num.parse().unwrap_or(0);
            let bn: u64 = b_num.parse().unwrap_or(0);
            match an.cmp(&bn) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        } else {
            match ac.cmp(&bc) {
                std::cmp::Ordering::Equal => {
                    ai += 1;
                    bi += 1;
                }
                other => return other,
            }
        }
    }
    a_chars.len().cmp(&b_chars.len())
}

/// Version comparison like PHP's version_compare
pub(crate) fn version_cmp(a: &str, b: &str) -> i32 {
    let normalize = |s: &str| -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        for ch in s.chars() {
            if ch == '.' || ch == '-' || ch == '_' {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            } else {
                current.push(ch);
            }
        }
        if !current.is_empty() {
            parts.push(current);
        }
        parts
    };
    let special_order = |s: &str| -> i32 {
        match s.to_lowercase().as_str() {
            "dev" => 0,
            "alpha" | "a" => 1,
            "beta" | "b" => 2,
            "rc" => 3,
            "pl" | "p" => 5,
            _ => 4,
        }
    };
    let a_parts = normalize(a);
    let b_parts = normalize(b);
    let max = a_parts.len().max(b_parts.len());
    for i in 0..max {
        let ap = a_parts.get(i).map(|s| s.as_str()).unwrap_or("");
        let bp = b_parts.get(i).map(|s| s.as_str()).unwrap_or("");
        let a_is_num = ap.chars().all(|c| c.is_ascii_digit()) && !ap.is_empty();
        let b_is_num = bp.chars().all(|c| c.is_ascii_digit()) && !bp.is_empty();
        if a_is_num && b_is_num {
            let an: i64 = ap.parse().unwrap_or(0);
            let bn: i64 = bp.parse().unwrap_or(0);
            if an != bn {
                return if an < bn { -1 } else { 1 };
            }
        } else if a_is_num {
            return 1; // number > string
        } else if b_is_num {
            return -1;
        } else {
            let ao = special_order(ap);
            let bo = special_order(bp);
            if ao != bo {
                return if ao < bo { -1 } else { 1 };
            }
        }
    }
    0
}

/// Compute days from epoch (1970-01-01) for a given date
pub(crate) fn days_from_epoch(year: i64, month: i64, day: i64) -> i64 {
    // Adjust for months before March
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    // Days from epoch to start of year
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * m as u32 + 2) / 5 + day as u32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Number of days in a given month
pub(crate) fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Convert a Unix timestamp to (year, month, day, hour, min, sec, wday, yday)
pub(crate) fn timestamp_to_parts(ts: i64) -> (i64, i64, i64, i64, i64, i64, i64, i64) {
    let secs_per_day: i64 = 86400;
    let mut days = ts / secs_per_day;
    let mut remaining = ts % secs_per_day;
    if remaining < 0 {
        remaining += secs_per_day;
        days -= 1;
    }
    let hour = remaining / 3600;
    remaining %= 3600;
    let min = remaining / 60;
    let sec = remaining % 60;

    // Day of week: 1970-01-01 was Thursday (4)
    let wday = ((days + 4) % 7 + 7) % 7;

    // Convert days since epoch to date
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let month = m as i64;
    let day = d as i64;

    // Day of year
    let jan1 = days_from_epoch(year, 1, 1);
    let yday = days - jan1;

    (year, month, day, hour, min, sec, wday, yday)
}

pub(crate) fn weekday_name(wday: i64) -> String {
    match wday {
        0 => "Sunday".into(),
        1 => "Monday".into(),
        2 => "Tuesday".into(),
        3 => "Wednesday".into(),
        4 => "Thursday".into(),
        5 => "Friday".into(),
        6 => "Saturday".into(),
        _ => "Unknown".into(),
    }
}

pub(crate) fn month_name(month: i64) -> String {
    match month {
        1 => "January".into(),
        2 => "February".into(),
        3 => "March".into(),
        4 => "April".into(),
        5 => "May".into(),
        6 => "June".into(),
        7 => "July".into(),
        8 => "August".into(),
        9 => "September".into(),
        10 => "October".into(),
        11 => "November".into(),
        12 => "December".into(),
        _ => "Unknown".into(),
    }
}

/// PHP date() format implementation
pub(crate) fn php_date_format(format: &str, timestamp: i64) -> String {
    let (year, month, day, hour, min, sec, wday, yday) = timestamp_to_parts(timestamp);
    let mut result = String::new();
    let mut escape = false;
    for ch in format.chars() {
        if escape {
            result.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        match ch {
            'Y' => result.push_str(&format!("{:04}", year)),
            'y' => result.push_str(&format!("{:02}", year % 100)),
            'm' => result.push_str(&format!("{:02}", month)),
            'n' => result.push_str(&format!("{}", month)),
            'd' => result.push_str(&format!("{:02}", day)),
            'j' => result.push_str(&format!("{}", day)),
            'H' => result.push_str(&format!("{:02}", hour)),
            'G' => result.push_str(&format!("{}", hour)),
            'i' => result.push_str(&format!("{:02}", min)),
            's' => result.push_str(&format!("{:02}", sec)),
            'A' => result.push_str(if hour < 12 { "AM" } else { "PM" }),
            'a' => result.push_str(if hour < 12 { "am" } else { "pm" }),
            'g' => {
                let h12 = if hour == 0 {
                    12
                } else if hour > 12 {
                    hour - 12
                } else {
                    hour
                };
                result.push_str(&format!("{}", h12));
            }
            'h' => {
                let h12 = if hour == 0 {
                    12
                } else if hour > 12 {
                    hour - 12
                } else {
                    hour
                };
                result.push_str(&format!("{:02}", h12));
            }
            'w' => result.push_str(&format!("{}", wday)),
            'N' => result.push_str(&format!("{}", if wday == 0 { 7 } else { wday })),
            'l' => result.push_str(&weekday_name(wday)),
            'D' => result.push_str(&weekday_name(wday)[..3]),
            'F' => result.push_str(&month_name(month)),
            'M' => result.push_str(&month_name(month)[..3]),
            'z' => result.push_str(&format!("{}", yday)),
            't' => result.push_str(&format!("{}", days_in_month(year, month))),
            'U' => result.push_str(&format!("{}", timestamp)),
            'L' => {
                let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
                result.push_str(if leap { "1" } else { "0" });
            }
            'S' => {
                // English ordinal suffix
                let suffix = match day {
                    1 | 21 | 31 => "st",
                    2 | 22 => "nd",
                    3 | 23 => "rd",
                    _ => "th",
                };
                result.push_str(suffix);
            }
            'c' => {
                // ISO 8601 date
                result.push_str(&format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
                    year, month, day, hour, min, sec
                ));
            }
            'r' => {
                // RFC 2822 date
                result.push_str(&format!(
                    "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
                    &weekday_name(wday)[..3],
                    day,
                    &month_name(month)[..3],
                    year,
                    hour,
                    min,
                    sec
                ));
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Parse relative time strings for strtotime()
pub(crate) fn parse_relative_time(s: &str, base: i64) -> Option<i64> {
    let s = s.trim().to_lowercase();

    // Handle "now"
    if s == "now" {
        return Some(base);
    }

    // Handle "yesterday", "today", "tomorrow"
    let day_secs = 86400i64;
    if s == "today" {
        return Some(base - base % day_secs);
    }
    if s == "yesterday" {
        return Some(base - base % day_secs - day_secs);
    }
    if s == "tomorrow" {
        return Some(base - base % day_secs + day_secs);
    }

    // Handle "+N seconds/minutes/hours/days/weeks/months/years"
    // and "-N seconds/..." and "N seconds ago"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        let ago = parts.last() == Some(&"ago");
        let (num_str, unit_str) = if ago && parts.len() >= 3 {
            (parts[0], parts[1])
        } else {
            (parts[0], parts[1])
        };
        if let Ok(mut num) = num_str.trim_start_matches('+').parse::<i64>() {
            if ago {
                num = -num;
            }
            let secs = match unit_str.trim_end_matches('s') {
                "second" => num,
                "minute" => num * 60,
                "hour" => num * 3600,
                "day" => num * day_secs,
                "week" => num * day_secs * 7,
                "month" => num * day_secs * 30,
                "year" => num * day_secs * 365,
                _ => return None,
            };
            return Some(base + secs);
        }
    }

    // Handle "next/last Monday/Tuesday/..."
    if parts.len() == 2 && (parts[0] == "next" || parts[0] == "last") {
        let target_wday = match parts[1] {
            "sunday" => Some(0),
            "monday" => Some(1),
            "tuesday" => Some(2),
            "wednesday" => Some(3),
            "thursday" => Some(4),
            "friday" => Some(5),
            "saturday" => Some(6),
            "week" => {
                let offset = if parts[0] == "next" { 7 } else { -7 };
                return Some(base + offset * day_secs);
            }
            "month" => {
                let offset = if parts[0] == "next" { 30 } else { -30 };
                return Some(base + offset * day_secs);
            }
            "year" => {
                let offset = if parts[0] == "next" { 365 } else { -365 };
                return Some(base + offset * day_secs);
            }
            _ => None,
        };
        if let Some(tw) = target_wday {
            let (_, _, _, _, _, _, current_wday, _) = timestamp_to_parts(base);
            let diff = if parts[0] == "next" {
                let d = tw - current_wday;
                if d <= 0 {
                    d + 7
                } else {
                    d
                }
            } else {
                let d = current_wday - tw;
                if d <= 0 {
                    -(d + 7)
                } else {
                    -d
                }
            };
            return Some(base + diff * day_secs);
        }
    }

    // Handle YYYY-MM-DD [HH:MM:SS]
    if s.len() >= 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
        let year: i64 = s[0..4].parse().ok()?;
        let month: i64 = s[5..7].parse().ok()?;
        let day: i64 = s[8..10].parse().ok()?;
        let (hour, min, sec) = if s.len() >= 19 && s.as_bytes()[10] == b' ' {
            let h: i64 = s[11..13].parse().ok()?;
            let m: i64 = s[14..16].parse().ok()?;
            let sc: i64 = s[17..19].parse().ok()?;
            (h, m, sc)
        } else {
            (0, 0, 0)
        };
        let days = days_from_epoch(year, month, day);
        return Some(days * 86400 + hour * 3600 + min * 60 + sec);
    }

    None
}

/// Convert a VM Value to a curl CurlValue for use with curl_setopt.
#[cfg(feature = "native-io")]
pub(crate) fn value_to_curl_value(value: &Value) -> php_rs_ext_curl::CurlValue {
    match value {
        Value::Bool(b) => php_rs_ext_curl::CurlValue::Bool(*b),
        Value::Long(l) => php_rs_ext_curl::CurlValue::Long(*l),
        Value::String(s) => php_rs_ext_curl::CurlValue::Str(s.clone()),
        Value::Double(d) => php_rs_ext_curl::CurlValue::Long(*d as i64),
        Value::Array(arr) => {
            let strings: Vec<String> = arr
                .entries()
                .iter()
                .map(|entry| entry.1.to_php_string())
                .collect();
            php_rs_ext_curl::CurlValue::Array(strings)
        }
        _ => php_rs_ext_curl::CurlValue::Null,
    }
}

// ===========================================================================
// PDO helper functions
// ===========================================================================

/// Convert a VM Value to a PdoValue for PDO parameter binding.
#[cfg(feature = "native-io")]
pub(crate) fn value_to_pdo_value(value: &Value) -> php_rs_ext_pdo::PdoValue {
    use php_rs_ext_pdo::PdoValue;

    match value {
        Value::Null => PdoValue::Null,
        Value::Bool(b) => PdoValue::Bool(*b),
        Value::Long(i) => PdoValue::Int(*i),
        Value::Double(f) => PdoValue::Float(*f),
        Value::String(s) => PdoValue::Str(s.clone()),
        Value::Reference(rc) => value_to_pdo_value(&rc.borrow()),
        _ => PdoValue::Str(value.to_php_string()),
    }
}

/// Convert a PdoValue to a VM Value.
#[cfg(feature = "native-io")]
pub(crate) fn pdo_value_to_value(pdo_val: &php_rs_ext_pdo::PdoValue) -> Value {
    use php_rs_ext_pdo::PdoValue;

    match pdo_val {
        PdoValue::Null => Value::Null,
        PdoValue::Bool(b) => Value::Bool(*b),
        PdoValue::Int(i) => Value::Long(*i),
        PdoValue::Float(f) => Value::Double(*f),
        PdoValue::Str(s) => Value::String(s.clone()),
        PdoValue::Blob(b) => Value::String(String::from_utf8_lossy(b).to_string()),
    }
}

/// Convert a PdoRow to a VM Value based on fetch mode.
#[cfg(feature = "native-io")]
pub(crate) fn pdo_row_to_value(
    row: &php_rs_ext_pdo::PdoRow,
    fetch_mode: php_rs_ext_pdo::FetchMode,
    vm: &mut Vm,
) -> Value {
    use php_rs_ext_pdo::FetchMode;

    match fetch_mode {
        FetchMode::Assoc => {
            let mut arr = PhpArray::new();
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
        FetchMode::Num => {
            let mut arr = PhpArray::new();
            for (i, val) in row.values.iter().enumerate() {
                arr.set_int(i as i64, pdo_value_to_value(val));
            }
            Value::Array(arr)
        }
        FetchMode::Both => {
            let mut arr = PhpArray::new();
            for (i, val) in row.values.iter().enumerate() {
                arr.set_int(i as i64, pdo_value_to_value(val));
                if let Some(col) = row.columns.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
        FetchMode::Obj => {
            let obj = PhpObject::new("stdClass".to_string());
            obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    obj.set_property(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Object(obj)
        }
        FetchMode::Column => {
            // Return first column value
            row.values
                .first()
                .map(pdo_value_to_value)
                .unwrap_or(Value::Null)
        }
        FetchMode::KeyPair | FetchMode::Group | FetchMode::Unique => {
            // These modes are handled at the fetchAll level, fall back to Assoc for individual rows
            let mut arr = PhpArray::new();
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
    }
}

/// Real PBKDF2-HMAC implementation for hash_pbkdf2().
/// Supports sha1, sha256, sha384, sha512, md5.
pub(crate) fn pbkdf2_hmac(
    algo: &str,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    length: usize,
    raw_output: bool,
) -> String {
    // Implements PBKDF2 per RFC 2898 using the hash extension's binary HMAC.
    let hash_len = match algo {
        "md5" => 16,
        "sha1" => 20,
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        _ => 32,
    };
    let output_len = if length > 0 { length } else { hash_len };
    let num_blocks = (output_len + hash_len - 1) / hash_len;
    let mut derived = Vec::with_capacity(num_blocks * hash_len);

    for block in 1u32..=(num_blocks as u32) {
        // U1 = HMAC(password, salt || INT(block))
        let mut block_salt = salt.to_vec();
        block_salt.extend_from_slice(&block.to_be_bytes());
        let mut u = php_rs_ext_hash::hmac_bytes(algo, password, &block_salt);
        let mut xor = u.clone();
        // U2..Ui
        for _ in 1..iterations {
            u = php_rs_ext_hash::hmac_bytes(algo, password, &u);
            for (a, b) in xor.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        derived.extend_from_slice(&xor);
    }
    derived.truncate(output_len);

    if raw_output {
        String::from_utf8_lossy(&derived).to_string()
    } else {
        derived.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Serialize a PhpArray (the $_SESSION data) to PHP session file format.
/// Format: key|serialized_value;key2|serialized_value2;
pub(crate) fn session_serialize(data: &crate::value::PhpArray) -> String {
    let mut result = String::new();
    for (key, val) in data.entries() {
        let key_str = match key {
            crate::value::ArrayKey::Int(n) => n.to_string(),
            crate::value::ArrayKey::String(s) => s.clone(),
        };
        // Keys with | or ! are disallowed in PHP session keys, skip them.
        if key_str.contains('|') || key_str.contains('!') {
            continue;
        }
        let serialized = php_rs_ext_standard::variables::php_serialize(&value_to_serializable(val));
        result.push_str(&key_str);
        result.push('|');
        result.push_str(&serialized);
    }
    result
}

/// Generate DatePeriod iteration entries and store on the object.
impl Vm {
    pub(crate) fn generate_date_period_entries(&mut self, obj: &PhpObject) {
        let start_ts = obj
            .get_property("__start_ts")
            .map(|v| v.to_long())
            .unwrap_or(0);
        let end_ts = obj.get_property("__end_ts").map(|v| v.to_long());
        let recurrences = obj
            .get_property("__recurrences")
            .map(|v| v.to_long() as u32);
        let options = obj
            .get_property("__options")
            .map(|v| v.to_long())
            .unwrap_or(0);

        let interval = php_rs_ext_date::PhpDateInterval {
            years: obj
                .get_property("__interval_y")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            months: obj
                .get_property("__interval_m")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            days: obj
                .get_property("__interval_d")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            hours: obj
                .get_property("__interval_h")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            minutes: obj
                .get_property("__interval_i")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            seconds: obj
                .get_property("__interval_s")
                .map(|v| v.to_long() as i32)
                .unwrap_or(0),
            invert: false,
        };

        let start = php_rs_ext_date::PhpDateTime {
            timestamp: start_ts,
            timezone: "UTC".to_string(),
        };
        let end = end_ts.map(|ts| php_rs_ext_date::PhpDateTime {
            timestamp: ts,
            timezone: "UTC".to_string(),
        });

        let period = php_rs_ext_date::PhpDatePeriod::new(start, interval, end, recurrences);
        let timestamps = period.timestamps();
        let exclude_start = (options & 1) != 0;

        let class_name = obj.class_name();
        let is_immutable = class_name.contains("Immutable");
        let dt_class = if is_immutable {
            "DateTimeImmutable"
        } else {
            "DateTime"
        };

        let mut entries = PhpArray::new();
        for (i, ts) in timestamps.iter().enumerate() {
            if exclude_start && i == 0 {
                continue;
            }
            let dt_obj = PhpObject::new(dt_class.to_string());
            dt_obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            dt_obj.set_property("__timestamp".to_string(), Value::Long(*ts));
            dt_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
            entries.push(Value::Object(dt_obj));
        }
        obj.set_property("__period_entries".to_string(), Value::Array(entries));
        obj.set_property("__period_index".to_string(), Value::Long(0));
    }
}

/// Deserialize a PHP session file's content into key-value pairs.
/// Format: key|serialized_value;key2|serialized_value2;
pub(crate) fn session_unserialize(data: &str) -> crate::value::PhpArray {
    let mut arr = crate::value::PhpArray::new();
    let mut remaining = data;
    while !remaining.is_empty() {
        // Find the key (everything before '|')
        let pipe_pos = match remaining.find('|') {
            Some(p) => p,
            None => break,
        };
        let key = &remaining[..pipe_pos];
        remaining = &remaining[pipe_pos + 1..];
        // Now deserialize the value (it consumes the serialized string + trailing ';' for simple types)
        // Use php_unserialize which should return how much it consumed — but our impl returns the value only.
        // So we call unserialize on the remainder and figure out where the next key starts.
        match php_rs_ext_standard::variables::php_unserialize(remaining) {
            Some(sv) => {
                let val = serializable_to_value(&sv);
                arr.set_string(key.to_string(), val);
                // Advance past the serialized value.
                // Re-serialize to find its length (only approximation available without a cursor-based parser).
                let reserialized = php_rs_ext_standard::variables::php_serialize(&sv);
                if remaining.len() >= reserialized.len() {
                    remaining = &remaining[reserialized.len()..];
                } else {
                    break;
                }
            }
            None => break,
        }
    }
    arr
}
