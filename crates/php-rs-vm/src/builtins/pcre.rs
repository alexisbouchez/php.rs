#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{apply_regex_flags, parse_php_regex, Vm, VmResult};
use php_rs_compiler::op::OperandType;

// ── Flag constants ──────────────────────────────────────────────────────────

const PREG_SPLIT_NO_EMPTY: i64 = 1;
const PREG_SPLIT_DELIM_CAPTURE: i64 = 2;
const PREG_SPLIT_OFFSET_CAPTURE: i64 = 4;
const PREG_OFFSET_CAPTURE: i64 = 256;
const PREG_UNMATCHED_AS_NULL: i64 = 512;
const PREG_PATTERN_ORDER: i64 = 1;
const PREG_SET_ORDER: i64 = 2;
const PREG_GREP_INVERT: i64 = 1;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Convert PHP-style backreferences in replacement strings to Rust regex format.
/// Handles: \0-\99 → $0-$99, \g{name} → ${name}
/// PHP $1, ${1}, ${name} already work in Rust regex as-is.
fn convert_php_replacement(rep: &str) -> String {
    let mut result = String::with_capacity(rep.len());
    let bytes = rep.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if bytes[i + 1].is_ascii_digit() {
                // \0-\99 → $0-$99
                result.push('$');
                i += 1;
                // Consume up to 2 digits
                result.push(bytes[i] as char);
                i += 1;
                if i < bytes.len() && bytes[i].is_ascii_digit() {
                    result.push(bytes[i] as char);
                    i += 1;
                }
            } else if bytes[i + 1] == b'g' && i + 2 < bytes.len() && bytes[i + 2] == b'{' {
                // \g{name} → ${name}
                result.push('$');
                i += 2; // skip \g
                while i < bytes.len() {
                    result.push(bytes[i] as char);
                    if bytes[i] == b'}' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Build the match value for a single capture group entry, considering
/// PREG_OFFSET_CAPTURE and PREG_UNMATCHED_AS_NULL flags.
fn build_match_value(
    matched: Option<(&str, usize)>,
    offset_capture: bool,
    unmatched_as_null: bool,
    byte_offset_adjust: usize,
) -> Value {
    match matched {
        Some((text, pos)) => {
            if offset_capture {
                let mut pair = PhpArray::new();
                pair.push(Value::String(text.to_string()));
                pair.push(Value::Long((pos + byte_offset_adjust) as i64));
                Value::Array(pair)
            } else {
                Value::String(text.to_string())
            }
        }
        None => {
            if offset_capture {
                let mut pair = PhpArray::new();
                if unmatched_as_null {
                    pair.push(Value::Null);
                } else {
                    pair.push(Value::String(String::new()));
                }
                pair.push(Value::Long(-1));
                Value::Array(pair)
            } else if unmatched_as_null {
                Value::Null
            } else {
                Value::String(String::new())
            }
        }
    }
}

/// Try to compile a pattern with regex::Regex first, fall back to fancy_regex.
/// Returns either a standard or fancy regex wrapped in an enum.
enum CompiledRegex {
    Standard(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl CompiledRegex {
    fn compile(pattern: &str) -> Option<Self> {
        match regex::Regex::new(pattern) {
            Ok(r) => Some(CompiledRegex::Standard(r)),
            Err(_) => match fancy_regex::Regex::new(pattern) {
                Ok(r) => Some(CompiledRegex::Fancy(r)),
                Err(_) => None,
            },
        }
    }

    fn capture_names(&self) -> Vec<Option<&str>> {
        match self {
            CompiledRegex::Standard(r) => r.capture_names().collect(),
            CompiledRegex::Fancy(r) => r.capture_names().collect(),
        }
    }

    fn captures_len(&self) -> usize {
        match self {
            CompiledRegex::Standard(r) => r.captures_len(),
            CompiledRegex::Fancy(r) => r.captures_len(),
        }
    }

    fn is_match(&self, text: &str) -> bool {
        match self {
            CompiledRegex::Standard(r) => r.is_match(text),
            CompiledRegex::Fancy(r) => r.is_match(text).unwrap_or(false),
        }
    }

    fn replace_all(&self, text: &str, replacement: &str) -> String {
        match self {
            CompiledRegex::Standard(r) => r.replace_all(text, replacement).to_string(),
            CompiledRegex::Fancy(r) => {
                // fancy_regex doesn't have replace_all with backreference support,
                // so we do it manually
                let mut result = String::new();
                let mut last_end = 0;
                let iter = r.captures_iter(text);
                for cap_result in iter {
                    match cap_result {
                        Ok(caps) => {
                            if let Some(full) = caps.get(0) {
                                result.push_str(&text[last_end..full.start()]);
                                // Expand backreferences in replacement
                                let expanded = expand_replacement(replacement, &FancyCaps(&caps));
                                result.push_str(&expanded);
                                last_end = full.end();
                            }
                        }
                        Err(_) => break,
                    }
                }
                result.push_str(&text[last_end..]);
                result
            }
        }
    }

    /// Iterate over all captures in the text. Returns a Vec of captured groups.
    /// Each capture is a Vec of Option<(text, byte_start)> for each group.
    fn captures_all(&self, text: &str) -> Vec<Vec<Option<(String, usize)>>> {
        let num_groups = self.captures_len();
        let mut all = Vec::new();
        match self {
            CompiledRegex::Standard(r) => {
                for caps in r.captures_iter(text) {
                    let mut groups = Vec::with_capacity(num_groups);
                    for g in 0..num_groups {
                        groups.push(caps.get(g).map(|m| (m.as_str().to_string(), m.start())));
                    }
                    all.push(groups);
                }
            }
            CompiledRegex::Fancy(r) => {
                for cap_result in r.captures_iter(text) {
                    match cap_result {
                        Ok(caps) => {
                            let mut groups = Vec::with_capacity(num_groups);
                            for g in 0..num_groups {
                                groups
                                    .push(caps.get(g).map(|m| (m.as_str().to_string(), m.start())));
                            }
                            all.push(groups);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        all
    }

    /// Find all match positions (start, end) for splitting with delimiter capture.
    fn find_matches_with_captures(
        &self,
        text: &str,
        limit: i64,
    ) -> Vec<Vec<Option<(String, usize, usize)>>> {
        let num_groups = self.captures_len();
        let mut all = Vec::new();
        match self {
            CompiledRegex::Standard(r) => {
                for caps in r.captures_iter(text) {
                    if limit > 0 && all.len() + 1 >= limit as usize {
                        break;
                    }
                    let mut groups = Vec::with_capacity(num_groups);
                    for g in 0..num_groups {
                        groups.push(
                            caps.get(g)
                                .map(|m| (m.as_str().to_string(), m.start(), m.end())),
                        );
                    }
                    all.push(groups);
                }
            }
            CompiledRegex::Fancy(r) => {
                for cap_result in r.captures_iter(text) {
                    if limit > 0 && all.len() + 1 >= limit as usize {
                        break;
                    }
                    match cap_result {
                        Ok(caps) => {
                            let mut groups = Vec::with_capacity(num_groups);
                            for g in 0..num_groups {
                                groups.push(
                                    caps.get(g)
                                        .map(|m| (m.as_str().to_string(), m.start(), m.end())),
                                );
                            }
                            all.push(groups);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        all
    }
}

/// Helper for expanding backreferences in replacement strings for fancy_regex.
struct FancyCaps<'a>(&'a fancy_regex::Captures<'a>);

fn expand_replacement(replacement: &str, caps: &FancyCaps<'_>) -> String {
    let mut result = String::new();
    let bytes = replacement.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                // ${name} or ${number}
                if let Some(close) = replacement[i + 2..].find('}') {
                    let name = &replacement[i + 2..i + 2 + close];
                    if let Ok(n) = name.parse::<usize>() {
                        if let Some(m) = caps.0.get(n) {
                            result.push_str(m.as_str());
                        }
                    }
                    // Named groups: try by index (fancy_regex named capture)
                    i = i + 3 + close;
                    continue;
                }
            } else if bytes[i + 1].is_ascii_digit() {
                let start = i + 1;
                i = start;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let num_str = &replacement[start..i];
                if let Ok(n) = num_str.parse::<usize>() {
                    if let Some(m) = caps.0.get(n) {
                        result.push_str(m.as_str());
                    }
                }
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Dispatch a built-in pcre function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        // ── preg_match ──────────────────────────────────────────────────
        "preg_match" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let flags_arg = args.get(3).map(|v| v.to_long()).unwrap_or(0);
            let offset = args.get(4).map(|v| v.to_long() as usize).unwrap_or(0);

            let offset_capture = flags_arg & PREG_OFFSET_CAPTURE != 0;
            let unmatched_as_null = flags_arg & PREG_UNMATCHED_AS_NULL != 0;

            let search_subj = if offset > 0 && offset < subj.len() {
                &subj[offset..]
            } else {
                &subj
            };

            match parse_php_regex(&pat) {
                Some((re, flags)) => {
                    let pattern = apply_regex_flags(&re, &flags);
                    let compiled = match CompiledRegex::compile(&pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Bool(false))),
                    };

                    let all_caps = compiled.captures_all(search_subj);
                    if let Some(cap_groups) = all_caps.first() {
                        if args.len() > 2 {
                            let names = compiled.capture_names();
                            let num_groups = compiled.captures_len();
                            let mut matches_arr = PhpArray::new();

                            for i in 0..num_groups {
                                let matched = cap_groups.get(i).and_then(|opt| {
                                    opt.as_ref().map(|(text, pos)| (text.as_str(), *pos))
                                });
                                let val = build_match_value(
                                    matched,
                                    offset_capture,
                                    unmatched_as_null,
                                    offset,
                                );

                                // Add named group first (if present)
                                if let Some(Some(name)) = names.get(i) {
                                    matches_arr.set(&Value::String(name.to_string()), val.clone());
                                }
                                // Then add numeric index
                                matches_arr.push(val);
                            }

                            vm.write_back_arg(
                                2,
                                Value::Array(matches_arr),
                                ref_args,
                                ref_prop_args,
                            );
                        }
                        Ok(Some(Value::Long(1)))
                    } else {
                        // No match — still write empty array if $matches arg provided
                        if args.len() > 2 {
                            vm.write_back_arg(
                                2,
                                Value::Array(PhpArray::new()),
                                ref_args,
                                ref_prop_args,
                            );
                        }
                        Ok(Some(Value::Long(0)))
                    }
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // ── preg_match_all ──────────────────────────────────────────────
        "preg_match_all" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let preg_flags = args.get(3).map(|v| v.to_long()).unwrap_or(0);
            let offset = args.get(4).map(|v| v.to_long() as usize).unwrap_or(0);

            let offset_capture = preg_flags & PREG_OFFSET_CAPTURE != 0;
            let unmatched_as_null = preg_flags & PREG_UNMATCHED_AS_NULL != 0;
            let set_order = preg_flags & PREG_SET_ORDER != 0;

            let search_subj = if offset > 0 && offset < subj.len() {
                &subj[offset..]
            } else {
                &subj
            };

            match parse_php_regex(&pat) {
                Some((re, flags)) => {
                    let pattern = apply_regex_flags(&re, &flags);
                    let compiled = match CompiledRegex::compile(&pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Bool(false))),
                    };

                    let names = compiled.capture_names();
                    let num_groups = compiled.captures_len();
                    let all_matches = compiled.captures_all(search_subj);
                    let match_count = all_matches.len() as i64;

                    if args.len() > 2 {
                        let matches_arr = if match_count == 0 {
                            // No matches — write empty array in appropriate format
                            if set_order {
                                PhpArray::new()
                            } else {
                                let mut arr = PhpArray::new();
                                for _ in 0..num_groups {
                                    arr.push(Value::Array(PhpArray::new()));
                                }
                                arr
                            }
                        } else if set_order {
                            // PREG_SET_ORDER: [[match0_groups...], [match1_groups...]]
                            let mut arr = PhpArray::new();
                            for match_groups in &all_matches {
                                let mut match_arr = PhpArray::new();
                                for (g, opt_capture) in match_groups.iter().enumerate() {
                                    let matched = opt_capture
                                        .as_ref()
                                        .map(|(text, pos)| (text.as_str(), *pos));
                                    let val = build_match_value(
                                        matched,
                                        offset_capture,
                                        unmatched_as_null,
                                        offset,
                                    );
                                    // Add named group
                                    if let Some(Some(name)) = names.get(g) {
                                        match_arr
                                            .set(&Value::String(name.to_string()), val.clone());
                                    }
                                    match_arr.push(val);
                                }
                                arr.push(Value::Array(match_arr));
                            }
                            arr
                        } else {
                            // PREG_PATTERN_ORDER (default): [[all_g0...], [all_g1...]]
                            let mut group_arrays: Vec<PhpArray> =
                                (0..num_groups).map(|_| PhpArray::new()).collect();

                            for match_groups in &all_matches {
                                for (g, opt_capture) in match_groups.iter().enumerate() {
                                    let matched = opt_capture
                                        .as_ref()
                                        .map(|(text, pos)| (text.as_str(), *pos));
                                    let val = build_match_value(
                                        matched,
                                        offset_capture,
                                        unmatched_as_null,
                                        offset,
                                    );
                                    group_arrays[g].push(val);
                                }
                            }

                            let mut arr = PhpArray::new();
                            // Add named group keys in PREG_PATTERN_ORDER mode
                            for (g, ga) in group_arrays.into_iter().enumerate() {
                                if let Some(Some(name)) = names.get(g) {
                                    arr.set(
                                        &Value::String(name.to_string()),
                                        Value::Array(ga.clone()),
                                    );
                                }
                                arr.push(Value::Array(ga));
                            }
                            arr
                        };

                        vm.write_back_arg(2, Value::Array(matches_arr), ref_args, ref_prop_args);
                    }
                    Ok(Some(Value::Long(match_count)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // ── preg_replace ────────────────────────────────────────────────
        "preg_replace" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let rep = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let subj_val = args.get(2).cloned().unwrap_or(Value::Null);
            let limit = args.get(3).map(|v| v.to_long()).unwrap_or(-1);

            let rust_rep = convert_php_replacement(&rep);

            match parse_php_regex(&pat) {
                Some((re, flags)) => {
                    let pattern = apply_regex_flags(&re, &flags);
                    let compiled = match CompiledRegex::compile(&pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Null)),
                    };

                    match subj_val {
                        Value::Array(ref arr) => {
                            let mut result = PhpArray::new();
                            for (key, val) in arr.entries() {
                                let s = val.to_php_string();
                                let replaced = if limit < 0 {
                                    compiled.replace_all(&s, &rust_rep)
                                } else {
                                    replace_with_limit(&compiled, &s, &rust_rep, limit)
                                };
                                match key {
                                    ArrayKey::Int(i) => result.set_int(*i, Value::String(replaced)),
                                    ArrayKey::String(k) => {
                                        result.set_string(k.clone(), Value::String(replaced))
                                    }
                                }
                            }
                            Ok(Some(Value::Array(result)))
                        }
                        _ => {
                            let s = subj_val.to_php_string();
                            let replaced = if limit < 0 {
                                compiled.replace_all(&s, &rust_rep)
                            } else {
                                replace_with_limit(&compiled, &s, &rust_rep, limit)
                            };
                            Ok(Some(Value::String(replaced)))
                        }
                    }
                }
                None => Ok(Some(Value::Null)),
            }
        }

        // ── preg_split ──────────────────────────────────────────────────
        "preg_split" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let limit = args.get(2).map(|v| v.to_long()).unwrap_or(-1);
            let flags = args.get(3).map(|v| v.to_long()).unwrap_or(0);

            let no_empty = flags & PREG_SPLIT_NO_EMPTY != 0;
            let delim_capture = flags & PREG_SPLIT_DELIM_CAPTURE != 0;
            let offset_capture_flag = flags & PREG_SPLIT_OFFSET_CAPTURE != 0;

            match parse_php_regex(&pat) {
                Some((re, re_flags)) => {
                    let pattern = apply_regex_flags(&re, &re_flags);
                    let compiled = match CompiledRegex::compile(&pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Bool(false))),
                    };

                    let mut arr = PhpArray::new();

                    if !delim_capture && !offset_capture_flag {
                        // Simple split (optimized path)
                        let all_caps = compiled.find_matches_with_captures(&subj, limit);
                        let mut last_end = 0;
                        let mut count = 0;

                        for cap_groups in &all_caps {
                            if let Some(Some((_, start, end))) = cap_groups.first() {
                                let part = &subj[last_end..*start];
                                if !no_empty || !part.is_empty() {
                                    arr.push(Value::String(part.to_string()));
                                }
                                last_end = *end;
                                count += 1;
                            }
                        }
                        // Add trailing part
                        let tail = &subj[last_end..];
                        if !no_empty || !tail.is_empty() {
                            arr.push(Value::String(tail.to_string()));
                        }
                    } else {
                        // Full split with DELIM_CAPTURE and/or OFFSET_CAPTURE
                        let all_caps = compiled.find_matches_with_captures(&subj, limit);
                        let mut last_end = 0usize;

                        for cap_groups in &all_caps {
                            if let Some(Some((_, start, end))) = cap_groups.first() {
                                let part = &subj[last_end..*start];
                                if !no_empty || !part.is_empty() {
                                    if offset_capture_flag {
                                        let mut pair = PhpArray::new();
                                        pair.push(Value::String(part.to_string()));
                                        pair.push(Value::Long(last_end as i64));
                                        arr.push(Value::Array(pair));
                                    } else {
                                        arr.push(Value::String(part.to_string()));
                                    }
                                }

                                // Add captured subgroups (PREG_SPLIT_DELIM_CAPTURE)
                                if delim_capture {
                                    for g in 1..cap_groups.len() {
                                        if let Some(Some((text, gstart, _gend))) = cap_groups.get(g)
                                        {
                                            if !no_empty || !text.is_empty() {
                                                if offset_capture_flag {
                                                    let mut pair = PhpArray::new();
                                                    pair.push(Value::String(text.clone()));
                                                    pair.push(Value::Long(*gstart as i64));
                                                    arr.push(Value::Array(pair));
                                                } else {
                                                    arr.push(Value::String(text.clone()));
                                                }
                                            }
                                        } else if !no_empty {
                                            // Unmatched optional group
                                            if offset_capture_flag {
                                                let mut pair = PhpArray::new();
                                                pair.push(Value::String(String::new()));
                                                pair.push(Value::Long(-1));
                                                arr.push(Value::Array(pair));
                                            } else {
                                                arr.push(Value::String(String::new()));
                                            }
                                        }
                                    }
                                }

                                last_end = *end;
                            }
                        }

                        // Add trailing part
                        let tail = &subj[last_end..];
                        if !no_empty || !tail.is_empty() {
                            if offset_capture_flag {
                                let mut pair = PhpArray::new();
                                pair.push(Value::String(tail.to_string()));
                                pair.push(Value::Long(last_end as i64));
                                arr.push(Value::Array(pair));
                            } else {
                                arr.push(Value::String(tail.to_string()));
                            }
                        }
                    }

                    Ok(Some(Value::Array(arr)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // ── preg_replace_callback ───────────────────────────────────────
        "preg_replace_callback" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let cb_val = args.get(1).cloned().unwrap_or(Value::Null);
            let cb_name = Vm::extract_closure_name(&cb_val);
            let subject = args.get(2).cloned().unwrap_or(Value::Null);
            let limit = args.get(3).map(|v| v.to_long()).unwrap_or(-1);

            let do_replace = |this: &mut Vm,
                              pat_str: &str,
                              subj_str: &str,
                              cb: &str,
                              limit: i64|
             -> VmResult<(String, i64)> {
                match parse_php_regex(pat_str) {
                    Some((re, flags)) => {
                        let pattern = apply_regex_flags(&re, &flags);
                        let compiled = match CompiledRegex::compile(&pattern) {
                            Some(c) => c,
                            None => return Ok((subj_str.to_string(), 0)),
                        };
                        let names = compiled.capture_names();
                        let num_groups = compiled.captures_len();
                        let all_caps = compiled.captures_all(subj_str);

                        let mut result = String::new();
                        let mut last_end = 0;
                        let mut count = 0i64;

                        for cap_groups in &all_caps {
                            if limit >= 0 && count >= limit {
                                break;
                            }
                            if let Some(Some((full_text, full_start))) = cap_groups.first() {
                                let full_end = full_start + full_text.len();
                                result.push_str(&subj_str[last_end..*full_start]);

                                // Build matches array
                                let mut matches_arr = PhpArray::new();
                                for (i, opt) in cap_groups.iter().enumerate() {
                                    let val = match opt {
                                        Some((text, _pos)) => Value::String(text.clone()),
                                        None => Value::String(String::new()),
                                    };
                                    if let Some(Some(name)) = names.get(i) {
                                        matches_arr
                                            .set(&Value::String(name.to_string()), val.clone());
                                    }
                                    matches_arr.push(val);
                                }

                                let replacement =
                                    this.invoke_user_callback(cb, vec![Value::Array(matches_arr)])?;
                                result.push_str(&replacement.to_php_string());
                                last_end = full_end;
                                count += 1;
                            }
                        }
                        result.push_str(&subj_str[last_end..]);
                        Ok((result, count))
                    }
                    None => Ok((subj_str.to_string(), 0)),
                }
            };

            match subject {
                Value::Array(ref arr) => {
                    let mut result_arr = PhpArray::new();
                    let mut total_count = 0i64;
                    for (key, val) in arr.entries().iter().cloned().collect::<Vec<_>>() {
                        let s = val.to_php_string();
                        let (replaced, cnt) = do_replace(vm, &pat, &s, &cb_name, limit)?;
                        total_count += cnt;
                        match key {
                            ArrayKey::Int(n) => result_arr.set_int(n, Value::String(replaced)),
                            ArrayKey::String(k) => {
                                result_arr.set_string(k, Value::String(replaced))
                            }
                        }
                    }
                    if args.len() > 4 {
                        vm.write_back_arg(4, Value::Long(total_count), ref_args, ref_prop_args);
                    }
                    Ok(Some(Value::Array(result_arr)))
                }
                _ => {
                    let s = subject.to_php_string();
                    let (replaced, count) = do_replace(vm, &pat, &s, &cb_name, limit)?;
                    if args.len() > 4 {
                        vm.write_back_arg(4, Value::Long(count), ref_args, ref_prop_args);
                    }
                    Ok(Some(Value::String(replaced)))
                }
            }
        }

        // ── preg_last_error / preg_last_error_msg ───────────────────────
        "preg_last_error" => Ok(Some(Value::Long(0))),
        "preg_last_error_msg" => Ok(Some(Value::String("No error".to_string()))),

        // ── preg_grep ───────────────────────────────────────────────────
        "preg_grep" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let input = args.get(1).cloned().unwrap_or(Value::Null);
            let flags = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            let invert = flags & PREG_GREP_INVERT != 0;

            match parse_php_regex(&pat) {
                Some((pattern, modifiers)) => {
                    let regex_pattern = apply_regex_flags(&pattern, &modifiers);
                    let compiled = match CompiledRegex::compile(&regex_pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Bool(false))),
                    };

                    let mut result = PhpArray::new();
                    if let Value::Array(ref arr) = input {
                        for (key, val) in arr.entries() {
                            let s = val.to_php_string();
                            let matched = compiled.is_match(&s);
                            if matched != invert {
                                match key {
                                    ArrayKey::Int(i) => result.set_int(*i, val.clone()),
                                    ArrayKey::String(s) => {
                                        result.set_string(s.clone(), val.clone())
                                    }
                                }
                            }
                        }
                    }
                    Ok(Some(Value::Array(result)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }

        // ── preg_quote ──────────────────────────────────────────────────
        "preg_quote" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let delim = args.get(1).map(|v| v.to_php_string());
            let special = ".\\+*?[^$(){}=!<>|:-#";
            let mut result = String::with_capacity(s.len() + 8);
            for ch in s.chars() {
                if special.contains(ch) {
                    result.push('\\');
                } else if let Some(ref d) = delim {
                    if d.contains(ch) {
                        result.push('\\');
                    }
                }
                result.push(ch);
            }
            Ok(Some(Value::String(result)))
        }

        // ── preg_filter ─────────────────────────────────────────────────
        "preg_filter" => {
            let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let rep = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let subj = args.get(2).cloned().unwrap_or(Value::Null);

            let rust_rep = convert_php_replacement(&rep);

            match parse_php_regex(&pat) {
                Some((re, flags)) => {
                    let pattern = apply_regex_flags(&re, &flags);
                    let compiled = match CompiledRegex::compile(&pattern) {
                        Some(c) => c,
                        None => return Ok(Some(Value::Null)),
                    };

                    match subj {
                        Value::Array(ref arr) => {
                            let mut result = PhpArray::new();
                            for (key, val) in arr.entries() {
                                let s = val.to_php_string();
                                if compiled.is_match(&s) {
                                    let replaced = compiled.replace_all(&s, &rust_rep);
                                    match key {
                                        ArrayKey::Int(i) => {
                                            result.set_int(*i, Value::String(replaced))
                                        }
                                        ArrayKey::String(k) => {
                                            result.set_string(k.clone(), Value::String(replaced))
                                        }
                                    }
                                }
                            }
                            Ok(Some(Value::Array(result)))
                        }
                        _ => {
                            let s = subj.to_php_string();
                            if compiled.is_match(&s) {
                                Ok(Some(Value::String(compiled.replace_all(&s, &rust_rep))))
                            } else {
                                Ok(Some(Value::Null))
                            }
                        }
                    }
                }
                None => Ok(Some(Value::Null)),
            }
        }

        // ── preg_replace_callback_array ─────────────────────────────────
        "preg_replace_callback_array" => {
            let patterns_val = args.first().cloned().unwrap_or(Value::Null);
            let subject = args.get(1).cloned().unwrap_or(Value::Null);
            let limit = args.get(2).map(|v| v.to_long()).unwrap_or(-1);

            let pairs: Vec<(String, String)> = if let Value::Array(ref arr) = patterns_val {
                arr.entries()
                    .iter()
                    .map(|(k, v)| {
                        let pat = match k {
                            ArrayKey::String(s) => s.clone(),
                            ArrayKey::Int(n) => n.to_string(),
                        };
                        let cb = Vm::extract_closure_name(v);
                        (pat, cb)
                    })
                    .collect()
            } else {
                vec![]
            };

            let do_cb_replace = |this: &mut Vm,
                                 pat_str: &str,
                                 subj_str: &str,
                                 cb: &str,
                                 limit: i64|
             -> VmResult<(String, i64)> {
                match parse_php_regex(pat_str) {
                    Some((re, flags)) => {
                        let pattern = apply_regex_flags(&re, &flags);
                        let compiled = match CompiledRegex::compile(&pattern) {
                            Some(c) => c,
                            None => return Ok((subj_str.to_string(), 0)),
                        };
                        let names = compiled.capture_names();
                        let all_caps = compiled.captures_all(subj_str);

                        let mut result = String::new();
                        let mut last_end = 0;
                        let mut count = 0i64;

                        for cap_groups in &all_caps {
                            if limit >= 0 && count >= limit {
                                break;
                            }
                            if let Some(Some((full_text, full_start))) = cap_groups.first() {
                                let full_end = full_start + full_text.len();
                                result.push_str(&subj_str[last_end..*full_start]);

                                let mut matches_arr = PhpArray::new();
                                for (i, opt) in cap_groups.iter().enumerate() {
                                    let val = match opt {
                                        Some((text, _)) => Value::String(text.clone()),
                                        None => Value::String(String::new()),
                                    };
                                    if let Some(Some(name)) = names.get(i) {
                                        matches_arr
                                            .set(&Value::String(name.to_string()), val.clone());
                                    }
                                    matches_arr.push(val);
                                }

                                let replacement =
                                    this.invoke_user_callback(cb, vec![Value::Array(matches_arr)])?;
                                result.push_str(&replacement.to_php_string());
                                last_end = full_end;
                                count += 1;
                            }
                        }
                        result.push_str(&subj_str[last_end..]);
                        Ok((result, count))
                    }
                    None => Ok((subj_str.to_string(), 0)),
                }
            };

            match subject {
                Value::Array(ref arr) => {
                    let mut result_arr = PhpArray::new();
                    let mut total_count = 0i64;
                    for (key, val) in arr.entries().iter().cloned().collect::<Vec<_>>() {
                        let mut s = val.to_php_string();
                        for (pat, cb) in &pairs {
                            let (replaced, cnt) = do_cb_replace(vm, pat, &s, cb, limit)?;
                            s = replaced;
                            total_count += cnt;
                        }
                        match key {
                            ArrayKey::Int(n) => result_arr.set_int(n, Value::String(s)),
                            ArrayKey::String(k) => result_arr.set_string(k, Value::String(s)),
                        }
                    }
                    if args.len() > 3 {
                        vm.write_back_arg(3, Value::Long(total_count), ref_args, ref_prop_args);
                    }
                    Ok(Some(Value::Array(result_arr)))
                }
                _ => {
                    let mut s = subject.to_php_string();
                    let mut total_count = 0i64;
                    for (pat, cb) in &pairs {
                        let (replaced, cnt) = do_cb_replace(vm, pat, &s, cb, limit)?;
                        s = replaced;
                        total_count += cnt;
                    }
                    if args.len() > 3 {
                        vm.write_back_arg(3, Value::Long(total_count), ref_args, ref_prop_args);
                    }
                    Ok(Some(Value::String(s)))
                }
            }
        }

        _ => Ok(None),
    }
}

/// Replace with a limit on the number of replacements.
fn replace_with_limit(
    compiled: &CompiledRegex,
    text: &str,
    replacement: &str,
    limit: i64,
) -> String {
    let all_caps = compiled.find_matches_with_captures(text, -1);
    let mut result = String::new();
    let mut last_end = 0;
    let mut count = 0i64;

    for cap_groups in &all_caps {
        if limit >= 0 && count >= limit {
            break;
        }
        if let Some(Some((_, start, end))) = cap_groups.first() {
            result.push_str(&text[last_end..*start]);
            // Expand replacement backreferences
            let expanded = expand_backrefs_standard(replacement, cap_groups);
            result.push_str(&expanded);
            last_end = *end;
            count += 1;
        }
    }
    result.push_str(&text[last_end..]);
    result
}

/// Expand backreferences ($0, $1, ${name}) in a replacement string using captures.
fn expand_backrefs_standard(
    replacement: &str,
    cap_groups: &[Option<(String, usize, usize)>],
) -> String {
    let mut result = String::new();
    let bytes = replacement.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                // ${number}
                if let Some(close) = replacement[i + 2..].find('}') {
                    let name = &replacement[i + 2..i + 2 + close];
                    if let Ok(n) = name.parse::<usize>() {
                        if let Some(Some((text, _, _))) = cap_groups.get(n) {
                            result.push_str(text);
                        }
                    }
                    i = i + 3 + close;
                    continue;
                }
            } else if bytes[i + 1].is_ascii_digit() {
                let start = i + 1;
                i = start;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let num_str = &replacement[start..i];
                if let Ok(n) = num_str.parse::<usize>() {
                    if let Some(Some((text, _, _))) = cap_groups.get(n) {
                        result.push_str(text);
                    }
                }
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}
