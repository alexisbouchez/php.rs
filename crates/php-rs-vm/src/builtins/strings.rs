#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;
use php_rs_ext_json::{self, JsonValue};

/// Dispatch a built-in strings function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "strlen" => {
            let s = args.first().cloned().unwrap_or(Value::Null);
            // PHP strings are binary — strlen counts bytes.
            // With Latin-1 encoding, each PHP byte = one Rust char.
            Ok(Some(Value::Long(s.to_php_string().chars().count() as i64)))
        }
        "implode" | "join" => {
            let (glue, pieces) = if args.len() >= 2 {
                (args[0].to_php_string(), args[1].clone())
            } else {
                (String::new(), args.first().cloned().unwrap_or(Value::Null))
            };
            let result = if let Value::Array(ref a) = pieces {
                let parts: Vec<String> =
                    a.entries().iter().map(|(_, v)| v.to_php_string()).collect();
                parts.join(&glue)
            } else {
                String::new()
            };
            Ok(Some(Value::String(result)))
        }
        "explode" => {
            let delimiter = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let mut arr = PhpArray::new();
            if delimiter.is_empty() {
                return Ok(Some(Value::Bool(false)));
            }
            for part in string.split(&delimiter) {
                arr.push(Value::String(part.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "strtolower" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s.to_lowercase())))
        }
        "strtoupper" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s.to_uppercase())))
        }
        "substr" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let start = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            let len = args.get(2).map(|v| v.to_long());

            // PHP strings are binary — substr operates on byte offsets.
            // Since we use Latin-1 encoding (each PHP byte = one Rust char),
            // we must count chars, not UTF-8 bytes.
            let chars: Vec<char> = s.chars().collect();
            let slen = chars.len() as i64;
            let start = if start < 0 {
                (slen + start).max(0) as usize
            } else {
                start.min(slen) as usize
            };

            let result: String = match len {
                Some(l) if l < 0 => {
                    let end = (slen + l).max(0) as usize;
                    if start < end {
                        chars[start..end].iter().collect()
                    } else {
                        String::new()
                    }
                }
                Some(l) => {
                    let end = (start + l as usize).min(chars.len());
                    chars[start..end].iter().collect()
                }
                None => chars[start..].iter().collect(),
            };
            Ok(Some(Value::String(result)))
        }
        "str_repeat" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let n = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            Ok(Some(Value::String(s.repeat(n.max(0) as usize))))
        }
        "trim" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mask = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| " \t\n\r\0\x0B".to_string());
            let trimmed = s.trim_matches(|c| mask.contains(c));
            Ok(Some(Value::String(trimmed.to_string())))
        }
        "ltrim" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mask = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| " \t\n\r\0\x0B".to_string());
            let trimmed = s.trim_start_matches(|c| mask.contains(c));
            Ok(Some(Value::String(trimmed.to_string())))
        }
        "rtrim" | "chop" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mask = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| " \t\n\r\0\x0B".to_string());
            let trimmed = s.trim_end_matches(|c| mask.contains(c));
            Ok(Some(Value::String(trimmed.to_string())))
        }
        "str_contains" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.contains(&needle))))
        }
        "str_starts_with" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.starts_with(&needle))))
        }
        "str_ends_with" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(haystack.ends_with(&needle))))
        }
        "strpos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            match haystack[offset..].find(&needle) {
                Some(pos) => Ok(Some(Value::Long((pos + offset) as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "str_replace" => {
            let search = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let replace = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let subject = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(subject.replace(&search, &replace))))
        }
        "sprintf" => {
            let fmt = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mut result = String::new();
            let mut auto_arg_idx = 1usize; // auto-incremented for non-positional args
            let bytes = fmt.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    i += 1;
                    if i >= bytes.len() {
                        result.push('%');
                        break;
                    }
                    if bytes[i] == b'%' {
                        result.push('%');
                        i += 1;
                        continue;
                    }

                    // Parse: [argnum$] [flags] [width] [.precision] type
                    let mut arg_num: Option<usize> = None;
                    let mut pad_char = ' ';
                    let mut left_align = false;
                    let mut width: Option<usize> = None;
                    let mut precision: Option<usize> = None;
                    let mut sign_plus = false;

                    // Check for argnum$ (digits followed by $)
                    let save = i;
                    let mut num = 0usize;
                    let mut has_digits = false;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        num = num * 10 + (bytes[i] - b'0') as usize;
                        has_digits = true;
                        i += 1;
                    }
                    if has_digits && i < bytes.len() && bytes[i] == b'$' {
                        arg_num = Some(num);
                        i += 1;
                    } else {
                        // Not a positional arg — rewind
                        i = save;
                    }

                    // Parse flags
                    loop {
                        if i >= bytes.len() {
                            break;
                        }
                        match bytes[i] {
                            b'-' => {
                                left_align = true;
                                i += 1;
                            }
                            b'+' => {
                                sign_plus = true;
                                i += 1;
                            }
                            b'0' => {
                                pad_char = '0';
                                i += 1;
                            }
                            b'\'' => {
                                i += 1;
                                if i < bytes.len() {
                                    pad_char = bytes[i] as char;
                                    i += 1;
                                }
                            }
                            b' ' => {
                                i += 1;
                            }
                            _ => break,
                        }
                    }

                    // Parse width (could be * for variable width)
                    if i < bytes.len() && bytes[i] == b'*' {
                        let w_idx = arg_num.unwrap_or(auto_arg_idx);
                        width = Some(
                            args.get(w_idx)
                                .map(|v| v.to_long().unsigned_abs() as usize)
                                .unwrap_or(0),
                        );
                        if arg_num.is_none() {
                            auto_arg_idx += 1;
                        }
                        arg_num = None; // width consumed the argnum
                        i += 1;
                    } else {
                        let mut w = 0usize;
                        let mut has_w = false;
                        while i < bytes.len() && bytes[i].is_ascii_digit() {
                            w = w * 10 + (bytes[i] - b'0') as usize;
                            has_w = true;
                            i += 1;
                        }
                        if has_w {
                            width = Some(w);
                        }
                    }

                    // Parse precision
                    if i < bytes.len() && bytes[i] == b'.' {
                        i += 1;
                        let mut p = 0usize;
                        while i < bytes.len() && bytes[i].is_ascii_digit() {
                            p = p * 10 + (bytes[i] - b'0') as usize;
                            i += 1;
                        }
                        precision = Some(p);
                    }

                    // Parse type
                    if i >= bytes.len() {
                        break;
                    }
                    let type_char = bytes[i] as char;
                    i += 1;

                    let idx = arg_num.unwrap_or_else(|| {
                        let cur = auto_arg_idx;
                        auto_arg_idx += 1;
                        cur
                    });
                    let val = args.get(idx).cloned().unwrap_or(Value::Null);

                    let formatted = match type_char {
                        's' => {
                            let s = val.to_php_string();
                            match precision {
                                Some(p) if p < s.len() => s[..p].to_string(),
                                _ => s,
                            }
                        }
                        'd' => {
                            let n = val.to_long();
                            if sign_plus && n >= 0 {
                                format!("+{}", n)
                            } else {
                                n.to_string()
                            }
                        }
                        'f' | 'F' => {
                            let p = precision.unwrap_or(6);
                            format!("{:.prec$}", val.to_double(), prec = p)
                        }
                        'x' => format!("{:x}", val.to_long()),
                        'X' => format!("{:X}", val.to_long()),
                        'o' => format!("{:o}", val.to_long()),
                        'b' => format!("{:b}", val.to_long()),
                        'c' => {
                            let n = val.to_long();
                            String::from(char::from_u32(n as u32).unwrap_or('\0'))
                        }
                        'e' | 'E' => {
                            let d = val.to_double();
                            let p = precision.unwrap_or(6);
                            if type_char == 'E' {
                                format!("{:.prec$E}", d, prec = p)
                            } else {
                                format!("{:.prec$e}", d, prec = p)
                            }
                        }
                        'u' => format!("{}", val.to_long() as u64),
                        _ => format!("%{}", type_char),
                    };

                    // Apply width and alignment
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
                } else {
                    result.push(bytes[i] as char);
                    i += 1;
                }
            }
            Ok(Some(Value::String(result)))
        }
        "chr" => {
            let n = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
            Ok(Some(Value::String(((n & 0xFF) as u8 as char).to_string())))
        }
        "ord" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let n = s.bytes().next().unwrap_or(0) as i64;
            Ok(Some(Value::Long(n)))
        }
        "str_pad" => {
            let input = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let length = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            let pad_str = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String(" ".to_string()))
                .to_php_string();
            let pad_type = args.get(3).cloned().unwrap_or(Value::Long(1)).to_long();

            if input.len() >= length || pad_str.is_empty() {
                return Ok(Some(Value::String(input)));
            }

            let diff = length - input.len();
            let padding: String = pad_str.chars().cycle().take(diff).collect();

            let result = match pad_type {
                2 => format!("{}{}", padding, input), // STR_PAD_LEFT
                _ => format!("{}{}", input, padding), // STR_PAD_RIGHT (default)
            };
            Ok(Some(Value::String(result)))
        }
        "quoted_printable_encode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_quoted_printable_encode(s.as_bytes()),
            )))
        }
        "quoted_printable_decode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_quoted_printable_decode(&s),
            )))
        }
        "addslashes" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_addslashes(&s),
            )))
        }
        "stripslashes" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_stripslashes(&s),
            )))
        }
        "md5" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(php_rs_ext_standard::strings::php_md5(
                &s,
            ))))
        }
        "sha1" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(php_rs_ext_standard::strings::php_sha1(
                &s,
            ))))
        }
        "base64_encode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_base64_encode(s.as_bytes()),
            )))
        }
        "base64_decode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_standard::strings::php_base64_decode(&s) {
                Some(b) => Ok(Some(Value::String(String::from_utf8_lossy(&b).to_string()))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "htmlspecialchars" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_htmlspecialchars(
                    &s,
                    php_rs_ext_standard::strings::HtmlFlags::default(),
                ),
            )))
        }
        "htmlspecialchars_decode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_htmlspecialchars_decode(&s),
            )))
        }
        "urlencode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_urlencode(&s),
            )))
        }
        "urldecode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_urldecode(&s),
            )))
        }
        "rawurlencode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_rawurlencode(&s),
            )))
        }
        "rawurldecode" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_rawurldecode(&s),
            )))
        }
        "crc32" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Long(php_rs_ext_standard::strings::php_crc32(
                &s,
            ))))
        }
        "str_rot13" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_str_rot13(&s),
            )))
        }
        "ucfirst" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_ucfirst(&s),
            )))
        }
        "lcfirst" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_lcfirst(&s),
            )))
        }
        "ucwords" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let d = args
                .get(1)
                .cloned()
                .unwrap_or(Value::String(String::new()))
                .to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_ucwords(&s, &d),
            )))
        }
        "strrpos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            match php_rs_ext_standard::strings::php_strrpos(&haystack, &needle, offset) {
                Some(pos) => Ok(Some(Value::Long(pos as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "strstr" | "strchr" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let before = args.get(2).is_some_and(|v| v.to_bool());
            match php_rs_ext_standard::strings::php_strstr(&haystack, &needle, before) {
                Some(s) => Ok(Some(Value::String(s))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "stristr" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let before = args.get(2).is_some_and(|v| v.to_bool());
            let hay_lower = haystack.to_lowercase();
            let needle_lower = needle.to_lowercase();
            match hay_lower.find(&needle_lower) {
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
        "stripos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let hay_lower = haystack.to_lowercase();
            let needle_lower = needle.to_lowercase();
            match hay_lower[offset..].find(&needle_lower) {
                Some(pos) => Ok(Some(Value::Long((pos + offset) as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "strripos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            let hay_lower = haystack.to_lowercase();
            let needle_lower = needle.to_lowercase();
            let start = if offset < 0 {
                (haystack.len() as i64 + offset).max(0) as usize
            } else {
                offset as usize
            };
            let end = if offset < 0 {
                haystack.len() - ((-offset) as usize).min(haystack.len())
            } else {
                haystack.len()
            };
            if start <= end && start <= hay_lower.len() {
                match hay_lower[start..end.min(hay_lower.len())].rfind(&needle_lower) {
                    Some(pos) => Ok(Some(Value::Long((pos + start) as i64))),
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "substr_count" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if needle.is_empty() {
                return Ok(Some(Value::Long(0)));
            }
            Ok(Some(Value::Long(haystack.matches(&needle).count() as i64)))
        }
        "substr_replace" => {
            let string = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let replacement = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let start = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long();
            let length = args.get(3).map(|v| v.to_long());
            let slen = string.len() as i64;
            let start_idx = if start < 0 {
                (slen + start).max(0) as usize
            } else {
                start.min(slen) as usize
            };
            let end_idx = match length {
                Some(l) if l < 0 => (slen + l).max(0) as usize,
                Some(l) => (start_idx + l as usize).min(string.len()),
                None => string.len(),
            };
            let mut result = String::new();
            result.push_str(&string[..start_idx]);
            result.push_str(&replacement);
            if end_idx < string.len() {
                result.push_str(&string[end_idx..]);
            }
            Ok(Some(Value::String(result)))
        }
        "str_ireplace" => {
            let search = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let replace = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let subject = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            if search.is_empty() {
                return Ok(Some(Value::String(subject)));
            }
            // Case-insensitive replace
            let mut result = String::new();
            let lower_subject = subject.to_lowercase();
            let lower_search = search.to_lowercase();
            let mut pos = 0;
            while let Some(found) = lower_subject[pos..].find(&lower_search) {
                result.push_str(&subject[pos..pos + found]);
                result.push_str(&replace);
                pos += found + search.len();
            }
            result.push_str(&subject[pos..]);
            Ok(Some(Value::String(result)))
        }
        "nl2br" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let is_xhtml = !args.get(1).is_some_and(|v| !v.to_bool());
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_nl2br(&s, is_xhtml),
            )))
        }
        "wordwrap" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let width = args.get(1).cloned().unwrap_or(Value::Long(75)).to_long() as usize;
            let brk = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String("\n".to_string()))
                .to_php_string();
            let cut = args.get(3).is_some_and(|v| v.to_bool());
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_wordwrap(&s, width, &brk, cut),
            )))
        }
        "chunk_split" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let chunklen = args.get(1).cloned().unwrap_or(Value::Long(76)).to_long() as usize;
            let end = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String("\r\n".to_string()))
                .to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_chunk_split(&s, chunklen, &end),
            )))
        }
        "hex2bin" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mut result = Vec::new();
            let bytes = s.as_bytes();
            let mut i = 0;
            while i + 1 < bytes.len() {
                let hi = match bytes[i] {
                    b'0'..=b'9' => bytes[i] - b'0',
                    b'a'..=b'f' => bytes[i] - b'a' + 10,
                    b'A'..=b'F' => bytes[i] - b'A' + 10,
                    _ => return Ok(Some(Value::Bool(false))),
                };
                let lo = match bytes[i + 1] {
                    b'0'..=b'9' => bytes[i + 1] - b'0',
                    b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                    b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
                    _ => return Ok(Some(Value::Bool(false))),
                };
                result.push((hi << 4) | lo);
                i += 2;
            }
            // PHP strings are binary: map each byte to its Latin-1 codepoint
            let s: String = result.iter().map(|&b| b as char).collect();
            Ok(Some(Value::String(s)))
        }
        "bin2hex" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            // PHP strings are binary: each char's Unicode codepoint IS the byte value
            let hex: String = s.chars().map(|c| format!("{:02x}", c as u32)).collect();
            Ok(Some(Value::String(hex)))
        }
        "str_split" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let length = args
                .get(1)
                .cloned()
                .unwrap_or(Value::Long(1))
                .to_long()
                .max(1) as usize;
            let parts = php_rs_ext_standard::strings::php_str_split(&s, length);
            let mut arr = PhpArray::new();
            for part in parts {
                arr.push(Value::String(part));
            }
            Ok(Some(Value::Array(arr)))
        }
        "str_word_count" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let format = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
            match format {
                0 => Ok(Some(Value::Long(
                    php_rs_ext_standard::strings::php_str_word_count(&s) as i64,
                ))),
                1 => {
                    let mut arr = PhpArray::new();
                    for word in s.split_whitespace() {
                        arr.push(Value::String(word.to_string()));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                2 => {
                    let mut arr = PhpArray::new();
                    let mut pos = 0;
                    for part in s.split_whitespace() {
                        if let Some(idx) = s[pos..].find(part) {
                            arr.set_int((pos + idx) as i64, Value::String(part.to_string()));
                            pos += idx + part.len();
                        }
                    }
                    Ok(Some(Value::Array(arr)))
                }
                _ => Ok(Some(Value::Bool(false))),
            }
        }
        "printf" => {
            // printf = echo sprintf(...)
            let fmt_args: Vec<Value> = args.to_vec();
            let result = vm.call_builtin("sprintf", &fmt_args, &[], &[])?;
            if let Some(Value::String(s)) = result {
                let len = s.len();
                vm.write_output(&s);
                Ok(Some(Value::Long(len as i64)))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }
        "strtok" => {
            // Simplified: just split on first char of delimiter and return first token
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let delim = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            if delim.is_empty() {
                return Ok(Some(Value::String(s)));
            }
            match s.find(|c: char| delim.contains(c)) {
                Some(pos) => Ok(Some(Value::String(s[..pos].to_string()))),
                None => Ok(Some(Value::String(s))),
            }
        }
        "str_getcsv" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let sep = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| ",".to_string());
            let enclosure = args
                .get(2)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\"".to_string());
            let escape = args
                .get(3)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\\".to_string());
            let sep_char = sep.chars().next().unwrap_or(',');
            let enc_char = enclosure.chars().next().unwrap_or('"');
            let esc_char = if escape.is_empty() {
                None
            } else {
                escape.chars().next()
            };
            let mut arr = PhpArray::new();
            let bytes = s.as_bytes();
            let len = bytes.len();
            let mut i = 0;
            while i <= len {
                if i == len {
                    // trailing separator produces empty field
                    break;
                }
                if bytes[i] == enc_char as u8 {
                    // Enclosed field
                    i += 1; // skip opening enclosure
                    let mut field = String::new();
                    while i < len {
                        // Check escape char (when different from enclosure)
                        if let Some(esc) = esc_char {
                            if esc as u8 != enc_char as u8 && bytes[i] == esc as u8 && i + 1 < len {
                                field.push(bytes[i + 1] as char);
                                i += 2;
                                continue;
                            }
                        }
                        // Doubled enclosure always means escaped enclosure
                        if bytes[i] == enc_char as u8
                            && i + 1 < len
                            && bytes[i + 1] == enc_char as u8
                        {
                            field.push(enc_char);
                            i += 2;
                            continue;
                        }
                        if bytes[i] == enc_char as u8 {
                            // end of enclosed field
                            i += 1; // skip closing enclosure
                                    // skip to separator
                            while i < len && bytes[i] != sep_char as u8 {
                                i += 1;
                            }
                            break;
                        }
                        field.push(bytes[i] as char);
                        i += 1;
                    }
                    arr.push(Value::String(field));
                } else {
                    // Unenclosed field
                    let start = i;
                    while i < len && bytes[i] != sep_char as u8 {
                        i += 1;
                    }
                    let field = &s[start..i];
                    arr.push(Value::String(field.to_string()));
                }
                // Skip separator
                if i < len && bytes[i] == sep_char as u8 {
                    i += 1;
                    // If separator is at end of string, add empty field
                    if i == len {
                        arr.push(Value::String(String::new()));
                    }
                } else {
                    break;
                }
            }
            Ok(Some(Value::Array(arr)))
        }
        "str_putcsv" => {
            let arr = args.first().cloned().unwrap_or(Value::Null);
            let sep = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| ",".to_string());
            let enclosure = args
                .get(2)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\"".to_string());
            let escape = args
                .get(3)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\\".to_string());
            let sep_char = sep.chars().next().unwrap_or(',');
            let enc_char = enclosure.chars().next().unwrap_or('"');
            let esc_char = escape.chars().next().unwrap_or('\\');

            if let Value::Array(ref a) = arr {
                let mut result = String::new();
                for (i, (_, val)) in a.entries().iter().enumerate() {
                    if i > 0 {
                        result.push(sep_char);
                    }
                    let field = val.to_php_string();
                    // Enclose if field contains separator, enclosure, newline, or space
                    if field.contains(sep_char)
                        || field.contains(enc_char)
                        || field.contains('\n')
                        || field.contains('\r')
                    {
                        result.push(enc_char);
                        for ch in field.chars() {
                            if ch == enc_char {
                                result.push(esc_char);
                            }
                            result.push(ch);
                        }
                        result.push(enc_char);
                    } else {
                        result.push_str(&field);
                    }
                }
                Ok(Some(Value::String(result)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "strrev" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s.chars().rev().collect())))
        }
        "str_shuffle" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mut chars: Vec<char> = s.chars().collect();
            let mut rng = php_rs_ext_random::Randomizer::new(Box::new(
                php_rs_ext_random::Mt19937::new(Some(vm.mt_rng.generate_u32() as u64)),
            ));
            rng.shuffle_array(&mut chars);
            Ok(Some(Value::String(chars.into_iter().collect())))
        }
        "similar_text" => {
            let s1 = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let s2 = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            // PHP's similar_text uses longest common substring recursively
            fn similar_text_calc(s1: &[u8], s2: &[u8]) -> i64 {
                if s1.is_empty() || s2.is_empty() {
                    return 0;
                }
                let mut longest = 0usize;
                let mut pos1 = 0usize;
                let mut pos2 = 0usize;
                for i in 0..s1.len() {
                    for j in 0..s2.len() {
                        let mut l = 0usize;
                        while i + l < s1.len() && j + l < s2.len() && s1[i + l] == s2[j + l] {
                            l += 1;
                        }
                        if l > longest {
                            longest = l;
                            pos1 = i;
                            pos2 = j;
                        }
                    }
                }
                if longest == 0 {
                    return 0;
                }
                let mut sum = longest as i64;
                if pos1 > 0 && pos2 > 0 {
                    sum += similar_text_calc(&s1[..pos1], &s2[..pos2]);
                }
                let after1 = pos1 + longest;
                let after2 = pos2 + longest;
                if after1 < s1.len() && after2 < s2.len() {
                    sum += similar_text_calc(&s1[after1..], &s2[after2..]);
                }
                sum
            }
            let count = similar_text_calc(s1.as_bytes(), s2.as_bytes());
            // If third arg (percent) is passed as a reference, we'd set it, but for now just return count
            Ok(Some(Value::Long(count)))
        }
        "soundex" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let s = s.to_uppercase();
            if s.is_empty() {
                return Ok(Some(Value::String("0000".to_string())));
            }
            let first = s.chars().next().unwrap();
            let mut code = String::new();
            code.push(first);
            let encode = |c: char| match c {
                'B' | 'F' | 'P' | 'V' => '1',
                'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
                'D' | 'T' => '3',
                'L' => '4',
                'M' | 'N' => '5',
                'R' => '6',
                _ => '0',
            };
            let mut last = encode(first);
            for c in s.chars().skip(1) {
                let coded = encode(c);
                if coded != '0' && coded != last {
                    code.push(coded);
                    if code.len() == 4 {
                        break;
                    }
                }
                last = coded;
            }
            while code.len() < 4 {
                code.push('0');
            }
            Ok(Some(Value::String(code)))
        }
        "metaphone" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let phoneme_len = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
            let max_len = if phoneme_len > 0 {
                phoneme_len
            } else {
                usize::MAX
            };
            let chars: Vec<char> = s
                .to_uppercase()
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .collect();
            if chars.is_empty() {
                return Ok(Some(Value::String(String::new())));
            }
            let mut result = String::new();
            let len = chars.len();
            let mut i = 0;
            // Drop initial silent letters
            if len >= 2 {
                match (chars[0], chars[1]) {
                    ('A', 'E') | ('G', 'N') | ('K', 'N') | ('P', 'N') | ('W', 'R') => i = 1,
                    _ => {}
                }
            }
            if chars[0] == 'W' && chars.get(1) == Some(&'H') {
                i = 1;
            }
            // Initial vowel maps to itself
            let is_vowel = |c: char| matches!(c, 'A' | 'E' | 'I' | 'O' | 'U');
            if i == 0 && is_vowel(chars[0]) {
                result.push(chars[0]);
                i = 1;
            }
            let get = |idx: usize| -> char {
                if idx < len {
                    chars[idx]
                } else {
                    '\0'
                }
            };
            while i < len && result.len() < max_len {
                let c = chars[i];
                // Skip duplicate adjacent letters (except C)
                if c != 'C' && i > 0 && chars[i - 1] == c {
                    i += 1;
                    continue;
                }
                match c {
                    'B' => {
                        if i == 0 || chars[i - 1] != 'M' {
                            result.push('B');
                        }
                    }
                    'C' => {
                        if get(i + 1) == 'I' && get(i + 2) == 'A' {
                            result.push('X');
                            i += 2;
                        } else if matches!(get(i + 1), 'E' | 'I' | 'Y') {
                            result.push('S');
                            i += 1;
                        } else {
                            result.push('K');
                        }
                    }
                    'D' => {
                        if get(i + 1) == 'G' && matches!(get(i + 2), 'E' | 'I' | 'Y') {
                            result.push('J');
                            i += 2;
                        } else {
                            result.push('T');
                        }
                    }
                    'F' => result.push('F'),
                    'G' => {
                        if i + 1 < len && get(i + 1) == 'H' && i + 2 < len && !is_vowel(get(i + 2))
                        {
                            // GH before non-vowel: silent
                            i += 1;
                        } else if i > 0
                            && (get(i + 1) == '\0'
                                || (matches!(get(i + 1), 'N')
                                    && (get(i + 2) == '\0' || get(i + 2) == 'S')))
                        {
                            // Silent G at end, or GN, GNS
                        } else if i > 0
                            && is_vowel(chars[i - 1])
                            && matches!(get(i + 1), 'E' | 'I' | 'Y')
                        {
                            result.push('J');
                        } else {
                            result.push('K');
                        }
                    }
                    'H' => {
                        if is_vowel(get(i + 1)) && (i == 0 || !is_vowel(chars[i - 1])) {
                            result.push('H');
                        }
                    }
                    'J' => result.push('J'),
                    'K' => {
                        if i == 0 || chars[i - 1] != 'C' {
                            result.push('K');
                        }
                    }
                    'L' => result.push('L'),
                    'M' => result.push('M'),
                    'N' => result.push('N'),
                    'P' => {
                        if get(i + 1) == 'H' {
                            result.push('F');
                            i += 1;
                        } else {
                            result.push('P');
                        }
                    }
                    'Q' => result.push('K'),
                    'R' => result.push('R'),
                    'S' => {
                        if get(i + 1) == 'H'
                            || (get(i + 1) == 'I' && matches!(get(i + 2), 'A' | 'O'))
                        {
                            result.push('X');
                            i += if get(i + 1) == 'H' { 1 } else { 2 };
                        } else {
                            result.push('S');
                        }
                    }
                    'T' => {
                        if get(i + 1) == 'H' {
                            result.push('0');
                            i += 1;
                        } else if get(i + 1) == 'I' && matches!(get(i + 2), 'A' | 'O') {
                            result.push('X');
                            i += 2;
                        } else {
                            result.push('T');
                        }
                    }
                    'V' => result.push('F'),
                    'W' | 'Y' => {
                        if is_vowel(get(i + 1)) {
                            result.push(c);
                        }
                    }
                    'X' => {
                        result.push('K');
                        if result.len() < max_len {
                            result.push('S');
                        }
                    }
                    'Z' => result.push('S'),
                    _ => {} // vowels and non-alpha are skipped
                }
                i += 1;
            }
            Ok(Some(Value::String(result)))
        }
        "levenshtein" => {
            let s1 = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let s2 = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let b1 = s1.as_bytes();
            let b2 = s2.as_bytes();
            let m = b1.len();
            let n = b2.len();
            let mut d = vec![vec![0usize; n + 1]; m + 1];
            for i in 0..=m {
                d[i][0] = i;
            }
            for j in 0..=n {
                d[0][j] = j;
            }
            for i in 1..=m {
                for j in 1..=n {
                    let cost = if b1[i - 1] == b2[j - 1] { 0 } else { 1 };
                    d[i][j] = (d[i - 1][j] + 1)
                        .min(d[i][j - 1] + 1)
                        .min(d[i - 1][j - 1] + cost);
                }
            }
            Ok(Some(Value::Long(d[m][n] as i64)))
        }
        "substr_compare" => {
            let main_str = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let str2 = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).cloned().unwrap_or(Value::Long(0)).to_long();
            let length = args.get(3).map(|v| v.to_long() as usize);
            let case_insensitive = args.get(4).is_some_and(|v| v.to_bool());
            let slen = main_str.len() as i64;
            let start = if offset < 0 {
                (slen + offset).max(0) as usize
            } else {
                offset as usize
            };
            if start > main_str.len() {
                return Ok(Some(Value::Bool(false)));
            }
            let sub = match length {
                Some(l) => &main_str[start..(start + l).min(main_str.len())],
                None => &main_str[start..],
            };
            let cmp_str = match length {
                Some(l) => &str2[..l.min(str2.len())],
                None => &str2,
            };
            if case_insensitive {
                Ok(Some(Value::Long(
                    sub.to_lowercase().cmp(&cmp_str.to_lowercase()) as i64,
                )))
            } else {
                Ok(Some(Value::Long(sub.cmp(cmp_str) as i64)))
            }
        }
        "number_format" => {
            let num = args.first().cloned().unwrap_or(Value::Null).to_double();
            let decimals = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
            let dec_point = args
                .get(2)
                .cloned()
                .unwrap_or(Value::String(".".to_string()))
                .to_php_string();
            let thousands = args
                .get(3)
                .cloned()
                .unwrap_or(Value::String(",".to_string()))
                .to_php_string();
            Ok(Some(Value::String(
                php_rs_ext_standard::strings::php_number_format(
                    num, decimals, &dec_point, &thousands,
                ),
            )))
        }
        "addcslashes" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let charlist = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let mut result = String::new();
            for ch in s.chars() {
                if charlist.contains(ch) {
                    result.push('\\');
                }
                result.push(ch);
            }
            Ok(Some(Value::String(result)))
        }
        "stripcslashes" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mut result = String::new();
            let chars: Vec<char> = s.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    match chars[i + 1] {
                        'n' => {
                            result.push('\n');
                            i += 2;
                        }
                        'r' => {
                            result.push('\r');
                            i += 2;
                        }
                        't' => {
                            result.push('\t');
                            i += 2;
                        }
                        'v' => {
                            result.push('\x0B');
                            i += 2;
                        }
                        'a' => {
                            result.push('\x07');
                            i += 2;
                        }
                        'f' => {
                            result.push('\x0C');
                            i += 2;
                        }
                        '\\' => {
                            result.push('\\');
                            i += 2;
                        }
                        _ => {
                            result.push(chars[i + 1]);
                            i += 2;
                        }
                    }
                } else {
                    result.push(chars[i]);
                    i += 1;
                }
            }
            Ok(Some(Value::String(result)))
        }
        "quotemeta" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mut result = String::new();
            for ch in s.chars() {
                if ".\\+*?[^]($)".contains(ch) {
                    result.push('\\');
                }
                result.push(ch);
            }
            Ok(Some(Value::String(result)))
        }
        "convert_uuencode" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let bytes = s.as_bytes();
            let mut result = String::new();
            for chunk in bytes.chunks(45) {
                result.push((chunk.len() as u8 + 32) as char);
                for triple in chunk.chunks(3) {
                    let b0 = triple[0] as u32;
                    let b1 = *triple.get(1).unwrap_or(&0) as u32;
                    let b2 = *triple.get(2).unwrap_or(&0) as u32;
                    result.push(((b0 >> 2) as u8 + 32) as char);
                    result.push((((b0 & 3) << 4 | b1 >> 4) as u8 + 32) as char);
                    result.push((((b1 & 0xF) << 2 | b2 >> 6) as u8 + 32) as char);
                    result.push(((b2 & 0x3F) as u8 + 32) as char);
                }
                result.push('\n');
            }
            result.push_str(" \n");
            Ok(Some(Value::String(result)))
        }
        "convert_uudecode" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mut result = Vec::new();
            for line in s.lines() {
                if line.is_empty() {
                    continue;
                }
                let n = (line.as_bytes()[0] as i32 - 32) & 0x3F;
                if n == 0 {
                    break;
                }
                let data: Vec<u8> = line
                    .bytes()
                    .skip(1)
                    .map(|b| b.wrapping_sub(32) & 0x3F)
                    .collect();
                let mut i = 0;
                let mut written = 0;
                while i + 3 < data.len() && written < n {
                    result.push((data[i] << 2 | data[i + 1] >> 4) as u8);
                    written += 1;
                    if written < n {
                        result.push((data[i + 1] << 4 | data[i + 2] >> 2) as u8);
                        written += 1;
                    }
                    if written < n {
                        result.push((data[i + 2] << 6 | data[i + 3]) as u8);
                        written += 1;
                    }
                    i += 4;
                }
            }
            Ok(Some(Value::String(
                String::from_utf8_lossy(&result).to_string(),
            )))
        }
        "count_chars" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mode = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let mut counts = [0i64; 256];
            for b in s.bytes() {
                counts[b as usize] += 1;
            }
            match mode {
                0 => {
                    let mut arr = PhpArray::new();
                    for (i, &c) in counts.iter().enumerate() {
                        arr.set_int(i as i64, Value::Long(c));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                1 => {
                    let mut arr = PhpArray::new();
                    for (i, &c) in counts.iter().enumerate() {
                        if c > 0 {
                            arr.set_int(i as i64, Value::Long(c));
                        }
                    }
                    Ok(Some(Value::Array(arr)))
                }
                2 => {
                    let mut arr = PhpArray::new();
                    for (i, &c) in counts.iter().enumerate() {
                        if c == 0 {
                            arr.set_int(i as i64, Value::Long(0));
                        }
                    }
                    Ok(Some(Value::Array(arr)))
                }
                3 => {
                    let mut unique: Vec<u8> =
                        (0..=255u8).filter(|&b| counts[b as usize] > 0).collect();
                    unique.sort();
                    Ok(Some(Value::String(
                        String::from_utf8_lossy(&unique).to_string(),
                    )))
                }
                4 => {
                    let unused: Vec<u8> =
                        (0..=255u8).filter(|&b| counts[b as usize] == 0).collect();
                    Ok(Some(Value::String(
                        String::from_utf8_lossy(&unused).to_string(),
                    )))
                }
                _ => Ok(Some(Value::Bool(false))),
            }
        }
        "html_entity_decode" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            // Decode named entities first
            let mut result = s
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#039;", "'")
                .replace("&apos;", "'")
                .replace("&nbsp;", "\u{00A0}")
                .replace("&copy;", "\u{00A9}")
                .replace("&reg;", "\u{00AE}")
                .replace("&trade;", "\u{2122}")
                .replace("&euro;", "\u{20AC}")
                .replace("&pound;", "\u{00A3}")
                .replace("&yen;", "\u{00A5}")
                .replace("&cent;", "\u{00A2}")
                .replace("&mdash;", "\u{2014}")
                .replace("&ndash;", "\u{2013}")
                .replace("&laquo;", "\u{00AB}")
                .replace("&raquo;", "\u{00BB}")
                .replace("&bull;", "\u{2022}")
                .replace("&hellip;", "\u{2026}");
            // Decode numeric entities: &#nnn; and &#xhex;
            let mut decoded = String::with_capacity(result.len());
            let bytes = result.as_bytes();
            let len = bytes.len();
            let mut i = 0;
            while i < len {
                if bytes[i] == b'&' && i + 2 < len && bytes[i + 1] == b'#' {
                    let start = i;
                    i += 2;
                    let hex = i < len && (bytes[i] == b'x' || bytes[i] == b'X');
                    if hex {
                        i += 1;
                    }
                    let num_start = i;
                    while i < len && bytes[i] != b';' && i - num_start < 10 {
                        i += 1;
                    }
                    if i < len && bytes[i] == b';' {
                        let num_str = &result[num_start..i];
                        let code = if hex {
                            u32::from_str_radix(num_str, 16).ok()
                        } else {
                            num_str.parse::<u32>().ok()
                        };
                        if let Some(cp) = code {
                            if let Some(ch) = char::from_u32(cp) {
                                decoded.push(ch);
                                i += 1;
                                continue;
                            }
                        }
                    }
                    // Not a valid numeric entity, output as-is
                    decoded.push('&');
                    i = start + 1;
                } else {
                    decoded.push(bytes[i] as char);
                    i += 1;
                }
            }
            Ok(Some(Value::String(decoded)))
        }
        "htmlentities" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let result = s
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#039;");
            Ok(Some(Value::String(result)))
        }
        "setlocale" => Ok(Some(Value::String("C".into()))),
        "mb_strlen" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Long(s.chars().count() as i64)))
        }
        "mb_substr" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let start = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let len = args.get(2).map(|v| v.to_long());
            let chars: Vec<char> = s.chars().collect();
            let total = chars.len() as i64;
            let start = if start < 0 {
                (total + start).max(0) as usize
            } else {
                start as usize
            };
            let end = match len {
                Some(l) if l < 0 => (total + l).max(start as i64) as usize,
                Some(l) => (start + l as usize).min(chars.len()),
                None => chars.len(),
            };
            if start >= chars.len() {
                Ok(Some(Value::String(String::new())))
            } else {
                Ok(Some(Value::String(
                    chars[start..end.min(chars.len())].iter().collect(),
                )))
            }
        }
        "mb_strpos" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let hay_chars: Vec<char> = haystack.chars().collect();
            let needle_chars: Vec<char> = needle.chars().collect();
            let mut found = None;
            if !needle_chars.is_empty() {
                for i in offset..hay_chars.len() {
                    if hay_chars[i..].starts_with(&needle_chars) {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(pos) => Ok(Some(Value::Long(pos as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_strrpos" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let hay_chars: Vec<char> = haystack.chars().collect();
            let needle_chars: Vec<char> = needle.chars().collect();
            let mut found = None;
            if !needle_chars.is_empty() {
                for i in (0..hay_chars.len()).rev() {
                    if hay_chars[i..].starts_with(&needle_chars) {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(pos) => Ok(Some(Value::Long(pos as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_strtolower" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(s.to_lowercase())))
        }
        "mb_strtoupper" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(s.to_uppercase())))
        }
        "mb_detect_encoding" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let detected = php_rs_ext_mbstring::mb_detect_encoding(&s, None);
            Ok(Some(Value::String(detected.to_string())))
        }
        "mb_internal_encoding" => {
            if args.is_empty() {
                let enc = php_rs_ext_mbstring::mb_internal_encoding(None);
                Ok(Some(Value::String(enc)))
            } else {
                let enc = args[0].to_php_string();
                php_rs_ext_mbstring::mb_internal_encoding(Some(&enc));
                Ok(Some(Value::Bool(true)))
            }
        }
        "mb_convert_encoding" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let to_enc = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let from_enc = args.get(2).map(|v| v.to_php_string());
            let result = php_rs_ext_mbstring::mb_convert_encoding(&s, &to_enc, from_enc.as_deref());
            Ok(Some(Value::String(result)))
        }
        "mb_substr_count" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::Long(haystack.matches(&needle).count() as i64)))
        }
        "mb_stripos" => {
            let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let hay_lower = haystack.to_lowercase();
            let needle_lower = needle.to_lowercase();
            let hay_chars: Vec<char> = hay_lower.chars().collect();
            let needle_chars: Vec<char> = needle_lower.chars().collect();
            let mut found = None;
            if !needle_chars.is_empty() {
                for i in offset..hay_chars.len() {
                    if hay_chars[i..].starts_with(&needle_chars) {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(pos) => Ok(Some(Value::Long(pos as i64))),
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_str_split" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let length = args.get(1).map(|v| v.to_long()).unwrap_or(1) as usize;
            let chars: Vec<char> = s.chars().collect();
            let mut arr = PhpArray::new();
            for chunk in chars.chunks(length.max(1)) {
                arr.push(Value::String(chunk.iter().collect()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "mb_convert_case" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mode = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            match mode {
                0 => Ok(Some(Value::String(s.to_uppercase()))), // MB_CASE_UPPER
                1 => Ok(Some(Value::String(s.to_lowercase()))), // MB_CASE_LOWER
                2 => {
                    // MB_CASE_TITLE
                    let mut result = String::new();
                    let mut cap_next = true;
                    for ch in s.chars() {
                        if cap_next && ch.is_alphabetic() {
                            result.extend(ch.to_uppercase());
                            cap_next = false;
                        } else {
                            result.push(ch);
                            if ch.is_whitespace() {
                                cap_next = true;
                            }
                        }
                    }
                    Ok(Some(Value::String(result)))
                }
                _ => Ok(Some(Value::String(s))),
            }
        }
        "sscanf" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let format = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let mut result = PhpArray::new();
            let mut si = 0;
            let mut fi = 0;
            let s_bytes = s.as_bytes();
            let f_bytes = format.as_bytes();
            while fi < f_bytes.len() {
                if f_bytes[fi] == b'%' && fi + 1 < f_bytes.len() {
                    fi += 1;
                    // Skip width specifier (e.g., %3d, %10s)
                    while fi < f_bytes.len() && f_bytes[fi].is_ascii_digit() {
                        fi += 1;
                    }
                    if fi >= f_bytes.len() {
                        break;
                    }
                    match f_bytes[fi] {
                        b'd' | b'i' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            let start = si;
                            if si < s_bytes.len() && (s_bytes[si] == b'-' || s_bytes[si] == b'+') {
                                si += 1;
                            }
                            while si < s_bytes.len() && s_bytes[si].is_ascii_digit() {
                                si += 1;
                            }
                            let num_str = &s[start..si];
                            result.push(Value::Long(num_str.parse().unwrap_or(0)));
                        }
                        b'u' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            let start = si;
                            while si < s_bytes.len() && s_bytes[si].is_ascii_digit() {
                                si += 1;
                            }
                            let num_str = &s[start..si];
                            result.push(Value::Long(num_str.parse::<u64>().unwrap_or(0) as i64));
                        }
                        b's' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            let start = si;
                            while si < s_bytes.len() && !s_bytes[si].is_ascii_whitespace() {
                                si += 1;
                            }
                            result.push(Value::String(s[start..si].to_string()));
                        }
                        b'f' | b'e' | b'g' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            let start = si;
                            if si < s_bytes.len() && (s_bytes[si] == b'-' || s_bytes[si] == b'+') {
                                si += 1;
                            }
                            while si < s_bytes.len()
                                && (s_bytes[si].is_ascii_digit()
                                    || s_bytes[si] == b'.'
                                    || s_bytes[si] == b'e'
                                    || s_bytes[si] == b'E')
                            {
                                si += 1;
                            }
                            let num_str = &s[start..si];
                            result.push(Value::Double(num_str.parse().unwrap_or(0.0)));
                        }
                        b'c' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            result.push(Value::String(s[si..si + 1].to_string()));
                            si += 1;
                        }
                        b'x' | b'X' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            // Skip optional 0x prefix
                            let start = si;
                            if si + 1 < s_bytes.len()
                                && s_bytes[si] == b'0'
                                && (s_bytes[si + 1] == b'x' || s_bytes[si + 1] == b'X')
                            {
                                si += 2;
                            }
                            while si < s_bytes.len() && s_bytes[si].is_ascii_hexdigit() {
                                si += 1;
                            }
                            let hex_str = &s[start..si];
                            let hex_str = hex_str
                                .strip_prefix("0x")
                                .or_else(|| hex_str.strip_prefix("0X"))
                                .unwrap_or(hex_str);
                            result.push(Value::Long(i64::from_str_radix(hex_str, 16).unwrap_or(0)));
                        }
                        b'o' => {
                            if si >= s_bytes.len() {
                                result.push(Value::Null);
                                fi += 1;
                                continue;
                            }
                            let start = si;
                            while si < s_bytes.len() && (s_bytes[si] >= b'0' && s_bytes[si] <= b'7')
                            {
                                si += 1;
                            }
                            let oct_str = &s[start..si];
                            result.push(Value::Long(i64::from_str_radix(oct_str, 8).unwrap_or(0)));
                        }
                        b'n' => {
                            // %n stores the number of characters consumed so far
                            result.push(Value::Long(si as i64));
                        }
                        b'%' => {
                            // Literal %
                            if si < s_bytes.len() && s_bytes[si] == b'%' {
                                si += 1;
                            }
                            fi += 1;
                            continue;
                        }
                        _ => {
                            fi += 1;
                            continue;
                        }
                    }
                    fi += 1;
                } else if si < s_bytes.len() && f_bytes[fi] == s_bytes[si] {
                    fi += 1;
                    si += 1;
                } else if f_bytes[fi] == b' ' {
                    // Format space matches any whitespace
                    fi += 1;
                    while si < s_bytes.len() && s_bytes[si].is_ascii_whitespace() {
                        si += 1;
                    }
                } else {
                    break;
                }
            }
            if args.len() <= 2 {
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Long(result.len() as i64)))
            }
        }
        "fprintf" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let format = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            let fmt_args: Vec<Value> = args.iter().skip(2).cloned().collect();
            let formatted = php_rs_ext_standard::strings::php_sprintf(
                &format,
                &fmt_args
                    .iter()
                    .map(|v| v.to_php_string())
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
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
        "vprintf" => {
            let format = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let arr_args = if let Some(Value::Array(ref a)) = args.get(1) {
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
            let len = formatted.len();
            vm.write_output(&formatted);
            Ok(Some(Value::Long(len as i64)))
        }
        "vsprintf" => {
            let format = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let arr_args = if let Some(Value::Array(ref a)) = args.get(1) {
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
            Ok(Some(Value::String(formatted)))
        }
        "hash_file" => {
            let algo = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let filename = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let raw = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
            if let Ok(data) = vm.vm_read_file(&filename) {
                let s = String::from_utf8_lossy(&data);
                match php_rs_ext_hash::php_hash(&algo, &s) {
                    Some(hash_result) => {
                        if raw {
                            let bytes: Vec<u8> = (0..hash_result.len())
                                .step_by(2)
                                .filter_map(|i| u8::from_str_radix(&hash_result[i..i + 2], 16).ok())
                                .collect();
                            Ok(Some(Value::String(
                                String::from_utf8_lossy(&bytes).to_string(),
                            )))
                        } else {
                            Ok(Some(Value::String(hash_result)))
                        }
                    }
                    None => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "hash_init" | "hash_copy" => {
            // Context-based hashing - return a resource placeholder
            Ok(Some(Value::Long(0)))
        }
        "hash_update" | "hash_update_file" | "hash_update_stream" => Ok(Some(Value::Bool(true))),
        "hash_final" => {
            // Without real context tracking, return empty hash
            Ok(Some(Value::String(
                "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            )))
        }
        "hash_pbkdf2" => {
            let algo = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_lowercase();
            let password = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let salt = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            let iterations = args.get(3).map(|v| v.to_long()).unwrap_or(1000) as usize;
            let length = args.get(4).map(|v| v.to_long()).unwrap_or(0) as usize;
            let raw_output = args.get(5).map(|v| v.to_bool()).unwrap_or(false);
            // PBKDF2 implementation using HMAC from ext-hash
            let hash_len = match algo.as_str() {
                "sha256" => 32,
                "sha1" => 20,
                "md5" => 16,
                "sha512" => 64,
                "sha384" => 48,
                _ => 32,
            };
            let dk_len = if length == 0 { hash_len } else { length };
            let blocks_needed = (dk_len + hash_len - 1) / hash_len;
            let mut dk = Vec::with_capacity(dk_len);
            for block_num in 1..=blocks_needed {
                let mut block_bytes = salt.as_bytes().to_vec();
                block_bytes.extend_from_slice(&(block_num as u32).to_be_bytes());
                let mut u = php_rs_ext_hash::hmac_bytes(&algo, password.as_bytes(), &block_bytes);
                let mut result = u.clone();
                for _ in 1..iterations {
                    u = php_rs_ext_hash::hmac_bytes(&algo, password.as_bytes(), &u);
                    for (r, b) in result.iter_mut().zip(u.iter()) {
                        *r ^= b;
                    }
                }
                dk.extend_from_slice(&result);
            }
            dk.truncate(dk_len);
            if raw_output {
                Ok(Some(Value::String(
                    dk.iter().map(|&b| b as char).collect(),
                )))
            } else {
                Ok(Some(Value::String(
                    dk.iter().map(|b| format!("{:02x}", b)).collect(),
                )))
            }
        }
        "iconv_strpos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(2).map(|v| v.to_long() as usize).unwrap_or(0);
            let chars: Vec<char> = haystack.chars().collect();
            let needle_chars: Vec<char> = needle.chars().collect();
            if needle_chars.is_empty() || offset >= chars.len() {
                return Ok(Some(Value::Bool(false)));
            }
            for i in offset..=chars.len().saturating_sub(needle_chars.len()) {
                if chars[i..i + needle_chars.len()] == needle_chars[..] {
                    return Ok(Some(Value::Long(i as i64)));
                }
            }
            Ok(Some(Value::Bool(false)))
        }
        "iconv_strrpos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let chars: Vec<char> = haystack.chars().collect();
            let needle_chars: Vec<char> = needle.chars().collect();
            if needle_chars.is_empty() {
                return Ok(Some(Value::Bool(false)));
            }
            for i in (0..=chars.len().saturating_sub(needle_chars.len())).rev() {
                if chars[i..i + needle_chars.len()] == needle_chars[..] {
                    return Ok(Some(Value::Long(i as i64)));
                }
            }
            Ok(Some(Value::Bool(false)))
        }
        "iconv_substr" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let length = args.get(2).map(|v| v.to_long());
            let chars: Vec<char> = s.chars().collect();
            let len = chars.len() as i64;
            let start = if offset < 0 {
                (len + offset).max(0) as usize
            } else {
                offset.min(len) as usize
            };
            let end = match length {
                Some(l) if l < 0 => (len + l).max(start as i64) as usize,
                Some(l) => (start as i64 + l).min(len) as usize,
                None => len as usize,
            };
            let result: String = chars[start..end].iter().collect();
            Ok(Some(Value::String(result)))
        }
        "iconv_mime_encode" => {
            let field = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let value = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(format!("{}: {}", field, value))))
        }
        "iconv_mime_decode" => {
            let encoded = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(encoded)))
        }
        "iconv_mime_decode_headers" => {
            let encoded = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mut arr = PhpArray::new();
            for line in encoded.lines() {
                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim().to_string();
                    let val = line[pos + 1..].trim().to_string();
                    arr.set_string(key, Value::String(val));
                }
            }
            Ok(Some(Value::Array(arr)))
        }
        "mb_chr" => {
            let code = args.first().map(|v| v.to_long()).unwrap_or(0) as u32;
            if let Some(c) = char::from_u32(code) {
                Ok(Some(Value::String(c.to_string())))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "mb_check_encoding" => {
            let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let encoding = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "UTF-8".to_string());
            let valid = match encoding.to_uppercase().as_str() {
                "UTF-8" | "UTF8" => std::str::from_utf8(s.as_bytes()).is_ok(),
                "ASCII" | "US-ASCII" => s.is_ascii(),
                _ => true, // Unknown encodings pass
            };
            Ok(Some(Value::Bool(valid)))
        }
        "mb_decode_mimeheader" | "mb_encode_mimeheader" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "mb_decode_numericentity" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "mb_encode_numericentity" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "mb_detect_order" => {
            if args.is_empty() {
                let mut arr = PhpArray::new();
                arr.push(Value::String("ASCII".into()));
                arr.push(Value::String("UTF-8".into()));
                Ok(Some(Value::Array(arr)))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "mb_encoding_aliases" => {
            let enc = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_uppercase();
            let mut arr = PhpArray::new();
            match enc.as_str() {
                "UTF-8" => {
                    arr.push(Value::String("utf8".into()));
                }
                "ASCII" => {
                    arr.push(Value::String("us-ascii".into()));
                }
                _ => {}
            }
            Ok(Some(Value::Array(arr)))
        }
        "mb_ereg" => {
            // mb_ereg(string $pattern, string $string, array &$matches = null): bool
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            match regex::Regex::new(&pattern) {
                Ok(re) => {
                    if let Some(caps) = re.captures(&string) {
                        // Write back matches if 3rd arg is a reference
                        // Write back matches if 3rd arg is a reference
                        if !ref_args.is_empty() {
                            let mut arr = PhpArray::new();
                            for i in 0..caps.len() {
                                if let Some(m) = caps.get(i) {
                                    arr.push(Value::String(m.as_str().to_string()));
                                } else {
                                    arr.push(Value::String(String::new()));
                                }
                            }
                            vm.write_back_arg(2, Value::Array(arr), ref_args, ref_prop_args);
                        }
                        // Return length of matched string (or true)
                        if let Some(m) = caps.get(0) {
                            Ok(Some(Value::Long(m.as_str().len() as i64)))
                        } else {
                            Ok(Some(Value::Bool(true)))
                        }
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_ereg_match" => {
            // mb_ereg_match(string $pattern, string $string): bool
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            // mb_ereg_match anchors to start of string
            let anchored = format!("^(?:{})", pattern);
            match regex::Regex::new(&anchored) {
                Ok(re) => Ok(Some(Value::Bool(re.is_match(&string)))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_ereg_replace" => {
            // mb_ereg_replace(string $pattern, string $replacement, string $string): string|false
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let replacement = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            match regex::Regex::new(&pattern) {
                Ok(re) => {
                    let result = re.replace_all(&string, replacement.as_str());
                    Ok(Some(Value::String(result.into_owned())))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_ereg_replace_callback" => {
            // Callback-based replacement — requires VM callback invocation
            let string = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(string)))
        }
        "mb_ereg_search" => Ok(Some(Value::Bool(false))),
        "mb_ereg_search_getpos" => Ok(Some(Value::Long(0))),
        "mb_ereg_search_getregs" | "mb_ereg_search_regs" | "mb_ereg_search_pos" => {
            Ok(Some(Value::Bool(false)))
        }
        "mb_ereg_search_init" => Ok(Some(Value::Bool(true))),
        "mb_eregi" => {
            // mb_eregi — case-insensitive mb_ereg
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let ci_pattern = format!("(?i){}", pattern);
            match regex::Regex::new(&ci_pattern) {
                Ok(re) => {
                    if let Some(caps) = re.captures(&string) {
                        if !ref_args.is_empty() {
                            let mut arr = PhpArray::new();
                            for i in 0..caps.len() {
                                if let Some(m) = caps.get(i) {
                                    arr.push(Value::String(m.as_str().to_string()));
                                } else {
                                    arr.push(Value::String(String::new()));
                                }
                            }
                            vm.write_back_arg(2, Value::Array(arr), ref_args, ref_prop_args);
                        }
                        if let Some(m) = caps.get(0) {
                            Ok(Some(Value::Long(m.as_str().len() as i64)))
                        } else {
                            Ok(Some(Value::Bool(true)))
                        }
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_eregi_replace" => {
            // mb_eregi_replace — case-insensitive mb_ereg_replace
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let replacement = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let string = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
            let ci_pattern = format!("(?i){}", pattern);
            match regex::Regex::new(&ci_pattern) {
                Ok(re) => {
                    let result = re.replace_all(&string, replacement.as_str());
                    Ok(Some(Value::String(result.into_owned())))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_http_input" | "mb_http_output" => {
            if args.is_empty() {
                Ok(Some(Value::String("UTF-8".into())))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "mb_language" => {
            if args.is_empty() {
                Ok(Some(Value::String("neutral".into())))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "mb_list_encodings" => {
            let mut arr = PhpArray::new();
            for enc in &[
                "UTF-8",
                "ASCII",
                "ISO-8859-1",
                "ISO-8859-15",
                "UTF-16",
                "UTF-16BE",
                "UTF-16LE",
                "UTF-32",
                "UTF-32BE",
                "UTF-32LE",
                "EUC-JP",
                "SJIS",
                "ISO-2022-JP",
                "GB18030",
                "BIG-5",
                "EUC-KR",
            ] {
                arr.push(Value::String(enc.to_string()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "mb_ord" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            if let Some(c) = s.chars().next() {
                Ok(Some(Value::Long(c as i64)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "mb_output_handler" => {
            let contents = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(contents)))
        }
        "mb_parse_str" => {
            // parse_str for mb strings
            Ok(Some(Value::Bool(true)))
        }
        "mb_preferred_mime_name" => {
            let enc = args
                .first()
                .cloned()
                .unwrap_or(Value::Null)
                .to_php_string()
                .to_uppercase();
            let name = match enc.as_str() {
                "UTF-8" | "UTF8" => "UTF-8",
                "ISO-8859-1" | "LATIN1" => "ISO-8859-1",
                _ => &enc,
            };
            Ok(Some(Value::String(name.to_string())))
        }
        "mb_regex_encoding" => {
            if args.is_empty() {
                Ok(Some(Value::String("UTF-8".into())))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "mb_scrub" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::String(s)))
        }
        "mb_send_mail" => Ok(Some(Value::Bool(false))),
        "mb_strcut" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let start = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
            let length = args.get(2).map(|v| v.to_long() as usize);
            let bytes = s.as_bytes();
            let start = start.min(bytes.len());
            let end = length
                .map(|l| (start + l).min(bytes.len()))
                .unwrap_or(bytes.len());
            Ok(Some(Value::String(
                String::from_utf8_lossy(&bytes[start..end]).to_string(),
            )))
        }
        "mb_strimwidth" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let start = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
            let width = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
            let trim_marker = args.get(3).map(|v| v.to_php_string()).unwrap_or_default();
            let chars: Vec<char> = s.chars().collect();
            let start = start.min(chars.len());
            if chars.len() - start <= width {
                return Ok(Some(Value::String(chars[start..].iter().collect())));
            }
            let marker_len = trim_marker.chars().count();
            let take = if width > marker_len {
                width - marker_len
            } else {
                0
            };
            let trimmed: String = chars[start..start + take].iter().collect();
            Ok(Some(Value::String(format!("{}{}", trimmed, trim_marker))))
        }
        "mb_ereg_search_setpos" => Ok(Some(Value::Bool(true))),
        "mb_strripos" => {
            let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let h_lower = haystack.to_lowercase();
            let n_lower = needle.to_lowercase();
            match h_lower.rfind(&n_lower) {
                Some(p) => {
                    let char_pos = h_lower[..p].chars().count();
                    Ok(Some(Value::Long(char_pos as i64)))
                }
                None => Ok(Some(Value::Bool(false))),
            }
        }
        "mb_strwidth" => {
            let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let width: usize = s
                .chars()
                .map(|c| {
                    let cp = c as u32;
                    if cp >= 0x1100
                        && ((cp <= 0x115f)
                            || cp == 0x2329
                            || cp == 0x232a
                            || (cp >= 0x2e80 && cp <= 0xa4cf && cp != 0x303f)
                            || (cp >= 0xac00 && cp <= 0xd7a3)
                            || (cp >= 0xf900 && cp <= 0xfaff)
                            || (cp >= 0xfe10 && cp <= 0xfe19)
                            || (cp >= 0xfe30 && cp <= 0xfe6f)
                            || (cp >= 0xff01 && cp <= 0xff60)
                            || (cp >= 0xffe0 && cp <= 0xffe6)
                            || (cp >= 0x20000 && cp <= 0x2fffd)
                            || (cp >= 0x30000 && cp <= 0x3fffd))
                    {
                        2
                    } else {
                        1
                    }
                })
                .sum();
            Ok(Some(Value::Long(width as i64)))
        }
        "mb_substitute_character" => {
            if args.is_empty() {
                // Return current substitute character setting
                Ok(Some(Value::Long(0x3F))) // '?' = 0x3F, PHP default
            } else {
                let arg = &args[0];
                match arg {
                    Value::String(s) if s == "none" || s == "long" || s == "entity" => {
                        Ok(Some(Value::Bool(true)))
                    }
                    _ => {
                        // Numeric codepoint
                        Ok(Some(Value::Bool(true)))
                    }
                }
            }
        }
        _ => Ok(None),
    }
}
