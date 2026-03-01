#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;
use std::net::ToSocketAddrs;

/// Parse a CSV line following RFC 4180 rules with PHP-compatible quoting.
/// Handles: quoted fields, escaped quotes (doubled or backslash-escaped),
/// embedded separators/newlines.
fn parse_csv_line(line: &str, sep: char, enc: char, esc: Option<char>) -> PhpArray {
    let mut arr = PhpArray::new();
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;

    loop {
        if i >= len {
            break;
        }

        if chars[i] == enc {
            // Quoted field
            i += 1; // skip opening enclosure
            let mut field = String::new();
            while i < len {
                // Doubled enclosure always means escaped enclosure (RFC 4180)
                if chars[i] == enc && i + 1 < len && chars[i + 1] == enc {
                    field.push(enc);
                    i += 2;
                    continue;
                }
                // Escape char (when different from enclosure) escapes the next char
                if let Some(esc_c) = esc {
                    if esc_c != enc && chars[i] == esc_c && i + 1 < len {
                        field.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                }
                if chars[i] == enc {
                    // End of quoted field
                    i += 1;
                    break;
                }
                field.push(chars[i]);
                i += 1;
            }
            arr.push(Value::String(field));
            // Skip separator after quoted field
            if i < len && chars[i] == sep {
                i += 1;
                // Trailing separator means empty final field
                if i >= len {
                    arr.push(Value::String(String::new()));
                }
            }
        } else {
            // Unquoted field
            let mut field = String::new();
            while i < len && chars[i] != sep {
                field.push(chars[i]);
                i += 1;
            }
            arr.push(Value::String(field));
            if i < len && chars[i] == sep {
                i += 1;
                // If separator is at end of line, there's one more empty field
                if i >= len {
                    arr.push(Value::String(String::new()));
                }
            }
        }
    }

    arr
}

/// Match a filename against a glob pattern supporting *, ?, and [...] character classes.
/// PHP's glob uses [...] for character classes: [abc] matches a, b, or c.
/// [[] matches a literal '['. [!abc] or [^abc] matches anything except a, b, c.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let (mut star_pi, mut star_ti) = (usize::MAX, usize::MAX);

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '[' {
            // Character class
            if let Some((matched, end)) = match_char_class(&pat[pi..], txt[ti]) {
                if matched {
                    pi += end;
                    ti += 1;
                    continue;
                }
            }
            // No match in char class
            if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_ti += 1;
                ti = star_ti;
                continue;
            }
            return false;
        } else if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Match a [...] character class at the start of `pat` against `ch`.
/// Returns Some((matched, consumed_len)) or None if not a valid class.
fn match_char_class(pat: &[char], ch: char) -> Option<(bool, usize)> {
    if pat.is_empty() || pat[0] != '[' {
        return None;
    }
    let mut i = 1;
    let negate = if i < pat.len() && (pat[i] == '!' || pat[i] == '^') {
        i += 1;
        true
    } else {
        false
    };
    let mut matched = false;
    // First char after [ (or [! / [^) can be ] and it's treated as literal
    let start = i;
    while i < pat.len() && (pat[i] != ']' || i == start) {
        if i + 2 < pat.len() && pat[i + 1] == '-' && pat[i + 2] != ']' {
            // Range: a-z
            if ch >= pat[i] && ch <= pat[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= pat.len() {
        return None; // Unclosed bracket
    }
    // pat[i] == ']'
    Some((if negate { !matched } else { matched }, i + 1))
}

/// Dispatch a built-in file function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "file_get_contents" => {
            let f = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            // Handle php://filter wrapper
            if f.starts_with("php://filter/") {
                let (read_filters, _, resource) =
                    parse_php_filter_spec(&f["php://filter/".len()..]);
                match vm.vm_read_to_string(&resource) {
                    Ok(s) => {
                        let mut data = s.into_bytes();
                        for filter in &read_filters {
                            data = apply_stream_filter(filter, &data);
                        }
                        Ok(Some(Value::String(
                            String::from_utf8_lossy(&data).to_string(),
                        )))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else if f.starts_with("data://") || f.starts_with("data:") {
                let uri = if f.starts_with("data://") {
                    &f["data://".len()..]
                } else {
                    &f["data:".len()..]
                };
                let data = if let Some(b64_pos) = uri.find(";base64,") {
                    let encoded = &uri[b64_pos + 8..];
                    base64_decode_bytes(encoded)
                } else if let Some(comma_pos) = uri.find(',') {
                    uri[comma_pos + 1..].as_bytes().to_vec()
                } else {
                    uri.as_bytes().to_vec()
                };
                Ok(Some(Value::String(
                    String::from_utf8_lossy(&data).to_string(),
                )))
            } else if f.starts_with("http://") || f.starts_with("https://") {
                #[cfg(feature = "native-io")]
                {
                    if vm.ini.get("allow_url_fopen") != "1" {
                        vm.write_output("Warning: file_get_contents(): http:// wrapper is disabled in the server configuration by allow_url_fopen=0\n");
                        return Ok(Some(Value::Bool(false)));
                    }
                    // Parse stream context options (arg index 2) for HTTP headers, method, content
                    let (method, header_str, content) = if let Some(Value::Resource(ctx_id, _)) = args.get(2) {
                        if let Some(ctx) = vm.stream_contexts.get(ctx_id) {
                            if let Some(http_opts) = ctx.options.get("http") {
                                let m = http_opts.get("method")
                                    .map(|v| v.to_php_string())
                                    .unwrap_or_default();
                                let h = http_opts.get("header")
                                    .map(|v| v.to_php_string())
                                    .unwrap_or_default();
                                let c = http_opts.get("content")
                                    .map(|v| v.to_php_string())
                                    .unwrap_or_default();
                                (m, h, c)
                            } else {
                                (String::new(), String::new(), String::new())
                            }
                        } else {
                            (String::new(), String::new(), String::new())
                        }
                    } else {
                        (String::new(), String::new(), String::new())
                    };

                    let agent = ureq::Agent::new_with_config(
                        ureq::Agent::config_builder()
                            .http_status_as_error(false)
                            .timeout_global(Some(std::time::Duration::from_secs(
                                vm.ini.get("default_socket_timeout").parse::<u64>().unwrap_or(60),
                            )))
                            .build(),
                    );

                    let effective_method = if method.is_empty() {
                        if content.is_empty() { "GET" } else { "POST" }
                    } else {
                        &method
                    };

                    // Helper closure to apply headers from stream context
                    let apply_headers = |header_str: &str| -> Vec<(String, String)> {
                        let mut headers = Vec::new();
                        for line in header_str.lines() {
                            let line = line.trim();
                            if let Some(colon_pos) = line.find(':') {
                                let key = line[..colon_pos].trim().to_string();
                                let val = line[colon_pos + 1..].trim().to_string();
                                if !key.is_empty() {
                                    headers.push((key, val));
                                }
                            }
                        }
                        headers
                    };

                    let headers = apply_headers(&header_str);

                    let result: Result<ureq::Body, ureq::Error> = match effective_method {
                        "POST" | "PUT" | "PATCH" => {
                            let mut req = match effective_method {
                                "PUT" => agent.put(&f),
                                "PATCH" => agent.patch(&f),
                                _ => agent.post(&f),
                            };
                            for (k, v) in &headers {
                                req = req.header(k, v);
                            }
                            req.send(content.as_bytes()).map(|r| r.into_body())
                        }
                        _ => {
                            let mut req = match effective_method {
                                "HEAD" => agent.head(&f),
                                "DELETE" => agent.delete(&f),
                                "OPTIONS" => agent.options(&f),
                                _ => agent.get(&f),
                            };
                            for (k, v) in &headers {
                                req = req.header(k, v);
                            }
                            req.call().map(|r| r.into_body())
                        }
                    };

                    match result {
                        Ok(mut body) => {
                            let text = body.read_to_string().unwrap_or_default();
                            Ok(Some(Value::String(text)))
                        }
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                }
                #[cfg(not(feature = "native-io"))]
                {
                    vm.write_output("Warning: file_get_contents(): https:// wrapper requires native-io feature\n");
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                vm.check_open_basedir(&f)?;
                match vm.vm_read_to_string(&f) {
                    Ok(c) => Ok(Some(Value::String(c))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
        }
        "file_put_contents" => {
            let f = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&f)?;
            let d = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            let flags = args
                .get(2)
                .map(|v| v.to_long())
                .unwrap_or(0);
            let append = (flags & 8) != 0; // FILE_APPEND = 8
            let lock_ex = (flags & 2) != 0; // LOCK_EX = 2

            let result = if append {
                // Append mode
                #[cfg(not(target_arch = "wasm32"))]
                {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&f);
                    match file {
                        Ok(ref mut file) => {
                            #[cfg(unix)]
                            if lock_ex {
                                use std::os::unix::io::AsRawFd;
                                unsafe {
                                    libc::flock(file.as_raw_fd(), libc::LOCK_EX);
                                }
                            }
                            file.write_all(d.as_bytes())
                        }
                        Err(e) => Err(e),
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = lock_ex;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "No filesystem",
                    ))
                }
            } else if lock_ex {
                // Write with lock
                #[cfg(not(target_arch = "wasm32"))]
                {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&f);
                    match file {
                        Ok(ref mut file) => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::io::AsRawFd;
                                unsafe {
                                    libc::flock(file.as_raw_fd(), libc::LOCK_EX);
                                }
                            }
                            file.write_all(d.as_bytes())
                        }
                        Err(e) => Err(e),
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "No filesystem",
                    ))
                }
            } else {
                vm.vm_write_file(&f, d.as_bytes())
            };

            match result {
                Ok(()) => Ok(Some(Value::Long(d.len() as i64))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "file_exists" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            Ok(Some(Value::Bool(vm.vm_file_exists(&p))))
        }
        "is_file" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            Ok(Some(Value::Bool(vm.vm_is_file(&p))))
        }
        "is_dir" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            Ok(Some(Value::Bool(vm.vm_is_dir(&p))))
        }
        "dirname" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let levels = args.get(1).map(|v| v.to_long()).unwrap_or(1).max(1) as usize;
            let mut path = std::path::PathBuf::from(&p);
            for _ in 0..levels {
                path = path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
            }
            let result = path.to_string_lossy().to_string();
            Ok(Some(Value::String(if result.is_empty() {
                ".".to_string()
            } else {
                result
            })))
        }
        "basename" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let suffix = args.get(1).map(|v| v.to_php_string());
            let mut name = std::path::Path::new(&p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Some(ref sfx) = suffix {
                if name.ends_with(sfx.as_str()) && name.len() > sfx.len() {
                    name.truncate(name.len() - sfx.len());
                }
            }
            Ok(Some(Value::String(name)))
        }
        "realpath" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::canonicalize(&p) {
                    Ok(rp) => Ok(Some(Value::String(rp.to_string_lossy().to_string()))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                if vm.vm_file_exists(&p) {
                    Ok(Some(Value::String(p)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "file" => {
            let f = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&f)?;
            match vm.vm_read_to_string(&f) {
                Ok(content) => {
                    let mut arr = PhpArray::new();
                    for line in content.lines() {
                        arr.push(Value::String(format!("{}\n", line)));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "mkdir" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&path)?;
            let _mode = args.get(1).cloned().unwrap_or(Value::Long(0o777));
            let recursive = args.get(2).is_some_and(|v| v.to_bool());
            let result = vm.vm_mkdir(&path, recursive);
            Ok(Some(Value::Bool(result.is_ok())))
        }
        "rmdir" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&path)?;
            Ok(Some(Value::Bool(vm.vm_rmdir(&path).is_ok())))
        }
        "unlink" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&path)?;
            Ok(Some(Value::Bool(vm.vm_remove_file(&path).is_ok())))
        }
        "rename" => {
            let from = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let to = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&from)?;
            vm.check_open_basedir(&to)?;
            Ok(Some(Value::Bool(vm.vm_rename(&from, &to).is_ok())))
        }
        "copy" => {
            let from = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let to = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&from)?;
            vm.check_open_basedir(&to)?;
            // Implement copy via VFS: read source then write to dest
            match vm.vm_read_file(&from) {
                Ok(data) => Ok(Some(Value::Bool(vm.vm_write_file(&to, &data).is_ok()))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "tempnam" => {
            let dir = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let prefix = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
            match php_rs_ext_standard::file::php_tempnam(&dir, &prefix) {
                Ok(p) => Ok(Some(Value::String(p))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "sys_get_temp_dir" => Ok(Some(Value::String(
            php_rs_ext_standard::file::php_sys_get_temp_dir(),
        ))),
        "filesize" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            match vm.vm_file_size(&p) {
                Ok(size) => Ok(Some(Value::Long(size as i64))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "filetype" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            if vm.vm_is_file(&p) {
                Ok(Some(Value::String("file".to_string())))
            } else if vm.vm_is_dir(&p) {
                Ok(Some(Value::String("dir".to_string())))
            } else if vm.vm_file_exists(&p) {
                Ok(Some(Value::String("unknown".to_string())))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "filemtime" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            match php_rs_ext_standard::file::php_filemtime(&p) {
                Ok(t) => Ok(Some(Value::Long(t as i64))),
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "fileatime" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::metadata(&p) {
                    Ok(m) => {
                        let t = m
                            .accessed()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        Ok(Some(Value::Long(t)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                if vm.vm_file_exists(&p) {
                    Ok(Some(Value::Long(0)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "filectime" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::metadata(&p) {
                    Ok(m) => {
                        let t = m
                            .created()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        Ok(Some(Value::Long(t)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                if vm.vm_file_exists(&p) {
                    Ok(Some(Value::Long(0)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "is_readable" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            Ok(Some(Value::Bool(vm.vm_file_exists(&p))))
        }
        "is_writable" | "is_writeable" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                let writable = if let Ok(meta) = std::fs::metadata(&p) {
                    // On Unix, check write permission
                    !meta.permissions().readonly()
                } else {
                    false
                };
                Ok(Some(Value::Bool(writable)))
            }
            #[cfg(target_arch = "wasm32")]
            {
                // In WASM with VFS, files are always writable if they exist
                Ok(Some(Value::Bool(vm.vm_file_exists(&p))))
            }
        }
        "is_executable" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&p)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let exec = std::fs::metadata(&p)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(exec)))
            }
            #[cfg(not(unix))]
            {
                Ok(Some(Value::Bool(false)))
            }
        }
        "pathinfo" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let option = args.get(1).map(|v| v.to_long());
            let info = php_rs_ext_standard::file::php_pathinfo(&p);
            match option {
                Some(1) => Ok(Some(Value::String(info.dirname))), // PATHINFO_DIRNAME
                Some(2) => Ok(Some(Value::String(info.basename))), // PATHINFO_BASENAME
                Some(4) => Ok(Some(Value::String(info.extension))), // PATHINFO_EXTENSION
                Some(8) => Ok(Some(Value::String(info.filename))), // PATHINFO_FILENAME
                _ => {
                    let mut arr = PhpArray::new();
                    arr.set_string("dirname".to_string(), Value::String(info.dirname));
                    arr.set_string("basename".to_string(), Value::String(info.basename));
                    arr.set_string("extension".to_string(), Value::String(info.extension));
                    arr.set_string("filename".to_string(), Value::String(info.filename));
                    Ok(Some(Value::Array(arr)))
                }
            }
        }
        "getcwd" => match std::env::current_dir() {
            Ok(p) => Ok(Some(Value::String(p.to_string_lossy().to_string()))),
            Err(_) => Ok(Some(Value::Bool(false))),
        },
        "chdir" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            Ok(Some(Value::Bool(std::env::set_current_dir(&path).is_ok())))
        }
        "chmod" => {
            let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let mode = args.get(1).cloned().unwrap_or(Value::Long(0o755)).to_long();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(mode as u32);
                Ok(Some(Value::Bool(
                    std::fs::set_permissions(&path, perms).is_ok(),
                )))
            }
            #[cfg(not(unix))]
            {
                let _ = (path, mode);
                Ok(Some(Value::Bool(false)))
            }
        }
        "scandir" => {
            let dir = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            vm.check_open_basedir(&dir)?;
            match php_rs_ext_standard::file::php_scandir(&dir) {
                Ok(entries) => {
                    let mut arr = PhpArray::new();
                    for entry in entries {
                        arr.push(Value::String(entry));
                    }
                    Ok(Some(Value::Array(arr)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "glob" => {
            // glob() with support for *, ?, and [...] character classes
            let pattern = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let glob_onlydir = flags & 0x4000 != 0; // GLOB_ONLYDIR = 0x4000 (platform-dependent)
            let mut arr = PhpArray::new();
            // Extract directory part and file pattern
            let dir = std::path::Path::new(&pattern)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());
            let file_pattern = std::path::Path::new(&pattern)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Ok(names) = vm.vm_read_dir(&dir) {
                let mut matched: Vec<String> = Vec::new();
                for name in names {
                    if glob_match(&file_pattern, &name) {
                        let full = if dir == "." {
                            name.clone()
                        } else {
                            format!("{}/{}", dir, name)
                        };
                        // GLOB_ONLYDIR: only include directories
                        if glob_onlydir {
                            if std::path::Path::new(&full).is_dir() {
                                matched.push(full);
                            }
                        } else {
                            matched.push(full);
                        }
                    }
                }
                matched.sort();
                for m in matched {
                    arr.push(Value::String(m));
                }
            }
            Ok(Some(Value::Array(arr)))
        }
        "is_link" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            #[cfg(not(target_arch = "wasm32"))]
            {
                Ok(Some(Value::Bool(
                    std::fs::symlink_metadata(&p)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false),
                )))
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = &p;
                Ok(Some(Value::Bool(false)))
            }
        }
        "touch" => {
            let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            // Create file if doesn't exist, otherwise just return true
            if !vm.vm_file_exists(&p) {
                let _ = vm.vm_write_file(&p, &[]);
            }
            Ok(Some(Value::Bool(true)))
        }
        "fopen" => {
            let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let mode = args
                .get(1)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "r".into());
            // Handle php:// stream wrappers for stdio
            match filename.as_str() {
                "php://stdin" => Ok(Some(Value::Resource(0, "stream".to_string()))),
                "php://stdout" | "php://output" => {
                    Ok(Some(Value::Resource(1, "stream".to_string())))
                }
                "php://stderr" => Ok(Some(Value::Resource(2, "stream".to_string()))),
                "php://input" => {
                    // Create an in-memory stream backed by the raw request body.
                    let body = vm
                        .raw_input_body
                        .as_deref()
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec();
                    let handle = php_rs_ext_standard::file::FileHandle::from_bytes(body);
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                "php://memory" | "php://temp" => {
                    // Empty writable in-memory stream.
                    let handle = php_rs_ext_standard::file::FileHandle::from_bytes(Vec::new());
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                _ if filename.starts_with("php://filter/") => {
                    // php://filter/read=convert.base64-encode/resource=file.txt
                    let (read_filters, _write_filters, resource) =
                        parse_php_filter_spec(&filename["php://filter/".len()..]);
                    // Read the resource
                    let data = if resource.is_empty() {
                        Vec::new()
                    } else {
                        match vm.vm_read_to_string(&resource) {
                            Ok(s) => s.into_bytes(),
                            Err(_) => return Ok(Some(Value::Bool(false))),
                        }
                    };
                    // Apply read filters
                    let mut result = data;
                    for filter in &read_filters {
                        result = apply_stream_filter(filter, &result);
                    }
                    let handle = php_rs_ext_standard::file::FileHandle::from_bytes(result);
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                _ if filename.starts_with("data://") || filename.starts_with("data:") => {
                    // data://text/plain;base64,SGVsbG8= or data://text/plain,Hello
                    let uri = if filename.starts_with("data://") {
                        &filename["data://".len()..]
                    } else {
                        &filename["data:".len()..]
                    };
                    let data = if let Some(b64_pos) = uri.find(";base64,") {
                        // Base64 encoded
                        let encoded = &uri[b64_pos + 8..];
                        base64_decode_bytes(encoded)
                    } else if let Some(comma_pos) = uri.find(',') {
                        uri[comma_pos + 1..].as_bytes().to_vec()
                    } else {
                        uri.as_bytes().to_vec()
                    };
                    let handle = php_rs_ext_standard::file::FileHandle::from_bytes(data);
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                _ if filename.starts_with("http://") || filename.starts_with("https://") => {
                    #[cfg(feature = "native-io")]
                    {
                        if vm.ini.get("allow_url_fopen") != "1" {
                            vm.write_output("Warning: fopen(): http:// wrapper is disabled in the server configuration by allow_url_fopen=0\n");
                            return Ok(Some(Value::Bool(false)));
                        }
                        let agent = ureq::Agent::new_with_config(
                            ureq::Agent::config_builder()
                                .http_status_as_error(false)
                                .timeout_global(Some(std::time::Duration::from_secs(
                                    vm.ini.get("default_socket_timeout").parse::<u64>().unwrap_or(60),
                                )))
                                .build(),
                        );
                        match agent.get(&filename).call() {
                            Ok(mut resp) => {
                                let body = resp.body_mut().read_to_string().unwrap_or_default();
                                let handle = php_rs_ext_standard::file::FileHandle::from_bytes(
                                    body.into_bytes(),
                                );
                                let id = vm.next_resource_id;
                                vm.next_resource_id += 1;
                                vm.file_handles.insert(id, handle);
                                Ok(Some(Value::Resource(id, "stream".to_string())))
                            }
                            Err(_) => Ok(Some(Value::Bool(false))),
                        }
                    }
                    #[cfg(not(feature = "native-io"))]
                    {
                        Ok(Some(Value::Bool(false)))
                    }
                }
                _ => match php_rs_ext_standard::file::FileHandle::open(&filename, &mode) {
                    Ok(handle) => {
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.file_handles.insert(id, handle);
                        Ok(Some(Value::Resource(id, "stream".to_string())))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                },
            }
        }
        "fclose" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if vm.file_handles.remove(&id).is_some() {
                Ok(Some(Value::Bool(true)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fread" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let length = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.read(length) {
                    Ok(data) => Ok(Some(Value::String(
                        String::from_utf8_lossy(&data).to_string(),
                    ))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fwrite" | "fputs" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.write(data.as_bytes()) {
                    Ok(n) => Ok(Some(Value::Long(n as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fgets" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.gets() {
                    Ok(Some(line)) => Ok(Some(Value::String(line))),
                    Ok(None) => Ok(Some(Value::Bool(false))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "feof" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get(&id) {
                Ok(Some(Value::Bool(handle.eof())))
            } else {
                Ok(Some(Value::Bool(true)))
            }
        }
        "fseek" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let whence = args.get(2).map(|v| v.to_long()).unwrap_or(0);
            let w = match whence {
                1 => php_rs_ext_standard::file::SeekWhence::Cur,
                2 => php_rs_ext_standard::file::SeekWhence::End,
                _ => php_rs_ext_standard::file::SeekWhence::Set,
            };
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.seek(offset, w) {
                    Ok(_) => Ok(Some(Value::Long(0))),
                    Err(_) => Ok(Some(Value::Long(-1))),
                }
            } else {
                Ok(Some(Value::Long(-1)))
            }
        }
        "ftell" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.tell() {
                    Ok(pos) => Ok(Some(Value::Long(pos as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "rewind" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.rewind() {
                    Ok(_) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fflush" => {
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
        "ftruncate" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let size = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u64;
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.truncate(size) {
                    Ok(_) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "flock" => {
            // Stub: always succeed
            Ok(Some(Value::Bool(true)))
        }
        "fgetc" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.read(1) {
                    Ok(data) if !data.is_empty() => Ok(Some(Value::String(
                        String::from_utf8_lossy(&data).to_string(),
                    ))),
                    _ => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fgetcsv" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let separator = args
                .get(2)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| ",".into());
            let enclosure = args
                .get(3)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\"".into());
            let escape_char = args
                .get(4)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "\\".into());
            let sep = separator.chars().next().unwrap_or(',');
            let enc = enclosure.chars().next().unwrap_or('"');
            let esc = escape_char.chars().next();
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                match handle.gets() {
                    Ok(Some(line)) => {
                        let line = line.trim_end_matches('\n').trim_end_matches('\r');
                        let arr = parse_csv_line(line, sep, enc, esc);
                        Ok(Some(Value::Array(arr)))
                    }
                    _ => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fputcsv" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let fields = args.get(1).cloned().unwrap_or(Value::Null);
            let separator = args
                .get(2)
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| ",".into());
            if let (Some(handle), Value::Array(ref arr)) = (vm.file_handles.get_mut(&id), &fields) {
                let line: Vec<String> = arr
                    .entries()
                    .iter()
                    .map(|(_, v)| {
                        let s = v.to_php_string();
                        if s.contains(&separator) || s.contains('"') || s.contains('\n') {
                            format!("\"{}\"", s.replace('"', "\"\""))
                        } else {
                            s
                        }
                    })
                    .collect();
                let csv_line = format!("{}\n", line.join(&separator));
                match handle.write(csv_line.as_bytes()) {
                    Ok(n) => Ok(Some(Value::Long(n as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "tmpfile" => {
            let dir = php_rs_ext_standard::file::php_sys_get_temp_dir();
            match php_rs_ext_standard::file::php_tempnam(&dir, "php") {
                Ok(path) => match php_rs_ext_standard::file::FileHandle::open(&path, "w+") {
                    Ok(handle) => {
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.file_handles.insert(id, handle);
                        Ok(Some(Value::Resource(id, "stream".to_string())))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                },
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "readfile" => {
            let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match vm.vm_read_to_string(&filename) {
                Ok(contents) => {
                    let len = contents.len();
                    vm.write_output(&contents);
                    Ok(Some(Value::Long(len as i64)))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "stat" | "lstat" => {
            let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if !vm.vm_file_exists(&filename) && !vm.vm_is_dir(&filename) {
                Ok(Some(Value::Bool(false)))
            } else {
                let size = vm.vm_file_size(&filename).unwrap_or(0) as i64;
                let is_dir = vm.vm_is_dir(&filename);
                let mode: i64 = if is_dir { 0o40755 } else { 0o100644 };
                let mtime: i64 = {
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let meta = if name == "lstat" {
                            std::fs::symlink_metadata(&filename)
                        } else {
                            std::fs::metadata(&filename)
                        };
                        meta.ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0)
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        0
                    }
                };
                let mut arr = PhpArray::new();
                arr.set_string("dev".into(), Value::Long(0));
                arr.set_string("ino".into(), Value::Long(0));
                arr.set_string("mode".into(), Value::Long(mode));
                arr.set_string("nlink".into(), Value::Long(1));
                arr.set_string("uid".into(), Value::Long(0));
                arr.set_string("gid".into(), Value::Long(0));
                arr.set_string("rdev".into(), Value::Long(0));
                arr.set_string("size".into(), Value::Long(size));
                arr.set_string("atime".into(), Value::Long(mtime));
                arr.set_string("mtime".into(), Value::Long(mtime));
                arr.set_string("ctime".into(), Value::Long(mtime));
                arr.set_string("blksize".into(), Value::Long(4096));
                arr.set_string("blocks".into(), Value::Long((size + 511) / 512));
                // Numeric indices too
                arr.set_int(0, Value::Long(0)); // dev
                arr.set_int(1, Value::Long(0)); // ino
                arr.set_int(2, Value::Long(mode));
                arr.set_int(3, Value::Long(1)); // nlink
                arr.set_int(4, Value::Long(0)); // uid
                arr.set_int(5, Value::Long(0)); // gid
                arr.set_int(6, Value::Long(0)); // rdev
                arr.set_int(7, Value::Long(size));
                arr.set_int(8, Value::Long(mtime));
                arr.set_int(9, Value::Long(mtime));
                arr.set_int(10, Value::Long(mtime));
                arr.set_int(11, Value::Long(4096));
                arr.set_int(12, Value::Long((size + 511) / 512));
                Ok(Some(Value::Array(arr)))
            }
        }
        "clearstatcache" => Ok(Some(Value::Null)),
        "fileperms" => {
            let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if vm.vm_file_exists(&filename) || vm.vm_is_dir(&filename) {
                let mode: i64 = if vm.vm_is_dir(&filename) {
                    0o40755
                } else {
                    0o100644
                };
                Ok(Some(Value::Long(mode)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "fileowner" | "filegroup" | "fileinode" => Ok(Some(Value::Long(0))),
        "linkinfo" => {
            let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => Ok(Some(Value::Long(0))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                if vm.vm_file_exists(&path) {
                    Ok(Some(Value::Long(0)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "symlink" => {
            let target = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let link = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            #[cfg(unix)]
            {
                match std::os::unix::fs::symlink(&target, &link) {
                    Ok(_) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (target, link);
                Ok(Some(Value::Bool(false)))
            }
        }
        "link" => {
            let target = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let link = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::hard_link(&target, &link) {
                    Ok(_) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                // Hard links not supported in VFS; emulate by copying
                match vm.vm_read_file(&target) {
                    Ok(data) => Ok(Some(Value::Bool(vm.vm_write_file(&link, &data).is_ok()))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
        }
        "readlink" => {
            let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            #[cfg(not(target_arch = "wasm32"))]
            {
                match std::fs::read_link(&path) {
                    Ok(target) => Ok(Some(Value::String(target.to_string_lossy().to_string()))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = &path;
                Ok(Some(Value::Bool(false)))
            }
        }
        "disk_free_space" | "diskfreespace" => Ok(Some(Value::Double(0.0))),
        "disk_total_space" => Ok(Some(Value::Double(0.0))),
        "opendir" => {
            let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            match vm.vm_read_dir(&path) {
                Ok(names) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    let data = names.join("\n");
                    // Store as serialized string in constants
                    vm.constants
                        .insert(format!("__dir_entries_{}", id), Value::String(data));
                    vm.constants
                        .insert(format!("__dir_pos_{}", id), Value::Long(0));
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                Err(_) => Ok(Some(Value::Bool(false))),
            }
        }
        "readdir" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let entries_key = format!("__dir_entries_{}", id);
            let pos_key = format!("__dir_pos_{}", id);
            if let Some(Value::String(ref entries)) = vm.constants.get(&entries_key).cloned() {
                let names: Vec<&str> = entries.split('\n').collect();
                let pos = vm.constants.get(&pos_key).map(|v| v.to_long()).unwrap_or(0) as usize;
                if pos < names.len() {
                    vm.constants.insert(pos_key, Value::Long((pos + 1) as i64));
                    Ok(Some(Value::String(names[pos].to_string())))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "closedir" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            vm.constants.remove(&format!("__dir_entries_{}", id));
            vm.constants.remove(&format!("__dir_pos_{}", id));
            Ok(Some(Value::Null))
        }
        "rewinddir" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            vm.constants
                .insert(format!("__dir_pos_{}", id), Value::Long(0));
            Ok(Some(Value::Null))
        }
        "chown" | "chgrp" | "lchown" | "lchgrp" => Ok(Some(Value::Bool(false))),
        "is_uploaded_file" | "move_uploaded_file" => Ok(Some(Value::Bool(false))),
        "stream_context_create" => {
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            let mut ctx = crate::vm::StreamContext::default();
            // Parse options array if provided: ['http' => ['method' => 'POST']]
            if let Some(Value::Array(ref opts)) = args.first() {
                for (wrapper_key, wrapper_opts) in opts.entries().iter() {
                    let wrapper_name = match wrapper_key {
                        ArrayKey::String(s) => s.clone(),
                        ArrayKey::Int(i) => i.to_string(),
                    };
                    if let Value::Array(ref inner) = wrapper_opts {
                        let mut inner_map = std::collections::HashMap::new();
                        for (k, v) in inner.entries().iter() {
                            let key = match k {
                                ArrayKey::String(s) => s.clone(),
                                ArrayKey::Int(i) => i.to_string(),
                            };
                            inner_map.insert(key, v.clone());
                        }
                        ctx.options.insert(wrapper_name, inner_map);
                    }
                }
            }
            vm.stream_contexts.insert(id, ctx);
            Ok(Some(Value::Resource(id, "stream-context".to_string())))
        }
        "stream_context_get_default" | "stream_context_set_default" => {
            // Return or set the default context (resource 0)
            if !vm.stream_contexts.contains_key(&0) {
                vm.stream_contexts
                    .insert(0, crate::vm::StreamContext::default());
            }
            Ok(Some(Value::Resource(0, "stream-context".to_string())))
        }
        "stream_context_get_options" => {
            let ctx_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(ctx) = vm.stream_contexts.get(&ctx_id) {
                let mut result = PhpArray::new();
                for (wrapper, opts) in &ctx.options {
                    let mut inner = PhpArray::new();
                    for (k, v) in opts {
                        inner.set_string(k.clone(), v.clone());
                    }
                    result.set_string(wrapper.clone(), Value::Array(inner));
                }
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Array(PhpArray::new())))
            }
        }
        "stream_context_get_params" => {
            let ctx_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(ctx) = vm.stream_contexts.get(&ctx_id) {
                let mut result = PhpArray::new();
                // Params include "options" key with the options array
                let mut opts_arr = PhpArray::new();
                for (wrapper, opts) in &ctx.options {
                    let mut inner = PhpArray::new();
                    for (k, v) in opts {
                        inner.set_string(k.clone(), v.clone());
                    }
                    opts_arr.set_string(wrapper.clone(), Value::Array(inner));
                }
                result.set_string("options".into(), Value::Array(opts_arr));
                Ok(Some(Value::Array(result)))
            } else {
                Ok(Some(Value::Array(PhpArray::new())))
            }
        }
        "stream_context_set_option" => {
            // stream_context_set_option($ctx, $wrapper, $option, $value) or
            // stream_context_set_option($ctx, $options_array)
            let ctx_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(Value::Array(ref opts)) = args.get(1) {
                // Array form
                if let Some(ctx) = vm.stream_contexts.get_mut(&ctx_id) {
                    for (wrapper_key, wrapper_opts) in opts.entries().iter() {
                        let wrapper_name = match wrapper_key {
                            ArrayKey::String(s) => s.clone(),
                            ArrayKey::Int(i) => i.to_string(),
                        };
                        if let Value::Array(ref inner) = wrapper_opts {
                            let entry = ctx.options.entry(wrapper_name).or_default();
                            for (k, v) in inner.entries().iter() {
                                let key = match k {
                                    ArrayKey::String(s) => s.clone(),
                                    ArrayKey::Int(i) => i.to_string(),
                                };
                                entry.insert(key, v.clone());
                            }
                        }
                    }
                }
            } else {
                // Positional form: set_option($ctx, $wrapper, $option, $value)
                let wrapper = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let option = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                let value = args.get(3).cloned().unwrap_or(Value::Null);
                if let Some(ctx) = vm.stream_contexts.get_mut(&ctx_id) {
                    ctx.options
                        .entry(wrapper)
                        .or_default()
                        .insert(option, value);
                }
            }
            Ok(Some(Value::Bool(true)))
        }
        "stream_context_set_options" | "stream_context_set_params" => Ok(Some(Value::Bool(true))),
        "stream_wrapper_register" | "stream_register_wrapper" => {
            // stream_wrapper_register(string $protocol, string $classname, int $flags = 0): bool
            // We register a simple in-memory wrapper for the protocol
            let protocol = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let _classname = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            // Check if already registered
            if vm.registered_stream_wrappers.contains(&protocol) {
                Ok(Some(Value::Bool(false)))
            } else {
                vm.registered_stream_wrappers.insert(protocol);
                Ok(Some(Value::Bool(true)))
            }
        }
        "stream_wrapper_unregister" => {
            let protocol = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let removed = vm.registered_stream_wrappers.remove(&protocol);
            Ok(Some(Value::Bool(removed)))
        }
        "stream_wrapper_restore" => {
            // Restores a built-in wrapper — we just return true for compatibility
            Ok(Some(Value::Bool(true)))
        }
        "stream_get_wrappers" => {
            let mut arr = PhpArray::new();
            // Built-in wrappers
            let builtins = [
                "https",
                "ftps",
                "compress.zlib",
                "compress.bzip2",
                "php",
                "file",
                "glob",
                "data",
                "http",
                "ftp",
                "phar",
            ];
            for name in builtins {
                arr.push(Value::String(name.to_string()));
            }
            // Custom-registered wrappers
            for name in &vm.registered_stream_wrappers {
                arr.push(Value::String(name.clone()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "stream_filter_register" => {
            let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let _classname = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            vm.registered_stream_filters.insert(name);
            Ok(Some(Value::Bool(true)))
        }
        "stream_filter_append" | "stream_filter_prepend" => {
            // stream_filter_append($stream, $filtername, $read_write, $params)
            // Returns a filter resource or false
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let filter_name = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            // read_write: STREAM_FILTER_READ=1, STREAM_FILTER_WRITE=2, STREAM_FILTER_ALL=3
            let read_write = args.get(2).map(|v| v.to_long()).unwrap_or(3);
            // Check if filter exists (built-in or user-registered)
            let known_filters = [
                "convert.base64-encode",
                "convert.base64-decode",
                "string.toupper",
                "string.tolower",
                "string.rot13",
                "string.strip_tags",
                "convert.quoted-printable-encode",
                "convert.quoted-printable-decode",
            ];
            if known_filters.contains(&filter_name.as_str())
                || vm.registered_stream_filters.contains(&filter_name)
            {
                // Attach filter to the stream
                if let Some(handle) = vm.file_handles.get_mut(&stream_id) {
                    let is_append = name == "stream_filter_append";
                    if read_write & 1 != 0 {
                        // STREAM_FILTER_READ
                        if is_append {
                            handle.read_filters.push(filter_name.clone());
                        } else {
                            handle.read_filters.insert(0, filter_name.clone());
                        }
                    }
                    if read_write & 2 != 0 {
                        // STREAM_FILTER_WRITE
                        if is_append {
                            handle.write_filters.push(filter_name.clone());
                        } else {
                            handle.write_filters.insert(0, filter_name.clone());
                        }
                    }
                }
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                Ok(Some(Value::Resource(id, "stream filter".to_string())))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_filter_remove" => {
            // Remove a previously appended filter
            Ok(Some(Value::Bool(true)))
        }
        "stream_get_filters" => {
            let mut arr = PhpArray::new();
            let builtins = [
                "convert.iconv.*",
                "mcrypt.*",
                "mdecrypt.*",
                "string.rot13",
                "string.toupper",
                "string.tolower",
                "string.strip_tags",
                "convert.*",
                "consumed",
                "dechunk",
                "convert.base64-encode",
                "convert.base64-decode",
                "convert.quoted-printable-encode",
                "convert.quoted-printable-decode",
            ];
            for name in builtins {
                arr.push(Value::String(name.to_string()));
            }
            for name in &vm.registered_stream_filters {
                arr.push(Value::String(name.clone()));
            }
            Ok(Some(Value::Array(arr)))
        }
        "stream_is_local" => {
            let uri = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let is_local = !uri.starts_with("http://")
                && !uri.starts_with("https://")
                && !uri.starts_with("ftp://")
                && !uri.starts_with("ftps://");
            Ok(Some(Value::Bool(is_local)))
        }
        "stream_resolve_include_path" => {
            let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            if std::path::Path::new(&filename).exists() {
                Ok(Some(Value::String(filename)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_supports_lock" => Ok(Some(Value::Bool(true))),
        "stream_get_meta_data" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let mut meta = PhpArray::new();
            meta.set_string("timed_out".into(), Value::Bool(false));
            meta.set_string("blocked".into(), Value::Bool(true));
            meta.set_string("eof".into(), Value::Bool(false));
            if let Some(handle) = vm.file_handles.get(&id) {
                meta.set_string("stream_type".into(), Value::String("STDIO".to_string()));
                meta.set_string("mode".into(), Value::String("r".to_string()));
                meta.set_string("unread_bytes".into(), Value::Long(0));
                meta.set_string("seekable".into(), Value::Bool(true));
                let _ = handle;
            } else {
                meta.set_string("stream_type".into(), Value::String("STDIO".to_string()));
                meta.set_string("mode".into(), Value::String("r".to_string()));
                meta.set_string("unread_bytes".into(), Value::Long(0));
                meta.set_string("seekable".into(), Value::Bool(false));
            }
            meta.set_string(
                "wrapper_type".into(),
                Value::String("plainfile".to_string()),
            );
            Ok(Some(Value::Array(meta)))
        }
        "stream_copy_to_stream" => {
            // stream_copy_to_stream($source, $dest, $maxlength = -1, $offset = 0)
            let src_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let dst_id = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            let _maxlength = args.get(2).map(|v| v.to_long()).unwrap_or(-1);
            // Read all from source
            let data = if let Some(handle) = vm.file_handles.get_mut(&src_id) {
                let mut buf = Vec::new();
                loop {
                    match handle.read(8192) {
                        Ok(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
                        _ => break,
                    }
                }
                Some(buf)
            } else {
                None
            };
            if let Some(data) = data {
                let len = data.len() as i64;
                if let Some(handle) = vm.file_handles.get_mut(&dst_id) {
                    let _ = handle.write(&data);
                }
                Ok(Some(Value::Long(len)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_get_contents" => {
            let id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(handle) = vm.file_handles.get_mut(&id) {
                let mut result = String::new();
                loop {
                    match handle.read(8192) {
                        Ok(data) if !data.is_empty() => {
                            result.push_str(&String::from_utf8_lossy(&data))
                        }
                        _ => break,
                    }
                }
                Ok(Some(Value::String(result)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_set_blocking" => {
            // stream_set_blocking($stream, $enable): bool
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let blocking = args.get(1).map(|v| v.to_bool()).unwrap_or(true);
            if let Some(handle) = vm.file_handles.get_mut(&stream_id) {
                match handle.set_blocking(blocking) {
                    Ok(()) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_set_timeout" => {
            // stream_set_timeout($stream, $seconds, $microseconds = 0): bool
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let seconds = args.get(1).map(|v| v.to_long()).unwrap_or(0) as u64;
            let microseconds = args.get(2).map(|v| v.to_long()).unwrap_or(0) as u64;
            let duration = std::time::Duration::from_secs(seconds)
                + std::time::Duration::from_micros(microseconds);
            if let Some(handle) = vm.file_handles.get_mut(&stream_id) {
                match handle.set_timeout(duration) {
                    Ok(()) => Ok(Some(Value::Bool(true))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_socket_client" => {
            // stream_socket_client($address, &$errno, &$errstr, $timeout, $flags, $context)
            let address = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let timeout_secs = args.get(3).map(|v| v.to_double()).unwrap_or(60.0);
            // Strip transport prefix (tcp://, udp://, unix://, etc.)
            let addr = address
                .strip_prefix("tcp://")
                .or_else(|| address.strip_prefix("ssl://"))
                .or_else(|| address.strip_prefix("tls://"))
                .unwrap_or(&address);
            let timeout = std::time::Duration::from_secs_f64(timeout_secs);
            let resolved = match addr.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => {
                        vm.write_back_arg(1, Value::Long(0), ref_args, ref_prop_args);
                        vm.write_back_arg(
                            2,
                            Value::String("No address found".to_string()),
                            ref_args,
                            ref_prop_args,
                        );
                        return Ok(Some(Value::Bool(false)));
                    }
                },
                Err(e) => {
                    vm.write_back_arg(1, Value::Long(0), ref_args, ref_prop_args);
                    vm.write_back_arg(2, Value::String(e.to_string()), ref_args, ref_prop_args);
                    return Ok(Some(Value::Bool(false)));
                }
            };
            match std::net::TcpStream::connect_timeout(&resolved, timeout) {
                Ok(stream) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    let handle = php_rs_ext_standard::file::FileHandle::from_tcp_stream(stream);
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                Err(e) => {
                    vm.write_back_arg(
                        1,
                        Value::Long(e.raw_os_error().unwrap_or(0) as i64),
                        ref_args,
                        ref_prop_args,
                    );
                    vm.write_back_arg(2, Value::String(e.to_string()), ref_args, ref_prop_args);
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "stream_socket_server" => {
            // stream_socket_server($address, &$errno, &$errstr, $flags, $context)
            let address = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            let addr = address.strip_prefix("tcp://").unwrap_or(&address);
            match std::net::TcpListener::bind(addr) {
                Ok(listener) => {
                    let id = vm.next_resource_id;
                    vm.next_resource_id += 1;
                    let handle = php_rs_ext_standard::file::FileHandle::from_tcp_listener(listener);
                    vm.file_handles.insert(id, handle);
                    Ok(Some(Value::Resource(id, "stream".to_string())))
                }
                Err(e) => {
                    vm.write_back_arg(
                        1,
                        Value::Long(e.raw_os_error().unwrap_or(0) as i64),
                        ref_args,
                        ref_prop_args,
                    );
                    vm.write_back_arg(2, Value::String(e.to_string()), ref_args, ref_prop_args);
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "stream_socket_accept" => {
            // stream_socket_accept($server_socket, $timeout, &$peer_name)
            let server_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            if let Some(server_handle) = vm.file_handles.get(&server_id) {
                match server_handle.accept() {
                    Ok((client_handle, peer_name)) => {
                        vm.write_back_arg(2, Value::String(peer_name), ref_args, ref_prop_args);
                        let id = vm.next_resource_id;
                        vm.next_resource_id += 1;
                        vm.file_handles.insert(id, client_handle);
                        Ok(Some(Value::Resource(id, "stream".to_string())))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_socket_get_name" => {
            // stream_socket_get_name($handle, $want_peer)
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let want_peer = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
            if let Some(handle) = vm.file_handles.get(&stream_id) {
                match handle.socket_name(want_peer) {
                    Ok(name) => Ok(Some(Value::String(name))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_socket_recvfrom" => {
            // stream_socket_recvfrom($socket, $length, $flags, &$address)
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let length = args.get(1).map(|v| v.to_long()).unwrap_or(8192) as usize;
            if let Some(handle) = vm.file_handles.get_mut(&stream_id) {
                match handle.read(length) {
                    Ok(data) => Ok(Some(Value::String(
                        String::from_utf8_lossy(&data).to_string(),
                    ))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_socket_sendto" => {
            // stream_socket_sendto($socket, $data, $flags, $address)
            let stream_id = args.first().map(|v| v.to_long()).unwrap_or(0);
            let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
            if let Some(handle) = vm.file_handles.get_mut(&stream_id) {
                match handle.write(data.as_bytes()) {
                    Ok(n) => Ok(Some(Value::Long(n as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }
        "stream_socket_shutdown" => {
            // stream_socket_shutdown($stream, $how)
            // $how: STREAM_SHUT_RD=0, STREAM_SHUT_WR=1, STREAM_SHUT_RDWR=2
            Ok(Some(Value::Bool(true)))
        }
        "stream_socket_pair" | "stream_socket_enable_crypto" => Ok(Some(Value::Bool(false))),
        "stream_select" => {
            // stream_select(&$read, &$write, &$except, $tv_sec, $tv_usec = 0)
            // Simplified implementation: for non-socket streams, report all as ready.
            // For socket streams, use poll with timeout.
            let tv_sec = args.get(3).cloned().unwrap_or(Value::Null);
            let tv_usec = args.get(4).map(|v| v.to_long()).unwrap_or(0);

            let timeout = if tv_sec.is_null() {
                None // Block indefinitely
            } else {
                let secs = tv_sec.to_long();
                Some(
                    std::time::Duration::from_secs(secs as u64)
                        + std::time::Duration::from_micros(tv_usec as u64),
                )
            };

            // Count ready streams from the read array
            let read_arr = args.first().cloned().unwrap_or(Value::Null);
            let mut ready_count = 0i64;

            if let Value::Array(arr) = &read_arr {
                // For file handles, check if data is available
                // For simplicity, we count all streams as ready (non-blocking check)
                for (_, val) in arr.entries() {
                    if let Value::Resource(id, _) = val {
                        if vm.file_handles.contains_key(id) {
                            ready_count += 1;
                        }
                    }
                }
            }

            // If timeout is 0, return immediately
            if let Some(t) = timeout {
                if !t.is_zero() && ready_count == 0 {
                    // Sleep for the timeout duration
                    std::thread::sleep(t);
                }
            }

            Ok(Some(Value::Long(ready_count)))
        }
        _ => Ok(None),
    }
}

/// Parse php://filter specification into (read_filters, write_filters, resource).
/// The resource= part can contain slashes (e.g., /tmp/file.txt), so we extract it first.
fn parse_php_filter_spec(spec: &str) -> (Vec<String>, Vec<String>, String) {
    let mut read_filters = Vec::new();
    let mut write_filters = Vec::new();
    let mut resource = String::new();

    // Extract resource= first (takes everything after "resource=")
    let (filter_part, res_part) = if let Some(pos) = spec.find("/resource=") {
        (&spec[..pos], &spec[pos + "/resource=".len()..])
    } else if let Some(pos) = spec.find("resource=") {
        (&spec[..pos], &spec[pos + "resource=".len()..])
    } else {
        (spec, "")
    };
    resource = res_part.to_string();

    // Parse filter specs from the non-resource part
    for part in filter_part.split('/') {
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("read=") {
            read_filters.extend(rest.split('|').map(String::from));
        } else if let Some(rest) = part.strip_prefix("write=") {
            write_filters.extend(rest.split('|').map(String::from));
        } else if read_filters.is_empty() && write_filters.is_empty() {
            read_filters.extend(part.split('|').map(String::from));
        }
    }

    (read_filters, write_filters, resource)
}

/// Apply a PHP stream filter to data bytes.
fn apply_stream_filter(filter: &str, data: &[u8]) -> Vec<u8> {
    match filter {
        "convert.base64-encode" => base64_encode_bytes(data).into_bytes(),
        "convert.base64-decode" => base64_decode_bytes(&String::from_utf8_lossy(data)),
        "string.toupper" => String::from_utf8_lossy(data).to_uppercase().into_bytes(),
        "string.tolower" => String::from_utf8_lossy(data).to_lowercase().into_bytes(),
        "string.rot13" => data
            .iter()
            .map(|&b| match b {
                b'a'..=b'm' | b'A'..=b'M' => b + 13,
                b'n'..=b'z' | b'N'..=b'Z' => b - 13,
                _ => b,
            })
            .collect(),
        "string.strip_tags" => {
            let s = String::from_utf8_lossy(data);
            let mut result = String::new();
            let mut in_tag = false;
            for ch in s.chars() {
                if ch == '<' {
                    in_tag = true;
                } else if ch == '>' {
                    in_tag = false;
                } else if !in_tag {
                    result.push(ch);
                }
            }
            result.into_bytes()
        }
        "convert.quoted-printable-encode" => {
            let s = String::from_utf8_lossy(data);
            quoted_printable_encode(&s).into_bytes()
        }
        "convert.quoted-printable-decode" => {
            let s = String::from_utf8_lossy(data);
            quoted_printable_decode(&s).into_bytes()
        }
        _ => data.to_vec(), // Unknown filter, pass through
    }
}

/// Simple base64 encoding.
fn base64_encode_bytes(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Simple base64 decoding.
fn base64_decode_bytes(input: &str) -> Vec<u8> {
    fn char_val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut result = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = char_val(chunk[0]).unwrap_or(0);
        let b = char_val(chunk[1]).unwrap_or(0);
        result.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = char_val(chunk[2]).unwrap_or(0);
            result.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 && chunk[3] != b'=' {
                let d = char_val(chunk[3]).unwrap_or(0);
                result.push((((c & 0x3) << 6) | d) as u8);
            }
        }
    }
    result
}

/// Quoted-printable encoding.
fn quoted_printable_encode(input: &str) -> String {
    let mut result = String::new();
    for b in input.bytes() {
        if (b >= 33 && b <= 126 && b != b'=') || b == b'\t' || b == b' ' {
            result.push(b as char);
        } else if b == b'\n' {
            result.push('\n');
        } else {
            result.push_str(&format!("={:02X}", b));
        }
    }
    result
}

/// Quoted-printable decoding.
fn quoted_printable_decode(input: &str) -> String {
    let mut result = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            if bytes[i + 1] == b'\r' || bytes[i + 1] == b'\n' {
                // Soft line break
                i += 2;
                if i < bytes.len() && bytes[i] == b'\n' {
                    i += 1;
                }
            } else if let Ok(val) =
                u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
                result.push(val as char);
                i += 3;
            } else {
                result.push('=');
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}
