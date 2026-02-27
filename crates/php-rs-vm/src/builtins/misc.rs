//! Catch-all module for built-in functions that don't belong to any
//! other named category module (strings, arrays, math, file, pcre,
//! json, date, type_check, output, hash, mbstring, ctype, spl,
//! bcmath, intl, curl, session, gd, sodium, openssl, mysqli,
//! calendar, bz2, zlib, iconv, filter, random).

use super::{BuiltinFn, BuiltinRegistry};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmError, VmResult};
use php_rs_compiler::op::OperandType;

// ── Helpers (moved from vm.rs) ──────────────────────────────────────

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
                        ArrayKey::Int(n) => SV::Int(*n),
                        ArrayKey::String(s) => SV::Str(s.clone()),
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

/// Parse INI-format string into a PhpArray.
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

// ── Registration ────────────────────────────────────────────────────

pub(crate) fn register(r: &mut BuiltinRegistry) {
    // -- Execution --
    r.insert("exit", php_exit);
    r.insert("die", php_exit);
    r.insert("sleep", php_sleep);
    r.insert("usleep", php_usleep);
    r.insert("time_nanosleep", php_time_nanosleep);
    r.insert("time_sleep_until", php_time_sleep_until);
    r.insert("set_time_limit", php_set_time_limit);
    r.insert("ignore_user_abort", php_ignore_user_abort);

    // -- Error handling --
    r.insert("trigger_error", php_trigger_error);
    r.insert("user_error", php_trigger_error);
    r.insert("error_reporting", php_error_reporting);
    r.insert("set_error_handler", php_set_error_handler);
    r.insert("restore_error_handler", php_restore_error_handler);
    r.insert("set_exception_handler", php_set_exception_handler);
    r.insert("restore_exception_handler", php_restore_exception_handler);
    r.insert("error_log", php_error_log);
    r.insert("error_clear_last", php_error_clear_last);
    r.insert("error_get_last", php_error_clear_last);
    r.insert("get_error_handler", php_get_error_handler);
    r.insert("get_exception_handler", php_get_error_handler);

    // -- Function handling --
    r.insert("call_user_func", php_call_user_func);
    r.insert("call_user_func_array", php_call_user_func_array);
    r.insert("register_shutdown_function", php_register_shutdown_function);
    r.insert("register_tick_function", php_register_tick_function);
    r.insert("unregister_tick_function", php_unregister_tick_function);
    r.insert("forward_static_call", php_forward_static_call);
    r.insert("forward_static_call_array", php_forward_static_call);
    r.insert("func_get_args", php_func_get_args);
    r.insert("func_get_arg", php_func_get_arg);
    r.insert("func_num_args", php_func_num_args);
    r.insert("function_exists", php_function_exists);
    r.insert("is_callable", php_is_callable);

    // -- Variable handling --
    r.insert("serialize", php_serialize);
    r.insert("unserialize", php_unserialize);
    // compact/extract are registered in arrays.rs with real implementations
    r.insert("isset", php_isset);
    r.insert("empty", php_empty);
    r.insert("var_export", php_var_export);
    r.insert("debug_zval_dump", php_debug_zval_dump);

    // -- INI --
    r.insert("ini_get", php_ini_get);
    r.insert("ini_set", php_ini_set);
    r.insert("ini_alter", php_ini_set);
    r.insert("ini_restore", php_ini_restore);
    r.insert("ini_get_all", php_ini_get_all);
    r.insert("get_cfg_var", php_get_cfg_var);
    r.insert("get_include_path", php_get_cfg_var);
    r.insert("set_include_path", php_get_cfg_var);
    r.insert("php_ini_loaded_file", php_php_ini_loaded_file);
    r.insert("php_ini_scanned_files", php_php_ini_loaded_file);
    r.insert("parse_ini_file", php_parse_ini_file);
    r.insert("parse_ini_string", php_parse_ini_string);
    r.insert("ini_parse_quantity", php_ini_parse_quantity);

    // -- Misc standard --
    r.insert("phpinfo", php_phpinfo);
    r.insert("phpcredits", php_phpcredits);
    r.insert("phpversion", php_phpversion);
    r.insert("php_uname", php_php_uname);
    r.insert("php_sapi_name", php_php_sapi_name);
    r.insert("getenv", php_getenv);
    r.insert("putenv", php_putenv);
    r.insert("constant", php_constant);
    r.insert("defined", php_defined);
    r.insert("define", php_define);
    r.insert("get_defined_constants", php_get_defined_constants);
    r.insert("get_defined_vars", php_get_defined_vars);
    r.insert("get_defined_functions", php_get_defined_functions);
    r.insert("time", php_time);
    r.insert("microtime", php_microtime);
    r.insert("uniqid", php_uniqid);
    r.insert("version_compare", php_version_compare);
    r.insert("assert", php_assert);
    r.insert("assert_options", php_assert_options);

    // -- Headers / HTTP --
    r.insert("header", php_header);
    r.insert("header_remove", php_header_remove);
    r.insert("headers_sent", php_headers_sent);
    r.insert("http_response_code", php_http_response_code);
    r.insert("header_register_callback", php_header_register_callback);
    r.insert("headers_list", php_headers_list);
    r.insert("setcookie", php_setcookie);
    r.insert("setrawcookie", php_setcookie);
    r.insert(
        "http_clear_last_response_headers",
        php_http_clear_last_response_headers,
    );
    r.insert(
        "http_get_last_response_headers",
        php_http_get_last_response_headers,
    );

    // -- Class / Object introspection --
    r.insert("class_exists", php_class_exists);
    r.insert("method_exists", php_method_exists);
    r.insert("property_exists", php_property_exists);
    r.insert("get_parent_class", php_get_parent_class);
    r.insert("is_a", php_is_a);
    r.insert("is_subclass_of", php_is_subclass_of);
    r.insert("get_called_class", php_get_called_class);
    r.insert("get_class_methods", php_get_class_methods);
    r.insert("get_class_vars", php_get_class_vars);
    r.insert("get_object_vars", php_get_object_vars);
    r.insert("interface_exists", php_interface_exists);
    r.insert("class_alias", php_class_alias);
    r.insert("extension_loaded", php_extension_loaded);
    r.insert("enum_exists", php_enum_exists);
    r.insert("get_declared_classes", php_get_declared_classes);
    r.insert("get_declared_interfaces", php_get_declared_interfaces);
    r.insert("get_declared_traits", php_get_declared_traits);
    r.insert("trait_exists", php_trait_exists);
    r.insert("settype", php_settype);
    r.insert("get_included_files", php_get_included_files);
    r.insert("get_required_files", php_get_included_files);
    r.insert("get_loaded_extensions", php_get_loaded_extensions);
    r.insert("get_extension_funcs", php_get_extension_funcs);
    r.insert("get_mangled_object_vars", php_get_mangled_object_vars);
    r.insert("get_resource_id", php_get_resource_id);
    r.insert("get_resource_type", php_get_resource_type);
    r.insert("get_resources", php_get_resources);
    r.insert("clone", php_clone);

    // -- Debug / Backtrace --
    r.insert("debug_backtrace", php_debug_backtrace);
    r.insert("debug_print_backtrace", php_debug_print_backtrace);

    // -- GC --
    r.insert("gc_collect_cycles", php_gc_collect_cycles);
    r.insert("gc_enabled", php_gc_enabled);
    r.insert("gc_enable", php_gc_enable);
    r.insert("gc_disable", php_gc_enable);
    r.insert("gc_mem_caches", php_gc_mem_caches);
    r.insert("gc_status", php_gc_status);

    // -- Zend --
    r.insert("zend_version", php_zend_version);
    r.insert("zend_thread_id", php_zend_thread_id);

    // -- Memory --
    r.insert("memory_get_usage", php_memory_get_usage);
    r.insert("memory_get_peak_usage", php_memory_get_usage);
    r.insert("memory_reset_peak_usage", php_memory_reset_peak_usage);

    // -- Process --
    r.insert("getmypid", php_getmypid);
    r.insert("getmyuid", php_getmyuid);
    r.insert("getmygid", php_getmyuid);
    r.insert("getmyinode", php_getmyuid);
    r.insert("getlastmod", php_getmyuid);
    r.insert("get_current_user", php_get_current_user);
    r.insert("gethostname", php_gethostname);
    r.insert("gettimeofday", php_gettimeofday);
    r.insert("hrtime", php_hrtime);
    r.insert("sys_getloadavg", php_sys_getloadavg);
    r.insert("getrusage", php_getrusage);

    // -- Locale --
    r.insert("setlocale", php_setlocale);
    r.insert("localeconv", php_localeconv);

    // -- Network --
    r.insert("ip2long", php_ip2long);
    r.insert("long2ip", php_long2ip);
    r.insert("inet_ntop", php_inet_ntop);
    r.insert("inet_pton", php_inet_pton);
    r.insert("gethostbyname", php_gethostbyname);
    r.insert("gethostbyaddr", php_gethostbyaddr);
    r.insert("gethostbynamel", php_gethostbynamel);
    r.insert("getprotobyname", php_getprotobyname);
    r.insert("getprotobynumber", php_getprotobynumber);
    r.insert("getservbyname", php_getservbyname);
    r.insert("getservbyport", php_getservbyport);
    r.insert("checkdnsrr", php_checkdnsrr);
    r.insert("dns_check_record", php_checkdnsrr);
    r.insert("dns_get_mx", php_dns_get_mx);
    r.insert("getmxrr", php_dns_get_mx);
    r.insert("dns_get_record", php_dns_get_record);
    r.insert("net_get_interfaces", php_dns_get_record);
    r.insert("fsockopen", php_fsockopen);
    r.insert("pfsockopen", php_fsockopen);
    r.insert("set_file_buffer", php_set_file_buffer);
    r.insert("socket_set_blocking", php_set_file_buffer);
    r.insert("socket_set_timeout", php_set_file_buffer);
    r.insert("socket_get_status", php_set_file_buffer);

    // -- Exec --
    r.insert("exec", php_exec);
    r.insert("shell_exec", php_shell_exec);
    r.insert("system", php_system);
    r.insert("passthru", php_passthru);
    r.insert("escapeshellarg", php_escapeshellarg);
    r.insert("escapeshellcmd", php_escapeshellcmd);
    r.insert("popen", php_popen);
    r.insert("pclose", php_pclose);
    r.insert("proc_open", php_proc_open);
    r.insert("proc_close", php_proc_close);
    r.insert("proc_get_status", php_proc_get_status);
    r.insert("proc_terminate", php_proc_terminate);
    r.insert("proc_nice", php_proc_nice);

    // -- Pack/Unpack --
    r.insert("pack", php_pack);
    r.insert("unpack", php_unpack);

    // -- Hash --
    r.insert("hash", php_hash_builtin);
    r.insert("hash_hmac", php_hash_hmac_builtin);
    r.insert("hash_equals", php_hash_equals_builtin);
    r.insert("hash_algos", php_hash_algos_builtin);

    // -- URL --
    r.insert("parse_url", php_parse_url);
    r.insert("parse_str", php_parse_str);
    r.insert("http_build_query", php_http_build_query);
    r.insert("getopt", php_getopt);

    // -- Misc --
    r.insert("crypt", php_crypt);
    r.insert("key", php_key);
    r.insert("next", php_next);
    r.insert("prev", php_prev);
    r.insert("get_html_translation_table", php_get_html_translation_table);
    r.insert("get_browser", php_get_browser);
    r.insert("get_meta_tags", php_get_browser);
    r.insert("get_headers", php_get_headers);
    r.insert("connection_status", php_connection_status);
    r.insert("connection_aborted", php_connection_status);
    r.insert("mail", php_mail);
    r.insert("config_get_hash", php_config_get_hash);
    r.insert("request_parse_body", php_request_parse_body);
    r.insert("openlog", php_openlog);
    r.insert("closelog", php_openlog);
    r.insert("syslog", php_syslog);
    r.insert("nl_langinfo", php_nl_langinfo);
    r.insert("ftok", php_ftok);
    r.insert("realpath_cache_get", php_realpath_cache_get);
    r.insert("realpath_cache_size", php_realpath_cache_size);

    // -- Deprecated/removed functions --
    r.insert("each", php_each);
    r.insert("money_format", php_money_format);

    // -- Image type helpers --
    r.insert("image_type_to_mime_type", php_image_type_to_mime_type);
    r.insert("image_type_to_extension", php_image_type_to_extension);
    r.insert("getimagesize", php_getimagesize);
    r.insert("getimagesizefromstring", php_getimagesize);
    r.insert("iptcparse", php_getimagesize);
    r.insert("iptcembed", php_getimagesize);

    // -- Windows stubs --
    r.insert("sapi_windows_cp_conv", php_sapi_windows_stub);
    r.insert("sapi_windows_cp_get", php_sapi_windows_stub);
    r.insert("sapi_windows_cp_is_utf8", php_sapi_windows_stub);
    r.insert("sapi_windows_cp_set", php_sapi_windows_stub);
    r.insert("sapi_windows_generate_ctrl_event", php_sapi_windows_stub);
    r.insert("sapi_windows_set_ctrl_handler", php_sapi_windows_stub);
    r.insert("sapi_windows_vt100_support", php_sapi_windows_stub);

    // -- Gettext --
    r.insert("gettext", php_gettext);
    r.insert("_", php_gettext);
    r.insert("dcgettext", php_gettext);
    r.insert("dcngettext", php_gettext);
    r.insert("dgettext", php_gettext);
    r.insert("dngettext", php_gettext);
    r.insert("ngettext", php_gettext);
    r.insert("bindtextdomain", php_bindtextdomain);
    r.insert("bind_textdomain_codeset", php_bindtextdomain);
    r.insert("textdomain", php_textdomain);

    // -- Posix --
    r.insert("posix_getpid", php_posix_getpid);
    r.insert("posix_getppid", php_posix_getppid);
    r.insert("posix_getuid", php_posix_getuid);
    r.insert("posix_geteuid", php_posix_getuid);
    r.insert("posix_getgid", php_posix_getuid);
    r.insert("posix_getegid", php_posix_getuid);
    r.insert("posix_getpgid", php_posix_getpgid);
    r.insert("posix_getpgrp", php_posix_getpgid);
    r.insert("posix_getsid", php_posix_getpgid);
    r.insert("posix_getlogin", php_posix_getlogin);
    r.insert("posix_uname", php_posix_uname);
    r.insert("posix_times", php_posix_times);
    r.insert("posix_isatty", php_posix_isatty);
    r.insert("posix_ttyname", php_posix_ttyname);
    r.insert("posix_ctermid", php_posix_ttyname);
    r.insert("posix_getcwd", php_posix_getcwd);
    r.insert("posix_mkfifo", php_posix_mkfifo);
    r.insert("posix_mknod", php_posix_mkfifo);
    r.insert("posix_setpgid", php_posix_mkfifo);
    r.insert("posix_setsid", php_posix_mkfifo);
    r.insert("posix_setuid", php_posix_mkfifo);
    r.insert("posix_setgid", php_posix_mkfifo);
    r.insert("posix_seteuid", php_posix_mkfifo);
    r.insert("posix_setegid", php_posix_mkfifo);
    r.insert("posix_setrlimit", php_posix_mkfifo);
    r.insert("posix_kill", php_posix_mkfifo);
    r.insert("posix_getrlimit", php_posix_getrlimit);
    r.insert("posix_get_last_error", php_posix_get_last_error);
    r.insert("posix_errno", php_posix_get_last_error);
    r.insert("posix_strerror", php_posix_strerror);
    r.insert("posix_access", php_posix_access);
    r.insert("posix_eaccess", php_posix_access);
    r.insert("posix_getpwnam", php_posix_getpwnam);
    r.insert("posix_getpwuid", php_posix_getpwnam);
    r.insert("posix_getgrnam", php_posix_getpwnam);
    r.insert("posix_getgrgid", php_posix_getpwnam);
    r.insert("posix_getgroups", php_posix_getpwnam);
    r.insert("posix_initgroups", php_posix_getpwnam);
    r.insert("posix_fpathconf", php_posix_getpwnam);
    r.insert("posix_pathconf", php_posix_getpwnam);
    r.insert("posix_sysconf", php_posix_getpwnam);

    // -- pcntl --
    r.insert("pcntl_fork", php_pcntl_fork);
    r.insert("pcntl_waitpid", php_pcntl_fork);
    r.insert("pcntl_wait", php_pcntl_fork);
    r.insert("pcntl_signal", php_pcntl_signal);
    r.insert("pcntl_signal_dispatch", php_pcntl_signal);
    r.insert("pcntl_signal_get_handler", php_pcntl_signal_get_handler);
    r.insert("pcntl_sigprocmask", php_pcntl_sigprocmask);
    r.insert("pcntl_sigwaitinfo", php_pcntl_sigprocmask);
    r.insert("pcntl_sigtimedwait", php_pcntl_sigprocmask);
    r.insert("pcntl_wifexited", php_pcntl_wifexited);
    r.insert("pcntl_wifstopped", php_pcntl_wifexited);
    r.insert("pcntl_wifsignaled", php_pcntl_wifexited);
    r.insert("pcntl_wifcontinued", php_pcntl_wifexited);
    r.insert("pcntl_wexitstatus", php_pcntl_wexitstatus);
    r.insert("pcntl_wtermsig", php_pcntl_wexitstatus);
    r.insert("pcntl_wstopsig", php_pcntl_wexitstatus);
    r.insert("pcntl_exec", php_pcntl_exec);
    r.insert("pcntl_alarm", php_pcntl_alarm);
    r.insert("pcntl_get_last_error", php_pcntl_alarm);
    r.insert("pcntl_errno", php_pcntl_alarm);
    r.insert("pcntl_strerror", php_pcntl_strerror);
    r.insert("pcntl_async_signals", php_pcntl_async_signals);
    r.insert("pcntl_unshare", php_pcntl_exec);
    r.insert("pcntl_setpriority", php_pcntl_exec);
    r.insert("pcntl_getpriority", php_pcntl_alarm);
    r.insert("pcntl_rfork", php_pcntl_fork);
    r.insert("pcntl_forkx", php_pcntl_fork);
    r.insert("pcntl_waitid", php_pcntl_exec);
    r.insert("pcntl_getqos_class", php_pcntl_alarm);
    r.insert("pcntl_setqos_class", php_pcntl_exec);

    // -- GMP --
    register_gmp(r);

    // -- XML --
    register_xml(r);

    // -- Fileinfo --
    register_fileinfo(r);

    // -- SimpleXML -- (now handled by remaining.rs with real ext crate)
    // register_simplexml(r);

    // -- XMLWriter --
    register_xmlwriter(r);

    // -- Readline --
    register_readline(r);

    // -- Exif -- (now handled by remaining.rs with real ext crate)
    // register_exif(r);

    // -- Zip --
    register_zip(r);

    // -- Shmop -- (now handled by remaining.rs with real ext crate)
    // register_shmop(r);

    // -- SysV -- (now handled by remaining.rs with real ext crate)
    // register_sysv(r);

    // -- Tidy --
    register_tidy(r);

    // -- SNMP -- (now handled by remaining.rs with real ext crate)
    // register_snmp(r);

    // -- Sockets -- (now handled by remaining.rs with real ext crate)
    // register_sockets(r);

    // -- Opcache --
    register_opcache(r);

    // -- DBA -- (now handled by remaining.rs with real ext crate)
    // register_dba(r);

    // -- Enchant -- (now handled by remaining.rs with real ext crate)
    // register_enchant(r);

    // -- FTP -- (now handled by remaining.rs with real ext crate)
    // register_ftp(r);

    // -- com_dotnet --
    register_com_dotnet(r);

    // -- LDAP -- (now handled by remaining.rs with real ext crate)
    // register_ldap(r);

    // -- pgsql --
    register_pgsql(r);

    // -- ODBC -- (now handled by remaining.rs with real ext crate)
    // register_odbc(r);

    // -- APCu --
    register_apcu(r);

    // -- Iconv --
    register_iconv(r);
}

// ═══════════════════════════════════════════════════════════════════
// Handler implementations
// ═══════════════════════════════════════════════════════════════════

// -- Execution --

fn php_exit(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arg = args.first().cloned().unwrap_or(Value::Null);
    match arg {
        Value::String(s) => {
            vm.write_output(&s);
            Err(VmError::Exit(0))
        }
        Value::Long(n) => Err(VmError::Exit(n as i32)),
        _ => Err(VmError::Exit(0)),
    }
}

fn php_sleep(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let secs = args
        .first()
        .cloned()
        .unwrap_or(Value::Long(0))
        .to_long()
        .max(0) as u64;
    std::thread::sleep(std::time::Duration::from_secs(secs));
    Ok(Value::Long(0))
}

fn php_usleep(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let us = args
        .first()
        .cloned()
        .unwrap_or(Value::Long(0))
        .to_long()
        .max(0) as u64;
    std::thread::sleep(std::time::Duration::from_micros(us));
    Ok(Value::Null)
}

fn php_time_nanosleep(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let secs = args.first().map(|v| v.to_long()).unwrap_or(0);
    let nsecs = args.get(1).map(|v| v.to_long()).unwrap_or(0);
    std::thread::sleep(std::time::Duration::new(
        secs.max(0) as u64,
        nsecs.max(0) as u32,
    ));
    Ok(Value::Bool(true))
}

fn php_time_sleep_until(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_set_time_limit(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_ignore_user_abort(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

// -- Error handling --

fn php_trigger_error(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let msg = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let level = args.get(1).cloned().unwrap_or(Value::Long(256)).to_long();
    // Only E_USER_* levels are allowed
    match level {
        256 => {
            // E_USER_ERROR — fatal
            vm.emit_error(level, &msg)?;
            return Err(VmError::FatalError(msg));
        }
        512 | 1024 | 16384 => {
            // E_USER_WARNING, E_USER_NOTICE, E_USER_DEPRECATED
            vm.emit_error(level, &msg)?;
        }
        _ => {
            // Invalid error type — emit warning about that
            vm.emit_error(2, &format!("trigger_error(): Invalid error type specified"))?;
            return Ok(Value::Bool(false));
        }
    }
    Ok(Value::Bool(true))
}

fn php_error_reporting(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let old_level = vm.error_reporting_level;
    if let Some(level_arg) = args.first() {
        vm.error_reporting_level = level_arg.to_long();
    }
    Ok(Value::Long(old_level))
}

fn php_set_error_handler(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let prev = vm
        .error_handler
        .clone()
        .map(|s| Value::String(s))
        .unwrap_or(Value::Null);
    // Push current handler onto stack before replacing
    vm.error_handler_stack.push(vm.error_handler.take());
    if let Some(cb) = args.first() {
        if cb.is_null() {
            vm.error_handler = None;
        } else {
            let name = Vm::extract_closure_name(cb);
            if !name.is_empty() {
                vm.error_handler = Some(name);
            }
        }
    }
    Ok(prev)
}

fn php_restore_error_handler(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // Pop previous handler from stack
    vm.error_handler = vm.error_handler_stack.pop().flatten();
    Ok(Value::Bool(true))
}

fn php_set_exception_handler(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let prev = vm
        .exception_handler
        .clone()
        .map(|s| Value::String(s))
        .unwrap_or(Value::Null);
    // Push current handler onto stack before replacing
    vm.exception_handler_stack.push(vm.exception_handler.take());
    if let Some(cb) = args.first() {
        if cb.is_null() {
            vm.exception_handler = None;
        } else {
            let name = Vm::extract_closure_name(cb);
            if !name.is_empty() {
                vm.exception_handler = Some(name);
            }
        }
    }
    Ok(prev)
}

fn php_restore_exception_handler(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // Pop previous handler from stack
    vm.exception_handler = vm.exception_handler_stack.pop().flatten();
    Ok(Value::Bool(true))
}

fn php_error_log(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let msg = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let message_type = args.get(1).map(|v| v.to_long()).unwrap_or(0);
    let destination = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();

    match message_type {
        0 => {
            // Type 0: Send to PHP's system logger (error_log INI or stderr)
            if let Some(ref log_path) = vm.error_log_path {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log_path)
                    {
                        let _ = writeln!(f, "{}", msg);
                        return Ok(Value::Bool(true));
                    }
                    return Ok(Value::Bool(false));
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = log_path;
                    return Ok(Value::Bool(false));
                }
            }
            eprintln!("{}", msg);
            Ok(Value::Bool(true))
        }
        3 => {
            // Type 3: Append to file specified in destination
            #[cfg(not(target_arch = "wasm32"))]
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&destination)
                {
                    let _ = write!(f, "{}", msg);
                    return Ok(Value::Bool(true));
                }
                Ok(Value::Bool(false))
            }
            #[cfg(target_arch = "wasm32")]
            Ok(Value::Bool(false))
        }
        4 => {
            // Type 4: SAPI logging handler
            eprintln!("{}", msg);
            Ok(Value::Bool(true))
        }
        _ => {
            eprintln!("{}", msg);
            Ok(Value::Bool(true))
        }
    }
}

fn php_error_clear_last(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

fn php_get_error_handler(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

// -- Function handling --

fn php_call_user_func(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let callable = args.first().cloned().unwrap_or(Value::Null);
    let func_args: Vec<Value> = args.get(1..).unwrap_or(&[]).to_vec();

    // Handle array callables: [$obj, "method"] or ["ClassName", "method"]
    if let Value::Array(ref arr) = callable {
        let entries = arr.entries();
        if entries.len() == 2 {
            let method_name = entries[1].1.to_php_string();
            match &entries[0].1 {
                Value::Object(obj) => {
                    let class_name = obj.class_name().to_string();
                    let full_name = format!("{}::{}", class_name, method_name);
                    let mut full_args = vec![Value::Object(obj.clone())];
                    full_args.extend(func_args);
                    return vm.invoke_user_callback(&full_name, full_args);
                }
                Value::String(class_name) => {
                    let full_name = format!("{}::{}", class_name, method_name);
                    return vm.invoke_user_callback(&full_name, func_args);
                }
                _ => {}
            }
        }
    }

    let func_name = Vm::extract_closure_name(&callable);
    vm.invoke_user_callback(&func_name, func_args)
}

fn php_call_user_func_array(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let callable = args.first().cloned().unwrap_or(Value::Null);
    let arr = args.get(1).cloned().unwrap_or(Value::Null);
    let func_args: Vec<Value> = if let Value::Array(ref a) = arr {
        a.entries().iter().map(|(_, v)| v.clone()).collect()
    } else {
        vec![]
    };

    // Handle array callables: [$obj, "method"] or ["ClassName", "method"]
    if let Value::Array(ref callable_arr) = callable {
        let entries = callable_arr.entries();
        if entries.len() == 2 {
            let method_name = entries[1].1.to_php_string();
            match &entries[0].1 {
                Value::Object(obj) => {
                    let class_name = obj.class_name().to_string();
                    let full_name = format!("{}::{}", class_name, method_name);
                    let mut full_args = vec![Value::Object(obj.clone())];
                    full_args.extend(func_args);
                    return vm.invoke_user_callback(&full_name, full_args);
                }
                Value::String(class_name) => {
                    let full_name = format!("{}::{}", class_name, method_name);
                    return vm.invoke_user_callback(&full_name, func_args);
                }
                _ => {}
            }
        }
    }

    let func_name = Vm::extract_closure_name(&callable);
    vm.invoke_user_callback(&func_name, func_args)
}

fn php_register_shutdown_function(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let func_name = Vm::extract_closure_name(&args.first().cloned().unwrap_or(Value::Null));
    if !func_name.is_empty() {
        vm.shutdown_functions.push(func_name);
    }
    Ok(Value::Null)
}

fn php_register_tick_function(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let func_name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    if !func_name.is_empty() && !vm.tick_functions.contains(&func_name) {
        vm.tick_functions.push(func_name);
    }
    Ok(Value::Bool(true))
}

fn php_unregister_tick_function(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let func_name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    vm.tick_functions.retain(|f| f != &func_name);
    Ok(Value::Null)
}

fn php_forward_static_call(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_func_get_args(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    if let Some(frame) = vm.call_stack.last() {
        for arg in &frame.args {
            arr.push(arg.clone());
        }
    }
    Ok(Value::Array(arr))
}

fn php_func_get_arg(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let idx = args.first().cloned().unwrap_or(Value::Long(0)).to_long() as usize;
    if let Some(frame) = vm.call_stack.last() {
        match frame.args.get(idx) {
            Some(v) => Ok(v.clone()),
            None => Ok(Value::Bool(false)),
        }
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_func_num_args(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(frame) = vm.call_stack.last() {
        Ok(Value::Long(frame.args.len() as i64))
    } else {
        Ok(Value::Long(-1))
    }
}

fn php_function_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let fname = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let exists = if vm.functions.contains_key(&fname) {
        true
    } else {
        match vm.call_builtin(&fname, &[], &[], &[]) {
            Ok(None) => false,
            _ => true,
        }
    };
    Ok(Value::Bool(exists))
}

fn php_is_callable(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let is_callable = match &v {
        Value::Object(o) if o.class_name() == "Closure" => true,
        Value::String(ref s) => vm.functions.contains_key(s),
        Value::Array(ref a) => a.entries().len() == 2,
        _ => false,
    };
    Ok(Value::Bool(is_callable))
}

// -- Variable handling --

fn php_serialize(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let val = args.first().cloned().unwrap_or(Value::Null);
    // For objects, try __serialize() first, then __sleep()
    if let Value::Object(ref o) = val {
        let class_name = o.class_name();
        // PHP 7.4+: __serialize() returns an array of data to serialize
        if let Some(method_name) = vm.find_magic_method(&class_name, "__serialize") {
            let result = vm.call_magic_method(&method_name, val.clone(), vec![])?;
            if let Value::Array(ref arr) = result {
                use php_rs_ext_standard::variables::SerializableValue as SV;
                let entries: Vec<_> = arr
                    .entries()
                    .iter()
                    .map(|(k, v)| {
                        let key = match k {
                            ArrayKey::Int(n) => SV::Int(*n),
                            ArrayKey::String(s) => SV::Str(s.clone()),
                        };
                        (key, value_to_serializable(v))
                    })
                    .collect();
                let sv = SV::Object(class_name.to_string(), entries);
                return Ok(Value::String(
                    php_rs_ext_standard::variables::php_serialize(&sv),
                ));
            }
        }
        // Serializable interface: call serialize() method
        if vm.implements_interface(&class_name, "Serializable") {
            if let Some(method_name) = vm.find_magic_method(&class_name, "serialize") {
                let result = vm.call_magic_method(&method_name, val.clone(), vec![])?;
                let serialized = result.to_php_string();
                // PHP wraps Serializable output: C:ClassName:length:{data}
                let output = format!(
                    "C:{}:\"{}\":{}:{{{}}}",
                    class_name.len(),
                    class_name,
                    serialized.len(),
                    serialized
                );
                return Ok(Value::String(output));
            }
        }
        // Legacy: __sleep() returns array of property names to serialize
        if let Some(method_name) = vm.find_magic_method(&class_name, "__sleep") {
            let result = vm.call_magic_method(&method_name, val.clone(), vec![])?;
            if let Value::Array(ref arr) = result {
                use php_rs_ext_standard::variables::SerializableValue as SV;
                let mut props = Vec::new();
                for (_, prop_name_val) in arr.entries() {
                    let prop_name = prop_name_val.to_php_string();
                    let prop_val = o.get_property(&prop_name).unwrap_or(Value::Null);
                    props.push((SV::Str(prop_name), value_to_serializable(&prop_val)));
                }
                let sv = SV::Object(class_name.to_string(), props);
                return Ok(Value::String(
                    php_rs_ext_standard::variables::php_serialize(&sv),
                ));
            }
        }
    }
    Ok(Value::String(
        php_rs_ext_standard::variables::php_serialize(&value_to_serializable(&val)),
    ))
}

fn php_unserialize(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    match php_rs_ext_standard::variables::php_unserialize(&s) {
        Some(sv) => {
            let val = serializable_to_value(&sv);
            // For objects, try __unserialize() first, then __wakeup()
            if let Value::Object(ref o) = val {
                let class_name = o.class_name();
                // PHP 7.4+: __unserialize(array $data) — reconstruct from serialized data
                if let Some(method_name) = vm.find_magic_method(&class_name, "__unserialize") {
                    // Build an array from the object properties
                    let mut arr = PhpArray::new();
                    for (k, v) in o.properties().iter() {
                        arr.set(&Value::String(k.clone()), v.clone());
                    }
                    let _ =
                        vm.call_magic_method(&method_name, val.clone(), vec![Value::Array(arr)]);
                    return Ok(val);
                }
                // Legacy: __wakeup() — called after unserialize
                if let Some(method_name) = vm.find_magic_method(&class_name, "__wakeup") {
                    let _ = vm.call_magic_method(&method_name, val.clone(), vec![]);
                }
            }
            Ok(val)
        }
        None => Ok(Value::Bool(false)),
    }
}

fn php_compact(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_extract(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_isset(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(!v.is_null()))
}

fn php_empty(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(!v.to_bool()))
}

fn php_var_export(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let val = args.first().cloned().unwrap_or(Value::Null);
    let ret = args.get(1).is_some_and(|v| v.to_bool());
    let s = vm.var_export_string(&val);
    if ret {
        Ok(Value::String(s))
    } else {
        vm.write_output(&s);
        Ok(Value::Null)
    }
}

fn php_debug_zval_dump(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    for arg in args {
        debug_zval_dump_value(vm, arg, 0);
    }
    Ok(Value::Null)
}

fn debug_zval_dump_value(vm: &mut Vm, val: &Value, depth: usize) {
    let indent = "  ".repeat(depth);
    match val {
        Value::Null => vm.write_output(&format!("{}NULL refcount(1)\n", indent)),
        Value::Bool(true) => vm.write_output(&format!("{}bool(true) refcount(1)\n", indent)),
        Value::Bool(false) => vm.write_output(&format!("{}bool(false) refcount(1)\n", indent)),
        Value::Long(n) => vm.write_output(&format!("{}int({}) refcount(1)\n", indent, n)),
        Value::Double(f) => {
            let s = if f.fract() == 0.0 && f.is_finite() {
                format!("{:.0}", f)
            } else {
                format!("{}", f)
            };
            vm.write_output(&format!("{}float({}) refcount(1)\n", indent, s));
        }
        Value::String(s) => {
            vm.write_output(&format!(
                "{}string({}) \"{}\" refcount({})\n",
                indent,
                s.len(),
                s,
                1 // Rust strings are value types; refcount is always 1 at call site
            ));
        }
        Value::Array(arr) => {
            vm.write_output(&format!(
                "{}array({}) refcount({}){{\n",
                indent,
                arr.len(),
                2
            ));
            for (key, v) in arr.entries() {
                let key_str = match key {
                    crate::value::ArrayKey::Int(n) => format!("[{}]=>", n),
                    crate::value::ArrayKey::String(s) => format!("[\"{}\"]=>", s),
                };
                vm.write_output(&format!("  {}{}\n", indent, key_str));
                debug_zval_dump_value(vm, v, depth + 1);
            }
            vm.write_output(&format!("{}}}\n", indent));
        }
        Value::Reference(r) => {
            let inner = r.borrow();
            vm.write_output(&format!("{}reference refcount(2) {{\n", indent));
            debug_zval_dump_value(vm, &inner, depth + 1);
            vm.write_output(&format!("{}}}\n", indent));
        }
        _ => {
            // Fallback to var_dump for objects/resources
            vm.var_dump(val, depth);
        }
    }
}

// -- INI --

fn php_ini_get(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    // Special handling for error_reporting/error_log which are also VM fields
    match name.as_str() {
        "error_log" => Ok(Value::String(vm.error_log_path.clone().unwrap_or_default())),
        "error_reporting" => Ok(Value::String(vm.error_reporting_level.to_string())),
        _ => {
            let val = vm.ini.get(&name);
            if val.is_empty() && vm.ini.get_entry(&name).is_none() {
                Ok(Value::Bool(false))
            } else {
                Ok(Value::String(val.to_string()))
            }
        }
    }
}

fn php_ini_set(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let new_val = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    // Special handling for error_reporting/error_log
    match name.as_str() {
        "error_log" => {
            let old = vm.error_log_path.clone().unwrap_or_default();
            if new_val.is_empty() {
                vm.error_log_path = None;
            } else {
                vm.error_log_path = Some(new_val.clone());
            }
            vm.ini.force_set(&name, &new_val);
            Ok(Value::String(old))
        }
        "error_reporting" => {
            let old = vm.error_reporting_level;
            vm.error_reporting_level = new_val.parse::<i64>().unwrap_or(0);
            vm.ini.force_set(&name, &new_val);
            Ok(Value::String(old.to_string()))
        }
        _ => match vm.ini.set(&name, &new_val) {
            Some(old) => Ok(Value::String(old)),
            None => Ok(Value::Bool(false)),
        },
    }
}

fn php_ini_restore(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    vm.ini.restore(&name);
    Ok(Value::Null)
}

fn php_ini_get_all(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let extension = args.first().map(|v| v.to_php_string());
    let details = args.get(1).map(|v| v.to_bool()).unwrap_or(true);
    let mut result = PhpArray::new();
    for name in vm.ini.directives() {
        // Filter by extension prefix if specified
        if let Some(ref ext) = extension {
            if !ext.is_empty() && !name.starts_with(ext.as_str()) {
                continue;
            }
        }
        if let Some(entry) = vm.ini.get_entry(name) {
            if details {
                let mut info = PhpArray::new();
                info.set_string(
                    "global_value".into(),
                    Value::String(entry.default_value.clone()),
                );
                info.set_string("local_value".into(), Value::String(entry.value.clone()));
                info.set_string("access".into(), Value::Long(entry.permission as i64));
                result.set_string(name.to_string(), Value::Array(info));
            } else {
                result.set_string(name.to_string(), Value::String(entry.value.clone()));
            }
        }
    }
    Ok(Value::Array(result))
}

fn php_get_cfg_var(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_php_ini_loaded_file(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_parse_ini_file(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let filename = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let process_sections = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
    if let Ok(content) = vm.vm_read_to_string(&filename) {
        Ok(Value::Array(parse_ini_to_array(&content, process_sections)))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_parse_ini_string(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let process_sections = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
    Ok(Value::Array(parse_ini_to_array(&s, process_sections)))
}

fn php_ini_parse_quantity(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let s = s.trim();
    let (num_part, suffix) = if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024i64)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024i64)
    } else if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len() - 1], 1024i64)
    } else {
        (s, 1i64)
    };
    let n: i64 = num_part.parse().unwrap_or(0);
    Ok(Value::Long(n * suffix))
}

// -- Misc standard --

fn php_phpinfo(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    vm.write_output("phpinfo()\nPHP Version => php-rs 0.1.0\n");
    Ok(Value::Bool(true))
}

fn php_phpcredits(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    vm.write_output("php-rs credits\n");
    Ok(Value::Bool(true))
}

fn php_phpversion(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("8.6.0-php.rs".to_string()))
}

fn php_php_uname(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let m = args
        .first()
        .cloned()
        .unwrap_or(Value::String("a".to_string()))
        .to_php_string();
    Ok(Value::String(php_rs_ext_standard::misc::php_uname(
        m.chars().next().unwrap_or('a'),
    )))
}

fn php_php_sapi_name(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("cli".to_string()))
}

fn php_getenv(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.is_empty() {
        // getenv() with no args returns all environment variables as an array
        let mut arr = crate::value::PhpArray::new();
        for (key, value) in std::env::vars() {
            arr.set_string(key, Value::String(value));
        }
        return Ok(Value::Array(arr));
    }
    let n = args[0].to_php_string();
    let local_only = args.get(1).map(|v| v.to_bool()).unwrap_or(false);

    // Check $_ENV superglobal first (in the main frame) unless local_only
    if !local_only {
        if let Some(main_frame) = vm.call_stack.first() {
            if let Some(oa) = vm.op_arrays.first() {
                if let Some(env_idx) = oa.vars.iter().position(|v| v == "_ENV") {
                    if env_idx < main_frame.cvs.len() {
                        if let Value::Array(ref env_arr) = main_frame.cvs[env_idx] {
                            if let Some(val) = env_arr.get_string(&n) {
                                return Ok(val.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Fall back to real environment
    match std::env::var(&n) {
        Ok(v) => Ok(Value::String(v)),
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn php_putenv(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    if let Some(eq) = s.find('=') {
        let key = &s[..eq];
        let value = &s[eq + 1..];
        // Update real environment
        #[allow(deprecated)]
        std::env::set_var(key, value);
        // Sync to $_ENV in the main frame (first frame, not current)
        if let Some(main_frame) = vm.call_stack.first_mut() {
            if let Some(oa) = vm.op_arrays.first() {
                if let Some(env_idx) = oa.vars.iter().position(|v| v == "_ENV") {
                    if env_idx < main_frame.cvs.len() {
                        if let Value::Array(ref mut env_arr) = main_frame.cvs[env_idx] {
                            env_arr.set_string(key.to_string(), Value::String(value.to_string()));
                        }
                    }
                }
            }
        }
    }
    Ok(Value::Bool(true))
}

fn php_constant(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    match vm.constants.get(&name) {
        Some(v) => Ok(v.clone()),
        None => Err(VmError::FatalError(format!(
            "Undefined constant \"{}\"",
            name
        ))),
    }
}

fn php_defined(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::Bool(vm.constants.contains_key(&name)))
}

fn php_define(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let value = args.get(1).cloned().unwrap_or(Value::Null);
    vm.constants.insert(name, value);
    Ok(Value::Bool(true))
}

fn php_get_defined_constants(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for (name, val) in &vm.constants {
        arr.set_string(name.clone(), val.clone());
    }
    Ok(Value::Array(arr))
}

fn php_get_defined_vars(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    if let Some(frame) = vm.call_stack.last() {
        let oa_idx = frame.op_array_idx;
        if oa_idx < vm.op_arrays.len() {
            let vars = &vm.op_arrays[oa_idx].vars;
            for (i, vname) in vars.iter().enumerate() {
                if i < frame.cvs.len() {
                    arr.set_string(vname.clone(), frame.cvs[i].clone());
                }
            }
        }
    }
    Ok(Value::Array(arr))
}

fn php_get_defined_functions(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let internal = PhpArray::new();
    let mut user = PhpArray::new();
    for name in vm.functions.keys() {
        user.push(Value::String(name.clone()));
    }
    let mut result = PhpArray::new();
    result.set_string("internal".to_string(), Value::Array(internal));
    result.set_string("user".to_string(), Value::Array(user));
    Ok(Value::Array(result))
}

fn php_time(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(Value::Long(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64,
    ))
}

fn php_microtime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if args.first().map(|v| v.to_bool()).unwrap_or(false) {
        Ok(Value::Double(now.as_secs_f64()))
    } else {
        Ok(Value::String(format!(
            "0.{:06}00 {}",
            now.subsec_micros(),
            now.as_secs()
        )))
    }
}

fn php_uniqid(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use std::time::SystemTime;
    let prefix = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let id = format!(
        "{}{:08x}{:05x}",
        prefix,
        dur.as_secs() as u32,
        dur.subsec_micros()
    );
    Ok(Value::String(id))
}

fn php_version_compare(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v1 = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let v2 = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let op = args.get(2).map(|v| v.to_php_string());
    let cmp = crate::vm::version_cmp(&v1, &v2);
    match op {
        None => Ok(Value::Long(if cmp < 0 {
            -1
        } else if cmp > 0 {
            1
        } else {
            0
        })),
        Some(op) => {
            let result = match op.as_str() {
                "<" | "lt" => cmp < 0,
                "<=" | "le" => cmp <= 0,
                ">" | "gt" => cmp > 0,
                ">=" | "ge" => cmp >= 0,
                "==" | "eq" => cmp == 0,
                "!=" | "ne" => cmp != 0,
                _ => false,
            };
            Ok(Value::Bool(result))
        }
    }
}

fn php_assert(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let val = args.first().map(|v| v.to_bool()).unwrap_or(true);
    if !val {
        vm.write_output("Warning: assert(): Assertion failed\n");
    }
    Ok(Value::Bool(val))
}

fn php_assert_options(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(1))
}

// -- Headers / HTTP --

fn php_header(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(header_str) = args.first() {
        let h = header_str.to_php_string();
        let replace = args.get(1).map(|v| v.is_truthy()).unwrap_or(true);
        if let Some(code_val) = args.get(2) {
            let code = code_val.to_long() as u16;
            if code > 0 {
                vm.response_code = Some(code);
            }
        }
        if let Some(colon_pos) = h.find(':') {
            let name = h[..colon_pos].trim().to_lowercase();
            if replace {
                vm.response_headers.retain(|existing| {
                    if let Some(ecp) = existing.find(':') {
                        existing[..ecp].trim().to_lowercase() != name
                    } else {
                        true
                    }
                });
            }
            vm.response_headers.push(h);
        } else if h.starts_with("HTTP/") {
            if let Some(code) = h.split_whitespace().nth(1) {
                if let Ok(c) = str::parse::<u16>(code) {
                    vm.response_code = Some(c);
                }
            }
        }
    }
    Ok(Value::Null)
}

fn php_header_remove(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(name_val) = args.first() {
        let name = name_val.to_php_string().to_lowercase();
        vm.response_headers.retain(|existing| {
            if let Some(cp) = existing.find(':') {
                existing[..cp].trim().to_lowercase() != name
            } else {
                true
            }
        });
    } else {
        vm.response_headers.clear();
    }
    Ok(Value::Null)
}

fn php_headers_sent(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_http_response_code(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let code = args.first().map(|v| v.to_long() as u16);
    match code {
        Some(c) if c > 0 => {
            vm.response_code = Some(c);
            Ok(Value::Long(c as i64))
        }
        _ => Ok(Value::Long(200)),
    }
}

fn php_header_register_callback(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_headers_list(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_setcookie(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_http_clear_last_response_headers(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

fn php_http_get_last_response_headers(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

// -- Class / Object introspection --

fn php_class_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let autoload = args.get(1).map(|v| v.to_bool()).unwrap_or(true);
    let exists = if vm.classes.contains_key(&name) {
        true
    } else if autoload {
        vm.try_autoload_class(&name);
        vm.classes.contains_key(&name)
    } else {
        false
    };
    Ok(Value::Bool(exists))
}

fn php_method_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let obj_or_class = args.first().cloned().unwrap_or(Value::Null);
    let method = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    let class_name = match obj_or_class {
        Value::Object(ref o) => o.class_name(),
        Value::String(s) => s,
        _ => String::new(),
    };
    let exists = vm
        .classes
        .get(&class_name)
        .is_some_and(|c| c.methods.contains_key(&method));
    Ok(Value::Bool(exists))
}

fn php_property_exists(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let obj = args.first().cloned().unwrap_or(Value::Null);
    let prop = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    let exists = match obj {
        Value::Object(ref o) => o.has_property(&prop),
        _ => false,
    };
    Ok(Value::Bool(exists))
}

fn php_get_parent_class(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let cn = match &v {
        Value::Object(o) => o.class_name(),
        Value::String(s) => s.clone(),
        _ => return Ok(Value::Bool(false)),
    };
    match vm.classes.get(&cn).and_then(|c| c.parent.clone()) {
        Some(p) => Ok(Value::String(p)),
        None => Ok(Value::Bool(false)),
    }
}

fn php_is_a(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let obj = args.first().cloned().unwrap_or(Value::Null);
    let target = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    let cn = match &obj {
        Value::Object(o) => o.class_name(),
        Value::String(s) => s.clone(),
        _ => return Ok(Value::Bool(false)),
    };
    if cn.eq_ignore_ascii_case(&target) {
        return Ok(Value::Bool(true));
    }
    let mut cur = cn;
    loop {
        match vm.classes.get(&cur).and_then(|c| c.parent.clone()) {
            Some(p) if p.eq_ignore_ascii_case(&target) => return Ok(Value::Bool(true)),
            Some(p) => cur = p,
            None => break,
        }
    }
    Ok(Value::Bool(false))
}

fn php_is_subclass_of(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let obj = args.first().cloned().unwrap_or(Value::Null);
    let target = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    let cn = match &obj {
        Value::Object(o) => o.class_name(),
        Value::String(s) => s.clone(),
        _ => return Ok(Value::Bool(false)),
    };
    if cn.eq_ignore_ascii_case(&target) {
        return Ok(Value::Bool(false));
    }
    let mut cur = cn;
    loop {
        match vm.classes.get(&cur).and_then(|c| c.parent.clone()) {
            Some(p) if p.eq_ignore_ascii_case(&target) => return Ok(Value::Bool(true)),
            Some(p) => cur = p,
            None => break,
        }
    }
    Ok(Value::Bool(false))
}

fn php_get_called_class(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_get_class_methods(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let mut arr = PhpArray::new();
    if let Some(class) = vm.classes.get(&class_name) {
        for name in class.methods.keys() {
            arr.push(Value::String(name.clone()));
        }
    }
    Ok(Value::Array(arr))
}

fn php_get_class_vars(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let mut arr = PhpArray::new();
    if let Some(class) = vm.classes.get(&class_name) {
        for (name, val) in &class.default_properties {
            arr.set_string(name.clone(), val.clone());
        }
    }
    Ok(Value::Array(arr))
}

fn php_get_object_vars(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let obj = args.first().cloned().unwrap_or(Value::Null);
    let mut arr = PhpArray::new();
    if let Value::Object(ref o) = obj {
        for (name, val) in &o.properties() {
            arr.set_string(name.clone(), val.clone());
        }
    }
    Ok(Value::Array(arr))
}

fn php_interface_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::Bool(vm.classes.contains_key(&name)))
}

fn php_class_alias(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let original = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let alias = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    if let Some(class) = vm.classes.get(&original).cloned() {
        vm.classes.insert(alias, class);
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_extension_loaded(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let loaded = matches!(
        name.as_str(),
        "standard" | "Core" | "json" | "pcre" | "date" | "ctype" | "mbstring" | "SPL"
    );
    Ok(Value::Bool(loaded))
}

fn php_enum_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(
        vm.classes.contains_key(&name) || vm.classes.contains_key(&name.to_lowercase()),
    ))
}

fn php_get_declared_classes(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for name in vm.classes.keys() {
        arr.push(Value::String(name.clone()));
    }
    Ok(Value::Array(arr))
}

fn php_get_declared_interfaces(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_get_declared_traits(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_trait_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let exists = vm.classes.contains_key(&name.to_lowercase());
    Ok(Value::Bool(exists))
}

fn php_settype(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_get_included_files(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for oa in &vm.op_arrays {
        if let Some(ref f) = oa.filename {
            if !f.is_empty() {
                arr.push(Value::String(f.clone()));
            }
        }
    }
    Ok(Value::Array(arr))
}

fn php_get_loaded_extensions(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for ext in &[
        "Core",
        "standard",
        "json",
        "pcre",
        "ctype",
        "filter",
        "hash",
        "mbstring",
        "date",
        "spl",
        "random",
        "bcmath",
        "session",
        "tokenizer",
        "Reflection",
    ] {
        arr.push(Value::String(ext.to_string()));
    }
    Ok(Value::Array(arr))
}

fn php_get_extension_funcs(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_get_mangled_object_vars(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(obj)) = args.first() {
        let mut arr = PhpArray::new();
        for (k, v) in &obj.properties() {
            arr.set_string(k.clone(), v.clone());
        }
        Ok(Value::Array(arr))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

fn php_get_resource_id(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let val = args.first().unwrap_or(&Value::Null);
    Ok(Value::Long(val.resource_id()))
}

fn php_get_resource_type(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let val = args.first().unwrap_or(&Value::Null);
    let rtype = match val {
        Value::Resource(_, ref t) => t.clone(),
        _ => "Unknown".to_string(),
    };
    Ok(Value::String(rtype))
}

fn php_get_resources(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_clone(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(args.first().cloned().unwrap_or(Value::Null))
}

// -- Debug / Backtrace --

fn php_debug_backtrace(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for frame in vm.call_stack.iter().rev() {
        let mut entry = PhpArray::new();
        let oa = &vm.op_arrays[frame.op_array_idx];
        entry.set_string(
            "function".into(),
            Value::String(oa.function_name.clone().unwrap_or_default()),
        );
        entry.set_string(
            "file".into(),
            Value::String(oa.filename.clone().unwrap_or_default()),
        );
        entry.set_string("line".into(), Value::Long(0));
        let mut fargs = PhpArray::new();
        for arg in &frame.args {
            fargs.push(arg.clone());
        }
        entry.set_string("args".into(), Value::Array(fargs));
        arr.push(Value::Array(entry));
    }
    Ok(Value::Array(arr))
}

fn php_debug_print_backtrace(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let lines: Vec<String> = vm
        .call_stack
        .iter()
        .rev()
        .enumerate()
        .map(|(i, frame)| {
            let oa = &vm.op_arrays[frame.op_array_idx];
            let fname = oa.function_name.as_deref().unwrap_or("<main>");
            format!("#{} {}()\n", i, fname)
        })
        .collect();
    for line in lines {
        vm.write_output(&line);
    }
    Ok(Value::Null)
}

// -- GC --

fn php_gc_collect_cycles(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_gc_enabled(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_gc_enable(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

fn php_gc_mem_caches(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_gc_status(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string("runs".into(), Value::Long(0));
    arr.set_string("collected".into(), Value::Long(0));
    arr.set_string("threshold".into(), Value::Long(10000));
    arr.set_string("roots".into(), Value::Long(0));
    Ok(Value::Array(arr))
}

// -- Zend --

fn php_zend_version(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("4.0.0-php-rs".into()))
}

fn php_zend_thread_id(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(1))
}

// -- Memory --

fn php_memory_get_usage(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_memory_reset_peak_usage(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

// -- Process --

fn php_getmypid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(std::process::id() as i64))
}

fn php_getmyuid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_get_current_user(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(
        std::env::var("USER").unwrap_or_else(|_| "nobody".into()),
    ))
}

fn php_gethostname(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("localhost".into()))
}

fn php_gettimeofday(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let return_float = args.first().map(|v| v.to_bool()).unwrap_or(false);
    if return_float {
        Ok(Value::Double(dur.as_secs_f64()))
    } else {
        let mut arr = PhpArray::new();
        arr.set_string("sec".into(), Value::Long(dur.as_secs() as i64));
        arr.set_string("usec".into(), Value::Long(dur.subsec_micros() as i64));
        arr.set_string("minuteswest".into(), Value::Long(0));
        arr.set_string("dsttime".into(), Value::Long(0));
        Ok(Value::Array(arr))
    }
}

fn php_hrtime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let as_number = args.first().map(|v| v.to_bool()).unwrap_or(false);
    if as_number {
        Ok(Value::Long(dur.as_nanos() as i64))
    } else {
        let mut arr = PhpArray::new();
        arr.push(Value::Long(dur.as_secs() as i64));
        arr.push(Value::Long(dur.subsec_nanos() as i64));
        Ok(Value::Array(arr))
    }
}

fn php_sys_getloadavg(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.push(Value::Double(0.0));
    arr.push(Value::Double(0.0));
    arr.push(Value::Double(0.0));
    Ok(Value::Array(arr))
}

fn php_getrusage(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string("ru_utime.tv_sec".into(), Value::Long(0));
    arr.set_string("ru_utime.tv_usec".into(), Value::Long(0));
    arr.set_string("ru_stime.tv_sec".into(), Value::Long(0));
    arr.set_string("ru_stime.tv_usec".into(), Value::Long(0));
    Ok(Value::Array(arr))
}

// -- Locale --

fn php_setlocale(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // setlocale(int $category, string $locales, string ...$rest): string|false
    // We always operate in the "C" locale but accept the call gracefully.
    let _category = args.first().map(|v| v.to_long()).unwrap_or(0);
    let locale = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();

    // Accept "C", "POSIX", "", or "0" — return "C"; anything else returns false
    match locale.as_str() {
        "" | "C" | "POSIX" | "0" => Ok(Value::String("C".into())),
        _ => {
            // We could try to "accept" locale names that match C locale conventions
            if locale.starts_with("en_") || locale == "C.UTF-8" || locale == "POSIX" {
                Ok(Value::String(locale))
            } else {
                // In a real implementation this would attempt to set the system locale.
                // For now, return the locale name (PHP returns it on success).
                Ok(Value::String(locale))
            }
        }
    }
}

fn php_localeconv(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // Returns an associative array with all locale numeric formatting information.
    // These values match the "C" / POSIX locale.
    let mut arr = PhpArray::new();
    arr.set_string("decimal_point".into(), Value::String(".".into()));
    arr.set_string("thousands_sep".into(), Value::String(String::new()));
    arr.set_string("int_curr_symbol".into(), Value::String(String::new()));
    arr.set_string("currency_symbol".into(), Value::String(String::new()));
    arr.set_string("mon_decimal_point".into(), Value::String(String::new()));
    arr.set_string("mon_thousands_sep".into(), Value::String(String::new()));
    arr.set_string("positive_sign".into(), Value::String(String::new()));
    arr.set_string("negative_sign".into(), Value::String(String::new()));
    arr.set_string("int_frac_digits".into(), Value::Long(127)); // CHAR_MAX
    arr.set_string("frac_digits".into(), Value::Long(127));
    arr.set_string("p_cs_precedes".into(), Value::Long(127));
    arr.set_string("p_sep_by_space".into(), Value::Long(127));
    arr.set_string("n_cs_precedes".into(), Value::Long(127));
    arr.set_string("n_sep_by_space".into(), Value::Long(127));
    arr.set_string("p_sign_posn".into(), Value::Long(127));
    arr.set_string("n_sign_posn".into(), Value::Long(127));
    // grouping is an array of grouping sizes (empty for C locale)
    arr.set_string("grouping".into(), Value::Array(PhpArray::new()));
    arr.set_string("mon_grouping".into(), Value::Array(PhpArray::new()));
    Ok(Value::Array(arr))
}

// -- Network --

fn php_ip2long(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ip = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        let a = parts[0].parse::<u32>().unwrap_or(0);
        let b = parts[1].parse::<u32>().unwrap_or(0);
        let c = parts[2].parse::<u32>().unwrap_or(0);
        let d = parts[3].parse::<u32>().unwrap_or(0);
        if a <= 255 && b <= 255 && c <= 255 && d <= 255 {
            Ok(Value::Long(((a << 24) | (b << 16) | (c << 8) | d) as i64))
        } else {
            Ok(Value::Bool(false))
        }
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_long2ip(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let n = args.first().map(|v| v.to_long()).unwrap_or(0) as u32;
    Ok(Value::String(format!(
        "{}.{}.{}.{}",
        n >> 24,
        (n >> 16) & 0xFF,
        (n >> 8) & 0xFF,
        n & 0xFF
    )))
}

fn php_inet_ntop(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let bytes = s.as_bytes();
    if bytes.len() == 4 {
        Ok(Value::String(format!(
            "{}.{}.{}.{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_inet_pton(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        let bytes: Vec<u8> = parts.iter().filter_map(|p| p.parse().ok()).collect();
        if bytes.len() == 4 {
            Ok(Value::String(String::from_utf8_lossy(&bytes).to_string()))
        } else {
            Ok(Value::Bool(false))
        }
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_gethostbyname(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let hostname = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    if hostname == "localhost" {
        Ok(Value::String("127.0.0.1".into()))
    } else {
        Ok(Value::String(hostname))
    }
}

fn php_gethostbyaddr(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ip = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    if ip == "127.0.0.1" {
        Ok(Value::String("localhost".into()))
    } else {
        Ok(Value::String(ip))
    }
}

fn php_gethostbynamel(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let hostname = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mut arr = PhpArray::new();
    if hostname == "localhost" {
        arr.push(Value::String("127.0.0.1".into()));
    }
    Ok(Value::Array(arr))
}

fn php_getprotobyname(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let proto = match name.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        _ => -1,
    };
    if proto >= 0 {
        Ok(Value::Long(proto))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_getprotobynumber(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let num = args.first().map(|v| v.to_long()).unwrap_or(-1);
    let name = match num {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "",
    };
    if name.is_empty() {
        Ok(Value::Bool(false))
    } else {
        Ok(Value::String(name.into()))
    }
}

fn php_getservbyname(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let port = match name.as_str() {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        "ssh" => 22,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "dns" => 53,
        _ => 0,
    };
    if port > 0 {
        Ok(Value::Long(port))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_getservbyport(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let port = args.first().map(|v| v.to_long()).unwrap_or(0);
    let name = match port {
        80 => "http",
        443 => "https",
        21 => "ftp",
        22 => "ssh",
        25 => "smtp",
        110 => "pop3",
        143 => "imap",
        53 => "dns",
        _ => "",
    };
    if name.is_empty() {
        Ok(Value::Bool(false))
    } else {
        Ok(Value::String(name.into()))
    }
}

fn php_checkdnsrr(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_dns_get_mx(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_dns_get_record(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_fsockopen(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_set_file_buffer(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// -- Exec --

fn php_exec(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let cmd = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string();
            let last_line = stdout.lines().last().unwrap_or("").to_string();
            Ok(Value::String(last_line))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn php_shell_exec(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let cmd = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
    {
        Ok(output) => Ok(Value::String(
            String::from_utf8_lossy(&output.stdout).to_string(),
        )),
        Err(_) => Ok(Value::Null),
    }
}

fn php_system(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let cmd = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            vm.write_output(&stdout);
            let last_line = stdout.trim_end().lines().last().unwrap_or("").to_string();
            Ok(Value::String(last_line))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn php_passthru(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let cmd = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
    {
        Ok(output) => {
            vm.write_output(&String::from_utf8_lossy(&output.stdout));
            Ok(Value::Null)
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn php_escapeshellarg(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arg = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::String(format!("'{}'", arg.replace('\'', "'\\''"))))
}

fn php_escapeshellcmd(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let cmd = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mut result = String::new();
    for ch in cmd.chars() {
        if "&#;`|*?~<>^()[]{}$\\!".contains(ch) {
            result.push('\\');
        }
        result.push(ch);
    }
    Ok(Value::String(result))
}

fn php_popen(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_pclose(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

/// proc_open($command, $descriptorspec, &$pipes, $cwd, $env, $other_options): resource|false
fn php_proc_open(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let command = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    let descriptor_spec = args.get(1).cloned().unwrap_or(Value::Null);
    let cwd = args.get(3).and_then(|v| {
        if v.is_null() {
            None
        } else {
            Some(v.to_php_string())
        }
    });
    let env = args.get(4).cloned();

    // Build the Command
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(&command);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(&command);
        c
    };

    if let Some(cwd) = &cwd {
        cmd.current_dir(cwd);
    }

    // Set environment variables if provided
    if let Some(Value::Array(env_arr)) = &env {
        cmd.env_clear();
        for (key, val) in env_arr.entries() {
            let key_str = match key {
                crate::value::ArrayKey::Int(i) => i.to_string(),
                crate::value::ArrayKey::String(s) => s.clone(),
            };
            cmd.env(key_str, val.to_php_string());
        }
    }

    // Parse descriptor spec to configure stdin/stdout/stderr
    // Default: pipe all
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // Check descriptor spec for each fd
    if let Value::Array(spec) = &descriptor_spec {
        for (key, val) in spec.entries() {
            let fd = match key {
                crate::value::ArrayKey::Int(i) => *i,
                _ => continue,
            };
            if let Value::Array(desc) = val {
                let desc_type = desc
                    .get_int(0)
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                match desc_type.as_str() {
                    "pipe" => {
                        // Already piped by default
                    }
                    "file" => {
                        let filename = desc
                            .get_int(1)
                            .map(|v| v.to_php_string())
                            .unwrap_or_default();
                        let mode = desc
                            .get_int(2)
                            .map(|v| v.to_php_string())
                            .unwrap_or_else(|| "r".to_string());
                        match fd {
                            0 => {
                                if let Ok(f) = std::fs::File::open(&filename) {
                                    cmd.stdin(f);
                                }
                            }
                            1 => {
                                let f = if mode.contains('a') {
                                    std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&filename)
                                } else {
                                    std::fs::File::create(&filename)
                                };
                                if let Ok(f) = f {
                                    cmd.stdout(f);
                                }
                            }
                            2 => {
                                let f = if mode.contains('a') {
                                    std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&filename)
                                } else {
                                    std::fs::File::create(&filename)
                                };
                                if let Ok(f) = f {
                                    cmd.stderr(f);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    match cmd.spawn() {
        Ok(mut child) => {
            let mut pipes_arr = PhpArray::new();

            // Create pipe file handles for stdin (0), stdout (1), stderr (2)
            if let Some(stdin) = child.stdin.take() {
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                let handle = php_rs_ext_standard::file::FileHandle::from_process_stdin(stdin);
                vm.file_handles.insert(id, handle);
                pipes_arr.set_int(0, Value::Resource(id, "stream".to_string()));
            }

            if let Some(stdout) = child.stdout.take() {
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                let handle = php_rs_ext_standard::file::FileHandle::from_process_stdout(stdout);
                vm.file_handles.insert(id, handle);
                pipes_arr.set_int(1, Value::Resource(id, "stream".to_string()));
            }

            if let Some(stderr) = child.stderr.take() {
                let id = vm.next_resource_id;
                vm.next_resource_id += 1;
                let handle = php_rs_ext_standard::file::FileHandle::from_process_stderr(stderr);
                vm.file_handles.insert(id, handle);
                pipes_arr.set_int(2, Value::Resource(id, "stream".to_string()));
            }

            // Write back $pipes array
            vm.write_back_arg(2, Value::Array(pipes_arr), ref_args, ref_prop_args);

            // Store the child process and return a resource
            let proc_id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.proc_handles.insert(proc_id, child);

            Ok(Value::Resource(proc_id, "process".to_string()))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

/// proc_close($process): int
fn php_proc_close(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let proc_id = args.first().map(|v| v.to_long()).unwrap_or(0);
    if let Some(mut child) = vm.proc_handles.remove(&proc_id) {
        match child.wait() {
            Ok(status) => Ok(Value::Long(status.code().unwrap_or(-1) as i64)),
            Err(_) => Ok(Value::Long(-1)),
        }
    } else {
        Ok(Value::Long(-1))
    }
}

/// proc_get_status($process): array
fn php_proc_get_status(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let proc_id = args.first().map(|v| v.to_long()).unwrap_or(0);
    let mut result = PhpArray::new();

    if let Some(child) = vm.proc_handles.get_mut(&proc_id) {
        // Try a non-blocking wait
        match child.try_wait() {
            Ok(Some(status)) => {
                result.set_string("command".into(), Value::String(String::new()));
                result.set_string("pid".into(), Value::Long(child.id() as i64));
                result.set_string("running".into(), Value::Bool(false));
                result.set_string("signaled".into(), Value::Bool(false));
                result.set_string("stopped".into(), Value::Bool(false));
                result.set_string(
                    "exitcode".into(),
                    Value::Long(status.code().unwrap_or(-1) as i64),
                );
                result.set_string("termsig".into(), Value::Long(0));
                result.set_string("stopsig".into(), Value::Long(0));
            }
            Ok(None) => {
                // Still running
                result.set_string("command".into(), Value::String(String::new()));
                result.set_string("pid".into(), Value::Long(child.id() as i64));
                result.set_string("running".into(), Value::Bool(true));
                result.set_string("signaled".into(), Value::Bool(false));
                result.set_string("stopped".into(), Value::Bool(false));
                result.set_string("exitcode".into(), Value::Long(-1));
                result.set_string("termsig".into(), Value::Long(0));
                result.set_string("stopsig".into(), Value::Long(0));
            }
            Err(_) => {
                result.set_string("running".into(), Value::Bool(false));
                result.set_string("exitcode".into(), Value::Long(-1));
            }
        }
    } else {
        result.set_string("running".into(), Value::Bool(false));
        result.set_string("exitcode".into(), Value::Long(-1));
    }

    Ok(Value::Array(result))
}

/// proc_terminate($process, $signal = 15): bool
fn php_proc_terminate(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let proc_id = args.first().map(|v| v.to_long()).unwrap_or(0);
    if let Some(mut child) = vm.proc_handles.remove(&proc_id) {
        match child.kill() {
            Ok(()) => Ok(Value::Bool(true)),
            Err(_) => Ok(Value::Bool(false)),
        }
    } else {
        Ok(Value::Bool(false))
    }
}

/// proc_nice($increment): bool
fn php_proc_nice(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // proc_nice is platform-specific; return true as best-effort
    Ok(Value::Bool(true))
}

// -- Pack/Unpack --

fn pack_one(result: &mut Vec<u8>, code: char, repeat: usize, args: &[Value], arg_idx: &mut usize) {
    // repeat == usize::MAX means '*' — consume all remaining args
    let count = if repeat == usize::MAX {
        args.len().saturating_sub(*arg_idx)
    } else {
        repeat
    };
    for _ in 0..count {
        let val = args.get(*arg_idx).map(|v| v.to_long()).unwrap_or(0);
        match code {
            'C' => {
                result.push(val as u8);
                *arg_idx += 1;
            }
            'c' => {
                result.push(val as i8 as u8);
                *arg_idx += 1;
            }
            'S' => {
                result.extend_from_slice(&(val as u16).to_ne_bytes());
                *arg_idx += 1;
            }
            's' => {
                result.extend_from_slice(&(val as i16).to_ne_bytes());
                *arg_idx += 1;
            }
            'n' => {
                result.extend_from_slice(&(val as u16).to_be_bytes());
                *arg_idx += 1;
            }
            'v' => {
                result.extend_from_slice(&(val as u16).to_le_bytes());
                *arg_idx += 1;
            }
            'N' => {
                result.extend_from_slice(&(val as u32).to_be_bytes());
                *arg_idx += 1;
            }
            'V' => {
                result.extend_from_slice(&(val as u32).to_le_bytes());
                *arg_idx += 1;
            }
            'J' => {
                result.extend_from_slice(&(val as u64).to_be_bytes());
                *arg_idx += 1;
            }
            'P' => {
                result.extend_from_slice(&(val as u64).to_le_bytes());
                *arg_idx += 1;
            }
            'L' => {
                result.extend_from_slice(&(val as u32).to_ne_bytes());
                *arg_idx += 1;
            }
            'l' => {
                result.extend_from_slice(&(val as i32).to_ne_bytes());
                *arg_idx += 1;
            }
            'Q' => {
                result.extend_from_slice(&(val as u64).to_ne_bytes());
                *arg_idx += 1;
            }
            'q' => {
                result.extend_from_slice(&(val as i64).to_ne_bytes());
                *arg_idx += 1;
            }
            'f' | 'g' => {
                let f = args.get(*arg_idx).map(|v| v.to_double()).unwrap_or(0.0);
                if code == 'g' {
                    result.extend_from_slice(&(f as f32).to_le_bytes());
                } else {
                    result.extend_from_slice(&(f as f32).to_ne_bytes());
                }
                *arg_idx += 1;
            }
            'd' | 'e' | 'E' | 'G' => {
                let f = args.get(*arg_idx).map(|v| v.to_double()).unwrap_or(0.0);
                match code {
                    'e' => result.extend_from_slice(&f.to_le_bytes()),
                    'E' => result.extend_from_slice(&f.to_be_bytes()),
                    _ => result.extend_from_slice(&f.to_ne_bytes()),
                }
                *arg_idx += 1;
            }
            'x' => result.push(0),
            'X' => {
                result.pop();
            }
            'Z' | 'A' | 'a' | 'H' | 'h' => {
                let s = args
                    .get(*arg_idx)
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                match code {
                    'A' => {
                        let bytes = s.as_bytes();
                        if repeat > 0 {
                            let mut buf = vec![b' '; repeat];
                            let len = bytes.len().min(repeat);
                            buf[..len].copy_from_slice(&bytes[..len]);
                            result.extend_from_slice(&buf);
                        } else {
                            result.extend_from_slice(bytes);
                        }
                    }
                    'a' => {
                        let bytes = s.as_bytes();
                        if repeat > 0 {
                            let mut buf = vec![0u8; repeat];
                            let len = bytes.len().min(repeat);
                            buf[..len].copy_from_slice(&bytes[..len]);
                            result.extend_from_slice(&buf);
                        } else {
                            result.extend_from_slice(bytes);
                        }
                    }
                    'Z' => {
                        let bytes = s.as_bytes();
                        if repeat > 0 {
                            let mut buf = vec![0u8; repeat];
                            let len = bytes.len().min(repeat.saturating_sub(1));
                            buf[..len].copy_from_slice(&bytes[..len]);
                            result.extend_from_slice(&buf);
                        } else {
                            result.extend_from_slice(bytes);
                            result.push(0);
                        }
                    }
                    'H' => {
                        // High nibble first hex string
                        let hex = s.as_bytes();
                        let len = if repeat > 0 { repeat } else { hex.len() };
                        for i in (0..len).step_by(2) {
                            let hi = hex.get(i).and_then(|c| hex_nibble(*c)).unwrap_or(0);
                            let lo = hex.get(i + 1).and_then(|c| hex_nibble(*c)).unwrap_or(0);
                            result.push((hi << 4) | lo);
                        }
                    }
                    'h' => {
                        // Low nibble first hex string
                        let hex = s.as_bytes();
                        let len = if repeat > 0 { repeat } else { hex.len() };
                        for i in (0..len).step_by(2) {
                            let lo = hex.get(i).and_then(|c| hex_nibble(*c)).unwrap_or(0);
                            let hi = hex.get(i + 1).and_then(|c| hex_nibble(*c)).unwrap_or(0);
                            result.push((hi << 4) | lo);
                        }
                    }
                    _ => {}
                }
                *arg_idx += 1;
                return; // String formats consume one arg for all repeats
            }
            _ => {}
        }
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse pack format string into (code, repeat_count) pairs.
fn parse_pack_format(format: &str) -> Vec<(char, usize)> {
    let mut result = Vec::new();
    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let code = chars[i];
        i += 1;
        // Parse optional repeat count or '*'
        let mut count_str = String::new();
        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '*') {
            if chars[i] == '*' {
                count_str = "*".to_string();
                i += 1;
                break;
            }
            count_str.push(chars[i]);
            i += 1;
        }
        let count = if count_str == "*" {
            usize::MAX
        } else if count_str.is_empty() {
            1
        } else {
            count_str.parse::<usize>().unwrap_or(1)
        };
        result.push((code, count));
    }
    result
}

/// Parse unpack format string into (code, repeat_count, field_name) tuples.
fn parse_unpack_format(format: &str) -> Vec<(char, usize, String)> {
    let mut result = Vec::new();
    // Split on '/' to get individual format specs
    // But we need to handle the format more carefully:
    // "Nval/nshort" means: N with name "val", then n with name "short"
    let parts: Vec<&str> = format.split('/').collect();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let chars: Vec<char> = part.chars().collect();
        let code = chars[0];
        let mut i = 1;
        // Parse optional repeat count or '*'
        let mut count_str = String::new();
        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '*') {
            if chars[i] == '*' {
                count_str = "*".to_string();
                i += 1;
                break;
            }
            count_str.push(chars[i]);
            i += 1;
        }
        // Rest is field name
        let name: String = chars[i..].iter().collect();
        let count = if count_str == "*" {
            usize::MAX
        } else if count_str.is_empty() {
            1
        } else {
            count_str.parse::<usize>().unwrap_or(1)
        };
        result.push((code, count, name));
    }
    result
}

fn php_pack(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mut result = Vec::new();
    let mut arg_idx = 1;
    let specs = parse_pack_format(&format);
    for (code, repeat) in specs {
        pack_one(&mut result, code, repeat, args, &mut arg_idx);
    }
    // Return as binary string (may contain non-UTF8 bytes)
    Ok(Value::String(
        result.iter().map(|&b| b as char).collect::<String>(),
    ))
}

fn php_unpack(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let data_offset = args.get(2).map(|v| v.to_long() as usize).unwrap_or(0);
    let bytes: Vec<u8> = data.bytes().collect();
    let mut arr = PhpArray::new();
    let mut offset = data_offset;
    let mut field_num = 1i64;

    // Parse format with named fields: "Cchar/nshort/Nlong"
    let fmt_chars: Vec<char> = format.chars().collect();
    let mut i = 0;
    while i < fmt_chars.len() {
        let code = fmt_chars[i];
        i += 1;
        // Parse repeat count
        let mut count_str = String::new();
        while i < fmt_chars.len() && (fmt_chars[i].is_ascii_digit() || fmt_chars[i] == '*') {
            count_str.push(fmt_chars[i]);
            i += 1;
        }
        // Parse optional field name
        let mut field_name = String::new();
        while i < fmt_chars.len() && fmt_chars[i] != '/' {
            field_name.push(fmt_chars[i]);
            i += 1;
        }
        if i < fmt_chars.len() && fmt_chars[i] == '/' {
            i += 1; // skip separator
        }

        let count = if count_str == "*" {
            usize::MAX
        } else {
            count_str.parse::<usize>().unwrap_or(1)
        };

        let size = match code {
            'C' | 'c' => 1,
            'S' | 's' | 'n' | 'v' => 2,
            'N' | 'V' | 'L' | 'l' => 4,
            'J' | 'P' | 'Q' | 'q' => 8,
            'f' | 'g' => 4,
            'd' | 'e' | 'E' | 'G' => 8,
            _ => 1,
        };

        // For string types, count is length
        if matches!(code, 'A' | 'a' | 'Z' | 'H' | 'h') {
            let len = if count == usize::MAX {
                bytes.len().saturating_sub(offset)
            } else {
                count
            };
            let end = (offset + len).min(bytes.len());
            let s: String = bytes[offset..end].iter().map(|&b| b as char).collect();
            let key = if field_name.is_empty() {
                Value::Long(field_num)
            } else {
                Value::String(field_name.clone())
            };
            let val = match code {
                'A' => Value::String(s.trim_end().to_string()),
                'Z' => Value::String(s.split('\0').next().unwrap_or("").to_string()),
                _ => Value::String(s),
            };
            arr.set(&key, val);
            offset = end;
            if field_name.is_empty() {
                field_num += 1;
            }
            continue;
        }

        let actual_count = if count == usize::MAX {
            bytes.len().saturating_sub(offset) / size
        } else {
            count
        };

        for ci in 0..actual_count {
            if offset + size > bytes.len() {
                break;
            }
            let val = match code {
                'C' => Value::Long(bytes[offset] as i64),
                'c' => Value::Long(bytes[offset] as i8 as i64),
                'n' => {
                    let v = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                    Value::Long(v as i64)
                }
                'v' => {
                    let v = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
                    Value::Long(v as i64)
                }
                'S' => {
                    let v = u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]);
                    Value::Long(v as i64)
                }
                's' => {
                    let v = i16::from_ne_bytes([bytes[offset], bytes[offset + 1]]);
                    Value::Long(v as i64)
                }
                'N' => {
                    let v = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'V' => {
                    let v = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'L' => {
                    let v = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'l' => {
                    let v = i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'J' => {
                    let v = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'P' => {
                    let v = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                    Value::Long(v as i64)
                }
                'f' | 'g' => {
                    let v = if code == 'g' {
                        f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
                    } else {
                        f32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
                    };
                    Value::Double(v as f64)
                }
                'd' | 'e' | 'E' | 'G' => {
                    let v = match code {
                        'e' => f64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                        'E' => f64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                        _ => f64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                    };
                    Value::Double(v)
                }
                _ => Value::Null,
            };

            let key = if field_name.is_empty() {
                Value::Long(field_num)
            } else if actual_count > 1 {
                Value::String(format!("{}{}", field_name, ci + 1))
            } else {
                Value::String(field_name.clone())
            };
            arr.set(&key, val);
            offset += size;
            if field_name.is_empty() {
                field_num += 1;
            }
        }
    }
    Ok(Value::Array(arr))
}

// -- Hash --

fn php_hash_builtin(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let algo = args.first().map(|v| v.to_php_string()).unwrap_or_default().to_lowercase();
    let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let raw = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
    match php_rs_ext_hash::php_hash(&algo, &data) {
        Some(hex) => {
            if raw {
                let bytes: Vec<u8> = hex
                    .as_bytes()
                    .chunks(2)
                    .filter_map(|c| std::str::from_utf8(c).ok())
                    .filter_map(|s| u8::from_str_radix(s, 16).ok())
                    .collect();
                Ok(Value::String(String::from_utf8_lossy(&bytes).to_string()))
            } else {
                Ok(Value::String(hex))
            }
        }
        None => Ok(Value::Bool(false)),
    }
}

fn php_hash_hmac_builtin(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let algo = args.first().map(|v| v.to_php_string()).unwrap_or_default().to_lowercase();
    let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let key = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
    match php_rs_ext_hash::php_hash_hmac(&algo, &data, &key) {
        Some(hex) => Ok(Value::String(hex)),
        None => Ok(Value::Bool(false)),
    }
}

fn php_hash_equals_builtin(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let known = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let user = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(php_rs_ext_hash::php_hash_equals(&known, &user)))
}

fn php_hash_algos_builtin(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for algo in php_rs_ext_hash::php_hash_algos() {
        arr.push(Value::String(algo.to_string()));
    }
    Ok(Value::Array(arr))
}

// -- URL --

fn php_parse_url(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let url = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let component = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
    let mut scheme = String::new();
    let host;
    let mut port: Option<i64> = None;
    let mut path = String::new();
    let mut query = String::new();
    let mut fragment = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    let mut rest = url.as_str();
    if let Some(pos) = rest.find("://") {
        scheme = rest[..pos].to_string();
        rest = &rest[pos + 3..];
    }
    if let Some(at_pos) = rest.find('@') {
        let has_slash = rest[..at_pos].contains('/');
        if !has_slash {
            let userinfo = &rest[..at_pos];
            if let Some(colon) = userinfo.find(':') {
                user = userinfo[..colon].to_string();
                pass = userinfo[colon + 1..].to_string();
            } else {
                user = userinfo.to_string();
            }
            rest = &rest[at_pos + 1..];
        }
    }
    if let Some(hash_pos) = rest.find('#') {
        fragment = rest[hash_pos + 1..].to_string();
        rest = &rest[..hash_pos];
    }
    if let Some(q_pos) = rest.find('?') {
        query = rest[q_pos + 1..].to_string();
        rest = &rest[..q_pos];
    }
    if let Some(slash_pos) = rest.find('/') {
        path = rest[slash_pos..].to_string();
        rest = &rest[..slash_pos];
    }
    if let Some(colon_pos) = rest.rfind(':') {
        host = rest[..colon_pos].to_string();
        port = rest[colon_pos + 1..].parse().ok();
    } else {
        host = rest.to_string();
    }
    match component {
        -1 => {
            let mut arr = PhpArray::new();
            if !scheme.is_empty() {
                arr.set_string("scheme".into(), Value::String(scheme));
            }
            if !host.is_empty() {
                arr.set_string("host".into(), Value::String(host));
            }
            if let Some(p) = port {
                arr.set_string("port".into(), Value::Long(p));
            }
            if !user.is_empty() {
                arr.set_string("user".into(), Value::String(user));
            }
            if !pass.is_empty() {
                arr.set_string("pass".into(), Value::String(pass));
            }
            if !path.is_empty() {
                arr.set_string("path".into(), Value::String(path));
            }
            if !query.is_empty() {
                arr.set_string("query".into(), Value::String(query));
            }
            if !fragment.is_empty() {
                arr.set_string("fragment".into(), Value::String(fragment));
            }
            Ok(Value::Array(arr))
        }
        0 => Ok(if scheme.is_empty() {
            Value::Null
        } else {
            Value::String(scheme)
        }),
        1 => Ok(if host.is_empty() {
            Value::Null
        } else {
            Value::String(host)
        }),
        2 => Ok(match port {
            Some(p) => Value::Long(p),
            None => Value::Null,
        }),
        3 => Ok(if user.is_empty() {
            Value::Null
        } else {
            Value::String(user)
        }),
        4 => Ok(if pass.is_empty() {
            Value::Null
        } else {
            Value::String(pass)
        }),
        5 => Ok(if path.is_empty() {
            Value::Null
        } else {
            Value::String(path)
        }),
        6 => Ok(if query.is_empty() {
            Value::Null
        } else {
            Value::String(query)
        }),
        7 => Ok(if fragment.is_empty() {
            Value::Null
        } else {
            Value::String(fragment)
        }),
        _ => Ok(Value::Bool(false)),
    }
}

fn php_parse_str(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mut arr = PhpArray::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        let key = key.replace('+', " ");
        let val = val.replace('+', " ");
        arr.set_string(key, Value::String(val));
    }
    // PHP 8: parse_str($string, &$result) writes to $result and returns void
    if args.len() >= 2 {
        vm.write_back_arg(1, Value::Array(arr), ref_args, ref_prop_args);
        Ok(Value::Null)
    } else {
        Ok(Value::Array(arr))
    }
}

fn php_http_build_query(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let data = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref arr) = data {
        let sep = args
            .get(1)
            .map(|v| v.to_php_string())
            .unwrap_or_else(|| "&".into());
        let parts: Vec<String> = arr
            .entries()
            .iter()
            .map(|(k, v)| {
                let key = match k {
                    ArrayKey::String(s) => s.clone(),
                    ArrayKey::Int(n) => n.to_string(),
                };
                format!("{}={}", key, v.to_php_string())
            })
            .collect();
        Ok(Value::String(parts.join(&sep)))
    } else {
        Ok(Value::String(String::new()))
    }
}

fn php_getopt(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// -- Misc --

fn php_crypt(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let str_val = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let salt = args
        .get(1)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "xx".into());
    if salt.starts_with("$2y$") || salt.starts_with("$2b$") || salt.starts_with("$2a$") {
        #[cfg(feature = "native-io")]
        {
            let _bcrypt_salt = salt.replacen("$2y$", "$2b$", 1);
            match bcrypt::hash_with_result(&str_val, 10) {
                Ok(parts) => {
                    let hash = parts.format_for_version(bcrypt::Version::TwoB);
                    let php_hash = hash.replacen("$2b$", "$2y$", 1);
                    Ok(Value::String(php_hash))
                }
                Err(_) => Ok(Value::String("*0".to_string())),
            }
        }
        #[cfg(not(feature = "native-io"))]
        Ok(Value::String("*0".to_string()))
    } else if salt.starts_with("$1$") {
        let data = format!("{}${}", str_val, &salt[3..]);
        let hash = php_rs_ext_standard::strings::php_md5(&data);
        Ok(Value::String(format!(
            "$1${}${}",
            &salt[3..11],
            &hash[..22]
        )))
    } else {
        let hash = php_rs_ext_standard::strings::php_md5(&format!("{}{}", salt, str_val));
        Ok(Value::String(format!(
            "{}{}",
            &salt[..2.min(salt.len())],
            &hash[..11]
        )))
    }
}

fn php_key(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(a.key_first())
    } else {
        Ok(Value::Null)
    }
}

fn php_next(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        if a.entries().len() > 1 {
            Ok(a.entries()[1].1.clone())
        } else {
            Ok(Value::Bool(false))
        }
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_prev(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_get_html_translation_table(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string("&".into(), Value::String("&amp;".into()));
    arr.set_string("<".into(), Value::String("&lt;".into()));
    arr.set_string(">".into(), Value::String("&gt;".into()));
    arr.set_string("\"".into(), Value::String("&quot;".into()));
    Ok(Value::Array(arr))
}

fn php_get_browser(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

/// get_headers(string $url, bool $associative = false, ?resource $context = null): array|false
/// Fetches HTTP headers from the given URL.
#[cfg(feature = "native-io")]
fn php_get_headers(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let url = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let associative = args.get(1).map(|v| v.to_bool()).unwrap_or(false);

    if url.is_empty() {
        return Ok(Value::Bool(false));
    }

    // Use a simple TCP/HTTP request to get headers
    match std::process::Command::new("curl")
        .args(["-sI", "-o", "/dev/null", "-D", "-", &url])
        .output()
    {
        Ok(output) => {
            let header_text = String::from_utf8_lossy(&output.stdout);
            let mut arr = PhpArray::new();
            for (i, line) in header_text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if associative {
                    if let Some(colon_pos) = line.find(':') {
                        let key = line[..colon_pos].trim().to_string();
                        let val = line[colon_pos + 1..].trim().to_string();
                        arr.set_string(key, Value::String(val));
                    } else {
                        // Status line
                        arr.push(Value::String(line.to_string()));
                    }
                } else {
                    let _ = i;
                    arr.push(Value::String(line.to_string()));
                }
            }
            Ok(Value::Array(arr))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

#[cfg(not(feature = "native-io"))]
fn php_get_headers(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_connection_status(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_mail(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_config_get_hash(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}

fn php_request_parse_body(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_openlog(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_syslog(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let msg = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    eprintln!("{}", msg);
    Ok(Value::Bool(true))
}

fn php_nl_langinfo(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}

fn php_ftok(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let proj = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let mut hash: i64 = 0;
    for b in path.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as i64);
    }
    if let Some(c) = proj.bytes().next() {
        hash ^= (c as i64) << 24;
    }
    Ok(Value::Long(hash))
}

fn php_realpath_cache_get(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

fn php_realpath_cache_size(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

// -- Image type helpers --

fn php_image_type_to_mime_type(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let t = args.first().map(|v| v.to_long()).unwrap_or(0);
    let mime = match t {
        1 => "image/gif",
        2 => "image/jpeg",
        3 => "image/png",
        6 => "image/bmp",
        18 => "image/webp",
        _ => "application/octet-stream",
    };
    Ok(Value::String(mime.into()))
}

fn php_image_type_to_extension(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let t = args.first().map(|v| v.to_long()).unwrap_or(0);
    let ext = match t {
        1 => ".gif",
        2 => ".jpeg",
        3 => ".png",
        6 => ".bmp",
        18 => ".webp",
        _ => "",
    };
    if ext.is_empty() {
        Ok(Value::Bool(false))
    } else {
        Ok(Value::String(ext.into()))
    }
}

fn php_getimagesize(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// -- Windows stubs --

fn php_sapi_windows_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// -- Gettext --

fn php_gettext(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let msg = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(msg))
}

fn php_bindtextdomain(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let domain = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(domain))
}

fn php_textdomain(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let domain = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(domain))
}

// -- Posix --

fn php_posix_getpid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(std::process::id() as i64))
}
fn php_posix_getppid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(1))
}
fn php_posix_getuid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}
fn php_posix_getpgid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(std::process::id() as i64))
}
fn php_posix_getlogin(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(
        std::env::var("USER").unwrap_or_else(|_| "root".into()),
    ))
}

fn php_posix_uname(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string(
        "sysname".into(),
        Value::String(std::env::consts::OS.to_string()),
    );
    arr.set_string("nodename".into(), Value::String("localhost".into()));
    arr.set_string("release".into(), Value::String("1.0.0".into()));
    arr.set_string("version".into(), Value::String("1".into()));
    arr.set_string(
        "machine".into(),
        Value::String(std::env::consts::ARCH.to_string()),
    );
    Ok(Value::Array(arr))
}

fn php_posix_times(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string("ticks".into(), Value::Long(0));
    arr.set_string("utime".into(), Value::Long(0));
    arr.set_string("stime".into(), Value::Long(0));
    arr.set_string("cutime".into(), Value::Long(0));
    arr.set_string("cstime".into(), Value::Long(0));
    Ok(Value::Array(arr))
}

fn php_posix_isatty(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}
fn php_posix_ttyname(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("/dev/tty".into()))
}
fn php_posix_getcwd(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(
        std::env::current_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    ))
}
fn php_posix_mkfifo(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_posix_getrlimit(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    arr.set_string("soft core".into(), Value::Long(-1));
    arr.set_string("hard core".into(), Value::Long(-1));
    Ok(Value::Array(arr))
}

fn php_posix_get_last_error(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_posix_strerror(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let errno = args.first().map(|v| v.to_long()).unwrap_or(0);
    Ok(Value::String(format!("Error {}", errno)))
}

fn php_posix_access(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let path = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::Bool(std::path::Path::new(&path).exists()))
}

fn php_posix_getpwnam(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// -- pcntl --

fn php_pcntl_fork(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(-1))
}
fn php_pcntl_signal(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}
fn php_pcntl_signal_get_handler(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}
fn php_pcntl_sigprocmask(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}
fn php_pcntl_wifexited(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}
fn php_pcntl_wexitstatus(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}
fn php_pcntl_exec(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}
fn php_pcntl_alarm(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_pcntl_strerror(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let errno = args.first().map(|v| v.to_long()).unwrap_or(0);
    Ok(Value::String(format!("Error {}", errno)))
}

fn php_pcntl_async_signals(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.is_empty() {
        Ok(Value::Bool(false))
    } else {
        Ok(Value::Bool(true))
    }
}

// ═══════════════════════════════════════════════════════════════════
// Extension stub registrations
// ═══════════════════════════════════════════════════════════════════

fn stub_false(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}
fn stub_true(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}
fn stub_null(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}
fn stub_zero(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}
fn stub_empty_string(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}
fn stub_empty_array(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}
fn stub_passthrough(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(args
        .first()
        .cloned()
        .unwrap_or(Value::Null)
        .to_php_string()
        .into())
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

fn register_gmp(r: &mut BuiltinRegistry) {
    r.insert("gmp_init", stub_zero);
    r.insert("gmp_intval", stub_zero);
    r.insert("gmp_strval", stub_empty_string);
    r.insert("gmp_add", stub_zero);
    r.insert("gmp_sub", stub_zero);
    r.insert("gmp_mul", stub_zero);
    r.insert("gmp_div_q", stub_zero);
    r.insert("gmp_div_r", stub_zero);
    r.insert("gmp_div_qr", stub_empty_array);
    r.insert("gmp_div", stub_zero);
    r.insert("gmp_mod", stub_zero);
    r.insert("gmp_divexact", stub_zero);
    r.insert("gmp_neg", stub_zero);
    r.insert("gmp_abs", stub_zero);
    r.insert("gmp_fact", stub_zero);
    r.insert("gmp_sqrt", stub_zero);
    r.insert("gmp_sqrtrem", stub_empty_array);
    r.insert("gmp_root", stub_zero);
    r.insert("gmp_rootrem", stub_empty_array);
    r.insert("gmp_pow", stub_zero);
    r.insert("gmp_powm", stub_zero);
    r.insert("gmp_perfect_square", stub_false);
    r.insert("gmp_perfect_power", stub_false);
    r.insert("gmp_prob_prime", stub_zero);
    r.insert("gmp_nextprime", stub_zero);
    r.insert("gmp_gcd", stub_zero);
    r.insert("gmp_gcdext", stub_empty_array);
    r.insert("gmp_lcm", stub_zero);
    r.insert("gmp_invert", stub_false);
    r.insert("gmp_jacobi", stub_zero);
    r.insert("gmp_legendre", stub_zero);
    r.insert("gmp_kronecker", stub_zero);
    r.insert("gmp_cmp", stub_zero);
    r.insert("gmp_sign", stub_zero);
    r.insert("gmp_and", stub_zero);
    r.insert("gmp_or", stub_zero);
    r.insert("gmp_xor", stub_zero);
    r.insert("gmp_com", stub_zero);
    r.insert("gmp_setbit", stub_null);
    r.insert("gmp_clrbit", stub_null);
    r.insert("gmp_testbit", stub_false);
    r.insert("gmp_scan0", stub_zero);
    r.insert("gmp_scan1", stub_zero);
    r.insert("gmp_popcount", stub_zero);
    r.insert("gmp_hamdist", stub_zero);
    r.insert("gmp_random_range", stub_zero);
    r.insert("gmp_random_bits", stub_zero);
    r.insert("gmp_random_seed", stub_null);
    r.insert("gmp_binomial", stub_zero);
    r.insert("gmp_export", stub_empty_string);
    r.insert("gmp_import", stub_zero);
}

fn register_xml(r: &mut BuiltinRegistry) {
    for name in &[
        "xml_parser_create",
        "xml_parser_create_ns",
        "xml_parser_free",
        "xml_parse",
        "xml_parse_into_struct",
        "xml_set_element_handler",
        "xml_set_character_data_handler",
        "xml_set_default_handler",
        "xml_set_processing_instruction_handler",
        "xml_set_notation_decl_handler",
        "xml_set_external_entity_ref_handler",
        "xml_set_unparsed_entity_decl_handler",
        "xml_set_start_namespace_decl_handler",
        "xml_set_end_namespace_decl_handler",
        "xml_set_object",
        "xml_get_current_byte_index",
        "xml_get_current_column_number",
        "xml_get_current_line_number",
        "xml_get_error_code",
        "xml_error_string",
        "xml_parser_get_option",
        "xml_parser_set_option",
    ] {
        r.insert(name, stub_false);
    }
    for name in &[
        "libxml_clear_errors",
        "libxml_disable_entity_loader",
        "libxml_get_errors",
        "libxml_get_external_entity_loader",
        "libxml_get_last_error",
        "libxml_set_external_entity_loader",
        "libxml_set_streams_context",
        "libxml_use_internal_errors",
    ] {
        r.insert(name, stub_false);
    }
}

fn register_fileinfo(r: &mut BuiltinRegistry) {
    r.insert("finfo_open", php_finfo_open);
    r.insert("finfo_close", stub_true);
    r.insert("finfo_file", php_finfo_file);
    r.insert("finfo_buffer", php_finfo_buffer);
    r.insert("finfo_set_flags", stub_true);
    r.insert("mime_content_type", php_mime_content_type);
}

fn php_finfo_open(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let options = args
        .first()
        .map(|v| v.to_long() as i32)
        .unwrap_or(php_rs_ext_fileinfo::FILEINFO_NONE);
    let _finfo = php_rs_ext_fileinfo::finfo_open(options);
    // Return a resource-like integer (store options as the resource ID)
    Ok(Value::Long(options as i64))
}

fn php_finfo_file(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let options = args
        .first()
        .map(|v| v.to_long() as i32)
        .unwrap_or(php_rs_ext_fileinfo::FILEINFO_MIME_TYPE);
    let filename = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let finfo = php_rs_ext_fileinfo::finfo_open(options);
    let result = php_rs_ext_fileinfo::finfo_file(&finfo, &filename);
    Ok(Value::String(result))
}

fn php_finfo_buffer(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let options = args
        .first()
        .map(|v| v.to_long() as i32)
        .unwrap_or(php_rs_ext_fileinfo::FILEINFO_MIME_TYPE);
    let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let finfo = php_rs_ext_fileinfo::finfo_open(options);
    let result = php_rs_ext_fileinfo::finfo_buffer(&finfo, data.as_bytes());
    Ok(Value::String(result))
}

fn php_mime_content_type(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mime = php_rs_ext_fileinfo::mime_content_type(&filename);
    Ok(Value::String(mime))
}

fn register_simplexml(r: &mut BuiltinRegistry) {
    r.insert("simplexml_load_file", stub_false);
    r.insert("simplexml_load_string", stub_false);
    r.insert("simplexml_import_dom", stub_false);
}

fn register_xmlwriter(r: &mut BuiltinRegistry) {
    for name in &[
        "xmlwriter_open_memory",
        "xmlwriter_open_uri",
        "xmlwriter_set_indent",
        "xmlwriter_set_indent_string",
        "xmlwriter_start_document",
        "xmlwriter_end_document",
        "xmlwriter_start_element",
        "xmlwriter_start_element_ns",
        "xmlwriter_end_element",
        "xmlwriter_full_end_element",
        "xmlwriter_start_attribute",
        "xmlwriter_start_attribute_ns",
        "xmlwriter_end_attribute",
        "xmlwriter_write_attribute",
        "xmlwriter_write_attribute_ns",
        "xmlwriter_start_cdata",
        "xmlwriter_end_cdata",
        "xmlwriter_write_cdata",
        "xmlwriter_start_comment",
        "xmlwriter_end_comment",
        "xmlwriter_write_comment",
        "xmlwriter_start_pi",
        "xmlwriter_end_pi",
        "xmlwriter_write_pi",
        "xmlwriter_text",
        "xmlwriter_write_raw",
        "xmlwriter_start_dtd",
        "xmlwriter_start_dtd_element",
        "xmlwriter_end_dtd_element",
        "xmlwriter_write_dtd_element",
        "xmlwriter_start_dtd_attlist",
        "xmlwriter_end_dtd_attlist",
        "xmlwriter_write_dtd_attlist",
        "xmlwriter_start_dtd_entity",
        "xmlwriter_end_dtd_entity",
        "xmlwriter_write_dtd_entity",
        "xmlwriter_end_dtd",
        "xmlwriter_write_dtd",
        "xmlwriter_output_memory",
        "xmlwriter_flush",
        "xmlwriter_to_memory",
    ] {
        r.insert(name, stub_false);
    }
}

fn register_readline(r: &mut BuiltinRegistry) {
    r.insert("readline", php_readline);
    r.insert("readline_add_history", php_readline_add_history);
    r.insert("readline_clear_history", php_readline_clear_history);
    r.insert("readline_read_history", php_readline_read_history);
    r.insert("readline_write_history", php_readline_write_history);
    r.insert("readline_info", php_readline_info);
    r.insert("readline_list_history", php_readline_list_history);
    // Callbacks not fully supported yet
    r.insert("readline_callback_handler_install", stub_false);
    r.insert("readline_callback_handler_remove", stub_false);
    r.insert("readline_callback_read_char", stub_false);
    r.insert("readline_completion_function", stub_true);
    r.insert("readline_on_new_line", stub_true);
    r.insert("readline_redisplay", stub_true);
}

fn php_readline(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let prompt = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    match php_rs_ext_readline::readline(&prompt) {
        Some(line) => Ok(Value::String(line)),
        None => Ok(Value::Bool(false)),
    }
}

fn php_readline_add_history(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let line = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(php_rs_ext_readline::readline_add_history(
        &line,
    )))
}

fn php_readline_clear_history(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(php_rs_ext_readline::readline_clear_history()))
}

fn php_readline_read_history(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(php_rs_ext_readline::readline_read_history(
        &filename,
    )))
}

fn php_readline_write_history(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(php_rs_ext_readline::readline_write_history(
        &filename,
    )))
}

fn php_readline_info(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let varname = args.first().map(|v| v.to_php_string());
    let newvalue = args.get(1).map(|v| v.to_php_string());
    let info = php_rs_ext_readline::readline_info(varname.as_deref(), newvalue.as_deref());
    let mut arr = PhpArray::new();
    arr.set_string("line_buffer".to_string(), Value::String(info.line_buffer));
    arr.set_string("point".to_string(), Value::Long(info.point as i64));
    arr.set_string("end".to_string(), Value::Long(info.end as i64));
    arr.set_string(
        "library_version".to_string(),
        Value::String(info.library_version),
    );
    arr.set_string(
        "readline_name".to_string(),
        Value::String(info.readline_name),
    );
    arr.set_string("done".to_string(), Value::Bool(info.done));
    Ok(Value::Array(arr))
}

fn php_readline_list_history(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let history = php_rs_ext_readline::get_history();
    let mut arr = PhpArray::new();
    for (i, line) in history.iter().enumerate() {
        arr.set_int(i as i64, Value::String(line.clone()));
    }
    Ok(Value::Array(arr))
}

fn register_exif(r: &mut BuiltinRegistry) {
    r.insert("exif_read_data", stub_false);
    r.insert("exif_imagetype", stub_false);
    r.insert("exif_thumbnail", stub_false);
    r.insert("exif_tagname", stub_false);
}

fn register_zip(r: &mut BuiltinRegistry) {
    // The procedural zip_* API is deprecated in PHP 8.0+
    // We still register them for compatibility
    r.insert("zip_open", stub_false);
    r.insert("zip_close", stub_true);
    r.insert("zip_read", stub_false);
    r.insert("zip_entry_open", stub_true);
    r.insert("zip_entry_close", stub_true);
    r.insert("zip_entry_read", stub_empty_string);
    r.insert("zip_entry_name", stub_empty_string);
    r.insert("zip_entry_filesize", stub_zero);
    r.insert("zip_entry_compressedsize", stub_zero);
    r.insert("zip_entry_compressionmethod", stub_empty_string);
}

fn register_shmop(r: &mut BuiltinRegistry) {
    for name in &[
        "shmop_open",
        "shmop_close",
        "shmop_read",
        "shmop_write",
        "shmop_size",
        "shmop_delete",
    ] {
        r.insert(name, stub_false);
    }
}

fn register_sysv(r: &mut BuiltinRegistry) {
    for name in &[
        "sem_get",
        "sem_acquire",
        "sem_release",
        "sem_remove",
        "shm_attach",
        "shm_detach",
        "shm_get_var",
        "shm_has_var",
        "shm_put_var",
        "shm_remove",
        "shm_remove_var",
        "msg_get_queue",
        "msg_receive",
        "msg_remove_queue",
        "msg_send",
        "msg_set_queue",
        "msg_stat_queue",
        "msg_queue_exists",
    ] {
        r.insert(name, stub_false);
    }
}

fn register_tidy(r: &mut BuiltinRegistry) {
    r.insert("tidy_parse_string", php_tidy_parse_string);
    r.insert("tidy_parse_file", php_tidy_parse_file);
    r.insert("tidy_clean_repair", php_tidy_clean_repair);
    r.insert("tidy_repair_string", php_tidy_repair_string);
    r.insert("tidy_repair_file", php_tidy_repair_string);
    r.insert("tidy_get_output", php_tidy_get_output);
    r.insert("tidy_get_error_buffer", php_tidy_get_error_buffer);
    r.insert("tidy_diagnose", php_tidy_diagnose);
    r.insert("tidy_warning_count", php_tidy_warning_count);
    r.insert("tidy_error_count", php_tidy_error_count);
    r.insert("tidy_access_count", php_tidy_access_count);
    r.insert("tidy_get_html", php_tidy_get_output);
    r.insert("tidy_get_head", php_tidy_get_output);
    r.insert("tidy_get_body", php_tidy_get_output);
    r.insert("tidy_get_root", php_tidy_get_output);
    // Stubs for less-used functions
    r.insert("tidy_config_count", stub_zero);
    r.insert("tidy_get_html_ver", stub_zero);
    r.insert("tidy_get_status", stub_zero);
    r.insert("tidy_get_opt_doc", stub_false);
    r.insert("tidy_get_release", php_tidy_get_release);
    r.insert("tidy_getopt", stub_false);
    r.insert("tidy_is_xhtml", stub_false);
    r.insert("tidy_is_xml", stub_false);
    r.insert("tidy_reset_config", stub_true);
    r.insert("tidy_save_config", stub_false);
    r.insert("tidy_set_encoding", stub_true);
    r.insert("tidy_setopt", stub_true);
    r.insert("tidy_get_config", stub_empty_array);
}

fn php_tidy_parse_string(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let config = php_rs_ext_tidy::TidyConfig::default();
    let doc = php_rs_ext_tidy::tidy_parse_string(&input, &config);
    let output = php_rs_ext_tidy::tidy_get_output(&doc);
    // Store as a string resource (simplified — full OOP tidy object not yet needed)
    Ok(Value::String(output))
}

fn php_tidy_parse_file(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    // Try to read the file, then parse
    match std::fs::read_to_string(&filename) {
        Ok(contents) => {
            let config = php_rs_ext_tidy::TidyConfig::default();
            let doc = php_rs_ext_tidy::tidy_parse_string(&contents, &config);
            Ok(Value::String(php_rs_ext_tidy::tidy_get_output(&doc)))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn php_tidy_clean_repair(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // In simplified mode, just return true (the parse already does repair)
    let _ = args;
    Ok(Value::Bool(true))
}

fn php_tidy_repair_string(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let config = php_rs_ext_tidy::TidyConfig::default();
    let doc = php_rs_ext_tidy::tidy_parse_string(&input, &config);
    Ok(Value::String(php_rs_ext_tidy::tidy_get_output(&doc)))
}

fn php_tidy_get_output(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // In simplified mode, the tidy object IS the output string
    let output = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::String(output))
}

fn php_tidy_get_error_buffer(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let config = php_rs_ext_tidy::TidyConfig::default();
    let doc = php_rs_ext_tidy::tidy_parse_string(&input, &config);
    let buffer = php_rs_ext_tidy::tidy_get_error_buffer(&doc);
    if buffer.is_empty() {
        Ok(Value::Bool(false))
    } else {
        Ok(Value::String(buffer))
    }
}

fn php_tidy_diagnose(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_tidy_warning_count(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let config = php_rs_ext_tidy::TidyConfig::default();
    let doc = php_rs_ext_tidy::tidy_parse_string(&input, &config);
    Ok(Value::Long(php_rs_ext_tidy::tidy_warning_count(&doc) as i64))
}

fn php_tidy_error_count(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let config = php_rs_ext_tidy::TidyConfig::default();
    let doc = php_rs_ext_tidy::tidy_parse_string(&input, &config);
    Ok(Value::Long(php_rs_ext_tidy::tidy_error_count(&doc) as i64))
}

fn php_tidy_access_count(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_tidy_get_release(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("php.rs tidy 1.0".to_string()))
}

fn register_snmp(r: &mut BuiltinRegistry) {
    for name in &[
        "snmpget",
        "snmpgetnext",
        "snmpwalk",
        "snmprealwalk",
        "snmpset",
        "snmpwalkoid",
        "snmp_get_quick_print",
        "snmp_get_valueretrieval",
        "snmp_read_mib",
        "snmp_set_enum_print",
        "snmp_set_oid_numeric_print",
        "snmp_set_oid_output_format",
        "snmp_set_quick_print",
        "snmp_set_valueretrieval",
        "snmp2_get",
        "snmp2_getnext",
        "snmp2_real_walk",
        "snmp2_set",
        "snmp2_walk",
        "snmp3_get",
        "snmp3_getnext",
        "snmp3_real_walk",
        "snmp3_set",
        "snmp3_walk",
    ] {
        r.insert(name, stub_false);
    }
}

fn register_sockets(r: &mut BuiltinRegistry) {
    r.insert("socket_create", stub_false);
    r.insert("socket_create_pair", stub_false);
    r.insert("socket_create_listen", stub_false);
    for name in &[
        "socket_accept",
        "socket_bind",
        "socket_connect",
        "socket_listen",
        "socket_shutdown",
        "socket_close",
        "socket_set_block",
        "socket_set_nonblock",
        "socket_set_option",
        "socket_read",
        "socket_recv",
        "socket_recvfrom",
        "socket_recvmsg",
        "socket_getpeername",
        "socket_getsockname",
        "socket_setopt",
        "socket_get_option",
        "socket_getopt",
        "socket_import_stream",
        "socket_export_stream",
        "socket_addrinfo_connect",
        "socket_addrinfo_bind",
        "socket_atmark",
        "socket_wsaprotocol_info_export",
        "socket_wsaprotocol_info_import",
        "socket_wsaprotocol_info_release",
    ] {
        r.insert(name, stub_false);
    }
    r.insert("socket_write", stub_zero);
    r.insert("socket_send", stub_zero);
    r.insert("socket_sendto", stub_zero);
    r.insert("socket_sendmsg", stub_zero);
    r.insert("socket_select", stub_zero);
    r.insert("socket_last_error", stub_zero);
    r.insert("socket_clear_error", stub_null);
    r.insert("socket_strerror", php_socket_strerror);
    r.insert("socket_cmsg_space", stub_zero);
    r.insert("socket_addrinfo_lookup", stub_empty_array);
    r.insert("socket_addrinfo_explain", stub_empty_array);
}

fn php_socket_strerror(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("Success".into()))
}

fn register_opcache(r: &mut BuiltinRegistry) {
    for name in &[
        "opcache_compile_file",
        "opcache_invalidate",
        "opcache_is_script_cached",
        "opcache_is_script_cached_in_file_cache",
        "opcache_reset",
        "opcache_jit_blacklist",
    ] {
        r.insert(name, stub_true);
    }
    r.insert("opcache_get_configuration", stub_empty_array);
    r.insert("opcache_get_status", stub_empty_array);
}

fn register_dba(r: &mut BuiltinRegistry) {
    r.insert("dba_open", stub_false);
    r.insert("dba_popen", stub_false);
    r.insert("dba_close", stub_true);
    r.insert("dba_exists", stub_false);
    r.insert("dba_delete", stub_false);
    r.insert("dba_fetch", stub_false);
    r.insert("dba_insert", stub_false);
    r.insert("dba_replace", stub_false);
    r.insert("dba_firstkey", stub_false);
    r.insert("dba_nextkey", stub_false);
    r.insert("dba_optimize", stub_true);
    r.insert("dba_sync", stub_true);
    r.insert("dba_handlers", stub_empty_array);
    r.insert("dba_list", stub_empty_array);
    r.insert("dba_key_split", stub_empty_array);
}

fn register_enchant(r: &mut BuiltinRegistry) {
    r.insert("enchant_broker_init", stub_zero);
    r.insert("enchant_broker_free", stub_true);
    r.insert("enchant_broker_free_dict", stub_true);
    r.insert("enchant_broker_dict_exists", stub_false);
    r.insert("enchant_broker_request_dict", stub_false);
    r.insert("enchant_broker_request_pwl_dict", stub_false);
    r.insert("enchant_broker_describe", stub_empty_array);
    r.insert("enchant_broker_list_dicts", stub_empty_array);
    r.insert("enchant_broker_get_error", stub_empty_string);
    r.insert("enchant_broker_get_dict_path", stub_empty_string);
    r.insert("enchant_broker_set_dict_path", stub_true);
    r.insert("enchant_broker_set_ordering", stub_true);
    r.insert("enchant_dict_check", stub_false);
    r.insert("enchant_dict_is_added", stub_false);
    r.insert("enchant_dict_is_in_session", stub_false);
    r.insert("enchant_dict_suggest", stub_empty_array);
    r.insert("enchant_dict_add", stub_null);
    r.insert("enchant_dict_add_to_personal", stub_null);
    r.insert("enchant_dict_add_to_session", stub_null);
    r.insert("enchant_dict_delete", stub_null);
    r.insert("enchant_dict_describe", stub_empty_array);
    r.insert("enchant_dict_get_error", stub_empty_string);
    r.insert("enchant_dict_quick_check", stub_true);
    r.insert("enchant_dict_store_replacement", stub_null);
    r.insert("enchant_dict_remove", stub_null);
    r.insert("enchant_dict_remove_from_session", stub_null);
}

fn register_ftp(r: &mut BuiltinRegistry) {
    r.insert("ftp_connect", stub_false);
    r.insert("ftp_ssl_connect", stub_false);
    r.insert("ftp_login", stub_false);
    r.insert("ftp_close", stub_true);
    r.insert("ftp_quit", stub_true);
    r.insert("ftp_pwd", php_ftp_pwd);
    r.insert("ftp_cdup", stub_false);
    r.insert("ftp_chdir", stub_false);
    r.insert("ftp_mkdir", stub_false);
    r.insert("ftp_rmdir", stub_false);
    r.insert("ftp_nlist", stub_empty_array);
    r.insert("ftp_rawlist", stub_empty_array);
    r.insert("ftp_mlsd", stub_empty_array);
    r.insert("ftp_systype", php_ftp_systype);
    r.insert("ftp_pasv", stub_true);
    r.insert("ftp_set_option", stub_true);
    r.insert("ftp_get_option", stub_zero);
    r.insert("ftp_get", stub_false);
    r.insert("ftp_fget", stub_false);
    r.insert("ftp_put", stub_false);
    r.insert("ftp_fput", stub_false);
    r.insert("ftp_append", stub_false);
    r.insert("ftp_delete", stub_false);
    r.insert("ftp_site", stub_false);
    r.insert("ftp_exec", stub_false);
    r.insert("ftp_rename", stub_false);
    r.insert("ftp_chmod", stub_false);
    r.insert("ftp_size", php_ftp_neg1);
    r.insert("ftp_mdtm", php_ftp_neg1);
    r.insert("ftp_raw", stub_empty_array);
    r.insert("ftp_nb_get", stub_zero);
    r.insert("ftp_nb_fget", stub_zero);
    r.insert("ftp_nb_put", stub_zero);
    r.insert("ftp_nb_fput", stub_zero);
    r.insert("ftp_nb_continue", stub_zero);
    r.insert("ftp_alloc", stub_false);
}

fn php_ftp_pwd(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("/".into()))
}
fn php_ftp_systype(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("UNIX".into()))
}
fn php_ftp_neg1(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(-1))
}

fn register_com_dotnet(r: &mut BuiltinRegistry) {
    r.insert("com_create_guid", php_com_create_guid);
    for name in &[
        "com_event_sink",
        "com_get_active_object",
        "com_load_typelib",
        "com_message_pump",
        "com_print_typeinfo",
    ] {
        r.insert(name, stub_false);
    }
    for name in &[
        "variant_abs",
        "variant_add",
        "variant_and",
        "variant_cast",
        "variant_cat",
        "variant_cmp",
        "variant_date_from_timestamp",
        "variant_date_to_timestamp",
        "variant_div",
        "variant_eqv",
        "variant_fix",
        "variant_get_type",
        "variant_idiv",
        "variant_imp",
        "variant_int",
        "variant_mod",
        "variant_mul",
        "variant_neg",
        "variant_not",
        "variant_or",
        "variant_pow",
        "variant_round",
        "variant_set",
        "variant_set_type",
        "variant_sub",
        "variant_xor",
    ] {
        r.insert(name, stub_null);
    }
}

fn php_com_create_guid(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(Value::String(format!(
        "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
        (ts >> 96) as u32,
        (ts >> 80) as u16,
        (ts >> 64) as u16,
        (ts >> 48) as u16,
        ts as u64 & 0xFFFFFFFFFFFF
    )))
}

fn register_ldap(r: &mut BuiltinRegistry) {
    r.insert("ldap_connect", stub_false);
    r.insert("ldap_unbind", stub_true);
    r.insert("ldap_close", stub_true);
    for name in &[
        "ldap_bind",
        "ldap_bind_ext",
        "ldap_sasl_bind",
        "ldap_search",
        "ldap_list",
        "ldap_read",
        "ldap_dn2ufn",
        "ldap_explode_dn",
        "ldap_add",
        "ldap_add_ext",
        "ldap_modify",
        "ldap_modify_ext",
        "ldap_mod_add",
        "ldap_mod_add_ext",
        "ldap_mod_del",
        "ldap_mod_del_ext",
        "ldap_mod_replace",
        "ldap_mod_replace_ext",
        "ldap_modify_batch",
        "ldap_delete",
        "ldap_delete_ext",
        "ldap_rename",
        "ldap_rename_ext",
        "ldap_set_option",
        "ldap_get_option",
        "ldap_control_paged_result",
        "ldap_control_paged_result_response",
        "ldap_parse_exop",
        "ldap_parse_reference",
        "ldap_parse_result",
        "ldap_start_tls",
        "ldap_sort",
        "ldap_exop",
        "ldap_exop_passwd",
        "ldap_exop_refresh",
        "ldap_exop_whoami",
        "ldap_connect_wallet",
        "ldap_count_references",
        "ldap_exop_sync",
        "ldap_first_reference",
        "ldap_next_reference",
    ] {
        r.insert(name, stub_false);
    }
    r.insert("ldap_free_result", stub_true);
    r.insert("ldap_count_entries", stub_zero);
    r.insert("ldap_first_entry", stub_false);
    r.insert("ldap_next_entry", stub_false);
    r.insert("ldap_get_entries", stub_empty_array);
    r.insert("ldap_get_attributes", stub_empty_array);
    r.insert("ldap_get_values", stub_empty_array);
    r.insert("ldap_get_values_len", stub_empty_array);
    r.insert("ldap_get_dn", stub_empty_string);
    r.insert("ldap_first_attribute", stub_empty_string);
    r.insert("ldap_next_attribute", stub_empty_string);
    r.insert("ldap_compare", php_ldap_compare);
    r.insert("ldap_errno", stub_zero);
    r.insert("ldap_error", php_ldap_error);
    r.insert("ldap_err2str", php_ldap_error);
    r.insert("ldap_set_rebind_proc", stub_true);
    r.insert("ldap_8859_to_t61", stub_passthrough);
    r.insert("ldap_t61_to_8859", stub_passthrough);
    r.insert("ldap_escape", stub_passthrough);
}

fn php_ldap_compare(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(-1))
}
fn php_ldap_error(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("Success".into()))
}

fn register_pgsql(r: &mut BuiltinRegistry) {
    for name in &[
        "pg_connect",
        "pg_pconnect",
        "pg_connect_poll",
        "pg_ping",
        "pg_query",
        "pg_query_params",
        "pg_prepare",
        "pg_execute",
        "pg_send_query",
        "pg_send_query_params",
        "pg_send_prepare",
        "pg_send_execute",
        "pg_fetch_result",
        "pg_fetch_row",
        "pg_fetch_assoc",
        "pg_fetch_array",
        "pg_fetch_object",
        "pg_fetch_all",
        "pg_fetch_all_columns",
        "pg_result_seek",
        "pg_field_is_null",
        "pg_end_copy",
        "pg_put_line",
        "pg_copy_from",
        "pg_copy_to",
        "pg_cancel_query",
        "pg_get_result",
        "pg_result_memory_size",
        "pg_change_password",
        "pg_get_notify",
        "pg_get_pid",
        "pg_consume_input",
        "pg_flush",
        "pg_meta_data",
        "pg_convert",
        "pg_insert",
        "pg_update",
        "pg_delete",
        "pg_select",
        "pg_lo_create",
        "pg_lo_open",
        "pg_lo_close",
        "pg_lo_read",
        "pg_lo_write",
        "pg_lo_read_all",
        "pg_lo_import",
        "pg_lo_export",
        "pg_lo_seek",
        "pg_lo_tell",
        "pg_lo_truncate",
        "pg_lo_unlink",
        "pg_trace",
        "pg_untrace",
        "pg_socket",
        "pg_jit",
        "pg_set_chunked_rows_size",
        "pg_lounlink",
        "pg_lowrite",
        "pg_put_copy_data",
        "pg_put_copy_end",
        "pg_result",
        "pg_service",
        "pg_exec",
        "pg_fieldisnull",
        "pg_freeresult",
        "pg_close_stmt",
    ] {
        r.insert(name, stub_false);
    }
    r.insert("pg_close", stub_true);
    r.insert("pg_free_result", stub_true);
    r.insert("pg_connection_status", stub_zero);
    r.insert("pg_connection_busy", stub_zero);
    r.insert("pg_connection_reset", stub_zero);
    for name in &[
        "pg_dbname",
        "pg_host",
        "pg_port",
        "pg_options",
        "pg_parameter_status",
        "pg_version",
        "pg_result_error",
        "pg_last_error",
        "pg_last_notice",
        "pg_field_name",
        "pg_field_type",
        "pg_field_type_oid",
        "pg_field_size",
        "pg_field_prtlen",
        "pg_field_table",
        "pg_errormessage",
        "pg_fieldname",
        "pg_fieldtype",
        "pg_tty",
    ] {
        r.insert(name, stub_empty_string);
    }
    r.insert("pg_result_status", stub_zero);
    r.insert("pg_result_error_field", stub_zero);
    r.insert("pg_num_rows", stub_zero);
    r.insert("pg_num_fields", stub_zero);
    r.insert("pg_affected_rows", stub_zero);
    r.insert("pg_last_oid", stub_zero);
    r.insert("pg_field_num", stub_zero);
    r.insert("pg_fieldnum", stub_zero);
    r.insert("pg_fieldprtlen", stub_zero);
    r.insert("pg_fieldsize", stub_zero);
    r.insert("pg_getlastoid", stub_zero);
    r.insert("pg_numfields", stub_zero);
    r.insert("pg_numrows", stub_zero);
    r.insert("pg_cmdtuples", stub_zero);
    r.insert("pg_set_error_verbosity", stub_zero);
    r.insert("pg_set_error_context_visibility", stub_zero);
    r.insert("pg_setclientencoding", stub_zero);
    r.insert("pg_socket_poll", stub_zero);
    r.insert("pg_transaction_status", stub_zero);
    r.insert("pg_client_encoding", php_pg_client_encoding);
    r.insert("pg_set_client_encoding", php_pg_client_encoding);
    r.insert("pg_clientencoding", php_pg_client_encoding);
    r.insert("pg_escape_string", stub_passthrough);
    r.insert("pg_escape_literal", stub_passthrough);
    r.insert("pg_escape_identifier", stub_passthrough);
    r.insert("pg_escape_bytea", stub_passthrough);
    r.insert("pg_unescape_bytea", stub_passthrough);
    r.insert("pg_loclose", stub_false);
    r.insert("pg_locreate", stub_false);
    r.insert("pg_loexport", stub_false);
    r.insert("pg_loimport", stub_false);
    r.insert("pg_loopen", stub_false);
    r.insert("pg_loread", stub_false);
    r.insert("pg_loreadall", stub_false);
}

fn php_pg_client_encoding(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("UTF8".into()))
}

fn register_odbc(r: &mut BuiltinRegistry) {
    r.insert("odbc_connect", stub_false);
    r.insert("odbc_pconnect", stub_false);
    r.insert("odbc_close", stub_null);
    r.insert("odbc_close_all", stub_null);
    for name in &[
        "odbc_exec",
        "odbc_do",
        "odbc_prepare",
        "odbc_execute",
        "odbc_fetch_array",
        "odbc_fetch_object",
        "odbc_fetch_row",
        "odbc_fetch_into",
        "odbc_result",
        "odbc_autocommit",
        "odbc_commit",
        "odbc_rollback",
        "odbc_setoption",
        "odbc_binmode",
        "odbc_longreadlen",
        "odbc_tables",
        "odbc_columns",
        "odbc_columnprivileges",
        "odbc_procedurecolumns",
        "odbc_procedures",
        "odbc_foreignkeys",
        "odbc_primarykeys",
        "odbc_specialcolumns",
        "odbc_statistics",
        "odbc_tableprivileges",
        "odbc_gettypeinfo",
        "odbc_data_source",
        "odbc_connection_string_is_quoted",
        "odbc_connection_string_should_quote",
    ] {
        r.insert(name, stub_false);
    }
    r.insert("odbc_next_result", stub_true);
    r.insert("odbc_free_result", stub_true);
    r.insert("odbc_cursor", stub_empty_string);
    r.insert("odbc_error", stub_empty_string);
    r.insert("odbc_errormsg", stub_empty_string);
    r.insert("odbc_field_name", stub_empty_string);
    r.insert("odbc_field_type", stub_empty_string);
    r.insert("odbc_result_all", stub_zero);
    r.insert("odbc_num_fields", stub_zero);
    r.insert("odbc_num_rows", stub_zero);
    r.insert("odbc_field_len", stub_zero);
    r.insert("odbc_field_scale", stub_zero);
    r.insert("odbc_field_num", stub_zero);
    r.insert("odbc_field_precision", stub_zero);
    r.insert(
        "odbc_connection_string_quote",
        php_odbc_connection_string_quote,
    );
}

fn php_odbc_connection_string_quote(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(format!("{{{}}}", s)))
}

fn register_apcu(r: &mut BuiltinRegistry) {
    r.insert("apcu_fetch", stub_false);
    r.insert("apcu_store", stub_true);
    r.insert("apcu_add", stub_true);
    r.insert("apcu_delete", stub_true);
    r.insert("apcu_exists", stub_false);
    r.insert("apcu_clear_cache", stub_true);
}

// ═══════════════════════════════════════════════════════════════════
// each() — deprecated in PHP 7.2, removed in PHP 8.0
// ═══════════════════════════════════════════════════════════════════

fn php_each(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // PHP 8.0+: each() is removed, emit fatal error
    vm.emit_error(
        8, // E_NOTICE
        "each() has been removed in PHP 8.0",
    )?;
    // Return false (PHP 7.x behavior when array pointer is past end)
    if let Some(Value::Array(ref arr)) = args.first() {
        if let Some((key, val)) = arr.entries().first() {
            let mut result = PhpArray::new();
            // Numeric keys
            result.push(val.clone());
            let key_val = match key {
                crate::value::ArrayKey::Int(n) => Value::Long(*n),
                crate::value::ArrayKey::String(s) => Value::String(s.clone()),
            };
            result.push(key_val.clone());
            // Named keys
            result.set(&Value::String("value".into()), val.clone());
            result.set(&Value::String("key".into()), key_val);
            return Ok(Value::Array(result));
        }
    }
    Ok(Value::Bool(false))
}

// ═══════════════════════════════════════════════════════════════════
// money_format() — deprecated in PHP 7.4, removed in PHP 8.0
// ═══════════════════════════════════════════════════════════════════

fn php_money_format(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    vm.emit_error(
        8192, // E_DEPRECATED
        "Function money_format() is deprecated",
    )?;
    // Minimal implementation: format with 2 decimal places
    let _format = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let number = args.get(1).map(|v| v.to_double()).unwrap_or(0.0);
    Ok(Value::String(format!("{:.2}", number)))
}

// ═══════════════════════════════════════════════════════════════════
// Iconv — character set conversion
// ═══════════════════════════════════════════════════════════════════

fn register_iconv(r: &mut BuiltinRegistry) {
    r.insert("iconv", php_iconv);
    r.insert("iconv_strlen", php_iconv_strlen);
    r.insert("iconv_strpos", php_iconv_strpos);
    r.insert("iconv_strrpos", php_iconv_strrpos);
    r.insert("iconv_substr", php_iconv_substr);
    r.insert("iconv_mime_encode", php_iconv_mime_encode);
    r.insert("iconv_mime_decode", php_iconv_mime_decode);
    r.insert("iconv_mime_decode_headers", php_iconv_mime_decode_headers);
    r.insert("iconv_get_encoding", php_iconv_get_encoding);
    r.insert("iconv_set_encoding", php_iconv_set_encoding);
}

fn php_iconv(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let in_charset = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let out_charset = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let input = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
    match php_rs_ext_iconv::iconv(&in_charset, &out_charset, &input) {
        Ok(result) => Ok(Value::String(result)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_strlen(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let charset = args
        .get(1)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    match php_rs_ext_iconv::iconv_strlen(&input, &charset) {
        Ok(len) => Ok(Value::Long(len as i64)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_strlen(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_strpos(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let offset = args.get(2).map(|v| v.to_long() as usize).unwrap_or(0);
    let charset = args
        .get(3)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    match php_rs_ext_iconv::iconv_strpos(&haystack, &needle, offset, &charset) {
        Ok(Some(pos)) => Ok(Value::Long(pos as i64)),
        Ok(None) => Ok(Value::Bool(false)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_strpos(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_strrpos(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let haystack = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let needle = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let charset = args
        .get(2)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    match php_rs_ext_iconv::iconv_strrpos(&haystack, &needle, &charset) {
        Ok(Some(pos)) => Ok(Value::Long(pos as i64)),
        Ok(None) => Ok(Value::Bool(false)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_strrpos(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_substr(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
    let length = match args.get(2) {
        Some(Value::Null) | None => None,
        Some(v) => Some(v.to_long()),
    };
    let charset = args
        .get(3)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    match php_rs_ext_iconv::iconv_substr(&input, offset, length, &charset) {
        Ok(result) => Ok(Value::String(result)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_substr(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_mime_encode(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let field_name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let field_value = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    let prefs = php_rs_ext_iconv::MimePreferences::default();
    match php_rs_ext_iconv::iconv_mime_encode(&field_name, &field_value, &prefs) {
        Ok(result) => Ok(Value::String(result)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_mime_encode(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_mime_decode(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let encoded = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let mode = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
    let charset = args
        .get(2)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    match php_rs_ext_iconv::iconv_mime_decode(&encoded, mode, &charset) {
        Ok(result) => Ok(Value::String(result)),
        Err(e) => {
            let _ = vm.emit_error(8, &format!("iconv_mime_decode(): {}", e));
            Ok(Value::Bool(false))
        }
    }
}

fn php_iconv_mime_decode_headers(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let encoded = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let _mode = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
    let charset = args
        .get(2)
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "UTF-8".to_string());
    // Split headers by newlines and decode each
    let mut arr = PhpArray::new();
    for line in encoded.lines() {
        if let Some((name, value)) = line.split_once(':') {
            let decoded = php_rs_ext_iconv::iconv_mime_decode(value.trim(), 0, &charset)
                .unwrap_or_else(|_| value.trim().to_string());
            arr.set_string(name.trim().to_string(), Value::String(decoded));
        }
    }
    Ok(Value::Array(arr))
}

fn php_iconv_get_encoding(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let type_name = args
        .first()
        .map(|v| v.to_php_string())
        .unwrap_or_else(|| "all".to_string());
    if type_name == "all" {
        let mut arr = PhpArray::new();
        arr.set_string(
            "input_encoding".to_string(),
            Value::String(php_rs_ext_iconv::iconv_get_encoding("input_encoding")),
        );
        arr.set_string(
            "output_encoding".to_string(),
            Value::String(php_rs_ext_iconv::iconv_get_encoding("output_encoding")),
        );
        arr.set_string(
            "internal_encoding".to_string(),
            Value::String(php_rs_ext_iconv::iconv_get_encoding("internal_encoding")),
        );
        Ok(Value::Array(arr))
    } else {
        let encoding = php_rs_ext_iconv::iconv_get_encoding(&type_name);
        if encoding.is_empty() {
            Ok(Value::Bool(false))
        } else {
            Ok(Value::String(encoding))
        }
    }
}

fn php_iconv_set_encoding(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let type_name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    let charset = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::Bool(php_rs_ext_iconv::iconv_set_encoding(
        &type_name, &charset,
    )))
}
