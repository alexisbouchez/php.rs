//! cURL function dispatch for the PHP VM.
//!
//! Wires php-rs-ext-curl functions into the VM's builtin dispatch system.

#![allow(unused_variables)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

/// Dispatch a cURL function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
#[cfg(feature = "native-io")]
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    use php_rs_ext_curl::{self, constants, CurlValue};

    match name {
        // ---------------------------------------------------------------
        // curl_init(?string $url = null): CurlHandle
        // ---------------------------------------------------------------
        "curl_init" => {
            let url = args.first().and_then(|v| match v {
                Value::Null => None,
                _ => Some(v.to_php_string()),
            });
            let handle = php_rs_ext_curl::curl_init(url.as_deref());
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.curl_handles.insert(id, handle);
            Ok(Some(Value::Long(id)))
        }

        // ---------------------------------------------------------------
        // curl_setopt(CurlHandle $handle, int $option, mixed $value): bool
        // ---------------------------------------------------------------
        "curl_setopt" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let option = args.get(1).map(|v| v.to_long() as u32).unwrap_or(0);
            let value = args.get(2).cloned().unwrap_or(Value::Null);
            let curl_val = value_to_curl_value(&value);

            if let Some(handle) = vm.curl_handles.get_mut(&handle_id) {
                let result = php_rs_ext_curl::curl_setopt_raw(handle, option, curl_val);
                Ok(Some(Value::Bool(result)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_setopt_array(CurlHandle $handle, array $options): bool
        // ---------------------------------------------------------------
        "curl_setopt_array" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let options_val = args.get(1).cloned().unwrap_or(Value::Null);

            if let Some(handle) = vm.curl_handles.get_mut(&handle_id) {
                if let Value::Array(ref arr) = options_val {
                    let mut success = true;
                    for (key, val) in arr.entries() {
                        let opt = match key {
                            ArrayKey::Int(i) => *i as u32,
                            ArrayKey::String(s) => {
                                constants::from_name(s).unwrap_or(s.parse().unwrap_or(0))
                            }
                        };
                        let curl_val = value_to_curl_value(val);
                        if !php_rs_ext_curl::curl_setopt_raw(handle, opt, curl_val) {
                            success = false;
                        }
                    }
                    Ok(Some(Value::Bool(success)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_exec(CurlHandle $handle): string|bool
        // ---------------------------------------------------------------
        "curl_exec" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);

            if let Some(handle) = vm.curl_handles.get_mut(&handle_id) {
                match php_rs_ext_curl::curl_exec(handle) {
                    php_rs_ext_curl::CurlResult::Body(body) => Ok(Some(Value::String(body))),
                    php_rs_ext_curl::CurlResult::Bool(b) => Ok(Some(Value::Bool(b))),
                    php_rs_ext_curl::CurlResult::Error(_) => Ok(Some(Value::Bool(false))),
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_close(CurlHandle $handle): void
        // ---------------------------------------------------------------
        "curl_close" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get_mut(&handle_id) {
                php_rs_ext_curl::curl_close(handle);
            }
            vm.curl_handles.remove(&handle_id);
            Ok(Some(Value::Null))
        }

        // ---------------------------------------------------------------
        // curl_getinfo(CurlHandle $handle, ?int $option = null): mixed
        // ---------------------------------------------------------------
        "curl_getinfo" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let opt = args.get(1).and_then(|v| match v {
                Value::Null => None,
                _ => Some(v.to_long() as u32),
            });

            if let Some(handle) = vm.curl_handles.get(&handle_id) {
                match php_rs_ext_curl::curl_getinfo(handle, opt) {
                    php_rs_ext_curl::CurlInfoResult::Single(val) => {
                        Ok(Some(curl_value_to_vm_value(&val)))
                    }
                    php_rs_ext_curl::CurlInfoResult::All(map) => {
                        let mut arr = PhpArray::new();
                        for (key, val) in &map {
                            arr.set_string(key.clone(), curl_value_to_vm_value(val));
                        }
                        Ok(Some(Value::Array(arr)))
                    }
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_errno(CurlHandle $handle): int
        // ---------------------------------------------------------------
        "curl_errno" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get(&handle_id) {
                Ok(Some(
                    Value::Long(php_rs_ext_curl::curl_errno(handle) as i64),
                ))
            } else {
                Ok(Some(Value::Long(0)))
            }
        }

        // ---------------------------------------------------------------
        // curl_error(CurlHandle $handle): string
        // ---------------------------------------------------------------
        "curl_error" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get(&handle_id) {
                Ok(Some(Value::String(php_rs_ext_curl::curl_error(handle))))
            } else {
                Ok(Some(Value::String(String::new())))
            }
        }

        // ---------------------------------------------------------------
        // curl_reset(CurlHandle $handle): void
        // ---------------------------------------------------------------
        "curl_reset" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get_mut(&handle_id) {
                php_rs_ext_curl::curl_reset(handle);
            }
            Ok(Some(Value::Null))
        }

        // ---------------------------------------------------------------
        // curl_copy_handle(CurlHandle $handle): CurlHandle
        // ---------------------------------------------------------------
        "curl_copy_handle" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get(&handle_id) {
                let copy = php_rs_ext_curl::curl_copy_handle(handle);
                let new_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.curl_handles.insert(new_id, copy);
                Ok(Some(Value::Long(new_id)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_version(): array
        // ---------------------------------------------------------------
        "curl_version" => {
            let ver = php_rs_ext_curl::curl_version();
            let mut arr = PhpArray::new();
            arr.set_string("version".to_string(), Value::String(ver.clone()));
            arr.set_string("version_number".to_string(), Value::Long(0x080000));
            arr.set_string("host".to_string(), Value::String("php-rs".to_string()));
            arr.set_string(
                "ssl_version".to_string(),
                Value::String("rustls".to_string()),
            );
            arr.set_string(
                "protocols".to_string(),
                Value::Array({
                    let mut p = PhpArray::new();
                    p.push(Value::String("http".to_string()));
                    p.push(Value::String("https".to_string()));
                    p
                }),
            );
            Ok(Some(Value::Array(arr)))
        }

        // ---------------------------------------------------------------
        // curl_strerror(int $errno): string
        // ---------------------------------------------------------------
        "curl_strerror" => {
            let errno = args.first().map(|v| v.to_long() as u32).unwrap_or(0);
            Ok(Some(Value::String(php_rs_ext_curl::curl_strerror(errno))))
        }

        // ---------------------------------------------------------------
        // curl_multi_init(): CurlMultiHandle
        // ---------------------------------------------------------------
        "curl_multi_init" => {
            let multi = php_rs_ext_curl::CurlMulti::new();
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.curl_multi_handles.insert(id, multi);
            Ok(Some(Value::Long(id)))
        }

        // ---------------------------------------------------------------
        // curl_multi_add_handle(CurlMultiHandle $multi, CurlHandle $handle): int
        // ---------------------------------------------------------------
        "curl_multi_add_handle" => {
            let multi_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let handle_id = args.get(1).map(|v| v.to_long()).unwrap_or(-1);

            // Clone the handle into the multi
            if let Some(handle) = vm.curl_handles.get(&handle_id).cloned() {
                if let Some(multi) = vm.curl_multi_handles.get_mut(&multi_id) {
                    let code = multi.add_handle(handle_id, handle);
                    return Ok(Some(Value::Long(code as i64)));
                }
            }
            Ok(Some(Value::Long(constants::CURLM_BAD_HANDLE as i64)))
        }

        // ---------------------------------------------------------------
        // curl_multi_remove_handle(CurlMultiHandle $multi, CurlHandle $handle): int
        // ---------------------------------------------------------------
        "curl_multi_remove_handle" => {
            let multi_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let handle_id = args.get(1).map(|v| v.to_long()).unwrap_or(-1);

            if let Some(multi) = vm.curl_multi_handles.get_mut(&multi_id) {
                if let Some(updated_handle) = multi.remove_handle(handle_id) {
                    // Update the original handle with the post-exec state
                    vm.curl_handles.insert(handle_id, updated_handle);
                }
                Ok(Some(Value::Long(constants::CURLM_OK as i64)))
            } else {
                Ok(Some(Value::Long(constants::CURLM_BAD_HANDLE as i64)))
            }
        }

        // ---------------------------------------------------------------
        // curl_multi_exec(CurlMultiHandle $multi, int &$still_running): int
        // ---------------------------------------------------------------
        "curl_multi_exec" => {
            let multi_id = args.first().map(|v| v.to_long()).unwrap_or(-1);

            if let Some(multi) = vm.curl_multi_handles.get_mut(&multi_id) {
                let (still_running, err) = multi.exec();

                // Write back $still_running (arg index 1) via ref_args
                vm.write_back_arg(
                    1,
                    Value::Long(still_running as i64),
                    ref_args,
                    ref_prop_args,
                );

                Ok(Some(Value::Long(err as i64)))
            } else {
                Ok(Some(Value::Long(constants::CURLM_BAD_HANDLE as i64)))
            }
        }

        // ---------------------------------------------------------------
        // curl_multi_info_read(CurlMultiHandle $multi): array|false
        // ---------------------------------------------------------------
        "curl_multi_info_read" => {
            let multi_id = args.first().map(|v| v.to_long()).unwrap_or(-1);

            if let Some(multi) = vm.curl_multi_handles.get_mut(&multi_id) {
                if let Some(msg) = multi.info_read() {
                    let mut arr = PhpArray::new();
                    arr.set_string("msg".to_string(), Value::Long(1)); // CURLMSG_DONE
                    arr.set_string("result".to_string(), Value::Long(msg.result as i64));
                    arr.set_string("handle".to_string(), Value::Long(msg.handle_id));
                    Ok(Some(Value::Array(arr)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_multi_close(CurlMultiHandle $multi): void
        // ---------------------------------------------------------------
        "curl_multi_close" => {
            let multi_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            vm.curl_multi_handles.remove(&multi_id);
            Ok(Some(Value::Null))
        }

        // ---------------------------------------------------------------
        // curl_multi_getcontent(CurlHandle $handle): ?string
        // ---------------------------------------------------------------
        "curl_multi_getcontent" => {
            let handle_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            if let Some(handle) = vm.curl_handles.get(&handle_id) {
                if handle.return_transfer {
                    Ok(Some(Value::String(handle.response_body.clone())))
                } else {
                    Ok(Some(Value::Null))
                }
            } else {
                Ok(Some(Value::Null))
            }
        }

        // ---------------------------------------------------------------
        // curl_multi_strerror(int $errno): string
        // ---------------------------------------------------------------
        "curl_multi_strerror" => {
            let errno = args.first().map(|v| v.to_long() as u32).unwrap_or(0);
            let msg = match errno {
                constants::CURLM_OK => "No error",
                constants::CURLM_BAD_HANDLE => "Invalid multi handle",
                _ => "Unknown error",
            };
            Ok(Some(Value::String(msg.to_string())))
        }

        // ---------------------------------------------------------------
        // curl_share_init(): CurlShareHandle
        // ---------------------------------------------------------------
        "curl_share_init" => {
            let share = php_rs_ext_curl::CurlShare::new();
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.curl_share_handles.insert(id, share);
            Ok(Some(Value::Long(id)))
        }

        // ---------------------------------------------------------------
        // curl_share_setopt(CurlShareHandle $share, int $option, mixed $value): bool
        // ---------------------------------------------------------------
        "curl_share_setopt" => {
            let share_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            let option = args.get(1).map(|v| v.to_long() as u32).unwrap_or(0);
            let value = args.get(2).map(|v| v.to_long() as u32).unwrap_or(0);

            if let Some(share) = vm.curl_share_handles.get_mut(&share_id) {
                let result = share.setopt(option, value);
                Ok(Some(Value::Bool(result == constants::CURLE_OK)))
            } else {
                Ok(Some(Value::Bool(false)))
            }
        }

        // ---------------------------------------------------------------
        // curl_share_close(CurlShareHandle $share): void
        // ---------------------------------------------------------------
        "curl_share_close" => {
            let share_id = args.first().map(|v| v.to_long()).unwrap_or(-1);
            vm.curl_share_handles.remove(&share_id);
            Ok(Some(Value::Null))
        }

        // ---------------------------------------------------------------
        // curl_share_strerror(int $errno): string
        // ---------------------------------------------------------------
        "curl_share_strerror" => {
            let errno = args.first().map(|v| v.to_long() as u32).unwrap_or(0);
            let msg = match errno {
                0 => "No error",
                _ => "Unknown share error",
            };
            Ok(Some(Value::String(msg.to_string())))
        }

        _ => Ok(None),
    }
}

/// Fallback for non-native-io builds.
#[cfg(not(feature = "native-io"))]
pub(crate) fn dispatch(
    _vm: &mut Vm,
    _name: &str,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    Ok(None)
}

// ===========================================================================
// Helper functions
// ===========================================================================

#[cfg(feature = "native-io")]
fn value_to_curl_value(value: &Value) -> php_rs_ext_curl::CurlValue {
    match value {
        Value::Bool(b) => php_rs_ext_curl::CurlValue::Bool(*b),
        Value::Long(l) => php_rs_ext_curl::CurlValue::Long(*l),
        Value::String(s) => php_rs_ext_curl::CurlValue::Str(s.clone()),
        Value::Double(d) => php_rs_ext_curl::CurlValue::Long(*d as i64),
        Value::Array(arr) => {
            // Check if any value is a CURLFile object
            let mut has_string_keys = false;
            for (key, _) in arr.entries() {
                if matches!(key, ArrayKey::String(_)) {
                    has_string_keys = true;
                    break;
                }
            }
            if has_string_keys {
                // Associative array → multipart form data
                let pairs: Vec<(String, String)> = arr
                    .entries()
                    .iter()
                    .map(|(k, v)| {
                        let key = match k {
                            ArrayKey::String(s) => s.clone(),
                            ArrayKey::Int(i) => i.to_string(),
                        };
                        (key, v.to_php_string())
                    })
                    .collect();
                php_rs_ext_curl::CurlValue::AssocArray(pairs)
            } else {
                // Numeric array → list of strings (for headers etc.)
                let strings: Vec<String> = arr
                    .entries()
                    .iter()
                    .map(|(_, v)| v.to_php_string())
                    .collect();
                php_rs_ext_curl::CurlValue::Array(strings)
            }
        }
        Value::Null => php_rs_ext_curl::CurlValue::Null,
        _ => php_rs_ext_curl::CurlValue::Str(value.to_php_string()),
    }
}

#[cfg(feature = "native-io")]
fn curl_value_to_vm_value(val: &php_rs_ext_curl::CurlValue) -> Value {
    match val {
        php_rs_ext_curl::CurlValue::Bool(b) => Value::Bool(*b),
        php_rs_ext_curl::CurlValue::Long(l) => Value::Long(*l),
        php_rs_ext_curl::CurlValue::Str(s) => Value::String(s.clone()),
        php_rs_ext_curl::CurlValue::Double(d) => Value::Double(*d),
        php_rs_ext_curl::CurlValue::Array(arr) => {
            let mut php_arr = PhpArray::new();
            for s in arr {
                php_arr.push(Value::String(s.clone()));
            }
            Value::Array(php_arr)
        }
        php_rs_ext_curl::CurlValue::AssocArray(arr) => {
            let mut php_arr = PhpArray::new();
            for (k, v) in arr {
                php_arr.set_string(k.clone(), Value::String(v.clone()));
            }
            Value::Array(php_arr)
        }
        php_rs_ext_curl::CurlValue::Null => Value::Null,
    }
}
