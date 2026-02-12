#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmError, VmResult};
use php_rs_compiler::op::OperandType;
use php_rs_ext_json::{self, JsonValue};

/// Dispatch a built-in json function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "json_encode" => {
            let val = args.first().cloned().unwrap_or(Value::Null);
            let options = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as u32;
            let depth = args.get(2).cloned().unwrap_or(Value::Long(512)).to_long() as usize;
            let throw_on_error = options & php_rs_ext_json::JSON_THROW_ON_ERROR != 0;

            // Check if object implements JsonSerializable
            let val_to_encode = if let Value::Object(ref o) = val {
                if vm.implements_interface(&o.class_name(), "JsonSerializable") {
                    match vm.call_method_sync(&val, "jsonSerialize") {
                        Ok(result) => result,
                        Err(_) => val.clone(),
                    }
                } else {
                    val.clone()
                }
            } else {
                val.clone()
            };

            let json_val = Vm::value_to_json(&val_to_encode);
            match php_rs_ext_json::json_encode_with_depth(&json_val, options, depth) {
                Some(s) => Ok(Some(Value::String(s))),
                None => {
                    if throw_on_error {
                        let msg = php_rs_ext_json::json_last_error_msg().to_string();
                        let exc = vm.create_error_object("JsonException", msg);
                        return Err(VmError::Thrown(exc));
                    }
                    Ok(Some(Value::Bool(false)))
                }
            }
        }
        "json_decode" => {
            let json_str = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let assoc = args.get(1).is_some_and(|v| v.to_bool());
            let depth = args.get(2).cloned().unwrap_or(Value::Long(512)).to_long() as usize;
            let options = args.get(3).cloned().unwrap_or(Value::Long(0)).to_long() as u32;
            let throw_on_error = options & php_rs_ext_json::JSON_THROW_ON_ERROR != 0;

            match php_rs_ext_json::json_decode(&json_str, assoc, depth) {
                Some(jv) => Ok(Some(Vm::json_to_value(&jv, assoc))),
                None => {
                    if throw_on_error {
                        let msg = php_rs_ext_json::json_last_error_msg().to_string();
                        let exc = vm.create_error_object("JsonException", msg);
                        return Err(VmError::Thrown(exc));
                    }
                    Ok(Some(Value::Null))
                }
            }
        }
        "json_last_error" => Ok(Some(Value::Long(php_rs_ext_json::json_last_error() as i64))),
        "json_last_error_msg" => Ok(Some(Value::String(
            php_rs_ext_json::json_last_error_msg().to_string(),
        ))),
        "json_validate" => {
            let json_str = args.first().cloned().unwrap_or(Value::Null).to_php_string();
            let depth = args.get(1).cloned().unwrap_or(Value::Long(512)).to_long() as usize;
            let valid = php_rs_ext_json::json_decode(&json_str, false, depth).is_some()
                && php_rs_ext_json::json_last_error() == php_rs_ext_json::JsonError::None;
            Ok(Some(Value::Bool(valid)))
        }
        _ => Ok(None),
    }
}
