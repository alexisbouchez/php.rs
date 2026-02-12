#![allow(unused_variables, unused_mut, unreachable_patterns, unused_imports)]

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

/// Dispatch a built-in output function call.
/// Returns `Ok(Some(value))` if handled, `Ok(None)` if not recognized.
pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "var_dump" => {
            for arg in args {
                vm.var_dump(arg, 0);
            }
            Ok(Some(Value::Null))
        }
        "print_r" => {
            let val = args.first().cloned().unwrap_or(Value::Null);
            let ret_string = args.get(1).is_some_and(|v| v.to_bool());
            let s = vm.print_r_string(&val, 0);
            if ret_string {
                Ok(Some(Value::String(s)))
            } else {
                vm.write_output(&s);
                Ok(Some(Value::Bool(true)))
            }
        }
        _ => Ok(None),
    }
}
