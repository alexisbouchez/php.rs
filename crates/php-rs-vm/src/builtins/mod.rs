//! Built-in function registry for the PHP VM.
//!
//! Each submodule registers its functions into a `BuiltinRegistry` HashMap.
//! The VM's `call_builtin` consults this registry before falling through
//! to the inline match arms.

use std::collections::HashMap;

use crate::value::Value;
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

/// Signature for a built-in PHP function implemented in Rust.
pub(crate) type BuiltinFn = fn(
    &mut Vm,
    &[Value],
    &[(usize, OperandType, u32)],
    &[(usize, Value, String)],
) -> VmResult<Value>;

/// Map of function name → handler.
pub(crate) type BuiltinRegistry = HashMap<&'static str, BuiltinFn>;

pub(crate) mod arrays;
pub(crate) mod curl;
pub(crate) mod date;
pub(crate) mod file;
pub(crate) mod json;
pub(crate) mod math;
pub(crate) mod misc;
pub(crate) mod mysqli;
pub(crate) mod output;
pub(crate) mod pcre;
pub(crate) mod remaining;
pub(crate) mod strings;
pub(crate) mod type_check;

/// Build and return the full built-in function registry.
pub(crate) fn build_registry() -> BuiltinRegistry {
    let mut r = BuiltinRegistry::new();
    arrays::register(&mut r);
    date::register(&mut r);
    misc::register(&mut r);
    mysqli::register(&mut r);
    type_check::register(&mut r);
    r
}
