//! Type checking and introspection built-in functions.

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

pub(crate) fn register(r: &mut super::BuiltinRegistry) {
    r.insert("is_int", php_is_int);
    r.insert("is_integer", php_is_int);
    r.insert("is_long", php_is_int);
    r.insert("is_float", php_is_float);
    r.insert("is_double", php_is_float);
    r.insert("is_string", php_is_string);
    r.insert("is_bool", php_is_bool);
    r.insert("is_null", php_is_null);
    r.insert("is_array", php_is_array);
    r.insert("is_numeric", php_is_numeric);
    r.insert("is_object", php_is_object);
    r.insert("is_resource", php_is_resource);
    r.insert("is_callable", php_is_callable);
    r.insert("gettype", php_gettype);
    r.insert("get_debug_type", php_get_debug_type);
    r.insert("settype", php_settype);
    r.insert("intval", php_intval);
    r.insert("floatval", php_floatval);
    r.insert("doubleval", php_floatval);
    r.insert("strval", php_strval);
    r.insert("boolval", php_boolval);
    r.insert("get_class", php_get_class);
    r.insert("get_parent_class", php_get_parent_class);
    r.insert("get_object_vars", php_get_object_vars);
    r.insert("get_class_methods", php_get_class_methods);
    r.insert("get_class_vars", php_get_class_vars);
    r.insert("class_exists", php_class_exists);
    r.insert("method_exists", php_method_exists);
    r.insert("property_exists", php_property_exists);
    r.insert("interface_exists", php_interface_exists);
    r.insert("trait_exists", php_trait_exists);
    r.insert("is_a", php_is_a);
    r.insert("is_subclass_of", php_is_subclass_of);
    r.insert("get_defined_vars", php_get_defined_vars);
    r.insert("get_defined_functions", php_get_defined_functions);
    r.insert("get_defined_constants", php_get_defined_constants);
    r.insert("class_alias", php_class_alias);
    r.insert("class_parents", php_class_parents);
    r.insert("class_implements", php_class_implements);
    r.insert("class_uses", php_class_uses);
    r.insert("function_exists", php_function_exists);
}

fn deref(v: &Value) -> Value {
    v.deref_value()
}

pub(crate) fn php_is_int(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Long(_))))
}

pub(crate) fn php_is_float(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Double(_))))
}

pub(crate) fn php_is_string(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::String(_))))
}

pub(crate) fn php_is_bool(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Bool(_))))
}

pub(crate) fn php_is_null(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Null)))
}

pub(crate) fn php_is_array(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Array(_))))
}

pub(crate) fn php_is_numeric(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    let result = match &v {
        Value::Long(_) | Value::Double(_) => true,
        Value::String(s) => is_numeric_string(s),
        _ => false,
    };
    Ok(Value::Bool(result))
}

fn is_numeric_string(s: &str) -> bool {
    let s = s.trim_start();
    if s.is_empty() {
        return false;
    }

    // PHP 7+: hex strings like "0xFF" are NOT numeric

    // Try parsing as integer or float
    let s_check = if s.starts_with('+') || s.starts_with('-') {
        &s[1..]
    } else {
        s
    };
    if s_check.is_empty() {
        return false;
    }

    // Try integer
    if s.parse::<i64>().is_ok() {
        return true;
    }
    // Try float
    if s.parse::<f64>().is_ok() {
        return true;
    }
    false
}

pub(crate) fn php_is_object(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Object(_))))
}

pub(crate) fn php_is_resource(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(matches!(deref(&v), Value::Resource(_, _))))
}

pub(crate) fn php_is_callable(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    let result = match &v {
        Value::String(name) => {
            let lc = name.to_lowercase();
            vm.functions.contains_key(&lc) || vm.functions.contains_key(name.as_str())
        }
        Value::Object(obj) => {
            let cn = obj.class_name();
            cn == "Closure" || cn == "closure"
        }
        Value::Array(arr) => {
            // [object_or_class, "method"] form
            let entries = arr.entries();
            if entries.len() == 2 {
                let method = entries[1].1.to_php_string();
                let class_name = match &entries[0].1 {
                    Value::Object(obj) => Some(obj.class_name()),
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                };
                if let Some(cn) = class_name {
                    let lc = cn.to_lowercase();
                    vm.classes
                        .get(&lc)
                        .or_else(|| vm.classes.get(&cn))
                        .map(|def| {
                            let lm = method.to_lowercase();
                            def.methods.contains_key(&lm) || def.methods.contains_key(&method)
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    };
    Ok(Value::Bool(result))
}

pub(crate) fn php_gettype(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    let name = match &v {
        Value::Null => "NULL",
        Value::Bool(_) => "boolean",
        Value::Long(_) => "integer",
        Value::Double(_) => "double",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Resource(_, _) => "resource",
        _ => "unknown type",
    };
    Ok(Value::String(name.to_string()))
}

pub(crate) fn php_get_debug_type(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    let name = match &v {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Long(_) => "int".to_string(),
        Value::Double(_) => "float".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Object(obj) => obj.class_name(),
        Value::Resource(_, ty) => {
            if ty.is_empty() || ty == "Unknown" {
                "resource (closed)".to_string()
            } else {
                format!("resource ({})", ty)
            }
        }
        _ => "unknown".to_string(),
    };
    Ok(Value::String(name))
}

pub(crate) fn php_settype(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }
    let val = deref(&args[0]);
    let type_name = args[1].to_php_string();

    let converted = match type_name.as_str() {
        "int" | "integer" => Value::Long(val.to_long()),
        "float" | "double" => Value::Double(val.to_double()),
        "string" => Value::String(val.to_php_string()),
        "bool" | "boolean" => Value::Bool(val.to_bool()),
        "array" => match val {
            Value::Array(_) => val,
            Value::Object(ref obj) => {
                let mut arr = PhpArray::new();
                for (k, v) in obj.properties() {
                    arr.set_string(k, v);
                }
                Value::Array(arr)
            }
            Value::Null => Value::Array(PhpArray::new()),
            other => {
                let mut arr = PhpArray::new();
                arr.push(other);
                Value::Array(arr)
            }
        },
        "object" => match val {
            Value::Object(_) => val,
            Value::Array(ref arr) => {
                let obj = PhpObject::new("stdClass".to_string());
                for (k, v) in arr.entries() {
                    let prop_name = match k {
                        ArrayKey::Int(i) => i.to_string(),
                        ArrayKey::String(s) => s.clone(),
                    };
                    obj.set_property(prop_name, v.clone());
                }
                Value::Object(obj)
            }
            Value::Null => Value::Object(PhpObject::new("stdClass".to_string())),
            _ => {
                let obj = PhpObject::new("stdClass".to_string());
                obj.set_property("scalar".to_string(), val);
                Value::Object(obj)
            }
        },
        "null" => Value::Null,
        _ => return Ok(Value::Bool(false)),
    };

    // Write back to ref if possible
    if let Some(Value::Reference(rc)) = args.first() {
        *rc.borrow_mut() = converted;
    } else {
        // Write back via CV ref_args mechanism
        _vm.write_back_arg(0, converted, _ref_args, _ref_prop_args);
    }

    Ok(Value::Bool(true))
}

pub(crate) fn php_intval(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    let base = args.get(1).map(|b| deref(b).to_long() as u32).unwrap_or(10);

    let result = if base != 10 {
        if let Value::String(ref s) = v {
            let s = s.trim_start();
            // Strip leading 0x/0X for base 16, 0b/0B for base 2, 0o/0O for base 8
            let s = if s.len() >= 2 {
                match (s.as_bytes()[0], s.as_bytes()[1]) {
                    (b'0', b'x' | b'X') if base == 16 => &s[2..],
                    (b'0', b'b' | b'B') if base == 2 => &s[2..],
                    (b'0', b'o' | b'O') if base == 8 => &s[2..],
                    _ => s,
                }
            } else {
                s
            };
            // Handle negative sign
            let (neg, s) = if s.starts_with('-') {
                (true, &s[1..])
            } else if s.starts_with('+') {
                (false, &s[1..])
            } else {
                (false, s)
            };
            // Parse valid prefix in given base
            let mut result: i64 = 0;
            for ch in s.chars() {
                let digit = match ch.to_ascii_lowercase() {
                    '0'..='9' => (ch as u8 - b'0') as u32,
                    'a'..='z' => (ch as u8 - b'a' + 10) as u32,
                    _ => break,
                };
                if digit >= base {
                    break;
                }
                result = result.wrapping_mul(base as i64).wrapping_add(digit as i64);
            }
            if neg {
                -result
            } else {
                result
            }
        } else {
            v.to_long()
        }
    } else {
        v.to_long()
    };
    Ok(Value::Long(result))
}

pub(crate) fn php_floatval(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Double(deref(&v).to_double()))
}

pub(crate) fn php_strval(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::String(deref(&v).to_php_string()))
}

pub(crate) fn php_boolval(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    Ok(Value::Bool(deref(&v).to_bool()))
}

pub(crate) fn php_get_class(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.is_empty() {
        // No args: return current class name from call stack
        if let Some(frame) = vm.call_stack.last() {
            let oa = &vm.op_arrays[frame.op_array_idx];
            if let Some(ref func_name) = oa.function_name {
                if let Some(idx) = func_name.find("::") {
                    return Ok(Value::String(func_name[..idx].to_string()));
                }
            }
        }
        return Ok(Value::Bool(false));
    }

    let v = deref(&args[0]);
    match &v {
        Value::Object(obj) => Ok(Value::String(obj.class_name())),
        _ => Ok(Value::Bool(false)),
    }
}

pub(crate) fn php_get_parent_class(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = if args.is_empty() {
        let cn = vm.call_stack.last().and_then(|frame| {
            let oa = &vm.op_arrays[frame.op_array_idx];
            oa.function_name
                .as_ref()
                .and_then(|name| name.find("::").map(|idx| name[..idx].to_string()))
        });
        match cn {
            Some(n) => n,
            None => return Ok(Value::Bool(false)),
        }
    } else {
        let v = deref(&args[0]);
        match &v {
            Value::Object(obj) => obj.class_name(),
            Value::String(s) => s.clone(),
            _ => return Ok(Value::Bool(false)),
        }
    };

    let lc = class_name.to_lowercase();
    if let Some(def) = vm.classes.get(&lc).or_else(|| vm.classes.get(&class_name)) {
        if let Some(ref parent) = def.parent {
            return Ok(Value::String(parent.clone()));
        }
    }
    Ok(Value::Bool(false))
}

pub(crate) fn php_get_object_vars(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().cloned().unwrap_or(Value::Null);
    let v = deref(&v);
    match &v {
        Value::Object(obj) => {
            let mut arr = PhpArray::new();
            for (k, v) in obj.properties() {
                arr.set_string(k, v);
            }
            Ok(Value::Array(arr))
        }
        _ => Ok(Value::Bool(false)),
    }
}

pub(crate) fn php_get_class_methods(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = match args.first() {
        Some(v) => {
            let v = deref(v);
            match &v {
                Value::Object(obj) => obj.class_name(),
                Value::String(s) => s.clone(),
                _ => return Ok(Value::Array(PhpArray::new())),
            }
        }
        None => return Ok(Value::Array(PhpArray::new())),
    };

    let lc = class_name.to_lowercase();
    if let Some(def) = vm.classes.get(&lc).or_else(|| vm.classes.get(&class_name)) {
        let mut arr = PhpArray::new();
        for name in def.methods.keys() {
            arr.push(Value::String(name.clone()));
        }
        Ok(Value::Array(arr))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

pub(crate) fn php_get_class_vars(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = args
        .first()
        .map(|v| deref(v).to_php_string())
        .unwrap_or_default();

    let lc = class_name.to_lowercase();
    if let Some(def) = vm.classes.get(&lc).or_else(|| vm.classes.get(&class_name)) {
        let mut arr = PhpArray::new();
        for (k, v) in &def.default_properties {
            arr.set_string(k.clone(), v.clone());
        }
        Ok(Value::Array(arr))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

pub(crate) fn php_class_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args
        .first()
        .map(|v| deref(v).to_php_string())
        .unwrap_or_default();
    let lc = name.to_lowercase();
    Ok(Value::Bool(
        vm.classes.contains_key(&lc) || vm.classes.contains_key(&name),
    ))
}

pub(crate) fn php_method_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let class_name = {
        let v = deref(&args[0]);
        match &v {
            Value::Object(obj) => obj.class_name(),
            Value::String(s) => s.clone(),
            _ => return Ok(Value::Bool(false)),
        }
    };
    let method = deref(&args[1]).to_php_string().to_lowercase();
    let lc = class_name.to_lowercase();

    if let Some(def) = vm.classes.get(&lc).or_else(|| vm.classes.get(&class_name)) {
        Ok(Value::Bool(def.methods.contains_key(&method)))
    } else {
        Ok(Value::Bool(false))
    }
}

pub(crate) fn php_property_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let class_name = {
        let v = deref(&args[0]);
        match &v {
            Value::Object(obj) => obj.class_name(),
            Value::String(s) => s.clone(),
            _ => return Ok(Value::Bool(false)),
        }
    };
    let prop = deref(&args[1]).to_php_string();
    let lc = class_name.to_lowercase();

    if let Some(def) = vm.classes.get(&lc).or_else(|| vm.classes.get(&class_name)) {
        Ok(Value::Bool(def.default_properties.contains_key(&prop)))
    } else {
        Ok(Value::Bool(false))
    }
}

pub(crate) fn php_interface_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args
        .first()
        .map(|v| deref(v).to_php_string())
        .unwrap_or_default();
    let lc = name.to_lowercase();
    Ok(Value::Bool(
        vm.classes.contains_key(&lc) || vm.classes.contains_key(&name),
    ))
}

pub(crate) fn php_trait_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args
        .first()
        .map(|v| deref(v).to_php_string())
        .unwrap_or_default();
    let lc = name.to_lowercase();
    Ok(Value::Bool(
        vm.classes.contains_key(&lc) || vm.classes.contains_key(&name),
    ))
}

pub(crate) fn php_is_a(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let class_name = {
        let v = deref(&args[0]);
        match &v {
            Value::Object(obj) => obj.class_name(),
            Value::String(s) => s.clone(),
            _ => return Ok(Value::Bool(false)),
        }
    };
    let target = deref(&args[1]).to_php_string();
    let target_lc = target.to_lowercase();

    // Check self
    if class_name.to_lowercase() == target_lc {
        return Ok(Value::Bool(true));
    }

    // Walk parent chain
    let mut current = class_name.to_lowercase();
    loop {
        let def = vm.classes.get(&current).cloned();
        match def {
            Some(def) => {
                // Check interfaces
                for iface in &def.interfaces {
                    if iface.to_lowercase() == target_lc {
                        return Ok(Value::Bool(true));
                    }
                }
                match &def.parent {
                    Some(parent) => {
                        let parent_lc = parent.to_lowercase();
                        if parent_lc == target_lc {
                            return Ok(Value::Bool(true));
                        }
                        current = parent_lc;
                    }
                    None => break,
                }
            }
            None => break,
        }
    }
    Ok(Value::Bool(false))
}

pub(crate) fn php_is_subclass_of(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let class_name = {
        let v = deref(&args[0]);
        match &v {
            Value::Object(obj) => obj.class_name(),
            Value::String(s) => s.clone(),
            _ => return Ok(Value::Bool(false)),
        }
    };
    let target = deref(&args[1]).to_php_string();
    let target_lc = target.to_lowercase();

    // Unlike is_a, do NOT match self
    let mut current = class_name.to_lowercase();
    loop {
        let def = vm.classes.get(&current).cloned();
        match def {
            Some(def) => {
                // Check interfaces
                for iface in &def.interfaces {
                    if iface.to_lowercase() == target_lc {
                        return Ok(Value::Bool(true));
                    }
                }
                match &def.parent {
                    Some(parent) => {
                        let parent_lc = parent.to_lowercase();
                        if parent_lc == target_lc {
                            return Ok(Value::Bool(true));
                        }
                        current = parent_lc;
                    }
                    None => break,
                }
            }
            None => break,
        }
    }
    Ok(Value::Bool(false))
}

pub(crate) fn php_get_defined_vars(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    if let Some(frame) = vm.call_stack.last() {
        let oa = &vm.op_arrays[frame.op_array_idx];
        for (i, name) in oa.vars.iter().enumerate() {
            if i < frame.cvs.len() {
                let val = frame.cvs[i].deref_value();
                arr.set_string(name.clone(), val);
            }
        }
    }
    Ok(Value::Array(arr))
}

pub(crate) fn php_get_defined_functions(
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

pub(crate) fn php_get_defined_constants(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut arr = PhpArray::new();
    for (k, v) in &vm.constants {
        arr.set_string(k.clone(), v.clone());
    }
    Ok(Value::Array(arr))
}

pub(crate) fn php_class_alias(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }
    let original = deref(&args[0]).to_php_string();
    let alias = deref(&args[1]).to_php_string();

    let lc = original.to_lowercase();
    let def = vm
        .classes
        .get(&lc)
        .or_else(|| vm.classes.get(&original))
        .cloned();
    match def {
        Some(class_def) => {
            let alias_lc = alias.to_lowercase();
            vm.classes.insert(alias_lc, class_def);
            Ok(Value::Bool(true))
        }
        None => Ok(Value::Bool(false)),
    }
}

pub(crate) fn php_class_parents(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = match args.first() {
        Some(v) => {
            let v = deref(v);
            match &v {
                Value::Object(obj) => obj.class_name(),
                Value::String(s) => s.clone(),
                _ => return Ok(Value::Bool(false)),
            }
        }
        None => return Ok(Value::Bool(false)),
    };

    let mut arr = PhpArray::new();
    let mut current = class_name.clone();
    loop {
        let def = vm
            .classes
            .get(&current)
            .or_else(|| vm.classes.get(&current.to_lowercase()))
            .cloned();
        match def {
            Some(def) => match &def.parent {
                Some(parent) => {
                    arr.set_string(parent.clone(), Value::String(parent.clone()));
                    current = parent.clone();
                }
                None => break,
            },
            None => break,
        }
    }
    Ok(Value::Array(arr))
}

pub(crate) fn php_class_implements(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = match args.first() {
        Some(v) => {
            let v = deref(v);
            match &v {
                Value::Object(obj) => obj.class_name(),
                Value::String(s) => s.clone(),
                _ => return Ok(Value::Bool(false)),
            }
        }
        None => return Ok(Value::Bool(false)),
    };

    let mut arr = PhpArray::new();
    let mut current = Some(class_name.clone());
    while let Some(cn) = current {
        let def = vm
            .classes
            .get(&cn)
            .or_else(|| vm.classes.get(&cn.to_lowercase()))
            .cloned();
        match def {
            Some(def) => {
                for iface in &def.interfaces {
                    arr.set_string(iface.clone(), Value::String(iface.clone()));
                }
                current = def.parent.clone();
            }
            None => break,
        }
    }
    Ok(Value::Array(arr))
}

pub(crate) fn php_class_uses(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let class_name = match args.first() {
        Some(v) => {
            let v = deref(v);
            match &v {
                Value::Object(obj) => obj.class_name(),
                Value::String(s) => s.clone(),
                _ => return Ok(Value::Bool(false)),
            }
        }
        None => return Ok(Value::Bool(false)),
    };

    if let Some(def) = vm
        .classes
        .get(&class_name)
        .or_else(|| vm.classes.get(&class_name.to_lowercase()))
    {
        let mut arr = PhpArray::new();
        for tr in &def.traits {
            arr.set_string(tr.clone(), Value::String(tr.clone()));
        }
        Ok(Value::Array(arr))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

pub(crate) fn php_function_exists(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args
        .first()
        .map(|v| deref(v).to_php_string())
        .unwrap_or_default();
    let lc = name.to_lowercase();
    Ok(Value::Bool(
        vm.functions.contains_key(&lc) || vm.functions.contains_key(&name),
    ))
}
