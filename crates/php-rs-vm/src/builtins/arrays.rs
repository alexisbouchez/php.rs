use crate::builtins::BuiltinRegistry;
use crate::value::{ArrayKey, PhpArray, Value};
use crate::vm::{nat_cmp, Vm, VmResult};
use php_rs_compiler::op::OperandType;

pub(crate) fn register(r: &mut BuiltinRegistry) {
    r.insert("count", php_count);
    r.insert("sizeof", php_count);
    r.insert("array_push", php_array_push);
    r.insert("array_key_exists", php_array_key_exists);
    r.insert("key_exists", php_array_key_exists);
    r.insert("in_array", php_in_array);
    r.insert("array_search", php_array_search);
    r.insert("array_keys", php_array_keys);
    r.insert("array_values", php_array_values);
    r.insert("array_merge", php_array_merge);
    r.insert("array_merge_recursive", php_array_merge_recursive);
    r.insert("array_reverse", php_array_reverse);
    r.insert("array_slice", php_array_slice);
    r.insert("array_splice", php_array_splice);
    r.insert("array_unique", php_array_unique);
    r.insert("array_flip", php_array_flip);
    r.insert("array_combine", php_array_combine);
    r.insert("array_sum", php_array_sum);
    r.insert("array_product", php_array_product);
    r.insert("array_count_values", php_array_count_values);
    r.insert("array_column", php_array_column);
    r.insert("array_chunk", php_array_chunk);
    r.insert("array_pad", php_array_pad);
    r.insert("array_rand", php_array_rand);
    r.insert("array_fill", php_array_fill);
    r.insert("array_fill_keys", php_array_fill_keys);
    r.insert("array_intersect", php_array_intersect);
    r.insert("array_intersect_key", php_array_intersect_key);
    r.insert("array_intersect_assoc", php_array_intersect_assoc);
    r.insert("array_diff", php_array_diff);
    r.insert("array_diff_key", php_array_diff_key);
    r.insert("array_diff_assoc", php_array_diff_assoc);
    r.insert("array_map", php_array_map);
    r.insert("array_filter", php_array_filter);
    r.insert("array_walk", php_array_walk);
    r.insert("array_walk_recursive", php_array_walk_recursive);
    r.insert("array_reduce", php_array_reduce);
    r.insert("sort", php_sort);
    r.insert("rsort", php_rsort);
    r.insert("asort", php_asort);
    r.insert("arsort", php_arsort);
    r.insert("ksort", php_ksort);
    r.insert("krsort", php_krsort);
    r.insert("usort", php_usort);
    r.insert("uasort", php_uasort);
    r.insert("uksort", php_uksort);
    r.insert("array_multisort", php_array_multisort);
    r.insert("compact", php_compact);
    r.insert("extract", php_extract);
    r.insert("list", php_list);
    r.insert("range", php_range);
    r.insert("current", php_current);
    r.insert("pos", php_current);
    r.insert("next", php_next);
    r.insert("prev", php_prev);
    r.insert("end", php_end);
    r.insert("reset", php_reset);
    r.insert("key", php_key);
    r.insert("array_key_first", php_array_key_first);
    r.insert("array_key_last", php_array_key_last);
    r.insert("array_is_list", php_array_is_list);
    r.insert("array_replace", php_array_replace);
    r.insert("array_replace_recursive", php_array_replace_recursive);
    r.insert("shuffle", php_shuffle);
    r.insert("array_pop", php_array_pop);
    r.insert("array_shift", php_array_shift);
    r.insert("array_unshift", php_array_unshift);
    r.insert("array_all", php_array_all);
    r.insert("array_any", php_array_any);
    r.insert("array_find", php_array_find);
    r.insert("array_find_key", php_array_find_key);
    r.insert("array_first", php_array_first);
    r.insert("array_last", php_array_last);
    r.insert("array_change_key_case", php_array_change_key_case);
    r.insert("natsort", php_natsort);
    r.insert("natcasesort", php_natcasesort);
    // NOTE: array_diff_u*/array_udiff*/array_uintersect* are NOT registered here
    // because php_array_diff_ucb needs the actual PHP function name to determine
    // comparison semantics, and that name is not available through the registry
    // signature. These remain as inline match arms in call_builtin for now.
}

// ---------------------------------------------------------------------------
// count / sizeof
// ---------------------------------------------------------------------------

fn php_count(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let v = args.first().map(|v| v.deref_value()).unwrap_or(Value::Null);
    let n = match &v {
        Value::Array(a) => a.len() as i64,
        Value::Object(_) => {
            // Try calling count() method for Countable objects
            let class_name = match &v {
                Value::Object(ref o) => o.class_name(),
                _ => unreachable!(),
            };
            let method_key = format!("{}::count", class_name);
            if let Ok(Some(result)) = vm.call_builtin_method(&method_key, &[v.clone()]) {
                result.to_long()
            } else if let Ok(result) = vm.call_method_sync(&v, "count") {
                result.to_long()
            } else {
                1
            }
        }
        _ => 1,
    };
    Ok(Value::Long(n))
}

// ---------------------------------------------------------------------------
// array_push
// ---------------------------------------------------------------------------

fn php_array_push(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr_val = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Reference(rc) = &arr_val {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            for val in &args[1..] {
                a.push(val.clone());
            }
            return Ok(Value::Long(a.len() as i64));
        }
        return Ok(Value::Long(0));
    }
    if let Value::Array(ref a) = arr_val {
        let mut new_arr = a.clone();
        for val in &args[1..] {
            new_arr.push(val.clone());
        }
        let count = new_arr.len() as i64;
        vm.write_back_arg(0, Value::Array(new_arr), ref_args, ref_prop_args);
        return Ok(Value::Long(count));
    }
    Ok(Value::Long(0))
}

// ---------------------------------------------------------------------------
// array_key_exists / key_exists
// ---------------------------------------------------------------------------

fn php_array_key_exists(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let key = args.first().map(|v| v.deref_value()).unwrap_or(Value::Null);
    let arr = args.get(1).map(|v| v.deref_value()).unwrap_or(Value::Null);
    let exists = if let Value::Array(ref a) = arr {
        a.get(&key).is_some()
    } else {
        false
    };
    Ok(Value::Bool(exists))
}

// ---------------------------------------------------------------------------
// in_array
// ---------------------------------------------------------------------------

fn php_in_array(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let needle = args.first().cloned().unwrap_or(Value::Null);
    let haystack = args.get(1).cloned().unwrap_or(Value::Null);
    let strict = args.get(2).is_some_and(|v| v.to_bool());
    let found = if let Value::Array(ref a) = haystack {
        a.entries().iter().any(|(_, v)| {
            if strict {
                needle.strict_eq(v)
            } else {
                needle.loose_eq(v)
            }
        })
    } else {
        false
    };
    Ok(Value::Bool(found))
}

// ---------------------------------------------------------------------------
// array_search
// ---------------------------------------------------------------------------

fn php_array_search(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let needle = args.first().cloned().unwrap_or(Value::Null);
    let haystack = args.get(1).cloned().unwrap_or(Value::Null);
    let strict = args.get(2).is_some_and(|v| v.to_bool());
    if let Value::Array(ref a) = haystack {
        for (key, val) in a.entries() {
            let found = if strict {
                needle.strict_eq(val)
            } else {
                needle.loose_eq(val)
            };
            if found {
                return Ok(match key {
                    ArrayKey::Int(n) => Value::Long(*n),
                    ArrayKey::String(s) => Value::String(s.clone()),
                });
            }
        }
    }
    Ok(Value::Bool(false))
}

// ---------------------------------------------------------------------------
// array_keys
// ---------------------------------------------------------------------------

fn php_array_keys(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let search_value = args.get(1).cloned();
    let strict = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
    let mut result = PhpArray::new();
    if let Value::Array(ref a) = arr {
        for (key, val) in a.entries() {
            // If search_value given, only include keys whose value matches
            if let Some(ref search) = search_value {
                let matches = if strict {
                    val.strict_eq(search)
                } else {
                    val.loose_eq(search)
                };
                if !matches {
                    continue;
                }
            }
            match key {
                ArrayKey::Int(n) => result.push(Value::Long(*n)),
                ArrayKey::String(s) => result.push(Value::String(s.clone())),
            }
        }
    }
    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_values
// ---------------------------------------------------------------------------

fn php_array_values(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let mut result = PhpArray::new();
    if let Value::Array(ref a) = arr {
        for (_, v) in a.entries() {
            result.push(v.clone());
        }
    }
    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_merge
// ---------------------------------------------------------------------------

fn php_array_merge(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut result = PhpArray::new();
    for arg in args {
        if let Value::Array(ref a) = arg {
            for (key, val) in a.entries() {
                match key {
                    ArrayKey::Int(_) => result.push(val.clone()),
                    ArrayKey::String(s) => {
                        result.set_string(s.clone(), val.clone());
                    }
                }
            }
        }
    }
    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_merge_recursive
// ---------------------------------------------------------------------------

fn php_array_merge_recursive(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut result = PhpArray::new();
    for arg in args {
        if let Value::Array(ref a) = arg {
            for (key, val) in a.entries() {
                match key {
                    ArrayKey::Int(_) => result.push(val.clone()),
                    ArrayKey::String(s) => {
                        if let Some(existing) = result.get_string(s).cloned() {
                            // Both are arrays → merge recursively
                            if let (Value::Array(ref ea), Value::Array(ref va)) = (&existing, val) {
                                let merged = merge_arrays_recursive(ea, va);
                                result.set_string(s.clone(), Value::Array(merged));
                            } else {
                                // Convert existing to array and append new value
                                let mut arr = PhpArray::new();
                                arr.push(existing.clone());
                                arr.push(val.clone());
                                result.set_string(s.clone(), Value::Array(arr));
                            }
                        } else {
                            result.set_string(s.clone(), val.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(Value::Array(result))
}

fn merge_arrays_recursive(a: &PhpArray, b: &PhpArray) -> PhpArray {
    let mut result = a.clone();
    for (key, val) in b.entries() {
        match key {
            ArrayKey::Int(_) => result.push(val.clone()),
            ArrayKey::String(s) => {
                if let Some(existing) = result.get_string(s).cloned() {
                    if let (Value::Array(ref ea), Value::Array(ref va)) = (&existing, val) {
                        let merged = merge_arrays_recursive(ea, va);
                        result.set_string(s.clone(), Value::Array(merged));
                    } else {
                        let mut arr = PhpArray::new();
                        arr.push(existing.clone());
                        arr.push(val.clone());
                        result.set_string(s.clone(), Value::Array(arr));
                    }
                } else {
                    result.set_string(s.clone(), val.clone());
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// array_reverse
// ---------------------------------------------------------------------------

fn php_array_reverse(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let preserve_keys = args.get(1).map(|v| v.to_bool()).unwrap_or(false);
    let mut result = PhpArray::new();
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().rev().collect();
        for (key, val) in entries {
            match key {
                ArrayKey::Int(n) => {
                    if preserve_keys {
                        result.set_int(*n, val.clone());
                    } else {
                        result.push(val.clone());
                    }
                }
                ArrayKey::String(s) => {
                    result.set_string(s.clone(), val.clone());
                }
            }
        }
    }
    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_slice
// ---------------------------------------------------------------------------

fn php_array_slice(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let offset = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
    let length = args.get(2).map(|v| v.to_long());

    if let Value::Array(ref a) = arr {
        let entries = a.entries();
        let len = entries.len() as i64;
        let start = if offset < 0 {
            (len + offset).max(0) as usize
        } else {
            offset as usize
        };
        let end = match length {
            Some(l) if l < 0 => (len + l).max(0) as usize,
            Some(l) => (start + l as usize).min(entries.len()),
            None => entries.len(),
        };
        let mut result = PhpArray::new();
        for (_, val) in &entries[start..end] {
            result.push(val.clone());
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_splice
// ---------------------------------------------------------------------------

fn php_array_splice(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let offset = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
    let length = args.get(2).map(|v| v.to_long());
    let replacement: Vec<Value> = if let Some(Value::Array(ref rep)) = args.get(3) {
        rep.entries().iter().map(|(_, v)| v.clone()).collect()
    } else if let Some(rep) = args.get(3) {
        vec![rep.clone()]
    } else {
        Vec::new()
    };
    if let Value::Array(ref a) = arr {
        let entries = a.entries();
        let len = entries.len() as i64;
        let start = if offset < 0 {
            (len + offset).max(0) as usize
        } else {
            (offset as usize).min(entries.len())
        };
        let end = match length {
            Some(l) if l < 0 => (len + l).max(0) as usize,
            Some(l) => (start + l as usize).min(entries.len()),
            None => entries.len(),
        };
        // Extract the removed portion (return value)
        let mut removed = PhpArray::new();
        for (_, val) in &entries[start..end] {
            removed.push(val.clone());
        }
        // Build the modified array: before + replacement + after
        let mut new_arr = PhpArray::new();
        // Keep entries before the splice point
        for (_, val) in &entries[..start] {
            new_arr.push(val.clone());
        }
        // Insert replacement values
        for val in &replacement {
            new_arr.push(val.clone());
        }
        // Keep entries after the splice range
        for (_, val) in &entries[end..] {
            new_arr.push(val.clone());
        }
        // Write back the modified array to the original variable
        if let Some(&(arg_idx, _, _)) = ref_args.first() {
            vm.write_back_arg(arg_idx, Value::Array(new_arr), ref_args, ref_prop_args);
        }
        Ok(Value::Array(removed))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_unique
// ---------------------------------------------------------------------------

fn php_array_unique(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        let mut seen: Vec<Value> = Vec::new();
        for (key, val) in a.entries() {
            if !seen.iter().any(|s| s.loose_eq(val)) {
                seen.push(val.clone());
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_flip
// ---------------------------------------------------------------------------

fn php_array_flip(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        for (key, val) in a.entries() {
            let new_key = val.clone();
            let new_val = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            result.set(&new_key, new_val);
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_combine
// ---------------------------------------------------------------------------

fn php_array_combine(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let keys = args.first().cloned().unwrap_or(Value::Null);
    let values = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref k), Value::Array(ref v)) = (&keys, &values) {
        if k.len() != v.len() {
            return Ok(Value::Bool(false));
        }
        let mut result = PhpArray::new();
        for (kentry, ventry) in k.entries().iter().zip(v.entries().iter()) {
            result.set(&kentry.1, ventry.1.clone());
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_sum
// ---------------------------------------------------------------------------

fn php_array_sum(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut sum = Value::Long(0);
        for (_, v) in a.entries() {
            sum = sum.add(v);
        }
        Ok(sum)
    } else {
        Ok(Value::Long(0))
    }
}

// ---------------------------------------------------------------------------
// array_product
// ---------------------------------------------------------------------------

fn php_array_product(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut product = Value::Long(1);
        for (_, v) in a.entries() {
            product = product.mul(v);
        }
        Ok(product)
    } else {
        Ok(Value::Long(0))
    }
}

// ---------------------------------------------------------------------------
// array_count_values
// ---------------------------------------------------------------------------

fn php_array_count_values(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        for (_, val) in a.entries() {
            let key_str = val.to_php_string();
            let current = result
                .get_string(&key_str)
                .cloned()
                .unwrap_or(Value::Long(0));
            result.set_string(key_str, current.add(&Value::Long(1)));
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_column
// ---------------------------------------------------------------------------

fn php_array_column(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = args.first().cloned().unwrap_or(Value::Null);
    let column_key = args.get(1).cloned().unwrap_or(Value::Null);
    let index_key = args.get(2).cloned();
    if let Value::Array(ref a) = input {
        let mut result = PhpArray::new();
        for (_, row) in a.entries() {
            // Helper to get a value by key from either arrays or objects
            let get_val = |row: &Value, key: &Value| -> Option<Value> {
                match row {
                    Value::Array(ref arr) => arr.get(key).cloned(),
                    Value::Object(ref obj) => {
                        let prop_name = key.to_php_string();
                        obj.get_property(&prop_name)
                    }
                    _ => None,
                }
            };

            let val = if column_key.is_null() {
                row.clone()
            } else {
                get_val(row, &column_key).unwrap_or(Value::Null)
            };
            match &index_key {
                Some(ik) if !ik.is_null() => {
                    if let Some(idx) = get_val(row, ik) {
                        result.set(&idx, val);
                    } else {
                        result.push(val);
                    }
                }
                _ => result.push(val),
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_chunk
// ---------------------------------------------------------------------------

fn php_array_chunk(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let size = args
        .get(1)
        .cloned()
        .unwrap_or(Value::Long(1))
        .to_long()
        .max(1) as usize;
    let preserve_keys = args.get(2).is_some_and(|v| v.to_bool());
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        let entries = a.entries();
        for chunk in entries.chunks(size) {
            let mut sub = PhpArray::new();
            for (key, val) in chunk {
                if preserve_keys {
                    match key {
                        ArrayKey::Int(n) => sub.set_int(*n, val.clone()),
                        ArrayKey::String(s) => sub.set_string(s.clone(), val.clone()),
                    }
                } else {
                    sub.push(val.clone());
                }
            }
            result.push(Value::Array(sub));
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_pad
// ---------------------------------------------------------------------------

fn php_array_pad(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let size = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
    let value = args.get(2).cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        let abs_size = size.unsigned_abs() as usize;
        if abs_size <= a.len() {
            // Already big enough, just copy
            for (_, val) in a.entries() {
                result.push(val.clone());
            }
        } else if size > 0 {
            // Pad right
            for (_, val) in a.entries() {
                result.push(val.clone());
            }
            for _ in 0..(abs_size - a.len()) {
                result.push(value.clone());
            }
        } else {
            // Pad left
            for _ in 0..(abs_size - a.len()) {
                result.push(value.clone());
            }
            for (_, val) in a.entries() {
                result.push(val.clone());
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_rand
// ---------------------------------------------------------------------------

fn php_array_rand(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let num = args
        .get(1)
        .cloned()
        .unwrap_or(Value::Long(1))
        .to_long()
        .max(1);
    if let Value::Array(ref a) = arr {
        if a.is_empty() {
            return Ok(Value::Null);
        }
        let mut rng = php_rs_ext_random::Randomizer::new(Box::new(
            php_rs_ext_random::Mt19937::new(Some(vm.mt_rng.generate_u32() as u64)),
        ));
        let entries = a.entries();
        if num == 1 {
            let idx = rng.next_int(0, entries.len() as i64 - 1) as usize;
            let (key, _) = &entries[idx];
            Ok(match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            })
        } else {
            let picked = rng.pick_array_keys(entries, num as usize);
            let mut result = PhpArray::new();
            for idx in picked {
                let (key, _) = &entries[idx];
                result.push(match key {
                    ArrayKey::Int(n) => Value::Long(*n),
                    ArrayKey::String(s) => Value::String(s.clone()),
                });
            }
            Ok(Value::Array(result))
        }
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_fill
// ---------------------------------------------------------------------------

fn php_array_fill(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let start = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
    let num = args
        .get(1)
        .cloned()
        .unwrap_or(Value::Long(0))
        .to_long()
        .max(0);
    let value = args.get(2).cloned().unwrap_or(Value::Null);
    let mut arr = PhpArray::new();
    for i in 0..num {
        arr.set_int(start + i, value.clone());
    }
    Ok(Value::Array(arr))
}

// ---------------------------------------------------------------------------
// array_fill_keys
// ---------------------------------------------------------------------------

fn php_array_fill_keys(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let keys = args.first().cloned().unwrap_or(Value::Null);
    let value = args.get(1).cloned().unwrap_or(Value::Null);
    let mut arr = PhpArray::new();
    if let Value::Array(ref k) = keys {
        for (_, key_val) in k.entries() {
            arr.set(key_val, value.clone());
        }
    }
    Ok(Value::Array(arr))
}

// ---------------------------------------------------------------------------
// array_intersect
// ---------------------------------------------------------------------------

fn php_array_intersect(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            if a2.entries().iter().any(|(_, v)| val.loose_eq(v)) {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_intersect_key
// ---------------------------------------------------------------------------

fn php_array_intersect_key(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            if a2.entries().iter().any(|(k, _)| k == key) {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_intersect_assoc
// ---------------------------------------------------------------------------

fn php_array_intersect_assoc(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            let found = a2
                .entries()
                .iter()
                .any(|(k, v)| k == key && val.loose_eq(v));
            if found {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_diff
// ---------------------------------------------------------------------------

fn php_array_diff(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            if !a2.entries().iter().any(|(_, v)| val.loose_eq(v)) {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_diff_key
// ---------------------------------------------------------------------------

fn php_array_diff_key(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            if !a2.entries().iter().any(|(k, _)| k == key) {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_diff_assoc
// ---------------------------------------------------------------------------

fn php_array_diff_assoc(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a1) = arr1 {
        // Collect all comparison arrays
        let compare_arrays: Vec<&PhpArray> = args
            .iter()
            .skip(1)
            .filter_map(|v| {
                if let Value::Array(ref a) = v {
                    Some(a)
                } else {
                    None
                }
            })
            .collect();
        let mut result = PhpArray::new();
        for (key, val) in a1.entries() {
            // Keep if not found in ANY of the comparison arrays (same key+value)
            let found_in_any = compare_arrays.iter().any(|a2| {
                a2.entries()
                    .iter()
                    .any(|(k, v)| k == key && val.to_php_string() == v.to_php_string())
            });
            if !found_in_any {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_map
// ---------------------------------------------------------------------------

fn php_array_map(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let callback = args.first().cloned().unwrap_or(Value::Null);

    // Collect all array arguments (args[1], args[2], ...)
    let arrays: Vec<&PhpArray> = args[1..]
        .iter()
        .filter_map(|v| match v {
            Value::Array(ref a) => Some(a),
            _ => None,
        })
        .collect();

    if arrays.is_empty() {
        return Ok(Value::Array(PhpArray::new()));
    }

    // Single array case (most common)
    if arrays.len() == 1 {
        let a = arrays[0];
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        let mut result = PhpArray::new();
        if callback == Value::Null {
            return Ok(args.get(1).cloned().unwrap_or(Value::Null));
        }
        let cb_name = Vm::extract_closure_name(&callback);
        for (key, val) in &entries {
            let mapped = vm.invoke_user_callback(&cb_name, vec![val.clone()])?;
            match key {
                ArrayKey::Int(n) => result.set_int(*n, mapped),
                ArrayKey::String(s) => result.set_string(s.clone(), mapped),
            }
        }
        return Ok(Value::Array(result));
    }

    // Multiple arrays case: iterate by index, pass one element from each array
    let max_len = arrays.iter().map(|a| a.len()).max().unwrap_or(0);
    let mut result = PhpArray::new();

    if callback == Value::Null {
        // null callback with multiple arrays = array of arrays
        for i in 0..max_len {
            let mut sub = PhpArray::new();
            for a in &arrays {
                let val = a
                    .get(&Value::Long(i as i64))
                    .cloned()
                    .unwrap_or(Value::Null);
                sub.push(val);
            }
            result.push(Value::Array(sub));
        }
    } else {
        let cb_name = Vm::extract_closure_name(&callback);
        for i in 0..max_len {
            let cb_args: Vec<Value> = arrays
                .iter()
                .map(|a| {
                    a.get(&Value::Long(i as i64))
                        .cloned()
                        .unwrap_or(Value::Null)
                })
                .collect();
            let mapped = vm.invoke_user_callback(&cb_name, cb_args)?;
            result.push(mapped);
        }
    }

    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_filter
// ---------------------------------------------------------------------------

fn php_array_filter(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let callback = args.get(1).cloned();
    let flag = args.get(2).map(|v| v.to_long()).unwrap_or(0);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        let mut result = PhpArray::new();
        for (key, val) in &entries {
            let keep = if let Some(ref cb) = callback {
                let cb_name = Vm::extract_closure_name(cb);
                let cb_args = match flag {
                    2 => {
                        // ARRAY_FILTER_USE_KEY
                        let k = match key {
                            ArrayKey::Int(n) => Value::Long(*n),
                            ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        vec![k]
                    }
                    1 => {
                        // ARRAY_FILTER_USE_BOTH
                        let k = match key {
                            ArrayKey::Int(n) => Value::Long(*n),
                            ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        vec![val.clone(), k]
                    }
                    _ => vec![val.clone()],
                };
                vm.invoke_user_callback(&cb_name, cb_args)?.to_bool()
            } else {
                val.to_bool()
            };
            if keep {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}

// ---------------------------------------------------------------------------
// array_walk
// ---------------------------------------------------------------------------

fn php_array_walk(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let callback = Vm::extract_closure_name(&args.get(1).cloned().unwrap_or(Value::Null));
    let extra = args.get(2).cloned();
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (key, val) in &entries {
            let k = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            let mut cb_args = vec![val.clone(), k];
            if let Some(ref e) = extra {
                cb_args.push(e.clone());
            }
            vm.invoke_user_callback(&callback, cb_args)?;
        }
    }
    Ok(Value::Bool(true))
}

// ---------------------------------------------------------------------------
// array_walk_recursive
// ---------------------------------------------------------------------------

fn php_array_walk_recursive(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let callback = Vm::extract_closure_name(&args.get(1).cloned().unwrap_or(Value::Null));
    let extra = args.get(2).cloned();
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        vm.walk_recursive_inner(&entries, &callback, &extra)?;
    }
    Ok(Value::Bool(true))
}

// ---------------------------------------------------------------------------
// array_reduce
// ---------------------------------------------------------------------------

fn php_array_reduce(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let callback = Vm::extract_closure_name(&args.get(1).cloned().unwrap_or(Value::Null));
    let mut carry = args.get(2).cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (_key, val) in &entries {
            carry = vm.invoke_user_callback(&callback, vec![carry, val.clone()])?;
        }
    }
    Ok(carry)
}

// ---------------------------------------------------------------------------
// sort / rsort / asort / arsort / ksort / krsort
// ---------------------------------------------------------------------------

/// Helper that performs a standard PHP sort on an array.
fn sort_common(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
    sort_name: &str,
) -> VmResult<Value> {
    let arr_val = args.first().cloned().unwrap_or(Value::Null);
    let sort_flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
    // SORT_REGULAR=0, SORT_NUMERIC=1, SORT_STRING=2, SORT_NATURAL=6,
    // SORT_FLAG_CASE=8 (can be ORed with SORT_STRING or SORT_NATURAL)
    let case_insensitive = (sort_flags & 8) != 0;
    let base_flag = sort_flags & !8;

    let cmp_ord = |r: i64| -> std::cmp::Ordering {
        if r < 0 {
            std::cmp::Ordering::Less
        } else if r > 0 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    };

    // Compare two values according to sort flags
    let value_cmp = |a: &Value, b: &Value| -> std::cmp::Ordering {
        match base_flag {
            1 => {
                // SORT_NUMERIC
                let fa = a.to_double();
                let fb = b.to_double();
                fa.partial_cmp(&fb).unwrap_or(std::cmp::Ordering::Equal)
            }
            2 => {
                // SORT_STRING
                let sa = a.to_php_string();
                let sb = b.to_php_string();
                if case_insensitive {
                    sa.to_lowercase().cmp(&sb.to_lowercase())
                } else {
                    sa.cmp(&sb)
                }
            }
            6 => {
                // SORT_NATURAL (natural order: "img2" < "img10")
                let sa = if case_insensitive {
                    a.to_php_string().to_lowercase()
                } else {
                    a.to_php_string()
                };
                let sb = if case_insensitive {
                    b.to_php_string().to_lowercase()
                } else {
                    b.to_php_string()
                };
                nat_cmp(&sa, &sb)
            }
            _ => {
                // SORT_REGULAR (default) — use spaceship
                cmp_ord(a.spaceship(b))
            }
        }
    };

    let sort_fn = |a: &mut PhpArray| {
        let mut entries = a.entries().to_vec();
        match sort_name {
            "sort" => {
                entries.sort_by(|(_, a), (_, b)| value_cmp(a, b));
                let sorted: Vec<(ArrayKey, Value)> = entries
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, v))| (ArrayKey::Int(i as i64), v))
                    .collect();
                *a = PhpArray::from_entries(sorted);
            }
            "rsort" => {
                entries.sort_by(|(_, a), (_, b)| value_cmp(b, a));
                let sorted: Vec<(ArrayKey, Value)> = entries
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, v))| (ArrayKey::Int(i as i64), v))
                    .collect();
                *a = PhpArray::from_entries(sorted);
            }
            "asort" => {
                entries.sort_by(|(_, a), (_, b)| value_cmp(a, b));
                *a = PhpArray::from_entries(entries);
            }
            "arsort" => {
                entries.sort_by(|(_, a), (_, b)| value_cmp(b, a));
                *a = PhpArray::from_entries(entries);
            }
            "ksort" => {
                entries.sort_by(|(ka, _), (kb, _)| {
                    let a = match ka {
                        ArrayKey::Int(i) => Value::Long(*i),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let b = match kb {
                        ArrayKey::Int(i) => Value::Long(*i),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    value_cmp(&a, &b)
                });
                *a = PhpArray::from_entries(entries);
            }
            "krsort" => {
                entries.sort_by(|(ka, _), (kb, _)| {
                    let a = match ka {
                        ArrayKey::Int(i) => Value::Long(*i),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let b = match kb {
                        ArrayKey::Int(i) => Value::Long(*i),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    value_cmp(&b, &a)
                });
                *a = PhpArray::from_entries(entries);
            }
            _ => {}
        }
    };
    if let Value::Reference(rc) = &arr_val {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            sort_fn(a);
        }
    } else if let Value::Array(ref a) = arr_val {
        let mut arr_clone = a.clone();
        sort_fn(&mut arr_clone);
        vm.write_back_arg(0, Value::Array(arr_clone), ref_args, ref_prop_args);
    }
    Ok(Value::Bool(true))
}

fn php_sort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "sort")
}

fn php_rsort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "rsort")
}

fn php_asort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "asort")
}

fn php_arsort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "arsort")
}

fn php_ksort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "ksort")
}

fn php_krsort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    sort_common(vm, args, ref_args, ref_prop_args, "krsort")
}

// ---------------------------------------------------------------------------
// usort / uasort / uksort
// ---------------------------------------------------------------------------

fn usort_common(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
    sort_type: &str,
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let callback = Vm::extract_closure_name(&args.get(1).cloned().unwrap_or(Value::Null));

    if let Value::Reference(rc) = &arr {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            let mut entries: Vec<(ArrayKey, Value)> = a.entries().iter().cloned().collect();
            usort_entries(vm, &mut entries, &callback, sort_type)?;
            let mut result = PhpArray::new();
            usort_build_result(&mut result, entries, sort_type);
            *a = result;
        }
        return Ok(Value::Bool(true));
    }

    if let Value::Array(ref a) = arr {
        let mut entries: Vec<(ArrayKey, Value)> = a.entries().iter().cloned().collect();
        usort_entries(vm, &mut entries, &callback, sort_type)?;
        let mut result = PhpArray::new();
        usort_build_result(&mut result, entries, sort_type);
        vm.write_back_arg(0, Value::Array(result), ref_args, ref_prop_args);
        return Ok(Value::Bool(true));
    }

    Ok(Value::Bool(true))
}

fn usort_entries(
    vm: &mut Vm,
    entries: &mut Vec<(ArrayKey, Value)>,
    callback: &str,
    sort_type: &str,
) -> VmResult<()> {
    let len = entries.len();
    for i in 1..len {
        let mut j = i;
        while j > 0 {
            let (a_val, b_val) = match sort_type {
                "uksort" => {
                    let ka = match &entries[j - 1].0 {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let kb = match &entries[j].0 {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    (ka, kb)
                }
                _ => (entries[j - 1].1.clone(), entries[j].1.clone()),
            };
            let cmp = vm
                .invoke_user_callback(callback, vec![a_val, b_val])?
                .to_long();
            if cmp > 0 {
                entries.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }
    Ok(())
}

fn usort_build_result(
    result: &mut PhpArray,
    entries: Vec<(ArrayKey, Value)>,
    sort_type: &str,
) {
    match sort_type {
        "usort" => {
            // usort: re-index with 0..n
            for (_key, val) in entries {
                result.push(val);
            }
        }
        _ => {
            // uasort/uksort: preserve keys
            for (key, val) in entries {
                match key {
                    ArrayKey::Int(n) => result.set_int(n, val),
                    ArrayKey::String(s) => result.set_string(s, val),
                }
            }
        }
    }
}

fn php_usort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    usort_common(vm, args, ref_args, ref_prop_args, "usort")
}

fn php_uasort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    usort_common(vm, args, ref_args, ref_prop_args, "uasort")
}

fn php_uksort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    usort_common(vm, args, ref_args, ref_prop_args, "uksort")
}

// ---------------------------------------------------------------------------
// array_multisort
// ---------------------------------------------------------------------------

fn php_array_multisort(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // Parse args: arrays interleaved with optional SORT_ASC(4)/SORT_DESC(3)
    // and SORT_REGULAR(0)/SORT_NUMERIC(1)/SORT_STRING(2) flags
    if args.is_empty() {
        return Ok(Value::Bool(false));
    }

    // Collect arrays and their sort options
    let mut arrays: Vec<(usize, Vec<(ArrayKey, Value)>)> = Vec::new(); // (arg_idx, entries)
    let mut sort_orders: Vec<bool> = Vec::new(); // true = ascending
    let mut sort_types: Vec<i64> = Vec::new(); // 0=regular, 1=numeric, 2=string
    let mut current_order = true; // ascending by default
    let mut current_type = 0i64; // SORT_REGULAR

    for (i, arg) in args.iter().enumerate() {
        match arg {
            Value::Array(ref a) => {
                if !arrays.is_empty() {
                    // Save flags for previous array
                    sort_orders.push(current_order);
                    sort_types.push(current_type);
                    current_order = true;
                    current_type = 0;
                }
                arrays.push((i, a.entries().iter().cloned().collect()));
            }
            Value::Long(v) => {
                match *v {
                    4 => current_order = true,          // SORT_ASC
                    3 => current_order = false,         // SORT_DESC
                    0 | 1 | 2 | 6 => current_type = *v, // SORT_REGULAR/NUMERIC/STRING/NATURAL
                    _ => {}
                }
            }
            _ => {}
        }
    }
    // Save flags for last array
    sort_orders.push(current_order);
    sort_types.push(current_type);

    if arrays.is_empty() {
        return Ok(Value::Bool(false));
    }

    let len = arrays[0].1.len();
    // All arrays must have the same length
    if arrays.iter().any(|(_, e)| e.len() != len) {
        return Ok(Value::Bool(false));
    }

    // Build index permutation
    let mut indices: Vec<usize> = (0..len).collect();
    let first_entries = &arrays[0].1;
    let asc = sort_orders.first().copied().unwrap_or(true);
    let stype = sort_types.first().copied().unwrap_or(0);
    indices.sort_by(|&a, &b| {
        let va = &first_entries[a].1;
        let vb = &first_entries[b].1;
        let ord = match stype {
            1 => {
                // SORT_NUMERIC
                let fa = va.to_double();
                let fb = vb.to_double();
                fa.partial_cmp(&fb).unwrap_or(std::cmp::Ordering::Equal)
            }
            2 => {
                // SORT_STRING
                va.to_php_string().cmp(&vb.to_php_string())
            }
            _ => {
                // SORT_REGULAR - PHP compare
                match va.spaceship(vb) {
                    n if n < 0 => std::cmp::Ordering::Less,
                    n if n > 0 => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Equal,
                }
            }
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });

    // Apply the permutation to all arrays and write them back
    for (arr_idx, (arg_idx, entries)) in arrays.iter().enumerate() {
        let _ = arr_idx;
        let mut new_arr = PhpArray::new();
        for &idx in &indices {
            new_arr.push(entries[idx].1.clone());
        }
        vm.write_back_arg(*arg_idx, Value::Array(new_arr), ref_args, ref_prop_args);
    }
    Ok(Value::Bool(true))
}

// ---------------------------------------------------------------------------
// compact / extract / list
// ---------------------------------------------------------------------------

fn php_compact(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut result = PhpArray::new();
    // Builtins are called without pushing a frame, so call_stack.last() is the caller's frame
    let frame = vm.call_stack.last().unwrap();
    let oa_idx = frame.op_array_idx;
    let vars = vm.op_arrays[oa_idx].vars.clone();
    let cvs = frame.cvs.clone();
    for arg in args {
        match arg {
            Value::String(name) => {
                // Find the variable by name in the caller's frame
                if let Some(idx) = vars.iter().position(|v| v == name) {
                    if idx < cvs.len() && !cvs[idx].is_null() {
                        result.set_string(name.clone(), cvs[idx].clone());
                    }
                }
            }
            Value::Array(arr) => {
                // Recursively compact array elements
                for (_, val) in arr.entries() {
                    if let Value::String(name) = val {
                        if let Some(idx) = vars.iter().position(|v| v == name) {
                            if idx < cvs.len() && !cvs[idx].is_null() {
                                result.set_string(name.clone(), cvs[idx].clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(Value::Array(result))
}

fn php_extract(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
    let prefix = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
    // EXTR_OVERWRITE=0, EXTR_SKIP=1, EXTR_PREFIX_SAME=2, EXTR_PREFIX_ALL=3
    let extract_type = flags & 0xff;

    if let Value::Array(ref a) = arr {
        let mut count = 0i64;
        let frame = vm.call_stack.last().unwrap();
        let oa_idx = frame.op_array_idx;
        let vars = vm.op_arrays[oa_idx].vars.clone();
        // Collect assignments first to avoid borrow conflicts
        let mut assignments: Vec<(usize, Value)> = Vec::new();
        let mut new_vars: Vec<(String, Value)> = Vec::new();
        for (key, val) in a.entries() {
            if let ArrayKey::String(name) = key {
                let var_name = if extract_type == 3 {
                    // EXTR_PREFIX_ALL
                    format!("{}_{}", prefix, name)
                } else {
                    name.clone()
                };
                if let Some(idx) = vars.iter().position(|v| v == &var_name) {
                    // Variable exists in scope
                    let existing = &vm.call_stack.last().unwrap().cvs;
                    let has_value = idx < existing.len() && !matches!(existing[idx], Value::Null);
                    match extract_type {
                        1 if has_value => continue, // EXTR_SKIP
                        2 if has_value => {
                            // EXTR_PREFIX_SAME — use prefixed name
                            let prefixed = format!("{}_{}", prefix, name);
                            new_vars.push((prefixed, val.clone()));
                            count += 1;
                            continue;
                        }
                        _ => {}
                    }
                    assignments.push((idx, val.clone()));
                    count += 1;
                } else {
                    new_vars.push((var_name, val.clone()));
                    count += 1;
                }
            }
        }
        // Apply assignments to existing variables
        for (idx, val) in assignments {
            let frame = vm.call_stack.last_mut().unwrap();
            while frame.cvs.len() <= idx {
                frame.cvs.push(Value::Null);
            }
            frame.cvs[idx] = val;
        }
        // Create new variables
        for (name, val) in new_vars {
            let idx = vm.op_arrays[oa_idx].lookup_cv(&name) as usize;
            let frame = vm.call_stack.last_mut().unwrap();
            while frame.cvs.len() <= idx {
                frame.cvs.push(Value::Null);
            }
            frame.cvs[idx] = val;
        }
        Ok(Value::Long(count))
    } else {
        Ok(Value::Long(0))
    }
}

fn php_list(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // list() is handled by compiler; shouldn't reach here
    Ok(Value::Null)
}

// ---------------------------------------------------------------------------
// range
// ---------------------------------------------------------------------------

fn php_range(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let low_val = args.first().cloned().unwrap_or(Value::Long(0));
    let high_val = args.get(1).cloned().unwrap_or(Value::Long(0));
    let step_val = args.get(2).cloned().unwrap_or(Value::Long(1));

    // Character range: both args are single-char strings
    let is_char_range = matches!((&low_val, &high_val), (Value::String(a), Value::String(b)) if a.len() == 1 && b.len() == 1);

    if is_char_range {
        let low_c = low_val.to_php_string().chars().next().unwrap() as u32;
        let high_c = high_val.to_php_string().chars().next().unwrap() as u32;
        let step = step_val.to_long().unsigned_abs().max(1) as u32;
        let mut arr = PhpArray::new();
        if low_c <= high_c {
            let mut i = low_c;
            while i <= high_c {
                if let Some(c) = char::from_u32(i) {
                    arr.push(Value::String(c.to_string()));
                }
                i += step;
            }
        } else {
            let mut i = low_c;
            while i >= high_c {
                if let Some(c) = char::from_u32(i) {
                    arr.push(Value::String(c.to_string()));
                }
                if i < step {
                    break;
                }
                i -= step;
            }
        }
        return Ok(Value::Array(arr));
    }

    // Float range: if any arg is a float or step is fractional
    let is_float = matches!(&low_val, Value::Double(_))
        || matches!(&high_val, Value::Double(_))
        || matches!(&step_val, Value::Double(_));

    if is_float {
        let low = low_val.to_double();
        let high = high_val.to_double();
        let step = step_val.to_double().abs().max(f64::EPSILON);
        let mut arr = PhpArray::new();
        if low <= high {
            let mut i = low;
            while i <= high + f64::EPSILON {
                arr.push(Value::Double(i));
                i += step;
            }
        } else {
            let mut i = low;
            while i >= high - f64::EPSILON {
                arr.push(Value::Double(i));
                i -= step;
            }
        }
        return Ok(Value::Array(arr));
    }

    // Integer range
    let low = low_val.to_long();
    let high = high_val.to_long();
    let step = step_val.to_long().unsigned_abs().max(1) as i64;
    let mut arr = PhpArray::new();
    if low <= high {
        let mut i = low;
        while i <= high {
            arr.push(Value::Long(i));
            i += step;
        }
    } else {
        let mut i = low;
        while i >= high {
            arr.push(Value::Long(i));
            i -= step;
        }
    }
    Ok(Value::Array(arr))
}

// ---------------------------------------------------------------------------
// current / pos
// ---------------------------------------------------------------------------

fn php_current(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(a.current())
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// next
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// prev
// ---------------------------------------------------------------------------

fn php_prev(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

// ---------------------------------------------------------------------------
// end
// ---------------------------------------------------------------------------

fn php_end(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        match a.entries().last() {
            Some((_, v)) => Ok(v.clone()),
            None => Ok(Value::Bool(false)),
        }
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

fn php_reset(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        match a.entries().first() {
            Some((_, v)) => Ok(v.clone()),
            None => Ok(Value::Bool(false)),
        }
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// key
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// array_key_first
// ---------------------------------------------------------------------------

fn php_array_key_first(
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

// ---------------------------------------------------------------------------
// array_key_last
// ---------------------------------------------------------------------------

fn php_array_key_last(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(a.key_last())
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_is_list
// ---------------------------------------------------------------------------

fn php_array_is_list(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(Value::Bool(a.is_list()))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_replace
// ---------------------------------------------------------------------------

fn php_array_replace(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let mut result = PhpArray::new();
    // Start with the first array
    if let Some(Value::Array(ref a)) = args.first() {
        for (key, val) in a.entries() {
            match key {
                ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
            }
        }
    }
    // Override with subsequent arrays
    for arg in args.iter().skip(1) {
        if let Value::Array(ref a) = arg {
            for (key, val) in a.entries() {
                match key {
                    ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val.clone()),
                }
            }
        }
    }
    Ok(Value::Array(result))
}

// ---------------------------------------------------------------------------
// array_replace_recursive
// ---------------------------------------------------------------------------

fn php_array_replace_recursive(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if args.is_empty() {
        return Ok(Value::Array(PhpArray::new()));
    }
    let mut result = if let Value::Array(ref a) = args[0] {
        a.clone()
    } else {
        PhpArray::new()
    };
    for arg in args.iter().skip(1) {
        if let Value::Array(ref a) = arg {
            result = replace_arrays_recursive(&result, a);
        }
    }
    Ok(Value::Array(result))
}

fn replace_arrays_recursive(base: &PhpArray, replacement: &PhpArray) -> PhpArray {
    let mut result = base.clone();
    for (key, val) in replacement.entries() {
        match key {
            ArrayKey::Int(n) => {
                if let (Some(Value::Array(ref existing)), Value::Array(ref new_arr)) =
                    (result.get_int(*n), val)
                {
                    let merged = replace_arrays_recursive(existing, new_arr);
                    result.set_int(*n, Value::Array(merged));
                } else {
                    result.set_int(*n, val.clone());
                }
            }
            ArrayKey::String(s) => {
                if let (Some(Value::Array(ref existing)), Value::Array(ref new_arr)) =
                    (result.get_string(s), val)
                {
                    let merged = replace_arrays_recursive(existing, new_arr);
                    result.set_string(s.clone(), Value::Array(merged));
                } else {
                    result.set_string(s.clone(), val.clone());
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// shuffle
// ---------------------------------------------------------------------------

fn php_shuffle(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut values: Vec<Value> = a.entries().iter().map(|(_, v)| v.clone()).collect();
        let mut rng = php_rs_ext_random::Randomizer::new(Box::new(
            php_rs_ext_random::Mt19937::new(Some(vm.mt_rng.generate_u32() as u64)),
        ));
        rng.shuffle_array(&mut values);
        let mut result = PhpArray::new();
        for v in values {
            result.push(v);
        }
        vm.write_back_arg(0, Value::Array(result), ref_args, ref_prop_args);
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_pop
// ---------------------------------------------------------------------------

fn php_array_pop(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr_val = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Reference(rc) = &arr_val {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            let popped = a.pop();
            Ok(popped)
        } else {
            Ok(Value::Null)
        }
    } else if let Value::Array(ref a) = arr_val {
        let mut arr_clone = a.clone();
        let popped = arr_clone.pop();
        vm.write_back_arg(0, Value::Array(arr_clone), ref_args, ref_prop_args);
        Ok(popped)
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_shift
// ---------------------------------------------------------------------------

fn php_array_shift(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr_val = args.first().cloned().unwrap_or(Value::Null);
    // If the argument is a Reference, modify in-place
    if let Value::Reference(rc) = &arr_val {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            let shifted = a.shift();
            Ok(shifted)
        } else {
            Ok(Value::Null)
        }
    } else if let Value::Array(ref a) = arr_val {
        let mut arr_clone = a.clone();
        let shifted = arr_clone.shift();
        vm.write_back_arg(0, Value::Array(arr_clone), ref_args, ref_prop_args);
        Ok(shifted)
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_unshift
// ---------------------------------------------------------------------------

fn php_array_unshift(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr_val = args.first().cloned().unwrap_or(Value::Null);
    let values_to_add: Vec<Value> = args.iter().skip(1).cloned().collect();
    if let Value::Reference(rc) = &arr_val {
        let mut inner = rc.borrow_mut();
        if let Value::Array(ref mut a) = *inner {
            for v in values_to_add.into_iter().rev() {
                a.unshift(v);
            }
            Ok(Value::Long(a.len() as i64))
        } else {
            Ok(Value::Long(0))
        }
    } else if let Value::Array(ref a) = arr_val {
        let mut arr_clone = a.clone();
        for v in values_to_add.into_iter().rev() {
            arr_clone.unshift(v);
        }
        let count = arr_clone.len() as i64;
        vm.write_back_arg(0, Value::Array(arr_clone), ref_args, ref_prop_args);
        Ok(Value::Long(count))
    } else {
        Ok(Value::Long(0))
    }
}

// ---------------------------------------------------------------------------
// array_all / array_any / array_find / array_find_key
// ---------------------------------------------------------------------------

fn php_array_all(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let cb_val = args.get(1).cloned().unwrap_or(Value::Null);
    let cb_name = Vm::extract_closure_name(&cb_val);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (key, val) in &entries {
            let k = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            let result = vm.invoke_user_callback(&cb_name, vec![val.clone(), k])?;
            if !result.is_truthy() {
                return Ok(Value::Bool(false));
            }
        }
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_array_any(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let cb_val = args.get(1).cloned().unwrap_or(Value::Null);
    let cb_name = Vm::extract_closure_name(&cb_val);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (key, val) in &entries {
            let k = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            let result = vm.invoke_user_callback(&cb_name, vec![val.clone(), k])?;
            if result.is_truthy() {
                return Ok(Value::Bool(true));
            }
        }
        Ok(Value::Bool(false))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_array_find(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let cb_val = args.get(1).cloned().unwrap_or(Value::Null);
    let cb_name = Vm::extract_closure_name(&cb_val);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (key, val) in &entries {
            let k = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            let result = vm.invoke_user_callback(&cb_name, vec![val.clone(), k])?;
            if result.is_truthy() {
                return Ok(val.clone());
            }
        }
        Ok(Value::Null)
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_array_find_key(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let cb_val = args.get(1).cloned().unwrap_or(Value::Null);
    let cb_name = Vm::extract_closure_name(&cb_val);
    if let Value::Array(ref a) = arr {
        let entries: Vec<_> = a.entries().iter().cloned().collect();
        for (key, val) in &entries {
            let k = match key {
                ArrayKey::Int(n) => Value::Long(*n),
                ArrayKey::String(s) => Value::String(s.clone()),
            };
            let result = vm.invoke_user_callback(&cb_name, vec![val.clone(), k.clone()])?;
            if result.is_truthy() {
                return Ok(k);
            }
        }
        Ok(Value::Null)
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_first / array_last
// ---------------------------------------------------------------------------

fn php_array_first(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(a.entries()
            .first()
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null))
    } else {
        Ok(Value::Null)
    }
}

fn php_array_last(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        Ok(a.entries()
            .last()
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null))
    } else {
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// array_change_key_case
// ---------------------------------------------------------------------------

fn php_array_change_key_case(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    let case = args.get(1).map(|v| v.to_long()).unwrap_or(0); // 0=lower, 1=upper
    if let Value::Array(ref a) = arr {
        let mut result = PhpArray::new();
        for (key, val) in a.entries() {
            match key {
                ArrayKey::String(s) => {
                    let new_key = if case == 0 {
                        s.to_lowercase()
                    } else {
                        s.to_uppercase()
                    };
                    result.set_string(new_key, val.clone());
                }
                ArrayKey::Int(n) => result.set_int(*n, val.clone()),
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// natsort / natcasesort
// ---------------------------------------------------------------------------

fn php_natsort(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut entries: Vec<(ArrayKey, Value)> = a.entries().to_vec();
        entries.sort_by(|a, b| nat_cmp(&a.1.to_php_string(), &b.1.to_php_string()));
        let mut result = PhpArray::new();
        for (k, v) in entries {
            match k {
                ArrayKey::Int(n) => result.set_int(n, v),
                ArrayKey::String(s) => result.set_string(s, v),
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Bool(false))
    }
}

fn php_natcasesort(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let arr = args.first().cloned().unwrap_or(Value::Null);
    if let Value::Array(ref a) = arr {
        let mut entries: Vec<(ArrayKey, Value)> = a.entries().to_vec();
        entries.sort_by(|a, b| {
            nat_cmp(
                &a.1.to_php_string().to_lowercase(),
                &b.1.to_php_string().to_lowercase(),
            )
        });
        let mut result = PhpArray::new();
        for (k, v) in entries {
            match k {
                ArrayKey::Int(n) => result.set_int(n, v),
                ArrayKey::String(s) => result.set_string(s, v),
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// array_diff_uassoc / array_diff_ukey / array_intersect_uassoc /
// array_intersect_ukey / array_udiff / array_udiff_assoc /
// array_udiff_uassoc / array_uintersect / array_uintersect_assoc /
// array_uintersect_uassoc
// ---------------------------------------------------------------------------

/// Generic handler for all user-callback diff/intersect variants.
///
/// Because many different PHP function names map to the same `fn` pointer we
/// need the *runtime* function name to decide which comparison logic to apply.
/// We recover it from the top call-stack frame's op-array function name.
fn php_array_diff_ucb(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // Recover the PHP function name from the call-stack.
    let func_name = vm
        .call_stack
        .last()
        .and_then(|f| {
            let oa = &vm.op_arrays[f.op_array_idx];
            oa.function_name.clone()
        })
        .unwrap_or_else(|| "array_diff_uassoc".to_string());

    let func_name = if func_name.starts_with("array_") {
        func_name
    } else {
        "array_diff_uassoc".to_string()
    };

    let arr1 = args.first().cloned().unwrap_or(Value::Null);
    let arr2 = args.get(1).cloned().unwrap_or(Value::Null);
    let is_diff = func_name.contains("diff");

    // Determine which callbacks to use:
    // *_uassoc variants: last 2 args are (value_cb, key_cb) for udiff_uassoc/uintersect_uassoc
    // Others: last arg is the callback
    let has_two_callbacks = func_name.ends_with("_uassoc");

    let (val_cb, key_cb) = if has_two_callbacks {
        let val_cb_val = args
            .get(args.len().saturating_sub(2))
            .cloned()
            .unwrap_or(Value::Null);
        let key_cb_val = args.last().cloned().unwrap_or(Value::Null);
        (
            Some(Vm::extract_closure_name(&val_cb_val)),
            Some(Vm::extract_closure_name(&key_cb_val)),
        )
    } else {
        let cb_val = args.last().cloned().unwrap_or(Value::Null);
        let cb = Vm::extract_closure_name(&cb_val);
        let compares_keys = func_name.contains("_ukey") || func_name.ends_with("_uassoc");
        let compares_values = func_name.contains("udiff") || func_name.contains("uintersect");
        if compares_keys {
            (None, Some(cb))
        } else if compares_values {
            (Some(cb), None)
        } else {
            (Some(cb), None)
        }
    };

    if let (Value::Array(ref a1), Value::Array(ref a2)) = (&arr1, &arr2) {
        let entries1: Vec<_> = a1.entries().iter().cloned().collect();
        let entries2: Vec<_> = a2.entries().iter().cloned().collect();
        let mut result = PhpArray::new();

        for (key1, val1) in &entries1 {
            let found = entries2.iter().any(|(key2, val2)| {
                // Compare values
                let vals_match = if let Some(ref vcb) = val_cb {
                    let r = vm.invoke_user_callback(vcb, vec![val1.clone(), val2.clone()]);
                    matches!(r, Ok(Value::Long(0)))
                } else {
                    val1.loose_eq(val2)
                };

                // Compare keys
                let keys_match = if let Some(ref kcb) = key_cb {
                    let k1 = match key1 {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let k2 = match key2 {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let r = vm.invoke_user_callback(kcb, vec![k1, k2]);
                    matches!(r, Ok(Value::Long(0)))
                } else {
                    key1 == key2
                };

                let needs_key = func_name.contains("ukey")
                    || func_name.contains("uassoc")
                    || func_name.contains("_assoc");
                let needs_val = func_name.contains("udiff")
                    || func_name.contains("uintersect")
                    || !func_name.contains("ukey");

                if needs_key && needs_val {
                    vals_match && keys_match
                } else if needs_key {
                    keys_match
                } else {
                    vals_match
                }
            });

            if (is_diff && !found) || (!is_diff && found) {
                match key1 {
                    ArrayKey::Int(n) => result.set_int(*n, val1.clone()),
                    ArrayKey::String(s) => result.set_string(s.clone(), val1.clone()),
                }
            }
        }
        Ok(Value::Array(result))
    } else {
        Ok(Value::Array(PhpArray::new()))
    }
}
