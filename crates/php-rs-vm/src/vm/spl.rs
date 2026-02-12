//! SPL classes and built-in method dispatch — extracted from vm.rs.
//!
//! ArrayIterator, DirectoryIterator, SplFileInfo, Exception methods,
//! call_builtin_method dispatch.

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::ZOpArray;

use super::helpers::*;
use super::{ClassDef, Vm, VmError, VmResult};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    /// Handle built-in class method calls (DateTime, DateTimeZone, etc.)
    /// Handle Exception/Error base class methods (getMessage, getCode, etc.)
    /// These work on any object that has the corresponding properties set.
    pub(crate) fn try_exception_method(full_name: &str, args: &[Value]) -> Option<Value> {
        let method = full_name.rsplit("::").next()?;
        let obj = match args.first() {
            Some(Value::Object(o)) => o,
            _ => return None,
        };
        // Check if this looks like an exception object (has "message" property)
        let class = obj.class_name();
        let base = class.rsplit('\\').next().unwrap_or(&class);
        if !base.contains("Exception") && !base.contains("Error") && base != "Throwable" {
            return None;
        }
        match method {
            "getMessage" => Some(
                obj.get_property("message")
                    .unwrap_or(Value::String(String::new())),
            ),
            "getCode" => Some(obj.get_property("code").unwrap_or(Value::Long(0))),
            "getPrevious" => Some(obj.get_property("previous").unwrap_or(Value::Null)),
            "getFile" => Some(
                obj.get_property("file")
                    .unwrap_or(Value::String(String::new())),
            ),
            "getLine" => Some(obj.get_property("line").unwrap_or(Value::Long(0))),
            "getTrace" => Some(Value::Array(PhpArray::new())),
            "getTraceAsString" => Some(Value::String(String::new())),
            "__toString" => {
                let msg = obj
                    .get_property("message")
                    .unwrap_or(Value::String(String::new()))
                    .to_php_string();
                Some(Value::String(msg))
            }
            _ => None,
        }
    }

    /// Check if a class inherits from an SPL class (returns the SPL ancestor name if found).
    pub(crate) fn find_spl_ancestor(&self, class_name: &str) -> Option<String> {
        let spl_classes = [
            "SplFileInfo",
            "DirectoryIterator",
            "FilesystemIterator",
            "RecursiveDirectoryIterator",
            "FilterIterator",
            "RecursiveFilterIterator",
            "RecursiveIteratorIterator",
            "IteratorIterator",
            "AppendIterator",
            "SplFileObject",
            "LimitIterator",
            "InfiniteIterator",
            "NoRewindIterator",
            "CachingIterator",
            "RegexIterator",
            "RecursiveRegexIterator",
            "MultipleIterator",
            "CallbackFilterIterator",
        ];
        let base = class_name.rsplit('\\').next().unwrap_or(class_name);
        if spl_classes.contains(&base) {
            return Some(base.to_string());
        }
        let mut current = class_name.to_string();
        for _ in 0..20 {
            // depth limit
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref parent) = class_def.parent {
                    let parent_base = parent.rsplit('\\').next().unwrap_or(parent);
                    if spl_classes.contains(&parent_base) {
                        return Some(parent_base.to_string());
                    }
                    current = parent.clone();
                    continue;
                }
            }
            break;
        }
        None
    }

    /// Check if a class is a directory iterator (DirectoryIterator, FilesystemIterator, or
    /// RecursiveDirectoryIterator) — as opposed to plain SplFileInfo.
    pub(crate) fn is_directory_iterator_class(&self, class_name: &str) -> bool {
        let dir_classes = [
            "DirectoryIterator",
            "FilesystemIterator",
            "RecursiveDirectoryIterator",
        ];
        let base = class_name.rsplit('\\').next().unwrap_or(class_name);
        if dir_classes.contains(&base) {
            return true;
        }
        // Walk the class hierarchy
        let mut current = class_name.to_string();
        for _ in 0..20 {
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref parent) = class_def.parent {
                    let parent_base = parent.rsplit('\\').next().unwrap_or(parent);
                    if dir_classes.contains(&parent_base) {
                        return true;
                    }
                    current = parent.clone();
                    continue;
                }
            }
            break;
        }
        false
    }

    /// Handle ArrayIterator / ArrayObject method calls.
    pub(crate) fn call_array_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                let data = args
                    .get(1)
                    .cloned()
                    .unwrap_or(Value::Array(PhpArray::new()));
                if let Value::Array(a) = data {
                    obj.set_property("__array_data".to_string(), Value::Array(a));
                } else {
                    obj.set_property("__array_data".to_string(), Value::Array(PhpArray::new()));
                }
                obj.set_property("__array_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__array_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__array_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let len = match obj.get_property("__array_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(index < len)))
            }
            "current" => {
                let index = obj
                    .get_property("__array_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    if let Some((_, val)) = a.entry_at(index) {
                        return Ok(Some(val.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "key" => {
                let index = obj
                    .get_property("__array_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    if let Some((key, _)) = a.entry_at(index) {
                        let key_val = match key {
                            crate::value::ArrayKey::Int(i) => Value::Long(*i),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        return Ok(Some(key_val));
                    }
                }
                Ok(Some(Value::Null))
            }
            "next" => {
                let index = obj
                    .get_property("__array_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__array_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            "count" => {
                let len = match obj.get_property("__array_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Long(len as i64)))
            }
            "offsetExists" => {
                let key = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    Ok(Some(Value::Bool(a.get(&key).is_some())))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "offsetGet" => {
                let key = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    Ok(Some(a.get(&key).cloned().unwrap_or(Value::Null)))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "offsetSet" => {
                let key = args.get(1).cloned().unwrap_or(Value::Null);
                let value = args.get(2).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    let mut a = a.clone();
                    if key == Value::Null {
                        a.push(value);
                    } else {
                        a.set(&key, value);
                    }
                    obj.set_property("__array_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "offsetUnset" => {
                let key = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    let mut a = a.clone();
                    a.unset(&key);
                    obj.set_property("__array_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "append" => {
                let value = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    let mut a = a.clone();
                    a.push(value);
                    obj.set_property("__array_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "getArrayCopy" => {
                let data = obj
                    .get_property("__array_data")
                    .unwrap_or(Value::Array(PhpArray::new()));
                Ok(Some(data))
            }
            "exchangeArray" => {
                let new_data = args
                    .get(1)
                    .cloned()
                    .unwrap_or(Value::Array(PhpArray::new()));
                let old_data = obj
                    .get_property("__array_data")
                    .unwrap_or(Value::Array(PhpArray::new()));
                if let Value::Array(a) = new_data {
                    obj.set_property("__array_data".to_string(), Value::Array(a));
                }
                obj.set_property("__array_index".to_string(), Value::Long(0));
                Ok(Some(old_data))
            }
            "getFlags" => {
                let flags = obj
                    .get_property("__array_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(flags)))
            }
            "setFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__array_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "asort" | "ksort" | "natsort" | "natcasesort" | "uasort" | "uksort" => {
                // Sorting: collect entries, sort, rebuild array
                if let Some(Value::Array(ref a)) = obj.get_property("__array_data") {
                    let mut entries: Vec<(ArrayKey, Value)> = a
                        .entries()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    match method {
                        "ksort" => {
                            entries.sort_by(|(k1, _), (k2, _)| {
                                let s1 = match k1 {
                                    ArrayKey::Int(i) => i.to_string(),
                                    ArrayKey::String(s) => s.clone(),
                                };
                                let s2 = match k2 {
                                    ArrayKey::Int(i) => i.to_string(),
                                    ArrayKey::String(s) => s.clone(),
                                };
                                s1.cmp(&s2)
                            });
                        }
                        _ => {
                            // asort, natsort, natcasesort: sort by value
                            entries.sort_by(|(_, v1), (_, v2)| {
                                let s1 = v1.to_php_string();
                                let s2 = v2.to_php_string();
                                s1.cmp(&s2)
                            });
                        }
                    }
                    let mut new_arr = PhpArray::new();
                    for (k, v) in entries {
                        match k {
                            ArrayKey::Int(i) => new_arr.set_int(i, v),
                            ArrayKey::String(s) => new_arr.set_string(s, v),
                        }
                    }
                    obj.set_property("__array_data".to_string(), Value::Array(new_arr));
                }
                Ok(Some(Value::Bool(true)))
            }
            "seek" => {
                let position = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                let len = match obj.get_property("__array_data") {
                    Some(Value::Array(ref a)) => a.len() as i64,
                    _ => 0,
                };
                if position < 0 || position >= len {
                    return Err(VmError::FatalError(format!(
                        "Seek position {} is out of range",
                        position
                    )));
                }
                obj.set_property("__array_index".to_string(), Value::Long(position));
                Ok(Some(Value::Null))
            }
            "serialize" => {
                let data = obj
                    .get_property("__array_data")
                    .unwrap_or(Value::Array(PhpArray::new()));
                // Simplified serialization
                Ok(Some(Value::String(format!("{}", data.to_php_string()))))
            }
            "getIterator" => {
                // ArrayObject::getIterator returns an ArrayIterator
                let iter = PhpObject::new("ArrayIterator".to_string());
                iter.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                let data = obj
                    .get_property("__array_data")
                    .unwrap_or(Value::Array(PhpArray::new()));
                iter.set_property("__array_data".to_string(), data);
                iter.set_property("__array_index".to_string(), Value::Long(0));
                Ok(Some(Value::Object(iter)))
            }
            _ => Ok(None),
        }
    }

    /// Handle CallbackFilterIterator method calls.
    /// CallbackFilterIterator wraps an iterator and filters using a callback function.
    pub(crate) fn call_callback_filter_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "accept" => {
                // Get the callback stored on the object
                let callback = obj.get_property("__filter_callback").unwrap_or(Value::Null);
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);

                // Get current value, key, and iterator from inner
                let current = if let Value::Object(_) = &inner {
                    self.call_method_sync(&inner, "current")
                        .unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                let key = if let Value::Object(_) = &inner {
                    self.call_method_sync(&inner, "key").unwrap_or(Value::Null)
                } else {
                    Value::Null
                };

                // Invoke the callback with (current, key, iterator)
                let callback_name = Self::extract_closure_name(&callback);
                let result =
                    self.invoke_user_callback(&callback_name, vec![current, key, inner])?;
                Ok(Some(Value::Bool(result.to_bool())))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            _ => Ok(None),
        }
    }

    /// Handle FilterIterator / IteratorIterator / RecursiveIteratorIterator method calls.
    /// These wrap an inner iterator and delegate to it.
    pub(crate) fn call_wrapper_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                // Store inner iterator — delegate all iteration to it
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                let _mode = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                Ok(Some(Value::Null))
            }
            "getInnerIterator" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                Ok(Some(inner))
            }
            "rewind" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                }
                // FilterIterator: skip to first accepted element
                let this_val = Value::Object(obj.clone());
                let class_name = obj.class_name();
                let base_cn = class_name.rsplit('\\').next().unwrap_or(&class_name);
                let has_accept = self.resolve_method(&class_name, "accept").is_some()
                    || matches!(
                        base_cn,
                        "CallbackFilterIterator"
                            | "RecursiveCallbackFilterIterator"
                            | "RegexIterator"
                            | "RecursiveRegexIterator"
                    )
                    || obj.get_property("__filter_callback").is_some();
                if has_accept {
                    for _ in 0..10000 {
                        let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                        let valid = if let Value::Object(_) = &inner {
                            self.call_method_sync(&inner, "valid")
                                .unwrap_or(Value::Bool(false))
                                .to_bool()
                        } else {
                            false
                        };
                        if !valid {
                            break;
                        }
                        let accepted = self
                            .call_method_sync(&this_val, "accept")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        if accepted {
                            break;
                        }
                        if let Value::Object(_) = &inner {
                            let _ = self.call_method_sync(&inner, "next");
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "valid" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    match self.call_method_sync(&inner, "valid") {
                        Ok(v) => Ok(Some(v)),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "next");
                }
                // FilterIterator: skip non-accepted elements
                let this_val = Value::Object(obj.clone());
                let class_name = obj.class_name();
                let base_cn = class_name.rsplit('\\').next().unwrap_or(&class_name);
                let has_accept = self.resolve_method(&class_name, "accept").is_some()
                    || matches!(
                        base_cn,
                        "CallbackFilterIterator"
                            | "RecursiveCallbackFilterIterator"
                            | "RegexIterator"
                            | "RecursiveRegexIterator"
                    )
                    || obj.get_property("__filter_callback").is_some();
                if has_accept {
                    for _ in 0..10000 {
                        let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                        let valid = if let Value::Object(_) = &inner {
                            self.call_method_sync(&inner, "valid")
                                .unwrap_or(Value::Bool(false))
                                .to_bool()
                        } else {
                            false
                        };
                        if !valid {
                            break;
                        }
                        let accepted = self
                            .call_method_sync(&this_val, "accept")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        if accepted {
                            break;
                        }
                        if let Value::Object(_) = &inner {
                            let _ = self.call_method_sync(&inner, "next");
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "current" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    match self.call_method_sync(&inner, "current") {
                        Ok(v) => Ok(Some(v)),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "key" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    match self.call_method_sync(&inner, "key") {
                        Ok(v) => Ok(Some(v)),
                        Err(_) => Ok(Some(Value::Null)),
                    }
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "setMaxDepth" => {
                let depth = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                obj.set_property("__max_depth".to_string(), Value::Long(depth));
                Ok(Some(Value::Null))
            }
            "getMaxDepth" => {
                let depth = obj
                    .get_property("__max_depth")
                    .map(|v| v.to_long())
                    .unwrap_or(-1);
                Ok(Some(Value::Long(depth)))
            }
            "getDepth" => {
                // For now, return 0 (single-level iteration)
                // TODO: Track actual recursion depth when implementing true recursive traversal
                Ok(Some(Value::Long(0)))
            }
            _ => Ok(None),
        }
    }

    /// Handle RecursiveDirectoryIterator / DirectoryIterator method calls.
    pub(crate) fn call_dir_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                // Initialize SplFileInfo or directory iterator state
                let path = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();

                // Check if this is a directory iterator subclass or just SplFileInfo
                let class_name = obj.class_name();
                let is_dir_iterator = self.is_directory_iterator_class(&class_name);

                if is_dir_iterator {
                    // Directory iterator: read directory entries
                    let mut entries = PhpArray::new();
                    if let Ok(names) = self.vm_read_dir(&path) {
                        for name in names {
                            let full = if path.ends_with('/') || path.ends_with('\\') {
                                format!("{}{}", path, name)
                            } else {
                                format!("{}/{}", path, name)
                            };
                            let mut info = PhpArray::new();
                            info.set_string("name".to_string(), Value::String(name));
                            info.set_string("path".to_string(), Value::String(full));
                            entries.push(Value::Array(info));
                        }
                    }
                    obj.set_property("__dir_path".to_string(), Value::String(path));
                    obj.set_property("__dir_entries".to_string(), Value::Array(entries));
                    obj.set_property("__dir_index".to_string(), Value::Long(0));
                    obj.set_property("__dir_sub_path".to_string(), Value::String(String::new()));
                } else {
                    // Plain SplFileInfo: just store the path
                    obj.set_property("__spl_path".to_string(), Value::String(path));
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__dir_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let entries = obj.get_property("__dir_entries").unwrap_or(Value::Null);
                let len = if let Value::Array(ref a) = entries {
                    a.len()
                } else {
                    0
                };
                Ok(Some(Value::Bool(index < len)))
            }
            "next" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__dir_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            "key" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "current" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let entries = obj.get_property("__dir_entries").unwrap_or(Value::Null);
                if let Value::Array(ref a) = entries {
                    if let Some((_, entry)) = a.entry_at(index) {
                        if let Value::Array(ref info) = entry {
                            let full_path = info
                                .get_string("path")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default();
                            // Return an SplFileInfo-like object
                            let fi = PhpObject::new("SplFileInfo".to_string());
                            fi.set_object_id(self.next_object_id);
                            self.next_object_id += 1;
                            fi.set_property("__spl_path".to_string(), Value::String(full_path));
                            return Ok(Some(Value::Object(fi)));
                        }
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "hasChildren" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let entries = obj.get_property("__dir_entries").unwrap_or(Value::Null);
                if let Value::Array(ref a) = entries {
                    if let Some((_, entry)) = a.entry_at(index) {
                        if let Value::Array(ref info) = entry {
                            let full_path = info
                                .get_string("path")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default();
                            return Ok(Some(Value::Bool(
                                std::path::Path::new(&full_path).is_dir(),
                            )));
                        }
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "getChildren" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let entries = obj.get_property("__dir_entries").unwrap_or(Value::Null);
                if let Value::Array(ref a) = entries {
                    if let Some((_, entry)) = a.entry_at(index) {
                        if let Value::Array(ref info) = entry {
                            let full_path = info
                                .get_string("path")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default();
                            // Create a new RecursiveDirectoryIterator for the subdirectory
                            let child_obj = PhpObject::new(obj.class_name().to_string());
                            child_obj.set_object_id(self.next_object_id);
                            self.next_object_id += 1;
                            // Initialize child's entries
                            let mut child_entries = PhpArray::new();
                            if let Ok(names) = self.vm_read_dir(&full_path) {
                                for name in names {
                                    let full =
                                        if full_path.ends_with('/') || full_path.ends_with('\\') {
                                            format!("{}{}", full_path, name)
                                        } else {
                                            format!("{}/{}", full_path, name)
                                        };
                                    let mut ei = PhpArray::new();
                                    ei.set_string("name".to_string(), Value::String(name));
                                    ei.set_string("path".to_string(), Value::String(full));
                                    child_entries.push(Value::Array(ei));
                                }
                            }
                            child_obj
                                .set_property("__dir_path".to_string(), Value::String(full_path));
                            child_obj.set_property(
                                "__dir_entries".to_string(),
                                Value::Array(child_entries),
                            );
                            child_obj.set_property("__dir_index".to_string(), Value::Long(0));
                            child_obj.set_property(
                                "__dir_sub_path".to_string(),
                                Value::String(String::new()),
                            );
                            return Ok(Some(Value::Object(child_obj)));
                        }
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "getSubPath" => {
                let sub = obj
                    .get_property("__dir_sub_path")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(sub)))
            }
            "getSubPathname" => {
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let entries = obj.get_property("__dir_entries").unwrap_or(Value::Null);
                let sub = obj
                    .get_property("__dir_sub_path")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                if let Value::Array(ref a) = entries {
                    if let Some((_, entry)) = a.entry_at(index) {
                        if let Value::Array(ref info) = entry {
                            let name = info
                                .get_string("name")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default();
                            if sub.is_empty() {
                                return Ok(Some(Value::String(name)));
                            } else {
                                return Ok(Some(Value::String(format!("{}/{}", sub, name))));
                            }
                        }
                    }
                }
                Ok(Some(Value::String(String::new())))
            }
            _ => Ok(None),
        }
    }

    /// Handle SplFileInfo method calls.
    pub(crate) fn call_spl_file_info_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let path = if let Some(Value::Object(ref obj)) = args.first() {
            // First try __spl_path (set directly on SplFileInfo objects)
            if let Some(p) = obj.get_property("__spl_path") {
                p.to_php_string()
            } else if let Some(entries) = obj.get_property("__dir_entries") {
                // For iterator objects, use the current entry's path
                let index = obj
                    .get_property("__dir_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Value::Array(ref a) = entries {
                    if let Some((_, entry)) = a.entry_at(index) {
                        if let Value::Array(ref info) = entry {
                            info.get_string("path")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            return Ok(None);
        };
        let p = std::path::Path::new(&path);
        match method {
            "isFile" => Ok(Some(Value::Bool(self.vm_is_file(&path)))),
            "isDir" => Ok(Some(Value::Bool(self.vm_is_dir(&path)))),
            "isLink" => Ok(Some(Value::Bool(p.is_symlink()))),
            "isReadable" | "isWritable" => Ok(Some(Value::Bool(self.vm_file_exists(&path)))),
            "getRealPath" => {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    match std::fs::canonicalize(p) {
                        Ok(real) => Ok(Some(Value::String(real.to_string_lossy().to_string()))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    if self.vm_file_exists(&path) {
                        Ok(Some(Value::String(path.clone())))
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                }
            }
            "getPathname" => Ok(Some(Value::String(path.clone()))),
            "getFilename" => {
                let fname = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(fname)))
            }
            "getBasename" => {
                let fname = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let suffix = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                if !suffix.is_empty() && fname.ends_with(&suffix) {
                    Ok(Some(Value::String(
                        fname[..fname.len() - suffix.len()].to_string(),
                    )))
                } else {
                    Ok(Some(Value::String(fname)))
                }
            }
            "getPath" => {
                let dir = p
                    .parent()
                    .map(|d| d.to_string_lossy().to_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(dir)))
            }
            "getExtension" => {
                let ext = p
                    .extension()
                    .map(|e| e.to_string_lossy().to_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(ext)))
            }
            "getSize" => match self.vm_file_size(&path) {
                Ok(size) => Ok(Some(Value::Long(size as i64))),
                Err(_) => Ok(Some(Value::Bool(false))),
            },
            "getMTime" | "getCTime" | "getATime" => {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    match std::fs::metadata(p) {
                        Ok(m) => {
                            let time = match method {
                                "getMTime" => m.modified(),
                                "getCTime" | "getATime" => m.modified(), // fallback to mtime
                                _ => m.modified(),
                            };
                            match time {
                                Ok(t) => {
                                    let secs = t
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                        as i64;
                                    Ok(Some(Value::Long(secs)))
                                }
                                Err(_) => Ok(Some(Value::Long(0))),
                            }
                        }
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = p;
                    Ok(Some(Value::Long(0)))
                }
            }
            "getType" => {
                if self.vm_is_file(&path) {
                    Ok(Some(Value::String("file".to_string())))
                } else if self.vm_is_dir(&path) {
                    Ok(Some(Value::String("dir".to_string())))
                } else if p.is_symlink() {
                    Ok(Some(Value::String("link".to_string())))
                } else {
                    Ok(Some(Value::String("unknown".to_string())))
                }
            }
            "getContents" => match self.vm_read_to_string(&path) {
                Ok(s) => Ok(Some(Value::String(s))),
                Err(e) => Err(VmError::FatalError(format!(
                    "SplFileInfo::getContents(): Unable to read file: {}",
                    e
                ))),
            },
            "__toString" | "toString" => Ok(Some(Value::String(path.clone()))),
            _ => Ok(None),
        }
    }

    pub(crate) fn call_builtin_method(
        &mut self,
        full_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let sep = full_name.find("::").unwrap_or(0);
        let class_part = &full_name[..sep];
        let method = &full_name[sep + 2..];
        let base_class = class_part.rsplit('\\').next().unwrap_or(class_part);

        // Check if this is a SplFileInfo family method
        let is_spl_file_info = matches!(
            base_class,
            "SplFileInfo"
                | "DirectoryIterator"
                | "FilesystemIterator"
                | "RecursiveDirectoryIterator"
        );

        if is_spl_file_info {
            // Check for iterator methods first
            if let Some(result) = self.call_dir_iterator_method(method, args)? {
                return Ok(Some(result));
            }
            return self.call_spl_file_info_method(method, args);
        }

        // Check if this class inherits from an SPL iterator/file class
        if !is_spl_file_info {
            let spl_ancestor = self.find_spl_ancestor(class_part);
            if let Some(ref ancestor) = spl_ancestor {
                let ancestor_base = ancestor.rsplit('\\').next().unwrap_or(ancestor);
                // For directory iterators, try dir methods first, then SplFileInfo
                if matches!(
                    ancestor_base,
                    "SplFileInfo"
                        | "DirectoryIterator"
                        | "FilesystemIterator"
                        | "RecursiveDirectoryIterator"
                ) {
                    if let Some(result) = self.call_dir_iterator_method(method, args)? {
                        return Ok(Some(result));
                    }
                    return self.call_spl_file_info_method(method, args);
                }
                // For filter/wrapper iterators, delegate to inner iterator
                if matches!(
                    ancestor_base,
                    "FilterIterator"
                        | "RecursiveFilterIterator"
                        | "IteratorIterator"
                        | "RecursiveIteratorIterator"
                ) {
                    if let Some(result) = self.call_wrapper_iterator_method(method, args)? {
                        return Ok(Some(result));
                    }
                }
            }
        }

        // Check if this is an ArrayIterator / ArrayObject
        if matches!(base_class, "ArrayIterator" | "ArrayObject") {
            if let Some(result) = self.call_array_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // EmptyIterator — always empty
        if base_class == "EmptyIterator" {
            return match method {
                "rewind" | "next" | "__construct" => Ok(Some(Value::Null)),
                "valid" => Ok(Some(Value::Bool(false))),
                "current" | "key" => Ok(Some(Value::Null)),
                _ => Ok(None),
            };
        }

        // Check if this is a PDO method
        #[cfg(feature = "native-io")]
        if base_class == "PDO" {
            return self.call_pdo_method(method, args);
        }

        // Check if this is a PDOStatement method
        #[cfg(feature = "native-io")]
        if base_class == "PDOStatement" {
            return self.call_pdo_statement_method(method, args);
        }

        // Check if this is a SQLite3 method
        #[cfg(feature = "native-io")]
        if base_class == "SQLite3" {
            return self.call_sqlite3_method(method, args);
        }

        // Check if this is a SQLite3Result method
        #[cfg(feature = "native-io")]
        if base_class == "SQLite3Result" {
            return self.call_sqlite3_result_method(method, args);
        }

        // Check if this is a SQLite3Stmt method
        #[cfg(feature = "native-io")]
        if base_class == "SQLite3Stmt" {
            return self.call_sqlite3_stmt_method(method, args);
        }

        // DateTime / DateTimeImmutable methods
        if matches!(base_class, "DateTime" | "DateTimeImmutable") {
            if let Some(result) = self.call_datetime_method(base_class, method, args)? {
                return Ok(Some(result));
            }
        }

        // DateTimeZone / CarbonTimeZone methods
        if matches!(base_class, "DateTimeZone" | "CarbonTimeZone") {
            if let Some(result) = self.call_datetimezone_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // DateInterval methods
        if base_class == "DateInterval" {
            if let Some(result) = self.call_dateinterval_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // DatePeriod methods
        if base_class == "DatePeriod" {
            if let Some(result) = self.call_dateperiod_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // SplFixedArray methods
        if base_class == "SplFixedArray" {
            if let Some(result) = self.call_spl_fixed_array_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // SplDoublyLinkedList / SplStack / SplQueue methods
        if matches!(base_class, "SplDoublyLinkedList" | "SplStack" | "SplQueue") {
            if let Some(result) = self.call_spl_dll_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // SplHeap / SplMinHeap / SplMaxHeap / SplPriorityQueue methods
        if matches!(
            base_class,
            "SplHeap" | "SplMinHeap" | "SplMaxHeap" | "SplPriorityQueue"
        ) {
            if let Some(result) = self.call_spl_heap_method(base_class, method, args)? {
                return Ok(Some(result));
            }
        }

        // SplObjectStorage methods
        if base_class == "SplObjectStorage" {
            if let Some(result) = self.call_spl_object_storage_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // CallbackFilterIterator — FilterIterator with callback-based accept()
        if matches!(
            base_class,
            "CallbackFilterIterator" | "RecursiveCallbackFilterIterator"
        ) {
            if let Some(result) = self.call_callback_filter_iterator_method(method, args)? {
                return Ok(Some(result));
            }
            // Fall through to wrapper iterator for rewind/valid/current/key/next
            if let Some(result) = self.call_wrapper_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // LimitIterator methods
        if base_class == "LimitIterator" {
            if let Some(result) = self.call_limit_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // InfiniteIterator methods
        if base_class == "InfiniteIterator" {
            if let Some(result) = self.call_infinite_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // NoRewindIterator methods
        if base_class == "NoRewindIterator" {
            if let Some(result) = self.call_norewind_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // AppendIterator methods
        if base_class == "AppendIterator" {
            if let Some(result) = self.call_append_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // CachingIterator methods
        if base_class == "CachingIterator" {
            if let Some(result) = self.call_caching_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // RegexIterator methods
        if base_class == "RegexIterator" {
            if let Some(result) = self.call_regex_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // RecursiveRegexIterator methods
        if base_class == "RecursiveRegexIterator" {
            if let Some(result) = self.call_regex_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // MultipleIterator methods
        if base_class == "MultipleIterator" {
            if let Some(result) = self.call_multiple_iterator_method(method, args)? {
                return Ok(Some(result));
            }
        }

        // SplFileObject methods
        if base_class == "SplFileObject" {
            if let Some(result) = self.call_spl_file_object_method(method, args)? {
                return Ok(Some(result));
            }
            // Fall through to SplFileInfo methods
            return self.call_spl_file_info_method(method, args);
        }

        // SplTempFileObject methods
        if base_class == "SplTempFileObject" {
            if let Some(result) = self.call_spl_file_object_method(method, args)? {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    // ── DateTime / DateTimeImmutable method dispatch ─────────────────────────

    fn call_datetime_method(
        &mut self,
        class_name: &str,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        // Handle static methods that may be called without $this
        let is_static_call = !matches!(args.first(), Some(Value::Object(_)));
        if is_static_call {
            // For static calls, args are direct (no $this prefix)
            return self.call_datetime_static_method(class_name, method, args);
        }
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };
        let is_immutable = class_name == "DateTimeImmutable";

        match method {
            "format" => {
                let fmt = args
                    .get(1)
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "Y-m-d H:i:s".to_string());
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or_else(php_rs_ext_date::php_time);
                let tz = obj
                    .get_property("__timezone")
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "UTC".to_string());
                let tz_offset = php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz).unwrap_or(0);
                Ok(Some(Value::String(php_date_format(
                    &fmt,
                    ts + tz_offset as i64,
                ))))
            }
            "getTimestamp" => {
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or_else(php_rs_ext_date::php_time);
                Ok(Some(Value::Long(ts)))
            }
            "modify" => {
                let modifier = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or_else(php_rs_ext_date::php_time);
                let new_ts = php_rs_ext_date::php_strtotime(&modifier, Some(ts)).unwrap_or(ts);
                if is_immutable {
                    let new_obj = PhpObject::new(class_name.to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    new_obj.set_property("__timestamp".to_string(), Value::Long(new_ts));
                    new_obj.set_property(
                        "__timezone".to_string(),
                        obj.get_property("__timezone")
                            .unwrap_or(Value::String("UTC".to_string())),
                    );
                    Ok(Some(Value::Object(new_obj)))
                } else {
                    obj.set_property("__timestamp".to_string(), Value::Long(new_ts));
                    Ok(Some(args.first().cloned().unwrap_or(Value::Null)))
                }
            }
            "setDate" => {
                let year = args.get(1).map(|v| v.to_long() as i32).unwrap_or(1970);
                let month = args.get(2).map(|v| v.to_long() as i32).unwrap_or(1);
                let day = args.get(3).map(|v| v.to_long() as i32).unwrap_or(1);
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let mut php_dt = php_rs_ext_date::PhpDateTime {
                    timestamp: ts,
                    timezone: "UTC".to_string(),
                };
                php_dt.set_date(year, month, day);
                if is_immutable {
                    let new_obj = PhpObject::new(class_name.to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    new_obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                    new_obj.set_property(
                        "__timezone".to_string(),
                        obj.get_property("__timezone")
                            .unwrap_or(Value::String("UTC".to_string())),
                    );
                    Ok(Some(Value::Object(new_obj)))
                } else {
                    obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                    Ok(Some(args.first().cloned().unwrap_or(Value::Null)))
                }
            }
            "setTime" => {
                let hour = args.get(1).map(|v| v.to_long() as i32).unwrap_or(0);
                let minute = args.get(2).map(|v| v.to_long() as i32).unwrap_or(0);
                let second = args.get(3).map(|v| v.to_long() as i32).unwrap_or(0);
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let mut php_dt = php_rs_ext_date::PhpDateTime {
                    timestamp: ts,
                    timezone: "UTC".to_string(),
                };
                php_dt.set_time(hour, minute, second);
                if is_immutable {
                    let new_obj = PhpObject::new(class_name.to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    new_obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                    new_obj.set_property(
                        "__timezone".to_string(),
                        obj.get_property("__timezone")
                            .unwrap_or(Value::String("UTC".to_string())),
                    );
                    Ok(Some(Value::Object(new_obj)))
                } else {
                    obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                    Ok(Some(args.first().cloned().unwrap_or(Value::Null)))
                }
            }
            "setTimezone" => {
                let tz_name = match args.get(1) {
                    Some(Value::Object(tz_obj)) => tz_obj
                        .get_property("__tz_name")
                        .map(|v| v.to_php_string())
                        .unwrap_or_else(|| "UTC".to_string()),
                    Some(v) => v.to_php_string(),
                    _ => "UTC".to_string(),
                };
                if is_immutable {
                    let new_obj = PhpObject::new(class_name.to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    new_obj.set_property(
                        "__timestamp".to_string(),
                        obj.get_property("__timestamp").unwrap_or(Value::Long(0)),
                    );
                    new_obj.set_property("__timezone".to_string(), Value::String(tz_name));
                    Ok(Some(Value::Object(new_obj)))
                } else {
                    obj.set_property("__timezone".to_string(), Value::String(tz_name));
                    Ok(Some(args.first().cloned().unwrap_or(Value::Null)))
                }
            }
            "getTimezone" => {
                let tz_name = obj
                    .get_property("__timezone")
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "UTC".to_string());
                let tz_obj = PhpObject::new("DateTimeZone".to_string());
                tz_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                let offset =
                    php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz_name).unwrap_or(0);
                tz_obj.set_property("__tz_name".to_string(), Value::String(tz_name));
                tz_obj.set_property("__tz_offset".to_string(), Value::Long(offset as i64));
                Ok(Some(Value::Object(tz_obj)))
            }
            "getOffset" => {
                let tz = obj
                    .get_property("__timezone")
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "UTC".to_string());
                let offset = php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz).unwrap_or(0);
                Ok(Some(Value::Long(offset as i64)))
            }
            "diff" => {
                let other_ts = match args.get(1) {
                    Some(Value::Object(ref other)) => other
                        .get_property("__timestamp")
                        .map(|v| v.to_long())
                        .unwrap_or(0),
                    _ => 0,
                };
                let my_ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let dt1 = php_rs_ext_date::PhpDateTime {
                    timestamp: my_ts,
                    timezone: "UTC".to_string(),
                };
                let dt2 = php_rs_ext_date::PhpDateTime {
                    timestamp: other_ts,
                    timezone: "UTC".to_string(),
                };
                let di = dt1.diff(&dt2);
                let interval = PhpObject::new("DateInterval".to_string());
                interval.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                interval.set_property("y".to_string(), Value::Long(di.years as i64));
                interval.set_property("m".to_string(), Value::Long(di.months as i64));
                interval.set_property("d".to_string(), Value::Long(di.days as i64));
                interval.set_property("h".to_string(), Value::Long(di.hours as i64));
                interval.set_property("i".to_string(), Value::Long(di.minutes as i64));
                interval.set_property("s".to_string(), Value::Long(di.seconds as i64));
                interval.set_property(
                    "invert".to_string(),
                    Value::Long(if di.invert { 1 } else { 0 }),
                );
                // Total days between dates
                let total_days = ((my_ts - other_ts).abs()) / 86400;
                interval.set_property("days".to_string(), Value::Long(total_days));
                Ok(Some(Value::Object(interval)))
            }
            "add" | "sub" => {
                // add/sub take a DateInterval object
                let di_obj = match args.get(1) {
                    Some(Value::Object(ref o)) => o,
                    _ => return Ok(Some(args.first().cloned().unwrap_or(Value::Null))),
                };
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let years = di_obj
                    .get_property("y")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let months = di_obj
                    .get_property("m")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let days = di_obj
                    .get_property("d")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let hours = di_obj
                    .get_property("h")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let minutes = di_obj
                    .get_property("i")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let seconds = di_obj
                    .get_property("s")
                    .map(|v| v.to_long() as i32)
                    .unwrap_or(0);
                let sign: i64 = if method == "sub" { -1 } else { 1 };
                // Apply month/year arithmetic
                let dt = php_rs_ext_date::DateTime::from_timestamp(ts);
                let total_months =
                    dt.year * 12 + dt.month as i64 - 1 + sign * (years as i64 * 12 + months as i64);
                let new_year = total_months.div_euclid(12);
                let new_month = (total_months.rem_euclid(12) + 1) as u8;
                let new_dt = php_rs_ext_date::DateTime {
                    year: new_year,
                    month: new_month,
                    day: dt.day,
                    hour: dt.hour,
                    minute: dt.minute,
                    second: dt.second,
                };
                let new_ts = new_dt.to_timestamp()
                    + sign
                        * (days as i64 * 86400
                            + hours as i64 * 3600
                            + minutes as i64 * 60
                            + seconds as i64);
                if is_immutable {
                    let new_obj = PhpObject::new(class_name.to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    new_obj.set_property("__timestamp".to_string(), Value::Long(new_ts));
                    new_obj.set_property(
                        "__timezone".to_string(),
                        obj.get_property("__timezone")
                            .unwrap_or(Value::String("UTC".to_string())),
                    );
                    Ok(Some(Value::Object(new_obj)))
                } else {
                    obj.set_property("__timestamp".to_string(), Value::Long(new_ts));
                    Ok(Some(args.first().cloned().unwrap_or(Value::Null)))
                }
            }
            "getLastErrors" => Ok(Some(Value::Bool(false))),
            "createFromFormat" => {
                // Static method: DateTime::createFromFormat($format, $datetime, $timezone)
                let fmt = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let datetime = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                match php_rs_ext_date::PhpDateTime::create_from_format(&fmt, &datetime) {
                    Ok(php_dt) => {
                        let new_obj = PhpObject::new(class_name.to_string());
                        new_obj.set_object_id(self.next_object_id);
                        self.next_object_id += 1;
                        new_obj
                            .set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                        new_obj
                            .set_property("__timezone".to_string(), Value::String(php_dt.timezone));
                        Ok(Some(Value::Object(new_obj)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            "createFromTimestamp" => {
                let ts = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                new_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                Ok(Some(Value::Object(new_obj)))
            }
            "createFromMutable" | "createFromImmutable" => {
                // Convert between DateTime and DateTimeImmutable
                let src = match args.get(1) {
                    Some(Value::Object(ref o)) => o,
                    _ => return Ok(Some(Value::Bool(false))),
                };
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property(
                    "__timestamp".to_string(),
                    src.get_property("__timestamp").unwrap_or(Value::Long(0)),
                );
                new_obj.set_property(
                    "__timezone".to_string(),
                    src.get_property("__timezone")
                        .unwrap_or(Value::String("UTC".to_string())),
                );
                Ok(Some(Value::Object(new_obj)))
            }
            "instance" | "create" | "parse" => {
                let time_str = args.get(1).map(|v| v.to_php_string());
                let ts = match time_str.as_deref() {
                    Some(s) => php_rs_ext_date::php_strtotime(s, None)
                        .unwrap_or_else(php_rs_ext_date::php_time),
                    None => php_rs_ext_date::php_time(),
                };
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                new_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                Ok(Some(Value::Object(new_obj)))
            }
            "__toString" => {
                let ts = obj
                    .get_property("__timestamp")
                    .map(|v| v.to_long())
                    .unwrap_or_else(php_rs_ext_date::php_time);
                Ok(Some(Value::String(php_date_format("Y-m-d H:i:s", ts))))
            }
            _ => Ok(None),
        }
    }

    /// Handle DateTime/DateTimeImmutable static methods (no $this in args)
    fn call_datetime_static_method(
        &mut self,
        class_name: &str,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        match method {
            "createFromFormat" => {
                // DateTime::createFromFormat($format, $datetime, $timezone)
                let fmt = args.first().map(|v| v.to_php_string()).unwrap_or_default();
                let datetime = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                match php_rs_ext_date::PhpDateTime::create_from_format(&fmt, &datetime) {
                    Ok(php_dt) => {
                        let new_obj = PhpObject::new(class_name.to_string());
                        new_obj.set_object_id(self.next_object_id);
                        self.next_object_id += 1;
                        new_obj
                            .set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
                        new_obj
                            .set_property("__timezone".to_string(), Value::String(php_dt.timezone));
                        Ok(Some(Value::Object(new_obj)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            "createFromTimestamp" => {
                let ts = args.first().map(|v| v.to_long()).unwrap_or(0);
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                new_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                Ok(Some(Value::Object(new_obj)))
            }
            "createFromMutable" | "createFromImmutable" => {
                let src = match args.first() {
                    Some(Value::Object(ref o)) => o,
                    _ => return Ok(Some(Value::Bool(false))),
                };
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property(
                    "__timestamp".to_string(),
                    src.get_property("__timestamp").unwrap_or(Value::Long(0)),
                );
                new_obj.set_property(
                    "__timezone".to_string(),
                    src.get_property("__timezone")
                        .unwrap_or(Value::String("UTC".to_string())),
                );
                Ok(Some(Value::Object(new_obj)))
            }
            "instance" | "create" | "parse" => {
                let time_str = args.first().map(|v| v.to_php_string());
                let ts = match time_str.as_deref() {
                    Some(s) => php_rs_ext_date::php_strtotime(s, None)
                        .unwrap_or_else(php_rs_ext_date::php_time),
                    None => php_rs_ext_date::php_time(),
                };
                let new_obj = PhpObject::new(class_name.to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                new_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                new_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                Ok(Some(Value::Object(new_obj)))
            }
            "getLastErrors" => Ok(Some(Value::Bool(false))),
            _ => Ok(None),
        }
    }

    // ── DateTimeZone method dispatch ────────────────────────────────────────

    fn call_datetimezone_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "getName" | "getTimezoneName" | "__toString" => {
                let name = obj
                    .get_property("__tz_name")
                    .or_else(|| obj.get_property("__datetime_value"))
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "UTC".to_string());
                Ok(Some(Value::String(name)))
            }
            "getOffset" => {
                let offset = obj
                    .get_property("__tz_offset")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(offset)))
            }
            "listIdentifiers" => {
                let ids = php_rs_ext_date::PhpDateTimeZone::list_identifiers();
                let mut arr = PhpArray::new();
                for id in ids {
                    arr.push(Value::String(id));
                }
                Ok(Some(Value::Array(arr)))
            }
            "listAbbreviations" => Ok(Some(Value::Array(PhpArray::new()))),
            "toMutable" => Ok(Some(args.first().cloned().unwrap_or(Value::Null))),
            _ => Ok(None),
        }
    }

    // ── DateInterval method dispatch ────────────────────────────────────────

    fn call_dateinterval_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "format" => {
                let fmt = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let di = php_rs_ext_date::PhpDateInterval {
                    years: obj
                        .get_property("y")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    months: obj
                        .get_property("m")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    days: obj
                        .get_property("d")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    hours: obj
                        .get_property("h")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    minutes: obj
                        .get_property("i")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    seconds: obj
                        .get_property("s")
                        .map(|v| v.to_long() as i32)
                        .unwrap_or(0),
                    invert: obj
                        .get_property("invert")
                        .map(|v| v.to_long() != 0)
                        .unwrap_or(false),
                };
                Ok(Some(Value::String(di.format(&fmt))))
            }
            "createFromDateString" => {
                // Static method
                let spec = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                // Try ISO 8601 first, then relative string
                let di = if spec.starts_with('P') || spec.starts_with('p') {
                    php_rs_ext_date::PhpDateInterval::create_from_date_string(&spec)
                } else {
                    // Parse relative string like "1 day" or "2 months"
                    parse_relative_to_interval(&spec)
                };
                match di {
                    Ok(di) => {
                        let interval = PhpObject::new("DateInterval".to_string());
                        interval.set_object_id(self.next_object_id);
                        self.next_object_id += 1;
                        interval.set_property("y".to_string(), Value::Long(di.years as i64));
                        interval.set_property("m".to_string(), Value::Long(di.months as i64));
                        interval.set_property("d".to_string(), Value::Long(di.days as i64));
                        interval.set_property("h".to_string(), Value::Long(di.hours as i64));
                        interval.set_property("i".to_string(), Value::Long(di.minutes as i64));
                        interval.set_property("s".to_string(), Value::Long(di.seconds as i64));
                        interval.set_property(
                            "invert".to_string(),
                            Value::Long(if di.invert { 1 } else { 0 }),
                        );
                        interval.set_property(
                            "days".to_string(),
                            Value::Long(
                                (di.years as i64 * 365) + (di.months as i64 * 30) + di.days as i64,
                            ),
                        );
                        Ok(Some(Value::Object(interval)))
                    }
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            _ => Ok(None),
        }
    }

    // ── DatePeriod method dispatch ──────────────────────────────────────────

    fn call_dateperiod_method(&mut self, method: &str, args: &[Value]) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "rewind" => {
                obj.set_property("__period_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__period_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let len = match obj.get_property("__period_entries") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(index < len)))
            }
            "current" => {
                let index = obj
                    .get_property("__period_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__period_entries") {
                    if let Some((_, val)) = a.entry_at(index) {
                        return Ok(Some(val.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "key" => {
                let index = obj
                    .get_property("__period_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "next" => {
                let index = obj
                    .get_property("__period_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__period_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            "getStartDate" => {
                let ts = obj
                    .get_property("__start_ts")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let dt_obj = PhpObject::new("DateTime".to_string());
                dt_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                dt_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                dt_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                Ok(Some(Value::Object(dt_obj)))
            }
            "getEndDate" => match obj.get_property("__end_ts") {
                Some(Value::Long(ts)) => {
                    let dt_obj = PhpObject::new("DateTime".to_string());
                    dt_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    dt_obj.set_property("__timestamp".to_string(), Value::Long(ts));
                    dt_obj.set_property("__timezone".to_string(), Value::String("UTC".to_string()));
                    Ok(Some(Value::Object(dt_obj)))
                }
                _ => Ok(Some(Value::Null)),
            },
            "getDateInterval" => {
                let interval = PhpObject::new("DateInterval".to_string());
                interval.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                for prop in &["y", "m", "d", "h", "i", "s"] {
                    let val = obj
                        .get_property(&format!("__interval_{}", prop))
                        .unwrap_or(Value::Long(0));
                    interval.set_property(prop.to_string(), val);
                }
                interval.set_property("invert".to_string(), Value::Long(0));
                interval.set_property("days".to_string(), Value::Long(0));
                Ok(Some(Value::Object(interval)))
            }
            "getRecurrences" => {
                let r = obj.get_property("__recurrences").unwrap_or(Value::Null);
                Ok(Some(r))
            }
            _ => Ok(None),
        }
    }

    // ── SplFixedArray method dispatch ───────────────────────────────────────

    fn call_spl_fixed_array_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "count" | "getSize" => {
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(size)))
            }
            "setSize" => {
                let new_size = args.get(1).map(|v| v.to_long()).unwrap_or(0).max(0) as usize;
                let old_size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let mut arr = match obj.get_property("__spl_data") {
                    Some(Value::Array(a)) => a,
                    _ => PhpArray::new(),
                };
                // Grow: add nulls
                for i in old_size..new_size {
                    arr.set_int(i as i64, Value::Null);
                }
                // Shrink: remove excess (PhpArray doesn't have truncate, but we track via __spl_size)
                obj.set_property("__spl_data".to_string(), Value::Array(arr));
                obj.set_property("__spl_size".to_string(), Value::Long(new_size as i64));
                Ok(Some(Value::Null))
            }
            "offsetExists" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Bool(index >= 0 && index < size)))
            }
            "offsetGet" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if index < 0 || index >= size {
                    return Err(super::VmError::FatalError(format!(
                        "SplFixedArray::offsetGet(): Index {} out of range [0, {})",
                        index, size
                    )));
                }
                if let Some(Value::Array(ref a)) = obj.get_property("__spl_data") {
                    Ok(Some(
                        a.get(&Value::Long(index)).cloned().unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "offsetSet" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let value = args.get(2).cloned().unwrap_or(Value::Null);
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if index < 0 || index >= size {
                    return Err(super::VmError::FatalError(format!(
                        "SplFixedArray::offsetSet(): Index {} out of range [0, {})",
                        index, size
                    )));
                }
                if let Some(Value::Array(ref a)) = obj.get_property("__spl_data") {
                    let mut a = a.clone();
                    a.set_int(index, value);
                    obj.set_property("__spl_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "offsetUnset" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if index >= 0 && index < size {
                    if let Some(Value::Array(ref a)) = obj.get_property("__spl_data") {
                        let mut a = a.clone();
                        a.set_int(index, Value::Null);
                        obj.set_property("__spl_data".to_string(), Value::Array(a));
                    }
                }
                Ok(Some(Value::Null))
            }
            "toArray" => {
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let data = match obj.get_property("__spl_data") {
                    Some(Value::Array(a)) => a,
                    _ => PhpArray::new(),
                };
                let mut result = PhpArray::new();
                for i in 0..size {
                    let val = data.get(&Value::Long(i)).cloned().unwrap_or(Value::Null);
                    result.push(val);
                }
                Ok(Some(Value::Array(result)))
            }
            "fromArray" => {
                // Static method: SplFixedArray::fromArray($array, $preserveKeys)
                let arr = match args.get(1) {
                    Some(Value::Array(ref a)) => a.clone(),
                    _ => PhpArray::new(),
                };
                let new_obj = PhpObject::new("SplFixedArray".to_string());
                new_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                let size = arr.len() as i64;
                let mut data = PhpArray::new();
                for (i, (_, val)) in arr.entries().iter().enumerate() {
                    data.set_int(i as i64, val.clone());
                }
                new_obj.set_property("__spl_data".to_string(), Value::Array(data));
                new_obj.set_property("__spl_size".to_string(), Value::Long(size));
                new_obj.set_property("__spl_index".to_string(), Value::Long(0));
                Ok(Some(Value::Object(new_obj)))
            }
            "rewind" => {
                obj.set_property("__spl_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__spl_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let size = obj
                    .get_property("__spl_size")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Bool(index >= 0 && index < size)))
            }
            "current" => {
                let index = obj
                    .get_property("__spl_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if let Some(Value::Array(ref a)) = obj.get_property("__spl_data") {
                    Ok(Some(
                        a.get(&Value::Long(index)).cloned().unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "key" => {
                let index = obj
                    .get_property("__spl_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "next" => {
                let index = obj
                    .get_property("__spl_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__spl_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // ── SplDoublyLinkedList / SplStack / SplQueue method dispatch ───────────

    fn call_spl_dll_method(&mut self, method: &str, args: &[Value]) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "push" | "enqueue" => {
                let value = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let mut a = a.clone();
                    a.push(value);
                    obj.set_property("__dll_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "unshift" => {
                let value = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let mut new_arr = PhpArray::new();
                    new_arr.push(value);
                    for (_, v) in a.entries() {
                        new_arr.push(v.clone());
                    }
                    obj.set_property("__dll_data".to_string(), Value::Array(new_arr));
                }
                Ok(Some(Value::Null))
            }
            "pop" | "dequeue" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let len = a.len();
                    if len == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't pop from an empty datastructure".to_string(),
                        ));
                    }
                    let mut new_arr = PhpArray::new();
                    let mut popped = Value::Null;
                    for (i, (_, v)) in a.entries().iter().enumerate() {
                        if i == len - 1 {
                            popped = v.clone();
                        } else {
                            new_arr.push(v.clone());
                        }
                    }
                    obj.set_property("__dll_data".to_string(), Value::Array(new_arr));
                    return Ok(Some(popped));
                }
                Err(super::VmError::FatalError(
                    "Can't pop from an empty datastructure".to_string(),
                ))
            }
            "shift" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let len = a.len();
                    if len == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't shift from an empty datastructure".to_string(),
                        ));
                    }
                    let mut new_arr = PhpArray::new();
                    let mut shifted = Value::Null;
                    for (i, (_, v)) in a.entries().iter().enumerate() {
                        if i == 0 {
                            shifted = v.clone();
                        } else {
                            new_arr.push(v.clone());
                        }
                    }
                    obj.set_property("__dll_data".to_string(), Value::Array(new_arr));
                    return Ok(Some(shifted));
                }
                Err(super::VmError::FatalError(
                    "Can't shift from an empty datastructure".to_string(),
                ))
            }
            "top" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let len = a.len();
                    if len == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't peek at an empty datastructure".to_string(),
                        ));
                    }
                    if let Some((_, v)) = a.entry_at(len - 1) {
                        return Ok(Some(v.clone()));
                    }
                }
                Err(super::VmError::FatalError(
                    "Can't peek at an empty datastructure".to_string(),
                ))
            }
            "bottom" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    if a.len() == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't peek at an empty datastructure".to_string(),
                        ));
                    }
                    if let Some((_, v)) = a.entry_at(0) {
                        return Ok(Some(v.clone()));
                    }
                }
                Err(super::VmError::FatalError(
                    "Can't peek at an empty datastructure".to_string(),
                ))
            }
            "count" => {
                let len = match obj.get_property("__dll_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Long(len as i64)))
            }
            "isEmpty" => {
                let len = match obj.get_property("__dll_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(len == 0)))
            }
            "rewind" => {
                let mode = obj
                    .get_property("__dll_mode")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let is_lifo = (mode & 2) != 0;
                let len = match obj.get_property("__dll_data") {
                    Some(Value::Array(ref a)) => a.len() as i64,
                    _ => 0,
                };
                let start = if is_lifo { len - 1 } else { 0 };
                obj.set_property("__dll_index".to_string(), Value::Long(start));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__dll_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let len = match obj.get_property("__dll_data") {
                    Some(Value::Array(ref a)) => a.len() as i64,
                    _ => 0,
                };
                Ok(Some(Value::Bool(index >= 0 && index < len)))
            }
            "current" => {
                let index = obj
                    .get_property("__dll_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    if let Some((_, v)) = a.entry_at(index) {
                        return Ok(Some(v.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "key" => {
                let index = obj
                    .get_property("__dll_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "next" => {
                let mode = obj
                    .get_property("__dll_mode")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let is_lifo = (mode & 2) != 0;
                let index = obj
                    .get_property("__dll_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let new_index = if is_lifo { index - 1 } else { index + 1 };
                obj.set_property("__dll_index".to_string(), Value::Long(new_index));
                Ok(Some(Value::Null))
            }
            "prev" => {
                let mode = obj
                    .get_property("__dll_mode")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let is_lifo = (mode & 2) != 0;
                let index = obj
                    .get_property("__dll_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let new_index = if is_lifo { index + 1 } else { index - 1 };
                obj.set_property("__dll_index".to_string(), Value::Long(new_index));
                Ok(Some(Value::Null))
            }
            "setIteratorMode" => {
                let mode = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__dll_mode".to_string(), Value::Long(mode));
                Ok(Some(Value::Null))
            }
            "getIteratorMode" => {
                let mode = obj
                    .get_property("__dll_mode")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(mode)))
            }
            "offsetExists" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let len = match obj.get_property("__dll_data") {
                    Some(Value::Array(ref a)) => a.len() as i64,
                    _ => 0,
                };
                Ok(Some(Value::Bool(index >= 0 && index < len)))
            }
            "offsetGet" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    if let Some((_, v)) = a.entry_at(index) {
                        return Ok(Some(v.clone()));
                    }
                }
                Ok(Some(Value::Null))
            }
            "offsetSet" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1);
                let value = args.get(2).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let mut a = a.clone();
                    if index < 0 || matches!(args.get(1), Some(Value::Null)) {
                        a.push(value);
                    } else {
                        a.set_int(index, value);
                    }
                    obj.set_property("__dll_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "offsetUnset" => {
                let index = args.get(1).map(|v| v.to_long()).unwrap_or(-1) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__dll_data") {
                    let mut new_arr = PhpArray::new();
                    for (i, (_, v)) in a.entries().iter().enumerate() {
                        if i != index {
                            new_arr.push(v.clone());
                        }
                    }
                    obj.set_property("__dll_data".to_string(), Value::Array(new_arr));
                }
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // ── SplHeap / SplMinHeap / SplMaxHeap / SplPriorityQueue method dispatch ─

    fn call_spl_heap_method(
        &mut self,
        class_name: &str,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "insert" => {
                let value = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__heap_data") {
                    let mut a = a.clone();
                    if class_name == "SplPriorityQueue" {
                        // insert($value, $priority)
                        let priority = args.get(2).cloned().unwrap_or(Value::Long(0));
                        let mut entry = PhpArray::new();
                        entry.set_string("data".to_string(), value);
                        entry.set_string("priority".to_string(), priority);
                        a.push(Value::Array(entry));
                    } else {
                        a.push(value);
                    }
                    // Bubble up (sift-up) to maintain heap property
                    let len = a.len();
                    self.heap_sift_up(&mut a, len - 1, class_name);
                    obj.set_property("__heap_data".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "extract" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__heap_data") {
                    let len = a.len();
                    if len == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't extract from an empty datastructure".to_string(),
                        ));
                    }
                    let top = a.entry_at(0).map(|(_, v)| v.clone()).unwrap_or(Value::Null);
                    let mut new_arr = PhpArray::new();
                    // Move last element to top, then sift down
                    if len > 1 {
                        let last = a
                            .entry_at(len - 1)
                            .map(|(_, v)| v.clone())
                            .unwrap_or(Value::Null);
                        new_arr.push(last);
                        for i in 1..len - 1 {
                            if let Some((_, v)) = a.entry_at(i) {
                                new_arr.push(v.clone());
                            }
                        }
                        self.heap_sift_down(&mut new_arr, 0, class_name);
                    }
                    obj.set_property("__heap_data".to_string(), Value::Array(new_arr));
                    if class_name == "SplPriorityQueue" {
                        if let Value::Array(ref entry) = top {
                            return Ok(Some(
                                entry.get_string("data").cloned().unwrap_or(Value::Null),
                            ));
                        }
                    }
                    return Ok(Some(top));
                }
                Err(super::VmError::FatalError(
                    "Can't extract from an empty datastructure".to_string(),
                ))
            }
            "top" | "current" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__heap_data") {
                    if a.len() == 0 {
                        return Err(super::VmError::FatalError(
                            "Can't peek at an empty datastructure".to_string(),
                        ));
                    }
                    let top = a.entry_at(0).map(|(_, v)| v.clone()).unwrap_or(Value::Null);
                    if class_name == "SplPriorityQueue" {
                        if let Value::Array(ref entry) = top {
                            return Ok(Some(
                                entry.get_string("data").cloned().unwrap_or(Value::Null),
                            ));
                        }
                    }
                    return Ok(Some(top));
                }
                Err(super::VmError::FatalError(
                    "Can't peek at an empty datastructure".to_string(),
                ))
            }
            "count" => {
                let len = match obj.get_property("__heap_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Long(len as i64)))
            }
            "isEmpty" => {
                let len = match obj.get_property("__heap_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(len == 0)))
            }
            "isCorrupted" => Ok(Some(Value::Bool(false))),
            "valid" => {
                let len = match obj.get_property("__heap_data") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(len > 0)))
            }
            "key" => {
                let index = obj
                    .get_property("__heap_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "next" => {
                // Extract top element (destructive iteration)
                let _ = self.call_spl_heap_method(class_name, "extract", args);
                let index = obj
                    .get_property("__heap_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__heap_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__heap_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "recoverFromCorruption" => Ok(Some(Value::Null)),
            _ => Ok(None),
        }
    }

    /// Heap sift-up: bubble element at `index` up to maintain heap property.
    fn heap_sift_up(&self, arr: &mut PhpArray, index: usize, class_name: &str) {
        if index == 0 {
            return;
        }
        let parent = (index - 1) / 2;
        let a_val = arr
            .entry_at(index)
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null);
        let b_val = arr
            .entry_at(parent)
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null);
        if self.heap_should_swap(&a_val, &b_val, class_name) {
            // Swap
            arr.set_int(index as i64, b_val);
            arr.set_int(parent as i64, a_val);
            self.heap_sift_up(arr, parent, class_name);
        }
    }

    /// Heap sift-down: push element at `index` down to maintain heap property.
    fn heap_sift_down(&self, arr: &mut PhpArray, index: usize, class_name: &str) {
        let len = arr.len();
        let left = 2 * index + 1;
        let right = 2 * index + 2;
        let mut target = index;

        if left < len {
            let t_val = arr
                .entry_at(target)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            let l_val = arr
                .entry_at(left)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            if self.heap_should_swap(&l_val, &t_val, class_name) {
                target = left;
            }
        }
        if right < len {
            let t_val = arr
                .entry_at(target)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            let r_val = arr
                .entry_at(right)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            if self.heap_should_swap(&r_val, &t_val, class_name) {
                target = right;
            }
        }

        if target != index {
            let i_val = arr
                .entry_at(index)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            let t_val = arr
                .entry_at(target)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null);
            arr.set_int(index as i64, t_val);
            arr.set_int(target as i64, i_val);
            self.heap_sift_down(arr, target, class_name);
        }
    }

    /// Determine if child should be above parent in the heap.
    fn heap_should_swap(&self, child: &Value, parent: &Value, class_name: &str) -> bool {
        let (a, b) = if class_name == "SplPriorityQueue" {
            // Compare by priority
            let a_pri = match child {
                Value::Array(ref arr) => arr
                    .get_string("priority")
                    .cloned()
                    .unwrap_or(Value::Long(0)),
                _ => child.clone(),
            };
            let b_pri = match parent {
                Value::Array(ref arr) => arr
                    .get_string("priority")
                    .cloned()
                    .unwrap_or(Value::Long(0)),
                _ => parent.clone(),
            };
            (a_pri, b_pri)
        } else {
            (child.clone(), parent.clone())
        };

        match class_name {
            "SplMinHeap" => {
                // Min-heap: child < parent means swap
                match (&a, &b) {
                    (Value::Long(a), Value::Long(b)) => a < b,
                    (Value::Double(a), Value::Double(b)) => a < b,
                    (Value::String(a), Value::String(b)) => a < b,
                    _ => a.to_long() < b.to_long(),
                }
            }
            _ => {
                // Max-heap (SplMaxHeap, SplHeap, SplPriorityQueue): child > parent means swap
                match (&a, &b) {
                    (Value::Long(a), Value::Long(b)) => a > b,
                    (Value::Double(a), Value::Double(b)) => a > b,
                    (Value::String(a), Value::String(b)) => a > b,
                    _ => a.to_long() > b.to_long(),
                }
            }
        }
    }

    // ── SplObjectStorage method dispatch ────────────────────────────────────

    fn call_spl_object_storage_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "attach" => {
                let target = args.get(1).cloned().unwrap_or(Value::Null);
                let info = args.get(2).cloned().unwrap_or(Value::Null);
                if let Value::Object(ref target_obj) = target {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                        let mut objects = objects.clone();
                        let mut infos = match obj.get_property("__sos_infos") {
                            Some(Value::Array(a)) => a,
                            _ => PhpArray::new(),
                        };
                        objects.set_int(oid as i64, target);
                        infos.set_int(oid as i64, info);
                        obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                        obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                    }
                }
                Ok(Some(Value::Null))
            }
            "detach" => {
                if let Some(Value::Object(ref target_obj)) = args.get(1) {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                        let mut objects = objects.clone();
                        let mut infos = match obj.get_property("__sos_infos") {
                            Some(Value::Array(a)) => a,
                            _ => PhpArray::new(),
                        };
                        objects.unset(&Value::Long(oid as i64));
                        infos.unset(&Value::Long(oid as i64));
                        obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                        obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                    }
                }
                Ok(Some(Value::Null))
            }
            "contains" | "offsetExists" => {
                if let Some(Value::Object(ref target_obj)) = args.get(1) {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                        return Ok(Some(Value::Bool(
                            objects.get(&Value::Long(oid as i64)).is_some(),
                        )));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "count" => {
                let len = match obj.get_property("__sos_objects") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Long(len as i64)))
            }
            "getInfo" => {
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                    if let Some((key, _)) = objects.entry_at(index as usize) {
                        let oid = match key {
                            ArrayKey::Int(i) => *i,
                            ArrayKey::String(s) => s.parse::<i64>().unwrap_or(0),
                        };
                        if let Some(Value::Array(ref infos)) = obj.get_property("__sos_infos") {
                            return Ok(Some(
                                infos.get(&Value::Long(oid)).cloned().unwrap_or(Value::Null),
                            ));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "setInfo" => {
                let info = args.get(1).cloned().unwrap_or(Value::Null);
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                    if let Some((key, _)) = objects.entry_at(index as usize) {
                        let oid = match key {
                            ArrayKey::Int(i) => *i,
                            ArrayKey::String(s) => s.parse::<i64>().unwrap_or(0),
                        };
                        if let Some(Value::Array(ref infos)) = obj.get_property("__sos_infos") {
                            let mut infos = infos.clone();
                            infos.set_int(oid, info);
                            obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__sos_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let len = match obj.get_property("__sos_objects") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(index < len)))
            }
            "current" => {
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                    if let Some((_, val)) = objects.entry_at(index) {
                        return Ok(Some(val.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "key" => {
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(index)))
            }
            "next" => {
                let index = obj
                    .get_property("__sos_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__sos_index".to_string(), Value::Long(index + 1));
                Ok(Some(Value::Null))
            }
            "offsetGet" => {
                if let Some(Value::Object(ref target_obj)) = args.get(1) {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref infos)) = obj.get_property("__sos_infos") {
                        return Ok(Some(
                            infos
                                .get(&Value::Long(oid as i64))
                                .cloned()
                                .unwrap_or(Value::Null),
                        ));
                    }
                }
                Ok(Some(Value::Null))
            }
            "offsetSet" => {
                // Same as attach
                let target = args.get(1).cloned().unwrap_or(Value::Null);
                let info = args.get(2).cloned().unwrap_or(Value::Null);
                if let Value::Object(ref target_obj) = target {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                        let mut objects = objects.clone();
                        let mut infos = match obj.get_property("__sos_infos") {
                            Some(Value::Array(a)) => a,
                            _ => PhpArray::new(),
                        };
                        objects.set_int(oid as i64, target);
                        infos.set_int(oid as i64, info);
                        obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                        obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                    }
                }
                Ok(Some(Value::Null))
            }
            "offsetUnset" => {
                // Same as detach
                if let Some(Value::Object(ref target_obj)) = args.get(1) {
                    let oid = target_obj.object_id();
                    if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                        let mut objects = objects.clone();
                        let mut infos = match obj.get_property("__sos_infos") {
                            Some(Value::Array(a)) => a,
                            _ => PhpArray::new(),
                        };
                        objects.unset(&Value::Long(oid as i64));
                        infos.unset(&Value::Long(oid as i64));
                        obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                        obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                    }
                }
                Ok(Some(Value::Null))
            }
            "getHash" => {
                if let Some(Value::Object(ref target_obj)) = args.get(1) {
                    Ok(Some(Value::String(format!(
                        "{:016x}",
                        target_obj.object_id()
                    ))))
                } else {
                    Ok(Some(Value::String(String::new())))
                }
            }
            "addAll" => {
                // Merge another SplObjectStorage
                if let Some(Value::Object(ref other)) = args.get(1) {
                    if let Some(Value::Array(ref other_objects)) =
                        other.get_property("__sos_objects")
                    {
                        if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                            let mut objects = objects.clone();
                            let mut infos = match obj.get_property("__sos_infos") {
                                Some(Value::Array(a)) => a,
                                _ => PhpArray::new(),
                            };
                            let other_infos = match other.get_property("__sos_infos") {
                                Some(Value::Array(a)) => a,
                                _ => PhpArray::new(),
                            };
                            for (key, val) in other_objects.entries() {
                                let k = match key {
                                    ArrayKey::Int(i) => Value::Long(*i),
                                    ArrayKey::String(s) => Value::String(s.clone()),
                                };
                                objects.set(&k, val.clone());
                                if let Some(info) = other_infos.get(&k) {
                                    infos.set(&k, info.clone());
                                }
                            }
                            obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                            obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "removeAll" => {
                if let Some(Value::Object(ref other)) = args.get(1) {
                    if let Some(Value::Array(ref other_objects)) =
                        other.get_property("__sos_objects")
                    {
                        if let Some(Value::Array(ref objects)) = obj.get_property("__sos_objects") {
                            let mut objects = objects.clone();
                            let mut infos = match obj.get_property("__sos_infos") {
                                Some(Value::Array(a)) => a,
                                _ => PhpArray::new(),
                            };
                            for (key, _) in other_objects.entries() {
                                let k = match key {
                                    ArrayKey::Int(i) => Value::Long(*i),
                                    ArrayKey::String(s) => Value::String(s.clone()),
                                };
                                objects.unset(&k);
                                infos.unset(&k);
                            }
                            obj.set_property("__sos_objects".to_string(), Value::Array(objects));
                            obj.set_property("__sos_infos".to_string(), Value::Array(infos));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }
    // ── LimitIterator ─────────────────────────────────────────────────────

    fn call_limit_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                let count = args.get(3).map(|v| v.to_long()).unwrap_or(-1);
                obj.set_property("__limit_offset".to_string(), Value::Long(offset));
                obj.set_property("__limit_count".to_string(), Value::Long(count));
                obj.set_property("__limit_pos".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "rewind" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                }
                let offset = obj
                    .get_property("__limit_offset")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                // Skip to offset
                for _ in 0..offset {
                    let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                    if let Value::Object(_) = &inner {
                        let valid = self
                            .call_method_sync(&inner, "valid")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        if !valid {
                            break;
                        }
                        let _ = self.call_method_sync(&inner, "next");
                    }
                }
                obj.set_property("__limit_pos".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let count = obj
                    .get_property("__limit_count")
                    .map(|v| v.to_long())
                    .unwrap_or(-1);
                let pos = obj
                    .get_property("__limit_pos")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if count >= 0 && pos >= count {
                    return Ok(Some(Value::Bool(false)));
                }
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "valid")
                            .unwrap_or(Value::Bool(false)),
                    ))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "current" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "key" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "key").unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "next");
                }
                let pos = obj
                    .get_property("__limit_pos")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__limit_pos".to_string(), Value::Long(pos + 1));
                Ok(Some(Value::Null))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            "getPosition" => {
                let pos = obj
                    .get_property("__limit_pos")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                let offset = obj
                    .get_property("__limit_offset")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(offset + pos)))
            }
            "seek" => {
                let target = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                let offset = obj
                    .get_property("__limit_offset")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                // Rewind and skip to target
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                    for _ in 0..(offset + target) {
                        let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                        let valid = self
                            .call_method_sync(&inner, "valid")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        if !valid {
                            break;
                        }
                        let _ = self.call_method_sync(&inner, "next");
                    }
                }
                obj.set_property("__limit_pos".to_string(), Value::Long(target));
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // ── InfiniteIterator ─────────────────────────────────────────────────

    fn call_infinite_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                }
                Ok(Some(Value::Null))
            }
            "valid" => {
                // InfiniteIterator is always valid
                Ok(Some(Value::Bool(true)))
            }
            "current" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "key" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "key").unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "next");
                    // If inner is exhausted, rewind it
                    let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                    let valid = self
                        .call_method_sync(&inner, "valid")
                        .unwrap_or(Value::Bool(false))
                        .to_bool();
                    if !valid {
                        let _ = self.call_method_sync(&inner, "rewind");
                    }
                }
                Ok(Some(Value::Null))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            _ => Ok(None),
        }
    }

    // ── NoRewindIterator ─────────────────────────────────────────────────

    fn call_norewind_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                // NoRewindIterator: rewind is a no-op
                Ok(Some(Value::Null))
            }
            "valid" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "valid")
                            .unwrap_or(Value::Bool(false)),
                    ))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "current" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "key" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "key").unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "next");
                }
                Ok(Some(Value::Null))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            _ => Ok(None),
        }
    }

    // ── AppendIterator ───────────────────────────────────────────────────

    fn call_append_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                obj.set_property(
                    "__append_iterators".to_string(),
                    Value::Array(PhpArray::new()),
                );
                obj.set_property("__append_index".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "append" => {
                let iter = args.get(1).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    let mut a = a.clone();
                    a.push(iter);
                    obj.set_property("__append_iterators".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__append_index".to_string(), Value::Long(0));
                // Rewind first iterator
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(0) {
                        if let Value::Object(_) = iter {
                            let _ = self.call_method_sync(iter, "rewind");
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "valid" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(idx) {
                        if let Value::Object(_) = iter {
                            return Ok(Some(
                                self.call_method_sync(iter, "valid")
                                    .unwrap_or(Value::Bool(false)),
                            ));
                        }
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "current" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(idx) {
                        if let Value::Object(_) = iter {
                            return Ok(Some(
                                self.call_method_sync(iter, "current")
                                    .unwrap_or(Value::Null),
                            ));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "key" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(idx) {
                        if let Value::Object(_) = iter {
                            return Ok(Some(
                                self.call_method_sync(iter, "key").unwrap_or(Value::Null),
                            ));
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "next" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(idx) {
                        if let Value::Object(_) = iter {
                            let _ = self.call_method_sync(iter, "next");
                            // Check if current iterator is exhausted
                            let iter_ref = obj
                                .get_property("__append_iterators")
                                .unwrap_or(Value::Null);
                            if let Value::Array(ref a2) = iter_ref {
                                if let Some((_, iter2)) = a2.entry_at(idx) {
                                    let valid = self
                                        .call_method_sync(iter2, "valid")
                                        .unwrap_or(Value::Bool(false))
                                        .to_bool();
                                    if !valid {
                                        // Move to next iterator
                                        let new_idx = idx + 1;
                                        obj.set_property(
                                            "__append_index".to_string(),
                                            Value::Long(new_idx as i64),
                                        );
                                        // Rewind next iterator
                                        if let Some((_, next_iter)) = a2.entry_at(new_idx) {
                                            if let Value::Object(_) = next_iter {
                                                let _ = self.call_method_sync(next_iter, "rewind");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "getIteratorIndex" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(idx)))
            }
            "getInnerIterator" => {
                let idx = obj
                    .get_property("__append_index")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__append_iterators") {
                    if let Some((_, iter)) = a.entry_at(idx) {
                        return Ok(Some(iter.clone()));
                    }
                }
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // ── CachingIterator ──────────────────────────────────────────────────

    fn call_caching_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                let flags = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__cache_flags".to_string(), Value::Long(flags));
                obj.set_property("__cache_valid".to_string(), Value::Bool(false));
                obj.set_property("__cache_current".to_string(), Value::Null);
                obj.set_property("__cache_key".to_string(), Value::Null);
                obj.set_property("__cache_has_next".to_string(), Value::Bool(false));
                Ok(Some(Value::Null))
            }
            "rewind" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                    let valid = self
                        .call_method_sync(&inner, "valid")
                        .unwrap_or(Value::Bool(false))
                        .to_bool();
                    obj.set_property("__cache_valid".to_string(), Value::Bool(valid));
                    if valid {
                        let current = self
                            .call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null);
                        let key = self.call_method_sync(&inner, "key").unwrap_or(Value::Null);
                        obj.set_property("__cache_current".to_string(), current);
                        obj.set_property("__cache_key".to_string(), key);
                        // Check if there's a next element
                        let inner2 = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                        let _ = self.call_method_sync(&inner2, "next");
                        let has_next = self
                            .call_method_sync(&inner2, "valid")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        obj.set_property("__cache_has_next".to_string(), Value::Bool(has_next));
                    }
                }
                Ok(Some(Value::Null))
            }
            "valid" => {
                let valid = obj
                    .get_property("__cache_valid")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(valid)))
            }
            "current" => Ok(Some(
                obj.get_property("__cache_current").unwrap_or(Value::Null),
            )),
            "key" => Ok(Some(obj.get_property("__cache_key").unwrap_or(Value::Null))),
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                let has_next = obj
                    .get_property("__cache_has_next")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                if has_next {
                    if let Value::Object(_) = &inner {
                        let current = self
                            .call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null);
                        let key = self.call_method_sync(&inner, "key").unwrap_or(Value::Null);
                        obj.set_property("__cache_current".to_string(), current);
                        obj.set_property("__cache_key".to_string(), key);
                        obj.set_property("__cache_valid".to_string(), Value::Bool(true));
                        // Advance inner and check if there's more
                        let inner2 = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                        let _ = self.call_method_sync(&inner2, "next");
                        let next_valid = self
                            .call_method_sync(&inner2, "valid")
                            .unwrap_or(Value::Bool(false))
                            .to_bool();
                        obj.set_property("__cache_has_next".to_string(), Value::Bool(next_valid));
                    }
                } else {
                    obj.set_property("__cache_valid".to_string(), Value::Bool(false));
                }
                Ok(Some(Value::Null))
            }
            "hasNext" => {
                let has_next = obj
                    .get_property("__cache_has_next")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(has_next)))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            "getFlags" => {
                let flags = obj
                    .get_property("__cache_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(flags)))
            }
            "setFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__cache_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "count" => {
                // Count requires FULL_CACHE flag (0x100)
                let flags = obj
                    .get_property("__cache_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if flags & 256 != 0 {
                    // Not implemented: would need to cache all elements
                    Ok(Some(Value::Long(0)))
                } else {
                    Err(VmError::FatalError(
                        "CachingIterator::count(): Requires CachingIterator::FULL_CACHE".into(),
                    ))
                }
            }
            "__toString" => {
                let current = obj.get_property("__cache_current").unwrap_or(Value::Null);
                Ok(Some(Value::String(current.to_php_string())))
            }
            _ => Ok(None),
        }
    }

    // ── RegexIterator ────────────────────────────────────────────────────

    fn call_regex_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                if let Some(inner) = args.get(1) {
                    obj.set_property("__inner_iterator".to_string(), inner.clone());
                }
                let pattern = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                let mode = args.get(3).map(|v| v.to_long()).unwrap_or(0); // MATCH = 0
                let flags = args.get(4).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__regex_pattern".to_string(), Value::String(pattern));
                obj.set_property("__regex_mode".to_string(), Value::Long(mode));
                obj.set_property("__regex_flags".to_string(), Value::Long(flags));
                obj.set_property("__regex_preg_flags".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "rewind" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "rewind");
                }
                // Skip to first matching element
                self.regex_iterator_find_next(obj, true)?;
                Ok(Some(Value::Null))
            }
            "valid" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "valid")
                            .unwrap_or(Value::Bool(false)),
                    ))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "current" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "current")
                            .unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "key" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    Ok(Some(
                        self.call_method_sync(&inner, "key").unwrap_or(Value::Null),
                    ))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "next" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                if let Value::Object(_) = &inner {
                    let _ = self.call_method_sync(&inner, "next");
                }
                self.regex_iterator_find_next(obj, false)?;
                Ok(Some(Value::Null))
            }
            "accept" => {
                let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
                let current = if let Value::Object(_) = &inner {
                    self.call_method_sync(&inner, "current")
                        .unwrap_or(Value::Null)
                        .to_php_string()
                } else {
                    return Ok(Some(Value::Bool(false)));
                };
                let pattern = obj
                    .get_property("__regex_pattern")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                let matched = self.regex_iterator_matches(&pattern, &current);
                Ok(Some(Value::Bool(matched)))
            }
            "getRegex" => Ok(Some(
                obj.get_property("__regex_pattern")
                    .unwrap_or(Value::String(String::new())),
            )),
            "getMode" => Ok(Some(
                obj.get_property("__regex_mode").unwrap_or(Value::Long(0)),
            )),
            "setMode" => {
                let mode = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__regex_mode".to_string(), Value::Long(mode));
                Ok(Some(Value::Null))
            }
            "getFlags" => Ok(Some(
                obj.get_property("__regex_flags").unwrap_or(Value::Long(0)),
            )),
            "setFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__regex_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "getPregFlags" => Ok(Some(
                obj.get_property("__regex_preg_flags")
                    .unwrap_or(Value::Long(0)),
            )),
            "setPregFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__regex_preg_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "getInnerIterator" => Ok(Some(
                obj.get_property("__inner_iterator").unwrap_or(Value::Null),
            )),
            _ => Ok(None),
        }
    }

    /// Helper: advance the inner iterator of a RegexIterator until we find a match.
    fn regex_iterator_find_next(&mut self, obj: &PhpObject, _is_rewind: bool) -> VmResult<()> {
        let pattern = obj
            .get_property("__regex_pattern")
            .map(|v| v.to_php_string())
            .unwrap_or_default();

        for _ in 0..100_000 {
            let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
            let valid = if let Value::Object(_) = &inner {
                self.call_method_sync(&inner, "valid")
                    .unwrap_or(Value::Bool(false))
                    .to_bool()
            } else {
                false
            };
            if !valid {
                break;
            }
            let current = if let Value::Object(_) = &inner {
                self.call_method_sync(&inner, "current")
                    .unwrap_or(Value::Null)
                    .to_php_string()
            } else {
                break;
            };
            if self.regex_iterator_matches(&pattern, &current) {
                break;
            }
            let inner = obj.get_property("__inner_iterator").unwrap_or(Value::Null);
            if let Value::Object(_) = &inner {
                let _ = self.call_method_sync(&inner, "next");
            }
        }
        Ok(())
    }

    /// Helper: check if a string matches a PHP regex pattern.
    fn regex_iterator_matches(&self, pattern: &str, subject: &str) -> bool {
        // Strip PHP delimiters (e.g., /pattern/flags)
        let (regex_str, _flags) = strip_php_regex_delimiters(pattern);
        match regex::Regex::new(&regex_str) {
            Ok(re) => re.is_match(subject),
            Err(_) => false,
        }
    }

    // ── MultipleIterator ─────────────────────────────────────────────────

    fn call_multiple_iterator_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        // Flags
        const MIT_NEED_ANY: i64 = 0;
        const MIT_NEED_ALL: i64 = 1;
        const MIT_KEYS_NUMERIC: i64 = 0;
        const MIT_KEYS_ASSOC: i64 = 2;

        match method {
            "__construct" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(MIT_NEED_ALL);
                obj.set_property(
                    "__multi_iterators".to_string(),
                    Value::Array(PhpArray::new()),
                );
                obj.set_property("__multi_infos".to_string(), Value::Array(PhpArray::new()));
                obj.set_property("__multi_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "attachIterator" => {
                let iter = args.get(1).cloned().unwrap_or(Value::Null);
                let info = args.get(2).cloned().unwrap_or(Value::Null);
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    let mut a = a.clone();
                    a.push(iter);
                    obj.set_property("__multi_iterators".to_string(), Value::Array(a));
                }
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_infos") {
                    let mut a = a.clone();
                    a.push(info);
                    obj.set_property("__multi_infos".to_string(), Value::Array(a));
                }
                Ok(Some(Value::Null))
            }
            "detachIterator" => {
                // Simplified: not commonly used
                Ok(Some(Value::Null))
            }
            "containsIterator" => {
                // Simplified
                Ok(Some(Value::Bool(false)))
            }
            "countIterators" => {
                let count = match obj.get_property("__multi_iterators") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Long(count as i64)))
            }
            "rewind" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    for i in 0..a.len() {
                        if let Some((_, iter)) = a.entry_at(i) {
                            if let Value::Object(_) = iter {
                                let _ = self.call_method_sync(iter, "rewind");
                            }
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "valid" => {
                let flags = obj
                    .get_property("__multi_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(MIT_NEED_ALL);
                let need_all = (flags & MIT_NEED_ALL) != 0;
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    if a.is_empty() {
                        return Ok(Some(Value::Bool(false)));
                    }
                    let mut any_valid = false;
                    let mut all_valid = true;
                    for i in 0..a.len() {
                        if let Some((_, iter)) = a.entry_at(i) {
                            if let Value::Object(_) = iter {
                                let valid = self
                                    .call_method_sync(iter, "valid")
                                    .unwrap_or(Value::Bool(false))
                                    .to_bool();
                                if valid {
                                    any_valid = true;
                                } else {
                                    all_valid = false;
                                }
                            }
                        }
                    }
                    if need_all {
                        Ok(Some(Value::Bool(all_valid)))
                    } else {
                        Ok(Some(Value::Bool(any_valid)))
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "current" => {
                let flags = obj
                    .get_property("__multi_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(MIT_NEED_ALL);
                let use_assoc = (flags & MIT_KEYS_ASSOC) != 0;
                let mut result = PhpArray::new();
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    let infos = obj.get_property("__multi_infos");
                    for i in 0..a.len() {
                        if let Some((_, iter)) = a.entry_at(i) {
                            let val = if let Value::Object(_) = iter {
                                let valid = self
                                    .call_method_sync(iter, "valid")
                                    .unwrap_or(Value::Bool(false))
                                    .to_bool();
                                if valid {
                                    self.call_method_sync(iter, "current")
                                        .unwrap_or(Value::Null)
                                } else {
                                    Value::Null
                                }
                            } else {
                                Value::Null
                            };
                            if use_assoc {
                                if let Some(Value::Array(ref info_arr)) = infos {
                                    if let Some((_, info)) = info_arr.entry_at(i) {
                                        if info != &Value::Null {
                                            result.set(&info.clone(), val);
                                            continue;
                                        }
                                    }
                                }
                            }
                            result.push(val);
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "key" => {
                let flags = obj
                    .get_property("__multi_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(MIT_NEED_ALL);
                let use_assoc = (flags & MIT_KEYS_ASSOC) != 0;
                let mut result = PhpArray::new();
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    let infos = obj.get_property("__multi_infos");
                    for i in 0..a.len() {
                        if let Some((_, iter)) = a.entry_at(i) {
                            let k = if let Value::Object(_) = iter {
                                self.call_method_sync(iter, "key").unwrap_or(Value::Null)
                            } else {
                                Value::Null
                            };
                            if use_assoc {
                                if let Some(Value::Array(ref info_arr)) = infos {
                                    if let Some((_, info)) = info_arr.entry_at(i) {
                                        if info != &Value::Null {
                                            result.set(&info.clone(), k);
                                            continue;
                                        }
                                    }
                                }
                            }
                            result.push(k);
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "next" => {
                if let Some(Value::Array(ref a)) = obj.get_property("__multi_iterators") {
                    for i in 0..a.len() {
                        if let Some((_, iter)) = a.entry_at(i) {
                            if let Value::Object(_) = iter {
                                let _ = self.call_method_sync(iter, "next");
                            }
                        }
                    }
                }
                Ok(Some(Value::Null))
            }
            "setFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(MIT_NEED_ALL);
                obj.set_property("__multi_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "getFlags" => {
                let flags = obj
                    .get_property("__multi_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(MIT_NEED_ALL);
                Ok(Some(Value::Long(flags)))
            }
            _ => Ok(None),
        }
    }

    // ── SplFileObject ────────────────────────────────────────────────────

    fn call_spl_file_object_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(ref o)) => o,
            _ => return Ok(None),
        };

        match method {
            "__construct" => {
                let filename = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let mode = args
                    .get(2)
                    .map(|v| v.to_php_string())
                    .unwrap_or_else(|| "r".to_string());
                obj.set_property("__spl_path".to_string(), Value::String(filename.clone()));
                obj.set_property("__sfo_mode".to_string(), Value::String(mode));
                obj.set_property("__sfo_line".to_string(), Value::Long(0));
                obj.set_property("__sfo_flags".to_string(), Value::Long(0));
                obj.set_property("__sfo_delimiter".to_string(), Value::String(",".into()));
                obj.set_property("__sfo_enclosure".to_string(), Value::String("\"".into()));
                obj.set_property("__sfo_escape".to_string(), Value::String("\\".into()));
                // Read file contents into lines
                match self.vm_read_to_string(&filename) {
                    Ok(contents) => {
                        let mut lines = PhpArray::new();
                        for line in contents.split('\n') {
                            lines.push(Value::String(format!("{}\n", line)));
                        }
                        // Fix last line if file doesn't end with newline
                        if !contents.ends_with('\n') && !contents.is_empty() {
                            let len = lines.len();
                            if len > 0 {
                                if let Some((_, last)) = lines.entry_at(len - 1) {
                                    let s = last.to_php_string();
                                    if s.ends_with('\n') {
                                        let trimmed = s[..s.len() - 1].to_string();
                                        lines.set_int((len - 1) as i64, Value::String(trimmed));
                                    }
                                }
                            }
                        }
                        obj.set_property("__sfo_lines".to_string(), Value::Array(lines));
                    }
                    Err(_) => {
                        // File might not exist for write mode
                        obj.set_property("__sfo_lines".to_string(), Value::Array(PhpArray::new()));
                    }
                }
                Ok(Some(Value::Null))
            }
            "rewind" => {
                obj.set_property("__sfo_line".to_string(), Value::Long(0));
                Ok(Some(Value::Null))
            }
            "valid" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let len = match obj.get_property("__sfo_lines") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(line < len)))
            }
            "current" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let flags = obj
                    .get_property("__sfo_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                if let Some(Value::Array(ref a)) = obj.get_property("__sfo_lines") {
                    if let Some((_, val)) = a.entry_at(line) {
                        // SplFileObject::READ_CSV = 8
                        if flags & 8 != 0 {
                            // Return CSV-parsed array
                            let s = val.to_php_string();
                            let delim = obj
                                .get_property("__sfo_delimiter")
                                .map(|v| v.to_php_string())
                                .unwrap_or_else(|| ",".into());
                            let d = delim.chars().next().unwrap_or(',');
                            let mut result = PhpArray::new();
                            for field in s.trim_end_matches('\n').split(d) {
                                let field = field.trim_matches('"');
                                result.push(Value::String(field.to_string()));
                            }
                            return Ok(Some(Value::Array(result)));
                        }
                        return Ok(Some(val.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "key" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(line)))
            }
            "next" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                obj.set_property("__sfo_line".to_string(), Value::Long(line + 1));
                Ok(Some(Value::Null))
            }
            "eof" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let len = match obj.get_property("__sfo_lines") {
                    Some(Value::Array(ref a)) => a.len(),
                    _ => 0,
                };
                Ok(Some(Value::Bool(line >= len)))
            }
            "fgets" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__sfo_lines") {
                    if let Some((_, val)) = a.entry_at(line) {
                        obj.set_property("__sfo_line".to_string(), Value::Long(line as i64 + 1));
                        return Ok(Some(val.clone()));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "fgetc" => {
                // Simplified: get first char of current line
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                if let Some(Value::Array(ref a)) = obj.get_property("__sfo_lines") {
                    if let Some((_, val)) = a.entry_at(line) {
                        let s = val.to_php_string();
                        if let Some(ch) = s.chars().next() {
                            return Ok(Some(Value::String(ch.to_string())));
                        }
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "fgetcsv" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0) as usize;
                let delim = args
                    .get(1)
                    .map(|v| v.to_php_string())
                    .or_else(|| {
                        obj.get_property("__sfo_delimiter")
                            .map(|v| v.to_php_string())
                    })
                    .unwrap_or_else(|| ",".into());
                let d = delim.chars().next().unwrap_or(',');
                if let Some(Value::Array(ref a)) = obj.get_property("__sfo_lines") {
                    if let Some((_, val)) = a.entry_at(line) {
                        let s = val.to_php_string();
                        let mut result = PhpArray::new();
                        for field in s.trim_end_matches('\n').split(d) {
                            let field = field.trim_matches('"');
                            result.push(Value::String(field.to_string()));
                        }
                        obj.set_property("__sfo_line".to_string(), Value::Long(line as i64 + 1));
                        return Ok(Some(Value::Array(result)));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "fwrite" | "fput" => {
                let data = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let filename = obj
                    .get_property("__spl_path")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                let bytes = data.len() as i64;
                let _ = self.vm_write_file(&filename, data.as_bytes());
                Ok(Some(Value::Long(bytes)))
            }
            "fflush" => Ok(Some(Value::Bool(true))),
            "ftruncate" => {
                let _size = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                Ok(Some(Value::Bool(true)))
            }
            "flock" => Ok(Some(Value::Bool(true))),
            "fseek" => {
                let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__sfo_line".to_string(), Value::Long(offset));
                Ok(Some(Value::Long(0)))
            }
            "ftell" => {
                let line = obj
                    .get_property("__sfo_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(line)))
            }
            "seek" => {
                let line = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__sfo_line".to_string(), Value::Long(line));
                Ok(Some(Value::Null))
            }
            "setFlags" => {
                let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__sfo_flags".to_string(), Value::Long(flags));
                Ok(Some(Value::Null))
            }
            "getFlags" => {
                let flags = obj
                    .get_property("__sfo_flags")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(flags)))
            }
            "setMaxLineLen" => {
                let len = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                obj.set_property("__sfo_max_line".to_string(), Value::Long(len));
                Ok(Some(Value::Null))
            }
            "getMaxLineLen" => {
                let len = obj
                    .get_property("__sfo_max_line")
                    .map(|v| v.to_long())
                    .unwrap_or(0);
                Ok(Some(Value::Long(len)))
            }
            "setCsvControl" => {
                if let Some(delim) = args.get(1) {
                    obj.set_property("__sfo_delimiter".to_string(), delim.clone());
                }
                if let Some(enc) = args.get(2) {
                    obj.set_property("__sfo_enclosure".to_string(), enc.clone());
                }
                if let Some(esc) = args.get(3) {
                    obj.set_property("__sfo_escape".to_string(), esc.clone());
                }
                Ok(Some(Value::Null))
            }
            "getCsvControl" => {
                let mut result = PhpArray::new();
                let delim = obj
                    .get_property("__sfo_delimiter")
                    .unwrap_or(Value::String(",".into()));
                let enc = obj
                    .get_property("__sfo_enclosure")
                    .unwrap_or(Value::String("\"".into()));
                let esc = obj
                    .get_property("__sfo_escape")
                    .unwrap_or(Value::String("\\".into()));
                result.push(delim);
                result.push(enc);
                result.push(esc);
                Ok(Some(Value::Array(result)))
            }
            "getChildren" => Ok(Some(Value::Null)),
            "hasChildren" => Ok(Some(Value::Bool(false))),
            _ => Ok(None),
        }
    }
}

/// Strip PHP regex delimiters and return (pattern, flags).
fn strip_php_regex_delimiters(pattern: &str) -> (String, String) {
    if pattern.is_empty() {
        return (String::new(), String::new());
    }
    let bytes = pattern.as_bytes();
    let delim = bytes[0];
    let close_delim = match delim {
        b'(' => b')',
        b'{' => b'}',
        b'[' => b']',
        b'<' => b'>',
        _ => delim,
    };
    // Find the closing delimiter from the end
    if let Some(end_pos) = pattern[1..].rfind(close_delim as char) {
        let regex_body = &pattern[1..end_pos + 1];
        let flags = &pattern[end_pos + 2..];
        // Apply flags to regex
        let mut result = String::new();
        let mut flag_str = String::new();
        for ch in flags.chars() {
            match ch {
                'i' => result.push_str("(?i)"),
                's' => result.push_str("(?s)"),
                'm' => result.push_str("(?m)"),
                'x' => result.push_str("(?x)"),
                'U' => result.push_str("(?U)"),
                _ => {}
            }
            flag_str.push(ch);
        }
        result.push_str(regex_body);
        (result, flag_str)
    } else {
        (pattern.to_string(), String::new())
    }
}
fn parse_relative_to_interval(spec: &str) -> Result<php_rs_ext_date::PhpDateInterval, String> {
    let spec = spec.trim().to_ascii_lowercase();
    let parts: Vec<&str> = spec.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid interval string: {}", spec));
    }
    let n: i32 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid number: {}", parts[0]))?;
    let unit = parts[1].trim();
    let mut di = php_rs_ext_date::PhpDateInterval {
        years: 0,
        months: 0,
        days: 0,
        hours: 0,
        minutes: 0,
        seconds: 0,
        invert: false,
    };
    match unit {
        "year" | "years" => di.years = n,
        "month" | "months" => di.months = n,
        "week" | "weeks" => di.days = n * 7,
        "day" | "days" => di.days = n,
        "hour" | "hours" => di.hours = n,
        "minute" | "minutes" | "min" | "mins" => di.minutes = n,
        "second" | "seconds" | "sec" | "secs" => di.seconds = n,
        _ => return Err(format!("Unknown interval unit: {}", unit)),
    }
    Ok(di)
}
