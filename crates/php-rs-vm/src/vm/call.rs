//! Function call handling — extracted from vm.rs.
//!
//! handle_include_or_eval, handle_do_fcall (the massive function dispatch).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;

use super::{
    literal_to_value, ClassDef, DispatchSignal, Frame, PendingCall, Vm, VmError, VmResult,
};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    pub(crate) fn handle_include_or_eval(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
    ) -> VmResult<DispatchSignal> {
        let operand = self.read_operand(op, 1, oa_idx)?;
        let mode = op.extended_value;
        // mode: 0=eval, 1=include, 2=include_once, 3=require, 4=require_once

        let (source, file_path) = match mode {
            0 => {
                // eval(): operand is the code string
                let code = operand.to_php_string();
                let code = if code.starts_with("<?php") || code.starts_with("<?") {
                    code
                } else {
                    format!("<?php {}", code)
                };
                (code, None)
            }
            1 | 2 | 3 | 4 => {
                let path = operand.to_php_string();

                // open_basedir check for include/require
                self.check_open_basedir(&path)?;

                // For once variants, check if already included
                if (mode == 2 || mode == 4) && self.included_files.contains(&path) {
                    self.write_result(op, oa_idx, Value::Bool(true))?;
                    return Ok(DispatchSignal::Next);
                }

                match self.vm_read_file(&path) {
                    Ok(bytes) => {
                        // PHP files may use ISO-8859-1 or other non-UTF-8 encodings;
                        // convert lossily so we can still parse them.
                        let contents = String::from_utf8(bytes)
                            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
                        self.included_files.insert(path.clone());
                        let kind_label = match mode { 1 => "include", 2 => "include_once", 3 => "require", _ => "require_once" };
                        self.record_event("include", format!("{} {}", kind_label, path));
                        (contents, Some(path))
                    }
                    Err(_) => {
                        if mode == 3 || mode == 4 {
                            return Err(VmError::FatalError(format!(
                                "require(): Failed opening required '{}'",
                                path
                            )));
                        }
                        self.write_result(op, oa_idx, Value::Bool(false))?;
                        return Ok(DispatchSignal::Next);
                    }
                }
            }
            _ => {
                return Err(VmError::InternalError(format!(
                    "Unknown include/eval mode: {}",
                    mode
                )));
            }
        };

        // Compile and execute the source
        let compile_result = if let Some(ref fp) = file_path {
            php_rs_compiler::compile_file(&source, fp)
        } else {
            php_rs_compiler::compile(&source)
        };
        match compile_result {
            Ok(included_oa) => {
                let base_idx = self.op_arrays.len();
                self.op_arrays.push(included_oa.clone());
                self.register_dynamic_func_defs(base_idx);

                // Advance caller's IP past the IncludeOrEval
                self.call_stack.last_mut().unwrap().ip += 1;

                let mut new_frame = Frame::new(&included_oa);
                new_frame.op_array_idx = base_idx;
                self.populate_superglobals(&mut new_frame, &included_oa);
                if op.result_type != OperandType::Unused {
                    new_frame.return_dest = Some((op.result_type, op.result.val));
                }

                // Inherit scope from entire include chain: walk up through
                // include frames so nested requires can see variables from
                // grandparent scopes (e.g., index.php → page/[n].php → pages/index.php).
                new_frame.is_include_frame = true;
                {
                    let child_vars = &included_oa.vars;
                    let mut found: Vec<bool> = vec![false; child_vars.len()];
                    // Walk up the call stack from nearest to farthest
                    for stack_idx in (0..self.call_stack.len()).rev() {
                        let ancestor = &self.call_stack[stack_idx];
                        let ancestor_oa = &self.op_arrays[ancestor.op_array_idx];
                        for (child_idx, child_name) in child_vars.iter().enumerate() {
                            if found[child_idx] {
                                continue;
                            }
                            if let Some(anc_cv_idx) = ancestor_oa.vars.iter().position(|v| v == child_name) {
                                if anc_cv_idx < ancestor.cvs.len() {
                                    new_frame.cvs[child_idx] = ancestor.cvs[anc_cv_idx].clone();
                                    new_frame.include_scope_map.push((child_idx, stack_idx, anc_cv_idx));
                                    found[child_idx] = true;
                                }
                            }
                        }
                        // Stop at function call boundaries — only walk through include frames
                        if !ancestor.is_include_frame && stack_idx < self.call_stack.len() - 1 {
                            break;
                        }
                    }
                }

                self.call_stack.push(new_frame);
                Ok(DispatchSignal::CallPushed)
            }
            Err(e) => {
                eprintln!("COMPILE ERROR for {:?}: {:?}", file_path, e);
                if mode == 0 {
                    return Err(VmError::FatalError("eval(): syntax error".to_string()));
                }
                self.write_result(op, oa_idx, Value::Bool(false))?;
                Ok(DispatchSignal::Next)
            }
        }
    }

    /// Handle DO_FCALL — execute a function call.
    pub(crate) fn handle_do_fcall(
        &mut self,
        op: &ZOp,
        caller_oa_idx: usize,
    ) -> VmResult<DispatchSignal> {
        let caller_frame = self.call_stack.last_mut().unwrap();
        let pending = caller_frame
            .call_stack_pending
            .pop()
            .unwrap_or(PendingCall {
                name: String::new(),
                args: Vec::new(),
                arg_names: Vec::new(),
                this_source: None,
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
        let func_name = if pending.name.starts_with('\\') && !pending.name.contains("::") {
            pending.name[1..].to_string()
        } else {
            pending.name
        };
        let mut args = pending.args;
        let mut arg_names = pending.arg_names;
        let this_source = pending.this_source;
        let pending_static_class = pending.static_class;
        let pending_forwarded_this = pending.forwarded_this;
        let ref_args = pending.ref_args;
        let ref_prop_args = pending.ref_prop_args;

        // For method calls via InitMethodCall, extract $this (first arg) before named arg reordering
        // so it doesn't participate in the parameter position shuffling.
        // InitMethodCall prepends $this as args[0] and sets this_source.
        // InitStaticMethodCall uses forwarded_this instead.
        let is_method = func_name.contains("::");
        let has_this_in_args = is_method && !args.is_empty() && this_source.is_some();
        let this_arg = if has_this_in_args {
            let this_val = args.remove(0);
            // Only remove from arg_names if it has an entry for $this (same length as args+1)
            if arg_names.len() > args.len() {
                arg_names.remove(0);
            }
            Some(this_val)
        } else {
            pending_forwarded_this
        };

        // Reorder named arguments to match parameter positions
        let has_named_args = arg_names.iter().any(|n| !n.is_empty());
        let mut named_arg_provided: Option<Vec<bool>> = None;
        if has_named_args {
            // Look up the function's arg_info to get parameter names
            let func_oa_idx = self.functions.get(&func_name).copied().or_else(|| {
                if let Some(sep) = func_name.find("::") {
                    let class = &func_name[..sep];
                    let method = &func_name[sep + 2..];
                    self.resolve_method(class, method)
                } else {
                    None
                }
            });
            if let Some(oa_idx) = func_oa_idx {
                let param_names: Vec<String> = self.op_arrays[oa_idx]
                    .arg_info
                    .iter()
                    .map(|a| a.name.clone())
                    .collect();
                if !param_names.is_empty() {
                    let reordered_len = param_names.len().max(args.len());
                    let mut reordered = vec![Value::Null; reordered_len];
                    let mut provided = vec![false; reordered_len];
                    for (i, (arg, name)) in args.iter().zip(arg_names.iter()).enumerate() {
                        if !name.is_empty() {
                            // Find the parameter index by name
                            if let Some(pos) = param_names.iter().position(|p| p == name) {
                                reordered[pos] = arg.clone();
                                provided[pos] = true;
                            } else {
                                // Unknown named arg — put it at its original position
                                if i < reordered.len() {
                                    reordered[i] = arg.clone();
                                    provided[i] = true;
                                } else {
                                    reordered.push(arg.clone());
                                    provided.push(true);
                                }
                            }
                        } else {
                            // Positional arg
                            if i < reordered.len() {
                                reordered[i] = arg.clone();
                                provided[i] = true;
                            } else {
                                reordered.push(arg.clone());
                                provided.push(true);
                            }
                        }
                    }
                    args = reordered;
                    named_arg_provided = Some(provided);
                }
            }
        }

        // Re-insert $this as first arg for method calls (builtin/reflection handlers expect it)
        if let Some(ref this_val) = this_arg {
            args.insert(0, this_val.clone());
        }

        // Handle no-op constructor (NEW without __construct)
        if func_name == "__new_noop__" {
            // Get the object from the result slot of the preceding NEW
            let obj_val = {
                let frame = self.call_stack.last().unwrap();
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    match op.result_type {
                        OperandType::TmpVar | OperandType::Var => frame.temps.get(slot).cloned(),
                        OperandType::Cv => frame.cvs.get(slot).cloned(),
                        _ => None,
                    }
                } else {
                    None
                }
            };

            if let Some(Value::Object(ref o)) = obj_val {
                // For Fiber objects, save the constructor args (callback name)
                if o.internal() == crate::value::InternalState::Fiber {
                    if !args.is_empty() {
                        let callback_name = Self::extract_closure_name(&args[0]);
                        if let Some(fiber_state) = self.fibers.get_mut(&o.object_id()) {
                            fiber_state.callback_name = callback_name;
                        }
                    }
                }

                // For SplFileInfo/directory iterator classes, store the filename path
                let class = o.class_name();
                let base_class = class.rsplit('\\').next().unwrap_or(&class);
                if base_class == "SplFileInfo" {
                    let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
                    o.set_property("__spl_path".to_string(), Value::String(path));
                }
                if matches!(
                    base_class,
                    "RecursiveDirectoryIterator" | "FilesystemIterator" | "DirectoryIterator"
                ) {
                    let path = args.first().map(|v| v.to_php_string()).unwrap_or_default();
                    // Read directory entries
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
                    o.set_property("__dir_path".to_string(), Value::String(path));
                    o.set_property("__dir_entries".to_string(), Value::Array(entries));
                    o.set_property("__dir_index".to_string(), Value::Long(0));
                    o.set_property("__dir_sub_path".to_string(), Value::String(String::new()));
                }

                // For RecursiveIteratorIterator / IteratorIterator / FilterIterator / CallbackFilterIterator
                // Also check parent chain for user classes extending these
                let is_wrapper_iter = matches!(
                    base_class,
                    "RecursiveIteratorIterator"
                        | "IteratorIterator"
                        | "FilterIterator"
                        | "RecursiveFilterIterator"
                        | "CallbackFilterIterator"
                        | "RecursiveCallbackFilterIterator"
                ) || self.find_spl_ancestor(base_class).map_or(false, |a| {
                    matches!(
                        a.as_str(),
                        "FilterIterator"
                            | "RecursiveFilterIterator"
                            | "IteratorIterator"
                            | "RecursiveIteratorIterator"
                    )
                });
                if is_wrapper_iter {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    // CallbackFilterIterator: store the callback
                    if matches!(
                        base_class,
                        "CallbackFilterIterator" | "RecursiveCallbackFilterIterator"
                    ) {
                        if let Some(callback) = args.get(1) {
                            o.set_property("__filter_callback".to_string(), callback.clone());
                        }
                    }
                }

                // For ArrayIterator / ArrayObject
                if matches!(base_class, "ArrayIterator" | "ArrayObject") {
                    let data = args
                        .first()
                        .cloned()
                        .unwrap_or(Value::Array(PhpArray::new()));
                    if let Value::Array(a) = data {
                        o.set_property("__array_data".to_string(), Value::Array(a));
                    } else {
                        o.set_property("__array_data".to_string(), Value::Array(PhpArray::new()));
                    }
                    o.set_property("__array_index".to_string(), Value::Long(0));
                }

                // LimitIterator
                if base_class == "LimitIterator" {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let offset = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                    let count = args.get(2).map(|v| v.to_long()).unwrap_or(-1);
                    o.set_property("__limit_offset".to_string(), Value::Long(offset));
                    o.set_property("__limit_count".to_string(), Value::Long(count));
                    o.set_property("__limit_pos".to_string(), Value::Long(0));
                }

                // InfiniteIterator
                if base_class == "InfiniteIterator" {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                }

                // NoRewindIterator
                if base_class == "NoRewindIterator" {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                }

                // AppendIterator
                if base_class == "AppendIterator" {
                    o.set_property(
                        "__append_iterators".to_string(),
                        Value::Array(PhpArray::new()),
                    );
                    o.set_property("__append_index".to_string(), Value::Long(0));
                }

                // CachingIterator
                if base_class == "CachingIterator" {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let flags = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                    o.set_property("__cache_flags".to_string(), Value::Long(flags));
                    o.set_property("__cache_valid".to_string(), Value::Bool(false));
                    o.set_property("__cache_current".to_string(), Value::Null);
                    o.set_property("__cache_key".to_string(), Value::Null);
                    o.set_property("__cache_has_next".to_string(), Value::Bool(false));
                }

                // RegexIterator / RecursiveRegexIterator
                if matches!(base_class, "RegexIterator" | "RecursiveRegexIterator") {
                    if let Some(inner) = args.first() {
                        o.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let pattern = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                    let mode = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                    let flags = args.get(3).map(|v| v.to_long()).unwrap_or(0);
                    o.set_property("__regex_pattern".to_string(), Value::String(pattern));
                    o.set_property("__regex_mode".to_string(), Value::Long(mode));
                    o.set_property("__regex_flags".to_string(), Value::Long(flags));
                    o.set_property("__regex_preg_flags".to_string(), Value::Long(0));
                }

                // MultipleIterator
                if base_class == "MultipleIterator" {
                    let flags = args.first().map(|v| v.to_long()).unwrap_or(1); // MIT_NEED_ALL
                    o.set_property(
                        "__multi_iterators".to_string(),
                        Value::Array(PhpArray::new()),
                    );
                    o.set_property("__multi_infos".to_string(), Value::Array(PhpArray::new()));
                    o.set_property("__multi_flags".to_string(), Value::Long(flags));
                }

                // SplFileObject / SplTempFileObject
                if matches!(base_class, "SplFileObject" | "SplTempFileObject") {
                    let filename = args.first().map(|v| v.to_php_string()).unwrap_or_default();
                    let mode = args
                        .get(1)
                        .map(|v| v.to_php_string())
                        .unwrap_or_else(|| "r".to_string());
                    o.set_property("__spl_path".to_string(), Value::String(filename.clone()));
                    o.set_property("__sfo_mode".to_string(), Value::String(mode));
                    o.set_property("__sfo_line".to_string(), Value::Long(0));
                    o.set_property("__sfo_flags".to_string(), Value::Long(0));
                    o.set_property("__sfo_delimiter".to_string(), Value::String(",".into()));
                    o.set_property("__sfo_enclosure".to_string(), Value::String("\"".into()));
                    o.set_property("__sfo_escape".to_string(), Value::String("\\".into()));
                    match self.vm_read_to_string(&filename) {
                        Ok(contents) => {
                            let mut lines = PhpArray::new();
                            for line in contents.split('\n') {
                                lines.push(Value::String(format!("{}\n", line)));
                            }
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
                            o.set_property("__sfo_lines".to_string(), Value::Array(lines));
                        }
                        Err(_) => {
                            o.set_property(
                                "__sfo_lines".to_string(),
                                Value::Array(PhpArray::new()),
                            );
                        }
                    }
                }

                // For Exception/Error classes, set message/code/previous from constructor args
                let base = base_class;
                if base.contains("Exception") || base.contains("Error") || base == "Throwable" {
                    if base == "ErrorException" {
                        // ErrorException($message, $code, $severity, $file, $line, $previous)
                        let msg = args
                            .first()
                            .cloned()
                            .unwrap_or(Value::String(String::new()));
                        let code = args.get(1).cloned().unwrap_or(Value::Long(0));
                        let severity = args.get(2).cloned().unwrap_or(Value::Long(2)); // E_WARNING
                        let file = args.get(3).cloned().unwrap_or(Value::String(String::new()));
                        let line = args.get(4).cloned().unwrap_or(Value::Long(0));
                        let previous = args.get(5).cloned().unwrap_or(Value::Null);
                        o.set_property("message".to_string(), msg);
                        o.set_property("code".to_string(), code);
                        o.set_property("severity".to_string(), severity);
                        o.set_property("file".to_string(), file);
                        o.set_property("line".to_string(), line);
                        o.set_property("previous".to_string(), previous);
                    } else {
                        let msg = args
                            .first()
                            .cloned()
                            .unwrap_or(Value::String(String::new()));
                        let code = args.get(1).cloned().unwrap_or(Value::Long(0));
                        let previous = args.get(2).cloned().unwrap_or(Value::Null);
                        o.set_property("message".to_string(), msg);
                        o.set_property("code".to_string(), code);
                        o.set_property("previous".to_string(), previous);
                    }
                }
            }
            return Ok(DispatchSignal::Next);
        }

        // Handle ReflectionClass/ReflectionObject constructor
        if func_name == "ReflectionClass::__construct"
            || func_name == "ReflectionObject::__construct"
        {
            // args[0] is $this (the ReflectionClass/Object), args[1] is the class name or object
            if let Some(Value::Object(ref obj)) = args.first() {
                if obj.internal() == crate::value::InternalState::ReflectionClass {
                    let obj_id = obj.object_id();
                    // ReflectionObject takes an object, ReflectionClass takes a string
                    let reflected_name = match args.get(1) {
                        Some(Value::Object(ref o)) => o.class_name().to_string(),
                        Some(v) => v.to_php_string(),
                        None => String::new(),
                    };

                    // Try autoloading the reflected class
                    if !self.classes.contains_key(&reflected_name) {
                        self.try_autoload_class(&reflected_name);
                    }

                    // If class still not found, throw ReflectionException
                    if !self.classes.contains_key(&reflected_name) {
                        let ex_obj = PhpObject::new("ReflectionException".to_string());
                        ex_obj.set_property(
                            "message".to_string(),
                            Value::String(format!("Class \"{}\" does not exist", reflected_name)),
                        );
                        return Err(VmError::Thrown(Value::Object(ex_obj)));
                    }

                    self.reflection_classes.insert(obj_id, reflected_name);
                }
            }
            // Don't write result — constructor doesn't return a value
            return Ok(DispatchSignal::Next);
        }

        // Handle ReflectionMethod constructor
        if func_name == "ReflectionMethod::__construct" {
            // args[0] is $this (ReflectionMethod obj), args[1] is class/object, args[2] is method name
            if let Some(Value::Object(ref obj)) = args.first() {
                let class_name = match args.get(1) {
                    Some(Value::Object(ref o)) => o.class_name().to_string(),
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_php_string(),
                    None => String::new(),
                };
                let method_name = match args.get(2) {
                    Some(v) => v.to_php_string(),
                    None => String::new(),
                };

                // Find the declaring class by looking up the op_array's function_name.
                // When methods are inherited, the op_array still has the original class prefix.
                let declaring_class = {
                    let full_method = format!("{}::{}", class_name, method_name);
                    if let Some(&oa_idx) = self.functions.get(&full_method) {
                        if let Some(ref fname) = self
                            .op_arrays
                            .get(oa_idx)
                            .and_then(|oa| oa.function_name.as_ref())
                        {
                            // function_name is like "OriginalClass::method"
                            if let Some(class_part) = fname.rsplit_once("::").map(|(c, _)| c) {
                                class_part.to_string()
                            } else {
                                class_name.clone()
                            }
                        } else {
                            class_name.clone()
                        }
                    } else {
                        class_name.clone()
                    }
                };

                obj.set_property("class".to_string(), Value::String(declaring_class));
                obj.set_property("name".to_string(), Value::String(method_name));
            }
            return Ok(DispatchSignal::Next);
        }

        // Handle ReflectionFunction constructor
        if func_name == "ReflectionFunction::__construct" {
            // args[0] is $this, args[1] is the function/closure
            if let Some(Value::Object(ref obj)) = args.first() {
                let func_val = args.get(1).cloned().unwrap_or(Value::Null);
                // Store the reflected function name/closure on the object
                let func_name_str = match &func_val {
                    Value::String(s) => s.clone(),
                    Value::Object(o) if o.class_name() == "Closure" => {
                        // Use the unique closure name so we can look up its op_array
                        Self::extract_closure_name(&func_val)
                    }
                    _ => func_val.to_php_string(),
                };
                obj.set_property("name".to_string(), Value::String(func_name_str));
                obj.set_property("_reflected_callable".to_string(), func_val);
            }
            return Ok(DispatchSignal::Next);
        }

        // Handle SQLite3 constructor
        if func_name == "SQLite3::__construct" {
            #[cfg(feature = "native-io")]
            if let Some(Value::Object(ref obj)) = args.first() {
                let filename = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                // flags: default READWRITE|CREATE = 6
                let flags = args.get(2).map(|v| v.to_long()).unwrap_or(6) as i32;
                match crate::sqlite3::Sqlite3Connection::open(&filename, flags) {
                    Ok(conn) => {
                        let obj_id = obj.object_id();
                        self.sqlite3_connections.insert(obj_id, conn);
                        obj.set_property("__sqlite3_filename".to_string(), Value::String(filename));
                    }
                    Err(e) => {
                        let ex_obj = PhpObject::new("Exception".to_string());
                        ex_obj.set_property(
                            "message".to_string(),
                            Value::String(format!("Unable to open database: {}", e)),
                        );
                        return Err(VmError::Thrown(Value::Object(ex_obj)));
                    }
                }
            }
            return Ok(DispatchSignal::Next);
        }

        // Handle PDO constructor
        if func_name == "PDO::__construct" {
            #[cfg(feature = "native-io")]
            if let Some(Value::Object(ref obj)) = args.first() {
                let dsn = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let username = args.get(2).and_then(|v| {
                    if matches!(v, Value::Null) {
                        None
                    } else {
                        Some(v.to_php_string())
                    }
                });
                let password = args.get(3).and_then(|v| {
                    if matches!(v, Value::Null) {
                        None
                    } else {
                        Some(v.to_php_string())
                    }
                });

                // Create PDO connection
                let conn = php_rs_ext_pdo::PdoConnection::new(
                    &dsn,
                    username.as_deref(),
                    password.as_deref(),
                );

                match conn {
                    Ok(pdo_conn) => {
                        let obj_id = obj.object_id();
                        self.pdo_connections.insert(obj_id, pdo_conn);
                        obj.set_property("__pdo_connected".to_string(), Value::Bool(true));
                    }
                    Err(e) => {
                        // Throw PDOException
                        let ex_obj = PhpObject::new("PDOException".to_string());
                        ex_obj.set_property(
                            "message".to_string(),
                            Value::String(format!("SQLSTATE[{}]: {}", e.sqlstate, e.message)),
                        );
                        ex_obj.set_property(
                            "code".to_string(),
                            e.code
                                .as_ref()
                                .map(|c| Value::String(c.clone()))
                                .unwrap_or(Value::Long(0)),
                        );
                        return Err(VmError::Thrown(Value::Object(ex_obj)));
                    }
                }
            }
            return Ok(DispatchSignal::Next);
        }

        // Handle built-in class constructors
        if func_name.ends_with("::__construct") {
            let class_part = &func_name[..func_name.len() - 13]; // strip "::__construct"
            let base_class = class_part.rsplit('\\').next().unwrap_or(class_part);

            // DateTime/DateTimeImmutable constructors — parse and store timestamp
            if base_class == "DateTime" || base_class == "DateTimeImmutable" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let time_str = args.get(1).and_then(|v| {
                        if matches!(v, Value::Null) {
                            None
                        } else {
                            Some(v.to_php_string())
                        }
                    });
                    let tz_str = args.get(2).and_then(|v| match v {
                        Value::Object(tz_obj) => {
                            tz_obj.get_property("__tz_name").map(|v| v.to_php_string())
                        }
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    });
                    let tz_ref = tz_str.as_deref();
                    match php_rs_ext_date::PhpDateTime::new(time_str.as_deref(), tz_ref) {
                        Ok(php_dt) => {
                            obj.set_property(
                                "__timestamp".to_string(),
                                Value::Long(php_dt.get_timestamp()),
                            );
                            obj.set_property(
                                "__timezone".to_string(),
                                Value::String(php_dt.timezone.clone()),
                            );
                        }
                        Err(_) => {
                            // Store current time as fallback
                            obj.set_property(
                                "__timestamp".to_string(),
                                Value::Long(php_rs_ext_date::php_time()),
                            );
                            obj.set_property(
                                "__timezone".to_string(),
                                Value::String("UTC".to_string()),
                            );
                        }
                    }
                }
                return Ok(DispatchSignal::Next);
            }

            // DateTimeZone constructor — resolve timezone name and offset
            if base_class == "DateTimeZone" || base_class == "CarbonTimeZone" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let tz_name = args
                        .get(1)
                        .map(|v| v.to_php_string())
                        .unwrap_or_else(|| "UTC".to_string());
                    let offset =
                        php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz_name).unwrap_or(0);
                    obj.set_property("__tz_name".to_string(), Value::String(tz_name));
                    obj.set_property("__tz_offset".to_string(), Value::Long(offset as i64));
                }
                return Ok(DispatchSignal::Next);
            }

            // DateInterval constructor — parse ISO 8601 duration
            if base_class == "DateInterval" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let spec = args
                        .get(1)
                        .map(|v| v.to_php_string())
                        .unwrap_or_else(|| "P0D".to_string());
                    if let Ok(di) = php_rs_ext_date::PhpDateInterval::create_from_date_string(&spec)
                    {
                        obj.set_property("y".to_string(), Value::Long(di.years as i64));
                        obj.set_property("m".to_string(), Value::Long(di.months as i64));
                        obj.set_property("d".to_string(), Value::Long(di.days as i64));
                        obj.set_property("h".to_string(), Value::Long(di.hours as i64));
                        obj.set_property("i".to_string(), Value::Long(di.minutes as i64));
                        obj.set_property("s".to_string(), Value::Long(di.seconds as i64));
                        obj.set_property(
                            "invert".to_string(),
                            Value::Long(if di.invert { 1 } else { 0 }),
                        );
                        obj.set_property(
                            "days".to_string(),
                            Value::Long(
                                (di.years as i64 * 365) + (di.months as i64 * 30) + di.days as i64,
                            ),
                        );
                    }
                }
                return Ok(DispatchSignal::Next);
            }

            // DatePeriod constructor
            if base_class == "DatePeriod" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    // DatePeriod($start, $interval, $recurrences_or_end, $options)
                    if let Some(Value::Object(ref start_obj)) = args.get(1) {
                        let start_ts = start_obj
                            .get_property("__timestamp")
                            .map(|v| v.to_long())
                            .unwrap_or(0);
                        obj.set_property("__start_ts".to_string(), Value::Long(start_ts));
                    }
                    if let Some(Value::Object(ref interval_obj)) = args.get(2) {
                        // Copy interval properties
                        for prop in &["y", "m", "d", "h", "i", "s"] {
                            if let Some(v) = interval_obj.get_property(prop) {
                                obj.set_property(format!("__interval_{}", prop), v);
                            }
                        }
                    }
                    match args.get(3) {
                        Some(Value::Long(n)) => {
                            obj.set_property("__recurrences".to_string(), Value::Long(*n));
                        }
                        Some(Value::Object(ref end_obj)) => {
                            let end_ts = end_obj
                                .get_property("__timestamp")
                                .map(|v| v.to_long())
                                .unwrap_or(0);
                            obj.set_property("__end_ts".to_string(), Value::Long(end_ts));
                        }
                        _ => {}
                    }
                    let options = args.get(4).map(|v| v.to_long()).unwrap_or(0);
                    obj.set_property("__options".to_string(), Value::Long(options));
                    // Pre-generate iteration entries
                    self.generate_date_period_entries(obj);
                }
                return Ok(DispatchSignal::Next);
            }

            // SplFixedArray constructor
            if base_class == "SplFixedArray" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let size = args.get(1).map(|v| v.to_long()).unwrap_or(0).max(0) as usize;
                    let mut arr = PhpArray::new();
                    for i in 0..size {
                        arr.set_int(i as i64, Value::Null);
                    }
                    obj.set_property("__spl_data".to_string(), Value::Array(arr));
                    obj.set_property("__spl_size".to_string(), Value::Long(size as i64));
                    obj.set_property("__spl_index".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // SplDoublyLinkedList / SplStack / SplQueue constructor
            if matches!(base_class, "SplDoublyLinkedList" | "SplStack" | "SplQueue") {
                if let Some(Value::Object(ref obj)) = args.first() {
                    obj.set_property("__dll_data".to_string(), Value::Array(PhpArray::new()));
                    obj.set_property("__dll_index".to_string(), Value::Long(0));
                    let mode = if base_class == "SplStack" { 6 } else { 0 }; // LIFO|DELETE vs FIFO|KEEP
                    obj.set_property("__dll_mode".to_string(), Value::Long(mode));
                }
                return Ok(DispatchSignal::Next);
            }

            // SplHeap / SplMinHeap / SplMaxHeap / SplPriorityQueue constructor
            if matches!(
                base_class,
                "SplHeap" | "SplMinHeap" | "SplMaxHeap" | "SplPriorityQueue"
            ) {
                if let Some(Value::Object(ref obj)) = args.first() {
                    obj.set_property("__heap_data".to_string(), Value::Array(PhpArray::new()));
                    obj.set_property("__heap_index".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // SplObjectStorage constructor
            if base_class == "SplObjectStorage" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    obj.set_property("__sos_objects".to_string(), Value::Array(PhpArray::new()));
                    obj.set_property("__sos_infos".to_string(), Value::Array(PhpArray::new()));
                    obj.set_property("__sos_index".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // LimitIterator constructor
            if base_class == "LimitIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    if let Some(inner) = args.get(1) {
                        obj.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                    let count = args.get(3).map(|v| v.to_long()).unwrap_or(-1);
                    obj.set_property("__limit_offset".to_string(), Value::Long(offset));
                    obj.set_property("__limit_count".to_string(), Value::Long(count));
                    obj.set_property("__limit_pos".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // InfiniteIterator constructor
            if base_class == "InfiniteIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    if let Some(inner) = args.get(1) {
                        obj.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                }
                return Ok(DispatchSignal::Next);
            }

            // NoRewindIterator constructor
            if base_class == "NoRewindIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    if let Some(inner) = args.get(1) {
                        obj.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                }
                return Ok(DispatchSignal::Next);
            }

            // AppendIterator constructor
            if base_class == "AppendIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    obj.set_property(
                        "__append_iterators".to_string(),
                        Value::Array(PhpArray::new()),
                    );
                    obj.set_property("__append_index".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // CachingIterator constructor
            if base_class == "CachingIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    if let Some(inner) = args.get(1) {
                        obj.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let flags = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                    obj.set_property("__cache_flags".to_string(), Value::Long(flags));
                    obj.set_property("__cache_valid".to_string(), Value::Bool(false));
                    obj.set_property("__cache_current".to_string(), Value::Null);
                    obj.set_property("__cache_key".to_string(), Value::Null);
                    obj.set_property("__cache_has_next".to_string(), Value::Bool(false));
                }
                return Ok(DispatchSignal::Next);
            }

            // RegexIterator / RecursiveRegexIterator constructor
            if matches!(base_class, "RegexIterator" | "RecursiveRegexIterator") {
                if let Some(Value::Object(ref obj)) = args.first() {
                    if let Some(inner) = args.get(1) {
                        obj.set_property("__inner_iterator".to_string(), inner.clone());
                    }
                    let pattern = args.get(2).map(|v| v.to_php_string()).unwrap_or_default();
                    let mode = args.get(3).map(|v| v.to_long()).unwrap_or(0);
                    let flags = args.get(4).map(|v| v.to_long()).unwrap_or(0);
                    obj.set_property("__regex_pattern".to_string(), Value::String(pattern));
                    obj.set_property("__regex_mode".to_string(), Value::Long(mode));
                    obj.set_property("__regex_flags".to_string(), Value::Long(flags));
                    obj.set_property("__regex_preg_flags".to_string(), Value::Long(0));
                }
                return Ok(DispatchSignal::Next);
            }

            // MultipleIterator constructor
            if base_class == "MultipleIterator" {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let flags = args.get(1).map(|v| v.to_long()).unwrap_or(1); // MIT_NEED_ALL
                    obj.set_property(
                        "__multi_iterators".to_string(),
                        Value::Array(PhpArray::new()),
                    );
                    obj.set_property("__multi_infos".to_string(), Value::Array(PhpArray::new()));
                    obj.set_property("__multi_flags".to_string(), Value::Long(flags));
                }
                return Ok(DispatchSignal::Next);
            }

            // SplFileObject / SplTempFileObject constructor
            if matches!(base_class, "SplFileObject" | "SplTempFileObject") {
                // Delegate to the method handler which does full initialization
                // But we need to return Next to not fall through
                if let Some(Value::Object(ref obj)) = args.first() {
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
                            obj.set_property(
                                "__sfo_lines".to_string(),
                                Value::Array(PhpArray::new()),
                            );
                        }
                    }
                }
                return Ok(DispatchSignal::Next);
            }

            // Exception/Error constructors: set message, code, previous properties
            // Only match if the class actually extends Exception/Error (check parent chain)
            if self.is_exception_class(class_part) {
                if let Some(Value::Object(ref obj)) = args.first() {
                    let msg = args.get(1).cloned().unwrap_or(Value::String(String::new()));
                    let code = args.get(2).cloned().unwrap_or(Value::Long(0));
                    let previous = args.get(3).cloned().unwrap_or(Value::Null);
                    obj.set_property("message".to_string(), msg);
                    obj.set_property("code".to_string(), code);
                    obj.set_property("previous".to_string(), previous);
                }
                return Ok(DispatchSignal::Next);
            }
        }

        // Fiber is a built-in class (not in the classes table). Compiled as INIT_FCALL "Fiber" + DO_FCALL;
        // return "Fiber" so NEW can create the instance, and save args for handle_new.
        if func_name == "Fiber" {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, Value::String("Fiber".to_string()))?;
            }
            if !args.is_empty() {
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name: "__ctor_args__".to_string(),
                    args,
                    arg_names: Vec::new(),
                    this_source: None,
                    static_class: None,
                    forwarded_this: None,
                    ref_args: Vec::new(),
                    ref_prop_args: Vec::new(),
                });
            }
            return Ok(DispatchSignal::Next);
        }

        // If the "function" name is a class name, return it as a string value
        // (used by NEW to resolve class references compiled as INIT_FCALL + DO_FCALL)
        // The args passed here are actually constructor args — save them for the NEW/DO_FCALL that follows.
        if self.classes.contains_key(&func_name) {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, Value::String(func_name.clone()))?;
            }
            // Store constructor args for later use by NEW
            if !args.is_empty() {
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name: "__ctor_args__".to_string(),
                    args,
                    arg_names: Vec::new(),
                    this_source: None,
                    static_class: None,
                    forwarded_this: None,
                    ref_args: Vec::new(),
                    ref_prop_args: Vec::new(),
                });
            }
            return Ok(DispatchSignal::Next);
        }

        // Check built-in functions first (use simple name for builtins)
        let simple_name = if func_name.contains("::") {
            func_name.rsplit("::").next().unwrap_or(&func_name)
        } else {
            &func_name
        };

        // For non-method calls, check builtins
        if !func_name.contains("::") {
            if let Some(result) =
                self.call_builtin(simple_name, &args, &ref_args, &ref_prop_args)?
            {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }
            // If the function has a namespace prefix, try short name as builtin fallback
            if func_name.contains('\\') {
                let short = func_name.rsplit('\\').next().unwrap_or(&func_name);
                if let Some(result) = self.call_builtin(short, &args, &ref_args, &ref_prop_args)? {
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, caller_oa_idx, result)?;
                    }
                    return Ok(DispatchSignal::Next);
                }
            }
        }

        // Handle Closure::bind() and Closure::fromCallable()
        if func_name == "Closure::bind" || func_name == "Closure::bindTo" {
            // Closure::bind($closure, $newThis, $newScope = "static")
            // For the Composer use case, just return the original closure
            let closure_val = args.first().cloned().unwrap_or(Value::Null);
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, closure_val)?;
            }
            return Ok(DispatchSignal::Next);
        }
        if func_name == "Closure::fromCallable" {
            // Closure::fromCallable($callable) — return the callable as-is
            let callable = args.first().cloned().unwrap_or(Value::Null);
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, callable)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Check if this is a Generator method call
        if let Some(gen_result) = self.try_generator_method(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, gen_result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Check if this is a Fiber method call
        if let Some(fiber_result) = self.try_fiber_method(&func_name, &args)? {
            // Fiber::suspend popped the current frame; return Yield so the dispatch loop exits
            // without incrementing the caller's IP (otherwise we'd advance the wrong frame).
            if func_name == "Fiber::suspend" {
                return Ok(DispatchSignal::Yield);
            }
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, fiber_result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Check if this is a Reflection* method call
        if let Some(refl_result) = self.try_reflection_method(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, refl_result)?;
            }
            return Ok(DispatchSignal::Next);
        }
        if let Some(refl_result) = self.try_reflection_method_call(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, refl_result)?;
            }
            return Ok(DispatchSignal::Next);
        }
        // Handle ReflectionAttribute::* calls
        if let Some(method) = func_name.strip_prefix("ReflectionAttribute::") {
            if let Some(Value::Object(ref attr_obj)) = args.first() {
                if attr_obj.class_name() == "ReflectionAttribute" {
                    let result = match method {
                        "getName" => attr_obj
                            .get_property("name")
                            .unwrap_or(Value::String(String::new())),
                        "getArguments" => attr_obj
                            .get_property("arguments")
                            .unwrap_or(Value::Array(PhpArray::new())),
                        "newInstance" => {
                            // Create an instance of the attribute class
                            let attr_name = attr_obj
                                .get_property("name")
                                .map(|v| v.to_php_string())
                                .unwrap_or_default();
                            let attr_args = attr_obj.get_property("arguments");
                            let instance = PhpObject::new(attr_name.clone());
                            instance.set_object_id(self.next_object_id);
                            self.next_object_id += 1;
                            // Set properties from arguments
                            if let Some(Value::Array(ref args_arr)) = attr_args {
                                for (key, val) in args_arr.entries() {
                                    match &key {
                                        crate::value::ArrayKey::String(k) => {
                                            instance.set_property(k.clone(), val.clone());
                                        }
                                        crate::value::ArrayKey::Int(i) => {
                                            instance.set_property(i.to_string(), val.clone());
                                        }
                                    }
                                }
                            }
                            Value::Object(instance)
                        }
                        _ => Value::Null,
                    };
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, caller_oa_idx, result)?;
                    }
                    return Ok(DispatchSignal::Next);
                }
            }
        }
        if let Some(refl_result) = self.try_reflection_parameter_call(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, refl_result)?;
            }
            return Ok(DispatchSignal::Next);
        }
        if let Some(refl_result) = self.try_reflection_named_type_call(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, refl_result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Look up user-defined function (with parent chain fallback for methods)
        let func_oa_idx = self.functions.get(&func_name).copied().or_else(|| {
            // If it's a method call (contains ::), try parent chain resolution
            if let Some(sep) = func_name.find("::") {
                let class = &func_name[..sep];
                let method = &func_name[sep + 2..];
                self.resolve_method(class, method)
            } else if func_name.contains('\\') {
                // Namespace fallback: try the short name (after last \)
                let short = func_name.rsplit('\\').next().unwrap_or(&func_name);
                self.functions.get(short).copied()
            } else {
                None
            }
        });
        if let Some(oa_idx) = func_oa_idx {
            // Check if this is a generator function
            if self.op_arrays[oa_idx].is_generator {
                return self.create_generator_object(op, caller_oa_idx, oa_idx, &args);
            }

            // Advance caller's IP past DO_FCALL BEFORE pushing new frame
            if self.call_stack.len() > 200 {
                let stack: Vec<String> = self
                    .call_stack
                    .iter()
                    .rev()
                    .take(20)
                    .map(|f| {
                        self.op_arrays
                            .get(f.op_array_idx)
                            .and_then(|oa| oa.function_name.as_deref())
                            .unwrap_or("<main>")
                            .to_string()
                    })
                    .collect();
                return Err(VmError::FatalError(format!(
                    "Maximum function nesting level of 200 reached, aborting! Stack (top 20): {}",
                    stack.join(" -> ")
                )));
            }
            self.call_stack.last_mut().unwrap().ip += 1;

            let func_oa = &self.op_arrays[oa_idx];
            let mut new_frame = Frame::new(func_oa);
            new_frame.op_array_idx = oa_idx;
            self.populate_superglobals(&mut new_frame, func_oa);
            new_frame.static_class = pending_static_class;
            new_frame.called_as = Some(func_name.clone());

            // Bind $this if we have one (extracted from args[0] or forwarded_this earlier)
            if let Some(ref this_val) = this_arg {
                let has_this_var = func_oa.vars.iter().any(|v| v == "this");
                if has_this_var {
                    let this_cv_idx = func_oa.vars.iter().position(|v| v == "this").unwrap_or(0);
                    if this_cv_idx < new_frame.cvs.len() {
                        new_frame.cvs[this_cv_idx] = this_val.clone();
                    }
                }
                // $this was re-inserted at args[0] for builtin handlers — skip it for user function args
                new_frame.args = args[1..].to_vec();
            } else {
                new_frame.args = args.clone();
            }
            new_frame.named_arg_provided = named_arg_provided;

            // For constructors, don't set return_dest (would overwrite the object with Null)
            let is_constructor = func_name.ends_with("::__construct");
            new_frame.is_constructor = is_constructor;

            if op.result_type != OperandType::Unused && !is_constructor {
                new_frame.return_dest = Some((op.result_type, op.result.val));
            }

            // Set up $this write-back for methods and constructors
            if let Some(src) = this_source {
                new_frame.this_write_back = Some(src);
            }

            // Bind parameters to CVs directly (for functions without RECV opcodes)
            let num_params = func_oa.arg_info.len();
            for i in 0..num_params {
                if i >= new_frame.cvs.len() {
                    break;
                }
                // For variadic params, collect remaining args into an array
                if func_oa.arg_info[i].is_variadic {
                    let mut arr = PhpArray::new();
                    for j in i..new_frame.args.len() {
                        arr.push(new_frame.args[j].clone());
                    }
                    new_frame.cvs[i] = Value::Array(arr);
                    break;
                }
                let is_provided = if let Some(ref provided) = new_frame.named_arg_provided {
                    *provided.get(i).unwrap_or(&false)
                } else {
                    i < new_frame.args.len()
                };
                if is_provided && i < new_frame.args.len() {
                    // Type check the parameter
                    if let Some(ref type_name) = func_oa.arg_info[i].type_name {
                        let val = &new_frame.args[i];
                        let derefed = val.deref_value();
                        if !self.value_matches_type(&derefed, type_name) {
                            // In strict mode, do NOT attempt coercion — reject immediately
                            let caller_is_strict = self.op_arrays[caller_oa_idx].strict_types;
                            let coerced = if caller_is_strict {
                                None
                            } else {
                                self.try_coerce_param(&derefed, type_name)
                            };
                            if let Some(coerced_val) = coerced {
                                new_frame.args[i] = coerced_val;
                            } else {
                                let fn_name =
                                    func_oa.function_name.as_deref().unwrap_or(&func_name);
                                let param_name = &func_oa.arg_info[i].name;
                                let actual = self.get_value_type_name(&derefed);
                                return Err(VmError::TypeError(format!(
                                    "{}(): Argument #{} ({}) must be of type {}, {} given",
                                    fn_name,
                                    i + 1,
                                    param_name,
                                    type_name,
                                    actual
                                )));
                            }
                        }
                    }
                    new_frame.cvs[i] = new_frame.args[i].clone();
                } else if let Some(ref default) = func_oa.arg_info[i].default {
                    // Apply default value from arg_info
                    new_frame.cvs[i] = match default {
                        Literal::Null => Value::Null,
                        Literal::Bool(b) => Value::Bool(*b),
                        Literal::Long(n) => Value::Long(*n),
                        Literal::Double(f) => Value::Double(*f),
                        Literal::String(s) if s == "__EMPTY_ARRAY__" => {
                            Value::Array(PhpArray::new())
                        }
                        Literal::String(s) => Value::String(s.clone()),
                        Literal::ClassConst(class_ref, const_name) => {
                            // Resolve class constant at runtime
                            let class_name = match class_ref.as_str() {
                                "self" | "static" | "parent" => {
                                    // Extract class from method name (Class::method)
                                    func_name
                                        .rsplit("::")
                                        .nth(1)
                                        .map(|s| {
                                            if class_ref == "parent" {
                                                // Look up parent class
                                                self.classes
                                                    .get(s)
                                                    .and_then(|c| c.parent.clone())
                                                    .unwrap_or_else(|| s.to_string())
                                            } else {
                                                s.to_string()
                                            }
                                        })
                                        .unwrap_or_else(|| class_ref.clone())
                                }
                                _ => class_ref.clone(),
                            };
                            self.resolve_class_constant(&class_name, const_name)
                                .unwrap_or(Value::Null)
                        }
                        Literal::LongJumpTable(_) | Literal::StringJumpTable(_) => Value::Null,
                    };
                }
            }

            // Set up pass-by-reference write-back
            // Set up true reference semantics for pass-by-reference params.
            // Create shared Value::Reference wrappers between caller and callee.
            for &(arg_idx, caller_op_type, caller_slot) in &ref_args {
                let effective_idx = if has_this_in_args && arg_idx > 0 {
                    arg_idx - 1
                } else {
                    arg_idx
                };
                if effective_idx < func_oa.arg_info.len()
                    && func_oa.arg_info[effective_idx].pass_by_reference
                {
                    let param_name = &func_oa.arg_info[effective_idx].name;
                    if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == param_name) {
                        let current_val = new_frame.cvs[cv_idx].clone();
                        // If already a Reference, share the same Rc (don't re-wrap)
                        let ref_val = if let Value::Reference(_) = &current_val {
                            current_val
                        } else {
                            // Create a new shared reference cell
                            Value::Reference(Rc::new(RefCell::new(current_val)))
                        };
                        // Store in callee's CV
                        new_frame.cvs[cv_idx] = ref_val.clone();
                        // Store back in caller's slot
                        if let Some(caller) = self.call_stack.last_mut() {
                            Self::write_to_slot(caller, caller_op_type, caller_slot, ref_val);
                        }
                    }
                }
            }

            // Set up true reference semantics for property-level pass-by-reference params.
            for (arg_idx, obj_val, prop_name) in &ref_prop_args {
                let effective_idx = if has_this_in_args && *arg_idx > 0 {
                    arg_idx - 1
                } else {
                    *arg_idx
                };
                if effective_idx < func_oa.arg_info.len()
                    && func_oa.arg_info[effective_idx].pass_by_reference
                {
                    let param_name = &func_oa.arg_info[effective_idx].name;
                    if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == param_name) {
                        let current_val = new_frame.cvs[cv_idx].clone();
                        // If already a Reference, share the same Rc (don't re-wrap)
                        let ref_val = if let Value::Reference(_) = &current_val {
                            current_val
                        } else {
                            Value::Reference(Rc::new(RefCell::new(current_val)))
                        };
                        // Store in callee's CV
                        new_frame.cvs[cv_idx] = ref_val.clone();
                        // Store back in caller's object property
                        if let Value::Object(ref obj) = obj_val {
                            obj.set_property(prop_name.clone(), ref_val);
                        }
                    }
                }
            }

            // Apply closure bindings (captured `use` variables)
            if let Some(bindings) = self.closure_bindings.get(&func_name) {
                for (var_name, val) in bindings {
                    if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == var_name) {
                        if cv_idx < new_frame.cvs.len() {
                            new_frame.cvs[cv_idx] = val.clone();
                        }
                    }
                }
            }

            // Apply declaring class scope for closures (so static:: resolves correctly)
            if new_frame.static_class.is_none() {
                if let Some(scope) = self.closure_scopes.get(&func_name) {
                    new_frame.static_class = Some(scope.clone());
                }
            }

            self.call_stack.push(new_frame);
            return Ok(DispatchSignal::CallPushed);
        }

        // For method calls, try class-specific method handlers first, then fall back
        if func_name.contains("::") {
            // Handle built-in class methods (SPL, DateTime, etc.) — must come before
            // call_builtin(simple_name) to avoid e.g. current() matching the array function
            if let Some(result) = self.call_builtin_method(&func_name, &args)? {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }

            // Handle Exception/Error base methods (getMessage, getCode, etc.)
            if let Some(result) = Self::try_exception_method(&func_name, &args) {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }

            // Fall back to non-prefixed builtin function (e.g. namespace-qualified calls)
            if let Some(result) =
                self.call_builtin(simple_name, &args, &ref_args, &ref_prop_args)?
            {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }

            // Try __callStatic / __call magic methods
            if let Some(sep) = func_name.find("::") {
                let class_part = &func_name[..sep];
                let method_part = &func_name[sep + 2..];

                // Determine if this is a static call or instance call
                let has_this = args
                    .first()
                    .map(|a| matches!(a, Value::Object(_)))
                    .unwrap_or(false);

                if has_this {
                    // Instance __call: $obj->method() where method doesn't exist
                    let magic_name = format!("{}::__call", class_part);
                    if let Some(oa_idx) = self
                        .functions
                        .get(&magic_name)
                        .copied()
                        .or_else(|| self.resolve_method(class_part, "__call"))
                    {
                        // Build args: $this, method_name, args_array
                        let this_val = args[0].clone();
                        let remaining_args: Vec<Value> = args[1..].to_vec();
                        let mut args_arr = PhpArray::new();
                        for a in &remaining_args {
                            args_arr.push(a.clone());
                        }

                        self.call_stack.last_mut().unwrap().ip += 1;
                        let func_oa = &self.op_arrays[oa_idx];
                        let mut new_frame = Frame::new(func_oa);
                        new_frame.op_array_idx = oa_idx;
                        self.populate_superglobals(&mut new_frame, func_oa);
                        new_frame.static_class = Some(class_part.to_string());
                        new_frame.args = vec![
                            Value::String(method_part.to_string()),
                            Value::Array(args_arr),
                        ];
                        // Bind $this
                        if let Some(this_idx) = func_oa.vars.iter().position(|v| v == "this") {
                            if this_idx < new_frame.cvs.len() {
                                new_frame.cvs[this_idx] = this_val;
                            }
                        }
                        // Bind params
                        for i in 0..func_oa.arg_info.len().min(new_frame.args.len()) {
                            if i < new_frame.cvs.len() {
                                new_frame.cvs[i] = new_frame.args[i].clone();
                            }
                        }
                        if op.result_type != OperandType::Unused {
                            new_frame.return_dest = Some((op.result_type, op.result.val));
                        }
                        self.call_stack.push(new_frame);
                        return Ok(DispatchSignal::CallPushed);
                    }
                }

                // Static __callStatic
                let magic_name = format!("{}::__callStatic", class_part);
                if let Some(oa_idx) = self
                    .functions
                    .get(&magic_name)
                    .copied()
                    .or_else(|| self.resolve_method(class_part, "__callStatic"))
                {
                    // Remove $this from args if present (static calls)
                    let actual_args = if has_this { &args[1..] } else { &args[..] };
                    let mut args_arr = PhpArray::new();
                    for a in actual_args {
                        args_arr.push(a.clone());
                    }

                    self.call_stack.last_mut().unwrap().ip += 1;
                    let func_oa = &self.op_arrays[oa_idx];
                    let mut new_frame = Frame::new(func_oa);
                    new_frame.op_array_idx = oa_idx;
                    self.populate_superglobals(&mut new_frame, func_oa);
                    new_frame.static_class = Some(class_part.to_string());
                    new_frame.args = vec![
                        Value::String(method_part.to_string()),
                        Value::Array(args_arr),
                    ];
                    // Bind params
                    for i in 0..func_oa.arg_info.len().min(new_frame.args.len()) {
                        if i < new_frame.cvs.len() {
                            new_frame.cvs[i] = new_frame.args[i].clone();
                        }
                    }
                    if op.result_type != OperandType::Unused {
                        new_frame.return_dest = Some((op.result_type, op.result.val));
                    }
                    self.call_stack.push(new_frame);
                    return Ok(DispatchSignal::CallPushed);
                }
            }
        }

        Err(VmError::UndefinedFunction(func_name))
    }
}
