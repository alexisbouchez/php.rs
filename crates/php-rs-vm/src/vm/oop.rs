//! OOP opcode handlers — extracted from vm.rs.
//!
//! Class declaration, object creation, property access, method calls,
//! instanceof, interface checks, class constants.

use std::collections::{HashMap, HashSet};

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, TraitAdaptationInfo, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;

use super::helpers::*;
use super::{
    ClassDef, DispatchSignal, Frame, PendingCall, Vm, VmError, VmResult, ACC_FINAL, ACC_PRIVATE,
    ACC_PRIVATE_SET, ACC_PROTECTED, ACC_PROTECTED_SET, ACC_READONLY,
};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    /// Extract the closure function name from a Value.
    /// Handles both Closure objects (new style) and plain strings (legacy).
    pub(crate) fn extract_closure_name(val: &Value) -> String {
        match val {
            Value::Object(o) if o.class_name() == "Closure" => o
                .get_property("__closure_name")
                .map(|v| v.to_php_string())
                .unwrap_or_default(),
            other => other.to_php_string(),
        }
    }

    /// Convert a MySQL value from a row to a PHP Value (static version).
    #[cfg(feature = "native-io")]
    pub(crate) fn mysqli_value_to_php_value_static(row: &mysql::Row, index: usize) -> Value {
        use mysql::prelude::FromValue;

        let mysql_val = match row.as_ref(index) {
            Some(val) => val,
            None => return Value::Null,
        };

        // Try different types in order
        if let Ok(s) = String::from_value_opt(mysql_val.clone()) {
            return Value::String(s);
        }
        if let Ok(i) = i64::from_value_opt(mysql_val.clone()) {
            return Value::Long(i);
        }
        if let Ok(f) = f64::from_value_opt(mysql_val.clone()) {
            return Value::Double(f);
        }
        if let Ok(bytes) = Vec::<u8>::from_value_opt(mysql_val.clone()) {
            // Convert bytes to string
            return Value::String(String::from_utf8_lossy(&bytes).to_string());
        }

        Value::Null
    }

    /// Resolve "self", "parent", "static" to the actual class name.
    /// Returns the original name if not a special keyword or can't be resolved.
    pub(crate) fn resolve_class_name(&self, name: &str) -> String {
        match name {
            "static" => {
                // Late static binding: resolve to the actual runtime class
                // Walk the call stack to find the most recent class context
                for frame in self.call_stack.iter().rev() {
                    // 1. Check frame's static_class (set by InitStaticMethodCall / InitMethodCall)
                    if let Some(ref sc) = frame.static_class {
                        return sc.clone();
                    }
                    // 2. Check $this object's class name (for instance methods)
                    let oa = &self.op_arrays[frame.op_array_idx];
                    if let Some(this_idx) = oa.vars.iter().position(|v| v == "this") {
                        if this_idx < frame.cvs.len() {
                            if let Value::Object(ref obj) = frame.cvs[this_idx] {
                                return obj.class_name().to_string();
                            }
                        }
                    }
                    // 3. Fall back to op_array's function name (skip closures)
                    if let Some(ref func_name) = oa.function_name {
                        if func_name.contains("::") && !func_name.contains("{closure}") {
                            if let Some(class) = func_name.split("::").next() {
                                return class.to_string();
                            }
                        }
                    }
                }
                name.to_string()
            }
            "self" => {
                // self:: resolves to the class where the method is lexically defined
                // (compile-time binding). Use the op_array's function_name which contains
                // the defining class. Do NOT use static_class or $this (those give runtime class).
                for frame in self.call_stack.iter().rev() {
                    let oa = &self.op_arrays[frame.op_array_idx];
                    if let Some(ref func_name) = oa.function_name {
                        if func_name.contains("::") && !func_name.contains("{closure}") {
                            if let Some(class) = func_name.split("::").next() {
                                return class.to_string();
                            }
                        }
                    }
                }
                name.to_string()
            }
            "parent" => {
                // Find the parent of the class where the code is lexically defined.
                // Priority:
                // 1. Use op_array's function_name to get the defining class
                // 2. If defining class has no parent (e.g. it's a trait), use called_as
                //    (the actual class::method name used to invoke the function)
                // 3. Fall back to static_class or $this
                if let Some(frame) = self.call_stack.last() {
                    let oa = &self.op_arrays[frame.op_array_idx];
                    let defining_class = oa.function_name.as_ref().and_then(|f| {
                        if f.contains("::") && !f.contains("{closure}") {
                            f.split("::").next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    });

                    // First try the defining class (works for normal methods)
                    if let Some(ref dc) = defining_class {
                        if let Some(class_def) = self.classes.get(dc) {
                            if let Some(ref parent) = class_def.parent {
                                return parent.clone();
                            }
                        }
                    }

                    // Defining class has no parent (trait or interface).
                    // Use called_as to find the actual class using this method.
                    if let Some(ref called) = frame.called_as {
                        if let Some(sep) = called.find("::") {
                            let called_class = &called[..sep];
                            if let Some(class_def) = self.classes.get(called_class) {
                                if let Some(ref parent) = class_def.parent {
                                    return parent.clone();
                                }
                            }
                        }
                    }

                    // Final fallback: try static_class, then $this
                    if let Some(ref sc) = frame.static_class {
                        if let Some(class_def) = self.classes.get(sc) {
                            if let Some(ref parent) = class_def.parent {
                                return parent.clone();
                            }
                        }
                    }
                    if let Some(this_idx) = oa.vars.iter().position(|v| v == "this") {
                        if let Some(Value::Object(ref obj)) = frame.cvs.get(this_idx) {
                            let cls = obj.class_name();
                            if let Some(class_def) = self.classes.get(&cls) {
                                if let Some(ref parent) = class_def.parent {
                                    return parent.clone();
                                }
                            }
                        }
                    }
                }
                name.to_string()
            }
            _ => name.strip_prefix('\\').unwrap_or(name).to_string(),
        }
    }

    /// Get the current class scope by examining the call stack.
    /// Skips closure frames and returns the declaring class of the nearest method frame.
    pub(crate) fn get_current_class_scope(&self) -> Option<String> {
        for frame in self.call_stack.iter().rev() {
            if let Some(ref sc) = frame.static_class {
                return Some(sc.clone());
            }
            let oa = &self.op_arrays[frame.op_array_idx];
            if let Some(this_idx) = oa.vars.iter().position(|v| v == "this") {
                if this_idx < frame.cvs.len() {
                    if let Value::Object(ref obj) = frame.cvs[this_idx] {
                        return Some(obj.class_name().to_string());
                    }
                }
            }
            if let Some(ref func_name) = oa.function_name {
                if func_name.contains("::") && !func_name.contains("{closure}") {
                    if let Some(class) = func_name.split("::").next() {
                        return Some(class.to_string());
                    }
                }
            }
        }
        None
    }

    /// Check property access visibility. Returns Ok(()) if access is allowed,
    /// or Err with a fatal error if not.
    pub(crate) fn check_property_access(&self, obj_class: &str, prop_name: &str) -> VmResult<()> {
        // Find the declaring class and its property flags
        let mut search = obj_class.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(&pflags) = class_def.property_flags.get(prop_name) {
                    let calling_scope = self.get_current_class_scope();
                    if pflags & ACC_PRIVATE != 0 {
                        // Private: only accessible from the declaring class
                        if calling_scope.as_deref() != Some(&search) {
                            return Err(VmError::FatalError(format!(
                                "Cannot access private property {}::${}",
                                search, prop_name
                            )));
                        }
                    } else if pflags & ACC_PROTECTED != 0 {
                        // Protected: accessible from declaring class and subclasses
                        match &calling_scope {
                            Some(scope) => {
                                if !self.is_same_or_subclass(scope, &search)
                                    && !self.is_same_or_subclass(&search, scope)
                                {
                                    return Err(VmError::FatalError(format!(
                                        "Cannot access protected property {}::${}",
                                        search, prop_name
                                    )));
                                }
                            }
                            None => {
                                return Err(VmError::FatalError(format!(
                                    "Cannot access protected property {}::${}",
                                    search, prop_name
                                )));
                            }
                        }
                    }
                    return Ok(());
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(()) // Property not declared in class hierarchy → dynamic property, allow
    }

    /// Check asymmetric set-visibility (PHP 8.4 `private(set)` / `protected(set)`).
    ///
    /// This is called on **write** paths only. The read-visibility is separately
    /// enforced by `check_property_access`. Returns `Ok(())` when the write is
    /// allowed, or a fatal error otherwise.
    fn check_property_set_access(&self, obj_class: &str, prop_name: &str) -> VmResult<()> {
        // Walk the class hierarchy to find the declaring class and its flags.
        let mut search = obj_class.to_string();
        let declaring_class;
        let pflags;
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(&flags) = class_def.property_flags.get(prop_name) {
                    declaring_class = search.clone();
                    pflags = flags;
                    break;
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    // Property not declared — dynamic property, no restriction
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        // Only check if one of the asymmetric set-visibility flags is present.
        if pflags & ACC_PRIVATE_SET != 0 {
            // private(set): only the declaring class may write
            let calling_scope = self.get_current_class_scope();
            if calling_scope.as_deref() != Some(declaring_class.as_str()) {
                return Err(VmError::FatalError(format!(
                    "Cannot modify private(set) property {}::${} from {}",
                    declaring_class,
                    prop_name,
                    calling_scope
                        .as_deref()
                        .unwrap_or("outside of class hierarchy")
                )));
            }
        } else if pflags & ACC_PROTECTED_SET != 0 {
            // protected(set): the declaring class and its subclasses may write
            let calling_scope = self.get_current_class_scope();
            let allowed = match &calling_scope {
                Some(scope) => {
                    self.is_same_or_subclass(scope, &declaring_class)
                        || self.is_same_or_subclass(&declaring_class, scope)
                }
                None => false,
            };
            if !allowed {
                return Err(VmError::FatalError(format!(
                    "Cannot modify protected(set) property {}::${} from {}",
                    declaring_class,
                    prop_name,
                    calling_scope
                        .as_deref()
                        .unwrap_or("outside of class hierarchy")
                )));
            }
        }
        // ACC_PUBLIC_SET (0x1000) imposes no restrictions beyond the read visibility.
        Ok(())
    }

    /// Get property flags for a class, walking the hierarchy.
    fn get_property_flags(&self, class_name: &str, prop_name: &str) -> Option<u32> {
        let mut search = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(&flags) = class_def.property_flags.get(prop_name) {
                    return Some(flags);
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    }

    /// Get the declared type of a property, walking the parent chain.
    fn get_property_type(&self, class_name: &str, prop_name: &str) -> Option<String> {
        let mut search = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(ptype) = class_def.property_types.get(prop_name) {
                    return Some(ptype.clone());
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    }

    /// Find a property get hook op_array index, walking the class hierarchy.
    pub(crate) fn find_property_get_hook(
        &self,
        class_name: &str,
        prop_name: &str,
    ) -> Option<&usize> {
        let mut search = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(idx) = class_def.property_get_hooks.get(prop_name) {
                    return Some(idx);
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    }

    /// Find a property set hook op_array index, walking the class hierarchy.
    pub(crate) fn find_property_set_hook(
        &self,
        class_name: &str,
        prop_name: &str,
    ) -> Option<&usize> {
        let mut search = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(idx) = class_def.property_set_hooks.get(prop_name) {
                    return Some(idx);
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    }

    /// Call a property hook function (get or set). Returns the hook's return value.
    fn call_property_hook(
        &mut self,
        hook_oa_idx: usize,
        this_obj: Value,
        args: Vec<Value>,
    ) -> VmResult<Value> {
        let saved_depth = self.call_stack.len();
        let func_oa = &self.op_arrays[hook_oa_idx];
        let mut frame = Frame::new(func_oa);
        frame.op_array_idx = hook_oa_idx;

        // Set $this (CV 0)
        if let Some(this_idx) = func_oa.vars.iter().position(|v| v == "this") {
            if this_idx < frame.cvs.len() {
                frame.cvs[this_idx] = this_obj;
            }
        }

        // Set hook parameters ($value for set hooks)
        frame.args = args.clone();
        let num_params = func_oa.arg_info.len().min(args.len());
        for i in 0..num_params {
            // Parameters start after $this in CVs
            let cv_name = &func_oa.arg_info[i].name;
            if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == cv_name) {
                if cv_idx < frame.cvs.len() {
                    frame.cvs[cv_idx] = args[i].clone();
                }
            }
        }

        self.call_stack.push(frame);
        let result = self.dispatch_loop_until(saved_depth);
        if let Err(e) = result {
            while self.call_stack.len() > saved_depth {
                self.call_stack.pop();
            }
            return Err(e);
        }

        Ok(self.last_return_value.clone())
    }

    /// Check if `child` is the same as or a subclass of `parent`.
    fn is_same_or_subclass(&self, child: &str, parent: &str) -> bool {
        let mut current = child.to_string();
        loop {
            if current == parent {
                return true;
            }
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref p) = class_def.parent {
                    current = p.clone();
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /// Check method access visibility. Returns Ok(()) if access is allowed.
    pub(crate) fn check_method_access(&self, class_name: &str, method_name: &str) -> VmResult<()> {
        // Walk the class hierarchy to find method flags
        let mut search = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&search) {
                if let Some(&mflags) = class_def.method_flags.get(method_name) {
                    let calling_scope = self.get_current_class_scope();
                    if mflags & ACC_PRIVATE != 0 {
                        if calling_scope.as_deref() != Some(&search) {
                            return Err(VmError::FatalError(format!(
                                "Call to private method {}::{}() from scope {}",
                                search,
                                method_name,
                                calling_scope.as_deref().unwrap_or("global")
                            )));
                        }
                    } else if mflags & ACC_PROTECTED != 0 {
                        match &calling_scope {
                            Some(scope) => {
                                if !self.is_same_or_subclass(scope, &search)
                                    && !self.is_same_or_subclass(&search, scope)
                                {
                                    return Err(VmError::FatalError(format!(
                                        "Call to protected method {}::{}() from scope {}",
                                        search, method_name, scope
                                    )));
                                }
                            }
                            None => {
                                return Err(VmError::FatalError(format!(
                                    "Call to protected method {}::{}() from global scope",
                                    search, method_name
                                )));
                            }
                        }
                    }
                    return Ok(());
                }
                if let Some(ref parent) = class_def.parent {
                    search = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(()) // Method not found in flags → assume public
    }

    /// Resolve a method by walking the parent chain.
    /// Returns the op_array index if found.
    pub(crate) fn resolve_method(&self, class_name: &str, method_name: &str) -> Option<usize> {
        let mut current = class_name.to_string();
        loop {
            let full_name = format!("{}::{}", current, method_name);
            if let Some(&oa_idx) = self.functions.get(&full_name) {
                return Some(oa_idx);
            }
            // Walk to parent
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref parent) = class_def.parent {
                    current = parent.clone();
                    continue;
                }
            }
            break;
        }
        None
    }

    /// Check if a class has a method (including inherited from parent classes).
    pub(crate) fn has_method(&self, class_name: &str, method_name: &str) -> bool {
        self.resolve_method(class_name, method_name).is_some()
    }

    /// Handle DECLARE_CLASS — register a class in the class table.
    pub(crate) fn handle_declare_class(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let name = self.read_operand(op, 1, oa_idx)?.to_php_string();

        // Parse parent/interfaces from op2: "parent\0iface1\0iface2\x01attr..."
        let class_info = if op.op2_type != OperandType::Unused {
            self.read_operand(op, 2, oa_idx)?.to_php_string()
        } else {
            String::new()
        };
        // Split off attributes (separated by \x01)
        let mut attr_sections: Vec<&str> = class_info.split('\x01').collect();
        let base_info = attr_sections.remove(0); // parent\0iface1\0iface2

        // Parse class attributes
        let mut class_attributes = Vec::new();
        for attr_section in &attr_sections {
            if attr_section.is_empty() {
                continue;
            }
            let mut attr_parts: Vec<&str> = attr_section.split('\x02').collect();
            let attr_name = attr_parts.remove(0).to_string();
            let mut args = Vec::new();
            for arg_str in attr_parts {
                if let Some((k, v)) = arg_str.split_once('=') {
                    args.push((Some(k.to_string()), v.to_string()));
                } else {
                    args.push((None, arg_str.to_string()));
                }
            }
            class_attributes.push((attr_name, args));
        }

        let mut parts: Vec<&str> = base_info.split('\0').collect();
        let parent = if !parts.is_empty() && !parts[0].is_empty() {
            Some(parts.remove(0).to_string())
        } else {
            if !parts.is_empty() {
                parts.remove(0);
            }
            None
        };
        let interfaces: Vec<String> = parts
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let flags = op.extended_value;
        let mut class_def = ClassDef {
            _name: name.clone(),
            parent,
            interfaces,
            traits: Vec::new(),
            is_abstract: flags & 0x20 != 0,
            is_final: flags & ACC_FINAL != 0,
            is_interface: flags & 0x40 != 0,
            is_enum: flags & 0x100 != 0,
            is_readonly: flags & ACC_READONLY != 0,
            methods: HashMap::new(),
            method_flags: HashMap::new(),
            property_flags: HashMap::new(),
            default_properties: HashMap::new(),
            class_constants: HashMap::new(),
            class_constant_flags: HashMap::new(),
            static_properties: HashMap::new(),
            property_types: HashMap::new(),
            attributes: class_attributes,
            property_get_hooks: HashMap::new(),
            property_set_hooks: HashMap::new(),
        };

        // Methods and property hooks are stored in dynamic_func_defs
        // Methods: "ClassName::method_name"
        // Hooks: "ClassName::$prop::get" or "ClassName::$prop::set"
        let prefix = format!("{}::", name);
        let defs: Vec<ZOpArray> = self.op_arrays[oa_idx].dynamic_func_defs.clone();
        for def in defs {
            let full_name = match def.function_name {
                Some(ref n) => n.clone(),
                None => continue,
            };
            if let Some(suffix) = full_name.strip_prefix(&prefix) {
                let suffix = suffix.to_string();
                let oa_idx_new = self.op_arrays.len();
                self.op_arrays.push(def);

                // Check if this is a property hook: "$prop::get" or "$prop::set"
                if let Some(prop_rest) = suffix.strip_prefix('$') {
                    if let Some(prop_name) = prop_rest.strip_suffix("::get") {
                        class_def
                            .property_get_hooks
                            .insert(prop_name.to_string(), oa_idx_new);
                        continue;
                    }
                    if let Some(prop_name) = prop_rest.strip_suffix("::set") {
                        class_def
                            .property_set_hooks
                            .insert(prop_name.to_string(), oa_idx_new);
                        continue;
                    }
                }

                // Regular method
                class_def.methods.insert(suffix.clone(), oa_idx_new);
                self.functions
                    .insert(format!("{}::{}", name, suffix), oa_idx_new);
            }
        }

        // Read class metadata (properties, constants, flags) from the op_array
        if let Some(metadata) = self.op_arrays[oa_idx].class_metadata.get(&name).cloned() {
            // Populate method flags
            for (method_name, mflags) in &metadata.method_flags {
                class_def.method_flags.insert(method_name.clone(), *mflags);
            }
            for prop_info in &metadata.properties {
                let default_val = match &prop_info.default {
                    Some(Literal::String(s)) if s == "__EMPTY_ARRAY__" => {
                        Value::Array(PhpArray::new())
                    }
                    Some(Literal::Null) => Value::Null,
                    Some(Literal::Bool(b)) => Value::Bool(*b),
                    Some(Literal::Long(n)) => Value::Long(*n),
                    Some(Literal::Double(f)) => Value::Double(*f),
                    Some(Literal::String(s)) => Value::String(s.clone()),
                    Some(Literal::ClassConst(class_ref, const_name)) => {
                        let resolved_class = if class_ref == "self" || class_ref == "static" {
                            name.clone()
                        } else {
                            class_ref.clone()
                        };
                        self.resolve_class_constant(&resolved_class, const_name)
                            .unwrap_or(Value::Null)
                    }
                    Some(Literal::LongJumpTable(_)) | Some(Literal::StringJumpTable(_)) => {
                        Value::Null
                    }
                    None => Value::Null,
                };
                // Store property modifier flags
                class_def
                    .property_flags
                    .insert(prop_info.name.clone(), prop_info.flags);
                // Store property type hint
                if let Some(ref type_name) = prop_info.type_name {
                    class_def
                        .property_types
                        .insert(prop_info.name.clone(), type_name.clone());
                }
                if prop_info.is_static {
                    class_def
                        .static_properties
                        .insert(prop_info.name.clone(), default_val);
                } else {
                    class_def
                        .default_properties
                        .insert(prop_info.name.clone(), default_val);
                }
            }
            for (const_name, lit) in &metadata.constants {
                let val = match lit {
                    Literal::Null => Value::Null,
                    Literal::Bool(b) => Value::Bool(*b),
                    Literal::Long(n) => Value::Long(*n),
                    Literal::Double(f) => Value::Double(*f),
                    Literal::String(s) if s == "__EMPTY_ARRAY__" => Value::Array(PhpArray::new()),
                    Literal::String(s) => Value::String(s.clone()),
                    Literal::ClassConst(class_ref, cname) => {
                        let resolved_class = if class_ref == "self" || class_ref == "static" {
                            name.clone()
                        } else {
                            class_ref.clone()
                        };
                        self.resolve_class_constant(&resolved_class, cname)
                            .unwrap_or(Value::Null)
                    }
                    Literal::LongJumpTable(_) | Literal::StringJumpTable(_) => Value::Null,
                };
                class_def.class_constants.insert(const_name.clone(), val);
            }
        }

        // Inherit from parent class (methods, constants, properties)
        if let Some(ref parent_name) = class_def.parent.clone() {
            // Try autoloading the parent if not already loaded
            if !self.classes.contains_key(parent_name) {
                self.try_autoload_class(parent_name);
            }
            if let Some(parent_def) = self.classes.get(parent_name).cloned() {
                // Copy parent methods that aren't overridden
                for (method_name, &oa_idx) in &parent_def.methods {
                    if !class_def.methods.contains_key(method_name) {
                        class_def.methods.insert(method_name.clone(), oa_idx);
                        // Also register in global functions table
                        let full_name = format!("{}::{}", name, method_name);
                        self.functions.insert(full_name, oa_idx);
                    }
                }
                // Copy parent method flags that aren't overridden
                for (method_name, &mflags) in &parent_def.method_flags {
                    if !class_def.method_flags.contains_key(method_name) {
                        class_def.method_flags.insert(method_name.clone(), mflags);
                    }
                }
                // Copy parent constants that aren't overridden
                for (const_name, val) in &parent_def.class_constants {
                    if !class_def.class_constants.contains_key(const_name) {
                        class_def
                            .class_constants
                            .insert(const_name.clone(), val.clone());
                    }
                }
                // Copy parent constant flags
                for (const_name, &cflags) in &parent_def.class_constant_flags {
                    if !class_def.class_constant_flags.contains_key(const_name) {
                        class_def
                            .class_constant_flags
                            .insert(const_name.clone(), cflags);
                    }
                }
                // Copy parent default properties that aren't overridden
                for (prop_name, val) in &parent_def.default_properties {
                    if !class_def.default_properties.contains_key(prop_name) {
                        class_def
                            .default_properties
                            .insert(prop_name.clone(), val.clone());
                    }
                }
                // Copy parent property flags that aren't overridden
                for (prop_name, &pflags) in &parent_def.property_flags {
                    if !class_def.property_flags.contains_key(prop_name) {
                        class_def.property_flags.insert(prop_name.clone(), pflags);
                    }
                }
                // Copy parent property types that aren't overridden
                for (prop_name, ptype) in &parent_def.property_types {
                    if !class_def.property_types.contains_key(prop_name) {
                        class_def
                            .property_types
                            .insert(prop_name.clone(), ptype.clone());
                    }
                }
                // NOTE: Do NOT copy parent static properties — they are shared
                // with the parent class in PHP (unless redeclared in the child).
                // The read path (handle_fetch_static_prop) and write path
                // (AssignStaticProp) walk the parent chain to find the declaring class.
            }
        }

        // Mix in traits (with adaptation support)
        if let Some(metadata) = self.op_arrays[oa_idx].class_metadata.get(&name).cloned() {
            let adaptations = metadata.trait_adaptations.clone();

            // Build precedence map: method_name → set of excluded trait names
            let mut precedence_excludes: HashMap<String, HashSet<String>> = HashMap::new();
            for adaptation in &adaptations {
                if let TraitAdaptationInfo::Precedence {
                    method, insteadof, ..
                } = adaptation
                {
                    let entry = precedence_excludes
                        .entry(method.clone())
                        .or_insert_with(HashSet::new);
                    for excluded in insteadof {
                        entry.insert(excluded.clone());
                    }
                }
            }

            // Track which methods are explicitly defined by the class itself
            let class_own_methods: HashSet<String> = class_def.methods.keys().cloned().collect();

            // Track which methods came from which trait (for conflict detection)
            let mut trait_method_sources: HashMap<String, Vec<(String, usize)>> = HashMap::new();

            for trait_name in &metadata.traits {
                class_def.traits.push(trait_name.clone());
                if !self.classes.contains_key(trait_name) {
                    self.try_autoload_class(trait_name);
                }
                if let Some(trait_def) = self.classes.get(trait_name).cloned() {
                    // Copy trait methods that aren't already defined by the class
                    for (method_name, &trait_oa_idx) in &trait_def.methods {
                        // Check precedence exclusions
                        if let Some(excluded) = precedence_excludes.get(method_name) {
                            if excluded.contains(trait_name) {
                                continue; // This trait's method is excluded by insteadof
                            }
                        }

                        // Track this trait's contribution
                        trait_method_sources
                            .entry(method_name.clone())
                            .or_default()
                            .push((trait_name.clone(), trait_oa_idx));

                        // Class-defined methods always take priority
                        if class_own_methods.contains(method_name) {
                            continue;
                        }

                        // First trait to provide this method wins
                        if !class_def.methods.contains_key(method_name) {
                            class_def.methods.insert(method_name.clone(), trait_oa_idx);
                            let full_name = format!("{}::{}", name, method_name);
                            self.functions.insert(full_name, trait_oa_idx);
                        }
                    }
                    // Copy trait method flags
                    for (method_name, &mflags) in &trait_def.method_flags {
                        if let Some(excluded) = precedence_excludes.get(method_name) {
                            if excluded.contains(trait_name) {
                                continue;
                            }
                        }
                        if !class_def.method_flags.contains_key(method_name) {
                            class_def.method_flags.insert(method_name.clone(), mflags);
                        }
                    }
                    // Copy trait property flags
                    for (prop_name, &pflags) in &trait_def.property_flags {
                        if !class_def.property_flags.contains_key(prop_name) {
                            class_def.property_flags.insert(prop_name.clone(), pflags);
                        }
                    }
                    // Copy trait default properties (with conflict check)
                    for (prop_name, val) in &trait_def.default_properties {
                        if !class_def.default_properties.contains_key(prop_name) {
                            class_def
                                .default_properties
                                .insert(prop_name.clone(), val.clone());
                        }
                    }
                    // Copy trait property types
                    for (prop_name, ptype) in &trait_def.property_types {
                        if !class_def.property_types.contains_key(prop_name) {
                            class_def
                                .property_types
                                .insert(prop_name.clone(), ptype.clone());
                        }
                    }
                    // Copy trait constants that aren't overridden
                    for (const_name, val) in &trait_def.class_constants {
                        if const_name != "class"
                            && !class_def.class_constants.contains_key(const_name)
                        {
                            class_def
                                .class_constants
                                .insert(const_name.clone(), val.clone());
                        }
                    }
                    // Copy trait static properties
                    for (prop_name, val) in &trait_def.static_properties {
                        if !class_def.static_properties.contains_key(prop_name) {
                            class_def
                                .static_properties
                                .insert(prop_name.clone(), val.clone());
                        }
                    }
                }
            }

            // Detect unresolved trait method conflicts (only for non-trait classes)
            if flags & 0x80 == 0 {
                for (method_name, sources) in &trait_method_sources {
                    // Multiple traits provide same method AND class didn't define it itself
                    if sources.len() > 1 && !class_own_methods.contains(method_name) {
                        let trait_names: Vec<&str> =
                            sources.iter().map(|(t, _)| t.as_str()).collect();
                        return Err(VmError::FatalError(format!(
                            "Trait method {} has not been applied as {}::{}, because of collision with {}",
                            method_name,
                            trait_names[0],
                            method_name,
                            trait_names[1..].join(", ")
                        )));
                    }
                }
            }

            // Apply trait aliases (as keyword)
            for adaptation in &adaptations {
                if let TraitAdaptationInfo::Alias {
                    trait_name: alias_trait,
                    method,
                    alias,
                    visibility,
                } = adaptation
                {
                    // Find the method's op_array index
                    let method_oa = if let Some(ref tn) = alias_trait {
                        // Specific trait::method
                        self.classes
                            .get(tn)
                            .and_then(|td| td.methods.get(method).copied())
                    } else {
                        // Unqualified — look in current class
                        class_def.methods.get(method).copied()
                    };

                    if let Some(oa_idx) = method_oa {
                        if let Some(ref new_name) = alias {
                            // Add alias method
                            class_def.methods.insert(new_name.clone(), oa_idx);
                            let full_name = format!("{}::{}", name, new_name);
                            self.functions.insert(full_name, oa_idx);
                            // Copy method flags with potential visibility override
                            let base_flags =
                                class_def.method_flags.get(method).copied().unwrap_or(0x01); // default public
                            let new_flags = if let Some(vis) = visibility {
                                // Replace visibility bits, keep other flags
                                (base_flags & !0x07) | vis
                            } else {
                                base_flags
                            };
                            class_def.method_flags.insert(new_name.clone(), new_flags);
                        } else if let Some(vis) = visibility {
                            // Just change visibility of existing method
                            if let Some(flags) = class_def.method_flags.get_mut(method) {
                                *flags = (*flags & !0x07) | vis;
                            }
                        }
                    }
                }
            }
        }

        // Also inherit traits from parent class
        if let Some(ref parent_name) = class_def.parent.clone() {
            if let Some(parent_def) = self.classes.get(parent_name).cloned() {
                for trait_name in &parent_def.traits {
                    if !class_def.traits.contains(trait_name) {
                        class_def.traits.push(trait_name.clone());
                    }
                }
            }
        }

        // Add `class` pseudo-constant (ClassName::class)
        class_def
            .class_constants
            .insert("class".to_string(), Value::String(name.clone()));

        // =====================================================================
        // OOP enforcement checks (only for concrete classes, not traits)
        // =====================================================================
        let is_trait = flags & 0x80 != 0;
        if !is_trait {
            // 2F.04: Final class extension prevention
            if let Some(ref parent_name) = class_def.parent {
                if let Some(parent_def) = self.classes.get(parent_name) {
                    if parent_def.is_final {
                        return Err(VmError::FatalError(format!(
                            "Class {} cannot extend final class {}",
                            name, parent_name
                        )));
                    }
                }
            }

            // 2F.03: Final method override prevention
            if let Some(ref parent_name) = class_def.parent.clone() {
                if let Some(parent_def) = self.classes.get(parent_name).cloned() {
                    for (method_name, &parent_flags) in &parent_def.method_flags {
                        if parent_flags & ACC_FINAL != 0 {
                            // Check if the child class explicitly declares this method
                            if let Some(metadata) =
                                self.op_arrays[oa_idx].class_metadata.get(&name).cloned()
                            {
                                if metadata.method_flags.iter().any(|(m, _)| m == method_name) {
                                    return Err(VmError::FatalError(format!(
                                        "Cannot override final method {}::{}()",
                                        parent_name, method_name
                                    )));
                                }
                            }
                        }
                    }
                }
            }

            // 2B.01 & 2B.04: Interface method implementation verification
            if !class_def.is_abstract && !class_def.is_interface {
                for iface_name in &class_def.interfaces.clone() {
                    if let Some(iface_def) = self.classes.get(iface_name).cloned() {
                        for (method_name, &iflags) in &iface_def.method_flags {
                            if !class_def.methods.contains_key(method_name) {
                                return Err(VmError::FatalError(format!(
                                    "Class {} contains 1 abstract method and must therefore be declared abstract or implement the remaining methods ({}::{})",
                                    name, iface_name, method_name
                                )));
                            }
                            // 2B.04: Interface methods must be public in implementing class
                            if let Some(&impl_flags) = class_def.method_flags.get(method_name) {
                                if impl_flags & ACC_PRIVATE != 0 || impl_flags & ACC_PROTECTED != 0
                                {
                                    return Err(VmError::FatalError(format!(
                                        "Access level to {}::{}() must be public (as in interface {})",
                                        name, method_name, iface_name
                                    )));
                                }
                            }
                            // 2B.02: Interface method signature compatibility check
                            if let Some(&iface_oa_idx) = iface_def.methods.get(method_name) {
                                if let Some(&impl_oa_idx) = class_def.methods.get(method_name) {
                                    let iface_oa = &self.op_arrays[iface_oa_idx];
                                    let impl_oa = &self.op_arrays[impl_oa_idx];
                                    let iface_required = iface_oa.required_num_args;
                                    let impl_required = impl_oa.required_num_args;
                                    let iface_total = iface_oa.arg_info.len() as u32;
                                    let impl_total = impl_oa.arg_info.len() as u32;
                                    if impl_required > iface_required {
                                        return Err(VmError::FatalError(format!(
                                            "Declaration of {}::{}() must be compatible with {}::{}()",
                                            name, method_name, iface_name, method_name
                                        )));
                                    }
                                    let impl_has_variadic =
                                        impl_oa.arg_info.iter().any(|a| a.is_variadic);
                                    if !impl_has_variadic && impl_total < iface_total {
                                        return Err(VmError::FatalError(format!(
                                            "Declaration of {}::{}() must be compatible with {}::{}()",
                                            name, method_name, iface_name, method_name
                                        )));
                                    }
                                    // 2F.01: Covariant return type check
                                    if let (Some(ref parent_ret), Some(ref child_ret)) =
                                        (&iface_oa.return_type, &impl_oa.return_type)
                                    {
                                        if !self.is_type_covariant(child_ret, parent_ret) {
                                            return Err(VmError::FatalError(format!(
                                                "Declaration of {}::{}() must be compatible with {}::{}()",
                                                name, method_name, iface_name, method_name
                                            )));
                                        }
                                    }
                                    // 2F.02: Contravariant parameter type check
                                    let check_count =
                                        iface_oa.arg_info.len().min(impl_oa.arg_info.len());
                                    for pi in 0..check_count {
                                        if let (Some(ref parent_pt), Some(ref child_pt)) = (
                                            &iface_oa.arg_info[pi].type_name,
                                            &impl_oa.arg_info[pi].type_name,
                                        ) {
                                            if !self.is_type_contravariant(child_pt, parent_pt) {
                                                return Err(VmError::FatalError(format!(
                                                    "Declaration of {}::{}() must be compatible with {}::{}()",
                                                    name, method_name, iface_name, method_name
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 2B.03: Interface final constant override prevention (PHP 8.1)
            if !class_def.is_interface {
                for iface_name in &class_def.interfaces.clone() {
                    if let Some(iface_def) = self.classes.get(iface_name).cloned() {
                        for (const_name, &cflags) in &iface_def.class_constant_flags {
                            if cflags & ACC_FINAL != 0 {
                                // Check if the implementing class overrides this final constant
                                if let Some(metadata) =
                                    self.op_arrays[oa_idx].class_metadata.get(&name)
                                {
                                    if metadata.constants.iter().any(|(cn, _)| cn == const_name) {
                                        return Err(VmError::FatalError(format!(
                                            "{} cannot override final constant {}::{}",
                                            name, iface_name, const_name
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Inherit interface constants that aren't overridden
            if !class_def.is_interface {
                for iface_name in &class_def.interfaces.clone() {
                    if let Some(iface_def) = self.classes.get(iface_name).cloned() {
                        for (const_name, val) in &iface_def.class_constants {
                            if const_name != "class"
                                && !class_def.class_constants.contains_key(const_name)
                            {
                                class_def
                                    .class_constants
                                    .insert(const_name.clone(), val.clone());
                            }
                        }
                        for (const_name, &cflags) in &iface_def.class_constant_flags {
                            if !class_def.class_constant_flags.contains_key(const_name) {
                                class_def
                                    .class_constant_flags
                                    .insert(const_name.clone(), cflags);
                            }
                        }
                    }
                }
            }

            // 2C.02 & 2C.03: Abstract method implementation verification
            if !class_def.is_abstract && !class_def.is_interface {
                // Check own method flags for unimplemented abstract methods
                // (inherited from parent abstract classes)
                if let Some(ref parent_name) = class_def.parent.clone() {
                    if let Some(parent_def) = self.classes.get(parent_name).cloned() {
                        if parent_def.is_abstract {
                            for (method_name, &pflags) in &parent_def.method_flags {
                                if pflags & 0x20 != 0 {
                                    // ACC_ABSTRACT
                                    if !class_def.methods.contains_key(method_name)
                                        || !self.op_arrays[oa_idx]
                                            .class_metadata
                                            .get(&name)
                                            .map(|m| {
                                                m.method_flags.iter().any(|(m, _)| m == method_name)
                                            })
                                            .unwrap_or(false)
                                    {
                                        return Err(VmError::FatalError(format!(
                                            "Class {} contains 1 abstract method and must therefore be declared abstract or implement the remaining methods ({}::{})",
                                            name, parent_name, method_name
                                        )));
                                    }
                                    // 2C.03: Abstract method signature compatibility
                                    if let Some(&abs_oa_idx) = parent_def.methods.get(method_name) {
                                        if let Some(&impl_oa_idx) =
                                            class_def.methods.get(method_name)
                                        {
                                            let abs_oa = &self.op_arrays[abs_oa_idx];
                                            let impl_oa = &self.op_arrays[impl_oa_idx];
                                            let abs_required = abs_oa.required_num_args;
                                            let impl_required = impl_oa.required_num_args;
                                            let abs_total = abs_oa.arg_info.len() as u32;
                                            let impl_total = impl_oa.arg_info.len() as u32;
                                            if impl_required > abs_required {
                                                return Err(VmError::FatalError(format!(
                                                    "Declaration of {}::{}() must be compatible with {}::{}()",
                                                    name, method_name, parent_name, method_name
                                                )));
                                            }
                                            let impl_has_variadic =
                                                impl_oa.arg_info.iter().any(|a| a.is_variadic);
                                            if !impl_has_variadic && impl_total < abs_total {
                                                return Err(VmError::FatalError(format!(
                                                    "Declaration of {}::{}() must be compatible with {}::{}()",
                                                    name, method_name, parent_name, method_name
                                                )));
                                            }
                                            // 2F.01: Covariant return type check
                                            if let (Some(ref parent_ret), Some(ref child_ret)) =
                                                (&abs_oa.return_type, &impl_oa.return_type)
                                            {
                                                if !self.is_type_covariant(child_ret, parent_ret) {
                                                    return Err(VmError::FatalError(format!(
                                                        "Declaration of {}::{}() must be compatible with {}::{}()",
                                                        name, method_name, parent_name, method_name
                                                    )));
                                                }
                                            }
                                            // 2F.02: Contravariant parameter type check
                                            let check_count =
                                                abs_oa.arg_info.len().min(impl_oa.arg_info.len());
                                            for pi in 0..check_count {
                                                if let (Some(ref parent_pt), Some(ref child_pt)) = (
                                                    &abs_oa.arg_info[pi].type_name,
                                                    &impl_oa.arg_info[pi].type_name,
                                                ) {
                                                    if !self
                                                        .is_type_contravariant(child_pt, parent_pt)
                                                    {
                                                        return Err(VmError::FatalError(format!(
                                                            "Declaration of {}::{}() must be compatible with {}::{}()",
                                                            name, method_name, parent_name, method_name
                                                        )));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 2F.07: Property type compatibility in inheritance
            // Property types must be invariant (exactly the same) when overridden
            if let Some(ref parent_name) = class_def.parent.clone() {
                if let Some(parent_def) = self.classes.get(parent_name).cloned() {
                    for (prop_name, child_type) in &class_def.property_types {
                        if let Some(parent_type) = parent_def.property_types.get(prop_name) {
                            if child_type != parent_type {
                                return Err(VmError::FatalError(format!(
                                    "Type of {}::${} must be {} (as in class {})",
                                    name, prop_name, parent_type, parent_name
                                )));
                            }
                        }
                    }
                }
            }

            // 2A.07: Readonly class enforcement
            // In a readonly class, all declared properties are implicitly readonly.
            // Static properties are not allowed in readonly classes.
            if class_def.is_readonly {
                // Make all properties implicitly readonly
                for (prop_name, pflags) in class_def.property_flags.iter_mut() {
                    *pflags |= ACC_READONLY;
                }
            }
        }

        self.classes.insert(name, class_def);
        Ok(())
    }

    /// Try to autoload a class by calling registered spl_autoload callbacks.
    /// Returns true if the class was successfully loaded.
    pub(crate) fn try_autoload_class(&mut self, class_name: &str) -> bool {
        // Normalize: strip leading backslash
        let class_name = class_name.strip_prefix('\\').unwrap_or(class_name);

        // Already loaded?
        if self.classes.contains_key(class_name) {
            return true;
        }

        // Prevent recursive autoloading of the same class
        if self.autoloading_classes.contains(class_name) {
            return false;
        }

        let callbacks = self.autoload_callbacks.clone();
        if callbacks.is_empty() {
            return false;
        }

        self.autoloading_classes.insert(class_name.to_string());

        for (callback_name, this_obj) in &callbacks {
            let oa_idx_opt = if callback_name.contains("::") {
                // Handle static/instance method calls like "ClassName::methodName"
                let parts: Vec<&str> = callback_name.splitn(2, "::").collect();
                let method_class = parts[0];
                let method_name = parts[1];
                self.classes
                    .get(method_class)
                    .and_then(|c| c.methods.get(method_name).copied())
            } else {
                // Regular function call
                self.functions.get(callback_name).copied()
            };

            if let Some(oa_idx) = oa_idx_opt {
                let oa = self.op_arrays[oa_idx].clone();
                let mut frame = Frame::new(&oa);
                frame.op_array_idx = oa_idx;

                if callback_name.contains("::") {
                    // Method call: first arg is $this, second is class name
                    let this_val = this_obj.clone().unwrap_or(Value::Null);
                    frame.args = vec![this_val.clone(), Value::String(class_name.to_string())];
                    // Set $this CV
                    let this_cv_idx = oa.vars.iter().position(|v| v == "this").unwrap_or(0);
                    if this_cv_idx < frame.cvs.len() {
                        frame.cvs[this_cv_idx] = this_val;
                    }
                    // Set the class name parameter (typically CV after $this)
                    let param_names: Vec<&str> = oa.vars.iter().map(|s| s.as_str()).collect();
                    if let Some(class_param_idx) = param_names.iter().position(|&v| v == "class") {
                        if class_param_idx < frame.cvs.len() {
                            frame.cvs[class_param_idx] = Value::String(class_name.to_string());
                        }
                    } else {
                        // Fallback: put class name in first non-$this CV
                        for i in 0..frame.cvs.len() {
                            if i != this_cv_idx {
                                frame.cvs[i] = Value::String(class_name.to_string());
                                break;
                            }
                        }
                    }
                } else {
                    frame.args = vec![Value::String(class_name.to_string())];
                    // Set first CV to the class name (the $class parameter)
                    if !frame.cvs.is_empty() {
                        frame.cvs[0] = Value::String(class_name.to_string());
                    }
                }

                let depth = self.call_stack.len();
                self.call_stack.push(frame);
                let _ = self.dispatch_loop_until(depth);
                if self.classes.contains_key(class_name) {
                    self.autoloading_classes.remove(class_name);
                    return true;
                }
            }
        }

        self.autoloading_classes.remove(class_name);
        false
    }

    /// Handle NEW — create a new object instance.
    pub(crate) fn handle_new(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let raw_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
        // Strip leading backslash from fully-qualified class names
        let stripped = raw_name.strip_prefix('\\').unwrap_or(&raw_name).to_string();
        // Resolve self/parent/static
        let class_name = self.resolve_class_name(&stripped);

        // Special handling for Fiber
        if class_name == "Fiber" {
            let obj = PhpObject::new("Fiber".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            obj.set_internal(crate::value::InternalState::Fiber);

            let obj_id = obj.object_id();
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val)?;

            // The constructor args contain the callable — save for start()
            // Store a pending call that DO_FCALL will consume
            let frame = self.call_stack.last_mut().unwrap();
            let saved_args = if let Some(pos) = frame
                .call_stack_pending
                .iter()
                .position(|p| p.name == "__ctor_args__")
            {
                frame.call_stack_pending.remove(pos).args
            } else {
                Vec::new()
            };

            // Get the callable name from saved args
            let callback_name = saved_args
                .first()
                .map(|v| v.to_php_string())
                .unwrap_or_default();

            // Create FiberState
            self.fibers.insert(
                obj_id,
                crate::value::FiberState {
                    saved_frames: Vec::new(),
                    status: crate::value::FiberStatus::Init,
                    callback_name,
                    transfer_value: Value::Null,
                    return_value: None,
                    start_depth: 0,
                },
            );

            // Push a dummy pending call for the constructor DO_FCALL
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "__new_noop__".to_string(),
                args: Vec::new(),
                arg_names: Vec::new(),
                this_source: None,
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for ReflectionFunction
        if class_name == "ReflectionFunction" {
            let obj = PhpObject::new("ReflectionFunction".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val.clone())?;
            // Push constructor pending call
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "ReflectionFunction::__construct".to_string(),
                args: vec![obj_val],
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for ReflectionClass / ReflectionObject
        if class_name == "ReflectionClass" || class_name == "ReflectionObject" {
            let obj = PhpObject::new("ReflectionClass".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            obj.set_internal(crate::value::InternalState::ReflectionClass);
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val.clone())?;

            // Push a constructor pending call — SEND_VAL will add the class name arg
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "ReflectionClass::__construct".to_string(),
                args: vec![obj_val],
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for ReflectionMethod
        if class_name == "ReflectionMethod" {
            let obj = PhpObject::new("ReflectionMethod".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val.clone())?;

            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "ReflectionMethod::__construct".to_string(),
                args: vec![obj_val],
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for SQLite3
        if class_name == "SQLite3" {
            let obj = PhpObject::new("SQLite3".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val.clone())?;
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "SQLite3::__construct".to_string(),
                args: vec![obj_val],
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for PDO
        if class_name == "PDO" {
            let obj = PhpObject::new("PDO".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val.clone())?;

            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "PDO::__construct".to_string(),
                args: vec![obj_val],
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
            return Ok(());
        }

        // Special handling for PDOStatement
        if class_name == "PDOStatement" {
            let obj = PhpObject::new("PDOStatement".to_string());
            obj.set_object_id(self.next_object_id);
            self.next_object_id += 1;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val)?;
            return Ok(());
        }

        // Try autoloading if the class isn't found
        if !self.classes.contains_key(&class_name) {
            self.try_autoload_class(&class_name);
        }

        // Enforce interface instantiation restriction
        if let Some(class_def) = self.classes.get(&class_name) {
            if class_def.is_interface {
                return Err(VmError::FatalError(format!(
                    "Cannot instantiate interface {}",
                    class_name
                )));
            }
        }

        // Enforce abstract class restriction
        if let Some(class_def) = self.classes.get(&class_name) {
            if class_def.is_abstract {
                return Err(VmError::FatalError(format!(
                    "Cannot instantiate abstract class {}",
                    class_name
                )));
            }
        }

        // Enforce private/protected constructor access
        if let Some(class_def) = self.classes.get(&class_name) {
            if let Some(&ctor_flags) = class_def.method_flags.get("__construct") {
                let calling_scope = self.get_current_class_scope();
                if ctor_flags & ACC_PRIVATE != 0 {
                    // Private constructor: only accessible from the same class
                    if calling_scope.as_deref() != Some(&class_name) {
                        return Err(VmError::FatalError(format!(
                            "Call to private {}::__construct() from scope {}",
                            class_name,
                            calling_scope.as_deref().unwrap_or("global")
                        )));
                    }
                } else if ctor_flags & ACC_PROTECTED != 0 {
                    // Protected constructor: accessible from same class and subclasses
                    match &calling_scope {
                        Some(scope) => {
                            if !self.is_same_or_subclass(scope, &class_name)
                                && !self.is_same_or_subclass(&class_name, scope)
                            {
                                return Err(VmError::FatalError(format!(
                                    "Call to protected {}::__construct() from scope {}",
                                    class_name, scope
                                )));
                            }
                        }
                        None => {
                            return Err(VmError::FatalError(format!(
                                "Call to protected {}::__construct() from scope global",
                                class_name
                            )));
                        }
                    }
                }
            }
        }

        let obj = PhpObject::new(class_name.clone());
        obj.set_object_id(self.next_object_id);
        self.next_object_id += 1;

        // Copy default properties from class definition
        if let Some(class_def) = self.classes.get(&class_name) {
            for (prop, val) in &class_def.default_properties {
                obj.set_property(prop.clone(), val.clone());
            }
        }

        let obj_val = Value::Object(obj);
        self.write_result(op, oa_idx, obj_val.clone())?;

        // Pick up saved constructor args (from class name resolution DO_FCALL)
        let frame = self.call_stack.last_mut().unwrap();
        let saved_args = if let Some(pos) = frame
            .call_stack_pending
            .iter()
            .position(|p| p.name == "__ctor_args__")
        {
            frame.call_stack_pending.remove(pos).args
        } else {
            Vec::new()
        };

        // Set up constructor call if one exists (walk parent chain for inherited constructors)
        let ctor_class = {
            let mut current = class_name.clone();
            let mut found = None;
            loop {
                if let Some(class_def) = self.classes.get(&current) {
                    if class_def.methods.contains_key("__construct") {
                        found = Some(current);
                        break;
                    }
                    if let Some(ref parent) = class_def.parent {
                        current = parent.clone();
                        continue;
                    }
                }
                break;
            }
            found
        };
        if let Some(ctor_owner) = ctor_class {
            let frame = self.call_stack.last_mut().unwrap();
            let ctor_name = format!("{}::__construct", ctor_owner);
            let mut ctor_args = vec![obj_val];
            ctor_args.extend(saved_args);
            // The constructor writes $this back to the NEW result slot
            frame.call_stack_pending.push(PendingCall {
                name: ctor_name,
                args: ctor_args,
                arg_names: Vec::new(),
                this_source: Some((op.result_type, op.result.val)),
                static_class: Some(class_name.clone()),
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
        } else {
            // Push a dummy pending call that DO_FCALL will consume (for the constructor call
            // that always follows NEW in compiled output).
            // Pass saved_args so __new_noop__ can initialize builtin classes (ArrayIterator, etc.)
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "__new_noop__".to_string(),
                args: saved_args,
                arg_names: Vec::new(),
                this_source: None,
                static_class: None,
                forwarded_this: None,
                ref_args: Vec::new(),
                ref_prop_args: Vec::new(),
            });
        }

        Ok(())
    }

    /// Handle FETCH_OBJ_R — read object property.
    pub(crate) fn handle_fetch_obj(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        // Enforce property visibility
        if let Value::Object(ref o) = obj {
            self.check_property_access(&o.class_name(), &prop_name)?;
        }

        // Check for property get hook
        if let Value::Object(ref o) = obj {
            let class_name = o.class_name();
            if let Some(&hook_oa_idx) = self.find_property_get_hook(&class_name, &prop_name) {
                let result = self.call_property_hook(hook_oa_idx, obj.clone(), vec![])?;
                if matches!(op.result_type, OperandType::TmpVar | OperandType::Var) {
                    let frame = self.call_stack.last_mut().unwrap();
                    frame
                        .temp_prop_source
                        .insert(op.result.val as usize, (obj.clone(), prop_name.clone()));
                }
                self.write_result(op, oa_idx, result)?;
                return Ok(());
            }
        }

        let val = match obj {
            Value::Object(ref o) => {
                match o.get_property(&prop_name) {
                    Some(v) => v,
                    None => {
                        // Property not found — try __get magic method
                        let class_name = o.class_name();
                        if let Some(magic) = self.find_magic_method(&class_name, "__get") {
                            self.call_magic_method(
                                &magic,
                                obj.clone(),
                                vec![Value::String(prop_name.clone())],
                            )?
                        } else {
                            Value::Null
                        }
                    }
                }
            }
            _ => Value::Null,
        };
        // Track the source object+property for this temp slot (for pass-by-reference write-back)
        if matches!(op.result_type, OperandType::TmpVar | OperandType::Var) {
            let frame = self.call_stack.last_mut().unwrap();
            frame
                .temp_prop_source
                .insert(op.result.val as usize, (obj.clone(), prop_name.clone()));
        }
        self.write_result(op, oa_idx, val)?;
        Ok(())
    }

    /// Handle ASSIGN_OBJ — set object property.
    pub(crate) fn handle_assign_obj(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj_cv = op.op1.val as usize;
        let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        // Enforce property visibility
        {
            let frame = self.call_stack.last().unwrap();
            let obj_val = match op.op1_type {
                OperandType::Cv => frame.cvs.get(obj_cv).cloned().unwrap_or(Value::Null),
                OperandType::TmpVar | OperandType::Var => {
                    frame.temps.get(obj_cv).cloned().unwrap_or(Value::Null)
                }
                _ => Value::Null,
            };
            if let Value::Object(ref o) = obj_val {
                self.check_property_access(&o.class_name(), &prop_name)?;
                // Enforce asymmetric set-visibility (PHP 8.4)
                self.check_property_set_access(&o.class_name(), &prop_name)?;
            }
        }

        // Look ahead for OP_DATA
        let frame = self.call_stack.last().unwrap();
        let next_ip = frame.ip + 1;
        let val = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
            let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
            if data_op.opcode == ZOpcode::OpData {
                self.read_operand_from(data_op, 1, oa_idx)?
            } else {
                Value::Null
            }
        } else {
            Value::Null
        };

        let frame = self.call_stack.last().unwrap();
        let obj_val = match op.op1_type {
            OperandType::Cv => frame.cvs.get(obj_cv).cloned().unwrap_or(Value::Null),
            OperandType::TmpVar | OperandType::Var => {
                frame.temps.get(obj_cv).cloned().unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };
        if let Value::Object(ref obj) = obj_val {
            // Check for property set hook — if present, call it instead of writing directly.
            // Skip hook if we're currently inside the same property's hook (avoid recursion).
            let obj_class = obj.class_name().to_string();
            let in_hook = self
                .call_stack
                .last()
                .and_then(|f| self.op_arrays.get(f.op_array_idx))
                .and_then(|oa| oa.function_name.as_deref())
                .map(|n| {
                    n == format!("{}::${}::set", obj_class, prop_name)
                        || n == format!("{}::${}::get", obj_class, prop_name)
                })
                .unwrap_or(false);
            if !in_hook {
                if let Some(&hook_oa_idx) = self.find_property_set_hook(&obj_class, &prop_name) {
                    let result =
                        self.call_property_hook(hook_oa_idx, obj_val.clone(), vec![val.clone()])?;
                    // Write the assigned value to the result slot
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, oa_idx, result)?;
                    }
                    // Skip OP_DATA
                    self.call_stack.last_mut().unwrap().ip += 1;
                    return Ok(());
                }
            }

            // Enforce readonly: if property is readonly and already initialized, reject write
            // (except during __construct of the declaring class)
            if obj.has_property(&prop_name) {
                if let Some(pflags) = self.get_property_flags(&obj_class, &prop_name) {
                    if pflags & ACC_READONLY != 0 {
                        // Check if we're in __construct of this class
                        let in_ctor = self
                            .call_stack
                            .last()
                            .and_then(|f| self.op_arrays.get(f.op_array_idx))
                            .and_then(|oa| oa.function_name.as_deref())
                            .map(|n| n.ends_with("::__construct"))
                            .unwrap_or(false);
                        if !in_ctor {
                            return Err(VmError::FatalError(format!(
                                "Cannot modify readonly property {}::${}",
                                obj_class, prop_name
                            )));
                        }
                    }
                }
            }

            // Enforce typed property constraints
            {
                let obj_class = obj.class_name().to_string();
                if let Some(type_name) = self.get_property_type(&obj_class, &prop_name) {
                    let check_val = val.deref_value();
                    if !self.value_matches_type(&check_val, &type_name) {
                        let actual = self.get_value_type_name(&check_val);
                        return Err(VmError::TypeError(format!(
                            "Cannot assign {} to property {}::${} of type {}",
                            actual, obj_class, prop_name, type_name
                        )));
                    }
                }
            }

            // If the property currently holds a Reference, write through it
            // (PHP semantics: assigning to a referenced property updates the shared storage)
            if let Some(Value::Reference(rc)) = obj.get_property(&prop_name) {
                *rc.borrow_mut() = val.deref_value();
            } else if obj.has_property(&prop_name) {
                // Property exists — write directly
                obj.set_property(prop_name, val.clone());
            } else {
                // Property doesn't exist — try __set magic method
                let class_name = obj.class_name();
                if let Some(magic) = self.find_magic_method(&class_name, "__set") {
                    self.call_magic_method(
                        &magic,
                        obj_val.clone(),
                        vec![Value::String(prop_name.clone()), val.clone()],
                    )?;
                } else {
                    // No __set — create dynamic property
                    obj.set_property(prop_name, val.clone());
                }
            }
        }

        // Write the assigned value to the result slot (for assignment expressions)
        if op.result_type != OperandType::Unused {
            self.write_result(op, oa_idx, val)?;
        }

        // Skip OP_DATA
        self.call_stack.last_mut().unwrap().ip += 1;
        Ok(())
    }

    /// Handle INIT_METHOD_CALL — prepare to call $obj->method().
    pub(crate) fn handle_init_method_call(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let method_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        // Dereference in case it's a Reference wrapping an object
        let obj = obj.deref_value();

        let class_name = match &obj {
            Value::Object(o) => o.class_name(),
            _ => {
                // Include method name and value type in error for debugging
                let val_type = match &obj {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Long(_) => "int",
                    Value::Double(_) => "float",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    _ => "unknown",
                };
                let current_func = self
                    .call_stack
                    .last()
                    .and_then(|f| self.op_arrays.get(f.op_array_idx))
                    .and_then(|oa| oa.function_name.as_deref())
                    .unwrap_or("<main>");
                let val_preview = match &obj {
                    Value::String(s) => {
                        format!("string(\"{}\")", if s.len() > 50 { &s[..50] } else { s })
                    }
                    _ => val_type.to_string(),
                };
                return Err(VmError::TypeError(format!(
                    "Call to a member function {}() on {} (in {})",
                    method_name, val_preview, current_func
                )));
            }
        };

        // Enforce method visibility
        self.check_method_access(&class_name, &method_name)?;

        let full_name = format!("{}::{}", class_name, method_name);
        let frame = self.call_stack.last_mut().unwrap();
        // Push the object as first arg ($this) followed by actual args.
        // Save the source operand so we can write $this back after the method returns.
        frame.call_stack_pending.push(PendingCall {
            name: full_name,
            args: vec![obj],
            arg_names: Vec::new(),
            this_source: Some((op.op1_type, op.op1.val)),
            static_class: Some(class_name),
            forwarded_this: None,
            ref_args: Vec::new(),
            ref_prop_args: Vec::new(),
        });
        Ok(())
    }

    /// Handle INIT_STATIC_METHOD_CALL — prepare to call Class::method().
    pub(crate) fn handle_init_static_method_call(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
    ) -> VmResult<()> {
        let raw_val = self.read_operand(op, 1, oa_idx)?;
        // Extract class name from object or string
        let raw = match &raw_val {
            Value::Object(o) => o.class_name(),
            _ => raw_val.to_php_string(),
        };
        let raw = raw.strip_prefix('\\').unwrap_or(&raw).to_string();
        let is_parent_call = raw == "parent";
        let is_static_call = raw == "static";
        let class_name = self.resolve_class_name(&raw);
        let method_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        // Try autoloading if the class isn't found
        if !self.classes.contains_key(&class_name) {
            self.try_autoload_class(&class_name);
        }

        // Enforce method visibility (skip for parent::/self::/static:: calls)
        if !is_parent_call && !is_static_call && raw != "self" {
            self.check_method_access(&class_name, &method_name)?;
        }

        let full_name = format!("{}::{}", class_name, method_name);

        // Track parent::__construct() call for constructor call tracking
        if is_parent_call && method_name == "__construct" {
            let frame = self.call_stack.last_mut().unwrap();
            frame.parent_ctor_called = true;
        }

        // For parent::/self::/static:: calls in a non-static context,
        // forward the current $this so the called method has the correct context.
        let frame = self.call_stack.last_mut().unwrap();

        // For parent:: and self:: calls, preserve the caller's static_class (late static binding).
        // For static:: calls, it's already resolved via resolve_class_name.
        // For explicit Class:: calls, use the resolved class name.
        let effective_static_class = if is_parent_call {
            // parent:: calls preserve late static binding from the current context
            frame.static_class.clone().or_else(|| {
                // Fall back to $this's class if no explicit static_class
                let oa = &self.op_arrays[frame.op_array_idx];
                if let Some(this_idx) = oa.vars.iter().position(|v| v == "this") {
                    if let Some(Value::Object(ref obj)) = frame.cvs.get(this_idx) {
                        return Some(obj.class_name().to_string());
                    }
                }
                Some(class_name.clone())
            })
        } else if is_static_call {
            Some(class_name.clone())
        } else {
            Some(class_name.clone())
        };

        let this_val = {
            let this_cv_idx = self.op_arrays[frame.op_array_idx]
                .vars
                .iter()
                .position(|v| v == "this");
            if let Some(idx) = this_cv_idx {
                let val = frame.cvs.get(idx).cloned();
                match val {
                    Some(Value::Object(_)) => val,
                    _ => None,
                }
            } else {
                None
            }
        };

        frame.call_stack_pending.push(PendingCall {
            name: full_name,
            args: Vec::new(),
            arg_names: Vec::new(),
            this_source: None,
            static_class: effective_static_class,
            forwarded_this: this_val,
            ref_args: Vec::new(),
            ref_prop_args: Vec::new(),
        });
        Ok(())
    }

    /// Handle FETCH_CLASS_CONSTANT — read Class::CONST.
    pub(crate) fn handle_fetch_class_constant(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let raw_val = self.read_operand(op, 1, oa_idx)?;
        let raw = match &raw_val {
            Value::Object(o) => o.class_name(),
            _ => raw_val.to_php_string(),
        };
        let raw = raw.strip_prefix('\\').unwrap_or(&raw).to_string();
        let class_name = self.resolve_class_name(&raw);
        let const_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        // Try autoloading if the class isn't found
        if !self.classes.contains_key(&class_name) {
            self.try_autoload_class(&class_name);
        }

        // The magic "class" constant returns the class name itself
        let val = if const_name == "class" {
            Value::String(class_name)
        } else {
            self.resolve_class_constant(&class_name, &const_name)
                .unwrap_or(Value::Null)
        };

        self.write_result(op, oa_idx, val)?;
        Ok(())
    }

    /// Resolve a class constant value by name, walking parent chain if needed.
    pub(crate) fn resolve_class_constant(
        &self,
        class_name: &str,
        const_name: &str,
    ) -> Option<Value> {
        // Handle built-in PDO class constants
        if class_name == "PDO" {
            if let Some(val) = resolve_pdo_class_constant(const_name) {
                return Some(val);
            }
        }

        let mut current = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(val) = class_def.class_constants.get(const_name) {
                    return Some(val.clone());
                }
                if let Some(ref parent) = class_def.parent {
                    current = parent.clone();
                    continue;
                }
            }
            break;
        }
        None
    }

    /// Handle INSTANCEOF.
    pub(crate) fn handle_instanceof(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let result = match obj {
            Value::Object(ref o) => {
                o.class_name() == class_name || self.is_subclass(&o.class_name(), &class_name)
            }
            _ => false,
        };

        self.write_result(op, oa_idx, Value::Bool(result))?;
        Ok(())
    }

    /// Check if a class is a subclass of or implements a given class/interface.
    pub(crate) fn is_subclass(&self, child: &str, parent: &str) -> bool {
        let mut current = child.to_string();
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return false;
            }
            if let Some(class_def) = self.classes.get(&current) {
                // Check implemented interfaces
                if class_def.interfaces.iter().any(|i| i == parent) {
                    return true;
                }
                // Check parent class
                if let Some(ref p) = class_def.parent {
                    if p == parent {
                        return true;
                    }
                    current = p.clone();
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /// Check if a class implements a specific interface (walks class hierarchy).
    pub(crate) fn implements_interface(&self, class_name: &str, interface_name: &str) -> bool {
        let mut current = class_name.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return false;
            }
            if let Some(class_def) = self.classes.get(&current) {
                if class_def.interfaces.iter().any(|i| i == interface_name) {
                    return true;
                }
                if let Some(ref p) = class_def.parent {
                    current = p.clone();
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /// Call a method on an object synchronously and return the result.
    /// Used for internal callbacks like JsonSerializable::jsonSerialize().
    pub(crate) fn call_method_sync(&mut self, obj: &Value, method_name: &str) -> VmResult<Value> {
        let class_name = match obj {
            Value::Object(ref o) => o.class_name(),
            _ => return Err(VmError::TypeError("Not an object".to_string())),
        };
        let method_key = format!("{}::{}", class_name, method_name);
        // Try user-defined method first (PHP-level overrides take priority)
        let oa_idx_opt = self
            .functions
            .get(&method_key)
            .copied()
            .or_else(|| self.resolve_method(&class_name, method_name));
        if let Some(oa_idx_val) = oa_idx_opt {
            let saved_depth = self.call_stack.len();
            let func_oa = &self.op_arrays[oa_idx_val];
            let mut frame = Frame::new(func_oa);
            frame.op_array_idx = oa_idx_val;
            let this_cv = func_oa.vars.iter().position(|v| v == "this").unwrap_or(0);
            if this_cv < frame.cvs.len() {
                frame.cvs[this_cv] = obj.clone();
            }
            self.call_stack.push(frame);
            self.dispatch_loop_until(saved_depth)?;
            return Ok(self.last_return_value.clone());
        }
        // Fall back to builtin method
        if let Some(result) = self.call_builtin_method(&method_key, &[obj.clone()])? {
            return Ok(result);
        }
        Err(VmError::UndefinedFunction(method_key))
    }

    /// Convert a Value to a PHP string, calling __toString() for objects.
    pub(crate) fn value_to_string(&mut self, val: &Value) -> VmResult<String> {
        match val {
            Value::Object(obj) => {
                let class_name = obj.class_name().to_string();
                // Walk the class hierarchy looking for __toString()
                let mut search_class = class_name.clone();
                loop {
                    let method_name = format!("{}::__toString", search_class);
                    if self.functions.contains_key(&method_name) {
                        let result = self.invoke_user_callback(&method_name, vec![val.clone()])?;
                        return Ok(result.to_php_string());
                    }
                    // Try parent class
                    if let Some(parent) = self
                        .classes
                        .get(&search_class)
                        .and_then(|c| c.parent.clone())
                    {
                        search_class = parent;
                    } else {
                        break;
                    }
                }
                // No __toString found — fallback
                Ok(val.to_php_string())
            }
            Value::Reference(rc) => {
                let inner = rc.borrow().clone();
                self.value_to_string(&inner)
            }
            _ => Ok(val.to_php_string()),
        }
    }

    /// Resolve a magic method by walking the class hierarchy.
    /// Returns the fully-qualified method name (e.g. "ParentClass::__get") if found.
    pub(crate) fn find_magic_method(&self, class_name: &str, magic: &str) -> Option<String> {
        let mut search = class_name.to_string();
        loop {
            let full = format!("{}::{}", search, magic);
            if self.functions.contains_key(&full) {
                return Some(full);
            }
            if let Some(parent) = self.classes.get(&search).and_then(|c| c.parent.clone()) {
                search = parent;
            } else {
                break;
            }
        }
        None
    }

    /// Call a magic method on an object (e.g. __get, __set, __isset, __unset).
    /// `obj_val` must be a Value::Object. Extra args are appended after $this.
    pub(crate) fn call_magic_method(
        &mut self,
        method_name: &str,
        obj_val: Value,
        args: Vec<Value>,
    ) -> VmResult<Value> {
        let mut full_args = vec![obj_val];
        full_args.extend(args);
        self.invoke_user_callback(method_name, full_args)
    }

    /// Invoke a user-defined callback (function or closure) synchronously.
    /// Returns the callback's return value. Used by call_user_func, array_map, etc.
    pub(crate) fn invoke_user_callback(
        &mut self,
        func_name: &str,
        args: Vec<Value>,
    ) -> VmResult<Value> {
        // Try builtin first
        if let Some(result) = self.call_builtin(func_name, &args, &[], &[])? {
            return Ok(result);
        }
        // Try builtin method dispatch (SPL classes, DateTime, etc.)
        if let Some(result) = self.call_builtin_method(func_name, &args)? {
            return Ok(result);
        }
        // Look up user-defined function (or closure like {closure}#N)
        let oa_idx = self
            .functions
            .get(func_name)
            .copied()
            .or_else(|| {
                if let Some(sep) = func_name.find("::") {
                    let class = &func_name[..sep];
                    let method = &func_name[sep + 2..];
                    self.resolve_method(class, method)
                } else {
                    None
                }
            })
            .ok_or_else(|| VmError::UndefinedFunction(func_name.to_string()))?;

        let saved_depth = self.call_stack.len();

        let func_oa = &self.op_arrays[oa_idx];
        let mut frame = Frame::new(func_oa);
        frame.op_array_idx = oa_idx;

        // For method calls (Name::method), extract $this from first arg
        let mut actual_args = args;
        if func_name.contains("::") {
            if !actual_args.is_empty() {
                if let Value::Object(_) = &actual_args[0] {
                    let this_val = actual_args.remove(0);
                    // Bind $this to the "this" CV
                    if let Some(this_idx) = func_oa.vars.iter().position(|v| v == "this") {
                        if this_idx < frame.cvs.len() {
                            frame.cvs[this_idx] = this_val;
                        }
                    }
                }
            }
        }
        frame.args = actual_args.clone();

        // Bind parameters to CVs
        let num_params = func_oa.arg_info.len().min(actual_args.len());
        for i in 0..num_params {
            if i < frame.cvs.len() {
                if func_oa.arg_info[i].is_variadic {
                    let mut arr = PhpArray::new();
                    for j in i..actual_args.len() {
                        arr.push(actual_args[j].clone());
                    }
                    frame.cvs[i] = Value::Array(arr);
                    break;
                }
                frame.cvs[i] = actual_args[i].clone();
            }
        }

        // Apply closure bindings (captured `use` variables)
        if let Some(bindings) = self.closure_bindings.get(func_name).cloned() {
            for (var_name, val) in &bindings {
                if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == var_name) {
                    if cv_idx < frame.cvs.len() {
                        frame.cvs[cv_idx] = val.clone();
                    }
                }
            }
        }

        // Apply declaring class scope for closures
        if frame.static_class.is_none() {
            if let Some(scope) = self.closure_scopes.get(func_name).cloned() {
                frame.static_class = Some(scope);
            }
        }

        self.call_stack.push(frame);
        let result = self.dispatch_loop_until(saved_depth);
        if let Err(e) = result {
            // Clean up frames that dispatch_loop_until didn't pop
            while self.call_stack.len() > saved_depth {
                self.call_stack.pop();
            }
            return Err(e);
        }

        Ok(self.last_return_value.clone())
    }

    /// Find the class that owns (declares) a static property by walking the parent chain.
    /// Returns the declaring class name, or the original class if not found anywhere.
    pub(crate) fn find_static_prop_owner(&self, class_name: &str, prop_name: &str) -> String {
        let mut current = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&current) {
                if class_def.static_properties.contains_key(prop_name) {
                    return current;
                }
                if let Some(ref parent) = class_def.parent {
                    current = parent.clone();
                    continue;
                }
            }
            break;
        }
        // Not found on any parent — write to the original class
        class_name.to_string()
    }

    /// Handle FETCH_STATIC_PROP_* — read/write static properties.
    pub(crate) fn handle_fetch_static_prop(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
        write_mode: bool,
    ) -> VmResult<()> {
        let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
        let raw_class = self.read_operand(op, 2, oa_idx)?.to_php_string();
        let class_name = self.resolve_class_name(&raw_class);

        // Walk parent chain to find the static property (and its declaring class for write-back)
        let (val, owner_class) = {
            let mut current = class_name.clone();
            let mut found = None;
            loop {
                if let Some(class_def) = self.classes.get(&current) {
                    if let Some(v) = class_def.static_properties.get(&prop_name) {
                        found = Some((v.clone(), current.clone()));
                        break;
                    }
                    if let Some(ref parent) = class_def.parent {
                        current = parent.clone();
                        continue;
                    }
                }
                break;
            }
            found.unwrap_or((Value::Null, class_name.clone()))
        };

        self.write_result(op, oa_idx, val)?;

        // For W/RW mode: record write-back info so ASSIGN_DIM can update the static property
        if write_mode {
            if let OperandType::TmpVar | OperandType::Var = op.result_type {
                let slot = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                frame
                    .static_prop_write_back
                    .push((slot, owner_class, prop_name));
            }
        }

        Ok(())
    }

    /// Handle INCLUDE_OR_EVAL — include/require/eval.
    /// Check if a class is an exception class (extends Exception, Error, or Throwable)
    pub(crate) fn is_exception_class(&self, class_name: &str) -> bool {
        let short = class_name.rsplit('\\').next().unwrap_or(class_name);
        // Known built-in exception/error base classes
        if matches!(
            short,
            "Exception"
                | "Error"
                | "Throwable"
                | "RuntimeException"
                | "LogicException"
                | "InvalidArgumentException"
                | "BadMethodCallException"
                | "BadFunctionCallException"
                | "OutOfRangeException"
                | "OverflowException"
                | "UnderflowException"
                | "LengthException"
                | "DomainException"
                | "RangeException"
                | "UnexpectedValueException"
                | "TypeError"
                | "ValueError"
                | "ArithmeticError"
                | "DivisionByZeroError"
                | "ParseError"
        ) {
            return true;
        }
        // Walk parent chain to check if it extends Exception or Error
        let mut current = class_name.to_string();
        for _ in 0..20 {
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref parent) = class_def.parent {
                    let parent_short = parent.rsplit('\\').next().unwrap_or(parent);
                    if matches!(
                        parent_short,
                        "Exception"
                            | "Error"
                            | "Throwable"
                            | "RuntimeException"
                            | "LogicException"
                            | "InvalidArgumentException"
                            | "BadMethodCallException"
                            | "BadFunctionCallException"
                            | "OutOfRangeException"
                            | "OverflowException"
                            | "UnderflowException"
                            | "LengthException"
                            | "DomainException"
                            | "RangeException"
                            | "UnexpectedValueException"
                            | "TypeError"
                            | "ValueError"
                            | "ArithmeticError"
                            | "DivisionByZeroError"
                            | "ParseError"
                    ) {
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

    /// Get the PHP type name for a Value (for error messages).
    pub(crate) fn get_value_type_name(&self, val: &Value) -> String {
        match val {
            Value::Null => "null".to_string(),
            Value::Bool(_) => "bool".to_string(),
            Value::Long(_) => "int".to_string(),
            Value::Double(_) => "float".to_string(),
            Value::String(_) => "string".to_string(),
            Value::Array(_) => "array".to_string(),
            Value::Object(obj) => obj.class_name().to_string(),
            Value::Resource(_, typ) => format!("resource ({})", typ),
            Value::Reference(rc) => self.get_value_type_name(&rc.borrow()),
            _ => "unknown".to_string(),
        }
    }

    /// Check if a value matches a declared PHP type string.
    /// Supports basic types, nullable (?Type), union (A|B), and class names.
    pub(crate) fn value_matches_type(&self, val: &Value, type_str: &str) -> bool {
        // Handle nullable: ?Type means Type|null
        if let Some(inner) = type_str.strip_prefix('?') {
            return val.is_null() || self.value_matches_type(val, inner);
        }

        // Handle DNF types containing parenthesized groups: (A&B)|C
        if type_str.contains('(') {
            return self.value_matches_dnf_type(val, type_str);
        }

        // Handle union: Type1|Type2
        if type_str.contains('|') {
            return type_str
                .split('|')
                .any(|t| self.value_matches_type(val, t.trim()));
        }

        // Handle intersection: Type1&Type2
        if type_str.contains('&') {
            return type_str
                .split('&')
                .all(|t| self.value_matches_type(val, t.trim()));
        }

        match type_str {
            "int" => matches!(val, Value::Long(_)),
            "float" => matches!(val, Value::Long(_) | Value::Double(_)),
            "string" => matches!(val, Value::String(_)),
            "bool" => matches!(val, Value::Bool(_)),
            "array" => matches!(val, Value::Array(_)),
            "object" => matches!(val, Value::Object(_)),
            "callable" => {
                // Strings (function names), arrays ([class, method]), and Closure objects
                match val {
                    Value::String(_) => true,
                    Value::Array(_) => true,
                    Value::Object(obj) => obj.class_name() == "Closure",
                    _ => false,
                }
            }
            "iterable" => matches!(val, Value::Array(_) | Value::Object(_)),
            "mixed" => true,
            "null" => val.is_null(),
            "false" => matches!(val, Value::Bool(false)),
            "true" => matches!(val, Value::Bool(true)),
            "void" => val.is_null(),
            "never" => false, // never type can never be satisfied
            "self" | "static" | "parent" => {
                // These need context — for now, check if it's an object
                matches!(val, Value::Object(_))
            }
            class_name => {
                // Class type check: value must be an object of that class or a subclass
                if let Value::Object(obj) = val {
                    let obj_class = obj.class_name().to_string();
                    if obj_class.eq_ignore_ascii_case(class_name) {
                        return true;
                    }
                    // Check inheritance
                    self.is_subclass(&obj_class, class_name)
                } else {
                    false
                }
            }
        }
    }

    /// Evaluate a DNF type string like `(A&B)|C|(D&E)`.
    /// Split on `|` at top level (outside parentheses), then evaluate each group.
    fn value_matches_dnf_type(&self, val: &Value, type_str: &str) -> bool {
        // Split on | at top level (respecting parentheses)
        let mut groups: Vec<&str> = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (i, ch) in type_str.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                '|' if depth == 0 => {
                    groups.push(type_str[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        groups.push(type_str[start..].trim());

        // Each group is either `(A&B)` or a plain type `C`
        groups.iter().any(|group| {
            let group = group.trim();
            if let Some(inner) = group.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
                // Intersection group: all types must match
                inner
                    .split('&')
                    .all(|t| self.value_matches_type(val, t.trim()))
            } else {
                self.value_matches_type(val, group)
            }
        })
    }

    /// Check if `child_type` is covariant with (a subtype of) `parent_type`.
    /// Used for return type checking in inheritance: child can return narrower type.
    /// Returns true if child_type is compatible as a return type replacement for parent_type.
    pub(crate) fn is_type_covariant(&self, child_type: &str, parent_type: &str) -> bool {
        // Same type is always covariant
        if child_type.eq_ignore_ascii_case(parent_type) {
            return true;
        }
        // Parent is mixed — everything is a subtype of mixed
        if parent_type == "mixed" {
            return true;
        }
        // Parent is void — child must also be void
        if parent_type == "void" {
            return child_type == "void";
        }
        // Handle nullable: ?T is a supertype of T
        let parent_nullable = parent_type.starts_with('?');
        let child_nullable = child_type.starts_with('?');
        let parent_inner = parent_type.strip_prefix('?').unwrap_or(parent_type);
        let child_inner = child_type.strip_prefix('?').unwrap_or(child_type);
        // If parent is not nullable but child is, that's widening (not covariant)
        if child_nullable && !parent_nullable && parent_type != "mixed" {
            return false;
        }
        // Check inner types
        if child_inner.eq_ignore_ascii_case(parent_inner) {
            return true;
        }
        // int is a subtype of float (covariant widening)
        if child_inner == "int" && parent_inner == "float" {
            return true;
        }
        // Class hierarchy: child class is a subtype of parent class
        if self.is_subclass(child_inner, parent_inner) {
            return true;
        }
        // Parent is iterable — array and Traversable are subtypes
        if parent_inner == "iterable"
            && (child_inner == "array" || self.is_subclass(child_inner, "Traversable"))
        {
            return true;
        }
        // Parent union: child must be subtype of at least one branch
        if parent_inner.contains('|') {
            return parent_inner
                .split('|')
                .any(|t| self.is_type_covariant(child_inner, t.trim()));
        }
        false
    }

    /// Check if `child_type` is contravariant with (a supertype of) `parent_type`.
    /// Used for parameter type checking in inheritance: child can accept wider type.
    /// Returns true if child_type is compatible as a parameter type replacement for parent_type.
    pub(crate) fn is_type_contravariant(&self, child_type: &str, parent_type: &str) -> bool {
        // Same type is always contravariant
        if child_type.eq_ignore_ascii_case(parent_type) {
            return true;
        }
        // Child is mixed — accepts everything (widest possible)
        if child_type == "mixed" {
            return true;
        }
        // Handle nullable: ?T is wider than T (accepts null too)
        let parent_nullable = parent_type.starts_with('?');
        let child_nullable = child_type.starts_with('?');
        let parent_inner = parent_type.strip_prefix('?').unwrap_or(parent_type);
        let child_inner = child_type.strip_prefix('?').unwrap_or(child_type);
        // Child accepting nullable when parent doesn't is widening (ok)
        if child_inner.eq_ignore_ascii_case(parent_inner) {
            return true;
        }
        // float is a supertype of int (contravariant widening)
        if child_inner == "float" && parent_inner == "int" {
            return true;
        }
        // Parent class is a subtype of child class (child accepts parent's superclass)
        if self.is_subclass(parent_inner, child_inner) {
            return true;
        }
        // Child is iterable — wider than array
        if child_inner == "iterable"
            && (parent_inner == "array" || self.is_subclass(parent_inner, "Traversable"))
        {
            return true;
        }
        // Child union: must cover all of parent's types
        if child_inner.contains('|') {
            // If parent is also a union, each parent branch must match some child branch
            if parent_inner.contains('|') {
                return parent_inner.split('|').all(|pt| {
                    child_inner
                        .split('|')
                        .any(|ct| self.is_type_contravariant(ct.trim(), pt.trim()))
                });
            }
            return child_inner
                .split('|')
                .any(|t| self.is_type_contravariant(t.trim(), parent_inner));
        }
        false
    }

    /// Try to coerce a value to match a type hint in non-strict mode.
    /// Returns Some(coerced_value) if coercion is possible, None if not.
    /// PHP coercion rules: int→float, float→int (truncates), numeric string→int/float,
    /// bool→int, int/float→string, etc.
    pub(crate) fn try_coerce_param(&self, val: &Value, type_str: &str) -> Option<Value> {
        // Handle nullable
        if let Some(inner) = type_str.strip_prefix('?') {
            if val.is_null() {
                return Some(val.clone());
            }
            return self.try_coerce_param(val, inner);
        }
        // Handle union: try to coerce to any branch
        if type_str.contains('|') {
            for branch in type_str.split('|') {
                let branch = branch.trim();
                if self.value_matches_type(val, branch) {
                    return Some(val.clone());
                }
                if let Some(c) = self.try_coerce_param(val, branch) {
                    return Some(c);
                }
            }
            return None;
        }
        match type_str {
            "int" => match val {
                Value::Double(f) => Some(Value::Long(*f as i64)),
                Value::Bool(b) => Some(Value::Long(if *b { 1 } else { 0 })),
                Value::String(s) => s.parse::<i64>().ok().map(Value::Long),
                _ => None,
            },
            "float" => match val {
                Value::Long(n) => Some(Value::Double(*n as f64)),
                Value::Bool(b) => Some(Value::Double(if *b { 1.0 } else { 0.0 })),
                Value::String(s) => s.parse::<f64>().ok().map(Value::Double),
                _ => None,
            },
            "string" => match val {
                Value::Long(n) => Some(Value::String(n.to_string())),
                Value::Double(f) => Some(Value::String(val.to_php_string())),
                Value::Bool(b) => Some(Value::String(if *b { "1" } else { "" }.to_string())),
                _ => None,
            },
            "bool" => match val {
                Value::Long(n) => Some(Value::Bool(*n != 0)),
                Value::Double(f) => Some(Value::Bool(*f != 0.0)),
                Value::String(s) => Some(Value::Bool(!s.is_empty() && s != "0")),
                _ => None,
            },
            "mixed" => Some(val.clone()),
            _ => None,
        }
    }
}

/// Resolve built-in PDO class constants.
fn resolve_pdo_class_constant(name: &str) -> Option<Value> {
    let val = match name {
        // Fetch modes
        "FETCH_LAZY" => 1,
        "FETCH_ASSOC" => 2,
        "FETCH_NUM" => 3,
        "FETCH_BOTH" => 4,
        "FETCH_OBJ" => 5,
        "FETCH_BOUND" => 6,
        "FETCH_COLUMN" => 7,
        "FETCH_CLASS" => 8,
        "FETCH_INTO" => 9,
        "FETCH_FUNC" => 10,
        "FETCH_NAMED" => 11,
        "FETCH_KEY_PAIR" => 12,
        "FETCH_GROUP" => 0x10000,
        "FETCH_UNIQUE" => 0x30000,
        // Attributes
        "ATTR_AUTOCOMMIT" => 0,
        "ATTR_PREFETCH" => 1,
        "ATTR_TIMEOUT" => 2,
        "ATTR_ERRMODE" => 3,
        "ATTR_SERVER_VERSION" => 4,
        "ATTR_CLIENT_VERSION" => 5,
        "ATTR_SERVER_INFO" => 6,
        "ATTR_CONNECTION_STATUS" => 7,
        "ATTR_CASE" => 8,
        "ATTR_CURSOR_NAME" => 9,
        "ATTR_CURSOR" => 10,
        "ATTR_STATEMENT_CLASS" => 13,
        "ATTR_DRIVER_NAME" => 16,
        "ATTR_STRINGIFY_FETCHES" => 17,
        "ATTR_DEFAULT_FETCH_MODE" => 19,
        "ATTR_EMULATE_PREPARES" => 20,
        // Error modes
        "ERRMODE_SILENT" => 0,
        "ERRMODE_WARNING" => 1,
        "ERRMODE_EXCEPTION" => 2,
        // Param types
        "PARAM_NULL" => 0,
        "PARAM_INT" => 1,
        "PARAM_STR" => 2,
        "PARAM_LOB" => 3,
        "PARAM_BOOL" => 5,
        "PARAM_INPUT_OUTPUT" => 0x80000000_u32 as i64,
        // Case
        "CASE_NATURAL" => 0,
        "CASE_UPPER" => 1,
        "CASE_LOWER" => 2,
        // Cursor
        "CURSOR_FWDONLY" => 0,
        "CURSOR_SCROLL" => 1,
        // NULL handling
        "NULL_NATURAL" => 0,
        "NULL_EMPTY_STRING" => 1,
        "NULL_TO_STRING" => 2,
        _ => return None,
    };
    Some(Value::Long(val))
}
