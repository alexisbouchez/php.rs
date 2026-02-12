//! Reflection API — extracted from vm.rs.
//!
//! ReflectionFunction, ReflectionMethod, ReflectionParameter, ReflectionNamedType.

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};

use super::{ClassDef, Vm, VmError, VmResult};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    /// Try handling a ReflectionFunction method call.
    pub(crate) fn try_reflection_function_method(
        &self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let method_name = if let Some(m) = func_name.strip_prefix("ReflectionFunction::") {
            m
        } else {
            return Ok(None);
        };
        // Get the ReflectionFunction object ($this is first arg)
        let obj = match args.first() {
            Some(Value::Object(o)) if o.class_name() == "ReflectionFunction" => o.clone(),
            _ => return Ok(None),
        };
        match method_name {
            "isAnonymous" => {
                let name = obj
                    .get_property("name")
                    .unwrap_or(Value::Null)
                    .to_php_string();
                Ok(Some(Value::Bool(
                    name.contains("{closure}") || name.is_empty(),
                )))
            }
            "getClosureScopeClass" => {
                // Return a ReflectionClass-like object with a `name` property, or null
                Ok(Some(Value::Null))
            }
            "getName" => {
                let name = obj
                    .get_property("name")
                    .unwrap_or(Value::String(String::new()));
                Ok(Some(name))
            }
            "getParameters" => {
                // Look up the function's op_array to get arg_info
                let func_n = obj
                    .get_property("name")
                    .unwrap_or(Value::Null)
                    .to_php_string();
                let oa_idx = self.functions.get(&func_n).copied();
                let mut params = PhpArray::new();
                if let Some(idx) = oa_idx {
                    let arg_info = &self.op_arrays[idx].arg_info;
                    for (i, info) in arg_info.iter().enumerate() {
                        let param_obj = PhpObject::new("ReflectionParameter".to_string());
                        param_obj
                            .set_property("name".to_string(), Value::String(info.name.clone()));
                        param_obj.set_property("position".to_string(), Value::Long(i as i64));
                        param_obj
                            .set_property("isVariadic".to_string(), Value::Bool(info.is_variadic));
                        param_obj.set_property(
                            "hasDefault".to_string(),
                            Value::Bool(info.default.is_some()),
                        );
                        if let Some(ref default) = info.default {
                            let default_val = match default {
                                Literal::Null => Value::Null,
                                Literal::Bool(b) => Value::Bool(*b),
                                Literal::Long(n) => Value::Long(*n),
                                Literal::Double(f) => Value::Double(*f),
                                Literal::String(s) if s == "__EMPTY_ARRAY__" => {
                                    Value::Array(PhpArray::new())
                                }
                                Literal::String(s) => Value::String(s.clone()),
                                Literal::ClassConst(class_ref, cname) => {
                                    let resolved_class = if class_ref == "self"
                                        || class_ref == "static"
                                    {
                                        func_n.rsplit("::").nth(1).unwrap_or(class_ref).to_string()
                                    } else {
                                        class_ref.clone()
                                    };
                                    self.resolve_class_constant(&resolved_class, cname)
                                        .unwrap_or(Value::Null)
                                }
                                Literal::LongJumpTable(_) | Literal::StringJumpTable(_) => {
                                    Value::Null
                                }
                            };
                            param_obj.set_property("defaultValue".to_string(), default_val);
                        }
                        let type_name = info.type_name.clone();
                        param_obj
                            .set_property("hasType".to_string(), Value::Bool(type_name.is_some()));
                        if let Some(ref tn) = type_name {
                            param_obj
                                .set_property("typeName".to_string(), Value::String(tn.clone()));
                        }
                        params.push(Value::Object(param_obj));
                    }
                }
                Ok(Some(Value::Array(params)))
            }
            "getNumberOfParameters" | "getNumberOfRequiredParameters" => {
                let func_n = obj
                    .get_property("name")
                    .unwrap_or(Value::Null)
                    .to_php_string();
                let count = self
                    .functions
                    .get(&func_n)
                    .map(|&idx| self.op_arrays[idx].arg_info.len() as i64)
                    .unwrap_or(0);
                Ok(Some(Value::Long(count)))
            }
            _ => Ok(None),
        }
    }

    /// Try handling a ReflectionClass method call.
    pub(crate) fn try_reflection_method(
        &mut self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        // Try ReflectionFunction methods first
        if func_name.starts_with("ReflectionFunction::") {
            return self.try_reflection_function_method(func_name, args);
        }
        // Match ReflectionClass/ReflectionObject::method
        let method_name = if let Some(m) = func_name.strip_prefix("ReflectionClass::") {
            m
        } else if let Some(m) = func_name.strip_prefix("ReflectionObject::") {
            m
        } else {
            return Ok(None);
        };

        // Get the ReflectionClass object ($this is first arg)
        let obj = match args.first() {
            Some(Value::Object(o))
                if o.internal() == crate::value::InternalState::ReflectionClass =>
            {
                o.clone()
            }
            _ => return Ok(None),
        };

        let obj_id = obj.object_id();
        let reflected_name = match self.reflection_classes.get(&obj_id) {
            Some(name) => name.clone(),
            None => return Ok(None),
        };

        match method_name {
            "getName" => Ok(Some(Value::String(reflected_name))),

            "isInstantiable" => {
                let is_instantiable = self
                    .classes
                    .get(&reflected_name)
                    .map(|c| !c.is_abstract && !c.is_interface)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(is_instantiable)))
            }

            "isInterface" => {
                let is_iface = self
                    .classes
                    .get(&reflected_name)
                    .map(|c| c.is_interface)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(is_iface)))
            }

            "isAbstract" => {
                let is_abstract = self
                    .classes
                    .get(&reflected_name)
                    .map(|c| c.is_abstract)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(is_abstract)))
            }

            "implementsInterface" => {
                let iface_name = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let implements = self.class_implements_interface(&reflected_name, &iface_name);
                Ok(Some(Value::Bool(implements)))
            }

            "isSubclassOf" => {
                let parent_name = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let is_sub = self.class_is_subclass_of(&reflected_name, &parent_name);
                Ok(Some(Value::Bool(is_sub)))
            }

            "getConstructor" => {
                // Check if the class has a __construct method
                let ctor_name = format!("{}::__construct", reflected_name);
                if self.functions.contains_key(&ctor_name) {
                    // Return a simple object representing the constructor
                    let method_obj = PhpObject::new("ReflectionMethod".to_string());
                    method_obj
                        .set_property("name".to_string(), Value::String("__construct".to_string()));
                    method_obj.set_property("class".to_string(), Value::String(reflected_name));
                    Ok(Some(Value::Object(method_obj)))
                } else {
                    Ok(Some(Value::Null))
                }
            }

            "getAttributes" => {
                // Return ReflectionAttribute objects for class attributes
                let filter_name = args.get(1).map(|v| v.to_php_string());
                let mut result = PhpArray::new();
                if let Some(class_def) = self.classes.get(&reflected_name) {
                    for (attr_name, attr_args) in &class_def.attributes {
                        // Apply filter if specified
                        if let Some(ref filter) = filter_name {
                            if attr_name != filter {
                                continue;
                            }
                        }
                        let attr_obj = PhpObject::new("ReflectionAttribute".to_string());
                        attr_obj.set_property("name".to_string(), Value::String(attr_name.clone()));
                        // Store args as properties for newInstance()
                        let mut args_arr = PhpArray::new();
                        for (arg_name, arg_value) in attr_args {
                            if let Some(name) = arg_name {
                                let key = Value::String(name.clone());
                                args_arr.set(&key, Value::String(arg_value.clone()));
                            } else {
                                args_arr.push(Value::String(arg_value.clone()));
                            }
                        }
                        attr_obj.set_property("arguments".to_string(), Value::Array(args_arr));
                        result.push(Value::Object(attr_obj));
                    }
                }
                Ok(Some(Value::Array(result)))
            }

            "getParentClass" => {
                if let Some(class_def) = self.classes.get(&reflected_name) {
                    if let Some(ref parent) = class_def.parent {
                        // Return a ReflectionClass for the parent
                        let parent_obj = PhpObject::new("ReflectionClass".to_string());
                        parent_obj.set_object_id(self.next_object_id);
                        self.next_object_id += 1;
                        parent_obj.set_internal(crate::value::InternalState::ReflectionClass);
                        let parent_id = parent_obj.object_id();
                        self.reflection_classes.insert(parent_id, parent.clone());
                        return Ok(Some(Value::Object(parent_obj)));
                    }
                }
                Ok(Some(Value::Bool(false)))
            }

            "getInterfaceNames" => {
                let interfaces = self.get_class_interfaces(&reflected_name);
                let mut arr = PhpArray::new();
                for name in interfaces {
                    arr.push(Value::String(name));
                }
                Ok(Some(Value::Array(arr)))
            }

            _ => Ok(None),
        }
    }

    /// Handle ReflectionMethod::* calls.
    pub(crate) fn try_reflection_method_call(
        &mut self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let method_name = if let Some(m) = func_name.strip_prefix("ReflectionMethod::") {
            m
        } else {
            return Ok(None);
        };

        // $this is first arg — a ReflectionMethod object with properties "class" and "name"
        let obj = match args.first() {
            Some(Value::Object(o)) if o.class_name() == "ReflectionMethod" => o.clone(),
            _ => return Ok(None),
        };

        let class_name = obj
            .get_property("class")
            .map(|v| v.to_php_string())
            .unwrap_or_default();
        let method_n = obj
            .get_property("name")
            .map(|v| v.to_php_string())
            .unwrap_or_default();

        match method_name {
            "getName" => Ok(Some(Value::String(method_n))),

            "getParameters" => {
                // Look up the function op_array to get arg_info
                let full_name = format!("{}::{}", class_name, method_n);
                let oa_idx = self
                    .functions
                    .get(&full_name)
                    .copied()
                    .or_else(|| self.resolve_method(&class_name, &method_n));
                let mut params = PhpArray::new();
                if let Some(idx) = oa_idx {
                    let arg_info = self.op_arrays[idx].arg_info.clone();
                    for (i, info) in arg_info.iter().enumerate() {
                        let param_obj = PhpObject::new("ReflectionParameter".to_string());
                        param_obj
                            .set_property("name".to_string(), Value::String(info.name.clone()));
                        param_obj.set_property("position".to_string(), Value::Long(i as i64));
                        param_obj
                            .set_property("class".to_string(), Value::String(class_name.clone()));
                        param_obj
                            .set_property("method".to_string(), Value::String(method_n.clone()));
                        param_obj
                            .set_property("isVariadic".to_string(), Value::Bool(info.is_variadic));
                        param_obj.set_property(
                            "hasDefault".to_string(),
                            Value::Bool(info.default.is_some()),
                        );
                        if let Some(ref default) = info.default {
                            let default_val = match default {
                                Literal::Null => Value::Null,
                                Literal::Bool(b) => Value::Bool(*b),
                                Literal::Long(n) => Value::Long(*n),
                                Literal::Double(f) => Value::Double(*f),
                                Literal::String(s) if s == "__EMPTY_ARRAY__" => {
                                    Value::Array(PhpArray::new())
                                }
                                Literal::String(s) => Value::String(s.clone()),
                                Literal::ClassConst(class_ref, cname) => {
                                    let resolved_class =
                                        if class_ref == "self" || class_ref == "static" {
                                            class_name.clone()
                                        } else {
                                            class_ref.clone()
                                        };
                                    self.resolve_class_constant(&resolved_class, cname)
                                        .unwrap_or(Value::Null)
                                }
                                Literal::LongJumpTable(_) | Literal::StringJumpTable(_) => {
                                    Value::Null
                                }
                            };
                            param_obj.set_property("defaultValue".to_string(), default_val);
                        }
                        // Type info from compile-time type hints
                        let type_name = self.op_arrays[idx]
                            .arg_info
                            .get(i)
                            .and_then(|a| a.type_name.clone());
                        param_obj
                            .set_property("hasType".to_string(), Value::Bool(type_name.is_some()));
                        if let Some(ref tn) = type_name {
                            param_obj
                                .set_property("typeName".to_string(), Value::String(tn.clone()));
                        }
                        params.push(Value::Object(param_obj));
                    }
                }
                Ok(Some(Value::Array(params)))
            }

            "getAttributes" => Ok(Some(Value::Array(PhpArray::new()))),

            "getDeclaringClass" => {
                let rc_obj = PhpObject::new("ReflectionClass".to_string());
                rc_obj.set_property("name".to_string(), Value::String(class_name.clone()));
                rc_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                rc_obj.set_internal(crate::value::InternalState::ReflectionClass);
                let obj_id = rc_obj.object_id();
                self.reflection_classes.insert(obj_id, class_name.clone());
                Ok(Some(Value::Object(rc_obj)))
            }

            "isPublic" => {
                // For now assume all methods are public
                Ok(Some(Value::Bool(true)))
            }

            "isStatic" => Ok(Some(Value::Bool(false))),

            "getNumberOfParameters" | "getNumberOfRequiredParameters" => {
                let full_name = format!("{}::{}", class_name, method_n);
                let oa_idx = self
                    .functions
                    .get(&full_name)
                    .copied()
                    .or_else(|| self.resolve_method(&class_name, &method_n));
                let count = if let Some(idx) = oa_idx {
                    let info = &self.op_arrays[idx].arg_info;
                    if method_name == "getNumberOfRequiredParameters" {
                        info.iter()
                            .filter(|a| a.default.is_none() && !a.is_variadic)
                            .count()
                    } else {
                        info.len()
                    }
                } else {
                    0
                };
                Ok(Some(Value::Long(count as i64)))
            }

            "invoke" | "invokeArgs" => {
                // invoke($object, ...$args) or invokeArgs($object, $args)
                let full_name = format!("{}::{}", class_name, method_n);
                let target_obj = args.get(1).cloned().unwrap_or(Value::Null);
                let call_args = if method_name == "invokeArgs" {
                    match args.get(2) {
                        Some(Value::Array(a)) => {
                            a.entries().iter().map(|(_, v)| v.clone()).collect()
                        }
                        _ => Vec::new(),
                    }
                } else {
                    args.get(2..).map(|s| s.to_vec()).unwrap_or_default()
                };
                let mut full_args = vec![target_obj];
                full_args.extend(call_args);
                let result = self.invoke_user_callback(&full_name, full_args)?;
                Ok(Some(result))
            }

            _ => Ok(None),
        }
    }

    /// Handle ReflectionParameter::* calls.
    pub(crate) fn try_reflection_parameter_call(
        &mut self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let method_name = if let Some(m) = func_name.strip_prefix("ReflectionParameter::") {
            m
        } else {
            return Ok(None);
        };

        let obj = match args.first() {
            Some(Value::Object(o)) if o.class_name() == "ReflectionParameter" => o.clone(),
            _ => return Ok(None),
        };

        match method_name {
            "getName" => {
                let name = obj
                    .get_property("name")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(name)))
            }

            "isVariadic" => {
                let v = obj
                    .get_property("isVariadic")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(v)))
            }

            "hasType" => {
                let v = obj
                    .get_property("hasType")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(v)))
            }

            "getType" => {
                // Return null if no type hint (causes Util::getParameterClassName to return null)
                let has_type = obj
                    .get_property("hasType")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                if has_type {
                    let type_name = obj
                        .get_property("typeName")
                        .map(|v| v.to_php_string())
                        .unwrap_or_default();
                    let type_obj = PhpObject::new("ReflectionNamedType".to_string());
                    let is_builtin = matches!(
                        type_name.as_str(),
                        "int"
                            | "float"
                            | "string"
                            | "bool"
                            | "array"
                            | "callable"
                            | "iterable"
                            | "object"
                            | "mixed"
                            | "void"
                            | "never"
                            | "null"
                            | "false"
                            | "true"
                    );
                    type_obj.set_property("name".to_string(), Value::String(type_name));
                    type_obj.set_property("isBuiltin".to_string(), Value::Bool(is_builtin));
                    type_obj.set_property("allowsNull".to_string(), Value::Bool(false));
                    Ok(Some(Value::Object(type_obj)))
                } else {
                    Ok(Some(Value::Null))
                }
            }

            "isDefaultValueAvailable" => {
                let v = obj
                    .get_property("hasDefault")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(v)))
            }

            "getDefaultValue" => {
                let val = obj.get_property("defaultValue").unwrap_or(Value::Null);
                Ok(Some(val))
            }

            "allowsNull" => {
                // For now, return false unless the type is nullable
                Ok(Some(Value::Bool(false)))
            }

            "getDeclaringClass" => {
                let class_name = obj
                    .get_property("class")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                if !class_name.is_empty() {
                    let refl_obj = PhpObject::new("ReflectionClass".to_string());
                    refl_obj.set_property("name".to_string(), Value::String(class_name.clone()));
                    refl_obj.set_internal(crate::value::InternalState::ReflectionClass);
                    refl_obj.set_object_id(self.next_object_id);
                    let obj_id = self.next_object_id;
                    self.next_object_id += 1;
                    self.reflection_classes.insert(obj_id, class_name);
                    Ok(Some(Value::Object(refl_obj)))
                } else {
                    Ok(Some(Value::Null))
                }
            }

            "getAttributes" => Ok(Some(Value::Array(PhpArray::new()))),

            _ => Ok(None),
        }
    }

    /// Handle ReflectionNamedType::* calls.
    pub(crate) fn try_reflection_named_type_call(
        &self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let method_name = if let Some(m) = func_name.strip_prefix("ReflectionNamedType::") {
            m
        } else {
            return Ok(None);
        };

        let obj = match args.first() {
            Some(Value::Object(o)) if o.class_name() == "ReflectionNamedType" => o.clone(),
            _ => return Ok(None),
        };

        match method_name {
            "getName" => {
                let name = obj
                    .get_property("name")
                    .map(|v| v.to_php_string())
                    .unwrap_or_default();
                Ok(Some(Value::String(name)))
            }
            "isBuiltin" => {
                let v = obj
                    .get_property("isBuiltin")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(v)))
            }
            "allowsNull" => {
                let v = obj
                    .get_property("allowsNull")
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Ok(Some(Value::Bool(v)))
            }
            _ => Ok(None),
        }
    }

    /// Check if a class implements an interface (walking parent chain).
    pub(crate) fn class_implements_interface(
        &self,
        class_name: &str,
        interface_name: &str,
    ) -> bool {
        let mut current = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&current) {
                if class_def.interfaces.contains(&interface_name.to_string()) {
                    return true;
                }
                // Also check traits' interfaces
                for trait_name in &class_def.traits {
                    if let Some(trait_def) = self.classes.get(trait_name) {
                        if trait_def.interfaces.contains(&interface_name.to_string()) {
                            return true;
                        }
                    }
                }
                if let Some(ref parent) = class_def.parent {
                    current = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        false
    }

    /// Check if a class is a subclass of another.
    pub(crate) fn class_is_subclass_of(&self, class_name: &str, parent_name: &str) -> bool {
        let mut current = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&current) {
                if let Some(ref parent) = class_def.parent {
                    if parent == parent_name {
                        return true;
                    }
                    current = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        false
    }
}
