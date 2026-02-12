//! Output formatting — extracted from vm.rs.
//!
//! var_dump, print_r, var_export, JSON encoding/decoding helpers.

use php_rs_ext_json::{self, JsonValue};

use super::helpers::*;
use super::{Vm, VmResult};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    /// Convert a VM Value to a JsonValue for encoding.
    pub(crate) fn value_to_json(val: &Value) -> JsonValue {
        if let Value::Reference(rc) = val {
            return Self::value_to_json(&rc.borrow());
        }
        match val {
            Value::Null => JsonValue::Null,
            Value::Bool(b) => JsonValue::Bool(*b),
            Value::Long(n) => JsonValue::Int(*n),
            Value::Double(f) => JsonValue::Float(*f),
            Value::String(s) => JsonValue::Str(s.clone()),
            Value::Array(a) => {
                // Check if it's a sequential integer-keyed array (JSON array)
                // or an associative array (JSON object)
                let is_list = a
                    .entries()
                    .iter()
                    .enumerate()
                    .all(|(i, (k, _))| matches!(k, ArrayKey::Int(n) if *n == i as i64));
                if is_list {
                    JsonValue::Array(
                        a.entries()
                            .iter()
                            .map(|(_, v)| Self::value_to_json(v))
                            .collect(),
                    )
                } else {
                    JsonValue::Object(
                        a.entries()
                            .iter()
                            .map(|(k, v)| {
                                let key = match k {
                                    ArrayKey::Int(n) => n.to_string(),
                                    ArrayKey::String(s) => s.clone(),
                                };
                                (key, Self::value_to_json(v))
                            })
                            .collect(),
                    )
                }
            }
            Value::Object(o) => {
                // Encode public properties as a JSON object
                let props_map = o.properties();
                let mut entries: Vec<(String, JsonValue)> = props_map
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::value_to_json(v)))
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                JsonValue::Object(entries)
            }
            Value::Resource(_, _) => JsonValue::Null,
            Value::Reference(_) => unreachable!("Reference handled above"),
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => JsonValue::Null,
        }
    }

    /// Convert a JsonValue to a VM Value after decoding.
    pub(crate) fn json_to_value(jv: &JsonValue, assoc: bool) -> Value {
        match jv {
            JsonValue::Null => Value::Null,
            JsonValue::Bool(b) => Value::Bool(*b),
            JsonValue::Int(n) => Value::Long(*n),
            JsonValue::Float(f) => Value::Double(*f),
            JsonValue::Str(s) => Value::String(s.clone()),
            JsonValue::Array(items) => {
                let mut arr = PhpArray::new();
                for item in items {
                    arr.push(Self::json_to_value(item, assoc));
                }
                Value::Array(arr)
            }
            JsonValue::Object(entries) => {
                if assoc {
                    // Return as associative array
                    let mut arr = PhpArray::new();
                    for (k, v) in entries {
                        arr.set_string(k.clone(), Self::json_to_value(v, assoc));
                    }
                    Value::Array(arr)
                } else {
                    // Return as stdClass object
                    let obj = PhpObject::new("stdClass".to_string());
                    for (k, v) in entries {
                        obj.set_property(k.clone(), Self::json_to_value(v, assoc));
                    }
                    Value::Object(obj)
                }
            }
        }
    }

    // =========================================================================
    // var_dump implementation
    // =========================================================================

    pub(crate) fn var_dump(&mut self, val: &Value, depth: usize) {
        if let Value::Reference(rc) = val {
            let inner = rc.borrow().clone();
            return self.var_dump(&inner, depth);
        }
        let indent = "  ".repeat(depth);
        match val {
            Value::Null => {
                self.write_output(&format!("{}NULL\n", indent));
            }
            Value::Bool(b) => {
                self.write_output(&format!("{}bool({})\n", indent, b));
            }
            Value::Long(n) => {
                self.write_output(&format!("{}int({})\n", indent, n));
            }
            Value::Double(f) => {
                let s = format_php_float(*f);
                self.write_output(&format!("{}float({})\n", indent, s));
            }
            Value::String(s) => {
                self.write_output(&format!("{}string({}) \"{}\"\n", indent, s.len(), s));
            }
            Value::Array(a) => {
                self.write_output(&format!("{}array({}) {{\n", indent, a.len()));
                for (key, v) in a.entries() {
                    let key_str = match key {
                        crate::value::ArrayKey::Int(n) => format!("[{}]=>", n),
                        crate::value::ArrayKey::String(s) => format!("[\"{}\"]=>", s),
                    };
                    self.write_output(&format!("{}  {}\n", indent, key_str));
                    self.var_dump(v, depth + 1);
                }
                self.write_output(&format!("{}}}\n", indent));
            }
            Value::Object(o) => {
                // Check for __debugInfo magic method
                let class_name = o.class_name();
                let debug_info = self.find_magic_method(&class_name, "__debugInfo");
                if let Some(ref method_name) = debug_info {
                    let result = self.call_magic_method(method_name, val.clone(), vec![]);
                    if let Ok(Value::Array(ref debug_arr)) = result {
                        self.write_output(&format!(
                            "{}object({})#{} ({}) {{\n",
                            indent,
                            o.class_name(),
                            o.object_id(),
                            debug_arr.len()
                        ));
                        for (key, v) in debug_arr.entries() {
                            let key_str = match key {
                                crate::value::ArrayKey::Int(n) => format!("[{}]=>", n),
                                crate::value::ArrayKey::String(s) => format!("[\"{}\"]=>", s),
                            };
                            self.write_output(&format!("{}  {}\n", indent, key_str));
                            self.var_dump(v, depth + 1);
                        }
                        self.write_output(&format!("{}}}\n", indent));
                    } else {
                        // __debugInfo returned non-array, dump normally
                        self.write_output(&format!(
                            "{}object({})#{} ({}) {{\n",
                            indent,
                            o.class_name(),
                            o.object_id(),
                            o.properties_count()
                        ));
                        self.write_output(&format!("{}}}\n", indent));
                    }
                } else {
                    self.write_output(&format!(
                        "{}object({})#{} ({}) {{\n",
                        indent,
                        o.class_name(),
                        o.object_id(),
                        o.properties_count()
                    ));
                    let props_map = o.properties();
                    let mut props: Vec<_> = props_map.iter().collect();
                    props.sort_by_key(|(k, _)| (*k).clone());
                    for (name, val) in props {
                        self.write_output(&format!("{}  [\"{}\"]=>", indent, name));
                        self.write_output("\n");
                        self.var_dump(val, depth + 1);
                    }
                    self.write_output(&format!("{}}}\n", indent));
                }
            }
            Value::Resource(id, _) => {
                self.write_output(&format!("{}resource({}) of type (stream)\n", indent, id));
            }
            Value::Reference(_) => unreachable!("Reference handled above"),
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => {
                self.write_output(&format!("{}NULL\n", indent));
            }
        }
    }

    pub(crate) fn print_r_string(&self, val: &Value, depth: usize) -> String {
        if let Value::Reference(rc) = val {
            return self.print_r_string(&rc.borrow(), depth);
        }
        let indent = "    ".repeat(depth);
        match val {
            Value::Null => String::new(),
            Value::Bool(true) => "1".to_string(),
            Value::Bool(false) => String::new(),
            Value::Long(n) => n.to_string(),
            Value::Double(f) => format_php_float(*f),
            Value::String(s) => s.clone(),
            Value::Array(a) => {
                let mut s = "Array\n".to_string();
                s.push_str(&format!("{}(\n", indent));
                for (key, v) in a.entries() {
                    let key_str = match key {
                        crate::value::ArrayKey::Int(n) => n.to_string(),
                        crate::value::ArrayKey::String(s) => s.clone(),
                    };
                    let val_str = self.print_r_string(v, depth + 1);
                    s.push_str(&format!("{}    [{}] => {}\n", indent, key_str, val_str));
                }
                s.push_str(&format!("{})\n", indent));
                s
            }
            Value::Object(o) => {
                let mut s = format!("{} Object\n", o.class_name());
                s.push_str(&format!("{}(\n", indent));
                let props_map = o.properties();
                let mut props: Vec<_> = props_map.iter().collect();
                props.sort_by_key(|(k, _)| (*k).clone());
                for (name, val) in props {
                    let val_str = self.print_r_string(val, depth + 1);
                    s.push_str(&format!("{}    [{}] => {}\n", indent, name, val_str));
                }
                s.push_str(&format!("{})\n", indent));
                s
            }
            Value::Resource(id, _) => format!("Resource id #{}", id),
            Value::Reference(_) => unreachable!("Reference handled above"),
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => String::new(),
        }
    }

    pub(crate) fn var_export_string(&self, val: &Value) -> String {
        if let Value::Reference(rc) = val {
            return self.var_export_string(&rc.borrow());
        }
        match val {
            Value::Null => "NULL".to_string(),
            Value::Bool(true) => "true".to_string(),
            Value::Bool(false) => "false".to_string(),
            Value::Long(n) => n.to_string(),
            Value::Double(f) => format_php_float(*f),
            Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
            Value::Array(a) => {
                let mut s = "array (\n".to_string();
                for (key, v) in a.entries() {
                    let key_str = match key {
                        crate::value::ArrayKey::Int(n) => n.to_string(),
                        crate::value::ArrayKey::String(s) => format!("'{}'", s),
                    };
                    s.push_str(&format!(
                        "  {} => {},\n",
                        key_str,
                        self.var_export_string(v)
                    ));
                }
                s.push_str(")");
                s
            }
            Value::Object(o) => {
                format!("(object) array(/* {} properties */)", o.properties_count())
            }
            Value::Resource(_, _) => "NULL".to_string(),
            Value::Reference(_) => unreachable!("Reference handled above"),
            Value::_Iterator { .. }
            | Value::_GeneratorIterator { .. }
            | Value::_ObjectIterator { .. }
            | Value::_Rope(_) => "NULL".to_string(),
        }
    }
}
