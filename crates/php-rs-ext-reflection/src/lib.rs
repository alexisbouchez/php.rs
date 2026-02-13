//! PHP Reflection extension.
//!
//! Provides classes for introspecting PHP classes, functions, methods, properties,
//! parameters, types, attributes, and enums at runtime.
//! Reference: php-src/ext/reflection/

use std::fmt;

// ── Visibility ──────────────────────────────────────────────────────────────

/// PHP member visibility (public, protected, private).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Protected,
    Private,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Protected => write!(f, "protected"),
            Visibility::Private => write!(f, "private"),
        }
    }
}

// ── ReflectionType / ReflectionNamedType ─────────────────────────────────────

/// Represents a PHP type declaration.
///
/// Corresponds to `ReflectionType` / `ReflectionNamedType` in PHP.
/// Covers single named types (int, string, Foo), nullable types (?int),
/// and tracks whether the type is a PHP built-in.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionType {
    /// The type name (e.g. "int", "string", "Foo", "array").
    pub name: String,
    /// Whether null is allowed (e.g. ?int or int|null).
    pub allows_null: bool,
    /// Whether this is a built-in type (int, string, float, bool, array, object, etc.)
    /// as opposed to a user-defined class/interface.
    pub is_builtin: bool,
}

impl ReflectionType {
    pub fn new(name: impl Into<String>, allows_null: bool, is_builtin: bool) -> Self {
        Self {
            name: name.into(),
            allows_null,
            is_builtin,
        }
    }

    /// Returns the string representation of the type.
    pub fn type_string(&self) -> String {
        if self.allows_null && self.name != "mixed" && self.name != "null" {
            format!("?{}", self.name)
        } else {
            self.name.clone()
        }
    }

    /// Built-in type names recognized by PHP.
    const BUILTIN_TYPES: &'static [&'static str] = &[
        "int", "float", "string", "bool", "array", "object", "callable", "iterable", "void",
        "never", "null", "false", "true", "mixed", "self", "parent", "static",
    ];

    /// Creates a ReflectionType from a type name, auto-detecting whether it is built-in.
    pub fn from_name(name: impl Into<String>, allows_null: bool) -> Self {
        let name = name.into();
        let is_builtin = Self::BUILTIN_TYPES.contains(&name.as_str());
        Self {
            name,
            allows_null,
            is_builtin,
        }
    }
}

impl fmt::Display for ReflectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_string())
    }
}

// ── ReflectionParameter ─────────────────────────────────────────────────────

/// A PHP function/method parameter.
///
/// Corresponds to `ReflectionParameter` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionParameter {
    /// Parameter name (without the $ prefix).
    pub name: String,
    /// Zero-based position in the parameter list.
    pub position: usize,
    /// Declared type, if any.
    pub param_type: Option<ReflectionType>,
    /// Whether the parameter has a default value.
    pub has_default: bool,
    /// Default value as a string representation (e.g. "null", "42", "'hello'").
    pub default_value: Option<String>,
    /// Whether the parameter is optional (has a default or is variadic).
    pub is_optional: bool,
    /// Whether the parameter is variadic (...$param).
    pub is_variadic: bool,
    /// Whether the parameter is passed by reference (&$param).
    pub is_passed_by_reference: bool,
}

impl ReflectionParameter {
    pub fn new(name: impl Into<String>, position: usize) -> Self {
        Self {
            name: name.into(),
            position,
            param_type: None,
            has_default: false,
            default_value: None,
            is_optional: false,
            is_variadic: false,
            is_passed_by_reference: false,
        }
    }

    /// Set the type of this parameter.
    pub fn with_type(mut self, param_type: ReflectionType) -> Self {
        self.param_type = Some(param_type);
        self
    }

    /// Set the default value.
    pub fn with_default(mut self, value: impl Into<String>) -> Self {
        self.has_default = true;
        self.default_value = Some(value.into());
        self.is_optional = true;
        self
    }

    /// Mark as variadic.
    pub fn variadic(mut self) -> Self {
        self.is_variadic = true;
        self.is_optional = true;
        self
    }

    /// Mark as pass-by-reference.
    pub fn by_reference(mut self) -> Self {
        self.is_passed_by_reference = true;
        self
    }

    /// Returns the type, if declared.
    pub fn get_type(&self) -> Option<&ReflectionType> {
        self.param_type.as_ref()
    }

    /// Returns the name of the parameter.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the zero-based position.
    pub fn get_position(&self) -> usize {
        self.position
    }
}

impl fmt::Display for ReflectionParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref ty) = self.param_type {
            write!(f, "{} ", ty)?;
        }
        if self.is_passed_by_reference {
            write!(f, "&")?;
        }
        if self.is_variadic {
            write!(f, "...")?;
        }
        write!(f, "${}", self.name)?;
        if self.has_default {
            if let Some(ref val) = self.default_value {
                write!(f, " = {}", val)?;
            }
        }
        Ok(())
    }
}

// ── ReflectionFunction ──────────────────────────────────────────────────────

/// A PHP function (user-defined or internal).
///
/// Corresponds to `ReflectionFunction` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionFunction {
    /// Function name.
    pub name: String,
    /// Parameters.
    pub parameters: Vec<ReflectionParameter>,
    /// Return type, if declared.
    pub return_type: Option<ReflectionType>,
    /// Whether this is an internal (built-in) function.
    pub is_internal: bool,
    /// Whether this is a user-defined function.
    pub is_user_defined: bool,
    /// Whether this is a generator function (contains yield).
    pub is_generator: bool,
    /// Whether this is a closure.
    pub is_closure: bool,
    /// Whether this function is deprecated.
    pub is_deprecated: bool,
    /// Whether this function returns by reference.
    pub returns_reference: bool,
    /// Whether this function is variadic.
    pub is_variadic: bool,
    /// The file this function was defined in (None for internal functions).
    pub file_name: Option<String>,
    /// The start line (None for internal functions).
    pub start_line: Option<u32>,
    /// The end line (None for internal functions).
    pub end_line: Option<u32>,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionFunction {
    /// Create a new ReflectionFunction for a user-defined function.
    pub fn new_user(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            return_type: None,
            is_internal: false,
            is_user_defined: true,
            is_generator: false,
            is_closure: false,
            is_deprecated: false,
            returns_reference: false,
            is_variadic: false,
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Create a new ReflectionFunction for an internal (built-in) function.
    pub fn new_internal(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            return_type: None,
            is_internal: true,
            is_user_defined: false,
            is_generator: false,
            is_closure: false,
            is_deprecated: false,
            returns_reference: false,
            is_variadic: false,
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, param: ReflectionParameter) {
        self.parameters.push(param);
    }

    /// Set the return type.
    pub fn set_return_type(&mut self, return_type: ReflectionType) {
        self.return_type = Some(return_type);
    }

    /// Get the number of parameters.
    pub fn get_number_of_parameters(&self) -> usize {
        self.parameters.len()
    }

    /// Get the number of required (non-optional) parameters.
    pub fn get_number_of_required_parameters(&self) -> usize {
        self.parameters.iter().filter(|p| !p.is_optional).count()
    }

    /// Get the parameters.
    pub fn get_parameters(&self) -> &[ReflectionParameter] {
        &self.parameters
    }

    /// Get a parameter by name.
    pub fn get_parameter(&self, name: &str) -> Option<&ReflectionParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }

    /// Get the return type.
    pub fn get_return_type(&self) -> Option<&ReflectionType> {
        self.return_type.as_ref()
    }

    /// Get the function name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for ReflectionFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Function [ ")?;
        if self.is_internal {
            write!(f, "<internal>")?;
        } else {
            write!(f, "<user>")?;
        }
        write!(f, " function {} ]", self.name)
    }
}

// ── ReflectionProperty ──────────────────────────────────────────────────────

/// A PHP class property.
///
/// Corresponds to `ReflectionProperty` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionProperty {
    /// Property name (without the $ prefix).
    pub name: String,
    /// Declaring class name.
    pub class: String,
    /// Visibility.
    pub visibility: Visibility,
    /// Whether this is a static property.
    pub is_static: bool,
    /// Whether this property is readonly.
    pub is_readonly: bool,
    /// Whether this property has a default value.
    pub has_default: bool,
    /// Default value as a string representation.
    pub default_value: Option<String>,
    /// Declared type, if any.
    pub property_type: Option<ReflectionType>,
    /// Whether this property is promoted (constructor promotion).
    pub is_promoted: bool,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionProperty {
    pub fn new(name: impl Into<String>, class: impl Into<String>, visibility: Visibility) -> Self {
        Self {
            name: name.into(),
            class: class.into(),
            visibility,
            is_static: false,
            is_readonly: false,
            has_default: false,
            default_value: None,
            property_type: None,
            is_promoted: false,
            doc_comment: None,
        }
    }

    /// Whether this property is public.
    pub fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    /// Whether this property is protected.
    pub fn is_protected(&self) -> bool {
        self.visibility == Visibility::Protected
    }

    /// Whether this property is private.
    pub fn is_private(&self) -> bool {
        self.visibility == Visibility::Private
    }

    /// Get the property name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the declaring class name.
    pub fn get_declaring_class(&self) -> &str {
        &self.class
    }

    /// Get the type, if declared.
    pub fn get_type(&self) -> Option<&ReflectionType> {
        self.property_type.as_ref()
    }

    /// Get the default value.
    pub fn get_default_value(&self) -> Option<&str> {
        self.default_value.as_deref()
    }

    /// Check if the property has a default value.
    pub fn has_default_value(&self) -> bool {
        self.has_default
    }
}

impl fmt::Display for ReflectionProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Property [ {} ", self.visibility)?;
        if self.is_static {
            write!(f, "static ")?;
        }
        if self.is_readonly {
            write!(f, "readonly ")?;
        }
        if let Some(ref ty) = self.property_type {
            write!(f, "{} ", ty)?;
        }
        write!(f, "${} ]", self.name)
    }
}

// ── ReflectionMethod ────────────────────────────────────────────────────────

/// A PHP class method.
///
/// Corresponds to `ReflectionMethod` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionMethod {
    /// Method name.
    pub name: String,
    /// Declaring class name.
    pub class: String,
    /// Visibility.
    pub visibility: Visibility,
    /// Whether this is a static method.
    pub is_static: bool,
    /// Whether this is an abstract method.
    pub is_abstract: bool,
    /// Whether this is a final method.
    pub is_final: bool,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Whether this method returns by reference.
    pub returns_reference: bool,
    /// Whether this is a generator method.
    pub is_generator: bool,
    /// Whether this method is deprecated.
    pub is_deprecated: bool,
    /// Whether this method is variadic.
    pub is_variadic: bool,
    /// Whether this is an internal (built-in) method.
    pub is_internal: bool,
    /// Whether this is a user-defined method.
    pub is_user_defined: bool,
    /// Parameters.
    pub parameters: Vec<ReflectionParameter>,
    /// Return type, if declared.
    pub return_type: Option<ReflectionType>,
    /// The file this method was defined in (None for internal methods).
    pub file_name: Option<String>,
    /// The start line (None for internal methods).
    pub start_line: Option<u32>,
    /// The end line (None for internal methods).
    pub end_line: Option<u32>,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionMethod {
    pub fn new(name: impl Into<String>, class: impl Into<String>, visibility: Visibility) -> Self {
        Self {
            name: name.into(),
            class: class.into(),
            visibility,
            is_static: false,
            is_abstract: false,
            is_final: false,
            is_constructor: false,
            is_destructor: false,
            returns_reference: false,
            is_generator: false,
            is_deprecated: false,
            is_variadic: false,
            is_internal: false,
            is_user_defined: true,
            parameters: Vec::new(),
            return_type: None,
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, param: ReflectionParameter) {
        self.parameters.push(param);
    }

    /// Set the return type.
    pub fn set_return_type(&mut self, return_type: ReflectionType) {
        self.return_type = Some(return_type);
    }

    /// Whether this method is public.
    pub fn is_public(&self) -> bool {
        self.visibility == Visibility::Public
    }

    /// Whether this method is protected.
    pub fn is_protected(&self) -> bool {
        self.visibility == Visibility::Protected
    }

    /// Whether this method is private.
    pub fn is_private(&self) -> bool {
        self.visibility == Visibility::Private
    }

    /// Get the method name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the declaring class name.
    pub fn get_declaring_class(&self) -> &str {
        &self.class
    }

    /// Get the number of parameters.
    pub fn get_number_of_parameters(&self) -> usize {
        self.parameters.len()
    }

    /// Get the number of required (non-optional) parameters.
    pub fn get_number_of_required_parameters(&self) -> usize {
        self.parameters.iter().filter(|p| !p.is_optional).count()
    }

    /// Get the parameters.
    pub fn get_parameters(&self) -> &[ReflectionParameter] {
        &self.parameters
    }

    /// Get the return type.
    pub fn get_return_type(&self) -> Option<&ReflectionType> {
        self.return_type.as_ref()
    }
}

impl fmt::Display for ReflectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Method [ ")?;
        if self.is_abstract {
            write!(f, "abstract ")?;
        }
        if self.is_final {
            write!(f, "final ")?;
        }
        write!(f, "{} ", self.visibility)?;
        if self.is_static {
            write!(f, "static ")?;
        }
        write!(f, "method {} ]", self.name)
    }
}

// ── ReflectionAttribute ─────────────────────────────────────────────────────

/// Target for a PHP attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeTarget {
    Class,
    Function,
    Method,
    Property,
    ClassConstant,
    Parameter,
    All,
}

impl fmt::Display for AttributeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttributeTarget::Class => write!(f, "class"),
            AttributeTarget::Function => write!(f, "function"),
            AttributeTarget::Method => write!(f, "method"),
            AttributeTarget::Property => write!(f, "property"),
            AttributeTarget::ClassConstant => write!(f, "class constant"),
            AttributeTarget::Parameter => write!(f, "parameter"),
            AttributeTarget::All => write!(f, "all"),
        }
    }
}

/// A PHP attribute (#[Attr(args)]).
///
/// Corresponds to `ReflectionAttribute` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionAttribute {
    /// Attribute class name.
    pub name: String,
    /// Arguments passed to the attribute constructor (as string representations).
    pub arguments: Vec<String>,
    /// The target this attribute is applied to.
    pub target: AttributeTarget,
    /// Whether the attribute is repeated (multiple of the same attribute).
    pub is_repeated: bool,
}

impl ReflectionAttribute {
    pub fn new(name: impl Into<String>, target: AttributeTarget) -> Self {
        Self {
            name: name.into(),
            arguments: Vec::new(),
            target,
            is_repeated: false,
        }
    }

    /// Add an argument to this attribute.
    pub fn add_argument(&mut self, arg: impl Into<String>) {
        self.arguments.push(arg.into());
    }

    /// Create an attribute with arguments.
    pub fn with_arguments(
        name: impl Into<String>,
        arguments: Vec<String>,
        target: AttributeTarget,
    ) -> Self {
        Self {
            name: name.into(),
            arguments,
            target,
            is_repeated: false,
        }
    }

    /// Get the attribute name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the arguments.
    pub fn get_arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Get the target.
    pub fn get_target(&self) -> AttributeTarget {
        self.target
    }
}

impl fmt::Display for ReflectionAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Attribute [ {} ]", self.name)
    }
}

// ── ReflectionEnumCase ──────────────────────────────────────────────────────

/// A case in a PHP enum.
///
/// Corresponds to `ReflectionEnumUnitCase` and `ReflectionEnumBackedCase` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionEnumCase {
    /// Case name.
    pub name: String,
    /// Backing value for backed enums (int or string). None for unit enums.
    pub value: Option<String>,
    /// The enum this case belongs to.
    pub enum_name: String,
    /// Attributes on this case.
    pub attributes: Vec<ReflectionAttribute>,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionEnumCase {
    /// Create a unit enum case (no backing value).
    pub fn new_unit(name: impl Into<String>, enum_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
            enum_name: enum_name.into(),
            attributes: Vec::new(),
            doc_comment: None,
        }
    }

    /// Create a backed enum case with a value.
    pub fn new_backed(
        name: impl Into<String>,
        value: impl Into<String>,
        enum_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            enum_name: enum_name.into(),
            attributes: Vec::new(),
            doc_comment: None,
        }
    }

    /// Get the case name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the backing value (for backed enums).
    pub fn get_backing_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Whether this is a backed case.
    pub fn is_backed(&self) -> bool {
        self.value.is_some()
    }
}

impl fmt::Display for ReflectionEnumCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Constant [ public {} {} ", self.enum_name, self.name)?;
        if let Some(ref val) = self.value {
            write!(f, "= {} ", val)?;
        }
        write!(f, "]")
    }
}

// ── ReflectionEnum ──────────────────────────────────────────────────────────

/// A PHP enum.
///
/// Corresponds to `ReflectionEnum` in PHP. Extends ReflectionClass conceptually.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionEnum {
    /// Enum name.
    pub name: String,
    /// Backing type ("int" or "string"), None for unit enums.
    pub backed_type: Option<ReflectionType>,
    /// Enum cases.
    pub cases: Vec<ReflectionEnumCase>,
    /// Methods defined on the enum.
    pub methods: Vec<ReflectionMethod>,
    /// Interfaces implemented by the enum.
    pub interfaces: Vec<String>,
    /// Traits used by the enum.
    pub traits: Vec<String>,
    /// Constants defined on the enum (separate from cases).
    pub constants: Vec<(String, String)>,
    /// Attributes on the enum.
    pub attributes: Vec<ReflectionAttribute>,
    /// The file this enum was defined in.
    pub file_name: Option<String>,
    /// The start line.
    pub start_line: Option<u32>,
    /// The end line.
    pub end_line: Option<u32>,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionEnum {
    /// Create a new unit enum (no backing type).
    pub fn new_unit(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            backed_type: None,
            cases: Vec::new(),
            methods: Vec::new(),
            interfaces: Vec::new(),
            traits: Vec::new(),
            constants: Vec::new(),
            attributes: Vec::new(),
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Create a new backed enum.
    pub fn new_backed(name: impl Into<String>, backing_type: ReflectionType) -> Self {
        Self {
            name: name.into(),
            backed_type: Some(backing_type),
            cases: Vec::new(),
            methods: Vec::new(),
            interfaces: Vec::new(),
            traits: Vec::new(),
            constants: Vec::new(),
            attributes: Vec::new(),
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Add a case to this enum.
    pub fn add_case(&mut self, case: ReflectionEnumCase) {
        self.cases.push(case);
    }

    /// Get all cases.
    pub fn get_cases(&self) -> &[ReflectionEnumCase] {
        &self.cases
    }

    /// Get a case by name.
    pub fn get_case(&self, name: &str) -> Option<&ReflectionEnumCase> {
        self.cases.iter().find(|c| c.name == name)
    }

    /// Whether this is a backed enum.
    pub fn is_backed(&self) -> bool {
        self.backed_type.is_some()
    }

    /// Get the backing type.
    pub fn get_backing_type(&self) -> Option<&ReflectionType> {
        self.backed_type.as_ref()
    }

    /// Get the enum name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Whether this enum has a specific case.
    pub fn has_case(&self, name: &str) -> bool {
        self.cases.iter().any(|c| c.name == name)
    }
}

impl fmt::Display for ReflectionEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enum [ <user> enum {} ", self.name)?;
        if let Some(ref bt) = self.backed_type {
            write!(f, ": {} ", bt)?;
        }
        write!(f, "]")
    }
}

// ── ReflectionClass ─────────────────────────────────────────────────────────

/// A PHP class, interface, or trait.
///
/// Corresponds to `ReflectionClass` in PHP.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflectionClass {
    /// Class name (fully qualified without leading backslash).
    pub name: String,
    /// Parent class name, if any.
    pub parent: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Used traits.
    pub traits: Vec<String>,
    /// Methods.
    pub methods: Vec<ReflectionMethod>,
    /// Properties.
    pub properties: Vec<ReflectionProperty>,
    /// Class constants as (name, value_repr) pairs.
    pub constants: Vec<(String, String)>,
    /// Whether this class is abstract.
    pub is_abstract: bool,
    /// Whether this class is final.
    pub is_final: bool,
    /// Whether this class is readonly (PHP 8.2+).
    pub is_readonly: bool,
    /// Whether this is an interface.
    pub is_interface: bool,
    /// Whether this is a trait.
    pub is_trait: bool,
    /// Whether this is an enum.
    pub is_enum: bool,
    /// Whether this is an anonymous class.
    pub is_anonymous: bool,
    /// Whether this class can be instantiated.
    pub is_instantiable: bool,
    /// Whether this is an internal (built-in) class.
    pub is_internal: bool,
    /// Whether this is a user-defined class.
    pub is_user_defined: bool,
    /// Attributes on the class.
    pub attributes: Vec<ReflectionAttribute>,
    /// The file this class was defined in (None for internal classes).
    pub file_name: Option<String>,
    /// The start line (None for internal classes).
    pub start_line: Option<u32>,
    /// The end line (None for internal classes).
    pub end_line: Option<u32>,
    /// Doc comment, if present.
    pub doc_comment: Option<String>,
}

impl ReflectionClass {
    /// Create a new ReflectionClass for a user-defined class.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: None,
            interfaces: Vec::new(),
            traits: Vec::new(),
            methods: Vec::new(),
            properties: Vec::new(),
            constants: Vec::new(),
            is_abstract: false,
            is_final: false,
            is_readonly: false,
            is_interface: false,
            is_trait: false,
            is_enum: false,
            is_anonymous: false,
            is_instantiable: true,
            is_internal: false,
            is_user_defined: true,
            attributes: Vec::new(),
            file_name: None,
            start_line: None,
            end_line: None,
            doc_comment: None,
        }
    }

    /// Create a new ReflectionClass for an interface.
    pub fn new_interface(name: impl Into<String>) -> Self {
        let mut rc = Self::new(name);
        rc.is_interface = true;
        rc.is_instantiable = false;
        rc
    }

    /// Create a new ReflectionClass for a trait.
    pub fn new_trait(name: impl Into<String>) -> Self {
        let mut rc = Self::new(name);
        rc.is_trait = true;
        rc.is_instantiable = false;
        rc
    }

    /// Create a new ReflectionClass for an abstract class.
    pub fn new_abstract(name: impl Into<String>) -> Self {
        let mut rc = Self::new(name);
        rc.is_abstract = true;
        rc.is_instantiable = false;
        rc
    }

    /// Get the class name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the parent class name.
    pub fn get_parent_class(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Get the interface names.
    pub fn get_interface_names(&self) -> &[String] {
        &self.interfaces
    }

    /// Get the trait names.
    pub fn get_trait_names(&self) -> &[String] {
        &self.traits
    }

    /// Add a method.
    pub fn add_method(&mut self, method: ReflectionMethod) {
        self.methods.push(method);
    }

    /// Add a property.
    pub fn add_property(&mut self, property: ReflectionProperty) {
        self.properties.push(property);
    }

    /// Add a constant.
    pub fn add_constant(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.constants.push((name.into(), value.into()));
    }

    /// Get all methods.
    pub fn get_methods(&self) -> &[ReflectionMethod] {
        &self.methods
    }

    /// Get a method by name.
    pub fn get_method(&self, name: &str) -> Option<&ReflectionMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Check if a method exists.
    pub fn has_method(&self, name: &str) -> bool {
        self.methods.iter().any(|m| m.name == name)
    }

    /// Get all properties.
    pub fn get_properties(&self) -> &[ReflectionProperty] {
        &self.properties
    }

    /// Get a property by name.
    pub fn get_property(&self, name: &str) -> Option<&ReflectionProperty> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// Check if a property exists.
    pub fn has_property(&self, name: &str) -> bool {
        self.properties.iter().any(|p| p.name == name)
    }

    /// Get all constants.
    pub fn get_constants(&self) -> &[(String, String)] {
        &self.constants
    }

    /// Get a constant by name.
    pub fn get_constant(&self, name: &str) -> Option<&str> {
        self.constants
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Check if a constant exists.
    pub fn has_constant(&self, name: &str) -> bool {
        self.constants.iter().any(|(n, _)| n == name)
    }

    /// Get the constructor method.
    pub fn get_constructor(&self) -> Option<&ReflectionMethod> {
        self.methods.iter().find(|m| m.is_constructor)
    }

    /// Whether this class has a constructor.
    pub fn has_constructor(&self) -> bool {
        self.methods.iter().any(|m| m.is_constructor)
    }

    /// Get methods filtered by visibility.
    pub fn get_methods_by_visibility(&self, visibility: Visibility) -> Vec<&ReflectionMethod> {
        self.methods
            .iter()
            .filter(|m| m.visibility == visibility)
            .collect()
    }

    /// Get properties filtered by visibility.
    pub fn get_properties_by_visibility(&self, visibility: Visibility) -> Vec<&ReflectionProperty> {
        self.properties
            .iter()
            .filter(|p| p.visibility == visibility)
            .collect()
    }

    /// Whether a given class name matches this class or any of its parents/interfaces.
    /// Note: This only checks the immediate class and direct interfaces, not the full
    /// hierarchy (which requires access to a class table).
    pub fn implements_interface(&self, interface_name: &str) -> bool {
        self.interfaces.iter().any(|i| i == interface_name)
    }

    /// Whether this class is a subclass of the given class.
    /// Note: Only checks immediate parent.
    pub fn is_subclass_of(&self, class_name: &str) -> bool {
        self.parent.as_deref() == Some(class_name)
    }
}

impl fmt::Display for ReflectionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Class [ ")?;
        if self.is_internal {
            write!(f, "<internal> ")?;
        } else {
            write!(f, "<user> ")?;
        }
        if self.is_abstract {
            write!(f, "abstract ")?;
        }
        if self.is_final {
            write!(f, "final ")?;
        }
        if self.is_readonly {
            write!(f, "readonly ")?;
        }
        if self.is_interface {
            write!(f, "interface ")?;
        } else if self.is_trait {
            write!(f, "trait ")?;
        } else if self.is_enum {
            write!(f, "enum ")?;
        } else {
            write!(f, "class ")?;
        }
        write!(f, "{}", self.name)?;
        if let Some(ref parent) = self.parent {
            write!(f, " extends {}", parent)?;
        }
        if !self.interfaces.is_empty() {
            if self.is_interface {
                write!(f, " extends {}", self.interfaces.join(", "))?;
            } else {
                write!(f, " implements {}", self.interfaces.join(", "))?;
            }
        }
        write!(f, " ]")
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReflectionType tests ────────────────────────────────────────────

    #[test]
    fn test_reflection_type_builtin() {
        let ty = ReflectionType::from_name("int", false);
        assert_eq!(ty.name, "int");
        assert!(!ty.allows_null);
        assert!(ty.is_builtin);
    }

    #[test]
    fn test_reflection_type_nullable() {
        let ty = ReflectionType::from_name("string", true);
        assert_eq!(ty.type_string(), "?string");
        assert!(ty.allows_null);
        assert!(ty.is_builtin);
    }

    #[test]
    fn test_reflection_type_user_class() {
        let ty = ReflectionType::from_name("MyClass", false);
        assert_eq!(ty.name, "MyClass");
        assert!(!ty.is_builtin);
    }

    #[test]
    fn test_reflection_type_mixed() {
        let ty = ReflectionType::from_name("mixed", true);
        // mixed implicitly allows null, so no ? prefix
        assert_eq!(ty.type_string(), "mixed");
    }

    #[test]
    fn test_reflection_type_display() {
        let ty = ReflectionType::new("array", false, true);
        assert_eq!(format!("{}", ty), "array");

        let ty = ReflectionType::new("float", true, true);
        assert_eq!(format!("{}", ty), "?float");
    }

    // ── ReflectionParameter tests ───────────────────────────────────────

    #[test]
    fn test_reflection_parameter_basic() {
        let param = ReflectionParameter::new("name", 0);
        assert_eq!(param.get_name(), "name");
        assert_eq!(param.get_position(), 0);
        assert!(!param.has_default);
        assert!(!param.is_optional);
        assert!(!param.is_variadic);
        assert!(!param.is_passed_by_reference);
        assert!(param.get_type().is_none());
    }

    #[test]
    fn test_reflection_parameter_with_type() {
        let param =
            ReflectionParameter::new("id", 0).with_type(ReflectionType::from_name("int", false));
        assert!(param.get_type().is_some());
        assert_eq!(param.get_type().unwrap().name, "int");
    }

    #[test]
    fn test_reflection_parameter_with_default() {
        let param = ReflectionParameter::new("limit", 1).with_default("10");
        assert!(param.has_default);
        assert!(param.is_optional);
        assert_eq!(param.default_value.as_deref(), Some("10"));
    }

    #[test]
    fn test_reflection_parameter_variadic() {
        let param = ReflectionParameter::new("args", 2)
            .with_type(ReflectionType::from_name("string", false))
            .variadic();
        assert!(param.is_variadic);
        assert!(param.is_optional);
        assert_eq!(format!("{}", param), "string ...$args");
    }

    #[test]
    fn test_reflection_parameter_by_reference() {
        let param = ReflectionParameter::new("output", 0).by_reference();
        assert!(param.is_passed_by_reference);
        assert_eq!(format!("{}", param), "&$output");
    }

    #[test]
    fn test_reflection_parameter_display_full() {
        let param = ReflectionParameter::new("value", 0)
            .with_type(ReflectionType::from_name("int", true))
            .with_default("null");
        assert_eq!(format!("{}", param), "?int $value = null");
    }

    // ── ReflectionFunction tests ────────────────────────────────────────

    #[test]
    fn test_reflection_function_user() {
        let mut func = ReflectionFunction::new_user("my_function");
        func.add_parameter(ReflectionParameter::new("x", 0));
        func.add_parameter(ReflectionParameter::new("y", 1).with_default("0"));
        func.set_return_type(ReflectionType::from_name("int", false));

        assert_eq!(func.get_name(), "my_function");
        assert!(!func.is_internal);
        assert!(func.is_user_defined);
        assert_eq!(func.get_number_of_parameters(), 2);
        assert_eq!(func.get_number_of_required_parameters(), 1);
        assert!(func.get_return_type().is_some());
        assert_eq!(func.get_return_type().unwrap().name, "int");
    }

    #[test]
    fn test_reflection_function_internal() {
        let func = ReflectionFunction::new_internal("strlen");
        assert!(func.is_internal);
        assert!(!func.is_user_defined);
        assert_eq!(func.get_name(), "strlen");
    }

    #[test]
    fn test_reflection_function_display() {
        let func = ReflectionFunction::new_user("foo");
        assert_eq!(format!("{}", func), "Function [ <user> function foo ]");

        let func = ReflectionFunction::new_internal("strlen");
        assert_eq!(
            format!("{}", func),
            "Function [ <internal> function strlen ]"
        );
    }

    #[test]
    fn test_reflection_function_get_parameter() {
        let mut func = ReflectionFunction::new_user("test");
        func.add_parameter(ReflectionParameter::new("a", 0));
        func.add_parameter(ReflectionParameter::new("b", 1));

        assert!(func.get_parameter("a").is_some());
        assert!(func.get_parameter("b").is_some());
        assert!(func.get_parameter("c").is_none());
    }

    // ── ReflectionProperty tests ────────────────────────────────────────

    #[test]
    fn test_reflection_property_basic() {
        let prop = ReflectionProperty::new("name", "User", Visibility::Public);
        assert_eq!(prop.get_name(), "name");
        assert_eq!(prop.get_declaring_class(), "User");
        assert!(prop.is_public());
        assert!(!prop.is_protected());
        assert!(!prop.is_private());
        assert!(!prop.is_static);
        assert!(!prop.is_readonly);
    }

    #[test]
    fn test_reflection_property_with_type_and_default() {
        let mut prop = ReflectionProperty::new("count", "Counter", Visibility::Private);
        prop.property_type = Some(ReflectionType::from_name("int", false));
        prop.has_default = true;
        prop.default_value = Some("0".to_string());

        assert!(prop.is_private());
        assert!(prop.has_default_value());
        assert_eq!(prop.get_default_value(), Some("0"));
        assert_eq!(prop.get_type().unwrap().name, "int");
    }

    #[test]
    fn test_reflection_property_display() {
        let mut prop = ReflectionProperty::new("instance", "Singleton", Visibility::Private);
        prop.is_static = true;
        prop.property_type = Some(ReflectionType::from_name("self", true));

        assert_eq!(
            format!("{}", prop),
            "Property [ private static ?self $instance ]"
        );
    }

    #[test]
    fn test_reflection_property_readonly() {
        let mut prop = ReflectionProperty::new("id", "Entity", Visibility::Public);
        prop.is_readonly = true;
        prop.property_type = Some(ReflectionType::from_name("int", false));

        assert!(prop.is_readonly);
        assert_eq!(format!("{}", prop), "Property [ public readonly int $id ]");
    }

    // ── ReflectionMethod tests ──────────────────────────────────────────

    #[test]
    fn test_reflection_method_basic() {
        let method = ReflectionMethod::new("doSomething", "MyClass", Visibility::Public);
        assert_eq!(method.get_name(), "doSomething");
        assert_eq!(method.get_declaring_class(), "MyClass");
        assert!(method.is_public());
        assert!(!method.is_static);
        assert!(!method.is_abstract);
        assert!(!method.is_final);
    }

    #[test]
    fn test_reflection_method_with_parameters() {
        let mut method = ReflectionMethod::new("setName", "User", Visibility::Public);
        method.add_parameter(
            ReflectionParameter::new("name", 0)
                .with_type(ReflectionType::from_name("string", false)),
        );
        method.set_return_type(ReflectionType::from_name("void", false));

        assert_eq!(method.get_number_of_parameters(), 1);
        assert_eq!(method.get_number_of_required_parameters(), 1);
        assert_eq!(method.get_return_type().unwrap().name, "void");
    }

    #[test]
    fn test_reflection_method_static_abstract() {
        let mut method = ReflectionMethod::new("create", "Factory", Visibility::Protected);
        method.is_static = true;
        method.is_abstract = true;

        assert!(method.is_static);
        assert!(method.is_abstract);
        assert!(method.is_protected());
        assert_eq!(
            format!("{}", method),
            "Method [ abstract protected static method create ]"
        );
    }

    #[test]
    fn test_reflection_method_constructor() {
        let mut method = ReflectionMethod::new("__construct", "User", Visibility::Public);
        method.is_constructor = true;
        method.add_parameter(
            ReflectionParameter::new("name", 0)
                .with_type(ReflectionType::from_name("string", false)),
        );
        method.add_parameter(
            ReflectionParameter::new("email", 1)
                .with_type(ReflectionType::from_name("string", false)),
        );
        method.add_parameter(
            ReflectionParameter::new("age", 2)
                .with_type(ReflectionType::from_name("int", false))
                .with_default("0"),
        );

        assert!(method.is_constructor);
        assert_eq!(method.get_number_of_parameters(), 3);
        assert_eq!(method.get_number_of_required_parameters(), 2);
    }

    #[test]
    fn test_reflection_method_display() {
        let method = ReflectionMethod::new("test", "Foo", Visibility::Public);
        assert_eq!(format!("{}", method), "Method [ public method test ]");

        let mut method = ReflectionMethod::new("bar", "Foo", Visibility::Private);
        method.is_final = true;
        assert_eq!(format!("{}", method), "Method [ final private method bar ]");
    }

    // ── ReflectionAttribute tests ───────────────────────────────────────

    #[test]
    fn test_reflection_attribute_basic() {
        let attr = ReflectionAttribute::new("Deprecated", AttributeTarget::Method);
        assert_eq!(attr.get_name(), "Deprecated");
        assert_eq!(attr.get_target(), AttributeTarget::Method);
        assert!(attr.get_arguments().is_empty());
    }

    #[test]
    fn test_reflection_attribute_with_arguments() {
        let attr = ReflectionAttribute::with_arguments(
            "Route",
            vec!["\"/users\"".to_string(), "\"GET\"".to_string()],
            AttributeTarget::Method,
        );
        assert_eq!(attr.get_arguments().len(), 2);
        assert_eq!(attr.get_arguments()[0], "\"/users\"");
    }

    #[test]
    fn test_reflection_attribute_add_argument() {
        let mut attr = ReflectionAttribute::new("Test", AttributeTarget::Class);
        attr.add_argument("'value'");
        assert_eq!(attr.get_arguments().len(), 1);
    }

    // ── ReflectionEnumCase tests ────────────────────────────────────────

    #[test]
    fn test_reflection_enum_case_unit() {
        let case = ReflectionEnumCase::new_unit("Hearts", "Suit");
        assert_eq!(case.get_name(), "Hearts");
        assert!(!case.is_backed());
        assert!(case.get_backing_value().is_none());
    }

    #[test]
    fn test_reflection_enum_case_backed() {
        let case = ReflectionEnumCase::new_backed("Active", "1", "Status");
        assert_eq!(case.get_name(), "Active");
        assert!(case.is_backed());
        assert_eq!(case.get_backing_value(), Some("1"));
    }

    // ── ReflectionEnum tests ────────────────────────────────────────────

    #[test]
    fn test_reflection_enum_unit() {
        let mut re = ReflectionEnum::new_unit("Suit");
        re.add_case(ReflectionEnumCase::new_unit("Hearts", "Suit"));
        re.add_case(ReflectionEnumCase::new_unit("Diamonds", "Suit"));
        re.add_case(ReflectionEnumCase::new_unit("Clubs", "Suit"));
        re.add_case(ReflectionEnumCase::new_unit("Spades", "Suit"));

        assert_eq!(re.get_name(), "Suit");
        assert!(!re.is_backed());
        assert_eq!(re.get_cases().len(), 4);
        assert!(re.has_case("Hearts"));
        assert!(!re.has_case("Joker"));
        assert!(re.get_case("Diamonds").is_some());
    }

    #[test]
    fn test_reflection_enum_backed() {
        let mut re =
            ReflectionEnum::new_backed("Color", ReflectionType::from_name("string", false));
        re.add_case(ReflectionEnumCase::new_backed("Red", "'red'", "Color"));
        re.add_case(ReflectionEnumCase::new_backed("Green", "'green'", "Color"));
        re.add_case(ReflectionEnumCase::new_backed("Blue", "'blue'", "Color"));

        assert!(re.is_backed());
        assert_eq!(re.get_backing_type().unwrap().name, "string");
        assert_eq!(re.get_cases().len(), 3);

        let red = re.get_case("Red").unwrap();
        assert_eq!(red.get_backing_value(), Some("'red'"));
    }

    #[test]
    fn test_reflection_enum_display() {
        let re = ReflectionEnum::new_unit("Suit");
        assert_eq!(format!("{}", re), "Enum [ <user> enum Suit ]");

        let re = ReflectionEnum::new_backed("Status", ReflectionType::from_name("int", false));
        assert_eq!(format!("{}", re), "Enum [ <user> enum Status : int ]");
    }

    // ── ReflectionClass tests ───────────────────────────────────────────

    #[test]
    fn test_reflection_class_basic() {
        let class = ReflectionClass::new("User");
        assert_eq!(class.get_name(), "User");
        assert!(class.get_parent_class().is_none());
        assert!(!class.is_abstract);
        assert!(!class.is_final);
        assert!(!class.is_interface);
        assert!(!class.is_trait);
        assert!(!class.is_enum);
        assert!(class.is_instantiable);
        assert!(class.is_user_defined);
        assert!(!class.is_internal);
    }

    #[test]
    fn test_reflection_class_with_parent() {
        let mut class = ReflectionClass::new("Admin");
        class.parent = Some("User".to_string());
        assert_eq!(class.get_parent_class(), Some("User"));
        assert!(class.is_subclass_of("User"));
        assert!(!class.is_subclass_of("Admin"));
    }

    #[test]
    fn test_reflection_class_with_interfaces() {
        let mut class = ReflectionClass::new("UserRepository");
        class.interfaces.push("Repository".to_string());
        class.interfaces.push("Countable".to_string());

        assert_eq!(class.get_interface_names().len(), 2);
        assert!(class.implements_interface("Repository"));
        assert!(class.implements_interface("Countable"));
        assert!(!class.implements_interface("Serializable"));
    }

    #[test]
    fn test_reflection_class_methods() {
        let mut class = ReflectionClass::new("Calculator");

        let mut constructor =
            ReflectionMethod::new("__construct", "Calculator", Visibility::Public);
        constructor.is_constructor = true;

        let mut add = ReflectionMethod::new("add", "Calculator", Visibility::Public);
        add.add_parameter(
            ReflectionParameter::new("a", 0).with_type(ReflectionType::from_name("int", false)),
        );
        add.add_parameter(
            ReflectionParameter::new("b", 1).with_type(ReflectionType::from_name("int", false)),
        );
        add.set_return_type(ReflectionType::from_name("int", false));

        let helper = ReflectionMethod::new("internalHelper", "Calculator", Visibility::Private);

        class.add_method(constructor);
        class.add_method(add);
        class.add_method(helper);

        assert_eq!(class.get_methods().len(), 3);
        assert!(class.has_method("add"));
        assert!(class.has_method("__construct"));
        assert!(!class.has_method("subtract"));
        assert!(class.has_constructor());

        let add_method = class.get_method("add").unwrap();
        assert_eq!(add_method.get_number_of_parameters(), 2);
        assert_eq!(add_method.get_return_type().unwrap().name, "int");

        let public_methods = class.get_methods_by_visibility(Visibility::Public);
        assert_eq!(public_methods.len(), 2);
        let private_methods = class.get_methods_by_visibility(Visibility::Private);
        assert_eq!(private_methods.len(), 1);
    }

    #[test]
    fn test_reflection_class_properties() {
        let mut class = ReflectionClass::new("User");

        let mut name_prop = ReflectionProperty::new("name", "User", Visibility::Private);
        name_prop.property_type = Some(ReflectionType::from_name("string", false));

        let mut age_prop = ReflectionProperty::new("age", "User", Visibility::Protected);
        age_prop.property_type = Some(ReflectionType::from_name("int", false));
        age_prop.has_default = true;
        age_prop.default_value = Some("0".to_string());

        let mut id_prop = ReflectionProperty::new("id", "User", Visibility::Public);
        id_prop.property_type = Some(ReflectionType::from_name("int", false));
        id_prop.is_readonly = true;

        class.add_property(name_prop);
        class.add_property(age_prop);
        class.add_property(id_prop);

        assert_eq!(class.get_properties().len(), 3);
        assert!(class.has_property("name"));
        assert!(class.has_property("age"));
        assert!(class.has_property("id"));
        assert!(!class.has_property("email"));

        let age = class.get_property("age").unwrap();
        assert!(age.has_default_value());
        assert_eq!(age.get_default_value(), Some("0"));
        assert!(age.is_protected());

        let id = class.get_property("id").unwrap();
        assert!(id.is_readonly);
        assert!(id.is_public());

        let public_props = class.get_properties_by_visibility(Visibility::Public);
        assert_eq!(public_props.len(), 1);
        assert_eq!(public_props[0].get_name(), "id");
    }

    #[test]
    fn test_reflection_class_constants() {
        let mut class = ReflectionClass::new("Http");
        class.add_constant("GET", "'GET'");
        class.add_constant("POST", "'POST'");
        class.add_constant("MAX_RETRIES", "3");

        assert_eq!(class.get_constants().len(), 3);
        assert!(class.has_constant("GET"));
        assert_eq!(class.get_constant("GET"), Some("'GET'"));
        assert_eq!(class.get_constant("MAX_RETRIES"), Some("3"));
        assert!(!class.has_constant("DELETE"));
    }

    #[test]
    fn test_reflection_class_interface() {
        let class = ReflectionClass::new_interface("Stringable");
        assert!(class.is_interface);
        assert!(!class.is_instantiable);
        assert!(!class.is_trait);
    }

    #[test]
    fn test_reflection_class_trait() {
        let class = ReflectionClass::new_trait("Timestampable");
        assert!(class.is_trait);
        assert!(!class.is_instantiable);
        assert!(!class.is_interface);
    }

    #[test]
    fn test_reflection_class_abstract() {
        let class = ReflectionClass::new_abstract("AbstractRepository");
        assert!(class.is_abstract);
        assert!(!class.is_instantiable);
    }

    #[test]
    fn test_reflection_class_display() {
        let class = ReflectionClass::new("Foo");
        assert_eq!(format!("{}", class), "Class [ <user> class Foo ]");

        let mut class = ReflectionClass::new_abstract("Bar");
        class.parent = Some("Foo".to_string());
        class.interfaces.push("Baz".to_string());
        assert_eq!(
            format!("{}", class),
            "Class [ <user> abstract class Bar extends Foo implements Baz ]"
        );

        let class = ReflectionClass::new_interface("Qux");
        assert_eq!(format!("{}", class), "Class [ <user> interface Qux ]");

        let class = ReflectionClass::new_trait("HasTimestamps");
        assert_eq!(format!("{}", class), "Class [ <user> trait HasTimestamps ]");
    }

    #[test]
    fn test_reflection_class_final_readonly() {
        let mut class = ReflectionClass::new("Config");
        class.is_final = true;
        class.is_readonly = true;

        assert!(class.is_final);
        assert!(class.is_readonly);
        assert_eq!(
            format!("{}", class),
            "Class [ <user> final readonly class Config ]"
        );
    }

    // ── Integration: method parameter introspection ─────────────────────

    #[test]
    fn test_method_parameter_introspection() {
        let mut class = ReflectionClass::new("UserService");

        let mut method = ReflectionMethod::new("createUser", "UserService", Visibility::Public);
        method.add_parameter(
            ReflectionParameter::new("name", 0)
                .with_type(ReflectionType::from_name("string", false)),
        );
        method.add_parameter(
            ReflectionParameter::new("email", 1)
                .with_type(ReflectionType::from_name("string", false)),
        );
        method.add_parameter(
            ReflectionParameter::new("roles", 2)
                .with_type(ReflectionType::from_name("array", false))
                .with_default("[]"),
        );
        method.set_return_type(ReflectionType::from_name("User", false));

        class.add_method(method);

        let method = class.get_method("createUser").unwrap();
        assert_eq!(method.get_number_of_parameters(), 3);
        assert_eq!(method.get_number_of_required_parameters(), 2);

        let params = method.get_parameters();

        // First param: string $name (required)
        assert_eq!(params[0].get_name(), "name");
        assert_eq!(params[0].get_type().unwrap().name, "string");
        assert!(params[0].get_type().unwrap().is_builtin);
        assert!(!params[0].is_optional);

        // Second param: string $email (required)
        assert_eq!(params[1].get_name(), "email");
        assert!(!params[1].is_optional);

        // Third param: array $roles = [] (optional)
        assert_eq!(params[2].get_name(), "roles");
        assert!(params[2].is_optional);
        assert!(params[2].has_default);
        assert_eq!(params[2].default_value.as_deref(), Some("[]"));

        // Return type
        let ret = method.get_return_type().unwrap();
        assert_eq!(ret.name, "User");
        assert!(!ret.is_builtin); // User is not a built-in type
    }

    #[test]
    fn test_parameter_type_checking() {
        // Test that ReflectionType correctly identifies built-in vs user types
        let builtin_types = vec![
            "int", "float", "string", "bool", "array", "object", "callable", "iterable", "void",
            "never", "null", "false", "true", "mixed", "self", "parent", "static",
        ];

        for type_name in &builtin_types {
            let ty = ReflectionType::from_name(*type_name, false);
            assert!(
                ty.is_builtin,
                "{} should be recognized as built-in",
                type_name
            );
        }

        let user_types = vec!["MyClass", "App\\Models\\User", "Iterator", "Closure"];
        for type_name in &user_types {
            let ty = ReflectionType::from_name(*type_name, false);
            assert!(
                !ty.is_builtin,
                "{} should NOT be recognized as built-in",
                type_name
            );
        }
    }

    // ── Visibility tests ────────────────────────────────────────────────

    #[test]
    fn test_visibility_display() {
        assert_eq!(format!("{}", Visibility::Public), "public");
        assert_eq!(format!("{}", Visibility::Protected), "protected");
        assert_eq!(format!("{}", Visibility::Private), "private");
    }

    // ── AttributeTarget tests ───────────────────────────────────────────

    #[test]
    fn test_attribute_target_display() {
        assert_eq!(format!("{}", AttributeTarget::Class), "class");
        assert_eq!(format!("{}", AttributeTarget::Method), "method");
        assert_eq!(format!("{}", AttributeTarget::Property), "property");
        assert_eq!(format!("{}", AttributeTarget::Parameter), "parameter");
        assert_eq!(format!("{}", AttributeTarget::Function), "function");
        assert_eq!(
            format!("{}", AttributeTarget::ClassConstant),
            "class constant"
        );
        assert_eq!(format!("{}", AttributeTarget::All), "all");
    }
}
