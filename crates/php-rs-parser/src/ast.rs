//! Abstract Syntax Tree node definitions
//!
//! This module defines all AST nodes for PHP, matching the structure
//! from php-src/Zend/zend_language_parser.y

use php_rs_lexer::Span;

/// Top-level program node containing all statements
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub statements: Vec<Statement>,
}

/// Statement node - represents all PHP statements
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// Expression statement: `expr;`
    Expression { expr: Expression, span: Span },
    /// Echo statement: `echo expr [, expr...];`
    Echo { exprs: Vec<Expression>, span: Span },
    /// Return statement: `return [expr];`
    Return {
        value: Option<Box<Expression>>,
        span: Span,
    },
    /// If/elseif/else statement
    If {
        condition: Box<Expression>,
        then_branch: Box<Statement>,
        elseif_branches: Vec<(Expression, Statement)>,
        else_branch: Option<Box<Statement>>,
        span: Span,
    },
    /// While loop: `while (expr) stmt`
    While {
        condition: Box<Expression>,
        body: Box<Statement>,
        span: Span,
    },
    /// Do-while loop: `do stmt while (expr);`
    DoWhile {
        body: Box<Statement>,
        condition: Box<Expression>,
        span: Span,
    },
    /// For loop: `for (init; cond; inc) stmt`
    For {
        init: Vec<Expression>,
        condition: Vec<Expression>,
        increment: Vec<Expression>,
        body: Box<Statement>,
        span: Span,
    },
    /// Foreach loop: `foreach (expr as [$key =>] $value) stmt`
    Foreach {
        iterable: Box<Expression>,
        key: Option<Box<Expression>>,
        value: Box<Expression>,
        by_ref: bool,
        body: Box<Statement>,
        span: Span,
    },
    /// Switch statement
    Switch {
        condition: Box<Expression>,
        cases: Vec<SwitchCase>,
        span: Span,
    },
    /// Match expression (PHP 8.0+)
    Match {
        condition: Box<Expression>,
        arms: Vec<MatchArm>,
        span: Span,
    },
    /// Break statement: `break [depth];`
    Break {
        depth: Option<Box<Expression>>,
        span: Span,
    },
    /// Continue statement: `continue [depth];`
    Continue {
        depth: Option<Box<Expression>>,
        span: Span,
    },
    /// Declare statement: `declare(key=value) stmt`
    Declare {
        directives: Vec<(String, Expression)>,
        body: Box<Statement>,
        span: Span,
    },
    /// Namespace definition: `namespace Name;` or `namespace Name { ... }`
    Namespace {
        name: Option<Name>,
        statements: Vec<Statement>,
        span: Span,
    },
    /// Use declaration: `use Name [as Alias];`
    Use {
        uses: Vec<UseDeclaration>,
        kind: UseKind,
        span: Span,
    },
    /// Try-catch-finally block
    Try {
        body: Vec<Statement>,
        catches: Vec<CatchClause>,
        finally: Option<Vec<Statement>>,
        span: Span,
    },
    /// Throw statement: `throw expr;`
    Throw {
        exception: Box<Expression>,
        span: Span,
    },
    /// Global declaration: `global $var [, $var...];`
    Global { vars: Vec<Expression>, span: Span },
    /// Static declaration: `static $var [= expr] [, ...];`
    Static { vars: Vec<StaticVar>, span: Span },
    /// Unset statement: `unset($var [, $var...]);`
    Unset { vars: Vec<Expression>, span: Span },
    /// Class declaration
    Class {
        name: String,
        modifiers: Vec<Modifier>,
        extends: Option<Name>,
        implements: Vec<Name>,
        members: Vec<ClassMember>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Interface declaration
    Interface {
        name: String,
        extends: Vec<Name>,
        members: Vec<ClassMember>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Trait declaration
    Trait {
        name: String,
        members: Vec<ClassMember>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Enum declaration (PHP 8.1+)
    Enum {
        name: String,
        backing_type: Option<Type>,
        implements: Vec<Name>,
        members: Vec<EnumMember>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Function declaration
    Function {
        name: String,
        params: Vec<Parameter>,
        return_type: Option<Type>,
        body: Vec<Statement>,
        by_ref: bool,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Const declaration: `const NAME = value [, ...];`
    Const {
        consts: Vec<(String, Expression)>,
        span: Span,
    },
    /// Goto statement: `goto label;`
    Goto { label: String, span: Span },
    /// Label: `label:`
    Label { name: String, span: Span },
    /// Block statement: `{ statements }`
    Block {
        statements: Vec<Statement>,
        span: Span,
    },
    /// Inline HTML (outside of <?php tags)
    InlineHtml { content: String, span: Span },
    /// __halt_compiler();
    HaltCompiler { remaining: String, span: Span },
}

/// Expression node - represents all PHP expressions
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// Integer literal
    IntLiteral { value: i64, span: Span },
    /// Float literal
    FloatLiteral { value: f64, span: Span },
    /// String literal
    StringLiteral { value: String, span: Span },
    /// Boolean literal
    BoolLiteral { value: bool, span: Span },
    /// Null literal
    Null { span: Span },
    /// Variable: `$name`
    Variable { name: String, span: Span },
    /// Assignment: `lhs = rhs`
    Assign {
        lhs: Box<Expression>,
        rhs: Box<Expression>,
        span: Span,
    },
    /// Assignment by reference: `lhs =& rhs`
    AssignRef {
        lhs: Box<Expression>,
        rhs: Box<Expression>,
        span: Span,
    },
    /// Binary operation: `lhs op rhs`
    BinaryOp {
        op: BinaryOperator,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
        span: Span,
    },
    /// Unary operation: `op expr`
    UnaryOp {
        op: UnaryOperator,
        operand: Box<Expression>,
        span: Span,
    },
    /// Ternary operation: `cond ? then : else`
    Ternary {
        condition: Box<Expression>,
        then_expr: Option<Box<Expression>>, // None for ?: shorthand
        else_expr: Box<Expression>,
        span: Span,
    },
    /// Null coalesce: `lhs ?? rhs`
    Coalesce {
        lhs: Box<Expression>,
        rhs: Box<Expression>,
        span: Span,
    },
    /// Function call: `name(args)`
    FunctionCall {
        name: Box<Expression>,
        args: Vec<Argument>,
        span: Span,
    },
    /// Method call: `object->method(args)`
    MethodCall {
        object: Box<Expression>,
        method: Box<Expression>,
        args: Vec<Argument>,
        span: Span,
    },
    /// Nullsafe method call: `object?->method(args)`
    NullsafeMethodCall {
        object: Box<Expression>,
        method: Box<Expression>,
        args: Vec<Argument>,
        span: Span,
    },
    /// Static call: `Class::method(args)`
    StaticCall {
        class: Box<Expression>,
        method: Box<Expression>,
        args: Vec<Argument>,
        span: Span,
    },
    /// Property access: `object->property`
    PropertyAccess {
        object: Box<Expression>,
        property: Box<Expression>,
        span: Span,
    },
    /// Nullsafe property access: `object?->property`
    NullsafePropertyAccess {
        object: Box<Expression>,
        property: Box<Expression>,
        span: Span,
    },
    /// Static property access: `Class::$property`
    StaticPropertyAccess {
        class: Box<Expression>,
        property: Box<Expression>,
        span: Span,
    },
    /// Array access: `array[index]`
    ArrayAccess {
        array: Box<Expression>,
        index: Option<Box<Expression>>,
        span: Span,
    },
    /// Array literal: `[elements]` or `array(elements)`
    ArrayLiteral {
        elements: Vec<ArrayElement>,
        span: Span,
    },
    /// List destructure: `list($a, $b) = expr`
    List {
        elements: Vec<Option<Expression>>,
        span: Span,
    },
    /// New object: `new Class(args)`
    New {
        class: Box<Expression>,
        args: Vec<Argument>,
        span: Span,
    },
    /// Clone: `clone expr`
    Clone { object: Box<Expression>, span: Span },
    /// Instanceof: `expr instanceof Class`
    Instanceof {
        expr: Box<Expression>,
        class: Box<Expression>,
        span: Span,
    },
    /// Cast: `(type) expr`
    Cast {
        cast_type: CastType,
        expr: Box<Expression>,
        span: Span,
    },
    /// Yield: `yield [key =>] value`
    Yield {
        key: Option<Box<Expression>>,
        value: Option<Box<Expression>>,
        span: Span,
    },
    /// Yield from: `yield from expr`
    YieldFrom { expr: Box<Expression>, span: Span },
    /// Arrow function: `fn(params) => expr`
    ArrowFunction {
        params: Vec<Parameter>,
        return_type: Option<Type>,
        body: Box<Expression>,
        by_ref: bool,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Closure: `function(params) use(vars) { body }`
    Closure {
        params: Vec<Parameter>,
        return_type: Option<Type>,
        body: Vec<Statement>,
        uses: Vec<ClosureUse>,
        by_ref: bool,
        is_static: bool,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Match expression (PHP 8.0+)
    MatchExpr {
        condition: Box<Expression>,
        arms: Vec<MatchArm>,
        span: Span,
    },
    /// Throw expression (PHP 8.0+): `throw expr`
    ThrowExpr {
        exception: Box<Expression>,
        span: Span,
    },
    /// Named argument in function call: `name: value`
    NamedArgument {
        name: String,
        value: Box<Expression>,
        span: Span,
    },
    /// Spread operator: `...expr`
    Spread { expr: Box<Expression>, span: Span },
    /// Isset construct: `isset($var [, $var...])`
    Isset { vars: Vec<Expression>, span: Span },
    /// Empty construct: `empty($var)`
    Empty { var: Box<Expression>, span: Span },
    /// Eval construct: `eval($code)`
    Eval { code: Box<Expression>, span: Span },
    /// Include: `include expr`
    Include { path: Box<Expression>, span: Span },
    /// Include once: `include_once expr`
    IncludeOnce { path: Box<Expression>, span: Span },
    /// Require: `require expr`
    Require { path: Box<Expression>, span: Span },
    /// Require once: `require_once expr`
    RequireOnce { path: Box<Expression>, span: Span },
    /// Class constant access: `Class::CONST`
    ClassConstant {
        class: Box<Expression>,
        constant: String,
        span: Span,
    },
    /// Magic constant (__LINE__, __FILE__, etc.)
    MagicConstant { kind: MagicConstantKind, span: Span },
    /// Pre-increment: `++$var`
    PreIncrement { var: Box<Expression>, span: Span },
    /// Post-increment: `$var++`
    PostIncrement { var: Box<Expression>, span: Span },
    /// Pre-decrement: `--$var`
    PreDecrement { var: Box<Expression>, span: Span },
    /// Post-decrement: `$var--`
    PostDecrement { var: Box<Expression>, span: Span },
    /// Print construct: `print expr`
    Print { expr: Box<Expression>, span: Span },
    /// Exit/die construct: `exit([expr])`
    Exit {
        expr: Option<Box<Expression>>,
        span: Span,
    },
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    // Arithmetic
    Add, // +
    Sub, // -
    Mul, // *
    Div, // /
    Mod, // %
    Pow, // **
    // String
    Concat, // .
    // Comparison
    Equal,        // ==
    NotEqual,     // !=
    Identical,    // ===
    NotIdentical, // !==
    Less,         // <
    LessEqual,    // <=
    Greater,      // >
    GreaterEqual, // >=
    Spaceship,    // <=>
    // Logical
    And,        // &&
    Or,         // ||
    LogicalAnd, // and
    LogicalOr,  // or
    LogicalXor, // xor
    // Bitwise
    BitwiseAnd, // &
    BitwiseOr,  // |
    BitwiseXor, // ^
    ShiftLeft,  // <<
    ShiftRight, // >>
    // Assignment operators
    AddAssign,        // +=
    SubAssign,        // -=
    MulAssign,        // *=
    DivAssign,        // /=
    ModAssign,        // %=
    PowAssign,        // **=
    ConcatAssign,     // .=
    BitwiseAndAssign, // &=
    BitwiseOrAssign,  // |=
    BitwiseXorAssign, // ^=
    ShiftLeftAssign,  // <<=
    ShiftRightAssign, // >>=
    CoalesceAssign,   // ??=
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    Plus,          // +
    Minus,         // -
    Not,           // !
    BitwiseNot,    // ~
    ErrorSuppress, // @
}

/// Cast types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CastType {
    Int,
    Float,
    String,
    Bool,
    Array,
    Object,
    Unset,
}

/// Magic constant kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MagicConstantKind {
    Line,      // __LINE__
    File,      // __FILE__
    Dir,       // __DIR__
    Class,     // __CLASS__
    Trait,     // __TRAIT__
    Method,    // __METHOD__
    Function,  // __FUNCTION__
    Namespace, // __NAMESPACE__
    Property,  // __PROPERTY__
}

/// Function/method argument
#[derive(Debug, Clone, PartialEq)]
pub struct Argument {
    pub name: Option<String>, // Named argument
    pub value: Expression,
    pub unpack: bool, // Spread operator
    pub by_ref: bool,
}

/// Array element in array literal
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayElement {
    pub key: Option<Expression>,
    pub value: Expression,
    pub by_ref: bool,
    pub unpack: bool, // Spread operator
}

/// Parameter in function/method declaration
#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub name: String,
    pub param_type: Option<Type>,
    pub default: Option<Expression>,
    pub by_ref: bool,
    pub variadic: bool,
    pub attributes: Vec<Attribute>,
    pub span: Span,
}

/// Type annotation
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// Named type (class name or built-in)
    Named { name: Name, span: Span },
    /// Nullable type: `?Type`
    Nullable { inner: Box<Type>, span: Span },
    /// Union type: `Type1|Type2`
    Union { types: Vec<Type>, span: Span },
    /// Intersection type: `Type1&Type2`
    Intersection { types: Vec<Type>, span: Span },
    /// DNF (Disjunctive Normal Form) type: `(A&B)|C`
    Dnf {
        groups: Vec<Vec<Type>>, // Each inner vec is an intersection group
        span: Span,
    },
}

/// Qualified name (may include namespace)
#[derive(Debug, Clone, PartialEq)]
pub struct Name {
    pub parts: Vec<String>,
    pub fully_qualified: bool, // Leading backslash
    pub relative: bool,        // Starts with 'namespace\'
}

/// Switch case
#[derive(Debug, Clone, PartialEq)]
pub struct SwitchCase {
    pub condition: Option<Expression>, // None for default case
    pub statements: Vec<Statement>,
}

/// Match arm (PHP 8.0+)
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub conditions: Vec<Expression>, // Empty for default case
    pub body: Expression,
}

/// Use declaration
#[derive(Debug, Clone, PartialEq)]
pub struct UseDeclaration {
    pub name: Name,
    pub alias: Option<String>,
}

/// Use kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseKind {
    Normal,
    Function,
    Const,
}

/// Catch clause
#[derive(Debug, Clone, PartialEq)]
pub struct CatchClause {
    pub types: Vec<Name>,
    pub var: Option<String>,
    pub body: Vec<Statement>,
}

/// Static variable declaration
#[derive(Debug, Clone, PartialEq)]
pub struct StaticVar {
    pub name: String,
    pub default: Option<Expression>,
}

/// Class member
#[derive(Debug, Clone, PartialEq)]
pub enum ClassMember {
    /// Property declaration
    Property {
        name: String,
        modifiers: Vec<Modifier>,
        prop_type: Option<Type>,
        default: Option<Expression>,
        hooks: Vec<PropertyHook>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Method declaration
    Method {
        name: String,
        modifiers: Vec<Modifier>,
        params: Vec<Parameter>,
        return_type: Option<Type>,
        body: Option<Vec<Statement>>, // None for abstract methods
        by_ref: bool,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Class constant
    Constant {
        name: String,
        modifiers: Vec<Modifier>,
        value: Expression,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Trait use
    TraitUse {
        traits: Vec<Name>,
        adaptations: Vec<TraitAdaptation>,
        span: Span,
    },
}

/// Property hook (PHP 8.4+)
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyHook {
    pub kind: PropertyHookKind,
    pub params: Vec<Parameter>,
    pub body: PropertyHookBody,
    pub by_ref: bool,
    pub span: Span,
}

/// Property hook kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyHookKind {
    Get,
    Set,
}

/// Property hook body
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyHookBody {
    Expression(Expression),
    Block(Vec<Statement>),
}

/// Trait adaptation (alias/precedence)
#[derive(Debug, Clone, PartialEq)]
pub enum TraitAdaptation {
    Precedence {
        trait_name: Option<Name>,
        method: String,
        insteadof: Vec<Name>,
    },
    Alias {
        trait_name: Option<Name>,
        method: String,
        alias: Option<String>,
        modifiers: Vec<Modifier>,
    },
}

/// Modifier (visibility, static, abstract, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    Public,
    Protected,
    Private,
    Static,
    Abstract,
    Final,
    Readonly,
}

/// Enum member
#[derive(Debug, Clone, PartialEq)]
pub enum EnumMember {
    /// Enum case: `case Name [= value];`
    Case {
        name: String,
        value: Option<Expression>,
        attributes: Vec<Attribute>,
        span: Span,
    },
    /// Method, constant, or trait use (same as ClassMember)
    ClassMember(ClassMember),
}

/// Closure use variable
#[derive(Debug, Clone, PartialEq)]
pub struct ClosureUse {
    pub name: String,
    pub by_ref: bool,
}

/// Attribute (#[...])
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub name: Name,
    pub args: Vec<Argument>,
    pub span: Span,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_node_construction() {
        // Test that all major AST nodes can be constructed
        let span = Span::new(0, 1, 1, 1);

        // Integer literal
        let int_lit = Expression::IntLiteral { value: 42, span };
        assert!(matches!(int_lit, Expression::IntLiteral { value: 42, .. }));

        // Variable
        let var = Expression::Variable {
            name: "x".to_string(),
            span,
        };
        assert!(matches!(var, Expression::Variable { .. }));

        // Binary operation
        let binop = Expression::BinaryOp {
            op: BinaryOperator::Add,
            lhs: Box::new(Expression::IntLiteral { value: 1, span }),
            rhs: Box::new(Expression::IntLiteral { value: 2, span }),
            span,
        };
        assert!(matches!(binop, Expression::BinaryOp { .. }));

        // Return statement
        let ret = Statement::Return {
            value: Some(Box::new(Expression::IntLiteral { value: 42, span })),
            span,
        };
        assert!(matches!(ret, Statement::Return { .. }));
    }

    #[test]
    fn test_statement_variants() {
        // Verify all statement variants can be constructed
        let span = Span::new(0, 1, 1, 1);
        let expr = Expression::IntLiteral { value: 1, span };

        let statements = vec![
            Statement::Expression {
                expr: expr.clone(),
                span,
            },
            Statement::Echo {
                exprs: vec![expr.clone()],
                span,
            },
            Statement::Return {
                value: Some(Box::new(expr.clone())),
                span,
            },
            Statement::Break { depth: None, span },
            Statement::Continue { depth: None, span },
        ];

        assert_eq!(statements.len(), 5);
    }

    #[test]
    fn test_expression_variants() {
        // Verify all expression literal variants can be constructed
        let span = Span::new(0, 1, 1, 1);

        let expressions = vec![
            Expression::IntLiteral { value: 42, span },
            Expression::FloatLiteral { value: 3.14, span },
            Expression::StringLiteral {
                value: "hello".to_string(),
                span,
            },
            Expression::BoolLiteral { value: true, span },
            Expression::Null { span },
        ];

        assert_eq!(expressions.len(), 5);
    }

    #[test]
    fn test_binary_operators() {
        // Test all binary operators are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let ops = vec![
            BinaryOperator::Add,
            BinaryOperator::Sub,
            BinaryOperator::Mul,
            BinaryOperator::Div,
            BinaryOperator::Mod,
            BinaryOperator::Pow,
            BinaryOperator::Concat,
            BinaryOperator::Equal,
            BinaryOperator::NotEqual,
            BinaryOperator::Identical,
            BinaryOperator::NotIdentical,
            BinaryOperator::Less,
            BinaryOperator::LessEqual,
            BinaryOperator::Greater,
            BinaryOperator::GreaterEqual,
            BinaryOperator::Spaceship,
            BinaryOperator::And,
            BinaryOperator::Or,
            BinaryOperator::LogicalAnd,
            BinaryOperator::LogicalOr,
            BinaryOperator::LogicalXor,
            BinaryOperator::BitwiseAnd,
            BinaryOperator::BitwiseOr,
            BinaryOperator::BitwiseXor,
            BinaryOperator::ShiftLeft,
            BinaryOperator::ShiftRight,
        ];

        for op in ops.iter() {
            assert!(set.insert(op), "Duplicate operator: {:?}", op);
        }
    }

    #[test]
    fn test_unary_operators() {
        // Test all unary operators are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let ops = vec![
            UnaryOperator::Plus,
            UnaryOperator::Minus,
            UnaryOperator::Not,
            UnaryOperator::BitwiseNot,
            UnaryOperator::ErrorSuppress,
        ];

        for op in ops.iter() {
            assert!(set.insert(op), "Duplicate operator: {:?}", op);
        }
    }

    #[test]
    fn test_cast_types() {
        // Test all cast types are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let types = vec![
            CastType::Int,
            CastType::Float,
            CastType::String,
            CastType::Bool,
            CastType::Array,
            CastType::Object,
            CastType::Unset,
        ];

        for t in types.iter() {
            assert!(set.insert(t), "Duplicate cast type: {:?}", t);
        }
    }

    #[test]
    fn test_magic_constants() {
        // Test all magic constants are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let consts = vec![
            MagicConstantKind::Line,
            MagicConstantKind::File,
            MagicConstantKind::Dir,
            MagicConstantKind::Class,
            MagicConstantKind::Trait,
            MagicConstantKind::Method,
            MagicConstantKind::Function,
            MagicConstantKind::Namespace,
            MagicConstantKind::Property,
        ];

        for c in consts.iter() {
            assert!(set.insert(c), "Duplicate magic constant: {:?}", c);
        }
    }

    #[test]
    fn test_modifiers() {
        // Test all modifiers are distinct
        use std::collections::HashSet;
        let mut set = HashSet::new();

        let mods = vec![
            Modifier::Public,
            Modifier::Protected,
            Modifier::Private,
            Modifier::Static,
            Modifier::Abstract,
            Modifier::Final,
            Modifier::Readonly,
        ];

        for m in mods.iter() {
            assert!(set.insert(m), "Duplicate modifier: {:?}", m);
        }
    }

    #[test]
    fn test_name_construction() {
        // Test qualified name construction
        let name = Name {
            parts: vec!["Foo".to_string(), "Bar".to_string()],
            fully_qualified: true,
            relative: false,
        };
        assert_eq!(name.parts.len(), 2);
        assert!(name.fully_qualified);
        assert!(!name.relative);

        let relative_name = Name {
            parts: vec!["Baz".to_string()],
            fully_qualified: false,
            relative: true,
        };
        assert_eq!(relative_name.parts.len(), 1);
        assert!(!relative_name.fully_qualified);
        assert!(relative_name.relative);
    }

    #[test]
    fn test_parameter_construction() {
        // Test parameter with all features
        let span = Span::new(0, 1, 1, 1);
        let param = Parameter {
            name: "x".to_string(),
            param_type: Some(Type::Named {
                name: Name {
                    parts: vec!["int".to_string()],
                    fully_qualified: false,
                    relative: false,
                },
                span,
            }),
            default: Some(Expression::IntLiteral { value: 42, span }),
            by_ref: false,
            variadic: false,
            attributes: vec![],
            span,
        };

        assert_eq!(param.name, "x");
        assert!(param.param_type.is_some());
        assert!(param.default.is_some());
    }

    #[test]
    fn test_type_variants() {
        // Test type construction
        let span = Span::new(0, 1, 1, 1);
        let name = Name {
            parts: vec!["int".to_string()],
            fully_qualified: false,
            relative: false,
        };

        // Named type
        let named_type = Type::Named {
            name: name.clone(),
            span,
        };
        assert!(matches!(named_type, Type::Named { .. }));

        // Nullable type
        let nullable = Type::Nullable {
            inner: Box::new(Type::Named { name, span }),
            span,
        };
        assert!(matches!(nullable, Type::Nullable { .. }));
    }

    #[test]
    fn test_class_member_variants() {
        // Test class member construction
        let span = Span::new(0, 1, 1, 1);

        let property = ClassMember::Property {
            name: "prop".to_string(),
            modifiers: vec![Modifier::Public],
            prop_type: None,
            default: None,
            hooks: vec![],
            attributes: vec![],
            span,
        };
        assert!(matches!(property, ClassMember::Property { .. }));

        let constant = ClassMember::Constant {
            name: "CONST".to_string(),
            modifiers: vec![Modifier::Public],
            value: Expression::IntLiteral { value: 42, span },
            attributes: vec![],
            span,
        };
        assert!(matches!(constant, ClassMember::Constant { .. }));
    }

    #[test]
    fn test_ast_serialize_debug() {
        // Verify Debug trait works for AST nodes
        let span = Span::new(0, 5, 1, 1);
        let expr = Expression::IntLiteral { value: 42, span };
        let debug_str = format!("{:?}", expr);
        assert!(debug_str.contains("IntLiteral"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_complex_expression_tree() {
        // Test: Build a complex expression tree: (1 + 2) * 3
        let span = Span::new(0, 1, 1, 1);

        let one = Expression::IntLiteral { value: 1, span };
        let two = Expression::IntLiteral { value: 2, span };
        let three = Expression::IntLiteral { value: 3, span };

        let add = Expression::BinaryOp {
            op: BinaryOperator::Add,
            lhs: Box::new(one),
            rhs: Box::new(two),
            span,
        };

        let mul = Expression::BinaryOp {
            op: BinaryOperator::Mul,
            lhs: Box::new(add),
            rhs: Box::new(three),
            span,
        };

        // Verify structure
        if let Expression::BinaryOp {
            op: BinaryOperator::Mul,
            lhs,
            ..
        } = mul
        {
            assert!(matches!(*lhs, Expression::BinaryOp { .. }));
        } else {
            panic!("Expected BinaryOp");
        }
    }

    #[test]
    fn test_statement_nesting() {
        // Test: Build nested if-else statement
        let span = Span::new(0, 1, 1, 1);
        let condition = Expression::BoolLiteral { value: true, span };
        let then_stmt = Statement::Return {
            value: Some(Box::new(Expression::IntLiteral { value: 1, span })),
            span,
        };
        let else_stmt = Statement::Return {
            value: Some(Box::new(Expression::IntLiteral { value: 0, span })),
            span,
        };

        let if_stmt = Statement::If {
            condition: Box::new(condition),
            then_branch: Box::new(then_stmt),
            elseif_branches: vec![],
            else_branch: Some(Box::new(else_stmt)),
            span,
        };

        assert!(matches!(if_stmt, Statement::If { .. }));
    }

    #[test]
    fn test_function_declaration() {
        // Test: Function with parameters and return type
        let span = Span::new(0, 1, 1, 1);
        let param = Parameter {
            name: "x".to_string(),
            param_type: Some(Type::Named {
                name: Name {
                    parts: vec!["int".to_string()],
                    fully_qualified: false,
                    relative: false,
                },
                span,
            }),
            default: None,
            by_ref: false,
            variadic: false,
            attributes: vec![],
            span,
        };

        let func = Statement::Function {
            name: "add".to_string(),
            params: vec![param],
            return_type: Some(Type::Named {
                name: Name {
                    parts: vec!["int".to_string()],
                    fully_qualified: false,
                    relative: false,
                },
                span,
            }),
            body: vec![Statement::Return {
                value: Some(Box::new(Expression::IntLiteral { value: 42, span })),
                span,
            }],
            by_ref: false,
            attributes: vec![],
            span,
        };

        assert!(matches!(func, Statement::Function { .. }));
    }

    #[test]
    fn test_class_declaration() {
        // Test: Class with properties and methods
        let span = Span::new(0, 1, 1, 1);

        let property = ClassMember::Property {
            name: "value".to_string(),
            modifiers: vec![Modifier::Private],
            prop_type: Some(Type::Named {
                name: Name {
                    parts: vec!["int".to_string()],
                    fully_qualified: false,
                    relative: false,
                },
                span,
            }),
            default: Some(Expression::IntLiteral { value: 0, span }),
            hooks: vec![],
            attributes: vec![],
            span,
        };

        let class = Statement::Class {
            name: "Counter".to_string(),
            modifiers: vec![],
            extends: None,
            implements: vec![],
            members: vec![property],
            attributes: vec![],
            span,
        };

        assert!(matches!(class, Statement::Class { .. }));
    }
}
