//! ZOpArray — compiled function/script representation.
//!
//! Mirrors `struct _zend_op_array` from php-src/Zend/zend_compile.h.

use crate::op::ZOp;
use std::collections::HashMap;
use std::fmt;

/// A try/catch/finally element — marks the opcode ranges for exception handling.
///
/// Mirrors `zend_try_catch_element` from zend_compile.h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryCatchElement {
    /// Opline index where the try block starts.
    pub try_op: u32,
    /// Opline index of the catch handler (0 if no catch).
    pub catch_op: u32,
    /// Opline index of the finally block (0 if no finally).
    pub finally_op: u32,
    /// Opline index where the finally block ends (0 if no finally).
    pub finally_end: u32,
}

/// Indicates the kind of value that lives in a live range.
///
/// Mirrors ZEND_LIVE_TMPVAR, ZEND_LIVE_LOOP, etc.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiveRangeKind {
    TmpVar = 0,
    Loop = 1,
    Silence = 2,
    Rope = 3,
    New = 4,
}

/// A live range for a temporary variable — used for cleanup on exception.
///
/// Mirrors `zend_live_range` from zend_compile.h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRange {
    /// The variable slot (low bits encode the kind).
    pub var: u32,
    /// Opline index where the variable becomes live.
    pub start: u32,
    /// Opline index where the variable is no longer live.
    pub end: u32,
}

impl LiveRange {
    pub fn new(var: u32, kind: LiveRangeKind, start: u32, end: u32) -> Self {
        Self {
            var: (var & !7) | kind as u32,
            start,
            end,
        }
    }

    pub fn kind(&self) -> LiveRangeKind {
        match self.var & 7 {
            0 => LiveRangeKind::TmpVar,
            1 => LiveRangeKind::Loop,
            2 => LiveRangeKind::Silence,
            3 => LiveRangeKind::Rope,
            4 => LiveRangeKind::New,
            _ => LiveRangeKind::TmpVar, // fallback
        }
    }

    pub fn var_slot(&self) -> u32 {
        self.var & !7
    }
}

/// Argument info for a function parameter.
///
/// Corresponds to `zend_arg_info` in php-src.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgInfo {
    /// Parameter name.
    pub name: String,
    /// Whether the parameter is pass-by-reference.
    pub pass_by_reference: bool,
    /// Whether the parameter is variadic (...$args).
    pub is_variadic: bool,
}

/// Info about a class property (for compile-time metadata).
#[derive(Debug, Clone, PartialEq)]
pub struct ClassPropertyInfo {
    pub name: String,
    pub default: Option<Literal>,
    pub is_static: bool,
}

/// Compile-time class metadata (properties, constants, traits).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClassMetadata {
    pub properties: Vec<ClassPropertyInfo>,
    pub constants: Vec<(String, Literal)>,
    pub traits: Vec<String>,
}

/// A compiled opcode array — one per function, method, or top-level script.
///
/// Mirrors `struct _zend_op_array` from php-src/Zend/zend_compile.h.
///
/// In PHP, every compiled file gets a top-level op_array. Each function and
/// method definition within that file also gets its own op_array. They share
/// a reference to the file's literal pool but have separate opcode sequences.
#[derive(Clone)]
pub struct ZOpArray {
    /// Function name (empty for top-level script).
    pub function_name: Option<String>,

    /// The compiled opcodes.
    pub opcodes: Vec<ZOp>,

    /// Constant pool — literal values referenced by Const operands.
    /// Indexed by the operand's `val` field.
    pub literals: Vec<Literal>,

    /// Compiled variable names (CVs) — named local variables.
    /// $a is CV(0), $b is CV(1), etc. Order matches first appearance.
    pub vars: Vec<String>,

    /// Number of temporary variable slots needed (for TmpVar and Var operands).
    pub num_temps: u32,

    /// Argument info for function parameters.
    pub arg_info: Vec<ArgInfo>,

    /// Number of required (non-optional) arguments.
    pub required_num_args: u32,

    /// Try/catch/finally blocks.
    pub try_catch_array: Vec<TryCatchElement>,

    /// Live ranges for temporaries (for exception cleanup).
    pub live_range: Vec<LiveRange>,

    /// Source file name.
    pub filename: Option<String>,

    /// First line of this function/script in the source.
    pub line_start: u32,

    /// Last line of this function/script in the source.
    pub line_end: u32,

    /// Nested function definitions (closures, arrow functions).
    pub dynamic_func_defs: Vec<ZOpArray>,

    /// Whether this function contains yield/yield from (is a generator).
    pub is_generator: bool,

    /// Class metadata: properties and constants (keyed by class name).
    /// Populated during class compilation, consumed by VM during DeclareClass.
    pub class_metadata: HashMap<String, ClassMetadata>,
}

/// A literal value in the constant pool.
///
/// During compilation, constant expressions are evaluated and stored here.
/// Const operands reference these by index.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Long(i64),
    Double(f64),
    String(String),
}

impl Literal {
    /// Display the literal as PHP would.
    pub fn as_php_string(&self) -> String {
        match self {
            Literal::Null => "null".to_string(),
            Literal::Bool(true) => "true".to_string(),
            Literal::Bool(false) => "false".to_string(),
            Literal::Long(n) => n.to_string(),
            Literal::Double(f) => {
                if f.is_infinite() {
                    if *f > 0.0 {
                        "INF".to_string()
                    } else {
                        "-INF".to_string()
                    }
                } else if f.is_nan() {
                    "NAN".to_string()
                } else {
                    // Match PHP's float formatting
                    let s = format!("{}", f);
                    if s.contains('.') || s.contains('E') || s.contains('e') {
                        s
                    } else {
                        format!("{}.0", s)
                    }
                }
            }
            Literal::String(s) => format!("\"{}\"", s),
        }
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_php_string())
    }
}

impl ZOpArray {
    /// Create a new empty op array (for a top-level script).
    pub fn new() -> Self {
        Self {
            function_name: None,
            opcodes: Vec::new(),
            literals: Vec::new(),
            vars: Vec::new(),
            num_temps: 0,
            arg_info: Vec::new(),
            required_num_args: 0,
            try_catch_array: Vec::new(),
            live_range: Vec::new(),
            filename: None,
            line_start: 0,
            line_end: 0,
            dynamic_func_defs: Vec::new(),
            is_generator: false,
            class_metadata: HashMap::new(),
        }
    }

    /// Create a new op array for a named function.
    pub fn for_function(name: impl Into<String>) -> Self {
        Self {
            function_name: Some(name.into()),
            ..Self::new()
        }
    }

    /// Add a literal to the constant pool and return its index.
    pub fn add_literal(&mut self, lit: Literal) -> u32 {
        let index = self.literals.len() as u32;
        self.literals.push(lit);
        index
    }

    /// Register a compiled variable name and return its CV index.
    /// If the variable was already registered, returns the existing index.
    pub fn lookup_cv(&mut self, name: &str) -> u32 {
        if let Some(pos) = self.vars.iter().position(|v| v == name) {
            pos as u32
        } else {
            let index = self.vars.len() as u32;
            self.vars.push(name.to_string());
            index
        }
    }

    /// Allocate a new temporary variable slot and return its number.
    pub fn alloc_temp(&mut self) -> u32 {
        let slot = self.num_temps;
        self.num_temps += 1;
        slot
    }

    /// Emit an opcode, appending it to the opcodes vector.
    /// Returns the opline index of the emitted instruction.
    pub fn emit(&mut self, op: ZOp) -> u32 {
        let index = self.opcodes.len() as u32;
        self.opcodes.push(op);
        index
    }

    /// Get the index of the next opcode that would be emitted.
    pub fn next_opline(&self) -> u32 {
        self.opcodes.len() as u32
    }

    /// Disassemble the op array to a human-readable string.
    pub fn disassemble(&self) -> String {
        let mut out = String::new();

        // Header
        if let Some(ref name) = self.function_name {
            out.push_str(&format!("function {}():\n", name));
        } else if let Some(ref filename) = self.filename {
            out.push_str(&format!("{}:\n", filename));
        } else {
            out.push_str("(main):\n");
        }

        // Literals
        if !self.literals.is_empty() {
            out.push_str("  literals:\n");
            for (i, lit) in self.literals.iter().enumerate() {
                out.push_str(&format!("    [{}] {}\n", i, lit));
            }
        }

        // CVs
        if !self.vars.is_empty() {
            out.push_str("  vars:\n");
            for (i, var) in self.vars.iter().enumerate() {
                out.push_str(&format!("    CV({}) = ${}\n", i, var));
            }
        }

        // Temps
        if self.num_temps > 0 {
            out.push_str(&format!("  temps: {}\n", self.num_temps));
        }

        // Opcodes
        out.push_str("  opcodes:\n");
        for (i, op) in self.opcodes.iter().enumerate() {
            out.push_str(&format!("    {:>4} {}\n", i, op.disassemble()));
        }

        out
    }
}

impl Default for ZOpArray {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ZOpArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZOpArray")
            .field("function_name", &self.function_name)
            .field("num_opcodes", &self.opcodes.len())
            .field("num_literals", &self.literals.len())
            .field("num_vars", &self.vars.len())
            .field("num_temps", &self.num_temps)
            .field("num_args", &self.arg_info.len())
            .field("num_try_catch", &self.try_catch_array.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::{Operand, OperandType};
    use crate::opcode::ZOpcode;

    #[test]
    fn test_op_array_new() {
        let op_array = ZOpArray::new();
        assert!(op_array.function_name.is_none());
        assert!(op_array.opcodes.is_empty());
        assert!(op_array.literals.is_empty());
        assert!(op_array.vars.is_empty());
        assert_eq!(op_array.num_temps, 0);
    }

    #[test]
    fn test_op_array_for_function() {
        let op_array = ZOpArray::for_function("foo");
        assert_eq!(op_array.function_name.as_deref(), Some("foo"));
    }

    #[test]
    fn test_add_literal() {
        let mut op_array = ZOpArray::new();
        let idx0 = op_array.add_literal(Literal::String("Hello".to_string()));
        let idx1 = op_array.add_literal(Literal::Long(42));
        let idx2 = op_array.add_literal(Literal::Null);
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(op_array.literals.len(), 3);
    }

    #[test]
    fn test_lookup_cv() {
        let mut op_array = ZOpArray::new();
        let a = op_array.lookup_cv("a");
        let b = op_array.lookup_cv("b");
        let a2 = op_array.lookup_cv("a"); // same variable
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(a2, 0); // reuses existing
        assert_eq!(op_array.vars.len(), 2);
    }

    #[test]
    fn test_alloc_temp() {
        let mut op_array = ZOpArray::new();
        assert_eq!(op_array.alloc_temp(), 0);
        assert_eq!(op_array.alloc_temp(), 1);
        assert_eq!(op_array.alloc_temp(), 2);
        assert_eq!(op_array.num_temps, 3);
    }

    #[test]
    fn test_emit_and_next_opline() {
        let mut op_array = ZOpArray::new();
        assert_eq!(op_array.next_opline(), 0);

        let idx = op_array
            .emit(ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(0), OperandType::Const));
        assert_eq!(idx, 0);
        assert_eq!(op_array.next_opline(), 1);

        let idx2 = op_array.emit(ZOp::new(ZOpcode::Return, 2));
        assert_eq!(idx2, 1);
        assert_eq!(op_array.opcodes.len(), 2);
    }

    #[test]
    fn test_compile_echo_hello() {
        // Simulate compiling: echo "Hello, World!\n";
        let mut op_array = ZOpArray::new();
        op_array.filename = Some("test.php".to_string());

        // Add the string literal
        let lit_idx = op_array.add_literal(Literal::String("Hello, World!\n".to_string()));

        // Emit ECHO instruction
        op_array.emit(
            ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(lit_idx), OperandType::Const),
        );

        // Emit RETURN
        let ret_lit = op_array.add_literal(Literal::Long(1));
        op_array.emit(
            ZOp::new(ZOpcode::Return, 1).with_op1(Operand::constant(ret_lit), OperandType::Const),
        );

        assert_eq!(op_array.opcodes.len(), 2);
        assert_eq!(op_array.literals.len(), 2);
        assert_eq!(op_array.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(op_array.opcodes[1].opcode, ZOpcode::Return);
    }

    #[test]
    fn test_compile_variable_assignment() {
        // Simulate: $a = 42; echo $a;
        let mut op_array = ZOpArray::new();

        // $a = 42
        let cv_a = op_array.lookup_cv("a");
        let lit_42 = op_array.add_literal(Literal::Long(42));
        op_array.emit(
            ZOp::new(ZOpcode::Assign, 1)
                .with_op1(Operand::cv(cv_a), OperandType::Cv)
                .with_op2(Operand::constant(lit_42), OperandType::Const),
        );

        // echo $a
        op_array.emit(ZOp::new(ZOpcode::Echo, 2).with_op1(Operand::cv(cv_a), OperandType::Cv));

        // return 1
        let lit_1 = op_array.add_literal(Literal::Long(1));
        op_array.emit(
            ZOp::new(ZOpcode::Return, 2).with_op1(Operand::constant(lit_1), OperandType::Const),
        );

        assert_eq!(op_array.opcodes.len(), 3);
        assert_eq!(op_array.vars, vec!["a"]);
        assert_eq!(op_array.literals.len(), 2); // 42 and 1
    }

    #[test]
    fn test_compile_addition() {
        // Simulate: $c = $a + $b;
        let mut op_array = ZOpArray::new();

        let cv_a = op_array.lookup_cv("a");
        let cv_b = op_array.lookup_cv("b");
        let cv_c = op_array.lookup_cv("c");
        let tmp = op_array.alloc_temp();

        // ADD $a, $b -> ~0
        op_array.emit(
            ZOp::new(ZOpcode::Add, 1)
                .with_op1(Operand::cv(cv_a), OperandType::Cv)
                .with_op2(Operand::cv(cv_b), OperandType::Cv)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        // ASSIGN $c, ~0
        op_array.emit(
            ZOp::new(ZOpcode::Assign, 1)
                .with_op1(Operand::cv(cv_c), OperandType::Cv)
                .with_op2(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        assert_eq!(op_array.vars, vec!["a", "b", "c"]);
        assert_eq!(op_array.num_temps, 1);
        assert_eq!(op_array.opcodes.len(), 2);
    }

    #[test]
    fn test_try_catch_element() {
        let elem = TryCatchElement {
            try_op: 0,
            catch_op: 5,
            finally_op: 10,
            finally_end: 15,
        };
        assert_eq!(elem.try_op, 0);
        assert_eq!(elem.catch_op, 5);
        assert_eq!(elem.finally_op, 10);
        assert_eq!(elem.finally_end, 15);
    }

    #[test]
    fn test_live_range() {
        let lr = LiveRange::new(16, LiveRangeKind::Loop, 5, 20);
        assert_eq!(lr.kind(), LiveRangeKind::Loop);
        assert_eq!(lr.var_slot(), 16);
        assert_eq!(lr.start, 5);
        assert_eq!(lr.end, 20);
    }

    #[test]
    fn test_live_range_kinds() {
        for kind in [
            LiveRangeKind::TmpVar,
            LiveRangeKind::Loop,
            LiveRangeKind::Silence,
            LiveRangeKind::Rope,
            LiveRangeKind::New,
        ] {
            let lr = LiveRange::new(8, kind, 0, 10);
            assert_eq!(lr.kind(), kind);
        }
    }

    #[test]
    fn test_literal_display() {
        assert_eq!(Literal::Null.as_php_string(), "null");
        assert_eq!(Literal::Bool(true).as_php_string(), "true");
        assert_eq!(Literal::Bool(false).as_php_string(), "false");
        assert_eq!(Literal::Long(42).as_php_string(), "42");
        assert_eq!(Literal::Long(-1).as_php_string(), "-1");
        assert_eq!(Literal::Double(3.125).as_php_string(), "3.125");
        assert_eq!(Literal::Double(f64::INFINITY).as_php_string(), "INF");
        assert_eq!(Literal::Double(f64::NEG_INFINITY).as_php_string(), "-INF");
        assert_eq!(Literal::Double(f64::NAN).as_php_string(), "NAN");
        assert_eq!(
            Literal::String("hello".to_string()).as_php_string(),
            "\"hello\""
        );
    }

    #[test]
    fn test_disassemble() {
        let mut op_array = ZOpArray::new();
        op_array.filename = Some("test.php".to_string());

        let lit_idx = op_array.add_literal(Literal::String("Hello".to_string()));
        op_array.emit(
            ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(lit_idx), OperandType::Const),
        );
        let ret_idx = op_array.add_literal(Literal::Long(1));
        op_array.emit(
            ZOp::new(ZOpcode::Return, 1).with_op1(Operand::constant(ret_idx), OperandType::Const),
        );

        let dis = op_array.disassemble();
        assert!(dis.contains("test.php"), "dis:\n{}", dis);
        assert!(dis.contains("ZEND_ECHO"), "dis:\n{}", dis);
        assert!(dis.contains("ZEND_RETURN"), "dis:\n{}", dis);
        assert!(dis.contains("\"Hello\""), "dis:\n{}", dis);
    }

    #[test]
    fn test_op_array_debug() {
        let op_array = ZOpArray::for_function("test_func");
        let debug = format!("{:?}", op_array);
        assert!(debug.contains("test_func"), "debug: {}", debug);
        assert!(debug.contains("num_opcodes: 0"), "debug: {}", debug);
    }

    #[test]
    fn test_op_array_default() {
        let op_array = ZOpArray::default();
        assert!(op_array.function_name.is_none());
        assert!(op_array.opcodes.is_empty());
    }

    #[test]
    fn test_dynamic_func_defs() {
        let mut main = ZOpArray::new();
        let closure = ZOpArray::for_function("{closure}");
        main.dynamic_func_defs.push(closure);
        assert_eq!(main.dynamic_func_defs.len(), 1);
        assert_eq!(
            main.dynamic_func_defs[0].function_name.as_deref(),
            Some("{closure}")
        );
    }

    #[test]
    fn test_arg_info() {
        let mut op_array = ZOpArray::for_function("add");
        op_array.arg_info.push(ArgInfo {
            name: "a".to_string(),
            pass_by_reference: false,
            is_variadic: false,
        });
        op_array.arg_info.push(ArgInfo {
            name: "b".to_string(),
            pass_by_reference: false,
            is_variadic: false,
        });
        op_array.required_num_args = 2;

        assert_eq!(op_array.arg_info.len(), 2);
        assert_eq!(op_array.arg_info[0].name, "a");
        assert_eq!(op_array.required_num_args, 2);
    }
}
