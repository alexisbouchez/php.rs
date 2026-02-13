//! ZOp — single VM instruction.
//!
//! Mirrors `struct _zend_op` from php-src/Zend/zend_compile.h.

use crate::opcode::ZOpcode;
use std::fmt;

/// Operand type, matching PHP's IS_UNUSED / IS_CONST / IS_TMP_VAR / IS_VAR / IS_CV.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandType {
    /// Operand slot is not used.
    Unused = 0,
    /// Compile-time constant (index into literals table).
    Const = 1, // 1 << 0
    /// Temporary variable (intermediate computation result).
    TmpVar = 2, // 1 << 1
    /// Engine-internal variable (may be reference-counted).
    Var = 4, // 1 << 2
    /// Compiled variable (named local, e.g., $x).
    Cv = 8, // 1 << 3
}

/// An operand value — a union represented as u32.
///
/// The interpretation depends on `OperandType`:
/// - `Const`: index into the literals array
/// - `TmpVar` / `Var`: offset into the temporary variables area
/// - `Cv`: index into the compiled variables (CV) table
/// - `Unused`: may hold a `num` or `opline_num` for jumps
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Operand {
    /// The raw u32 value. Interpretation depends on the operand type.
    pub val: u32,
}

impl Operand {
    /// Create a new operand with a constant index.
    pub fn constant(index: u32) -> Self {
        Self { val: index }
    }

    /// Create a new operand with a temporary variable slot.
    pub fn tmp_var(slot: u32) -> Self {
        Self { val: slot }
    }

    /// Create a new operand with a variable slot.
    pub fn var(slot: u32) -> Self {
        Self { val: slot }
    }

    /// Create a new operand with a compiled variable index.
    pub fn cv(index: u32) -> Self {
        Self { val: index }
    }

    /// Create a new operand for a jump target (opline offset).
    pub fn jmp_target(offset: u32) -> Self {
        Self { val: offset }
    }

    /// Create an unused operand.
    pub fn unused() -> Self {
        Self { val: u32::MAX }
    }
}

impl fmt::Debug for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operand({})", self.val)
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.val == u32::MAX {
            write!(f, "-")
        } else {
            write!(f, "{}", self.val)
        }
    }
}

/// A single VM instruction.
///
/// Mirrors `struct _zend_op` from zend_compile.h:
/// ```c
/// struct _zend_op {
///     zend_vm_opcode_handler_t handler;
///     znode_op op1, op2, result;
///     uint32_t extended_value;
///     uint32_t lineno;
///     uint8_t opcode;
///     uint8_t op1_type, op2_type, result_type;
/// };
/// ```
///
/// We omit the `handler` pointer (the VM will resolve it at dispatch time).
#[derive(Clone, PartialEq, Eq)]
pub struct ZOp {
    /// The opcode for this instruction.
    pub opcode: ZOpcode,
    /// First operand.
    pub op1: Operand,
    /// Type of first operand.
    pub op1_type: OperandType,
    /// Second operand.
    pub op2: Operand,
    /// Type of second operand.
    pub op2_type: OperandType,
    /// Result operand.
    pub result: Operand,
    /// Type of result operand.
    pub result_type: OperandType,
    /// Extended value — used for sub-operations (e.g., cast type, include type, assign op type).
    pub extended_value: u32,
    /// Source line number.
    pub lineno: u32,
}

impl ZOp {
    /// Create a NOP instruction.
    pub fn nop() -> Self {
        Self {
            opcode: ZOpcode::Nop,
            op1: Operand::unused(),
            op1_type: OperandType::Unused,
            op2: Operand::unused(),
            op2_type: OperandType::Unused,
            result: Operand::unused(),
            result_type: OperandType::Unused,
            extended_value: 0,
            lineno: 0,
        }
    }

    /// Create a new instruction with the given opcode and all operands unused.
    pub fn new(opcode: ZOpcode, lineno: u32) -> Self {
        Self {
            opcode,
            op1: Operand::unused(),
            op1_type: OperandType::Unused,
            op2: Operand::unused(),
            op2_type: OperandType::Unused,
            result: Operand::unused(),
            result_type: OperandType::Unused,
            extended_value: 0,
            lineno,
        }
    }

    /// Set op1 with its type.
    pub fn with_op1(mut self, op: Operand, op_type: OperandType) -> Self {
        self.op1 = op;
        self.op1_type = op_type;
        self
    }

    /// Set op2 with its type.
    pub fn with_op2(mut self, op: Operand, op_type: OperandType) -> Self {
        self.op2 = op;
        self.op2_type = op_type;
        self
    }

    /// Set result with its type.
    pub fn with_result(mut self, op: Operand, op_type: OperandType) -> Self {
        self.result = op;
        self.result_type = op_type;
        self
    }

    /// Set the extended value.
    pub fn with_extended_value(mut self, val: u32) -> Self {
        self.extended_value = val;
        self
    }
}

impl fmt::Debug for ZOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L{:04} {}", self.lineno, self.opcode)?;

        if self.op1_type != OperandType::Unused {
            write!(f, " {:?}({})", self.op1_type, self.op1)?;
        }
        if self.op2_type != OperandType::Unused {
            write!(f, " {:?}({})", self.op2_type, self.op2)?;
        }
        if self.result_type != OperandType::Unused {
            write!(f, " -> {:?}({})", self.result_type, self.result)?;
        }
        if self.extended_value != 0 {
            write!(f, " ext:{}", self.extended_value)?;
        }

        Ok(())
    }
}

impl fmt::Display for ZOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Helper to format an operand with its type for disassembly.
fn format_operand(op: &Operand, op_type: OperandType) -> String {
    match op_type {
        OperandType::Unused => "-".to_string(),
        OperandType::Const => format!("const({})", op.val),
        OperandType::TmpVar => format!("~{}", op.val),
        OperandType::Var => format!("${}", op.val),
        OperandType::Cv => format!("CV({})", op.val),
    }
}

impl ZOp {
    /// Produce a disassembly-style string for this instruction.
    pub fn disassemble(&self) -> String {
        let op1 = format_operand(&self.op1, self.op1_type);
        let op2 = format_operand(&self.op2, self.op2_type);
        let result = format_operand(&self.result, self.result_type);

        if self.result_type != OperandType::Unused {
            format!(
                "{:>4} {} {} {} -> {}",
                self.lineno, self.opcode, op1, op2, result
            )
        } else {
            format!("{:>4} {} {} {}", self.lineno, self.opcode, op1, op2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operand_type_values() {
        assert_eq!(OperandType::Unused as u8, 0);
        assert_eq!(OperandType::Const as u8, 1);
        assert_eq!(OperandType::TmpVar as u8, 2);
        assert_eq!(OperandType::Var as u8, 4);
        assert_eq!(OperandType::Cv as u8, 8);
    }

    #[test]
    fn test_operand_constructors() {
        let c = Operand::constant(42);
        assert_eq!(c.val, 42);

        let t = Operand::tmp_var(3);
        assert_eq!(t.val, 3);

        let v = Operand::var(7);
        assert_eq!(v.val, 7);

        let cv = Operand::cv(0);
        assert_eq!(cv.val, 0);

        let jmp = Operand::jmp_target(10);
        assert_eq!(jmp.val, 10);

        let u = Operand::unused();
        assert_eq!(u.val, u32::MAX);
    }

    #[test]
    fn test_zop_nop() {
        let nop = ZOp::nop();
        assert_eq!(nop.opcode, ZOpcode::Nop);
        assert_eq!(nop.op1_type, OperandType::Unused);
        assert_eq!(nop.op2_type, OperandType::Unused);
        assert_eq!(nop.result_type, OperandType::Unused);
        assert_eq!(nop.extended_value, 0);
        assert_eq!(nop.lineno, 0);
    }

    #[test]
    fn test_zop_new() {
        let op = ZOp::new(ZOpcode::Echo, 5);
        assert_eq!(op.opcode, ZOpcode::Echo);
        assert_eq!(op.lineno, 5);
        assert_eq!(op.op1_type, OperandType::Unused);
    }

    #[test]
    fn test_zop_builder() {
        // echo "hello" → ZEND_ECHO const(0)
        let op = ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(0), OperandType::Const);

        assert_eq!(op.opcode, ZOpcode::Echo);
        assert_eq!(op.op1_type, OperandType::Const);
        assert_eq!(op.op1.val, 0);
        assert_eq!(op.op2_type, OperandType::Unused);
        assert_eq!(op.result_type, OperandType::Unused);
    }

    #[test]
    fn test_zop_add() {
        // $c = $a + $b → ZEND_ADD CV(0) CV(1) -> TmpVar(0)
        let op = ZOp::new(ZOpcode::Add, 3)
            .with_op1(Operand::cv(0), OperandType::Cv)
            .with_op2(Operand::cv(1), OperandType::Cv)
            .with_result(Operand::tmp_var(0), OperandType::TmpVar);

        assert_eq!(op.opcode, ZOpcode::Add);
        assert_eq!(op.op1_type, OperandType::Cv);
        assert_eq!(op.op1.val, 0);
        assert_eq!(op.op2_type, OperandType::Cv);
        assert_eq!(op.op2.val, 1);
        assert_eq!(op.result_type, OperandType::TmpVar);
        assert_eq!(op.result.val, 0);
    }

    #[test]
    fn test_zop_debug_format() {
        let op = ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(0), OperandType::Const);
        let debug = format!("{:?}", op);
        assert!(debug.contains("ZEND_ECHO"), "debug: {}", debug);
        assert!(debug.contains("Const"), "debug: {}", debug);
    }

    #[test]
    fn test_zop_display() {
        let op = ZOp::new(ZOpcode::Add, 3)
            .with_op1(Operand::cv(0), OperandType::Cv)
            .with_op2(Operand::cv(1), OperandType::Cv)
            .with_result(Operand::tmp_var(0), OperandType::TmpVar);
        let display = format!("{}", op);
        assert!(display.contains("ZEND_ADD"), "display: {}", display);
    }

    #[test]
    fn test_zop_disassemble() {
        let op = ZOp::new(ZOpcode::Echo, 1).with_op1(Operand::constant(0), OperandType::Const);
        let dis = op.disassemble();
        assert!(dis.contains("ZEND_ECHO"), "dis: {}", dis);
        assert!(dis.contains("const(0)"), "dis: {}", dis);
    }

    #[test]
    fn test_zop_disassemble_add() {
        let op = ZOp::new(ZOpcode::Add, 3)
            .with_op1(Operand::cv(0), OperandType::Cv)
            .with_op2(Operand::cv(1), OperandType::Cv)
            .with_result(Operand::tmp_var(0), OperandType::TmpVar);
        let dis = op.disassemble();
        assert!(dis.contains("ZEND_ADD"), "dis: {}", dis);
        assert!(dis.contains("CV(0)"), "dis: {}", dis);
        assert!(dis.contains("CV(1)"), "dis: {}", dis);
        assert!(dis.contains("~0"), "dis: {}", dis);
    }

    #[test]
    fn test_zop_extended_value() {
        // ZEND_CAST with extended_value = type
        let op = ZOp::new(ZOpcode::Cast, 5)
            .with_op1(Operand::cv(0), OperandType::Cv)
            .with_result(Operand::tmp_var(0), OperandType::TmpVar)
            .with_extended_value(3); // IS_LONG

        assert_eq!(op.extended_value, 3);
        let debug = format!("{:?}", op);
        assert!(debug.contains("ext:3"), "debug: {}", debug);
    }

    #[test]
    fn test_zop_clone_eq() {
        let op1 = ZOp::new(ZOpcode::Add, 1)
            .with_op1(Operand::cv(0), OperandType::Cv)
            .with_op2(Operand::cv(1), OperandType::Cv)
            .with_result(Operand::tmp_var(0), OperandType::TmpVar);
        let op2 = op1.clone();
        assert_eq!(op1, op2);
    }

    #[test]
    fn test_operand_display_unused() {
        let op = Operand::unused();
        assert_eq!(format!("{}", op), "-");
    }

    #[test]
    fn test_operand_display_value() {
        let op = Operand::constant(42);
        assert_eq!(format!("{}", op), "42");
    }
}
