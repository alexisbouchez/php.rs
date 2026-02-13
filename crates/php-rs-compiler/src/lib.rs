//! PHP compiler
//!
//! This crate compiles PHP AST to Zend VM opcodes.
//! Equivalent to php-src/Zend/zend_compile.c

pub mod op;
pub mod op_array;
pub mod opcode;

pub use op::{Operand, OperandType, ZOp};
pub use op_array::{LiveRange, LiveRangeKind, TryCatchElement, ZOpArray};
pub use opcode::ZOpcode;
