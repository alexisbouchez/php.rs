//! PHP compiler -- transforms AST into Zend VM opcode arrays.
//!
//! This crate takes the AST produced by [`php_rs_parser`] and compiles it into
//! [`ZOpArray`] structures containing [`ZOp`] instructions, ready for execution
//! by the VM in `php-rs-vm`. It is equivalent to `php-src/Zend/zend_compile.c`.
//!
//! # Main types
//!
//! - [`Compiler`] -- The AST-to-opcode compiler. Walks AST nodes and emits
//!   instructions into a [`ZOpArray`].
//! - [`ZOpArray`] -- A compiled function, method, or top-level script. Contains
//!   the opcode sequence, literal pool, variable tables, and exception handling info.
//! - [`ZOp`] -- A single VM instruction with opcode, operands, and source line number.
//!   Mirrors `struct _zend_op` from `zend_compile.h`.
//! - [`ZOpcode`] -- Enum of all 212 Zend VM opcodes, matching
//!   `php-src/Zend/zend_vm_opcodes.h` exactly.
//! - [`Operand`] / [`OperandType`] -- Instruction operands (constants, temps,
//!   compiled variables, jump targets).
//!
//! # Convenience functions
//!
//! - [`compile`] -- Parse and compile a PHP source string in one step.
//! - [`compile_file`] -- Same as `compile`, but with a filename for `__FILE__` / `__DIR__`.
//! - [`compile_optimized`] -- Compile with basic optimization passes (constant folding,
//!   dead code elimination).
//! - [`optimize`] -- Apply optimization passes to an existing [`ZOpArray`].

pub mod compiler;
pub mod op;
pub mod op_array;
pub mod opcode;

pub use compiler::{compile, compile_file, compile_optimized, optimize, Compiler};
pub use op::{Operand, OperandType, ZOp};
pub use op_array::{LiveRange, LiveRangeKind, TryCatchElement, ZOpArray};
pub use opcode::ZOpcode;
