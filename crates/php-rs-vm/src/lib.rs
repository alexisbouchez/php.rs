//! PHP virtual machine -- executes compiled opcode arrays.
//!
//! This crate implements the Zend VM executor that runs the [`ZOpArray`]
//! bytecode produced by [`php_rs_compiler`]. It is equivalent to
//! `php-src/Zend/zend_execute.c` and `php-src/Zend/zend_vm_def.h`.
//!
//! # Main types
//!
//! - [`Vm`] -- The virtual machine. Holds all runtime state (output buffer,
//!   function/class tables, call stack, constants, open resources, etc.) and
//!   provides [`Vm::execute`] to run compiled PHP code.
//! - [`VmConfig`] -- Runtime configuration parsed from PHP INI settings
//!   (memory limit, execution timeout, disabled functions, open_basedir).
//! - [`Value`] -- High-level PHP value representation used during execution.
//!   Supports all PHP types: null, bool, int, float, string, array, object,
//!   resource, and reference.
//! - [`PhpArray`] -- Ordered map with copy-on-write semantics and dual-mode
//!   storage (packed + hash), used as the backing store for PHP arrays.
//! - [`PhpObject`] -- Reference-counted object instance with class name,
//!   properties, and internal state.
//! - [`VmError`] / [`VmResult`] -- Error types for fatal errors, type errors,
//!   undefined variables/functions, exceptions, and resource limit violations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use php_rs_compiler::compile;
//! use php_rs_vm::{Vm, Value};
//!
//! let op_array = compile("<?php echo 'Hello, world!';").unwrap();
//! let mut vm = Vm::new();
//! let output = vm.execute(&op_array, None).unwrap();
//! assert_eq!(output, "Hello, world!");
//! ```
//!
//! [`ZOpArray`]: php_rs_compiler::ZOpArray

pub(crate) mod builtins;
#[cfg(feature = "native-io")]
pub(crate) mod sqlite3;
pub mod value;
pub mod vm;

pub use value::{PhpArray, PhpObject, Value};
pub use vm::{Vm, VmConfig, VmError, VmEvent, VmResult};
