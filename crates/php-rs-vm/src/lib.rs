//! PHP virtual machine
//!
//! This crate implements the Zend VM executor.
//! Equivalent to php-src/Zend/zend_vm_execute.h and zend_vm_def.h

pub mod value;
pub mod vm;

pub use value::{PhpArray, PhpObject, Value};
pub use vm::{Vm, VmConfig, VmError, VmResult};
