//! PHP Virtual Machine — executes compiled opcode arrays.
//!
//! Equivalent to php-src/Zend/zend_execute.c and zend_vm_def.h.

use std::collections::HashMap;

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;

use crate::value::{PhpArray, Value};

/// VM execution result.
#[derive(Debug)]
pub enum VmError {
    /// A PHP fatal error occurred.
    FatalError(String),
    /// Division by zero.
    DivisionByZero,
    /// Undefined variable.
    UndefinedVariable(String),
    /// Undefined function.
    UndefinedFunction(String),
    /// Match error (no arm matched).
    MatchError,
    /// Type error.
    TypeError(String),
    /// Thrown exception (value).
    Thrown(Value),
    /// Internal: invalid opcode / bad operand.
    InternalError(String),
}

pub type VmResult<T> = Result<T, VmError>;

/// An execution frame — one per function call / script execution.
///
/// Mirrors `_zend_execute_data` from php-src.
struct Frame {
    /// Reference to the op_array being executed (index into VM's op_array storage).
    op_array_idx: usize,
    /// Instruction pointer (index into op_array.opcodes).
    ip: usize,
    /// Compiled variables (CVs): named local variables.
    cvs: Vec<Value>,
    /// Temporary variable slots.
    temps: Vec<Value>,
    /// Return value from this frame (set by RETURN).
    return_value: Value,
    /// Stack of pending calls (supports nested calls like add(mul(2,3), mul(4,5))).
    /// Each entry is (function_name, args_so_far).
    call_stack_pending: Vec<(String, Vec<Value>)>,
    /// Arguments passed to this frame (for RECV opcodes).
    args: Vec<Value>,
    /// Where to store the return value in the caller's frame when this frame returns.
    /// (result_type, result_slot)
    return_dest: Option<(OperandType, u32)>,
}

impl Frame {
    fn new(op_array: &ZOpArray) -> Self {
        let num_cvs = op_array.vars.len();
        let num_temps = op_array.num_temps as usize;
        Self {
            op_array_idx: 0,
            ip: 0,
            cvs: vec![Value::Null; num_cvs],
            temps: vec![Value::Null; num_temps],
            return_value: Value::Null,
            call_stack_pending: Vec::new(),
            args: Vec::new(),
            return_dest: None,
        }
    }
}

/// The PHP Virtual Machine.
pub struct Vm {
    /// Output buffer (captures echo output).
    output: String,
    /// Function table: name → op_array index.
    functions: HashMap<String, usize>,
    /// All op_arrays (main script + declared functions).
    op_arrays: Vec<ZOpArray>,
    /// Call stack.
    call_stack: Vec<Frame>,
    /// Global constants.
    constants: HashMap<String, Value>,
}

/// Signal from an opcode handler to the dispatch loop.
enum DispatchSignal {
    /// Continue to next opcode.
    Next,
    /// Jump to a specific opline.
    Jump(usize),
    /// Return from the current frame.
    Return,
    /// A new frame was pushed; don't advance IP (callee starts at ip=0).
    CallPushed,
}

impl Vm {
    /// Create a new VM.
    pub fn new() -> Self {
        Self {
            output: String::new(),
            functions: HashMap::new(),
            op_arrays: Vec::new(),
            call_stack: Vec::new(),
            constants: HashMap::new(),
        }
    }

    /// Execute a compiled op_array and return the output.
    pub fn execute(&mut self, op_array: &ZOpArray) -> VmResult<String> {
        // Store the main op_array
        self.op_arrays.clear();
        self.op_arrays.push(op_array.clone());
        self.functions.clear();
        self.output.clear();

        // Pre-register any nested function definitions from dynamic_func_defs
        self.register_dynamic_func_defs(0);

        // Create the main frame
        let mut frame = Frame::new(op_array);
        frame.op_array_idx = 0;

        self.call_stack.push(frame);
        self.dispatch_loop()?;

        Ok(self.output.clone())
    }

    /// Register dynamic_func_defs from an op_array into the function table.
    fn register_dynamic_func_defs(&mut self, parent_idx: usize) {
        let defs: Vec<ZOpArray> = self.op_arrays[parent_idx].dynamic_func_defs.clone();
        for def in defs {
            if let Some(ref name) = def.function_name {
                let idx = self.op_arrays.len();
                let name = name.clone();
                self.op_arrays.push(def);
                self.functions.insert(name, idx);
            }
        }
    }

    /// Main dispatch loop.
    fn dispatch_loop(&mut self) -> VmResult<()> {
        loop {
            if self.call_stack.is_empty() {
                return Ok(());
            }

            let frame = self.call_stack.last().unwrap();
            let op_array_idx = frame.op_array_idx;
            let ip = frame.ip;

            if ip >= self.op_arrays[op_array_idx].opcodes.len() {
                // Fell off end — implicit return
                self.call_stack.pop();
                continue;
            }

            let op = self.op_arrays[op_array_idx].opcodes[ip].clone();

            match self.dispatch_op(&op, op_array_idx)? {
                DispatchSignal::Next => {
                    self.call_stack.last_mut().unwrap().ip += 1;
                }
                DispatchSignal::Jump(target) => {
                    self.call_stack.last_mut().unwrap().ip = target;
                }
                DispatchSignal::Return => {
                    let frame = self.call_stack.pop().unwrap();
                    let ret_val = frame.return_value;
                    // Store return value in caller's result slot if specified
                    if let Some((ret_type, ret_slot)) = frame.return_dest {
                        if let Some(caller) = self.call_stack.last_mut() {
                            match ret_type {
                                OperandType::TmpVar | OperandType::Var => {
                                    let slot = ret_slot as usize;
                                    if slot >= caller.temps.len() {
                                        caller.temps.resize(slot + 1, Value::Null);
                                    }
                                    caller.temps[slot] = ret_val;
                                }
                                OperandType::Cv => {
                                    let idx = ret_slot as usize;
                                    if idx >= caller.cvs.len() {
                                        caller.cvs.resize(idx + 1, Value::Null);
                                    }
                                    caller.cvs[idx] = ret_val;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                DispatchSignal::CallPushed => {
                    // New frame was pushed; don't advance IP.
                    // The callee's ip starts at 0.
                }
            }
        }
    }

    /// Dispatch a single opcode.
    fn dispatch_op(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        match op.opcode {
            ZOpcode::Nop => Ok(DispatchSignal::Next),

            // =====================================================================
            // Arithmetic
            // =====================================================================
            ZOpcode::Add => self.op_binary(op, oa_idx, |a, b| a.add(&b)),
            ZOpcode::Sub => self.op_binary(op, oa_idx, |a, b| a.sub(&b)),
            ZOpcode::Mul => self.op_binary(op, oa_idx, |a, b| a.mul(&b)),
            ZOpcode::Div => self.op_binary(op, oa_idx, |a, b| a.div(&b)),
            ZOpcode::Mod => self.op_binary(op, oa_idx, |a, b| a.modulo(&b)),
            ZOpcode::Pow => self.op_binary(op, oa_idx, |a, b| a.pow(&b)),
            ZOpcode::Sl => self.op_binary(op, oa_idx, |a, b| a.shl(&b)),
            ZOpcode::Sr => self.op_binary(op, oa_idx, |a, b| a.shr(&b)),
            ZOpcode::Concat | ZOpcode::FastConcat => {
                self.op_binary(op, oa_idx, |a, b| a.concat(&b))
            }

            // Bitwise
            ZOpcode::BwOr => self.op_binary(op, oa_idx, |a, b| a.bw_or(&b)),
            ZOpcode::BwAnd => self.op_binary(op, oa_idx, |a, b| a.bw_and(&b)),
            ZOpcode::BwXor => self.op_binary(op, oa_idx, |a, b| a.bw_xor(&b)),
            ZOpcode::BwNot => self.op_unary(op, oa_idx, |a| a.bw_not()),
            ZOpcode::BoolNot => self.op_unary(op, oa_idx, |a| a.bool_not()),
            ZOpcode::BoolXor => self.op_binary(op, oa_idx, |a, b| a.bool_xor(&b)),

            // =====================================================================
            // Comparison
            // =====================================================================
            ZOpcode::IsEqual => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.loose_eq(&b))),
            ZOpcode::IsNotEqual => self.op_binary(op, oa_idx, |a, b| Value::Bool(!a.loose_eq(&b))),
            ZOpcode::IsIdentical => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.strict_eq(&b))),
            ZOpcode::IsNotIdentical => {
                self.op_binary(op, oa_idx, |a, b| Value::Bool(!a.strict_eq(&b)))
            }
            ZOpcode::IsSmaller => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.is_smaller(&b))),
            ZOpcode::IsSmallerOrEqual => {
                self.op_binary(op, oa_idx, |a, b| Value::Bool(!b.is_smaller(&a)))
            }
            ZOpcode::Spaceship => self.op_binary(op, oa_idx, |a, b| Value::Long(a.spaceship(&b))),
            ZOpcode::Case | ZOpcode::CaseStrict => {
                // CASE: compare op1 (switch value) with op2, result is bool
                let switch_val = self.read_operand(op, 1, oa_idx)?;
                let case_val = self.read_operand(op, 2, oa_idx)?;
                let result = if op.opcode == ZOpcode::CaseStrict {
                    switch_val.strict_eq(&case_val)
                } else {
                    switch_val.loose_eq(&case_val)
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Assignment
            // =====================================================================
            ZOpcode::Assign => {
                let val = self.read_operand(op, 2, oa_idx)?;
                self.write_cv(op, oa_idx, val.clone())?;
                // If result is used, store the assigned value
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, val)?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignDim => {
                // $arr[$key] = $val
                // op1 = array CV, op2 = key (or Unused for append), next op is OP_DATA with value
                let arr_cv = op.op1.val as usize;
                let key = if op.op2_type != OperandType::Unused {
                    Some(self.read_operand(op, 2, oa_idx)?)
                } else {
                    None
                };

                // Look ahead for OP_DATA
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let val = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if data_op.opcode == ZOpcode::OpData {
                        self.read_operand_from(data_op, 1, oa_idx)?
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let frame = self.call_stack.last_mut().unwrap();
                let arr_val = &mut frame.cvs[arr_cv];
                // Ensure it's an array
                if matches!(arr_val, Value::Null) {
                    *arr_val = Value::Array(PhpArray::new());
                }
                if let Value::Array(ref mut arr) = arr_val {
                    match key {
                        Some(k) => arr.set(&k, val),
                        None => arr.push(val),
                    }
                }

                // Skip OP_DATA
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignOp => {
                // Compound assignment: +=, -=, etc.
                // op1 = CV, op2 = value, extended_value = operation
                let cv_idx = op.op1.val as usize;
                let rhs = self.read_operand(op, 2, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                let lhs = frame.cvs[cv_idx].clone();
                let result = apply_assign_op(op.extended_value, &lhs, &rhs);
                frame.cvs[cv_idx] = result.clone();
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, result)?;
                }
                Ok(DispatchSignal::Next)
            }

            // Increment / Decrement
            ZOpcode::PreInc => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let new_val = frame.cvs[cv_idx].increment();
                frame.cvs[cv_idx] = new_val.clone();
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = new_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PreDec => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let new_val = frame.cvs[cv_idx].decrement();
                frame.cvs[cv_idx] = new_val.clone();
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = new_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PostInc => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let old_val = frame.cvs[cv_idx].clone();
                frame.cvs[cv_idx] = old_val.increment();
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = old_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PostDec => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let old_val = frame.cvs[cv_idx].clone();
                frame.cvs[cv_idx] = old_val.decrement();
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = old_val;
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Variable access
            // =====================================================================
            ZOpcode::QmAssign | ZOpcode::Bool => {
                // QM_ASSIGN: copy op1 to result (used for ternary, etc.)
                // BOOL: convert op1 to boolean in result
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = if op.opcode == ZOpcode::Bool {
                    Value::Bool(val.to_bool())
                } else {
                    val
                };
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchDimR | ZOpcode::FetchDimIs => {
                // Array read: op1[$op2] → result
                let arr = self.read_operand(op, 1, oa_idx)?;
                let key = self.read_operand(op, 2, oa_idx)?;
                let val = if let Value::Array(ref a) = arr {
                    a.get(&key).cloned().unwrap_or(Value::Null)
                } else if let Value::String(ref s) = arr {
                    // String character access
                    let idx = key.to_long();
                    if idx >= 0 && (idx as usize) < s.len() {
                        Value::String(s.chars().nth(idx as usize).unwrap().to_string())
                    } else {
                        Value::String(String::new())
                    }
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyCv => {
                // Check if CV is set and not null (isset) or empty
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let val = &frame.cvs[cv_idx];
                // extended_value: 0x0200000 = ISSET, 0x0100000 = EMPTY
                let result = if op.extended_value & 1 != 0 {
                    // empty()
                    !val.to_bool()
                } else {
                    // isset()
                    !val.is_null()
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyDimObj => {
                // isset($arr[$key]) / empty($arr[$key])
                let arr = self.read_operand(op, 1, oa_idx)?;
                let key = self.read_operand(op, 2, oa_idx)?;
                let val = if let Value::Array(ref a) = arr {
                    a.get(&key).cloned().unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                let result = if op.extended_value & 1 != 0 {
                    !val.to_bool() // empty
                } else {
                    !val.is_null() // isset
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetCv => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                frame.cvs[cv_idx] = Value::Null;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetDim => {
                // unset($arr[$key])
                let cv_idx = op.op1.val as usize;
                let key = self.read_operand(op, 2, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                if let Value::Array(ref mut arr) = frame.cvs[cv_idx] {
                    arr.unset(&key);
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Control flow
            // =====================================================================
            ZOpcode::Jmp => {
                let target = op.op1.val as usize;
                Ok(DispatchSignal::Jump(target))
            }
            ZOpcode::Jmpz => {
                let val = self.read_operand(op, 1, oa_idx)?;
                if !val.to_bool() {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Jmpnz => {
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.to_bool() {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpzEx => {
                // Jump if zero, also store bool result
                let val = self.read_operand(op, 1, oa_idx)?;
                let b = val.to_bool();
                self.write_result(op, oa_idx, Value::Bool(b))?;
                if !b {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpnzEx => {
                // Jump if non-zero, also store bool result
                let val = self.read_operand(op, 1, oa_idx)?;
                let b = val.to_bool();
                self.write_result(op, oa_idx, Value::Bool(b))?;
                if b {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpSet => {
                // $a ?: $b — if op1 is truthy, result = op1 and jump
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.to_bool() {
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Coalesce => {
                // $a ?? $b — if op1 is not null, result = op1 and jump
                let val = self.read_operand(op, 1, oa_idx)?;
                if !val.is_null() {
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Match => {
                // MATCH: compare op1 against a jump table
                // For simplicity, we treat it like a NOP and let CASE_STRICT do the work
                Ok(DispatchSignal::Next)
            }
            ZOpcode::MatchError => Err(VmError::MatchError),

            // Foreach
            ZOpcode::FeResetR => {
                // Initialize foreach iterator
                let arr = self.read_operand(op, 1, oa_idx)?;
                match arr {
                    Value::Array(a) => {
                        let iter = Value::_Iterator { array: a, index: 0 };
                        self.write_result(op, oa_idx, iter)?;
                        Ok(DispatchSignal::Next)
                    }
                    _ => {
                        // Jump to end if not iterable
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                }
            }
            ZOpcode::FeFetchR => {
                // Fetch current element: op1 = iterator, result = value
                // op2 = jump target when exhausted
                let iter_slot = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let iter = frame.temps[iter_slot].clone();

                if let Value::_Iterator { ref array, index } = iter {
                    if let Some((key, val)) = array.entry_at(index) {
                        let val = val.clone();
                        let key_val = match key {
                            crate::value::ArrayKey::Int(n) => Value::Long(*n),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        // Store value in result
                        self.write_result(op, oa_idx, val)?;
                        // If extended_value indicates key variable, store key in the next temp
                        if op.result_type != OperandType::Unused {
                            let result_slot = op.result.val as usize;
                            // Key is stored in result_slot + 1 (convention)
                            let frame = self.call_stack.last_mut().unwrap();
                            if result_slot + 1 < frame.temps.len() {
                                frame.temps[result_slot + 1] = key_val;
                            }
                        }
                        // Advance iterator
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_Iterator {
                            array: array.clone(),
                            index: index + 1,
                        };
                        Ok(DispatchSignal::Next)
                    } else {
                        // Exhausted
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                } else {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                }
            }
            ZOpcode::FeFree => {
                // Free foreach iterator
                let slot = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                frame.temps[slot] = Value::Null;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Array operations
            // =====================================================================
            ZOpcode::InitArray => {
                let mut arr = PhpArray::new();
                if op.op1_type != OperandType::Unused {
                    let val = self.read_operand(op, 1, oa_idx)?;
                    if op.op2_type != OperandType::Unused {
                        let key = self.read_operand(op, 2, oa_idx)?;
                        arr.set(&key, val);
                    } else {
                        arr.push(val);
                    }
                }
                self.write_result(op, oa_idx, Value::Array(arr))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AddArrayElement => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let key = if op.op2_type != OperandType::Unused {
                    Some(self.read_operand(op, 2, oa_idx)?)
                } else {
                    None
                };
                let result_slot = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if let Value::Array(ref mut arr) = frame.temps[result_slot] {
                    match key {
                        Some(k) => arr.set(&k, val),
                        None => arr.push(val),
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Function calls
            // =====================================================================
            ZOpcode::InitFcall | ZOpcode::InitFcallByName | ZOpcode::InitNsFcallByName => {
                // Push a new pending call onto the stack
                let name_val = self.read_operand(op, 2, oa_idx)?;
                let name = name_val.to_php_string();
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push((name, Vec::new()));
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitDynamicCall => {
                let name_val = self.read_operand(op, 2, oa_idx)?;
                let name = name_val.to_php_string();
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push((name, Vec::new()));
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendVal
            | ZOpcode::SendVar
            | ZOpcode::SendValEx
            | ZOpcode::SendVarEx
            | ZOpcode::SendRef
            | ZOpcode::SendVarNoRef
            | ZOpcode::SendVarNoRefEx
            | ZOpcode::SendFuncArg => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                if let Some(pending) = frame.call_stack_pending.last_mut() {
                    pending.1.push(val);
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendUnpack => {
                // ...$args spread
                let val = self.read_operand(op, 1, oa_idx)?;
                if let Value::Array(ref arr) = val {
                    let frame = self.call_stack.last_mut().unwrap();
                    if let Some(pending) = frame.call_stack_pending.last_mut() {
                        for (_key, v) in arr.entries() {
                            pending.1.push(v.clone());
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DoFcall | ZOpcode::DoIcall | ZOpcode::DoUcall | ZOpcode::DoFcallByName => {
                self.handle_do_fcall(op, oa_idx)
            }
            ZOpcode::Recv => {
                // Receive parameter: op1 = arg number (1-based)
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if arg_num > 0 && arg_num <= frame.args.len() {
                    let val = frame.args[arg_num - 1].clone();
                    frame.cvs[result_cv] = val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RecvInit => {
                // Receive parameter with default: op1 = arg number, op2 = default
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last().unwrap();
                let has_arg = arg_num > 0 && arg_num <= frame.args.len();
                let val = if has_arg {
                    frame.args[arg_num - 1].clone()
                } else {
                    self.read_operand(op, 2, oa_idx)?
                };
                let frame = self.call_stack.last_mut().unwrap();
                frame.cvs[result_cv] = val;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RecvVariadic => {
                // Collect remaining args into array
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let mut arr = PhpArray::new();
                if arg_num > 0 {
                    for i in (arg_num - 1)..frame.args.len() {
                        arr.push(frame.args[i].clone());
                    }
                }
                frame.cvs[result_cv] = Value::Array(arr);
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Return
            // =====================================================================
            ZOpcode::Return | ZOpcode::ReturnByRef | ZOpcode::GeneratorReturn => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                frame.return_value = val;
                Ok(DispatchSignal::Return)
            }

            // =====================================================================
            // I/O
            // =====================================================================
            ZOpcode::Echo => {
                let val = self.read_operand(op, 1, oa_idx)?;
                self.output.push_str(&val.to_php_string());
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Type & Cast
            // =====================================================================
            ZOpcode::Cast => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = val.cast(op.extended_value);
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::TypeCheck => {
                // Check type: extended_value encodes which type to check
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = match op.extended_value {
                    1 => val.is_null(),                     // IS_NULL
                    2 => matches!(val, Value::Bool(false)), // IS_FALSE
                    4 => matches!(val, Value::Bool(true)),  // IS_TRUE
                    16 => matches!(val, Value::Long(_)),    // IS_LONG
                    32 => matches!(val, Value::Double(_)),  // IS_DOUBLE
                    64 => matches!(val, Value::String(_)),  // IS_STRING
                    128 => matches!(val, Value::Array(_)),  // IS_ARRAY
                    _ => false,
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Strlen => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let len = match val {
                    Value::String(ref s) => s.len() as i64,
                    _ => val.to_php_string().len() as i64,
                };
                self.write_result(op, oa_idx, Value::Long(len))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Count => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let count = match val {
                    Value::Array(ref a) => a.len() as i64,
                    Value::Null => 0,
                    _ => 1,
                };
                self.write_result(op, oa_idx, Value::Long(count))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Declarations
            // =====================================================================
            ZOpcode::DeclareFunction => {
                // op1 = function name (Const) — register it
                let name_val = self.read_operand(op, 1, oa_idx)?;
                let name = name_val.to_php_string();
                // The function's op_array is in dynamic_func_defs
                // It should already be registered from register_dynamic_func_defs
                if !self.functions.contains_key(&name) {
                    // Try to find it in dynamic_func_defs
                    let defs = &self.op_arrays[oa_idx].dynamic_func_defs;
                    for def in defs {
                        if def.function_name.as_deref() == Some(name.as_str()) {
                            let idx = self.op_arrays.len();
                            self.op_arrays.push(def.clone());
                            self.functions.insert(name, idx);
                            break;
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareConst => {
                // op1 = name (Const), op2 = value
                let name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.read_operand(op, 2, oa_idx)?;
                self.constants.insert(name, val);
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchConstant => {
                // op2 = constant name
                let name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let val = self.constants.get(&name).cloned().unwrap_or(Value::Null);
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareClass | ZOpcode::DeclareClassDelayed | ZOpcode::DeclareAnonClass => {
                // For now, NOP — class support will be Phase 5.10
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareLambdaFunction => {
                // Creates a closure value
                // op1 = index into dynamic_func_defs
                // For now just produce Null
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Exception handling (basic stubs)
            // =====================================================================
            ZOpcode::Throw => {
                let val = self.read_operand(op, 1, oa_idx)?;
                Err(VmError::Thrown(val))
            }
            ZOpcode::Catch => {
                // Handled by dispatch_loop's error handling (TODO: proper implementation)
                Ok(DispatchSignal::Next)
            }
            ZOpcode::HandleException | ZOpcode::DiscardException => Ok(DispatchSignal::Next),
            ZOpcode::FastCall => {
                // Jump to finally block
                Ok(DispatchSignal::Jump(op.op1.val as usize))
            }
            ZOpcode::FastRet => {
                // Return from finally block
                Ok(DispatchSignal::Jump(op.op1.val as usize))
            }

            // =====================================================================
            // Other
            // =====================================================================
            ZOpcode::Free => {
                // Free a temporary
                let slot = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if slot < frame.temps.len() {
                    frame.temps[slot] = Value::Null;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::OpData => {
                // OP_DATA is consumed by the preceding instruction
                Ok(DispatchSignal::Next)
            }
            ZOpcode::BindGlobal => {
                // For now, NOP
                Ok(DispatchSignal::Next)
            }
            ZOpcode::BindStatic => Ok(DispatchSignal::Next),
            ZOpcode::VerifyReturnType | ZOpcode::VerifyNeverType => Ok(DispatchSignal::Next),
            ZOpcode::CheckVar | ZOpcode::CheckFuncArg | ZOpcode::CheckUndefArgs => {
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Defined => {
                let name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let exists = self.constants.contains_key(&name);
                self.write_result(op, oa_idx, Value::Bool(exists))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::CopyTmp => {
                let val = self.read_operand(op, 1, oa_idx)?;
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }

            // Anything else: NOP for now
            _ => Ok(DispatchSignal::Next),
        }
    }

    /// Handle DO_FCALL — execute a function call.
    fn handle_do_fcall(&mut self, op: &ZOp, caller_oa_idx: usize) -> VmResult<DispatchSignal> {
        let caller_frame = self.call_stack.last_mut().unwrap();
        let (func_name, args) = caller_frame.call_stack_pending.pop().unwrap_or_default();

        // Check built-in functions first
        if let Some(result) = self.call_builtin(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Look up user-defined function
        let func_oa_idx = self.functions.get(&func_name).copied();
        if let Some(oa_idx) = func_oa_idx {
            // Advance caller's IP past DO_FCALL BEFORE pushing new frame
            self.call_stack.last_mut().unwrap().ip += 1;

            let func_oa = &self.op_arrays[oa_idx];
            let mut new_frame = Frame::new(func_oa);
            new_frame.op_array_idx = oa_idx;
            new_frame.args = args.clone();

            // Store where to put the return value
            if op.result_type != OperandType::Unused {
                new_frame.return_dest = Some((op.result_type, op.result.val));
            }

            // Bind parameters to CVs directly (for functions without RECV opcodes)
            let num_params = func_oa.arg_info.len().min(args.len());
            for i in 0..num_params {
                if i < new_frame.cvs.len() {
                    new_frame.cvs[i] = args[i].clone();
                }
            }

            self.call_stack.push(new_frame);
            return Ok(DispatchSignal::CallPushed);
        }

        Err(VmError::UndefinedFunction(func_name))
    }

    /// Call a built-in function. Returns Some(Value) if handled, None if not a built-in.
    fn call_builtin(&mut self, name: &str, args: &[Value]) -> VmResult<Option<Value>> {
        match name {
            "strlen" => {
                let s = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Long(s.to_php_string().len() as i64)))
            }
            "count" | "sizeof" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                let n = match v {
                    Value::Array(ref a) => a.len() as i64,
                    _ => 1,
                };
                Ok(Some(Value::Long(n)))
            }
            "var_dump" => {
                for arg in args {
                    self.var_dump(arg, 0);
                }
                Ok(Some(Value::Null))
            }
            "print_r" => {
                let val = args.first().cloned().unwrap_or(Value::Null);
                let ret_string = args.get(1).is_some_and(|v| v.to_bool());
                let s = self.print_r_string(&val, 0);
                if ret_string {
                    Ok(Some(Value::String(s)))
                } else {
                    self.output.push_str(&s);
                    Ok(Some(Value::Bool(true)))
                }
            }
            "is_int" | "is_integer" | "is_long" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::Long(_)))))
            }
            "is_float" | "is_double" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::Double(_)))))
            }
            "is_string" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::String(_)))))
            }
            "is_bool" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::Bool(_)))))
            }
            "is_null" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(v.is_null())))
            }
            "is_array" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::Array(_)))))
            }
            "is_numeric" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                let result = match v {
                    Value::Long(_) | Value::Double(_) => true,
                    Value::String(ref s) => s.trim().parse::<f64>().is_ok(),
                    _ => false,
                };
                Ok(Some(Value::Bool(result)))
            }
            "intval" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Long(v.to_long())))
            }
            "floatval" | "doubleval" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Double(v.to_double())))
            }
            "strval" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::String(v.to_php_string())))
            }
            "boolval" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(v.to_bool())))
            }
            "gettype" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                let t = match v {
                    Value::Null => "NULL",
                    Value::Bool(_) => "boolean",
                    Value::Long(_) => "integer",
                    Value::Double(_) => "double",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::_Iterator { .. } => "unknown type",
                };
                Ok(Some(Value::String(t.to_string())))
            }
            "settype" => {
                // Can't mutate args directly in our model; return success
                Ok(Some(Value::Bool(true)))
            }
            "abs" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                let result = match v {
                    Value::Long(n) => Value::Long(n.abs()),
                    Value::Double(f) => Value::Double(f.abs()),
                    _ => Value::Long(v.to_long().abs()),
                };
                Ok(Some(result))
            }
            "max" => {
                if args.len() == 1 {
                    if let Value::Array(ref a) = args[0] {
                        let mut max = Value::Null;
                        for (_, v) in a.entries() {
                            if max.is_null() || v.is_smaller(&max) == false && !max.strict_eq(v) {
                                max = v.clone();
                            }
                        }
                        return Ok(Some(max));
                    }
                }
                let mut max = args.first().cloned().unwrap_or(Value::Null);
                for v in args.iter().skip(1) {
                    if max.is_smaller(v) {
                        max = v.clone();
                    }
                }
                Ok(Some(max))
            }
            "min" => {
                if args.len() == 1 {
                    if let Value::Array(ref a) = args[0] {
                        let mut min = Value::Null;
                        for (_, v) in a.entries() {
                            if min.is_null() || v.is_smaller(&min) {
                                min = v.clone();
                            }
                        }
                        return Ok(Some(min));
                    }
                }
                let mut min = args.first().cloned().unwrap_or(Value::Null);
                for v in args.iter().skip(1) {
                    if v.is_smaller(&min) {
                        min = v.clone();
                    }
                }
                Ok(Some(min))
            }
            "array_push" => {
                // Can't mutate args; return count
                let arr = args.first().cloned().unwrap_or(Value::Null);
                let count = if let Value::Array(ref a) = arr {
                    a.len() + args.len() - 1
                } else {
                    0
                };
                Ok(Some(Value::Long(count as i64)))
            }
            "array_pop" => Ok(Some(Value::Null)),
            "array_key_exists" => {
                let key = args.first().cloned().unwrap_or(Value::Null);
                let arr = args.get(1).cloned().unwrap_or(Value::Null);
                let exists = if let Value::Array(ref a) = arr {
                    a.get(&key).is_some()
                } else {
                    false
                };
                Ok(Some(Value::Bool(exists)))
            }
            "in_array" => {
                let needle = args.first().cloned().unwrap_or(Value::Null);
                let haystack = args.get(1).cloned().unwrap_or(Value::Null);
                let strict = args.get(2).is_some_and(|v| v.to_bool());
                let found = if let Value::Array(ref a) = haystack {
                    a.entries().iter().any(|(_, v)| {
                        if strict {
                            needle.strict_eq(v)
                        } else {
                            needle.loose_eq(v)
                        }
                    })
                } else {
                    false
                };
                Ok(Some(Value::Bool(found)))
            }
            "implode" | "join" => {
                let (glue, pieces) = if args.len() >= 2 {
                    (args[0].to_php_string(), args[1].clone())
                } else {
                    (String::new(), args.first().cloned().unwrap_or(Value::Null))
                };
                let result = if let Value::Array(ref a) = pieces {
                    let parts: Vec<String> =
                        a.entries().iter().map(|(_, v)| v.to_php_string()).collect();
                    parts.join(&glue)
                } else {
                    String::new()
                };
                Ok(Some(Value::String(result)))
            }
            "explode" => {
                let delimiter = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let string = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let mut arr = PhpArray::new();
                if delimiter.is_empty() {
                    return Ok(Some(Value::Bool(false)));
                }
                for part in string.split(&delimiter) {
                    arr.push(Value::String(part.to_string()));
                }
                Ok(Some(Value::Array(arr)))
            }
            "strtolower" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(s.to_lowercase())))
            }
            "strtoupper" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(s.to_uppercase())))
            }
            "substr" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let start = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                let len = args.get(2).map(|v| v.to_long());

                let slen = s.len() as i64;
                let start = if start < 0 {
                    (slen + start).max(0) as usize
                } else {
                    start.min(slen) as usize
                };

                let result = match len {
                    Some(l) if l < 0 => {
                        let end = (slen + l).max(0) as usize;
                        if start < end {
                            &s[start..end]
                        } else {
                            ""
                        }
                    }
                    Some(l) => {
                        let end = (start + l as usize).min(s.len());
                        &s[start..end]
                    }
                    None => &s[start..],
                };
                Ok(Some(Value::String(result.to_string())))
            }
            "str_repeat" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let n = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                Ok(Some(Value::String(s.repeat(n.max(0) as usize))))
            }
            "trim" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(s.trim().to_string())))
            }
            "ltrim" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(s.trim_start().to_string())))
            }
            "rtrim" | "chop" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(s.trim_end().to_string())))
            }
            "str_contains" => {
                let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(haystack.contains(&needle))))
            }
            "str_starts_with" => {
                let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(haystack.starts_with(&needle))))
            }
            "str_ends_with" => {
                let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(haystack.ends_with(&needle))))
            }
            "strpos" => {
                let haystack = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let needle = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let offset = args.get(2).map(|v| v.to_long()).unwrap_or(0) as usize;
                match haystack[offset..].find(&needle) {
                    Some(pos) => Ok(Some(Value::Long((pos + offset) as i64))),
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "str_replace" => {
                let search = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let replace = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let subject = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(subject.replace(&search, &replace))))
            }
            "sprintf" => {
                // Basic sprintf: handle %s, %d, %f
                let fmt = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let mut result = String::new();
                let mut arg_idx = 1;
                let mut chars = fmt.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '%' {
                        if let Some(&next) = chars.peek() {
                            match next {
                                '%' => {
                                    chars.next();
                                    result.push('%');
                                }
                                's' => {
                                    chars.next();
                                    let v = args.get(arg_idx).cloned().unwrap_or(Value::Null);
                                    result.push_str(&v.to_php_string());
                                    arg_idx += 1;
                                }
                                'd' => {
                                    chars.next();
                                    let v = args.get(arg_idx).cloned().unwrap_or(Value::Null);
                                    result.push_str(&v.to_long().to_string());
                                    arg_idx += 1;
                                }
                                'f' => {
                                    chars.next();
                                    let v = args.get(arg_idx).cloned().unwrap_or(Value::Null);
                                    result.push_str(&format!("{:.6}", v.to_double()));
                                    arg_idx += 1;
                                }
                                _ => {
                                    result.push(ch);
                                }
                            }
                        } else {
                            result.push(ch);
                        }
                    } else {
                        result.push(ch);
                    }
                }
                Ok(Some(Value::String(result)))
            }
            "chr" => {
                let n = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
                Ok(Some(Value::String(((n & 0xFF) as u8 as char).to_string())))
            }
            "ord" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let n = s.bytes().next().unwrap_or(0) as i64;
                Ok(Some(Value::Long(n)))
            }
            "array_keys" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                let mut result = PhpArray::new();
                if let Value::Array(ref a) = arr {
                    for (key, _) in a.entries() {
                        match key {
                            crate::value::ArrayKey::Int(n) => result.push(Value::Long(*n)),
                            crate::value::ArrayKey::String(s) => {
                                result.push(Value::String(s.clone()))
                            }
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "array_values" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                let mut result = PhpArray::new();
                if let Value::Array(ref a) = arr {
                    for (_, v) in a.entries() {
                        result.push(v.clone());
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "array_merge" => {
                let mut result = PhpArray::new();
                for arg in args {
                    if let Value::Array(ref a) = arg {
                        for (key, val) in a.entries() {
                            match key {
                                crate::value::ArrayKey::Int(_) => result.push(val.clone()),
                                crate::value::ArrayKey::String(s) => {
                                    result.set_string(s.clone(), val.clone());
                                }
                            }
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "array_reverse" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                let mut result = PhpArray::new();
                if let Value::Array(ref a) = arr {
                    let entries: Vec<_> = a.entries().iter().rev().collect();
                    for (key, val) in entries {
                        match key {
                            crate::value::ArrayKey::Int(_) => result.push(val.clone()),
                            crate::value::ArrayKey::String(s) => {
                                result.set_string(s.clone(), val.clone());
                            }
                        }
                    }
                }
                Ok(Some(Value::Array(result)))
            }
            "array_map" => {
                // array_map(null, $array) = identity
                // We can't execute closures yet, so just handle null case
                let arr = args.get(1).cloned().unwrap_or(Value::Null);
                Ok(Some(arr))
            }
            "array_slice" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                let offset = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                let length = args.get(2).map(|v| v.to_long());

                if let Value::Array(ref a) = arr {
                    let entries = a.entries();
                    let len = entries.len() as i64;
                    let start = if offset < 0 {
                        (len + offset).max(0) as usize
                    } else {
                        offset as usize
                    };
                    let end = match length {
                        Some(l) if l < 0 => (len + l).max(0) as usize,
                        Some(l) => (start + l as usize).min(entries.len()),
                        None => entries.len(),
                    };
                    let mut result = PhpArray::new();
                    for (_, val) in &entries[start..end] {
                        result.push(val.clone());
                    }
                    Ok(Some(Value::Array(result)))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "range" => {
                let low = args.first().cloned().unwrap_or(Value::Long(0)).to_long();
                let high = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                let step = args
                    .get(2)
                    .cloned()
                    .unwrap_or(Value::Long(1))
                    .to_long()
                    .max(1);
                let mut arr = PhpArray::new();
                if low <= high {
                    let mut i = low;
                    while i <= high {
                        arr.push(Value::Long(i));
                        i += step;
                    }
                } else {
                    let mut i = low;
                    while i >= high {
                        arr.push(Value::Long(i));
                        i -= step;
                    }
                }
                Ok(Some(Value::Array(arr)))
            }
            "floor" => {
                let v = args.first().cloned().unwrap_or(Value::Null).to_double();
                Ok(Some(Value::Double(v.floor())))
            }
            "ceil" => {
                let v = args.first().cloned().unwrap_or(Value::Null).to_double();
                Ok(Some(Value::Double(v.ceil())))
            }
            "round" => {
                let v = args.first().cloned().unwrap_or(Value::Null).to_double();
                let precision = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                let factor = 10f64.powi(precision as i32);
                Ok(Some(Value::Double((v * factor).round() / factor)))
            }
            "array_sum" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                if let Value::Array(ref a) = arr {
                    let mut sum = Value::Long(0);
                    for (_, v) in a.entries() {
                        sum = sum.add(v);
                    }
                    Ok(Some(sum))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }
            "array_product" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                if let Value::Array(ref a) = arr {
                    let mut product = Value::Long(1);
                    for (_, v) in a.entries() {
                        product = product.mul(v);
                    }
                    Ok(Some(product))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }
            "array_unique" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                if let Value::Array(ref a) = arr {
                    let mut result = PhpArray::new();
                    let mut seen: Vec<Value> = Vec::new();
                    for (key, val) in a.entries() {
                        if !seen.iter().any(|s| s.loose_eq(val)) {
                            seen.push(val.clone());
                            match key {
                                crate::value::ArrayKey::Int(n) => result.set_int(*n, val.clone()),
                                crate::value::ArrayKey::String(s) => {
                                    result.set_string(s.clone(), val.clone())
                                }
                            }
                        }
                    }
                    Ok(Some(Value::Array(result)))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "array_flip" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                if let Value::Array(ref a) = arr {
                    let mut result = PhpArray::new();
                    for (key, val) in a.entries() {
                        let new_key = val.clone();
                        let new_val = match key {
                            crate::value::ArrayKey::Int(n) => Value::Long(*n),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        result.set(&new_key, new_val);
                    }
                    Ok(Some(Value::Array(result)))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "sort" | "rsort" | "asort" | "arsort" | "ksort" | "krsort" => {
                // Sorting functions modify in-place; we can't do that, return true
                Ok(Some(Value::Bool(true)))
            }
            "array_count_values" => {
                let arr = args.first().cloned().unwrap_or(Value::Null);
                if let Value::Array(ref a) = arr {
                    let mut result = PhpArray::new();
                    for (_, val) in a.entries() {
                        let key_str = val.to_php_string();
                        let current = result
                            .get_string(&key_str)
                            .cloned()
                            .unwrap_or(Value::Long(0));
                        result.set_string(key_str, current.add(&Value::Long(1)));
                    }
                    Ok(Some(Value::Array(result)))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "str_pad" => {
                let input = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let length = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as usize;
                let pad_str = args
                    .get(2)
                    .cloned()
                    .unwrap_or(Value::String(" ".to_string()))
                    .to_php_string();
                let pad_type = args.get(3).cloned().unwrap_or(Value::Long(1)).to_long();

                if input.len() >= length || pad_str.is_empty() {
                    return Ok(Some(Value::String(input)));
                }

                let diff = length - input.len();
                let padding: String = pad_str.chars().cycle().take(diff).collect();

                let result = match pad_type {
                    2 => format!("{}{}", padding, input), // STR_PAD_LEFT
                    _ => format!("{}{}", input, padding), // STR_PAD_RIGHT (default)
                };
                Ok(Some(Value::String(result)))
            }
            "number_format" => {
                let num = args.first().cloned().unwrap_or(Value::Null).to_double();
                let decimals = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long();
                Ok(Some(Value::String(format!(
                    "{:.prec$}",
                    num,
                    prec = decimals as usize
                ))))
            }
            "isset" => {
                // Shouldn't normally reach here (ISSET is usually compiled as opcode)
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(!v.is_null())))
            }
            "empty" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(!v.to_bool())))
            }
            "var_export" => {
                let val = args.first().cloned().unwrap_or(Value::Null);
                let ret = args.get(1).is_some_and(|v| v.to_bool());
                let s = self.var_export_string(&val);
                if ret {
                    Ok(Some(Value::String(s)))
                } else {
                    self.output.push_str(&s);
                    Ok(Some(Value::Null))
                }
            }
            _ => Ok(None),
        }
    }

    // =========================================================================
    // var_dump implementation
    // =========================================================================

    fn var_dump(&mut self, val: &Value, depth: usize) {
        let indent = "  ".repeat(depth);
        match val {
            Value::Null => {
                self.output.push_str(&format!("{}NULL\n", indent));
            }
            Value::Bool(b) => {
                self.output.push_str(&format!("{}bool({})\n", indent, b));
            }
            Value::Long(n) => {
                self.output.push_str(&format!("{}int({})\n", indent, n));
            }
            Value::Double(f) => {
                let s = format_php_float(*f);
                self.output.push_str(&format!("{}float({})\n", indent, s));
            }
            Value::String(s) => {
                self.output
                    .push_str(&format!("{}string({}) \"{}\"\n", indent, s.len(), s));
            }
            Value::Array(a) => {
                self.output
                    .push_str(&format!("{}array({}) {{\n", indent, a.len()));
                for (key, v) in a.entries() {
                    let key_str = match key {
                        crate::value::ArrayKey::Int(n) => format!("[{}]=>", n),
                        crate::value::ArrayKey::String(s) => format!("[\"{}\"]=>", s),
                    };
                    self.output.push_str(&format!("{}  {}\n", indent, key_str));
                    self.var_dump(v, depth + 1);
                }
                self.output.push_str(&format!("{}}}\n", indent));
            }
            Value::_Iterator { .. } => {
                self.output.push_str(&format!("{}NULL\n", indent));
            }
        }
    }

    fn print_r_string(&self, val: &Value, depth: usize) -> String {
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
            Value::_Iterator { .. } => String::new(),
        }
    }

    fn var_export_string(&self, val: &Value) -> String {
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
            Value::_Iterator { .. } => "NULL".to_string(),
        }
    }

    // =========================================================================
    // Operand helpers
    // =========================================================================

    /// Read an operand value (op1 or op2).
    fn read_operand(&self, op: &ZOp, which: u8, oa_idx: usize) -> VmResult<Value> {
        let (operand, op_type) = if which == 1 {
            (&op.op1, op.op1_type)
        } else {
            (&op.op2, op.op2_type)
        };

        let frame = self.call_stack.last().unwrap();
        match op_type {
            OperandType::Const => {
                let idx = operand.val as usize;
                let lit = &self.op_arrays[oa_idx].literals[idx];
                Ok(literal_to_value(lit))
            }
            OperandType::TmpVar | OperandType::Var => {
                let slot = operand.val as usize;
                Ok(frame.temps[slot].clone())
            }
            OperandType::Cv => {
                let idx = operand.val as usize;
                Ok(frame.cvs[idx].clone())
            }
            OperandType::Unused => Ok(Value::Null),
        }
    }

    /// Read an operand from a specific op (used for OP_DATA).
    fn read_operand_from(&self, op: &ZOp, which: u8, oa_idx: usize) -> VmResult<Value> {
        self.read_operand(op, which, oa_idx)
    }

    /// Write to the result operand.
    fn write_result(&mut self, op: &ZOp, _oa_idx: usize, val: Value) -> VmResult<()> {
        let frame = self.call_stack.last_mut().unwrap();
        match op.result_type {
            OperandType::TmpVar | OperandType::Var => {
                let slot = op.result.val as usize;
                if slot >= frame.temps.len() {
                    frame.temps.resize(slot + 1, Value::Null);
                }
                frame.temps[slot] = val;
            }
            OperandType::Cv => {
                let idx = op.result.val as usize;
                if idx >= frame.cvs.len() {
                    frame.cvs.resize(idx + 1, Value::Null);
                }
                frame.cvs[idx] = val;
            }
            _ => {}
        }
        Ok(())
    }

    /// Write to a CV from op1.
    fn write_cv(&mut self, op: &ZOp, _oa_idx: usize, val: Value) -> VmResult<()> {
        let frame = self.call_stack.last_mut().unwrap();
        if op.op1_type == OperandType::Cv {
            let idx = op.op1.val as usize;
            if idx >= frame.cvs.len() {
                frame.cvs.resize(idx + 1, Value::Null);
            }
            frame.cvs[idx] = val;
        }
        Ok(())
    }

    /// Execute a binary operation: result = f(op1, op2).
    fn op_binary(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
        f: impl FnOnce(Value, Value) -> Value,
    ) -> VmResult<DispatchSignal> {
        let a = self.read_operand(op, 1, oa_idx)?;
        let b = self.read_operand(op, 2, oa_idx)?;
        let result = f(a, b);
        self.write_result(op, oa_idx, result)?;
        Ok(DispatchSignal::Next)
    }

    /// Execute a unary operation: result = f(op1).
    fn op_unary(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
        f: impl FnOnce(Value) -> Value,
    ) -> VmResult<DispatchSignal> {
        let a = self.read_operand(op, 1, oa_idx)?;
        let result = f(a);
        self.write_result(op, oa_idx, result)?;
        Ok(DispatchSignal::Next)
    }
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a compiler Literal to a VM Value.
fn literal_to_value(lit: &Literal) -> Value {
    match lit {
        Literal::Null => Value::Null,
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Long(n) => Value::Long(*n),
        Literal::Double(f) => Value::Double(*f),
        Literal::String(s) => Value::String(s.clone()),
    }
}

/// Apply a compound assignment operation.
fn apply_assign_op(op_code: u32, lhs: &Value, rhs: &Value) -> Value {
    match op_code {
        1 => lhs.add(rhs),     // ADD
        2 => lhs.sub(rhs),     // SUB
        3 => lhs.mul(rhs),     // MUL
        4 => lhs.div(rhs),     // DIV
        5 => lhs.modulo(rhs),  // MOD
        6 => lhs.shl(rhs),     // SL
        7 => lhs.shr(rhs),     // SR
        8 => lhs.concat(rhs),  // CONCAT
        9 => lhs.bw_or(rhs),   // BW_OR
        10 => lhs.bw_and(rhs), // BW_AND
        11 => lhs.bw_xor(rhs), // BW_XOR
        12 => lhs.pow(rhs),    // POW
        _ => lhs.add(rhs),     // fallback
    }
}

/// Format a float as PHP would.
fn format_php_float(f: f64) -> String {
    if f.is_nan() {
        "NAN".to_string()
    } else if f.is_infinite() {
        if f > 0.0 {
            "INF".to_string()
        } else {
            "-INF".to_string()
        }
    } else {
        let s = format!("{}", f);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use php_rs_compiler::compile;

    /// Helper: compile PHP source and execute it, returning the output.
    fn run_php(source: &str) -> String {
        let op_array = compile(source).unwrap_or_else(|e| {
            panic!("Compilation failed for:\n{}\nError: {:?}", source, e);
        });
        let mut vm = Vm::new();
        vm.execute(&op_array).unwrap_or_else(|e| {
            panic!(
                "Execution failed for:\n{}\nError: {:?}\nOpcodes:\n{}",
                source,
                e,
                op_array.disassemble()
            );
        })
    }

    // =========================================================================
    // 5.1 Frame & basic execution
    // =========================================================================

    #[test]
    fn test_vm_empty_script() {
        let output = run_php("<?php ?>");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_string() {
        let output = run_php("<?php echo \"Hello, World!\";");
        assert_eq!(output, "Hello, World!");
    }

    #[test]
    fn test_vm_echo_integer() {
        let output = run_php("<?php echo 42;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_echo_multiple() {
        let output = run_php("<?php echo \"a\"; echo \"b\"; echo \"c\";");
        assert_eq!(output, "abc");
    }

    // =========================================================================
    // 5.2 Dispatch & operand fetch
    // =========================================================================

    #[test]
    fn test_vm_variable_assignment() {
        let output = run_php("<?php $a = 42; echo $a;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_variable_string() {
        let output = run_php("<?php $name = \"PHP\"; echo $name;");
        assert_eq!(output, "PHP");
    }

    #[test]
    fn test_vm_multiple_variables() {
        let output = run_php("<?php $a = \"Hello\"; $b = \" World\"; echo $a; echo $b;");
        assert_eq!(output, "Hello World");
    }

    // =========================================================================
    // 5.3 Arithmetic & comparison
    // =========================================================================

    #[test]
    fn test_vm_addition() {
        let output = run_php("<?php $a = 2 + 3; echo $a;");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_subtraction() {
        let output = run_php("<?php echo 10 - 3;");
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_multiplication() {
        let output = run_php("<?php echo 6 * 7;");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_division() {
        let output = run_php("<?php echo 10 / 3;");
        // PHP produces a float here
        assert!(output.starts_with("3.333"));
    }

    #[test]
    fn test_vm_integer_division() {
        let output = run_php("<?php echo 10 / 2;");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_modulo() {
        let output = run_php("<?php echo 10 % 3;");
        assert_eq!(output, "1");
    }

    #[test]
    fn test_vm_power() {
        let output = run_php("<?php echo 2 ** 10;");
        assert_eq!(output, "1024");
    }

    #[test]
    fn test_vm_concat() {
        let output = run_php("<?php echo \"Hello\" . \" \" . \"World\";");
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_vm_compound_expression() {
        let output = run_php("<?php echo 2 + 3 * 4;");
        assert_eq!(output, "14");
    }

    #[test]
    fn test_vm_comparison_equal() {
        let output = run_php("<?php if (1 == 1) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_comparison_not_equal() {
        let output = run_php("<?php if (1 != 2) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_comparison_less() {
        let output = run_php("<?php if (1 < 2) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "yes");
    }

    // =========================================================================
    // 5.4 Variables
    // =========================================================================

    #[test]
    fn test_vm_assign_op_add() {
        let output = run_php("<?php $a = 10; $a += 5; echo $a;");
        assert_eq!(output, "15");
    }

    #[test]
    fn test_vm_assign_op_concat() {
        let output = run_php("<?php $a = \"Hello\"; $a .= \" World\"; echo $a;");
        assert_eq!(output, "Hello World");
    }

    #[test]
    fn test_vm_pre_increment() {
        let output = run_php("<?php $a = 5; ++$a; echo $a;");
        assert_eq!(output, "6");
    }

    #[test]
    fn test_vm_post_increment() {
        let output = run_php("<?php $a = 5; $b = $a++; echo $b; echo $a;");
        assert_eq!(output, "56");
    }

    #[test]
    fn test_vm_array_literal() {
        let output = run_php("<?php $a = [1, 2, 3]; echo $a[0]; echo $a[1]; echo $a[2];");
        assert_eq!(output, "123");
    }

    #[test]
    fn test_vm_array_string_key() {
        let output = run_php("<?php $a = [\"name\" => \"PHP\"]; echo $a[\"name\"];");
        assert_eq!(output, "PHP");
    }

    // =========================================================================
    // 5.5 Control flow
    // =========================================================================

    #[test]
    fn test_vm_if_true() {
        let output = run_php("<?php if (true) { echo \"yes\"; }");
        assert_eq!(output, "yes");
    }

    #[test]
    fn test_vm_if_false() {
        let output = run_php("<?php if (false) { echo \"yes\"; } else { echo \"no\"; }");
        assert_eq!(output, "no");
    }

    #[test]
    fn test_vm_if_elseif() {
        let output = run_php(
            "<?php $x = 2; if ($x == 1) { echo \"one\"; } elseif ($x == 2) { echo \"two\"; } else { echo \"other\"; }",
        );
        assert_eq!(output, "two");
    }

    #[test]
    fn test_vm_while_loop() {
        let output = run_php("<?php $i = 0; while ($i < 5) { echo $i; $i++; }");
        assert_eq!(output, "01234");
    }

    #[test]
    fn test_vm_for_loop() {
        let output = run_php("<?php for ($i = 0; $i < 5; $i++) { echo $i; }");
        assert_eq!(output, "01234");
    }

    #[test]
    fn test_vm_do_while() {
        let output = run_php("<?php $i = 0; do { echo $i; $i++; } while ($i < 3);");
        assert_eq!(output, "012");
    }

    #[test]
    fn test_vm_foreach_values() {
        let output =
            run_php("<?php $arr = [10, 20, 30]; foreach ($arr as $v) { echo $v; echo \",\"; }");
        assert_eq!(output, "10,20,30,");
    }

    #[test]
    fn test_vm_break() {
        let output =
            run_php("<?php for ($i = 0; $i < 10; $i++) { if ($i == 3) { break; } echo $i; }");
        assert_eq!(output, "012");
    }

    #[test]
    fn test_vm_continue() {
        let output =
            run_php("<?php for ($i = 0; $i < 5; $i++) { if ($i == 2) { continue; } echo $i; }");
        assert_eq!(output, "0134");
    }

    // =========================================================================
    // 5.6 Function calls
    // =========================================================================

    #[test]
    fn test_vm_function_decl_and_call() {
        let output = run_php("<?php function greet() { echo \"Hello!\"; } greet();");
        assert_eq!(output, "Hello!");
    }

    #[test]
    fn test_vm_function_with_params() {
        let output = run_php("<?php function add($a, $b) { return $a + $b; } echo add(3, 4);");
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_function_return() {
        let output = run_php("<?php function double($x) { return $x * 2; } echo double(21);");
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_nested_function_calls() {
        let output = run_php(
            "<?php function add($a, $b) { return $a + $b; } function mul($a, $b) { return $a * $b; } echo add(mul(2, 3), mul(4, 5));",
        );
        assert_eq!(output, "26");
    }

    #[test]
    fn test_vm_recursive_function() {
        let output = run_php(
            "<?php function fact($n) { if ($n <= 1) { return 1; } return $n * fact($n - 1); } echo fact(5);",
        );
        assert_eq!(output, "120");
    }

    // =========================================================================
    // 5.7 I/O (echo with types)
    // =========================================================================

    #[test]
    fn test_vm_echo_bool_true() {
        let output = run_php("<?php echo true;");
        assert_eq!(output, "1");
    }

    #[test]
    fn test_vm_echo_bool_false() {
        let output = run_php("<?php echo false;");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_null() {
        let output = run_php("<?php echo null;");
        assert_eq!(output, "");
    }

    #[test]
    fn test_vm_echo_float() {
        let output = run_php("<?php echo 3.14;");
        assert_eq!(output, "3.14");
    }

    // =========================================================================
    // Built-in functions
    // =========================================================================

    #[test]
    fn test_vm_builtin_strlen() {
        let output = run_php("<?php echo strlen(\"Hello\");");
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_builtin_strtoupper() {
        let output = run_php("<?php echo strtoupper(\"hello\");");
        assert_eq!(output, "HELLO");
    }

    #[test]
    fn test_vm_builtin_substr() {
        let output = run_php("<?php echo substr(\"Hello World\", 6);");
        assert_eq!(output, "World");
    }

    #[test]
    fn test_vm_builtin_implode() {
        let output = run_php("<?php echo implode(\", \", [\"a\", \"b\", \"c\"]);");
        assert_eq!(output, "a, b, c");
    }

    // =========================================================================
    // Integration: compile + execute end-to-end
    // =========================================================================

    #[test]
    fn test_vm_fizzbuzz() {
        let output = run_php(
            r#"<?php
for ($i = 1; $i <= 15; $i++) {
    if ($i % 15 == 0) {
        echo "FizzBuzz";
    } elseif ($i % 3 == 0) {
        echo "Fizz";
    } elseif ($i % 5 == 0) {
        echo "Buzz";
    } else {
        echo $i;
    }
    echo "\n";
}
"#,
        );
        let expected = "1\n2\nFizz\n4\nBuzz\nFizz\n7\n8\nFizz\nBuzz\n11\nFizz\n13\n14\nFizzBuzz\n";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_vm_fibonacci() {
        let output = run_php(
            r#"<?php
function fib($n) {
    if ($n <= 1) { return $n; }
    return fib($n - 1) + fib($n - 2);
}
echo fib(10);
"#,
        );
        assert_eq!(output, "55");
    }

    #[test]
    fn test_vm_string_operations() {
        let output = run_php(
            r#"<?php
$str = "Hello";
$str .= " ";
$str .= "World";
echo $str;
echo "\n";
echo strlen($str);
"#,
        );
        assert_eq!(output, "Hello World\n11");
    }

    #[test]
    fn test_vm_array_operations() {
        let output = run_php(
            r#"<?php
$arr = [1, 2, 3, 4, 5];
$sum = 0;
foreach ($arr as $v) {
    $sum += $v;
}
echo $sum;
"#,
        );
        assert_eq!(output, "15");
    }

    #[test]
    fn test_vm_nested_loops() {
        let output = run_php(
            r#"<?php
for ($i = 1; $i <= 3; $i++) {
    for ($j = 1; $j <= 3; $j++) {
        echo $i * $j;
        echo " ";
    }
    echo "\n";
}
"#,
        );
        assert_eq!(output, "1 2 3 \n2 4 6 \n3 6 9 \n");
    }
}
