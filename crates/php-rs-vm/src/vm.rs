//! PHP Virtual Machine — executes compiled opcode arrays.
//!
//! Equivalent to php-src/Zend/zend_execute.c and zend_vm_def.h.

use std::collections::{HashMap, HashSet};

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;
use php_rs_ext_json::{self, JsonValue};

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

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
    /// Undefined class.
    UndefinedClass(String),
    /// Undefined method.
    UndefinedMethod(String, String),
    /// Undefined property.
    UndefinedProperty(String, String),
    /// Undefined class constant.
    UndefinedClassConstant(String, String),
    /// Internal: invalid opcode / bad operand.
    InternalError(String),
    /// exit() / die() — clean script termination with an exit code.
    Exit(i32),
}

pub type VmResult<T> = Result<T, VmError>;

/// A pending function/method call on the call stack.
struct PendingCall {
    /// Function or method name (e.g., "strlen" or "Counter::increment").
    name: String,
    /// Arguments collected so far via SEND_VAL/SEND_VAR.
    args: Vec<Value>,
    /// For method calls: the source location of $this in the caller so we can write
    /// the modified object back after the method returns (PHP objects have reference semantics).
    this_source: Option<(OperandType, u32)>,
}

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
    call_stack_pending: Vec<PendingCall>,
    /// Arguments passed to this frame (for RECV opcodes).
    args: Vec<Value>,
    /// Where to store the return value in the caller's frame when this frame returns.
    /// (result_type, result_slot)
    return_dest: Option<(OperandType, u32)>,
    /// For method calls (including constructors): the slot in the caller where $this
    /// should be written back after this frame returns, to support PHP object reference semantics.
    this_write_back: Option<(OperandType, u32)>,
    /// Whether this is a constructor call (don't overwrite result with Null return value).
    is_constructor: bool,
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
            this_write_back: None,
            is_constructor: false,
        }
    }
}

/// A class definition stored in the VM's class table.
#[derive(Debug, Clone)]
struct ClassDef {
    /// Class name.
    _name: String,
    /// Parent class name (if any).
    parent: Option<String>,
    /// Implemented interfaces.
    interfaces: Vec<String>,
    /// Method table: method_name → op_array index.
    methods: HashMap<String, usize>,
    /// Default property values: prop_name → default value.
    default_properties: HashMap<String, Value>,
    /// Class constants: const_name → value.
    class_constants: HashMap<String, Value>,
    /// Static properties: prop_name → value.
    static_properties: HashMap<String, Value>,
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
    /// Class table: class_name → ClassDef.
    classes: HashMap<String, ClassDef>,
    /// Next object ID.
    next_object_id: u64,
    /// Current exception being handled (for catch/handle_exception).
    current_exception: Option<Value>,
    /// Set of already-included files (for include_once/require_once).
    included_files: HashSet<String>,
    /// Last return value from a frame (used for synchronous method calls).
    last_return_value: Value,
    /// Shutdown functions registered via register_shutdown_function().
    shutdown_functions: Vec<String>,
    /// Generator states: object_id → GeneratorState.
    generators: HashMap<u64, crate::value::GeneratorState>,
    /// Fiber states: object_id → FiberState.
    fibers: HashMap<u64, crate::value::FiberState>,
    /// Currently executing fiber object_id (if any).
    current_fiber_id: Option<u64>,
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
    /// Generator yielded or returned — break inner dispatch loop.
    Yield,
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
            classes: HashMap::new(),
            next_object_id: 1,
            current_exception: None,
            included_files: HashSet::new(),
            last_return_value: Value::Null,
            shutdown_functions: Vec::new(),
            generators: HashMap::new(),
            fibers: HashMap::new(),
            current_fiber_id: None,
        }
    }

    /// Execute a compiled op_array and return the output.
    pub fn execute(&mut self, op_array: &ZOpArray) -> VmResult<String> {
        // Store the main op_array
        self.op_arrays.clear();
        self.op_arrays.push(op_array.clone());
        self.functions.clear();
        self.output.clear();
        self.shutdown_functions.clear();

        // Pre-register any nested function definitions from dynamic_func_defs
        self.register_dynamic_func_defs(0);

        // Create the main frame
        let mut frame = Frame::new(op_array);
        frame.op_array_idx = 0;

        self.call_stack.push(frame);

        let dispatch_result = self.dispatch_loop();

        // Run registered shutdown functions regardless of script result
        self.run_shutdown_functions();

        // Propagate any error from dispatch (except Exit which is normal termination)
        match dispatch_result {
            Err(VmError::Exit(_)) => {}
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        Ok(self.output.clone())
    }

    /// Run registered shutdown functions (called after script execution).
    fn run_shutdown_functions(&mut self) {
        let funcs: Vec<String> = self.shutdown_functions.drain(..).collect();
        for func_name in funcs {
            // Try built-in first
            if let Ok(Some(_)) = self.call_builtin(&func_name, &[]) {
                continue;
            }
            // Try user-defined function
            if let Some(&oa_idx) = self.functions.get(&func_name) {
                let func_oa = &self.op_arrays[oa_idx];
                let mut new_frame = Frame::new(func_oa);
                new_frame.op_array_idx = oa_idx;
                self.call_stack.push(new_frame);
                // Ignore errors during shutdown
                let _ = self.dispatch_loop();
            }
        }
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
        self.dispatch_loop_until(0)
    }

    /// Dispatch loop that runs until call stack depth drops to min_depth.
    /// Used for recursive method calls (e.g., JsonSerializable::jsonSerialize).
    fn dispatch_loop_until(&mut self, min_depth: usize) -> VmResult<()> {
        loop {
            if self.call_stack.len() <= min_depth {
                return Ok(());
            }

            let frame = self.call_stack.last().unwrap();
            let op_array_idx = frame.op_array_idx;
            let ip = frame.ip;

            if ip >= self.op_arrays[op_array_idx].opcodes.len() {
                // Fell off end — implicit return
                let frame = self.call_stack.pop().unwrap();
                self.last_return_value = frame.return_value;
                continue;
            }

            let op = self.op_arrays[op_array_idx].opcodes[ip].clone();

            let result = self.dispatch_op(&op, op_array_idx);

            // Handle exceptions: look for catch blocks
            let result = match result {
                Err(VmError::Thrown(ref exception_val)) => {
                    if let Some(catch_target) = self.find_catch_block(op_array_idx, ip) {
                        self.current_exception = Some(exception_val.clone());
                        Ok(DispatchSignal::Jump(catch_target))
                    } else {
                        result
                    }
                }
                other => other,
            };

            match result? {
                DispatchSignal::Next => {
                    self.call_stack.last_mut().unwrap().ip += 1;
                }
                DispatchSignal::Jump(target) => {
                    self.call_stack.last_mut().unwrap().ip = target;
                }
                DispatchSignal::Return => {
                    let frame = self.call_stack.pop().unwrap();
                    let ret_val = frame.return_value;
                    self.last_return_value = ret_val.clone();

                    // Write modified $this back to caller (PHP object reference semantics)
                    if let Some((dest_type, dest_slot)) = frame.this_write_back {
                        let oa = &self.op_arrays[frame.op_array_idx];
                        let this_idx = oa.vars.iter().position(|v| v == "this").unwrap_or(0);
                        let this_val = if this_idx < frame.cvs.len() {
                            frame.cvs[this_idx].clone()
                        } else {
                            Value::Null
                        };
                        if let Some(caller) = self.call_stack.last_mut() {
                            Self::write_to_slot(caller, dest_type, dest_slot, this_val);
                        }
                    }

                    // Store return value in caller's result slot if specified
                    if let Some((ret_type, ret_slot)) = frame.return_dest {
                        if let Some(caller) = self.call_stack.last_mut() {
                            Self::write_to_slot(caller, ret_type, ret_slot, ret_val);
                        }
                    }
                }
                DispatchSignal::CallPushed => {
                    // New frame was pushed; don't advance IP.
                    // The callee's ip starts at 0.
                }
                DispatchSignal::Yield => {
                    // Generator yielded or fiber suspended — frame already saved.
                    return Ok(());
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
            ZOpcode::AssignRef => {
                // Reference assignment: $a = &$b
                // For now, just copy the value (true reference semantics need Rc<RefCell>)
                let val = self.read_operand(op, 2, oa_idx)?;
                self.write_cv(op, oa_idx, val.clone())?;
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
            ZOpcode::JmpNull => {
                // JMP_NULL: if op1 is null, set result to null and jump to op2
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.is_null() {
                    self.write_result(op, oa_idx, Value::Null)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    // Pass the value through to result for chained access
                    self.write_result(op, oa_idx, val)?;
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
                match &arr {
                    Value::Array(a) => {
                        let iter = Value::_Iterator { array: a.clone(), index: 0 };
                        self.write_result(op, oa_idx, iter)?;
                        Ok(DispatchSignal::Next)
                    }
                    Value::Object(o) if o.internal == crate::value::InternalState::Generator => {
                        let obj_id = o.object_id;
                        // Initialize the generator
                        self.ensure_generator_initialized(obj_id)?;
                        let iter = Value::_GeneratorIterator { object_id: obj_id };
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
                // The following OpData opcode (if present) holds the key dest.
                let iter_slot = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let ip = frame.ip;
                let iter = frame.temps[iter_slot].clone();

                // Check if the next opcode is OpData (for key variable)
                let key_dest = {
                    let next_ip = ip + 1;
                    let ops = &self.op_arrays[oa_idx].opcodes;
                    if next_ip < ops.len() && ops[next_ip].opcode == ZOpcode::OpData {
                        Some((ops[next_ip].result_type, ops[next_ip].result.val))
                    } else {
                        None
                    }
                };

                if let Value::_Iterator { ref array, index } = iter {
                    if let Some((key, val)) = array.entry_at(index) {
                        let val = val.clone();
                        let key_val = match key {
                            crate::value::ArrayKey::Int(n) => Value::Long(*n),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        // Store value in result
                        self.write_result(op, oa_idx, val)?;
                        // Store key in OpData's result slot if present
                        if let Some((key_type, key_slot)) = key_dest {
                            let frame = self.call_stack.last_mut().unwrap();
                            Self::write_to_slot(frame, key_type, key_slot, key_val);
                            // Skip the OpData opcode
                            frame.ip += 1;
                        }
                        // Advance iterator
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_Iterator {
                            array: array.clone(),
                            index: index + 1,
                        };
                        Ok(DispatchSignal::Next)
                    } else {
                        // Exhausted — skip OpData if present
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                } else if let Value::_GeneratorIterator { object_id } = iter {
                    // Generator iterator
                    let gen_status = self.generators.get(&object_id)
                        .map(|g| g.status)
                        .unwrap_or(crate::value::GeneratorStatus::Closed);

                    if gen_status == crate::value::GeneratorStatus::Closed {
                        // Skip OpData if present
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    } else {
                        let gen_val = self.generators.get(&object_id)
                            .map(|g| g.value.clone())
                            .unwrap_or(Value::Null);
                        let gen_key = self.generators.get(&object_id)
                            .map(|g| g.key.clone())
                            .unwrap_or(Value::Null);

                        // Store value in result
                        self.write_result(op, oa_idx, gen_val)?;
                        // Store key in OpData's result slot if present
                        if let Some((key_type, key_slot)) = key_dest {
                            let frame = self.call_stack.last_mut().unwrap();
                            Self::write_to_slot(frame, key_type, key_slot, gen_key);
                            // Skip the OpData opcode
                            frame.ip += 1;
                        }

                        // Restore the iterator in the iter slot
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_GeneratorIterator { object_id };

                        // Advance generator to next yield
                        let status = self.generators.get(&object_id)
                            .map(|g| g.status)
                            .unwrap_or(crate::value::GeneratorStatus::Closed);
                        if status == crate::value::GeneratorStatus::Suspended {
                            self.resume_generator(object_id)?;
                        }

                        Ok(DispatchSignal::Next)
                    }
                } else {
                    if key_dest.is_some() {
                        self.call_stack.last_mut().unwrap().ip += 1;
                    }
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
                frame.call_stack_pending.push(PendingCall {
                    name,
                    args: Vec::new(),
                    this_source: None,
                });
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitDynamicCall => {
                let name_val = self.read_operand(op, 2, oa_idx)?;
                let name = name_val.to_php_string();
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name,
                    args: Vec::new(),
                    this_source: None,
                });
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
                    pending.args.push(val);
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
                            pending.args.push(v.clone());
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
            ZOpcode::Return | ZOpcode::ReturnByRef => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                frame.return_value = val;
                Ok(DispatchSignal::Return)
            }
            ZOpcode::GeneratorReturn => {
                self.handle_generator_return(op, oa_idx)
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
                    0 => {
                        // empty() check: value is "empty" if it's falsy in PHP
                        match &val {
                            Value::Null => true,
                            Value::Bool(b) => !b,
                            Value::Long(n) => *n == 0,
                            Value::Double(f) => *f == 0.0,
                            Value::String(s) => s.is_empty() || s == "0",
                            Value::Array(a) => a.is_empty(),
                            _ => false,
                        }
                    }
                    1 => val.is_null(),                     // IS_NULL
                    2 => matches!(val, Value::Bool(false)), // IS_FALSE
                    4 => matches!(val, Value::Bool(true)),  // IS_TRUE
                    16 => matches!(val, Value::Long(_)),    // IS_LONG
                    32 => matches!(val, Value::Double(_)),  // IS_DOUBLE
                    64 => matches!(val, Value::String(_)),  // IS_STRING
                    128 => matches!(val, Value::Array(_)),  // IS_ARRAY
                    256 => matches!(val, Value::Object(_)), // IS_OBJECT
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
                self.handle_declare_class(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareLambdaFunction => {
                // Creates a closure value
                // op1 = index into dynamic_func_defs
                // For now just produce Null
                Ok(DispatchSignal::Next)
            }
            ZOpcode::New => {
                self.handle_new(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Clone => {
                let val = self.read_operand(op, 1, oa_idx)?;
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchObjR | ZOpcode::FetchObjIs => {
                self.handle_fetch_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchObjW | ZOpcode::FetchObjRw | ZOpcode::FetchObjFuncArg => {
                // Write/read-write modes — same read for now
                self.handle_fetch_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignObj => {
                self.handle_assign_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitMethodCall => {
                self.handle_init_method_call(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitStaticMethodCall => {
                self.handle_init_static_method_call(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchClassConstant => {
                self.handle_fetch_class_constant(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Instanceof => {
                self.handle_instanceof(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchClass => {
                // Resolve class name → just pass through the class name as string
                let name = self.read_operand(op, 2, oa_idx)?;
                self.write_result(op, oa_idx, name)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchStaticPropR
            | ZOpcode::FetchStaticPropW
            | ZOpcode::FetchStaticPropRw
            | ZOpcode::FetchStaticPropIs => {
                self.handle_fetch_static_prop(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Exception handling
            // =====================================================================
            ZOpcode::Throw => {
                let val = self.read_operand(op, 1, oa_idx)?;
                Err(VmError::Thrown(val))
            }
            ZOpcode::Catch => {
                // Store the current exception in the result CV (if any)
                if op.result_type == OperandType::Cv {
                    let cv_idx = op.result.val as usize;
                    let exception = self.current_exception.take().unwrap_or(Value::Null);
                    let frame = self.call_stack.last_mut().unwrap();
                    if cv_idx >= frame.cvs.len() {
                        frame.cvs.resize(cv_idx + 1, Value::Null);
                    }
                    frame.cvs[cv_idx] = exception;
                } else {
                    self.current_exception = None;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::HandleException => {
                // Discard exception and continue
                self.current_exception = None;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DiscardException => {
                self.current_exception = None;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FastCall => {
                // Jump to finally block (op1 = target)
                Ok(DispatchSignal::Jump(op.op1.val as usize))
            }
            ZOpcode::FastRet => {
                // Return from finally block (op1 = target)
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

            // =====================================================================
            // Include / Eval
            // =====================================================================
            ZOpcode::IncludeOrEval => self.handle_include_or_eval(op, oa_idx),

            // =====================================================================
            // Generators (full coroutine semantics)
            // =====================================================================
            ZOpcode::GeneratorCreate => {
                // NOP — generator creation is handled in handle_do_fcall
                // when it detects is_generator on the op_array.
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Yield => {
                self.handle_yield(op, oa_idx)
            }
            ZOpcode::YieldFrom => {
                self.handle_yield_from(op, oa_idx)
            }

            // Anything else: NOP for now
            _ => Ok(DispatchSignal::Next),
        }
    }

    /// Find a catch block for the current IP in the given op_array.
    fn find_catch_block(&self, oa_idx: usize, ip: usize) -> Option<usize> {
        let oa = &self.op_arrays[oa_idx];
        for tc in &oa.try_catch_array {
            if ip >= tc.try_op as usize && tc.catch_op > 0 {
                // Check if we're in the try block (before catch starts)
                if ip < tc.catch_op as usize {
                    return Some(tc.catch_op as usize);
                }
            }
        }
        None
    }

    /// Handle DECLARE_CLASS — register a class in the class table.
    fn handle_declare_class(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let name = self.read_operand(op, 1, oa_idx)?.to_php_string();

        // Parse parent/interfaces from op2: "parent\0iface1\0iface2"
        let class_info = if op.op2_type != OperandType::Unused {
            self.read_operand(op, 2, oa_idx)?.to_php_string()
        } else {
            String::new()
        };
        let mut parts: Vec<&str> = class_info.split('\0').collect();
        let parent = if !parts.is_empty() && !parts[0].is_empty() {
            Some(parts.remove(0).to_string())
        } else {
            if !parts.is_empty() {
                parts.remove(0);
            }
            None
        };
        let interfaces: Vec<String> = parts
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let mut class_def = ClassDef {
            _name: name.clone(),
            parent,
            interfaces,
            methods: HashMap::new(),
            default_properties: HashMap::new(),
            class_constants: HashMap::new(),
            static_properties: HashMap::new(),
        };

        // Methods are stored in dynamic_func_defs with names like "ClassName::method_name"
        let prefix = format!("{}::", name);
        let defs: Vec<ZOpArray> = self.op_arrays[oa_idx].dynamic_func_defs.clone();
        for def in defs {
            if let Some(ref full_name) = def.function_name {
                if let Some(method_name) = full_name.strip_prefix(&prefix) {
                    let method_oa_idx = self.op_arrays.len();
                    let method_name = method_name.to_string();
                    self.op_arrays.push(def);
                    class_def.methods.insert(method_name.clone(), method_oa_idx);
                    // Also register as a global function for static call resolution
                    self.functions
                        .insert(format!("{}::{}", name, method_name), method_oa_idx);
                }
            }
        }

        self.classes.insert(name, class_def);
        Ok(())
    }

    /// Handle NEW — create a new object instance.
    fn handle_new(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let class_name = self.read_operand(op, 1, oa_idx)?.to_php_string();

        // Special handling for Fiber
        if class_name == "Fiber" {
            let mut obj = PhpObject::new("Fiber".to_string());
            obj.object_id = self.next_object_id;
            self.next_object_id += 1;
            obj.internal = crate::value::InternalState::Fiber;

            let obj_id = obj.object_id;
            let obj_val = Value::Object(obj);
            self.write_result(op, oa_idx, obj_val)?;

            // The constructor args contain the callable — save for start()
            // Store a pending call that DO_FCALL will consume
            let frame = self.call_stack.last_mut().unwrap();
            let saved_args = if let Some(pos) = frame
                .call_stack_pending
                .iter()
                .position(|p| p.name == "__ctor_args__")
            {
                frame.call_stack_pending.remove(pos).args
            } else {
                Vec::new()
            };

            // Get the callable name from saved args
            let callback_name = saved_args
                .first()
                .map(|v| v.to_php_string())
                .unwrap_or_default();

            // Create FiberState
            self.fibers.insert(
                obj_id,
                crate::value::FiberState {
                    saved_frames: Vec::new(),
                    status: crate::value::FiberStatus::Init,
                    callback_name,
                    transfer_value: Value::Null,
                    return_value: None,
                    start_depth: 0,
                },
            );

            // Push a dummy pending call for the constructor DO_FCALL
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "__new_noop__".to_string(),
                args: Vec::new(),
                this_source: None,
            });
            return Ok(());
        }

        let mut obj = PhpObject::new(class_name.clone());
        obj.object_id = self.next_object_id;
        self.next_object_id += 1;

        // Copy default properties from class definition
        if let Some(class_def) = self.classes.get(&class_name) {
            for (prop, val) in &class_def.default_properties {
                obj.properties.insert(prop.clone(), val.clone());
            }
        }

        let obj_val = Value::Object(obj);
        self.write_result(op, oa_idx, obj_val.clone())?;

        // Pick up saved constructor args (from class name resolution DO_FCALL)
        let frame = self.call_stack.last_mut().unwrap();
        let saved_args = if let Some(pos) = frame
            .call_stack_pending
            .iter()
            .position(|p| p.name == "__ctor_args__")
        {
            frame.call_stack_pending.remove(pos).args
        } else {
            Vec::new()
        };

        // Set up constructor call if one exists
        let has_constructor = self
            .classes
            .get(&class_name)
            .is_some_and(|c| c.methods.contains_key("__construct"));
        if has_constructor {
            let frame = self.call_stack.last_mut().unwrap();
            let ctor_name = format!("{}::__construct", class_name);
            let mut ctor_args = vec![obj_val];
            ctor_args.extend(saved_args);
            // The constructor writes $this back to the NEW result slot
            frame.call_stack_pending.push(PendingCall {
                name: ctor_name,
                args: ctor_args,
                this_source: Some((op.result_type, op.result.val)),
            });
        } else {
            // Push a dummy pending call that DO_FCALL will consume (for the constructor call
            // that always follows NEW in compiled output)
            let frame = self.call_stack.last_mut().unwrap();
            frame.call_stack_pending.push(PendingCall {
                name: "__new_noop__".to_string(),
                args: Vec::new(),
                this_source: None,
            });
        }

        Ok(())
    }

    /// Handle FETCH_OBJ_R — read object property.
    fn handle_fetch_obj(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let val = match obj {
            Value::Object(ref o) => o.get_property(&prop_name).cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        };
        self.write_result(op, oa_idx, val)?;
        Ok(())
    }

    /// Handle ASSIGN_OBJ — set object property.
    fn handle_assign_obj(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj_cv = op.op1.val as usize;
        let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

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
        if let Value::Object(ref mut obj) = frame.cvs[obj_cv] {
            obj.set_property(prop_name, val);
        }

        // Skip OP_DATA
        self.call_stack.last_mut().unwrap().ip += 1;
        Ok(())
    }

    /// Handle INIT_METHOD_CALL — prepare to call $obj->method().
    fn handle_init_method_call(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let method_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let class_name = match &obj {
            Value::Object(o) => o.class_name.clone(),
            _ => {
                return Err(VmError::TypeError(
                    "Call to a member function on a non-object".to_string(),
                ));
            }
        };

        let full_name = format!("{}::{}", class_name, method_name);
        let frame = self.call_stack.last_mut().unwrap();
        // Push the object as first arg ($this) followed by actual args.
        // Save the source operand so we can write $this back after the method returns.
        frame.call_stack_pending.push(PendingCall {
            name: full_name,
            args: vec![obj],
            this_source: Some((op.op1_type, op.op1.val)),
        });
        Ok(())
    }

    /// Handle INIT_STATIC_METHOD_CALL — prepare to call Class::method().
    fn handle_init_static_method_call(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let class_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
        let method_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
        let full_name = format!("{}::{}", class_name, method_name);
        let frame = self.call_stack.last_mut().unwrap();
        frame.call_stack_pending.push(PendingCall {
            name: full_name,
            args: Vec::new(),
            this_source: None,
        });
        Ok(())
    }

    /// Handle FETCH_CLASS_CONSTANT — read Class::CONST.
    fn handle_fetch_class_constant(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let class_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
        let const_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let val = self
            .classes
            .get(&class_name)
            .and_then(|c| c.class_constants.get(&const_name))
            .cloned()
            .unwrap_or(Value::Null);

        self.write_result(op, oa_idx, val)?;
        Ok(())
    }

    /// Handle INSTANCEOF.
    fn handle_instanceof(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let obj = self.read_operand(op, 1, oa_idx)?;
        let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let result = match obj {
            Value::Object(ref o) => {
                o.class_name == class_name || self.is_subclass(&o.class_name, &class_name)
            }
            _ => false,
        };

        self.write_result(op, oa_idx, Value::Bool(result))?;
        Ok(())
    }

    /// Check if a class is a subclass of or implements a given class/interface.
    fn is_subclass(&self, child: &str, parent: &str) -> bool {
        let mut current = child.to_string();
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return false;
            }
            if let Some(class_def) = self.classes.get(&current) {
                // Check implemented interfaces
                if class_def.interfaces.iter().any(|i| i == parent) {
                    return true;
                }
                // Check parent class
                if let Some(ref p) = class_def.parent {
                    if p == parent {
                        return true;
                    }
                    current = p.clone();
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /// Check if a class implements a specific interface (walks class hierarchy).
    fn implements_interface(&self, class_name: &str, interface_name: &str) -> bool {
        let mut current = class_name.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return false;
            }
            if let Some(class_def) = self.classes.get(&current) {
                if class_def.interfaces.iter().any(|i| i == interface_name) {
                    return true;
                }
                if let Some(ref p) = class_def.parent {
                    current = p.clone();
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /// Call a method on an object synchronously and return the result.
    /// Used for internal callbacks like JsonSerializable::jsonSerialize().
    fn call_method_sync(&mut self, obj: &Value, method_name: &str) -> VmResult<Value> {
        let class_name = match obj {
            Value::Object(ref o) => o.class_name.clone(),
            _ => return Err(VmError::TypeError("Not an object".to_string())),
        };
        let method_key = format!("{}::{}", class_name, method_name);
        let oa_idx = self
            .functions
            .get(&method_key)
            .copied()
            .ok_or_else(|| VmError::UndefinedFunction(method_key.clone()))?;

        let saved_depth = self.call_stack.len();

        let func_oa = &self.op_arrays[oa_idx];
        let mut frame = Frame::new(func_oa);
        frame.op_array_idx = oa_idx;

        // Bind $this
        let this_cv = func_oa.vars.iter().position(|v| v == "this").unwrap_or(0);
        if this_cv < frame.cvs.len() {
            frame.cvs[this_cv] = obj.clone();
        }

        self.call_stack.push(frame);
        self.dispatch_loop_until(saved_depth)?;

        Ok(self.last_return_value.clone())
    }

    /// Handle FETCH_STATIC_PROP_* — read/write static properties.
    fn handle_fetch_static_prop(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<()> {
        let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
        let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

        let val = self
            .classes
            .get(&class_name)
            .and_then(|c| c.static_properties.get(&prop_name))
            .cloned()
            .unwrap_or(Value::Null);

        self.write_result(op, oa_idx, val)?;
        Ok(())
    }

    /// Handle INCLUDE_OR_EVAL — include/require/eval.
    fn handle_include_or_eval(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        let operand = self.read_operand(op, 1, oa_idx)?;
        let mode = op.extended_value;
        // mode: 0=eval, 1=include, 2=include_once, 3=require, 4=require_once

        let source = match mode {
            0 => {
                // eval(): operand is the code string
                let code = operand.to_php_string();
                if code.starts_with("<?php") || code.starts_with("<?") {
                    code
                } else {
                    format!("<?php {}", code)
                }
            }
            1 | 2 | 3 | 4 => {
                let path = operand.to_php_string();

                // For once variants, check if already included
                if (mode == 2 || mode == 4) && self.included_files.contains(&path) {
                    self.write_result(op, oa_idx, Value::Bool(true))?;
                    return Ok(DispatchSignal::Next);
                }

                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        self.included_files.insert(path);
                        contents
                    }
                    Err(_) => {
                        if mode == 3 || mode == 4 {
                            return Err(VmError::FatalError(format!(
                                "require(): Failed opening required '{}'",
                                path
                            )));
                        }
                        self.write_result(op, oa_idx, Value::Bool(false))?;
                        return Ok(DispatchSignal::Next);
                    }
                }
            }
            _ => {
                return Err(VmError::InternalError(format!(
                    "Unknown include/eval mode: {}",
                    mode
                )));
            }
        };

        // Compile and execute the source
        match php_rs_compiler::compile(&source) {
            Ok(included_oa) => {
                let base_idx = self.op_arrays.len();
                self.op_arrays.push(included_oa.clone());
                self.register_dynamic_func_defs(base_idx);

                // Advance caller's IP past the IncludeOrEval
                self.call_stack.last_mut().unwrap().ip += 1;

                let mut new_frame = Frame::new(&included_oa);
                new_frame.op_array_idx = base_idx;
                if op.result_type != OperandType::Unused {
                    new_frame.return_dest = Some((op.result_type, op.result.val));
                }

                self.call_stack.push(new_frame);
                Ok(DispatchSignal::CallPushed)
            }
            Err(_) => {
                if mode == 0 {
                    return Err(VmError::FatalError("eval(): syntax error".to_string()));
                }
                self.write_result(op, oa_idx, Value::Bool(false))?;
                Ok(DispatchSignal::Next)
            }
        }
    }

    /// Handle DO_FCALL — execute a function call.
    fn handle_do_fcall(&mut self, op: &ZOp, caller_oa_idx: usize) -> VmResult<DispatchSignal> {
        let caller_frame = self.call_stack.last_mut().unwrap();
        let pending = caller_frame
            .call_stack_pending
            .pop()
            .unwrap_or(PendingCall {
                name: String::new(),
                args: Vec::new(),
                this_source: None,
            });
        let func_name = pending.name;
        let args = pending.args;
        let this_source = pending.this_source;

        // Handle no-op constructor (NEW without __construct)
        if func_name == "__new_noop__" {
            return Ok(DispatchSignal::Next);
        }

        // If the "function" name is a class name, return it as a string value
        // (used by NEW to resolve class references compiled as INIT_FCALL + DO_FCALL)
        // The args passed here are actually constructor args — save them for the NEW/DO_FCALL that follows.
        if self.classes.contains_key(&func_name) {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, Value::String(func_name.clone()))?;
            }
            // Store constructor args for later use by NEW
            if !args.is_empty() {
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name: "__ctor_args__".to_string(),
                    args,
                    this_source: None,
                });
            }
            return Ok(DispatchSignal::Next);
        }

        // Check built-in functions first (use simple name for builtins)
        let simple_name = if func_name.contains("::") {
            func_name.rsplit("::").next().unwrap_or(&func_name)
        } else {
            &func_name
        };

        // For non-method calls, check builtins
        if !func_name.contains("::") {
            if let Some(result) = self.call_builtin(simple_name, &args)? {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }
        }

        // Check if this is a Generator method call
        if let Some(gen_result) = self.try_generator_method(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, gen_result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Check if this is a Fiber method call
        if let Some(fiber_result) = self.try_fiber_method(&func_name, &args)? {
            if op.result_type != OperandType::Unused {
                self.write_result(op, caller_oa_idx, fiber_result)?;
            }
            return Ok(DispatchSignal::Next);
        }

        // Look up user-defined function
        let func_oa_idx = self.functions.get(&func_name).copied();
        if let Some(oa_idx) = func_oa_idx {
            // Check if this is a generator function
            if self.op_arrays[oa_idx].is_generator {
                return self.create_generator_object(op, caller_oa_idx, oa_idx, &args);
            }

            // Advance caller's IP past DO_FCALL BEFORE pushing new frame
            self.call_stack.last_mut().unwrap().ip += 1;

            let func_oa = &self.op_arrays[oa_idx];
            let mut new_frame = Frame::new(func_oa);
            new_frame.op_array_idx = oa_idx;

            // For method calls, first arg is $this — bind it to CV(0) named "this"
            if func_name.contains("::") && !args.is_empty() {
                // Find the "this" CV index
                let this_cv_idx = func_oa.vars.iter().position(|v| v == "this").unwrap_or(0);
                if this_cv_idx < new_frame.cvs.len() {
                    new_frame.cvs[this_cv_idx] = args[0].clone();
                }
                // The rest are actual arguments (skip $this for RECV)
                new_frame.args = args[1..].to_vec();
            } else {
                new_frame.args = args.clone();
            }

            // For constructors, don't set return_dest (would overwrite the object with Null)
            let is_constructor = func_name.ends_with("::__construct");
            new_frame.is_constructor = is_constructor;

            if op.result_type != OperandType::Unused && !is_constructor {
                new_frame.return_dest = Some((op.result_type, op.result.val));
            }

            // Set up $this write-back for methods and constructors
            if let Some(src) = this_source {
                new_frame.this_write_back = Some(src);
            }

            // Bind parameters to CVs directly (for functions without RECV opcodes)
            let num_params = func_oa.arg_info.len().min(new_frame.args.len());
            for i in 0..num_params {
                if i < new_frame.cvs.len() {
                    new_frame.cvs[i] = new_frame.args[i].clone();
                }
            }

            self.call_stack.push(new_frame);
            return Ok(DispatchSignal::CallPushed);
        }

        // For method calls, try falling back to non-prefixed function
        if func_name.contains("::") {
            if let Some(result) = self.call_builtin(simple_name, &args)? {
                if op.result_type != OperandType::Unused {
                    self.write_result(op, caller_oa_idx, result)?;
                }
                return Ok(DispatchSignal::Next);
            }
        }

        Err(VmError::UndefinedFunction(func_name))
    }

    // =========================================================================
    // Generator support
    // =========================================================================

    /// Create a Generator object from a generator function call.
    fn create_generator_object(
        &mut self,
        op: &ZOp,
        caller_oa_idx: usize,
        gen_oa_idx: usize,
        args: &[Value],
    ) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let func_oa = &self.op_arrays[gen_oa_idx];
        let mut frame_cvs = vec![Value::Null; func_oa.vars.len()];
        let frame_temps = vec![Value::Null; func_oa.num_temps as usize];
        let frame_args = args.to_vec();

        // Bind parameters to CVs
        let num_params = func_oa.arg_info.len().min(args.len());
        for i in 0..num_params {
            if i < frame_cvs.len() {
                frame_cvs[i] = args[i].clone();
            }
        }

        // Create the Generator object
        let mut obj = PhpObject::new("Generator".to_string());
        obj.object_id = self.next_object_id;
        self.next_object_id += 1;
        obj.internal = InternalState::Generator;
        let obj_id = obj.object_id;

        // Create GeneratorState with the saved frame
        // ip=1 to skip past the GeneratorCreate opcode
        let gen_state = GeneratorState {
            frame: Some(GeneratorFrame {
                op_array_idx: gen_oa_idx,
                ip: 1,
                cvs: frame_cvs,
                temps: frame_temps,
                args: frame_args,
            }),
            op_array_idx: gen_oa_idx,
            value: Value::Null,
            key: Value::Null,
            return_value: None,
            send_value: Value::Null,
            largest_int_key: -1,
            status: GeneratorStatus::Created,
            yield_result_slot: None,
            delegate: None,
        };

        self.generators.insert(obj_id, gen_state);

        // Write the Generator object to the result slot
        if op.result_type != OperandType::Unused {
            self.write_result(op, caller_oa_idx, Value::Object(obj))?;
        }

        Ok(DispatchSignal::Next)
    }

    /// Resume a generator: restore its frame, run until yield/return, save state.
    fn resume_generator(&mut self, object_id: u64) -> VmResult<()> {
        use crate::value::*;

        let gen = self.generators.get_mut(&object_id)
            .ok_or_else(|| VmError::InternalError("Generator not found".to_string()))?;

        if gen.status == GeneratorStatus::Closed {
            return Ok(());
        }

        // Check if there's an active delegate
        if let Some(delegate) = gen.delegate.take() {
            match delegate {
                GeneratorDelegate::Array { entries, index } => {
                    if index < entries.len() {
                        // Yield next array element
                        let key = match entries[index].0 {
                            ArrayKey::Int(n) => Value::Long(n),
                            ArrayKey::String(ref s) => Value::String(s.clone()),
                        };
                        let val = entries[index].1.clone();
                        gen.key = key;
                        gen.value = val;
                        gen.status = GeneratorStatus::Suspended;
                        if index + 1 < entries.len() {
                            gen.delegate = Some(GeneratorDelegate::Array { entries, index: index + 1 });
                        }
                        // else: delegate exhausted, will resume frame on next call
                        return Ok(());
                    }
                    // Delegate exhausted — resume the generator frame
                    // Fall through to normal resume
                }
                GeneratorDelegate::Generator { inner_id } => {
                    // Resume the inner generator
                    let inner_status = self.generators.get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status == GeneratorStatus::Suspended {
                        self.resume_generator(inner_id)?;
                    }

                    let inner_status = self.generators.get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status != GeneratorStatus::Closed {
                        // Inner still has values — proxy them
                        let inner_val = self.generators.get(&inner_id)
                            .map(|g| g.value.clone())
                            .unwrap_or(Value::Null);
                        let inner_key = self.generators.get(&inner_id)
                            .map(|g| g.key.clone())
                            .unwrap_or(Value::Null);

                        let gen = self.generators.get_mut(&object_id).unwrap();
                        gen.value = inner_val;
                        gen.key = inner_key;
                        gen.status = GeneratorStatus::Suspended;
                        gen.delegate = Some(GeneratorDelegate::Generator { inner_id });
                        return Ok(());
                    }

                    // Inner generator closed — get return value and resume outer
                    let inner_ret = self.generators.get(&inner_id)
                        .and_then(|g| g.return_value.clone())
                        .unwrap_or(Value::Null);

                    // Resume the outer generator with inner's return value as the yield_from result
                    let gen = self.generators.get_mut(&object_id).unwrap();
                    gen.send_value = inner_ret;
                    // Fall through to normal resume
                }
            }
        }

        let gen = self.generators.get_mut(&object_id).unwrap();

        // Take the saved frame
        let saved_frame = match gen.frame.take() {
            Some(f) => f,
            None => return Ok(()), // No frame to resume (closed or error)
        };

        let send_value = gen.send_value.clone();
        let yield_result_slot = gen.yield_result_slot.take();
        gen.status = GeneratorStatus::Running;

        // Push the generator's frame onto the call stack
        let mut frame = Frame::new(&self.op_arrays[saved_frame.op_array_idx]);
        frame.op_array_idx = saved_frame.op_array_idx;
        frame.ip = saved_frame.ip;
        frame.cvs = saved_frame.cvs;
        frame.temps = saved_frame.temps;
        frame.args = saved_frame.args;

        // Write the send_value to the yield result slot
        if let Some((slot_type, slot_val)) = yield_result_slot {
            Self::write_to_slot(&mut frame, slot_type, slot_val, send_value);
        }

        let depth = self.call_stack.len();
        self.call_stack.push(frame);

        // Run the dispatch loop until it returns (via Yield or Return signal)
        self.dispatch_loop_until(depth)?;

        Ok(())
    }

    /// Ensure a generator is initialized (run to first yield if status == Created).
    fn ensure_generator_initialized(&mut self, object_id: u64) -> VmResult<()> {
        let status = self.generators.get(&object_id)
            .map(|g| g.status)
            .unwrap_or(crate::value::GeneratorStatus::Closed);

        if status == crate::value::GeneratorStatus::Created {
            self.resume_generator(object_id)?;
        }
        Ok(())
    }

    /// Handle the Yield opcode — save frame and signal yield.
    fn handle_yield(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let val = self.read_operand(op, 1, oa_idx)?;

        // Read key from op2 if provided
        let key = if op.op2_type != OperandType::Unused {
            self.read_operand(op, 2, oa_idx)?
        } else {
            Value::Null
        };

        // Find which generator owns this frame
        let frame = self.call_stack.last().unwrap();
        let frame_oa_idx = frame.op_array_idx;

        // Find the generator by matching op_array_idx
        let gen_id = self.generators.iter()
            .find(|(_, g)| g.op_array_idx == frame_oa_idx && g.status == GeneratorStatus::Running)
            .map(|(id, _)| *id);

        if let Some(object_id) = gen_id {
            // Save the frame (advance IP past this Yield instruction)
            let frame = self.call_stack.pop().unwrap();
            let saved = GeneratorFrame {
                op_array_idx: frame.op_array_idx,
                ip: frame.ip + 1,  // resume after this yield
                cvs: frame.cvs,
                temps: frame.temps,
                args: frame.args,
            };

            let gen = self.generators.get_mut(&object_id).unwrap();

            // Set the key: use explicit key if provided, otherwise auto-increment
            if op.op2_type != OperandType::Unused {
                gen.key = key;
                // Update largest_int_key if this is an integer key
                if let Value::Long(k) = &gen.key {
                    if *k > gen.largest_int_key {
                        gen.largest_int_key = *k;
                    }
                }
            } else {
                gen.largest_int_key += 1;
                gen.key = Value::Long(gen.largest_int_key);
            }

            gen.value = val;
            gen.frame = Some(saved);
            gen.status = GeneratorStatus::Suspended;
            gen.yield_result_slot = if op.result_type != OperandType::Unused {
                Some((op.result_type, op.result.val))
            } else {
                None
            };
            gen.send_value = Value::Null;

            Ok(DispatchSignal::Yield)
        } else {
            // Not in a generator context — just pass through (shouldn't happen with correct compilation)
            self.write_result(op, oa_idx, val)?;
            Ok(DispatchSignal::Next)
        }
    }

    /// Handle GeneratorReturn — set return value, close generator.
    fn handle_generator_return(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let val = self.read_operand(op, 1, oa_idx)?;

        let frame = self.call_stack.last().unwrap();
        let frame_oa_idx = frame.op_array_idx;

        let gen_id = self.generators.iter()
            .find(|(_, g)| g.op_array_idx == frame_oa_idx && g.status == GeneratorStatus::Running)
            .map(|(id, _)| *id);

        if let Some(object_id) = gen_id {
            // Pop the frame — generator is done
            self.call_stack.pop();

            let gen = self.generators.get_mut(&object_id).unwrap();
            gen.return_value = Some(val);
            gen.status = GeneratorStatus::Closed;
            gen.frame = None;
            gen.value = Value::Null;

            Ok(DispatchSignal::Yield)
        } else {
            // Not in a generator context — treat as normal return
            let frame = self.call_stack.last_mut().unwrap();
            frame.return_value = val;
            Ok(DispatchSignal::Return)
        }
    }

    /// Handle yield from delegation.
    fn handle_yield_from(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let val = self.read_operand(op, 1, oa_idx)?;

        // Find which generator owns this frame
        let frame = self.call_stack.last().unwrap();
        let frame_oa_idx = frame.op_array_idx;

        let gen_id = self.generators.iter()
            .find(|(_, g)| g.op_array_idx == frame_oa_idx && g.status == GeneratorStatus::Running)
            .map(|(id, _)| *id);

        if let Some(outer_id) = gen_id {
            match val {
                Value::Array(ref arr) => {
                    if arr.is_empty() {
                        self.write_result(op, oa_idx, Value::Null)?;
                        return Ok(DispatchSignal::Next);
                    }
                    let entries: Vec<_> = arr.entries().to_vec();
                    let first_key = match &entries[0].0 {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let first_val = entries[0].1.clone();
                    let delegate = GeneratorDelegate::Array { entries, index: 1 };

                    let frame = self.call_stack.pop().unwrap();
                    let saved = GeneratorFrame {
                        op_array_idx: frame.op_array_idx,
                        ip: frame.ip + 1, // resume after YieldFrom
                        cvs: frame.cvs,
                        temps: frame.temps,
                        args: frame.args,
                    };

                    let gen = self.generators.get_mut(&outer_id).unwrap();
                    gen.key = first_key;
                    gen.value = first_val;
                    gen.frame = Some(saved);
                    gen.status = GeneratorStatus::Suspended;
                    gen.yield_result_slot = if op.result_type != OperandType::Unused {
                        Some((op.result_type, op.result.val))
                    } else {
                        None
                    };
                    gen.delegate = Some(delegate);
                    gen.send_value = Value::Null;

                    Ok(DispatchSignal::Yield)
                }
                Value::Object(ref o) if o.internal == InternalState::Generator => {
                    let inner_id = o.object_id;
                    self.ensure_generator_initialized(inner_id)?;

                    let inner_status = self.generators.get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status == GeneratorStatus::Closed {
                        let ret = self.generators.get(&inner_id)
                            .and_then(|g| g.return_value.clone())
                            .unwrap_or(Value::Null);
                        self.write_result(op, oa_idx, ret)?;
                        return Ok(DispatchSignal::Next);
                    }

                    let inner_val = self.generators.get(&inner_id)
                        .map(|g| g.value.clone())
                        .unwrap_or(Value::Null);
                    let inner_key = self.generators.get(&inner_id)
                        .map(|g| g.key.clone())
                        .unwrap_or(Value::Null);
                    let delegate = GeneratorDelegate::Generator { inner_id };

                    let frame = self.call_stack.pop().unwrap();
                    let saved = GeneratorFrame {
                        op_array_idx: frame.op_array_idx,
                        ip: frame.ip + 1, // resume after YieldFrom
                        cvs: frame.cvs,
                        temps: frame.temps,
                        args: frame.args,
                    };

                    let gen = self.generators.get_mut(&outer_id).unwrap();
                    gen.value = inner_val;
                    gen.key = inner_key;
                    gen.frame = Some(saved);
                    gen.status = GeneratorStatus::Suspended;
                    gen.yield_result_slot = if op.result_type != OperandType::Unused {
                        Some((op.result_type, op.result.val))
                    } else {
                        None
                    };
                    gen.delegate = Some(delegate);

                    Ok(DispatchSignal::Yield)
                }
                _ => {
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Next)
                }
            }
        } else {
            self.write_result(op, oa_idx, val)?;
            Ok(DispatchSignal::Next)
        }
    }

    /// Try to dispatch a Generator method call. Returns Some if handled.
    fn try_generator_method(&mut self, func_name: &str, args: &[Value]) -> VmResult<Option<Value>> {
        use crate::value::*;

        // Check if the first arg ($this) is a Generator object
        let (method_name, object_id) = if func_name.contains("::") {
            let parts: Vec<&str> = func_name.splitn(2, "::").collect();
            let class = parts[0];
            let method = parts[1];
            if class != "Generator" {
                // Check if $this (first arg) is a Generator
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal == InternalState::Generator {
                        (method, o.object_id)
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            } else {
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal == InternalState::Generator {
                        (method, o.object_id)
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        } else {
            return Ok(None);
        };

        match method_name {
            "current" => {
                self.ensure_generator_initialized(object_id)?;
                let val = self.generators.get(&object_id)
                    .map(|g| g.value.clone())
                    .unwrap_or(Value::Null);
                Ok(Some(val))
            }
            "key" => {
                self.ensure_generator_initialized(object_id)?;
                let val = self.generators.get(&object_id)
                    .map(|g| g.key.clone())
                    .unwrap_or(Value::Null);
                Ok(Some(val))
            }
            "valid" => {
                self.ensure_generator_initialized(object_id)?;
                let is_valid = self.generators.get(&object_id)
                    .map(|g| g.status != GeneratorStatus::Closed)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(is_valid)))
            }
            "rewind" => {
                let status = self.generators.get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);
                if status == GeneratorStatus::Created {
                    self.ensure_generator_initialized(object_id)?;
                }
                // Rewind after started is a no-op (PHP behavior — emits warning but continues)
                Ok(Some(Value::Null))
            }
            "next" => {
                self.ensure_generator_initialized(object_id)?;
                let status = self.generators.get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);
                if status == GeneratorStatus::Suspended {
                    self.resume_generator(object_id)?;
                }
                Ok(Some(Value::Null))
            }
            "send" => {
                let send_val = args.get(1).cloned().unwrap_or(Value::Null);

                // If Created, initialize first (ignore send value for first call)
                let status = self.generators.get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);

                if status == GeneratorStatus::Created {
                    self.ensure_generator_initialized(object_id)?;
                }

                let status = self.generators.get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);

                if status == GeneratorStatus::Suspended {
                    if let Some(gen) = self.generators.get_mut(&object_id) {
                        gen.send_value = send_val;
                    }
                    self.resume_generator(object_id)?;
                }

                let val = self.generators.get(&object_id)
                    .map(|g| g.value.clone())
                    .unwrap_or(Value::Null);
                Ok(Some(val))
            }
            "getReturn" => {
                let gen = self.generators.get(&object_id);
                match gen {
                    Some(g) if g.status == GeneratorStatus::Closed => {
                        Ok(Some(g.return_value.clone().unwrap_or(Value::Null)))
                    }
                    _ => {
                        Err(VmError::FatalError(
                            "Cannot get return value of a generator that hasn't returned".to_string()
                        ))
                    }
                }
            }
            "throw" => {
                let exc = args.get(1).cloned().unwrap_or(Value::Null);
                self.ensure_generator_initialized(object_id)?;
                // Set exception and resume
                self.current_exception = Some(exc);
                let status = self.generators.get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);
                if status == GeneratorStatus::Suspended {
                    self.resume_generator(object_id)?;
                }
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // =========================================================================
    // Fiber support
    // =========================================================================

    /// Try to dispatch a Fiber method call. Returns Some if handled.
    fn try_fiber_method(&mut self, func_name: &str, args: &[Value]) -> VmResult<Option<Value>> {
        use crate::value::*;

        // Handle Fiber::suspend() as a static call
        if func_name == "Fiber::suspend" {
            let suspend_val = args.first().cloned().unwrap_or(Value::Null);
            return self.fiber_suspend(suspend_val).map(Some);
        }

        // Check if the first arg ($this) is a Fiber object
        let (method_name, object_id) = if func_name.contains("::") {
            let parts: Vec<&str> = func_name.splitn(2, "::").collect();
            let class = parts[0];
            let method = parts[1];
            if class != "Fiber" {
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal == InternalState::Fiber {
                        (method, o.object_id)
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            } else {
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal == InternalState::Fiber {
                        (method, o.object_id)
                    } else {
                        return Ok(None);
                    }
                } else {
                    // Static methods on Fiber class
                    if method == "suspend" {
                        let suspend_val = args.first().cloned().unwrap_or(Value::Null);
                        return self.fiber_suspend(suspend_val).map(Some);
                    }
                    return Ok(None);
                }
            }
        } else {
            return Ok(None);
        };

        match method_name {
            "start" => {
                let start_args = args[1..].to_vec();
                self.fiber_start(object_id, &start_args)
            }
            "resume" => {
                let resume_val = args.get(1).cloned().unwrap_or(Value::Null);
                self.fiber_resume(object_id, resume_val)
            }
            "getReturn" => {
                let fiber = self.fibers.get(&object_id);
                match fiber {
                    Some(f) if f.status == FiberStatus::Terminated => {
                        Ok(Some(f.return_value.clone().unwrap_or(Value::Null)))
                    }
                    _ => {
                        Err(VmError::FatalError(
                            "Cannot get return value of a fiber that hasn't terminated".to_string()
                        ))
                    }
                }
            }
            "isStarted" => {
                let started = self.fibers.get(&object_id)
                    .map(|f| f.status != FiberStatus::Init)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(started)))
            }
            "isRunning" => {
                let running = self.fibers.get(&object_id)
                    .map(|f| f.status == FiberStatus::Running)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(running)))
            }
            "isSuspended" => {
                let suspended = self.fibers.get(&object_id)
                    .map(|f| f.status == FiberStatus::Suspended)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(suspended)))
            }
            "isTerminated" => {
                let terminated = self.fibers.get(&object_id)
                    .map(|f| f.status == FiberStatus::Terminated)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(terminated)))
            }
            _ => Ok(None),
        }
    }

    /// Start a fiber: look up its callable, create frame, run until suspend/complete.
    fn fiber_start(&mut self, object_id: u64, args: &[Value]) -> VmResult<Option<Value>> {
        use crate::value::*;

        let callback_name = self.fibers.get(&object_id)
            .map(|f| f.callback_name.clone())
            .ok_or_else(|| VmError::InternalError("Fiber not found".to_string()))?;

        let status = self.fibers.get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if status != FiberStatus::Init {
            return Err(VmError::FatalError("Cannot start a fiber that is not in init state".to_string()));
        }

        // Look up the callable
        let func_oa_idx = self.functions.get(&callback_name).copied()
            .ok_or_else(|| VmError::UndefinedFunction(callback_name.clone()))?;

        let func_oa = &self.op_arrays[func_oa_idx];
        let mut new_frame = Frame::new(func_oa);
        new_frame.op_array_idx = func_oa_idx;
        new_frame.args = args.to_vec();

        // Bind parameters to CVs
        let num_params = func_oa.arg_info.len().min(args.len());
        for i in 0..num_params {
            if i < new_frame.cvs.len() {
                new_frame.cvs[i] = args[i].clone();
            }
        }

        let start_depth = self.call_stack.len();

        if let Some(fiber) = self.fibers.get_mut(&object_id) {
            fiber.status = FiberStatus::Running;
            fiber.start_depth = start_depth;
        }

        self.current_fiber_id = Some(object_id);
        self.call_stack.push(new_frame);

        // Run until fiber suspends or completes
        let result = self.dispatch_loop_until(start_depth);

        // Check if fiber suspended or completed
        let fiber_status = self.fibers.get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if fiber_status == FiberStatus::Running {
            // Fiber completed normally (dispatch loop returned because call stack unwound)
            if let Some(fiber) = self.fibers.get_mut(&object_id) {
                fiber.status = FiberStatus::Terminated;
                fiber.return_value = Some(self.last_return_value.clone());
            }
            self.current_fiber_id = None;
        }

        result?;

        let transfer = self.fibers.get(&object_id)
            .map(|f| f.transfer_value.clone())
            .unwrap_or(Value::Null);

        Ok(Some(transfer))
    }

    /// Resume a suspended fiber.
    fn fiber_resume(&mut self, object_id: u64, value: Value) -> VmResult<Option<Value>> {
        use crate::value::*;

        let status = self.fibers.get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if status != FiberStatus::Suspended {
            return Err(VmError::FatalError("Cannot resume a fiber that is not suspended".to_string()));
        }

        // Restore saved frames
        let saved_frames = self.fibers.get_mut(&object_id)
            .map(|f| std::mem::take(&mut f.saved_frames))
            .unwrap_or_default();

        let start_depth = self.call_stack.len();

        for sf in saved_frames {
            let func_oa = &self.op_arrays[sf.op_array_idx];
            let mut frame = Frame::new(func_oa);
            frame.op_array_idx = sf.op_array_idx;
            frame.ip = sf.ip;
            frame.cvs = sf.cvs;
            frame.temps = sf.temps;
            frame.args = sf.args;
            frame.return_value = sf.return_value;
            frame.return_dest = sf.return_dest;
            frame.this_write_back = sf.this_write_back;
            frame.is_constructor = sf.is_constructor;
            self.call_stack.push(frame);
        }

        if let Some(fiber) = self.fibers.get_mut(&object_id) {
            fiber.status = FiberStatus::Running;
            fiber.transfer_value = value;
            fiber.start_depth = start_depth;
        }

        self.current_fiber_id = Some(object_id);

        // Run until fiber suspends or completes
        let result = self.dispatch_loop_until(start_depth);

        let fiber_status = self.fibers.get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if fiber_status == FiberStatus::Running {
            if let Some(fiber) = self.fibers.get_mut(&object_id) {
                fiber.status = FiberStatus::Terminated;
                fiber.return_value = Some(self.last_return_value.clone());
            }
            self.current_fiber_id = None;
        }

        result?;

        let transfer = self.fibers.get(&object_id)
            .map(|f| f.transfer_value.clone())
            .unwrap_or(Value::Null);

        Ok(Some(transfer))
    }

    /// Fiber::suspend() — save current fiber's frames and break execution.
    fn fiber_suspend(&mut self, value: Value) -> VmResult<Value> {
        use crate::value::*;

        let fiber_id = self.current_fiber_id
            .ok_or_else(|| VmError::FatalError("Cannot call Fiber::suspend() outside of a fiber".to_string()))?;

        let start_depth = self.fibers.get(&fiber_id)
            .map(|f| f.start_depth)
            .unwrap_or(0);

        // Drain frames from start_depth to current top
        let mut saved_frames = Vec::new();
        while self.call_stack.len() > start_depth {
            let frame = self.call_stack.pop().unwrap();
            saved_frames.push(FiberFrame {
                op_array_idx: frame.op_array_idx,
                ip: frame.ip + 1,  // resume after the DO_FCALL that called suspend
                cvs: frame.cvs,
                temps: frame.temps,
                args: frame.args,
                return_value: frame.return_value,
                return_dest: frame.return_dest,
                this_write_back: frame.this_write_back,
                is_constructor: frame.is_constructor,
            });
        }
        saved_frames.reverse();  // Maintain original order

        if let Some(fiber) = self.fibers.get_mut(&fiber_id) {
            fiber.saved_frames = saved_frames;
            fiber.status = FiberStatus::Suspended;
            fiber.transfer_value = value;
        }

        self.current_fiber_id = None;
        Ok(Value::Null)
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
                    Value::Object(_) => "object",
                    Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => "unknown type",
                };
                Ok(Some(Value::String(t.to_string())))
            }
            "get_class" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                match v {
                    Value::Object(ref o) => Ok(Some(Value::String(o.class_name.clone()))),
                    _ => Ok(Some(Value::Bool(false))),
                }
            }
            "is_object" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(matches!(v, Value::Object(_)))))
            }
            "property_exists" => {
                let obj = args.first().cloned().unwrap_or(Value::Null);
                let prop = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let exists = match obj {
                    Value::Object(ref o) => o.properties.contains_key(&prop),
                    _ => false,
                };
                Ok(Some(Value::Bool(exists)))
            }
            "class_exists" => {
                let name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(self.classes.contains_key(&name))))
            }
            "method_exists" => {
                let obj_or_class = args.first().cloned().unwrap_or(Value::Null);
                let method = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let class_name = match obj_or_class {
                    Value::Object(ref o) => o.class_name.clone(),
                    Value::String(s) => s,
                    _ => String::new(),
                };
                let exists = self
                    .classes
                    .get(&class_name)
                    .is_some_and(|c| c.methods.contains_key(&method));
                Ok(Some(Value::Bool(exists)))
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
            "json_encode" => {
                let val = args.first().cloned().unwrap_or(Value::Null);
                let options = args.get(1).cloned().unwrap_or(Value::Long(0)).to_long() as u32;

                // Check if object implements JsonSerializable
                let val_to_encode = if let Value::Object(ref o) = val {
                    if self.implements_interface(&o.class_name, "JsonSerializable") {
                        // Call jsonSerialize() method synchronously
                        match self.call_method_sync(&val, "jsonSerialize") {
                            Ok(result) => result,
                            Err(_) => val.clone(),
                        }
                    } else {
                        val.clone()
                    }
                } else {
                    val.clone()
                };

                let json_val = Self::value_to_json(&val_to_encode);
                match php_rs_ext_json::json_encode(&json_val, options) {
                    Some(s) => Ok(Some(Value::String(s))),
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "json_decode" => {
                let json_str = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let assoc = args.get(1).is_some_and(|v| v.to_bool());
                let depth = args.get(2).cloned().unwrap_or(Value::Long(512)).to_long() as usize;
                match php_rs_ext_json::json_decode(&json_str, assoc, depth) {
                    Some(jv) => Ok(Some(Self::json_to_value(&jv, assoc))),
                    None => Ok(Some(Value::Null)),
                }
            }
            "json_last_error" => Ok(Some(Value::Long(php_rs_ext_json::json_last_error() as i64))),
            "json_last_error_msg" => Ok(Some(Value::String(
                php_rs_ext_json::json_last_error_msg().to_string(),
            ))),
            // ── Phase 8 additions ──
            "quoted_printable_encode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_quoted_printable_encode(s.as_bytes()),
                )))
            }
            "quoted_printable_decode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_quoted_printable_decode(&s),
                )))
            }
            "addslashes" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_addslashes(&s),
                )))
            }
            "stripslashes" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_stripslashes(&s),
                )))
            }
            "get_parent_class" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                let cn = match &v {
                    Value::Object(o) => o.class_name.clone(),
                    Value::String(s) => s.clone(),
                    _ => return Ok(Some(Value::Bool(false))),
                };
                match self.classes.get(&cn).and_then(|c| c.parent.clone()) {
                    Some(p) => Ok(Some(Value::String(p))),
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "is_a" => {
                let obj = args.first().cloned().unwrap_or(Value::Null);
                let target = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let cn = match &obj {
                    Value::Object(o) => o.class_name.clone(),
                    Value::String(s) => s.clone(),
                    _ => return Ok(Some(Value::Bool(false))),
                };
                if cn.eq_ignore_ascii_case(&target) {
                    return Ok(Some(Value::Bool(true)));
                }
                let mut cur = cn;
                loop {
                    match self.classes.get(&cur).and_then(|c| c.parent.clone()) {
                        Some(p) if p.eq_ignore_ascii_case(&target) => {
                            return Ok(Some(Value::Bool(true)))
                        }
                        Some(p) => cur = p,
                        None => break,
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "is_subclass_of" => {
                let obj = args.first().cloned().unwrap_or(Value::Null);
                let target = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let cn = match &obj {
                    Value::Object(o) => o.class_name.clone(),
                    Value::String(s) => s.clone(),
                    _ => return Ok(Some(Value::Bool(false))),
                };
                if cn.eq_ignore_ascii_case(&target) {
                    return Ok(Some(Value::Bool(false)));
                }
                let mut cur = cn;
                loop {
                    match self.classes.get(&cur).and_then(|c| c.parent.clone()) {
                        Some(p) if p.eq_ignore_ascii_case(&target) => {
                            return Ok(Some(Value::Bool(true)))
                        }
                        Some(p) => cur = p,
                        None => break,
                    }
                }
                Ok(Some(Value::Bool(false)))
            }
            "call_user_func" => {
                let func_name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let func_args: Vec<Value> = args.get(1..).unwrap_or(&[]).to_vec();
                // Try built-in first, then user-defined
                match self.call_builtin(&func_name, &func_args) {
                    Ok(Some(v)) => Ok(Some(v)),
                    _ => {
                        // User-defined function call would go through the main exec loop
                        // For now, return false if not a built-in
                        Ok(Some(Value::Bool(false)))
                    }
                }
            }
            "call_user_func_array" => {
                let func_name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let arr = args.get(1).cloned().unwrap_or(Value::Null);
                let func_args: Vec<Value> = if let Value::Array(ref a) = arr {
                    a.entries().iter().map(|(_, v)| v.clone()).collect()
                } else {
                    vec![]
                };
                match self.call_builtin(&func_name, &func_args) {
                    Ok(Some(v)) => Ok(Some(v)),
                    _ => Ok(Some(Value::Bool(false))),
                }
            }
            "header" | "header_remove" => Ok(Some(Value::Null)),
            "headers_sent" => Ok(Some(Value::Bool(false))),
            "http_response_code" => {
                let code = args.first().map(|v| v.to_long() as u16);
                match code {
                    Some(c) if c > 0 => Ok(Some(Value::Long(c as i64))),
                    _ => Ok(Some(Value::Long(200))),
                }
            }
            "exit" | "die" => {
                let arg = args.first().cloned().unwrap_or(Value::Null);
                match arg {
                    Value::String(s) => {
                        self.output.push_str(&s);
                        Err(VmError::Exit(0))
                    }
                    Value::Long(n) => Err(VmError::Exit(n as i32)),
                    _ => Err(VmError::Exit(0)),
                }
            }
            "register_shutdown_function" => {
                let func_name = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                if !func_name.is_empty() {
                    self.shutdown_functions.push(func_name);
                }
                Ok(Some(Value::Null))
            }
            "set_time_limit" => Ok(Some(Value::Bool(true))),
            "ignore_user_abort" => Ok(Some(Value::Long(0))),
            "function_exists" => {
                let fname = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(self.functions.contains_key(&fname))))
            }
            "is_callable" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::Bool(
                    matches!(v, Value::String(ref s) if self.functions.contains_key(s)),
                )))
            }
            "preg_match" => {
                let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                match parse_php_regex(&pat) {
                    Some((re, flags)) => match regex::Regex::new(&apply_regex_flags(&re, &flags)) {
                        Ok(r) => Ok(Some(Value::Long(if r.is_match(&subj) { 1 } else { 0 }))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    },
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "preg_match_all" => {
                let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                match parse_php_regex(&pat) {
                    Some((re, flags)) => match regex::Regex::new(&apply_regex_flags(&re, &flags)) {
                        Ok(r) => Ok(Some(Value::Long(r.find_iter(&subj).count() as i64))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    },
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "preg_replace" => {
                let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let rep = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                let subj = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
                match parse_php_regex(&pat) {
                    Some((re, flags)) => match regex::Regex::new(&apply_regex_flags(&re, &flags)) {
                        Ok(r) => {
                            let rr = rep
                                .replace("\\1", "$1")
                                .replace("\\2", "$2")
                                .replace("\\3", "$3");
                            Ok(Some(Value::String(
                                r.replace_all(&subj, rr.as_str()).to_string(),
                            )))
                        }
                        Err(_) => Ok(Some(Value::Null)),
                    },
                    None => Ok(Some(Value::Null)),
                }
            }
            "preg_split" => {
                let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let subj = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                match parse_php_regex(&pat) {
                    Some((re, flags)) => match regex::Regex::new(&apply_regex_flags(&re, &flags)) {
                        Ok(r) => {
                            let mut arr = PhpArray::new();
                            for part in r.split(&subj) {
                                arr.push(Value::String(part.to_string()));
                            }
                            Ok(Some(Value::Array(arr)))
                        }
                        Err(_) => Ok(Some(Value::Bool(false))),
                    },
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "preg_replace_callback" => {
                // Stub: return the subject unchanged (callback execution is complex)
                let subject = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(subject)))
            }
            "preg_last_error" => {
                // PREG_NO_ERROR = 0
                Ok(Some(Value::Long(0)))
            }
            "preg_last_error_msg" => Ok(Some(Value::String("No error".to_string()))),
            "preg_grep" => {
                let pat = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let input = args.get(1).cloned().unwrap_or(Value::Null);
                let flags = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                let invert = flags & 1 != 0; // PREG_GREP_INVERT = 1

                match parse_php_regex(&pat) {
                    Some((pattern, modifiers)) => {
                        let case_insensitive = modifiers.contains('i');
                        let regex_pattern = if case_insensitive {
                            format!("(?i){}", pattern)
                        } else {
                            pattern
                        };
                        match regex::Regex::new(&regex_pattern) {
                            Ok(re) => {
                                let mut result = PhpArray::new();
                                if let Value::Array(ref arr) = input {
                                    for (key, val) in arr.entries() {
                                        let s = val.to_php_string();
                                        let matched = re.is_match(&s);
                                        if matched != invert {
                                            match key {
                                                ArrayKey::Int(i) => {
                                                    result.set_int(*i, val.clone());
                                                }
                                                ArrayKey::String(s) => {
                                                    result.set_string(s.clone(), val.clone());
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(Some(Value::Array(result)))
                            }
                            Err(_) => Ok(Some(Value::Bool(false))),
                        }
                    }
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "preg_quote" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let delim = args.get(1).map(|v| v.to_php_string());
                let special = ".\\+*?[^$(){}=!<>|:-#";
                let mut result = String::with_capacity(s.len() + 8);
                for ch in s.chars() {
                    if special.contains(ch) {
                        result.push('\\');
                    } else if let Some(ref d) = delim {
                        if d.contains(ch) {
                            result.push('\\');
                        }
                    }
                    result.push(ch);
                }
                Ok(Some(Value::String(result)))
            }
            "md5" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(php_rs_ext_standard::strings::php_md5(
                    &s,
                ))))
            }
            "sha1" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(php_rs_ext_standard::strings::php_sha1(
                    &s,
                ))))
            }
            "base64_encode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_base64_encode(s.as_bytes()),
                )))
            }
            "base64_decode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                match php_rs_ext_standard::strings::php_base64_decode(&s) {
                    Some(b) => Ok(Some(Value::String(String::from_utf8_lossy(&b).to_string()))),
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "htmlspecialchars" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_htmlspecialchars(
                        &s,
                        php_rs_ext_standard::strings::HtmlFlags::default(),
                    ),
                )))
            }
            "htmlspecialchars_decode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_htmlspecialchars_decode(&s),
                )))
            }
            "urlencode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_urlencode(&s),
                )))
            }
            "urldecode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_urldecode(&s),
                )))
            }
            "rawurlencode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_rawurlencode(&s),
                )))
            }
            "rawurldecode" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_rawurldecode(&s),
                )))
            }
            "crc32" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Long(php_rs_ext_standard::strings::php_crc32(
                    &s,
                ))))
            }
            "str_rot13" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_str_rot13(&s),
                )))
            }
            "ucfirst" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_ucfirst(&s),
                )))
            }
            "lcfirst" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_lcfirst(&s),
                )))
            }
            "ucwords" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let d = args
                    .get(1)
                    .cloned()
                    .unwrap_or(Value::String(String::new()))
                    .to_php_string();
                Ok(Some(Value::String(
                    php_rs_ext_standard::strings::php_ucwords(&s, &d),
                )))
            }
            "serialize" => {
                let val = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::String(
                    php_rs_ext_standard::variables::php_serialize(&value_to_serializable(&val)),
                )))
            }
            "unserialize" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                match php_rs_ext_standard::variables::php_unserialize(&s) {
                    Some(sv) => Ok(Some(serializable_to_value(&sv))),
                    None => Ok(Some(Value::Bool(false))),
                }
            }
            "get_debug_type" => {
                let v = args.first().cloned().unwrap_or(Value::Null);
                Ok(Some(Value::String(
                    match v {
                        Value::Null => "null",
                        Value::Bool(_) => "bool",
                        Value::Long(_) => "int",
                        Value::Double(_) => "float",
                        Value::String(_) => "string",
                        Value::Array(_) => "array",
                        Value::Object(_) => "object",
                        Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => "unknown",
                    }
                    .to_string(),
                )))
            }
            "time" => {
                use std::time::{SystemTime, UNIX_EPOCH};
                Ok(Some(Value::Long(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0) as i64,
                )))
            }
            "microtime" => {
                use std::time::{SystemTime, UNIX_EPOCH};
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                if args.first().map(|v| v.to_bool()).unwrap_or(false) {
                    Ok(Some(Value::Double(now.as_secs_f64())))
                } else {
                    Ok(Some(Value::String(format!(
                        "0.{:06}00 {}",
                        now.subsec_micros(),
                        now.as_secs()
                    ))))
                }
            }
            "sleep" => {
                let secs = args
                    .first()
                    .cloned()
                    .unwrap_or(Value::Long(0))
                    .to_long()
                    .max(0) as u64;
                std::thread::sleep(std::time::Duration::from_secs(secs));
                Ok(Some(Value::Long(0)))
            }
            "usleep" => {
                let us = args
                    .first()
                    .cloned()
                    .unwrap_or(Value::Long(0))
                    .to_long()
                    .max(0) as u64;
                std::thread::sleep(std::time::Duration::from_micros(us));
                Ok(Some(Value::Null))
            }
            "phpversion" => Ok(Some(Value::String("8.6.0-php.rs".to_string()))),
            "php_uname" => {
                let m = args
                    .first()
                    .cloned()
                    .unwrap_or(Value::String("a".to_string()))
                    .to_php_string();
                Ok(Some(Value::String(php_rs_ext_standard::misc::php_uname(
                    m.chars().next().unwrap_or('a'),
                ))))
            }
            "php_sapi_name" => Ok(Some(Value::String("cli".to_string()))),
            "getenv" => {
                let n = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                match std::env::var(&n) {
                    Ok(v) => Ok(Some(Value::String(v))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            "putenv" => {
                let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                if let Some(eq) = s.find('=') {
                    std::env::set_var(&s[..eq], &s[eq + 1..]);
                }
                Ok(Some(Value::Bool(true)))
            }
            "file_get_contents" => {
                let f = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                match std::fs::read_to_string(&f) {
                    Ok(c) => Ok(Some(Value::String(c))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            "file_put_contents" => {
                let f = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                let d = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
                match std::fs::write(&f, &d) {
                    Ok(()) => Ok(Some(Value::Long(d.len() as i64))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            "file_exists" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(std::path::Path::new(&p).exists())))
            }
            "is_file" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(std::path::Path::new(&p).is_file())))
            }
            "is_dir" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::Bool(std::path::Path::new(&p).is_dir())))
            }
            "dirname" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    std::path::Path::new(&p)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| ".".to_string()),
                )))
            }
            "basename" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                Ok(Some(Value::String(
                    std::path::Path::new(&p)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                )))
            }
            "realpath" => {
                let p = args.first().cloned().unwrap_or(Value::Null).to_php_string();
                match std::fs::canonicalize(&p) {
                    Ok(rp) => Ok(Some(Value::String(rp.to_string_lossy().to_string()))),
                    Err(_) => Ok(Some(Value::Bool(false))),
                }
            }
            _ => Ok(None),
        }
    }

    /// Convert a VM Value to a JsonValue for encoding.
    fn value_to_json(val: &Value) -> JsonValue {
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
                let mut entries: Vec<(String, JsonValue)> = o
                    .properties
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::value_to_json(v)))
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                JsonValue::Object(entries)
            }
            Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => JsonValue::Null,
        }
    }

    /// Convert a JsonValue to a VM Value after decoding.
    fn json_to_value(jv: &JsonValue, assoc: bool) -> Value {
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
                    let mut obj = PhpObject::new("stdClass".to_string());
                    for (k, v) in entries {
                        obj.properties
                            .insert(k.clone(), Self::json_to_value(v, assoc));
                    }
                    Value::Object(obj)
                }
            }
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
            Value::Object(o) => {
                self.output.push_str(&format!(
                    "{}object({})#{} ({}) {{\n",
                    indent,
                    o.class_name,
                    o.object_id,
                    o.properties.len()
                ));
                let mut props: Vec<_> = o.properties.iter().collect();
                props.sort_by_key(|(k, _)| (*k).clone());
                for (name, val) in props {
                    self.output
                        .push_str(&format!("{}  [\"{}\"]=>", indent, name));
                    self.output.push('\n');
                    self.var_dump(val, depth + 1);
                }
                self.output.push_str(&format!("{}}}\n", indent));
            }
            Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => {
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
            Value::Object(o) => {
                let mut s = format!("{} Object\n", o.class_name);
                s.push_str(&format!("{}(\n", indent));
                let mut props: Vec<_> = o.properties.iter().collect();
                props.sort_by_key(|(k, _)| (*k).clone());
                for (name, val) in props {
                    let val_str = self.print_r_string(val, depth + 1);
                    s.push_str(&format!("{}    [{}] => {}\n", indent, name, val_str));
                }
                s.push_str(&format!("{})\n", indent));
                s
            }
            Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => String::new(),
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
            Value::Object(o) => {
                format!("(object) array(/* {} properties */)", o.properties.len())
            }
            Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => "NULL".to_string(),
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
    /// Write a value to a specific slot in a frame (used for return value / $this write-back).
    fn write_to_slot(frame: &mut Frame, op_type: OperandType, slot: u32, val: Value) {
        match op_type {
            OperandType::TmpVar | OperandType::Var => {
                let idx = slot as usize;
                if idx >= frame.temps.len() {
                    frame.temps.resize(idx + 1, Value::Null);
                }
                frame.temps[idx] = val;
            }
            OperandType::Cv => {
                let idx = slot as usize;
                if idx >= frame.cvs.len() {
                    frame.cvs.resize(idx + 1, Value::Null);
                }
                frame.cvs[idx] = val;
            }
            _ => {}
        }
    }

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

// ── Helper functions for built-in implementations ──

/// Parse a PHP-style regex pattern like /pattern/flags.
fn parse_php_regex(pattern: &str) -> Option<(String, String)> {
    if pattern.is_empty() {
        return None;
    }
    let delimiter = pattern.as_bytes()[0] as char;
    let end_delim = match delimiter {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        c if c.is_alphanumeric() || c == '\\' => return None,
        c => c,
    };
    // Find the closing delimiter (not escaped)
    let body = &pattern[1..];
    let mut i = 0;
    let bytes = body.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // Skip escaped char
        } else if bytes[i] == end_delim as u8 {
            let re_pattern = &body[..i];
            let flags = &body[i + 1..];
            return Some((re_pattern.to_string(), flags.to_string()));
        } else {
            i += 1;
        }
    }
    None
}

/// Apply PHP regex modifier flags to a pattern string for Rust regex.
fn apply_regex_flags(pattern: &str, flags: &str) -> String {
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('s') {
        prefix.push_str("(?s)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    if flags.contains('x') {
        prefix.push_str("(?x)");
    }
    format!("{}{}", prefix, pattern)
}

/// Convert a VM Value to a SerializableValue for PHP serialize().
fn value_to_serializable(val: &Value) -> php_rs_ext_standard::variables::SerializableValue {
    use php_rs_ext_standard::variables::SerializableValue as SV;
    match val {
        Value::Null => SV::Null,
        Value::Bool(b) => SV::Bool(*b),
        Value::Long(n) => SV::Int(*n),
        Value::Double(f) => SV::Float(*f),
        Value::String(s) => SV::Str(s.clone()),
        Value::Array(a) => {
            let entries: Vec<_> = a
                .entries()
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        crate::value::ArrayKey::Int(n) => SV::Int(*n),
                        crate::value::ArrayKey::String(s) => SV::Str(s.clone()),
                    };
                    (key, value_to_serializable(v))
                })
                .collect();
            SV::Array(entries)
        }
        Value::Object(_) => SV::Null, // Simplified: objects serialize as null for now
        Value::_Iterator { .. } | Value::_GeneratorIterator { .. } => SV::Null,
    }
}

/// Convert a SerializableValue back to a VM Value for PHP unserialize().
fn serializable_to_value(sv: &php_rs_ext_standard::variables::SerializableValue) -> Value {
    use php_rs_ext_standard::variables::SerializableValue as SV;
    match sv {
        SV::Null => Value::Null,
        SV::Bool(b) => Value::Bool(*b),
        SV::Int(n) => Value::Long(*n),
        SV::Float(f) => Value::Double(*f),
        SV::Str(s) => Value::String(s.clone()),
        SV::Array(entries) => {
            let mut arr = PhpArray::new();
            for (k, v) in entries {
                let key = match k {
                    SV::Int(n) => Value::Long(*n),
                    SV::Str(s) => Value::String(s.clone()),
                    _ => Value::String(String::new()),
                };
                arr.set(&key, serializable_to_value(v));
            }
            Value::Array(arr)
        }
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

    // =========================================================================
    // 5.5.4 JMPZNZ
    // =========================================================================

    #[test]
    fn test_vm_null_coalesce_chain() {
        let output = run_php("<?php $a = null; $b = null; $c = 42; echo $a ?? $b ?? $c;");
        assert_eq!(output, "42");
    }

    // =========================================================================
    // 5.8 Exception handling
    // =========================================================================

    #[test]
    fn test_vm_try_catch_basic() {
        let output = run_php(
            r#"<?php
try {
    echo "try ";
    throw 42;
} catch (Exception $e) {
    echo "catch";
}
"#,
        );
        assert_eq!(output, "try catch");
    }

    #[test]
    fn test_vm_try_catch_exception_variable() {
        let output = run_php(
            r#"<?php
try {
    throw "error!";
} catch (Exception $e) {
    echo $e;
}
"#,
        );
        assert_eq!(output, "error!");
    }

    #[test]
    fn test_vm_try_catch_finally() {
        let output = run_php(
            r#"<?php
try {
    echo "A";
} catch (Exception $e) {
    echo "B";
} finally {
    echo "C";
}
"#,
        );
        // No exception: try body + finally
        assert!(output.contains("A"));
        assert!(output.contains("C"));
        assert!(!output.contains("B"));
    }

    #[test]
    fn test_vm_try_catch_with_throw_and_finally() {
        let output = run_php(
            r#"<?php
try {
    echo "A";
    throw "err";
} catch (Exception $e) {
    echo "B";
} finally {
    echo "C";
}
"#,
        );
        assert_eq!(output, "ABC");
    }

    #[test]
    fn test_vm_uncaught_exception() {
        let op_array = php_rs_compiler::compile("<?php throw 42;").unwrap();
        let mut vm = Vm::new();
        let result = vm.execute(&op_array);
        assert!(result.is_err());
    }

    // =========================================================================
    // 5.10 Class & object handlers
    // =========================================================================

    #[test]
    fn test_vm_class_basic() {
        let output = run_php(
            r#"<?php
class Greeter {
    public function greet() {
        echo "Hello from class!";
    }
}
$g = new Greeter();
$g->greet();
"#,
        );
        assert_eq!(output, "Hello from class!");
    }

    #[test]
    fn test_vm_class_constructor() {
        let output = run_php(
            r#"<?php
class Person {
    public function __construct($name) {
        $this->name = $name;
    }
    public function greet() {
        echo "Hi, " . $this->name;
    }
}
$p = new Person("Alice");
$p->greet();
"#,
        );
        assert_eq!(output, "Hi, Alice");
    }

    #[test]
    fn test_vm_class_property_access() {
        let output = run_php(
            r#"<?php
class Box {
    public function __construct($value) {
        $this->value = $value;
    }
    public function getValue() {
        return $this->value;
    }
}
$b = new Box(42);
echo $b->getValue();
"#,
        );
        assert_eq!(output, "42");
    }

    #[test]
    fn test_vm_class_method_with_params() {
        let output = run_php(
            r#"<?php
class Calculator {
    public function add($a, $b) {
        return $a + $b;
    }
}
$calc = new Calculator();
echo $calc->add(3, 4);
"#,
        );
        assert_eq!(output, "7");
    }

    #[test]
    fn test_vm_class_multiple_instances() {
        let output = run_php(
            r#"<?php
class Counter {
    public function __construct($start) {
        $this->count = $start;
    }
    public function increment() {
        $this->count = $this->count + 1;
    }
    public function getCount() {
        return $this->count;
    }
}
$a = new Counter(0);
$b = new Counter(10);
$a->increment();
$a->increment();
$b->increment();
echo $a->getCount();
echo " ";
echo $b->getCount();
"#,
        );
        assert_eq!(output, "2 11");
    }

    #[test]
    fn test_vm_instanceof() {
        let output = run_php(
            r#"<?php
class Animal {}
class Dog {}
$a = new Animal();
$d = new Dog();
if ($a instanceof Animal) { echo "yes "; }
if ($d instanceof Animal) { echo "no"; } else { echo "no "; }
if ($d instanceof Dog) { echo "yes"; }
"#,
        );
        assert_eq!(output, "yes no yes");
    }

    #[test]
    fn test_vm_gettype_object() {
        let output = run_php(
            r#"<?php
class Foo {}
$f = new Foo();
echo gettype($f);
"#,
        );
        assert_eq!(output, "object");
    }

    #[test]
    fn test_vm_get_class() {
        let output = run_php(
            r#"<?php
class MyClass {}
$obj = new MyClass();
echo get_class($obj);
"#,
        );
        assert_eq!(output, "MyClass");
    }

    #[test]
    fn test_vm_static_method() {
        let output = run_php(
            r#"<?php
class MathHelper {
    public static function double($x) {
        return $x * 2;
    }
}
echo MathHelper::double(21);
"#,
        );
        assert_eq!(output, "42");
    }

    // =========================================================================
    // 5.12 Include & eval
    // =========================================================================

    #[test]
    fn test_vm_eval_basic() {
        let output = run_php(
            r#"<?php
eval('echo "hello from eval";');
"#,
        );
        assert_eq!(output, "hello from eval");
    }

    #[test]
    fn test_vm_eval_expression() {
        let output = run_php(
            r#"<?php
$x = eval('return 2 + 3;');
echo $x;
"#,
        );
        assert_eq!(output, "5");
    }

    #[test]
    fn test_vm_include_file() {
        // Create a temp file to include
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_include.php");
        std::fs::write(&path, "<?php echo \"included\";").unwrap();

        let source = format!(
            "<?php include '{}';",
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "included");

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_vm_require_missing_file() {
        let op_array = compile("<?php require '/nonexistent/file.php';").unwrap();
        let mut vm = Vm::new();
        let result = vm.execute(&op_array);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_include_once_dedup() {
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_test_include_once.php");
        std::fs::write(&path, "<?php echo \"X\";").unwrap();

        let source = format!(
            "<?php\ninclude_once '{0}';\ninclude_once '{0}';",
            path.to_str().unwrap().replace('\\', "\\\\")
        );
        let output = run_php(&source);
        assert_eq!(output, "X"); // Only once

        let _ = std::fs::remove_file(&path);
    }

    // =========================================================================
    // json_encode / json_decode
    // =========================================================================

    #[test]
    fn test_json_encode_scalar() {
        assert_eq!(run_php(r#"<?php echo json_encode(42);"#), "42");
        assert_eq!(run_php(r#"<?php echo json_encode("hello");"#), "\"hello\"");
        assert_eq!(run_php(r#"<?php echo json_encode(true);"#), "true");
        assert_eq!(run_php(r#"<?php echo json_encode(false);"#), "false");
        assert_eq!(run_php(r#"<?php echo json_encode(null);"#), "null");
        assert_eq!(run_php(r#"<?php echo json_encode(1.5);"#), "1.5");
    }

    #[test]
    fn test_json_encode_array() {
        assert_eq!(run_php(r#"<?php echo json_encode([1, 2, 3]);"#), "[1,2,3]");
    }

    #[test]
    fn test_json_encode_assoc_array() {
        assert_eq!(
            run_php(r#"<?php echo json_encode(["a" => 1, "b" => 2]);"#),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn test_json_encode_object() {
        let output = run_php(
            r#"<?php
$obj = new stdClass;
$obj->name = "PHP";
$obj->version = 8;
echo json_encode($obj);
"#,
        );
        assert_eq!(output, r#"{"name":"PHP","version":8}"#);
    }

    #[test]
    fn test_json_decode_scalar() {
        assert_eq!(run_php(r#"<?php echo json_decode("42");"#), "42");
        assert_eq!(run_php(r#"<?php echo json_decode('"hello"');"#), "hello");
        assert_eq!(
            run_php(r#"<?php var_dump(json_decode("true"));"#),
            "bool(true)\n"
        );
        assert_eq!(run_php(r#"<?php var_dump(json_decode("null"));"#), "NULL\n");
    }

    #[test]
    fn test_json_decode_assoc() {
        assert_eq!(
            run_php(
                r#"<?php
$data = json_decode('{"a":1,"b":"hello"}', true);
echo $data["a"] . " " . $data["b"];
"#
            ),
            "1 hello"
        );
    }

    #[test]
    fn test_json_last_error() {
        assert_eq!(
            run_php(
                r#"<?php
json_decode("{bad}");
echo json_last_error();
"#
            ),
            "4"
        );
    }

    #[test]
    fn test_json_last_error_msg() {
        assert_eq!(
            run_php(
                r#"<?php
json_decode("{bad}");
echo json_last_error_msg();
"#
            ),
            "Syntax error"
        );
    }

    // =========================================================================
    // JsonSerializable interface
    // =========================================================================

    #[test]
    fn test_json_serializable() {
        let output = run_php(
            r#"<?php
class Foo implements JsonSerializable {
    public function jsonSerialize() {
        return ["custom" => "data", "count" => 42];
    }
}
echo json_encode(new Foo());
"#,
        );
        assert_eq!(output, r#"{"custom":"data","count":42}"#);
    }

    #[test]
    fn test_json_serializable_scalar_return() {
        let output = run_php(
            r#"<?php
class Bar implements JsonSerializable {
    public function jsonSerialize() {
        return "just a string";
    }
}
echo json_encode(new Bar());
"#,
        );
        assert_eq!(output, r#""just a string""#);
    }

    // =========================================================================
    // Interface / instanceof
    // =========================================================================

    #[test]
    fn test_instanceof_interface() {
        assert_eq!(
            run_php(
                r#"<?php
interface Printable {}
class Doc implements Printable {}
$d = new Doc();
var_dump($d instanceof Printable);
"#
            ),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_instanceof_interface_negative() {
        assert_eq!(
            run_php(
                r#"<?php
interface Printable {}
class Doc {}
$d = new Doc();
var_dump($d instanceof Printable);
"#
            ),
            "bool(false)\n"
        );
    }

    // =========================================================================
    // 8.2.15: list() / array destructuring
    // =========================================================================

    #[test]
    fn test_list_simple() {
        assert_eq!(
            run_php("<?php list($a, $b) = [1, 2]; echo $a . ',' . $b;"),
            "1,2"
        );
    }

    #[test]
    fn test_list_with_skip() {
        assert_eq!(
            run_php("<?php list($a, , $c) = [1, 2, 3]; echo $a . ',' . $c;"),
            "1,3"
        );
    }

    #[test]
    fn test_list_from_variable() {
        assert_eq!(
            run_php("<?php $arr = [10, 20, 30]; list($x, $y, $z) = $arr; echo $x . ' ' . $y . ' ' . $z;"),
            "10 20 30"
        );
    }

    // =========================================================================
    // 8.3.5: isset, unset, empty
    // =========================================================================

    #[test]
    fn test_isset_single() {
        assert_eq!(
            run_php("<?php $a = 1; var_dump(isset($a));"),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_isset_unset_variable() {
        assert_eq!(
            run_php("<?php $a = 1; unset($a); var_dump(isset($a));"),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_unset_array_element() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = [1, 2, 3];
unset($arr[1]);
var_dump(count($arr));
echo $arr[0] . "," . $arr[2];
"#
            ),
            "int(2)\n1,3"
        );
    }

    #[test]
    fn test_isset_array_element() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ['a' => 1, 'b' => 2];
var_dump(isset($arr['a']));
var_dump(isset($arr['c']));
"#
            ),
            "bool(true)\nbool(false)\n"
        );
    }

    #[test]
    fn test_isset_multiple_variables() {
        assert_eq!(
            run_php("<?php $a = 1; $b = 2; var_dump(isset($a, $b));"),
            "bool(true)\n"
        );
    }

    #[test]
    fn test_isset_multiple_one_unset() {
        assert_eq!(
            run_php("<?php $a = 1; var_dump(isset($a, $b));"),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_empty_variable() {
        assert_eq!(
            run_php(
                r#"<?php
$a = "";
$b = "hello";
$c = 0;
var_dump(empty($a));
var_dump(empty($b));
var_dump(empty($c));
"#
            ),
            "bool(true)\nbool(false)\nbool(true)\n"
        );
    }

    // =========================================================================
    // 8.6.10: register_shutdown_function
    // =========================================================================

    #[test]
    fn test_register_shutdown_function() {
        assert_eq!(
            run_php(
                r#"<?php
function my_shutdown() {
    echo "shutdown!";
}
register_shutdown_function("my_shutdown");
echo "main ";
"#
            ),
            "main shutdown!"
        );
    }

    #[test]
    fn test_register_multiple_shutdown_functions() {
        assert_eq!(
            run_php(
                r#"<?php
function shutdown1() { echo "1"; }
function shutdown2() { echo "2"; }
register_shutdown_function("shutdown1");
register_shutdown_function("shutdown2");
echo "main ";
"#
            ),
            "main 12"
        );
    }

    // =========================================================================
    // 8.7.1-8.7.4: preg_* regex functions
    // =========================================================================

    #[test]
    fn test_preg_replace_callback_stub() {
        assert_eq!(
            run_php(
                r#"<?php
$result = preg_replace_callback("/foo/", "strtoupper", "hello foo world");
echo $result;
"#
            ),
            "hello foo world"
        );
    }

    #[test]
    fn test_preg_last_error() {
        assert_eq!(run_php("<?php echo preg_last_error();"), "0");
    }

    #[test]
    fn test_preg_last_error_msg() {
        assert_eq!(run_php("<?php echo preg_last_error_msg();"), "No error");
    }

    #[test]
    fn test_preg_grep() {
        assert_eq!(
            run_php(
                r#"<?php
$arr = ["foo", "bar", "baz", "foobar"];
$result = preg_grep("/^foo/", $arr);
echo count($result);
"#
            ),
            "2"
        );
    }

    #[test]
    fn test_preg_match() {
        assert_eq!(
            run_php("<?php echo preg_match('/hello/', 'hello world');"),
            "1"
        );
    }

    #[test]
    fn test_preg_match_no_match() {
        assert_eq!(
            run_php("<?php echo preg_match('/xyz/', 'hello world');"),
            "0"
        );
    }

    #[test]
    fn test_preg_replace() {
        assert_eq!(
            run_php(r#"<?php echo preg_replace('/world/', 'PHP', 'hello world');"#),
            "hello PHP"
        );
    }

    #[test]
    fn test_preg_split() {
        assert_eq!(
            run_php(
                r#"<?php
$parts = preg_split('/[\s,]+/', 'one, two, three');
echo count($parts);
"#
            ),
            "3"
        );
    }

    #[test]
    fn test_preg_quote() {
        assert_eq!(
            run_php(r#"<?php echo preg_quote('$var.test+value');"#),
            r#"\$var\.test\+value"#
        );
    }

    // =========================================================================
    // 5.11 Generators & Fibers
    // =========================================================================

    #[test]
    fn test_generator_debug_creation() {
        // Test that calling a generator function returns a Generator object
        let source = r#"<?php
function gen() { yield 1; yield 2; }
$g = gen();
echo get_class($g);
"#;
        let op_array = compile(source).unwrap();
        // Check that the sub-function is marked as generator
        for def in &op_array.dynamic_func_defs {
            if def.function_name.as_deref() == Some("gen") {
                assert!(def.is_generator, "gen() should be marked as generator");
            }
        }
        let mut vm = Vm::new();
        let output = vm.execute(&op_array).unwrap();
        assert_eq!(output, "Generator");
    }

    #[test]
    fn test_generator_debug_foreach_opcodes() {
        let source = r#"<?php
function gen() { yield 1; yield 2; yield 3; }
foreach (gen() as $v) { echo "$v\n"; }
"#;
        let op_array = compile(source).unwrap();
        eprintln!("{}", op_array.disassemble());
        // Make sure it disassembles, but don't check output (debugging)
    }

    #[test]
    fn test_generator_basic_foreach() {
        // Simpler test
        assert_eq!(
            run_php(concat!(
                "<?php\n",
                "function gen() { yield 10; yield 20; yield 30; }\n",
                "foreach (gen() as $v) { echo $v; }\n",
            )),
            "102030"
        );
    }

    #[test]
    fn test_generator_manual_iteration() {
        // Test generator without foreach, using manual iteration
        assert_eq!(
            run_php(concat!(
                "<?php\n",
                "function gen() { yield 10; yield 20; }\n",
                "$g = gen();\n",
                "echo $g->current();\n",
                "$g->next();\n",
                "echo $g->current();\n",
                "$g->next();\n",
                "echo $g->valid() ? 'yes' : 'no';\n",
            )),
            "1020no"
        );
    }

    #[test]
    fn test_generator_foreach_with_keys() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; yield 3; }
foreach (gen() as $k => $v) { echo $k . ": " . $v . "\n"; }
"#
            ),
            "0: 1\n1: 2\n2: 3\n"
        );
    }

    #[test]
    fn test_generator_method_current_key_valid_next() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; yield 3; }
$g = gen();
var_dump($g->current());
var_dump($g->key());
$g->next();
var_dump($g->current());
var_dump($g->valid());
$g->next();
$g->next();
var_dump($g->valid());
"#
            ),
            "int(1)\nint(0)\nint(2)\nbool(true)\nbool(false)\n"
        );
    }

    #[test]
    fn test_generator_send() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    $x = yield 'first';
    echo "Got: " . $x . "\n";
    yield 'second';
}
$g = gen();
$g->current();
$g->send('hello');
"#
            ),
            "Got: hello\n"
        );
    }

    #[test]
    fn test_generator_get_return() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; return 42; }
$g = gen();
$g->current();
$g->next();
var_dump($g->getReturn());
"#
            ),
            "int(42)\n"
        );
    }

    #[test]
    fn test_generator_yield_with_explicit_keys() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield 'a' => 1;
    yield 'b' => 2;
}
foreach (gen() as $k => $v) { echo $k . ": " . $v . "\n"; }
"#
            ),
            "a: 1\nb: 2\n"
        );
    }

    #[test]
    fn test_generator_fibonacci() {
        assert_eq!(
            run_php(
                r#"<?php
function fibonacci() {
    $a = 0;
    $b = 1;
    while (true) {
        yield $a;
        $temp = $a;
        $a = $b;
        $b = $temp + $b;
    }
}
$count = 0;
foreach (fibonacci() as $n) {
    if ($n > 100) break;
    echo $n . "\n";
    $count = $count + 1;
}
"#
            ),
            "0\n1\n1\n2\n3\n5\n8\n13\n21\n34\n55\n89\n"
        );
    }

    #[test]
    fn test_generator_multiple_generators() {
        assert_eq!(
            run_php(
                r#"<?php
function range_gen($start, $end) {
    $i = $start;
    while ($i <= $end) {
        yield $i;
        $i = $i + 1;
    }
}
$a = range_gen(1, 3);
$b = range_gen(10, 12);
echo $a->current() . "\n";
echo $b->current() . "\n";
$a->next();
echo $a->current() . "\n";
echo $b->current() . "\n";
"#
            ),
            "1\n10\n2\n10\n"
        );
    }

    #[test]
    fn test_generator_rewind() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() { yield 1; yield 2; }
$g = gen();
$g->rewind();
var_dump($g->current());
"#
            ),
            "int(1)\n"
        );
    }

    #[test]
    fn test_generator_empty() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    return;
    yield 1;
}
$g = gen();
var_dump($g->valid());
"#
            ),
            "bool(false)\n"
        );
    }

    #[test]
    fn test_fiber_basic() {
        assert_eq!(
            run_php(
                r#"<?php
function work() {
    Fiber::suspend(1);
    Fiber::suspend(2);
    return 3;
}
$f = new Fiber('work');
var_dump($f->start());
var_dump($f->resume());
var_dump($f->resume());
"#
            ),
            "int(1)\nint(2)\nint(3)\n"
        );
    }

    #[test]
    fn test_fiber_status_methods() {
        assert_eq!(
            run_php(
                r#"<?php
function work() {
    Fiber::suspend();
}
$f = new Fiber('work');
var_dump($f->isStarted());
$f->start();
var_dump($f->isStarted());
var_dump($f->isSuspended());
$f->resume();
var_dump($f->isTerminated());
"#
            ),
            "bool(false)\nbool(true)\nbool(true)\nbool(true)\n"
        );
    }

    #[test]
    fn test_fiber_get_return() {
        assert_eq!(
            run_php(
                r#"<?php
function work() { return 42; }
$f = new Fiber('work');
$f->start();
var_dump($f->getReturn());
"#
            ),
            "int(42)\n"
        );
    }

    #[test]
    fn test_generator_yield_from_array() {
        assert_eq!(
            run_php(
                r#"<?php
function gen() {
    yield from [1, 2, 3];
    yield 4;
}
foreach (gen() as $v) { echo $v . "\n"; }
"#
            ),
            "1\n2\n3\n4\n"
        );
    }

    #[test]
    fn test_generator_yield_from_generator() {
        assert_eq!(
            run_php(
                r#"<?php
function inner() { yield 1; yield 2; return 'ret'; }
function outer() {
    $r = yield from inner();
    echo "inner returned: " . $r . "\n";
    yield 3;
}
foreach (outer() as $v) { echo $v . "\n"; }
"#
            ),
            "1\n2\ninner returned: ret\n3\n"
        );
    }
}
