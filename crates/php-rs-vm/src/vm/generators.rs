//! Generator and Fiber support — extracted from vm.rs.

use std::collections::HashMap;

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;

use super::{ClassDef, DispatchSignal, Frame, PendingCall, Vm, VmError, VmResult};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    // =========================================================================
    // Generator support
    // =========================================================================

    /// Create a Generator object from a generator function call.
    pub(crate) fn create_generator_object(
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
                if func_oa.arg_info[i].is_variadic {
                    let mut arr = PhpArray::new();
                    for j in i..args.len() {
                        arr.push(args[j].clone());
                    }
                    frame_cvs[i] = Value::Array(arr);
                    break;
                }
                frame_cvs[i] = args[i].clone();
            }
        }

        // Create the Generator object
        let obj = PhpObject::new("Generator".to_string());
        obj.set_object_id(self.next_object_id);
        self.next_object_id += 1;
        obj.set_internal(InternalState::Generator);
        let obj_id = obj.object_id();

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
    pub(crate) fn resume_generator(&mut self, object_id: u64) -> VmResult<()> {
        use crate::value::*;

        let gen = self
            .generators
            .get_mut(&object_id)
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
                            gen.delegate = Some(GeneratorDelegate::Array {
                                entries,
                                index: index + 1,
                            });
                        }
                        // else: delegate exhausted, will resume frame on next call
                        return Ok(());
                    }
                    // Delegate exhausted — resume the generator frame
                    // Fall through to normal resume
                }
                GeneratorDelegate::Generator { inner_id } => {
                    // Resume the inner generator
                    let inner_status = self
                        .generators
                        .get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status == GeneratorStatus::Suspended {
                        self.resume_generator(inner_id)?;
                    }

                    let inner_status = self
                        .generators
                        .get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status != GeneratorStatus::Closed {
                        // Inner still has values — proxy them
                        let inner_val = self
                            .generators
                            .get(&inner_id)
                            .map(|g| g.value.clone())
                            .unwrap_or(Value::Null);
                        let inner_key = self
                            .generators
                            .get(&inner_id)
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
                    let inner_ret = self
                        .generators
                        .get(&inner_id)
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
    pub(crate) fn ensure_generator_initialized(&mut self, object_id: u64) -> VmResult<()> {
        let status = self
            .generators
            .get(&object_id)
            .map(|g| g.status)
            .unwrap_or(crate::value::GeneratorStatus::Closed);

        if status == crate::value::GeneratorStatus::Created {
            self.resume_generator(object_id)?;
        }
        Ok(())
    }

    /// Handle the Yield opcode — save frame and signal yield.
    pub(crate) fn handle_yield(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
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
        let gen_id = self
            .generators
            .iter()
            .find(|(_, g)| g.op_array_idx == frame_oa_idx && g.status == GeneratorStatus::Running)
            .map(|(id, _)| *id);

        if let Some(object_id) = gen_id {
            // Save the frame (advance IP past this Yield instruction)
            let frame = self.call_stack.pop().unwrap();
            let saved = GeneratorFrame {
                op_array_idx: frame.op_array_idx,
                ip: frame.ip + 1, // resume after this yield
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
    pub(crate) fn handle_generator_return(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
    ) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let val = self.read_operand(op, 1, oa_idx)?;

        let frame = self.call_stack.last().unwrap();
        let frame_oa_idx = frame.op_array_idx;

        let gen_id = self
            .generators
            .iter()
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
    pub(crate) fn handle_yield_from(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
    ) -> VmResult<DispatchSignal> {
        use crate::value::*;

        let val = self.read_operand(op, 1, oa_idx)?;

        // Find which generator owns this frame
        let frame = self.call_stack.last().unwrap();
        let frame_oa_idx = frame.op_array_idx;

        let gen_id = self
            .generators
            .iter()
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
                Value::Object(ref o) if o.internal() == InternalState::Generator => {
                    let inner_id = o.object_id();
                    self.ensure_generator_initialized(inner_id)?;

                    let inner_status = self
                        .generators
                        .get(&inner_id)
                        .map(|g| g.status)
                        .unwrap_or(GeneratorStatus::Closed);

                    if inner_status == GeneratorStatus::Closed {
                        let ret = self
                            .generators
                            .get(&inner_id)
                            .and_then(|g| g.return_value.clone())
                            .unwrap_or(Value::Null);
                        self.write_result(op, oa_idx, ret)?;
                        return Ok(DispatchSignal::Next);
                    }

                    let inner_val = self
                        .generators
                        .get(&inner_id)
                        .map(|g| g.value.clone())
                        .unwrap_or(Value::Null);
                    let inner_key = self
                        .generators
                        .get(&inner_id)
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
    pub(crate) fn try_generator_method(
        &mut self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        use crate::value::*;

        // Check if the first arg ($this) is a Generator object
        let (method_name, object_id) = if func_name.contains("::") {
            let parts: Vec<&str> = func_name.splitn(2, "::").collect();
            let class = parts[0];
            let method = parts[1];
            if class != "Generator" {
                // Check if $this (first arg) is a Generator
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal() == InternalState::Generator {
                        (method, o.object_id())
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            } else {
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal() == InternalState::Generator {
                        (method, o.object_id())
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
                let val = self
                    .generators
                    .get(&object_id)
                    .map(|g| g.value.clone())
                    .unwrap_or(Value::Null);
                Ok(Some(val))
            }
            "key" => {
                self.ensure_generator_initialized(object_id)?;
                let val = self
                    .generators
                    .get(&object_id)
                    .map(|g| g.key.clone())
                    .unwrap_or(Value::Null);
                Ok(Some(val))
            }
            "valid" => {
                self.ensure_generator_initialized(object_id)?;
                let is_valid = self
                    .generators
                    .get(&object_id)
                    .map(|g| g.status != GeneratorStatus::Closed)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(is_valid)))
            }
            "rewind" => {
                let status = self
                    .generators
                    .get(&object_id)
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
                let status = self
                    .generators
                    .get(&object_id)
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
                let status = self
                    .generators
                    .get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);

                if status == GeneratorStatus::Created {
                    self.ensure_generator_initialized(object_id)?;
                }

                let status = self
                    .generators
                    .get(&object_id)
                    .map(|g| g.status)
                    .unwrap_or(GeneratorStatus::Closed);

                if status == GeneratorStatus::Suspended {
                    if let Some(gen) = self.generators.get_mut(&object_id) {
                        gen.send_value = send_val;
                    }
                    self.resume_generator(object_id)?;
                }

                let val = self
                    .generators
                    .get(&object_id)
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
                    _ => Err(VmError::FatalError(
                        "Cannot get return value of a generator that hasn't returned".to_string(),
                    )),
                }
            }
            "throw" => {
                let exc = args.get(1).cloned().unwrap_or(Value::Null);
                self.ensure_generator_initialized(object_id)?;
                // Set exception and resume
                self.current_exception = Some(exc);
                let status = self
                    .generators
                    .get(&object_id)
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
    pub(crate) fn try_fiber_method(
        &mut self,
        func_name: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
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
                    if o.internal() == InternalState::Fiber {
                        (method, o.object_id())
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            } else {
                if let Some(Value::Object(ref o)) = args.first() {
                    if o.internal() == InternalState::Fiber {
                        (method, o.object_id())
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
                    _ => Err(VmError::FatalError(
                        "Cannot get return value of a fiber that hasn't terminated".to_string(),
                    )),
                }
            }
            "isStarted" => {
                let started = self
                    .fibers
                    .get(&object_id)
                    .map(|f| f.status != FiberStatus::Init)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(started)))
            }
            "isRunning" => {
                let running = self
                    .fibers
                    .get(&object_id)
                    .map(|f| f.status == FiberStatus::Running)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(running)))
            }
            "isSuspended" => {
                let suspended = self
                    .fibers
                    .get(&object_id)
                    .map(|f| f.status == FiberStatus::Suspended)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(suspended)))
            }
            "isTerminated" => {
                let terminated = self
                    .fibers
                    .get(&object_id)
                    .map(|f| f.status == FiberStatus::Terminated)
                    .unwrap_or(false);
                Ok(Some(Value::Bool(terminated)))
            }
            _ => Ok(None),
        }
    }

    /// Start a fiber: look up its callable, create frame, run until suspend/complete.
    pub(crate) fn fiber_start(
        &mut self,
        object_id: u64,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        use crate::value::*;

        let callback_name = self
            .fibers
            .get(&object_id)
            .map(|f| f.callback_name.clone())
            .ok_or_else(|| VmError::InternalError("Fiber not found".to_string()))?;

        let status = self
            .fibers
            .get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if status != FiberStatus::Init {
            return Err(VmError::FatalError(
                "Cannot start a fiber that is not in init state".to_string(),
            ));
        }

        // Look up the callable
        let func_oa_idx = self
            .functions
            .get(&callback_name)
            .copied()
            .ok_or_else(|| VmError::UndefinedFunction(callback_name.clone()))?;

        let func_oa = &self.op_arrays[func_oa_idx];
        let mut new_frame = Frame::new(func_oa);
        new_frame.op_array_idx = func_oa_idx;
        new_frame.args = args.to_vec();

        // Bind parameters to CVs
        let num_params = func_oa.arg_info.len().min(args.len());
        for i in 0..num_params {
            if i < new_frame.cvs.len() {
                if func_oa.arg_info[i].is_variadic {
                    let mut arr = PhpArray::new();
                    for j in i..args.len() {
                        arr.push(args[j].clone());
                    }
                    new_frame.cvs[i] = Value::Array(arr);
                    break;
                }
                new_frame.cvs[i] = args[i].clone();
            }
        }

        // Apply closure bindings (captured `use` variables)
        if let Some(bindings) = self.closure_bindings.get(&callback_name) {
            for (var_name, val) in bindings {
                if let Some(cv_idx) = func_oa.vars.iter().position(|v| v == var_name) {
                    if cv_idx < new_frame.cvs.len() {
                        new_frame.cvs[cv_idx] = val.clone();
                    }
                }
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
        let fiber_status = self
            .fibers
            .get(&object_id)
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

        // When the fiber terminated, return its return value; when suspended, return transfer_value.
        let value = self
            .fibers
            .get(&object_id)
            .map(|f| {
                if f.status == FiberStatus::Terminated {
                    f.return_value.clone().unwrap_or(Value::Null)
                } else {
                    f.transfer_value.clone()
                }
            })
            .unwrap_or(Value::Null);

        Ok(Some(value))
    }

    /// Resume a suspended fiber.
    pub(crate) fn fiber_resume(&mut self, object_id: u64, value: Value) -> VmResult<Option<Value>> {
        use crate::value::*;

        let status = self
            .fibers
            .get(&object_id)
            .map(|f| f.status)
            .unwrap_or(FiberStatus::Terminated);

        if status != FiberStatus::Suspended {
            return Err(VmError::FatalError(
                "Cannot resume a fiber that is not suspended".to_string(),
            ));
        }

        // Restore saved frames
        let saved_frames = self
            .fibers
            .get_mut(&object_id)
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
            fiber.transfer_value = value.clone();
            fiber.start_depth = start_depth;
        }

        self.current_fiber_id = Some(object_id);

        // Write the resume value to the Fiber::suspend() result slot.
        // The topmost frame's IP was saved past the DO_FCALL, so ip-1 is the DO_FCALL op.
        if let Some(top_frame) = self.call_stack.last() {
            let oa_idx = top_frame.op_array_idx;
            let prev_ip = top_frame.ip.wrapping_sub(1);
            if prev_ip < self.op_arrays[oa_idx].opcodes.len() {
                let prev_op = self.op_arrays[oa_idx].opcodes[prev_ip].clone();
                if prev_op.result_type != OperandType::Unused {
                    self.write_result(&prev_op, oa_idx, value)?;
                }
            }
        }

        // Run until fiber suspends or completes
        let result = self.dispatch_loop_until(start_depth);

        let fiber_status = self
            .fibers
            .get(&object_id)
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

        // When the fiber terminated, return its return value; when suspended, return transfer_value.
        let value = self
            .fibers
            .get(&object_id)
            .map(|f| {
                if f.status == FiberStatus::Terminated {
                    f.return_value.clone().unwrap_or(Value::Null)
                } else {
                    f.transfer_value.clone()
                }
            })
            .unwrap_or(Value::Null);

        Ok(Some(value))
    }

    /// Fiber::suspend() — save current fiber's frames and break execution.
    pub(crate) fn fiber_suspend(&mut self, value: Value) -> VmResult<Value> {
        use crate::value::*;

        let fiber_id = self.current_fiber_id.ok_or_else(|| {
            VmError::FatalError("Cannot call Fiber::suspend() outside of a fiber".to_string())
        })?;

        let start_depth = self
            .fibers
            .get(&fiber_id)
            .map(|f| f.start_depth)
            .unwrap_or(0);

        // Drain frames from start_depth to current top
        let mut saved_frames = Vec::new();
        while self.call_stack.len() > start_depth {
            let frame = self.call_stack.pop().unwrap();
            saved_frames.push(FiberFrame {
                op_array_idx: frame.op_array_idx,
                ip: frame.ip + 1, // resume after the DO_FCALL that called suspend
                cvs: frame.cvs,
                temps: frame.temps,
                args: frame.args,
                return_value: frame.return_value,
                return_dest: frame.return_dest,
                this_write_back: frame.this_write_back,
                is_constructor: frame.is_constructor,
            });
        }
        saved_frames.reverse(); // Maintain original order

        if let Some(fiber) = self.fibers.get_mut(&fiber_id) {
            fiber.saved_frames = saved_frames;
            fiber.status = FiberStatus::Suspended;
            fiber.transfer_value = value;
        }

        self.current_fiber_id = None;
        Ok(Value::Null)
    }
}
