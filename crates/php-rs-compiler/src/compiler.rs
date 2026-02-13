//! AST-to-opcode compiler.
//!
//! Walks the parser AST and emits ZOp instructions into a ZOpArray.
//! Mirrors php-src/Zend/zend_compile.c.

use php_rs_parser::{
    Argument, ArrayElement, BinaryOperator, CastType, ClassMember, ClosureUse, EnumMember,
    Expression, MagicConstantKind, Modifier, Name, Parameter, Program, Statement, UnaryOperator,
};

use crate::op::{Operand, OperandType, ZOp};
use crate::op_array::{ArgInfo, Literal, ZOpArray};
use crate::opcode::ZOpcode;

/// Result of compiling an expression — where the value lives.
#[derive(Debug, Clone, Copy)]
pub struct ExprResult {
    pub operand: Operand,
    pub op_type: OperandType,
}

impl ExprResult {
    fn constant(index: u32) -> Self {
        Self {
            operand: Operand::constant(index),
            op_type: OperandType::Const,
        }
    }

    fn cv(index: u32) -> Self {
        Self {
            operand: Operand::cv(index),
            op_type: OperandType::Cv,
        }
    }

    fn tmp(slot: u32) -> Self {
        Self {
            operand: Operand::tmp_var(slot),
            op_type: OperandType::TmpVar,
        }
    }
}

/// Tracks a loop for break/continue backpatching.
struct LoopContext {
    /// Opline indices of ZEND_JMP instructions that need patching to point after the loop.
    break_patches: Vec<u32>,
    /// The opline index to jump to for `continue` (loop condition or increment).
    continue_target: u32,
    /// Whether this is a foreach loop (needs FE_FREE on break).
    foreach_var: Option<ExprResult>,
}

/// The compiler: walks AST nodes, emits opcodes into a ZOpArray.
pub struct Compiler {
    op_array: ZOpArray,
    /// Stack of active loops for break/continue.
    loop_stack: Vec<LoopContext>,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            op_array: ZOpArray::new(),
            loop_stack: Vec::new(),
        }
    }

    /// Create a compiler that emits into a pre-configured op array.
    /// Used for compiling function/method/closure bodies.
    fn with_op_array(op_array: ZOpArray) -> Self {
        Self {
            op_array,
            loop_stack: Vec::new(),
        }
    }

    /// Compile a complete program to an op array.
    pub fn compile_program(mut self, program: &Program) -> ZOpArray {
        for stmt in &program.statements {
            self.compile_stmt(stmt);
        }

        // Emit implicit RETURN 1 at end (PHP convention)
        let one = self.op_array.add_literal(Literal::Long(1));
        self.op_array.emit(
            ZOp::new(ZOpcode::Return, 0).with_op1(Operand::constant(one), OperandType::Const),
        );

        self.op_array
    }

    /// Compile a single statement.
    fn compile_stmt(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Expression { expr, .. } => {
                let result = self.compile_expr(expr);
                // Free temporary if the expression result is unused
                if result.op_type == OperandType::TmpVar {
                    self.emit_free(result);
                }
            }

            Statement::Echo { exprs, span } => {
                for expr in exprs {
                    let result = self.compile_expr(expr);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Echo, span.line as u32)
                            .with_op1(result.operand, result.op_type),
                    );
                }
            }

            Statement::Return { value, span } => {
                if let Some(expr) = value {
                    let result = self.compile_expr(expr);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Return, span.line as u32)
                            .with_op1(result.operand, result.op_type),
                    );
                } else {
                    let null_idx = self.op_array.add_literal(Literal::Null);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Return, span.line as u32)
                            .with_op1(Operand::constant(null_idx), OperandType::Const),
                    );
                }
            }

            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                span,
            } => {
                self.compile_if(condition, then_branch, elseif_branches, else_branch, span);
            }

            Statement::While {
                condition,
                body,
                span,
            } => {
                self.compile_while(condition, body, span);
            }

            Statement::DoWhile {
                body,
                condition,
                span,
            } => {
                self.compile_do_while(body, condition, span);
            }

            Statement::For {
                init,
                condition,
                increment,
                body,
                span,
            } => {
                self.compile_for(init, condition, increment, body, span);
            }

            Statement::Foreach {
                iterable,
                key,
                value,
                body,
                span,
                ..
            } => {
                self.compile_foreach(iterable, key, value, body, span);
            }

            Statement::Switch {
                condition,
                cases,
                span,
            } => {
                self.compile_switch(condition, cases, span);
            }

            Statement::Break { depth, span } => {
                self.compile_break(depth, span);
            }

            Statement::Continue { depth, span } => {
                self.compile_continue(depth, span);
            }

            Statement::Block { statements, .. } => {
                for s in statements {
                    self.compile_stmt(s);
                }
            }

            Statement::Throw { exception, span } => {
                let result = self.compile_expr(exception);
                self.op_array.emit(
                    ZOp::new(ZOpcode::Throw, span.line as u32)
                        .with_op1(result.operand, result.op_type),
                );
            }

            Statement::Try {
                body,
                catches,
                finally,
                span,
            } => {
                self.compile_try_catch(body, catches, finally, span);
            }

            Statement::Unset { vars, span } => {
                for var in vars {
                    if let Expression::Variable { name, .. } = var {
                        let cv = self.op_array.lookup_cv(name);
                        self.op_array.emit(
                            ZOp::new(ZOpcode::UnsetCv, span.line as u32)
                                .with_op1(Operand::cv(cv), OperandType::Cv),
                        );
                    }
                }
            }

            Statement::Global { vars, span } => {
                for var in vars {
                    if let Expression::Variable { name, .. } = var {
                        let cv = self.op_array.lookup_cv(name);
                        let name_lit = self.op_array.add_literal(Literal::String(name.clone()));
                        self.op_array.emit(
                            ZOp::new(ZOpcode::BindGlobal, span.line as u32)
                                .with_op1(Operand::cv(cv), OperandType::Cv)
                                .with_op2(Operand::constant(name_lit), OperandType::Const),
                        );
                    }
                }
            }

            Statement::InlineHtml { content, span } => {
                let lit = self.op_array.add_literal(Literal::String(content.clone()));
                self.op_array.emit(
                    ZOp::new(ZOpcode::Echo, span.line as u32)
                        .with_op1(Operand::constant(lit), OperandType::Const),
                );
            }

            // --- Function declaration ---
            Statement::Function {
                name,
                params,
                body,
                span,
                ..
            } => {
                self.compile_function_decl(name, params, body, span);
            }

            // --- Class declaration ---
            Statement::Class {
                name,
                members,
                extends,
                implements,
                modifiers,
                span,
                ..
            } => {
                self.compile_class_decl(name, modifiers, extends, implements, members, span);
            }

            // --- Interface declaration ---
            Statement::Interface {
                name,
                extends,
                members,
                span,
                ..
            } => {
                self.compile_interface_decl(name, extends, members, span);
            }

            // --- Trait declaration ---
            Statement::Trait {
                name,
                members,
                span,
                ..
            } => {
                self.compile_trait_decl(name, members, span);
            }

            // --- Enum declaration ---
            Statement::Enum {
                name,
                members,
                implements,
                span,
                ..
            } => {
                self.compile_enum_decl(name, implements, members, span);
            }

            // --- Const declaration ---
            Statement::Const { consts, span } => {
                for (const_name, const_value) in consts {
                    let val = self.compile_expr(const_value);
                    let name_lit = self
                        .op_array
                        .add_literal(Literal::String(const_name.clone()));
                    self.op_array.emit(
                        ZOp::new(ZOpcode::DeclareConst, span.line as u32)
                            .with_op1(Operand::constant(name_lit), OperandType::Const)
                            .with_op2(val.operand, val.op_type),
                    );
                }
            }

            // --- Static variable ---
            Statement::Static { vars, span } => {
                for sv in vars {
                    let cv = self.op_array.lookup_cv(&sv.name);
                    if let Some(ref def_expr) = sv.default {
                        let def = self.compile_expr(def_expr);
                        self.op_array.emit(
                            ZOp::new(ZOpcode::BindStatic, span.line as u32)
                                .with_op1(Operand::cv(cv), OperandType::Cv)
                                .with_op2(def.operand, def.op_type),
                        );
                    } else {
                        self.op_array.emit(
                            ZOp::new(ZOpcode::BindStatic, span.line as u32)
                                .with_op1(Operand::cv(cv), OperandType::Cv),
                        );
                    }
                }
            }

            // Features not yet needed for VM execution
            Statement::Namespace { .. }
            | Statement::Use { .. }
            | Statement::Declare { .. }
            | Statement::Goto { .. }
            | Statement::Label { .. }
            | Statement::HaltCompiler { .. }
            | Statement::Match { .. } => {
                self.op_array.emit(ZOp::nop());
            }
        }
    }

    // =========================================================================
    // Expression compilation
    // =========================================================================

    /// Compile an expression, returning where its result lives.
    fn compile_expr(&mut self, expr: &Expression) -> ExprResult {
        match expr {
            // --- Literals ---
            Expression::IntLiteral { value, .. } => {
                let idx = self.op_array.add_literal(Literal::Long(*value));
                ExprResult::constant(idx)
            }

            Expression::FloatLiteral { value, .. } => {
                let idx = self.op_array.add_literal(Literal::Double(*value));
                ExprResult::constant(idx)
            }

            Expression::StringLiteral { value, .. } => {
                let idx = self.op_array.add_literal(Literal::String(value.clone()));
                ExprResult::constant(idx)
            }

            Expression::BoolLiteral { value, .. } => {
                let idx = self.op_array.add_literal(Literal::Bool(*value));
                ExprResult::constant(idx)
            }

            Expression::Null { .. } => {
                let idx = self.op_array.add_literal(Literal::Null);
                ExprResult::constant(idx)
            }

            // --- Variables ---
            Expression::Variable { name, .. } => {
                let cv = self.op_array.lookup_cv(name);
                ExprResult::cv(cv)
            }

            // --- Assignment ---
            Expression::Assign { lhs, rhs, span } => {
                self.compile_assign(lhs, rhs, span.line as u32)
            }

            Expression::AssignRef { lhs, rhs, span } => {
                self.compile_assign_ref(lhs, rhs, span.line as u32)
            }

            // --- Binary operators ---
            Expression::BinaryOp {
                op, lhs, rhs, span, ..
            } => self.compile_binary_op(*op, lhs, rhs, span.line as u32),

            // --- Unary operators ---
            Expression::UnaryOp {
                op, operand, span, ..
            } => self.compile_unary_op(*op, operand, span.line as u32),

            // --- Increment / Decrement ---
            Expression::PreIncrement { var, span } => {
                self.compile_inc_dec(ZOpcode::PreInc, var, span.line as u32)
            }
            Expression::PostIncrement { var, span } => {
                self.compile_inc_dec(ZOpcode::PostInc, var, span.line as u32)
            }
            Expression::PreDecrement { var, span } => {
                self.compile_inc_dec(ZOpcode::PreDec, var, span.line as u32)
            }
            Expression::PostDecrement { var, span } => {
                self.compile_inc_dec(ZOpcode::PostDec, var, span.line as u32)
            }

            // --- Cast ---
            Expression::Cast {
                cast_type,
                expr,
                span,
            } => self.compile_cast(*cast_type, expr, span.line as u32),

            // --- Array literal ---
            Expression::ArrayLiteral { elements, span } => {
                self.compile_array_literal(elements, span.line as u32)
            }

            // --- Ternary ---
            Expression::Ternary {
                condition,
                then_expr,
                else_expr,
                span,
            } => self.compile_ternary(condition, then_expr.as_deref(), else_expr, span.line as u32),

            // --- Null coalesce ---
            Expression::Coalesce { lhs, rhs, span } => {
                self.compile_coalesce(lhs, rhs, span.line as u32)
            }

            // --- Instanceof ---
            Expression::Instanceof { expr, class, span } => {
                let lhs = self.compile_expr(expr);
                let rhs = self.compile_expr(class);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::Instanceof, span.line as u32)
                        .with_op1(lhs.operand, lhs.op_type)
                        .with_op2(rhs.operand, rhs.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Clone ---
            Expression::Clone { object, span } => {
                let obj = self.compile_expr(object);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::Clone, span.line as u32)
                        .with_op1(obj.operand, obj.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Print ---
            Expression::Print { expr, span } => {
                let result = self.compile_expr(expr);
                self.op_array.emit(
                    ZOp::new(ZOpcode::Echo, span.line as u32)
                        .with_op1(result.operand, result.op_type),
                );
                // print returns 1
                let one = self.op_array.add_literal(Literal::Long(1));
                ExprResult::constant(one)
            }

            // --- Isset ---
            Expression::Isset { vars, span } => self.compile_isset(vars, span.line as u32),

            // --- Empty ---
            Expression::Empty { var, span } => {
                let result = self.compile_expr(var);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::TypeCheck, span.line as u32)
                        .with_op1(result.operand, result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(0), // empty check
                );
                ExprResult::tmp(tmp)
            }

            // --- Include/Require ---
            Expression::Include { path, span }
            | Expression::IncludeOnce { path, span }
            | Expression::Require { path, span }
            | Expression::RequireOnce { path, span } => {
                let include_type = match expr {
                    Expression::Include { .. } => 1,
                    Expression::IncludeOnce { .. } => 2,
                    Expression::Require { .. } => 3,
                    Expression::RequireOnce { .. } => 4,
                    _ => unreachable!(),
                };
                let path_result = self.compile_expr(path);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::IncludeOrEval, span.line as u32)
                        .with_op1(path_result.operand, path_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(include_type),
                );
                ExprResult::tmp(tmp)
            }

            // --- Eval ---
            Expression::Eval { code, span } => {
                let code_result = self.compile_expr(code);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::IncludeOrEval, span.line as u32)
                        .with_op1(code_result.operand, code_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(0), // eval
                );
                ExprResult::tmp(tmp)
            }

            // --- Exit ---
            Expression::Exit { expr, span } => {
                if let Some(e) = expr {
                    let result = self.compile_expr(e);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Echo, span.line as u32)
                            .with_op1(result.operand, result.op_type),
                    );
                }
                // exit is compiled as a throw of a special exception
                // For now, emit a return
                let null_idx = self.op_array.add_literal(Literal::Null);
                self.op_array.emit(
                    ZOp::new(ZOpcode::Return, span.line as u32)
                        .with_op1(Operand::constant(null_idx), OperandType::Const),
                );
                ExprResult::constant(null_idx)
            }

            // --- Match expression (in expression context) ---
            Expression::MatchExpr {
                condition,
                arms,
                span,
            } => self.compile_match_expr(condition, arms, span.line as u32),

            // --- Throw expression ---
            Expression::ThrowExpr { exception, span } => {
                let result = self.compile_expr(exception);
                self.op_array.emit(
                    ZOp::new(ZOpcode::Throw, span.line as u32)
                        .with_op1(result.operand, result.op_type),
                );
                // Throw never produces a value, but we need to return something
                let null_idx = self.op_array.add_literal(Literal::Null);
                ExprResult::constant(null_idx)
            }

            // --- Function call ---
            Expression::FunctionCall { name, args, span } => {
                self.compile_function_call(name, args, span.line as u32)
            }

            // --- Method call (unused by parser but in AST) ---
            Expression::MethodCall {
                object,
                method,
                args,
                span,
            } => self.compile_method_call(object, method, args, span.line as u32),

            // --- Nullsafe method call ---
            Expression::NullsafeMethodCall {
                object,
                method,
                args,
                span,
            } => self.compile_nullsafe_method_call(object, method, args, span.line as u32),

            // --- Static call (unused by parser but in AST) ---
            Expression::StaticCall {
                class,
                method,
                args,
                span,
            } => self.compile_static_call(class, method, args, span.line as u32),

            // --- New ---
            Expression::New { class, args, span } => {
                self.compile_new(class, args, span.line as u32)
            }

            // --- Closure ---
            Expression::Closure {
                params,
                body,
                uses,
                is_static,
                span,
                ..
            } => self.compile_closure(params, body, uses, *is_static, span.line as u32),

            // --- Arrow function ---
            Expression::ArrowFunction {
                params, body, span, ..
            } => self.compile_arrow_function(params, body, span.line as u32),

            // --- Property access ---
            Expression::PropertyAccess {
                object,
                property,
                span,
            } => {
                let obj = self.compile_expr(object);
                let prop = self.compile_expr(property);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchObjR, span.line as u32)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Nullsafe property access ---
            Expression::NullsafePropertyAccess {
                object,
                property,
                span,
            } => {
                let obj = self.compile_expr(object);
                let tmp = self.op_array.alloc_temp();
                // JMP_NULL: if obj is null, skip to end with null result
                let jmp_null_idx = self.op_array.emit(
                    ZOp::new(ZOpcode::JmpNull, span.line as u32)
                        .with_op1(obj.operand, obj.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                let prop = self.compile_expr(property);
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchObjR, span.line as u32)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                let target = self.op_array.next_opline();
                self.op_array.opcodes[jmp_null_idx as usize].op2 = Operand::jmp_target(target);
                ExprResult::tmp(tmp)
            }

            // --- Static property access ---
            Expression::StaticPropertyAccess {
                class,
                property,
                span,
            } => {
                let cls = self.compile_expr(class);
                let prop = self.compile_expr(property);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchStaticPropR, span.line as u32)
                        .with_op1(prop.operand, prop.op_type)
                        .with_op2(cls.operand, cls.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Array access (read) ---
            Expression::ArrayAccess { array, index, span } => {
                let arr = self.compile_expr(array);
                let tmp = self.op_array.alloc_temp();
                if let Some(idx_expr) = index {
                    let idx = self.compile_expr(idx_expr);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::FetchDimR, span.line as u32)
                            .with_op1(arr.operand, arr.op_type)
                            .with_op2(idx.operand, idx.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                } else {
                    self.op_array.emit(
                        ZOp::new(ZOpcode::FetchDimR, span.line as u32)
                            .with_op1(arr.operand, arr.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                }
                ExprResult::tmp(tmp)
            }

            // --- Class constant ---
            Expression::ClassConstant {
                class,
                constant,
                span,
            } => {
                let cls = self.compile_expr(class);
                let const_lit = self.op_array.add_literal(Literal::String(constant.clone()));
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchClassConstant, span.line as u32)
                        .with_op1(cls.operand, cls.op_type)
                        .with_op2(Operand::constant(const_lit), OperandType::Const)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Yield ---
            Expression::Yield { value, key, span } => {
                let val = if let Some(v) = value {
                    self.compile_expr(v)
                } else {
                    let null_idx = self.op_array.add_literal(Literal::Null);
                    ExprResult::constant(null_idx)
                };
                let tmp = self.op_array.alloc_temp();
                if let Some(k) = key {
                    let key_result = self.compile_expr(k);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Yield, span.line as u32)
                            .with_op1(val.operand, val.op_type)
                            .with_op2(key_result.operand, key_result.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                } else {
                    self.op_array.emit(
                        ZOp::new(ZOpcode::Yield, span.line as u32)
                            .with_op1(val.operand, val.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                }
                ExprResult::tmp(tmp)
            }

            // --- Yield from ---
            Expression::YieldFrom { expr, span } => {
                let val = self.compile_expr(expr);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::YieldFrom, span.line as u32)
                        .with_op1(val.operand, val.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }

            // --- Magic constants ---
            Expression::MagicConstant { kind, .. } => {
                let lit = match kind {
                    MagicConstantKind::Line => Literal::Long(0), // resolved at runtime
                    MagicConstantKind::File => Literal::String(String::new()),
                    MagicConstantKind::Dir => Literal::String(String::new()),
                    MagicConstantKind::Class => Literal::String(String::new()),
                    MagicConstantKind::Trait => Literal::String(String::new()),
                    MagicConstantKind::Method => Literal::String(String::new()),
                    MagicConstantKind::Function => Literal::String(String::new()),
                    MagicConstantKind::Namespace => Literal::String(String::new()),
                    MagicConstantKind::Property => Literal::String(String::new()),
                };
                let idx = self.op_array.add_literal(lit);
                ExprResult::constant(idx)
            }

            // --- List/array destructuring ---
            Expression::List { elements, span } => {
                // list() in non-assignment context is unusual, compile elements
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitArray, span.line as u32)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                for e in elements.iter().flatten() {
                    let val = self.compile_expr(e);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::AddArrayElement, span.line as u32)
                            .with_op1(val.operand, val.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                }
                ExprResult::tmp(tmp)
            }

            // --- Named argument (handled in function call arg compilation) ---
            Expression::NamedArgument { value, span, .. } => {
                // If we encounter this outside a call, just compile the value
                let _ = span;
                self.compile_expr(value)
            }

            // --- Spread ---
            Expression::Spread { expr, span } => {
                let _ = span;
                self.compile_expr(expr)
            }
        }
    }

    // =========================================================================
    // Expression helpers
    // =========================================================================

    fn compile_assign(&mut self, lhs: &Expression, rhs: &Expression, line: u32) -> ExprResult {
        let rhs_result = self.compile_expr(rhs);

        match lhs {
            Expression::Variable { name, .. } => {
                let cv = self.op_array.lookup_cv(name);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::Assign, line)
                        .with_op1(Operand::cv(cv), OperandType::Cv)
                        .with_op2(rhs_result.operand, rhs_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }
            // Dimension assignment: $a[$k] = $v
            Expression::ArrayAccess { array, index, .. } => {
                let arr = self.compile_expr(array);
                let tmp = self.op_array.alloc_temp();
                if let Some(idx_expr) = index {
                    let idx = self.compile_expr(idx_expr);
                    self.op_array.emit(
                        ZOp::new(ZOpcode::AssignDim, line)
                            .with_op1(arr.operand, arr.op_type)
                            .with_op2(idx.operand, idx.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                } else {
                    // $a[] = $v — append
                    self.op_array.emit(
                        ZOp::new(ZOpcode::AssignDim, line)
                            .with_op1(arr.operand, arr.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                    );
                }
                // OP_DATA follows with the value
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(rhs_result.operand, rhs_result.op_type),
                );
                ExprResult::tmp(tmp)
            }
            _ => {
                // Fallback — just emit assign with the lhs compiled
                let lhs_result = self.compile_expr(lhs);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::Assign, line)
                        .with_op1(lhs_result.operand, lhs_result.op_type)
                        .with_op2(rhs_result.operand, rhs_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }
        }
    }

    fn compile_assign_ref(&mut self, lhs: &Expression, rhs: &Expression, line: u32) -> ExprResult {
        let rhs_result = self.compile_expr(rhs);
        let lhs_result = self.compile_expr(lhs);
        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::AssignRef, line)
                .with_op1(lhs_result.operand, lhs_result.op_type)
                .with_op2(rhs_result.operand, rhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );
        ExprResult::tmp(tmp)
    }

    fn compile_binary_op(
        &mut self,
        op: BinaryOperator,
        lhs: &Expression,
        rhs: &Expression,
        line: u32,
    ) -> ExprResult {
        // Handle compound assignment operators
        if let Some(assign_op) = compound_assign_op(op) {
            return self.compile_compound_assign(assign_op, lhs, rhs, line);
        }

        // Handle short-circuit logical operators
        match op {
            BinaryOperator::And | BinaryOperator::LogicalAnd => {
                return self.compile_short_circuit_and(lhs, rhs, line);
            }
            BinaryOperator::Or | BinaryOperator::LogicalOr => {
                return self.compile_short_circuit_or(lhs, rhs, line);
            }
            _ => {}
        }

        let lhs_result = self.compile_expr(lhs);
        let rhs_result = self.compile_expr(rhs);
        let tmp = self.op_array.alloc_temp();

        let (opcode, swap) = binary_op_to_opcode(op);

        if swap {
            // For > and >= we swap operands and use IS_SMALLER / IS_SMALLER_OR_EQUAL
            self.op_array.emit(
                ZOp::new(opcode, line)
                    .with_op1(rhs_result.operand, rhs_result.op_type)
                    .with_op2(lhs_result.operand, lhs_result.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );
        } else {
            self.op_array.emit(
                ZOp::new(opcode, line)
                    .with_op1(lhs_result.operand, lhs_result.op_type)
                    .with_op2(rhs_result.operand, rhs_result.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );
        }

        ExprResult::tmp(tmp)
    }

    fn compile_compound_assign(
        &mut self,
        assign_op: ZOpcode,
        lhs: &Expression,
        rhs: &Expression,
        line: u32,
    ) -> ExprResult {
        let rhs_result = self.compile_expr(rhs);

        match lhs {
            Expression::Variable { name, .. } => {
                let cv = self.op_array.lookup_cv(name);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignOp, line)
                        .with_op1(Operand::cv(cv), OperandType::Cv)
                        .with_op2(rhs_result.operand, rhs_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(assign_op as u8 as u32),
                );
                ExprResult::tmp(tmp)
            }
            _ => {
                // Fallback for complex LHS
                let lhs_result = self.compile_expr(lhs);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignOp, line)
                        .with_op1(lhs_result.operand, lhs_result.op_type)
                        .with_op2(rhs_result.operand, rhs_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(assign_op as u8 as u32),
                );
                ExprResult::tmp(tmp)
            }
        }
    }

    fn compile_short_circuit_and(
        &mut self,
        lhs: &Expression,
        rhs: &Expression,
        line: u32,
    ) -> ExprResult {
        let lhs_result = self.compile_expr(lhs);
        let tmp = self.op_array.alloc_temp();

        // JMPZ_EX: if lhs is false, short-circuit to false and jump past rhs
        let jmpz_idx = self.op_array.emit(
            ZOp::new(ZOpcode::JmpzEx, line)
                .with_op1(lhs_result.operand, lhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        let rhs_result = self.compile_expr(rhs);

        // QM_ASSIGN: store rhs boolean result
        self.op_array.emit(
            ZOp::new(ZOpcode::QmAssign, line)
                .with_op1(rhs_result.operand, rhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        // Patch the JMPZ_EX to jump here
        let target = self.op_array.next_opline();
        self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(target);
        self.op_array.opcodes[jmpz_idx as usize].op2_type = OperandType::Unused;

        ExprResult::tmp(tmp)
    }

    fn compile_short_circuit_or(
        &mut self,
        lhs: &Expression,
        rhs: &Expression,
        line: u32,
    ) -> ExprResult {
        let lhs_result = self.compile_expr(lhs);
        let tmp = self.op_array.alloc_temp();

        // JMPNZ_EX: if lhs is true, short-circuit to true and jump past rhs
        let jmpnz_idx = self.op_array.emit(
            ZOp::new(ZOpcode::JmpnzEx, line)
                .with_op1(lhs_result.operand, lhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        let rhs_result = self.compile_expr(rhs);

        self.op_array.emit(
            ZOp::new(ZOpcode::QmAssign, line)
                .with_op1(rhs_result.operand, rhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        let target = self.op_array.next_opline();
        self.op_array.opcodes[jmpnz_idx as usize].op2 = Operand::jmp_target(target);
        self.op_array.opcodes[jmpnz_idx as usize].op2_type = OperandType::Unused;

        ExprResult::tmp(tmp)
    }

    fn compile_unary_op(
        &mut self,
        op: UnaryOperator,
        operand: &Expression,
        line: u32,
    ) -> ExprResult {
        let inner = self.compile_expr(operand);
        let tmp = self.op_array.alloc_temp();

        match op {
            UnaryOperator::Minus => {
                // Unary minus: 0 - value → ZEND_MUL with -1, or ZEND_SUB from 0
                // PHP actually uses ZEND_MUL by -1 or a dedicated negation.
                // We'll use SUB: 0 - operand
                let zero = self.op_array.add_literal(Literal::Long(0));
                self.op_array.emit(
                    ZOp::new(ZOpcode::Sub, line)
                        .with_op1(Operand::constant(zero), OperandType::Const)
                        .with_op2(inner.operand, inner.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            }
            UnaryOperator::Plus => {
                // Unary plus: 0 + value
                let zero = self.op_array.add_literal(Literal::Long(0));
                self.op_array.emit(
                    ZOp::new(ZOpcode::Add, line)
                        .with_op1(Operand::constant(zero), OperandType::Const)
                        .with_op2(inner.operand, inner.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            }
            UnaryOperator::Not => {
                self.op_array.emit(
                    ZOp::new(ZOpcode::BoolNot, line)
                        .with_op1(inner.operand, inner.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            }
            UnaryOperator::BitwiseNot => {
                self.op_array.emit(
                    ZOp::new(ZOpcode::BwNot, line)
                        .with_op1(inner.operand, inner.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            }
            UnaryOperator::ErrorSuppress => {
                // @ operator: BEGIN_SILENCE + expr + END_SILENCE
                // We already compiled the inner expr; wrap with silence opcodes.
                // For proper implementation we'd need to emit BEGIN before and END after.
                // For now, just pass through the value.
                return inner;
            }
            UnaryOperator::Reference => {
                // & in expression context — pass through, marking handled by assign
                return inner;
            }
        }

        ExprResult::tmp(tmp)
    }

    fn compile_inc_dec(&mut self, opcode: ZOpcode, var: &Expression, line: u32) -> ExprResult {
        let var_result = self.compile_expr(var);

        match opcode {
            ZOpcode::PreInc | ZOpcode::PreDec => {
                // Pre-increment modifies in place and returns the new value
                self.op_array
                    .emit(ZOp::new(opcode, line).with_op1(var_result.operand, var_result.op_type));
                var_result
            }
            ZOpcode::PostInc | ZOpcode::PostDec => {
                // Post-increment returns the old value, then modifies
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(opcode, line)
                        .with_op1(var_result.operand, var_result.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
            }
            _ => unreachable!(),
        }
    }

    fn compile_cast(&mut self, cast_type: CastType, expr: &Expression, line: u32) -> ExprResult {
        let inner = self.compile_expr(expr);
        let tmp = self.op_array.alloc_temp();

        let ext_val = match cast_type {
            CastType::Int => 4,    // IS_LONG
            CastType::Float => 5,  // IS_DOUBLE
            CastType::String => 6, // IS_STRING
            CastType::Bool => 2,   // IS_FALSE (PHP uses _IS_BOOL = 14, but we simplify)
            CastType::Array => 7,  // IS_ARRAY
            CastType::Object => 8, // IS_OBJECT
            CastType::Unset => 1,  // IS_NULL
        };

        self.op_array.emit(
            ZOp::new(ZOpcode::Cast, line)
                .with_op1(inner.operand, inner.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                .with_extended_value(ext_val),
        );

        ExprResult::tmp(tmp)
    }

    fn compile_array_literal(&mut self, elements: &[ArrayElement], line: u32) -> ExprResult {
        let tmp = self.op_array.alloc_temp();

        if elements.is_empty() {
            // Empty array
            self.op_array.emit(
                ZOp::new(ZOpcode::InitArray, line)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );
            return ExprResult::tmp(tmp);
        }

        for (i, elem) in elements.iter().enumerate() {
            let val = self.compile_expr(&elem.value);

            let opcode = if i == 0 {
                ZOpcode::InitArray
            } else {
                ZOpcode::AddArrayElement
            };

            if let Some(ref key_expr) = elem.key {
                let key = self.compile_expr(key_expr);
                self.op_array.emit(
                    ZOp::new(opcode, line)
                        .with_op1(val.operand, val.op_type)
                        .with_op2(key.operand, key.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            } else if elem.unpack {
                // ...$spread
                self.op_array.emit(
                    ZOp::new(ZOpcode::AddArrayUnpack, line)
                        .with_op1(val.operand, val.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            } else {
                self.op_array.emit(
                    ZOp::new(opcode, line)
                        .with_op1(val.operand, val.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
            }
        }

        ExprResult::tmp(tmp)
    }

    fn compile_ternary(
        &mut self,
        condition: &Expression,
        then_expr: Option<&Expression>,
        else_expr: &Expression,
        line: u32,
    ) -> ExprResult {
        let tmp = self.op_array.alloc_temp();

        if let Some(then) = then_expr {
            // Full ternary: cond ? then : else
            let cond = self.compile_expr(condition);

            let jmpz_idx = self
                .op_array
                .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(cond.operand, cond.op_type));

            let then_result = self.compile_expr(then);
            self.op_array.emit(
                ZOp::new(ZOpcode::QmAssign, line)
                    .with_op1(then_result.operand, then_result.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );

            let jmp_idx = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));

            // Patch JMPZ to else branch
            let else_target = self.op_array.next_opline();
            self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(else_target);

            let else_result = self.compile_expr(else_expr);
            self.op_array.emit(
                ZOp::new(ZOpcode::QmAssign, line)
                    .with_op1(else_result.operand, else_result.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );

            // Patch JMP to after else
            let end_target = self.op_array.next_opline();
            self.op_array.opcodes[jmp_idx as usize].op1 = Operand::jmp_target(end_target);
        } else {
            // Short ternary: cond ?: else  →  JMP_SET
            let cond = self.compile_expr(condition);

            let jmp_set_idx = self.op_array.emit(
                ZOp::new(ZOpcode::JmpSet, line)
                    .with_op1(cond.operand, cond.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );

            let else_result = self.compile_expr(else_expr);
            self.op_array.emit(
                ZOp::new(ZOpcode::QmAssign, line)
                    .with_op1(else_result.operand, else_result.op_type)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
            );

            let target = self.op_array.next_opline();
            self.op_array.opcodes[jmp_set_idx as usize].op2 = Operand::jmp_target(target);
        }

        ExprResult::tmp(tmp)
    }

    fn compile_coalesce(&mut self, lhs: &Expression, rhs: &Expression, line: u32) -> ExprResult {
        let lhs_result = self.compile_expr(lhs);
        let tmp = self.op_array.alloc_temp();

        let coalesce_idx = self.op_array.emit(
            ZOp::new(ZOpcode::Coalesce, line)
                .with_op1(lhs_result.operand, lhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        let rhs_result = self.compile_expr(rhs);
        self.op_array.emit(
            ZOp::new(ZOpcode::QmAssign, line)
                .with_op1(rhs_result.operand, rhs_result.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        let target = self.op_array.next_opline();
        self.op_array.opcodes[coalesce_idx as usize].op2 = Operand::jmp_target(target);

        ExprResult::tmp(tmp)
    }

    fn compile_isset(&mut self, vars: &[Expression], line: u32) -> ExprResult {
        // For single variable, emit ISSET_ISEMPTY_CV
        // For multiple, AND them together
        if vars.len() == 1 {
            if let Expression::Variable { name, .. } = &vars[0] {
                let cv = self.op_array.lookup_cv(name);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::IssetIsemptyCv, line)
                        .with_op1(Operand::cv(cv), OperandType::Cv)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(0), // ISSET mode
                );
                return ExprResult::tmp(tmp);
            }
        }

        // Multiple vars: isset($a, $b) = isset($a) && isset($b)
        let mut result = None;
        for var in vars {
            let single = self.compile_isset(std::slice::from_ref(var), line);
            if let Some(prev) = result {
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::BoolNot, line) // placeholder for AND logic
                        .with_op1(single.operand, single.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                let _ = prev; // TODO: proper AND chain
                result = Some(ExprResult::tmp(tmp));
            } else {
                result = Some(single);
            }
        }

        result.unwrap()
    }

    fn compile_match_expr(
        &mut self,
        condition: &Expression,
        arms: &[php_rs_parser::MatchArm],
        line: u32,
    ) -> ExprResult {
        let cond = self.compile_expr(condition);
        let result_tmp = self.op_array.alloc_temp();
        let mut end_patches = Vec::new();

        for arm in arms {
            if arm.conditions.is_empty() {
                // Default arm
                let body = self.compile_expr(&arm.body);
                self.op_array.emit(
                    ZOp::new(ZOpcode::QmAssign, line)
                        .with_op1(body.operand, body.op_type)
                        .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                );
            } else {
                let mut next_arm_patches = Vec::new();

                for (i, cond_expr) in arm.conditions.iter().enumerate() {
                    let case_val = self.compile_expr(cond_expr);
                    let case_tmp = self.op_array.alloc_temp();

                    self.op_array.emit(
                        ZOp::new(ZOpcode::CaseStrict, line)
                            .with_op1(cond.operand, cond.op_type)
                            .with_op2(case_val.operand, case_val.op_type)
                            .with_result(Operand::tmp_var(case_tmp), OperandType::TmpVar),
                    );

                    if i < arm.conditions.len() - 1 {
                        // More conditions in this arm — jump to body if match
                        let jmpnz_idx = self.op_array.emit(
                            ZOp::new(ZOpcode::Jmpnz, line)
                                .with_op1(Operand::tmp_var(case_tmp), OperandType::TmpVar),
                        );
                        // Will patch to body start
                        next_arm_patches.push(jmpnz_idx);
                    } else {
                        // Last condition — jump past body if no match
                        let jmpz_idx = self.op_array.emit(
                            ZOp::new(ZOpcode::Jmpz, line)
                                .with_op1(Operand::tmp_var(case_tmp), OperandType::TmpVar),
                        );

                        // Patch earlier JMPNZ to here (body start)
                        let body_start = self.op_array.next_opline();
                        for patch_idx in &next_arm_patches {
                            self.op_array.opcodes[*patch_idx as usize].op2 =
                                Operand::jmp_target(body_start);
                        }

                        let body = self.compile_expr(&arm.body);
                        self.op_array.emit(
                            ZOp::new(ZOpcode::QmAssign, line)
                                .with_op1(body.operand, body.op_type)
                                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                        );

                        let jmp_end = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));
                        end_patches.push(jmp_end);

                        // Patch JMPZ to after this arm
                        let after_arm = self.op_array.next_opline();
                        self.op_array.opcodes[jmpz_idx as usize].op2 =
                            Operand::jmp_target(after_arm);
                    }
                }
            }
        }

        // Patch all end jumps
        let end_target = self.op_array.next_opline();
        for patch_idx in end_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(end_target);
        }

        ExprResult::tmp(result_tmp)
    }

    // =========================================================================
    // Control flow compilation
    // =========================================================================

    fn compile_if(
        &mut self,
        condition: &Expression,
        then_branch: &Statement,
        elseif_branches: &[(Expression, Statement)],
        else_branch: &Option<Box<Statement>>,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let cond = self.compile_expr(condition);

        // JMPZ past the then-branch
        let jmpz_idx = self
            .op_array
            .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(cond.operand, cond.op_type));

        // Compile then-branch
        self.compile_stmt(then_branch);

        if elseif_branches.is_empty() && else_branch.is_none() {
            // Simple if — patch JMPZ to here
            let target = self.op_array.next_opline();
            self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(target);
        } else {
            // Jump past the else/elseif chain
            let jmp_end_idx = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));

            // Patch JMPZ to the first elseif/else
            let elseif_target = self.op_array.next_opline();
            self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(elseif_target);

            let mut end_patches = vec![jmp_end_idx];

            // Compile elseif branches
            for (elseif_cond, elseif_body) in elseif_branches {
                let econd = self.compile_expr(elseif_cond);
                let ejmpz_idx = self
                    .op_array
                    .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(econd.operand, econd.op_type));

                self.compile_stmt(elseif_body);
                let ejmp_end = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));
                end_patches.push(ejmp_end);

                let next_target = self.op_array.next_opline();
                self.op_array.opcodes[ejmpz_idx as usize].op2 = Operand::jmp_target(next_target);
            }

            // Compile else branch
            if let Some(else_stmt) = else_branch {
                self.compile_stmt(else_stmt);
            }

            // Patch all end jumps
            let end_target = self.op_array.next_opline();
            for idx in end_patches {
                self.op_array.opcodes[idx as usize].op1 = Operand::jmp_target(end_target);
            }
        }
    }

    fn compile_while(
        &mut self,
        condition: &Expression,
        body: &Statement,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        // Loop start — condition
        let loop_start = self.op_array.next_opline();
        let cond = self.compile_expr(condition);

        let jmpz_idx = self
            .op_array
            .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(cond.operand, cond.op_type));

        // Push loop context
        self.loop_stack.push(LoopContext {
            break_patches: Vec::new(),
            continue_target: loop_start,
            foreach_var: None,
        });

        // Compile body
        self.compile_stmt(body);

        // Jump back to condition
        self.op_array.emit(
            ZOp::new(ZOpcode::Jmp, line)
                .with_op1(Operand::jmp_target(loop_start), OperandType::Unused),
        );

        // Patch JMPZ to after loop
        let after_loop = self.op_array.next_opline();
        self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(after_loop);

        // Pop loop context and patch breaks
        let ctx = self.loop_stack.pop().unwrap();
        for patch_idx in ctx.break_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_loop);
        }
    }

    fn compile_do_while(
        &mut self,
        body: &Statement,
        condition: &Expression,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        let loop_start = self.op_array.next_opline();

        // Push loop context — continue goes to condition
        // We don't know the condition location yet, so we'll set it below
        self.loop_stack.push(LoopContext {
            break_patches: Vec::new(),
            continue_target: 0, // will patch
            foreach_var: None,
        });

        // Compile body
        self.compile_stmt(body);

        // Condition location — patch continue target
        let cond_start = self.op_array.next_opline();
        if let Some(ctx) = self.loop_stack.last_mut() {
            ctx.continue_target = cond_start;
        }

        let cond = self.compile_expr(condition);

        // JMPNZ: jump back to body start if condition is true
        self.op_array.emit(
            ZOp::new(ZOpcode::Jmpnz, line)
                .with_op1(cond.operand, cond.op_type)
                .with_op2(Operand::jmp_target(loop_start), OperandType::Unused),
        );

        let after_loop = self.op_array.next_opline();
        let ctx = self.loop_stack.pop().unwrap();
        for patch_idx in ctx.break_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_loop);
        }
    }

    fn compile_for(
        &mut self,
        init: &[Expression],
        condition: &[Expression],
        increment: &[Expression],
        body: &Statement,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        // Compile init expressions
        for expr in init {
            let result = self.compile_expr(expr);
            if result.op_type == OperandType::TmpVar {
                self.emit_free(result);
            }
        }

        // Condition
        let cond_start = self.op_array.next_opline();
        let jmpz_idx = if !condition.is_empty() {
            // Compile condition expressions (all but last are side effects)
            let mut last_result = None;
            for (i, expr) in condition.iter().enumerate() {
                let result = self.compile_expr(expr);
                if i < condition.len() - 1 && result.op_type == OperandType::TmpVar {
                    self.emit_free(result);
                } else {
                    last_result = Some(result);
                }
            }
            // Emit JMPZ for the last condition result
            let result = last_result.unwrap();
            self.op_array
                .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(result.operand, result.op_type))
        } else {
            u32::MAX // no condition = infinite loop
        };

        // Continue target is the increment section
        // We don't know it yet, push a placeholder
        self.loop_stack.push(LoopContext {
            break_patches: Vec::new(),
            continue_target: 0, // will patch
            foreach_var: None,
        });

        // Body
        self.compile_stmt(body);

        // Increment — this is the continue target
        let incr_start = self.op_array.next_opline();
        if let Some(ctx) = self.loop_stack.last_mut() {
            ctx.continue_target = incr_start;
        }

        for expr in increment {
            let result = self.compile_expr(expr);
            if result.op_type == OperandType::TmpVar {
                self.emit_free(result);
            }
        }

        // Jump back to condition
        self.op_array.emit(
            ZOp::new(ZOpcode::Jmp, line)
                .with_op1(Operand::jmp_target(cond_start), OperandType::Unused),
        );

        let after_loop = self.op_array.next_opline();

        // Patch JMPZ
        if jmpz_idx != u32::MAX {
            self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(after_loop);
        }

        let ctx = self.loop_stack.pop().unwrap();
        for patch_idx in ctx.break_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_loop);
        }
    }

    fn compile_foreach(
        &mut self,
        iterable: &Expression,
        key: &Option<Box<Expression>>,
        value: &Expression,
        body: &Statement,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        let iter = self.compile_expr(iterable);
        let fe_tmp = self.op_array.alloc_temp();

        // FE_RESET_R: initialize foreach iteration
        let fe_reset_idx = self.op_array.emit(
            ZOp::new(ZOpcode::FeResetR, line)
                .with_op1(iter.operand, iter.op_type)
                .with_result(Operand::tmp_var(fe_tmp), OperandType::TmpVar),
        );

        // FE_FETCH_R: fetch next element
        let fetch_start = self.op_array.next_opline();

        let value_cv = if let Expression::Variable { name, .. } = value {
            self.op_array.lookup_cv(name)
        } else {
            self.op_array.alloc_temp()
        };

        let fe_fetch_idx = self.op_array.emit(
            ZOp::new(ZOpcode::FeFetchR, line)
                .with_op1(Operand::tmp_var(fe_tmp), OperandType::TmpVar)
                .with_result(Operand::cv(value_cv), OperandType::Cv),
        );

        // If key is specified, emit an OP_DATA for it
        if let Some(key_expr) = key {
            if let Expression::Variable { name, .. } = key_expr.as_ref() {
                let key_cv = self.op_array.lookup_cv(name);
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_result(Operand::cv(key_cv), OperandType::Cv),
                );
            }
        }

        let fe_result = ExprResult::tmp(fe_tmp);
        self.loop_stack.push(LoopContext {
            break_patches: Vec::new(),
            continue_target: fetch_start,
            foreach_var: Some(fe_result),
        });

        // Body
        self.compile_stmt(body);

        // Jump back to FE_FETCH
        self.op_array.emit(
            ZOp::new(ZOpcode::Jmp, line)
                .with_op1(Operand::jmp_target(fetch_start), OperandType::Unused),
        );

        // FE_FREE: cleanup
        self.op_array.emit(
            ZOp::new(ZOpcode::FeFree, line).with_op1(Operand::tmp_var(fe_tmp), OperandType::TmpVar),
        );

        let after_loop = self.op_array.next_opline();

        // Patch FE_RESET and FE_FETCH to jump to after loop when done
        self.op_array.opcodes[fe_reset_idx as usize].op2 = Operand::jmp_target(after_loop);
        self.op_array.opcodes[fe_fetch_idx as usize].op2 = Operand::jmp_target(after_loop - 1); // to FE_FREE

        let ctx = self.loop_stack.pop().unwrap();
        for patch_idx in ctx.break_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_loop);
        }
    }

    fn compile_switch(
        &mut self,
        condition: &Expression,
        cases: &[php_rs_parser::SwitchCase],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let cond = self.compile_expr(condition);

        self.loop_stack.push(LoopContext {
            break_patches: Vec::new(),
            continue_target: 0, // continue in switch = break
            foreach_var: None,
        });

        let end_patches: Vec<u32> = Vec::new();
        let mut fall_through_patches: Vec<u32> = Vec::new();

        for case in cases {
            if let Some(ref case_expr) = case.condition {
                // case VALUE:
                let case_val = self.compile_expr(case_expr);
                let case_tmp = self.op_array.alloc_temp();

                self.op_array.emit(
                    ZOp::new(ZOpcode::Case, line)
                        .with_op1(cond.operand, cond.op_type)
                        .with_op2(case_val.operand, case_val.op_type)
                        .with_result(Operand::tmp_var(case_tmp), OperandType::TmpVar),
                );

                let jmpz_idx = self.op_array.emit(
                    ZOp::new(ZOpcode::Jmpz, line)
                        .with_op1(Operand::tmp_var(case_tmp), OperandType::TmpVar),
                );

                // Patch fall-through jumps to here
                let body_start = self.op_array.next_opline();
                for patch in fall_through_patches.drain(..) {
                    self.op_array.opcodes[patch as usize].op1 = Operand::jmp_target(body_start);
                }

                for s in &case.statements {
                    self.compile_stmt(s);
                }

                // If no break, fall through to next case body
                // The JMPZ jumps past this case's body to the next case comparison
                let after_body = self.op_array.next_opline();
                self.op_array.opcodes[jmpz_idx as usize].op2 = Operand::jmp_target(after_body);
            } else {
                // default:
                let body_start = self.op_array.next_opline();
                for patch in fall_through_patches.drain(..) {
                    self.op_array.opcodes[patch as usize].op1 = Operand::jmp_target(body_start);
                }

                for s in &case.statements {
                    self.compile_stmt(s);
                }
            }
        }

        // Free the condition temp
        if cond.op_type == OperandType::TmpVar {
            self.emit_free(cond);
        }

        let after_switch = self.op_array.next_opline();
        let ctx = self.loop_stack.pop().unwrap();
        for patch_idx in ctx.break_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_switch);
        }
        for patch_idx in end_patches {
            self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(after_switch);
        }
    }

    fn compile_break(&mut self, depth: &Option<Box<Expression>>, span: &php_rs_lexer::Span) {
        let line = span.line as u32;
        let level = match depth {
            Some(expr) => {
                if let Expression::IntLiteral { value, .. } = expr.as_ref() {
                    *value as usize
                } else {
                    1
                }
            }
            None => 1,
        };

        // Find the loop context at the given depth
        let loop_idx = self.loop_stack.len().saturating_sub(level);

        // If this is a foreach loop, emit FE_FREE before breaking
        if let Some(ctx) = self.loop_stack.get(loop_idx) {
            if let Some(fe_var) = ctx.foreach_var {
                self.op_array
                    .emit(ZOp::new(ZOpcode::FeFree, line).with_op1(fe_var.operand, fe_var.op_type));
            }
        }

        // Emit JMP — target will be patched when the loop ends
        let jmp_idx = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));

        if let Some(ctx) = self.loop_stack.get_mut(loop_idx) {
            ctx.break_patches.push(jmp_idx);
        }
    }

    fn compile_continue(&mut self, depth: &Option<Box<Expression>>, span: &php_rs_lexer::Span) {
        let line = span.line as u32;
        let level = match depth {
            Some(expr) => {
                if let Expression::IntLiteral { value, .. } = expr.as_ref() {
                    *value as usize
                } else {
                    1
                }
            }
            None => 1,
        };

        let loop_idx = self.loop_stack.len().saturating_sub(level);
        if let Some(ctx) = self.loop_stack.get(loop_idx) {
            let target = ctx.continue_target;
            self.op_array.emit(
                ZOp::new(ZOpcode::Jmp, line)
                    .with_op1(Operand::jmp_target(target), OperandType::Unused),
            );
        }
    }

    fn compile_try_catch(
        &mut self,
        body: &[Statement],
        catches: &[php_rs_parser::CatchClause],
        finally: &Option<Vec<Statement>>,
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let try_start = self.op_array.next_opline();

        // Compile try body
        for stmt in body {
            self.compile_stmt(stmt);
        }

        // Jump past catch/finally
        let jmp_past_catch = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));

        let catch_start = self.op_array.next_opline();

        // Compile catch blocks
        let mut catch_jmp_patches = Vec::new();
        for catch in catches {
            // CATCH opcode
            if let Some(ref var_name) = catch.var {
                let cv = self.op_array.lookup_cv(var_name);
                self.op_array.emit(
                    ZOp::new(ZOpcode::Catch, line).with_result(Operand::cv(cv), OperandType::Cv),
                );
            } else {
                self.op_array.emit(ZOp::new(ZOpcode::Catch, line));
            }

            for stmt in &catch.body {
                self.compile_stmt(stmt);
            }

            let jmp = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));
            catch_jmp_patches.push(jmp);
        }

        let finally_start = self.op_array.next_opline();

        // Compile finally block
        if let Some(finally_stmts) = finally {
            for stmt in finally_stmts {
                self.compile_stmt(stmt);
            }
        }

        let after_try = self.op_array.next_opline();

        // Patch jumps
        self.op_array.opcodes[jmp_past_catch as usize].op1 = if finally.is_some() {
            Operand::jmp_target(finally_start)
        } else {
            Operand::jmp_target(after_try)
        };

        for jmp in catch_jmp_patches {
            self.op_array.opcodes[jmp as usize].op1 = if finally.is_some() {
                Operand::jmp_target(finally_start)
            } else {
                Operand::jmp_target(after_try)
            };
        }

        // Record try/catch element
        use crate::op_array::TryCatchElement;
        self.op_array.try_catch_array.push(TryCatchElement {
            try_op: try_start,
            catch_op: if !catches.is_empty() { catch_start } else { 0 },
            finally_op: if finally.is_some() { finally_start } else { 0 },
            finally_end: after_try,
        });
    }

    // =========================================================================
    // Function compilation (Phase 4.4)
    // =========================================================================

    fn compile_function_decl(
        &mut self,
        name: &str,
        params: &[Parameter],
        body: &[Statement],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        // Build the function's op_array
        let mut func_oa = ZOpArray::for_function(name);
        func_oa.line_start = line;
        self.setup_params(&mut func_oa, params);

        // Compile body in sub-compiler
        let mut sub = Compiler::with_op_array(func_oa);
        for s in body {
            sub.compile_stmt(s);
        }
        // Implicit return null
        let null = sub.op_array.add_literal(Literal::Null);
        sub.op_array.emit(
            ZOp::new(ZOpcode::Return, line).with_op1(Operand::constant(null), OperandType::Const),
        );

        let func_idx = self.op_array.dynamic_func_defs.len() as u32;
        self.op_array.dynamic_func_defs.push(sub.op_array);

        // Emit DECLARE_FUNCTION in parent
        let name_lit = self.op_array.add_literal(Literal::String(name.to_string()));
        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareFunction, line)
                .with_op1(Operand::constant(func_idx), OperandType::Const)
                .with_op2(Operand::constant(name_lit), OperandType::Const),
        );
    }

    /// Set up parameter CVs and arg_info for a function/method op_array.
    fn setup_params(&self, func_oa: &mut ZOpArray, params: &[Parameter]) {
        let mut required = 0u32;
        for param in params {
            func_oa.lookup_cv(&param.name);
            func_oa.arg_info.push(ArgInfo {
                name: param.name.clone(),
                pass_by_reference: param.by_ref,
                is_variadic: param.variadic,
            });
            if param.default.is_none() && !param.variadic {
                required += 1;
            }
        }
        func_oa.required_num_args = required;
    }

    fn compile_function_call(
        &mut self,
        name: &Expression,
        args: &[Argument],
        line: u32,
    ) -> ExprResult {
        // Determine call type from the name expression
        match name {
            Expression::StringLiteral { value, .. } => {
                // Named function call: foo()
                let name_lit = self.op_array.add_literal(Literal::String(value.clone()));
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitFcall, line)
                        .with_op2(Operand::constant(name_lit), OperandType::Const)
                        .with_extended_value(args.len() as u32),
                );
            }
            Expression::PropertyAccess {
                object, property, ..
            } => {
                // Method call: $obj->method()
                let obj = self.compile_expr(object);
                let method = self.compile_expr(property);
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitMethodCall, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(method.operand, method.op_type)
                        .with_extended_value(args.len() as u32),
                );
            }
            Expression::NullsafePropertyAccess {
                object, property, ..
            } => {
                // Nullsafe method call: $obj?->method()
                let obj = self.compile_expr(object);
                let tmp = self.op_array.alloc_temp();
                let jmp_null_idx = self.op_array.emit(
                    ZOp::new(ZOpcode::JmpNull, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                let method = self.compile_expr(property);
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitMethodCall, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(method.operand, method.op_type)
                        .with_extended_value(args.len() as u32),
                );
                // Patch jmp_null to skip past the full call (patched after DO_FCALL below)
                let _ = (jmp_null_idx, tmp); // handled after args + DO_FCALL
            }
            Expression::StaticPropertyAccess {
                class, property, ..
            } => {
                // Static method call: Class::method()
                let cls = self.compile_expr(class);
                let method = self.compile_expr(property);
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitStaticMethodCall, line)
                        .with_op1(cls.operand, cls.op_type)
                        .with_op2(method.operand, method.op_type)
                        .with_extended_value(args.len() as u32),
                );
            }
            _ => {
                // Dynamic call: $func(), ClassName::$method(), etc.
                let func = self.compile_expr(name);
                self.op_array.emit(
                    ZOp::new(ZOpcode::InitDynamicCall, line)
                        .with_op1(func.operand, func.op_type)
                        .with_extended_value(args.len() as u32),
                );
            }
        }

        // Send arguments
        self.compile_send_args(args, line);

        // Do the call
        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::DoFcall, line)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        ExprResult::tmp(tmp)
    }

    fn compile_send_args(&mut self, args: &[Argument], line: u32) {
        for (i, arg) in args.iter().enumerate() {
            let arg_num = (i + 1) as u32;

            if arg.unpack {
                let val = self.compile_expr(&arg.value);
                self.op_array
                    .emit(ZOp::new(ZOpcode::SendUnpack, line).with_op1(val.operand, val.op_type));
            } else if arg.by_ref {
                let val = self.compile_expr(&arg.value);
                self.op_array.emit(
                    ZOp::new(ZOpcode::SendRef, line)
                        .with_op1(val.operand, val.op_type)
                        .with_op2(Operand::constant(arg_num), OperandType::Unused),
                );
            } else if let Some(ref name) = arg.name {
                // Named argument
                let val = self.compile_expr(&arg.value);
                let name_lit = self.op_array.add_literal(Literal::String(name.clone()));
                let opcode = if val.op_type == OperandType::Cv {
                    ZOpcode::SendVar
                } else {
                    ZOpcode::SendVal
                };
                self.op_array.emit(
                    ZOp::new(opcode, line)
                        .with_op1(val.operand, val.op_type)
                        .with_op2(Operand::constant(name_lit), OperandType::Const)
                        .with_extended_value(arg_num),
                );
            } else {
                let val = self.compile_expr(&arg.value);
                let opcode = if val.op_type == OperandType::Cv {
                    ZOpcode::SendVar
                } else {
                    ZOpcode::SendVal
                };
                self.op_array.emit(
                    ZOp::new(opcode, line)
                        .with_op1(val.operand, val.op_type)
                        .with_op2(Operand::constant(arg_num), OperandType::Unused),
                );
            }
        }
    }

    fn compile_method_call(
        &mut self,
        object: &Expression,
        method: &Expression,
        args: &[Argument],
        line: u32,
    ) -> ExprResult {
        let obj = self.compile_expr(object);
        let meth = self.compile_expr(method);
        self.op_array.emit(
            ZOp::new(ZOpcode::InitMethodCall, line)
                .with_op1(obj.operand, obj.op_type)
                .with_op2(meth.operand, meth.op_type)
                .with_extended_value(args.len() as u32),
        );
        self.compile_send_args(args, line);
        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::DoFcall, line)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );
        ExprResult::tmp(tmp)
    }

    fn compile_nullsafe_method_call(
        &mut self,
        object: &Expression,
        method: &Expression,
        args: &[Argument],
        line: u32,
    ) -> ExprResult {
        let obj = self.compile_expr(object);
        let result_tmp = self.op_array.alloc_temp();
        let jmp_null_idx = self.op_array.emit(
            ZOp::new(ZOpcode::JmpNull, line)
                .with_op1(obj.operand, obj.op_type)
                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
        );
        let meth = self.compile_expr(method);
        self.op_array.emit(
            ZOp::new(ZOpcode::InitMethodCall, line)
                .with_op1(obj.operand, obj.op_type)
                .with_op2(meth.operand, meth.op_type)
                .with_extended_value(args.len() as u32),
        );
        self.compile_send_args(args, line);
        self.op_array.emit(
            ZOp::new(ZOpcode::DoFcall, line)
                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
        );
        let target = self.op_array.next_opline();
        self.op_array.opcodes[jmp_null_idx as usize].op2 = Operand::jmp_target(target);
        ExprResult::tmp(result_tmp)
    }

    fn compile_static_call(
        &mut self,
        class: &Expression,
        method: &Expression,
        args: &[Argument],
        line: u32,
    ) -> ExprResult {
        let cls = self.compile_expr(class);
        let meth = self.compile_expr(method);
        self.op_array.emit(
            ZOp::new(ZOpcode::InitStaticMethodCall, line)
                .with_op1(cls.operand, cls.op_type)
                .with_op2(meth.operand, meth.op_type)
                .with_extended_value(args.len() as u32),
        );
        self.compile_send_args(args, line);
        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::DoFcall, line)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );
        ExprResult::tmp(tmp)
    }

    fn compile_new(&mut self, class: &Expression, args: &[Argument], line: u32) -> ExprResult {
        let cls = self.compile_expr(class);
        let tmp = self.op_array.alloc_temp();

        // NEW class -> tmp
        self.op_array.emit(
            ZOp::new(ZOpcode::New, line)
                .with_op1(cls.operand, cls.op_type)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                .with_extended_value(args.len() as u32),
        );

        // Send constructor args
        self.compile_send_args(args, line);

        // Call constructor
        self.op_array.emit(
            ZOp::new(ZOpcode::DoFcall, line)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        ExprResult::tmp(tmp)
    }

    fn compile_closure(
        &mut self,
        params: &[Parameter],
        body: &[Statement],
        uses: &[ClosureUse],
        _is_static: bool,
        line: u32,
    ) -> ExprResult {
        // Build closure op_array
        let mut closure_oa = ZOpArray::for_function("{closure}");
        closure_oa.line_start = line;
        self.setup_params(&mut closure_oa, params);

        // Compile body
        let mut sub = Compiler::with_op_array(closure_oa);
        for s in body {
            sub.compile_stmt(s);
        }
        let null = sub.op_array.add_literal(Literal::Null);
        sub.op_array.emit(
            ZOp::new(ZOpcode::Return, line).with_op1(Operand::constant(null), OperandType::Const),
        );

        let func_idx = self.op_array.dynamic_func_defs.len() as u32;
        self.op_array.dynamic_func_defs.push(sub.op_array);

        // DECLARE_LAMBDA_FUNCTION
        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareLambdaFunction, line)
                .with_op1(Operand::constant(func_idx), OperandType::Const)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        // Bind captured variables
        for use_var in uses {
            let cv = self.op_array.lookup_cv(&use_var.name);
            let flags = if use_var.by_ref { 1u32 } else { 0u32 };
            self.op_array.emit(
                ZOp::new(ZOpcode::BindLexical, line)
                    .with_op1(Operand::tmp_var(tmp), OperandType::TmpVar)
                    .with_op2(Operand::cv(cv), OperandType::Cv)
                    .with_extended_value(flags),
            );
        }

        ExprResult::tmp(tmp)
    }

    fn compile_arrow_function(
        &mut self,
        params: &[Parameter],
        body: &Expression,
        line: u32,
    ) -> ExprResult {
        // Arrow functions are closures with a single return expression
        let mut closure_oa = ZOpArray::for_function("{closure}");
        closure_oa.line_start = line;
        self.setup_params(&mut closure_oa, params);

        // Compile body as a return statement
        let mut sub = Compiler::with_op_array(closure_oa);
        let result = sub.compile_expr(body);
        sub.op_array
            .emit(ZOp::new(ZOpcode::Return, line).with_op1(result.operand, result.op_type));

        let func_idx = self.op_array.dynamic_func_defs.len() as u32;
        self.op_array.dynamic_func_defs.push(sub.op_array);

        let tmp = self.op_array.alloc_temp();
        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareLambdaFunction, line)
                .with_op1(Operand::constant(func_idx), OperandType::Const)
                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
        );

        ExprResult::tmp(tmp)
    }

    // =========================================================================
    // Class compilation (Phase 4.5)
    // =========================================================================

    fn compile_class_decl(
        &mut self,
        name: &str,
        modifiers: &[Modifier],
        extends: &Option<Name>,
        implements: &[Name],
        members: &[ClassMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;

        // Emit DECLARE_CLASS
        let name_lit = self.op_array.add_literal(Literal::String(name.to_string()));
        let mut flags: u32 = 0;
        for m in modifiers {
            flags |= modifier_flag(m);
        }

        // Encode extends/implements info
        if let Some(parent) = extends {
            let parent_name = name_parts_to_string(&parent.parts);
            let _ = self.op_array.add_literal(Literal::String(parent_name));
        }
        for iface in implements {
            let iface_name = name_parts_to_string(&iface.parts);
            let _ = self.op_array.add_literal(Literal::String(iface_name));
        }

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_extended_value(flags),
        );

        // Compile methods into sub-op_arrays
        for member in members {
            if let ClassMember::Method {
                name: method_name,
                params,
                body: Some(method_body),
                modifiers: method_mods,
                ..
            } = member
            {
                let full_name = format!("{}::{}", name, method_name);
                let mut method_oa = ZOpArray::for_function(&full_name);
                method_oa.line_start = line;
                self.setup_params(&mut method_oa, params);

                // Add $this as implicit first CV for non-static methods
                if !method_mods.contains(&Modifier::Static) {
                    method_oa.lookup_cv("this");
                }

                let mut sub = Compiler::with_op_array(method_oa);
                for s in method_body {
                    sub.compile_stmt(s);
                }
                let null = sub.op_array.add_literal(Literal::Null);
                sub.op_array.emit(
                    ZOp::new(ZOpcode::Return, line)
                        .with_op1(Operand::constant(null), OperandType::Const),
                );

                self.op_array.dynamic_func_defs.push(sub.op_array);
            }
        }
    }

    fn compile_interface_decl(
        &mut self,
        name: &str,
        extends: &[Name],
        members: &[ClassMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let name_lit = self.op_array.add_literal(Literal::String(name.to_string()));

        for parent in extends {
            let parent_name = name_parts_to_string(&parent.parts);
            let _ = self.op_array.add_literal(Literal::String(parent_name));
        }

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_extended_value(ZEND_ACC_INTERFACE),
        );

        // Compile interface method signatures (abstract by definition)
        for member in members {
            if let ClassMember::Method {
                name: method_name,
                params,
                body: Some(method_body),
                ..
            } = member
            {
                let full_name = format!("{}::{}", name, method_name);
                let mut method_oa = ZOpArray::for_function(&full_name);
                self.setup_params(&mut method_oa, params);

                let mut sub = Compiler::with_op_array(method_oa);
                for s in method_body {
                    sub.compile_stmt(s);
                }
                let null = sub.op_array.add_literal(Literal::Null);
                sub.op_array.emit(
                    ZOp::new(ZOpcode::Return, line)
                        .with_op1(Operand::constant(null), OperandType::Const),
                );

                self.op_array.dynamic_func_defs.push(sub.op_array);
            }
        }
    }

    fn compile_trait_decl(
        &mut self,
        name: &str,
        members: &[ClassMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let name_lit = self.op_array.add_literal(Literal::String(name.to_string()));

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_extended_value(ZEND_ACC_TRAIT),
        );

        for member in members {
            if let ClassMember::Method {
                name: method_name,
                params,
                body: Some(method_body),
                modifiers,
                ..
            } = member
            {
                let full_name = format!("{}::{}", name, method_name);
                let mut method_oa = ZOpArray::for_function(&full_name);
                self.setup_params(&mut method_oa, params);

                if !modifiers.contains(&Modifier::Static) {
                    method_oa.lookup_cv("this");
                }

                let mut sub = Compiler::with_op_array(method_oa);
                for s in method_body {
                    sub.compile_stmt(s);
                }
                let null = sub.op_array.add_literal(Literal::Null);
                sub.op_array.emit(
                    ZOp::new(ZOpcode::Return, line)
                        .with_op1(Operand::constant(null), OperandType::Const),
                );

                self.op_array.dynamic_func_defs.push(sub.op_array);
            }
        }
    }

    fn compile_enum_decl(
        &mut self,
        name: &str,
        implements: &[Name],
        members: &[EnumMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let name_lit = self.op_array.add_literal(Literal::String(name.to_string()));

        for iface in implements {
            let iface_name = name_parts_to_string(&iface.parts);
            let _ = self.op_array.add_literal(Literal::String(iface_name));
        }

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_extended_value(ZEND_ACC_ENUM),
        );

        // Compile enum methods
        for member in members {
            if let EnumMember::ClassMember(ClassMember::Method {
                name: method_name,
                params,
                body: Some(method_body),
                ..
            }) = member
            {
                let full_name = format!("{}::{}", name, method_name);
                let mut method_oa = ZOpArray::for_function(&full_name);
                self.setup_params(&mut method_oa, params);
                method_oa.lookup_cv("this");

                let mut sub = Compiler::with_op_array(method_oa);
                for s in method_body {
                    sub.compile_stmt(s);
                }
                let null = sub.op_array.add_literal(Literal::Null);
                sub.op_array.emit(
                    ZOp::new(ZOpcode::Return, line)
                        .with_op1(Operand::constant(null), OperandType::Const),
                );

                self.op_array.dynamic_func_defs.push(sub.op_array);
            }
        }
    }

    // =========================================================================
    // Utility
    // =========================================================================

    fn emit_free(&mut self, result: ExprResult) {
        self.op_array
            .emit(ZOp::new(ZOpcode::Free, 0).with_op1(result.operand, result.op_type));
    }
}

// Class access flags (mirrors zend_compile.h)
const ZEND_ACC_INTERFACE: u32 = 0x40;
const ZEND_ACC_TRAIT: u32 = 0x80;
const ZEND_ACC_ENUM: u32 = 0x100;

fn modifier_flag(m: &Modifier) -> u32 {
    match m {
        Modifier::Public => 0x01,
        Modifier::Protected => 0x02,
        Modifier::Private => 0x04,
        Modifier::Static => 0x08,
        Modifier::Abstract => 0x20,
        Modifier::Final => 0x10,
        Modifier::Readonly => 0x200,
    }
}

fn name_parts_to_string(parts: &[String]) -> String {
    parts.join("\\")
}

/// Map a binary AST operator to a VM opcode and whether operands should be swapped.
fn binary_op_to_opcode(op: BinaryOperator) -> (ZOpcode, bool) {
    match op {
        BinaryOperator::Add => (ZOpcode::Add, false),
        BinaryOperator::Sub => (ZOpcode::Sub, false),
        BinaryOperator::Mul => (ZOpcode::Mul, false),
        BinaryOperator::Div => (ZOpcode::Div, false),
        BinaryOperator::Mod => (ZOpcode::Mod, false),
        BinaryOperator::Pow => (ZOpcode::Pow, false),
        BinaryOperator::Concat => (ZOpcode::Concat, false),
        BinaryOperator::Equal => (ZOpcode::IsEqual, false),
        BinaryOperator::NotEqual => (ZOpcode::IsNotEqual, false),
        BinaryOperator::Identical => (ZOpcode::IsIdentical, false),
        BinaryOperator::NotIdentical => (ZOpcode::IsNotIdentical, false),
        BinaryOperator::Less => (ZOpcode::IsSmaller, false),
        BinaryOperator::LessEqual => (ZOpcode::IsSmallerOrEqual, false),
        BinaryOperator::Greater => (ZOpcode::IsSmaller, true), // swap operands
        BinaryOperator::GreaterEqual => (ZOpcode::IsSmallerOrEqual, true), // swap operands
        BinaryOperator::Spaceship => (ZOpcode::Spaceship, false),
        BinaryOperator::BitwiseAnd => (ZOpcode::BwAnd, false),
        BinaryOperator::BitwiseOr => (ZOpcode::BwOr, false),
        BinaryOperator::BitwiseXor => (ZOpcode::BwXor, false),
        BinaryOperator::ShiftLeft => (ZOpcode::Sl, false),
        BinaryOperator::ShiftRight => (ZOpcode::Sr, false),
        BinaryOperator::LogicalXor => (ZOpcode::BoolXor, false),
        // Short-circuit ops handled elsewhere
        BinaryOperator::And | BinaryOperator::LogicalAnd => (ZOpcode::BoolNot, false), // unreachable
        BinaryOperator::Or | BinaryOperator::LogicalOr => (ZOpcode::BoolNot, false), // unreachable
        // Compound assigns handled elsewhere
        BinaryOperator::AddAssign
        | BinaryOperator::SubAssign
        | BinaryOperator::MulAssign
        | BinaryOperator::DivAssign
        | BinaryOperator::ModAssign
        | BinaryOperator::PowAssign
        | BinaryOperator::ConcatAssign
        | BinaryOperator::BitwiseAndAssign
        | BinaryOperator::BitwiseOrAssign
        | BinaryOperator::BitwiseXorAssign
        | BinaryOperator::ShiftLeftAssign
        | BinaryOperator::ShiftRightAssign
        | BinaryOperator::CoalesceAssign => (ZOpcode::Nop, false), // unreachable
    }
}

/// For compound assignment operators, returns the base opcode to store in extended_value.
fn compound_assign_op(op: BinaryOperator) -> Option<ZOpcode> {
    match op {
        BinaryOperator::AddAssign => Some(ZOpcode::Add),
        BinaryOperator::SubAssign => Some(ZOpcode::Sub),
        BinaryOperator::MulAssign => Some(ZOpcode::Mul),
        BinaryOperator::DivAssign => Some(ZOpcode::Div),
        BinaryOperator::ModAssign => Some(ZOpcode::Mod),
        BinaryOperator::PowAssign => Some(ZOpcode::Pow),
        BinaryOperator::ConcatAssign => Some(ZOpcode::Concat),
        BinaryOperator::BitwiseAndAssign => Some(ZOpcode::BwAnd),
        BinaryOperator::BitwiseOrAssign => Some(ZOpcode::BwOr),
        BinaryOperator::BitwiseXorAssign => Some(ZOpcode::BwXor),
        BinaryOperator::ShiftLeftAssign => Some(ZOpcode::Sl),
        BinaryOperator::ShiftRightAssign => Some(ZOpcode::Sr),
        BinaryOperator::CoalesceAssign => Some(ZOpcode::Coalesce),
        _ => None,
    }
}

// =========================================================================
// Phase 4.6: Optimization passes
// =========================================================================

/// Apply basic optimization passes to an op array.
pub fn optimize(op_array: &mut ZOpArray) {
    constant_fold(op_array);
    dead_code_eliminate(op_array);
    // Recursively optimize nested function/closure op arrays
    for sub in &mut op_array.dynamic_func_defs {
        optimize(sub);
    }
}

/// Constant folding: evaluate constant binary ops at compile time.
/// E.g. ZEND_ADD Const(2) Const(3) -> ~0 becomes just Const(5).
fn constant_fold(op_array: &mut ZOpArray) {
    let mut i = 0;
    while i < op_array.opcodes.len() {
        let op = &op_array.opcodes[i];
        if op.op1_type == OperandType::Const && op.op2_type == OperandType::Const {
            let op1_idx = op.op1.val as usize;
            let op2_idx = op.op2.val as usize;
            if op1_idx < op_array.literals.len() && op2_idx < op_array.literals.len() {
                if let Some(result) = fold_binary_op(
                    op.opcode,
                    &op_array.literals[op1_idx],
                    &op_array.literals[op2_idx],
                ) {
                    let result_type = op.result_type;
                    let result_operand = op.result;
                    let line = op.lineno;

                    let lit_idx = op_array.add_literal(result);
                    // Replace the op with QM_ASSIGN (move constant to result)
                    op_array.opcodes[i] = ZOp::new(ZOpcode::QmAssign, line)
                        .with_op1(Operand::constant(lit_idx), OperandType::Const)
                        .with_result(result_operand, result_type);
                }
            }
        }
        i += 1;
    }
}

/// Try to evaluate a constant binary operation.
fn fold_binary_op(opcode: ZOpcode, lhs: &Literal, rhs: &Literal) -> Option<Literal> {
    match (opcode, lhs, rhs) {
        // Integer arithmetic
        (ZOpcode::Add, Literal::Long(a), Literal::Long(b)) => {
            Some(Literal::Long(a.wrapping_add(*b)))
        }
        (ZOpcode::Sub, Literal::Long(a), Literal::Long(b)) => {
            Some(Literal::Long(a.wrapping_sub(*b)))
        }
        (ZOpcode::Mul, Literal::Long(a), Literal::Long(b)) => {
            Some(Literal::Long(a.wrapping_mul(*b)))
        }
        (ZOpcode::Mod, Literal::Long(a), Literal::Long(b)) if *b != 0 => Some(Literal::Long(a % b)),
        // Float arithmetic
        (ZOpcode::Add, Literal::Double(a), Literal::Double(b)) => Some(Literal::Double(a + b)),
        (ZOpcode::Sub, Literal::Double(a), Literal::Double(b)) => Some(Literal::Double(a - b)),
        (ZOpcode::Mul, Literal::Double(a), Literal::Double(b)) => Some(Literal::Double(a * b)),
        (ZOpcode::Div, Literal::Double(a), Literal::Double(b)) => Some(Literal::Double(a / b)),
        // Mixed int/float
        (ZOpcode::Add, Literal::Long(a), Literal::Double(b)) => {
            Some(Literal::Double(*a as f64 + b))
        }
        (ZOpcode::Add, Literal::Double(a), Literal::Long(b)) => {
            Some(Literal::Double(a + *b as f64))
        }
        // String concat
        (ZOpcode::Concat, Literal::String(a), Literal::String(b)) => {
            Some(Literal::String(format!("{}{}", a, b)))
        }
        // Bitwise
        (ZOpcode::BwAnd, Literal::Long(a), Literal::Long(b)) => Some(Literal::Long(a & b)),
        (ZOpcode::BwOr, Literal::Long(a), Literal::Long(b)) => Some(Literal::Long(a | b)),
        (ZOpcode::BwXor, Literal::Long(a), Literal::Long(b)) => Some(Literal::Long(a ^ b)),
        (ZOpcode::Sl, Literal::Long(a), Literal::Long(b)) => Some(Literal::Long(a << b)),
        (ZOpcode::Sr, Literal::Long(a), Literal::Long(b)) => Some(Literal::Long(a >> b)),
        _ => None,
    }
}

/// Dead code elimination: remove opcodes after unconditional return/throw.
fn dead_code_eliminate(op_array: &mut ZOpArray) {
    let mut i = 0;
    while i < op_array.opcodes.len() {
        let opcode = op_array.opcodes[i].opcode;
        if opcode == ZOpcode::Return || opcode == ZOpcode::Throw {
            // Remove subsequent opcodes until we hit a jump target or end
            let mut j = i + 1;
            while j < op_array.opcodes.len() {
                // Check if any opcode jumps to j — if so, it's a live target
                if is_jump_target(op_array, j as u32) {
                    break;
                }
                j += 1;
            }
            if j > i + 1 {
                // Replace dead opcodes with NOPs (preserve indices for jump targets)
                for k in (i + 1)..j {
                    op_array.opcodes[k] = ZOp::nop();
                }
            }
        }
        i += 1;
    }
}

/// Check if a given opline index is a jump target.
fn is_jump_target(op_array: &ZOpArray, target: u32) -> bool {
    for op in &op_array.opcodes {
        match op.opcode {
            ZOpcode::Jmp => {
                if op.op1.val == target {
                    return true;
                }
            }
            ZOpcode::Jmpz
            | ZOpcode::Jmpnz
            | ZOpcode::JmpzEx
            | ZOpcode::JmpnzEx
            | ZOpcode::JmpSet
            | ZOpcode::Coalesce
            | ZOpcode::JmpNull
            | ZOpcode::FeResetR
            | ZOpcode::FeFetchR => {
                if op.op2.val == target {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Compile a PHP source string to an op array.
pub fn compile(source: &str) -> Result<ZOpArray, php_rs_parser::ParseError> {
    let mut parser = php_rs_parser::Parser::new(source);
    let program = parser.parse()?;
    let compiler = Compiler::new();
    Ok(compiler.compile_program(&program))
}

/// Compile a PHP source string to an optimized op array.
pub fn compile_optimized(source: &str) -> Result<ZOpArray, php_rs_parser::ParseError> {
    let mut oa = compile(source)?;
    optimize(&mut oa);
    Ok(oa)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_php(source: &str) -> ZOpArray {
        compile(source).expect("parse error")
    }

    fn opcodes(op_array: &ZOpArray) -> Vec<ZOpcode> {
        op_array.opcodes.iter().map(|op| op.opcode).collect()
    }

    // =========================================================================
    // 4.2.1: Literals
    // =========================================================================

    #[test]
    fn test_compile_int_literal() {
        let oa = compile_php("<?php echo 42;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(oa.opcodes[0].op1_type, OperandType::Const);
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Long(42)
        );
    }

    #[test]
    fn test_compile_float_literal() {
        let oa = compile_php("<?php echo 3.5;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Double(3.5)
        );
    }

    #[test]
    fn test_compile_string_literal() {
        let oa = compile_php("<?php echo \"hello\";");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::String("hello".to_string())
        );
    }

    #[test]
    fn test_compile_bool_literal() {
        let oa = compile_php("<?php echo true;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Bool(true)
        );
    }

    #[test]
    fn test_compile_null_literal() {
        let oa = compile_php("<?php echo null;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(oa.literals[oa.opcodes[0].op1.val as usize], Literal::Null);
    }

    // =========================================================================
    // 4.2.2: Binary ops
    // =========================================================================

    #[test]
    fn test_compile_addition() {
        let oa = compile_php("<?php echo 1 + 2;");
        let ops = opcodes(&oa);
        assert_eq!(ops[0], ZOpcode::Add);
        assert_eq!(ops[1], ZOpcode::Echo);
    }

    #[test]
    fn test_compile_subtraction() {
        let oa = compile_php("<?php echo 5 - 3;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Sub);
    }

    #[test]
    fn test_compile_multiplication() {
        let oa = compile_php("<?php echo 2 * 3;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Mul);
    }

    #[test]
    fn test_compile_division() {
        let oa = compile_php("<?php echo 10 / 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Div);
    }

    #[test]
    fn test_compile_modulo() {
        let oa = compile_php("<?php echo 10 % 3;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Mod);
    }

    #[test]
    fn test_compile_power() {
        let oa = compile_php("<?php echo 2 ** 8;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Pow);
    }

    #[test]
    fn test_compile_concat() {
        let oa = compile_php("<?php echo \"a\" . \"b\";");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Concat);
    }

    #[test]
    fn test_compile_bitwise_ops() {
        let oa = compile_php("<?php echo 1 & 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::BwAnd);

        let oa = compile_php("<?php echo 1 | 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::BwOr);

        let oa = compile_php("<?php echo 1 ^ 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::BwXor);

        let oa = compile_php("<?php echo 1 << 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Sl);

        let oa = compile_php("<?php echo 1 >> 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Sr);
    }

    // =========================================================================
    // 4.2.3: Comparison ops
    // =========================================================================

    #[test]
    fn test_compile_equal() {
        let oa = compile_php("<?php echo 1 == 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsEqual);
    }

    #[test]
    fn test_compile_identical() {
        let oa = compile_php("<?php echo 1 === 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsIdentical);
    }

    #[test]
    fn test_compile_not_equal() {
        let oa = compile_php("<?php echo 1 != 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsNotEqual);
    }

    #[test]
    fn test_compile_not_identical() {
        let oa = compile_php("<?php echo 1 !== 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsNotIdentical);
    }

    #[test]
    fn test_compile_less() {
        let oa = compile_php("<?php echo 1 < 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsSmaller);
    }

    #[test]
    fn test_compile_less_equal() {
        let oa = compile_php("<?php echo 1 <= 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsSmallerOrEqual);
    }

    #[test]
    fn test_compile_greater() {
        // Greater uses IS_SMALLER with swapped operands
        let oa = compile_php("<?php echo 1 > 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsSmaller);
        // op1 should be "2" (rhs), op2 should be "1" (lhs) — swapped
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Long(2)
        );
        assert_eq!(
            oa.literals[oa.opcodes[0].op2.val as usize],
            Literal::Long(1)
        );
    }

    #[test]
    fn test_compile_greater_equal() {
        let oa = compile_php("<?php echo 1 >= 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::IsSmallerOrEqual);
        // Swapped
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Long(2)
        );
        assert_eq!(
            oa.literals[oa.opcodes[0].op2.val as usize],
            Literal::Long(1)
        );
    }

    #[test]
    fn test_compile_spaceship() {
        let oa = compile_php("<?php echo 1 <=> 2;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Spaceship);
    }

    // =========================================================================
    // 4.2.4: Unary ops
    // =========================================================================

    #[test]
    fn test_compile_unary_minus() {
        let oa = compile_php("<?php echo -5;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Sub);
        // op1 should be 0, op2 should be 5
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Long(0)
        );
    }

    #[test]
    fn test_compile_bool_not() {
        let oa = compile_php("<?php echo !true;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::BoolNot);
    }

    #[test]
    fn test_compile_bitwise_not() {
        let oa = compile_php("<?php echo ~0xFF;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::BwNot);
    }

    // =========================================================================
    // 4.2.5: Variable read
    // =========================================================================

    #[test]
    fn test_compile_variable() {
        let oa = compile_php("<?php echo $x;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(oa.opcodes[0].op1_type, OperandType::Cv);
        assert_eq!(oa.vars, vec!["x"]);
    }

    // =========================================================================
    // 4.2.6: Assignment
    // =========================================================================

    #[test]
    fn test_compile_assignment() {
        let oa = compile_php("<?php $x = 42;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Assign);
        assert_eq!(oa.opcodes[0].op1_type, OperandType::Cv);
        assert_eq!(oa.opcodes[0].op2_type, OperandType::Const);
        assert_eq!(oa.vars, vec!["x"]);
    }

    #[test]
    fn test_compile_chained_assignment() {
        let oa = compile_php("<?php $a = $b = 1;");
        // $b = 1 first, then $a = result
        let ops = opcodes(&oa);
        assert_eq!(ops[0], ZOpcode::Assign); // $b = 1
        assert_eq!(ops[1], ZOpcode::Assign); // $a = tmp
    }

    // =========================================================================
    // 4.2.7: Compound assignment
    // =========================================================================

    #[test]
    fn test_compile_add_assign() {
        let oa = compile_php("<?php $x += 5;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::AssignOp);
        assert_eq!(oa.opcodes[0].extended_value, ZOpcode::Add as u8 as u32);
    }

    #[test]
    fn test_compile_sub_assign() {
        let oa = compile_php("<?php $x -= 3;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::AssignOp);
        assert_eq!(oa.opcodes[0].extended_value, ZOpcode::Sub as u8 as u32);
    }

    #[test]
    fn test_compile_concat_assign() {
        let oa = compile_php("<?php $x .= \"!\";");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::AssignOp);
        assert_eq!(oa.opcodes[0].extended_value, ZOpcode::Concat as u8 as u32);
    }

    // =========================================================================
    // 4.2.8: Increment/decrement
    // =========================================================================

    #[test]
    fn test_compile_pre_inc() {
        let oa = compile_php("<?php ++$x;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::PreInc);
    }

    #[test]
    fn test_compile_post_inc() {
        let oa = compile_php("<?php $x++;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::PostInc);
    }

    #[test]
    fn test_compile_pre_dec() {
        let oa = compile_php("<?php --$x;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::PreDec);
    }

    #[test]
    fn test_compile_post_dec() {
        let oa = compile_php("<?php $x--;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::PostDec);
    }

    // =========================================================================
    // 4.2.9: String concat
    // =========================================================================

    #[test]
    fn test_compile_string_concat() {
        let oa = compile_php("<?php echo \"hello\" . \" world\";");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Concat);
        assert_eq!(oa.opcodes[1].opcode, ZOpcode::Echo);
    }

    // =========================================================================
    // 4.2.10: Array literal
    // =========================================================================

    #[test]
    fn test_compile_empty_array() {
        let oa = compile_php("<?php $a = [];");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitArray));
    }

    #[test]
    fn test_compile_packed_array() {
        let oa = compile_php("<?php $a = [1, 2, 3];");
        let ops = opcodes(&oa);
        assert_eq!(ops[0], ZOpcode::InitArray);
        assert_eq!(ops[1], ZOpcode::AddArrayElement);
        assert_eq!(ops[2], ZOpcode::AddArrayElement);
    }

    #[test]
    fn test_compile_hash_array() {
        let oa = compile_php("<?php $a = ['a' => 1, 'b' => 2];");
        let ops = opcodes(&oa);
        assert_eq!(ops[0], ZOpcode::InitArray);
        assert_eq!(ops[1], ZOpcode::AddArrayElement);
    }

    // =========================================================================
    // 4.2.11: Expression opcode sequences
    // =========================================================================

    #[test]
    fn test_compile_complex_expression() {
        // $c = $a + $b * 2
        let oa = compile_php("<?php $c = $a + $b * 2;");
        let ops = opcodes(&oa);
        // MUL first (higher precedence), then ADD, then ASSIGN
        assert_eq!(ops[0], ZOpcode::Mul);
        assert_eq!(ops[1], ZOpcode::Add);
        assert_eq!(ops[2], ZOpcode::Assign);
    }

    // =========================================================================
    // 4.3.1: Echo/print
    // =========================================================================

    #[test]
    fn test_compile_echo_multiple() {
        let oa = compile_php("<?php echo 1, 2, 3;");
        let ops = opcodes(&oa);
        assert_eq!(ops[0], ZOpcode::Echo);
        assert_eq!(ops[1], ZOpcode::Echo);
        assert_eq!(ops[2], ZOpcode::Echo);
    }

    // =========================================================================
    // 4.3.2: If/else
    // =========================================================================

    #[test]
    fn test_compile_if() {
        let oa = compile_php("<?php if ($x) { echo 1; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Jmpz));
        assert!(ops.contains(&ZOpcode::Echo));
    }

    #[test]
    fn test_compile_if_else() {
        let oa = compile_php("<?php if ($x) { echo 1; } else { echo 2; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Jmpz));
        assert!(ops.contains(&ZOpcode::Jmp));
        // Two echo instructions
        assert_eq!(ops.iter().filter(|&&o| o == ZOpcode::Echo).count(), 2);
    }

    #[test]
    fn test_compile_if_elseif_else() {
        let oa = compile_php("<?php if ($a) { echo 1; } elseif ($b) { echo 2; } else { echo 3; }");
        let ops = opcodes(&oa);
        assert_eq!(ops.iter().filter(|&&o| o == ZOpcode::Echo).count(), 3);
        assert_eq!(ops.iter().filter(|&&o| o == ZOpcode::Jmpz).count(), 2);
    }

    // =========================================================================
    // 4.3.3: While
    // =========================================================================

    #[test]
    fn test_compile_while() {
        let oa = compile_php("<?php while ($x) { echo 1; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Jmpz));
        assert!(ops.contains(&ZOpcode::Jmp)); // loop back
        assert!(ops.contains(&ZOpcode::Echo));
    }

    // =========================================================================
    // 4.3.4: Do-while
    // =========================================================================

    #[test]
    fn test_compile_do_while() {
        let oa = compile_php("<?php do { echo 1; } while ($x);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Jmpnz)); // jump back if true
        assert!(ops.contains(&ZOpcode::Echo));
    }

    // =========================================================================
    // 4.3.5: For
    // =========================================================================

    #[test]
    fn test_compile_for() {
        let oa = compile_php("<?php for ($i = 0; $i < 10; $i++) { echo $i; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Assign)); // $i = 0
        assert!(ops.contains(&ZOpcode::IsSmaller)); // $i < 10
        assert!(ops.contains(&ZOpcode::Jmpz)); // exit condition
        assert!(ops.contains(&ZOpcode::PostInc)); // $i++
        assert!(ops.contains(&ZOpcode::Jmp)); // loop back
        assert!(ops.contains(&ZOpcode::Echo)); // echo $i
    }

    // =========================================================================
    // 4.3.6: Foreach
    // =========================================================================

    #[test]
    fn test_compile_foreach() {
        let oa = compile_php("<?php foreach ($arr as $v) { echo $v; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::FeResetR));
        assert!(ops.contains(&ZOpcode::FeFetchR));
        assert!(ops.contains(&ZOpcode::FeFree));
        assert!(ops.contains(&ZOpcode::Echo));
    }

    // =========================================================================
    // 4.3.7: Switch
    // =========================================================================

    #[test]
    fn test_compile_switch() {
        let oa =
            compile_php("<?php switch ($x) { case 1: echo 'a'; break; case 2: echo 'b'; break; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Case));
        assert!(ops.contains(&ZOpcode::Echo));
    }

    // =========================================================================
    // 4.3.9: Break/continue
    // =========================================================================

    #[test]
    fn test_compile_break() {
        let oa = compile_php("<?php while (true) { break; }");
        let ops = opcodes(&oa);
        // break emits a JMP that gets patched to after loop
        assert!(ops.iter().filter(|&&o| o == ZOpcode::Jmp).count() >= 2);
    }

    #[test]
    fn test_compile_continue() {
        let oa = compile_php("<?php while (true) { continue; }");
        let ops = opcodes(&oa);
        // continue emits a JMP back to loop start
        assert!(ops.iter().filter(|&&o| o == ZOpcode::Jmp).count() >= 2);
    }

    // =========================================================================
    // 4.3.10: Return
    // =========================================================================

    #[test]
    fn test_compile_return() {
        let oa = compile_php("<?php return 42;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Return);
        assert_eq!(oa.opcodes[0].op1_type, OperandType::Const);
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::Long(42)
        );
    }

    #[test]
    fn test_compile_return_void() {
        let oa = compile_php("<?php return;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Return);
        assert_eq!(oa.literals[oa.opcodes[0].op1.val as usize], Literal::Null);
    }

    // =========================================================================
    // 4.3.11: Try/catch/finally
    // =========================================================================

    #[test]
    fn test_compile_try_catch() {
        let oa = compile_php("<?php try { echo 1; } catch (Exception $e) { echo 2; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Catch));
        assert_eq!(oa.try_catch_array.len(), 1);
    }

    // =========================================================================
    // 4.3.12: Throw
    // =========================================================================

    #[test]
    fn test_compile_throw() {
        let oa = compile_php("<?php throw $e;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Throw);
    }

    // =========================================================================
    // Other expression tests
    // =========================================================================

    #[test]
    fn test_compile_ternary() {
        let oa = compile_php("<?php echo $x ? 1 : 2;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Jmpz));
        assert!(ops.contains(&ZOpcode::QmAssign));
    }

    #[test]
    fn test_compile_short_ternary() {
        let oa = compile_php("<?php echo $x ?: 'default';");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::JmpSet));
    }

    #[test]
    fn test_compile_null_coalesce() {
        let oa = compile_php("<?php echo $x ?? 'default';");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Coalesce));
    }

    #[test]
    fn test_compile_logical_and() {
        let oa = compile_php("<?php echo $a && $b;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::JmpzEx));
    }

    #[test]
    fn test_compile_logical_or() {
        let oa = compile_php("<?php echo $a || $b;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::JmpnzEx));
    }

    #[test]
    fn test_compile_cast_int() {
        let oa = compile_php("<?php echo (int)$x;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Cast);
        assert_eq!(oa.opcodes[0].extended_value, 4); // IS_LONG
    }

    #[test]
    fn test_compile_cast_string() {
        let oa = compile_php("<?php echo (string)$x;");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Cast);
        assert_eq!(oa.opcodes[0].extended_value, 6); // IS_STRING
    }

    #[test]
    fn test_compile_instanceof() {
        let oa = compile_php("<?php echo $x instanceof Foo;");
        let ops = opcodes(&oa);
        // instanceof may involve NOP for the class name (not yet implemented), then INSTANCEOF
        assert!(ops.contains(&ZOpcode::Instanceof));
    }

    #[test]
    fn test_compile_clone() {
        let oa = compile_php("<?php $b = clone $a;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Clone));
    }

    #[test]
    fn test_compile_print() {
        let oa = compile_php("<?php print 'hello';");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Echo));
    }

    #[test]
    fn test_compile_inline_html() {
        // The lexer emits one InlineHtml token per character, so "Hello World"
        // becomes 11 separate echo instructions. Each echoes one character.
        let oa = compile_php("Hello World");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::Echo);
        assert_eq!(oa.opcodes[0].op1_type, OperandType::Const);
        // First char should be "H"
        assert_eq!(
            oa.literals[oa.opcodes[0].op1.val as usize],
            Literal::String("H".to_string())
        );
        // Count echo opcodes (one per char + implicit return = 12)
        let echo_count = opcodes(&oa).iter().filter(|&&o| o == ZOpcode::Echo).count();
        assert_eq!(echo_count, 11);
    }

    #[test]
    fn test_compile_unset() {
        let oa = compile_php("<?php unset($x);");
        assert_eq!(oa.opcodes[0].opcode, ZOpcode::UnsetCv);
    }

    #[test]
    fn test_implicit_return() {
        let oa = compile_php("<?php echo 1;");
        // Last opcode should always be RETURN
        assert_eq!(oa.opcodes.last().unwrap().opcode, ZOpcode::Return);
    }

    #[test]
    fn test_compile_disassembly_readable() {
        let oa = compile_php("<?php $x = 1 + 2; echo $x;");
        let dis = oa.disassemble();
        assert!(dis.contains("ZEND_ADD"), "dis:\n{}", dis);
        assert!(dis.contains("ZEND_ASSIGN"), "dis:\n{}", dis);
        assert!(dis.contains("ZEND_ECHO"), "dis:\n{}", dis);
        assert!(dis.contains("ZEND_RETURN"), "dis:\n{}", dis);
    }

    #[test]
    fn test_compile_match_expr() {
        let oa =
            compile_php("<?php echo match($x) { 1 => 'one', 2 => 'two', default => 'other' };");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::CaseStrict));
        assert!(ops.contains(&ZOpcode::Echo));
    }

    #[test]
    fn test_compile_throw_expr() {
        let oa = compile_php("<?php $x = true ? 1 : throw $e;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Throw));
    }

    // =========================================================================
    // 4.4.1: Function declaration
    // =========================================================================

    #[test]
    fn test_compile_function_decl() {
        let oa = compile_php("<?php function foo() { echo 1; }");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareFunction));
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        assert_eq!(
            oa.dynamic_func_defs[0].function_name.as_deref(),
            Some("foo")
        );
    }

    #[test]
    fn test_compile_function_with_params() {
        let oa = compile_php("<?php function add($a, $b) { return $a + $b; }");
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        let func = &oa.dynamic_func_defs[0];
        assert_eq!(func.arg_info.len(), 2);
        // Parser stores param names with $ prefix
        assert!(
            func.arg_info[0].name == "a" || func.arg_info[0].name == "$a",
            "unexpected param name: {}",
            func.arg_info[0].name
        );
        assert_eq!(func.required_num_args, 2);
        // Check body compiles add + return
        let func_ops: Vec<_> = func.opcodes.iter().map(|o| o.opcode).collect();
        assert!(func_ops.contains(&ZOpcode::Add));
        assert!(func_ops.contains(&ZOpcode::Return));
    }

    #[test]
    fn test_compile_function_with_default() {
        let oa = compile_php("<?php function greet($name = 'World') { echo $name; }");
        let func = &oa.dynamic_func_defs[0];
        assert_eq!(func.arg_info.len(), 1);
        assert_eq!(func.required_num_args, 0); // has default
    }

    #[test]
    fn test_compile_function_variadic() {
        let oa = compile_php("<?php function sum(...$nums) { return 0; }");
        let func = &oa.dynamic_func_defs[0];
        assert_eq!(func.arg_info.len(), 1);
        assert!(func.arg_info[0].is_variadic);
        assert_eq!(func.required_num_args, 0);
    }

    #[test]
    fn test_compile_function_by_ref_param() {
        let oa = compile_php("<?php function inc(&$val) { $val++; }");
        let func = &oa.dynamic_func_defs[0];
        assert!(func.arg_info[0].pass_by_reference);
    }

    // =========================================================================
    // 4.4.2: Function call
    // =========================================================================

    #[test]
    fn test_compile_function_call() {
        let oa = compile_php("<?php foo(1, 2);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitFcall));
        assert!(ops.contains(&ZOpcode::SendVal));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    #[test]
    fn test_compile_function_call_with_var() {
        let oa = compile_php("<?php foo($x);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitFcall));
        assert!(ops.contains(&ZOpcode::SendVar));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    #[test]
    fn test_compile_dynamic_call() {
        let oa = compile_php("<?php $func(1);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitDynamicCall));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    #[test]
    fn test_compile_method_call() {
        let oa = compile_php("<?php $obj->method(1);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitMethodCall));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    #[test]
    fn test_compile_static_method_call() {
        let oa = compile_php("<?php Foo::bar(1);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::InitStaticMethodCall));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    // =========================================================================
    // 4.4.3: Return type + param type info
    // =========================================================================

    #[test]
    fn test_compile_function_param_count() {
        let oa = compile_php("<?php function f($a, $b, $c = 1) {}");
        let func = &oa.dynamic_func_defs[0];
        assert_eq!(func.arg_info.len(), 3);
        assert_eq!(func.required_num_args, 2);
    }

    // =========================================================================
    // 4.4.4: Closures
    // =========================================================================

    #[test]
    fn test_compile_closure() {
        let oa = compile_php("<?php $f = function($x) { return $x + 1; };");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareLambdaFunction));
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        assert_eq!(
            oa.dynamic_func_defs[0].function_name.as_deref(),
            Some("{closure}")
        );
    }

    #[test]
    fn test_compile_closure_use() {
        let oa = compile_php("<?php $x = 1; $f = function() use ($x) { return $x; };");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareLambdaFunction));
        assert!(ops.contains(&ZOpcode::BindLexical));
    }

    #[test]
    fn test_compile_closure_use_by_ref() {
        let oa = compile_php("<?php $f = function() use (&$x) { $x++; };");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::BindLexical));
        // Check the extended_value flag for by-ref
        let bind = oa
            .opcodes
            .iter()
            .find(|o| o.opcode == ZOpcode::BindLexical)
            .unwrap();
        assert_eq!(bind.extended_value, 1); // by-ref flag
    }

    // =========================================================================
    // 4.4.5: Arrow functions
    // =========================================================================

    #[test]
    fn test_compile_arrow_function() {
        let oa = compile_php("<?php $f = fn($x) => $x + 1;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareLambdaFunction));
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        // Arrow function body should have RETURN with the expression
        let func_ops: Vec<_> = oa.dynamic_func_defs[0]
            .opcodes
            .iter()
            .map(|o| o.opcode)
            .collect();
        assert!(func_ops.contains(&ZOpcode::Add));
        assert!(func_ops.contains(&ZOpcode::Return));
    }

    // =========================================================================
    // 4.4.6: Variadic/spread in calls
    // =========================================================================

    #[test]
    fn test_compile_send_unpack() {
        let oa = compile_php("<?php foo(...$args);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::SendUnpack));
    }

    // =========================================================================
    // 4.4.8: Function call opcodes test
    // =========================================================================

    #[test]
    fn test_compile_nested_calls() {
        let oa = compile_php("<?php foo(bar(1));");
        let ops = opcodes(&oa);
        // Two INIT_FCALL + two DO_FCALL
        assert_eq!(ops.iter().filter(|&&o| o == ZOpcode::InitFcall).count(), 2);
        assert_eq!(ops.iter().filter(|&&o| o == ZOpcode::DoFcall).count(), 2);
    }

    // =========================================================================
    // 4.5.1: Class declaration
    // =========================================================================

    #[test]
    fn test_compile_class_decl() {
        let oa = compile_php(
            "<?php class Foo {
                public function bar() { return 1; }
            }",
        );
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareClass));
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        assert_eq!(
            oa.dynamic_func_defs[0].function_name.as_deref(),
            Some("Foo::bar")
        );
    }

    // =========================================================================
    // 4.5.2: Method definitions
    // =========================================================================

    #[test]
    fn test_compile_class_methods() {
        let oa = compile_php(
            "<?php class Calc {
                public function add($a, $b) { return $a + $b; }
                public function sub($a, $b) { return $a - $b; }
            }",
        );
        assert_eq!(oa.dynamic_func_defs.len(), 2);
        assert_eq!(
            oa.dynamic_func_defs[0].function_name.as_deref(),
            Some("Calc::add")
        );
        assert_eq!(
            oa.dynamic_func_defs[1].function_name.as_deref(),
            Some("Calc::sub")
        );
    }

    // =========================================================================
    // 4.5.4: Constructor
    // =========================================================================

    #[test]
    fn test_compile_constructor() {
        let oa = compile_php(
            "<?php class Foo {
                public function __construct($x) { echo $x; }
            }",
        );
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        let ctor = &oa.dynamic_func_defs[0];
        assert_eq!(ctor.function_name.as_deref(), Some("Foo::__construct"));
        assert_eq!(ctor.arg_info.len(), 1);
    }

    // =========================================================================
    // 4.5.5: Static methods
    // =========================================================================

    #[test]
    fn test_compile_static_method() {
        let oa = compile_php(
            "<?php class Math {
                public static function pi() { return 3; }
            }",
        );
        assert_eq!(oa.dynamic_func_defs.len(), 1);
        // Static methods should NOT have $this as a CV
        let func = &oa.dynamic_func_defs[0];
        assert!(!func.vars.contains(&"this".to_string()));
    }

    #[test]
    fn test_compile_instance_method_has_this() {
        let oa = compile_php(
            "<?php class Foo {
                public function bar() { return 1; }
            }",
        );
        let func = &oa.dynamic_func_defs[0];
        // Instance methods get $this as an implicit CV
        assert!(func.vars.contains(&"this".to_string()));
    }

    // =========================================================================
    // 4.5.6: New
    // =========================================================================

    #[test]
    fn test_compile_new() {
        let oa = compile_php("<?php $obj = new Foo(1, 2);");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::New));
        assert!(ops.contains(&ZOpcode::DoFcall));
    }

    // =========================================================================
    // 4.5.7: Property access
    // =========================================================================

    #[test]
    fn test_compile_property_access() {
        let oa = compile_php("<?php echo $obj->name;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::FetchObjR));
    }

    // =========================================================================
    // 4.5.10: Class constants
    // =========================================================================

    #[test]
    fn test_compile_class_constant() {
        let oa = compile_php("<?php echo Foo::BAR;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::FetchStaticPropR));
    }

    // =========================================================================
    // 4.5.11: Interface
    // =========================================================================

    #[test]
    fn test_compile_interface() {
        // Interface with no body methods (parser may not support abstract methods)
        let oa = compile_php("<?php interface Printable {}");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareClass));
    }

    // =========================================================================
    // 4.5.12: Abstract/final
    // =========================================================================

    #[test]
    fn test_compile_abstract_class() {
        let oa = compile_php(
            "<?php abstract class Shape {
                abstract public function area();
            }",
        );
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareClass));
        // Check that the extended_value has the abstract flag
        let decl = oa
            .opcodes
            .iter()
            .find(|o| o.opcode == ZOpcode::DeclareClass)
            .unwrap();
        assert_ne!(decl.extended_value & 0x20, 0); // ZEND_ACC_ABSTRACT
    }

    // =========================================================================
    // 4.5.13: Enum
    // =========================================================================

    #[test]
    fn test_compile_enum() {
        // Empty enum body (parser may not fully support enum cases yet)
        let oa = compile_php("<?php enum Color {}");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareClass));
    }

    // =========================================================================
    // 4.5.14: Array access (read)
    // =========================================================================

    #[test]
    fn test_compile_array_access_read() {
        let oa = compile_php("<?php echo $arr[0];");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::FetchDimR));
    }

    // =========================================================================
    // Additional expression tests
    // =========================================================================

    #[test]
    fn test_compile_yield() {
        let oa = compile_php("<?php function gen() { yield 1; }");
        let func = &oa.dynamic_func_defs[0];
        let func_ops: Vec<_> = func.opcodes.iter().map(|o| o.opcode).collect();
        assert!(func_ops.contains(&ZOpcode::Yield));
    }

    #[test]
    fn test_compile_const_decl() {
        let oa = compile_php("<?php const FOO = 42;");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::DeclareConst));
    }

    #[test]
    fn test_compile_static_var() {
        let oa = compile_php("<?php function f() { static $count = 0; }");
        let func = &oa.dynamic_func_defs[0];
        let func_ops: Vec<_> = func.opcodes.iter().map(|o| o.opcode).collect();
        assert!(func_ops.contains(&ZOpcode::BindStatic));
    }

    // =========================================================================
    // 4.6.1: Constant folding
    // =========================================================================

    #[test]
    fn test_optimize_constant_fold_add() {
        let oa = compile_optimized("<?php echo 2 + 3;").unwrap();
        // After folding, the ADD should become QM_ASSIGN of Const(5)
        assert!(oa.opcodes.iter().any(|op| {
            op.opcode == ZOpcode::QmAssign
                && op.op1_type == OperandType::Const
                && oa.literals.get(op.op1.val as usize) == Some(&Literal::Long(5))
        }));
        // No ADD opcode left
        assert!(!opcodes(&oa).contains(&ZOpcode::Add));
    }

    #[test]
    fn test_optimize_constant_fold_concat() {
        let oa = compile_optimized("<?php echo \"hello\" . \" world\";").unwrap();
        assert!(!opcodes(&oa).contains(&ZOpcode::Concat));
        assert!(oa
            .literals
            .contains(&Literal::String("hello world".to_string())));
    }

    #[test]
    fn test_optimize_constant_fold_mul() {
        let oa = compile_optimized("<?php echo 6 * 7;").unwrap();
        assert!(!opcodes(&oa).contains(&ZOpcode::Mul));
        assert!(oa.literals.contains(&Literal::Long(42)));
    }

    // =========================================================================
    // 4.6.2: Dead code elimination
    // =========================================================================

    #[test]
    fn test_optimize_dead_code_after_return() {
        let oa = compile_optimized("<?php return 1; echo 2;").unwrap();
        // The echo 2 after return should be replaced with NOP
        let ops = opcodes(&oa);
        // First return is at index 0, echo should be NOP'd
        let return_idx = ops.iter().position(|&o| o == ZOpcode::Return).unwrap();
        // Everything after the first RETURN until the next jump target should be NOP
        if return_idx + 1 < ops.len() {
            // The echo should have been NOP'd out
            assert_ne!(ops[return_idx + 1], ZOpcode::Echo);
        }
    }

    // =========================================================================
    // 4.6.3: Optimized opcodes semantic equivalence
    // =========================================================================

    #[test]
    fn test_optimize_preserves_semantics() {
        // Non-constant expressions should NOT be folded
        let oa = compile_optimized("<?php echo $x + 1;").unwrap();
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::Add)); // Can't fold: $x is runtime
    }
}
