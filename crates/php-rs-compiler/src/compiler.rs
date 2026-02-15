//! AST-to-opcode compiler.
//!
//! Walks the parser AST and emits ZOp instructions into a ZOpArray.
//! Mirrors php-src/Zend/zend_compile.c.

use php_rs_parser::{
    Argument, ArrayElement, BinaryOperator, CastType, ClassMember, ClosureUse, EnumMember,
    Expression, MagicConstantKind, Modifier, Name, Parameter, Program, Statement, UnaryOperator,
    UseKind,
};

use std::collections::HashMap;

use crate::op::{Operand, OperandType, ZOp};
use crate::op_array::{ArgInfo, ClassMetadata, ClassPropertyInfo, Literal, ZOpArray};
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
    /// Opline indices of ZEND_JMP instructions from `continue` that need patching.
    continue_patches: Vec<u32>,
    /// The opline index to jump to for `continue` (loop condition or increment).
    /// Only valid after the continue target is known; 0 means "needs patching".
    continue_target: u32,
    /// Whether this is a foreach loop (needs FE_FREE on break).
    foreach_var: Option<ExprResult>,
}

/// The compiler: walks AST nodes, emits opcodes into a ZOpArray.
pub struct Compiler {
    op_array: ZOpArray,
    /// Stack of active loops for break/continue.
    loop_stack: Vec<LoopContext>,
    /// Source filename (for resolving __FILE__ and __DIR__).
    source_filename: Option<String>,
    /// Current namespace (for prefixing class/function names).
    current_namespace: Option<String>,
    /// Currently compiling class name (for resolving self::).
    current_class: Option<String>,
    /// Parent class of the currently compiling class (for resolving parent::).
    current_class_parent: Option<String>,
    /// Use imports: short name → fully qualified name.
    use_imports: HashMap<String, String>,
    /// Use function imports: short name → fully qualified function name.
    use_function_imports: HashMap<String, String>,
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
            source_filename: None,
            current_namespace: None,
            current_class: None,
            current_class_parent: None,
            use_imports: HashMap::new(),
            use_function_imports: HashMap::new(),
        }
    }

    /// Create a compiler with a source filename for resolving __FILE__ and __DIR__.
    pub fn with_filename(filename: String) -> Self {
        Self {
            op_array: ZOpArray::new(),
            loop_stack: Vec::new(),
            source_filename: Some(filename),
            current_namespace: None,
            current_class: None,
            current_class_parent: None,
            use_imports: HashMap::new(),
            use_function_imports: HashMap::new(),
        }
    }

    /// Create a compiler that emits into a pre-configured op array.
    /// Used for compiling function/method/closure bodies.
    fn with_op_array(op_array: ZOpArray) -> Self {
        Self {
            op_array,
            loop_stack: Vec::new(),
            source_filename: None,
            current_namespace: None,
            current_class: None,
            current_class_parent: None,
            use_imports: HashMap::new(),
            use_function_imports: HashMap::new(),
        }
    }

    /// Create a sub-compiler that inherits the source filename, namespace, and class context from parent.
    fn sub_compiler(&self, op_array: ZOpArray) -> Self {
        Self {
            op_array,
            loop_stack: Vec::new(),
            source_filename: self.source_filename.clone(),
            current_namespace: self.current_namespace.clone(),
            current_class: self.current_class.clone(),
            current_class_parent: self.current_class_parent.clone(),
            use_imports: self.use_imports.clone(),
            use_function_imports: self.use_function_imports.clone(),
        }
    }

    /// Qualify a name with the current namespace (if any).
    /// Checks use imports first, then prepends namespace.
    fn qualify_name(&self, name: &str) -> String {
        // Fully qualified name: starts with backslash (e.g. \Foo\Bar -> Foo\Bar)
        if name.starts_with('\\') {
            return name[1..].to_string();
        }
        // Check use imports for single-part names
        if let Some(fq) = self.use_imports.get(name) {
            return fq.clone();
        }
        // Multi-part relative name (e.g. Configuration\ApplicationBuilder):
        // check if the first segment matches a use import
        if let Some(sep) = name.find('\\') {
            let first = &name[..sep];
            let rest = &name[sep + 1..];
            if let Some(fq_prefix) = self.use_imports.get(first) {
                return format!("{}\\{}", fq_prefix, rest);
            }
            // No use import match — prepend current namespace
            if let Some(ref ns) = self.current_namespace {
                if !ns.is_empty() {
                    return format!("{}\\{}", ns, name);
                }
            }
            return name.to_string();
        }
        // Single-part unqualified name — prepend current namespace
        match &self.current_namespace {
            Some(ns) if !ns.is_empty() => format!("{}\\{}", ns, name),
            _ => name.to_string(),
        }
    }

    /// Qualify a function name with use function imports, then namespace.
    /// Falls back to unqualified name for built-in functions.
    fn qualify_function_name(&self, name: &str) -> String {
        // Fully qualified: starts with backslash
        if name.starts_with('\\') {
            return name[1..].to_string();
        }
        // Check use function imports
        if let Some(fq) = self.use_function_imports.get(name) {
            return fq.clone();
        }
        // For functions, we DON'T namespace-qualify by default because
        // PHP falls back to global functions. The VM handles this.
        name.to_string()
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
                    match var {
                        Expression::Variable { name, .. } => {
                            let cv = self.op_array.lookup_cv(name);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::UnsetCv, span.line as u32)
                                    .with_op1(Operand::cv(cv), OperandType::Cv),
                            );
                        }
                        Expression::ArrayAccess { array, index, .. } => {
                            let arr = self.compile_expr(array);
                            if let Some(idx_expr) = index {
                                let idx = self.compile_expr(idx_expr);
                                self.op_array.emit(
                                    ZOp::new(ZOpcode::UnsetDim, span.line as u32)
                                        .with_op1(arr.operand, arr.op_type)
                                        .with_op2(idx.operand, idx.op_type),
                                );
                            }
                        }
                        Expression::PropertyAccess {
                            object, property, ..
                        } => {
                            let obj = self.compile_expr(object);
                            let prop = self.compile_expr(property);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::UnsetObj, span.line as u32)
                                    .with_op1(obj.operand, obj.op_type)
                                    .with_op2(prop.operand, prop.op_type),
                            );
                        }
                        _ => {
                            // Fallback: try to compile as variable-like expression
                        }
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

            // Namespace declaration: set current namespace for class/function prefixing
            Statement::Namespace {
                name, statements, ..
            } => {
                self.current_namespace = name.as_ref().map(|n| name_parts_to_string(&n.parts));
                for stmt in statements {
                    self.compile_stmt(stmt);
                }
                // Braced namespace: reset namespace after block
                if !statements.is_empty() {
                    self.current_namespace = None;
                }
            }

            // Use declarations: register import aliases
            Statement::Use { uses, kind, .. } => {
                for u in uses {
                    let fq = name_parts_to_string(&u.name.parts);
                    let short = if let Some(ref alias) = u.alias {
                        alias.clone()
                    } else {
                        // Use the last part of the name as the short alias
                        u.name.parts.last().cloned().unwrap_or(fq.clone())
                    };
                    match kind {
                        UseKind::Function => {
                            self.use_function_imports.insert(short, fq);
                        }
                        _ => {
                            self.use_imports.insert(short, fq);
                        }
                    }
                }
            }

            // Features not yet needed for VM execution
            Statement::Declare { .. }
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

    /// Compile a class name expression, resolving self/parent/static at compile time.
    /// Class names are always emitted as string literals (not FetchConstant).
    fn compile_class_name_expr(&mut self, expr: &Expression) -> ExprResult {
        if let Expression::ConstantAccess { name, .. } = expr {
            let resolved = match name.as_str() {
                "self" => self.current_class.clone().unwrap_or_else(|| name.clone()),
                // "static" must NOT be resolved at compile time — it uses late static binding
                "static" => "static".to_string(),
                "parent" => self
                    .current_class_parent
                    .clone()
                    .unwrap_or_else(|| "parent".to_string()),
                _ => self.qualify_name(name),
            };
            let idx = self.op_array.add_literal(Literal::String(resolved));
            return ExprResult::constant(idx);
        }
        // StringLiteral class names come from `new Foo()` or `new Foo\Bar()` parsing
        // They need namespace qualification too
        if let Expression::StringLiteral { value, .. } = expr {
            let resolved = match value.as_str() {
                "self" => self.current_class.clone().unwrap_or_else(|| value.clone()),
                "static" => "static".to_string(),
                "parent" => self
                    .current_class_parent
                    .clone()
                    .unwrap_or_else(|| "parent".to_string()),
                _ => self.qualify_name(value),
            };
            let idx = self.op_array.add_literal(Literal::String(resolved));
            return ExprResult::constant(idx);
        }
        self.compile_expr(expr)
    }

    /// Compile a static property name (the `$prop` in `Class::$prop`).
    /// If the property is a simple Variable, emit its name as a string literal
    /// rather than fetching the variable's runtime value.
    fn compile_static_prop_name(&mut self, expr: &Expression) -> ExprResult {
        if let Expression::Variable { name, .. } = expr {
            let idx = self.op_array.add_literal(Literal::String(name.clone()));
            return ExprResult::constant(idx);
        }
        self.compile_expr(expr)
    }

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
                // For instanceof, the class operand is always a class name, not a constant
                let rhs = match class.as_ref() {
                    Expression::ConstantAccess { name, .. } => {
                        let qualified = self.qualify_name(name);
                        let idx = self.op_array.add_literal(Literal::String(qualified));
                        ExprResult::constant(idx)
                    }
                    _ => self.compile_expr(class),
                };
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
                let cls = self.compile_class_name_expr(class);
                let prop = self.compile_static_prop_name(property);
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
                // Handle ClassName::class magic constant
                if constant == "class" {
                    let class_name = match class.as_ref() {
                        Expression::ConstantAccess { name, .. }
                        | Expression::StringLiteral { value: name, .. } => match name.as_str() {
                            "self" | "static" => {
                                self.current_class.clone().unwrap_or_else(|| name.clone())
                            }
                            "parent" => self
                                .current_class_parent
                                .clone()
                                .unwrap_or_else(|| name.clone()),
                            _ => self.qualify_name(name),
                        },
                        _ => {
                            // Dynamic class::class — compile as FetchClassConstant
                            let cls = self.compile_class_name_expr(class);
                            let const_lit = self
                                .op_array
                                .add_literal(Literal::String("class".to_string()));
                            let tmp = self.op_array.alloc_temp();
                            self.op_array.emit(
                                ZOp::new(ZOpcode::FetchClassConstant, span.line as u32)
                                    .with_op1(cls.operand, cls.op_type)
                                    .with_op2(Operand::constant(const_lit), OperandType::Const)
                                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                            );
                            return ExprResult::tmp(tmp);
                        }
                    };
                    let idx = self.op_array.add_literal(Literal::String(class_name));
                    return ExprResult::constant(idx);
                }
                let cls = self.compile_class_name_expr(class);
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
                    MagicConstantKind::File => {
                        Literal::String(self.source_filename.clone().unwrap_or_default())
                    }
                    MagicConstantKind::Dir => Literal::String(
                        self.source_filename
                            .as_ref()
                            .map(|f| {
                                std::path::Path::new(f)
                                    .parent()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            })
                            .unwrap_or_default(),
                    ),
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

            // --- Constant access ---
            Expression::ConstantAccess { name, span } => {
                // Check if this looks like a class name being used where a constant
                // would normally be. In most contexts, emit FetchConstant. The VM
                // will return the constant value or null for undefined constants.
                let lit_idx = self.op_array.add_literal(Literal::String(name.clone()));
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchConstant, span.line as u32)
                        .with_op2(Operand::constant(lit_idx), OperandType::Const)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
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

            // --- Anonymous class ---
            Expression::AnonymousClass { span, .. } => {
                // For now, compile anonymous classes as new stdClass
                let class_name = "stdClass".to_string();
                let lit_idx = self.op_array.add_literal(Literal::String(class_name));
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::New, span.line as u32)
                        .with_op1(Operand::constant(lit_idx), OperandType::Const)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                ExprResult::tmp(tmp)
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
            // Dimension assignment: $a[$k] = $v or $obj->prop[$k] = $v
            Expression::ArrayAccess { array, index, .. } => {
                // Walk the ArrayAccess chain to detect property-dim patterns:
                // $obj->prop[$k] = $v  or  $obj->prop[$k1][$k2] = $v
                let mut dim_keys: Vec<&Option<Box<Expression>>> = Vec::new();
                let mut base = array.as_ref();
                loop {
                    match base {
                        Expression::ArrayAccess {
                            array: inner,
                            index: inner_idx,
                            ..
                        } => {
                            dim_keys.push(inner_idx);
                            base = inner.as_ref();
                        }
                        _ => break,
                    }
                }

                if let Expression::PropertyAccess {
                    object, property, ..
                } = base
                {
                    // Property-dim assignment with write-back
                    // dim_keys collected inner-to-outer (reversed), plus current `index`
                    dim_keys.reverse(); // now inner-to-outer order
                    dim_keys.push(index); // add the outermost key

                    let obj_r = self.compile_expr(object);
                    let prop_r = self.compile_expr(property);

                    // FetchObjR to get the base property array
                    let base_tmp = self.op_array.alloc_temp();
                    self.op_array.emit(
                        ZOp::new(ZOpcode::FetchObjR, line)
                            .with_op1(obj_r.operand, obj_r.op_type)
                            .with_op2(prop_r.operand, prop_r.op_type)
                            .with_result(Operand::tmp_var(base_tmp), OperandType::TmpVar),
                    );

                    // For nested dims, fetch intermediate levels
                    let mut temps = vec![base_tmp];
                    for key_expr in &dim_keys[..dim_keys.len() - 1] {
                        let prev_tmp = *temps.last().unwrap();
                        let next_tmp = self.op_array.alloc_temp();
                        if let Some(k) = key_expr {
                            let k_r = self.compile_expr(k);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::FetchDimR, line)
                                    .with_op1(Operand::tmp_var(prev_tmp), OperandType::TmpVar)
                                    .with_op2(k_r.operand, k_r.op_type)
                                    .with_result(Operand::tmp_var(next_tmp), OperandType::TmpVar),
                            );
                        }
                        temps.push(next_tmp);
                    }

                    // AssignDim on the innermost level
                    let innermost_tmp = *temps.last().unwrap();
                    let result_tmp = self.op_array.alloc_temp();
                    let last_key = dim_keys.last().unwrap();
                    if let Some(k) = last_key {
                        let k_r = self.compile_expr(k);
                        self.op_array.emit(
                            ZOp::new(ZOpcode::AssignDim, line)
                                .with_op1(Operand::tmp_var(innermost_tmp), OperandType::TmpVar)
                                .with_op2(k_r.operand, k_r.op_type)
                                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                        );
                    } else {
                        self.op_array.emit(
                            ZOp::new(ZOpcode::AssignDim, line)
                                .with_op1(Operand::tmp_var(innermost_tmp), OperandType::TmpVar)
                                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                        );
                    }
                    // OP_DATA with the assigned value
                    self.op_array.emit(
                        ZOp::new(ZOpcode::OpData, line)
                            .with_op1(rhs_result.operand, rhs_result.op_type),
                    );

                    // Write-back chain: propagate modifications back up
                    // For each intermediate level (reverse order), write inner back to outer
                    for i in (0..temps.len() - 1).rev() {
                        let outer_tmp = temps[i];
                        let inner_tmp = temps[i + 1];
                        let wb_result = self.op_array.alloc_temp();
                        if let Some(k) = dim_keys[i] {
                            let k_r = self.compile_expr(k);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::AssignDim, line)
                                    .with_op1(Operand::tmp_var(outer_tmp), OperandType::TmpVar)
                                    .with_op2(k_r.operand, k_r.op_type)
                                    .with_result(Operand::tmp_var(wb_result), OperandType::TmpVar),
                            );
                        }
                        self.op_array.emit(
                            ZOp::new(ZOpcode::OpData, line)
                                .with_op1(Operand::tmp_var(inner_tmp), OperandType::TmpVar),
                        );
                    }

                    // Final write-back: assign the modified array back to the property
                    let wb_final = self.op_array.alloc_temp();
                    self.op_array.emit(
                        ZOp::new(ZOpcode::AssignObj, line)
                            .with_op1(obj_r.operand, obj_r.op_type)
                            .with_op2(prop_r.operand, prop_r.op_type)
                            .with_result(Operand::tmp_var(wb_final), OperandType::TmpVar),
                    );
                    self.op_array.emit(
                        ZOp::new(ZOpcode::OpData, line)
                            .with_op1(Operand::tmp_var(base_tmp), OperandType::TmpVar),
                    );

                    ExprResult::tmp(result_tmp)
                } else if let Expression::StaticPropertyAccess {
                    class, property, ..
                } = base
                {
                    // Static-property-dim assignment with write-back:
                    // static::$arr[$k] = $v  or  self::$arr[$k1][$k2] = $v
                    dim_keys.reverse();
                    dim_keys.push(index);

                    let cls = self.compile_class_name_expr(class);
                    let prop = self.compile_static_prop_name(property);

                    // FetchStaticPropW to get the current array value
                    let base_tmp = self.op_array.alloc_temp();
                    self.op_array.emit(
                        ZOp::new(ZOpcode::FetchStaticPropW, line)
                            .with_op1(prop.operand, prop.op_type)
                            .with_op2(cls.operand, cls.op_type)
                            .with_result(Operand::tmp_var(base_tmp), OperandType::TmpVar),
                    );

                    // For nested dims, fetch intermediate levels
                    let mut temps = vec![base_tmp];
                    for key_expr in &dim_keys[..dim_keys.len() - 1] {
                        let prev_tmp = *temps.last().unwrap();
                        let next_tmp = self.op_array.alloc_temp();
                        if let Some(k) = key_expr {
                            let k_r = self.compile_expr(k);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::FetchDimR, line)
                                    .with_op1(Operand::tmp_var(prev_tmp), OperandType::TmpVar)
                                    .with_op2(k_r.operand, k_r.op_type)
                                    .with_result(Operand::tmp_var(next_tmp), OperandType::TmpVar),
                            );
                        }
                        temps.push(next_tmp);
                    }

                    // AssignDim on the innermost level
                    let innermost_tmp = *temps.last().unwrap();
                    let result_tmp = self.op_array.alloc_temp();
                    let last_key = dim_keys.last().unwrap();
                    if let Some(k) = last_key {
                        let k_r = self.compile_expr(k);
                        self.op_array.emit(
                            ZOp::new(ZOpcode::AssignDim, line)
                                .with_op1(Operand::tmp_var(innermost_tmp), OperandType::TmpVar)
                                .with_op2(k_r.operand, k_r.op_type)
                                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                        );
                    } else {
                        self.op_array.emit(
                            ZOp::new(ZOpcode::AssignDim, line)
                                .with_op1(Operand::tmp_var(innermost_tmp), OperandType::TmpVar)
                                .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                        );
                    }
                    // OP_DATA with the assigned value
                    self.op_array.emit(
                        ZOp::new(ZOpcode::OpData, line)
                            .with_op1(rhs_result.operand, rhs_result.op_type),
                    );

                    // Write-back chain for nested dims
                    for i in (0..temps.len() - 1).rev() {
                        let outer_tmp = temps[i];
                        let inner_tmp = temps[i + 1];
                        let wb_result = self.op_array.alloc_temp();
                        if let Some(k) = dim_keys[i] {
                            let k_r = self.compile_expr(k);
                            self.op_array.emit(
                                ZOp::new(ZOpcode::AssignDim, line)
                                    .with_op1(Operand::tmp_var(outer_tmp), OperandType::TmpVar)
                                    .with_op2(k_r.operand, k_r.op_type)
                                    .with_result(Operand::tmp_var(wb_result), OperandType::TmpVar),
                            );
                        }
                        self.op_array.emit(
                            ZOp::new(ZOpcode::OpData, line)
                                .with_op1(Operand::tmp_var(inner_tmp), OperandType::TmpVar),
                        );
                    }

                    // Final write-back: assign the modified array back to the static property
                    self.op_array.emit(
                        ZOp::new(ZOpcode::AssignStaticProp, line)
                            .with_op1(cls.operand, cls.op_type)
                            .with_op2(prop.operand, prop.op_type),
                    );
                    self.op_array.emit(
                        ZOp::new(ZOpcode::OpData, line)
                            .with_op1(Operand::tmp_var(base_tmp), OperandType::TmpVar),
                    );

                    ExprResult::tmp(result_tmp)
                } else {
                    // Simple array dim assignment: $arr[$k] = $v
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
            }
            // Property assignment: $obj->prop = $val
            Expression::PropertyAccess {
                object, property, ..
            } => {
                let obj = self.compile_expr(object);
                let prop = self.compile_expr(property);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignObj, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                // OP_DATA follows with the value
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(rhs_result.operand, rhs_result.op_type),
                );
                ExprResult::tmp(tmp)
            }
            // Static property assignment: Class::$prop = $val
            Expression::StaticPropertyAccess {
                class, property, ..
            } => {
                let cls = self.compile_class_name_expr(class);
                let prop = self.compile_static_prop_name(property);
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignStaticProp, line)
                        .with_op1(cls.operand, cls.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                // OP_DATA follows with the value
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(rhs_result.operand, rhs_result.op_type),
                );
                ExprResult::tmp(tmp)
            }
            // List/array destructuring: list($a, $b) = expr
            Expression::List { elements, .. } => {
                // rhs_result is the source array. For each element in the list,
                // emit FetchDimR to read the corresponding index, then Assign.
                for (i, elem) in elements.iter().enumerate() {
                    if let Some(target) = elem {
                        let idx_lit = self.op_array.add_literal(Literal::Long(i as i64));
                        let fetch_tmp = self.op_array.alloc_temp();
                        self.op_array.emit(
                            ZOp::new(ZOpcode::FetchDimR, line)
                                .with_op1(rhs_result.operand, rhs_result.op_type)
                                .with_op2(Operand::constant(idx_lit), OperandType::Const)
                                .with_result(Operand::tmp_var(fetch_tmp), OperandType::TmpVar),
                        );
                        match target {
                            Expression::Variable { name, .. } => {
                                let cv = self.op_array.lookup_cv(name);
                                let assign_tmp = self.op_array.alloc_temp();
                                self.op_array.emit(
                                    ZOp::new(ZOpcode::Assign, line)
                                        .with_op1(Operand::cv(cv), OperandType::Cv)
                                        .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                        .with_result(
                                            Operand::tmp_var(assign_tmp),
                                            OperandType::TmpVar,
                                        ),
                                );
                            }
                            // Nested list: list($a, list($b, $c)) = expr
                            Expression::List {
                                elements: nested, ..
                            } => {
                                // Recursively compile nested list destructuring
                                let fetch_result = ExprResult::tmp(fetch_tmp);
                                self.compile_list_destructure(nested, fetch_result, line);
                            }
                            _ => {
                                // Compile target as an expression (e.g., $arr[$key])
                                let lhs_result = self.compile_expr(target);
                                let assign_tmp = self.op_array.alloc_temp();
                                self.op_array.emit(
                                    ZOp::new(ZOpcode::Assign, line)
                                        .with_op1(lhs_result.operand, lhs_result.op_type)
                                        .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                        .with_result(
                                            Operand::tmp_var(assign_tmp),
                                            OperandType::TmpVar,
                                        ),
                                );
                            }
                        }
                    }
                }
                rhs_result
            }

            // Short array destructuring: [$a, $b] = expr
            Expression::ArrayLiteral { elements, .. } => {
                // Treat like list() destructuring
                for (i, elem) in elements.iter().enumerate() {
                    // Determine the key for this element
                    let key_expr = if let Some(ref k) = elem.key {
                        // Keyed destructuring: [$key => $var]
                        self.compile_expr(k)
                    } else {
                        let idx_lit = self.op_array.add_literal(Literal::Long(i as i64));
                        ExprResult::constant(idx_lit)
                    };
                    let fetch_tmp = self.op_array.alloc_temp();
                    self.op_array.emit(
                        ZOp::new(ZOpcode::FetchDimR, line)
                            .with_op1(rhs_result.operand, rhs_result.op_type)
                            .with_op2(key_expr.operand, key_expr.op_type)
                            .with_result(Operand::tmp_var(fetch_tmp), OperandType::TmpVar),
                    );
                    let target = &elem.value;
                    match target {
                        Expression::Variable { name, .. } => {
                            let cv = self.op_array.lookup_cv(name);
                            let assign_tmp = self.op_array.alloc_temp();
                            self.op_array.emit(
                                ZOp::new(ZOpcode::Assign, line)
                                    .with_op1(Operand::cv(cv), OperandType::Cv)
                                    .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                    .with_result(Operand::tmp_var(assign_tmp), OperandType::TmpVar),
                            );
                        }
                        Expression::ArrayLiteral {
                            elements: nested, ..
                        } => {
                            // Nested array destructuring [$a, [$b, $c]] = expr
                            let fetch_result = ExprResult::tmp(fetch_tmp);
                            let nested_elems: Vec<Option<Expression>> =
                                nested.iter().map(|e| Some(e.value.clone())).collect();
                            self.compile_list_destructure(&nested_elems, fetch_result, line);
                        }
                        _ => {
                            let lhs_result = self.compile_expr(target);
                            let assign_tmp = self.op_array.alloc_temp();
                            self.op_array.emit(
                                ZOp::new(ZOpcode::Assign, line)
                                    .with_op1(lhs_result.operand, lhs_result.op_type)
                                    .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                    .with_result(Operand::tmp_var(assign_tmp), OperandType::TmpVar),
                            );
                        }
                    }
                }
                rhs_result
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

    /// Helper for nested list destructuring.
    fn compile_list_destructure(
        &mut self,
        elements: &[Option<Expression>],
        source: ExprResult,
        line: u32,
    ) {
        for (i, elem) in elements.iter().enumerate() {
            if let Some(target) = elem {
                let idx_lit = self.op_array.add_literal(Literal::Long(i as i64));
                let fetch_tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchDimR, line)
                        .with_op1(source.operand, source.op_type)
                        .with_op2(Operand::constant(idx_lit), OperandType::Const)
                        .with_result(Operand::tmp_var(fetch_tmp), OperandType::TmpVar),
                );
                match target {
                    Expression::Variable { name, .. } => {
                        let cv = self.op_array.lookup_cv(name);
                        let assign_tmp = self.op_array.alloc_temp();
                        self.op_array.emit(
                            ZOp::new(ZOpcode::Assign, line)
                                .with_op1(Operand::cv(cv), OperandType::Cv)
                                .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                .with_result(Operand::tmp_var(assign_tmp), OperandType::TmpVar),
                        );
                    }
                    Expression::List {
                        elements: nested, ..
                    } => {
                        let fetch_result = ExprResult::tmp(fetch_tmp);
                        self.compile_list_destructure(nested, fetch_result, line);
                    }
                    _ => {
                        let lhs_result = self.compile_expr(target);
                        let assign_tmp = self.op_array.alloc_temp();
                        self.op_array.emit(
                            ZOp::new(ZOpcode::Assign, line)
                                .with_op1(lhs_result.operand, lhs_result.op_type)
                                .with_op2(Operand::tmp_var(fetch_tmp), OperandType::TmpVar)
                                .with_result(Operand::tmp_var(assign_tmp), OperandType::TmpVar),
                        );
                    }
                }
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
            Expression::PropertyAccess {
                object, property, ..
            } => {
                // $obj->prop += $val → read, operate, write back
                let obj = self.compile_expr(object);
                let prop = self.compile_expr(property);

                // Read current: FetchObjR(obj, prop) → tmp_old
                let tmp_old = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::FetchObjR, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp_old), OperandType::TmpVar),
                );

                // Compute: assign_op(tmp_old, rhs) → tmp_new
                let tmp_new = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(assign_op, line)
                        .with_op1(Operand::tmp_var(tmp_old), OperandType::TmpVar)
                        .with_op2(rhs_result.operand, rhs_result.op_type)
                        .with_result(Operand::tmp_var(tmp_new), OperandType::TmpVar),
                );

                // Write back: AssignObj(obj, prop) + OpData(tmp_new)
                let tmp_assign = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignObj, line)
                        .with_op1(obj.operand, obj.op_type)
                        .with_op2(prop.operand, prop.op_type)
                        .with_result(Operand::tmp_var(tmp_assign), OperandType::TmpVar),
                );
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(Operand::tmp_var(tmp_new), OperandType::TmpVar),
                );

                ExprResult::tmp(tmp_new)
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
        // Special handling for property access: $obj->prop++ needs read-modify-write
        if let Expression::PropertyAccess {
            object, property, ..
        } = var
        {
            let obj = self.compile_expr(object);
            let prop = self.compile_expr(property);

            // Read current value: FetchObjR(obj, prop) → tmp_old
            let tmp_old = self.op_array.alloc_temp();
            self.op_array.emit(
                ZOp::new(ZOpcode::FetchObjR, line)
                    .with_op1(obj.operand, obj.op_type)
                    .with_op2(prop.operand, prop.op_type)
                    .with_result(Operand::tmp_var(tmp_old), OperandType::TmpVar),
            );

            // Compute new value
            let is_inc = matches!(opcode, ZOpcode::PreInc | ZOpcode::PostInc);
            let one_lit = self.op_array.add_literal(Literal::Long(1));
            let tmp_new = self.op_array.alloc_temp();
            self.op_array.emit(
                ZOp::new(if is_inc { ZOpcode::Add } else { ZOpcode::Sub }, line)
                    .with_op1(Operand::tmp_var(tmp_old), OperandType::TmpVar)
                    .with_op2(Operand::constant(one_lit), OperandType::Const)
                    .with_result(Operand::tmp_var(tmp_new), OperandType::TmpVar),
            );

            // Write back: AssignObj(obj, prop) + OpData(tmp_new)
            let tmp_assign = self.op_array.alloc_temp();
            self.op_array.emit(
                ZOp::new(ZOpcode::AssignObj, line)
                    .with_op1(obj.operand, obj.op_type)
                    .with_op2(prop.operand, prop.op_type)
                    .with_result(Operand::tmp_var(tmp_assign), OperandType::TmpVar),
            );
            self.op_array.emit(
                ZOp::new(ZOpcode::OpData, line)
                    .with_op1(Operand::tmp_var(tmp_new), OperandType::TmpVar),
            );

            // Pre returns new value, Post returns old value
            return match opcode {
                ZOpcode::PreInc | ZOpcode::PreDec => ExprResult::tmp(tmp_new),
                _ => ExprResult::tmp(tmp_old),
            };
        }

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
        // Compile a single isset check for one variable expression
        let compile_isset_single = |compiler: &mut Compiler, var: &Expression| -> ExprResult {
            match var {
                Expression::Variable { name, .. } => {
                    let cv = compiler.op_array.lookup_cv(name);
                    let tmp = compiler.op_array.alloc_temp();
                    compiler.op_array.emit(
                        ZOp::new(ZOpcode::IssetIsemptyCv, line)
                            .with_op1(Operand::cv(cv), OperandType::Cv)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                            .with_extended_value(0), // ISSET mode
                    );
                    ExprResult::tmp(tmp)
                }
                Expression::ArrayAccess { array, index, .. } => {
                    let arr = compiler.compile_expr(array);
                    let tmp = compiler.op_array.alloc_temp();
                    if let Some(idx_expr) = index {
                        let idx = compiler.compile_expr(idx_expr);
                        compiler.op_array.emit(
                            ZOp::new(ZOpcode::IssetIsemptyDimObj, line)
                                .with_op1(arr.operand, arr.op_type)
                                .with_op2(idx.operand, idx.op_type)
                                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                                .with_extended_value(0), // ISSET mode
                        );
                    } else {
                        compiler.op_array.emit(
                            ZOp::new(ZOpcode::IssetIsemptyDimObj, line)
                                .with_op1(arr.operand, arr.op_type)
                                .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                                .with_extended_value(0),
                        );
                    }
                    ExprResult::tmp(tmp)
                }
                Expression::PropertyAccess {
                    object, property, ..
                } => {
                    let obj = compiler.compile_expr(object);
                    let prop = compiler.compile_expr(property);
                    let tmp = compiler.op_array.alloc_temp();
                    compiler.op_array.emit(
                        ZOp::new(ZOpcode::IssetIsemptyDimObj, line)
                            .with_op1(obj.operand, obj.op_type)
                            .with_op2(prop.operand, prop.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                            .with_extended_value(0x100), // property mode
                    );
                    ExprResult::tmp(tmp)
                }
                _ => {
                    // Fallback: compile as expression and check non-null
                    let val = compiler.compile_expr(var);
                    let tmp = compiler.op_array.alloc_temp();
                    compiler.op_array.emit(
                        ZOp::new(ZOpcode::TypeCheck, line)
                            .with_op1(val.operand, val.op_type)
                            .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                            .with_extended_value(1), // isset-like check
                    );
                    ExprResult::tmp(tmp)
                }
            }
        };

        if vars.len() == 1 {
            return compile_isset_single(self, &vars[0]);
        }

        // Multiple vars: isset($a, $b, $c) => isset($a) && isset($b) && isset($c)
        // Use JmpZ chain: check first, if false jump to end with false result
        let result_tmp = self.op_array.alloc_temp();
        let mut end_patches = Vec::new();

        for (i, var) in vars.iter().enumerate() {
            let check = compile_isset_single(self, var);

            if i < vars.len() - 1 {
                // Not the last: emit JmpZ to short-circuit to false
                let jmpz_idx = self
                    .op_array
                    .emit(ZOp::new(ZOpcode::Jmpz, line).with_op1(check.operand, check.op_type));
                end_patches.push(jmpz_idx);
            } else {
                // Last variable: store its result as the overall result
                self.op_array.emit(
                    ZOp::new(ZOpcode::QmAssign, line)
                        .with_op1(check.operand, check.op_type)
                        .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                );
                let jmp_end_idx = self.op_array.emit(ZOp::new(ZOpcode::Jmp, line));
                end_patches.push(jmp_end_idx);

                // False target: store false
                let false_target = self.op_array.next_opline();
                // Patch all JmpZ to here
                for &patch_idx in &end_patches[..end_patches.len() - 1] {
                    self.op_array.opcodes[patch_idx as usize].op2 =
                        Operand::jmp_target(false_target);
                }

                let false_lit = self.op_array.add_literal(Literal::Bool(false));
                self.op_array.emit(
                    ZOp::new(ZOpcode::QmAssign, line)
                        .with_op1(Operand::constant(false_lit), OperandType::Const)
                        .with_result(Operand::tmp_var(result_tmp), OperandType::TmpVar),
                );

                // Patch the JMP-past-false to here (Jmp uses op1 for target)
                let end_target = self.op_array.next_opline();
                let jmp_idx = end_patches[end_patches.len() - 1];
                self.op_array.opcodes[jmp_idx as usize].op1 = Operand::jmp_target(end_target);
            }
        }

        ExprResult::tmp(result_tmp)
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
            continue_patches: Vec::new(),
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
            continue_patches: Vec::new(),
            continue_target: 0, // will patch
            foreach_var: None,
        });

        // Compile body
        self.compile_stmt(body);

        // Condition location — patch continue target
        let cond_start = self.op_array.next_opline();
        if let Some(ctx) = self.loop_stack.last_mut() {
            ctx.continue_target = cond_start;
            for patch_idx in std::mem::take(&mut ctx.continue_patches) {
                self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(cond_start);
            }
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
            continue_patches: Vec::new(),
            continue_target: 0, // will patch
            foreach_var: None,
        });

        // Body
        self.compile_stmt(body);

        // Increment — this is the continue target
        let incr_start = self.op_array.next_opline();
        if let Some(ctx) = self.loop_stack.last_mut() {
            ctx.continue_target = incr_start;
            // Patch any continue JMPs that were emitted before we knew the target
            for patch_idx in std::mem::take(&mut ctx.continue_patches) {
                self.op_array.opcodes[patch_idx as usize].op1 = Operand::jmp_target(incr_start);
            }
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
            continue_patches: Vec::new(),
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
            continue_patches: Vec::new(),
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
        // In switch, continue acts like break
        for patch_idx in ctx.continue_patches {
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
        if let Some(ctx) = self.loop_stack.get_mut(loop_idx) {
            let target = ctx.continue_target;
            if target == 0 {
                // Target not yet known — emit placeholder JMP and record for patching
                let jmp_idx = self.op_array.emit(
                    ZOp::new(ZOpcode::Jmp, line)
                        .with_op1(Operand::jmp_target(0), OperandType::Unused),
                );
                ctx.continue_patches.push(jmp_idx);
            } else {
                self.op_array.emit(
                    ZOp::new(ZOpcode::Jmp, line)
                        .with_op1(Operand::jmp_target(target), OperandType::Unused),
                );
            }
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

        // Compile catch blocks, recording each catch's opline and types
        use crate::op_array::TryCatchElement;
        let mut catch_jmp_patches = Vec::new();
        let mut catch_info: Vec<(u32, Vec<String>)> = Vec::new(); // (catch_opline, class_names)
        for catch in catches {
            let this_catch_op = self.op_array.next_opline();

            // Collect exception class names for this catch clause
            let mut class_names = Vec::new();
            for type_name in &catch.types {
                let joined = type_name.parts.join("\\");
                let name_str = self.qualify_name(&joined);
                class_names.push(name_str);
            }
            catch_info.push((this_catch_op, class_names));

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

        // Record one TryCatchElement per catch clause for type-checked dispatch
        for (catch_op, class_names) in catch_info {
            self.op_array.try_catch_array.push(TryCatchElement {
                try_op: try_start,
                catch_op,
                finally_op: if finally.is_some() { finally_start } else { 0 },
                finally_end: after_try,
                catch_classes: class_names,
            });
        }

        // If no catch clauses but there's a finally, still record the try/finally
        if catches.is_empty() {
            self.op_array.try_catch_array.push(TryCatchElement {
                try_op: try_start,
                catch_op: 0,
                finally_op: if finally.is_some() { finally_start } else { 0 },
                finally_end: after_try,
                catch_classes: Vec::new(),
            });
        }
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

        // Qualify function name with namespace
        let fq_name = self.qualify_name(name);

        // Build the function's op_array
        let mut func_oa = ZOpArray::for_function(&fq_name);
        func_oa.line_start = line;
        self.setup_params(&mut func_oa, params);

        // Compile body in sub-compiler
        let mut sub = self.sub_compiler(func_oa);
        for s in body {
            sub.compile_stmt(s);
        }
        // Check if function body contains yield/yield_from → mark as generator
        let has_yield = sub
            .op_array
            .opcodes
            .iter()
            .any(|o| matches!(o.opcode, ZOpcode::Yield | ZOpcode::YieldFrom));

        if has_yield {
            sub.op_array.is_generator = true;
            // Convert all existing Return opcodes to GeneratorReturn
            for op in sub.op_array.opcodes.iter_mut() {
                if op.opcode == ZOpcode::Return {
                    op.opcode = ZOpcode::GeneratorReturn;
                }
            }
            // Prepend GeneratorCreate opcode at position 0
            let gen_create = ZOp::new(ZOpcode::GeneratorCreate, line);
            sub.op_array.opcodes.insert(0, gen_create);
            // Add implicit GeneratorReturn at the end
            let null = sub.op_array.add_literal(Literal::Null);
            sub.op_array.emit(
                ZOp::new(ZOpcode::GeneratorReturn, line)
                    .with_op1(Operand::constant(null), OperandType::Const),
            );
        } else {
            // Implicit return null
            let null = sub.op_array.add_literal(Literal::Null);
            sub.op_array.emit(
                ZOp::new(ZOpcode::Return, line)
                    .with_op1(Operand::constant(null), OperandType::Const),
            );
        }

        let func_idx = self.op_array.dynamic_func_defs.len() as u32;
        self.op_array.dynamic_func_defs.push(sub.op_array);

        // Emit DECLARE_FUNCTION in parent
        let name_lit = self.op_array.add_literal(Literal::String(fq_name));
        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareFunction, line)
                .with_op1(Operand::constant(func_idx), OperandType::Const)
                .with_op2(Operand::constant(name_lit), OperandType::Const),
        );
    }

    /// Extract the primary type name from a Type annotation.
    fn extract_type_name(t: &php_rs_parser::Type) -> Option<String> {
        match t {
            php_rs_parser::Type::Named { name, .. } => {
                let full = name.parts.join("\\");
                if name.fully_qualified {
                    Some(full.strip_prefix('\\').unwrap_or(&full).to_string())
                } else {
                    Some(full)
                }
            }
            php_rs_parser::Type::Nullable { inner, .. } => Self::extract_type_name(inner),
            php_rs_parser::Type::Union { types, .. } => {
                types.first().and_then(|t| Self::extract_type_name(t))
            }
            _ => None,
        }
    }

    /// Try to evaluate a constant expression to a Literal (for parameter defaults).
    fn expr_to_literal(expr: &Expression) -> Option<Literal> {
        match expr {
            Expression::IntLiteral { value, .. } => Some(Literal::Long(*value)),
            Expression::FloatLiteral { value, .. } => Some(Literal::Double(*value)),
            Expression::StringLiteral { value, .. } => Some(Literal::String(value.clone())),
            Expression::BoolLiteral { value, .. } => Some(Literal::Bool(*value)),
            Expression::Null { .. } => Some(Literal::Null),
            Expression::ConstantAccess { name, .. } => {
                let lower = name.to_lowercase();
                match lower.as_str() {
                    "null" => Some(Literal::Null),
                    "true" => Some(Literal::Bool(true)),
                    "false" => Some(Literal::Bool(false)),
                    _ => None, // Non-trivial constant — can't evaluate at compile time
                }
            }
            Expression::ArrayLiteral { elements, .. } if elements.is_empty() => {
                // Empty array [] — store as special literal
                Some(Literal::String("__EMPTY_ARRAY__".to_string()))
            }
            Expression::UnaryOp { op, operand, .. } => {
                // Handle negative numbers: -1, -3.14
                if *op == php_rs_parser::UnaryOperator::Minus {
                    match Self::expr_to_literal(operand) {
                        Some(Literal::Long(n)) => Some(Literal::Long(-n)),
                        Some(Literal::Double(f)) => Some(Literal::Double(-f)),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            Expression::ClassConstant {
                class, constant, ..
            } => {
                // Extract class name for runtime resolution
                let class_name = match class.as_ref() {
                    Expression::ConstantAccess { name, .. } => name.clone(),
                    Expression::StringLiteral { value, .. } => value.clone(),
                    Expression::Variable { name, .. } => name.clone(),
                    _ => return None,
                };
                Some(Literal::ClassConst(class_name, constant.clone()))
            }
            _ => None, // Complex expression — not a simple literal
        }
    }

    /// Set up parameter CVs and arg_info for a function/method op_array.
    fn setup_params(&self, func_oa: &mut ZOpArray, params: &[Parameter]) {
        let mut required = 0u32;
        for param in params {
            // Strip leading $ from parameter name to match variable reference CVs
            let cv_name = param.name.strip_prefix('$').unwrap_or(&param.name);
            func_oa.lookup_cv(cv_name);
            let default_lit = param
                .default
                .as_ref()
                .and_then(|expr| Self::expr_to_literal(expr));
            // Extract type hint name if available
            let type_name = param
                .param_type
                .as_ref()
                .and_then(|t| Self::extract_type_name(t));
            // Qualify the type name with the current namespace
            let type_name = type_name.map(|t| {
                match t.as_str() {
                    // Built-in types: don't qualify
                    "int" | "float" | "string" | "bool" | "array" | "callable" | "iterable"
                    | "object" | "mixed" | "void" | "never" | "null" | "false" | "true"
                    | "self" | "static" | "parent" => t,
                    // Class types: qualify with namespace
                    _ => self.qualify_name(&t),
                }
            });
            func_oa.arg_info.push(ArgInfo {
                name: cv_name.to_string(),
                pass_by_reference: param.by_ref,
                is_variadic: param.variadic,
                default: default_lit,
                type_name,
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
                let qualified = self.qualify_function_name(value);
                let name_lit = self.op_array.add_literal(Literal::String(qualified));
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
                let cls = self.compile_class_name_expr(class);
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
        let cls = self.compile_class_name_expr(class);
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
        let cls = self.compile_class_name_expr(class);
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
        let mut sub = self.sub_compiler(closure_oa);
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

        // Implicit $this binding for non-static closures in method context
        if !_is_static && self.current_class.is_some() {
            // Check if the closure body references $this
            let closure_oa = self.op_array.dynamic_func_defs.last().unwrap();
            if closure_oa.vars.iter().any(|v| v == "this") {
                let this_cv = self.op_array.lookup_cv("this");
                self.op_array.emit(
                    ZOp::new(ZOpcode::BindLexical, line)
                        .with_op1(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_op2(Operand::cv(this_cv), OperandType::Cv)
                        .with_extended_value(0), // by value
                );
            }
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
        let mut sub = self.sub_compiler(closure_oa);
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

        // Arrow functions auto-capture all referenced variables from parent scope
        let closure_oa = &self.op_array.dynamic_func_defs[func_idx as usize];
        let captured_vars: Vec<String> = closure_oa
            .vars
            .iter()
            .filter(|v| {
                // Skip parameters (they're local to the arrow function)
                !closure_oa.arg_info.iter().any(|a| &a.name == *v)
            })
            .filter(|v| {
                // Only bind variables that exist in the parent scope
                self.op_array.vars.contains(v)
            })
            .cloned()
            .collect();

        for var_name in &captured_vars {
            let parent_cv = self.op_array.lookup_cv(var_name);
            self.op_array.emit(
                ZOp::new(ZOpcode::BindLexical, line)
                    .with_op1(Operand::tmp_var(tmp), OperandType::TmpVar)
                    .with_op2(Operand::cv(parent_cv), OperandType::Cv)
                    .with_extended_value(0),
            );
        }

        // Implicit $this binding for arrow functions in method context
        if self.current_class.is_some() && !captured_vars.contains(&"this".to_string()) {
            let closure_oa = &self.op_array.dynamic_func_defs[func_idx as usize];
            if closure_oa.vars.iter().any(|v| v == "this") {
                let this_cv = self.op_array.lookup_cv("this");
                self.op_array.emit(
                    ZOp::new(ZOpcode::BindLexical, line)
                        .with_op1(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_op2(Operand::cv(this_cv), OperandType::Cv)
                        .with_extended_value(0),
                );
            }
        }

        ExprResult::tmp(tmp)
    }

    // =========================================================================
    // Class compilation (Phase 4.5)
    // =========================================================================

    /// Try to evaluate a compile-time constant expression to a Literal.
    fn try_expr_to_literal(expr: &Expression) -> Option<Literal> {
        match expr {
            Expression::Null { .. } => Some(Literal::Null),
            Expression::BoolLiteral { value, .. } => Some(Literal::Bool(*value)),
            Expression::IntLiteral { value, .. } => Some(Literal::Long(*value)),
            Expression::FloatLiteral { value, .. } => Some(Literal::Double(*value)),
            Expression::StringLiteral { value, .. } => Some(Literal::String(value.clone())),
            Expression::ArrayLiteral { elements, .. } if elements.is_empty() => {
                // Empty array [] — store as special literal
                Some(Literal::String("__EMPTY_ARRAY__".to_string()))
            }
            Expression::ConstantAccess { name, .. } => match name.as_str() {
                "true" | "TRUE" => Some(Literal::Bool(true)),
                "false" | "FALSE" => Some(Literal::Bool(false)),
                "null" | "NULL" => Some(Literal::Null),
                _ => None,
            },
            Expression::UnaryOp { op, operand, .. } if *op == UnaryOperator::Minus => {
                match Self::try_expr_to_literal(operand) {
                    Some(Literal::Long(n)) => Some(Literal::Long(-n)),
                    Some(Literal::Double(f)) => Some(Literal::Double(-f)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

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

        // Qualify class name with current namespace
        let fq_name = self.qualify_name(name);

        // Set current class context for self::/parent:: resolution
        let parent_name = extends
            .as_ref()
            .map(|p| self.qualify_name(&name_parts_to_string(&p.parts)));
        self.current_class = Some(fq_name.clone());
        self.current_class_parent = parent_name.clone();

        // Emit DECLARE_CLASS
        let name_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));
        let mut flags: u32 = 0;
        for m in modifiers {
            flags |= modifier_flag(m);
        }

        // Encode extends/implements info as "parent\0iface1\0iface2" in op2
        let mut class_info = String::new();
        if let Some(parent) = extends {
            class_info.push_str(&self.qualify_name(&name_parts_to_string(&parent.parts)));
        }
        for iface in implements {
            class_info.push('\0');
            class_info.push_str(&self.qualify_name(&name_parts_to_string(&iface.parts)));
        }
        let info_lit = self.op_array.add_literal(Literal::String(class_info));

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_op2(Operand::constant(info_lit), OperandType::Const)
                .with_extended_value(flags),
        );

        // Collect class metadata (properties and constants)
        let mut metadata = ClassMetadata::default();

        // Deferred runtime initializations (complex default values)
        struct DeferredPropInit {
            name: String,
            is_static: bool,
            expr: Expression,
        }
        struct DeferredConstInit {
            name: String,
            expr: Expression,
        }
        let mut deferred_props: Vec<DeferredPropInit> = Vec::new();
        let mut deferred_consts: Vec<DeferredConstInit> = Vec::new();

        // Compile members
        for member in members {
            match member {
                ClassMember::Property {
                    name: prop_name,
                    modifiers: prop_mods,
                    default,
                    ..
                } => {
                    let is_static = prop_mods.contains(&Modifier::Static);
                    let default_lit = default.as_ref().and_then(|e| Self::try_expr_to_literal(e));
                    if default_lit.is_some() || default.is_none() {
                        // Simple literal or no default — use metadata
                        metadata.properties.push(ClassPropertyInfo {
                            name: prop_name.clone(),
                            default: default_lit,
                            is_static,
                        });
                    } else {
                        // Complex default — register property with None and defer
                        metadata.properties.push(ClassPropertyInfo {
                            name: prop_name.clone(),
                            default: None,
                            is_static,
                        });
                        deferred_props.push(DeferredPropInit {
                            name: prop_name.clone(),
                            is_static,
                            expr: default.as_ref().unwrap().clone(),
                        });
                    }
                }
                ClassMember::Constant {
                    name: const_name,
                    value,
                    ..
                } => {
                    let lit = Self::try_expr_to_literal(value);
                    if let Some(l) = lit {
                        metadata.constants.push((const_name.clone(), l));
                    } else {
                        // Complex constant value — use Null as placeholder and defer
                        metadata.constants.push((const_name.clone(), Literal::Null));
                        deferred_consts.push(DeferredConstInit {
                            name: const_name.clone(),
                            expr: value.clone(),
                        });
                    }
                }
                ClassMember::Method {
                    name: method_name,
                    params,
                    body: Some(method_body),
                    modifiers: method_mods,
                    ..
                } => {
                    let full_name = format!("{}::{}", fq_name, method_name);
                    let mut method_oa = ZOpArray::for_function(&full_name);
                    method_oa.line_start = line;
                    self.setup_params(&mut method_oa, params);

                    // Add $this as implicit first CV for non-static methods
                    if !method_mods.contains(&Modifier::Static) {
                        method_oa.lookup_cv("this");
                    }

                    let mut sub = self.sub_compiler(method_oa);

                    // Constructor property promotion: for promoted params,
                    // emit $this->paramName = $paramName at the start
                    if method_name == "__construct" {
                        for param in params {
                            let has_visibility = param.modifiers.iter().any(|m| {
                                matches!(
                                    m,
                                    Modifier::Public | Modifier::Protected | Modifier::Private
                                )
                            });
                            if has_visibility {
                                let param_name_stripped =
                                    param.name.strip_prefix('$').unwrap_or(&param.name);
                                // Also register as a class property
                                metadata.properties.push(ClassPropertyInfo {
                                    name: param_name_stripped.to_string(),
                                    default: None,
                                    is_static: false,
                                });
                                // Emit: $this->paramName = $paramName
                                let this_cv = sub.op_array.lookup_cv("this");
                                let param_cv = sub.op_array.lookup_cv(param_name_stripped);
                                let prop_lit = sub
                                    .op_array
                                    .add_literal(Literal::String(param_name_stripped.to_string()));
                                let tmp = sub.op_array.alloc_temp();
                                sub.op_array.emit(
                                    ZOp::new(ZOpcode::AssignObj, line)
                                        .with_op1(Operand::cv(this_cv), OperandType::Cv)
                                        .with_op2(Operand::constant(prop_lit), OperandType::Const)
                                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                                );
                                sub.op_array.emit(
                                    ZOp::new(ZOpcode::OpData, line)
                                        .with_op1(Operand::cv(param_cv), OperandType::Cv),
                                );
                            }
                        }
                    }

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
                ClassMember::TraitUse { traits, .. } => {
                    for trait_name in traits {
                        metadata
                            .traits
                            .push(self.qualify_name(&name_parts_to_string(&trait_name.parts)));
                    }
                }
                _ => {} // abstract methods, etc.
            }
        }

        // Store class metadata in op_array
        self.op_array
            .class_metadata
            .insert(fq_name.clone(), metadata);

        // Emit runtime initialization opcodes for complex property defaults
        for dp in deferred_props {
            let val_result = self.compile_expr(&dp.expr);
            let cls_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));
            let prop_lit = self.op_array.add_literal(Literal::String(dp.name));
            if dp.is_static {
                // AssignStaticProp cls prop + OpData value
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignStaticProp, line)
                        .with_op1(Operand::constant(cls_lit), OperandType::Const)
                        .with_op2(Operand::constant(prop_lit), OperandType::Const)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar),
                );
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(val_result.operand, val_result.op_type),
                );
            } else {
                // For instance properties, use AssignObjProp with class default
                // Store as a deferred property assignment — we use a special opcode
                // DeclareClassProperty: op1=class, op2=prop_name, result=value
                // We'll reuse AssignStaticProp with a flag in extended_value
                let tmp = self.op_array.alloc_temp();
                self.op_array.emit(
                    ZOp::new(ZOpcode::AssignStaticProp, line)
                        .with_op1(Operand::constant(cls_lit), OperandType::Const)
                        .with_op2(Operand::constant(prop_lit), OperandType::Const)
                        .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                        .with_extended_value(1), // flag: instance property default
                );
                self.op_array.emit(
                    ZOp::new(ZOpcode::OpData, line)
                        .with_op1(val_result.operand, val_result.op_type),
                );
            }
        }

        // Emit runtime initialization for complex class constants
        for dc in deferred_consts {
            let val_result = self.compile_expr(&dc.expr);
            let cls_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));
            let const_lit = self.op_array.add_literal(Literal::String(dc.name));
            // Use AssignStaticProp with extended_value=2 to indicate class constant
            let tmp = self.op_array.alloc_temp();
            self.op_array.emit(
                ZOp::new(ZOpcode::AssignStaticProp, line)
                    .with_op1(Operand::constant(cls_lit), OperandType::Const)
                    .with_op2(Operand::constant(const_lit), OperandType::Const)
                    .with_result(Operand::tmp_var(tmp), OperandType::TmpVar)
                    .with_extended_value(2), // flag: class constant
            );
            self.op_array.emit(
                ZOp::new(ZOpcode::OpData, line).with_op1(val_result.operand, val_result.op_type),
            );
        }

        // Clear class context
        self.current_class = None;
        self.current_class_parent = None;
    }

    fn compile_interface_decl(
        &mut self,
        name: &str,
        extends: &[Name],
        members: &[ClassMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let fq_name = self.qualify_name(name);
        let name_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));

        // Encode parent interfaces as "\0iface1\0iface2" in op2
        let mut class_info = String::new();
        for parent in extends {
            class_info.push('\0');
            class_info.push_str(&self.qualify_name(&name_parts_to_string(&parent.parts)));
        }
        let info_lit = self.op_array.add_literal(Literal::String(class_info));

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_op2(Operand::constant(info_lit), OperandType::Const)
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
                let full_name = format!("{}::{}", fq_name, method_name);
                let mut method_oa = ZOpArray::for_function(&full_name);
                self.setup_params(&mut method_oa, params);

                let mut sub = self.sub_compiler(method_oa);
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
        let fq_name = self.qualify_name(name);
        let name_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_extended_value(ZEND_ACC_TRAIT),
        );

        let mut metadata = ClassMetadata::default();

        for member in members {
            match member {
                ClassMember::Method {
                    name: method_name,
                    params,
                    body: Some(method_body),
                    modifiers,
                    ..
                } => {
                    let full_name = format!("{}::{}", fq_name, method_name);
                    let mut method_oa = ZOpArray::for_function(&full_name);
                    self.setup_params(&mut method_oa, params);

                    if !modifiers.contains(&Modifier::Static) {
                        method_oa.lookup_cv("this");
                    }

                    let mut sub = self.sub_compiler(method_oa);
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
                ClassMember::Property {
                    name: prop_name,
                    modifiers: prop_mods,
                    default,
                    ..
                } => {
                    let is_static = prop_mods.contains(&Modifier::Static);
                    let default_lit = default.as_ref().and_then(|e| Self::try_expr_to_literal(e));
                    metadata.properties.push(ClassPropertyInfo {
                        name: prop_name.clone(),
                        default: default_lit,
                        is_static,
                    });
                }
                ClassMember::Constant {
                    name: const_name,
                    value,
                    ..
                } => {
                    if let Some(l) = Self::try_expr_to_literal(value) {
                        metadata.constants.push((const_name.clone(), l));
                    }
                }
                ClassMember::TraitUse { traits, .. } => {
                    for trait_name in traits {
                        metadata
                            .traits
                            .push(self.qualify_name(&name_parts_to_string(&trait_name.parts)));
                    }
                }
                _ => {} // abstract methods, etc.
            }
        }

        // Store trait metadata for property/constant resolution
        self.op_array.class_metadata.insert(fq_name, metadata);
    }

    fn compile_enum_decl(
        &mut self,
        name: &str,
        implements: &[Name],
        members: &[EnumMember],
        span: &php_rs_lexer::Span,
    ) {
        let line = span.line as u32;
        let fq_name = self.qualify_name(name);
        let name_lit = self.op_array.add_literal(Literal::String(fq_name.clone()));

        // Encode implements info as "\0iface1\0iface2" in op2
        let mut class_info = String::new();
        for iface in implements {
            class_info.push('\0');
            class_info.push_str(&name_parts_to_string(&iface.parts));
        }
        let info_lit = self.op_array.add_literal(Literal::String(class_info));

        self.op_array.emit(
            ZOp::new(ZOpcode::DeclareClass, line)
                .with_op1(Operand::constant(name_lit), OperandType::Const)
                .with_op2(Operand::constant(info_lit), OperandType::Const)
                .with_extended_value(ZEND_ACC_ENUM),
        );

        // Set class context for self:: resolution
        self.current_class = Some(fq_name.clone());

        // Compile enum members
        let mut metadata = ClassMetadata::default();

        for member in members {
            match member {
                EnumMember::Case {
                    name: case_name,
                    value,
                    ..
                } => {
                    // Store enum case as a class constant
                    let lit = if let Some(val_expr) = value {
                        Self::try_expr_to_literal(val_expr)
                            .unwrap_or(Literal::String(case_name.clone()))
                    } else {
                        // Unit enum case — store name as value
                        Literal::String(case_name.clone())
                    };
                    metadata.constants.push((case_name.clone(), lit));
                }
                EnumMember::ClassMember(ClassMember::Method {
                    name: method_name,
                    params,
                    body: Some(method_body),
                    modifiers,
                    ..
                }) => {
                    let full_name = format!("{}::{}", fq_name, method_name);
                    let mut method_oa = ZOpArray::for_function(&full_name);
                    self.setup_params(&mut method_oa, params);
                    if !modifiers.contains(&Modifier::Static) {
                        method_oa.lookup_cv("this");
                    }

                    let mut sub = self.sub_compiler(method_oa);
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
                EnumMember::ClassMember(ClassMember::TraitUse { traits, .. }) => {
                    for trait_name in traits {
                        metadata
                            .traits
                            .push(self.qualify_name(&name_parts_to_string(&trait_name.parts)));
                    }
                }
                _ => {}
            }
        }

        self.op_array
            .class_metadata
            .insert(fq_name.clone(), metadata);
        self.current_class = None;
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

/// Compile a PHP source string with a known filename (for __FILE__ and __DIR__).
pub fn compile_file(source: &str, filename: &str) -> Result<ZOpArray, php_rs_parser::ParseError> {
    let mut parser = php_rs_parser::Parser::new(source);
    let program = parser.parse()?;
    let compiler = Compiler::with_filename(filename.to_string());
    let mut oa = compiler.compile_program(&program);
    oa.filename = Some(filename.to_string());
    Ok(oa)
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
        assert!(ops.contains(&ZOpcode::FetchClassConstant));
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

    // =========================================================================
    // 8.2.15: list() / array destructuring
    // =========================================================================

    #[test]
    fn test_compile_list_assignment() {
        let oa = compile_php("<?php list($a, $b) = [1, 2];");
        let ops = opcodes(&oa);
        // Should contain FetchDimR for reading indices from the array
        assert!(
            ops.contains(&ZOpcode::FetchDimR),
            "list() assignment should emit FetchDimR to read array elements"
        );
        // Should contain Assign for writing to the variables
        assert!(
            ops.contains(&ZOpcode::Assign),
            "list() assignment should emit Assign to write to variables"
        );
        // Should have CVs for $a and $b
        assert!(oa.vars.contains(&"a".to_string()));
        assert!(oa.vars.contains(&"b".to_string()));
    }

    #[test]
    fn test_compile_list_with_skip() {
        let oa = compile_php("<?php list($a, , $c) = [1, 2, 3];");
        let ops = opcodes(&oa);
        assert!(ops.contains(&ZOpcode::FetchDimR));
        assert!(ops.contains(&ZOpcode::Assign));
        assert!(oa.vars.contains(&"a".to_string()));
        assert!(oa.vars.contains(&"c".to_string()));
    }

    // =========================================================================
    // 8.3.5: unset($arr[$key]), unset($obj->prop)
    // =========================================================================

    #[test]
    fn test_compile_unset_array_element() {
        let oa = compile_php("<?php unset($arr[0]);");
        let ops = opcodes(&oa);
        assert!(
            ops.contains(&ZOpcode::UnsetDim),
            "unset($arr[$key]) should emit UnsetDim"
        );
    }

    #[test]
    fn test_compile_unset_object_property() {
        let oa = compile_php("<?php unset($obj->prop);");
        let ops = opcodes(&oa);
        assert!(
            ops.contains(&ZOpcode::UnsetObj),
            "unset($obj->prop) should emit UnsetObj"
        );
    }

    #[test]
    fn test_compile_unset_simple_variable() {
        let oa = compile_php("<?php unset($x);");
        let ops = opcodes(&oa);
        assert!(
            ops.contains(&ZOpcode::UnsetCv),
            "unset($x) should emit UnsetCv"
        );
    }

    // =========================================================================
    // 8.3.5: isset with multiple variables and array access
    // =========================================================================

    #[test]
    fn test_compile_isset_single() {
        let oa = compile_php("<?php echo isset($x);");
        let ops = opcodes(&oa);
        assert!(
            ops.contains(&ZOpcode::IssetIsemptyCv),
            "isset($x) should emit IssetIsemptyCv"
        );
    }

    #[test]
    fn test_compile_isset_multiple() {
        let oa = compile_php("<?php echo isset($a, $b, $c);");
        let ops = opcodes(&oa);
        // Should have multiple IssetIsemptyCv and JmpZ for short-circuit evaluation
        let isset_count = ops
            .iter()
            .filter(|&&o| o == ZOpcode::IssetIsemptyCv)
            .count();
        assert!(
            isset_count >= 3,
            "isset($a, $b, $c) should emit 3 IssetIsemptyCv opcodes, got {}",
            isset_count
        );
        assert!(
            ops.contains(&ZOpcode::Jmpz),
            "isset($a, $b, $c) should emit Jmpz for short-circuit"
        );
    }

    #[test]
    fn test_compile_isset_array_access() {
        let oa = compile_php("<?php echo isset($arr[0]);");
        let ops = opcodes(&oa);
        assert!(
            ops.contains(&ZOpcode::IssetIsemptyDimObj),
            "isset($arr[0]) should emit IssetIsemptyDimObj"
        );
    }
}
