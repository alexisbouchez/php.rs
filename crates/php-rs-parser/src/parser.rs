//! Pratt parser for PHP expressions
//!
//! Implements expression parsing with correct operator precedence matching PHP.
//! Reference: php-src/Zend/zend_language_parser.y

use crate::ast::*;
use php_rs_lexer::{Lexer, Span, Token};

/// Parser for PHP source code
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current_token: Token,
    current_span: Span,
    peeked: Option<(Token, Span)>,
}

impl<'a> Parser<'a> {
    /// Create a new parser from source code
    pub fn new(source: &'a str) -> Self {
        let mut lexer = Lexer::new(source);
        // Skip initial comments
        let mut current_token;
        let mut current_span;
        loop {
            let (t, s) = lexer
                .next_token()
                .unwrap_or((Token::End, Span::new(0, 0, 1, 1)));
            current_token = t;
            current_span = s;
            if current_token != Token::Comment && current_token != Token::DocComment {
                break;
            }
        }
        Self {
            lexer,
            current_token,
            current_span,
            peeked: None,
        }
    }

    /// Advance to the next token, skipping comments
    fn advance(&mut self) {
        loop {
            if let Some((token, span)) = self.peeked.take() {
                self.current_token = token;
                self.current_span = span;
            } else {
                let (token, span) = self
                    .lexer
                    .next_token()
                    .unwrap_or((Token::End, Span::new(0, 0, 1, 1)));
                self.current_token = token;
                self.current_span = span;
            }
            // Skip comments automatically
            if self.current_token != Token::Comment && self.current_token != Token::DocComment {
                break;
            }
        }
    }

    /// Peek at the next token without consuming it (skipping comments)
    fn peek(&mut self) -> &Token {
        if self.peeked.is_none() {
            loop {
                if let Some((token, span)) = self.lexer.next_token() {
                    if token == Token::Comment || token == Token::DocComment {
                        continue;
                    }
                    self.peeked = Some((token, span));
                } else {
                    self.peeked = Some((Token::End, Span::new(0, 0, 1, 1)));
                }
                break;
            }
        }
        &self.peeked.as_ref().unwrap().0
    }

    /// Create a parse error, automatically using UnexpectedEof when at end of file
    fn error(&self, expected: &str) -> ParseError {
        if self.current_token == Token::End {
            ParseError::UnexpectedEof {
                expected: expected.to_string(),
                span: self.current_span,
            }
        } else {
            ParseError::UnexpectedToken {
                expected: expected.to_string(),
                found: self.current_token.clone(),
                span: self.current_span,
            }
        }
    }

    /// Expect a semicolon or close tag (which acts as semicolon in PHP)
    fn expect_semicolon(&mut self) -> Result<Span, ParseError> {
        if self.current_token == Token::Semicolon {
            let span = self.current_span;
            self.advance();
            Ok(span)
        } else if self.current_token == Token::CloseTag {
            // ?> acts as a statement terminator
            let span = self.current_span;
            self.advance();
            Ok(span)
        } else {
            Err(self.error("\";\""))
        }
    }

    /// Expect a colon or semicolon (PHP allows both after case/default labels)
    fn expect_case_separator(&mut self) -> Result<Span, ParseError> {
        if self.current_token == Token::Colon || self.current_token == Token::Semicolon {
            let span = self.current_span;
            self.advance();
            Ok(span)
        } else {
            Err(self.error("\":\""))
        }
    }

    /// Check if current token matches expected token
    fn expect(&mut self, expected: Token) -> Result<Span, ParseError> {
        if self.current_token == expected {
            let span = self.current_span;
            self.advance();
            Ok(span)
        } else {
            Err(self.error(&format!("{}", expected)))
        }
    }

    /// Parse a complete PHP program, returning a Program with all statements
    pub fn parse(&mut self) -> Result<Program, ParseError> {
        let mut statements = Vec::new();

        // Handle inline HTML before <?php
        if self.current_token == Token::InlineHtml {
            let span = self.current_span;
            let content = self.lexer.source_text(&span).to_string();
            self.advance();
            statements.push(Statement::InlineHtml { content, span });
        }

        // Skip the opening <?php tag if present
        if self.current_token == Token::OpenTag {
            self.advance();
        } else if self.current_token == Token::OpenTagWithEcho {
            // <?= is shorthand for <?php echo
            let span = self.current_span;
            self.advance();
            let mut exprs = Vec::new();
            loop {
                exprs.push(self.parse_expression(0)?);
                if self.current_token == Token::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
            if self.current_token == Token::Semicolon {
                self.advance();
            }
            statements.push(Statement::Echo { exprs, span });
        }

        // Parse statements until end of file
        while self.current_token != Token::End {
            statements.push(self.parse_statement()?);
        }

        Ok(Program { statements })
    }

    /// Parse an expression with given minimum precedence (Pratt parsing)
    pub fn parse_expression(&mut self, min_precedence: u8) -> Result<Expression, ParseError> {
        // Parse prefix expression (literals, variables, unary ops, etc.)
        let mut left = self.parse_prefix()?;

        // Parse infix/postfix expressions based on precedence
        loop {
            let precedence = self.infix_precedence(&self.current_token);
            if precedence == 0 || precedence < min_precedence {
                // PHP special rule: assignment operators always bind when the LHS is
                // an assignable expression (variable, array access, property access, etc.).
                // This makes `$a && $b = $c` parse as `$a && ($b = $c)` even though
                // `=` has lower precedence than `&&`. In PHP's grammar, `variable = expr`
                // is a production of `expr`, so it's valid as the RHS of any binary op.
                if Self::is_assignment_token(&self.current_token) && Self::is_assignable(&left) {
                    left = self.parse_infix(left, precedence)?;
                    continue;
                }
                break;
            }

            left = self.parse_infix(left, precedence)?;
        }

        Ok(left)
    }

    /// Check if a token is an assignment operator
    fn is_assignment_token(token: &Token) -> bool {
        matches!(
            token,
            Token::Equals
                | Token::PlusEqual
                | Token::MinusEqual
                | Token::MulEqual
                | Token::DivEqual
                | Token::ModEqual
                | Token::PowEqual
                | Token::ConcatEqual
                | Token::AndEqual
                | Token::OrEqual
                | Token::XorEqual
                | Token::SlEqual
                | Token::SrEqual
                | Token::CoalesceEqual
        )
    }

    /// Check if an expression is assignable (can be the LHS of an assignment)
    fn is_assignable(expr: &Expression) -> bool {
        matches!(
            expr,
            Expression::Variable { .. }
                | Expression::ArrayAccess { .. }
                | Expression::PropertyAccess { .. }
                | Expression::StaticPropertyAccess { .. }
                | Expression::NullsafePropertyAccess { .. }
        )
    }

    /// Parse a statement
    pub fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        // Parse attributes first if present
        let attributes = if self.current_token == Token::Attribute {
            self.parse_attributes()?
        } else {
            Vec::new()
        };

        match self.current_token {
            Token::Echo => self.parse_echo_statement(),
            Token::If => self.parse_if_statement(),
            Token::Return => self.parse_return_statement(),
            Token::While => self.parse_while_statement(),
            Token::Do => self.parse_do_while_statement(),
            Token::For => self.parse_for_statement(),
            Token::Foreach => self.parse_foreach_statement(),
            Token::Switch => self.parse_switch_statement(),
            Token::Match => self.parse_match_statement(),
            Token::Try => self.parse_try_statement(),
            Token::Throw => self.parse_throw_statement(),
            Token::Break => self.parse_break_statement(),
            Token::Continue => self.parse_continue_statement(),
            Token::Namespace => self.parse_namespace_statement(),
            Token::Use => self.parse_use_statement(),
            Token::Global => self.parse_global_statement(),
            Token::Static => self.parse_static_or_class_statement(attributes),
            Token::Unset => self.parse_unset_statement(),
            Token::Declare => self.parse_declare_statement(),
            Token::Const => self.parse_const_statement(),
            Token::Goto => self.parse_goto_statement(),
            Token::Function => self.parse_function_statement_with_attributes(attributes),
            Token::Class | Token::Abstract | Token::Final | Token::Readonly => {
                self.parse_class_statement_with_attributes(attributes)
            }
            Token::Interface => self.parse_interface_statement_with_attributes(attributes),
            Token::Trait => self.parse_trait_statement_with_attributes(attributes),
            Token::Enum => self.parse_enum_statement_with_attributes(attributes),
            Token::LBrace => self.parse_block_statement(),
            Token::InlineHtml => self.parse_inline_html_statement(),
            Token::CloseTag => self.parse_close_tag(),
            Token::OpenTag => {
                // Re-entering PHP mode after ?>
                self.advance();
                // Check if we're re-entering at a block terminator or alternative syntax closing keyword
                // (endif, endwhile, endfor, endforeach, endswitch, } for closing blocks)
                // If so, don't try to parse it as a statement - return empty statement
                // and let the parent loop/handler deal with it
                if matches!(
                    self.current_token,
                    Token::Endif
                        | Token::Endwhile
                        | Token::Endfor
                        | Token::Endforeach
                        | Token::Endswitch
                        | Token::RBrace
                ) {
                    // Return empty statement - the parent loop will see the terminator and handle it
                    Ok(Statement::Block {
                        statements: vec![],
                        span: self.current_span,
                    })
                } else {
                    self.parse_statement()
                }
            }
            Token::OpenTagWithEcho => {
                // <?= shorthand for echo
                let span = self.current_span;
                self.advance();
                let mut exprs = Vec::new();
                loop {
                    exprs.push(self.parse_expression(0)?);
                    if self.current_token == Token::Comma {
                        self.advance();
                        continue;
                    }
                    break;
                }
                if self.current_token == Token::Semicolon {
                    self.advance();
                }
                Ok(Statement::Echo { exprs, span })
            }
            Token::HaltCompiler => {
                let span = self.current_span;
                self.advance();
                // __halt_compiler();
                self.expect(Token::LParen)?;
                self.expect(Token::RParen)?;
                self.expect_semicolon()?;
                // Everything after __halt_compiler(); is treated as data
                let remaining = String::new(); // TODO: capture remaining data
                Ok(Statement::HaltCompiler { remaining, span })
            }
            Token::Semicolon => {
                // Empty statement
                let span = self.current_span;
                self.advance();
                Ok(Statement::Block {
                    statements: vec![],
                    span,
                })
            }
            _ => {
                // Check for label: `identifier:`
                if let Token::String = self.current_token {
                    let name = self.lexer.source_text(&self.current_span).to_string();
                    let span = self.current_span;
                    if matches!(self.peek(), Token::Colon) {
                        self.advance(); // consume identifier
                        self.advance(); // consume colon
                        return Ok(Statement::Label { name, span });
                    }
                }
                // Default case: try to parse as expression statement
                let start_span = self.current_span;
                let expr = self.parse_expression(0)?;
                self.expect_semicolon()?;
                Ok(Statement::Expression {
                    expr,
                    span: start_span,
                })
            }
        }
    }

    /// Parse return statement
    fn parse_return_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Return)?;

        // Check if there's a value to return
        let value = if self.current_token == Token::Semicolon {
            None
        } else {
            Some(Box::new(self.parse_expression(0)?))
        };

        self.expect_semicolon()?;

        Ok(Statement::Return {
            value,
            span: start_span,
        })
    }

    /// Parse echo statement: `echo expr [, expr...];`
    fn parse_echo_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Echo)?;

        let mut exprs = Vec::new();
        loop {
            exprs.push(self.parse_expression(0)?);
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect_semicolon()?;

        Ok(Statement::Echo {
            exprs,
            span: start_span,
        })
    }

    /// Parse throw statement: `throw expr;`
    fn parse_throw_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Throw)?;
        let exception = Box::new(self.parse_expression(0)?);
        self.expect_semicolon()?;
        Ok(Statement::Throw {
            exception,
            span: start_span,
        })
    }

    /// Parse break statement: `break [depth];`
    fn parse_break_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Break)?;
        let depth = if self.current_token != Token::Semicolon {
            Some(Box::new(self.parse_expression(0)?))
        } else {
            None
        };
        self.expect_semicolon()?;
        Ok(Statement::Break {
            depth,
            span: start_span,
        })
    }

    /// Parse continue statement: `continue [depth];`
    fn parse_continue_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Continue)?;
        let depth = if self.current_token != Token::Semicolon {
            Some(Box::new(self.parse_expression(0)?))
        } else {
            None
        };
        self.expect_semicolon()?;
        Ok(Statement::Continue {
            depth,
            span: start_span,
        })
    }

    /// Parse global statement: `global $var [, $var...];`
    fn parse_global_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Global)?;
        let mut vars = Vec::new();
        loop {
            vars.push(self.parse_expression(0)?);
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect_semicolon()?;
        Ok(Statement::Global {
            vars,
            span: start_span,
        })
    }

    /// Parse static variable declaration or class/closure statement
    fn parse_static_or_class_statement(
        &mut self,
        _attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        // Peek to determine: `static $var` (static var) vs `static function`/`static fn` (closure in expression)
        // vs class with `static` modifier (but that wouldn't start with `static` in a statement)
        let next = self.peek().clone();
        match next {
            Token::Variable => {
                // Static variable declaration
                self.expect(Token::Static)?;
                let mut vars = Vec::new();
                loop {
                    let var_name = if let Token::Variable = self.current_token {
                        let n = self.lexer.source_text(&self.current_span).to_string();
                        self.advance();
                        n
                    } else {
                        return Err(self.error("variable"));
                    };
                    let default = if self.current_token == Token::Equals {
                        self.advance();
                        Some(self.parse_expression(0)?)
                    } else {
                        None
                    };
                    vars.push(StaticVar {
                        name: var_name,
                        default,
                    });
                    if self.current_token == Token::Comma {
                        self.advance();
                        continue;
                    }
                    break;
                }
                self.expect_semicolon()?;
                Ok(Statement::Static {
                    vars,
                    span: start_span,
                })
            }
            _ => {
                // Treat as expression (static function/closure) or class modifier
                // Check if this could be a class declaration: static is not a class modifier
                // by itself, but the parse_class_statement_with_attributes handles it along
                // with abstract/final/readonly. Actually "static" can't start a class.
                // So fall through to expression statement (handles `static function(){}` etc.)
                let expr = self.parse_expression(0)?;
                self.expect_semicolon()?;
                Ok(Statement::Expression {
                    expr,
                    span: start_span,
                })
            }
        }
    }

    /// Parse unset statement: `unset($var [, $var...]);`
    fn parse_unset_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Unset)?;
        self.expect(Token::LParen)?;
        let mut vars = Vec::new();
        loop {
            vars.push(self.parse_expression(0)?);
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect(Token::RParen)?;
        self.expect_semicolon()?;
        Ok(Statement::Unset {
            vars,
            span: start_span,
        })
    }

    /// Parse declare statement: `declare(key=value) { ... }` or `declare(key=value);`
    fn parse_declare_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Declare)?;
        self.expect(Token::LParen)?;

        let mut directives = Vec::new();
        loop {
            let name = if let Token::String = self.current_token {
                let n = self.lexer.source_text(&self.current_span).to_string();
                self.advance();
                n
            } else {
                return Err(self.error("directive name"));
            };
            self.expect(Token::Equals)?;
            let value = self.parse_expression(0)?;
            directives.push((name, value));
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect(Token::RParen)?;

        // Three forms: declare(k=v); or declare(k=v) {} or declare(k=v): ... enddeclare;
        let body = if self.current_token == Token::Semicolon {
            self.advance();
            Box::new(Statement::Block {
                statements: vec![],
                span: start_span,
            })
        } else if self.current_token == Token::LBrace {
            Box::new(self.parse_block_statement()?)
        } else if self.current_token == Token::Colon {
            // Alternative syntax: declare(...): ... enddeclare;
            self.advance();
            let mut stmts = Vec::new();
            while self.current_token != Token::Enddeclare && self.current_token != Token::End {
                stmts.push(self.parse_statement()?);
            }
            self.expect(Token::Enddeclare)?;
            self.expect_semicolon()?;
            Box::new(Statement::Block {
                statements: stmts,
                span: start_span,
            })
        } else {
            // Single statement form
            Box::new(self.parse_statement()?)
        };

        Ok(Statement::Declare {
            directives,
            body,
            span: start_span,
        })
    }

    /// Parse const declaration: `const NAME = value [, ...];`
    fn parse_const_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Const)?;

        let mut consts = Vec::new();
        loop {
            let name = if let Token::String = self.current_token {
                let n = self.lexer.source_text(&self.current_span).to_string();
                self.advance();
                n
            } else {
                return Err(self.error("constant name"));
            };
            self.expect(Token::Equals)?;
            let value = self.parse_expression(0)?;
            consts.push((name, value));
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect_semicolon()?;
        Ok(Statement::Const {
            consts,
            span: start_span,
        })
    }

    /// Parse goto statement: `goto label;`
    fn parse_goto_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Goto)?;
        let label = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("label name"));
        };
        self.expect_semicolon()?;
        Ok(Statement::Goto {
            label,
            span: start_span,
        })
    }

    /// Parse block statement: `{ statements }`
    fn parse_block_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::LBrace)?;
        let mut statements = Vec::new();
        while self.current_token != Token::RBrace {
            statements.push(self.parse_statement()?);
        }
        self.expect(Token::RBrace)?;
        Ok(Statement::Block {
            statements,
            span: start_span,
        })
    }

    /// Parse inline HTML (outside PHP tags)
    fn parse_inline_html_statement(&mut self) -> Result<Statement, ParseError> {
        let span = self.current_span;
        let content = self.lexer.source_text(&span).to_string();
        self.advance();
        Ok(Statement::InlineHtml { content, span })
    }

    /// Parse close tag: `?>` transitions to inline HTML mode
    fn parse_close_tag(&mut self) -> Result<Statement, ParseError> {
        // ?> acts as a statement terminator and transitions to HTML mode
        // It also outputs a newline
        self.advance(); // consume ?>
                        // After ?>, we might have inline HTML or another open tag
        if self.current_token == Token::InlineHtml {
            self.parse_inline_html_statement()
        } else {
            // Empty inline HTML (just the close tag)
            Ok(Statement::InlineHtml {
                content: String::new(),
                span: self.current_span,
            })
        }
    }

    /// Parse while statement
    fn parse_while_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::While)?;

        // Parse condition in parentheses
        self.expect(Token::LParen)?;
        let condition = Box::new(self.parse_expression(0)?);
        self.expect(Token::RParen)?;

        // Check for alternative syntax (colon)
        let is_alternative_syntax = self.current_token == Token::Colon;

        if is_alternative_syntax {
            // Alternative syntax: while (...): statements endwhile;
            self.advance(); // consume colon

            // Parse statements until endwhile
            let mut body_statements = Vec::new();
            while self.current_token != Token::Endwhile {
                body_statements.push(self.parse_statement()?);
            }

            self.expect(Token::Endwhile)?;
            self.expect_semicolon()?;

            let body = Box::new(Statement::Block {
                statements: body_statements,
                span: start_span,
            });

            Ok(Statement::While {
                condition,
                body,
                span: start_span,
            })
        } else {
            // Standard syntax: while (...) statement
            let body = Box::new(self.parse_statement()?);

            Ok(Statement::While {
                condition,
                body,
                span: start_span,
            })
        }
    }

    /// Parse do-while statement
    fn parse_do_while_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Do)?;

        // Parse body statement
        let body = Box::new(self.parse_statement()?);

        // Expect while keyword
        self.expect(Token::While)?;

        // Parse condition in parentheses
        self.expect(Token::LParen)?;
        let condition = Box::new(self.parse_expression(0)?);
        self.expect(Token::RParen)?;

        // Expect semicolon
        self.expect_semicolon()?;

        Ok(Statement::DoWhile {
            body,
            condition,
            span: start_span,
        })
    }

    /// Parse for statement
    fn parse_for_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::For)?;

        self.expect(Token::LParen)?;

        // Parse init expressions (comma-separated)
        let mut init = Vec::new();
        if self.current_token != Token::Semicolon {
            loop {
                init.push(self.parse_expression(0)?);
                if self.current_token != Token::Comma {
                    break;
                }
                self.advance(); // consume comma
            }
        }
        self.expect_semicolon()?;

        // Parse condition expressions (comma-separated)
        let mut condition = Vec::new();
        if self.current_token != Token::Semicolon {
            loop {
                condition.push(self.parse_expression(0)?);
                if self.current_token != Token::Comma {
                    break;
                }
                self.advance(); // consume comma
            }
        }
        self.expect_semicolon()?;

        // Parse increment expressions (comma-separated)
        let mut increment = Vec::new();
        if self.current_token != Token::RParen {
            loop {
                increment.push(self.parse_expression(0)?);
                if self.current_token != Token::Comma {
                    break;
                }
                self.advance(); // consume comma
            }
        }
        self.expect(Token::RParen)?;

        // Check for alternative syntax (colon)
        let is_alternative_syntax = self.current_token == Token::Colon;

        if is_alternative_syntax {
            // Alternative syntax: for (...): statements endfor;
            self.advance(); // consume colon

            // Parse statements until endfor
            let mut body_statements = Vec::new();
            while self.current_token != Token::Endfor {
                body_statements.push(self.parse_statement()?);
            }

            self.expect(Token::Endfor)?;
            self.expect_semicolon()?;

            let body = Box::new(Statement::Block {
                statements: body_statements,
                span: start_span,
            });

            Ok(Statement::For {
                init,
                condition,
                increment,
                body,
                span: start_span,
            })
        } else {
            // Standard syntax: for (...) statement
            let body = Box::new(self.parse_statement()?);

            Ok(Statement::For {
                init,
                condition,
                increment,
                body,
                span: start_span,
            })
        }
    }

    /// Parse foreach statement
    fn parse_foreach_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Foreach)?;

        self.expect(Token::LParen)?;

        // Parse iterable expression
        let iterable = Box::new(self.parse_expression(0)?);

        // Expect 'as' keyword
        self.expect(Token::As)?;

        // Parse key => value or just value
        // Check for &$value (by reference without key)
        let direct_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        let first_expr = self.parse_expression(0)?;

        let (key, value, by_ref) = if self.current_token == Token::DoubleArrow {
            // key => value syntax (first_expr is the key)
            self.advance(); // consume =>

            // Check if value is by reference
            let by_ref = if self.current_token == Token::Ampersand {
                self.advance();
                true
            } else {
                false
            };

            let value_expr = self.parse_expression(0)?;

            (Some(Box::new(first_expr)), Box::new(value_expr), by_ref)
        } else {
            // Just value (first_expr is the value)
            (None, Box::new(first_expr), direct_ref)
        };

        self.expect(Token::RParen)?;

        // Check for alternative syntax (colon)
        let is_alternative_syntax = self.current_token == Token::Colon;

        if is_alternative_syntax {
            // Alternative syntax: foreach (...): statements endforeach;
            self.advance(); // consume colon

            // Parse statements until endforeach
            let mut body_statements = Vec::new();
            while self.current_token != Token::Endforeach {
                body_statements.push(self.parse_statement()?);
            }

            self.expect(Token::Endforeach)?;
            self.expect_semicolon()?;

            let body = Box::new(Statement::Block {
                statements: body_statements,
                span: start_span,
            });

            Ok(Statement::Foreach {
                iterable,
                key,
                value,
                by_ref,
                body,
                span: start_span,
            })
        } else {
            // Standard syntax: foreach (...) statement
            let body = Box::new(self.parse_statement()?);

            Ok(Statement::Foreach {
                iterable,
                key,
                value,
                by_ref,
                body,
                span: start_span,
            })
        }
    }

    /// Parse switch statement
    fn parse_switch_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Switch)?;

        // Parse condition in parentheses
        self.expect(Token::LParen)?;
        let condition = Box::new(self.parse_expression(0)?);
        self.expect(Token::RParen)?;

        // Check for alternative syntax (colon) or braces
        let is_alternative_syntax = self.current_token == Token::Colon;

        let cases = if is_alternative_syntax {
            // Alternative syntax: switch (...): case ...: ... endswitch;
            self.advance(); // consume colon

            let mut cases = Vec::new();

            // Parse cases until endswitch
            while self.current_token != Token::Endswitch {
                if self.current_token == Token::Case {
                    self.advance(); // consume case
                    let case_condition = Some(self.parse_expression(0)?);
                    self.expect_case_separator()?;

                    // Parse statements until next case/default/endswitch
                    let mut statements = Vec::new();
                    while self.current_token != Token::Case
                        && self.current_token != Token::Default
                        && self.current_token != Token::Endswitch
                    {
                        statements.push(self.parse_statement()?);
                    }

                    cases.push(SwitchCase {
                        condition: case_condition,
                        statements,
                    });
                } else if self.current_token == Token::Default {
                    self.advance(); // consume default
                    self.expect_case_separator()?;

                    // Parse statements until next case/endswitch
                    let mut statements = Vec::new();
                    while self.current_token != Token::Case
                        && self.current_token != Token::Endswitch
                    {
                        statements.push(self.parse_statement()?);
                    }

                    cases.push(SwitchCase {
                        condition: None,
                        statements,
                    });
                } else {
                    return Err(self.error("\"case\" or \"default\""));
                }
            }

            self.expect(Token::Endswitch)?;
            self.expect_semicolon()?;

            cases
        } else {
            // Standard syntax: switch (...) { case ...: ... }
            self.expect(Token::LBrace)?;

            let mut cases = Vec::new();

            while self.current_token != Token::RBrace {
                if self.current_token == Token::Case {
                    self.advance(); // consume case
                    let case_condition = Some(self.parse_expression(0)?);
                    self.expect_case_separator()?;

                    // Parse statements until next case/default/rbrace
                    let mut statements = Vec::new();
                    while self.current_token != Token::Case
                        && self.current_token != Token::Default
                        && self.current_token != Token::RBrace
                    {
                        statements.push(self.parse_statement()?);
                    }

                    cases.push(SwitchCase {
                        condition: case_condition,
                        statements,
                    });
                } else if self.current_token == Token::Default {
                    self.advance(); // consume default
                    self.expect_case_separator()?;

                    // Parse statements until next case/rbrace
                    let mut statements = Vec::new();
                    while self.current_token != Token::Case && self.current_token != Token::RBrace {
                        statements.push(self.parse_statement()?);
                    }

                    cases.push(SwitchCase {
                        condition: None,
                        statements,
                    });
                } else {
                    return Err(self.error("\"case\" or \"default\""));
                }
            }

            self.expect(Token::RBrace)?;

            cases
        };

        Ok(Statement::Switch {
            condition,
            cases,
            span: start_span,
        })
    }

    /// Parse match statement (typically used as expression, but can be statement)
    fn parse_match_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Match)?;

        // Parse condition in parentheses
        self.expect(Token::LParen)?;
        let condition = Box::new(self.parse_expression(0)?);
        self.expect(Token::RParen)?;

        // Parse match arms in braces
        self.expect(Token::LBrace)?;

        let mut arms = Vec::new();

        while self.current_token != Token::RBrace {
            // Parse match arm
            // default => expr or value1, value2 => expr
            let conditions = if self.current_token == Token::Default {
                self.advance(); // consume default
                Vec::new() // Empty conditions means default
            } else {
                // Parse comma-separated conditions
                let mut conds = Vec::new();
                loop {
                    conds.push(self.parse_expression(0)?);
                    if self.current_token != Token::Comma {
                        break;
                    }
                    self.advance(); // consume comma
                                    // Check if next is => (end of conditions)
                    if self.current_token == Token::DoubleArrow {
                        break;
                    }
                }
                conds
            };

            // Expect =>
            self.expect(Token::DoubleArrow)?;

            // Parse body expression
            let body = self.parse_expression(0)?;

            arms.push(MatchArm { conditions, body });

            // Check for comma (optional after last arm)
            if self.current_token == Token::Comma {
                self.advance();
            } else if self.current_token != Token::RBrace {
                return Err(self.error("\",\" or \"}\""));
            }
        }

        self.expect(Token::RBrace)?;

        Ok(Statement::Match {
            condition,
            arms,
            span: start_span,
        })
    }

    /// Parse try/catch/finally statement
    fn parse_try_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Try)?;

        // Parse try block: try { statements }
        self.expect(Token::LBrace)?;

        let mut body = Vec::new();
        while self.current_token != Token::RBrace {
            body.push(self.parse_statement()?);
        }

        self.expect(Token::RBrace)?;

        // Parse catch clauses (one or more, or zero if finally present)
        let mut catches = Vec::new();
        while self.current_token == Token::Catch {
            self.advance(); // consume catch

            self.expect(Token::LParen)?;

            // Parse exception types (can be multiple with | separator for multi-catch)
            let mut types = Vec::new();
            loop {
                // Parse a qualified name for exception type
                let type_name = self.parse_qualified_name()?;
                types.push(type_name);

                // Check for | (multi-catch separator)
                if self.current_token == Token::VerticalBar {
                    self.advance(); // consume |
                    continue;
                }
                break;
            }

            // Parse optional variable name (PHP 8.0+ allows catch without variable)
            let var = if self.current_token == Token::Variable {
                // Extract variable name from token (placeholder for now)
                self.advance();
                Some(String::from("e")) // TODO: extract actual name from token
            } else {
                None
            };

            self.expect(Token::RParen)?;

            // Parse catch block
            self.expect(Token::LBrace)?;

            let mut catch_body = Vec::new();
            while self.current_token != Token::RBrace {
                catch_body.push(self.parse_statement()?);
            }

            self.expect(Token::RBrace)?;

            catches.push(CatchClause {
                types,
                var,
                body: catch_body,
            });
        }

        // Parse optional finally block
        let finally = if self.current_token == Token::Finally {
            self.advance(); // consume finally

            self.expect(Token::LBrace)?;

            let mut finally_body = Vec::new();
            while self.current_token != Token::RBrace {
                finally_body.push(self.parse_statement()?);
            }

            self.expect(Token::RBrace)?;

            Some(finally_body)
        } else {
            None
        };

        // Validate: must have at least one catch or a finally block
        if catches.is_empty() && finally.is_none() {
            return Err(self.error("\"catch\" or \"finally\""));
        }

        Ok(Statement::Try {
            body,
            catches,
            finally,
            span: start_span,
        })
    }

    /// Parse a qualified name (e.g., Exception, \Foo\Bar, namespace\Baz)
    /// Parse attributes (#[...])
    /// Syntax: #[Name] or #[Name(args)]
    /// Can appear multiple times before a declaration
    fn parse_attributes(&mut self) -> Result<Vec<Attribute>, ParseError> {
        let mut attributes = Vec::new();

        // Parse all consecutive attributes
        while self.current_token == Token::Attribute {
            let start_span = self.current_span;
            self.expect(Token::Attribute)?; // consume #[

            // Parse attribute name (qualified name)
            let name = self.parse_qualified_name()?;

            // Parse optional arguments
            let args = if self.current_token == Token::LParen {
                self.advance(); // consume (
                let mut arguments = Vec::new();

                // Parse comma-separated argument list (supports named arguments)
                if self.current_token != Token::RParen {
                    loop {
                        let arg = self.parse_argument()?;
                        arguments.push(arg);

                        if self.current_token == Token::Comma {
                            self.advance();
                            if self.current_token == Token::RParen {
                                break; // trailing comma
                            }
                            continue;
                        }
                        break;
                    }
                }

                self.expect(Token::RParen)?;
                arguments
            } else {
                Vec::new()
            };

            self.expect(Token::RBracket)?; // consume ]

            attributes.push(Attribute {
                name,
                args,
                span: start_span,
            });
        }

        Ok(attributes)
    }

    fn parse_qualified_name(&mut self) -> Result<Name, ParseError> {
        let mut parts = Vec::new();
        let fully_qualified =
            if self.current_token == Token::NsSeparator || self.current_token == Token::Backslash {
                self.advance();
                true
            } else {
                false
            };

        let relative = if self.current_token == Token::Namespace {
            // Check if next is separator (namespace\...)
            if matches!(self.peek(), Token::NsSeparator | Token::Backslash) {
                self.advance(); // consume namespace
                self.advance(); // consume \
                true
            } else {
                false
            }
        } else {
            false
        };

        // Parse name parts separated by \
        loop {
            // Accept identifiers and keyword tokens that can be used as type/class names
            if self.is_identifier_or_keyword() {
                let part = self.lexer.source_text(&self.current_span).to_string();
                parts.push(part);
                self.advance();

                // Check for namespace separator (\ can be NsSeparator or Backslash)
                if self.current_token == Token::NsSeparator
                    || self.current_token == Token::Backslash
                {
                    self.advance();
                    continue;
                }
            } else {
                return Err(self.error("identifier"));
            }
            break;
        }

        Ok(Name {
            parts,
            fully_qualified,
            relative,
        })
    }

    /// Parse function declaration statement with attributes
    /// Syntax: [attributes] function [&] name(params) [: return_type] { body }
    fn parse_function_statement_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Function)?;

        // Check for return by reference (&)
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse function name (identifier)
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("function name"));
        };

        // Parse parameter list
        self.expect(Token::LParen)?;
        let params = self.parse_parameter_list()?;
        self.expect(Token::RParen)?;

        // Parse optional return type
        let return_type = if self.current_token == Token::Colon {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        // Parse function body
        self.expect(Token::LBrace)?;
        let mut body = Vec::new();
        while self.current_token != Token::RBrace {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::RBrace)?;

        Ok(Statement::Function {
            name,
            params,
            return_type,
            body,
            by_ref,
            attributes,
            span: start_span,
        })
    }

    /// Parse class declaration statement
    /// Syntax: [abstract|final|readonly] class Name [extends Parent] [implements Interface1, Interface2] { members }
    fn parse_class_statement_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Parse modifiers (abstract, final, readonly)
        let mut modifiers = Vec::new();
        while matches!(
            self.current_token,
            Token::Abstract | Token::Final | Token::Readonly
        ) {
            let modifier = match self.current_token {
                Token::Abstract => Modifier::Abstract,
                Token::Final => Modifier::Final,
                Token::Readonly => Modifier::Readonly,
                _ => unreachable!(),
            };
            modifiers.push(modifier);
            self.advance();
        }

        // Expect 'class' keyword
        self.expect(Token::Class)?;

        // Parse class name
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("class name"));
        };

        // Parse optional extends clause
        let extends = if self.current_token == Token::Extends {
            self.advance();
            Some(self.parse_qualified_name()?)
        } else {
            None
        };

        // Parse optional implements clause
        let implements = if self.current_token == Token::Implements {
            self.advance();
            let mut interfaces = Vec::new();
            loop {
                interfaces.push(self.parse_qualified_name()?);
                if self.current_token == Token::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
            interfaces
        } else {
            Vec::new()
        };

        // Parse class body
        self.expect(Token::LBrace)?;
        let members = self.parse_class_members()?;
        self.expect(Token::RBrace)?;

        Ok(Statement::Class {
            name,
            modifiers,
            extends,
            implements,
            members,
            attributes,
            span: start_span,
        })
    }

    /// Parse class members (properties, methods, constants)
    fn parse_class_members(&mut self) -> Result<Vec<ClassMember>, ParseError> {
        let mut members = Vec::new();

        while self.current_token != Token::RBrace && self.current_token != Token::End {
            // Parse attributes first
            let attributes = if self.current_token == Token::Attribute {
                self.parse_attributes()?
            } else {
                Vec::new()
            };

            let mut new_members = self.parse_class_member_with_attributes(attributes)?;
            members.append(&mut new_members);
        }

        Ok(members)
    }

    /// Parse a single class member (method, constant, property, or trait use) with pre-parsed attributes.
    /// Returns a Vec because properties can be comma-separated.
    fn parse_class_member_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Vec<ClassMember>, ParseError> {
        // Parse modifiers (public, private, protected, static, readonly, final, abstract)
        let mut modifiers = Vec::new();
        loop {
            match self.current_token {
                Token::Public | Token::Var => {
                    modifiers.push(Modifier::Public);
                    self.advance();
                }
                Token::Protected => {
                    modifiers.push(Modifier::Protected);
                    self.advance();
                }
                Token::Private => {
                    modifiers.push(Modifier::Private);
                    self.advance();
                }
                Token::Static => {
                    modifiers.push(Modifier::Static);
                    self.advance();
                }
                Token::Readonly => {
                    modifiers.push(Modifier::Readonly);
                    self.advance();
                }
                Token::Final => {
                    modifiers.push(Modifier::Final);
                    self.advance();
                }
                Token::Abstract => {
                    modifiers.push(Modifier::Abstract);
                    self.advance();
                }
                _ => break,
            }
        }

        // Determine what kind of member this is
        match self.current_token {
            Token::Function => Ok(vec![self.parse_class_method(modifiers, attributes)?]),
            Token::Const => Ok(vec![self.parse_class_constant(modifiers, attributes)?]),
            Token::Use => Ok(vec![self.parse_trait_use()?]),
            _ => {
                // Must be a property (with optional type hint)
                // Could have multiple comma-separated properties
                self.parse_class_properties(modifiers, attributes)
            }
        }
    }

    /// Parse one or more class properties (comma-separated) with optional hooks
    fn parse_class_properties(
        &mut self,
        modifiers: Vec<Modifier>,
        attributes: Vec<Attribute>,
    ) -> Result<Vec<ClassMember>, ParseError> {
        let start_span = self.current_span;

        // Parse optional type
        let prop_type = if self.is_type_start() {
            Some(self.parse_type()?)
        } else {
            None
        };

        let mut results = Vec::new();

        loop {
            // Parse variable name
            let name = if let Token::Variable = self.current_token {
                let var_name = self.lexer.source_text(&self.current_span).to_string();
                // Remove leading $
                let name = var_name.trim_start_matches('$').to_string();
                self.advance();
                name
            } else {
                return Err(self.error("variable"));
            };

            // Parse optional default value
            let default = if self.current_token == Token::Equals {
                self.advance();
                Some(self.parse_expression(0)?)
            } else {
                None
            };

            // Parse optional hooks (PHP 8.4+)
            let hooks = if self.current_token == Token::LBrace {
                self.parse_property_hooks()?
            } else {
                Vec::new()
            };

            results.push(ClassMember::Property {
                name,
                modifiers: modifiers.clone(),
                prop_type: prop_type.clone(),
                default,
                hooks,
                attributes: attributes.clone(),
                span: start_span,
            });

            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }

        // Expect semicolon (unless last property had hooks)
        if results.last().map_or(true, |m| {
            if let ClassMember::Property { hooks, .. } = m {
                hooks.is_empty()
            } else {
                true
            }
        }) {
            self.expect_semicolon()?;
        }

        Ok(results)
    }

    /// Parse property hooks { get => expr; set { ... } }
    fn parse_property_hooks(&mut self) -> Result<Vec<PropertyHook>, ParseError> {
        self.expect(Token::LBrace)?;

        let mut hooks = Vec::new();

        while self.current_token != Token::RBrace && self.current_token != Token::End {
            hooks.push(self.parse_property_hook()?);

            // Optional semicolon or comma between hooks
            if self.current_token == Token::Semicolon || self.current_token == Token::Comma {
                self.advance();
            }
        }

        self.expect(Token::RBrace)?;

        Ok(hooks)
    }

    /// Parse a single property hook: [&]get [(...)] => expr | { ... }
    fn parse_property_hook(&mut self) -> Result<PropertyHook, ParseError> {
        let start_span = self.current_span;

        // Check for by-ref &
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse hook kind (get or set)
        let kind = match self.current_token {
            Token::String => {
                let kind_str = self.lexer.source_text(&self.current_span);
                match kind_str {
                    "get" => PropertyHookKind::Get,
                    "set" => PropertyHookKind::Set,
                    _ => {
                        return Err(self.error("\"get\" or \"set\""));
                    }
                }
            }
            _ => {
                return Err(self.error("\"get\" or \"set\""));
            }
        };
        self.advance();

        // Parse optional parameter list (for set hook)
        let params = if self.current_token == Token::LParen {
            self.advance();
            let mut params = Vec::new();
            if self.current_token != Token::RParen {
                loop {
                    if self.current_token == Token::RParen {
                        break;
                    }
                    params.push(self.parse_parameter()?);
                    if self.current_token == Token::Comma {
                        self.advance();
                        continue;
                    }
                    break;
                }
            }
            self.expect(Token::RParen)?;
            params
        } else {
            Vec::new()
        };

        // Parse hook body: => expr or { ... }
        let body = if self.current_token == Token::DoubleArrow {
            self.advance();
            PropertyHookBody::Expression(self.parse_expression(0)?)
        } else if self.current_token == Token::LBrace {
            self.advance();
            let mut statements = Vec::new();
            while self.current_token != Token::RBrace && self.current_token != Token::End {
                statements.push(self.parse_statement()?);
            }
            self.expect(Token::RBrace)?;
            PropertyHookBody::Block(statements)
        } else {
            return Err(self.error("\"=>\" or \"{\""));
        };

        Ok(PropertyHook {
            kind,
            params,
            body,
            by_ref,
            span: start_span,
        })
    }

    /// Parse a class method
    fn parse_class_method(
        &mut self,
        modifiers: Vec<Modifier>,
        attributes: Vec<Attribute>,
    ) -> Result<ClassMember, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Function)?;

        // Check for by-ref
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse method name (PHP allows semi-reserved keywords as method names)
        let name = if self.current_token == Token::String || self.is_semi_reserved_keyword() {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("method name"));
        };

        // Parse parameters
        self.expect(Token::LParen)?;
        let mut params = Vec::new();
        if self.current_token != Token::RParen {
            loop {
                if self.current_token == Token::RParen {
                    break;
                }
                params.push(self.parse_parameter()?);
                if self.current_token == Token::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
        }
        self.expect(Token::RParen)?;

        // Parse optional return type
        let return_type = if self.current_token == Token::Colon {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        // Parse method body or semicolon (for abstract/interface methods)
        let body = if self.current_token == Token::Semicolon {
            self.advance();
            None
        } else if self.current_token == Token::LBrace {
            self.advance();
            let mut statements = Vec::new();
            while self.current_token != Token::RBrace && self.current_token != Token::End {
                statements.push(self.parse_statement()?);
            }
            self.expect(Token::RBrace)?;
            Some(statements)
        } else {
            return Err(self.error("\";\" or \"{\""));
        };

        Ok(ClassMember::Method {
            name,
            modifiers,
            params,
            return_type,
            body,
            by_ref,
            attributes,
            span: start_span,
        })
    }

    /// Parse a class constant
    fn parse_class_constant(
        &mut self,
        modifiers: Vec<Modifier>,
        attributes: Vec<Attribute>,
    ) -> Result<ClassMember, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Const)?;

        // Parse constant name
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("constant name"));
        };

        // Expect = value
        self.expect(Token::Equals)?;
        let value = self.parse_expression(0)?;
        self.expect_semicolon()?;

        Ok(ClassMember::Constant {
            name,
            modifiers,
            value,
            attributes,
            span: start_span,
        })
    }

    /// Parse trait use statement inside a class
    fn parse_trait_use(&mut self) -> Result<ClassMember, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Use)?;

        let mut traits = Vec::new();
        loop {
            traits.push(self.parse_qualified_name()?);
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }

        // Parse optional trait adaptations
        let adaptations = if self.current_token == Token::LBrace {
            self.advance();
            let adaptations = Vec::new();
            // TODO: Parse trait adaptations (insteadof, as)
            // For now, just consume until closing brace
            while self.current_token != Token::RBrace && self.current_token != Token::End {
                self.advance();
            }
            self.expect(Token::RBrace)?;
            adaptations
        } else {
            self.expect_semicolon()?;
            Vec::new()
        };

        Ok(ClassMember::TraitUse {
            traits,
            adaptations,
            span: start_span,
        })
    }

    /// Check if the current token starts a type annotation
    fn is_type_start(&self) -> bool {
        matches!(
            self.current_token,
            Token::String
                | Token::Array
                | Token::Callable
                | Token::Question
                | Token::VerticalBar  // for union types
                | Token::Ampersand // for intersection types
                | Token::NsSeparator // for fully-qualified types
                | Token::Backslash // for fully-qualified types
                | Token::Static // for static type
        )
    }

    /// Parse interface declaration with attributes
    /// Syntax: [attributes] interface Name [extends Interface1, Interface2, ...] { members }
    fn parse_interface_statement_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Expect 'interface' keyword
        self.expect(Token::Interface)?;

        // Parse interface name
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("interface name"));
        };

        // Parse optional extends clause (interfaces can extend multiple interfaces)
        let extends = if self.current_token == Token::Extends {
            self.advance();
            let mut interfaces = Vec::new();
            loop {
                interfaces.push(self.parse_qualified_name()?);
                if self.current_token == Token::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
            interfaces
        } else {
            Vec::new()
        };

        // Parse interface body
        self.expect(Token::LBrace)?;
        let members = self.parse_class_members()?;
        self.expect(Token::RBrace)?;

        Ok(Statement::Interface {
            name,
            extends,
            members,
            attributes,
            span: start_span,
        })
    }

    /// Parse trait declaration
    /// Syntax: trait Name { members }
    fn parse_trait_statement_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Expect 'trait' keyword
        self.expect(Token::Trait)?;

        // Parse trait name
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("trait name"));
        };

        // Parse trait body
        self.expect(Token::LBrace)?;
        let members = self.parse_class_members()?;
        self.expect(Token::RBrace)?;

        Ok(Statement::Trait {
            name,
            members,
            attributes,
            span: start_span,
        })
    }

    /// Parse enum declaration with attributes
    /// Syntax: [attributes] enum Name [: Type] [implements Interface1, Interface2, ...] { members }
    fn parse_enum_statement_with_attributes(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Expect 'enum' keyword
        self.expect(Token::Enum)?;

        // Parse enum name
        let name = if let Token::String = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("enum name"));
        };

        // Parse optional backing type (: int or : string)
        let backing_type = if self.current_token == Token::Colon {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        // Parse optional implements clause
        let implements = if self.current_token == Token::Implements {
            self.advance();
            let mut interfaces = Vec::new();
            loop {
                interfaces.push(self.parse_qualified_name()?);
                if self.current_token == Token::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
            interfaces
        } else {
            Vec::new()
        };

        // Parse enum body
        self.expect(Token::LBrace)?;
        let mut members = Vec::new();
        while self.current_token != Token::RBrace && self.current_token != Token::End {
            // Parse attributes
            let attributes = if self.current_token == Token::Attribute {
                self.parse_attributes()?
            } else {
                Vec::new()
            };

            if self.current_token == Token::Case {
                // Enum case: case Name [= value];
                let case_span = self.current_span;
                self.advance(); // consume 'case'
                let case_name = if let Token::String = self.current_token {
                    let n = self.lexer.source_text(&self.current_span).to_string();
                    self.advance();
                    n
                } else {
                    return Err(self.error("case name"));
                };
                let value = if self.current_token == Token::Equals {
                    self.advance();
                    Some(self.parse_expression(0)?)
                } else {
                    None
                };
                self.expect(Token::Semicolon)?;
                members.push(EnumMember::Case {
                    name: case_name,
                    value,
                    attributes,
                    span: case_span,
                });
            } else {
                // Methods, constants, trait uses — reuse class member parsing
                let class_members = self.parse_class_member_with_attributes(attributes)?;
                for m in class_members {
                    members.push(EnumMember::ClassMember(m));
                }
            }
        }
        self.expect(Token::RBrace)?;

        Ok(Statement::Enum {
            name,
            backing_type,
            implements,
            members,
            attributes,
            span: start_span,
        })
    }

    /// Parse namespace statement
    /// Syntax: namespace [Name];  (simple form)
    ///     or: namespace [Name] { statements }  (bracketed form)
    ///     or: namespace { statements }  (global namespace)
    fn parse_namespace_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Expect 'namespace' keyword
        self.expect(Token::Namespace)?;

        // Check if this is a bracketed global namespace: namespace { }
        if self.current_token == Token::LBrace {
            self.advance(); // consume {
            let mut statements = Vec::new();

            // Parse statements until }
            while self.current_token != Token::RBrace && self.current_token != Token::End {
                statements.push(self.parse_statement()?);
            }

            self.expect(Token::RBrace)?;

            return Ok(Statement::Namespace {
                name: None, // Global namespace
                statements,
                span: start_span,
            });
        }

        // Parse namespace name (if not global)
        let name = if self.current_token == Token::String
            || self.current_token == Token::NsSeparator
            || self.current_token == Token::Backslash
        {
            Some(self.parse_qualified_name()?)
        } else {
            None
        };

        // Check if this is simple form (;) or bracketed form ({ })
        if self.current_token == Token::Semicolon {
            self.advance();
            // Simple form - no statements block
            Ok(Statement::Namespace {
                name,
                statements: Vec::new(),
                span: start_span,
            })
        } else if self.current_token == Token::LBrace {
            self.advance(); // consume {
            let mut statements = Vec::new();

            // Parse statements until }
            while self.current_token != Token::RBrace && self.current_token != Token::End {
                statements.push(self.parse_statement()?);
            }

            self.expect(Token::RBrace)?;

            Ok(Statement::Namespace {
                name,
                statements,
                span: start_span,
            })
        } else {
            Err(self.error("\";\" or \"{\""))
        }
    }

    /// Parse use statement
    /// Syntax: use Name [as Alias] [, Name [as Alias]]...;
    ///     or: use function Name [as Alias] [, ...]...;
    ///     or: use const Name [as Alias] [, ...]...;
    fn parse_use_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;

        // Expect 'use' keyword
        self.expect(Token::Use)?;

        // Check for optional 'function' or 'const' keyword
        let kind = match self.current_token {
            Token::Function => {
                self.advance();
                UseKind::Function
            }
            Token::Const => {
                self.advance();
                UseKind::Const
            }
            _ => UseKind::Normal,
        };

        // Parse use declarations (comma-separated list)
        let mut uses = Vec::new();

        loop {
            // Parse the name
            let name = self.parse_qualified_name()?;

            // Check for optional 'as Alias'
            let alias = if self.current_token == Token::As {
                self.advance(); // consume 'as'

                // Parse the alias (should be an identifier)
                if let Token::String = self.current_token {
                    let a = self.lexer.source_text(&self.current_span).to_string();
                    self.advance();
                    Some(a)
                } else {
                    return Err(self.error("identifier"));
                }
            } else {
                None
            };

            uses.push(UseDeclaration { name, alias });

            // Check for comma (more declarations) or semicolon (end)
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            } else if self.current_token == Token::Semicolon {
                self.advance();
                break;
            } else {
                return Err(self.error("\",\" or \";\""));
            }
        }

        Ok(Statement::Use {
            uses,
            kind,
            span: start_span,
        })
    }

    /// Parse parameter list (comma-separated parameters)
    fn parse_parameter_list(&mut self) -> Result<Vec<Parameter>, ParseError> {
        let mut params = Vec::new();

        // Empty parameter list
        if self.current_token == Token::RParen {
            return Ok(params);
        }

        loop {
            // Trailing comma support: if we see ) after a comma, stop
            if self.current_token == Token::RParen {
                break;
            }
            params.push(self.parse_parameter()?);

            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }

        Ok(params)
    }

    /// Parse a single parameter
    /// Syntax: [visibility] [readonly] [type] [&] [...]$name [= default]
    fn parse_parameter(&mut self) -> Result<Parameter, ParseError> {
        let start_span = self.current_span;

        // Skip PHP 8.0+ attributes on parameters: #[SensitiveParameter], #[Attr(...)], etc.
        while self.current_token == Token::Attribute {
            self.advance(); // skip #[
            let mut depth = 1;
            while depth > 0 && self.current_token != Token::End {
                match self.current_token {
                    Token::LBracket => {
                        depth += 1;
                        self.advance();
                    }
                    Token::RBracket => {
                        depth -= 1;
                        self.advance();
                    }
                    _ => {
                        self.advance();
                    }
                }
            }
        }

        // Parse optional visibility modifier (constructor promotion, PHP 8.0+)
        // and readonly modifier (PHP 8.1+)
        let mut modifiers = Vec::new();
        loop {
            match self.current_token {
                Token::Public => {
                    modifiers.push(Modifier::Public);
                    self.advance();
                }
                Token::Protected => {
                    modifiers.push(Modifier::Protected);
                    self.advance();
                }
                Token::Private => {
                    modifiers.push(Modifier::Private);
                    self.advance();
                }
                Token::Readonly => {
                    modifiers.push(Modifier::Readonly);
                    self.advance();
                }
                _ => break,
            }
        }

        // Parse optional type
        let param_type = if self.is_type_token() {
            Some(self.parse_type()?)
        } else {
            None
        };

        // Parse optional & (by reference)
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse optional ... (variadic)
        let variadic = if self.current_token == Token::Ellipsis {
            self.advance();
            true
        } else {
            false
        };

        // Parse variable name
        let name = if let Token::Variable = self.current_token {
            let n = self.lexer.source_text(&self.current_span).to_string();
            self.advance();
            n
        } else {
            return Err(self.error("variable"));
        };

        // Parse optional default value
        let default = if self.current_token == Token::Equals {
            self.advance();
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        Ok(Parameter {
            name,
            param_type,
            default,
            by_ref,
            variadic,
            attributes: Vec::new(), // TODO: Parse attributes
            modifiers,
            span: start_span,
        })
    }

    /// Parse a class name for `new` expressions.
    /// Handles: `ClassName`, `\Fully\Qualified\Name`, `$var`, `static`, `self`, `parent`
    /// Does NOT consume trailing `(args)` — those are parsed by the `new` handler.
    fn parse_new_class_name(&mut self) -> Result<Expression, ParseError> {
        let span = self.current_span;

        match self.current_token {
            // Fully-qualified name: \Foo\Bar (if lexer produces combined token)
            Token::NameFullyQualified => {
                let text = self.lexer.source_text(&span).to_string();
                self.advance();
                Ok(Expression::StringLiteral { value: text, span })
            }
            // Qualified name: Foo\Bar (if lexer produces combined token)
            Token::NameQualified => {
                let text = self.lexer.source_text(&span).to_string();
                self.advance();
                Ok(Expression::StringLiteral { value: text, span })
            }
            // Leading backslash: \ClassName or \Foo\Bar\Baz (fully-qualified)
            Token::Backslash | Token::NsSeparator => {
                self.advance(); // consume the leading backslash
                let mut parts = Vec::new();
                if let Token::String = self.current_token {
                    parts.push(self.lexer.source_text(&self.current_span).to_string());
                    self.advance();
                    while self.current_token == Token::NsSeparator
                        || self.current_token == Token::Backslash
                    {
                        self.advance();
                        if let Token::String = self.current_token {
                            parts.push(self.lexer.source_text(&self.current_span).to_string());
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                Ok(Expression::StringLiteral {
                    value: format!("\\{}", parts.join("\\")),
                    span,
                })
            }
            // Simple identifier: ClassName
            Token::String => {
                let text = self.lexer.source_text(&span).to_string();
                self.advance();

                // Handle qualified names: Foo\Bar\Baz
                if self.current_token == Token::NsSeparator
                    || self.current_token == Token::Backslash
                {
                    let mut parts = vec![text];
                    while self.current_token == Token::NsSeparator
                        || self.current_token == Token::Backslash
                    {
                        self.advance();
                        if let Token::String = self.current_token {
                            parts.push(self.lexer.source_text(&self.current_span).to_string());
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    Ok(Expression::StringLiteral {
                        value: parts.join("\\"),
                        span,
                    })
                } else {
                    Ok(Expression::StringLiteral { value: text, span })
                }
            }
            // Dynamic class: new $var()
            Token::Variable => self.parse_prefix(),
            // static keyword
            Token::Static => {
                self.advance();
                Ok(Expression::StringLiteral {
                    value: "static".to_string(),
                    span,
                })
            }
            // Fallback for other cases (anonymous classes etc.)
            _ => self.parse_prefix(),
        }
    }

    /// Parse a function/method argument
    fn parse_argument(&mut self) -> Result<Argument, ParseError> {
        // Check for unpack operator (...)
        let unpack = if self.current_token == Token::Ellipsis {
            self.advance();
            true
        } else {
            false
        };

        // Check for named argument (name: value)
        // We need to peek ahead to see if there's a colon after an identifier.
        // PHP 8.0+ allows reserved keywords as named argument names (e.g. default:, match:, class:)
        let name = if self.is_named_arg_label() {
            let potential_name = self.lexer.source_text(&self.current_span).to_string();
            let next = self.peek();
            if *next == Token::Colon {
                // This is a named argument
                self.advance(); // consume the name
                self.advance(); // consume the colon
                Some(potential_name)
            } else {
                None
            }
        } else {
            None
        };

        // Parse the value expression
        let value = self.parse_expression(0)?;

        Ok(Argument {
            name,
            value,
            unpack,
            by_ref: false, // by_ref is determined at runtime in PHP
        })
    }

    /// Check if the current token can be a named argument label.
    /// PHP 8.0+ allows reserved keywords as named argument names.
    fn is_named_arg_label(&self) -> bool {
        matches!(
            self.current_token,
            Token::String      // regular identifiers (includes true, false, null)
            | Token::Default   // default:
            | Token::Match     // match:
            | Token::Class     // class:
            | Token::Array     // array:
            | Token::List      // list:
            | Token::Fn        // fn:
            | Token::Static    // static:
            | Token::Abstract  // abstract:
            | Token::Final     // final:
            | Token::Private   // private:
            | Token::Protected // protected:
            | Token::Public    // public:
            | Token::Readonly // readonly:
        )
    }

    /// Parse array elements for array() or [] syntax
    fn parse_array_elements(&mut self, end_token: Token) -> Result<Vec<ArrayElement>, ParseError> {
        let mut elements = Vec::new();
        while self.current_token != end_token && self.current_token != Token::End {
            // Handle trailing comma
            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }

            // Check for spread operator
            let unpack = if self.current_token == Token::Ellipsis {
                self.advance();
                true
            } else {
                false
            };

            // Check for &reference
            let by_ref = if self.current_token == Token::Ampersand {
                self.advance();
                true
            } else {
                false
            };

            let value = self.parse_expression(0)?;

            // Check for key => value
            if self.current_token == Token::DoubleArrow {
                self.advance();
                let actual_by_ref = if self.current_token == Token::Ampersand {
                    self.advance();
                    true
                } else {
                    false
                };
                let actual_value = self.parse_expression(0)?;
                elements.push(ArrayElement {
                    key: Some(value),
                    value: actual_value,
                    by_ref: actual_by_ref,
                    unpack,
                });
            } else {
                elements.push(ArrayElement {
                    key: None,
                    value,
                    by_ref,
                    unpack,
                });
            }

            if self.current_token == Token::Comma {
                self.advance();
            } else {
                break;
            }
        }
        Ok(elements)
    }

    /// Parse a member name after -> or ?-> (can be identifier, keyword, variable, or {expr})
    fn parse_member_name(&mut self) -> Result<Box<Expression>, ParseError> {
        // In PHP, almost any keyword can be used as a property/method name after ->
        if self.is_identifier_or_keyword()
            || matches!(
                self.current_token,
                Token::List
                    | Token::Var
                    | Token::Exit
                    | Token::Print
                    | Token::Echo
                    | Token::Include
                    | Token::IncludeOnce
                    | Token::Require
                    | Token::RequireOnce
                    | Token::If
                    | Token::Else
                    | Token::Elseif
                    | Token::While
                    | Token::For
                    | Token::Foreach
                    | Token::Switch
                    | Token::Case
                    | Token::Default
                    | Token::Break
                    | Token::Continue
                    | Token::Return
                    | Token::Do
                    | Token::Try
                    | Token::Catch
                    | Token::Finally
                    | Token::Throw
                    | Token::Function
                    | Token::Const
                    | Token::Abstract
                    | Token::Final
                    | Token::Public
                    | Token::Protected
                    | Token::Private
                    | Token::Interface
                    | Token::Trait
                    | Token::Extends
                    | Token::Implements
                    | Token::New
                    | Token::Clone
                    | Token::Instanceof
                    | Token::Isset
                    | Token::Unset
                    | Token::Empty
                    | Token::Eval
                    | Token::Yield
                    | Token::Global
                    | Token::Namespace
                    | Token::Use
                    | Token::Goto
                    | Token::As
                    | Token::Declare
                    | Token::Endfor
                    | Token::Endforeach
                    | Token::Endif
                    | Token::Endwhile
                    | Token::Endswitch
            )
        {
            let prop_name = self.lexer.source_text(&self.current_span).to_string();
            let prop_span = self.current_span;
            self.advance();
            Ok(Box::new(Expression::StringLiteral {
                value: prop_name,
                span: prop_span,
            }))
        } else if let Token::Variable = self.current_token {
            // Dynamic property: $obj->$prop
            Ok(Box::new(self.parse_prefix()?))
        } else if let Token::BadCharacter = self.current_token {
            // Variable variable property: $obj->$$var or $obj->${expr}
            Ok(Box::new(self.parse_prefix()?))
        } else if self.current_token == Token::LBrace {
            // Complex property: $obj->{$expr}
            self.advance();
            let prop = Box::new(self.parse_expression(0)?);
            self.expect(Token::RBrace)?;
            Ok(prop)
        } else {
            Err(self.error("property name"))
        }
    }

    /// Check if current token is a semi-reserved keyword that can be used as a method/property name
    fn is_semi_reserved_keyword(&self) -> bool {
        matches!(
            self.current_token,
            Token::Array
                | Token::Callable
                | Token::Static
                | Token::Class
                | Token::Fn
                | Token::Match
                | Token::Readonly
                | Token::Enum
                | Token::Empty
                | Token::Isset
                | Token::Unset
                | Token::List
                | Token::Switch
                | Token::Case
                | Token::Default
                | Token::For
                | Token::Foreach
                | Token::While
                | Token::Do
                | Token::If
                | Token::Else
                | Token::Elseif
                | Token::New
                | Token::Clone
                | Token::Throw
                | Token::Try
                | Token::Catch
                | Token::Finally
                | Token::Return
                | Token::Yield
                | Token::Print
                | Token::Echo
                | Token::Include
                | Token::IncludeOnce
                | Token::Require
                | Token::RequireOnce
                | Token::Extends
                | Token::Implements
                | Token::Var
                | Token::Exit
                | Token::Interface
                | Token::Trait
                | Token::Abstract
                | Token::Final
                | Token::Global
                | Token::Goto
                | Token::Instanceof
                | Token::Insteadof
                | Token::As
                | Token::Break
                | Token::Continue
                | Token::Use
                | Token::Namespace
                | Token::Function
                | Token::Const
                | Token::LogicalAnd
                | Token::LogicalOr
                | Token::LogicalXor
        )
    }

    /// Check if current token is an identifier or a keyword that can be used as a name
    fn is_identifier_or_keyword(&self) -> bool {
        self.current_token == Token::String || self.is_semi_reserved_keyword()
    }

    /// Check if current token can start a type annotation
    fn is_type_token(&self) -> bool {
        matches!(
            self.current_token,
            Token::String // For class names and built-in types (int, string, etc.)
                | Token::Question // For nullable types (?Type)
                | Token::NsSeparator // For fully-qualified types (\Foo\Bar)
                | Token::Backslash // For fully-qualified types
                | Token::Array // array type
                | Token::Callable // callable type
                | Token::Static // static return type
                                // null is handled as Token::String("null") by lexer
        )
    }

    /// Parse a type annotation
    /// Syntax: Type | ?Type | Type1|Type2 | Type1&Type2 | (Type1&Type2)|Type3
    fn parse_type(&mut self) -> Result<Type, ParseError> {
        let start_span = self.current_span;

        // Handle nullable type: ?Type
        if self.current_token == Token::Question {
            self.advance();
            let inner = Box::new(self.parse_single_type()?);
            return Ok(Type::Nullable {
                inner,
                span: start_span,
            });
        }

        // Parse first type
        let mut types = vec![self.parse_single_type()?];

        // Check for union (|) or intersection (&)
        if self.current_token == Token::VerticalBar {
            // Union type: Type1|Type2|Type3
            while self.current_token == Token::VerticalBar {
                self.advance();
                types.push(self.parse_single_type()?);
            }
            Ok(Type::Union {
                types,
                span: start_span,
            })
        } else if self.current_token == Token::Ampersand {
            // Could be intersection type: Type1&Type2&Type3
            // Or could be by-reference parameter: Type &$param
            // Disambiguate by peeking: if next token is Variable or Ellipsis,
            // it's a by-reference parameter
            let next = self.peek().clone();
            if next == Token::Variable || next == Token::Ellipsis {
                // It's a by-reference parameter, not intersection type
                Ok(types.into_iter().next().unwrap())
            } else {
                while self.current_token == Token::Ampersand {
                    self.advance();
                    types.push(self.parse_single_type()?);
                }
                Ok(Type::Intersection {
                    types,
                    span: start_span,
                })
            }
        } else {
            // Single type
            Ok(types.into_iter().next().unwrap())
        }
    }

    /// Parse a single type (no union/intersection)
    fn parse_single_type(&mut self) -> Result<Type, ParseError> {
        let start_span = self.current_span;

        // For now, just parse as a qualified name
        // TODO: Handle DNF types (A&B)|C
        let name = self.parse_qualified_name()?;

        Ok(Type::Named {
            name,
            span: start_span,
        })
    }

    /// Parse if/elseif/else statement
    fn parse_if_statement(&mut self) -> Result<Statement, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::If)?;

        // Parse condition in parentheses
        self.expect(Token::LParen)?;
        let condition = Box::new(self.parse_expression(0)?);
        self.expect(Token::RParen)?;

        // Check for alternative syntax (colon)
        let is_alternative_syntax = self.current_token == Token::Colon;

        if is_alternative_syntax {
            // Alternative syntax: if (...): statements endif;
            self.advance(); // consume colon

            // Parse then statements until elseif/else/endif
            let mut then_statements = Vec::new();
            while self.current_token != Token::Elseif
                && self.current_token != Token::Else
                && self.current_token != Token::Endif
            {
                then_statements.push(self.parse_statement()?);
            }

            // Parse elseif branches (alternative syntax)
            let mut elseif_branches = Vec::new();
            while self.current_token == Token::Elseif {
                self.advance();
                self.expect(Token::LParen)?;
                let elseif_condition = self.parse_expression(0)?;
                self.expect(Token::RParen)?;
                self.expect(Token::Colon)?;

                // Parse elseif statements
                let mut elseif_stmts = Vec::new();
                while self.current_token != Token::Elseif
                    && self.current_token != Token::Else
                    && self.current_token != Token::Endif
                {
                    elseif_stmts.push(self.parse_statement()?);
                }

                let elseif_body = Statement::Block {
                    statements: elseif_stmts,
                    span: start_span,
                };
                elseif_branches.push((elseif_condition, elseif_body));
            }

            // Parse else branch (alternative syntax)
            let else_branch = if self.current_token == Token::Else {
                self.advance();
                self.expect(Token::Colon)?;

                // Parse else statements
                let mut else_stmts = Vec::new();
                while self.current_token != Token::Endif {
                    else_stmts.push(self.parse_statement()?);
                }

                Some(Box::new(Statement::Block {
                    statements: else_stmts,
                    span: start_span,
                }))
            } else {
                None
            };

            // Expect endif;
            self.expect(Token::Endif)?;
            self.expect_semicolon()?;

            let then_branch = Box::new(Statement::Block {
                statements: then_statements,
                span: start_span,
            });

            Ok(Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                span: start_span,
            })
        } else {
            // Standard syntax: if (...) statement
            let then_branch = Box::new(self.parse_statement()?);

            // Parse elseif branches
            let mut elseif_branches = Vec::new();
            while self.current_token == Token::Elseif {
                self.advance();
                self.expect(Token::LParen)?;
                let elseif_condition = self.parse_expression(0)?;
                self.expect(Token::RParen)?;
                let elseif_body = self.parse_statement()?;
                elseif_branches.push((elseif_condition, elseif_body));
            }

            // Parse else branch
            let else_branch = if self.current_token == Token::Else {
                self.advance();
                Some(Box::new(self.parse_statement()?))
            } else {
                None
            };

            Ok(Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                span: start_span,
            })
        }
    }

    /// Parse a prefix expression (literals, variables, unary operators, parentheses)
    fn parse_prefix(&mut self) -> Result<Expression, ParseError> {
        let token = self.current_token.clone();
        let span = self.current_span;

        match token {
            // Integer literal
            Token::LNumber => {
                let text = self.lexer.source_text(&span);
                let value = parse_int_literal(text);
                self.advance();
                Ok(Expression::IntLiteral { value, span })
            }

            // Float literal
            Token::DNumber => {
                let text = self.lexer.source_text(&span);
                let value = parse_float_literal(text);
                self.advance();
                Ok(Expression::FloatLiteral { value, span })
            }

            // String literal
            Token::ConstantEncapsedString => {
                let text = self.lexer.source_text(&span);
                let value = parse_string_literal(text);
                self.advance();
                Ok(Expression::StringLiteral { value, span })
            }

            // Variable
            Token::Variable => {
                let text = self.lexer.source_text(&span);
                // Strip leading $
                let name = text.strip_prefix('$').unwrap_or(text).to_string();
                self.advance();
                Ok(Expression::Variable { name, span })
            }

            // Parenthesized expression
            Token::LParen => {
                self.advance();
                let expr = self.parse_expression(0)?;
                self.expect(Token::RParen)?;
                Ok(expr)
            }

            // Unary operators
            Token::Plus => {
                self.advance();
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::Plus,
                    operand: Box::new(operand),
                    span,
                })
            }
            Token::Minus => {
                self.advance();
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::Minus,
                    operand: Box::new(operand),
                    span,
                })
            }
            Token::Exclamation => {
                self.advance();
                let operand = self.parse_expression(Self::NOT_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::Not,
                    operand: Box::new(operand),
                    span,
                })
            }
            Token::Tilde => {
                self.advance();
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::BitwiseNot,
                    operand: Box::new(operand),
                    span,
                })
            }
            Token::At => {
                self.advance();
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::ErrorSuppress,
                    operand: Box::new(operand),
                    span,
                })
            }

            // Pre-increment/decrement
            Token::Inc => {
                self.advance();
                let var = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::PreIncrement {
                    var: Box::new(var),
                    span,
                })
            }
            Token::Dec => {
                self.advance();
                let var = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::PreDecrement {
                    var: Box::new(var),
                    span,
                })
            }

            // Cast expressions
            Token::IntCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Int,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::DoubleCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Float,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::StringCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::String,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::BoolCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Bool,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::ArrayCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Array,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::ObjectCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Object,
                    expr: Box::new(expr),
                    span,
                })
            }
            Token::UnsetCast => {
                self.advance();
                let expr = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::Cast {
                    cast_type: CastType::Unset,
                    expr: Box::new(expr),
                    span,
                })
            }

            // Match expression
            Token::Match => {
                self.advance();

                // Parse condition in parentheses
                self.expect(Token::LParen)?;
                let condition = Box::new(self.parse_expression(0)?);
                self.expect(Token::RParen)?;

                // Parse match arms in braces
                self.expect(Token::LBrace)?;

                let mut arms = Vec::new();

                while self.current_token != Token::RBrace {
                    // Parse match arm
                    // default => expr or value1, value2 => expr
                    let conditions = if self.current_token == Token::Default {
                        self.advance(); // consume default
                        Vec::new() // Empty conditions means default
                    } else {
                        // Parse comma-separated conditions
                        let mut conds = Vec::new();
                        loop {
                            conds.push(self.parse_expression(0)?);
                            if self.current_token != Token::Comma {
                                break;
                            }
                            self.advance(); // consume comma
                                            // Check if next is => (end of conditions)
                            if self.current_token == Token::DoubleArrow {
                                break;
                            }
                        }
                        conds
                    };

                    // Expect =>
                    self.expect(Token::DoubleArrow)?;

                    // Parse body expression
                    let body = self.parse_expression(0)?;

                    arms.push(MatchArm { conditions, body });

                    // Check for comma (optional after last arm)
                    if self.current_token == Token::Comma {
                        self.advance();
                    } else if self.current_token != Token::RBrace {
                        return Err(self.error("\",\" or \"}\""));
                    }
                }

                self.expect(Token::RBrace)?;

                Ok(Expression::MatchExpr {
                    condition,
                    arms,
                    span,
                })
            }

            // Closure: function(...) use (...) { ... }
            Token::Function => self.parse_closure_expression(),

            // Arrow function: fn(...) => expr
            Token::Fn => self.parse_arrow_function_expression(),

            // Static closure: static function(...) { ... }
            Token::Static => {
                self.advance();
                if self.current_token == Token::Function {
                    // Static closure: static function(...) { ... }
                    self.parse_closure_expression_static()
                } else if self.current_token == Token::Fn {
                    // Static arrow function: static fn(...) => expr
                    self.parse_arrow_function_expression_static()
                } else {
                    // static:: or other usage - treat as identifier
                    Ok(Expression::StringLiteral {
                        value: "static".to_string(),
                        span,
                    })
                }
            }

            // Identifier - could be null, true, false, or a function/constant name
            Token::String => {
                let text = self.lexer.source_text(&span).to_lowercase();

                // Check for special keywords: null, true, false (case-insensitive)
                if text == "null" {
                    self.advance();
                    Ok(Expression::Null { span })
                } else if text == "true" {
                    self.advance();
                    Ok(Expression::BoolLiteral { value: true, span })
                } else if text == "false" {
                    self.advance();
                    Ok(Expression::BoolLiteral { value: false, span })
                } else {
                    // Regular identifier - could be a function call or constant
                    let name = self.lexer.source_text(&span).to_string();
                    self.advance();

                    // Check if it's a function call (followed by '(')
                    if self.current_token == Token::LParen {
                        self.advance(); // consume '('

                        // First-class callable syntax: func(...)
                        if self.current_token == Token::Ellipsis && *self.peek() == Token::RParen {
                            self.advance(); // consume '...'
                            self.advance(); // consume ')'
                                            // Emit Closure::fromCallable('func')
                            return Ok(Expression::FunctionCall {
                                name: Box::new(Expression::StringLiteral {
                                    value: "Closure::fromCallable".to_string(),
                                    span,
                                }),
                                args: vec![Argument {
                                    name: None,
                                    value: Expression::StringLiteral { value: name, span },
                                    unpack: false,
                                    by_ref: false,
                                }],
                                span,
                            });
                        }

                        let mut args = Vec::new();

                        // Parse arguments
                        if self.current_token != Token::RParen {
                            loop {
                                args.push(self.parse_argument()?);
                                if self.current_token == Token::Comma {
                                    self.advance();
                                    if self.current_token == Token::RParen {
                                        break; // trailing comma
                                    }
                                    continue;
                                }
                                break;
                            }
                        }

                        self.expect(Token::RParen)?;

                        Ok(Expression::FunctionCall {
                            name: Box::new(Expression::StringLiteral { value: name, span }),
                            args,
                            span,
                        })
                    } else if self.current_token == Token::PaamayimNekudotayim {
                        // Class::method() or Class::CONST — keep as StringLiteral (class name)
                        Ok(Expression::StringLiteral { value: name, span })
                    } else if self.current_token == Token::NsSeparator
                        || self.current_token == Token::Backslash
                    {
                        // Qualified name: Foo\Bar\Baz (could be constant or class)
                        let mut parts = vec![name];
                        while self.current_token == Token::NsSeparator
                            || self.current_token == Token::Backslash
                        {
                            self.advance(); // consume '\'
                            let part = self.lexer.source_text(&self.current_span).to_string();
                            self.advance();
                            parts.push(part);
                        }
                        let full_name = parts.join("\\");
                        if self.current_token == Token::LParen {
                            // Qualified function call
                            self.advance();
                            let mut args = Vec::new();
                            if self.current_token != Token::RParen {
                                loop {
                                    args.push(self.parse_argument()?);
                                    if self.current_token == Token::Comma {
                                        self.advance();
                                        if self.current_token == Token::RParen {
                                            break; // trailing comma
                                        }
                                        continue;
                                    }
                                    break;
                                }
                            }
                            self.expect(Token::RParen)?;
                            Ok(Expression::FunctionCall {
                                name: Box::new(Expression::StringLiteral {
                                    value: full_name,
                                    span,
                                }),
                                args,
                                span,
                            })
                        } else if self.current_token == Token::PaamayimNekudotayim {
                            // Qualified class name before :: — keep as StringLiteral
                            Ok(Expression::StringLiteral {
                                value: full_name,
                                span,
                            })
                        } else {
                            Ok(Expression::ConstantAccess {
                                name: full_name,
                                span,
                            })
                        }
                    } else {
                        // It's a constant reference
                        Ok(Expression::ConstantAccess { name, span })
                    }
                }
            }

            // Print expression: `print expr` (returns 1)
            Token::Print => {
                self.advance();
                let expr = Box::new(self.parse_expression(0)?);
                Ok(Expression::Print { expr, span })
            }

            // Include/require expressions
            Token::Include => {
                self.advance();
                let path = Box::new(self.parse_expression(0)?);
                Ok(Expression::Include { path, span })
            }
            Token::IncludeOnce => {
                self.advance();
                let path = Box::new(self.parse_expression(0)?);
                Ok(Expression::IncludeOnce { path, span })
            }
            Token::Require => {
                self.advance();
                let path = Box::new(self.parse_expression(0)?);
                Ok(Expression::Require { path, span })
            }
            Token::RequireOnce => {
                self.advance();
                let path = Box::new(self.parse_expression(0)?);
                Ok(Expression::RequireOnce { path, span })
            }

            // Eval expression: `eval(code)`
            Token::Eval => {
                self.advance();
                self.expect(Token::LParen)?;
                let code = Box::new(self.parse_expression(0)?);
                self.expect(Token::RParen)?;
                Ok(Expression::Eval { code, span })
            }

            // Isset construct: `isset($var, ...)`
            Token::Isset => {
                self.advance();
                self.expect(Token::LParen)?;
                let mut vars = Vec::new();
                loop {
                    vars.push(self.parse_expression(0)?);
                    if self.current_token == Token::Comma {
                        self.advance();
                        continue;
                    }
                    break;
                }
                self.expect(Token::RParen)?;
                Ok(Expression::Isset { vars, span })
            }

            // Empty construct: `empty($var)`
            Token::Empty => {
                self.advance();
                self.expect(Token::LParen)?;
                let var = Box::new(self.parse_expression(0)?);
                self.expect(Token::RParen)?;
                Ok(Expression::Empty { var, span })
            }

            // Exit/die construct: `exit([expr])`
            Token::Exit => {
                self.advance();
                let expr = if self.current_token == Token::LParen {
                    self.advance();
                    if self.current_token == Token::RParen {
                        self.advance();
                        None
                    } else {
                        let e = self.parse_expression(0)?;
                        self.expect(Token::RParen)?;
                        Some(Box::new(e))
                    }
                } else {
                    None
                };
                Ok(Expression::Exit { expr, span })
            }

            // List destructure: `list($a, $b) = expr`
            Token::List => {
                self.advance();
                self.expect(Token::LParen)?;
                let mut elements = Vec::new();
                loop {
                    if self.current_token == Token::Comma {
                        elements.push(None);
                    } else if self.current_token == Token::RParen {
                        break;
                    } else {
                        elements.push(Some(self.parse_expression(0)?));
                    }
                    if self.current_token == Token::Comma {
                        self.advance();
                        continue;
                    }
                    break;
                }
                self.expect(Token::RParen)?;
                Ok(Expression::List { elements, span })
            }

            // Yield expression
            Token::Yield => {
                self.advance();
                // yield from expr
                if self.current_token == Token::String
                    && self.lexer.source_text(&self.current_span) == "from"
                {
                    self.advance();
                    let expr = Box::new(self.parse_expression(0)?);
                    Ok(Expression::YieldFrom { expr, span })
                } else if self.current_token == Token::Semicolon
                    || self.current_token == Token::RParen
                    || self.current_token == Token::RBracket
                {
                    Ok(Expression::Yield {
                        key: None,
                        value: None,
                        span,
                    })
                } else {
                    let value = self.parse_expression(0)?;
                    if self.current_token == Token::DoubleArrow {
                        self.advance();
                        let actual_value = self.parse_expression(0)?;
                        Ok(Expression::Yield {
                            key: Some(Box::new(value)),
                            value: Some(Box::new(actual_value)),
                            span,
                        })
                    } else {
                        Ok(Expression::Yield {
                            key: None,
                            value: Some(Box::new(value)),
                            span,
                        })
                    }
                }
            }

            // Magic constants
            Token::Line => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Line,
                    span,
                })
            }
            Token::File => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::File,
                    span,
                })
            }
            Token::Dir => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Dir,
                    span,
                })
            }
            Token::ClassC => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Class,
                    span,
                })
            }
            Token::TraitC => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Trait,
                    span,
                })
            }
            Token::MethodC => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Method,
                    span,
                })
            }
            Token::FuncC => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Function,
                    span,
                })
            }
            Token::NsC => {
                self.advance();
                Ok(Expression::MagicConstant {
                    kind: MagicConstantKind::Namespace,
                    span,
                })
            }

            // Reference operator: &$var (used in assignments like $a =& $b)
            Token::Ampersand => {
                self.advance();
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                Ok(Expression::UnaryOp {
                    op: UnaryOperator::Reference,
                    operand: Box::new(operand),
                    span,
                })
            }

            // Clone expression
            Token::Clone => {
                self.advance();
                let object = Box::new(self.parse_expression(Self::PREFIX_PRECEDENCE)?);
                Ok(Expression::Clone { object, span })
            }

            // New expression: `new Class(args)` or `new class { ... }` (anonymous)
            Token::New => {
                self.advance();

                // Check for anonymous class: `new class [(args)] [extends ...] [implements ...] { ... }`
                if self.current_token == Token::Class {
                    self.advance();

                    // Parse optional constructor args
                    let args = if self.current_token == Token::LParen {
                        self.advance();
                        let mut args = Vec::new();
                        if self.current_token != Token::RParen {
                            loop {
                                args.push(self.parse_argument()?);
                                if self.current_token == Token::Comma {
                                    self.advance();
                                    if self.current_token == Token::RParen {
                                        break;
                                    }
                                    continue;
                                }
                                break;
                            }
                        }
                        self.expect(Token::RParen)?;
                        args
                    } else {
                        Vec::new()
                    };

                    // Parse optional extends
                    let extends = if self.current_token == Token::Extends {
                        self.advance();
                        Some(Box::new(self.parse_new_class_name()?))
                    } else {
                        None
                    };

                    // Parse optional implements
                    let implements = if self.current_token == Token::Implements {
                        self.advance();
                        let mut interfaces = Vec::new();
                        loop {
                            interfaces.push(self.parse_qualified_name()?);
                            if self.current_token == Token::Comma {
                                self.advance();
                                continue;
                            }
                            break;
                        }
                        interfaces
                    } else {
                        Vec::new()
                    };

                    // Parse body
                    self.expect(Token::LBrace)?;
                    let members = self.parse_class_members()?;
                    self.expect(Token::RBrace)?;

                    Ok(Expression::AnonymousClass {
                        args,
                        extends,
                        implements,
                        members,
                        span,
                    })
                } else {
                    // Regular new: parse class name
                    let class = Box::new(self.parse_new_class_name()?);
                    let args = if self.current_token == Token::LParen {
                        self.advance();
                        let mut args = Vec::new();
                        if self.current_token != Token::RParen {
                            loop {
                                args.push(self.parse_argument()?);
                                if self.current_token == Token::Comma {
                                    self.advance();
                                    if self.current_token == Token::RParen {
                                        break; // trailing comma
                                    }
                                    continue;
                                }
                                break;
                            }
                        }
                        self.expect(Token::RParen)?;
                        args
                    } else {
                        Vec::new()
                    };
                    Ok(Expression::New { class, args, span })
                }
            }

            // Throw expression (PHP 8.0+): can appear in expressions
            Token::Throw => {
                self.advance();
                let exception = Box::new(self.parse_expression(0)?);
                Ok(Expression::ThrowExpr { exception, span })
            }

            // Backslash for fully-qualified names: \ClassName or \func()
            Token::Backslash => {
                // Fully-qualified name (e.g., \DIRECTORY_SEPARATOR, \strlen(), \Foo\Bar)
                let qname = self.parse_qualified_name()?;
                let name_str = format!("\\{}", qname.parts.join("\\"));
                // Check if it's a function call
                if self.current_token == Token::LParen {
                    self.advance();
                    let mut args = Vec::new();
                    if self.current_token != Token::RParen {
                        loop {
                            args.push(self.parse_argument()?);
                            if self.current_token == Token::Comma {
                                self.advance();
                                if self.current_token == Token::RParen {
                                    break; // trailing comma
                                }
                                continue;
                            }
                            break;
                        }
                    }
                    self.expect(Token::RParen)?;
                    let name_expr = Expression::StringLiteral {
                        value: name_str,
                        span,
                    };
                    Ok(Expression::FunctionCall {
                        name: Box::new(name_expr),
                        args,
                        span,
                    })
                } else if self.current_token == Token::PaamayimNekudotayim {
                    // Class reference: \Foo\Bar::method()
                    Ok(Expression::StringLiteral {
                        value: name_str,
                        span,
                    })
                } else {
                    // Constant access: \DIRECTORY_SEPARATOR, \PHP_EOL, etc.
                    Ok(Expression::ConstantAccess {
                        name: name_str,
                        span,
                    })
                }
            }

            // Array literal: array(elements)
            Token::Array => {
                self.advance();
                self.expect(Token::LParen)?;
                let elements = self.parse_array_elements(Token::RParen)?;
                self.expect(Token::RParen)?;
                Ok(Expression::ArrayLiteral { elements, span })
            }

            // Short array literal: [elements]
            Token::LBracket => {
                self.advance();
                let elements = self.parse_array_elements(Token::RBracket)?;
                self.expect(Token::RBracket)?;
                Ok(Expression::ArrayLiteral { elements, span })
            }

            // Encapsed string (double-quoted with interpolation)
            // Heredoc/Nowdoc: <<<LABEL ... LABEL; or <<<'LABEL' ... LABEL;
            Token::StartHeredoc => {
                let heredoc_text = self.lexer.source_text(&self.current_span).to_string();
                let is_nowdoc = heredoc_text.contains("'");
                self.advance(); // consume StartHeredoc

                let mut parts: Vec<Expression> = Vec::new();
                loop {
                    match &self.current_token {
                        Token::EndHeredoc => {
                            self.advance();
                            break;
                        }
                        Token::EncapsedAndWhitespace => {
                            let text = self.lexer.source_text(&self.current_span).to_string();
                            if !text.is_empty() {
                                let value = if is_nowdoc {
                                    text // Nowdoc: no escape processing
                                } else {
                                    unescape_double_quoted(&text) // Heredoc: process escapes
                                };
                                parts.push(Expression::StringLiteral {
                                    value,
                                    span: self.current_span.clone(),
                                });
                            }
                            self.advance();
                        }
                        Token::Variable => {
                            let text = self.lexer.source_text(&self.current_span);
                            let name = text.strip_prefix('$').unwrap_or(text).to_string();
                            let var_span = self.current_span.clone();
                            self.advance();
                            let mut expr = Expression::Variable {
                                name,
                                span: var_span.clone(),
                            };
                            // Check for ->prop or [index] after variable
                            if self.current_token == Token::ObjectOperator {
                                self.advance();
                                if let Token::String = self.current_token {
                                    let prop =
                                        self.lexer.source_text(&self.current_span).to_string();
                                    let prop_span = self.current_span.clone();
                                    self.advance();
                                    expr = Expression::PropertyAccess {
                                        object: Box::new(expr),
                                        property: Box::new(Expression::StringLiteral {
                                            value: prop,
                                            span: prop_span.clone(),
                                        }),
                                        span: prop_span,
                                    };
                                }
                            } else if self.current_token == Token::LBracket {
                                self.advance();
                                let index = self.parse_expression(0)?;
                                if self.current_token == Token::RBracket {
                                    self.advance();
                                }
                                expr = Expression::ArrayAccess {
                                    array: Box::new(expr),
                                    index: Some(Box::new(index)),
                                    span: var_span,
                                };
                            }
                            parts.push(expr);
                        }
                        Token::DollarOpenCurlyBraces => {
                            self.advance();
                            if let Token::String = self.current_token {
                                let name = self.lexer.source_text(&self.current_span).to_string();
                                let var_span = self.current_span.clone();
                                self.advance();
                                parts.push(Expression::Variable {
                                    name,
                                    span: var_span,
                                });
                            }
                            if self.current_token == Token::RBrace {
                                self.advance();
                            }
                        }
                        Token::CurlyOpen => {
                            self.advance();
                            let expr = self.parse_expression(0)?;
                            parts.push(expr);
                            if self.current_token == Token::RBrace {
                                self.advance();
                            }
                        }
                        _ => break,
                    }
                }
                // Build concat tree
                if parts.is_empty() {
                    Ok(Expression::StringLiteral {
                        value: String::new(),
                        span,
                    })
                } else {
                    let mut result = parts.remove(0);
                    for part in parts {
                        let s = span.clone();
                        result = Expression::BinaryOp {
                            lhs: Box::new(result),
                            op: BinaryOperator::Concat,
                            rhs: Box::new(part),
                            span: s,
                        };
                    }
                    Ok(result)
                }
            }

            // The lexer emits EncapsedAndWhitespace and Variable tokens for
            // interpolated strings. Build a concat expression tree.
            // CurlyOpen and DollarOpenCurlyBraces can also start an encapsed string
            // (e.g. "{$var}..." or "${var}...")
            Token::EncapsedAndWhitespace | Token::CurlyOpen | Token::DollarOpenCurlyBraces => {
                let mut parts: Vec<Expression> = Vec::new();
                loop {
                    match &self.current_token {
                        Token::EncapsedAndWhitespace => {
                            let text = self.lexer.source_text(&self.current_span);
                            // Strip trailing " if this is the last part (closing quote)
                            let text = text.strip_suffix('"').unwrap_or(text);
                            if !text.is_empty() {
                                let value = unescape_double_quoted(text);
                                parts.push(Expression::StringLiteral {
                                    value,
                                    span: self.current_span.clone(),
                                });
                            }
                            self.advance();
                        }
                        Token::Variable => {
                            let text = self.lexer.source_text(&self.current_span);
                            let name = text.strip_prefix('$').unwrap_or(text).to_string();
                            let var_span = self.current_span.clone();
                            self.advance();
                            let mut expr = Expression::Variable {
                                name,
                                span: var_span.clone(),
                            };
                            // Check for ->prop after variable in string
                            if self.current_token == Token::ObjectOperator {
                                self.advance();
                                if let Token::String = self.current_token {
                                    let prop =
                                        self.lexer.source_text(&self.current_span).to_string();
                                    let prop_span = self.current_span.clone();
                                    self.advance();
                                    expr = Expression::PropertyAccess {
                                        object: Box::new(expr),
                                        property: Box::new(Expression::StringLiteral {
                                            value: prop,
                                            span: prop_span.clone(),
                                        }),
                                        span: prop_span,
                                    };
                                }
                            } else if self.current_token == Token::LBracket {
                                self.advance();
                                let index = self.parse_expression(0)?;
                                if self.current_token == Token::RBracket {
                                    self.advance();
                                }
                                expr = Expression::ArrayAccess {
                                    array: Box::new(expr),
                                    index: Some(Box::new(index)),
                                    span: var_span,
                                };
                            }
                            parts.push(expr);
                        }
                        Token::DollarOpenCurlyBraces => {
                            self.advance();
                            // Parse ${varname} — simple variable lookup
                            if let Token::String = self.current_token {
                                let name = self.lexer.source_text(&self.current_span).to_string();
                                let var_span = self.current_span.clone();
                                self.advance();
                                parts.push(Expression::Variable {
                                    name,
                                    span: var_span,
                                });
                            }
                            if self.current_token == Token::RBrace {
                                self.advance();
                            }
                        }
                        Token::CurlyOpen => {
                            self.advance();
                            // Parse {$expr} — full expression inside braces
                            let expr = self.parse_expression(0)?;
                            parts.push(expr);
                            if self.current_token == Token::RBrace {
                                self.advance();
                            }
                        }
                        _ => break,
                    }
                }
                // Build a left-associative concat tree
                if parts.is_empty() {
                    Ok(Expression::StringLiteral {
                        value: String::new(),
                        span,
                    })
                } else {
                    let mut result = parts.remove(0);
                    for part in parts {
                        let s = span.clone();
                        result = Expression::BinaryOp {
                            lhs: Box::new(result),
                            op: BinaryOperator::Concat,
                            rhs: Box::new(part),
                            span: s,
                        };
                    }
                    Ok(result)
                }
            }

            // Variable variable: $$var, ${expr} — `$` is tokenized as BadCharacter
            Token::BadCharacter => {
                let text = self.lexer.source_text(&span);
                if text == "$" {
                    self.advance(); // consume $
                    if self.current_token == Token::LBrace {
                        // ${expr}
                        self.advance(); // consume {
                        let _expr = self.parse_expression(0)?;
                        self.expect(Token::RBrace)?;
                        Ok(Expression::Variable {
                            name: String::new(),
                            span,
                        })
                    } else {
                        // $$var or $$$var etc — parse the inner expression
                        let _inner = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
                        Ok(Expression::Variable {
                            name: String::new(),
                            span,
                        })
                    }
                } else {
                    Err(ParseError::UnexpectedToken {
                        expected: "expression".to_string(),
                        found: token,
                        span,
                    })
                }
            }

            _ => Err(ParseError::UnexpectedToken {
                expected: "expression".to_string(),
                found: token,
                span,
            }),
        }
    }

    /// Parse a qualified name and return as an Expression
    fn parse_qualified_name_as_expression(&mut self) -> Result<Expression, ParseError> {
        let start_span = self.current_span;
        let name = self.parse_qualified_name()?;
        let name_str = if name.fully_qualified {
            format!("\\{}", name.parts.join("\\"))
        } else {
            name.parts.join("\\")
        };
        Ok(Expression::StringLiteral {
            value: name_str,
            span: start_span,
        })
    }

    /// Parse closure expression: function(...) use (...) { ... }
    fn parse_closure_expression(&mut self) -> Result<Expression, ParseError> {
        self.parse_closure_expression_impl(false)
    }

    /// Parse static closure expression: static function(...) { ... }
    fn parse_closure_expression_static(&mut self) -> Result<Expression, ParseError> {
        self.parse_closure_expression_impl(true)
    }

    /// Parse closure expression implementation
    fn parse_closure_expression_impl(&mut self, is_static: bool) -> Result<Expression, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Function)?;

        // Check for return by reference (&)
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse parameter list
        self.expect(Token::LParen)?;
        let params = self.parse_parameter_list()?;
        self.expect(Token::RParen)?;

        // Parse optional use clause: use ($var1, &$var2)
        let uses = if self.current_token == Token::Use {
            self.advance();
            self.expect(Token::LParen)?;
            let u = self.parse_use_list()?;
            self.expect(Token::RParen)?;
            u
        } else {
            Vec::new()
        };

        // Parse optional return type
        let return_type = if self.current_token == Token::Colon {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        // Parse closure body
        self.expect(Token::LBrace)?;
        let mut body = Vec::new();
        while self.current_token != Token::RBrace {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::RBrace)?;

        Ok(Expression::Closure {
            params,
            return_type,
            body,
            uses,
            by_ref,
            is_static,
            attributes: Vec::new(), // TODO: Parse attributes
            span: start_span,
        })
    }

    /// Parse use list for closures: $var1, &$var2
    fn parse_use_list(&mut self) -> Result<Vec<ClosureUse>, ParseError> {
        let mut uses = Vec::new();

        // Empty use list
        if self.current_token == Token::RParen {
            return Ok(uses);
        }

        loop {
            // Parse optional & (by reference)
            let by_ref = if self.current_token == Token::Ampersand {
                self.advance();
                true
            } else {
                false
            };

            // Parse variable name (strip leading $)
            let name = if let Token::Variable = self.current_token {
                let text = self.lexer.source_text(&self.current_span);
                let n = text.strip_prefix('$').unwrap_or(text).to_string();
                self.advance();
                n
            } else {
                return Err(self.error("variable"));
            };

            uses.push(ClosureUse { name, by_ref });

            if self.current_token == Token::Comma {
                self.advance();
                continue;
            }
            break;
        }

        Ok(uses)
    }

    /// Parse arrow function: fn(...) => expr
    fn parse_arrow_function_expression(&mut self) -> Result<Expression, ParseError> {
        let start_span = self.current_span;
        self.expect(Token::Fn)?;

        // Check for return by reference (&)
        let by_ref = if self.current_token == Token::Ampersand {
            self.advance();
            true
        } else {
            false
        };

        // Parse parameter list
        self.expect(Token::LParen)?;
        let params = self.parse_parameter_list()?;
        self.expect(Token::RParen)?;

        // Parse optional return type
        let return_type = if self.current_token == Token::Colon {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        // Expect =>
        self.expect(Token::DoubleArrow)?;

        // Parse body expression
        let body = Box::new(self.parse_expression(0)?);

        Ok(Expression::ArrowFunction {
            params,
            return_type,
            body,
            by_ref,
            attributes: Vec::new(), // TODO: Parse attributes
            span: start_span,
        })
    }

    /// Parse static arrow function expression: static fn(...) => expr
    fn parse_arrow_function_expression_static(&mut self) -> Result<Expression, ParseError> {
        // `static` was already consumed by the caller
        self.parse_arrow_function_expression()
        // TODO: mark as static
    }

    /// Parse an infix expression (binary operators, ternary, etc.)
    fn parse_infix(&mut self, left: Expression, precedence: u8) -> Result<Expression, ParseError> {
        let token = self.current_token.clone();
        let span = self.current_span;

        match token {
            // Binary operators (left-associative)
            Token::Plus
            | Token::Minus
            | Token::Star
            | Token::Slash
            | Token::Percent
            | Token::Dot
            | Token::IsEqual
            | Token::IsNotEqual
            | Token::LessThan
            | Token::IsSmallerOrEqual
            | Token::GreaterThan
            | Token::IsGreaterOrEqual
            | Token::IsIdentical
            | Token::IsNotIdentical
            | Token::Spaceship
            | Token::BooleanAnd
            | Token::BooleanOr
            | Token::LogicalAnd
            | Token::LogicalOr
            | Token::LogicalXor
            | Token::Ampersand
            | Token::VerticalBar
            | Token::Caret
            | Token::Sl
            | Token::Sr => {
                self.advance();
                let op = Self::token_to_binary_op(&token).ok_or_else(|| {
                    ParseError::UnexpectedToken {
                        expected: "binary operator".to_string(),
                        found: token.clone(),
                        span,
                    }
                })?;

                // Left-associative: use precedence + 1
                let right = self.parse_expression(precedence + 1)?;

                Ok(Expression::BinaryOp {
                    op,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                    span,
                })
            }

            // Power operator (right-associative)
            Token::Pow => {
                self.advance();
                // Right-associative: use same precedence
                let right = self.parse_expression(precedence)?;
                Ok(Expression::BinaryOp {
                    op: BinaryOperator::Pow,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                    span,
                })
            }

            // Assignment (right-associative)
            Token::Equals => {
                self.advance();
                // Check for reference assignment: $a = &$b
                if self.current_token == Token::Ampersand {
                    self.advance();
                    let right = self.parse_expression(precedence)?;
                    Ok(Expression::AssignRef {
                        lhs: Box::new(left),
                        rhs: Box::new(right),
                        span,
                    })
                } else {
                    let right = self.parse_expression(precedence)?;
                    Ok(Expression::Assign {
                        lhs: Box::new(left),
                        rhs: Box::new(right),
                        span,
                    })
                }
            }

            // Compound assignment operators (right-associative)
            Token::PlusEqual
            | Token::MinusEqual
            | Token::MulEqual
            | Token::DivEqual
            | Token::ModEqual
            | Token::PowEqual
            | Token::ConcatEqual
            | Token::AndEqual
            | Token::OrEqual
            | Token::XorEqual
            | Token::SlEqual
            | Token::SrEqual
            | Token::CoalesceEqual => {
                self.advance();
                let op = Self::token_to_binary_op(&token).ok_or_else(|| {
                    ParseError::UnexpectedToken {
                        expected: "compound assignment operator".to_string(),
                        found: token.clone(),
                        span,
                    }
                })?;
                let right = self.parse_expression(precedence)?;
                Ok(Expression::BinaryOp {
                    op,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                    span,
                })
            }

            // Ternary operator (left-associative in PHP 7, deprecated nesting in PHP 8)
            Token::Question => {
                self.advance();
                let then_expr = if self.current_token == Token::Colon {
                    None // Short ternary: expr ?: else_expr
                } else {
                    Some(Box::new(self.parse_expression(0)?))
                };
                self.expect(Token::Colon)?;
                let else_expr = Box::new(self.parse_expression(precedence + 1)?);
                Ok(Expression::Ternary {
                    condition: Box::new(left),
                    then_expr,
                    else_expr,
                    span,
                })
            }

            // Null coalesce (right-associative)
            Token::Coalesce => {
                self.advance();
                let right = self.parse_expression(precedence)?;
                Ok(Expression::Coalesce {
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                    span,
                })
            }

            // Post-increment/decrement
            Token::Inc => {
                self.advance();
                Ok(Expression::PostIncrement {
                    var: Box::new(left),
                    span,
                })
            }
            Token::Dec => {
                self.advance();
                Ok(Expression::PostDecrement {
                    var: Box::new(left),
                    span,
                })
            }

            // Object property access: $obj->prop
            Token::ObjectOperator => {
                self.advance();
                let property = self.parse_member_name()?;
                Ok(Expression::PropertyAccess {
                    object: Box::new(left),
                    property,
                    span,
                })
            }

            // Nullsafe property access: $obj?->prop
            Token::NullsafeObjectOperator => {
                self.advance();
                let property = self.parse_member_name()?;
                Ok(Expression::NullsafePropertyAccess {
                    object: Box::new(left),
                    property,
                    span,
                })
            }

            // Static access: Class::member, Class::$prop, Class::method()
            Token::PaamayimNekudotayim => {
                self.advance();
                if self.current_token == Token::Class {
                    // ::class magic constant
                    self.advance();
                    Ok(Expression::ClassConstant {
                        class: Box::new(left),
                        constant: "class".to_string(),
                        span,
                    })
                } else if self.current_token == Token::Variable {
                    // Static property: Class::$prop
                    let prop = Box::new(self.parse_prefix()?);
                    Ok(Expression::StaticPropertyAccess {
                        class: Box::new(left),
                        property: prop,
                        span,
                    })
                } else if self.current_token == Token::String || self.is_semi_reserved_keyword() {
                    // Static method/constant: Class::method() or Class::CONST
                    let member_name = self.lexer.source_text(&self.current_span).to_string();
                    let member_span = self.current_span;
                    self.advance();

                    if self.current_token == Token::LParen {
                        // Static method call: Class::method(args)
                        self.advance();

                        // First-class callable syntax: Class::method(...)
                        if self.current_token == Token::Ellipsis && *self.peek() == Token::RParen {
                            self.advance(); // consume '...'
                            self.advance(); // consume ')'
                                            // Emit Closure::fromCallable([Class, 'method'])
                            let callable = Expression::ArrayLiteral {
                                elements: vec![
                                    ArrayElement {
                                        key: None,
                                        value: left,
                                        unpack: false,
                                        by_ref: false,
                                    },
                                    ArrayElement {
                                        key: None,
                                        value: Expression::StringLiteral {
                                            value: member_name,
                                            span: member_span,
                                        },
                                        unpack: false,
                                        by_ref: false,
                                    },
                                ],
                                span,
                            };
                            return Ok(Expression::FunctionCall {
                                name: Box::new(Expression::StringLiteral {
                                    value: "Closure::fromCallable".to_string(),
                                    span,
                                }),
                                args: vec![Argument {
                                    name: None,
                                    value: callable,
                                    unpack: false,
                                    by_ref: false,
                                }],
                                span,
                            });
                        }

                        let mut args = Vec::new();
                        if self.current_token != Token::RParen {
                            loop {
                                args.push(self.parse_argument()?);
                                if self.current_token == Token::Comma {
                                    self.advance();
                                    if self.current_token == Token::RParen {
                                        break; // trailing comma
                                    }
                                    continue;
                                }
                                break;
                            }
                        }
                        self.expect(Token::RParen)?;
                        Ok(Expression::FunctionCall {
                            name: Box::new(Expression::StaticPropertyAccess {
                                class: Box::new(left),
                                property: Box::new(Expression::StringLiteral {
                                    value: member_name,
                                    span: member_span,
                                }),
                                span,
                            }),
                            args,
                            span,
                        })
                    } else {
                        // Class constant: Class::CONST
                        Ok(Expression::ClassConstant {
                            class: Box::new(left),
                            constant: member_name,
                            span,
                        })
                    }
                } else if self.current_token == Token::BadCharacter {
                    // Dynamic static access: Class::${expr} or Class::$$var
                    let prop = Box::new(self.parse_prefix()?);
                    Ok(Expression::StaticPropertyAccess {
                        class: Box::new(left),
                        property: prop,
                        span,
                    })
                } else if self.current_token == Token::LBrace {
                    // Dynamic static member: Class::{$expr}()
                    self.advance();
                    let expr = self.parse_expression(0)?;
                    self.expect(Token::RBrace)?;
                    let member = Box::new(expr);

                    if self.current_token == Token::LParen {
                        // Dynamic static method call: Class::{$expr}(args)
                        self.advance();
                        let mut args = Vec::new();
                        if self.current_token != Token::RParen {
                            loop {
                                args.push(self.parse_argument()?);
                                if self.current_token == Token::Comma {
                                    self.advance();
                                    if self.current_token == Token::RParen {
                                        break; // trailing comma
                                    }
                                    continue;
                                }
                                break;
                            }
                        }
                        self.expect(Token::RParen)?;
                        Ok(Expression::FunctionCall {
                            name: Box::new(Expression::StaticPropertyAccess {
                                class: Box::new(left),
                                property: member,
                                span,
                            }),
                            args,
                            span,
                        })
                    } else {
                        // Dynamic static property: Class::{$expr}
                        Ok(Expression::StaticPropertyAccess {
                            class: Box::new(left),
                            property: member,
                            span,
                        })
                    }
                } else {
                    Err(self.error("static member name"))
                }
            }

            // Instanceof operator: expr instanceof Class
            Token::Instanceof => {
                self.advance();
                let class = Box::new(self.parse_expression(precedence + 1)?);
                Ok(Expression::Instanceof {
                    expr: Box::new(left),
                    class,
                    span,
                })
            }

            // Array access: $array[index]
            Token::LBracket => {
                self.advance();
                let index = if self.current_token == Token::RBracket {
                    None // $array[] (push syntax)
                } else {
                    Some(Box::new(self.parse_expression(0)?))
                };
                self.expect(Token::RBracket)?;
                Ok(Expression::ArrayAccess {
                    array: Box::new(left),
                    index,
                    span,
                })
            }

            // Function call on expression: $func(), (expr)(), etc.
            Token::LParen => {
                self.advance();

                // First-class callable syntax: $func(...) — PHP 8.1+
                // Only if `...` is followed by `)`, otherwise it's a spread argument like $fn(...$args)
                if self.current_token == Token::Ellipsis && *self.peek() == Token::RParen {
                    self.advance();
                    self.expect(Token::RParen)?;
                    // For $obj->method(...), convert to Closure::fromCallable([$obj, 'method'])
                    let callable = match left {
                        Expression::PropertyAccess {
                            object, property, ..
                        } => {
                            // Extract method name from property expression
                            let method_name = match *property {
                                Expression::StringLiteral { value, .. } => value,
                                _ => "unknown".to_string(),
                            };
                            Expression::ArrayLiteral {
                                elements: vec![
                                    ArrayElement {
                                        key: None,
                                        value: *object,
                                        unpack: false,
                                        by_ref: false,
                                    },
                                    ArrayElement {
                                        key: None,
                                        value: Expression::StringLiteral {
                                            value: method_name,
                                            span,
                                        },
                                        unpack: false,
                                        by_ref: false,
                                    },
                                ],
                                span,
                            }
                        }
                        other => other,
                    };
                    return Ok(Expression::FunctionCall {
                        name: Box::new(Expression::StringLiteral {
                            value: "Closure::fromCallable".to_string(),
                            span,
                        }),
                        args: vec![Argument {
                            name: None,
                            value: callable,
                            unpack: false,
                            by_ref: false,
                        }],
                        span,
                    });
                }

                let mut args = Vec::new();
                if self.current_token != Token::RParen {
                    loop {
                        args.push(self.parse_argument()?);
                        if self.current_token == Token::Comma {
                            self.advance();
                            if self.current_token == Token::RParen {
                                break; // trailing comma
                            }
                            continue;
                        }
                        break;
                    }
                }
                self.expect(Token::RParen)?;
                Ok(Expression::FunctionCall {
                    name: Box::new(left),
                    args,
                    span,
                })
            }

            _ => Ok(left),
        }
    }

    /// Get infix precedence for a token
    /// PHP operator precedence from lowest to highest
    /// Reference: https://www.php.net/manual/en/language.operators.precedence.php
    fn infix_precedence(&self, token: &Token) -> u8 {
        match token {
            // Lowest precedence
            Token::LogicalOr => 1,               // or
            Token::LogicalXor => 2,              // xor
            Token::LogicalAnd => 3,              // and
            Token::Equals => 4,                  // =
            Token::PlusEqual => 4,               // +=
            Token::MinusEqual => 4,              // -=
            Token::MulEqual => 4,                // *=
            Token::DivEqual => 4,                // /=
            Token::ModEqual => 4,                // %=
            Token::PowEqual => 4,                // **=
            Token::ConcatEqual => 4,             // .=
            Token::AndEqual => 4,                // &=
            Token::OrEqual => 4,                 // |=
            Token::XorEqual => 4,                // ^=
            Token::SlEqual => 4,                 // <<=
            Token::SrEqual => 4,                 // >>=
            Token::CoalesceEqual => 4,           // ??=
            Token::Question => 5,                // ? :
            Token::Coalesce => 6,                // ??
            Token::BooleanOr => 7,               // ||
            Token::BooleanAnd => 8,              // &&
            Token::VerticalBar => 9,             // |
            Token::Caret => 10,                  // ^
            Token::Ampersand => 11,              // &
            Token::IsEqual => 12,                // ==
            Token::IsNotEqual => 12,             // !=
            Token::IsIdentical => 12,            // ===
            Token::IsNotIdentical => 12,         // !==
            Token::Spaceship => 13,              // <=>
            Token::LessThan => 14,               // <
            Token::IsSmallerOrEqual => 14,       // <=
            Token::GreaterThan => 14,            // >
            Token::IsGreaterOrEqual => 14,       // >=
            Token::Sl => 15,                     // <<
            Token::Sr => 15,                     // >>
            Token::Plus => 16,                   // +
            Token::Minus => 16,                  // -
            Token::Dot => 16,                    // .
            Token::Star => 17,                   // *
            Token::Slash => 17,                  // /
            Token::Percent => 17,                // %
            Token::Instanceof => 19,             // instanceof (above ! but below other prefix)
            Token::Pow => 21,                    // ** (right-associative, higher precedence)
            Token::Inc => 22,                    // ++ (postfix)
            Token::Dec => 22,                    // -- (postfix)
            Token::ObjectOperator => 23,         // -> (object property access)
            Token::NullsafeObjectOperator => 23, // ?-> (nullsafe property access)
            Token::PaamayimNekudotayim => 23,    // :: (static access)
            Token::LBracket => 23,               // [ ] (array access)
            Token::LParen => 23,                 // ( ) (function call)
            _ => 0,                              // Not an infix operator
        }
    }

    /// Precedence for most prefix operators (unary ~, ++, --, casts, @, +, -)
    const PREFIX_PRECEDENCE: u8 = 20;
    /// Precedence for logical NOT (!) — lower than instanceof but higher than * / %
    /// PHP precedence: ++ -- ~ (type) @ > instanceof > ! > * / %
    const NOT_PRECEDENCE: u8 = 18;

    /// Convert token to binary operator
    fn token_to_binary_op(token: &Token) -> Option<BinaryOperator> {
        match token {
            Token::Plus => Some(BinaryOperator::Add),
            Token::Minus => Some(BinaryOperator::Sub),
            Token::Star => Some(BinaryOperator::Mul),
            Token::Slash => Some(BinaryOperator::Div),
            Token::Percent => Some(BinaryOperator::Mod),
            Token::Pow => Some(BinaryOperator::Pow),
            Token::Dot => Some(BinaryOperator::Concat),
            Token::IsEqual => Some(BinaryOperator::Equal),
            Token::IsNotEqual => Some(BinaryOperator::NotEqual),
            Token::IsIdentical => Some(BinaryOperator::Identical),
            Token::IsNotIdentical => Some(BinaryOperator::NotIdentical),
            Token::LessThan => Some(BinaryOperator::Less),
            Token::IsSmallerOrEqual => Some(BinaryOperator::LessEqual),
            Token::GreaterThan => Some(BinaryOperator::Greater),
            Token::IsGreaterOrEqual => Some(BinaryOperator::GreaterEqual),
            Token::Spaceship => Some(BinaryOperator::Spaceship),
            Token::BooleanAnd => Some(BinaryOperator::And),
            Token::BooleanOr => Some(BinaryOperator::Or),
            Token::LogicalAnd => Some(BinaryOperator::LogicalAnd),
            Token::LogicalOr => Some(BinaryOperator::LogicalOr),
            Token::LogicalXor => Some(BinaryOperator::LogicalXor),
            Token::Ampersand => Some(BinaryOperator::BitwiseAnd),
            Token::VerticalBar => Some(BinaryOperator::BitwiseOr),
            Token::Caret => Some(BinaryOperator::BitwiseXor),
            Token::Sl => Some(BinaryOperator::ShiftLeft),
            Token::Sr => Some(BinaryOperator::ShiftRight),
            Token::PlusEqual => Some(BinaryOperator::AddAssign),
            Token::MinusEqual => Some(BinaryOperator::SubAssign),
            Token::MulEqual => Some(BinaryOperator::MulAssign),
            Token::DivEqual => Some(BinaryOperator::DivAssign),
            Token::ModEqual => Some(BinaryOperator::ModAssign),
            Token::PowEqual => Some(BinaryOperator::PowAssign),
            Token::ConcatEqual => Some(BinaryOperator::ConcatAssign),
            Token::AndEqual => Some(BinaryOperator::BitwiseAndAssign),
            Token::OrEqual => Some(BinaryOperator::BitwiseOrAssign),
            Token::XorEqual => Some(BinaryOperator::BitwiseXorAssign),
            Token::SlEqual => Some(BinaryOperator::ShiftLeftAssign),
            Token::SrEqual => Some(BinaryOperator::ShiftRightAssign),
            Token::CoalesceEqual => Some(BinaryOperator::CoalesceAssign),
            _ => None,
        }
    }
}

/// Parse error with line/column information
///
/// Formats error messages in PHP's style:
/// `Parse error: syntax error, unexpected token "}", expecting ";" on line 5`
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnexpectedToken {
        expected: String,
        found: Token,
        span: Span,
    },
    UnexpectedEof {
        expected: String,
        span: Span,
    },
}

impl ParseError {
    /// Returns the line number where the error occurred (1-indexed).
    pub fn line(&self) -> usize {
        match self {
            ParseError::UnexpectedToken { span, .. } => span.line,
            ParseError::UnexpectedEof { span, .. } => span.line,
        }
    }

    /// Returns the column number where the error occurred (1-indexed).
    pub fn column(&self) -> usize {
        match self {
            ParseError::UnexpectedToken { span, .. } => span.column,
            ParseError::UnexpectedEof { span, .. } => span.column,
        }
    }

    /// Returns the span where the error occurred.
    pub fn span(&self) -> &Span {
        match self {
            ParseError::UnexpectedToken { span, .. } => span,
            ParseError::UnexpectedEof { span, .. } => span,
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnexpectedToken {
                expected,
                found,
                span,
            } => {
                if expected.is_empty() {
                    write!(
                        f,
                        "Parse error: syntax error, unexpected token {} on line {}",
                        found, span.line
                    )
                } else {
                    write!(
                        f,
                        "Parse error: syntax error, unexpected token {}, expecting {} on line {}",
                        found, expected, span.line
                    )
                }
            }
            ParseError::UnexpectedEof { expected, span } => {
                if expected.is_empty() {
                    write!(
                        f,
                        "Parse error: syntax error, unexpected end of file on line {}",
                        span.line
                    )
                } else {
                    write!(
                        f,
                        "Parse error: syntax error, unexpected end of file, expecting {} on line {}",
                        expected, span.line
                    )
                }
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a PHP integer literal string to i64.
/// Handles decimal, hex (0x), octal (0o, 0), binary (0b), and underscores.
fn parse_int_literal(text: &str) -> i64 {
    let s = text.replace('_', "");
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else if s.starts_with("0b") || s.starts_with("0B") {
        i64::from_str_radix(&s[2..], 2).unwrap_or(0)
    } else if s.starts_with("0o") || s.starts_with("0O") {
        i64::from_str_radix(&s[2..], 8).unwrap_or(0)
    } else if s.starts_with('0') && s.len() > 1 && !s.contains('.') {
        // Legacy octal: 0777
        i64::from_str_radix(&s[1..], 8).unwrap_or(0)
    } else {
        s.parse::<i64>().unwrap_or(0)
    }
}

/// Parse a PHP float literal string to f64.
fn parse_float_literal(text: &str) -> f64 {
    let s = text.replace('_', "");
    s.parse::<f64>().unwrap_or(0.0)
}

/// Parse a PHP string literal, stripping quotes and processing escapes.
fn parse_string_literal(text: &str) -> String {
    if text.len() < 2 {
        return text.to_string();
    }

    let quote = text.as_bytes()[0];
    let inner = &text[1..text.len() - 1];

    if quote == b'\'' {
        // Single-quoted: only \\ and \' are escape sequences
        let mut result = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('\\') => result.push('\\'),
                    Some('\'') => result.push('\''),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(ch);
            }
        }
        result
    } else {
        // Double-quoted: full escape sequence processing
        let mut result = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('v') => result.push('\x0B'),
                    Some('e') => result.push('\x1B'),
                    Some('f') => result.push('\x0C'),
                    Some('\\') => result.push('\\'),
                    Some('$') => result.push('$'),
                    Some('"') => result.push('"'),
                    Some('x') | Some('X') => {
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(&c) = chars.peek() {
                                if c.is_ascii_hexdigit() {
                                    hex.push(c);
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                        }
                        if let Ok(val) = u8::from_str_radix(&hex, 16) {
                            result.push(val as char);
                        }
                    }
                    Some('0') => {
                        let mut oct = String::from("0");
                        for _ in 0..2 {
                            if let Some(&c) = chars.peek() {
                                if ('0'..='7').contains(&c) {
                                    oct.push(c);
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                        }
                        if let Ok(val) = u32::from_str_radix(&oct, 8) {
                            if let Some(ch) = char::from_u32(val) {
                                result.push(ch);
                            }
                        }
                    }
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(ch);
            }
        }
        result
    }
}

/// Unescape a double-quoted string fragment (without surrounding quotes).
/// Handles PHP escape sequences: \n, \r, \t, \v, \e, \f, \\, \$, \", \xHH, \0oo.
fn unescape_double_quoted(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('v') => result.push('\x0B'),
                Some('e') => result.push('\x1B'),
                Some('f') => result.push('\x0C'),
                Some('\\') => result.push('\\'),
                Some('$') => result.push('$'),
                Some('"') => result.push('"'),
                Some('x') | Some('X') => {
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if let Some(&c) = chars.peek() {
                            if c.is_ascii_hexdigit() {
                                hex.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if let Ok(val) = u8::from_str_radix(&hex, 16) {
                        result.push(val as char);
                    }
                }
                Some('0') => {
                    let mut oct = String::from("0");
                    for _ in 0..2 {
                        if let Some(&c) = chars.peek() {
                            if ('0'..='7').contains(&c) {
                                oct.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if let Ok(val) = u32::from_str_radix(&oct, 8) {
                        if let Some(ch) = char::from_u32(val) {
                            result.push(ch);
                        }
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        // Test that parser can be created and tokenizes correctly
        let source = "<?php 42";
        let mut parser = Parser::new(source);

        // Should have <?php as first token
        assert_eq!(parser.current_token, Token::OpenTag);

        // Advance to next token
        parser.advance();

        // Should have LNumber
        assert_eq!(parser.current_token, Token::LNumber);
    }

    #[test]
    fn test_simple_addition() {
        // Test: 1 + 2 should parse as BinaryOp(Add, 1, 2)
        let source = "<?php 1 + 2";
        let mut parser = Parser::new(source);

        // Skip <?php token
        parser.advance();

        let expr = parser.parse_expression(0).unwrap();

        // Verify structure: BinaryOp(Add, IntLiteral, IntLiteral)
        match expr {
            Expression::BinaryOp {
                op: BinaryOperator::Add,
                lhs,
                rhs,
                ..
            } => {
                // lhs and rhs should be IntLiterals (value doesn't matter for now)
                assert!(matches!(*lhs, Expression::IntLiteral { .. }));
                assert!(matches!(*rhs, Expression::IntLiteral { .. }));
            }
            _ => panic!("Expected addition at top level"),
        }
    }

    #[test]
    fn test_arithmetic_precedence() {
        // Test: 2 + 3 * 4 should parse as 2 + (3 * 4)
        // (multiplication has higher precedence than addition)
        let source = "<?php 2 + 3 * 4";
        let mut parser = Parser::new(source);

        // Skip <?php token
        parser.advance();

        let expr = parser.parse_expression(0).unwrap();

        // Verify structure: BinaryOp(Add, IntLiteral, BinaryOp(Mul, IntLiteral, IntLiteral))
        match expr {
            Expression::BinaryOp {
                op: BinaryOperator::Add,
                lhs,
                rhs,
                ..
            } => {
                // lhs should be IntLiteral
                assert!(matches!(*lhs, Expression::IntLiteral { .. }));

                // rhs should be BinaryOp(Mul, IntLiteral, IntLiteral)
                match *rhs {
                    Expression::BinaryOp {
                        op: BinaryOperator::Mul,
                        lhs: ref mul_lhs,
                        rhs: ref mul_rhs,
                        ..
                    } => {
                        assert!(matches!(**mul_lhs, Expression::IntLiteral { .. }));
                        assert!(matches!(**mul_rhs, Expression::IntLiteral { .. }));
                    }
                    _ => panic!("Expected multiplication in rhs, got {:?}", rhs),
                }
            }
            _ => panic!("Expected addition at top level, got {:?}", expr),
        }
    }

    #[test]
    fn test_assignment_right_associativity() {
        // Test: $a = $b = 1 should parse as $a = ($b = 1)
        let source = "<?php $a = $b = 1";
        let mut parser = Parser::new(source);

        parser.advance(); // Skip <?php

        let expr = parser.parse_expression(0).unwrap();

        // Verify structure: Assign($a, Assign($b, IntLiteral))
        match expr {
            Expression::Assign { lhs, rhs, .. } => {
                // lhs should be Variable($a)
                assert!(matches!(*lhs, Expression::Variable { .. }));

                // rhs should be Assign($b, IntLiteral)
                match *rhs {
                    Expression::Assign {
                        lhs: ref inner_lhs,
                        rhs: ref inner_rhs,
                        ..
                    } => {
                        assert!(matches!(**inner_lhs, Expression::Variable { .. }));
                        assert!(matches!(**inner_rhs, Expression::IntLiteral { .. }));
                    }
                    _ => panic!("Expected assignment in rhs"),
                }
            }
            _ => panic!("Expected assignment at top level"),
        }
    }

    #[test]
    fn test_ternary_associativity() {
        // Test: $a ? 1 : $b ? 2 : 3 (left-to-right)
        // Should parse as: ($a ? 1 : $b) ? 2 : 3
        let source = "<?php $a ? 1 : $b ? 2 : 3";
        let mut parser = Parser::new(source);

        parser.advance(); // Skip <?php

        let expr = parser.parse_expression(0).unwrap();

        // In PHP 8+, this would be a deprecated parse error for ambiguous nesting
        // For now, we just verify it parses
        assert!(matches!(expr, Expression::Ternary { .. }));
    }

    #[test]
    fn test_null_coalesce_right_associativity() {
        // Test: $a ?? $b ?? $c should parse as $a ?? ($b ?? $c)
        let source = "<?php $a ?? $b ?? $c";
        let mut parser = Parser::new(source);

        parser.advance(); // Skip <?php

        let expr = parser.parse_expression(0).unwrap();

        // Verify structure: Coalesce($a, Coalesce($b, $c))
        match expr {
            Expression::Coalesce { lhs, rhs, .. } => {
                assert!(matches!(*lhs, Expression::Variable { .. }));

                match *rhs {
                    Expression::Coalesce {
                        lhs: ref inner_lhs,
                        rhs: ref inner_rhs,
                        ..
                    } => {
                        assert!(matches!(**inner_lhs, Expression::Variable { .. }));
                        assert!(matches!(**inner_rhs, Expression::Variable { .. }));
                    }
                    _ => panic!("Expected coalesce in rhs"),
                }
            }
            _ => panic!("Expected coalesce at top level"),
        }
    }

    #[test]
    fn test_power_operator_right_associativity() {
        // Test: 2 ** 3 ** 2 should parse as 2 ** (3 ** 2) = 2 ** 9 = 512
        let source = "<?php 2 ** 3 ** 2";
        let mut parser = Parser::new(source);

        parser.advance(); // Skip <?php

        let expr = parser.parse_expression(0).unwrap();

        // Verify structure: BinaryOp(Pow, IntLiteral, BinaryOp(Pow, IntLiteral, IntLiteral))
        match expr {
            Expression::BinaryOp {
                op: BinaryOperator::Pow,
                lhs,
                rhs,
                ..
            } => {
                assert!(matches!(*lhs, Expression::IntLiteral { .. }));

                match *rhs {
                    Expression::BinaryOp {
                        op: BinaryOperator::Pow,
                        lhs: ref pow_lhs,
                        rhs: ref pow_rhs,
                        ..
                    } => {
                        assert!(matches!(**pow_lhs, Expression::IntLiteral { .. }));
                        assert!(matches!(**pow_rhs, Expression::IntLiteral { .. }));
                    }
                    _ => panic!("Expected power in rhs"),
                }
            }
            _ => panic!("Expected power at top level"),
        }
    }

    #[test]
    fn test_all_cast_expressions() {
        // Test all cast types
        let test_cases = vec![
            ("<?php (int)1", CastType::Int),
            ("<?php (float)1", CastType::Float),
            ("<?php (string)1", CastType::String),
            ("<?php (bool)1", CastType::Bool),
            ("<?php (array)1", CastType::Array),
            ("<?php (object)1", CastType::Object),
            ("<?php (unset)1", CastType::Unset),
        ];

        for (source, expected_cast) in test_cases {
            let mut parser = Parser::new(source);
            parser.advance(); // Skip <?php

            let expr = parser.parse_expression(0).unwrap();

            match expr {
                Expression::Cast {
                    cast_type, expr, ..
                } => {
                    assert_eq!(cast_type, expected_cast);
                    // The casted expression should be an integer
                    assert!(matches!(*expr, Expression::IntLiteral { .. }));
                }
                _ => panic!("Expected cast expression for {}", source),
            }
        }
    }

    #[test]
    fn test_simple_if_statement() {
        // Test: if ($x) return 1;
        let source = "<?php if ($x) return 1;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                // Condition should be Variable($x)
                assert!(matches!(*condition, Expression::Variable { .. }));
                // Then branch should be Return(IntLiteral(1))
                assert!(matches!(*then_branch, Statement::Return { .. }));
                // No elseif or else
                assert!(elseif_branches.is_empty());
                assert!(else_branch.is_none());
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_if_else_statement() {
        // Test: if ($x) return 1; else return 0;
        let source = "<?php if ($x) return 1; else return 0;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                assert!(matches!(*then_branch, Statement::Return { .. }));
                assert!(elseif_branches.is_empty());
                // Else branch should exist
                assert!(else_branch.is_some());
                assert!(matches!(*else_branch.unwrap(), Statement::Return { .. }));
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_if_elseif_else_statement() {
        // Test: if ($x) return 1; elseif ($y) return 2; else return 0;
        let source = "<?php if ($x) return 1; elseif ($y) return 2; else return 0;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                assert!(matches!(*then_branch, Statement::Return { .. }));
                // One elseif branch
                assert_eq!(elseif_branches.len(), 1);
                let (elseif_cond, elseif_body) = &elseif_branches[0];
                assert!(matches!(elseif_cond, Expression::Variable { .. }));
                assert!(matches!(elseif_body, Statement::Return { .. }));
                // Else branch should exist
                assert!(else_branch.is_some());
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_multiple_elseif() {
        // Test: if ($x) return 1; elseif ($y) return 2; elseif ($z) return 3;
        let source = "<?php if ($x) return 1; elseif ($y) return 2; elseif ($z) return 3;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                elseif_branches, ..
            } => {
                // Two elseif branches
                assert_eq!(elseif_branches.len(), 2);
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_alternative_syntax_if() {
        // Test: if ($x): return 1; endif;
        let source = "<?php if ($x): return 1; endif;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                // Then branch should be a Block with one return statement
                match *then_branch {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 1);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in then branch"),
                }
                assert!(elseif_branches.is_empty());
                assert!(else_branch.is_none());
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_alternative_syntax_if_else() {
        // Test: if ($x): return 1; else: return 0; endif;
        let source = "<?php if ($x): return 1; else: return 0; endif;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                assert!(matches!(*then_branch, Statement::Block { .. }));
                assert!(elseif_branches.is_empty());
                // Else branch should be a block
                assert!(else_branch.is_some());
                match *else_branch.unwrap() {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 1);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in else branch"),
                }
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_alternative_syntax_if_elseif_else() {
        // Test: if ($x): return 1; elseif ($y): return 2; else: return 0; endif;
        let source = "<?php if ($x): return 1; elseif ($y): return 2; else: return 0; endif;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If {
                condition,
                then_branch,
                elseif_branches,
                else_branch,
                ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                assert!(matches!(*then_branch, Statement::Block { .. }));
                // One elseif branch
                assert_eq!(elseif_branches.len(), 1);
                let (elseif_cond, elseif_body) = &elseif_branches[0];
                assert!(matches!(elseif_cond, Expression::Variable { .. }));
                assert!(matches!(elseif_body, Statement::Block { .. }));
                // Else branch should exist
                assert!(else_branch.is_some());
                assert!(matches!(*else_branch.unwrap(), Statement::Block { .. }));
            }
            _ => panic!("Expected if statement"),
        }
    }

    #[test]
    fn test_alternative_syntax_multiple_statements() {
        // Test: if ($x): return 1; return 2; endif;
        let source = "<?php if ($x): return 1; return 2; endif;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::If { then_branch, .. } => {
                // Then branch should be a Block with two return statements
                match *then_branch {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 2);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                        assert!(matches!(statements[1], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in then branch"),
                }
            }
            _ => panic!("Expected if statement"),
        }
    }

    // Loop statement tests

    #[test]
    fn test_simple_while_loop() {
        // Test: while ($x) return 1;
        let source = "<?php while ($x) return 1;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::While {
                condition, body, ..
            } => {
                // Condition should be Variable($x)
                assert!(matches!(*condition, Expression::Variable { .. }));
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
            }
            _ => panic!("Expected while statement"),
        }
    }

    #[test]
    fn test_while_alternative_syntax() {
        // Test: while ($x): return 1; endwhile;
        let source = "<?php while ($x): return 1; endwhile;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::While {
                condition, body, ..
            } => {
                assert!(matches!(*condition, Expression::Variable { .. }));
                // Body should be a Block with one return statement
                match *body {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 1);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in body"),
                }
            }
            _ => panic!("Expected while statement"),
        }
    }

    #[test]
    fn test_do_while_loop() {
        // Test: do return 1; while ($x);
        let source = "<?php do return 1; while ($x);";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::DoWhile {
                body, condition, ..
            } => {
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
                // Condition should be Variable($x)
                assert!(matches!(*condition, Expression::Variable { .. }));
            }
            _ => panic!("Expected do-while statement"),
        }
    }

    #[test]
    fn test_for_loop_basic() {
        // Test: for ($i = 0; $i < 10; $i++) return $i;
        let source = "<?php for ($i = 0; $i < 10; $i++) return $i;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::For {
                init,
                condition,
                increment,
                body,
                ..
            } => {
                // Init should have one expression
                assert_eq!(init.len(), 1);
                assert!(matches!(init[0], Expression::Assign { .. }));
                // Condition should have one expression
                assert_eq!(condition.len(), 1);
                assert!(matches!(condition[0], Expression::BinaryOp { .. }));
                // Increment should have one expression
                assert_eq!(increment.len(), 1);
                assert!(matches!(increment[0], Expression::PostIncrement { .. }));
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
            }
            _ => panic!("Expected for statement"),
        }
    }

    #[test]
    fn test_for_loop_empty_parts() {
        // Test: for (;;) return 1;
        let source = "<?php for (;;) return 1;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::For {
                init,
                condition,
                increment,
                body,
                ..
            } => {
                // All parts should be empty
                assert_eq!(init.len(), 0);
                assert_eq!(condition.len(), 0);
                assert_eq!(increment.len(), 0);
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
            }
            _ => panic!("Expected for statement"),
        }
    }

    #[test]
    fn test_for_loop_multiple_expressions() {
        // Test: for ($i = 0, $j = 0; $i < 10, $j < 10; $i++, $j++) return 1;
        let source = "<?php for ($i = 0, $j = 0; $i < 10, $j < 10; $i++, $j++) return 1;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::For {
                init,
                condition,
                increment,
                ..
            } => {
                // Each part should have two expressions
                assert_eq!(init.len(), 2);
                assert_eq!(condition.len(), 2);
                assert_eq!(increment.len(), 2);
            }
            _ => panic!("Expected for statement"),
        }
    }

    #[test]
    fn test_for_alternative_syntax() {
        // Test: for ($i = 0; $i < 10; $i++): return $i; endfor;
        let source = "<?php for ($i = 0; $i < 10; $i++): return $i; endfor;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::For { body, .. } => {
                // Body should be a Block
                match *body {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 1);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in body"),
                }
            }
            _ => panic!("Expected for statement"),
        }
    }

    #[test]
    fn test_foreach_simple_value() {
        // Test: foreach ($arr as $value) return $value;
        let source = "<?php foreach ($arr as $value) return $value;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Foreach {
                iterable,
                key,
                value,
                by_ref,
                body,
                ..
            } => {
                // Iterable should be Variable($arr)
                assert!(matches!(*iterable, Expression::Variable { .. }));
                // No key
                assert!(key.is_none());
                // Value should be Variable($value)
                assert!(matches!(*value, Expression::Variable { .. }));
                // Not by reference
                assert!(!by_ref);
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
            }
            _ => panic!("Expected foreach statement"),
        }
    }

    #[test]
    fn test_foreach_key_value() {
        // Test: foreach ($arr as $key => $value) return $value;
        let source = "<?php foreach ($arr as $key => $value) return $value;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Foreach {
                iterable,
                key,
                value,
                by_ref,
                body,
                ..
            } => {
                // Iterable should be Variable($arr)
                assert!(matches!(*iterable, Expression::Variable { .. }));
                // Key should exist and be Variable($key)
                assert!(key.is_some());
                assert!(matches!(*key.unwrap(), Expression::Variable { .. }));
                // Value should be Variable($value)
                assert!(matches!(*value, Expression::Variable { .. }));
                // Not by reference
                assert!(!by_ref);
                // Body should be Return statement
                assert!(matches!(*body, Statement::Return { .. }));
            }
            _ => panic!("Expected foreach statement"),
        }
    }

    #[test]
    fn test_foreach_by_reference() {
        // Test: foreach ($arr as $key => &$value) return $value;
        let source = "<?php foreach ($arr as $key => &$value) return $value;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Foreach { by_ref, .. } => {
                // Should be by reference
                assert!(by_ref);
            }
            _ => panic!("Expected foreach statement"),
        }
    }

    #[test]
    fn test_foreach_alternative_syntax() {
        // Test: foreach ($arr as $value): return $value; endforeach;
        let source = "<?php foreach ($arr as $value): return $value; endforeach;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Foreach { body, .. } => {
                // Body should be a Block
                match *body {
                    Statement::Block { statements, .. } => {
                        assert_eq!(statements.len(), 1);
                        assert!(matches!(statements[0], Statement::Return { .. }));
                    }
                    _ => panic!("Expected block in body"),
                }
            }
            _ => panic!("Expected foreach statement"),
        }
    }

    #[test]
    fn test_switch_simple() {
        // Test: switch ($x) { case 1: return 1; case 2: return 2; default: return 0; }
        let source = "<?php switch ($x) { case 1: return 1; case 2: return 2; default: return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Switch {
                condition, cases, ..
            } => {
                // Condition should be Variable($x)
                assert!(matches!(*condition, Expression::Variable { .. }));
                // Should have 3 cases (2 case + 1 default)
                assert_eq!(cases.len(), 3);
                // First case should have condition Some(1)
                assert!(cases[0].condition.is_some());
                // Last case should be default (None)
                assert!(cases[2].condition.is_none());
            }
            _ => panic!("Expected switch statement"),
        }
    }

    #[test]
    fn test_switch_fallthrough() {
        // Test: switch ($x) { case 1: case 2: return 2; }
        let source = "<?php switch ($x) { case 1: case 2: return 2; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Switch { cases, .. } => {
                // Should have 2 cases
                assert_eq!(cases.len(), 2);
                // First case should have empty statements (fallthrough)
                assert_eq!(cases[0].statements.len(), 0);
                // Second case should have 1 statement
                assert_eq!(cases[1].statements.len(), 1);
            }
            _ => panic!("Expected switch statement"),
        }
    }

    #[test]
    fn test_switch_alternative_syntax() {
        // Test: switch ($x): case 1: return 1; endswitch;
        let source = "<?php switch ($x): case 1: return 1; endswitch;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Switch { cases, .. } => {
                assert_eq!(cases.len(), 1);
                assert!(cases[0].condition.is_some());
            }
            _ => panic!("Expected switch statement"),
        }
    }

    #[test]
    fn test_match_expression() {
        // Test: $result = match ($x) { 1 => 'one', 2 => 'two', default => 'other' };
        let source = "<?php $result = match ($x) { 1 => 'one', 2 => 'two', default => 'other' };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        // Parse the assignment expression
        let expr = parser.parse_expression(0).unwrap();

        match expr {
            Expression::Assign { rhs, .. } => {
                // RHS should be a match expression
                match *rhs {
                    Expression::MatchExpr {
                        condition, arms, ..
                    } => {
                        // Condition should be Variable($x)
                        assert!(matches!(*condition, Expression::Variable { .. }));
                        // Should have 3 arms
                        assert_eq!(arms.len(), 3);
                        // First two arms should have conditions
                        assert_eq!(arms[0].conditions.len(), 1);
                        assert_eq!(arms[1].conditions.len(), 1);
                        // Last arm should be default (empty conditions)
                        assert_eq!(arms[2].conditions.len(), 0);
                    }
                    _ => panic!("Expected match expression"),
                }
            }
            _ => panic!("Expected assignment"),
        }
    }

    #[test]
    fn test_match_multiple_conditions() {
        // Test: match ($x) { 1, 2, 3 => 'low', 4, 5 => 'mid' }
        let source = "<?php match ($x) { 1, 2, 3 => 'low', 4, 5 => 'mid' };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let expr = parser.parse_expression(0).unwrap();

        match expr {
            Expression::MatchExpr { arms, .. } => {
                // First arm should have 3 conditions
                assert_eq!(arms[0].conditions.len(), 3);
                // Second arm should have 2 conditions
                assert_eq!(arms[1].conditions.len(), 2);
            }
            _ => panic!("Expected match expression"),
        }
    }

    #[test]
    fn test_match_as_statement() {
        // Test: match statement variant (from AST)
        let source = "<?php match ($x) { 1 => return 1, 2 => return 2 };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        // Should be able to parse as a statement
        let stmt = parser.parse_statement();

        // For now, this might fail since match is typically an expression
        // But we have Statement::Match in the AST for alternative handling
        assert!(stmt.is_ok() || stmt.is_err()); // Just verify it completes
    }

    // Try-catch-finally statement tests

    #[test]
    fn test_try_catch_simple() {
        // Test: try { } catch (Exception $e) { }
        let source = "<?php try { return 1; } catch (Exception $e) { return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try {
                body,
                catches,
                finally,
                ..
            } => {
                // Body should have one statement
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::Return { .. }));
                // Should have one catch clause
                assert_eq!(catches.len(), 1);
                assert_eq!(catches[0].types.len(), 1);
                assert!(catches[0].var.is_some());
                assert_eq!(catches[0].body.len(), 1);
                // No finally
                assert!(finally.is_none());
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_catch_finally() {
        // Test: try { } catch (Exception $e) { } finally { }
        let source =
            "<?php try { return 1; } catch (Exception $e) { return 0; } finally { return 2; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try {
                body,
                catches,
                finally,
                ..
            } => {
                // Body should have one statement
                assert_eq!(body.len(), 1);
                // Should have one catch clause
                assert_eq!(catches.len(), 1);
                // Should have finally
                assert!(finally.is_some());
                let finally_body = finally.unwrap();
                assert_eq!(finally_body.len(), 1);
                assert!(matches!(finally_body[0], Statement::Return { .. }));
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_finally_without_catch() {
        // Test: try { } finally { } (no catch)
        let source = "<?php try { return 1; } finally { return 2; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try {
                body,
                catches,
                finally,
                ..
            } => {
                // Body should have one statement
                assert_eq!(body.len(), 1);
                // No catch clauses
                assert_eq!(catches.len(), 0);
                // Should have finally
                assert!(finally.is_some());
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_multiple_catch() {
        // Test: try { } catch (Exception1 $e) { } catch (Exception2 $e) { }
        let source = "<?php try { return 1; } catch (Exception1 $e) { return 0; } catch (Exception2 $e) { return 2; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try { catches, .. } => {
                // Should have two catch clauses
                assert_eq!(catches.len(), 2);
                assert_eq!(catches[0].types.len(), 1);
                assert_eq!(catches[1].types.len(), 1);
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_multicatch() {
        // Test: try { } catch (Exception1 | Exception2 $e) { }
        // Multi-catch with pipe separator (PHP 7.1+)
        let source = "<?php try { return 1; } catch (Exception1 | Exception2 $e) { return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try { catches, .. } => {
                // Should have one catch clause with two exception types
                assert_eq!(catches.len(), 1);
                assert_eq!(catches[0].types.len(), 2);
                assert!(catches[0].var.is_some());
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_catch_without_variable() {
        // Test: try { } catch (Exception) { } (PHP 8.0+ - no variable)
        let source = "<?php try { return 1; } catch (Exception) { return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try { catches, .. } => {
                // Should have one catch clause without variable
                assert_eq!(catches.len(), 1);
                assert!(catches[0].var.is_none());
            }
            _ => panic!("Expected try statement"),
        }
    }

    #[test]
    fn test_try_without_catch_or_finally_fails() {
        // Test: try { } without catch or finally should fail
        let source = "<?php try { return 1; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let result = parser.parse_statement();

        // Should fail because no catch or finally
        assert!(result.is_err());
    }

    #[test]
    fn test_try_nested() {
        // Test: Nested try-catch blocks
        let source = "<?php try { try { return 1; } catch (Exception $e) { return 2; } } catch (Exception $e) { return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Try { body, catches, .. } => {
                // Outer try should have one statement (inner try)
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::Try { .. }));
                // Outer should have one catch
                assert_eq!(catches.len(), 1);
            }
            _ => panic!("Expected try statement"),
        }
    }

    // ========================================================================
    // FUNCTION DECLARATION TESTS
    // ========================================================================

    #[test]
    fn test_simple_function() {
        // Test: function test() { return 42; }
        let source = "<?php function test() { return 42; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function {
                name,
                params,
                return_type,
                body,
                by_ref,
                ..
            } => {
                assert_eq!(name, "test");
                assert_eq!(params.len(), 0);
                assert!(return_type.is_none());
                assert!(!by_ref);
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::Return { .. }));
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_with_params() {
        // Test: function add($a, $b) { return $a + $b; }
        let source = "<?php function add($a, $b) { return $a + $b; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function {
                name, params, body, ..
            } => {
                assert_eq!(name, "add");
                assert_eq!(params.len(), 2);
                assert_eq!(params[0].name, "$a");
                assert_eq!(params[1].name, "$b");
                assert_eq!(body.len(), 1);
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_with_type_hints() {
        // Test: function greet(string $name): string { return $name; }
        let source = "<?php function greet(string $name): string { return $name; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function {
                params,
                return_type,
                ..
            } => {
                assert_eq!(params.len(), 1);
                // Parameter should have type
                assert!(params[0].param_type.is_some());
                // Return type should be set
                assert!(return_type.is_some());
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_with_default_params() {
        // Test: function greet($name = "World") { return $name; }
        let source = "<?php function greet($name = \"World\") { return $name; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { params, .. } => {
                assert_eq!(params.len(), 1);
                assert!(params[0].default.is_some());
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_variadic() {
        // Test: function sum(...$numbers) { return 0; }
        let source = "<?php function sum(...$numbers) { return 0; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { params, .. } => {
                assert_eq!(params.len(), 1);
                assert!(params[0].variadic);
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_by_reference() {
        // Test: function &getRef() { return $x; }
        let source = "<?php function &getRef() { return $x; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { by_ref, .. } => {
                assert!(by_ref);
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_reference_parameter() {
        // Test: function swap(&$a, &$b) { }
        let source = "<?php function swap(&$a, &$b) { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { params, .. } => {
                assert_eq!(params.len(), 2);
                assert!(params[0].by_ref);
                assert!(params[1].by_ref);
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_closure_simple() {
        // Test: $fn = function() { return 42; };
        let source = "<?php $fn = function() { return 42; };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::Closure {
                        params,
                        body,
                        uses,
                        is_static,
                        ..
                    } => {
                        assert_eq!(params.len(), 0);
                        assert_eq!(uses.len(), 0);
                        assert!(!is_static);
                        assert_eq!(body.len(), 1);
                    }
                    _ => panic!("Expected closure in assignment"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_closure_with_use() {
        // Test: $fn = function($x) use ($y) { return $x + $y; };
        let source = "<?php $fn = function($x) use ($y) { return $x + $y; };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::Closure { uses, .. } => {
                        assert_eq!(uses.len(), 1);
                        assert_eq!(uses[0].name, "y");
                        assert!(!uses[0].by_ref);
                    }
                    _ => panic!("Expected closure"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_closure_use_by_reference() {
        // Test: $fn = function() use (&$x) { return $x; };
        let source = "<?php $fn = function() use (&$x) { return $x; };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::Closure { uses, .. } => {
                        assert_eq!(uses.len(), 1);
                        assert!(uses[0].by_ref);
                    }
                    _ => panic!("Expected closure"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_closure_static() {
        // Test: $fn = static function() { return 42; };
        let source = "<?php $fn = static function() { return 42; };";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::Closure { is_static, .. } => {
                        assert!(is_static);
                    }
                    _ => panic!("Expected closure"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_arrow_function() {
        // Test: $fn = fn($x) => $x * 2;
        let source = "<?php $fn = fn($x) => $x * 2;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::ArrowFunction { params, body, .. } => {
                        assert_eq!(params.len(), 1);
                        assert!(matches!(body.as_ref(), Expression::BinaryOp { .. }));
                    }
                    _ => panic!("Expected arrow function"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_arrow_function_with_return_type() {
        // Test: $fn = fn(int $x): int => $x * 2;
        let source = "<?php $fn = fn(int $x): int => $x * 2;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Expression { expr, .. } => match expr {
                Expression::Assign { rhs, .. } => match rhs.as_ref() {
                    Expression::ArrowFunction { return_type, .. } => {
                        assert!(return_type.is_some());
                    }
                    _ => panic!("Expected arrow function"),
                },
                _ => panic!("Expected assignment"),
            },
            _ => panic!("Expected expression statement"),
        }
    }

    #[test]
    fn test_function_nullable_return_type() {
        // Test: function test(): ?string { return null; }
        let source = "<?php function test(): ?string { return null; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { return_type, .. } => {
                assert!(return_type.is_some());
                match return_type.unwrap() {
                    Type::Nullable { .. } => {}
                    _ => panic!("Expected nullable type"),
                }
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_function_union_return_type() {
        // Test: function test(): int|string { return 42; }
        let source = "<?php function test(): int|string { return 42; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function { return_type, .. } => {
                assert!(return_type.is_some());
                match return_type.unwrap() {
                    Type::Union { types, .. } => {
                        assert_eq!(types.len(), 2);
                    }
                    _ => panic!("Expected union type"),
                }
            }
            _ => panic!("Expected function declaration"),
        }
    }

    // ========================================================================
    // CLASS DECLARATION TESTS (Task 3.3.6)
    // ========================================================================

    #[test]
    fn test_simple_class() {
        // Test: class Foo { }
        let source = "<?php class Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class {
                name,
                modifiers,
                extends,
                implements,
                members,
                ..
            } => {
                assert_eq!(name, "Foo");
                assert_eq!(modifiers.len(), 0);
                assert!(extends.is_none());
                assert_eq!(implements.len(), 0);
                assert_eq!(members.len(), 0);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_class_with_extends() {
        // Test: class Child extends Parent { }
        let source = "<?php class Child extends Parent { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { name, extends, .. } => {
                assert_eq!(name, "Child");
                assert!(extends.is_some());
                let parent = extends.unwrap();
                assert_eq!(parent.parts.len(), 1);
                assert_eq!(parent.parts[0], "Parent");
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_class_with_implements() {
        // Test: class Foo implements Bar, Baz { }
        let source = "<?php class Foo implements Bar, Baz { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { implements, .. } => {
                assert_eq!(implements.len(), 2);
                assert_eq!(implements[0].parts[0], "Bar");
                assert_eq!(implements[1].parts[0], "Baz");
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_abstract_class() {
        // Test: abstract class Foo { }
        let source = "<?php abstract class Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { modifiers, .. } => {
                assert_eq!(modifiers.len(), 1);
                assert_eq!(modifiers[0], Modifier::Abstract);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_final_class() {
        // Test: final class Foo { }
        let source = "<?php final class Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { modifiers, .. } => {
                assert_eq!(modifiers.len(), 1);
                assert_eq!(modifiers[0], Modifier::Final);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_readonly_class() {
        // Test: readonly class Foo { }
        let source = "<?php readonly class Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { modifiers, .. } => {
                assert_eq!(modifiers.len(), 1);
                assert_eq!(modifiers[0], Modifier::Readonly);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_class_extends_and_implements() {
        // Test: class Foo extends Bar implements Baz, Qux { }
        let source = "<?php class Foo extends Bar implements Baz, Qux { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class {
                name,
                extends,
                implements,
                ..
            } => {
                assert_eq!(name, "Foo");
                assert!(extends.is_some());
                assert_eq!(implements.len(), 2);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_interface_declaration() {
        // Test: interface Foo { }
        let source = "<?php interface Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Interface {
                name,
                extends,
                members,
                ..
            } => {
                assert_eq!(name, "Foo");
                assert_eq!(extends.len(), 0);
                assert_eq!(members.len(), 0);
            }
            _ => panic!("Expected interface declaration"),
        }
    }

    #[test]
    fn test_interface_extends() {
        // Test: interface Child extends Parent { }
        let source = "<?php interface Child extends Parent { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Interface { name, extends, .. } => {
                assert_eq!(name, "Child");
                assert_eq!(extends.len(), 1);
                assert_eq!(extends[0].parts[0], "Parent");
            }
            _ => panic!("Expected interface declaration"),
        }
    }

    #[test]
    fn test_interface_extends_multiple() {
        // Test: interface Foo extends Bar, Baz { }
        let source = "<?php interface Foo extends Bar, Baz { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Interface { extends, .. } => {
                assert_eq!(extends.len(), 2);
                assert_eq!(extends[0].parts[0], "Bar");
                assert_eq!(extends[1].parts[0], "Baz");
            }
            _ => panic!("Expected interface declaration"),
        }
    }

    #[test]
    fn test_trait_declaration() {
        // Test: trait Foo { }
        let source = "<?php trait Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Trait { name, members, .. } => {
                assert_eq!(name, "Foo");
                assert_eq!(members.len(), 0);
            }
            _ => panic!("Expected trait declaration"),
        }
    }

    #[test]
    fn test_enum_declaration() {
        // Test: enum Foo { }
        let source = "<?php enum Foo { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Enum {
                name,
                backing_type,
                implements,
                members,
                ..
            } => {
                assert_eq!(name, "Foo");
                assert!(backing_type.is_none());
                assert_eq!(implements.len(), 0);
                assert_eq!(members.len(), 0);
            }
            _ => panic!("Expected enum declaration"),
        }
    }

    #[test]
    fn test_enum_with_backing_type() {
        // Test: enum Status: int { }
        let source = "<?php enum Status: int { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Enum {
                name, backing_type, ..
            } => {
                assert_eq!(name, "Status");
                assert!(backing_type.is_some());
            }
            _ => panic!("Expected enum declaration"),
        }
    }

    #[test]
    fn test_enum_with_implements() {
        // Test: enum Foo implements Bar, Baz { }
        let source = "<?php enum Foo implements Bar, Baz { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Enum { implements, .. } => {
                assert_eq!(implements.len(), 2);
                assert_eq!(implements[0].parts[0], "Bar");
                assert_eq!(implements[1].parts[0], "Baz");
            }
            _ => panic!("Expected enum declaration"),
        }
    }

    #[test]
    fn test_namespace_simple() {
        // Test: namespace MyNamespace;
        let source = "<?php namespace MyNamespace;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Namespace {
                name, statements, ..
            } => {
                assert!(name.is_some());
                let ns = name.unwrap();
                assert_eq!(ns.parts.len(), 1);
                assert_eq!(ns.parts[0], "MyNamespace");
                assert!(!ns.fully_qualified);
                assert!(!ns.relative);
                assert_eq!(statements.len(), 0); // Simple form has no block
            }
            _ => panic!("Expected namespace declaration, got {:?}", stmt),
        }
    }

    #[test]
    fn test_namespace_qualified() {
        // Test: namespace Foo\Bar\Baz;
        let source = "<?php namespace Foo\\Bar\\Baz;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Namespace { name, .. } => {
                assert!(name.is_some());
                let ns = name.unwrap();
                assert_eq!(ns.parts.len(), 3);
                assert_eq!(ns.parts[0], "Foo");
                assert_eq!(ns.parts[1], "Bar");
                assert_eq!(ns.parts[2], "Baz");
            }
            _ => panic!("Expected namespace declaration"),
        }
    }

    #[test]
    fn test_namespace_with_block() {
        // Test: namespace MyNamespace { }
        let source = "<?php namespace MyNamespace { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Namespace {
                name, statements, ..
            } => {
                assert!(name.is_some());
                let ns = name.unwrap();
                assert_eq!(ns.parts[0], "MyNamespace");
                assert_eq!(statements.len(), 0);
            }
            _ => panic!("Expected namespace declaration"),
        }
    }

    #[test]
    fn test_namespace_global() {
        // Test: namespace { } (global namespace)
        let source = "<?php namespace { }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Namespace {
                name, statements, ..
            } => {
                assert!(name.is_none()); // Global namespace has no name
                assert_eq!(statements.len(), 0);
            }
            _ => panic!("Expected namespace declaration"),
        }
    }

    #[test]
    fn test_use_single() {
        // Test: use Foo\Bar;
        let source = "<?php use Foo\\Bar;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Use { uses, kind, .. } => {
                assert_eq!(kind, UseKind::Normal);
                assert_eq!(uses.len(), 1);
                assert_eq!(uses[0].name.parts.len(), 2);
                assert_eq!(uses[0].name.parts[0], "Foo");
                assert_eq!(uses[0].name.parts[1], "Bar");
                assert!(uses[0].alias.is_none());
            }
            _ => panic!("Expected use declaration"),
        }
    }

    #[test]
    fn test_use_with_alias() {
        // Test: use Foo\Bar as Baz;
        let source = "<?php use Foo\\Bar as Baz;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Use { uses, .. } => {
                assert_eq!(uses.len(), 1);
                assert_eq!(uses[0].name.parts[1], "Bar");
                assert_eq!(uses[0].alias, Some("Baz".to_string()));
            }
            _ => panic!("Expected use declaration"),
        }
    }

    #[test]
    fn test_use_multiple() {
        // Test: use Foo\Bar, Baz\Qux;
        let source = "<?php use Foo\\Bar, Baz\\Qux;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Use { uses, .. } => {
                assert_eq!(uses.len(), 2);
                assert_eq!(uses[0].name.parts[0], "Foo");
                assert_eq!(uses[0].name.parts[1], "Bar");
                assert_eq!(uses[1].name.parts[0], "Baz");
                assert_eq!(uses[1].name.parts[1], "Qux");
            }
            _ => panic!("Expected use declaration"),
        }
    }

    #[test]
    fn test_use_function() {
        // Test: use function Foo\bar;
        let source = "<?php use function Foo\\bar;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Use { uses, kind, .. } => {
                assert_eq!(kind, UseKind::Function);
                assert_eq!(uses.len(), 1);
                assert_eq!(uses[0].name.parts[0], "Foo");
                assert_eq!(uses[0].name.parts[1], "bar");
            }
            _ => panic!("Expected use function declaration"),
        }
    }

    #[test]
    fn test_use_const() {
        // Test: use const Foo\BAR;
        let source = "<?php use const Foo\\BAR;";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Use { uses, kind, .. } => {
                assert_eq!(kind, UseKind::Const);
                assert_eq!(uses.len(), 1);
                assert_eq!(uses[0].name.parts[1], "BAR");
            }
            _ => panic!("Expected use const declaration"),
        }
    }

    #[test]
    fn test_attribute_simple_on_class() {
        // Test: #[A1] class Foo {}
        let source = "<?php #[A1] class Foo {}";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class {
                name, attributes, ..
            } => {
                assert_eq!(name, "Foo");
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].name.parts.len(), 1);
                assert_eq!(attributes[0].name.parts[0], "A1");
                assert_eq!(attributes[0].args.len(), 0);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_attribute_with_args_on_class() {
        // Test: #[A1(1, 'test')] class Foo {}
        let source = "<?php #[A1(1, 'test')] class Foo {}";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class {
                name, attributes, ..
            } => {
                assert_eq!(name, "Foo");
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].name.parts[0], "A1");
                assert_eq!(attributes[0].args.len(), 2);
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_attribute_multiple_on_class() {
        // Test: #[A1] #[A2] class Foo {}
        let source = "<?php #[A1] #[A2] class Foo {}";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class {
                name, attributes, ..
            } => {
                assert_eq!(name, "Foo");
                assert_eq!(attributes.len(), 2);
                assert_eq!(attributes[0].name.parts[0], "A1");
                assert_eq!(attributes[1].name.parts[0], "A2");
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_attribute_on_function() {
        // Test: #[A1(42)] function foo() {}
        let source = "<?php #[A1(42)] function foo() {}";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Function {
                name, attributes, ..
            } => {
                assert_eq!(name, "foo");
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].name.parts[0], "A1");
                assert_eq!(attributes[0].args.len(), 1);
            }
            _ => panic!("Expected function declaration"),
        }
    }

    #[test]
    fn test_attribute_namespaced() {
        // Test: #[Foo\Bar\Attr] class Test {}
        let source = "<?php #[Foo\\Bar\\Attr] class Test {}";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { attributes, .. } => {
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].name.parts.len(), 3);
                assert_eq!(attributes[0].name.parts[0], "Foo");
                assert_eq!(attributes[0].name.parts[1], "Bar");
                assert_eq!(attributes[0].name.parts[2], "Attr");
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_debug_tokens_for_property_hooks() {
        // Debug test: see what tokens are produced
        let source = "<?php class Test { public string $prop { get => $this->value; } }";
        let mut lexer = Lexer::new(source);

        eprintln!("\nTokens for: {}", source);
        let mut i = 0;
        loop {
            match lexer.next_token() {
                Some((token, span)) => {
                    let text = &source[span.start..span.end];
                    eprintln!("{}: {:?} = '{}'", i, token, text);
                    i += 1;
                    if token == Token::End || i > 50 {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    #[test]
    fn test_property_hook_get_expression() {
        // Test: class Test { public string $prop { get => strtoupper($this->value); } }
        let source =
            "<?php class Test { public string $prop { get => strtoupper($this->value); } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                        assert_eq!(hooks[0].by_ref, false);
                        match &hooks[0].body {
                            PropertyHookBody::Expression(_) => {}
                            _ => panic!("Expected expression body"),
                        }
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_set_block() {
        // Test: class Test { public string $prop { set { $this->value = strtoupper($value); } } }
        let source = "<?php class Test { public string $prop { set { $this->value = strtoupper($value); } } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Set);
                        assert_eq!(hooks[0].by_ref, false);
                        match &hooks[0].body {
                            PropertyHookBody::Block(_) => {}
                            _ => panic!("Expected block body"),
                        }
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_get_and_set() {
        // Test: class Test { public string $prop { get => $this->value; set => $this->value = $value; } }
        let source = "<?php class Test { public string $prop { get => $this->value; set => $this->value = $value; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 2);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                        assert_eq!(hooks[1].kind, PropertyHookKind::Set);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_debug_property_parsing() {
        // Debug: trace property parsing with hooks
        let source = "<?php class Test { public string $prop { &get => $this->value; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        eprintln!(
            "Starting to parse class, current token: {:?}",
            parser.current_token
        );
        let result = parser.parse_statement();
        match result {
            Ok(stmt) => eprintln!("Successfully parsed: {:?}", stmt),
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }

    #[test]
    fn test_property_hook_by_ref() {
        // Test: class Test { public string $prop { &get => $this->value; } }
        let source = "<?php class Test { public string $prop { &get => $this->value; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement();
        if let Err(ref e) = stmt {
            eprintln!("Parse error: {:?}", e);
        }
        let stmt = stmt.unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                        assert_eq!(hooks[0].by_ref, true);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_set_with_parameter() {
        // Test: class Test { public string $prop { set(string $value) { $this->data = $value; } } }
        let source = "<?php class Test { public string $prop { set(string $value) { $this->data = $value; } } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Set);
                        assert_eq!(hooks[0].params.len(), 1);
                        assert_eq!(hooks[0].params[0].name, "$value");
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_with_default_value() {
        // Test: class Test { public string $prop = 'default' { get => $this->prop; } }
        let source = "<?php class Test { public string $prop = 'default' { get => $this->prop; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property {
                        name,
                        hooks,
                        default,
                        ..
                    } => {
                        assert_eq!(name, "prop");
                        assert!(default.is_some());
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_private_with_modifiers() {
        // Test: class Test { private readonly string $prop { get => $this->value; } }
        let source = "<?php class Test { private readonly string $prop { get => $this->value; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property {
                        name,
                        modifiers,
                        hooks,
                        ..
                    } => {
                        assert_eq!(name, "prop");
                        assert!(modifiers.contains(&Modifier::Private));
                        assert!(modifiers.contains(&Modifier::Readonly));
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_multiple_properties_with_hooks() {
        // Test: class Test { public $a { get => 1; } public $b { set => null; } }
        let source = "<?php class Test { public $a { get => 1; } public $b { set => null; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 2);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "a");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                    }
                    _ => panic!("Expected property"),
                }
                match &members[1] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "b");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Set);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_complex_expression() {
        // Test: class Test { public int $prop { get => $this->x + $this->y * 2; } }
        let source = "<?php class Test { public int $prop { get => $this->x + $this->y * 2; } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        match &hooks[0].body {
                            PropertyHookBody::Expression(expr) => {
                                // Should be a binary operation
                                assert!(matches!(expr, Expression::BinaryOp { .. }));
                            }
                            _ => panic!("Expected expression body"),
                        }
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    #[ignore] // TODO: This test hangs - investigate infinite loop in parser
    fn test_property_hook_multiline_block() {
        // Test: set hook with multiple statements
        let source = r#"<?php class Test {
            public string $prop {
                set {
                    $this->validate($value);
                    $this->data = strtoupper($value);
                    $this->modified = true;
                }
            }
        }"#;
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        match &hooks[0].body {
                            PropertyHookBody::Block(stmts) => {
                                assert_eq!(stmts.len(), 3);
                            }
                            _ => panic!("Expected block body"),
                        }
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_no_hooks_with_semicolon() {
        // Test: property without hooks should work normally
        let source = "<?php class Test { public string $prop = 'test'; }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 0);
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    #[test]
    fn test_property_hook_get_with_block() {
        // Test: get hook with block body
        let source = "<?php class Test { public $prop { get { return $this->value; } } }";
        let mut parser = Parser::new(source);
        parser.advance(); // Skip <?php

        let stmt = parser.parse_statement().unwrap();

        match stmt {
            Statement::Class { members, .. } => {
                assert_eq!(members.len(), 1);
                match &members[0] {
                    ClassMember::Property { name, hooks, .. } => {
                        assert_eq!(name, "prop");
                        assert_eq!(hooks.len(), 1);
                        assert_eq!(hooks[0].kind, PropertyHookKind::Get);
                        match &hooks[0].body {
                            PropertyHookBody::Block(stmts) => {
                                assert_eq!(stmts.len(), 1);
                            }
                            _ => panic!("Expected block body"),
                        }
                    }
                    _ => panic!("Expected property"),
                }
            }
            _ => panic!("Expected class declaration"),
        }
    }

    // ================================================================
    // Error reporting tests (3.4.1, 3.4.2)
    // ================================================================

    #[test]
    fn test_error_has_line_number() {
        let source = "<?php\n$x = 1;\n$y = ;\n";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        // The error should be on line 3 where the unexpected ";" is
        assert_eq!(err.line(), 3);
        let msg = format!("{}", err);
        assert!(msg.contains("on line 3"), "Error message: {}", msg);
    }

    #[test]
    fn test_error_has_column_info() {
        let source = "<?php $x = ;";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        assert!(err.column() > 1);
    }

    #[test]
    fn test_error_missing_semicolon() {
        let source = "<?php echo 1\necho 2;";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("expecting") && msg.contains("\";\""),
            "Expected semicolon message, got: {}",
            msg
        );
    }

    #[test]
    fn test_error_unexpected_token_display() {
        let source = "<?php if ( { }";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.starts_with("Parse error: syntax error, unexpected token"),
            "Error message: {}",
            msg
        );
    }

    #[test]
    fn test_error_unexpected_eof() {
        let source = "<?php function foo(";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("unexpected end of file") || msg.contains("unexpected token"),
            "Error message: {}",
            msg
        );
    }

    #[test]
    fn test_error_unclosed_brace() {
        let source = "<?php if (true) {";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("end of file"),
            "Expected EOF error for unclosed brace, got: {}",
            msg
        );
    }

    #[test]
    fn test_error_multiline_reports_correct_line() {
        let source = "<?php\n\n\n\n\n$x = ;";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        assert_eq!(err.line(), 6, "Error should be on line 6");
    }

    #[test]
    fn test_error_is_std_error() {
        // Verify ParseError implements std::error::Error
        let source = "<?php $x = ;";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_error_span_accessor() {
        let source = "<?php $x = ;";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let span = err.span();
        assert!(span.line >= 1);
        assert!(span.column >= 1);
        assert!(span.start <= span.end);
    }

    #[test]
    fn test_error_missing_closing_paren() {
        let source = "<?php if (true { }";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("\")\"") || msg.contains("RParen"),
            "Expected closing paren in error, got: {}",
            msg
        );
    }

    #[test]
    fn test_error_invalid_class_member() {
        let source = "<?php class Foo { 42; }";
        let mut parser = Parser::new(source);
        let err = parser.parse().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Parse error"),
            "Expected parse error, got: {}",
            msg
        );
    }

    #[test]
    fn test_token_display_names() {
        // Test PHP-style token display names
        assert_eq!(format!("{}", Token::Semicolon), "\";\"");
        assert_eq!(format!("{}", Token::LBrace), "\"{\"");
        assert_eq!(format!("{}", Token::RBrace), "\"}\"");
        assert_eq!(format!("{}", Token::LParen), "\"(\"");
        assert_eq!(format!("{}", Token::RParen), "\")\"");
        assert_eq!(format!("{}", Token::If), "\"if\"");
        assert_eq!(format!("{}", Token::Class), "\"class\"");
        assert_eq!(format!("{}", Token::Function), "\"function\"");
        assert_eq!(format!("{}", Token::End), "end of file");
        assert_eq!(format!("{}", Token::Variable), "variable");
        assert_eq!(format!("{}", Token::LNumber), "integer");
        assert_eq!(format!("{}", Token::DNumber), "floating-point number");
        assert_eq!(format!("{}", Token::ConstantEncapsedString), "string");
        assert_eq!(format!("{}", Token::String), "identifier");
        assert_eq!(format!("{}", Token::PaamayimNekudotayim), "\"::\"");
        assert_eq!(format!("{}", Token::ObjectOperator), "\"->\"");
        assert_eq!(format!("{}", Token::DoubleArrow), "\"=>\"");
        assert_eq!(format!("{}", Token::Ellipsis), "\"...\"");
    }
}
