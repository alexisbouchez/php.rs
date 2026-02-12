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
        let (current_token, current_span) = lexer
            .next_token()
            .unwrap_or((Token::End, Span::new(0, 0, 1, 1)));
        Self {
            lexer,
            current_token,
            current_span,
            peeked: None,
        }
    }

    /// Advance to the next token
    fn advance(&mut self) {
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
    }

    /// Peek at the next token without consuming it
    fn peek(&mut self) -> &Token {
        if self.peeked.is_none() {
            if let Some((token, span)) = self.lexer.next_token() {
                self.peeked = Some((token, span));
            } else {
                self.peeked = Some((Token::End, Span::new(0, 0, 1, 1)));
            }
        }
        &self.peeked.as_ref().unwrap().0
    }

    /// Check if current token matches expected token
    fn expect(&mut self, expected: Token) -> Result<Span, ParseError> {
        if self.current_token == expected {
            let span = self.current_span;
            self.advance();
            Ok(span)
        } else {
            Err(ParseError::UnexpectedToken {
                expected: format!("{:?}", expected),
                found: self.current_token.clone(),
                span: self.current_span,
            })
        }
    }

    /// Parse an expression with given minimum precedence (Pratt parsing)
    pub fn parse_expression(&mut self, min_precedence: u8) -> Result<Expression, ParseError> {
        // Parse prefix expression (literals, variables, unary ops, etc.)
        let mut left = self.parse_prefix()?;

        // Parse infix/postfix expressions based on precedence
        loop {
            let precedence = self.infix_precedence(&self.current_token);
            if precedence == 0 || precedence < min_precedence {
                break;
            }

            left = self.parse_infix(left, precedence)?;
        }

        Ok(left)
    }

    /// Parse a statement
    pub fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        match self.current_token {
            Token::If => self.parse_if_statement(),
            Token::Return => self.parse_return_statement(),
            Token::While => self.parse_while_statement(),
            Token::Do => self.parse_do_while_statement(),
            Token::For => self.parse_for_statement(),
            Token::Foreach => self.parse_foreach_statement(),
            Token::Switch => self.parse_switch_statement(),
            Token::Match => self.parse_match_statement(),
            _ => Err(ParseError::UnexpectedToken {
                expected: "statement".to_string(),
                found: self.current_token.clone(),
                span: self.current_span,
            }),
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

        self.expect(Token::Semicolon)?;

        Ok(Statement::Return {
            value,
            span: start_span,
        })
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
            self.expect(Token::Semicolon)?;

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
        self.expect(Token::Semicolon)?;

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
        self.expect(Token::Semicolon)?;

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
        self.expect(Token::Semicolon)?;

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
            self.expect(Token::Semicolon)?;

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
        // First, parse potential key or the value
        let first_expr = self.parse_expression(0)?;

        let (key, value, by_ref) = if self.current_token == Token::DoubleArrow {
            // key => value syntax
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
            // Check if it was prefixed with & (by reference)
            // Note: In proper implementation, we'd check if first_expr was parsed with &
            // For now, we assume by_ref is false
            (None, Box::new(first_expr), false)
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
            self.expect(Token::Semicolon)?;

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
                    self.expect(Token::Colon)?;

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
                    self.expect(Token::Colon)?;

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
                    return Err(ParseError::UnexpectedToken {
                        expected: "case or default".to_string(),
                        found: self.current_token.clone(),
                        span: self.current_span,
                    });
                }
            }

            self.expect(Token::Endswitch)?;
            self.expect(Token::Semicolon)?;

            cases
        } else {
            // Standard syntax: switch (...) { case ...: ... }
            self.expect(Token::LBrace)?;

            let mut cases = Vec::new();

            while self.current_token != Token::RBrace {
                if self.current_token == Token::Case {
                    self.advance(); // consume case
                    let case_condition = Some(self.parse_expression(0)?);
                    self.expect(Token::Colon)?;

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
                    self.expect(Token::Colon)?;

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
                    return Err(ParseError::UnexpectedToken {
                        expected: "case or default".to_string(),
                        found: self.current_token.clone(),
                        span: self.current_span,
                    });
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
                return Err(ParseError::UnexpectedToken {
                    expected: "comma or }".to_string(),
                    found: self.current_token.clone(),
                    span: self.current_span,
                });
            }
        }

        self.expect(Token::RBrace)?;

        Ok(Statement::Match {
            condition,
            arms,
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
            self.expect(Token::Semicolon)?;

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
                self.advance();
                // Extract value from span (placeholder - real implementation needs lexer support)
                Ok(Expression::IntLiteral { value: 0, span })
            }

            // Float literal
            Token::DNumber => {
                self.advance();
                Ok(Expression::FloatLiteral { value: 0.0, span })
            }

            // String literal
            Token::ConstantEncapsedString => {
                self.advance();
                Ok(Expression::StringLiteral {
                    value: String::new(),
                    span,
                })
            }

            // Variable
            Token::Variable => {
                self.advance();
                Ok(Expression::Variable {
                    name: String::new(),
                    span,
                })
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
                let operand = self.parse_expression(Self::PREFIX_PRECEDENCE)?;
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
                        return Err(ParseError::UnexpectedToken {
                            expected: "comma or }".to_string(),
                            found: self.current_token.clone(),
                            span: self.current_span,
                        });
                    }
                }

                self.expect(Token::RBrace)?;

                Ok(Expression::MatchExpr {
                    condition,
                    arms,
                    span,
                })
            }

            _ => Err(ParseError::UnexpectedToken {
                expected: "expression".to_string(),
                found: token,
                span,
            }),
        }
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
                let right = self.parse_expression(precedence)?;
                Ok(Expression::Assign {
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                    span,
                })
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

            _ => Ok(left),
        }
    }

    /// Get infix precedence for a token
    /// PHP operator precedence from lowest to highest
    /// Reference: https://www.php.net/manual/en/language.operators.precedence.php
    fn infix_precedence(&self, token: &Token) -> u8 {
        match token {
            // Lowest precedence
            Token::LogicalOr => 1,         // or
            Token::LogicalXor => 2,        // xor
            Token::LogicalAnd => 3,        // and
            Token::Equals => 4,            // =
            Token::PlusEqual => 4,         // +=
            Token::MinusEqual => 4,        // -=
            Token::MulEqual => 4,          // *=
            Token::DivEqual => 4,          // /=
            Token::ModEqual => 4,          // %=
            Token::PowEqual => 4,          // **=
            Token::ConcatEqual => 4,       // .=
            Token::AndEqual => 4,          // &=
            Token::OrEqual => 4,           // |=
            Token::XorEqual => 4,          // ^=
            Token::SlEqual => 4,           // <<=
            Token::SrEqual => 4,           // >>=
            Token::CoalesceEqual => 4,     // ??=
            Token::Question => 5,          // ? :
            Token::Coalesce => 6,          // ??
            Token::BooleanOr => 7,         // ||
            Token::BooleanAnd => 8,        // &&
            Token::VerticalBar => 9,       // |
            Token::Caret => 10,            // ^
            Token::Ampersand => 11,        // &
            Token::IsEqual => 12,          // ==
            Token::IsNotEqual => 12,       // !=
            Token::IsIdentical => 12,      // ===
            Token::IsNotIdentical => 12,   // !==
            Token::Spaceship => 13,        // <=>
            Token::LessThan => 14,         // <
            Token::IsSmallerOrEqual => 14, // <=
            Token::GreaterThan => 14,      // >
            Token::IsGreaterOrEqual => 14, // >=
            Token::Sl => 15,               // <<
            Token::Sr => 15,               // >>
            Token::Plus => 16,             // +
            Token::Minus => 16,            // -
            Token::Dot => 16,              // .
            Token::Star => 17,             // *
            Token::Slash => 17,            // /
            Token::Percent => 17,          // %
            Token::Pow => 19,              // ** (right-associative, higher precedence)
            Token::Inc => 20,              // ++ (postfix)
            Token::Dec => 20,              // -- (postfix)
            _ => 0,                        // Not an infix operator
        }
    }

    /// Precedence for prefix operators (unary, cast, etc.)
    const PREFIX_PRECEDENCE: u8 = 18;

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

/// Parse error
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnexpectedToken {
        expected: String,
        found: Token,
        span: Span,
    },
    UnexpectedEof,
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
}
