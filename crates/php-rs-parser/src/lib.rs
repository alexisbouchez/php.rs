//! PHP parser -- recursive descent parser producing an abstract syntax tree.
//!
//! This crate transforms a stream of tokens from [`php_rs_lexer`] into a typed
//! AST (abstract syntax tree). It is equivalent to the Bison-generated parser
//! in `php-src/Zend/zend_language_parser.y`, reimplemented as a hand-written
//! recursive descent / Pratt parser in Rust.
//!
//! # Main types
//!
//! - [`Parser`] -- The parser. Accepts PHP source code and produces a [`Program`] AST.
//! - [`Program`] -- Root AST node containing a list of [`Statement`] nodes.
//! - [`Statement`] -- Enum of all PHP statement types (if, while, class, function, etc.).
//! - [`Expression`] -- Enum of all PHP expression types (literals, binary ops, calls, etc.).
//! - [`ParseError`] -- Error type with source location for syntax errors.
//!
//! # Usage
//!
//! ```rust,ignore
//! use php_rs_parser::Parser;
//!
//! let mut parser = Parser::new("<?php echo 1 + 2;");
//! let program = parser.parse().expect("parse error");
//! // program.statements contains the AST
//! ```

mod ast;
mod parser;

pub use ast::*;
pub use parser::{ParseError, Parser};
