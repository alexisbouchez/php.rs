//! PHP parser
//!
//! This crate implements the parser for PHP source code, producing an AST.
//! Equivalent to php-src/Zend/zend_language_parser.y

mod ast;

pub use ast::*;
