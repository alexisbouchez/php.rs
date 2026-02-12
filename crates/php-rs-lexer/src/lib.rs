//! PHP lexer/tokenizer
//!
//! This crate implements the lexical scanner for PHP source code,
//! equivalent to php-src/Zend/zend_language_scanner.l

mod span;
mod token;

pub use span::Span;
pub use token::Token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_enum_exists() {
        // Verify Token enum can be constructed
        let _token = Token::LNumber;
    }
}
