//! PHP lexer/tokenizer
//!
//! This crate implements the lexical scanner for PHP source code,
//! equivalent to php-src/Zend/zend_language_scanner.l

mod lexer;
mod span;
mod token;

pub use lexer::Lexer;
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

    #[test]
    fn test_token_span_roundtrip() {
        // Test: Token + Span roundtrip
        // This verifies that Token and Span can be combined, stored,
        // and retrieved with all information intact.

        // Simulate a tokenized PHP snippet: "<?php echo 42;"
        let source = "<?php echo 42;";

        // Token 1: <?php at position 0-5, line 1, column 1
        let token1 = Token::OpenTag;
        let span1 = Span::new(0, 5, 1, 1);

        // Token 2: echo at position 6-10, line 1, column 7
        let token2 = Token::Echo;
        let span2 = Span::new(6, 10, 1, 7);

        // Token 3: 42 at position 11-13, line 1, column 12
        let token3 = Token::LNumber;
        let span3 = Span::new(11, 13, 1, 12);

        // Combine tokens and spans into a vec (simulating lexer output)
        let tokens = vec![
            (token1.clone(), span1),
            (token2.clone(), span2),
            (token3.clone(), span3),
        ];

        // Roundtrip: verify all data is preserved
        assert_eq!(tokens.len(), 3);

        // Verify first token
        let (t1, s1) = &tokens[0];
        assert_eq!(*t1, Token::OpenTag);
        assert_eq!(s1.start, 0);
        assert_eq!(s1.end, 5);
        assert_eq!(s1.line, 1);
        assert_eq!(s1.column, 1);
        assert_eq!(s1.extract(source), "<?php");

        // Verify second token
        let (t2, s2) = &tokens[1];
        assert_eq!(*t2, Token::Echo);
        assert_eq!(s2.start, 6);
        assert_eq!(s2.end, 10);
        assert_eq!(s2.line, 1);
        assert_eq!(s2.column, 7);
        assert_eq!(s2.extract(source), "echo");

        // Verify third token
        let (t3, s3) = &tokens[2];
        assert_eq!(*t3, Token::LNumber);
        assert_eq!(s3.start, 11);
        assert_eq!(s3.end, 13);
        assert_eq!(s3.line, 1);
        assert_eq!(s3.column, 12);
        assert_eq!(s3.extract(source), "42");
    }

    #[test]
    fn test_token_span_multiline_roundtrip() {
        // Test Token + Span roundtrip with multiline source
        let source = "<?php\necho 'hello';\necho 'world';";

        // Token 1: <?php at bytes 0-5, line 1, column 1
        let token1 = Token::OpenTag;
        let span1 = Span::new(0, 5, 1, 1);

        // Token 2: echo at bytes 6-10, line 2, column 1
        let token2 = Token::Echo;
        let span2 = Span::new(6, 10, 2, 1);

        // Token 3: 'hello' at bytes 11-18, line 2, column 6
        let token3 = Token::ConstantEncapsedString;
        let span3 = Span::new(11, 18, 2, 6);

        // Token 4: echo at bytes 20-24, line 3, column 1
        let token4 = Token::Echo;
        let span4 = Span::new(20, 24, 3, 1);

        let tokens = vec![
            (token1, span1),
            (token2, span2),
            (token3, span3),
            (token4, span4),
        ];

        // Verify each token and span
        assert_eq!(tokens[0].1.extract(source), "<?php");
        assert_eq!(tokens[0].1.line, 1);

        assert_eq!(tokens[1].1.extract(source), "echo");
        assert_eq!(tokens[1].1.line, 2);

        assert_eq!(tokens[2].1.extract(source), "'hello'");
        assert_eq!(tokens[2].1.line, 2);

        assert_eq!(tokens[3].1.extract(source), "echo");
        assert_eq!(tokens[3].1.line, 3);
    }

    #[test]
    fn test_token_span_all_token_types() {
        // Test that all major token types work with Span
        let test_cases = vec![
            (Token::LNumber, "42"),
            (Token::DNumber, "3.14"),
            (Token::String, "identifier"),
            (Token::Variable, "$var"),
            (Token::If, "if"),
            (Token::Else, "else"),
            (Token::Function, "function"),
            (Token::Class, "class"),
            (Token::Echo, "echo"),
            (Token::Return, "return"),
            (Token::PlusEqual, "+="),
            (Token::IsIdentical, "==="),
            (Token::ObjectOperator, "->"),
            (Token::DoubleArrow, "=>"),
            (Token::Ellipsis, "..."),
            (Token::Coalesce, "??"),
        ];

        for (token, text) in test_cases {
            let span = Span::new(0, text.len(), 1, 1);
            let extracted = span.extract(text);

            // Verify the span extracts the correct text
            assert_eq!(extracted, text);

            // Verify the token can be cloned and compared
            let token_clone = token.clone();
            assert_eq!(token, token_clone);
        }
    }

    #[test]
    fn test_token_span_edge_cases() {
        // Test edge cases for Token + Span combinations

        // Empty span
        let empty_span = Span::new(0, 0, 1, 1);
        assert!(empty_span.is_empty());
        assert_eq!(empty_span.len(), 0);

        // Token with empty span (e.g., end-of-file marker)
        let eof_token = Token::End;
        let eof_span = Span::new(100, 100, 10, 50);
        assert!(eof_span.is_empty());
        assert_eq!(eof_token, Token::End);

        // Very long span
        let source = "x".repeat(10000);
        let long_span = Span::new(0, 10000, 1, 1);
        assert_eq!(long_span.len(), 10000);
        assert_eq!(long_span.extract(&source), source);

        // Unicode handling (Span works with byte offsets, not char offsets)
        let unicode_source = "<?php echo '你好';";
        // "<?php echo '" is 12 bytes (0-11)
        // '你' is 3 bytes in UTF-8 (bytes 12-14)
        // '好' is 3 bytes in UTF-8 (bytes 15-17)
        // Total for '你好' is 6 bytes (12-17 inclusive = bytes 12,13,14,15,16,17)
        let span = Span::new(12, 18, 1, 13); // '你好' = 6 bytes (12..18 exclusive)
        assert_eq!(span.extract(unicode_source), "你好");
    }
}
