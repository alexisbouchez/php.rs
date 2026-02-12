//! PHP Lexer implementation
//!
//! Reference: php-src/Zend/zend_language_scanner.l

use crate::{Span, Token};

/// Lexer state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// INITIAL state - before <?php or in HTML passthrough
    Initial,
    /// ST_IN_SCRIPTING - inside PHP code
    InScripting,
}

/// PHP Lexer
pub struct Lexer<'src> {
    /// Source code being tokenized
    source: &'src str,
    /// Current byte position
    pos: usize,
    /// Current line number (1-indexed)
    line: usize,
    /// Current column (1-indexed, byte offset within line)
    column: usize,
    /// Current lexer state
    state: State,
    /// Whether short open tags are enabled (short_open_tag INI)
    allow_short_tags: bool,
}

impl<'src> Lexer<'src> {
    /// Create a new lexer for the given source code
    pub fn new(source: &'src str) -> Self {
        Self {
            source,
            pos: 0,
            line: 1,
            column: 1,
            state: State::Initial,
            allow_short_tags: false,
        }
    }

    /// Create a new lexer with short_open_tag enabled
    pub fn new_with_short_tags(source: &'src str) -> Self {
        Self {
            source,
            pos: 0,
            line: 1,
            column: 1,
            state: State::Initial,
            allow_short_tags: true,
        }
    }

    /// Peek at the current character without consuming it
    fn peek(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    /// Peek at the next N bytes as a string slice
    /// Returns empty string if the slice would be invalid UTF-8
    fn peek_str(&self, n: usize) -> &'src str {
        let end = (self.pos + n).min(self.source.len());

        // Ensure we're at a valid UTF-8 boundary
        if !self.source.is_char_boundary(self.pos) {
            return "";
        }

        // Try to peek, but handle invalid boundary gracefully
        if !self.source.is_char_boundary(end) {
            // If end is not a char boundary, we can't slice there
            // This can happen when we're in the middle of a multi-byte character
            // Return empty string to signal no match
            return "";
        }

        &self.source[self.pos..end]
    }

    /// Consume and return the next character
    fn consume(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();

        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }

        Some(ch)
    }

    /// Consume N bytes (used when we've already peeked a multi-byte ASCII sequence)
    /// Note: This is only safe to use with ASCII sequences where byte count = char count
    fn consume_bytes(&mut self, n: usize) {
        for _ in 0..n {
            if self.peek().is_some() {
                self.consume();
            }
        }
    }

    /// Check if we're at end of input
    fn is_eof(&self) -> bool {
        self.pos >= self.source.len()
    }

    /// Scan the next token
    pub fn next_token(&mut self) -> Option<(Token, Span)> {
        match self.state {
            State::Initial => self.scan_initial(),
            State::InScripting => self.scan_scripting(),
        }
    }

    /// Scan in INITIAL state - looking for <?php, <?=, or <? (if short_open_tag)
    fn scan_initial(&mut self) -> Option<(Token, Span)> {
        if self.is_eof() {
            return None;
        }

        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        // Look for opening tags
        if self.peek_str(5) == "<?php" {
            // Check that after <?php we have whitespace, newline, or EOF
            // This prevents matching "<?phps" or "<?phpinfo" etc.
            let after = self.peek_str(6);
            if after.len() == 5 || after.chars().nth(5).is_none_or(|ch| ch.is_whitespace()) {
                self.consume_bytes(5);
                self.state = State::InScripting;
                let span = Span::new(start_pos, self.pos, start_line, start_column);
                return Some((Token::OpenTag, span));
            }
        }

        // <?= is always recognized (regardless of short_open_tag)
        if self.peek_str(3) == "<?=" {
            self.consume_bytes(3);
            self.state = State::InScripting;
            let span = Span::new(start_pos, self.pos, start_line, start_column);
            return Some((Token::OpenTagWithEcho, span));
        }

        // <? only recognized if short_open_tag is enabled
        if self.allow_short_tags && self.peek_str(2) == "<?" {
            // Make sure it's not <?xml (special case - not a PHP tag)
            let after = self.peek_str(5);
            if after != "<?xml" {
                self.consume_bytes(2);
                self.state = State::InScripting;
                let span = Span::new(start_pos, self.pos, start_line, start_column);
                return Some((Token::OpenTag, span));
            }
        }

        // If we're here, we're in inline HTML - consume until we find an opening tag
        // For now, we'll consume one character at a time and return it as InlineHtml
        // TODO: optimize to consume runs of HTML
        self.consume()?;
        let span = Span::new(start_pos, self.pos, start_line, start_column);
        Some((Token::InlineHtml, span))
    }

    /// Scan in ST_IN_SCRIPTING state - inside PHP code
    fn scan_scripting(&mut self) -> Option<(Token, Span)> {
        // Skip whitespace
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.consume();
            } else {
                break;
            }
        }

        if self.is_eof() {
            return None;
        }

        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        // Try to match multi-character operators first (longest match wins)
        // Three-character operators
        if self.peek_str(3) == "===" {
            self.consume_bytes(3);
            return Some((
                Token::IsIdentical,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "!==" {
            self.consume_bytes(3);
            return Some((
                Token::IsNotIdentical,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "<=>" {
            self.consume_bytes(3);
            return Some((
                Token::Spaceship,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "<<=" {
            self.consume_bytes(3);
            return Some((
                Token::SlEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == ">>=" {
            self.consume_bytes(3);
            return Some((
                Token::SrEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "**=" {
            self.consume_bytes(3);
            return Some((
                Token::PowEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "..." {
            self.consume_bytes(3);
            return Some((
                Token::Ellipsis,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "??=" {
            self.consume_bytes(3);
            return Some((
                Token::CoalesceEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(3) == "?->" {
            self.consume_bytes(3);
            return Some((
                Token::NullsafeObjectOperator,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }

        // Two-character operators
        if self.peek_str(2) == "==" {
            self.consume_bytes(2);
            return Some((
                Token::IsEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "!=" || self.peek_str(2) == "<>" {
            self.consume_bytes(2);
            return Some((
                Token::IsNotEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "<=" {
            self.consume_bytes(2);
            return Some((
                Token::IsSmallerOrEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == ">=" {
            self.consume_bytes(2);
            return Some((
                Token::IsGreaterOrEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "<<" {
            self.consume_bytes(2);
            return Some((
                Token::Sl,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == ">>" {
            self.consume_bytes(2);
            return Some((
                Token::Sr,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "++" {
            self.consume_bytes(2);
            return Some((
                Token::Inc,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "--" {
            self.consume_bytes(2);
            return Some((
                Token::Dec,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "+=" {
            self.consume_bytes(2);
            return Some((
                Token::PlusEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "-=" {
            self.consume_bytes(2);
            return Some((
                Token::MinusEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "*=" {
            self.consume_bytes(2);
            return Some((
                Token::MulEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "/=" {
            self.consume_bytes(2);
            return Some((
                Token::DivEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == ".=" {
            self.consume_bytes(2);
            return Some((
                Token::ConcatEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "%=" {
            self.consume_bytes(2);
            return Some((
                Token::ModEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "&=" {
            self.consume_bytes(2);
            return Some((
                Token::AndEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "|=" {
            self.consume_bytes(2);
            return Some((
                Token::OrEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "^=" {
            self.consume_bytes(2);
            return Some((
                Token::XorEqual,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "&&" {
            self.consume_bytes(2);
            return Some((
                Token::BooleanAnd,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "||" {
            self.consume_bytes(2);
            return Some((
                Token::BooleanOr,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "**" {
            self.consume_bytes(2);
            return Some((
                Token::Pow,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "??" {
            self.consume_bytes(2);
            return Some((
                Token::Coalesce,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "->" {
            self.consume_bytes(2);
            return Some((
                Token::ObjectOperator,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "=>" {
            self.consume_bytes(2);
            return Some((
                Token::DoubleArrow,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "::" {
            self.consume_bytes(2);
            return Some((
                Token::PaamayimNekudotayim,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }
        if self.peek_str(2) == "#[" {
            self.consume_bytes(2);
            return Some((
                Token::Attribute,
                Span::new(start_pos, self.pos, start_line, start_column),
            ));
        }

        // Single-character operators and punctuation
        let ch = self.peek()?;
        match ch {
            '+' | '-' | '*' | '/' | '%' | '=' | '<' | '>' | '!' | '&' | '|' | '^' | '~' | '('
            | ')' | '{' | '}' | '[' | ']' | ';' | ',' | '.' | ':' | '?' | '@' | '#' | '\\' => {
                self.consume();
                let span = Span::new(start_pos, self.pos, start_line, start_column);
                // For now, return these as String tokens (will be refined later)
                // Actually, we should return BadCharacter for unrecognized single chars
                // But for basic arithmetic/logic, these are valid
                // For simplicity in this implementation, we'll just consume them
                // The parser will handle the semantic meaning
                Some((Token::BadCharacter, span))
            }
            '$' => {
                // Variable
                self.consume(); // consume '$'

                // Variable name must start with letter or underscore
                if let Some(first) = self.peek() {
                    if first.is_alphabetic() || first == '_' {
                        self.consume();
                        // Continue consuming alphanumeric or underscore
                        while let Some(ch) = self.peek() {
                            if ch.is_alphanumeric() || ch == '_' {
                                self.consume();
                            } else {
                                break;
                            }
                        }
                        return Some((
                            Token::Variable,
                            Span::new(start_pos, self.pos, start_line, start_column),
                        ));
                    }
                }

                // If we get here, it's just a '$' with no valid identifier
                Some((
                    Token::BadCharacter,
                    Span::new(start_pos, self.pos, start_line, start_column),
                ))
            }
            _ if ch.is_alphabetic() || ch == '_' => {
                // Identifier or keyword
                self.consume();
                while let Some(ch) = self.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        self.consume();
                    } else {
                        break;
                    }
                }

                let span = Span::new(start_pos, self.pos, start_line, start_column);
                let text = span.extract(self.source);

                // Check if it's a keyword (case-insensitive in PHP)
                let token = match text.to_lowercase().as_str() {
                    "abstract" => Token::Abstract,
                    "and" => Token::LogicalAnd,
                    "array" => Token::Array,
                    "as" => Token::As,
                    "break" => Token::Break,
                    "callable" => Token::Callable,
                    "case" => Token::Case,
                    "catch" => Token::Catch,
                    "class" => Token::Class,
                    "clone" => Token::Clone,
                    "const" => Token::Const,
                    "continue" => Token::Continue,
                    "declare" => Token::Declare,
                    "default" => Token::Default,
                    "die" => Token::Exit,
                    "do" => Token::Do,
                    "echo" => Token::Echo,
                    "else" => Token::Else,
                    "elseif" => Token::Elseif,
                    "empty" => Token::Empty,
                    "enddeclare" => Token::Enddeclare,
                    "endfor" => Token::Endfor,
                    "endforeach" => Token::Endforeach,
                    "endif" => Token::Endif,
                    "endswitch" => Token::Endswitch,
                    "endwhile" => Token::Endwhile,
                    "enum" => Token::Enum,
                    "eval" => Token::Eval,
                    "exit" => Token::Exit,
                    "extends" => Token::Extends,
                    "final" => Token::Final,
                    "finally" => Token::Finally,
                    "fn" => Token::Fn,
                    "for" => Token::For,
                    "foreach" => Token::Foreach,
                    "function" => Token::Function,
                    "global" => Token::Global,
                    "goto" => Token::Goto,
                    "if" => Token::If,
                    "implements" => Token::Implements,
                    "include" => Token::Include,
                    "include_once" => Token::IncludeOnce,
                    "instanceof" => Token::Instanceof,
                    "insteadof" => Token::Insteadof,
                    "interface" => Token::Interface,
                    "isset" => Token::Isset,
                    "list" => Token::List,
                    "match" => Token::Match,
                    "namespace" => Token::Namespace,
                    "new" => Token::New,
                    "or" => Token::LogicalOr,
                    "print" => Token::Print,
                    "private" => Token::Private,
                    "protected" => Token::Protected,
                    "public" => Token::Public,
                    "readonly" => Token::Readonly,
                    "require" => Token::Require,
                    "require_once" => Token::RequireOnce,
                    "return" => Token::Return,
                    "static" => Token::Static,
                    "switch" => Token::Switch,
                    "throw" => Token::Throw,
                    "trait" => Token::Trait,
                    "try" => Token::Try,
                    "unset" => Token::Unset,
                    "use" => Token::Use,
                    "var" => Token::Var,
                    "while" => Token::While,
                    "xor" => Token::LogicalXor,
                    "yield" => Token::Yield,
                    // Magic constants (case-insensitive)
                    "__class__" => Token::ClassC,
                    "__dir__" => Token::Dir,
                    "__file__" => Token::File,
                    "__function__" => Token::FuncC,
                    "__line__" => Token::Line,
                    "__method__" => Token::MethodC,
                    "__namespace__" => Token::NsC,
                    "__trait__" => Token::TraitC,
                    "__property__" => Token::PropertyC,
                    // Check for "yield from" (two keywords)
                    "from" if self.peek_str(0).is_empty() => {
                        // This is tricky - we need to look back to see if previous token was yield
                        // For now, just treat "from" as an identifier
                        // The parser will handle "yield from" as two tokens
                        Token::String
                    }
                    _ => Token::String, // Regular identifier
                };

                Some((token, span))
            }
            _ => {
                // Unknown character
                self.consume();
                Some((
                    Token::BadCharacter,
                    Span::new(start_pos, self.pos, start_line, start_column),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_open_tag_standard() {
        // Test: <?php opening tag
        let mut lexer = Lexer::new("<?php ");

        let (token, span) = lexer.next_token().expect("Should tokenize <?php");
        assert_eq!(token, Token::OpenTag);
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 5);
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
        assert_eq!(span.extract("<?php "), "<?php");
    }

    #[test]
    fn test_scan_open_tag_with_newline() {
        // Test: <?php followed by newline
        let source = "<?php\necho";
        let mut lexer = Lexer::new(source);

        let (token, span) = lexer.next_token().expect("Should tokenize <?php");
        assert_eq!(token, Token::OpenTag);
        assert_eq!(span.extract(source), "<?php");
    }

    #[test]
    fn test_scan_open_tag_at_eof() {
        // Test: <?php at end of file
        let source = "<?php";
        let mut lexer = Lexer::new(source);

        let (token, span) = lexer.next_token().expect("Should tokenize <?php");
        assert_eq!(token, Token::OpenTag);
        assert_eq!(span.extract(source), "<?php");
    }

    #[test]
    fn test_scan_open_tag_not_phpinfo() {
        // Test: <?php must be followed by whitespace/EOF, not more letters
        // "<?phpinfo" should NOT match as <?php
        let source = "<?phpinfo";
        let mut lexer = Lexer::new(source);

        // Should treat '<' as inline HTML since <?phpinfo is not a valid tag
        let (token, span) = lexer.next_token().expect("Should tokenize");
        assert_eq!(token, Token::InlineHtml);
        assert_eq!(span.extract(source), "<");
    }

    #[test]
    fn test_scan_open_tag_with_echo() {
        // Test: <?= opening tag (always enabled, regardless of short_open_tag)
        let source = "<?= 'hello'";
        let mut lexer = Lexer::new(source);

        let (token, span) = lexer.next_token().expect("Should tokenize <?=");
        assert_eq!(token, Token::OpenTagWithEcho);
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 3);
        assert_eq!(span.extract(source), "<?=");
    }

    #[test]
    fn test_scan_short_tag_disabled() {
        // Test: <? should NOT be recognized when short_open_tag is disabled
        let source = "<? echo";
        let mut lexer = Lexer::new(source); // short_open_tag defaults to false

        let (token, span) = lexer.next_token().expect("Should tokenize");
        assert_eq!(token, Token::InlineHtml);
        assert_eq!(span.extract(source), "<");
    }

    #[test]
    fn test_scan_short_tag_enabled() {
        // Test: <? SHOULD be recognized when short_open_tag is enabled
        let source = "<? echo";
        let mut lexer = Lexer::new_with_short_tags(source);

        let (token, span) = lexer.next_token().expect("Should tokenize <?");
        assert_eq!(token, Token::OpenTag);
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 2);
        assert_eq!(span.extract(source), "<?");
    }

    #[test]
    fn test_scan_xml_declaration_not_php() {
        // Test: <?xml should NOT be treated as a PHP opening tag, even with short_open_tag
        let source = "<?xml version='1.0'?>";
        let mut lexer = Lexer::new_with_short_tags(source);

        let (token, span) = lexer.next_token().expect("Should tokenize");
        assert_eq!(token, Token::InlineHtml);
        assert_eq!(span.extract(source), "<");
    }

    #[test]
    fn test_scan_inline_html_before_php() {
        // Test: Inline HTML before <?php tag
        let source = "<!DOCTYPE html>\n<?php";
        let mut lexer = Lexer::new(source);

        // Should get a series of InlineHtml tokens until we hit <?php
        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            let text = span.extract(source).to_string();
            let is_open_tag = token == Token::OpenTag;
            tokens.push((token, text));
            if is_open_tag {
                break;
            }
        }

        // Last token should be OpenTag
        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);
        assert_eq!(tokens.last().unwrap().1, "<?php");
    }

    #[test]
    fn test_state_transition_to_scripting() {
        // Test: After <?php, lexer should be in InScripting state
        let mut lexer = Lexer::new("<?php ");

        // Consume the <?php token
        let (token, _) = lexer.next_token().expect("Should tokenize <?php");
        assert_eq!(token, Token::OpenTag);

        // Verify state changed
        assert_eq!(lexer.state, State::InScripting);
    }

    // ======================================================================
    // Task 2.2.2: Test inline HTML passthrough before <?php
    // ======================================================================

    #[test]
    fn test_inline_html_simple_text_before_php() {
        // Test: Simple text before <?php should be tokenized as InlineHtml
        let source = "Hello World<?php";
        let mut lexer = Lexer::new(source);

        // Should get InlineHtml tokens until we hit <?php
        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        // Last token should be OpenTag
        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);
        assert_eq!(tokens.last().unwrap().1, "<?php");

        // All preceding tokens should be InlineHtml
        for (token, _) in tokens.iter().take(tokens.len() - 1) {
            assert_eq!(*token, Token::InlineHtml);
        }

        // When we concatenate all InlineHtml tokens, we should get "Hello World"
        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "Hello World");
    }

    #[test]
    fn test_inline_html_doctype_before_php() {
        // Test: HTML doctype before <?php
        let source = "<!DOCTYPE html>\n<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        // Last token should be OpenTag
        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);
        assert_eq!(tokens.last().unwrap().1, "<?php");

        // Concatenate HTML parts
        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "<!DOCTYPE html>\n");
    }

    #[test]
    fn test_inline_html_complete_html_document() {
        // Test: Complete HTML document with embedded PHP
        let source = r#"<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <?php echo 'Hello'; ?>
</body>
</html>"#;
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token.clone(), span.extract(source).to_string()));
        }

        // Should have InlineHtml tokens, then OpenTag
        let mut found_open_tag = false;
        for (token, text) in &tokens {
            match token {
                Token::InlineHtml => {
                    assert!(
                        !found_open_tag,
                        "InlineHtml should only appear before first OpenTag"
                    );
                }
                Token::OpenTag => {
                    found_open_tag = true;
                    assert_eq!(text, "<?php");
                }
                _ => {}
            }
        }

        assert!(found_open_tag, "Should have found at least one OpenTag");

        // Collect all HTML before first <?php
        let html: String = tokens
            .iter()
            .take_while(|(token, _)| *token == Token::InlineHtml)
            .map(|(_, text)| text.as_str())
            .collect();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<body>"));
    }

    #[test]
    fn test_inline_html_empty_before_php() {
        // Test: No HTML before <?php (file starts with <?php)
        let source = "<?php echo 'test';";
        let mut lexer = Lexer::new(source);

        // First token should be OpenTag
        let (token, span) = lexer.next_token().expect("Should have OpenTag");
        assert_eq!(token, Token::OpenTag);
        assert_eq!(span.extract(source), "<?php");

        // No InlineHtml tokens should have been emitted
    }

    #[test]
    fn test_inline_html_single_char_before_php() {
        // Test: Single character before <?php
        let source = "x<?php";
        let mut lexer = Lexer::new(source);

        let (token1, span1) = lexer.next_token().expect("Should have InlineHtml");
        assert_eq!(token1, Token::InlineHtml);
        assert_eq!(span1.extract(source), "x");

        let (token2, span2) = lexer.next_token().expect("Should have OpenTag");
        assert_eq!(token2, Token::OpenTag);
        assert_eq!(span2.extract(source), "<?php");
    }

    #[test]
    fn test_inline_html_special_chars() {
        // Test: Inline HTML with special characters
        let source = "Test: <>&\"'\t\n\r<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);

        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "Test: <>&\"'\t\n\r");
    }

    #[test]
    fn test_inline_html_looks_like_php_tag_but_isnt() {
        // Test: Text that looks like it might be a PHP tag but isn't
        let source = "<?phpinfo() is not a tag\n<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        // Last token should be the real <?php tag
        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);
        assert_eq!(tokens.last().unwrap().1, "<?php");

        // Everything before should be InlineHtml
        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "<?phpinfo() is not a tag\n");
    }

    #[test]
    fn test_inline_html_unicode_before_php() {
        // Test: Unicode text before <?php
        let source = "你好世界 Hello 🌍\n<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);

        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "你好世界 Hello 🌍\n");
    }

    #[test]
    fn test_inline_html_multiline_before_php() {
        // Test: Multiple lines of HTML before <?php
        let source = "Line 1\nLine 2\nLine 3\n<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            let line = span.line;
            tokens.push((token, span.extract(source).to_string(), line));
        }

        // Last token should be OpenTag on line 4
        assert_eq!(tokens.last().unwrap().0, Token::OpenTag);
        assert_eq!(tokens.last().unwrap().2, 4);

        // Concatenate HTML
        let html: String = tokens
            .iter()
            .take(tokens.len() - 1)
            .map(|(_, text, _)| text.as_str())
            .collect();
        assert_eq!(html, "Line 1\nLine 2\nLine 3\n");
    }

    #[test]
    fn test_inline_html_with_open_tag_with_echo() {
        // Test: HTML before <?= tag
        let source = "HTML content<?= 'value' ?>";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        // Should find OpenTagWithEcho
        assert!(tokens
            .iter()
            .any(|(token, _)| *token == Token::OpenTagWithEcho));

        // Collect HTML before <?=
        let html: String = tokens
            .iter()
            .take_while(|(token, _)| *token == Token::InlineHtml)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(html, "HTML content");
    }

    #[test]
    fn test_inline_html_line_and_column_tracking() {
        // Test: Line and column numbers are tracked correctly through inline HTML
        let source = "abc\ndef\n<?php";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.line, span.column));
        }

        // Last token (<?php) should be on line 3, column 1
        let last = tokens.last().unwrap();
        assert_eq!(last.0, Token::OpenTag);
        assert_eq!(last.1, 3); // line 3
        assert_eq!(last.2, 1); // column 1
    }

    // ======================================================================
    // Task 2.2.3: Test ST_IN_SCRIPTING state - keywords, operators, identifiers
    // ======================================================================

    #[test]
    fn test_scripting_basic_keywords() {
        // Test: Basic PHP keywords are recognized
        let source = "<?php if else while for foreach";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        assert_eq!(tokens[0].0, Token::OpenTag);
        assert_eq!(tokens[1].0, Token::If);
        assert_eq!(tokens[2].0, Token::Else);
        assert_eq!(tokens[3].0, Token::While);
        assert_eq!(tokens[4].0, Token::For);
        assert_eq!(tokens[5].0, Token::Foreach);
    }

    #[test]
    fn test_scripting_keywords_case_insensitive() {
        // Test: PHP keywords are case-insensitive
        let test_cases = vec![
            ("<?php IF", Token::If),
            ("<?php If", Token::If),
            ("<?php if", Token::If),
            ("<?php FUNCTION", Token::Function),
            ("<?php Function", Token::Function),
            ("<?php function", Token::Function),
            ("<?php CLASS", Token::Class),
            ("<?php Class", Token::Class),
            ("<?php class", Token::Class),
        ];

        for (source, expected_token) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for source: {}", source);
        }
    }

    #[test]
    fn test_scripting_all_control_flow_keywords() {
        // Test: All control flow keywords
        let keywords = vec![
            ("if", Token::If),
            ("else", Token::Else),
            ("elseif", Token::Elseif),
            ("endif", Token::Endif),
            ("while", Token::While),
            ("endwhile", Token::Endwhile),
            ("do", Token::Do),
            ("for", Token::For),
            ("endfor", Token::Endfor),
            ("foreach", Token::Foreach),
            ("endforeach", Token::Endforeach),
            ("switch", Token::Switch),
            ("endswitch", Token::Endswitch),
            ("case", Token::Case),
            ("default", Token::Default),
            ("match", Token::Match),
            ("break", Token::Break),
            ("continue", Token::Continue),
            ("goto", Token::Goto),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token);
            assert_eq!(span.extract(&source), keyword);
        }
    }

    #[test]
    fn test_scripting_all_declaration_keywords() {
        // Test: All declaration keywords
        let keywords = vec![
            ("function", Token::Function),
            ("fn", Token::Fn),
            ("class", Token::Class),
            ("interface", Token::Interface),
            ("trait", Token::Trait),
            ("enum", Token::Enum),
            ("extends", Token::Extends),
            ("implements", Token::Implements),
            ("namespace", Token::Namespace),
            ("use", Token::Use),
            ("const", Token::Const),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token);
        }
    }

    #[test]
    fn test_scripting_all_visibility_keywords() {
        // Test: All visibility and modifier keywords
        let keywords = vec![
            ("public", Token::Public),
            ("protected", Token::Protected),
            ("private", Token::Private),
            ("static", Token::Static),
            ("final", Token::Final),
            ("abstract", Token::Abstract),
            ("readonly", Token::Readonly),
            ("var", Token::Var),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token);
        }
    }

    #[test]
    fn test_scripting_exception_keywords() {
        // Test: Exception handling keywords
        let keywords = vec![
            ("try", Token::Try),
            ("catch", Token::Catch),
            ("finally", Token::Finally),
            ("throw", Token::Throw),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token);
        }
    }

    #[test]
    fn test_scripting_other_keywords() {
        // Test: Other keywords (echo, return, new, etc.)
        let keywords = vec![
            ("echo", Token::Echo),
            ("print", Token::Print),
            ("return", Token::Return),
            ("yield", Token::Yield),
            ("new", Token::New),
            ("clone", Token::Clone),
            ("instanceof", Token::Instanceof),
            ("include", Token::Include),
            ("include_once", Token::IncludeOnce),
            ("require", Token::Require),
            ("require_once", Token::RequireOnce),
            ("eval", Token::Eval),
            ("isset", Token::Isset),
            ("empty", Token::Empty),
            ("unset", Token::Unset),
            ("exit", Token::Exit),
            ("die", Token::Exit), // die is alias for exit
            ("list", Token::List),
            ("array", Token::Array),
            ("callable", Token::Callable),
            ("declare", Token::Declare),
            ("enddeclare", Token::Enddeclare),
            ("global", Token::Global),
            ("insteadof", Token::Insteadof),
            ("as", Token::As),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token, "Failed for keyword: {}", keyword);
        }
    }

    #[test]
    fn test_scripting_logical_keyword_operators() {
        // Test: Logical operators that are keywords (and, or, xor)
        let keywords = vec![
            ("and", Token::LogicalAnd),
            ("or", Token::LogicalOr),
            ("xor", Token::LogicalXor),
        ];

        for (keyword, expected_token) in keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));
            assert_eq!(token, expected_token);
        }
    }

    #[test]
    fn test_scripting_magic_constants() {
        // Test: Magic constants are recognized (case-insensitive)
        let constants = vec![
            ("__LINE__", Token::Line),
            ("__line__", Token::Line),
            ("__FILE__", Token::File),
            ("__file__", Token::File),
            ("__DIR__", Token::Dir),
            ("__CLASS__", Token::ClassC),
            ("__TRAIT__", Token::TraitC),
            ("__METHOD__", Token::MethodC),
            ("__FUNCTION__", Token::FuncC),
            ("__NAMESPACE__", Token::NsC),
            ("__PROPERTY__", Token::PropertyC),
        ];

        for (constant, expected_token) in constants {
            let source = format!("<?php {}", constant);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", constant));
            assert_eq!(token, expected_token, "Failed for constant: {}", constant);
        }
    }

    #[test]
    fn test_scripting_identifiers() {
        // Test: Regular identifiers are recognized
        let identifiers = vec![
            "myVariable",
            "MyClass",
            "_private",
            "test123",
            "camelCase",
            "snake_case",
            "UPPER_CASE",
            "x",
            "_",
            "__construct",
            "é", // Unicode identifier
        ];

        for identifier in identifiers {
            let source = format!("<?php {}", identifier);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", identifier));
            assert_eq!(
                token,
                Token::String,
                "Failed for identifier: {}",
                identifier
            );
            assert_eq!(span.extract(&source), identifier);
        }
    }

    #[test]
    fn test_scripting_variables() {
        // Test: Variables (starting with $) are recognized
        let variables = vec!["$var", "$myVar", "$_private", "$var123", "$x", "$_"];

        for variable in variables {
            let source = format!("<?php {}", variable);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", variable));
            assert_eq!(token, Token::Variable, "Failed for variable: {}", variable);
            assert_eq!(span.extract(&source), variable);
        }
    }

    #[test]
    fn test_scripting_comparison_operators() {
        // Test: Comparison operators
        let operators = vec![
            ("==", Token::IsEqual),
            ("!=", Token::IsNotEqual),
            ("<>", Token::IsNotEqual), // <> is alias for !=
            ("===", Token::IsIdentical),
            ("!==", Token::IsNotIdentical),
            ("<=", Token::IsSmallerOrEqual),
            (">=", Token::IsGreaterOrEqual),
            ("<=>", Token::Spaceship),
        ];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_arithmetic_compound_assignment() {
        // Test: Compound assignment operators
        let operators = vec![
            ("+=", Token::PlusEqual),
            ("-=", Token::MinusEqual),
            ("*=", Token::MulEqual),
            ("/=", Token::DivEqual),
            ("%=", Token::ModEqual),
            (".=", Token::ConcatEqual),
            ("**=", Token::PowEqual),
        ];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_bitwise_compound_assignment() {
        // Test: Bitwise compound assignment operators
        let operators = vec![
            ("&=", Token::AndEqual),
            ("|=", Token::OrEqual),
            ("^=", Token::XorEqual),
            ("<<=", Token::SlEqual),
            (">>=", Token::SrEqual),
        ];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_logical_operators() {
        // Test: Logical operators (symbolic)
        let operators = vec![("&&", Token::BooleanAnd), ("||", Token::BooleanOr)];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_bitwise_shift_operators() {
        // Test: Bitwise shift operators
        let operators = vec![("<<", Token::Sl), (">>", Token::Sr)];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_increment_decrement() {
        // Test: Increment and decrement operators
        let operators = vec![("++", Token::Inc), ("--", Token::Dec)];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_power_operator() {
        // Test: Power operator
        let source = "<?php **";
        let mut lexer = Lexer::new(source);
        lexer.next_token(); // Skip <?php
        let (token, span) = lexer.next_token().expect("Should tokenize **");
        assert_eq!(token, Token::Pow);
        assert_eq!(span.extract(source), "**");
    }

    #[test]
    fn test_scripting_null_coalesce() {
        // Test: Null coalesce operator
        let operators = vec![("??", Token::Coalesce), ("??=", Token::CoalesceEqual)];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_object_operators() {
        // Test: Object access operators
        let operators = vec![
            ("->", Token::ObjectOperator),
            ("?->", Token::NullsafeObjectOperator),
            ("::", Token::PaamayimNekudotayim),
        ];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_arrow_operators() {
        // Test: Arrow operators
        let operators = vec![("=>", Token::DoubleArrow)];

        for (op, expected_token) in operators {
            let source = format!("<?php {}", op);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", op));
            assert_eq!(token, expected_token, "Failed for operator: {}", op);
            assert_eq!(span.extract(&source), op);
        }
    }

    #[test]
    fn test_scripting_ellipsis() {
        // Test: Ellipsis/spread operator
        let source = "<?php ...";
        let mut lexer = Lexer::new(source);
        lexer.next_token(); // Skip <?php
        let (token, span) = lexer.next_token().expect("Should tokenize ...");
        assert_eq!(token, Token::Ellipsis);
        assert_eq!(span.extract(source), "...");
    }

    #[test]
    fn test_scripting_attribute_syntax() {
        // Test: Attribute syntax #[
        let source = "<?php #[";
        let mut lexer = Lexer::new(source);
        lexer.next_token(); // Skip <?php
        let (token, span) = lexer.next_token().expect("Should tokenize #[");
        assert_eq!(token, Token::Attribute);
        assert_eq!(span.extract(source), "#[");
    }

    #[test]
    fn test_scripting_whitespace_handling() {
        // Test: Whitespace is skipped in scripting mode
        let source = "<?php   if    else     while";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, _)) = lexer.next_token() {
            tokens.push(token);
        }

        // Should only get: OpenTag, If, Else, While (no whitespace tokens)
        assert_eq!(
            tokens,
            vec![Token::OpenTag, Token::If, Token::Else, Token::While]
        );
    }

    #[test]
    fn test_scripting_multiline_code() {
        // Test: Code spanning multiple lines
        let source = "<?php\nfunction\ntest\n(\n)";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, _)) = lexer.next_token() {
            tokens.push(token);
        }

        // OpenTag, Function, String (test)
        assert_eq!(tokens[0], Token::OpenTag);
        assert_eq!(tokens[1], Token::Function);
        assert_eq!(tokens[2], Token::String);
    }

    #[test]
    fn test_scripting_mixed_tokens() {
        // Test: Mix of keywords, identifiers, operators, variables
        let source = "<?php function test($var) { return $var + 1; }";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token.clone(), span.extract(source).to_string()));
        }

        // Debug: print all tokens
        // for (i, (token, text)) in tokens.iter().enumerate() {
        //     println!("{}: {:?} = {:?}", i, token, text);
        // }

        // Find key tokens (skip BadCharacter tokens for punctuation)
        let mut idx = 0;

        // Token 0: <?php
        assert_eq!(tokens[idx].0, Token::OpenTag);
        idx += 1;

        // Token 1: function
        assert_eq!(tokens[idx].0, Token::Function);
        idx += 1;

        // Token 2: test
        assert_eq!(tokens[idx].0, Token::String);
        assert_eq!(tokens[idx].1, "test");
        idx += 1;

        // Skip BadCharacter for (
        if tokens[idx].0 == Token::BadCharacter {
            idx += 1;
        }

        // Variable $var
        assert_eq!(tokens[idx].0, Token::Variable);
        assert_eq!(tokens[idx].1, "$var");
        idx += 1;

        // Skip BadCharacter for )
        if tokens[idx].0 == Token::BadCharacter {
            idx += 1;
        }

        // Skip BadCharacter for {
        if tokens[idx].0 == Token::BadCharacter {
            idx += 1;
        }

        // return keyword
        assert_eq!(tokens[idx].0, Token::Return);
        idx += 1;

        // Variable $var
        assert_eq!(tokens[idx].0, Token::Variable);
        assert_eq!(tokens[idx].1, "$var");
    }

    #[test]
    fn test_scripting_operator_precedence_tokenization() {
        // Test: Operators are tokenized correctly even when adjacent
        let source = "<?php $a++--";
        let mut lexer = Lexer::new(source);

        let mut tokens = Vec::new();
        while let Some((token, span)) = lexer.next_token() {
            tokens.push((token, span.extract(source).to_string()));
        }

        assert_eq!(tokens[0].0, Token::OpenTag);
        assert_eq!(tokens[1].0, Token::Variable);
        assert_eq!(tokens[1].1, "$a");
        assert_eq!(tokens[2].0, Token::Inc);
        assert_eq!(tokens[2].1, "++");
        assert_eq!(tokens[3].0, Token::Dec);
        assert_eq!(tokens[3].1, "--");
    }

    #[test]
    fn test_scripting_longest_match_wins() {
        // Test: Longest operator match wins (e.g., === not ==)
        let test_cases = vec![
            ("<?php ===", Token::IsIdentical, "==="),
            ("<?php !==", Token::IsNotIdentical, "!=="),
            ("<?php <=>", Token::Spaceship, "<=>"),
            ("<?php **=", Token::PowEqual, "**="),
            ("<?php ??=", Token::CoalesceEqual, "??="),
            ("<?php ?->", Token::NullsafeObjectOperator, "?->"),
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for source: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }
}
