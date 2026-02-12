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
    fn peek_str(&self, n: usize) -> &'src str {
        let end = (self.pos + n).min(self.source.len());
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

    /// Consume N bytes (used when we've already peeked a multi-byte sequence)
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
            if after.len() == 5 || after.chars().nth(5).map_or(true, |ch| ch.is_whitespace()) {
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
        // Placeholder for now - will implement in next tasks
        None
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
}
