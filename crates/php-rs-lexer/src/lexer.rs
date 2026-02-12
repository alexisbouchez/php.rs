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
}
