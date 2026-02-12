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

    /// Scan a number literal (decimal, hex, octal, binary)
    /// Reference: php-src/Zend/zend_language_scanner.l
    fn scan_number(&mut self) -> Option<(Token, Span)> {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        let first = self.peek()?;

        if first == '0' {
            self.consume(); // consume '0'

            // Check for hex (0x or 0X)
            if let Some(next) = self.peek() {
                if next == 'x' || next == 'X' {
                    self.consume(); // consume 'x' or 'X'
                                    // Consume hex digits (and underscores)
                    let mut has_digits = false;
                    while let Some(ch) = self.peek() {
                        if ch.is_ascii_hexdigit() {
                            self.consume();
                            has_digits = true;
                        } else if ch == '_' {
                            self.consume(); // Allow underscores as separators
                        } else {
                            break;
                        }
                    }
                    // If no hex digits after 0x, this is an error, but we'll let the parser handle it
                    if !has_digits {
                        // Still return LNumber for now
                    }
                    let span = Span::new(start_pos, self.pos, start_line, start_column);
                    let token = self.detect_integer_overflow(&self.source[start_pos..self.pos]);
                    return Some((token, span));
                }

                // Check for octal (0o or 0O)
                if next == 'o' || next == 'O' {
                    self.consume(); // consume 'o' or 'O'
                                    // Consume octal digits (0-7 and underscores)
                    let mut has_digits = false;
                    while let Some(ch) = self.peek() {
                        if ('0'..='7').contains(&ch) {
                            self.consume();
                            has_digits = true;
                        } else if ch == '_' {
                            self.consume();
                        } else {
                            break;
                        }
                    }
                    if !has_digits {
                        // Still return LNumber
                    }
                    let span = Span::new(start_pos, self.pos, start_line, start_column);
                    let token = self.detect_integer_overflow(&self.source[start_pos..self.pos]);
                    return Some((token, span));
                }

                // Check for binary (0b or 0B)
                if next == 'b' || next == 'B' {
                    self.consume(); // consume 'b' or 'B'
                                    // Consume binary digits (0-1 and underscores)
                    let mut has_digits = false;
                    while let Some(ch) = self.peek() {
                        if ch == '0' || ch == '1' {
                            self.consume();
                            has_digits = true;
                        } else if ch == '_' {
                            self.consume();
                        } else {
                            break;
                        }
                    }
                    if !has_digits {
                        // Still return LNumber
                    }
                    let span = Span::new(start_pos, self.pos, start_line, start_column);
                    let token = self.detect_integer_overflow(&self.source[start_pos..self.pos]);
                    return Some((token, span));
                }

                // Traditional octal (leading 0 followed by octal digits)
                // e.g., 0777, 0123
                // This is the old-style octal notation
                // Note: we only consume valid octal digits (0-7)
                // If we encounter 8 or 9, we stop
                if ('0'..='7').contains(&next) {
                    while let Some(ch) = self.peek() {
                        if ('0'..='7').contains(&ch) || ch == '_' {
                            self.consume();
                        } else {
                            break;
                        }
                    }
                    let span = Span::new(start_pos, self.pos, start_line, start_column);
                    let token = self.detect_integer_overflow(&self.source[start_pos..self.pos]);
                    return Some((token, span));
                }

                // Check if next is '8' or '9' - invalid for traditional octal
                // In this case, just return "0"
                if next == '8' || next == '9' {
                    let span = Span::new(start_pos, self.pos, start_line, start_column);
                    return Some((Token::LNumber, span));
                }

                // Just "0" followed by something else (not a digit, not a base prefix)
                // Return just the "0"
            }

            // Just "0" by itself
            let span = Span::new(start_pos, self.pos, start_line, start_column);
            return Some((Token::LNumber, span));
        }

        // Decimal number (starts with 1-9)
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.consume();
            } else if ch == '_' {
                self.consume(); // Allow underscores as separators
            } else {
                break;
            }
        }

        let span = Span::new(start_pos, self.pos, start_line, start_column);
        let token = self.detect_integer_overflow(&self.source[start_pos..self.pos]);
        Some((token, span))
    }

    /// Detect if a number literal overflows PHP_INT_MAX and should be DNumber instead of LNumber
    /// PHP_INT_MAX = 9223372036854775807 (0x7FFFFFFFFFFFFFFF) for 64-bit systems
    fn detect_integer_overflow(&self, num_str: &str) -> Token {
        // Strip underscores for parsing
        let clean_str = num_str.replace('_', "");

        // Try to parse based on prefix
        let result = if clean_str.starts_with("0x") || clean_str.starts_with("0X") {
            // Hex
            let digits = &clean_str[2..];
            if digits.is_empty() {
                return Token::LNumber; // Invalid literal like "0x", treat as LNumber for now
            }
            i64::from_str_radix(digits, 16)
        } else if clean_str.starts_with("0b") || clean_str.starts_with("0B") {
            // Binary
            let digits = &clean_str[2..];
            if digits.is_empty() {
                return Token::LNumber; // Invalid literal like "0b"
            }
            i64::from_str_radix(digits, 2)
        } else if clean_str.starts_with("0o") || clean_str.starts_with("0O") {
            // Octal with prefix
            let digits = &clean_str[2..];
            if digits.is_empty() {
                return Token::LNumber; // Invalid literal like "0o"
            }
            i64::from_str_radix(digits, 8)
        } else if clean_str.len() > 1 && clean_str.starts_with('0') {
            // Traditional octal (leading 0)
            i64::from_str_radix(&clean_str, 8)
        } else {
            // Decimal
            clean_str.parse::<i64>()
        };

        match result {
            Ok(_) => Token::LNumber,  // Fits in i64
            Err(_) => Token::DNumber, // Overflows to float
        }
    }

    /// Scan a single-quoted string literal
    /// Single-quoted strings in PHP only recognize two escape sequences:
    /// - \\ (escaped backslash)
    /// - \' (escaped single quote)
    /// All other characters (including \n, \t, etc.) are treated literally.
    fn scan_single_quoted_string(&mut self) -> Option<(Token, Span)> {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        // Consume opening single quote
        self.consume(); // '

        loop {
            match self.peek() {
                None => {
                    // Unterminated string - reached EOF
                    // For now, return what we have as a string
                    // (A proper implementation might want to emit an error)
                    return Some((
                        Token::ConstantEncapsedString,
                        Span::new(start_pos, self.pos, start_line, start_column),
                    ));
                }
                Some('\\') => {
                    // Check if it's an escape sequence
                    self.consume(); // consume backslash
                    match self.peek() {
                        Some('\\') | Some('\'') => {
                            // Valid escape sequence: \\ or \'
                            self.consume();
                        }
                        _ => {
                            // Not an escape sequence, backslash is literal
                            // The backslash is already consumed, continue
                        }
                    }
                }
                Some('\'') => {
                    // Closing single quote
                    self.consume();
                    return Some((
                        Token::ConstantEncapsedString,
                        Span::new(start_pos, self.pos, start_line, start_column),
                    ));
                }
                Some(_) => {
                    // Regular character
                    self.consume();
                }
            }
        }
    }

    /// Scan a double-quoted string literal
    /// Double-quoted strings in PHP support many escape sequences:
    /// - \n (newline), \r (carriage return), \t (tab)
    /// - \v (vertical tab), \e (escape), \f (form feed)
    /// - \\ (backslash), \$ (dollar sign), \" (double quote)
    /// - \xHH (hex escape, 2 hex digits)
    /// - \u{HHHHHH} (unicode escape, 1-6 hex digits)
    /// - \OOO (octal escape, 1-3 octal digits)
    /// Variable interpolation is handled separately in task 2.2.8.
    fn scan_double_quoted_string(&mut self) -> Option<(Token, Span)> {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        // Consume opening double quote
        self.consume(); // "

        loop {
            match self.peek() {
                None => {
                    // Unterminated string - reached EOF
                    return Some((
                        Token::ConstantEncapsedString,
                        Span::new(start_pos, self.pos, start_line, start_column),
                    ));
                }
                Some('\\') => {
                    // Check if it's an escape sequence
                    self.consume(); // consume backslash
                    match self.peek() {
                        Some('n') | Some('r') | Some('t') | Some('v') | Some('e') | Some('f')
                        | Some('\\') | Some('$') | Some('"') => {
                            // Valid escape sequence
                            self.consume();
                        }
                        Some('x') => {
                            // Hex escape: \xHH (2 hex digits)
                            self.consume(); // consume 'x'
                                            // Consume up to 2 hex digits
                            for _ in 0..2 {
                                if let Some(ch) = self.peek() {
                                    if ch.is_ascii_hexdigit() {
                                        self.consume();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        Some('u') => {
                            // Unicode escape: \u{HHHHHH} (1-6 hex digits)
                            self.consume(); // consume 'u'
                            if let Some('{') = self.peek() {
                                self.consume(); // consume '{'
                                                // Consume up to 6 hex digits
                                for _ in 0..6 {
                                    if let Some(ch) = self.peek() {
                                        if ch.is_ascii_hexdigit() {
                                            self.consume();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                // Consume closing '}'
                                if let Some('}') = self.peek() {
                                    self.consume();
                                }
                            }
                        }
                        Some(ch) if ch.is_ascii_digit() => {
                            // Octal escape: \OOO (1-3 octal digits)
                            // First digit already peeked, consume it
                            self.consume();
                            // Consume up to 2 more octal digits
                            for _ in 0..2 {
                                if let Some(ch) = self.peek() {
                                    if ch >= '0' && ch <= '7' {
                                        self.consume();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        _ => {
                            // Not a recognized escape sequence, backslash is literal
                            // The backslash is already consumed, continue
                        }
                    }
                }
                Some('"') => {
                    // Closing double quote
                    self.consume();
                    return Some((
                        Token::ConstantEncapsedString,
                        Span::new(start_pos, self.pos, start_line, start_column),
                    ));
                }
                Some(_) => {
                    // Regular character (including $, which we'll handle in task 2.2.8)
                    self.consume();
                }
            }
        }
    }

    /// Scan heredoc or nowdoc
    /// Reference: php-src/Zend/zend_language_scanner.l
    /// Heredoc: <<<LABEL or <<<"LABEL" or <<<'LABEL'
    /// Nowdoc: <<<'LABEL' (single quotes only)
    fn scan_heredoc_or_nowdoc(&mut self) -> Option<(Token, Span)> {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_column = self.column;

        // Consume <<<
        if self.peek_str(3) != "<<<" {
            return None;
        }
        self.consume_bytes(3);

        // Skip any whitespace after <<<
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.consume();
            } else {
                break;
            }
        }

        // Check if we have a quote
        let is_quoted = matches!(self.peek(), Some('\'') | Some('"'));
        let quote_char = if is_quoted {
            let q = self.peek()?;
            self.consume();
            Some(q)
        } else {
            None
        };

        // Read the label (identifier)
        let _label_start = self.pos; // Will be used later for extracting label
        let first_char = self.peek()?;

        // Label must start with letter or underscore
        if !first_char.is_alphabetic() && first_char != '_' {
            // Not a valid heredoc/nowdoc label
            // This could be <<< used as operator sequence
            // Backtrack and return None
            self.pos = start_pos;
            self.line = start_line;
            self.column = start_column;
            return None;
        }

        self.consume();

        // Continue reading label (alphanumeric and underscore)
        while let Some(ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                self.consume();
            } else {
                break;
            }
        }

        let _label_end = self.pos;
        // let label = &self.source[label_start..label_end];

        // If quoted, we need the closing quote
        if let Some(quote) = quote_char {
            if self.peek() != Some(quote) {
                // Missing closing quote - invalid
                self.pos = start_pos;
                self.line = start_line;
                self.column = start_column;
                return None;
            }
            self.consume();
        }

        // After the label (and optional closing quote), we expect newline or whitespace
        // In PHP, the heredoc label line should end with a newline
        // Capture the span BEFORE consuming the newline
        let span_end = self.pos;

        // Consume optional whitespace and newline (but don't include in span)
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.consume();
            } else if ch == '\n' || ch == '\r' {
                // Consume newline
                if ch == '\r' {
                    self.consume();
                    if self.peek() == Some('\n') {
                        self.consume(); // \r\n
                    }
                } else {
                    self.consume(); // \n
                }
                break;
            } else {
                // Invalid character after heredoc label
                // This might not be a heredoc after all
                self.pos = start_pos;
                self.line = start_line;
                self.column = start_column;
                return None;
            }
        }

        // We've successfully scanned a heredoc/nowdoc start
        // For now, we just return StartHeredoc token
        // The distinction between heredoc and nowdoc will be handled by checking
        // if the label was single-quoted (nowdoc) or not (heredoc)
        //
        // Note: In full implementation, we would also scan the body and closing marker
        // But for this task, we're just scanning the opening marker

        let span = Span::new(start_pos, span_end, start_line, start_column);
        Some((Token::StartHeredoc, span))
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
        // Check for heredoc/nowdoc before left shift operator
        // Heredoc: <<<LABEL or <<<"LABEL" or <<<'LABEL'
        // Nowdoc: <<<'LABEL' (single quotes)
        if self.peek_str(3) == "<<<" {
            // Peek ahead to see if this is heredoc/nowdoc or just <<< operator sequence
            // For heredoc/nowdoc, after <<< we need either:
            // - An identifier (unquoted label)
            // - A quoted identifier ('LABEL' or "LABEL")
            // We'll try to scan it as heredoc/nowdoc
            if let Some(heredoc_token) = self.scan_heredoc_or_nowdoc() {
                return Some(heredoc_token);
            }
            // If scan_heredoc_or_nowdoc returns None, fall through to regular << handling
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
            '\'' => {
                // Single-quoted string
                self.scan_single_quoted_string()
            }
            '"' => {
                // Double-quoted string
                self.scan_double_quoted_string()
            }
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
            _ if ch.is_ascii_digit() => {
                // Number literal: decimal, hex (0x), octal (0o/0), binary (0b)
                self.scan_number()
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

    // ======================================================================
    // Task 2.2.4: Test all 70+ PHP keywords
    // ======================================================================

    #[test]
    fn test_all_php_keywords_comprehensive() {
        // Test: All PHP 8.6 keywords are recognized (case-insensitive)
        // Reference: php-src/Zend/zend_language_scanner.l
        // Total: 70+ keywords including control flow, declarations, operators, etc.

        let all_keywords = vec![
            // Control flow keywords
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
            ("break", Token::Break),
            ("continue", Token::Continue),
            ("goto", Token::Goto),
            ("match", Token::Match),
            // Declaration keywords
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
            ("declare", Token::Declare),
            ("enddeclare", Token::Enddeclare),
            // Visibility and modifiers
            ("public", Token::Public),
            ("protected", Token::Protected),
            ("private", Token::Private),
            ("static", Token::Static),
            ("final", Token::Final),
            ("abstract", Token::Abstract),
            ("readonly", Token::Readonly),
            ("var", Token::Var),
            // Exception handling
            ("try", Token::Try),
            ("catch", Token::Catch),
            ("finally", Token::Finally),
            ("throw", Token::Throw),
            // Language constructs
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
            ("die", Token::Exit), // die is an alias for exit
            ("list", Token::List),
            ("array", Token::Array),
            ("callable", Token::Callable),
            ("global", Token::Global),
            ("as", Token::As),
            ("insteadof", Token::Insteadof),
            // Logical operators (keyword form)
            ("and", Token::LogicalAnd),
            ("or", Token::LogicalOr),
            ("xor", Token::LogicalXor),
        ];

        println!("\nTesting {} PHP keywords...", all_keywords.len());

        for (keyword, expected_token) in &all_keywords {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);

            // Skip <?php
            lexer.next_token();

            // Get the keyword token
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize keyword: {}", keyword));

            assert_eq!(
                token, *expected_token,
                "Keyword '{}' should tokenize to {:?}, got {:?}",
                keyword, expected_token, token
            );
            assert_eq!(
                span.extract(&source),
                *keyword,
                "Span should extract '{}'",
                keyword
            );
        }

        println!("✓ All {} keywords passed!", all_keywords.len());
    }

    #[test]
    fn test_all_php_keywords_case_insensitive() {
        // Test: Verify keywords are case-insensitive (fundamental PHP behavior)
        // Test a representative sample with different cases

        let case_variants = vec![
            // Each entry: (lowercase, UPPERCASE, MixedCase, expected_token)
            ("if", "IF", "If", Token::If),
            ("function", "FUNCTION", "Function", Token::Function),
            ("class", "CLASS", "Class", Token::Class),
            ("namespace", "NAMESPACE", "NameSpace", Token::Namespace),
            ("foreach", "FOREACH", "ForEach", Token::Foreach),
            ("instanceof", "INSTANCEOF", "InstanceOf", Token::Instanceof),
            ("readonly", "READONLY", "ReadOnly", Token::Readonly),
            ("match", "MATCH", "Match", Token::Match),
            ("enum", "ENUM", "Enum", Token::Enum),
            ("trait", "TRAIT", "Trait", Token::Trait),
        ];

        for (lower, upper, mixed, expected_token) in case_variants {
            // Test lowercase
            let source_lower = format!("<?php {}", lower);
            let mut lexer = Lexer::new(&source_lower);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", lower));
            assert_eq!(token, expected_token, "Failed for lowercase: {}", lower);

            // Test UPPERCASE
            let source_upper = format!("<?php {}", upper);
            let mut lexer = Lexer::new(&source_upper);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", upper));
            assert_eq!(token, expected_token, "Failed for UPPERCASE: {}", upper);

            // Test MixedCase
            let source_mixed = format!("<?php {}", mixed);
            let mut lexer = Lexer::new(&source_mixed);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", mixed));
            assert_eq!(token, expected_token, "Failed for MixedCase: {}", mixed);
        }
    }

    #[test]
    fn test_all_magic_constants() {
        // Test: All magic constants (case-insensitive)
        // Reference: php-src/Zend/zend_language_scanner.l

        let magic_constants = vec![
            ("__LINE__", Token::Line),
            ("__FILE__", Token::File),
            ("__DIR__", Token::Dir),
            ("__FUNCTION__", Token::FuncC),
            ("__CLASS__", Token::ClassC),
            ("__TRAIT__", Token::TraitC),
            ("__METHOD__", Token::MethodC),
            ("__NAMESPACE__", Token::NsC),
            ("__PROPERTY__", Token::PropertyC),
        ];

        for (constant, expected_token) in magic_constants {
            // Test as-is (uppercase)
            let source = format!("<?php {}", constant);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", constant));
            assert_eq!(
                token, expected_token,
                "Magic constant '{}' should tokenize to {:?}",
                constant, expected_token
            );
            assert_eq!(span.extract(&source), constant);

            // Test lowercase variant
            let lowercase = constant.to_lowercase();
            let source_lower = format!("<?php {}", lowercase);
            let mut lexer_lower = Lexer::new(&source_lower);
            lexer_lower.next_token(); // Skip <?php
            let (token_lower, _) = lexer_lower
                .next_token()
                .expect(&format!("Should tokenize: {}", lowercase));
            assert_eq!(
                token_lower, expected_token,
                "Magic constant '{}' (lowercase) should tokenize to {:?}",
                lowercase, expected_token
            );
        }
    }

    #[test]
    fn test_keywords_vs_identifiers() {
        // Test: Keywords are recognized, but similar identifiers are not
        // This ensures we correctly distinguish keywords from identifiers

        let test_cases = vec![
            // (input, is_keyword, expected_token)
            ("if", true, Token::If),
            ("ifx", false, Token::String), // Not a keyword
            ("iffy", false, Token::String),
            ("function", true, Token::Function),
            ("function1", false, Token::String),
            ("my_function", false, Token::String),
            ("class", true, Token::Class),
            ("class_name", false, Token::String),
            ("MyClass", false, Token::String),
            ("foreach", true, Token::Foreach),
            ("foreachable", false, Token::String),
            ("match", true, Token::Match),
            ("matcher", false, Token::String),
            ("readonly", true, Token::Readonly),
            ("readonly_property", false, Token::String),
        ];

        for (text, is_keyword, expected_token) in test_cases {
            let source = format!("<?php {}", text);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", text));

            assert_eq!(
                token,
                expected_token,
                "'{}' should be {} (got {:?})",
                text,
                if is_keyword {
                    "a keyword"
                } else {
                    "an identifier"
                },
                token
            );
            assert_eq!(span.extract(&source), text);
        }
    }

    #[test]
    fn test_keyword_count_completeness() {
        // Test: Verify we have all expected keywords
        // This is a meta-test to ensure we're not missing any keywords

        // Count keywords in our lexer implementation
        let keywords_in_lexer = vec![
            "abstract",
            "and",
            "array",
            "as",
            "break",
            "callable",
            "case",
            "catch",
            "class",
            "clone",
            "const",
            "continue",
            "declare",
            "default",
            "die",
            "do",
            "echo",
            "else",
            "elseif",
            "empty",
            "enddeclare",
            "endfor",
            "endforeach",
            "endif",
            "endswitch",
            "endwhile",
            "enum",
            "eval",
            "exit",
            "extends",
            "final",
            "finally",
            "fn",
            "for",
            "foreach",
            "function",
            "global",
            "goto",
            "if",
            "implements",
            "include",
            "include_once",
            "instanceof",
            "insteadof",
            "interface",
            "isset",
            "list",
            "match",
            "namespace",
            "new",
            "or",
            "print",
            "private",
            "protected",
            "public",
            "readonly",
            "require",
            "require_once",
            "return",
            "static",
            "switch",
            "throw",
            "trait",
            "try",
            "unset",
            "use",
            "var",
            "while",
            "xor",
            "yield",
        ];

        // Magic constants (also case-insensitive like keywords)
        let magic_constants = vec![
            "__CLASS__",
            "__DIR__",
            "__FILE__",
            "__FUNCTION__",
            "__LINE__",
            "__METHOD__",
            "__NAMESPACE__",
            "__TRAIT__",
            "__PROPERTY__",
        ];

        println!("\nKeyword count: {}", keywords_in_lexer.len());
        println!("Magic constant count: {}", magic_constants.len());
        println!("Total: {}", keywords_in_lexer.len() + magic_constants.len());

        // Verify we have at least 70 total (keywords + magic constants)
        assert!(
            keywords_in_lexer.len() + magic_constants.len() >= 70,
            "Expected at least 70 keywords/constants, found {}",
            keywords_in_lexer.len() + magic_constants.len()
        );

        // Test each keyword actually works
        for keyword in keywords_in_lexer {
            let source = format!("<?php {}", keyword);
            let mut lexer = Lexer::new(&source);
            lexer.next_token(); // Skip <?php
            let (token, _) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", keyword));

            // Should NOT be a regular String token (should be recognized as keyword)
            if keyword != "from" {
                // "from" is special - not a standalone keyword in PHP
                assert_ne!(
                    token,
                    Token::String,
                    "Keyword '{}' should not tokenize as String (got {:?})",
                    keyword,
                    token
                );
            }
        }
    }

    // ======================================================================
    // Task 2.2.5: Test number literals - decimal, hex, octal, binary, underscores
    // ======================================================================

    #[test]
    fn test_number_literal_decimal() {
        // Test: Decimal integers
        let test_cases = vec![
            ("<?php 0", "0"),
            ("<?php 1", "1"),
            ("<?php 42", "42"),
            ("<?php 123", "123"),
            ("<?php 999", "999"),
            ("<?php 1234567890", "1234567890"),
        ];

        for (source, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, Token::LNumber, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_hex() {
        // Test: Hexadecimal integers (0x prefix)
        let test_cases = vec![
            ("<?php 0x0", "0x0"),
            ("<?php 0x1", "0x1"),
            ("<?php 0x10", "0x10"),
            ("<?php 0xFF", "0xFF"),
            ("<?php 0xff", "0xff"),
            ("<?php 0xABCD", "0xABCD"),
            ("<?php 0xabcd", "0xabcd"),
            ("<?php 0X1F", "0X1F"), // Capital X is also valid
            ("<?php 0xDEADBEEF", "0xDEADBEEF"),
        ];

        for (source, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, Token::LNumber, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_octal() {
        // Test: Octal integers (0o prefix or leading 0)
        // PHP 8.1+ supports 0o prefix, and traditional leading 0 (but 0o is preferred)
        let test_cases = vec![
            ("<?php 0o0", "0o0"),
            ("<?php 0o7", "0o7"),
            ("<?php 0o10", "0o10"),
            ("<?php 0o77", "0o77"),
            ("<?php 0o777", "0o777"),
            ("<?php 0O77", "0O77"), // Capital O is also valid
            // Traditional leading 0 (deprecated style but still valid)
            ("<?php 00", "00"),
            ("<?php 07", "07"),
            ("<?php 010", "010"),
            ("<?php 0777", "0777"),
        ];

        for (source, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, Token::LNumber, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_binary() {
        // Test: Binary integers (0b prefix)
        let test_cases = vec![
            ("<?php 0b0", "0b0"),
            ("<?php 0b1", "0b1"),
            ("<?php 0b10", "0b10"),
            ("<?php 0b11", "0b11"),
            ("<?php 0b1111", "0b1111"),
            ("<?php 0b10101010", "0b10101010"),
            ("<?php 0B1010", "0B1010"), // Capital B is also valid
        ];

        for (source, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, Token::LNumber, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_with_underscores() {
        // Test: Numeric separators (underscores) - PHP 7.4+
        // Underscores can appear anywhere in the number except:
        // - At the start
        // - At the end
        // - Adjacent to another underscore
        // - Adjacent to the base prefix (0x, 0o, 0b)

        let test_cases = vec![
            // Decimal with underscores
            ("<?php 1_000", "1_000"),
            ("<?php 1_000_000", "1_000_000"),
            ("<?php 100_000", "100_000"),
            ("<?php 1_2_3_4", "1_2_3_4"),
            // Hex with underscores
            ("<?php 0xFF_FF", "0xFF_FF"),
            ("<?php 0xDEAD_BEEF", "0xDEAD_BEEF"),
            // Octal with underscores
            ("<?php 0o7_7_7", "0o7_7_7"),
            // Binary with underscores
            ("<?php 0b1010_1010", "0b1010_1010"),
            ("<?php 0b1111_0000_1111_0000", "0b1111_0000_1111_0000"),
        ];

        for (source, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, Token::LNumber, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_edge_cases() {
        // Test: Edge cases for number literals
        let test_cases = vec![
            // Just 0
            ("<?php 0", Token::LNumber, "0"),
            // Leading zeros with decimal (traditional octal - now deprecated but still works)
            ("<?php 0123", Token::LNumber, "0123"),
            // Underscore in various positions (valid)
            ("<?php 1_0", Token::LNumber, "1_0"),
            ("<?php 10_0", Token::LNumber, "10_0"),
            // Maximum safe values
            (
                "<?php 9223372036854775807",
                Token::LNumber,
                "9223372036854775807",
            ), // PHP_INT_MAX (64-bit)
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php
            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_number_literal_in_expression() {
        // Test: Numbers in expressions (ensure they're properly delimited)
        let source = "<?php 42+100";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token1, span1) = lexer.next_token().expect("Should get first number");
        assert_eq!(token1, Token::LNumber);
        assert_eq!(span1.extract(source), "42");

        // Next should be + (currently BadCharacter, but that's OK for now)
        let (_token2, _) = lexer.next_token().expect("Should get operator");
        // We expect BadCharacter for now since single-char operators aren't fully implemented

        let (token3, span3) = lexer.next_token().expect("Should get second number");
        assert_eq!(token3, Token::LNumber);
        assert_eq!(span3.extract(source), "100");
    }

    #[test]
    fn test_number_literal_followed_by_identifier() {
        // Test: Number followed by identifier (should be two separate tokens)
        let source = "<?php 42abc";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // This should fail during tokenization because "42abc" is invalid
        // In PHP, this would be a parse error
        // The lexer should recognize "42" as a number, then "abc" as an identifier

        let (token1, span1) = lexer.next_token().expect("Should get number");
        assert_eq!(token1, Token::LNumber);
        assert_eq!(span1.extract(source), "42");

        let (token2, span2) = lexer.next_token().expect("Should get identifier");
        assert_eq!(token2, Token::String);
        assert_eq!(span2.extract(source), "abc");
    }

    // ======================================================================
    // Task 2.2.6: Test integer overflow to float, edge cases
    // ======================================================================

    #[test]
    fn test_integer_overflow_to_float() {
        // Test: Integer literals that exceed PHP_INT_MAX should become DNumber (float)
        // PHP_INT_MAX for 64-bit: 9223372036854775807
        // PHP_INT_MAX + 1: 9223372036854775808 → should be DNumber

        let test_cases = vec![
            // Exact PHP_INT_MAX - should still be LNumber
            (
                "<?php 9223372036854775807",
                Token::LNumber,
                "9223372036854775807",
            ),
            // PHP_INT_MAX + 1 - should overflow to DNumber
            (
                "<?php 9223372036854775808",
                Token::DNumber,
                "9223372036854775808",
            ),
            // Much larger number - definitely DNumber
            (
                "<?php 99999999999999999999",
                Token::DNumber,
                "99999999999999999999",
            ),
            // Negative: PHP_INT_MIN is -9223372036854775808 (exact)
            // At lexer level, we just scan the positive number; the minus is a separate token
            // So -9223372036854775808 is: '-' (unary minus) + '9223372036854775808'
            // The number 9223372036854775808 itself overflows, so it's DNumber
            // Hex overflow
            (
                "<?php 0x7FFFFFFFFFFFFFFF",
                Token::LNumber,
                "0x7FFFFFFFFFFFFFFF",
            ), // PHP_INT_MAX in hex
            (
                "<?php 0x8000000000000000",
                Token::DNumber,
                "0x8000000000000000",
            ), // Overflows
            (
                "<?php 0xFFFFFFFFFFFFFFFF",
                Token::DNumber,
                "0xFFFFFFFFFFFFFFFF",
            ), // Overflows
            // Octal overflow
            (
                "<?php 0o777777777777777777777",
                Token::LNumber,
                "0o777777777777777777777",
            ), // PHP_INT_MAX in octal
            (
                "<?php 0o1000000000000000000000",
                Token::DNumber,
                "0o1000000000000000000000",
            ), // Overflows
            // Binary overflow
            (
                "<?php 0b111111111111111111111111111111111111111111111111111111111111111",
                Token::LNumber,
                "0b111111111111111111111111111111111111111111111111111111111111111",
            ), // 63 ones = PHP_INT_MAX
            (
                "<?php 0b1000000000000000000000000000000000000000000000000000000000000000",
                Token::DNumber,
                "0b1000000000000000000000000000000000000000000000000000000000000000",
            ), // 64 bits = overflows
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php

            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_integer_edge_cases_comprehensive() {
        // Test: Various edge cases for integer literals

        let test_cases = vec![
            // Single digit
            ("<?php 0", Token::LNumber, "0"),
            ("<?php 1", Token::LNumber, "1"),
            ("<?php 9", Token::LNumber, "9"),
            // Multiple underscores (valid in PHP 7.4+)
            ("<?php 1_000_000", Token::LNumber, "1_000_000"),
            ("<?php 1_2_3_4_5", Token::LNumber, "1_2_3_4_5"),
            // Leading underscore in number body (after first digit)
            ("<?php 1_", Token::LNumber, "1_"), // Trailing underscore - we'll scan it
            // Hex edge cases
            ("<?php 0x0", Token::LNumber, "0x0"),
            ("<?php 0x1", Token::LNumber, "0x1"),
            ("<?php 0xF", Token::LNumber, "0xF"),
            ("<?php 0xf", Token::LNumber, "0xf"),
            ("<?php 0xFF", Token::LNumber, "0xFF"),
            ("<?php 0X1A", Token::LNumber, "0X1A"), // Capital X
            ("<?php 0x1_A_F", Token::LNumber, "0x1_A_F"), // Underscore in hex
            // Octal edge cases
            ("<?php 0o0", Token::LNumber, "0o0"),
            ("<?php 0o7", Token::LNumber, "0o7"),
            ("<?php 0o77", Token::LNumber, "0o77"),
            ("<?php 0O7", Token::LNumber, "0O7"), // Capital O
            ("<?php 0o1_7", Token::LNumber, "0o1_7"), // Underscore in octal
            // Traditional octal (just leading 0)
            ("<?php 00", Token::LNumber, "00"),
            ("<?php 01", Token::LNumber, "01"),
            ("<?php 07", Token::LNumber, "07"),
            ("<?php 0123", Token::LNumber, "0123"),
            // Binary edge cases
            ("<?php 0b0", Token::LNumber, "0b0"),
            ("<?php 0b1", Token::LNumber, "0b1"),
            ("<?php 0b10", Token::LNumber, "0b10"),
            ("<?php 0B1", Token::LNumber, "0B1"), // Capital B
            ("<?php 0b1_0_1", Token::LNumber, "0b1_0_1"), // Underscore in binary
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php

            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_invalid_number_literals() {
        // Test: Invalid number literals that should still tokenize but may have no digits
        // PHP is lenient and will parse what it can

        let test_cases = vec![
            // Hex with no digits after 0x - still scans as LNumber "0x"
            ("<?php 0x", Token::LNumber, "0x"),
            ("<?php 0X", Token::LNumber, "0X"),
            // Octal with no digits after 0o
            ("<?php 0o", Token::LNumber, "0o"),
            ("<?php 0O", Token::LNumber, "0O"),
            // Binary with no digits after 0b
            ("<?php 0b", Token::LNumber, "0b"),
            ("<?php 0B", Token::LNumber, "0B"),
            // Hex with invalid digits (8, 9, G) - should stop at invalid char
            ("<?php 0xG", Token::LNumber, "0x"), // G is not valid hex
            ("<?php 0x1G", Token::LNumber, "0x1"), // Stops at G
            // Octal with invalid digits (8, 9) - traditional octal
            ("<?php 08", Token::LNumber, "0"), // 8 is not valid octal, so stops at 0
            ("<?php 0789", Token::LNumber, "07"), // Consumes 07, stops at 8 (8 is invalid octal)
            // Octal with 0o prefix and invalid digit
            ("<?php 0o8", Token::LNumber, "0o"), // 8 is not valid octal
            // Binary with invalid digits (2, 3, etc.)
            ("<?php 0b2", Token::LNumber, "0b"), // 2 is not valid binary
            ("<?php 0b12", Token::LNumber, "0b1"), // Stops at 2
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php

            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for: {}", source);
            assert_eq!(span.extract(source), expected_text);
        }
    }

    #[test]
    fn test_single_quoted_string_simple() {
        // Test: simple single-quoted string
        let source = "<?php 'hello'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), "'hello'");
    }

    #[test]
    fn test_single_quoted_string_empty() {
        // Test: empty single-quoted string
        let source = "<?php ''";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize empty string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), "''");
    }

    #[test]
    fn test_single_quoted_string_escaped_backslash() {
        // Test: single-quoted string with escaped backslash
        let source = r"<?php 'hello\\world'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\\\");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r"'hello\\world'");
    }

    #[test]
    fn test_single_quoted_string_escaped_quote() {
        // Test: single-quoted string with escaped single quote
        let source = r"<?php 'hello\'world'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\'");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r"'hello\'world'");
    }

    #[test]
    fn test_single_quoted_string_no_variable_interpolation() {
        // Test: single-quoted strings do NOT interpolate variables
        let source = "<?php 'hello $var world'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), "'hello $var world'");
    }

    #[test]
    fn test_single_quoted_string_no_escape_sequences() {
        // Test: single-quoted strings do NOT process most escape sequences
        let source = r"<?php 'hello\nworld\t'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r"'hello\nworld\t'");
    }

    #[test]
    fn test_single_quoted_string_multiple() {
        // Test: multiple single-quoted strings in sequence
        let source = "<?php 'hello' 'world'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token1, span1) = lexer.next_token().expect("Should tokenize first string");
        assert_eq!(token1, Token::ConstantEncapsedString);
        assert_eq!(span1.extract(source), "'hello'");

        let (token2, span2) = lexer.next_token().expect("Should tokenize second string");
        assert_eq!(token2, Token::ConstantEncapsedString);
        assert_eq!(span2.extract(source), "'world'");
    }

    #[test]
    fn test_single_quoted_string_multiline() {
        // Test: single-quoted string spanning multiple lines
        let source = "<?php 'hello\nworld\ntest'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize multiline string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), "'hello\nworld\ntest'");
        // Verify line tracking
        assert_eq!(span.line, 1); // Starts on line 1
    }

    #[test]
    fn test_single_quoted_string_backslash_at_end() {
        // Test: single-quoted string with backslash before closing quote
        let source = r"<?php 'test\\'";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\\\");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r"'test\\'");
    }

    #[test]
    fn test_single_quoted_string_special_chars() {
        // Test: single-quoted string with special characters
        let source = r#"<?php 'hello"world'"#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with double quotes");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#"'hello"world'"#);
    }

    #[test]
    fn test_double_quoted_string_simple() {
        // Test: simple double-quoted string without escape sequences
        let source = r#"<?php "hello""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize double-quoted string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello""#);
    }

    #[test]
    fn test_double_quoted_string_empty() {
        // Test: empty double-quoted string
        let source = r#"<?php """#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize empty string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""""#);
    }

    #[test]
    fn test_double_quoted_string_escape_newline() {
        // Test: double-quoted string with \n escape
        let source = r#"<?php "hello\nworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\n");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\nworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_tab() {
        // Test: double-quoted string with \t escape
        let source = r#"<?php "hello\tworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\t");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\tworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_return() {
        // Test: double-quoted string with \r escape
        let source = r#"<?php "hello\rworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\r");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\rworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_vertical_tab() {
        // Test: double-quoted string with \v escape
        let source = r#"<?php "hello\vworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\v");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\vworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_escape() {
        // Test: double-quoted string with \e escape (ASCII escape character)
        let source = r#"<?php "hello\eworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\e");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\eworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_form_feed() {
        // Test: double-quoted string with \f escape
        let source = r#"<?php "hello\fworld""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\f");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\fworld""#);
    }

    #[test]
    fn test_double_quoted_string_escape_backslash() {
        // Test: double-quoted string with \\ escape
        let source = r#"<?php "hello\\world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\\\");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\\world""#);
    }

    #[test]
    fn test_double_quoted_string_escape_dollar() {
        // Test: double-quoted string with \$ escape (literal dollar sign)
        let source = r#"<?php "hello\$world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\$");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\$world""#);
    }

    #[test]
    fn test_double_quoted_string_escape_double_quote() {
        // Test: double-quoted string with \" escape
        let source = r#"<?php "hello\"world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\\"");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\"world""#);
    }

    #[test]
    fn test_double_quoted_string_escape_hex() {
        // Test: double-quoted string with \x hex escape
        let source = r#"<?php "hello\x41world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string with \\x");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\x41world""#);
    }

    #[test]
    fn test_double_quoted_string_escape_unicode() {
        // Test: double-quoted string with \u{} unicode escape
        let source = r#"<?php "hello\u{1F600}world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\u{}");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\u{1F600}world""#);
    }

    #[test]
    fn test_double_quoted_string_escape_octal() {
        // Test: double-quoted string with \0 octal escape
        let source = r#"<?php "hello\101world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with \\101");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello\101world""#);
    }

    #[test]
    fn test_double_quoted_string_multiple_escapes() {
        // Test: double-quoted string with multiple escape sequences
        let source = r#"<?php "line1\nline2\ttab\r\nend""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with multiple escapes");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""line1\nline2\ttab\r\nend""#);
    }

    #[test]
    fn test_double_quoted_string_single_quote_no_escape() {
        // Test: single quotes don't need escaping in double-quoted strings
        let source = r#"<?php "hello'world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize string with single quote");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello'world""#);
    }

    #[test]
    fn test_double_quoted_string_multiline() {
        // Test: double-quoted string spanning multiple lines
        let source = "<?php \"hello\nworld\"";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer
            .next_token()
            .expect("Should tokenize multiline string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), "\"hello\nworld\"");
    }

    #[test]
    fn test_double_quoted_string_no_variable_interpolation_for_now() {
        // Test: for now, we'll tokenize $var inside strings as part of the string
        // Later (task 2.2.8), we'll handle interpolation properly
        let source = r#"<?php "hello $var world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string");
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello $var world""#);
    }

    // ======================================================================
    // Task 2.2.7: Test heredoc implementation
    // ======================================================================

    #[test]
    fn test_heredoc_simple() {
        // Test: Basic heredoc syntax
        // Reference: php-src/Zend/tests/heredoc_nowdoc/heredoc_001.phpt
        let source = "<?php <<<EOT\nHello World\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize heredoc");
        assert_eq!(token, Token::StartHeredoc);
        assert_eq!(span.extract(source), "<<<EOT");
    }

    #[test]
    fn test_heredoc_with_content() {
        // Test: Heredoc with multiline content
        let source = "<?php <<<EOT\nLine 1\nLine 2\nLine 3\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, _) = lexer.next_token().expect("Should tokenize heredoc start");
        assert_eq!(token, Token::StartHeredoc);
    }

    #[test]
    fn test_heredoc_empty() {
        // Test: Empty heredoc
        let source = "<?php <<<EOT\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, _) = lexer.next_token().expect("Should tokenize empty heredoc");
        assert_eq!(token, Token::StartHeredoc);
    }

    #[test]
    fn test_heredoc_different_labels() {
        // Test: Heredoc with different delimiter labels
        let labels = vec!["EOT", "EOF", "HTML", "SQL", "END", "MARKER"];

        for label in labels {
            let source = format!("<?php <<<{}\nContent\n{};\n", label, label);
            let mut lexer = Lexer::new(&source);

            lexer.next_token(); // Skip <?php

            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize heredoc with label {}", label));
            assert_eq!(token, Token::StartHeredoc, "Failed for label: {}", label);
            assert_eq!(
                span.extract(&source),
                format!("<<<{}", label),
                "Failed for label: {}",
                label
            );
        }
    }

    #[test]
    fn test_heredoc_indented_modern() {
        // Test: Flexible heredoc (PHP 7.3+) - indented closing marker
        // Reference: php-src/Zend/tests/heredoc_nowdoc/flexible-heredoc-complex-test1.phpt
        let source = "<?php <<<EOT\n    Line 1\n    Line 2\n    EOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, _) = lexer
            .next_token()
            .expect("Should tokenize flexible heredoc");
        assert_eq!(token, Token::StartHeredoc);
    }

    #[test]
    fn test_heredoc_no_semicolon() {
        // Test: Heredoc without trailing semicolon (valid in some contexts)
        let source = "<?php <<<EOT\nContent\nEOT\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, _) = lexer.next_token().expect("Should tokenize heredoc");
        assert_eq!(token, Token::StartHeredoc);
    }

    #[test]
    fn test_heredoc_assignment() {
        // Test: Heredoc in assignment context
        let source = "<?php $var = <<<EOT\nHello\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (var_token, _) = lexer.next_token().expect("Should tokenize variable");
        assert_eq!(var_token, Token::Variable);

        // Skip = operator (BadCharacter for now)
        lexer.next_token();

        let (heredoc_token, _) = lexer.next_token().expect("Should tokenize heredoc");
        assert_eq!(heredoc_token, Token::StartHeredoc);
    }

    #[test]
    fn test_nowdoc_simple() {
        // Test: Basic nowdoc syntax (single quotes around label)
        // Reference: php-src/Zend/tests/heredoc_nowdoc/nowdoc_001.phpt
        // Note: PHP uses T_START_HEREDOC for both heredoc and nowdoc
        // The distinction is made by checking if the label is quoted
        let source = "<?php <<<'EOT'\nHello World\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize nowdoc");
        assert_eq!(token, Token::StartHeredoc); // Both use StartHeredoc
        assert_eq!(span.extract(source), "<<<'EOT'");
    }

    #[test]
    fn test_nowdoc_double_quotes_syntax() {
        // Test: Heredoc can also use double quotes (optional)
        // <<<\"EOT\" is valid heredoc syntax
        let source = "<?php <<<\"EOT\"\nContent\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize");
        assert_eq!(token, Token::StartHeredoc);
        assert_eq!(span.extract(source), "<<<\"EOT\"");
    }

    #[test]
    fn test_nowdoc_no_interpolation_marker() {
        // Test: Nowdoc uses single quotes - this is the marker for no interpolation
        let source = "<?php <<<'EOT'\n$var {$var}\nEOT;\n";
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize nowdoc");
        assert_eq!(token, Token::StartHeredoc);
        assert_eq!(span.extract(source), "<<<'EOT'");
        // Content tokenization would be tested in subsequent tokens
        // The lexer/parser will need to remember that this was a nowdoc (quoted label)
    }

    #[test]
    fn test_heredoc_vs_nowdoc_label_distinction() {
        // Test: Ensure heredoc and nowdoc labels are distinguished correctly
        // PHP uses the same token (T_START_HEREDOC) but the label format differs
        let test_cases = vec![
            ("<?php <<<EOT\nEOT;\n", Token::StartHeredoc, "<<<EOT"),
            ("<?php <<<'EOT'\nEOT;\n", Token::StartHeredoc, "<<<'EOT'"),
            (
                "<?php <<<\"EOT\"\nEOT;\n",
                Token::StartHeredoc,
                "<<<\"EOT\"",
            ),
        ];

        for (source, expected_token, expected_text) in test_cases {
            let mut lexer = Lexer::new(source);
            lexer.next_token(); // Skip <?php

            let (token, span) = lexer
                .next_token()
                .expect(&format!("Should tokenize: {}", source));
            assert_eq!(token, expected_token, "Failed for: {}", source);
            assert_eq!(
                span.extract(source),
                expected_text,
                "Failed for: {}",
                source
            );
        }
    }

    // ======================================================================
    // Task 2.2.8: Test string interpolation
    // Reference: php-src/Zend/zend_language_scanner.l (ST_DOUBLE_QUOTES state)
    // Reference: php-src/tests/lang/string/interpolation/
    // ======================================================================

    #[test]
    fn test_string_interpolation_simple_variable() {
        // Test: Simple variable interpolation "$var"
        // Reference: This is the most common form of string interpolation
        // Expected: Should tokenize as sequence of string parts and variable tokens
        //
        // In PHP's lexer, when scanning double-quoted strings, the lexer switches
        // to ST_DOUBLE_QUOTES state and emits multiple tokens:
        // 1. Opening quote (implicit in ConstantEncapsedString start)
        // 2. T_ENCAPSED_AND_WHITESPACE for "hello "
        // 3. T_VARIABLE for $var
        // 4. T_ENCAPSED_AND_WHITESPACE for " world"
        // 5. Closing quote (implicit in ConstantEncapsedString end)
        //
        // For now, we test that the lexer can at least recognize this pattern.
        // Full implementation will be in the scanner state machine.
        let source = r#"<?php "hello $var world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should return multiple tokens
        // For now, it should return a single ConstantEncapsedString token
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // This test documents current behavior (no interpolation yet)
        // When task 2.2.8 implementation is done, update this to expect:
        // - Token::EncapsedAndWhitespace for "hello "
        // - Token::Variable for $var
        // - Token::EncapsedAndWhitespace for " world"
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello $var world""#);
    }

    #[test]
    fn test_string_interpolation_curly_braces_complex() {
        // Test: Complex syntax with braces "{$var}"
        // Reference: php-src/Zend/zend_language_scanner.l - T_CURLY_OPEN
        // This syntax is used for complex expressions: "{$obj->prop}", "{$arr['key']}"
        let source = r#"<?php "hello {$var} world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should return:
        // - T_ENCAPSED_AND_WHITESPACE for "hello "
        // - T_CURLY_OPEN for {$
        // - T_STRING_VARNAME or T_VARIABLE for var
        // - '}' (single char)
        // - T_ENCAPSED_AND_WHITESPACE for " world"
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello {$var} world""#);
    }

    #[test]
    fn test_string_interpolation_dollar_curly_deprecated() {
        // Test: Deprecated syntax "${var}"
        // Reference: php-src/Zend/zend_language_scanner.l - T_DOLLAR_OPEN_CURLY_BRACES
        // This syntax is deprecated in PHP 8.2+ but still needs to be tokenized
        let source = r#"<?php "hello ${var} world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should return:
        // - T_ENCAPSED_AND_WHITESPACE for "hello "
        // - T_DOLLAR_OPEN_CURLY_BRACES for ${
        // - T_STRING_VARNAME for var
        // - '}' (single char)
        // - T_ENCAPSED_AND_WHITESPACE for " world"
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello ${var} world""#);
    }

    #[test]
    fn test_string_interpolation_object_property() {
        // Test: Object property access "$obj->prop"
        // Reference: php-src/Zend/zend_language_scanner.l
        // The lexer needs to recognize -> inside strings as T_OBJECT_OPERATOR
        let source = r#"<?php "hello $obj->prop world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should return:
        // - T_ENCAPSED_AND_WHITESPACE for "hello "
        // - T_VARIABLE for $obj
        // - T_OBJECT_OPERATOR for ->
        // - T_STRING for prop (property name)
        // - T_ENCAPSED_AND_WHITESPACE for " world"
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello $obj->prop world""#);
    }

    #[test]
    fn test_string_interpolation_array_access() {
        // Test: Array access "$arr[key]"
        // Reference: php-src/Zend/zend_language_scanner.l
        // Array access inside strings has special tokenization rules
        let source = r#"<?php "hello $arr[key] world""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should return:
        // - T_ENCAPSED_AND_WHITESPACE for "hello "
        // - T_VARIABLE for $arr
        // - '[' (single char)
        // - T_STRING or T_NUM_STRING for key (unquoted key inside string interpolation)
        // - ']' (single char)
        // - T_ENCAPSED_AND_WHITESPACE for " world"
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""hello $arr[key] world""#);
    }

    #[test]
    fn test_string_interpolation_multiple_variables() {
        // Test: Multiple variables in one string
        let source = r#"<?php "x=$x, y=$y, z=$z""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, this should alternate between
        // T_ENCAPSED_AND_WHITESPACE and T_VARIABLE tokens
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""x=$x, y=$y, z=$z""#);
    }

    #[test]
    fn test_string_interpolation_escaped_dollar() {
        // Test: Escaped dollar sign should not trigger interpolation
        let source = r#"<?php "price is \$100""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // This should remain as a single string token since $ is escaped
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""price is \$100""#);
    }

    #[test]
    fn test_string_interpolation_complex_array_access() {
        // Test: Complex array access with integer key
        let source = r#"<?php "value is $arr[0]""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented:
        // - T_ENCAPSED_AND_WHITESPACE for "value is "
        // - T_VARIABLE for $arr
        // - '['
        // - T_NUM_STRING for 0
        // - ']'
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""value is $arr[0]""#);
    }

    #[test]
    fn test_string_interpolation_nested_complex() {
        // Test: Complex nested expression with braces
        let source = r#"<?php "result: {$obj->method()['key']}""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // TODO: When interpolation is implemented, the {$ syntax allows
        // arbitrary expressions inside the braces
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Current behavior: returns single string token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""result: {$obj->method()['key']}""#);
    }

    #[test]
    fn test_string_no_interpolation_in_single_quotes() {
        // Test: Single-quoted strings should never interpolate
        let source = r#"<?php 'hello $var world'"#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        let (token, span) = lexer.next_token().expect("Should tokenize string");

        // Single-quoted strings never interpolate - always one token
        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#"'hello $var world'"#);
    }

    #[test]
    fn test_string_interpolation_edge_case_dollar_at_end() {
        // Test: Dollar sign at end of string
        let source = r#"<?php "price $""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // $ at end with no variable name should be treated as literal
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""price $""#);
    }

    #[test]
    fn test_string_interpolation_dollar_before_number() {
        // Test: Dollar sign followed by number (invalid variable name)
        let source = r#"<?php "$123""#;
        let mut lexer = Lexer::new(source);

        lexer.next_token(); // Skip <?php

        // $123 is not a valid variable name, so $ should be literal
        let (token, span) = lexer.next_token().expect("Should tokenize string");

        assert_eq!(token, Token::ConstantEncapsedString);
        assert_eq!(span.extract(source), r#""$123""#);
    }
}
