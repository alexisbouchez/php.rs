//! PHP tokenizer extension.
//!
//! Implements token_get_all(), token_name(), PhpToken class.
//! Reference: php-src/ext/tokenizer/

/// PHP token IDs (matching Zend engine token constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TokenKind {
    InlineHtml = 0,
    OpenTag = 392,
    CloseTag = 393,
    OpenTagWithEcho = 394,
    Whitespace = 401,
    Variable = 320,
    String = 321,
    LNumber = 317,
    DNumber = 318,
    ConstantEncapsedString = 323,
    EncapsedAndWhitespace = 324,
    If = 336,
    Else = 338,
    ElseIf = 337,
    While = 340,
    For = 342,
    ForEach = 344,
    Do = 341,
    Switch = 345,
    Case = 346,
    Default = 347,
    Break = 348,
    Continue = 349,
    Return = 350,
    Function = 351,
    Class = 369,
    Interface = 370,
    Extends = 380,
    Implements = 381,
    New = 360,
    Echo = 328,
    Print = 329,
    Isset = 363,
    Unset = 364,
    Empty = 365,
    Array = 372,
    List = 373,
    Eval = 260,
    Include = 262,
    IncludeOnce = 263,
    Require = 264,
    RequireOnce = 265,
    Throw = 284,
    Try = 358,
    Catch = 359,
    Finally = 357,
    Yield = 270,
    YieldFrom = 271,
    Fn = 343,
    Match = 395,
    Enum = 396,
    Readonly = 399,
    NamedArgument = 400,
    Comment = 397,
    DocComment = 398,
    IsEqual = 289,
    IsNotEqual = 290,
    IsIdentical = 291,
    IsNotIdentical = 292,
    Spaceship = 293,
    DoubleArrow = 268,
    Arrow = 402,
    PlusEqual = 277,
    MinusEqual = 278,
    MulEqual = 279,
    DivEqual = 280,
    ConcatEqual = 281,
    ModEqual = 282,
    BooleanAnd = 287,
    BooleanOr = 288,
    NullCoalesce = 286,
    Ellipsis = 305,
    Ns = 403,
    NsSeparator = 404,
}

/// A PHP token.
#[derive(Debug, Clone, PartialEq)]
pub struct PhpToken {
    /// Token ID.
    pub id: u32,
    /// Token text.
    pub text: String,
    /// Line number.
    pub line: u32,
}

impl PhpToken {
    pub fn new(id: u32, text: impl Into<String>, line: u32) -> Self {
        Self {
            id,
            text: text.into(),
            line,
        }
    }
}

/// token_name() — Get the symbolic name of a given PHP token.
pub fn token_name(id: u32) -> &'static str {
    match id {
        392 => "T_OPEN_TAG",
        393 => "T_CLOSE_TAG",
        394 => "T_OPEN_TAG_WITH_ECHO",
        401 => "T_WHITESPACE",
        320 => "T_VARIABLE",
        321 => "T_STRING",
        317 => "T_LNUMBER",
        318 => "T_DNUMBER",
        323 => "T_CONSTANT_ENCAPSED_STRING",
        336 => "T_IF",
        338 => "T_ELSE",
        337 => "T_ELSEIF",
        340 => "T_WHILE",
        342 => "T_FOR",
        344 => "T_FOREACH",
        350 => "T_RETURN",
        351 => "T_FUNCTION",
        369 => "T_CLASS",
        370 => "T_INTERFACE",
        360 => "T_NEW",
        328 => "T_ECHO",
        329 => "T_PRINT",
        397 => "T_COMMENT",
        398 => "T_DOC_COMMENT",
        260 => "T_EVAL",
        262 => "T_INCLUDE",
        263 => "T_INCLUDE_ONCE",
        264 => "T_REQUIRE",
        265 => "T_REQUIRE_ONCE",
        284 => "T_THROW",
        358 => "T_TRY",
        359 => "T_CATCH",
        270 => "T_YIELD",
        395 => "T_MATCH",
        _ => "UNKNOWN",
    }
}

/// token_get_all() — Split given source into PHP tokens.
///
/// Simplified tokenizer for basic PHP code.
pub fn token_get_all(source: &str) -> Vec<PhpToken> {
    let mut tokens = Vec::new();
    let mut line = 1u32;
    let bytes = source.as_bytes();
    let mut pos = 0;

    // Check for open tag
    if source.starts_with("<?php") {
        tokens.push(PhpToken::new(TokenKind::OpenTag as u32, "<?php", line));
        pos = 5;
        if pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\n') {
            let start = pos;
            while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'\n' {
                pos += 1;
                line += 1;
            }
            if pos > start {
                tokens.push(PhpToken::new(
                    TokenKind::Whitespace as u32,
                    &source[start..pos],
                    line,
                ));
            }
        }
    }

    while pos < bytes.len() {
        let ch = bytes[pos];
        match ch {
            // Whitespace
            b' ' | b'\t' | b'\r' => {
                let start = pos;
                while pos < bytes.len()
                    && (bytes[pos] == b' ' || bytes[pos] == b'\t' || bytes[pos] == b'\r')
                {
                    pos += 1;
                }
                tokens.push(PhpToken::new(
                    TokenKind::Whitespace as u32,
                    &source[start..pos],
                    line,
                ));
            }
            b'\n' => {
                tokens.push(PhpToken::new(TokenKind::Whitespace as u32, "\n", line));
                pos += 1;
                line += 1;
            }
            // Variable
            b'$' => {
                let start = pos;
                pos += 1;
                while pos < bytes.len()
                    && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_')
                {
                    pos += 1;
                }
                tokens.push(PhpToken::new(
                    TokenKind::Variable as u32,
                    &source[start..pos],
                    line,
                ));
            }
            // Number
            b'0'..=b'9' => {
                let start = pos;
                let mut is_float = false;
                while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                if pos < bytes.len() && bytes[pos] == b'.' {
                    is_float = true;
                    pos += 1;
                    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                }
                let kind = if is_float {
                    TokenKind::DNumber as u32
                } else {
                    TokenKind::LNumber as u32
                };
                tokens.push(PhpToken::new(kind, &source[start..pos], line));
            }
            // String literal
            b'"' | b'\'' => {
                let quote = ch;
                let start = pos;
                pos += 1;
                while pos < bytes.len() && bytes[pos] != quote {
                    if bytes[pos] == b'\\' {
                        pos += 1;
                    }
                    if pos < bytes.len() && bytes[pos] == b'\n' {
                        line += 1;
                    }
                    pos += 1;
                }
                if pos < bytes.len() {
                    pos += 1; // closing quote
                }
                tokens.push(PhpToken::new(
                    TokenKind::ConstantEncapsedString as u32,
                    &source[start..pos],
                    line,
                ));
            }
            // Identifier or keyword
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = pos;
                while pos < bytes.len()
                    && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_')
                {
                    pos += 1;
                }
                let word = &source[start..pos];
                let kind = match word {
                    "if" => TokenKind::If as u32,
                    "else" => TokenKind::Else as u32,
                    "elseif" => TokenKind::ElseIf as u32,
                    "while" => TokenKind::While as u32,
                    "for" => TokenKind::For as u32,
                    "foreach" => TokenKind::ForEach as u32,
                    "return" => TokenKind::Return as u32,
                    "function" => TokenKind::Function as u32,
                    "class" => TokenKind::Class as u32,
                    "new" => TokenKind::New as u32,
                    "echo" => TokenKind::Echo as u32,
                    "print" => TokenKind::Print as u32,
                    "try" => TokenKind::Try as u32,
                    "catch" => TokenKind::Catch as u32,
                    "throw" => TokenKind::Throw as u32,
                    "match" => TokenKind::Match as u32,
                    "yield" => TokenKind::Yield as u32,
                    "include" => TokenKind::Include as u32,
                    "require" => TokenKind::Require as u32,
                    _ => TokenKind::String as u32,
                };
                tokens.push(PhpToken::new(kind, word, line));
            }
            // Single-character tokens (returned as-is)
            _ => {
                tokens.push(PhpToken::new(ch as u32, &source[pos..pos + 1], line));
                pos += 1;
            }
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_name() {
        assert_eq!(token_name(TokenKind::OpenTag as u32), "T_OPEN_TAG");
        assert_eq!(token_name(TokenKind::Variable as u32), "T_VARIABLE");
        assert_eq!(token_name(TokenKind::Echo as u32), "T_ECHO");
        assert_eq!(token_name(TokenKind::If as u32), "T_IF");
        assert_eq!(token_name(9999), "UNKNOWN");
    }

    #[test]
    fn test_token_get_all_simple() {
        let tokens = token_get_all("<?php echo 42;");
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].id, TokenKind::OpenTag as u32);
        assert_eq!(tokens[0].text, "<?php");
    }

    #[test]
    fn test_token_get_all_variable() {
        let tokens = token_get_all("<?php $x = 1;");
        let var_token = tokens.iter().find(|t| t.id == TokenKind::Variable as u32);
        assert!(var_token.is_some());
        assert_eq!(var_token.unwrap().text, "$x");
    }

    #[test]
    fn test_token_get_all_string() {
        let tokens = token_get_all("<?php echo \"hello\";");
        let str_token = tokens
            .iter()
            .find(|t| t.id == TokenKind::ConstantEncapsedString as u32);
        assert!(str_token.is_some());
        assert_eq!(str_token.unwrap().text, "\"hello\"");
    }

    #[test]
    fn test_token_get_all_keywords() {
        let tokens = token_get_all("<?php if ($x) { return 1; }");
        let if_token = tokens.iter().find(|t| t.id == TokenKind::If as u32);
        assert!(if_token.is_some());
        let ret_token = tokens.iter().find(|t| t.id == TokenKind::Return as u32);
        assert!(ret_token.is_some());
    }

    #[test]
    fn test_token_get_all_number() {
        let tokens = token_get_all("<?php 42 3.14");
        let int_token = tokens.iter().find(|t| t.id == TokenKind::LNumber as u32);
        assert_eq!(int_token.unwrap().text, "42");
        let float_token = tokens.iter().find(|t| t.id == TokenKind::DNumber as u32);
        assert_eq!(float_token.unwrap().text, "3.14");
    }

    #[test]
    fn test_php_token_struct() {
        let token = PhpToken::new(TokenKind::Echo as u32, "echo", 1);
        assert_eq!(token.id, 328);
        assert_eq!(token.text, "echo");
        assert_eq!(token.line, 1);
    }
}
