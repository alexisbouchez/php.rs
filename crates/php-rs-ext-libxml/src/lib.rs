//! PHP libxml extension — base XML library used by DOM, SimpleXML, XMLReader, XMLWriter.
//!
//! Provides shared error handling, entity loading control, and XML parsing configuration
//! that all other XML extensions depend on.
//! Reference: php-src/ext/libxml/

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants — libxml error levels
// ---------------------------------------------------------------------------

/// No errors.
pub const LIBXML_ERR_NONE: i32 = 0;
/// A simple warning.
pub const LIBXML_ERR_WARNING: i32 = 1;
/// A recoverable error.
pub const LIBXML_ERR_ERROR: i32 = 2;
/// A fatal error.
pub const LIBXML_ERR_FATAL: i32 = 3;

// ---------------------------------------------------------------------------
// Constants — libxml parser options (bitmask)
// ---------------------------------------------------------------------------

/// Substitute entities.
pub const LIBXML_NOENT: i32 = 1 << 1;
/// Load the external subset.
pub const LIBXML_DTDLOAD: i32 = 1 << 2;
/// Default DTD attributes.
pub const LIBXML_DTDATTR: i32 = 1 << 3;
/// Validate with the DTD.
pub const LIBXML_DTDVALID: i32 = 1 << 4;
/// Suppress error reports.
pub const LIBXML_NOERROR: i32 = 1 << 5;
/// Suppress warning reports.
pub const LIBXML_NOWARNING: i32 = 1 << 6;
/// Remove blank nodes.
pub const LIBXML_NOBLANKS: i32 = 1 << 8;
/// Enable XInclude substitution.
pub const LIBXML_XINCLUDE: i32 = 1 << 10;
/// Remove redundant namespace declarations.
pub const LIBXML_NSCLEAN: i32 = 1 << 13;
/// Merge CDATA as text nodes.
pub const LIBXML_NOCDATA: i32 = 1 << 14;
/// Compact small text nodes (optimization).
pub const LIBXML_COMPACT: i32 = 1 << 16;
/// Forbid network access.
pub const LIBXML_NONET: i32 = 1 << 11;
/// Relax any hardcoded limit from the parser.
pub const LIBXML_PARSEHUGE: i32 = 1 << 19;
/// Big lines numbers support.
pub const LIBXML_BIGLINES: i32 = 1 << 22;

/// Version constant matching PHP's LIBXML_VERSION.
pub const LIBXML_VERSION: i32 = 21200;
/// Dotted version string.
pub const LIBXML_DOTTED_VERSION: &str = "2.12.0";

// ---------------------------------------------------------------------------
// LibXmlError — structured error information
// ---------------------------------------------------------------------------

/// A structured error from the XML parser, matching PHP's libXMLError class.
#[derive(Debug, Clone, PartialEq)]
pub struct LibXmlError {
    /// Error severity level (LIBXML_ERR_*).
    pub level: i32,
    /// The error's code.
    pub code: i32,
    /// The column where the error occurred.
    pub column: i32,
    /// The error message.
    pub message: String,
    /// The filename (or empty if parsing from string).
    pub file: String,
    /// The line number where the error occurred.
    pub line: i32,
}

impl LibXmlError {
    pub fn new(level: i32, code: i32, message: &str) -> Self {
        Self {
            level,
            code,
            column: 0,
            message: message.to_string(),
            file: String::new(),
            line: 0,
        }
    }

    pub fn with_position(mut self, line: i32, column: i32) -> Self {
        self.line = line;
        self.column = column;
        self
    }

    pub fn with_file(mut self, file: &str) -> Self {
        self.file = file.to_string();
        self
    }
}

impl fmt::Display for LibXmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LibXmlError {}

// ---------------------------------------------------------------------------
// LibXmlErrorBuffer — thread-local error collection
// ---------------------------------------------------------------------------

/// Collects XML errors for retrieval by `libxml_get_errors()` / `libxml_get_last_error()`.
#[derive(Debug, Clone, Default)]
pub struct LibXmlErrorBuffer {
    errors: Vec<LibXmlError>,
    use_internal_errors: bool,
}

impl LibXmlErrorBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable internal error handling (like PHP's `libxml_use_internal_errors()`).
    /// Returns the previous setting.
    pub fn use_internal_errors(&mut self, enable: bool) -> bool {
        let prev = self.use_internal_errors;
        self.use_internal_errors = enable;
        prev
    }

    /// Whether internal errors mode is active.
    pub fn is_internal_errors(&self) -> bool {
        self.use_internal_errors
    }

    /// Push an error if internal error handling is enabled.
    pub fn push_error(&mut self, error: LibXmlError) {
        if self.use_internal_errors {
            self.errors.push(error);
        }
    }

    /// Get all accumulated errors (like PHP's `libxml_get_errors()`).
    pub fn get_errors(&self) -> &[LibXmlError] {
        &self.errors
    }

    /// Get the last error (like PHP's `libxml_get_last_error()`).
    pub fn get_last_error(&self) -> Option<&LibXmlError> {
        self.errors.last()
    }

    /// Clear all accumulated errors (like PHP's `libxml_clear_errors()`).
    pub fn clear_errors(&mut self) {
        self.errors.clear();
    }
}

// ---------------------------------------------------------------------------
// LibXmlStreamContext — entity loader configuration
// ---------------------------------------------------------------------------

/// Controls how external entities are loaded.
#[derive(Debug, Clone, Default)]
pub struct LibXmlStreamContext {
    /// Stream context options (e.g., HTTP headers for remote DTD fetching).
    pub options: HashMap<String, HashMap<String, String>>,
}

impl LibXmlStreamContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_option(&mut self, wrapper: &str, key: &str, value: &str) {
        self.options
            .entry(wrapper.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    pub fn get_option(&self, wrapper: &str, key: &str) -> Option<&str> {
        self.options
            .get(wrapper)
            .and_then(|m| m.get(key))
            .map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// Entity loader control
// ---------------------------------------------------------------------------

/// Whether to disable external entity loading (security measure).
/// Mirrors PHP's `libxml_disable_entity_loader()` (deprecated in PHP 8.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityLoaderPolicy {
    /// Allow loading external entities (default pre-PHP 8.0).
    Allow,
    /// Disallow loading external entities.
    Disallow,
}

impl Default for EntityLoaderPolicy {
    fn default() -> Self {
        // PHP 8.0+ defaults to disallowing external entity loading
        Self::Disallow
    }
}

// ---------------------------------------------------------------------------
// Utility: check if XML is well-formed
// ---------------------------------------------------------------------------

/// Quick well-formedness check on an XML string.
/// Returns Ok(()) if well-formed, or Err with a descriptive error.
pub fn check_well_formed(xml: &str) -> Result<(), LibXmlError> {
    let xml = xml.trim();
    if xml.is_empty() {
        return Err(LibXmlError::new(
            LIBXML_ERR_FATAL,
            1,
            "Empty string supplied as input",
        ));
    }

    // Simple nesting validation
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0;
    let bytes = xml.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            // Skip processing instructions, declarations, comments
            if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                // Processing instruction — skip to ?>
                if let Some(end) = xml[i..].find("?>") {
                    i += end + 2;
                    continue;
                }
                return Err(LibXmlError::new(
                    LIBXML_ERR_FATAL,
                    76,
                    "Unterminated processing instruction",
                ));
            }
            if xml[i..].starts_with("<!--") {
                if let Some(end) = xml[i..].find("-->") {
                    i += end + 3;
                    continue;
                }
                return Err(LibXmlError::new(
                    LIBXML_ERR_FATAL,
                    45,
                    "Unterminated comment",
                ));
            }
            if xml[i..].starts_with("<!") {
                // DOCTYPE or CDATA
                if let Some(end) = xml[i..].find('>') {
                    i += end + 1;
                    continue;
                }
                return Err(LibXmlError::new(
                    LIBXML_ERR_FATAL,
                    73,
                    "Unterminated markup declaration",
                ));
            }

            // Regular tag
            let tag_start = i + 1;
            if let Some(end_offset) = xml[i..].find('>') {
                let tag_content = &xml[tag_start..i + end_offset];
                let is_closing = tag_content.starts_with('/');
                let is_self_closing = tag_content.ends_with('/');

                let tag_name = if is_closing {
                    tag_content[1..].split_whitespace().next().unwrap_or("")
                } else {
                    tag_content
                        .split(|c: char| c.is_whitespace() || c == '/')
                        .next()
                        .unwrap_or("")
                };

                if !tag_name.is_empty() {
                    if is_closing {
                        if let Some(open) = stack.pop() {
                            if open != tag_name {
                                return Err(LibXmlError::new(
                                    LIBXML_ERR_FATAL,
                                    76,
                                    &format!(
                                        "Opening and ending tag mismatch: {} and {}",
                                        open, tag_name
                                    ),
                                ));
                            }
                        } else {
                            return Err(LibXmlError::new(
                                LIBXML_ERR_FATAL,
                                76,
                                &format!("Unexpected closing tag: {}", tag_name),
                            ));
                        }
                    } else if !is_self_closing {
                        stack.push(tag_name.to_string());
                    }
                }

                i += end_offset + 1;
            } else {
                return Err(LibXmlError::new(LIBXML_ERR_FATAL, 73, "Unterminated tag"));
            }
        } else {
            i += 1;
        }
    }

    if !stack.is_empty() {
        return Err(LibXmlError::new(
            LIBXML_ERR_FATAL,
            76,
            &format!(
                "Premature end of data, unclosed tag: {}",
                stack.last().unwrap()
            ),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_buffer_basic() {
        let mut buf = LibXmlErrorBuffer::new();
        assert!(!buf.is_internal_errors());

        // Errors are not collected when internal errors are disabled
        buf.push_error(LibXmlError::new(LIBXML_ERR_WARNING, 1, "test warning"));
        assert!(buf.get_errors().is_empty());

        // Enable internal errors
        let prev = buf.use_internal_errors(true);
        assert!(!prev);
        assert!(buf.is_internal_errors());

        buf.push_error(LibXmlError::new(LIBXML_ERR_WARNING, 1, "test warning"));
        buf.push_error(LibXmlError::new(LIBXML_ERR_ERROR, 2, "test error"));
        assert_eq!(buf.get_errors().len(), 2);

        let last = buf.get_last_error().unwrap();
        assert_eq!(last.level, LIBXML_ERR_ERROR);
        assert_eq!(last.message, "test error");

        buf.clear_errors();
        assert!(buf.get_errors().is_empty());
    }

    #[test]
    fn test_error_with_position() {
        let err = LibXmlError::new(LIBXML_ERR_FATAL, 76, "tag mismatch")
            .with_position(10, 5)
            .with_file("test.xml");
        assert_eq!(err.line, 10);
        assert_eq!(err.column, 5);
        assert_eq!(err.file, "test.xml");
    }

    #[test]
    fn test_stream_context() {
        let mut ctx = LibXmlStreamContext::new();
        ctx.set_option("http", "header", "Authorization: Bearer abc");
        assert_eq!(
            ctx.get_option("http", "header"),
            Some("Authorization: Bearer abc")
        );
        assert_eq!(ctx.get_option("http", "missing"), None);
        assert_eq!(ctx.get_option("ftp", "header"), None);
    }

    #[test]
    fn test_entity_loader_default() {
        let policy = EntityLoaderPolicy::default();
        assert_eq!(policy, EntityLoaderPolicy::Disallow);
    }

    #[test]
    fn test_well_formed_valid() {
        assert!(check_well_formed("<root><child/></root>").is_ok());
        assert!(check_well_formed("<?xml version=\"1.0\"?><root/>").is_ok());
        assert!(check_well_formed("<a><b><c/></b></a>").is_ok());
        assert!(check_well_formed("<!-- comment --><root/>").is_ok());
    }

    #[test]
    fn test_well_formed_invalid() {
        assert!(check_well_formed("").is_err());
        assert!(check_well_formed("<a><b></a>").is_err());
        assert!(check_well_formed("<a>").is_err());
        assert!(check_well_formed("</a>").is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(LIBXML_ERR_NONE, 0);
        assert_eq!(LIBXML_ERR_WARNING, 1);
        assert_eq!(LIBXML_ERR_ERROR, 2);
        assert_eq!(LIBXML_ERR_FATAL, 3);
        assert_eq!(LIBXML_NOENT, 2);
        assert_eq!(LIBXML_NOBLANKS, 256);
    }

    #[test]
    fn test_parser_options_bitmask() {
        let opts = LIBXML_NOENT | LIBXML_NOBLANKS | LIBXML_NONET;
        assert!(opts & LIBXML_NOENT != 0);
        assert!(opts & LIBXML_NOBLANKS != 0);
        assert!(opts & LIBXML_NONET != 0);
        assert!(opts & LIBXML_DTDLOAD == 0);
    }

    #[test]
    fn test_well_formed_comment() {
        assert!(check_well_formed("<!-- test --><root/>").is_ok());
    }

    #[test]
    fn test_well_formed_self_closing() {
        assert!(check_well_formed("<br/>").is_ok());
        assert!(check_well_formed("<img src=\"x\"/>").is_ok());
    }
}
