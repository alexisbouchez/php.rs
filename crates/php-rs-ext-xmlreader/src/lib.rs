//! PHP XMLReader extension.
//!
//! Provides the XMLReader class for pull-based XML parsing.
//! The core implementation lives in `php-rs-ext-xml`; this crate re-exports it
//! and adds XMLReader-specific wrappers.
//! Reference: php-src/ext/xmlreader/

// Re-export from the xml crate
pub use php_rs_ext_xml::XmlNodeType;
pub use php_rs_ext_xml::XmlReader;

use std::fmt;

// ---------------------------------------------------------------------------
// Constants — node type aliases matching PHP's XMLReader::* constants
// ---------------------------------------------------------------------------

pub const XML_READER_TYPE_NONE: i32 = 0;
pub const XML_READER_TYPE_ELEMENT: i32 = 1;
pub const XML_READER_TYPE_ATTRIBUTE: i32 = 2;
pub const XML_READER_TYPE_TEXT: i32 = 3;
pub const XML_READER_TYPE_CDATA: i32 = 4;
pub const XML_READER_TYPE_ENTITY_REFERENCE: i32 = 5;
pub const XML_READER_TYPE_ENTITY: i32 = 6;
pub const XML_READER_TYPE_PROCESSING_INSTRUCTION: i32 = 7;
pub const XML_READER_TYPE_COMMENT: i32 = 8;
pub const XML_READER_TYPE_DOCUMENT: i32 = 9;
pub const XML_READER_TYPE_DOCUMENT_TYPE: i32 = 10;
pub const XML_READER_TYPE_DOCUMENT_FRAGMENT: i32 = 11;
pub const XML_READER_TYPE_NOTATION: i32 = 12;
pub const XML_READER_TYPE_WHITESPACE: i32 = 13;
pub const XML_READER_TYPE_SIGNIFICANT_WHITESPACE: i32 = 14;
pub const XML_READER_TYPE_END_ELEMENT: i32 = 15;
pub const XML_READER_TYPE_END_ENTITY: i32 = 16;
pub const XML_READER_TYPE_XML_DECLARATION: i32 = 17;

// ---------------------------------------------------------------------------
// XMLReader parser properties (matching PHP's XMLReader::LOADDTD etc.)
// ---------------------------------------------------------------------------

pub const XML_READER_LOADDTD: i32 = 1;
pub const XML_READER_DEFAULTATTRS: i32 = 2;
pub const XML_READER_VALIDATE: i32 = 3;
pub const XML_READER_SUBST_ENTITIES: i32 = 4;

// ---------------------------------------------------------------------------
// XmlReaderError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct XmlReaderError {
    pub message: String,
}

impl XmlReaderError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for XmlReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XMLReader: {}", self.message)
    }
}

impl std::error::Error for XmlReaderError {}

// ---------------------------------------------------------------------------
// Convenience: open from file
// ---------------------------------------------------------------------------

/// Create an XMLReader from a file path, analogous to `XMLReader::open()`.
pub fn xmlreader_open(path: &str) -> Result<XmlReader, XmlReaderError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(XmlReader::from_string(&contents)),
        Err(e) => Err(XmlReaderError::new(&format!(
            "Unable to open source data: {}",
            e
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_from_string() {
        let mut reader = XmlReader::from_string("<root><child>text</child></root>");
        // Should be able to advance through nodes
        assert!(reader.read());
    }

    #[test]
    fn test_open_missing_file() {
        let result = xmlreader_open("/nonexistent/file.xml");
        assert!(result.is_err());
    }

    #[test]
    fn test_node_type_constants() {
        assert_eq!(XML_READER_TYPE_ELEMENT, 1);
        assert_eq!(XML_READER_TYPE_TEXT, 3);
        assert_eq!(XML_READER_TYPE_END_ELEMENT, 15);
    }

    #[test]
    fn test_reader_walk() {
        let xml = "<root><a>1</a><b>2</b></root>";
        let mut reader = XmlReader::from_string(xml);
        let mut element_count = 0;
        while reader.read() {
            if reader.node_type() == XmlNodeType::Element {
                element_count += 1;
            }
        }
        assert!(element_count >= 2); // at least <a> and <b>
    }

    #[test]
    fn test_error_display() {
        let err = XmlReaderError::new("parse error");
        assert_eq!(format!("{}", err), "XMLReader: parse error");
    }
}
