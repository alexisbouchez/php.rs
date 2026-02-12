//! PHP SimpleXML extension.
//!
//! Provides the SimpleXMLElement class and `simplexml_load_string()` /
//! `simplexml_load_file()` functions for easy XML access.
//!
//! The core implementation lives in `php-rs-ext-xml`; this crate re-exports it
//! and adds SimpleXML-specific convenience wrappers.
//! Reference: php-src/ext/simplexml/

// Re-export the SimpleXML types from the xml crate
pub use php_rs_ext_xml::simplexml_load_string;
pub use php_rs_ext_xml::SimpleXmlElement;

use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// simplexml_load_file() / simplexml_load_string() option: use CDATA.
pub const LIBXML_NOCDATA: i32 = 1 << 14;

// ---------------------------------------------------------------------------
// SimpleXmlError
// ---------------------------------------------------------------------------

/// An error from the SimpleXML extension.
#[derive(Debug, Clone, PartialEq)]
pub struct SimpleXmlError {
    pub message: String,
}

impl SimpleXmlError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for SimpleXmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimpleXML: {}", self.message)
    }
}

impl std::error::Error for SimpleXmlError {}

// ---------------------------------------------------------------------------
// SimpleXml iterator support
// ---------------------------------------------------------------------------

/// An iterator over child elements of a SimpleXMLElement, matching PHP's
/// `SimpleXMLElement::children()` when iterated.
pub struct SimpleXmlIterator<'a> {
    elements: &'a [SimpleXmlElement],
    index: usize,
}

impl<'a> SimpleXmlIterator<'a> {
    pub fn new(elements: &'a [SimpleXmlElement]) -> Self {
        Self { elements, index: 0 }
    }
}

impl<'a> Iterator for SimpleXmlIterator<'a> {
    type Item = &'a SimpleXmlElement;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.elements.len() {
            let elem = &self.elements[self.index];
            self.index += 1;
            Some(elem)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Load an XML file into a SimpleXMLElement.
/// This is a convenience wrapper that reads the file and calls `simplexml_load_string()`.
pub fn simplexml_load_file(path: &str) -> Result<SimpleXmlElement, SimpleXmlError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => simplexml_load_string(&contents)
            .ok_or_else(|| SimpleXmlError::new("Failed to parse XML")),
        Err(e) => Err(SimpleXmlError::new(&format!(
            "Failed to read file '{}': {}",
            path, e
        ))),
    }
}

/// Import a DOM node as a SimpleXMLElement.
/// Stub — returns None until DOM interop is fully wired.
pub fn simplexml_import_dom() -> Option<SimpleXmlElement> {
    None
}

// ---------------------------------------------------------------------------
// XPath wrapper
// ---------------------------------------------------------------------------

/// Holds the result of an XPath query on a SimpleXMLElement.
/// In PHP, `SimpleXMLElement::xpath()` returns an array of SimpleXMLElement.
#[derive(Debug, Clone)]
pub struct SimpleXmlXpathResult {
    pub elements: Vec<SimpleXmlElement>,
}

impl SimpleXmlXpathResult {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }
}

impl Default for SimpleXmlXpathResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_string_basic() {
        let xml = r#"<root><item>hello</item></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.name, "root");
        assert_eq!(elem.children().len(), 1);
        assert_eq!(elem.children()[0].name, "item");
    }

    #[test]
    fn test_iterator() {
        let xml = r#"<root><a/><b/><c/></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let names: Vec<&str> = SimpleXmlIterator::new(elem.children())
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_xpath_result_default() {
        let result = SimpleXmlXpathResult::new();
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_error_display() {
        let err = SimpleXmlError::new("parse failed");
        assert_eq!(format!("{}", err), "SimpleXML: parse failed");
    }

    #[test]
    fn test_load_file_missing() {
        let result = simplexml_load_file("/nonexistent/file.xml");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_dom_stub() {
        assert!(simplexml_import_dom().is_none());
    }

    #[test]
    fn test_get_child() {
        let xml = r#"<root><title>Test</title><body>Content</body></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let title = elem.get_child("title").unwrap();
        assert_eq!(title.to_string_value(), "Test");
    }

    #[test]
    fn test_attributes() {
        let xml = r#"<item id="42" type="book">data</item>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.get_attribute("id"), Some("42"));
        assert_eq!(elem.get_attribute("type"), Some("book"));
        assert_eq!(elem.get_attribute("missing"), None);
    }
}
