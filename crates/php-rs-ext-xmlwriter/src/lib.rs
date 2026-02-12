//! PHP XMLWriter extension.
//!
//! Provides the XMLWriter class for generating well-formed XML.
//! The core implementation lives in `php-rs-ext-xml`; this crate re-exports it
//! and adds XMLWriter-specific wrappers.
//! Reference: php-src/ext/xmlwriter/

// Re-export from the xml crate
pub use php_rs_ext_xml::XmlWriter;

use std::fmt;

// ---------------------------------------------------------------------------
// XmlWriterError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct XmlWriterError {
    pub message: String,
}

impl XmlWriterError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for XmlWriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XMLWriter: {}", self.message)
    }
}

impl std::error::Error for XmlWriterError {}

// ---------------------------------------------------------------------------
// Convenience constructors matching PHP's procedural API
// ---------------------------------------------------------------------------

/// Create a new XMLWriter that outputs to memory.
/// Corresponds to `xmlwriter_open_memory()`.
pub fn xmlwriter_open_memory() -> XmlWriter {
    XmlWriter::new()
}

/// Create a new XMLWriter that outputs to a URI (file path).
/// Corresponds to `xmlwriter_open_uri()`.
pub fn xmlwriter_open_uri(path: &str) -> Result<XmlWriterToFile, XmlWriterError> {
    Ok(XmlWriterToFile {
        writer: XmlWriter::new(),
        path: path.to_string(),
    })
}

// ---------------------------------------------------------------------------
// XmlWriterToFile — wraps XmlWriter with file output
// ---------------------------------------------------------------------------

/// An XMLWriter that flushes to a file on `end_document()`.
pub struct XmlWriterToFile {
    writer: XmlWriter,
    path: String,
}

impl XmlWriterToFile {
    /// Access the inner writer for element/attribute writing operations.
    pub fn writer(&mut self) -> &mut XmlWriter {
        &mut self.writer
    }

    /// Flush the generated XML to the file.
    pub fn flush(&self) -> Result<(), XmlWriterError> {
        std::fs::write(&self.path, self.writer.output())
            .map_err(|e| XmlWriterError::new(&format!("Failed to write to '{}': {}", self.path, e)))
    }

    /// Get the current output as a string (for inspection before flushing).
    pub fn get_output(&self) -> &str {
        self.writer.output()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let mut w = xmlwriter_open_memory();
        w.start_document("1.0", Some("UTF-8"), None);
        w.start_element("root");
        w.write_element("child", "value");
        w.end_element();
        w.end_document();
        let output = w.output();
        assert!(output.contains("<root>"));
        assert!(output.contains("<child>value</child>"));
        assert!(output.contains("</root>"));
    }

    #[test]
    fn test_open_uri() {
        let result = xmlwriter_open_uri("/tmp/test_xmlwriter.xml");
        assert!(result.is_ok());
    }

    #[test]
    fn test_writer_to_file_output_memory() {
        let mut wf = xmlwriter_open_uri("/tmp/test_xmlwriter2.xml").unwrap();
        wf.writer().start_element("test");
        wf.writer().end_element();
        let output = wf.get_output();
        assert!(output.contains("<test"));
    }

    #[test]
    fn test_error_display() {
        let err = XmlWriterError::new("write failed");
        assert_eq!(format!("{}", err), "XMLWriter: write failed");
    }

    #[test]
    fn test_xmlwriter_attributes() {
        let mut w = xmlwriter_open_memory();
        w.start_element("item");
        w.write_attribute("id", "42");
        w.end_element();
        let output = w.output();
        assert!(output.contains("id=\"42\""));
    }
}
