//! Source code span tracking
//!
//! Represents the location of a token in the source file with byte offsets,
//! line and column information.

/// Represents a location in the source code.
///
/// A span tracks both byte offsets (for efficient slicing) and human-readable
/// line/column numbers (for error messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// Byte offset from the start of the source (inclusive)
    pub start: usize,
    /// Byte offset from the start of the source (exclusive)
    pub end: usize,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed, counted in bytes)
    pub column: usize,
}

impl Span {
    /// Creates a new span.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting byte offset (inclusive)
    /// * `end` - Ending byte offset (exclusive)
    /// * `line` - Line number (1-indexed)
    /// * `column` - Column number (1-indexed)
    pub fn new(start: usize, end: usize, line: usize, column: usize) -> Self {
        Span {
            start,
            end,
            line,
            column,
        }
    }

    /// Returns the length of the span in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if the span is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Extracts the text covered by this span from the source code.
    pub fn extract<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }
}

impl Default for Span {
    fn default() -> Self {
        Span {
            start: 0,
            end: 0,
            line: 1,
            column: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let span = Span::new(0, 5, 1, 1);
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 5);
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
    }

    #[test]
    fn test_span_len() {
        let span = Span::new(10, 25, 2, 5);
        assert_eq!(span.len(), 15);
    }

    #[test]
    fn test_span_is_empty() {
        let empty_span = Span::new(10, 10, 1, 1);
        assert!(empty_span.is_empty());

        let non_empty_span = Span::new(10, 15, 1, 1);
        assert!(!non_empty_span.is_empty());
    }

    #[test]
    fn test_span_extract() {
        let source = "<?php echo 'hello';";
        let span = Span::new(6, 10, 1, 7); // "echo"
        assert_eq!(span.extract(source), "echo");
    }

    #[test]
    fn test_span_extract_multiline() {
        let source = "<?php\necho 'hello';\necho 'world';";
        let span = Span::new(6, 10, 2, 1); // "echo" on line 2
        assert_eq!(span.extract(source), "echo");
    }

    #[test]
    fn test_span_default() {
        let span = Span::default();
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 0);
        assert_eq!(span.line, 1);
        assert_eq!(span.column, 1);
        assert!(span.is_empty());
    }

    #[test]
    fn test_span_equality() {
        let span1 = Span::new(0, 5, 1, 1);
        let span2 = Span::new(0, 5, 1, 1);
        let span3 = Span::new(0, 6, 1, 1);

        assert_eq!(span1, span2);
        assert_ne!(span1, span3);
    }

    #[test]
    fn test_span_clone() {
        let span = Span::new(5, 10, 2, 3);
        let cloned = span.clone();
        assert_eq!(span, cloned);
    }

    #[test]
    fn test_span_debug() {
        let span = Span::new(0, 5, 1, 1);
        let debug_str = format!("{:?}", span);
        assert!(debug_str.contains("start"));
        assert!(debug_str.contains("end"));
        assert!(debug_str.contains("line"));
        assert!(debug_str.contains("column"));
    }

    #[test]
    fn test_span_different_lines() {
        let span1 = Span::new(0, 5, 1, 1);
        let span2 = Span::new(10, 15, 2, 1);
        let span3 = Span::new(20, 25, 3, 1);

        assert_ne!(span1, span2);
        assert_ne!(span2, span3);
        assert_eq!(span1.line, 1);
        assert_eq!(span2.line, 2);
        assert_eq!(span3.line, 3);
    }

    #[test]
    fn test_span_different_columns() {
        let span1 = Span::new(0, 5, 1, 1);
        let span2 = Span::new(5, 10, 1, 6);
        let span3 = Span::new(10, 15, 1, 11);

        assert_ne!(span1, span2);
        assert_ne!(span2, span3);
        assert_eq!(span1.column, 1);
        assert_eq!(span2.column, 6);
        assert_eq!(span3.column, 11);
    }

    #[test]
    fn test_span_roundtrip() {
        // Test that we can construct a Span and all fields are accessible
        let original = Span {
            start: 42,
            end: 100,
            line: 10,
            column: 15,
        };

        let reconstructed = Span::new(original.start, original.end, original.line, original.column);

        assert_eq!(original, reconstructed);
        assert_eq!(original.start, reconstructed.start);
        assert_eq!(original.end, reconstructed.end);
        assert_eq!(original.line, reconstructed.line);
        assert_eq!(original.column, reconstructed.column);
    }
}
