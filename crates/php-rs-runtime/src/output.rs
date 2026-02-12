//! PHP output buffering system.
//!
//! Implements ob_start(), ob_end_flush(), ob_get_contents(), nested buffers,
//! and implicit flush mode.
//!
//! Reference: php-src/main/output.c, php-src/main/output.h

/// Callback type for output buffer handlers (e.g., ob_gzhandler).
pub type OutputCallback = Box<dyn Fn(&str) -> String>;

/// A single output buffer level.
struct BufferLevel {
    /// Accumulated output for this level.
    contents: String,
    /// Optional handler callback.
    handler: Option<OutputCallback>,
    /// Name of this buffer (e.g., "default output handler").
    name: String,
}

impl BufferLevel {
    fn new(name: impl Into<String>, handler: Option<OutputCallback>) -> Self {
        Self {
            contents: String::new(),
            handler,
            name: name.into(),
        }
    }

    /// Flush this buffer through its handler (if any) and return the output.
    fn flush(&mut self) -> String {
        let contents = std::mem::take(&mut self.contents);
        match &self.handler {
            Some(handler) => handler(&contents),
            None => contents,
        }
    }
}

/// The output buffering system.
///
/// Manages a stack of output buffers. When no buffers are active,
/// output goes directly to the final output sink.
pub struct OutputBuffer {
    /// Stack of buffer levels (outermost first).
    stack: Vec<BufferLevel>,
    /// Final output (what would be sent to the client).
    final_output: String,
    /// Whether implicit flush is enabled (flush after every output).
    implicit_flush: bool,
}

impl OutputBuffer {
    /// Create a new output buffering system.
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            final_output: String::new(),
            implicit_flush: false,
        }
    }

    /// Start a new output buffer level (ob_start).
    pub fn start(&mut self, handler: Option<OutputCallback>) {
        self.stack
            .push(BufferLevel::new("default output handler", handler));
    }

    /// Start a named output buffer level.
    pub fn start_named(&mut self, name: impl Into<String>, handler: Option<OutputCallback>) {
        self.stack.push(BufferLevel::new(name, handler));
    }

    /// Write output. Goes to the topmost buffer, or final output if none.
    pub fn write(&mut self, data: &str) {
        if let Some(level) = self.stack.last_mut() {
            level.contents.push_str(data);
        } else {
            self.final_output.push_str(data);
        }

        if self.implicit_flush && self.stack.is_empty() {
            // In implicit flush mode with no buffers, output is immediate
            // (already written to final_output above)
        }
    }

    /// Get the contents of the current buffer (ob_get_contents).
    /// Returns None if no buffer is active.
    pub fn get_contents(&self) -> Option<&str> {
        self.stack.last().map(|level| level.contents.as_str())
    }

    /// Get the length of the current buffer (ob_get_length).
    /// Returns None if no buffer is active.
    pub fn get_length(&self) -> Option<usize> {
        self.stack.last().map(|level| level.contents.len())
    }

    /// Get the nesting level (ob_get_level).
    pub fn get_level(&self) -> usize {
        self.stack.len()
    }

    /// Flush the current buffer to the next level and keep it active (ob_flush).
    /// Returns false if no buffer is active.
    pub fn flush(&mut self) -> bool {
        let len = self.stack.len();
        if len == 0 {
            return false;
        }

        let output = self.stack[len - 1].flush();

        if len >= 2 {
            // Flush to the next buffer level
            self.stack[len - 2].contents.push_str(&output);
        } else {
            // Flush to final output
            self.final_output.push_str(&output);
        }
        true
    }

    /// End the current buffer and flush it to the next level (ob_end_flush).
    /// Returns false if no buffer is active.
    pub fn end_flush(&mut self) -> bool {
        if self.stack.is_empty() {
            return false;
        }

        let mut level = self.stack.pop().unwrap();
        let output = level.flush();

        if let Some(parent) = self.stack.last_mut() {
            parent.contents.push_str(&output);
        } else {
            self.final_output.push_str(&output);
        }
        true
    }

    /// End the current buffer and discard its contents (ob_end_clean).
    /// Returns false if no buffer is active.
    pub fn end_clean(&mut self) -> bool {
        self.stack.pop().is_some()
    }

    /// Get contents and end the buffer (ob_get_clean).
    /// Returns None if no buffer is active.
    pub fn get_clean(&mut self) -> Option<String> {
        self.stack.pop().map(|level| level.contents)
    }

    /// Get contents and flush the buffer (ob_get_flush).
    /// Returns None if no buffer is active.
    pub fn get_flush(&mut self) -> Option<String> {
        if self.stack.is_empty() {
            return None;
        }

        let mut level = self.stack.pop().unwrap();
        let contents = level.contents.clone();
        let output = level.flush();

        if let Some(parent) = self.stack.last_mut() {
            parent.contents.push_str(&output);
        } else {
            self.final_output.push_str(&output);
        }

        Some(contents)
    }

    /// Flush all buffer levels to final output (called at request end).
    pub fn flush_all(&mut self) {
        while !self.stack.is_empty() {
            self.end_flush();
        }
    }

    /// Clean (discard) all buffer levels.
    pub fn clean_all(&mut self) {
        self.stack.clear();
    }

    /// Get list of active buffer handler names (ob_list_handlers).
    pub fn list_handlers(&self) -> Vec<&str> {
        self.stack.iter().map(|l| l.name.as_str()).collect()
    }

    /// Set implicit flush mode.
    pub fn set_implicit_flush(&mut self, enabled: bool) {
        self.implicit_flush = enabled;
    }

    /// Get the accumulated final output.
    pub fn final_output(&self) -> &str {
        &self.final_output
    }

    /// Take the final output (consuming it).
    pub fn take_final_output(&mut self) -> String {
        std::mem::take(&mut self.final_output)
    }

    /// Reset the entire output system.
    pub fn reset(&mut self) {
        self.stack.clear();
        self.final_output.clear();
        self.implicit_flush = false;
    }
}

impl Default for OutputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_buffer_direct_output() {
        let mut ob = OutputBuffer::new();
        ob.write("Hello, World!");
        assert_eq!(ob.final_output(), "Hello, World!");
        assert_eq!(ob.get_level(), 0);
    }

    #[test]
    fn test_basic_buffering() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("buffered");
        assert_eq!(ob.get_contents(), Some("buffered"));
        assert_eq!(ob.get_length(), Some(8));
        assert_eq!(ob.get_level(), 1);
        assert_eq!(ob.final_output(), "");

        ob.end_flush();
        assert_eq!(ob.final_output(), "buffered");
        assert_eq!(ob.get_level(), 0);
    }

    #[test]
    fn test_nested_buffers() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("outer ");
        ob.start(None);
        ob.write("inner");
        assert_eq!(ob.get_level(), 2);

        // Flush inner to outer
        ob.end_flush();
        assert_eq!(ob.get_level(), 1);
        assert_eq!(ob.get_contents(), Some("outer inner"));

        // Flush outer to final
        ob.end_flush();
        assert_eq!(ob.final_output(), "outer inner");
    }

    #[test]
    fn test_end_clean() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("discarded");
        assert!(ob.end_clean());
        assert_eq!(ob.final_output(), "");
        assert_eq!(ob.get_level(), 0);
    }

    #[test]
    fn test_get_clean() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("captured");
        let contents = ob.get_clean();
        assert_eq!(contents, Some("captured".to_string()));
        assert_eq!(ob.get_level(), 0);
        assert_eq!(ob.final_output(), "");
    }

    #[test]
    fn test_flush_keeps_buffer_active() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("first ");
        ob.flush();
        assert_eq!(ob.get_level(), 1); // Still active
        assert_eq!(ob.get_contents(), Some("")); // Cleared
        assert_eq!(ob.final_output(), "first ");

        ob.write("second");
        ob.end_flush();
        assert_eq!(ob.final_output(), "first second");
    }

    #[test]
    fn test_handler_callback() {
        let mut ob = OutputBuffer::new();
        ob.start(Some(Box::new(|s: &str| s.to_uppercase())));
        ob.write("hello");
        ob.end_flush();
        assert_eq!(ob.final_output(), "HELLO");
    }

    #[test]
    fn test_flush_all() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("level1 ");
        ob.start(None);
        ob.write("level2");

        ob.flush_all();
        assert_eq!(ob.get_level(), 0);
        assert_eq!(ob.final_output(), "level1 level2");
    }

    #[test]
    fn test_list_handlers() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.start_named("ob_gzhandler", None);
        let handlers = ob.list_handlers();
        assert_eq!(handlers, vec!["default output handler", "ob_gzhandler"]);
    }

    #[test]
    fn test_no_buffer_operations_return_false() {
        let mut ob = OutputBuffer::new();
        assert!(!ob.flush());
        assert!(!ob.end_flush());
        assert!(!ob.end_clean());
        assert!(ob.get_clean().is_none());
        assert!(ob.get_contents().is_none());
        assert!(ob.get_length().is_none());
    }

    #[test]
    fn test_get_flush() {
        let mut ob = OutputBuffer::new();
        ob.start(None);
        ob.write("data");
        let contents = ob.get_flush();
        assert_eq!(contents, Some("data".to_string()));
        assert_eq!(ob.get_level(), 0);
        assert_eq!(ob.final_output(), "data");
    }

    #[test]
    fn test_take_final_output() {
        let mut ob = OutputBuffer::new();
        ob.write("output");
        let taken = ob.take_final_output();
        assert_eq!(taken, "output");
        assert_eq!(ob.final_output(), "");
    }
}
