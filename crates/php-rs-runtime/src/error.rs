//! PHP error handling system.
//!
//! Implements error levels (E_ERROR, E_WARNING, etc.), custom error handlers,
//! and the @ error suppression operator.
//!
//! Reference: php-src/main/main.c, php-src/Zend/zend_errors.h

use std::fmt;

/// PHP error levels (bitmask).
///
/// Reference: php-src/Zend/zend_errors.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorLevel {
    /// Fatal error — execution cannot continue.
    Error = 1, // E_ERROR
    /// Non-fatal warning — execution continues.
    Warning = 2, // E_WARNING
    /// Parser error.
    Parse = 4, // E_PARSE
    /// Informational notice.
    Notice = 8, // E_NOTICE
    /// Fatal error triggered by the core.
    CoreError = 16, // E_CORE_ERROR
    /// Warning triggered by the core.
    CoreWarning = 32, // E_CORE_WARNING
    /// Fatal error during compilation.
    CompileError = 64, // E_COMPILE_ERROR
    /// Warning during compilation.
    CompileWarning = 128, // E_COMPILE_WARNING
    /// User-triggered error (trigger_error).
    UserError = 256, // E_USER_ERROR
    /// User-triggered warning.
    UserWarning = 512, // E_USER_WARNING
    /// User-triggered notice.
    UserNotice = 1024, // E_USER_NOTICE
    /// Coding standards suggestion.
    Strict = 2048, // E_STRICT
    /// Catchable fatal error.
    RecoverableError = 4096, // E_RECOVERABLE_ERROR
    /// Feature deprecation notice.
    Deprecated = 8192, // E_DEPRECATED
    /// User-triggered deprecation.
    UserDeprecated = 16384, // E_USER_DEPRECATED
}

impl ErrorLevel {
    /// E_ALL constant — all error levels combined.
    pub const ALL: u32 = 32767;

    /// Get the bitmask value.
    pub fn mask(self) -> u32 {
        self as u32
    }

    /// Check if this level is fatal (stops execution).
    pub fn is_fatal(self) -> bool {
        matches!(
            self,
            ErrorLevel::Error
                | ErrorLevel::CoreError
                | ErrorLevel::CompileError
                | ErrorLevel::UserError
        )
    }

    /// Get the PHP name for this error level (e.g., "E_WARNING").
    pub fn name(self) -> &'static str {
        match self {
            ErrorLevel::Error => "E_ERROR",
            ErrorLevel::Warning => "E_WARNING",
            ErrorLevel::Parse => "E_PARSE",
            ErrorLevel::Notice => "E_NOTICE",
            ErrorLevel::CoreError => "E_CORE_ERROR",
            ErrorLevel::CoreWarning => "E_CORE_WARNING",
            ErrorLevel::CompileError => "E_COMPILE_ERROR",
            ErrorLevel::CompileWarning => "E_COMPILE_WARNING",
            ErrorLevel::UserError => "E_USER_ERROR",
            ErrorLevel::UserWarning => "E_USER_WARNING",
            ErrorLevel::UserNotice => "E_USER_NOTICE",
            ErrorLevel::Strict => "E_STRICT",
            ErrorLevel::RecoverableError => "E_RECOVERABLE_ERROR",
            ErrorLevel::Deprecated => "E_DEPRECATED",
            ErrorLevel::UserDeprecated => "E_USER_DEPRECATED",
        }
    }

    /// Get the PHP label (for error messages, e.g., "Warning", "Fatal error").
    pub fn label(self) -> &'static str {
        match self {
            ErrorLevel::Error | ErrorLevel::CoreError | ErrorLevel::CompileError => "Fatal error",
            ErrorLevel::UserError => "Fatal error",
            ErrorLevel::Warning
            | ErrorLevel::CoreWarning
            | ErrorLevel::CompileWarning
            | ErrorLevel::UserWarning => "Warning",
            ErrorLevel::Parse => "Parse error",
            ErrorLevel::Notice | ErrorLevel::UserNotice => "Notice",
            ErrorLevel::Strict => "Strict Standards",
            ErrorLevel::RecoverableError => "Catchable fatal error",
            ErrorLevel::Deprecated | ErrorLevel::UserDeprecated => "Deprecated",
        }
    }

    /// Try to convert a u32 to an ErrorLevel.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(ErrorLevel::Error),
            2 => Some(ErrorLevel::Warning),
            4 => Some(ErrorLevel::Parse),
            8 => Some(ErrorLevel::Notice),
            16 => Some(ErrorLevel::CoreError),
            32 => Some(ErrorLevel::CoreWarning),
            64 => Some(ErrorLevel::CompileError),
            128 => Some(ErrorLevel::CompileWarning),
            256 => Some(ErrorLevel::UserError),
            512 => Some(ErrorLevel::UserWarning),
            1024 => Some(ErrorLevel::UserNotice),
            2048 => Some(ErrorLevel::Strict),
            4096 => Some(ErrorLevel::RecoverableError),
            8192 => Some(ErrorLevel::Deprecated),
            16384 => Some(ErrorLevel::UserDeprecated),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A PHP error with level, message, and location.
#[derive(Debug, Clone)]
pub struct PhpError {
    /// Error level.
    pub level: ErrorLevel,
    /// Error message.
    pub message: String,
    /// File where the error occurred.
    pub file: Option<String>,
    /// Line number.
    pub line: Option<u32>,
}

impl PhpError {
    /// Create a new error.
    pub fn new(level: ErrorLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            file: None,
            line: None,
        }
    }

    /// Set the file location.
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set the line number.
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Format as PHP would display it.
    pub fn format(&self) -> String {
        let location = match (&self.file, self.line) {
            (Some(f), Some(l)) => format!(" in {} on line {}", f, l),
            (Some(f), None) => format!(" in {}", f),
            _ => String::new(),
        };
        format!("{}: {}{}", self.level.label(), self.message, location)
    }
}

impl fmt::Display for PhpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Custom error/exception handler callback type.
pub type ErrorCallback = Box<dyn Fn(&PhpError) -> bool>;
pub type ExceptionCallback = Box<dyn Fn(&str)>;

/// The error handling subsystem.
///
/// Manages error_reporting level, custom error/exception handlers,
/// and the @ silence operator.
pub struct ErrorHandler {
    /// Current error_reporting bitmask (which levels to report).
    error_reporting: u32,
    /// Stack of saved error_reporting levels (for @ operator).
    silence_stack: Vec<u32>,
    /// Custom error handler (set via set_error_handler).
    custom_handler: Option<ErrorCallback>,
    /// Custom exception handler (set via set_exception_handler).
    exception_handler: Option<ExceptionCallback>,
    /// Collected errors (for testing/inspection).
    errors: Vec<PhpError>,
}

impl ErrorHandler {
    /// Create a new error handler with default settings (E_ALL).
    pub fn new() -> Self {
        Self {
            error_reporting: ErrorLevel::ALL,
            silence_stack: Vec::new(),
            custom_handler: None,
            exception_handler: None,
            errors: Vec::new(),
        }
    }

    /// Get the current error_reporting level.
    pub fn error_reporting(&self) -> u32 {
        self.error_reporting
    }

    /// Set the error_reporting level. Returns the previous value.
    pub fn set_error_reporting(&mut self, level: u32) -> u32 {
        let old = self.error_reporting;
        self.error_reporting = level;
        old
    }

    /// Set a custom error handler. Returns the previous one (if any).
    pub fn set_error_handler(&mut self, handler: Option<ErrorCallback>) -> Option<ErrorCallback> {
        std::mem::replace(&mut self.custom_handler, handler)
    }

    /// Set a custom exception handler. Returns the previous one (if any).
    pub fn set_exception_handler(
        &mut self,
        handler: Option<ExceptionCallback>,
    ) -> Option<ExceptionCallback> {
        std::mem::replace(&mut self.exception_handler, handler)
    }

    /// Begin error suppression (@ operator). Saves current level and sets to 0.
    pub fn begin_silence(&mut self) {
        self.silence_stack.push(self.error_reporting);
        self.error_reporting = 0;
    }

    /// End error suppression (@ operator). Restores previous level.
    pub fn end_silence(&mut self) {
        if let Some(level) = self.silence_stack.pop() {
            self.error_reporting = level;
        }
    }

    /// Check if errors are currently suppressed (@ operator active).
    pub fn is_silenced(&self) -> bool {
        !self.silence_stack.is_empty()
    }

    /// Handle an error. Returns true if the error was handled (not fatal).
    pub fn handle_error(&mut self, error: PhpError) -> bool {
        // Check if this error level is reported
        if error.level.mask() & self.error_reporting == 0 {
            return true; // Suppressed
        }

        // Try custom handler first
        if let Some(ref handler) = self.custom_handler {
            if handler(&error) {
                return !error.level.is_fatal();
            }
        }

        // Store the error
        let is_fatal = error.level.is_fatal();
        self.errors.push(error);

        !is_fatal
    }

    /// Handle an uncaught exception.
    pub fn handle_exception(&self, message: &str) {
        if let Some(ref handler) = self.exception_handler {
            handler(message);
        }
    }

    /// Get all collected errors.
    pub fn errors(&self) -> &[PhpError] {
        &self.errors
    }

    /// Get the last error (if any).
    pub fn last_error(&self) -> Option<&PhpError> {
        self.errors.last()
    }

    /// Clear all collected errors.
    pub fn clear_errors(&mut self) {
        self.errors.clear();
    }

    /// Reset to default state.
    pub fn reset(&mut self) {
        self.error_reporting = ErrorLevel::ALL;
        self.silence_stack.clear();
        self.custom_handler = None;
        self.exception_handler = None;
        self.errors.clear();
    }
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_level_values() {
        assert_eq!(ErrorLevel::Error.mask(), 1);
        assert_eq!(ErrorLevel::Warning.mask(), 2);
        assert_eq!(ErrorLevel::Notice.mask(), 8);
        assert_eq!(ErrorLevel::Deprecated.mask(), 8192);
        assert_eq!(ErrorLevel::ALL, 32767);
    }

    #[test]
    fn test_error_level_is_fatal() {
        assert!(ErrorLevel::Error.is_fatal());
        assert!(ErrorLevel::CoreError.is_fatal());
        assert!(ErrorLevel::CompileError.is_fatal());
        assert!(ErrorLevel::UserError.is_fatal());
        assert!(!ErrorLevel::Warning.is_fatal());
        assert!(!ErrorLevel::Notice.is_fatal());
        assert!(!ErrorLevel::Deprecated.is_fatal());
    }

    #[test]
    fn test_error_level_names() {
        assert_eq!(ErrorLevel::Error.name(), "E_ERROR");
        assert_eq!(ErrorLevel::Warning.name(), "E_WARNING");
        assert_eq!(ErrorLevel::Warning.label(), "Warning");
        assert_eq!(ErrorLevel::Error.label(), "Fatal error");
        assert_eq!(ErrorLevel::Deprecated.label(), "Deprecated");
    }

    #[test]
    fn test_php_error_format() {
        let err = PhpError::new(ErrorLevel::Warning, "Division by zero")
            .with_file("test.php")
            .with_line(42);
        assert_eq!(
            err.format(),
            "Warning: Division by zero in test.php on line 42"
        );
    }

    #[test]
    fn test_error_handler_default() {
        let handler = ErrorHandler::new();
        assert_eq!(handler.error_reporting(), ErrorLevel::ALL);
        assert!(!handler.is_silenced());
    }

    #[test]
    fn test_error_reporting_set_get() {
        let mut handler = ErrorHandler::new();
        let old =
            handler.set_error_reporting(ErrorLevel::Error.mask() | ErrorLevel::Warning.mask());
        assert_eq!(old, ErrorLevel::ALL);
        assert_eq!(handler.error_reporting(), 3);
    }

    #[test]
    fn test_silence_operator() {
        let mut handler = ErrorHandler::new();
        assert_eq!(handler.error_reporting(), ErrorLevel::ALL);

        handler.begin_silence();
        assert!(handler.is_silenced());
        assert_eq!(handler.error_reporting(), 0);

        // Suppressed error should be handled silently
        let result = handler.handle_error(PhpError::new(ErrorLevel::Warning, "test"));
        assert!(result); // Handled (suppressed)
        assert!(handler.errors().is_empty()); // Not stored

        handler.end_silence();
        assert!(!handler.is_silenced());
        assert_eq!(handler.error_reporting(), ErrorLevel::ALL);
    }

    #[test]
    fn test_nested_silence() {
        let mut handler = ErrorHandler::new();
        handler.begin_silence();
        handler.begin_silence();
        assert_eq!(handler.error_reporting(), 0);

        handler.end_silence();
        assert_eq!(handler.error_reporting(), 0); // Still silenced (nested)
        assert!(handler.is_silenced());

        handler.end_silence();
        assert_eq!(handler.error_reporting(), ErrorLevel::ALL);
        assert!(!handler.is_silenced());
    }

    #[test]
    fn test_handle_warning() {
        let mut handler = ErrorHandler::new();
        let result = handler.handle_error(PhpError::new(ErrorLevel::Warning, "test warning"));
        assert!(result); // Non-fatal
        assert_eq!(handler.errors().len(), 1);
        assert_eq!(handler.last_error().unwrap().message, "test warning");
    }

    #[test]
    fn test_handle_fatal_error() {
        let mut handler = ErrorHandler::new();
        let result = handler.handle_error(PhpError::new(ErrorLevel::Error, "test fatal"));
        assert!(!result); // Fatal
        assert_eq!(handler.errors().len(), 1);
    }

    #[test]
    fn test_suppressed_by_reporting_level() {
        let mut handler = ErrorHandler::new();
        // Only report errors, not notices
        handler.set_error_reporting(ErrorLevel::Error.mask());

        let result = handler.handle_error(PhpError::new(ErrorLevel::Notice, "suppressed notice"));
        assert!(result);
        assert!(handler.errors().is_empty()); // Not stored
    }

    #[test]
    fn test_custom_error_handler() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let captured = Rc::new(RefCell::new(Vec::new()));
        let captured_clone = captured.clone();

        let mut handler = ErrorHandler::new();
        handler.set_error_handler(Some(Box::new(move |err| {
            captured_clone.borrow_mut().push(err.message.clone());
            true
        })));

        handler.handle_error(PhpError::new(ErrorLevel::Warning, "custom handled"));
        assert_eq!(captured.borrow().len(), 1);
        assert_eq!(captured.borrow()[0], "custom handled");
    }

    #[test]
    fn test_error_level_from_u32() {
        assert_eq!(ErrorLevel::from_u32(1), Some(ErrorLevel::Error));
        assert_eq!(ErrorLevel::from_u32(2), Some(ErrorLevel::Warning));
        assert_eq!(ErrorLevel::from_u32(999), None);
    }
}
