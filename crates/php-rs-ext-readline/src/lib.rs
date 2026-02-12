//! PHP readline extension.
//!
//! Implements interactive line reading functions with history management.
//! Reference: php-src/ext/readline/
//!
//! Uses thread-local storage for history since we cannot depend on the
//! actual readline/editline C library.

use std::cell::RefCell;

// ── Data structures ───────────────────────────────────────────────────────────

/// Information about the readline state, returned by readline_info().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadlineInfo {
    /// The current line buffer contents.
    pub line_buffer: String,
    /// The current cursor position within the line buffer.
    pub point: usize,
    /// The index of the end of the line buffer.
    pub end: usize,
    /// The version string of the readline library.
    pub library_version: String,
    /// The application name for readline.
    pub readline_name: String,
    /// Whether readline has finished reading a line.
    pub done: bool,
}

impl Default for ReadlineInfo {
    fn default() -> Self {
        ReadlineInfo {
            line_buffer: String::new(),
            point: 0,
            end: 0,
            library_version: "php-rs-readline 1.0".to_string(),
            readline_name: "php".to_string(),
            done: false,
        }
    }
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// A completion function that takes a partial word and returns possible completions.
type CompletionFn = fn(&str) -> Vec<String>;

// ── Thread-local storage ──────────────────────────────────────────────────────

thread_local! {
    static HISTORY: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static READLINE_INFO: RefCell<ReadlineInfo> = RefCell::new(ReadlineInfo::default());
    static COMPLETION_FN: RefCell<Option<CompletionFn>> = const { RefCell::new(None) };
}

// ── Readline functions ────────────────────────────────────────────────────────

/// readline() - Reads a single line from the user.
///
/// In this stub implementation, returns None since we don't have a real terminal.
/// In a real implementation, this would read from stdin with line editing support.
pub fn readline(prompt: &str) -> Option<String> {
    let _ = prompt;
    // Stub: cannot read from terminal in this context.
    // In production, this would use actual readline/editline.
    None
}

/// readline_add_history() - Adds a line to the history.
///
/// Returns true on success.
pub fn readline_add_history(line: &str) -> bool {
    HISTORY.with(|history| {
        history.borrow_mut().push(line.to_string());
    });
    true
}

/// readline_clear_history() - Clears the history.
///
/// Returns true on success.
pub fn readline_clear_history() -> bool {
    HISTORY.with(|history| {
        history.borrow_mut().clear();
    });
    true
}

/// readline_read_history() - Reads the history from a file.
///
/// Returns true on success, false if the file cannot be read.
pub fn readline_read_history(filename: &str) -> bool {
    use std::fs;
    match fs::read_to_string(filename) {
        Ok(contents) => {
            HISTORY.with(|history| {
                let mut history = history.borrow_mut();
                for line in contents.lines() {
                    if !line.is_empty() {
                        history.push(line.to_string());
                    }
                }
            });
            true
        }
        Err(_) => false,
    }
}

/// readline_write_history() - Writes the history to a file.
///
/// Returns true on success, false if the file cannot be written.
pub fn readline_write_history(filename: &str) -> bool {
    use std::fs;
    HISTORY.with(|history| {
        let history = history.borrow();
        let contents = history.join("\n");
        fs::write(filename, contents).is_ok()
    })
}

/// readline_info() - Gets/sets various internal readline variables.
///
/// When called with a variable name and new value, sets that variable.
/// Returns the current ReadlineInfo state.
pub fn readline_info(varname: Option<&str>, newvalue: Option<&str>) -> ReadlineInfo {
    READLINE_INFO.with(|info| {
        let mut info = info.borrow_mut();
        if let (Some(name), Some(value)) = (varname, newvalue) {
            match name {
                "line_buffer" => info.line_buffer = value.to_string(),
                "readline_name" => info.readline_name = value.to_string(),
                _ => {} // Unknown variables are silently ignored.
            }
        }
        info.clone()
    })
}

/// readline_completion_function() - Registers a completion function.
///
/// The completion function takes a partial word and returns a list of completions.
pub fn readline_completion_function(function: fn(&str) -> Vec<String>) {
    COMPLETION_FN.with(|f| {
        *f.borrow_mut() = Some(function);
    });
}

/// Get completions for a given text using the registered completion function.
///
/// Returns an empty Vec if no completion function is registered.
pub fn get_completions(text: &str) -> Vec<String> {
    COMPLETION_FN.with(|f| {
        let f = f.borrow();
        match &*f {
            Some(func) => func(text),
            None => Vec::new(),
        }
    })
}

/// Get the current history as a Vec.
pub fn get_history() -> Vec<String> {
    HISTORY.with(|history| history.borrow().clone())
}

/// Get the number of entries in the history.
pub fn history_length() -> usize {
    HISTORY.with(|history| history.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_state() {
        HISTORY.with(|h| h.borrow_mut().clear());
        READLINE_INFO.with(|i| *i.borrow_mut() = ReadlineInfo::default());
        COMPLETION_FN.with(|f| *f.borrow_mut() = None);
    }

    #[test]
    fn test_readline_returns_none() {
        // Stub readline returns None since there's no terminal.
        assert_eq!(readline("prompt> "), None);
    }

    #[test]
    fn test_readline_add_history() {
        reset_state();

        assert!(readline_add_history("first command"));
        assert!(readline_add_history("second command"));

        let history = get_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], "first command");
        assert_eq!(history[1], "second command");
    }

    #[test]
    fn test_readline_clear_history() {
        reset_state();

        readline_add_history("command 1");
        readline_add_history("command 2");
        assert_eq!(history_length(), 2);

        assert!(readline_clear_history());
        assert_eq!(history_length(), 0);
    }

    #[test]
    fn test_readline_write_and_read_history() {
        reset_state();

        readline_add_history("line one");
        readline_add_history("line two");
        readline_add_history("line three");

        let tmpfile = std::env::temp_dir().join("php_rs_test_readline_history.txt");
        let tmpfile_str = tmpfile.to_str().unwrap();

        // Write history.
        assert!(readline_write_history(tmpfile_str));

        // Clear and read back.
        readline_clear_history();
        assert_eq!(history_length(), 0);

        assert!(readline_read_history(tmpfile_str));
        let history = get_history();
        assert!(history.len() >= 3);
        // Note: the lines are joined by \n, so reading them back splits correctly.

        // Cleanup.
        let _ = std::fs::remove_file(&tmpfile);
    }

    #[test]
    fn test_readline_read_history_nonexistent_file() {
        assert!(!readline_read_history("/nonexistent/path/history.txt"));
    }

    #[test]
    fn test_readline_info_default() {
        reset_state();

        let info = readline_info(None, None);
        assert_eq!(info.line_buffer, "");
        assert_eq!(info.point, 0);
        assert_eq!(info.end, 0);
        assert_eq!(info.library_version, "php-rs-readline 1.0");
        assert_eq!(info.readline_name, "php");
        assert!(!info.done);
    }

    #[test]
    fn test_readline_info_set_variable() {
        reset_state();

        let info = readline_info(Some("readline_name"), Some("my_app"));
        assert_eq!(info.readline_name, "my_app");

        let info = readline_info(Some("line_buffer"), Some("test input"));
        assert_eq!(info.line_buffer, "test input");
    }

    #[test]
    fn test_readline_info_unknown_variable() {
        reset_state();

        // Setting unknown variable should be silently ignored.
        let info = readline_info(Some("nonexistent"), Some("value"));
        assert_eq!(info.readline_name, "php"); // Unchanged.
    }

    #[test]
    fn test_readline_completion_function() {
        reset_state();

        fn my_completer(text: &str) -> Vec<String> {
            let commands = vec!["help", "history", "exit", "echo"];
            commands
                .into_iter()
                .filter(|c| c.starts_with(text))
                .map(|c| c.to_string())
                .collect()
        }

        readline_completion_function(my_completer);

        let completions = get_completions("h");
        assert_eq!(completions, vec!["help", "history"]);

        let completions = get_completions("e");
        assert_eq!(completions, vec!["exit", "echo"]);

        let completions = get_completions("z");
        assert!(completions.is_empty());
    }

    #[test]
    fn test_get_completions_no_function() {
        reset_state();

        let completions = get_completions("test");
        assert!(completions.is_empty());
    }

    #[test]
    fn test_history_length() {
        reset_state();

        assert_eq!(history_length(), 0);
        readline_add_history("one");
        assert_eq!(history_length(), 1);
        readline_add_history("two");
        assert_eq!(history_length(), 2);
        readline_clear_history();
        assert_eq!(history_length(), 0);
    }
}
