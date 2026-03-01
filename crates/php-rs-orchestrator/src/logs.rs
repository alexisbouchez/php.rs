//! Log aggregation — capture, store, and retrieve app logs.
//!
//! Each app's stdout/stderr is written to a log file in the state directory.
//! Logs are stored in a ring buffer (max N lines) to prevent unbounded growth.
//! The `logs` command can tail these files with follow mode.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Maximum number of log lines to keep per app.
const MAX_LOG_LINES: usize = 10_000;

/// Get the log file path for an app.
pub fn log_path(app_name: &str, logs_dir: &Path) -> PathBuf {
    logs_dir.join(format!("{}.log", app_name))
}

/// Get the default logs directory.
pub fn default_logs_dir() -> PathBuf {
    let state_dir = std::env::var("PHPRS_STATE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{}/.php-rs", home)
    });
    let dir = PathBuf::from(state_dir).join("logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Read the last N lines from an app's log file.
pub fn read_logs(app_name: &str, logs_dir: &Path, num_lines: usize) -> Vec<String> {
    let path = log_path(app_name, logs_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
            if lines.len() > num_lines {
                lines[lines.len() - num_lines..].to_vec()
            } else {
                lines
            }
        }
        Err(_) => Vec::new(),
    }
}

/// Append a log line to an app's log file.
pub fn append_log(app_name: &str, logs_dir: &Path, line: &str) {
    let path = log_path(app_name, logs_dir);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{}", line);
    }
}

/// Truncate log file to MAX_LOG_LINES if it's grown too large.
pub fn truncate_if_needed(app_name: &str, logs_dir: &Path) {
    let path = log_path(app_name, logs_dir);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() > MAX_LOG_LINES * 2 {
        // Keep only the last MAX_LOG_LINES lines.
        let kept = &lines[lines.len() - MAX_LOG_LINES..];
        let truncated = kept.join("\n") + "\n";
        let _ = std::fs::write(&path, truncated);
    }
}

/// Clear all logs for an app.
pub fn clear_logs(app_name: &str, logs_dir: &Path) {
    let path = log_path(app_name, logs_dir);
    let _ = std::fs::remove_file(&path);
}

/// Follow a log file (like `tail -f`). Blocks until shutdown flag is set.
pub fn follow_logs(
    app_name: &str,
    logs_dir: &Path,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    let path = log_path(app_name, logs_dir);

    // Print existing content.
    if let Ok(content) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = if lines.len() > 100 { lines.len() - 100 } else { 0 };
        for line in &lines[start..] {
            println!("{}", line);
        }
    }

    // Tail the file for new content.
    let mut last_pos = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(0);

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(500));

        if let Ok(file) = std::fs::File::open(&path) {
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len > last_pos {
                let mut reader = BufReader::new(file);
                if reader.seek(SeekFrom::Start(last_pos)).is_ok() {
                    let mut new_content = String::new();
                    if reader.read_to_string(&mut new_content).is_ok() {
                        for line in new_content.lines() {
                            println!("{}", line);
                        }
                        last_pos = file_len;
                    }
                }
            } else if file_len < last_pos {
                // File was truncated — reset position.
                last_pos = 0;
            }
        }
    }
}

/// Start a background thread that captures a child process's output
/// and writes it to the app's log file.
pub fn start_log_capture(
    app_name: String,
    logs_dir: PathBuf,
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
) {
    let name = app_name.clone();
    let dir = logs_dir.clone();
    // Capture stdout.
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            append_log(&name, &dir, &line);
        }
    });

    // Capture stderr.
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            let tagged = format!("[stderr] {}", line);
            append_log(&app_name, &logs_dir, &tagged);
        }
    });
}

/// Parse a .env file into key-value pairs.
/// Supports:
///   KEY=value
///   KEY="quoted value"
///   KEY='single quoted'
///   # comments
///   Empty lines
pub fn parse_dotenv(content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Find the = separator.
        let eq = match line.find('=') {
            Some(pos) => pos,
            None => continue,
        };

        let key = line[..eq].trim().to_string();
        let mut value = line[eq + 1..].trim().to_string();

        // Remove surrounding quotes.
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }

        // Skip internal keys.
        if key.starts_with("_PHPRS_") {
            continue;
        }

        if !key.is_empty() {
            vars.push((key, value));
        }
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_logs_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "phprs-logs-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_append_and_read_logs() {
        let dir = test_logs_dir();

        append_log("testapp", &dir, "line 1");
        append_log("testapp", &dir, "line 2");
        append_log("testapp", &dir, "line 3");

        let logs = read_logs("testapp", &dir, 100);
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0], "line 1");
        assert_eq!(logs[2], "line 3");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_logs_limit() {
        let dir = test_logs_dir();

        for i in 0..20 {
            append_log("limited", &dir, &format!("line {}", i));
        }

        let logs = read_logs("limited", &dir, 5);
        assert_eq!(logs.len(), 5);
        assert_eq!(logs[0], "line 15");
        assert_eq!(logs[4], "line 19");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_logs_empty() {
        let dir = test_logs_dir();
        let logs = read_logs("nonexistent", &dir, 100);
        assert!(logs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_clear_logs() {
        let dir = test_logs_dir();
        append_log("clearme", &dir, "some log");
        assert!(!read_logs("clearme", &dir, 100).is_empty());

        clear_logs("clearme", &dir);
        assert!(read_logs("clearme", &dir, 100).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_truncate_if_needed() {
        let dir = test_logs_dir();

        // Write more than 2*MAX_LOG_LINES lines.
        let path = log_path("bigapp", &dir);
        let mut file = std::fs::File::create(&path).unwrap();
        for i in 0..(MAX_LOG_LINES * 2 + 500) {
            writeln!(file, "line {}", i).unwrap();
        }
        drop(file);

        truncate_if_needed("bigapp", &dir);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), MAX_LOG_LINES);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_dotenv_basic() {
        let content = r#"
# Comment
APP_ENV=production
APP_KEY="base64:abc123"
DB_HOST=localhost
DB_PASSWORD='s3cret'

EMPTY=
"#;
        let vars = parse_dotenv(content);
        assert_eq!(vars.len(), 5);
        assert_eq!(vars[0], ("APP_ENV".into(), "production".into()));
        assert_eq!(vars[1], ("APP_KEY".into(), "base64:abc123".into()));
        assert_eq!(vars[2], ("DB_HOST".into(), "localhost".into()));
        assert_eq!(vars[3], ("DB_PASSWORD".into(), "s3cret".into()));
        assert_eq!(vars[4], ("EMPTY".into(), "".into()));
    }

    #[test]
    fn test_parse_dotenv_comments_and_empty() {
        let content = "# This is a comment\n\n\nKEY=value\n# Another comment\n";
        let vars = parse_dotenv(content);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], ("KEY".into(), "value".into()));
    }

    #[test]
    fn test_parse_dotenv_internal_keys_skipped() {
        let content = "_PHPRS_SERVICES={}\nAPP_ENV=test\n";
        let vars = parse_dotenv(content);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "APP_ENV");
    }

    #[test]
    fn test_log_path() {
        let dir = PathBuf::from("/tmp/logs");
        let path = log_path("myapp", &dir);
        assert_eq!(path, PathBuf::from("/tmp/logs/myapp.log"));
    }
}
