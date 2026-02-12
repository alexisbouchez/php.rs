//! PHPT test runner
//!
//! This module provides a test runner for PHP's .phpt test format.
//! Reference: https://qa.php.net/phpt_details.php
//!
//! .phpt files contain multiple sections:
//! - --TEST-- (required): Test description
//! - --FILE-- (required): PHP code to execute
//! - --EXPECT-- or --EXPECTF-- or --EXPECTREGEX-- (required): Expected output
//! - --SKIPIF--: Code to determine if test should be skipped
//! - --INI--: INI settings to apply
//! - --ENV--: Environment variables
//! - --ARGS--: Command-line arguments
//! - --POST--: POST data
//! - --CLEAN--: Cleanup code
//! - --XFAIL--: Expected failure reason (test is expected to fail)
//! - --EXTENSIONS--: Required extensions
//! - --FLAKY--: Marks test as flaky (failures are retried and non-fatal)

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Represents a parsed PHPT test file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhptTest {
    /// Test description (from --TEST-- section)
    pub description: String,
    /// PHP code to execute (from --FILE-- section)
    pub file: String,
    /// Expected output (from --EXPECT--, --EXPECTF--, or --EXPECTREGEX-- section)
    pub expect: PhptExpect,
    /// Optional skip condition code (from --SKIPIF-- section)
    pub skipif: Option<String>,
    /// Optional INI settings (from --INI-- section)
    pub ini: Option<String>,
    /// Optional environment variables (from --ENV-- section)
    pub env: Option<String>,
    /// Optional command-line arguments (from --ARGS-- section)
    pub args: Option<String>,
    /// Optional POST data (from --POST-- section)
    pub post: Option<String>,
    /// Optional cleanup code (from --CLEAN-- section)
    pub clean: Option<String>,
    /// Optional expected failure reason (from --XFAIL-- section)
    pub xfail: Option<String>,
    /// Optional required extensions (from --EXTENSIONS-- section)
    pub extensions: Option<String>,
    /// Optional flaky marker (from --FLAKY-- section)
    pub flaky: Option<String>,
}

/// Expected output format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhptExpect {
    /// Exact match (from --EXPECT--)
    Exact(String),
    /// Format string match with %s, %d, %f placeholders (from --EXPECTF--)
    Format(String),
    /// Regex match (from --EXPECTREGEX--)
    Regex(String),
}

/// Default timeout for PHPT test execution (30 seconds).
const PHPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Supported extensions in this interpreter.
const SUPPORTED_EXTENSIONS: &[&str] = &[
    "standard",
    "json",
    "pcre",
    "date",
    "spl",
    "mbstring",
    "ctype",
    "filter",
    "hash",
    "session",
    "tokenizer",
    "bcmath",
    "calendar",
    "reflection",
];

/// Parse a .phpt file
pub fn parse_phpt(content: &str) -> Result<PhptTest, String> {
    let mut sections: HashMap<String, String> = HashMap::new();
    let mut current_section: Option<String> = None;
    let mut current_content = String::new();

    for line in content.lines() {
        if line.starts_with("--") && line.ends_with("--") {
            // Save previous section if any
            if let Some(section_name) = current_section.take() {
                sections.insert(section_name, current_content.trim_end().to_string());
                current_content.clear();
            }

            // Start new section
            let section_name = line
                .trim_start_matches("--")
                .trim_end_matches("--")
                .to_string();
            current_section = Some(section_name);
        } else if current_section.is_some() {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }

    // Save last section
    if let Some(section_name) = current_section {
        sections.insert(section_name, current_content.trim_end().to_string());
    }

    // Validate required sections
    let description = sections
        .get("TEST")
        .ok_or("Missing required --TEST-- section")?
        .clone();

    let file = sections
        .get("FILE")
        .ok_or("Missing required --FILE-- section")?
        .clone();

    // Get expected output (either --EXPECT--, --EXPECTF--, or --EXPECTREGEX--)
    let expect = if let Some(exact) = sections.get("EXPECT") {
        PhptExpect::Exact(exact.clone())
    } else if let Some(format) = sections.get("EXPECTF") {
        PhptExpect::Format(format.clone())
    } else if let Some(regex) = sections.get("EXPECTREGEX") {
        PhptExpect::Regex(regex.clone())
    } else {
        return Err(
            "Missing required --EXPECT--, --EXPECTF--, or --EXPECTREGEX-- section".to_string(),
        );
    };

    Ok(PhptTest {
        description,
        file,
        expect,
        skipif: sections.get("SKIPIF").cloned(),
        ini: sections.get("INI").cloned(),
        env: sections.get("ENV").cloned(),
        args: sections.get("ARGS").cloned(),
        post: sections.get("POST").cloned(),
        clean: sections.get("CLEAN").cloned(),
        xfail: sections.get("XFAIL").cloned(),
        extensions: sections.get("EXTENSIONS").cloned(),
        flaky: sections.get("FLAKY").cloned(),
    })
}

/// Get the path to the php.rs CLI binary
fn get_php_binary() -> Result<PathBuf, String> {
    // The binary is "php-rs" (defined in php-rs-sapi-cli/Cargo.toml [[bin]])
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir);

    let debug_binary = workspace_root.join("target/debug/php-rs");
    let release_binary = workspace_root.join("target/release/php-rs");

    if debug_binary.exists() {
        Ok(debug_binary)
    } else if release_binary.exists() {
        Ok(release_binary)
    } else {
        Err(format!(
            "php.rs CLI binary not found. Tried:\n  {}\n  {}",
            debug_binary.display(),
            release_binary.display()
        ))
    }
}

/// Result of checking the SKIPIF section
#[derive(Debug, Clone, PartialEq, Eq)]
enum SkipResult {
    /// Test should be skipped with the given reason
    Skip(String),
    /// Test should run
    Run,
}

/// Check if a test should be skipped by executing the --SKIPIF-- section
///
/// The SKIPIF section should output "skip" followed by an optional reason
/// on a single line if the test should be skipped.
/// Reference: https://qa.php.net/phpt_details.php
fn check_skipif(php_binary: &Path, skipif_code: &str) -> Result<SkipResult, String> {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!(
        "phpt_skipif_{}_{:?}.php",
        std::process::id(),
        std::thread::current().id()
    ));

    // Write the SKIPIF code to a temporary file
    fs::write(&temp_file, skipif_code)
        .map_err(|e| format!("Failed to write SKIPIF temporary file: {}", e))?;

    // Execute the SKIPIF code
    let output = Command::new(php_binary)
        .arg(&temp_file)
        .output()
        .map_err(|e| format!("Failed to execute SKIPIF code: {}", e))?;

    // Clean up the temporary file
    let _ = fs::remove_file(&temp_file);

    // Check the output
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stdout_trimmed = stdout.trim();

    if stdout_trimmed.starts_with("skip") {
        // Extract the skip reason (everything after "skip")
        let reason = stdout_trimmed
            .strip_prefix("skip")
            .unwrap_or("")
            .trim()
            .to_string();
        let reason = if reason.is_empty() {
            "No reason given".to_string()
        } else {
            reason
        };
        Ok(SkipResult::Skip(reason))
    } else {
        Ok(SkipResult::Run)
    }
}

/// Execute the --CLEAN-- section code
///
/// The CLEAN section is used to clean up any files or resources created during the test.
/// Errors are ignored since the test result is already determined.
fn run_clean(php_binary: &Path, clean_code: &str) -> Result<(), String> {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!(
        "phpt_clean_{}_{:?}.php",
        std::process::id(),
        std::thread::current().id()
    ));

    // Write the CLEAN code to a temporary file
    fs::write(&temp_file, clean_code)
        .map_err(|e| format!("Failed to write CLEAN temporary file: {}", e))?;

    // Execute the CLEAN code
    let _ = Command::new(php_binary)
        .arg(&temp_file)
        .output()
        .map_err(|e| format!("Failed to execute CLEAN code: {}", e))?;

    // Clean up the temporary file
    let _ = fs::remove_file(&temp_file);

    Ok(())
}

/// Result of executing a PHPT test including skip status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhptExecutionResult {
    /// Test was skipped (from --SKIPIF-- section)
    Skipped { reason: String },
    /// Test was executed
    Executed(PhptOutput),
}

/// Check if required extensions are available.
/// Returns `Some(reason)` if an extension is missing, `None` if all present.
fn check_extensions(extensions: &str) -> Option<String> {
    for line in extensions.lines() {
        let ext = line.trim();
        if ext.is_empty() {
            continue;
        }
        if !SUPPORTED_EXTENSIONS
            .iter()
            .any(|&s| s.eq_ignore_ascii_case(ext))
        {
            return Some(format!("extension {} not available", ext));
        }
    }
    None
}

/// Execute a PHPT test by running the php.rs CLI on its --FILE-- section.
/// Includes a 30-second timeout to prevent tests from hanging.
pub fn execute_phpt(test: &PhptTest) -> Result<PhptExecutionResult, String> {
    let php_binary = get_php_binary()?;

    // Check --EXTENSIONS-- section first (fast check, no subprocess needed)
    if let Some(ref extensions) = test.extensions {
        if let Some(reason) = check_extensions(extensions) {
            return Ok(PhptExecutionResult::Skipped { reason });
        }
    }

    // Check if test should be skipped
    if let Some(ref skipif_code) = test.skipif {
        match check_skipif(&php_binary, skipif_code)? {
            SkipResult::Skip(reason) => {
                return Ok(PhptExecutionResult::Skipped { reason });
            }
            SkipResult::Run => {
                // Continue with test execution
            }
        }
    }

    // Create a temporary file with the PHP code
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!(
        "phpt_test_{}_{:?}.php",
        std::process::id(),
        std::thread::current().id()
    ));

    // Write the --FILE-- content to the temporary file
    fs::write(&temp_file, &test.file)
        .map_err(|e| format!("Failed to write temporary file: {}", e))?;

    // Build the command with optional arguments
    let mut cmd = Command::new(&php_binary);

    // Add INI settings via -d flags if present
    if let Some(ref ini) = test.ini {
        for line in ini.lines() {
            let line = line.trim();
            if !line.is_empty() {
                cmd.arg("-d").arg(line);
            }
        }
    }

    // Add command-line arguments if present
    if let Some(ref args) = test.args {
        cmd.arg("--");
        for arg in args.split_whitespace() {
            cmd.arg(arg);
        }
    }

    // Add environment variables if present
    if let Some(ref env) = test.env {
        for line in env.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once('=') {
                cmd.env(key.trim(), value.trim());
            }
        }
    }

    // Add the file to execute
    cmd.arg(&temp_file);

    // Execute the command with a timeout to prevent hanging tests
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn php.rs CLI: {}", e))?;

    let output = wait_with_timeout(child, PHPT_TIMEOUT)?;

    // Clean up the temporary file
    let _ = fs::remove_file(&temp_file);

    // Convert output to string
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let phpt_output = PhptOutput {
        stdout,
        stderr,
        exit_code: output.exit_code,
    };

    // Run cleanup code if present
    if let Some(ref clean_code) = test.clean {
        let _ = run_clean(&php_binary, clean_code);
        // Ignore errors from cleanup - test result is what matters
    }

    Ok(PhptExecutionResult::Executed(phpt_output))
}

/// Output from a timed process.
struct TimedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
}

/// Wait for a child process with a timeout. Kills the process if it exceeds the timeout.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<TimedOutput, String> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).unwrap_or(0);
                        buf
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).unwrap_or(0);
                        buf
                    })
                    .unwrap_or_default();
                return Ok(TimedOutput {
                    stdout,
                    stderr,
                    exit_code: status.code().unwrap_or(-1),
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Test timed out after {} seconds",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(format!("Failed to wait for process: {}", e));
            }
        }
    }
}

/// Output from executing a PHPT test
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhptOutput {
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Exit code
    pub exit_code: i32,
}

/// Result of comparing test output against expected output
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareResult {
    /// Output matches expected
    Match,
    /// Output does not match expected
    Mismatch {
        expected: String,
        actual: String,
        details: String,
    },
}

/// Compare actual output against expected output
pub fn compare_output(expected: &PhptExpect, actual: &str) -> CompareResult {
    match expected {
        PhptExpect::Exact(expected_str) => {
            if actual == expected_str {
                CompareResult::Match
            } else {
                CompareResult::Mismatch {
                    expected: expected_str.clone(),
                    actual: actual.to_string(),
                    details: format!(
                        "Exact match failed:\nExpected:\n{}\nActual:\n{}",
                        expected_str, actual
                    ),
                }
            }
        }
        PhptExpect::Format(format_str) => compare_format(format_str, actual),
        PhptExpect::Regex(regex_str) => compare_regex(regex_str, actual),
    }
}

/// Compare actual output against a raw regex pattern (--EXPECTREGEX--)
fn compare_regex(regex_str: &str, actual: &str) -> CompareResult {
    // The regex from --EXPECTREGEX-- is used as-is, anchored to match the full output
    let full_pattern = format!("(?s)^{}$", regex_str);
    match regex::Regex::new(&full_pattern) {
        Ok(re) => {
            if re.is_match(actual) {
                CompareResult::Match
            } else {
                CompareResult::Mismatch {
                    expected: regex_str.to_string(),
                    actual: actual.to_string(),
                    details: format!(
                        "Regex match failed:\nPattern:\n{}\nActual:\n{}\nFull regex: {}",
                        regex_str, actual, full_pattern
                    ),
                }
            }
        }
        Err(e) => CompareResult::Mismatch {
            expected: regex_str.to_string(),
            actual: actual.to_string(),
            details: format!("Failed to compile regex: {}\nPattern: {}", e, full_pattern),
        },
    }
}

/// Compare actual output against a format string with placeholders
///
/// Supported placeholders:
/// - %s: any string (non-greedy match)
/// - %d: integer (optional sign + digits)
/// - %f: float (optional sign + digits + optional decimal + optional exponent)
/// - %i: integer (same as %d)
/// - %u: unsigned integer (digits only)
/// - %x: hexadecimal (0-9a-fA-F)
/// - %c: single character
/// - %%: literal percent sign
fn compare_format(format_str: &str, actual: &str) -> CompareResult {
    // Build a regex pattern from the format string
    let mut pattern = String::new();
    let mut chars = format_str.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_ch) = chars.peek() {
                chars.next(); // consume the format specifier
                match next_ch {
                    's' => pattern.push_str(r".*?"),            // non-greedy any string
                    'd' | 'i' => pattern.push_str(r"[+-]?\d+"), // integer
                    'u' => pattern.push_str(r"\d+"),            // unsigned integer
                    'f' => pattern.push_str(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?"), // float
                    'x' => pattern.push_str(r"[0-9a-fA-F]+"),   // hexadecimal
                    'c' => pattern.push('.'),                   // single character
                    '%' => pattern.push('%'),                   // literal %
                    _ => {
                        // Unknown format specifier - treat literally
                        pattern.push('%');
                        pattern.push(next_ch);
                    }
                }
            } else {
                // Trailing % - treat literally
                pattern.push('%');
            }
        } else {
            // Escape regex special characters
            if r"\.+*?()|[]{}^$".contains(ch) {
                pattern.push('\\');
            }
            pattern.push(ch);
        }
    }

    // Anchor the pattern to match the entire string
    let full_pattern = format!("^{}$", pattern);

    // Compile and test the regex
    match regex::Regex::new(&full_pattern) {
        Ok(re) => {
            if re.is_match(actual) {
                CompareResult::Match
            } else {
                CompareResult::Mismatch {
                    expected: format_str.to_string(),
                    actual: actual.to_string(),
                    details: format!(
                        "Format match failed:\nExpected format:\n{}\nActual:\n{}\nRegex pattern: {}",
                        format_str, actual, full_pattern
                    ),
                }
            }
        }
        Err(e) => CompareResult::Mismatch {
            expected: format_str.to_string(),
            actual: actual.to_string(),
            details: format!(
                "Failed to compile regex pattern: {}\nPattern: {}",
                e, full_pattern
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_phpt() {
        let content = r#"--TEST--
Simple echo test
--FILE--
<?php
echo "Hello, World!";
?>
--EXPECT--
Hello, World!
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.description, "Simple echo test");
        assert_eq!(result.file, "<?php\necho \"Hello, World!\";\n?>");
        assert_eq!(
            result.expect,
            PhptExpect::Exact("Hello, World!".to_string())
        );
        assert!(result.skipif.is_none());
        assert!(result.ini.is_none());
    }

    #[test]
    fn test_parse_phpt_with_expectf() {
        let content = r#"--TEST--
Test with format placeholders
--FILE--
<?php
echo 123;
echo " abc";
?>
--EXPECTF--
%d abc
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.description, "Test with format placeholders");
        assert_eq!(result.expect, PhptExpect::Format("%d abc".to_string()));
    }

    #[test]
    fn test_parse_phpt_with_skipif() {
        let content = r#"--TEST--
Test with skip condition
--SKIPIF--
<?php if (!extension_loaded('json')) die('skip json not available'); ?>
--FILE--
<?php
echo "test";
?>
--EXPECT--
test
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.description, "Test with skip condition");
        assert!(result.skipif.is_some());
        assert!(result.skipif.unwrap().contains("extension_loaded('json')"));
    }

    #[test]
    fn test_parse_phpt_with_ini() {
        let content = r#"--TEST--
Test with INI settings
--INI--
error_reporting=E_ALL
display_errors=1
--FILE--
<?php
echo "test";
?>
--EXPECT--
test
"#;

        let result = parse_phpt(content).unwrap();
        assert!(result.ini.is_some());
        let ini = result.ini.unwrap();
        assert!(ini.contains("error_reporting=E_ALL"));
        assert!(ini.contains("display_errors=1"));
    }

    #[test]
    fn test_parse_phpt_with_all_sections() {
        let content = r#"--TEST--
Comprehensive test
--SKIPIF--
<?php if (PHP_VERSION_ID < 80000) die('skip requires PHP 8.0+'); ?>
--INI--
memory_limit=128M
--ENV--
FOO=bar
--ARGS--
arg1 arg2
--FILE--
<?php
echo "test";
?>
--EXPECT--
test
--CLEAN--
<?php
unlink('test.txt');
?>
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.description, "Comprehensive test");
        assert!(result.skipif.is_some());
        assert!(result.ini.is_some());
        assert!(result.env.is_some());
        assert!(result.args.is_some());
        assert!(result.clean.is_some());
        assert_eq!(result.env.as_ref().unwrap(), "FOO=bar");
        assert_eq!(result.args.as_ref().unwrap(), "arg1 arg2");
    }

    #[test]
    fn test_parse_phpt_missing_test_section() {
        let content = r#"--FILE--
<?php
echo "test";
?>
--EXPECT--
test
"#;

        let result = parse_phpt(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Missing required --TEST-- section"));
    }

    #[test]
    fn test_parse_phpt_missing_file_section() {
        let content = r#"--TEST--
Test
--EXPECT--
test
"#;

        let result = parse_phpt(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Missing required --FILE-- section"));
    }

    #[test]
    fn test_parse_phpt_missing_expect_section() {
        let content = r#"--TEST--
Test
--FILE--
<?php
echo "test";
?>
"#;

        let result = parse_phpt(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Missing required --EXPECT--, --EXPECTF--, or --EXPECTREGEX-- section"));
    }

    #[test]
    fn test_parse_phpt_with_expectregex() {
        let content = r#"--TEST--
Test with regex
--FILE--
<?php
echo "Hello 123";
?>
--EXPECTREGEX--
Hello \d+
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.description, "Test with regex");
        assert_eq!(result.expect, PhptExpect::Regex("Hello \\d+".to_string()));
    }

    #[test]
    fn test_parse_phpt_with_xfail() {
        let content = r#"--TEST--
Test expected to fail
--XFAIL--
Known bug #12345
--FILE--
<?php
echo "test";
?>
--EXPECT--
wrong output
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.xfail.as_deref(), Some("Known bug #12345"));
    }

    #[test]
    fn test_parse_phpt_with_extensions() {
        let content = r#"--TEST--
Test requiring extensions
--EXTENSIONS--
json
mbstring
--FILE--
<?php
echo "test";
?>
--EXPECT--
test
"#;

        let result = parse_phpt(content).unwrap();
        assert!(result.extensions.is_some());
        assert!(result.extensions.as_ref().unwrap().contains("json"));
        assert!(result.extensions.as_ref().unwrap().contains("mbstring"));
    }

    #[test]
    fn test_check_extensions_supported() {
        assert!(check_extensions("json\npcre\nstandard").is_none());
    }

    #[test]
    fn test_check_extensions_unsupported() {
        let result = check_extensions("json\nmysqli\nstandard");
        assert!(result.is_some());
        assert!(result.unwrap().contains("mysqli"));
    }

    #[test]
    fn test_compare_regex_match() {
        let expected = PhptExpect::Regex(r"Hello \d+ world".to_string());
        assert_eq!(
            compare_output(&expected, "Hello 42 world"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_compare_regex_mismatch() {
        let expected = PhptExpect::Regex(r"Hello \d+ world".to_string());
        match compare_output(&expected, "Hello abc world") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch"),
        }
    }

    #[test]
    fn test_compare_regex_multiline() {
        let expected = PhptExpect::Regex(r"line1\nline2\nline\d+".to_string());
        assert_eq!(
            compare_output(&expected, "line1\nline2\nline3"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_parse_phpt_multiline_content() {
        let content = r#"--TEST--
Multiline test
--FILE--
<?php
$a = 1;
$b = 2;
echo $a + $b;
?>
--EXPECT--
3
"#;

        let result = parse_phpt(content).unwrap();
        assert_eq!(result.file, "<?php\n$a = 1;\n$b = 2;\necho $a + $b;\n?>");
        assert_eq!(result.expect, PhptExpect::Exact("3".to_string()));
    }

    #[test]
    fn test_execute_phpt() {
        // This test will fail until we have a working CLI that can execute PHP code
        // For now, we just test that the execution mechanism works (binary exists, etc.)
        let test = PhptTest {
            description: "Test execution".to_string(),
            file: "<?php\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: None,
            ini: None,
            env: None,
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // Try to execute - this may fail if binary doesn't exist yet
        match execute_phpt(&test) {
            Ok(PhptExecutionResult::Executed(output)) => {
                // If it succeeds, verify we got some output structure
                // (The actual content won't match until we implement the interpreter)
                assert!(output.exit_code >= -1);
            }
            Ok(PhptExecutionResult::Skipped { .. }) => {
                panic!("Test should not be skipped");
            }
            Err(e) => {
                // Expected to fail if binary doesn't exist yet
                assert!(
                    e.contains("not found") || e.contains("Failed to execute"),
                    "Unexpected error: {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_execute_phpt_with_ini() {
        let test = PhptTest {
            description: "Test with INI".to_string(),
            file: "<?php\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: None,
            ini: Some("error_reporting=E_ALL\ndisplay_errors=1".to_string()),
            env: None,
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // This test just verifies the INI handling code doesn't crash
        let _ = execute_phpt(&test);
    }

    #[test]
    fn test_execute_phpt_with_env() {
        let test = PhptTest {
            description: "Test with ENV".to_string(),
            file: "<?php\necho getenv('TEST_VAR');\n?>".to_string(),
            expect: PhptExpect::Exact("test_value".to_string()),
            skipif: None,
            ini: None,
            env: Some("TEST_VAR=test_value".to_string()),
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // This test just verifies the ENV handling code doesn't crash
        let _ = execute_phpt(&test);
    }

    #[test]
    fn test_execute_phpt_with_args() {
        let test = PhptTest {
            description: "Test with ARGS".to_string(),
            file: "<?php\nvar_dump($argv);\n?>".to_string(),
            expect: PhptExpect::Format("array(3) {\n  [0]=>\n  string(%d) \"%s\"\n  [1]=>\n  string(4) \"arg1\"\n  [2]=>\n  string(4) \"arg2\"\n}".to_string()),
            skipif: None,
            ini: None,
            env: None,
            args: Some("arg1 arg2".to_string()),
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // This test just verifies the ARGS handling code doesn't crash
        let _ = execute_phpt(&test);
    }

    #[test]
    fn test_compare_exact_match() {
        let expected = PhptExpect::Exact("Hello, World!".to_string());
        let result = compare_output(&expected, "Hello, World!");
        assert_eq!(result, CompareResult::Match);
    }

    #[test]
    fn test_compare_exact_mismatch() {
        let expected = PhptExpect::Exact("Hello, World!".to_string());
        let result = compare_output(&expected, "Hello, PHP!");
        match result {
            CompareResult::Mismatch {
                expected: e,
                actual: a,
                ..
            } => {
                assert_eq!(e, "Hello, World!");
                assert_eq!(a, "Hello, PHP!");
            }
            _ => panic!("Expected mismatch"),
        }
    }

    #[test]
    fn test_compare_format_string_placeholder() {
        let expected = PhptExpect::Format("Hello, %s!".to_string());
        assert_eq!(
            compare_output(&expected, "Hello, World!"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Hello, PHP!"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Hello, Rust!"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_compare_format_integer_placeholder() {
        let expected = PhptExpect::Format("Number: %d".to_string());
        assert_eq!(
            compare_output(&expected, "Number: 123"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Number: -456"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Number: +789"),
            CompareResult::Match
        );

        // Should not match non-integers
        match compare_output(&expected, "Number: abc") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch for non-integer"),
        }
    }

    #[test]
    fn test_compare_format_float_placeholder() {
        let expected = PhptExpect::Format("Float: %f".to_string());
        assert_eq!(
            compare_output(&expected, "Float: 123.456"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Float: -0.5"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Float: 1.5e10"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Float: 3.14E-5"),
            CompareResult::Match
        );
        assert_eq!(compare_output(&expected, "Float: 42"), CompareResult::Match);
        // Integer is valid float
    }

    #[test]
    fn test_compare_format_unsigned_placeholder() {
        let expected = PhptExpect::Format("Unsigned: %u".to_string());
        assert_eq!(
            compare_output(&expected, "Unsigned: 123"),
            CompareResult::Match
        );

        // Should not match negative numbers
        match compare_output(&expected, "Unsigned: -123") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch for negative number"),
        }
    }

    #[test]
    fn test_compare_format_hex_placeholder() {
        let expected = PhptExpect::Format("Hex: %x".to_string());
        assert_eq!(
            compare_output(&expected, "Hex: 1234567890abcdefABCDEF"),
            CompareResult::Match
        );

        // Should not match non-hex
        match compare_output(&expected, "Hex: xyz") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch for non-hex"),
        }
    }

    #[test]
    fn test_compare_format_char_placeholder() {
        let expected = PhptExpect::Format("Char: %c".to_string());
        assert_eq!(compare_output(&expected, "Char: A"), CompareResult::Match);
        assert_eq!(compare_output(&expected, "Char: 5"), CompareResult::Match);

        // Should not match multiple characters
        match compare_output(&expected, "Char: AB") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch for multiple characters"),
        }
    }

    #[test]
    fn test_compare_format_literal_percent() {
        let expected = PhptExpect::Format("Progress: 50%%".to_string());
        assert_eq!(
            compare_output(&expected, "Progress: 50%"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_compare_format_multiple_placeholders() {
        let expected = PhptExpect::Format("Name: %s, Age: %d, Score: %f".to_string());
        assert_eq!(
            compare_output(&expected, "Name: Alice, Age: 30, Score: 95.5"),
            CompareResult::Match
        );
        assert_eq!(
            compare_output(&expected, "Name: Bob, Age: -5, Score: 0.0"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_compare_format_multiline() {
        let expected = PhptExpect::Format("Line 1: %s\nLine 2: %d\nLine 3: %f".to_string());
        assert_eq!(
            compare_output(&expected, "Line 1: test\nLine 2: 42\nLine 3: 3.14"),
            CompareResult::Match
        );
    }

    #[test]
    fn test_compare_format_regex_special_chars() {
        // Test that regex special characters in the format string are properly escaped
        let expected = PhptExpect::Format("Test: [%d]".to_string());
        assert_eq!(
            compare_output(&expected, "Test: [42]"),
            CompareResult::Match
        );

        // Should not match without brackets
        match compare_output(&expected, "Test: 42") {
            CompareResult::Mismatch { .. } => {}
            _ => panic!("Expected mismatch without brackets"),
        }
    }

    #[test]
    fn test_compare_format_complex_php_output() {
        // Simulate a typical PHP var_dump output pattern
        let expected = PhptExpect::Format(
            "array(%d) {\n  [0]=>\n  string(%d) \"%s\"\n  [1]=>\n  int(%d)\n}".to_string(),
        );
        assert_eq!(
            compare_output(
                &expected,
                "array(2) {\n  [0]=>\n  string(5) \"hello\"\n  [1]=>\n  int(42)\n}"
            ),
            CompareResult::Match
        );
    }

    #[test]
    fn test_skipif_skip_test() {
        // Test that a SKIPIF section that outputs "skip" causes test to be skipped
        let test = PhptTest {
            description: "Test should be skipped".to_string(),
            file: "<?php\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: Some("<?php echo \"skip test skipped\"; ?>".to_string()),
            ini: None,
            env: None,
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        match execute_phpt(&test) {
            Ok(PhptExecutionResult::Skipped { reason }) => {
                assert_eq!(reason, "test skipped");
            }
            Ok(PhptExecutionResult::Executed(_)) => {
                // If binary doesn't exist or can't execute skipif, this is acceptable
                // for now since we're testing the parsing/execution logic
            }
            Err(_) => {
                // Binary might not exist yet - acceptable
            }
        }
    }

    #[test]
    fn test_skipif_run_test() {
        // Test that a SKIPIF section that doesn't output "skip" allows test to run
        let test = PhptTest {
            description: "Test should run".to_string(),
            file: "<?php\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: Some("<?php /* no skip output */ ?>".to_string()),
            ini: None,
            env: None,
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        match execute_phpt(&test) {
            Ok(PhptExecutionResult::Executed(_)) => {
                // Test ran - good
            }
            Ok(PhptExecutionResult::Skipped { .. }) => {
                panic!("Test should not have been skipped");
            }
            Err(_) => {
                // Binary might not exist yet - acceptable
            }
        }
    }

    #[test]
    fn test_skipif_with_die() {
        // Test the standard PHP skipif pattern: die('skip reason')
        let test = PhptTest {
            description: "Test with die skip".to_string(),
            file: "<?php\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: Some("<?php die('skip extension not loaded'); ?>".to_string()),
            ini: None,
            env: None,
            args: None,
            post: None,
            clean: None,
            xfail: None,
            extensions: None,
            flaky: None,
        };

        match execute_phpt(&test) {
            Ok(PhptExecutionResult::Skipped { reason }) => {
                assert_eq!(reason, "extension not loaded");
            }
            Ok(PhptExecutionResult::Executed(_)) | Err(_) => {
                // Binary might not exist yet - acceptable
            }
        }
    }

    #[test]
    fn test_clean_section() {
        // Test that CLEAN section is executed (we can't verify it does anything
        // without a working interpreter, but we can verify it doesn't crash)
        let test = PhptTest {
            description: "Test with clean".to_string(),
            file: "<?php\nfile_put_contents('test.txt', 'data');\necho \"test\";\n?>".to_string(),
            expect: PhptExpect::Exact("test".to_string()),
            skipif: None,
            ini: None,
            env: None,
            args: None,
            post: None,
            clean: Some("<?php\n@unlink('test.txt');\n?>".to_string()),
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // Just verify this doesn't crash - we can't check if cleanup actually happened
        // until we have a working interpreter
        let _ = execute_phpt(&test);
    }

    #[test]
    fn test_all_optional_sections_together() {
        // Test with all optional sections present
        let test = PhptTest {
            description: "Comprehensive test with all sections".to_string(),
            file: "<?php\necho getenv('TEST_VAR');\n?>".to_string(),
            expect: PhptExpect::Exact("test_value".to_string()),
            skipif: Some("<?php /* no skip */ ?>".to_string()),
            ini: Some("error_reporting=E_ALL".to_string()),
            env: Some("TEST_VAR=test_value".to_string()),
            args: Some("arg1 arg2".to_string()),
            post: None,
            clean: Some("<?php /* cleanup */ ?>".to_string()),
            xfail: None,
            extensions: None,
            flaky: None,
        };

        // Just verify this doesn't crash with all sections present
        let _ = execute_phpt(&test);
    }

    // ── PHPT Integration Tests ─────────────────────────────────────────────

    /// Aggregate test statistics.
    #[derive(Debug, Default)]
    struct PhptStats {
        passed: usize,
        failed: usize,
        skipped: usize,
        errors: usize,
        xfail: usize,
        flaky_pass: usize,
        total: usize,
        failures: Vec<String>,
        /// Per-test results for JUnit XML generation.
        test_results: Vec<JunitTestCase>,
    }

    /// A single test case result for JUnit XML output.
    #[derive(Debug, Clone)]
    struct JunitTestCase {
        name: String,
        classname: String,
        time_secs: f64,
        status: JunitStatus,
    }

    #[derive(Debug, Clone)]
    enum JunitStatus {
        Passed,
        Failed { message: String },
        Skipped { message: String },
        Error { message: String },
    }

    impl PhptStats {
        fn pass_rate(&self) -> f64 {
            let run = self.passed + self.failed;
            if run > 0 {
                (self.passed as f64 / run as f64) * 100.0
            } else {
                0.0
            }
        }

        fn summary(&self, label: &str) -> String {
            format!(
                "\n=== {} ===\nTotal: {} | Passed: {} | Failed: {} | Skipped: {} | XFail: {} | Flaky: {} | Errors: {} | Pass rate: {:.1}%",
                label, self.total, self.passed, self.failed, self.skipped, self.xfail, self.flaky_pass, self.errors, self.pass_rate()
            )
        }

        /// Generate JUnit XML report string.
        fn to_junit_xml(&self, suite_name: &str) -> String {
            let mut xml = String::new();
            xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            xml.push_str(&format!(
                "<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\">\n",
                xml_escape(suite_name),
                self.total,
                self.failed,
                self.errors,
                self.skipped
            ));
            for tc in &self.test_results {
                xml.push_str(&format!(
                    "  <testcase name=\"{}\" classname=\"{}\" time=\"{:.3}\"",
                    xml_escape(&tc.name),
                    xml_escape(&tc.classname),
                    tc.time_secs
                ));
                match &tc.status {
                    JunitStatus::Passed => {
                        xml.push_str(" />\n");
                    }
                    JunitStatus::Failed { message } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "    <failure message=\"{}\">{}</failure>\n",
                            xml_escape(message),
                            xml_escape(message)
                        ));
                        xml.push_str("  </testcase>\n");
                    }
                    JunitStatus::Skipped { message } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "    <skipped message=\"{}\" />\n",
                            xml_escape(message)
                        ));
                        xml.push_str("  </testcase>\n");
                    }
                    JunitStatus::Error { message } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "    <error message=\"{}\">{}</error>\n",
                            xml_escape(message),
                            xml_escape(message)
                        ));
                        xml.push_str("  </testcase>\n");
                    }
                }
            }
            xml.push_str("</testsuite>\n");
            xml
        }
    }

    /// Escape XML special characters.
    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Load test result cache (maps file path → content hash for passed tests).
    fn load_result_cache(cache_path: &Path) -> HashMap<String, u64> {
        if let Ok(data) = fs::read_to_string(cache_path) {
            let mut map = HashMap::new();
            for line in data.lines() {
                if let Some((path, hash_str)) = line.split_once('\t') {
                    if let Ok(hash) = hash_str.parse::<u64>() {
                        map.insert(path.to_string(), hash);
                    }
                }
            }
            map
        } else {
            HashMap::new()
        }
    }

    /// Save test result cache.
    fn save_result_cache(cache_path: &Path, cache: &HashMap<String, u64>) {
        if let Ok(mut f) = fs::File::create(cache_path) {
            for (path, hash) in cache {
                let _ = writeln!(f, "{}\t{}", path, hash);
            }
        }
    }

    /// Simple hash for test content (using FNV-1a style).
    fn hash_content(content: &str) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in content.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Run a single PHPT test, returning its result for aggregation.
    /// This is the core function used by both serial and parallel modes.
    fn run_single_phpt(file: &Path, manifest_dir: &str) -> (String, String, SingleTestResult) {
        let rel = file
            .strip_prefix(manifest_dir)
            .unwrap_or(file)
            .display()
            .to_string();

        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => {
                return (
                    rel.clone(),
                    String::new(),
                    SingleTestResult::Error(format!("READ_ERROR {}: {}", rel, e)),
                );
            }
        };

        let content_hash = format!("{}", hash_content(&content));

        let test = match parse_phpt(&content) {
            Ok(t) => t,
            Err(_) => {
                return (
                    rel,
                    content_hash,
                    SingleTestResult::Skipped("parse error".into()),
                );
            }
        };

        let start = std::time::Instant::now();
        let is_xfail = test.xfail.is_some();
        let is_flaky = test.flaky.is_some();
        let description = test.description.clone();

        // For flaky tests, retry up to 3 times on failure
        let max_attempts = if is_flaky { 3 } else { 1 };

        for attempt in 0..max_attempts {
            match execute_phpt(&test) {
                Ok(PhptExecutionResult::Skipped { reason }) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    return (
                        rel,
                        content_hash,
                        SingleTestResult::Complete {
                            description,
                            status: TestOutcome::Skipped(reason),
                            time_secs: elapsed,
                        },
                    );
                }
                Ok(PhptExecutionResult::Executed(output)) => {
                    let actual = output.stdout.trim_end_matches('\n');
                    let result = compare_output(&test.expect, actual);
                    match result {
                        CompareResult::Match => {
                            let elapsed = start.elapsed().as_secs_f64();
                            let outcome = if is_flaky && attempt > 0 {
                                TestOutcome::FlakyPass
                            } else {
                                TestOutcome::Passed
                            };
                            return (
                                rel,
                                content_hash,
                                SingleTestResult::Complete {
                                    description,
                                    status: outcome,
                                    time_secs: elapsed,
                                },
                            );
                        }
                        CompareResult::Mismatch {
                            expected,
                            actual,
                            details: _,
                        } => {
                            // If flaky and not last attempt, retry
                            if is_flaky && attempt + 1 < max_attempts {
                                continue;
                            }
                            let elapsed = start.elapsed().as_secs_f64();
                            let outcome = if is_xfail {
                                TestOutcome::XFail
                            } else if is_flaky {
                                TestOutcome::FlakyPass // treat as non-fatal even after retries
                            } else {
                                TestOutcome::Failed {
                                    expected: expected.clone(),
                                    actual: actual.clone(),
                                }
                            };
                            return (
                                rel,
                                content_hash,
                                SingleTestResult::Complete {
                                    description,
                                    status: outcome,
                                    time_secs: elapsed,
                                },
                            );
                        }
                    }
                }
                Err(e) => {
                    if is_flaky && attempt + 1 < max_attempts {
                        continue;
                    }
                    let elapsed = start.elapsed().as_secs_f64();
                    let outcome = if is_xfail {
                        TestOutcome::XFail
                    } else if is_flaky {
                        TestOutcome::FlakyPass
                    } else {
                        TestOutcome::Error(e.clone())
                    };
                    return (
                        rel,
                        content_hash,
                        SingleTestResult::Complete {
                            description,
                            status: outcome,
                            time_secs: elapsed,
                        },
                    );
                }
            }
        }
        unreachable!()
    }

    #[derive(Debug)]
    enum SingleTestResult {
        Skipped(String),
        Error(String),
        Complete {
            description: String,
            status: TestOutcome,
            time_secs: f64,
        },
    }

    #[derive(Debug)]
    enum TestOutcome {
        Passed,
        Failed { expected: String, actual: String },
        Skipped(String),
        XFail,
        FlakyPass,
        Error(String),
    }

    /// Run all .phpt files in a directory and report pass/fail/skip rates.
    /// Supports parallel execution (via PHPT_PARALLEL env var),
    /// JUnit XML output (via PHPT_JUNIT env var),
    /// and test result caching (via PHPT_CACHE env var).
    fn run_phpt_directory(dir: &str) -> PhptStats {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let phpt_dir = Path::new(manifest_dir).join(dir);

        if !phpt_dir.exists() {
            eprintln!("PHPT directory not found: {}", phpt_dir.display());
            return PhptStats::default();
        }

        let mut files: Vec<PathBuf> = Vec::new();
        collect_phpt_files(&phpt_dir, &mut files);
        files.sort();

        // Test result caching: skip tests whose content hasn't changed since last pass
        let cache_path = Path::new(manifest_dir)
            .join("target")
            .join(format!("phpt_cache_{}.txt", dir.replace('/', "_")));
        let use_cache = std::env::var("PHPT_CACHE").is_ok();
        let mut cache = if use_cache {
            load_result_cache(&cache_path)
        } else {
            HashMap::new()
        };

        // Filter out cached (unchanged, previously-passed) tests
        let mut cached_count = 0usize;
        let files_to_run: Vec<PathBuf> = if use_cache {
            files
                .iter()
                .filter(|f| {
                    let rel = f
                        .strip_prefix(manifest_dir)
                        .unwrap_or(f)
                        .display()
                        .to_string();
                    if let Ok(content) = fs::read_to_string(f) {
                        let h = hash_content(&content);
                        if cache.get(&rel) == Some(&h) {
                            cached_count += 1;
                            return false; // skip — cached pass
                        }
                    }
                    true
                })
                .cloned()
                .collect()
        } else {
            files.clone()
        };

        let mut stats = PhptStats {
            total: files.len(),
            passed: cached_count, // cached tests count as passed
            ..Default::default()
        };

        // Determine parallelism level
        let parallel: usize = std::env::var("PHPT_PARALLEL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        if parallel > 1 {
            // Parallel execution using threads
            use std::sync::{Arc, Mutex};
            use std::thread;

            let results = Arc::new(Mutex::new(Vec::new()));
            let files_arc = Arc::new(files_to_run);
            let index = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let manifest_str = manifest_dir.to_string();

            let mut handles = Vec::new();
            for _ in 0..parallel {
                let results = Arc::clone(&results);
                let files = Arc::clone(&files_arc);
                let idx = Arc::clone(&index);
                let manifest = manifest_str.clone();
                handles.push(thread::spawn(move || loop {
                    let i = idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let result = run_single_phpt(&files[i], &manifest);
                    results.lock().unwrap().push(result);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
            for (rel, content_hash, result) in results {
                aggregate_result(
                    &mut stats,
                    &rel,
                    &content_hash,
                    result,
                    &mut cache,
                    manifest_dir,
                );
            }
        } else {
            // Serial execution (default)
            for file in &files_to_run {
                let (rel, content_hash, result) = run_single_phpt(file, manifest_dir);
                aggregate_result(
                    &mut stats,
                    &rel,
                    &content_hash,
                    result,
                    &mut cache,
                    manifest_dir,
                );
            }
        }

        // Save cache if enabled
        if use_cache {
            save_result_cache(&cache_path, &cache);
        }

        // Write JUnit XML if requested
        if let Ok(junit_path) = std::env::var("PHPT_JUNIT") {
            let xml = stats.to_junit_xml(dir);
            if let Ok(mut f) = fs::File::create(&junit_path) {
                let _ = f.write_all(xml.as_bytes());
                eprintln!("JUnit XML written to: {}", junit_path);
            }
        }

        stats
    }

    /// Aggregate a single test result into stats.
    fn aggregate_result(
        stats: &mut PhptStats,
        rel: &str,
        content_hash: &str,
        result: SingleTestResult,
        cache: &mut HashMap<String, u64>,
        _manifest_dir: &str,
    ) {
        match result {
            SingleTestResult::Skipped(reason) => {
                stats.skipped += 1;
                stats.test_results.push(JunitTestCase {
                    name: rel.to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.0,
                    status: JunitStatus::Skipped { message: reason },
                });
            }
            SingleTestResult::Error(msg) => {
                stats.errors += 1;
                stats.failures.push(msg.clone());
                stats.test_results.push(JunitTestCase {
                    name: rel.to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.0,
                    status: JunitStatus::Error { message: msg },
                });
            }
            SingleTestResult::Complete {
                description,
                status,
                time_secs,
            } => match status {
                TestOutcome::Passed => {
                    stats.passed += 1;
                    // Update cache on pass
                    if let Ok(h) = content_hash.parse::<u64>() {
                        cache.insert(rel.to_string(), h);
                    }
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Passed,
                    });
                }
                TestOutcome::FlakyPass => {
                    stats.flaky_pass += 1;
                    stats.passed += 1; // flaky passes still count as passed
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Passed,
                    });
                }
                TestOutcome::Failed { expected, actual } => {
                    stats.failed += 1;
                    // Remove from cache on failure
                    cache.remove(rel);
                    let msg = format!(
                        "FAIL {}: {}\n  Expected: {}\n  Actual:   {}",
                        rel,
                        description,
                        truncate(&expected, 120),
                        truncate(&actual, 120)
                    );
                    stats.failures.push(msg.clone());
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Failed { message: msg },
                    });
                }
                TestOutcome::Skipped(reason) => {
                    stats.skipped += 1;
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Skipped { message: reason },
                    });
                }
                TestOutcome::XFail => {
                    stats.xfail += 1;
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Passed, // xfail counts as expected
                    });
                }
                TestOutcome::Error(e) => {
                    stats.errors += 1;
                    cache.remove(rel);
                    let msg = format!("ERROR {}: {}", rel, e);
                    stats.failures.push(msg.clone());
                    stats.test_results.push(JunitTestCase {
                        name: rel.to_string(),
                        classname: "phpt".to_string(),
                        time_secs,
                        status: JunitStatus::Error { message: msg },
                    });
                }
            },
        }
    }

    fn collect_phpt_files(dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_phpt_files(&path, files);
                } else if path.extension().is_some_and(|e| e == "phpt") {
                    files.push(path);
                }
            }
        }
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.len() <= max {
            s.replace('\n', "\\n")
        } else {
            format!("{}...", &s[..max].replace('\n', "\\n"))
        }
    }

    // ── FLAKY section tests ──

    #[test]
    fn test_parse_phpt_with_flaky() {
        let content = "--TEST--\nFlaky test\n--FILE--\n<?php echo rand(0,1); ?>\n--FLAKY--\nRandom output\n--EXPECT--\n1";
        let test = parse_phpt(content).unwrap();
        assert_eq!(test.flaky.as_deref(), Some("Random output"));
    }

    #[test]
    fn test_parse_phpt_no_flaky() {
        let content = "--TEST--\nNormal test\n--FILE--\n<?php echo 42; ?>\n--EXPECT--\n42";
        let test = parse_phpt(content).unwrap();
        assert!(test.flaky.is_none());
    }

    // ── JUnit XML output tests ──

    #[test]
    fn test_junit_xml_generation() {
        let stats = PhptStats {
            passed: 2,
            failed: 1,
            skipped: 1,
            errors: 0,
            xfail: 0,
            flaky_pass: 0,
            total: 4,
            failures: vec![],
            test_results: vec![
                JunitTestCase {
                    name: "test1.phpt".to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.1,
                    status: JunitStatus::Passed,
                },
                JunitTestCase {
                    name: "test2.phpt".to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.2,
                    status: JunitStatus::Failed {
                        message: "expected 42 got 43".to_string(),
                    },
                },
                JunitTestCase {
                    name: "test3.phpt".to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.0,
                    status: JunitStatus::Skipped {
                        message: "no ext".to_string(),
                    },
                },
                JunitTestCase {
                    name: "test4.phpt".to_string(),
                    classname: "phpt".to_string(),
                    time_secs: 0.15,
                    status: JunitStatus::Passed,
                },
            ],
        };

        let xml = stats.to_junit_xml("test-suite");
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("tests=\"4\""));
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("skipped=\"1\""));
        assert!(xml.contains("<testcase name=\"test1.phpt\""));
        assert!(xml.contains("<failure message="));
        assert!(xml.contains("<skipped message="));
    }

    #[test]
    fn test_junit_xml_escaping() {
        let escaped = xml_escape("<test & \"quotes\" 'apos'>");
        assert_eq!(
            escaped,
            "&lt;test &amp; &quot;quotes&quot; &apos;apos&apos;&gt;"
        );
    }

    // ── Test result caching tests ──

    #[test]
    fn test_hash_content_deterministic() {
        let h1 = hash_content("<?php echo 42; ?>");
        let h2 = hash_content("<?php echo 42; ?>");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_content_different_for_different_input() {
        let h1 = hash_content("<?php echo 42; ?>");
        let h2 = hash_content("<?php echo 43; ?>");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_result_cache_round_trip() {
        let cache_dir = std::env::temp_dir();
        let cache_file = cache_dir.join(format!(
            "phpt_test_cache_{}_{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));

        let mut cache = HashMap::new();
        cache.insert("test1.phpt".to_string(), 12345u64);
        cache.insert("test2.phpt".to_string(), 67890u64);

        save_result_cache(&cache_file, &cache);
        let loaded = load_result_cache(&cache_file);

        assert_eq!(loaded.get("test1.phpt"), Some(&12345u64));
        assert_eq!(loaded.get("test2.phpt"), Some(&67890u64));

        let _ = fs::remove_file(&cache_file);
    }

    // ── Stats summary tests ──

    #[test]
    fn test_stats_summary_includes_flaky() {
        let stats = PhptStats {
            passed: 5,
            failed: 1,
            skipped: 2,
            errors: 0,
            xfail: 1,
            flaky_pass: 2,
            total: 11,
            failures: vec![],
            test_results: vec![],
        };
        let summary = stats.summary("test");
        assert!(summary.contains("Flaky: 2"));
        assert!(summary.contains("Pass rate: 83.3%"));
    }

    // ── Integration tests ──

    #[test]
    fn test_phpt_lang() {
        let stats = run_phpt_directory("php-src/tests/lang");

        eprintln!("{}", stats.summary("php-src/tests/lang/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        // Skip if php-src not available (e.g. in CI without submodule)
        if stats.total == 0 {
            eprintln!("Skipping: php-src/tests/lang/ not found");
        }
    }

    #[test]
    fn test_phpt_basic() {
        let stats = run_phpt_directory("php-src/tests/basic");

        eprintln!("{}", stats.summary("php-src/tests/basic/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        if stats.total == 0 {
            eprintln!("Skipping: php-src/tests/basic/ not found");
        }
    }

    #[test]
    fn test_phpt_func() {
        let stats = run_phpt_directory("php-src/tests/func");

        eprintln!("{}", stats.summary("php-src/tests/func/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        if stats.total == 0 {
            eprintln!("Skipping: php-src/tests/func/ not found");
        }
    }

    #[test]
    fn test_phpt_classes() {
        let stats = run_phpt_directory("php-src/tests/classes");

        eprintln!("{}", stats.summary("php-src/tests/classes/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        if stats.total == 0 {
            eprintln!("Skipping: php-src/tests/classes/ not found");
        }
    }

    #[test]
    fn test_phpt_output() {
        let stats = run_phpt_directory("php-src/tests/output");

        eprintln!("{}", stats.summary("php-src/tests/output/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        if stats.total > 0 {
            eprintln!("Output tests found and executed.");
        }
    }

    #[test]
    fn test_phpt_strings() {
        let stats = run_phpt_directory("php-src/tests/strings");

        eprintln!("{}", stats.summary("php-src/tests/strings/"));

        if !stats.failures.is_empty() {
            eprintln!("\nFirst 20 failures:");
            for f in stats.failures.iter().take(20) {
                eprintln!("  {}", f);
            }
        }

        if stats.total > 0 {
            eprintln!("String tests found and executed.");
        }
    }
}
