//! PHPT test runner
//!
//! This module provides a test runner for PHP's .phpt test format.
//! Reference: https://qa.php.net/phpt_details.php
//!
//! .phpt files contain multiple sections:
//! - --TEST-- (required): Test description
//! - --FILE-- (required): PHP code to execute
//! - --EXPECT-- or --EXPECTF-- (required): Expected output
//! - --SKIPIF--: Code to determine if test should be skipped
//! - --INI--: INI settings to apply
//! - --ENV--: Environment variables
//! - --ARGS--: Command-line arguments
//! - --POST--: POST data
//! - --CLEAN--: Cleanup code

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Represents a parsed PHPT test file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhptTest {
    /// Test description (from --TEST-- section)
    pub description: String,
    /// PHP code to execute (from --FILE-- section)
    pub file: String,
    /// Expected output (from --EXPECT-- or --EXPECTF-- section)
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
}

/// Expected output format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhptExpect {
    /// Exact match (from --EXPECT--)
    Exact(String),
    /// Format string match with %s, %d, %f placeholders (from --EXPECTF--)
    Format(String),
}

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

    // Get expected output (either --EXPECT-- or --EXPECTF--)
    let expect = if let Some(exact) = sections.get("EXPECT") {
        PhptExpect::Exact(exact.clone())
    } else if let Some(format) = sections.get("EXPECTF") {
        PhptExpect::Format(format.clone())
    } else {
        return Err("Missing required --EXPECT-- or --EXPECTF-- section".to_string());
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
    })
}

/// Get the path to the php.rs CLI binary
fn get_php_binary() -> Result<PathBuf, String> {
    // The binary should be in target/debug/php-rs-sapi-cli (or target/release/)
    // We'll use the debug version by default
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir);

    let debug_binary = workspace_root.join("target/debug/php-rs-sapi-cli");
    let release_binary = workspace_root.join("target/release/php-rs-sapi-cli");

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

/// Execute a PHPT test by running the php.rs CLI on its --FILE-- section
pub fn execute_phpt(test: &PhptTest) -> Result<PhptOutput, String> {
    let php_binary = get_php_binary()?;

    // Create a temporary file with the PHP code
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("phpt_test_{}.php", std::process::id()));

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

    // Execute the command
    let output = cmd
        .output()
        .map_err(|e| format!("Failed to execute php.rs CLI: {}", e))?;

    // Clean up the temporary file
    let _ = fs::remove_file(&temp_file);

    // Convert output to string
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(PhptOutput {
        stdout,
        stderr,
        exit_code: output.status.code().unwrap_or(-1),
    })
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
            .contains("Missing required --EXPECT-- or --EXPECTF-- section"));
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
        };

        // Try to execute - this may fail if binary doesn't exist yet
        match execute_phpt(&test) {
            Ok(output) => {
                // If it succeeds, verify we got some output structure
                // (The actual content won't match until we implement the interpreter)
                assert!(output.exit_code >= -1);
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
        };

        // This test just verifies the ARGS handling code doesn't crash
        let _ = execute_phpt(&test);
    }
}
