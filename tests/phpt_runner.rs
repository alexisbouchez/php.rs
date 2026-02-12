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
}
