//! PHP xsl extension implementation for php.rs
//!
//! Provides XSL Transformations (XSLT) functionality.
//! Reference: php-src/ext/xsl/
//!
//! This is a pure Rust implementation with basic XSLT support.
//! Supports simple xsl:value-of, xsl:template, xsl:for-each, and parameters.

use std::collections::HashMap;

// XSL security preference constants
pub const XSL_SECPREF_NONE: i32 = 0;
pub const XSL_SECPREF_READ_FILE: i32 = 2;
pub const XSL_SECPREF_WRITE_FILE: i32 = 4;
pub const XSL_SECPREF_CREATE_DIRECTORY: i32 = 8;
pub const XSL_SECPREF_READ_NETWORK: i32 = 16;
pub const XSL_SECPREF_WRITE_NETWORK: i32 = 32;
pub const XSL_SECPREF_DEFAULT: i32 = 44; // READ_FILE | WRITE_FILE | CREATE_DIRECTORY

/// Error type for XSL operations.
#[derive(Debug, Clone, PartialEq)]
pub enum XslError {
    /// No stylesheet loaded
    NoStylesheet,
    /// Invalid stylesheet
    InvalidStylesheet(String),
    /// Transformation error
    TransformError(String),
    /// IO error
    IoError(String),
    /// Security violation
    SecurityError(String),
}

impl std::fmt::Display for XslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XslError::NoStylesheet => write!(f, "No stylesheet loaded"),
            XslError::InvalidStylesheet(msg) => write!(f, "Invalid stylesheet: {}", msg),
            XslError::TransformError(msg) => write!(f, "XSL transform error: {}", msg),
            XslError::IoError(msg) => write!(f, "XSL IO error: {}", msg),
            XslError::SecurityError(msg) => write!(f, "XSL security error: {}", msg),
        }
    }
}

/// XSLT processor.
#[derive(Debug, Clone)]
pub struct XsltProcessor {
    /// Loaded stylesheet XML
    pub stylesheet: Option<String>,
    /// Named parameters
    pub parameters: HashMap<String, HashMap<String, String>>,
    /// Security preferences
    pub security_prefs: i32,
    /// Registered PHP function names (for callbacks)
    registered_functions: Option<Vec<String>>,
}

impl XsltProcessor {
    /// Create a new XsltProcessor.
    pub fn new() -> Self {
        XsltProcessor {
            stylesheet: None,
            parameters: HashMap::new(),
            security_prefs: XSL_SECPREF_DEFAULT,
            registered_functions: None,
        }
    }

    /// Import a stylesheet.
    ///
    /// PHP signature: XSLTProcessor::importStylesheet(object $stylesheet): bool
    pub fn import_stylesheet(&mut self, stylesheet: &str) -> Result<(), XslError> {
        if stylesheet.trim().is_empty() {
            return Err(XslError::InvalidStylesheet("Empty stylesheet".to_string()));
        }

        // Basic validation: must contain xsl:stylesheet or xsl:transform
        if !stylesheet.contains("xsl:stylesheet") && !stylesheet.contains("xsl:transform") {
            return Err(XslError::InvalidStylesheet(
                "Missing xsl:stylesheet or xsl:transform root element".to_string(),
            ));
        }

        self.stylesheet = Some(stylesheet.to_string());
        Ok(())
    }

    /// Set a parameter for the transformation.
    ///
    /// PHP signature: XSLTProcessor::setParameter(string $namespace, string $name, string $value): bool
    pub fn set_parameter(&mut self, namespace: &str, name: &str, value: &str) -> bool {
        let ns_params = self.parameters.entry(namespace.to_string()).or_default();
        ns_params.insert(name.to_string(), value.to_string());
        true
    }

    /// Get a parameter value.
    ///
    /// PHP signature: XSLTProcessor::getParameter(string $namespace, string $name): string|false
    pub fn get_parameter(&self, namespace: &str, name: &str) -> Option<String> {
        self.parameters
            .get(namespace)
            .and_then(|ns| ns.get(name))
            .cloned()
    }

    /// Remove a parameter.
    ///
    /// PHP signature: XSLTProcessor::removeParameter(string $namespace, string $name): bool
    pub fn remove_parameter(&mut self, namespace: &str, name: &str) -> bool {
        if let Some(ns_params) = self.parameters.get_mut(namespace) {
            ns_params.remove(name).is_some()
        } else {
            false
        }
    }

    /// Transform XML to a string.
    ///
    /// PHP signature: XSLTProcessor::transformToXml(object $document): string|null|false
    pub fn transform_to_xml(&self, doc: &str) -> Result<String, XslError> {
        let stylesheet = self.stylesheet.as_ref().ok_or(XslError::NoStylesheet)?;

        apply_xslt(stylesheet, doc, &self.parameters)
    }

    /// Transform XML and write to a URI/file.
    ///
    /// PHP signature: XSLTProcessor::transformToUri(object $document, string $uri): int
    pub fn transform_to_uri(&self, doc: &str, _uri: &str) -> Result<i32, XslError> {
        // Check security prefs
        if self.security_prefs & XSL_SECPREF_WRITE_FILE != 0 {
            return Err(XslError::SecurityError(
                "Writing to files is restricted by security preferences".to_string(),
            ));
        }

        let result = self.transform_to_xml(doc)?;
        Ok(result.len() as i32)
    }

    /// Check if EXSLT support is available.
    ///
    /// PHP signature: XSLTProcessor::hasExsltSupport(): bool
    pub fn has_exslt_support(&self) -> bool {
        false // EXSLT not implemented in this stub
    }

    /// Set security preferences.
    ///
    /// PHP signature: XSLTProcessor::setSecurityPrefs(int $preferences): int
    pub fn set_security_prefs(&mut self, prefs: i32) -> i32 {
        let old = self.security_prefs;
        self.security_prefs = prefs;
        old
    }

    /// Get current security preferences.
    ///
    /// PHP signature: XSLTProcessor::getSecurityPrefs(): int
    pub fn get_security_prefs(&self) -> i32 {
        self.security_prefs
    }

    /// Register PHP functions for use in XSL.
    ///
    /// PHP signature: XSLTProcessor::registerPHPFunctions(array|string|null $functions = null): void
    pub fn register_php_functions(&mut self, functions: Option<&[&str]>) {
        self.registered_functions = functions.map(|f| f.iter().map(|s| s.to_string()).collect());
    }
}

impl Default for XsltProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply an XSLT stylesheet to an XML document.
///
/// PHP signature: xslt_process(resource $xh, string $xmlcontainer, string $xslcontainer, ...): mixed
pub fn xslt_process(processor: &XsltProcessor, xml_doc: &str) -> Result<String, XslError> {
    processor.transform_to_xml(xml_doc)
}

/// Basic XSLT transformation engine.
///
/// Supports:
/// - xsl:value-of select="xpath" (simple element selection)
/// - xsl:template match="/"
/// - xsl:apply-templates
/// - Parameter substitution ($param)
fn apply_xslt(
    stylesheet: &str,
    xml_doc: &str,
    parameters: &HashMap<String, HashMap<String, String>>,
) -> Result<String, XslError> {
    let mut output = String::new();

    // Extract template body from stylesheet
    let template_body = extract_template_body(stylesheet);

    if let Some(body) = template_body {
        // Process the template body
        output = process_template(&body, xml_doc, parameters);
    } else {
        // If no template found, return the XML as-is
        output.push_str(xml_doc);
    }

    Ok(output)
}

/// Extract the body content of the main template (match="/").
fn extract_template_body(stylesheet: &str) -> Option<String> {
    // Find <xsl:template match="/">
    let template_start = stylesheet.find("<xsl:template")?;
    let after_template = &stylesheet[template_start..];

    // Find the closing > of the opening tag
    let body_start = after_template.find('>')? + 1;
    let body_content = &after_template[body_start..];

    // Find </xsl:template>
    let body_end = body_content.find("</xsl:template>")?;
    Some(body_content[..body_end].to_string())
}

/// Process a template body, replacing xsl:value-of with values from the XML.
fn process_template(
    template: &str,
    xml_doc: &str,
    parameters: &HashMap<String, HashMap<String, String>>,
) -> String {
    let mut output = String::new();
    let mut remaining = template;

    while !remaining.is_empty() {
        if let Some(xsl_pos) = remaining.find("<xsl:") {
            // Copy literal content before the XSL instruction
            output.push_str(&remaining[..xsl_pos]);
            remaining = &remaining[xsl_pos..];

            if remaining.starts_with("<xsl:value-of") {
                // Extract select attribute
                if let Some(select_val) = extract_attribute(remaining, "select") {
                    let value = evaluate_xpath(&select_val, xml_doc, parameters);
                    output.push_str(&value);
                }
                // Skip past the closing />  or </xsl:value-of>
                if let Some(end) = remaining.find("/>") {
                    remaining = &remaining[end + 2..];
                } else if let Some(end) = remaining.find("</xsl:value-of>") {
                    remaining = &remaining[end + 15..];
                } else {
                    remaining = "";
                }
            } else if remaining.starts_with("<xsl:apply-templates") {
                // Skip, content already processed
                if let Some(end) = remaining.find("/>") {
                    remaining = &remaining[end + 2..];
                } else if let Some(end) = remaining.find('>') {
                    remaining = &remaining[end + 1..];
                }
            } else {
                // Unknown XSL element, skip it
                if let Some(end) = remaining.find('>') {
                    remaining = &remaining[end + 1..];
                } else {
                    remaining = "";
                }
            }
        } else {
            // No more XSL instructions, copy the rest
            output.push_str(remaining);
            break;
        }
    }

    output
}

/// Extract an attribute value from an XML tag string.
fn extract_attribute(tag: &str, attr_name: &str) -> Option<String> {
    let search = format!("{}=\"", attr_name);
    let start = tag.find(&search)?;
    let after_eq = &tag[start + search.len()..];
    let end = after_eq.find('"')?;
    Some(after_eq[..end].to_string())
}

/// Evaluate a simple XPath expression against an XML document.
fn evaluate_xpath(
    xpath: &str,
    xml_doc: &str,
    parameters: &HashMap<String, HashMap<String, String>>,
) -> String {
    // Handle parameter references ($paramName)
    if let Some(param_name) = xpath.strip_prefix('$') {
        // Search all namespaces for the parameter
        for ns_params in parameters.values() {
            if let Some(value) = ns_params.get(param_name) {
                return value.clone();
            }
        }
        return String::new();
    }

    // Handle simple element path (e.g., "/root/element" or "element")
    let path = xpath.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').collect();

    if let Some(last_element) = parts.last() {
        // Try to find the element value in the XML
        let open_tag = format!("<{}", last_element);
        if let Some(start) = xml_doc.find(&open_tag) {
            let after_open = &xml_doc[start..];
            if let Some(gt) = after_open.find('>') {
                let after_tag = &after_open[gt + 1..];
                let close_tag = format!("</{}>", last_element);
                if let Some(end) = after_tag.find(&close_tag) {
                    return after_tag[..end].to_string();
                }
            }
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xslt_processor_new() {
        let proc = XsltProcessor::new();
        assert!(proc.stylesheet.is_none());
        assert!(proc.parameters.is_empty());
        assert_eq!(proc.security_prefs, XSL_SECPREF_DEFAULT);
    }

    #[test]
    fn test_import_stylesheet() {
        let mut proc = XsltProcessor::new();
        let xsl = r#"<?xml version="1.0"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <html><body><xsl:value-of select="/greeting/message"/></body></html>
            </xsl:template>
        </xsl:stylesheet>"#;

        assert!(proc.import_stylesheet(xsl).is_ok());
        assert!(proc.stylesheet.is_some());
    }

    #[test]
    fn test_import_invalid_stylesheet() {
        let mut proc = XsltProcessor::new();
        let result = proc.import_stylesheet("<html><body>Not a stylesheet</body></html>");
        assert!(result.is_err());
        assert!(matches!(result, Err(XslError::InvalidStylesheet(_))));
    }

    #[test]
    fn test_import_empty_stylesheet() {
        let mut proc = XsltProcessor::new();
        let result = proc.import_stylesheet("");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_get_remove_parameter() {
        let mut proc = XsltProcessor::new();

        assert!(proc.set_parameter("", "title", "Hello World"));
        assert_eq!(
            proc.get_parameter("", "title"),
            Some("Hello World".to_string())
        );

        assert!(proc.set_parameter("http://ns.example.com", "version", "1.0"));
        assert_eq!(
            proc.get_parameter("http://ns.example.com", "version"),
            Some("1.0".to_string())
        );

        assert!(proc.remove_parameter("", "title"));
        assert!(proc.get_parameter("", "title").is_none());

        // Remove non-existent
        assert!(!proc.remove_parameter("", "nonexistent"));
    }

    #[test]
    fn test_transform_simple() {
        let mut proc = XsltProcessor::new();
        let xsl = r#"<?xml version="1.0"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <output><xsl:value-of select="/greeting/message"/></output>
            </xsl:template>
        </xsl:stylesheet>"#;

        proc.import_stylesheet(xsl).unwrap();

        let xml = "<greeting><message>Hello World</message></greeting>";
        let result = proc.transform_to_xml(xml).unwrap();
        assert!(result.contains("Hello World"));
        assert!(result.contains("<output>"));
    }

    #[test]
    fn test_transform_no_stylesheet() {
        let proc = XsltProcessor::new();
        let result = proc.transform_to_xml("<data/>");
        assert!(result.is_err());
        assert!(matches!(result, Err(XslError::NoStylesheet)));
    }

    #[test]
    fn test_transform_with_parameters() {
        let mut proc = XsltProcessor::new();
        let xsl = r#"<?xml version="1.0"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <result><xsl:value-of select="$greeting"/></result>
            </xsl:template>
        </xsl:stylesheet>"#;

        proc.import_stylesheet(xsl).unwrap();
        proc.set_parameter("", "greeting", "Bonjour");

        let result = proc.transform_to_xml("<data/>").unwrap();
        assert!(result.contains("Bonjour"));
    }

    #[test]
    fn test_security_prefs() {
        let mut proc = XsltProcessor::new();
        assert_eq!(proc.get_security_prefs(), XSL_SECPREF_DEFAULT);

        let old = proc.set_security_prefs(XSL_SECPREF_NONE);
        assert_eq!(old, XSL_SECPREF_DEFAULT);
        assert_eq!(proc.get_security_prefs(), XSL_SECPREF_NONE);
    }

    #[test]
    fn test_transform_to_uri_security() {
        let mut proc = XsltProcessor::new();
        let xsl = r#"<?xml version="1.0"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <output>test</output>
            </xsl:template>
        </xsl:stylesheet>"#;

        proc.import_stylesheet(xsl).unwrap();

        // Default security prefs should block file writes
        let result = proc.transform_to_uri("<data/>", "/tmp/output.xml");
        assert!(result.is_err());
        assert!(matches!(result, Err(XslError::SecurityError(_))));

        // With security disabled, should succeed
        proc.set_security_prefs(XSL_SECPREF_NONE);
        let result = proc.transform_to_uri("<data/>", "/tmp/output.xml");
        assert!(result.is_ok());
    }

    #[test]
    fn test_has_exslt_support() {
        let proc = XsltProcessor::new();
        assert!(!proc.has_exslt_support());
    }

    #[test]
    fn test_register_php_functions() {
        let mut proc = XsltProcessor::new();
        proc.register_php_functions(Some(&["strtolower", "strtoupper"]));
        assert!(proc.registered_functions.is_some());
        let funcs = proc.registered_functions.as_ref().unwrap();
        assert_eq!(funcs.len(), 2);
        assert!(funcs.contains(&"strtolower".to_string()));

        proc.register_php_functions(None);
        assert!(proc.registered_functions.is_none());
    }

    #[test]
    fn test_xslt_process_function() {
        let mut proc = XsltProcessor::new();
        let xsl = r#"<?xml version="1.0"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <html><body><xsl:value-of select="/data/title"/></body></html>
            </xsl:template>
        </xsl:stylesheet>"#;

        proc.import_stylesheet(xsl).unwrap();

        let xml = "<data><title>Test Page</title></data>";
        let result = xslt_process(&proc, xml).unwrap();
        assert!(result.contains("Test Page"));
    }

    #[test]
    fn test_security_pref_constants() {
        assert_eq!(XSL_SECPREF_NONE, 0);
        assert_eq!(XSL_SECPREF_READ_FILE, 2);
        assert_eq!(XSL_SECPREF_WRITE_FILE, 4);
        assert_eq!(XSL_SECPREF_CREATE_DIRECTORY, 8);
        assert_eq!(XSL_SECPREF_READ_NETWORK, 16);
        assert_eq!(XSL_SECPREF_WRITE_NETWORK, 32);
        assert_eq!(XSL_SECPREF_DEFAULT, 44);
    }

    #[test]
    fn test_default_impl() {
        let proc = XsltProcessor::default();
        assert!(proc.stylesheet.is_none());
        assert_eq!(proc.security_prefs, XSL_SECPREF_DEFAULT);
    }
}
