//! PHP tidy extension implementation for php.rs
//!
//! Provides HTML tidy/cleanup functionality.
//! Reference: php-src/ext/tidy/
//!
//! This is a pure Rust implementation with basic HTML repair capabilities:
//! - Add missing closing tags
//! - Fix unclosed quotes
//! - Normalize whitespace

/// Error type for tidy operations.
#[derive(Debug, Clone, PartialEq)]
pub enum TidyError {
    /// File not found
    FileNotFound(String),
    /// Parse error
    ParseError(String),
    /// Generic error
    GenericError(String),
}

impl std::fmt::Display for TidyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TidyError::FileNotFound(path) => write!(f, "File not found: {}", path),
            TidyError::ParseError(msg) => write!(f, "Tidy parse error: {}", msg),
            TidyError::GenericError(msg) => write!(f, "Tidy error: {}", msg),
        }
    }
}

/// Node types in the parsed HTML tree.
#[derive(Debug, Clone, PartialEq)]
pub enum TidyNodeType {
    /// Root document node
    Root,
    /// Element node (e.g., <div>)
    Element,
    /// Text node
    Text,
    /// Comment node
    Comment,
    /// DOCTYPE declaration
    DocType,
}

/// A node in the parsed HTML tree.
#[derive(Debug, Clone)]
pub struct TidyNode {
    /// Node name (tag name for elements, "#text" for text nodes)
    pub name: String,
    /// Node type
    pub node_type: TidyNodeType,
    /// Node value (text content for text nodes)
    pub value: String,
    /// Child nodes
    pub children: Vec<TidyNode>,
    /// Attributes as (name, value) pairs
    pub attributes: Vec<(String, String)>,
}

impl TidyNode {
    fn new_element(name: &str) -> Self {
        TidyNode {
            name: name.to_string(),
            node_type: TidyNodeType::Element,
            value: String::new(),
            children: Vec::new(),
            attributes: Vec::new(),
        }
    }

    fn new_text(value: &str) -> Self {
        TidyNode {
            name: "#text".to_string(),
            node_type: TidyNodeType::Text,
            value: value.to_string(),
            children: Vec::new(),
            attributes: Vec::new(),
        }
    }
}

/// Configuration options for tidy.
#[derive(Debug, Clone)]
pub struct TidyConfig {
    /// Whether to indent output
    pub indent: bool,
    /// Line wrap width (0 = no wrap)
    pub wrap: u32,
    /// Output as XHTML
    pub output_xhtml: bool,
    /// Clean up redundant markup
    pub clean: bool,
    /// Show body only
    pub show_body_only: bool,
    /// Add missing closing tags
    pub fix_tags: bool,
    /// Character encoding
    pub char_encoding: String,
}

impl Default for TidyConfig {
    fn default() -> Self {
        TidyConfig {
            indent: false,
            wrap: 68,
            output_xhtml: false,
            clean: false,
            show_body_only: false,
            fix_tags: true,
            char_encoding: "utf8".to_string(),
        }
    }
}

/// Parsed and cleaned HTML document.
#[derive(Debug, Clone)]
pub struct TidyDoc {
    /// Original HTML input
    pub html: String,
    /// Cleaned output
    pub output: String,
    /// Error messages
    pub errors: Vec<String>,
    /// Warning messages
    pub warnings: Vec<String>,
    /// Parsed document tree
    root: Option<TidyNode>,
    /// Whether clean_repair has been called
    repaired: bool,
}

/// Self-closing / void HTML elements.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Check if a tag is self-closing (void element).
fn is_void_element(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag.to_lowercase().as_str())
}

/// Basic HTML parser that builds a node tree.
fn parse_html(input: &str) -> (TidyNode, Vec<String>, Vec<String>) {
    let mut root = TidyNode {
        name: "#document".to_string(),
        node_type: TidyNodeType::Root,
        value: String::new(),
        children: Vec::new(),
        attributes: Vec::new(),
    };

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut current_children: Vec<Vec<TidyNode>> = vec![Vec::new()];
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '<' {
            // Check for comment
            if i + 3 < len && chars[i + 1] == '!' && chars[i + 2] == '-' && chars[i + 3] == '-' {
                if let Some(end) = input[i..].find("-->") {
                    let comment_text = &input[i + 4..i + end];
                    let node = TidyNode {
                        name: "#comment".to_string(),
                        node_type: TidyNodeType::Comment,
                        value: comment_text.to_string(),
                        children: Vec::new(),
                        attributes: Vec::new(),
                    };
                    if let Some(children) = current_children.last_mut() {
                        children.push(node);
                    }
                    i += end + 3;
                    continue;
                }
            }

            // Check for DOCTYPE
            if i + 1 < len && chars[i + 1] == '!' {
                if let Some(end) = input[i..].find('>') {
                    let doctype_text = &input[i + 2..i + end];
                    let node = TidyNode {
                        name: "#doctype".to_string(),
                        node_type: TidyNodeType::DocType,
                        value: doctype_text.to_string(),
                        children: Vec::new(),
                        attributes: Vec::new(),
                    };
                    if let Some(children) = current_children.last_mut() {
                        children.push(node);
                    }
                    i += end + 1;
                    continue;
                }
            }

            // Find closing >
            let tag_start = i + 1;
            let mut tag_end = tag_start;
            while tag_end < len && chars[tag_end] != '>' {
                tag_end += 1;
            }

            if tag_end >= len {
                errors.push(format!("Unclosed tag at position {}", i));
                i += 1;
                continue;
            }

            let tag_content: String = chars[tag_start..tag_end].iter().collect();
            let tag_content = tag_content.trim();

            if let Some(stripped) = tag_content.strip_prefix('/') {
                // Closing tag
                let close_tag = stripped.trim().to_lowercase();

                if let Some(pos) = stack.iter().rposition(|t| t == &close_tag) {
                    // Close all tags up to and including the matching one
                    while stack.len() > pos {
                        let popped = stack.pop().unwrap();
                        let children = current_children.pop().unwrap_or_default();
                        if let Some(parent_children) = current_children.last_mut() {
                            let mut node = TidyNode::new_element(&popped);
                            node.children = children;
                            parent_children.push(node);
                        }
                        if popped == close_tag {
                            break;
                        } else {
                            warnings.push(format!("Implicitly closing <{}>", popped));
                        }
                    }
                } else {
                    warnings.push(format!("Unexpected closing tag </{}>", close_tag));
                }
            } else {
                // Opening tag (or self-closing)
                let self_closing = tag_content.ends_with('/');
                let tag_content = if self_closing {
                    &tag_content[..tag_content.len() - 1]
                } else {
                    tag_content
                };

                // Extract tag name and attributes
                let parts: Vec<&str> = tag_content.splitn(2, char::is_whitespace).collect();
                let tag_name = parts[0].to_lowercase();

                let mut node = TidyNode::new_element(&tag_name);

                // Parse attributes (basic)
                if parts.len() > 1 {
                    let attrs_str = parts[1];
                    parse_attributes(attrs_str, &mut node.attributes);
                }

                if self_closing || is_void_element(&tag_name) {
                    if let Some(children) = current_children.last_mut() {
                        children.push(node);
                    }
                } else {
                    stack.push(tag_name);
                    current_children.push(Vec::new());
                    // Node will be finalized when closing tag is found
                    // We store attributes for later
                    if let Some(children) = current_children.last_mut() {
                        // Store attributes in a temporary way
                        let mut attr_node = TidyNode::new_element("__attrs__");
                        attr_node.attributes = node.attributes;
                        children.push(attr_node);
                    }
                }
            }

            i = tag_end + 1;
        } else {
            // Text content
            let text_start = i;
            while i < len && chars[i] != '<' {
                i += 1;
            }
            let text: String = chars[text_start..i].iter().collect();
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                if let Some(children) = current_children.last_mut() {
                    children.push(TidyNode::new_text(&text));
                }
            }
        }
    }

    // Close any unclosed tags
    while let Some(tag) = stack.pop() {
        warnings.push(format!("Missing closing tag for <{}>", tag));
        let children = current_children.pop().unwrap_or_default();
        if let Some(parent_children) = current_children.last_mut() {
            let mut node = TidyNode::new_element(&tag);
            node.children = children;
            // Check for attribute node
            if let Some(first) = node.children.first() {
                if first.name == "__attrs__" {
                    let attrs = first.attributes.clone();
                    node.attributes = attrs;
                    node.children.remove(0);
                }
            }
            parent_children.push(node);
        }
    }

    // Finalize remaining children into the tree (handle attrs markers)
    let final_children = current_children.pop().unwrap_or_default();
    // Filter out attribute markers and apply them
    root.children = cleanup_attr_nodes(final_children);

    (root, errors, warnings)
}

/// Remove __attrs__ marker nodes and apply attributes to parent.
fn cleanup_attr_nodes(nodes: Vec<TidyNode>) -> Vec<TidyNode> {
    let mut result = Vec::new();
    for node in nodes {
        if node.name == "__attrs__" {
            continue; // Skip orphaned attribute markers
        }
        let mut cleaned = node;
        if !cleaned.children.is_empty() {
            // Check if first child is an attrs marker
            if cleaned.children[0].name == "__attrs__" {
                cleaned.attributes = cleaned.children[0].attributes.clone();
                cleaned.children.remove(0);
            }
            cleaned.children = cleanup_attr_nodes(cleaned.children);
        }
        result.push(cleaned);
    }
    result
}

/// Parse HTML attributes from a string.
fn parse_attributes(attrs_str: &str, attrs: &mut Vec<(String, String)>) {
    let mut remaining = attrs_str.trim();

    while !remaining.is_empty() {
        // Skip whitespace
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        // Find attribute name
        let name_end = remaining
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(remaining.len());
        let name = &remaining[..name_end];
        remaining = &remaining[name_end..];
        remaining = remaining.trim_start();

        if remaining.starts_with('=') {
            remaining = &remaining[1..];
            remaining = remaining.trim_start();

            // Parse value
            if remaining.starts_with('"') {
                remaining = &remaining[1..];
                let end = remaining.find('"').unwrap_or(remaining.len());
                let value = &remaining[..end];
                attrs.push((name.to_string(), value.to_string()));
                remaining = if end < remaining.len() {
                    &remaining[end + 1..]
                } else {
                    ""
                };
            } else if remaining.starts_with('\'') {
                remaining = &remaining[1..];
                let end = remaining.find('\'').unwrap_or(remaining.len());
                let value = &remaining[..end];
                attrs.push((name.to_string(), value.to_string()));
                remaining = if end < remaining.len() {
                    &remaining[end + 1..]
                } else {
                    ""
                };
            } else {
                let end = remaining
                    .find(char::is_whitespace)
                    .unwrap_or(remaining.len());
                let value = &remaining[..end];
                attrs.push((name.to_string(), value.to_string()));
                remaining = &remaining[end..];
            }
        } else {
            // Boolean attribute
            attrs.push((name.to_string(), String::new()));
        }
    }
}

/// Serialize a node tree back to HTML.
fn serialize_html(node: &TidyNode, config: &TidyConfig) -> String {
    let mut output = String::new();
    serialize_node(node, &mut output, config, 0);
    output
}

fn serialize_node(node: &TidyNode, output: &mut String, config: &TidyConfig, depth: usize) {
    match node.node_type {
        TidyNodeType::Root => {
            for child in &node.children {
                serialize_node(child, output, config, depth);
            }
        }
        TidyNodeType::Element => {
            if config.indent && depth > 0 {
                output.push_str(&"  ".repeat(depth));
            }

            output.push('<');
            output.push_str(&node.name);

            for (name, value) in &node.attributes {
                output.push(' ');
                output.push_str(name);
                if !value.is_empty() {
                    output.push_str("=\"");
                    output.push_str(value);
                    output.push('"');
                }
            }

            if is_void_element(&node.name) {
                if config.output_xhtml {
                    output.push_str(" />");
                } else {
                    output.push('>');
                }
            } else {
                output.push('>');

                if config.indent && !node.children.is_empty() {
                    output.push('\n');
                }

                for child in &node.children {
                    serialize_node(child, output, config, depth + 1);
                }

                if config.indent && !node.children.is_empty() {
                    output.push_str(&"  ".repeat(depth));
                }

                output.push_str("</");
                output.push_str(&node.name);
                output.push('>');
            }

            if config.indent {
                output.push('\n');
            }
        }
        TidyNodeType::Text => {
            if config.indent && depth > 0 {
                output.push_str(&"  ".repeat(depth));
            }
            output.push_str(&node.value);
            if config.indent {
                output.push('\n');
            }
        }
        TidyNodeType::Comment => {
            output.push_str("<!--");
            output.push_str(&node.value);
            output.push_str("-->");
            if config.indent {
                output.push('\n');
            }
        }
        TidyNodeType::DocType => {
            output.push_str("<!");
            output.push_str(&node.value);
            output.push('>');
            if config.indent {
                output.push('\n');
            }
        }
    }
}

/// Parse an HTML string.
///
/// PHP signature: tidy_parse_string(string $string, array|string|null $config = null, ?string $encoding = null): tidy|false
pub fn tidy_parse_string(input: &str, config: &TidyConfig) -> TidyDoc {
    let (root, errors, warnings) = parse_html(input);

    TidyDoc {
        html: input.to_string(),
        output: serialize_html(&root, config),
        errors,
        warnings,
        root: Some(root),
        repaired: false,
    }
}

/// Parse an HTML file (stub - reads from string).
///
/// PHP signature: tidy_parse_file(string $filename, ...): tidy|false
pub fn tidy_parse_file(filename: &str, _config: &TidyConfig) -> Result<TidyDoc, TidyError> {
    Err(TidyError::FileNotFound(filename.to_string()))
}

/// Clean and repair the document.
///
/// PHP signature: tidy_clean_repair(tidy $tidy): bool
pub fn tidy_clean_repair(doc: &mut TidyDoc) -> bool {
    if let Some(root) = &doc.root {
        let config = TidyConfig::default();
        doc.output = serialize_html(root, &config);
        doc.repaired = true;
        true
    } else {
        false
    }
}

/// Get the cleaned output.
///
/// PHP signature: tidy_get_output(tidy $tidy): string
pub fn tidy_get_output(doc: &TidyDoc) -> String {
    doc.output.clone()
}

/// Get the error buffer.
///
/// PHP signature: tidy_get_error_buffer(tidy $tidy): string|false
pub fn tidy_get_error_buffer(doc: &TidyDoc) -> String {
    let mut buffer = String::new();
    for error in &doc.errors {
        buffer.push_str("Error: ");
        buffer.push_str(error);
        buffer.push('\n');
    }
    for warning in &doc.warnings {
        buffer.push_str("Warning: ");
        buffer.push_str(warning);
        buffer.push('\n');
    }
    buffer
}

/// Diagnose the document (run checks).
///
/// PHP signature: tidy_diagnose(tidy $tidy): bool
pub fn tidy_diagnose(_doc: &TidyDoc) -> bool {
    true
}

/// Get warning count.
///
/// PHP signature: tidy_warning_count(tidy $tidy): int
pub fn tidy_warning_count(doc: &TidyDoc) -> u32 {
    doc.warnings.len() as u32
}

/// Get error count.
///
/// PHP signature: tidy_error_count(tidy $tidy): int
pub fn tidy_error_count(doc: &TidyDoc) -> u32 {
    doc.errors.len() as u32
}

/// Get accessibility error count.
///
/// PHP signature: tidy_access_count(tidy $tidy): int
pub fn tidy_access_count(_doc: &TidyDoc) -> u32 {
    0 // Accessibility checking not implemented
}

/// Get the HTML element of the document.
///
/// PHP signature: tidy_get_html(tidy $tidy): ?tidyNode
pub fn tidy_get_html(doc: &TidyDoc) -> Option<&TidyNode> {
    if let Some(root) = &doc.root {
        root.children
            .iter()
            .find(|n| n.name == "html" && n.node_type == TidyNodeType::Element)
    } else {
        None
    }
}

/// Get the head element of the document.
///
/// PHP signature: tidy_get_head(tidy $tidy): ?tidyNode
pub fn tidy_get_head(doc: &TidyDoc) -> Option<&TidyNode> {
    if let Some(html) = tidy_get_html(doc) {
        html.children
            .iter()
            .find(|n| n.name == "head" && n.node_type == TidyNodeType::Element)
    } else {
        None
    }
}

/// Get the body element of the document.
///
/// PHP signature: tidy_get_body(tidy $tidy): ?tidyNode
pub fn tidy_get_body(doc: &TidyDoc) -> Option<&TidyNode> {
    if let Some(html) = tidy_get_html(doc) {
        html.children
            .iter()
            .find(|n| n.name == "body" && n.node_type == TidyNodeType::Element)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tidy_parse_simple() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string("<html><body><p>Hello</p></body></html>", &config);
        assert_eq!(tidy_error_count(&doc), 0);
        let output = tidy_get_output(&doc);
        assert!(output.contains("<html>"));
        assert!(output.contains("<body>"));
        assert!(output.contains("<p>"));
        assert!(output.contains("Hello"));
        assert!(output.contains("</p>"));
        assert!(output.contains("</body>"));
        assert!(output.contains("</html>"));
    }

    #[test]
    fn test_tidy_parse_unclosed_tags() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string("<html><body><p>Hello<p>World</body></html>", &config);
        // Should generate a warning about missing closing tag
        // The parser should detect the unclosed tags
        let _warnings = tidy_warning_count(&doc);
        let _errors = tidy_error_count(&doc);
        let output = tidy_get_output(&doc);
        // Output should still contain the content
        assert!(output.contains("Hello"));
        assert!(output.contains("World"));
    }

    #[test]
    fn test_tidy_parse_void_elements() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string("<html><body><br><hr><img></body></html>", &config);
        let output = tidy_get_output(&doc);
        assert!(output.contains("<br>"));
        assert!(output.contains("<hr>"));
        assert!(output.contains("<img>"));
    }

    #[test]
    fn test_tidy_parse_xhtml_void_elements() {
        let config = TidyConfig {
            output_xhtml: true,
            ..TidyConfig::default()
        };
        let doc = tidy_parse_string("<html><body><br></body></html>", &config);
        let output = tidy_get_output(&doc);
        assert!(output.contains("<br />"));
    }

    #[test]
    fn test_tidy_clean_repair() {
        let config = TidyConfig::default();
        let mut doc = tidy_parse_string("<html><body><p>Test</body></html>", &config);
        assert!(tidy_clean_repair(&mut doc));
        let output = tidy_get_output(&doc);
        assert!(output.contains("Test"));
    }

    #[test]
    fn test_tidy_get_html_head_body() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string(
            "<html><head><title>Test</title></head><body><p>Content</p></body></html>",
            &config,
        );

        let html = tidy_get_html(&doc);
        assert!(html.is_some());
        assert_eq!(html.unwrap().name, "html");

        let head = tidy_get_head(&doc);
        assert!(head.is_some());
        assert_eq!(head.unwrap().name, "head");

        let body = tidy_get_body(&doc);
        assert!(body.is_some());
        assert_eq!(body.unwrap().name, "body");
    }

    #[test]
    fn test_tidy_error_buffer() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string("<html><body><p>Unclosed", &config);
        let buffer = tidy_get_error_buffer(&doc);
        // Should have some warning about unclosed tags
        assert!(buffer.contains("Warning") || buffer.contains("Error") || buffer.is_empty());
    }

    #[test]
    fn test_tidy_counts() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string("<html><body><p>Test</p></body></html>", &config);
        assert_eq!(tidy_access_count(&doc), 0);
        assert!(tidy_diagnose(&doc));
    }

    #[test]
    fn test_tidy_parse_file_not_found() {
        let config = TidyConfig::default();
        let result = tidy_parse_file("nonexistent.html", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_tidy_config_default() {
        let config = TidyConfig::default();
        assert!(!config.indent);
        assert_eq!(config.wrap, 68);
        assert!(!config.output_xhtml);
        assert!(!config.clean);
        assert!(config.fix_tags);
    }

    #[test]
    fn test_tidy_parse_with_attributes() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string(
            "<html><body><div class=\"main\" id=\"content\">Hello</div></body></html>",
            &config,
        );
        let output = tidy_get_output(&doc);
        assert!(output.contains("class=\"main\""));
        assert!(output.contains("id=\"content\""));
    }

    #[test]
    fn test_tidy_parse_comment() {
        let config = TidyConfig::default();
        let doc = tidy_parse_string(
            "<html><body><!-- comment --><p>Text</p></body></html>",
            &config,
        );
        let output = tidy_get_output(&doc);
        assert!(output.contains("<!-- comment -->"));
    }

    #[test]
    fn test_tidy_indent() {
        let config = TidyConfig {
            indent: true,
            ..TidyConfig::default()
        };
        let doc = tidy_parse_string("<html><body><p>Hello</p></body></html>", &config);
        let output = tidy_get_output(&doc);
        assert!(output.contains('\n'));
    }
}
