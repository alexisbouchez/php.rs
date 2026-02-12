//! PHP Lexbor extension — HTML5 parser.
//!
//! Provides HTML5-compliant parsing based on the lexbor library.
//! In the PHP source, this wraps the C lexbor library. Here we provide
//! a pure-Rust HTML5 parser with the same API surface.
//! Reference: php-src/ext/lexbor/

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants — node types
// ---------------------------------------------------------------------------

pub const LXB_DOM_NODE_TYPE_ELEMENT: u32 = 1;
pub const LXB_DOM_NODE_TYPE_ATTRIBUTE: u32 = 2;
pub const LXB_DOM_NODE_TYPE_TEXT: u32 = 3;
pub const LXB_DOM_NODE_TYPE_CDATA_SECTION: u32 = 4;
pub const LXB_DOM_NODE_TYPE_PROCESSING_INSTRUCTION: u32 = 7;
pub const LXB_DOM_NODE_TYPE_COMMENT: u32 = 8;
pub const LXB_DOM_NODE_TYPE_DOCUMENT: u32 = 9;
pub const LXB_DOM_NODE_TYPE_DOCUMENT_TYPE: u32 = 10;
pub const LXB_DOM_NODE_TYPE_DOCUMENT_FRAGMENT: u32 = 11;

// ---------------------------------------------------------------------------
// Constants — tag IDs (commonly used HTML tags)
// ---------------------------------------------------------------------------

pub const LXB_TAG_HTML: u32 = 1;
pub const LXB_TAG_HEAD: u32 = 2;
pub const LXB_TAG_BODY: u32 = 3;
pub const LXB_TAG_DIV: u32 = 4;
pub const LXB_TAG_SPAN: u32 = 5;
pub const LXB_TAG_P: u32 = 6;
pub const LXB_TAG_A: u32 = 7;
pub const LXB_TAG_IMG: u32 = 8;
pub const LXB_TAG_TABLE: u32 = 9;
pub const LXB_TAG_FORM: u32 = 10;
pub const LXB_TAG_INPUT: u32 = 11;
pub const LXB_TAG_SCRIPT: u32 = 12;
pub const LXB_TAG_STYLE: u32 = 13;

// ---------------------------------------------------------------------------
// LexborError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct LexborError {
    pub message: String,
}

impl LexborError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for LexborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lexbor: {}", self.message)
    }
}

impl std::error::Error for LexborError {}

// ---------------------------------------------------------------------------
// HtmlNode — simplified DOM node
// ---------------------------------------------------------------------------

/// A node in the parsed HTML document tree.
#[derive(Debug, Clone, PartialEq)]
pub enum HtmlNode {
    /// A document node (root).
    Document { children: Vec<HtmlNode> },
    /// An element node with tag name, attributes, and children.
    Element {
        tag: String,
        attributes: HashMap<String, String>,
        children: Vec<HtmlNode>,
    },
    /// A text node.
    Text { content: String },
    /// A comment node.
    Comment { content: String },
    /// A DOCTYPE declaration.
    Doctype { name: String },
}

impl HtmlNode {
    /// Get the tag name for Element nodes.
    pub fn tag_name(&self) -> Option<&str> {
        match self {
            HtmlNode::Element { tag, .. } => Some(tag),
            _ => None,
        }
    }

    /// Get the text content for Text nodes.
    pub fn text_content(&self) -> String {
        match self {
            HtmlNode::Text { content } => content.clone(),
            HtmlNode::Element { children, .. } | HtmlNode::Document { children } => {
                children.iter().map(|c| c.text_content()).collect()
            }
            _ => String::new(),
        }
    }

    /// Get the children of this node.
    pub fn children(&self) -> &[HtmlNode] {
        match self {
            HtmlNode::Document { children } | HtmlNode::Element { children, .. } => children,
            _ => &[],
        }
    }

    /// Get an attribute value.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        match self {
            HtmlNode::Element { attributes, .. } => attributes.get(name).map(|s| s.as_str()),
            _ => None,
        }
    }

    /// Find all descendant elements with a given tag name.
    pub fn get_elements_by_tag_name(&self, name: &str) -> Vec<&HtmlNode> {
        let mut result = Vec::new();
        self.collect_by_tag(name, &mut result);
        result
    }

    fn collect_by_tag<'a>(&'a self, name: &str, result: &mut Vec<&'a HtmlNode>) {
        if let Some(tag) = self.tag_name() {
            if tag.eq_ignore_ascii_case(name) {
                result.push(self);
            }
        }
        for child in self.children() {
            child.collect_by_tag(name, result);
        }
    }
}

// ---------------------------------------------------------------------------
// HTML5 parser — simplified
// ---------------------------------------------------------------------------

/// Void elements that don't have closing tags.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn is_void_element(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag.to_ascii_lowercase().as_str())
}

/// Parse an HTML5 string into a document tree.
pub fn parse_html(input: &str) -> Result<HtmlNode, LexborError> {
    let mut children = Vec::new();
    let mut pos = 0;
    let bytes = input.as_bytes();

    parse_nodes(bytes, &mut pos, &mut children, None)?;

    Ok(HtmlNode::Document { children })
}

fn parse_nodes(
    bytes: &[u8],
    pos: &mut usize,
    children: &mut Vec<HtmlNode>,
    parent_tag: Option<&str>,
) -> Result<(), LexborError> {
    let input = std::str::from_utf8(bytes).map_err(|_| LexborError::new("Invalid UTF-8"))?;

    while *pos < bytes.len() {
        if bytes[*pos] == b'<' {
            // Check for closing tag
            if *pos + 1 < bytes.len() && bytes[*pos + 1] == b'/' {
                // Closing tag — check if it matches our parent
                if parent_tag.is_some() {
                    return Ok(());
                }
                // Skip unmatched closing tag
                if let Some(end) = input[*pos..].find('>') {
                    *pos += end + 1;
                } else {
                    *pos = bytes.len();
                }
                continue;
            }

            // Comment
            if input[*pos..].starts_with("<!--") {
                if let Some(end) = input[*pos + 4..].find("-->") {
                    let content = &input[*pos + 4..*pos + 4 + end];
                    children.push(HtmlNode::Comment {
                        content: content.to_string(),
                    });
                    *pos += 4 + end + 3;
                } else {
                    *pos = bytes.len();
                }
                continue;
            }

            // DOCTYPE
            if input[*pos..].len() >= 9 && input[*pos..*pos + 9].eq_ignore_ascii_case("<!doctype") {
                if let Some(end) = input[*pos..].find('>') {
                    let decl = input[*pos + 9..*pos + end].trim();
                    children.push(HtmlNode::Doctype {
                        name: decl.to_string(),
                    });
                    *pos += end + 1;
                } else {
                    *pos = bytes.len();
                }
                continue;
            }

            // Other declarations / processing instructions
            if *pos + 1 < bytes.len() && (bytes[*pos + 1] == b'!' || bytes[*pos + 1] == b'?') {
                if let Some(end) = input[*pos..].find('>') {
                    *pos += end + 1;
                } else {
                    *pos = bytes.len();
                }
                continue;
            }

            // Element tag
            let tag_start = *pos + 1;
            if let Some(end_offset) = input[*pos..].find('>') {
                let tag_region = &input[tag_start..*pos + end_offset];
                let self_closing = tag_region.ends_with('/');
                let tag_content = if self_closing {
                    &tag_region[..tag_region.len() - 1]
                } else {
                    tag_region
                };

                // Parse tag name and attributes
                let mut parts = tag_content.splitn(2, |c: char| c.is_whitespace());
                let tag_name = parts.next().unwrap_or("").to_ascii_lowercase();
                let attrs_str = parts.next().unwrap_or("");

                let attributes = parse_attributes(attrs_str);

                *pos += end_offset + 1;

                if tag_name.is_empty() {
                    continue;
                }

                if self_closing || is_void_element(&tag_name) {
                    children.push(HtmlNode::Element {
                        tag: tag_name,
                        attributes,
                        children: Vec::new(),
                    });
                } else {
                    let mut element_children = Vec::new();
                    parse_nodes(bytes, pos, &mut element_children, Some(&tag_name))?;

                    // Skip closing tag
                    let expected = format!("</{}", tag_name);
                    if *pos < bytes.len()
                        && input[*pos..].to_ascii_lowercase().starts_with(&expected)
                    {
                        if let Some(end) = input[*pos..].find('>') {
                            *pos += end + 1;
                        }
                    }

                    children.push(HtmlNode::Element {
                        tag: tag_name,
                        attributes,
                        children: element_children,
                    });
                }
            } else {
                *pos = bytes.len();
            }
        } else {
            // Text node
            let text_start = *pos;
            while *pos < bytes.len() && bytes[*pos] != b'<' {
                *pos += 1;
            }
            let text = &input[text_start..*pos];
            if !text.trim().is_empty() {
                children.push(HtmlNode::Text {
                    content: text.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Parse HTML attribute string: `key="value" key2='value2' boolean-attr`
fn parse_attributes(input: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let mut rest = input.trim();

    while !rest.is_empty() {
        // Skip whitespace
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }

        // Find attribute name
        let name_end = rest
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();

        if rest.starts_with('=') {
            rest = rest[1..].trim_start();
            // Parse value
            if rest.starts_with('"') {
                rest = &rest[1..];
                let end = rest.find('"').unwrap_or(rest.len());
                attrs.insert(name, rest[..end].to_string());
                rest = if end < rest.len() {
                    &rest[end + 1..]
                } else {
                    ""
                };
            } else if rest.starts_with('\'') {
                rest = &rest[1..];
                let end = rest.find('\'').unwrap_or(rest.len());
                attrs.insert(name, rest[..end].to_string());
                rest = if end < rest.len() {
                    &rest[end + 1..]
                } else {
                    ""
                };
            } else {
                // Unquoted value
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                attrs.insert(name, rest[..end].to_string());
                rest = &rest[end..];
            }
        } else if !name.is_empty() {
            // Boolean attribute
            attrs.insert(name, String::new());
        }
    }

    attrs
}

/// Serialize an HTML node tree back to an HTML string.
pub fn serialize_html(node: &HtmlNode) -> String {
    let mut output = String::new();
    serialize_node(node, &mut output);
    output
}

fn serialize_node(node: &HtmlNode, output: &mut String) {
    match node {
        HtmlNode::Document { children } => {
            for child in children {
                serialize_node(child, output);
            }
        }
        HtmlNode::Doctype { name } => {
            output.push_str("<!DOCTYPE ");
            output.push_str(name);
            output.push('>');
        }
        HtmlNode::Element {
            tag,
            attributes,
            children,
        } => {
            output.push('<');
            output.push_str(tag);
            for (k, v) in attributes {
                output.push(' ');
                output.push_str(k);
                if !v.is_empty() {
                    output.push_str("=\"");
                    output.push_str(v);
                    output.push('"');
                }
            }
            if is_void_element(tag) {
                output.push_str(" />");
            } else {
                output.push('>');
                for child in children {
                    serialize_node(child, output);
                }
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
        }
        HtmlNode::Text { content } => {
            output.push_str(content);
        }
        HtmlNode::Comment { content } => {
            output.push_str("<!--");
            output.push_str(content);
            output.push_str("-->");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let doc = parse_html("<div>hello</div>").unwrap();
        let children = doc.children();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag_name(), Some("div"));
        assert_eq!(children[0].text_content(), "hello");
    }

    #[test]
    fn test_parse_attributes() {
        let doc = parse_html(r#"<a href="http://x" class="link">text</a>"#).unwrap();
        let a = &doc.children()[0];
        assert_eq!(a.get_attribute("href"), Some("http://x"));
        assert_eq!(a.get_attribute("class"), Some("link"));
    }

    #[test]
    fn test_parse_void_elements() {
        let doc = parse_html("<br><img src='x'><hr>").unwrap();
        assert_eq!(doc.children().len(), 3);
        assert_eq!(doc.children()[0].tag_name(), Some("br"));
        assert_eq!(doc.children()[1].tag_name(), Some("img"));
        assert_eq!(doc.children()[2].tag_name(), Some("hr"));
    }

    #[test]
    fn test_parse_nested() {
        let doc = parse_html("<div><p>text</p></div>").unwrap();
        let div = &doc.children()[0];
        assert_eq!(div.tag_name(), Some("div"));
        let p = &div.children()[0];
        assert_eq!(p.tag_name(), Some("p"));
        assert_eq!(p.text_content(), "text");
    }

    #[test]
    fn test_parse_comment() {
        let doc = parse_html("<!-- comment --><div></div>").unwrap();
        assert_eq!(doc.children().len(), 2);
        if let HtmlNode::Comment { content } = &doc.children()[0] {
            assert_eq!(content.trim(), "comment");
        } else {
            panic!("Expected Comment node");
        }
    }

    #[test]
    fn test_parse_doctype() {
        let doc = parse_html("<!DOCTYPE html><html></html>").unwrap();
        if let HtmlNode::Doctype { name } = &doc.children()[0] {
            assert_eq!(name, "html");
        } else {
            panic!("Expected Doctype node");
        }
    }

    #[test]
    fn test_get_elements_by_tag_name() {
        let doc = parse_html("<div><p>a</p><p>b</p></div>").unwrap();
        let ps = doc.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let html = "<div><p>hello</p></div>";
        let doc = parse_html(html).unwrap();
        let output = serialize_html(&doc);
        assert!(output.contains("<div>"));
        assert!(output.contains("<p>hello</p>"));
        assert!(output.contains("</div>"));
    }

    #[test]
    fn test_self_closing() {
        let doc = parse_html("<input type='text'/>").unwrap();
        assert_eq!(doc.children().len(), 1);
        assert_eq!(doc.children()[0].get_attribute("type"), Some("text"));
    }

    #[test]
    fn test_boolean_attributes() {
        let doc = parse_html("<input disabled required>").unwrap();
        let input = &doc.children()[0];
        assert_eq!(input.get_attribute("disabled"), Some(""));
        assert_eq!(input.get_attribute("required"), Some(""));
    }

    #[test]
    fn test_text_only() {
        let doc = parse_html("just text").unwrap();
        assert_eq!(doc.text_content(), "just text");
    }

    #[test]
    fn test_empty_parse() {
        let doc = parse_html("").unwrap();
        assert_eq!(doc.children().len(), 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(LXB_DOM_NODE_TYPE_ELEMENT, 1);
        assert_eq!(LXB_DOM_NODE_TYPE_TEXT, 3);
        assert_eq!(LXB_DOM_NODE_TYPE_DOCUMENT, 9);
    }

    #[test]
    fn test_mixed_content() {
        let doc = parse_html("<p>hello <b>world</b>!</p>").unwrap();
        let p = &doc.children()[0];
        assert_eq!(p.text_content(), "hello world!");
    }
}
