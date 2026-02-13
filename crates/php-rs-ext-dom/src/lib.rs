//! PHP DOM extension.
//!
//! Implements DOMDocument, DOMElement, DOMNode, DOMNodeList, DOMText,
//! DOMComment, DOMAttr, and basic XPath support.
//! Reference: php-src/ext/dom/

use std::collections::HashMap;
use std::fmt;

// ── Node types ──────────────────────────────────────────────────────────────

/// DOM node type constants matching PHP's XML_*_NODE values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DomNodeType {
    Element = 1,
    Attribute = 2,
    Text = 3,
    CDataSection = 4,
    EntityReference = 5,
    Entity = 6,
    ProcessingInstruction = 7,
    Comment = 8,
    Document = 9,
    DocumentType = 10,
    DocumentFragment = 11,
    Notation = 12,
}

// ── DomAttr ─────────────────────────────────────────────────────────────────

/// An attribute on a DOM element.
#[derive(Debug, Clone, PartialEq)]
pub struct DomAttr {
    pub name: String,
    pub value: String,
}

impl DomAttr {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

// ── DomText ─────────────────────────────────────────────────────────────────

/// A text node.
#[derive(Debug, Clone, PartialEq)]
pub struct DomText {
    pub data: String,
}

impl DomText {
    pub fn new(data: &str) -> Self {
        Self {
            data: data.to_string(),
        }
    }

    pub fn whole_text(&self) -> &str {
        &self.data
    }
}

// ── DomComment ──────────────────────────────────────────────────────────────

/// A comment node.
#[derive(Debug, Clone, PartialEq)]
pub struct DomComment {
    pub data: String,
}

impl DomComment {
    pub fn new(data: &str) -> Self {
        Self {
            data: data.to_string(),
        }
    }
}

// ── DomNode ─────────────────────────────────────────────────────────────────

/// A node in the DOM tree. This enum unifies all node types.
#[derive(Debug, Clone, PartialEq)]
pub enum DomNode {
    Element(DomElement),
    Text(DomText),
    Comment(DomComment),
    Attribute(DomAttr),
    CDataSection(String),
    ProcessingInstruction { target: String, data: String },
    Document(Box<DomDocument>),
}

impl DomNode {
    /// Returns the node type enum.
    pub fn node_type(&self) -> DomNodeType {
        match self {
            DomNode::Element(_) => DomNodeType::Element,
            DomNode::Text(_) => DomNodeType::Text,
            DomNode::Comment(_) => DomNodeType::Comment,
            DomNode::Attribute(_) => DomNodeType::Attribute,
            DomNode::CDataSection(_) => DomNodeType::CDataSection,
            DomNode::ProcessingInstruction { .. } => DomNodeType::ProcessingInstruction,
            DomNode::Document(_) => DomNodeType::Document,
        }
    }

    /// Returns the node name (tag name for elements, #text, #comment, etc.).
    pub fn node_name(&self) -> &str {
        match self {
            DomNode::Element(e) => &e.tag_name,
            DomNode::Text(_) => "#text",
            DomNode::Comment(_) => "#comment",
            DomNode::Attribute(a) => &a.name,
            DomNode::CDataSection(_) => "#cdata-section",
            DomNode::ProcessingInstruction { target, .. } => target,
            DomNode::Document(_) => "#document",
        }
    }

    /// Returns the text content of this node.
    pub fn text_content(&self) -> String {
        match self {
            DomNode::Element(e) => e.text_content(),
            DomNode::Text(t) => t.data.clone(),
            DomNode::Comment(c) => c.data.clone(),
            DomNode::Attribute(a) => a.value.clone(),
            DomNode::CDataSection(s) => s.clone(),
            DomNode::ProcessingInstruction { data, .. } => data.clone(),
            DomNode::Document(d) => {
                if let Some(ref root) = d.document_element {
                    root.text_content()
                } else {
                    String::new()
                }
            }
        }
    }

    /// Returns children if this node has them (elements and documents only).
    pub fn child_nodes(&self) -> &[DomNode] {
        match self {
            DomNode::Element(e) => &e.children,
            DomNode::Document(d) => {
                if let Some(ref root) = d.document_element {
                    // For documents, the root element's children are not directly
                    // the document children. Return slice from document_element wrapped.
                    // This is a simplification; a full DOM would have the root as child.
                    &root.children
                } else {
                    &[]
                }
            }
            _ => &[],
        }
    }
}

impl fmt::Display for DomNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomNode::Element(e) => write!(f, "{}", e.to_xml()),
            DomNode::Text(t) => write!(f, "{}", xml_escape(&t.data)),
            DomNode::Comment(c) => write!(f, "<!--{}-->", c.data),
            DomNode::Attribute(a) => write!(f, "{}=\"{}\"", a.name, xml_escape_attr(&a.value)),
            DomNode::CDataSection(s) => write!(f, "<![CDATA[{}]]>", s),
            DomNode::ProcessingInstruction { target, data } => {
                if data.is_empty() {
                    write!(f, "<?{}?>", target)
                } else {
                    write!(f, "<?{} {}?>", target, data)
                }
            }
            DomNode::Document(d) => write!(f, "{}", d.save_xml()),
        }
    }
}

// ── DomElement ──────────────────────────────────────────────────────────────

/// An element node in the DOM tree.
#[derive(Debug, Clone, PartialEq)]
pub struct DomElement {
    pub tag_name: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<DomNode>,
    /// Namespace URI (if any).
    pub namespace_uri: Option<String>,
    /// Namespace prefix (if any).
    pub prefix: Option<String>,
}

impl DomElement {
    pub fn new(tag_name: &str) -> Self {
        Self {
            tag_name: tag_name.to_string(),
            attributes: HashMap::new(),
            children: Vec::new(),
            namespace_uri: None,
            prefix: None,
        }
    }

    /// Set an attribute on this element.
    pub fn set_attribute(&mut self, name: &str, value: &str) {
        self.attributes.insert(name.to_string(), value.to_string());
    }

    /// Get an attribute value by name.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    /// Remove an attribute by name.
    pub fn remove_attribute(&mut self, name: &str) -> bool {
        self.attributes.remove(name).is_some()
    }

    /// Check if an attribute exists.
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.contains_key(name)
    }

    /// Append a child node.
    pub fn append_child(&mut self, child: DomNode) {
        self.children.push(child);
    }

    /// Remove a child node at the given index. Returns the removed node, or None.
    pub fn remove_child(&mut self, index: usize) -> Option<DomNode> {
        if index < self.children.len() {
            Some(self.children.remove(index))
        } else {
            None
        }
    }

    /// Insert a child node before the given index.
    pub fn insert_before(&mut self, new_child: DomNode, index: usize) {
        let idx = if index > self.children.len() {
            self.children.len()
        } else {
            index
        };
        self.children.insert(idx, new_child);
    }

    /// Returns the number of child nodes.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns the concatenated text content of all descendant text nodes.
    pub fn text_content(&self) -> String {
        let mut result = String::new();
        self.collect_text(&mut result);
        result
    }

    fn collect_text(&self, out: &mut String) {
        for child in &self.children {
            match child {
                DomNode::Text(t) => out.push_str(&t.data),
                DomNode::CDataSection(s) => out.push_str(s),
                DomNode::Element(e) => e.collect_text(out),
                _ => {}
            }
        }
    }

    /// Find all descendant elements with the given tag name.
    pub fn get_elements_by_tag_name(&self, tag_name: &str) -> Vec<&DomElement> {
        let mut result = Vec::new();
        self.collect_elements_by_tag(tag_name, &mut result);
        result
    }

    fn collect_elements_by_tag<'a>(&'a self, tag_name: &str, result: &mut Vec<&'a DomElement>) {
        for child in &self.children {
            if let DomNode::Element(ref e) = child {
                if e.tag_name == tag_name || tag_name == "*" {
                    result.push(e);
                }
                e.collect_elements_by_tag(tag_name, result);
            }
        }
    }

    /// Serialize this element to an XML string.
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write_xml(&mut out, 0);
        out
    }

    fn write_xml(&self, out: &mut String, _depth: usize) {
        out.push('<');
        out.push_str(&self.tag_name);

        // Sort attributes for deterministic output.
        let mut attrs: Vec<(&String, &String)> = self.attributes.iter().collect();
        attrs.sort_by_key(|(k, _)| k.as_str());

        for (name, value) in attrs {
            out.push(' ');
            out.push_str(name);
            out.push_str("=\"");
            out.push_str(&xml_escape_attr(value));
            out.push('"');
        }

        if self.children.is_empty() {
            out.push_str("/>");
        } else {
            out.push('>');
            for child in &self.children {
                match child {
                    DomNode::Element(e) => e.write_xml(out, _depth + 1),
                    DomNode::Text(t) => out.push_str(&xml_escape(&t.data)),
                    DomNode::Comment(c) => {
                        out.push_str("<!--");
                        out.push_str(&c.data);
                        out.push_str("-->");
                    }
                    DomNode::CDataSection(s) => {
                        out.push_str("<![CDATA[");
                        out.push_str(s);
                        out.push_str("]]>");
                    }
                    DomNode::ProcessingInstruction { target, data } => {
                        out.push_str("<?");
                        out.push_str(target);
                        if !data.is_empty() {
                            out.push(' ');
                            out.push_str(data);
                        }
                        out.push_str("?>");
                    }
                    DomNode::Attribute(_) => {} // Attributes are not child nodes in serialization.
                    DomNode::Document(_) => {}
                }
            }
            out.push_str("</");
            out.push_str(&self.tag_name);
            out.push('>');
        }
    }
}

// ── DomNodeList ─────────────────────────────────────────────────────────────

/// A list of DOM nodes, returned from queries.
#[derive(Debug, Clone, PartialEq)]
pub struct DomNodeList {
    nodes: Vec<DomNode>,
}

impl DomNodeList {
    pub fn new(nodes: Vec<DomNode>) -> Self {
        Self { nodes }
    }

    pub fn empty() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Returns the node at the given index, or None.
    pub fn item(&self, index: usize) -> Option<&DomNode> {
        self.nodes.get(index)
    }

    /// Returns the number of nodes.
    pub fn length(&self) -> usize {
        self.nodes.len()
    }

    /// Returns an iterator over the nodes.
    pub fn iter(&self) -> std::slice::Iter<'_, DomNode> {
        self.nodes.iter()
    }

    /// Returns the underlying Vec.
    pub fn into_vec(self) -> Vec<DomNode> {
        self.nodes
    }
}

impl IntoIterator for DomNodeList {
    type Item = DomNode;
    type IntoIter = std::vec::IntoIter<DomNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_iter()
    }
}

impl<'a> IntoIterator for &'a DomNodeList {
    type Item = &'a DomNode;
    type IntoIter = std::slice::Iter<'a, DomNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.iter()
    }
}

// ── DomDocument ─────────────────────────────────────────────────────────────

/// The root document node.
#[derive(Debug, Clone, PartialEq)]
pub struct DomDocument {
    pub version: String,
    pub encoding: String,
    pub standalone: Option<bool>,
    pub document_element: Option<DomElement>,
}

impl DomDocument {
    /// Creates a new empty document.
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            encoding: "UTF-8".to_string(),
            standalone: None,
            document_element: None,
        }
    }

    /// Creates a new element node (not yet attached to the tree).
    pub fn create_element(&self, tag_name: &str) -> DomElement {
        DomElement::new(tag_name)
    }

    /// Creates a new text node.
    pub fn create_text_node(&self, data: &str) -> DomText {
        DomText::new(data)
    }

    /// Creates a new comment node.
    pub fn create_comment(&self, data: &str) -> DomComment {
        DomComment::new(data)
    }

    /// Creates a new attribute node.
    pub fn create_attribute(&self, name: &str) -> DomAttr {
        DomAttr::new(name, "")
    }

    /// Creates a CDATA section.
    pub fn create_cdata_section(&self, data: &str) -> DomNode {
        DomNode::CDataSection(data.to_string())
    }

    /// Creates a processing instruction.
    pub fn create_processing_instruction(&self, target: &str, data: &str) -> DomNode {
        DomNode::ProcessingInstruction {
            target: target.to_string(),
            data: data.to_string(),
        }
    }

    /// Set the document element (root).
    pub fn set_document_element(&mut self, element: DomElement) {
        self.document_element = Some(element);
    }

    /// Find all elements with the given tag name in the entire document.
    pub fn get_elements_by_tag_name(&self, tag_name: &str) -> Vec<&DomElement> {
        let mut result = Vec::new();
        if let Some(ref root) = self.document_element {
            if root.tag_name == tag_name || tag_name == "*" {
                result.push(root);
            }
            root.collect_elements_by_tag(tag_name, &mut result);
        }
        result
    }

    /// Find element by id attribute. Searches the entire tree for an element
    /// with attribute "id" matching the given value.
    pub fn get_element_by_id(&self, id: &str) -> Option<&DomElement> {
        if let Some(ref root) = self.document_element {
            Self::find_by_id(root, id)
        } else {
            None
        }
    }

    fn find_by_id<'a>(element: &'a DomElement, id: &str) -> Option<&'a DomElement> {
        if element.get_attribute("id") == Some(id) {
            return Some(element);
        }
        for child in &element.children {
            if let DomNode::Element(ref e) = child {
                if let Some(found) = Self::find_by_id(e, id) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Serialize the entire document to XML.
    pub fn save_xml(&self) -> String {
        let mut out = String::new();
        out.push_str("<?xml version=\"");
        out.push_str(&self.version);
        out.push('"');
        if !self.encoding.is_empty() {
            out.push_str(" encoding=\"");
            out.push_str(&self.encoding);
            out.push('"');
        }
        if let Some(standalone) = self.standalone {
            out.push_str(" standalone=\"");
            out.push_str(if standalone { "yes" } else { "no" });
            out.push('"');
        }
        out.push_str("?>\n");

        if let Some(ref root) = self.document_element {
            root.write_xml(&mut out, 0);
            out.push('\n');
        }

        out
    }
}

impl Default for DomDocument {
    fn default() -> Self {
        Self::new()
    }
}

// ── XML Parser (simple recursive descent) ───────────────────────────────────

/// Parse an XML string into a DomDocument.
///
/// This is a basic recursive descent XML parser sufficient for well-formed XML.
/// It does not support DTD validation, external entities, or namespaces beyond
/// basic prefix handling.
pub fn load_xml(source: &str) -> Result<DomDocument, String> {
    let mut parser = XmlParserInternal::new(source);
    parser.parse_document()
}

struct XmlParserInternal<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> XmlParserInternal<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.remaining().starts_with(s)
    }

    fn expect(&mut self, s: &str) -> Result<(), String> {
        if self.starts_with(s) {
            self.advance(s.len());
            Ok(())
        } else {
            Err(format!(
                "Expected '{}' at position {}, found '{}'",
                s,
                self.pos,
                &self.remaining()[..self.remaining().len().min(20)]
            ))
        }
    }

    fn parse_document(&mut self) -> Result<DomDocument, String> {
        let mut doc = DomDocument::new();

        self.skip_whitespace();

        // Parse XML declaration if present.
        if self.starts_with("<?xml") {
            self.parse_xml_declaration(&mut doc)?;
        }

        self.skip_whitespace();

        // Skip comments and processing instructions before root.
        while self.pos < self.input.len() {
            self.skip_whitespace();
            if self.starts_with("<!--") {
                self.parse_comment()?;
            } else if self.starts_with("<?") {
                self.parse_pi()?;
            } else if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
                self.skip_doctype()?;
            } else {
                break;
            }
        }

        self.skip_whitespace();

        // Parse root element.
        if self.starts_with("<") && !self.starts_with("</") {
            let root = self.parse_element()?;
            doc.document_element = Some(root);
        }

        self.skip_whitespace();

        Ok(doc)
    }

    fn parse_xml_declaration(&mut self, doc: &mut DomDocument) -> Result<(), String> {
        self.expect("<?xml")?;
        self.skip_whitespace();

        // Parse attributes of the declaration.
        while !self.starts_with("?>") {
            if self.pos >= self.input.len() {
                return Err("Unterminated XML declaration".to_string());
            }
            self.skip_whitespace();
            if self.starts_with("?>") {
                break;
            }
            let (name, value) = self.parse_attr()?;
            match name.as_str() {
                "version" => doc.version = value,
                "encoding" => doc.encoding = value,
                "standalone" => doc.standalone = Some(value == "yes"),
                _ => {}
            }
            self.skip_whitespace();
        }
        self.expect("?>")?;
        Ok(())
    }

    fn parse_comment(&mut self) -> Result<DomComment, String> {
        self.expect("<!--")?;
        let start = self.pos;
        loop {
            if self.pos >= self.input.len() {
                return Err("Unterminated comment".to_string());
            }
            if self.starts_with("-->") {
                let data = &self.input[start..self.pos];
                self.advance(3);
                return Ok(DomComment::new(data));
            }
            self.advance(1);
        }
    }

    fn parse_pi(&mut self) -> Result<DomNode, String> {
        self.expect("<?")?;
        let target = self.parse_name()?;
        self.skip_whitespace();
        let start = self.pos;
        loop {
            if self.pos >= self.input.len() {
                return Err("Unterminated processing instruction".to_string());
            }
            if self.starts_with("?>") {
                let data = self.input[start..self.pos].trim_end().to_string();
                self.advance(2);
                return Ok(DomNode::ProcessingInstruction { target, data });
            }
            self.advance(1);
        }
    }

    fn skip_doctype(&mut self) -> Result<(), String> {
        self.expect("<!")?;
        let mut depth = 1;
        while depth > 0 {
            if self.pos >= self.input.len() {
                return Err("Unterminated DOCTYPE".to_string());
            }
            match self.peek() {
                Some('<') => {
                    depth += 1;
                    self.advance(1);
                }
                Some('>') => {
                    depth -= 1;
                    self.advance(1);
                }
                Some(c) => self.advance(c.len_utf8()),
                None => return Err("Unterminated DOCTYPE".to_string()),
            }
        }
        Ok(())
    }

    fn parse_element(&mut self) -> Result<DomElement, String> {
        self.expect("<")?;
        let tag_name = self.parse_name()?;
        let mut element = DomElement::new(&tag_name);
        self.skip_whitespace();

        // Parse attributes.
        while self.pos < self.input.len() && !self.starts_with(">") && !self.starts_with("/>") {
            self.skip_whitespace();
            if self.starts_with(">") || self.starts_with("/>") {
                break;
            }
            let (name, value) = self.parse_attr()?;

            // Handle namespace prefixes.
            if let Some(prefix) = name.strip_prefix("xmlns:") {
                if element.prefix.is_none() && tag_name.starts_with(&format!("{}:", prefix)) {
                    element.namespace_uri = Some(value.clone());
                    element.prefix = Some(prefix.to_string());
                }
            } else if name == "xmlns" && element.namespace_uri.is_none() {
                element.namespace_uri = Some(value.clone());
            }

            element.attributes.insert(name, value);
            self.skip_whitespace();
        }

        // Self-closing?
        if self.starts_with("/>") {
            self.advance(2);
            return Ok(element);
        }

        self.expect(">")?;

        // Parse children.
        loop {
            if self.pos >= self.input.len() {
                return Err(format!("Unterminated element <{}>", tag_name));
            }

            if self.starts_with("</") {
                // Closing tag.
                self.advance(2);
                let close_name = self.parse_name()?;
                self.skip_whitespace();
                self.expect(">")?;
                if close_name != tag_name {
                    return Err(format!(
                        "Mismatched closing tag: expected </{}>, found </{}>",
                        tag_name, close_name
                    ));
                }
                return Ok(element);
            } else if self.starts_with("<!--") {
                let comment = self.parse_comment()?;
                element.children.push(DomNode::Comment(comment));
            } else if self.starts_with("<![CDATA[") {
                let cdata = self.parse_cdata()?;
                element.children.push(DomNode::CDataSection(cdata));
            } else if self.starts_with("<?") {
                let pi = self.parse_pi()?;
                element.children.push(pi);
            } else if self.starts_with("<") {
                let child = self.parse_element()?;
                element.children.push(DomNode::Element(child));
            } else {
                let text = self.parse_text()?;
                if !text.is_empty() {
                    element.children.push(DomNode::Text(DomText::new(&text)));
                }
            }
        }
    }

    fn parse_name(&mut self) -> Result<String, String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':' {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(format!(
                "Expected name at position {}, found '{}'",
                self.pos,
                &self.remaining()[..self.remaining().len().min(10)]
            ));
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_attr(&mut self) -> Result<(String, String), String> {
        let name = self.parse_name()?;
        self.skip_whitespace();
        self.expect("=")?;
        self.skip_whitespace();
        let value = self.parse_attr_value()?;
        Ok((name, value))
    }

    fn parse_attr_value(&mut self) -> Result<String, String> {
        let quote = match self.peek() {
            Some('"') => '"',
            Some('\'') => '\'',
            _ => return Err(format!("Expected quote at position {}", self.pos)),
        };
        self.advance(1);
        let mut value = String::new();
        loop {
            if self.pos >= self.input.len() {
                return Err("Unterminated attribute value".to_string());
            }
            match self.peek() {
                Some(c) if c == quote => {
                    self.advance(1);
                    return Ok(value);
                }
                Some('&') => {
                    let entity = self.parse_entity_ref()?;
                    value.push_str(&entity);
                }
                Some(c) => {
                    value.push(c);
                    self.advance(c.len_utf8());
                }
                None => return Err("Unterminated attribute value".to_string()),
            }
        }
    }

    fn parse_text(&mut self) -> Result<String, String> {
        let mut text = String::new();
        loop {
            if self.pos >= self.input.len() || self.starts_with("<") {
                break;
            }
            if self.starts_with("&") {
                let entity = self.parse_entity_ref()?;
                text.push_str(&entity);
            } else {
                let c = self.peek().unwrap();
                text.push(c);
                self.advance(c.len_utf8());
            }
        }
        Ok(text)
    }

    fn parse_cdata(&mut self) -> Result<String, String> {
        self.expect("<![CDATA[")?;
        let start = self.pos;
        loop {
            if self.pos >= self.input.len() {
                return Err("Unterminated CDATA section".to_string());
            }
            if self.starts_with("]]>") {
                let data = self.input[start..self.pos].to_string();
                self.advance(3);
                return Ok(data);
            }
            self.advance(1);
        }
    }

    fn parse_entity_ref(&mut self) -> Result<String, String> {
        self.expect("&")?;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == ';' {
                let name = &self.input[start..self.pos];
                self.advance(1);
                return Ok(match name {
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "amp" => "&".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    _ if name.starts_with('#') => self.decode_char_ref(&name[1..])?,
                    _ => format!("&{};", name), // Unknown entity, keep as-is.
                });
            }
            self.advance(c.len_utf8());
        }
        Err("Unterminated entity reference".to_string())
    }

    fn decode_char_ref(&self, s: &str) -> Result<String, String> {
        let codepoint = if let Some(hex) = s.strip_prefix('x') {
            u32::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex character reference: {}", s))?
        } else {
            s.parse::<u32>()
                .map_err(|_| format!("Invalid decimal character reference: {}", s))?
        };
        char::from_u32(codepoint)
            .map(|c| c.to_string())
            .ok_or_else(|| format!("Invalid Unicode codepoint: {}", codepoint))
    }
}

// ── DomXPath ────────────────────────────────────────────────────────────────

/// Basic XPath query support.
///
/// Supports simple expressions:
/// - `//tag` — find all descendant elements with given tag name
/// - `/root/child` — absolute path from root
/// - `/root/child/grandchild` — multi-level absolute path
/// - `//tag[@attr]` — elements with a given attribute
/// - `//tag[@attr='value']` — elements with a given attribute value
pub struct DomXPath;

impl DomXPath {
    /// Execute an XPath query against a document.
    pub fn query(expr: &str, doc: &DomDocument) -> Vec<DomNode> {
        if let Some(ref root) = doc.document_element {
            Self::query_element(expr, root)
        } else {
            Vec::new()
        }
    }

    /// Execute an XPath query against an element.
    pub fn query_element(expr: &str, element: &DomElement) -> Vec<DomNode> {
        let expr = expr.trim();

        if let Some(rest) = expr.strip_prefix("//") {
            // Descendant-or-self search.
            let (tag, predicate) = Self::parse_step(rest);
            let mut results = Vec::new();
            Self::find_descendants(element, &tag, &predicate, &mut results, true);
            results
        } else if let Some(rest) = expr.strip_prefix('/') {
            // Absolute path from the element (treated as root).
            let steps: Vec<&str> = rest.split('/').collect();
            if steps.is_empty() {
                return Vec::new();
            }

            let (first_tag, first_pred) = Self::parse_step(steps[0]);
            if first_tag != element.tag_name && first_tag != "*" {
                return Vec::new();
            }
            if !Self::matches_predicate(element, &first_pred) {
                return Vec::new();
            }

            if steps.len() == 1 {
                return vec![DomNode::Element(element.clone())];
            }

            // Walk remaining steps.
            let mut current_set: Vec<&DomElement> = vec![element];

            for step in &steps[1..] {
                let (tag, pred) = Self::parse_step(step);
                let mut next_set = Vec::new();
                for elem in &current_set {
                    for child in &elem.children {
                        if let DomNode::Element(ref e) = child {
                            if (e.tag_name == tag || tag == "*")
                                && Self::matches_predicate(e, &pred)
                            {
                                next_set.push(e);
                            }
                        }
                    }
                }
                current_set = next_set;
            }

            current_set
                .into_iter()
                .map(|e| DomNode::Element(e.clone()))
                .collect()
        } else {
            // Simple tag name (relative).
            let (tag, predicate) = Self::parse_step(expr);
            let mut results = Vec::new();
            for child in &element.children {
                if let DomNode::Element(ref e) = child {
                    if (e.tag_name == tag || tag == "*") && Self::matches_predicate(e, &predicate) {
                        results.push(DomNode::Element(e.clone()));
                    }
                }
            }
            results
        }
    }

    /// Parse a step like `tag`, `tag[@attr]`, or `tag[@attr='value']`.
    fn parse_step(step: &str) -> (String, Option<XPathPredicate>) {
        if let Some(bracket_pos) = step.find('[') {
            let tag = step[..bracket_pos].to_string();
            let pred_str = &step[bracket_pos + 1..step.len() - 1]; // strip [ and ]
            let predicate = Self::parse_predicate(pred_str);
            (tag, Some(predicate))
        } else {
            (step.to_string(), None)
        }
    }

    fn parse_predicate(s: &str) -> XPathPredicate {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('@') {
            if let Some(eq_pos) = rest.find('=') {
                let attr_name = rest[..eq_pos].trim().to_string();
                let value = rest[eq_pos + 1..].trim();
                // Strip quotes.
                let value = if (value.starts_with('\'') && value.ends_with('\''))
                    || (value.starts_with('"') && value.ends_with('"'))
                {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                };
                XPathPredicate::AttrEquals(attr_name, value)
            } else {
                XPathPredicate::HasAttr(rest.to_string())
            }
        } else {
            XPathPredicate::Unknown
        }
    }

    fn matches_predicate(element: &DomElement, predicate: &Option<XPathPredicate>) -> bool {
        match predicate {
            None => true,
            Some(XPathPredicate::HasAttr(attr)) => element.has_attribute(attr),
            Some(XPathPredicate::AttrEquals(attr, value)) => {
                element.get_attribute(attr) == Some(value.as_str())
            }
            Some(XPathPredicate::Unknown) => true,
        }
    }

    fn find_descendants(
        element: &DomElement,
        tag: &str,
        predicate: &Option<XPathPredicate>,
        results: &mut Vec<DomNode>,
        include_self: bool,
    ) {
        if include_self
            && (element.tag_name == tag || tag == "*")
            && Self::matches_predicate(element, predicate)
        {
            results.push(DomNode::Element(element.clone()));
        }
        for child in &element.children {
            if let DomNode::Element(ref e) = child {
                Self::find_descendants(e, tag, predicate, results, true);
            }
        }
    }
}

#[derive(Debug)]
enum XPathPredicate {
    HasAttr(String),
    AttrEquals(String, String),
    Unknown,
}

// ── HTML5 Parser ────────────────────────────────────────────────────────────

/// HTML5 void elements that cannot have children and do not require a closing tag.
const HTML5_VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
];

/// HTML5 raw text elements whose content is not parsed as HTML.
const HTML5_RAW_TEXT_ELEMENTS: &[&str] = &["script", "style"];

/// Elements that implicitly close a `<p>` when opened.
const P_CLOSING_ELEMENTS: &[&str] = &[
    "address", "article", "aside", "blockquote", "details", "dialog", "dd",
    "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "li",
    "main", "nav", "ol", "p", "pre", "section", "table", "ul",
];

/// Returns true if `tag` is an HTML5 void element (case-insensitive).
fn is_void_element(tag: &str) -> bool {
    HTML5_VOID_ELEMENTS.iter().any(|v| v.eq_ignore_ascii_case(tag))
}

/// Returns true if `tag` is an HTML5 raw text element (case-insensitive).
fn is_raw_text_element(tag: &str) -> bool {
    HTML5_RAW_TEXT_ELEMENTS.iter().any(|v| v.eq_ignore_ascii_case(tag))
}

/// Returns true if opening `tag` should implicitly close an open `<p>`.
fn closes_p_element(tag: &str) -> bool {
    P_CLOSING_ELEMENTS.iter().any(|v| v.eq_ignore_ascii_case(tag))
}

/// An HTML5 parser that produces a `DomDocument`.
///
/// This parser handles common HTML5 constructs including:
/// - Void (self-closing) elements like `<br>`, `<img>`, `<input>`
/// - Optional closing tags and implicit close semantics
/// - Boolean and unquoted attributes
/// - Comments and DOCTYPE declarations
/// - Raw text elements (`<script>`, `<style>`)
/// - Basic error recovery (auto-closing unclosed tags)
///
/// It does not implement the full HTML5 parsing specification (e.g., foster
/// parenting, adoption agency algorithm, or encoding sniffing) but covers the
/// common cases needed by PHP's `DOMDocument::loadHTML()`.
pub struct Html5Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Html5Parser<'a> {
    /// Create a new parser for the given HTML string.
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    /// Parse the input and return a `DomDocument`.
    pub fn parse(mut self) -> Result<DomDocument, String> {
        self.parse_document()
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.input.len());
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.remaining().starts_with(s)
    }

    fn starts_with_ignore_case(&self, s: &str) -> bool {
        let rem = self.remaining();
        if rem.len() < s.len() {
            return false;
        }
        rem[..s.len()].eq_ignore_ascii_case(s)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn parse_document(&mut self) -> Result<DomDocument, String> {
        let mut doc = DomDocument::new();
        doc.encoding = "UTF-8".to_string();

        // Collect all top-level nodes, then wrap in <html> if needed.
        let mut top_nodes: Vec<DomNode> = Vec::new();

        while !self.at_end() {
            self.skip_whitespace();
            if self.at_end() {
                break;
            }

            if self.starts_with("<!--") {
                let comment = self.parse_comment()?;
                top_nodes.push(DomNode::Comment(comment));
            } else if self.starts_with_ignore_case("<!doctype") {
                self.skip_doctype();
            } else if self.starts_with("</") {
                // Stray closing tag at top level -- skip it (error recovery).
                self.skip_stray_end_tag();
            } else if self.starts_with("<") {
                let elem = self.parse_element()?;
                top_nodes.push(DomNode::Element(elem));
            } else {
                let text = self.parse_text();
                if !text.trim().is_empty() {
                    top_nodes.push(DomNode::Text(DomText::new(&text)));
                }
            }
        }

        // Find or create the root <html> element.
        let html_idx = top_nodes.iter().position(|n| {
            matches!(n, DomNode::Element(ref e) if e.tag_name.eq_ignore_ascii_case("html"))
        });

        if let Some(idx) = html_idx {
            if let DomNode::Element(html) = top_nodes.remove(idx) {
                doc.set_document_element(html);
            }
        } else {
            // Wrap everything in an implicit <html><body>...</body></html>.
            let mut body = DomElement::new("body");
            for node in top_nodes {
                body.append_child(node);
            }
            let mut html = DomElement::new("html");
            html.append_child(DomNode::Element(body));
            doc.set_document_element(html);
        }

        Ok(doc)
    }

    fn skip_doctype(&mut self) {
        // Advance past "<!DOCTYPE" or "<!doctype".
        self.advance(9);
        while !self.at_end() {
            if self.peek() == Some('>') {
                self.advance(1);
                return;
            }
            self.advance(1);
        }
    }

    fn skip_stray_end_tag(&mut self) {
        // Skip "</...>"
        self.advance(2); // skip "</"
        while !self.at_end() {
            if self.peek() == Some('>') {
                self.advance(1);
                return;
            }
            self.advance(1);
        }
    }

    fn parse_comment(&mut self) -> Result<DomComment, String> {
        // Advance past "<!--".
        self.advance(4);
        let start = self.pos;
        loop {
            if self.at_end() {
                // Error recovery: treat rest as comment.
                let data = &self.input[start..];
                return Ok(DomComment::new(data));
            }
            if self.starts_with("-->") {
                let data = &self.input[start..self.pos];
                self.advance(3);
                return Ok(DomComment::new(data));
            }
            self.advance(1);
        }
    }

    fn parse_text(&mut self) -> String {
        let mut text = String::new();
        while !self.at_end() && !self.starts_with("<") {
            if self.starts_with("&") {
                let entity = self.parse_entity();
                text.push_str(&entity);
            } else {
                let c = self.peek().unwrap();
                text.push(c);
                self.advance(c.len_utf8());
            }
        }
        text
    }

    fn parse_entity(&mut self) -> String {
        self.advance(1); // skip '&'
        let start = self.pos;
        while !self.at_end() {
            let c = self.peek().unwrap();
            if c == ';' {
                let name = &self.input[start..self.pos];
                self.advance(1);
                return match name {
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "amp" => "&".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    "nbsp" => "\u{00A0}".to_string(),
                    _ if name.starts_with('#') => {
                        self.decode_char_ref(&name[1..]).unwrap_or_else(|_| format!("&{};", name))
                    }
                    _ => format!("&{};", name),
                };
            }
            // Entity names are alphanumeric or '#'.
            if !c.is_alphanumeric() && c != '#' && c != 'x' {
                break;
            }
            self.advance(c.len_utf8());
        }
        // No semicolon found -- error recovery: return the literal '&' + what we consumed.
        format!("&{}", &self.input[start..self.pos])
    }

    fn decode_char_ref(&self, s: &str) -> Result<String, String> {
        let codepoint = if let Some(hex) = s.strip_prefix('x') {
            u32::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex character reference: {}", s))?
        } else {
            s.parse::<u32>()
                .map_err(|_| format!("Invalid decimal character reference: {}", s))?
        };
        char::from_u32(codepoint)
            .map(|c| c.to_string())
            .ok_or_else(|| format!("Invalid Unicode codepoint: {}", codepoint))
    }

    fn parse_element(&mut self) -> Result<DomElement, String> {
        self.advance(1); // skip '<'
        let tag_name = self.parse_tag_name();
        if tag_name.is_empty() {
            return Err(format!("Expected tag name at position {}", self.pos));
        }
        let lower_tag = tag_name.to_ascii_lowercase();
        let mut element = DomElement::new(&lower_tag);

        // Parse attributes.
        loop {
            self.skip_whitespace();
            if self.at_end() {
                break;
            }
            if self.starts_with("/>") {
                self.advance(2);
                return Ok(element);
            }
            if self.starts_with(">") {
                self.advance(1);
                break;
            }
            let (attr_name, attr_value) = self.parse_attribute()?;
            element.attributes.insert(attr_name, attr_value);
        }

        // Void elements have no children.
        if is_void_element(&lower_tag) {
            return Ok(element);
        }

        // Raw text elements: consume everything until matching closing tag.
        if is_raw_text_element(&lower_tag) {
            let content = self.parse_raw_text_content(&lower_tag);
            if !content.is_empty() {
                element.append_child(DomNode::Text(DomText::new(&content)));
            }
            return Ok(element);
        }

        // Parse children until we hit the matching closing tag or EOF.
        self.parse_children(&mut element)?;

        Ok(element)
    }

    fn parse_tag_name(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.' {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn parse_attribute(&mut self) -> Result<(String, String), String> {
        let name = self.parse_attr_name();
        if name.is_empty() {
            // Skip one character to avoid infinite loop on unexpected input.
            self.advance(1);
            return Ok((String::new(), String::new()));
        }
        let lower_name = name.to_ascii_lowercase();

        self.skip_whitespace();
        if self.peek() != Some('=') {
            // Boolean attribute (no value).
            return Ok((lower_name, String::new()));
        }
        self.advance(1); // skip '='
        self.skip_whitespace();

        let value = self.parse_attr_value();
        Ok((lower_name, value))
    }

    fn parse_attr_name(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() || c == '=' || c == '>' || c == '/' {
                break;
            }
            self.advance(c.len_utf8());
        }
        self.input[start..self.pos].to_string()
    }

    fn parse_attr_value(&mut self) -> String {
        match self.peek() {
            Some('"') => self.parse_quoted_value('"'),
            Some('\'') => self.parse_quoted_value('\''),
            _ => self.parse_unquoted_value(),
        }
    }

    fn parse_quoted_value(&mut self, quote: char) -> String {
        self.advance(1); // skip opening quote
        let mut value = String::new();
        while !self.at_end() {
            let c = self.peek().unwrap();
            if c == quote {
                self.advance(1);
                return value;
            }
            if c == '&' {
                let entity = self.parse_entity();
                value.push_str(&entity);
            } else {
                value.push(c);
                self.advance(c.len_utf8());
            }
        }
        value // unterminated quote -- error recovery
    }

    fn parse_unquoted_value(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() || c == '>' || c == '/' {
                break;
            }
            self.advance(c.len_utf8());
        }
        self.input[start..self.pos].to_string()
    }

    fn parse_raw_text_content(&mut self, tag: &str) -> String {
        let start = self.pos;
        let close_tag = format!("</{}", tag);
        loop {
            if self.at_end() {
                return self.input[start..].to_string();
            }
            if self.starts_with_ignore_case(&close_tag) {
                let content = self.input[start..self.pos].to_string();
                // Skip the closing tag.
                self.advance(close_tag.len());
                // Skip any whitespace and the closing '>'.
                self.skip_whitespace();
                if self.peek() == Some('>') {
                    self.advance(1);
                }
                return content;
            }
            self.advance(1);
        }
    }

    fn parse_children(&mut self, parent: &mut DomElement) -> Result<(), String> {
        loop {
            if self.at_end() {
                return Ok(()); // Error recovery: implicitly close.
            }

            if self.starts_with("</") {
                // Peek at the closing tag name.
                let saved_pos = self.pos;
                self.advance(2);
                let close_name = self.parse_tag_name().to_ascii_lowercase();
                self.skip_whitespace();
                if self.peek() == Some('>') {
                    self.advance(1);
                }

                if close_name == parent.tag_name {
                    // Matching close tag -- done with this element.
                    return Ok(());
                }

                // Mismatched close tag -- error recovery.
                // If this close tag matches an ancestor, rewind and let the
                // ancestor handle it. Otherwise, discard it.
                //
                // Simple heuristic: if it's a known block element being closed,
                // rewind so the caller can handle it.
                if is_likely_ancestor_close(&close_name) {
                    // Rewind; let the caller handle this closing tag.
                    self.pos = saved_pos;
                    return Ok(());
                }
                // Otherwise discard the stray close tag and continue.
                continue;
            }

            if self.starts_with("<!--") {
                let comment = self.parse_comment()?;
                parent.append_child(DomNode::Comment(comment));
                continue;
            }

            if self.starts_with("<") && !self.starts_with("</") {
                // Peek at the next tag name to see if it should implicitly close
                // the current element.
                if parent.tag_name == "p" {
                    let saved = self.pos;
                    self.advance(1);
                    let next_tag = self.parse_tag_name().to_ascii_lowercase();
                    self.pos = saved; // rewind
                    if closes_p_element(&next_tag) {
                        // Implicitly close the <p> and let the caller handle
                        // this new element.
                        return Ok(());
                    }
                }

                // Implicit close for <li>: a new <li> closes the previous one.
                if parent.tag_name == "li" {
                    let saved = self.pos;
                    self.advance(1);
                    let next_tag = self.parse_tag_name().to_ascii_lowercase();
                    self.pos = saved;
                    if next_tag == "li" {
                        return Ok(());
                    }
                }

                let child = self.parse_element()?;
                parent.append_child(DomNode::Element(child));
                continue;
            }

            let text = self.parse_text();
            if !text.is_empty() {
                parent.append_child(DomNode::Text(DomText::new(&text)));
            }
        }
    }
}

/// Heuristic: tag names that are likely to be ancestor elements in error
/// recovery. We rewind rather than discarding close tags for these.
fn is_likely_ancestor_close(tag: &str) -> bool {
    matches!(
        tag,
        "html" | "head" | "body" | "table" | "thead" | "tbody" | "tfoot" | "tr"
            | "div" | "section" | "article" | "aside" | "nav" | "main" | "form"
            | "ul" | "ol" | "dl" | "details" | "fieldset" | "figure"
    )
}

/// Parse an HTML5 string into a `DomDocument`.
///
/// This is the main entry point for HTML5 parsing, equivalent to PHP's
/// `DOMDocument::loadHTML()`. It handles:
///
/// - DOCTYPE declarations
/// - Void elements (`<br>`, `<img>`, etc.)
/// - Optional and implicit closing tags
/// - Boolean and unquoted attributes
/// - Entity references (named and numeric)
/// - Comments
/// - Raw text elements (`<script>`, `<style>`)
/// - Basic error recovery for malformed markup
///
/// Tag names and attribute names are lowercased to match browser behavior.
///
/// # Examples
///
/// ```
/// use php_rs_ext_dom::dom_html5_parse;
///
/// let doc = dom_html5_parse("<p>Hello <b>world</b>!</p>").unwrap();
/// let root = doc.document_element.as_ref().unwrap();
/// assert_eq!(root.tag_name, "html");
/// ```
pub fn dom_html5_parse(html: &str) -> Result<DomDocument, String> {
    Html5Parser::new(html).parse()
}

// ── XML escape helpers ──────────────────────────────────────────────────────

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn xml_escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Document creation and manipulation ──────────────────────────────

    #[test]
    fn test_create_empty_document() {
        let doc = DomDocument::new();
        assert_eq!(doc.version, "1.0");
        assert_eq!(doc.encoding, "UTF-8");
        assert!(doc.document_element.is_none());
    }

    #[test]
    fn test_create_element_and_serialize() {
        let doc = DomDocument::new();
        let mut root = doc.create_element("root");
        let mut child = doc.create_element("child");
        child.set_attribute("id", "c1");
        child.append_child(DomNode::Text(doc.create_text_node("Hello")));
        root.append_child(DomNode::Element(child));

        let mut doc = doc;
        doc.set_document_element(root);

        let xml = doc.save_xml();
        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<root>"));
        assert!(xml.contains("<child id=\"c1\">Hello</child>"));
        assert!(xml.contains("</root>"));
    }

    #[test]
    fn test_element_attributes() {
        let mut elem = DomElement::new("div");
        elem.set_attribute("class", "container");
        elem.set_attribute("id", "main");

        assert_eq!(elem.get_attribute("class"), Some("container"));
        assert_eq!(elem.get_attribute("id"), Some("main"));
        assert!(elem.has_attribute("class"));
        assert!(!elem.has_attribute("style"));

        elem.remove_attribute("class");
        assert!(!elem.has_attribute("class"));
        assert_eq!(elem.get_attribute("class"), None);
    }

    #[test]
    fn test_append_and_remove_child() {
        let mut parent = DomElement::new("parent");
        parent.append_child(DomNode::Element(DomElement::new("a")));
        parent.append_child(DomNode::Element(DomElement::new("b")));
        parent.append_child(DomNode::Element(DomElement::new("c")));

        assert_eq!(parent.child_count(), 3);

        let removed = parent.remove_child(1).unwrap();
        assert_eq!(removed.node_name(), "b");
        assert_eq!(parent.child_count(), 2);

        // First child is still 'a', second is now 'c'.
        assert_eq!(parent.children[0].node_name(), "a");
        assert_eq!(parent.children[1].node_name(), "c");
    }

    #[test]
    fn test_insert_before() {
        let mut parent = DomElement::new("parent");
        parent.append_child(DomNode::Element(DomElement::new("a")));
        parent.append_child(DomNode::Element(DomElement::new("c")));

        parent.insert_before(DomNode::Element(DomElement::new("b")), 1);

        assert_eq!(parent.child_count(), 3);
        assert_eq!(parent.children[0].node_name(), "a");
        assert_eq!(parent.children[1].node_name(), "b");
        assert_eq!(parent.children[2].node_name(), "c");
    }

    #[test]
    fn test_text_content() {
        let mut root = DomElement::new("root");
        root.append_child(DomNode::Text(DomText::new("Hello ")));
        let mut span = DomElement::new("span");
        span.append_child(DomNode::Text(DomText::new("World")));
        root.append_child(DomNode::Element(span));
        root.append_child(DomNode::Text(DomText::new("!")));

        assert_eq!(root.text_content(), "Hello World!");
    }

    #[test]
    fn test_get_elements_by_tag_name() {
        let mut root = DomElement::new("root");
        let mut div1 = DomElement::new("div");
        div1.set_attribute("id", "d1");
        let mut div2 = DomElement::new("div");
        div2.set_attribute("id", "d2");
        let p = DomElement::new("p");

        div1.append_child(DomNode::Element(div2));
        root.append_child(DomNode::Element(div1));
        root.append_child(DomNode::Element(p));

        let divs = root.get_elements_by_tag_name("div");
        assert_eq!(divs.len(), 2);

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 1);

        let all = root.get_elements_by_tag_name("*");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_document_get_element_by_id() {
        let mut doc = DomDocument::new();
        let mut root = doc.create_element("html");
        let mut body = doc.create_element("body");
        let mut div = doc.create_element("div");
        div.set_attribute("id", "main");
        div.append_child(DomNode::Text(DomText::new("content")));
        body.append_child(DomNode::Element(div));
        root.append_child(DomNode::Element(body));
        doc.set_document_element(root);

        let found = doc.get_element_by_id("main");
        assert!(found.is_some());
        assert_eq!(found.unwrap().tag_name, "div");

        let not_found = doc.get_element_by_id("nonexistent");
        assert!(not_found.is_none());
    }

    // ── XML Parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_simple_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<root>
  <item id="1">First</item>
  <item id="2">Second</item>
</root>"#;

        let doc = load_xml(xml).unwrap();
        assert_eq!(doc.version, "1.0");
        assert_eq!(doc.encoding, "UTF-8");

        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "root");

        let items = doc.get_elements_by_tag_name("item");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get_attribute("id"), Some("1"));
        assert_eq!(items[0].text_content(), "First");
        assert_eq!(items[1].get_attribute("id"), Some("2"));
        assert_eq!(items[1].text_content(), "Second");
    }

    #[test]
    fn test_parse_self_closing_elements() {
        let xml = r#"<root><br/><hr /><img src="test.png"/></root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.children.len(), 3);
        assert_eq!(root.children[0].node_name(), "br");
        assert_eq!(root.children[1].node_name(), "hr");
        assert_eq!(root.children[2].node_name(), "img");
    }

    #[test]
    fn test_parse_entity_references() {
        let xml = r#"<root>&lt;hello&gt; &amp; &quot;world&quot;</root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.text_content(), "<hello> & \"world\"");
    }

    #[test]
    fn test_parse_cdata() {
        let xml = r#"<root><![CDATA[<not> &xml;]]></root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.children.len(), 1);
        if let DomNode::CDataSection(ref s) = root.children[0] {
            assert_eq!(s, "<not> &xml;");
        } else {
            panic!("Expected CDATA section");
        }
    }

    #[test]
    fn test_parse_comments() {
        let xml = r#"<root><!-- A comment --><child/></root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.children.len(), 2);
        if let DomNode::Comment(ref c) = root.children[0] {
            assert_eq!(c.data, " A comment ");
        } else {
            panic!("Expected comment node");
        }
    }

    #[test]
    fn test_parse_nested_elements() {
        let xml = r#"<a><b><c>deep</c></b></a>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "a");

        if let DomNode::Element(ref b) = root.children[0] {
            assert_eq!(b.tag_name, "b");
            if let DomNode::Element(ref c) = b.children[0] {
                assert_eq!(c.tag_name, "c");
                assert_eq!(c.text_content(), "deep");
            } else {
                panic!("Expected element c");
            }
        } else {
            panic!("Expected element b");
        }
    }

    #[test]
    fn test_parse_mismatched_tags() {
        let xml = r#"<a><b></a></b>"#;
        let result = load_xml(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_attributes_with_entities() {
        let xml = r#"<root attr="a&amp;b"/>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.get_attribute("attr"), Some("a&b"));
    }

    #[test]
    fn test_parse_numeric_character_refs() {
        let xml = r#"<root>&#65;&#x42;</root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.text_content(), "AB");
    }

    #[test]
    fn test_roundtrip_serialize_parse() {
        let mut doc = DomDocument::new();
        let mut root = doc.create_element("catalog");
        let mut book = doc.create_element("book");
        book.set_attribute("isbn", "978-0-123456-78-9");
        let mut title = doc.create_element("title");
        title.append_child(DomNode::Text(DomText::new("Rust Programming")));
        book.append_child(DomNode::Element(title));
        root.append_child(DomNode::Element(book));
        doc.set_document_element(root);

        let xml = doc.save_xml();
        let doc2 = load_xml(&xml).unwrap();

        let root2 = doc2.document_element.as_ref().unwrap();
        assert_eq!(root2.tag_name, "catalog");
        let books = doc2.get_elements_by_tag_name("book");
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].get_attribute("isbn"), Some("978-0-123456-78-9"));
    }

    // ── Tree manipulation ───────────────────────────────────────────────

    #[test]
    fn test_add_remove_children() {
        let mut root = DomElement::new("root");
        let a = DomElement::new("a");
        let b = DomElement::new("b");
        let c = DomElement::new("c");

        root.append_child(DomNode::Element(a));
        root.append_child(DomNode::Element(b));
        root.append_child(DomNode::Element(c));
        assert_eq!(root.child_count(), 3);

        // Remove middle child.
        root.remove_child(1);
        assert_eq!(root.child_count(), 2);
        assert_eq!(root.children[0].node_name(), "a");
        assert_eq!(root.children[1].node_name(), "c");

        // Remove non-existent.
        assert!(root.remove_child(10).is_none());
    }

    #[test]
    fn test_mixed_content() {
        let xml = r#"<p>Hello <b>world</b>!</p>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.children.len(), 3);
        assert_eq!(root.text_content(), "Hello world!");
    }

    // ── XPath ───────────────────────────────────────────────────────────

    #[test]
    fn test_xpath_descendant() {
        let xml = r#"<root><a><b><c/></b></a><c/></root>"#;
        let doc = load_xml(xml).unwrap();
        let results = DomXPath::query("//c", &doc);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_xpath_absolute_path() {
        let xml = r#"<root><a><b>text</b></a></root>"#;
        let doc = load_xml(xml).unwrap();

        let results = DomXPath::query("/root/a/b", &doc);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text_content(), "text");
    }

    #[test]
    fn test_xpath_with_attribute_predicate() {
        let xml = r#"<root><item type="a"/><item type="b"/><item/></root>"#;
        let doc = load_xml(xml).unwrap();

        let results = DomXPath::query("//item[@type]", &doc);
        assert_eq!(results.len(), 2);

        let results = DomXPath::query("//item[@type='b']", &doc);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_xpath_wildcard() {
        let xml = r#"<root><a/><b/><c/></root>"#;
        let doc = load_xml(xml).unwrap();
        let results = DomXPath::query("/root/*", &doc);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_xpath_no_match() {
        let xml = r#"<root><a/></root>"#;
        let doc = load_xml(xml).unwrap();
        let results = DomXPath::query("//nonexistent", &doc);
        assert!(results.is_empty());
    }

    // ── DomNodeList ─────────────────────────────────────────────────────

    #[test]
    fn test_node_list() {
        let nodes = vec![
            DomNode::Element(DomElement::new("a")),
            DomNode::Element(DomElement::new("b")),
        ];
        let list = DomNodeList::new(nodes);
        assert_eq!(list.length(), 2);
        assert_eq!(list.item(0).unwrap().node_name(), "a");
        assert_eq!(list.item(1).unwrap().node_name(), "b");
        assert!(list.item(2).is_none());
    }

    #[test]
    fn test_node_list_iteration() {
        let nodes = vec![
            DomNode::Element(DomElement::new("x")),
            DomNode::Element(DomElement::new("y")),
            DomNode::Element(DomElement::new("z")),
        ];
        let list = DomNodeList::new(nodes);
        let names: Vec<&str> = list.iter().map(|n| n.node_name()).collect();
        assert_eq!(names, vec!["x", "y", "z"]);
    }

    // ── Node types ──────────────────────────────────────────────────────

    #[test]
    fn test_node_types() {
        let elem = DomNode::Element(DomElement::new("div"));
        assert_eq!(elem.node_type(), DomNodeType::Element);

        let text = DomNode::Text(DomText::new("hello"));
        assert_eq!(text.node_type(), DomNodeType::Text);

        let comment = DomNode::Comment(DomComment::new("note"));
        assert_eq!(comment.node_type(), DomNodeType::Comment);

        let attr = DomNode::Attribute(DomAttr::new("key", "val"));
        assert_eq!(attr.node_type(), DomNodeType::Attribute);

        let cdata = DomNode::CDataSection("raw".to_string());
        assert_eq!(cdata.node_type(), DomNodeType::CDataSection);
    }

    // ── Serialization edge cases ────────────────────────────────────────

    #[test]
    fn test_serialize_special_chars() {
        let mut root = DomElement::new("root");
        root.append_child(DomNode::Text(DomText::new("a < b & c > d")));
        let xml = root.to_xml();
        assert_eq!(xml, "<root>a &lt; b &amp; c &gt; d</root>");
    }

    #[test]
    fn test_serialize_attribute_special_chars() {
        let mut root = DomElement::new("root");
        root.set_attribute("val", "a\"b'c&d");
        let xml = root.to_xml();
        assert!(xml.contains("val=\"a&quot;b&apos;c&amp;d\""));
    }

    #[test]
    fn test_serialize_empty_element() {
        let root = DomElement::new("br");
        assert_eq!(root.to_xml(), "<br/>");
    }

    #[test]
    fn test_document_standalone() {
        let mut doc = DomDocument::new();
        doc.standalone = Some(true);
        doc.set_document_element(DomElement::new("root"));
        let xml = doc.save_xml();
        assert!(xml.contains("standalone=\"yes\""));
    }

    #[test]
    fn test_create_processing_instruction() {
        let doc = DomDocument::new();
        let pi = doc.create_processing_instruction("php", "echo 'hi';");
        if let DomNode::ProcessingInstruction {
            ref target,
            ref data,
        } = pi
        {
            assert_eq!(target, "php");
            assert_eq!(data, "echo 'hi';");
        } else {
            panic!("Expected PI");
        }
    }

    #[test]
    fn test_parse_processing_instruction() {
        let xml = r#"<root><?php echo 'hi'; ?></root>"#;
        let doc = load_xml(xml).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.children.len(), 1);
        if let DomNode::ProcessingInstruction {
            ref target,
            ref data,
        } = root.children[0]
        {
            assert_eq!(target, "php");
            assert_eq!(data, "echo 'hi';");
        } else {
            panic!("Expected PI, got {:?}", root.children[0]);
        }
    }

    // ── Complex document test ───────────────────────────────────────────

    #[test]
    fn test_complex_document() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<library>
  <book isbn="978-0-13-468599-1">
    <title>The Rust Programming Language</title>
    <author>Steve Klabnik</author>
    <author>Carol Nichols</author>
    <year>2019</year>
  </book>
  <book isbn="978-1-491-92728-1">
    <title>Programming Rust</title>
    <author>Jim Blandy</author>
    <year>2021</year>
  </book>
</library>"#;

        let doc = load_xml(xml).unwrap();

        // Query all books.
        let books = doc.get_elements_by_tag_name("book");
        assert_eq!(books.len(), 2);

        // Query all authors.
        let authors = doc.get_elements_by_tag_name("author");
        assert_eq!(authors.len(), 3);

        // XPath: find all books.
        let results = DomXPath::query("//book", &doc);
        assert_eq!(results.len(), 2);

        // XPath: find by attribute.
        let results = DomXPath::query("//book[@isbn='978-1-491-92728-1']", &doc);
        assert_eq!(results.len(), 1);
        if let DomNode::Element(ref e) = results[0] {
            let titles = e.get_elements_by_tag_name("title");
            assert_eq!(titles[0].text_content(), "Programming Rust");
        }

        // XPath: absolute path.
        let results = DomXPath::query("/library/book", &doc);
        assert_eq!(results.len(), 2);
    }

    // ── HTML5 Parser ─────────────────────────────────────────────────────

    #[test]
    fn test_html5_parse_basic_document() {
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body><p>Hello World</p></body>
</html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "html");

        let heads = root.get_elements_by_tag_name("head");
        assert_eq!(heads.len(), 1);

        let titles = root.get_elements_by_tag_name("title");
        assert_eq!(titles.len(), 1);
        assert_eq!(titles[0].text_content(), "Test");

        let bodies = root.get_elements_by_tag_name("body");
        assert_eq!(bodies.len(), 1);

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].text_content(), "Hello World");
    }

    #[test]
    fn test_html5_void_elements() {
        let html = r#"<html><body>
<br>
<hr>
<img src="logo.png" alt="Logo">
<input type="text" value="hello">
<meta charset="utf-8">
<link rel="stylesheet" href="style.css">
</body></html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let brs = root.get_elements_by_tag_name("br");
        assert_eq!(brs.len(), 1);
        assert_eq!(brs[0].child_count(), 0);

        let hrs = root.get_elements_by_tag_name("hr");
        assert_eq!(hrs.len(), 1);
        assert_eq!(hrs[0].child_count(), 0);

        let imgs = root.get_elements_by_tag_name("img");
        assert_eq!(imgs.len(), 1);
        assert_eq!(imgs[0].get_attribute("src"), Some("logo.png"));
        assert_eq!(imgs[0].get_attribute("alt"), Some("Logo"));
        assert_eq!(imgs[0].child_count(), 0);

        let inputs = root.get_elements_by_tag_name("input");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].get_attribute("type"), Some("text"));

        let metas = root.get_elements_by_tag_name("meta");
        assert_eq!(metas.len(), 1);

        let links = root.get_elements_by_tag_name("link");
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_html5_self_closing_syntax() {
        // HTML5 allows self-closing syntax on void elements.
        let html = r#"<html><body><br/><hr /><img src="x" /></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let brs = root.get_elements_by_tag_name("br");
        assert_eq!(brs.len(), 1);
        assert_eq!(brs[0].child_count(), 0);

        let hrs = root.get_elements_by_tag_name("hr");
        assert_eq!(hrs.len(), 1);

        let imgs = root.get_elements_by_tag_name("img");
        assert_eq!(imgs.len(), 1);
    }

    #[test]
    fn test_html5_boolean_attributes() {
        let html = r#"<html><body>
<input type="checkbox" checked disabled>
<select><option selected>One</option></select>
</body></html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let inputs = root.get_elements_by_tag_name("input");
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].has_attribute("checked"));
        assert!(inputs[0].has_attribute("disabled"));
        assert_eq!(inputs[0].get_attribute("type"), Some("checkbox"));

        let options = root.get_elements_by_tag_name("option");
        assert_eq!(options.len(), 1);
        assert!(options[0].has_attribute("selected"));
    }

    #[test]
    fn test_html5_tag_name_case_insensitivity() {
        let html = r#"<HTML><BODY><DIV CLASS="test">Content</DIV></BODY></HTML>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "html");

        let divs = root.get_elements_by_tag_name("div");
        assert_eq!(divs.len(), 1);
        assert_eq!(divs[0].get_attribute("class"), Some("test"));
        assert_eq!(divs[0].text_content(), "Content");
    }

    #[test]
    fn test_html5_comments() {
        let html = r#"<html><body><!-- A comment --><p>Text</p><!-- Another --></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let bodies = root.get_elements_by_tag_name("body");
        assert_eq!(bodies.len(), 1);

        let body = bodies[0];
        let comments: Vec<&DomNode> = body
            .children
            .iter()
            .filter(|n| matches!(n, DomNode::Comment(_)))
            .collect();
        assert_eq!(comments.len(), 2);

        if let DomNode::Comment(ref c) = comments[0] {
            assert_eq!(c.data, " A comment ");
        }
        if let DomNode::Comment(ref c) = comments[1] {
            assert_eq!(c.data, " Another ");
        }
    }

    #[test]
    fn test_html5_entity_references() {
        let html = r#"<html><body><p>&lt;hello&gt; &amp; &quot;world&quot;</p></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps[0].text_content(), "<hello> & \"world\"");
    }

    #[test]
    fn test_html5_nbsp_entity() {
        let html = r#"<html><body><p>Hello&nbsp;World</p></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps[0].text_content(), "Hello\u{00A0}World");
    }

    #[test]
    fn test_html5_numeric_character_refs() {
        let html = r#"<html><body>&#65;&#x42;</body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let bodies = root.get_elements_by_tag_name("body");
        assert_eq!(bodies[0].text_content(), "AB");
    }

    #[test]
    fn test_html5_nested_structure() {
        let html = r#"<!DOCTYPE html>
<html>
<body>
  <div id="container">
    <h1>Title</h1>
    <ul>
      <li>Item 1</li>
      <li>Item 2</li>
      <li>Item 3</li>
    </ul>
  </div>
</body>
</html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let h1s = root.get_elements_by_tag_name("h1");
        assert_eq!(h1s.len(), 1);
        assert_eq!(h1s[0].text_content(), "Title");

        let lis = root.get_elements_by_tag_name("li");
        assert_eq!(lis.len(), 3);
        assert_eq!(lis[0].text_content(), "Item 1");
        assert_eq!(lis[1].text_content(), "Item 2");
        assert_eq!(lis[2].text_content(), "Item 3");

        let container = doc.get_element_by_id("container");
        assert!(container.is_some());
        assert_eq!(container.unwrap().tag_name, "div");
    }

    #[test]
    fn test_html5_mixed_content() {
        let html = r#"<html><body><p>Hello <b>bold</b> and <i>italic</i> text</p></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].text_content(), "Hello bold and italic text");
    }

    #[test]
    fn test_html5_script_raw_text() {
        let html = r#"<html><body><script>var x = 1 < 2 && 3 > 0;</script><p>After</p></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let scripts = root.get_elements_by_tag_name("script");
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].text_content(), "var x = 1 < 2 && 3 > 0;");

        // Ensure elements after the script are parsed correctly.
        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].text_content(), "After");
    }

    #[test]
    fn test_html5_style_raw_text() {
        let html = r#"<html><head><style>body { color: red; } p > span { font-weight: bold; }</style></head><body></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let styles = root.get_elements_by_tag_name("style");
        assert_eq!(styles.len(), 1);
        assert_eq!(
            styles[0].text_content(),
            "body { color: red; } p > span { font-weight: bold; }"
        );
    }

    #[test]
    fn test_html5_implicit_html_wrapper() {
        // When no <html> element is present, the parser wraps in <html><body>.
        let html = r#"<p>Just a paragraph</p>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "html");

        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].text_content(), "Just a paragraph");
    }

    #[test]
    fn test_html5_unclosed_tags_error_recovery() {
        // Unclosed tags should be implicitly closed at EOF.
        let html = r#"<html><body><div><p>Unclosed paragraph<p>Another paragraph</div></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        // Both paragraphs should be parsed.
        let ps = root.get_elements_by_tag_name("p");
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn test_html5_attributes_with_various_quotes() {
        let html = r#"<html><body><div class="double" id='single' data-x=unquoted></div></body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let divs = root.get_elements_by_tag_name("div");
        assert_eq!(divs.len(), 1);
        assert_eq!(divs[0].get_attribute("class"), Some("double"));
        assert_eq!(divs[0].get_attribute("id"), Some("single"));
        assert_eq!(divs[0].get_attribute("data-x"), Some("unquoted"));
    }

    #[test]
    fn test_html5_doctype_handling() {
        let html = r#"<!DOCTYPE html><html><head></head><body>OK</body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "html");

        let bodies = root.get_elements_by_tag_name("body");
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].text_content(), "OK");
    }

    #[test]
    fn test_html5_complex_page() {
        let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Page</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About</a>
        </nav>
    </header>
    <main>
        <article>
            <h1>Welcome</h1>
            <p>This is a <strong>test</strong> page with <em>various</em> elements.</p>
            <img src="photo.jpg" alt="A photo">
            <br>
            <ul>
                <li>First</li>
                <li>Second</li>
                <li>Third</li>
            </ul>
        </article>
    </main>
    <footer>
        <p>&copy; 2024</p>
    </footer>
</body>
</html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        assert_eq!(root.tag_name, "html");
        assert_eq!(root.get_attribute("lang"), Some("en"));

        // Check structure.
        let titles = root.get_elements_by_tag_name("title");
        assert_eq!(titles.len(), 1);
        assert_eq!(titles[0].text_content(), "Test Page");

        let links_a = root.get_elements_by_tag_name("a");
        assert_eq!(links_a.len(), 2);
        assert_eq!(links_a[0].get_attribute("href"), Some("/"));
        assert_eq!(links_a[0].text_content(), "Home");

        let h1s = root.get_elements_by_tag_name("h1");
        assert_eq!(h1s.len(), 1);
        assert_eq!(h1s[0].text_content(), "Welcome");

        let imgs = root.get_elements_by_tag_name("img");
        assert_eq!(imgs.len(), 1);
        assert_eq!(imgs[0].get_attribute("alt"), Some("A photo"));
        assert_eq!(imgs[0].child_count(), 0);

        let lis = root.get_elements_by_tag_name("li");
        assert_eq!(lis.len(), 3);

        // XPath should work on parsed HTML5 documents too.
        let articles = DomXPath::query("//article", &doc);
        assert_eq!(articles.len(), 1);

        let strong = DomXPath::query("//strong", &doc);
        assert_eq!(strong.len(), 1);
        assert_eq!(strong[0].text_content(), "test");
    }

    #[test]
    fn test_html5_void_elements_in_sequence() {
        // Verify void elements don't consume subsequent content.
        let html = r#"<html><body>Before<br>Between<hr>After</body></html>"#;
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let bodies = root.get_elements_by_tag_name("body");
        let body = bodies[0];
        // Should have: Text("Before"), br, Text("Between"), hr, Text("After")
        assert_eq!(body.child_count(), 5);
        assert_eq!(body.text_content(), "BeforeBetweenAfter");
    }

    #[test]
    fn test_html5_empty_document() {
        let html = "";
        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();
        // Should produce an empty <html><body></body></html>.
        assert_eq!(root.tag_name, "html");
    }

    #[test]
    fn test_html5_table_structure() {
        let html = r#"<html><body>
<table>
  <thead><tr><th>Name</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>A</td><td>1</td></tr>
    <tr><td>B</td><td>2</td></tr>
  </tbody>
</table>
</body></html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let tables = root.get_elements_by_tag_name("table");
        assert_eq!(tables.len(), 1);

        let ths = root.get_elements_by_tag_name("th");
        assert_eq!(ths.len(), 2);
        assert_eq!(ths[0].text_content(), "Name");

        let tds = root.get_elements_by_tag_name("td");
        assert_eq!(tds.len(), 4);
        assert_eq!(tds[0].text_content(), "A");
        assert_eq!(tds[3].text_content(), "2");
    }

    #[test]
    fn test_html5_form_elements() {
        let html = r#"<html><body>
<form action="/submit" method="post">
  <label for="name">Name:</label>
  <input type="text" id="name" name="name" required>
  <textarea name="bio">Default text</textarea>
  <button type="submit">Send</button>
</form>
</body></html>"#;

        let doc = dom_html5_parse(html).unwrap();
        let root = doc.document_element.as_ref().unwrap();

        let forms = root.get_elements_by_tag_name("form");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].get_attribute("action"), Some("/submit"));
        assert_eq!(forms[0].get_attribute("method"), Some("post"));

        let inputs = root.get_elements_by_tag_name("input");
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].has_attribute("required"));
        assert_eq!(inputs[0].child_count(), 0);

        let textareas = root.get_elements_by_tag_name("textarea");
        assert_eq!(textareas.len(), 1);
        assert_eq!(textareas[0].text_content(), "Default text");

        let buttons = root.get_elements_by_tag_name("button");
        assert_eq!(buttons.len(), 1);
        assert_eq!(buttons[0].text_content(), "Send");
    }
}
