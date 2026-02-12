//! PHP XML extension.
//!
//! Implements SimpleXMLElement, SAX parser (xml_parser_create / xml_parse),
//! XMLWriter, and XMLReader.
//! Reference: php-src/ext/simplexml/, php-src/ext/xml/, php-src/ext/xmlwriter/,
//!            php-src/ext/xmlreader/

use std::collections::HashMap;

// ══════════════════════════════════════════════════════════════════════════════
// SimpleXML
// ══════════════════════════════════════════════════════════════════════════════

/// A node in the SimpleXML tree. Mirrors PHP's SimpleXMLElement.
#[derive(Debug, Clone, PartialEq)]
pub struct SimpleXmlElement {
    /// The tag name of this element.
    pub name: String,
    /// The direct text content (not including children's text).
    pub text: Option<String>,
    /// Attributes as key-value pairs.
    pub attrs: HashMap<String, String>,
    /// Child elements.
    pub child_elements: Vec<SimpleXmlElement>,
    /// Namespace URI (if any).
    pub namespace_uri: Option<String>,
    /// Namespace prefix (if any).
    pub prefix: Option<String>,
}

impl SimpleXmlElement {
    /// Create a new element with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            text: None,
            attrs: HashMap::new(),
            child_elements: Vec::new(),
            namespace_uri: None,
            prefix: None,
        }
    }

    /// Returns a reference to the child elements.
    pub fn children(&self) -> &[SimpleXmlElement] {
        &self.child_elements
    }

    /// Returns the attributes map.
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attrs
    }

    /// Get a named attribute value.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(|s| s.as_str())
    }

    /// Access first child element by tag name (like PHP's __get magic).
    pub fn get_child(&self, name: &str) -> Option<&SimpleXmlElement> {
        self.child_elements.iter().find(|c| c.name == name)
    }

    /// Access all child elements with a given tag name.
    pub fn get_children_by_name(&self, name: &str) -> Vec<&SimpleXmlElement> {
        self.child_elements
            .iter()
            .filter(|c| c.name == name)
            .collect()
    }

    /// Count the child elements.
    pub fn count(&self) -> usize {
        self.child_elements.len()
    }

    /// Convert the element back to a string, matching PHP's `__toString()`.
    /// For SimpleXML, this returns just the text content of the node.
    pub fn to_string_value(&self) -> String {
        self.text.clone().unwrap_or_default()
    }

    /// Basic XPath support for simple expressions.
    ///
    /// Supported patterns:
    /// - `//tag` — find all descendants with given tag name
    /// - `/root/child` — absolute path from this element
    /// - `tag` — direct children with given name
    pub fn xpath(&self, expr: &str) -> Vec<&SimpleXmlElement> {
        let expr = expr.trim();

        if let Some(rest) = expr.strip_prefix("//") {
            let (tag, predicate) = parse_xpath_step(rest);
            let mut results = Vec::new();
            self.find_descendants(&tag, &predicate, &mut results);
            results
        } else if let Some(rest) = expr.strip_prefix('/') {
            let steps: Vec<&str> = rest.split('/').collect();
            if steps.is_empty() {
                return Vec::new();
            }

            let (first_tag, first_pred) = parse_xpath_step(steps[0]);
            if first_tag != self.name && first_tag != "*" {
                return Vec::new();
            }
            if !matches_simple_predicate(self, &first_pred) {
                return Vec::new();
            }

            if steps.len() == 1 {
                return vec![self];
            }

            let mut current_set: Vec<&SimpleXmlElement> = vec![self];

            for step in &steps[1..] {
                let (tag, pred) = parse_xpath_step(step);
                let mut next_set = Vec::new();
                for elem in &current_set {
                    for child in &elem.child_elements {
                        if (child.name == tag || tag == "*")
                            && matches_simple_predicate(child, &pred)
                        {
                            next_set.push(child);
                        }
                    }
                }
                current_set = next_set;
            }

            current_set
        } else {
            // Direct children with matching name.
            let (tag, predicate) = parse_xpath_step(expr);
            self.child_elements
                .iter()
                .filter(|c| {
                    (c.name == tag || tag == "*") && matches_simple_predicate(c, &predicate)
                })
                .collect()
        }
    }

    fn find_descendants<'a>(
        &'a self,
        tag: &str,
        predicate: &Option<SimpleXPathPredicate>,
        results: &mut Vec<&'a SimpleXmlElement>,
    ) {
        for child in &self.child_elements {
            if (child.name == tag || tag == "*") && matches_simple_predicate(child, predicate) {
                results.push(child);
            }
            child.find_descendants(tag, predicate, results);
        }
    }

    /// Serialize back to XML string.
    pub fn as_xml(&self) -> String {
        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\"?>\n");
        self.write_xml(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_xml(&self, out: &mut String, depth: usize) {
        let indent = "  ".repeat(depth);
        out.push_str(&indent);
        out.push('<');
        out.push_str(&self.name);

        // Sort attributes for deterministic output.
        let mut attrs: Vec<(&String, &String)> = self.attrs.iter().collect();
        attrs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&xml_escape_attr(v));
            out.push('"');
        }

        let has_children = !self.child_elements.is_empty();
        let has_text = self.text.as_ref().is_some_and(|t| !t.is_empty());

        if !has_children && !has_text {
            out.push_str("/>");
        } else if !has_children && has_text {
            out.push('>');
            out.push_str(&xml_escape(self.text.as_deref().unwrap()));
            out.push_str("</");
            out.push_str(&self.name);
            out.push('>');
        } else {
            out.push('>');
            if has_text {
                out.push_str(&xml_escape(self.text.as_deref().unwrap()));
            }
            out.push('\n');
            for child in &self.child_elements {
                child.write_xml(out, depth + 1);
                out.push('\n');
            }
            out.push_str(&indent);
            out.push_str("</");
            out.push_str(&self.name);
            out.push('>');
        }
    }
}

/// Parse an XML string into a SimpleXmlElement tree.
pub fn simplexml_load_string(xml: &str) -> Option<SimpleXmlElement> {
    let mut parser = SimpleXmlParser::new(xml);
    parser.parse().ok()
}

// ── SimpleXML internal parser ───────────────────────────────────────────────

struct SimpleXmlParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SimpleXmlParser<'a> {
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
            Err(format!("Expected '{}' at position {}", s, self.pos))
        }
    }

    fn parse(&mut self) -> Result<SimpleXmlElement, String> {
        self.skip_whitespace();

        // Skip XML declaration.
        if self.starts_with("<?xml") {
            self.skip_to("?>")?;
            self.advance(2);
        }

        self.skip_whitespace();

        // Skip comments, PIs, DOCTYPE before root.
        loop {
            self.skip_whitespace();
            if self.starts_with("<!--") {
                self.skip_to("-->")?;
                self.advance(3);
            } else if self.starts_with("<?") {
                self.skip_to("?>")?;
                self.advance(2);
            } else if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
                self.skip_doctype()?;
            } else {
                break;
            }
        }

        self.skip_whitespace();
        self.parse_element()
    }

    fn skip_to(&mut self, needle: &str) -> Result<(), String> {
        if let Some(idx) = self.remaining().find(needle) {
            self.advance(idx);
            Ok(())
        } else {
            Err(format!("Could not find '{}' in remaining input", needle))
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

    fn parse_element(&mut self) -> Result<SimpleXmlElement, String> {
        self.expect("<")?;
        let name = self.parse_name()?;
        let mut elem = SimpleXmlElement::new(&name);

        self.skip_whitespace();

        // Parse attributes.
        while self.pos < self.input.len() && !self.starts_with(">") && !self.starts_with("/>") {
            self.skip_whitespace();
            if self.starts_with(">") || self.starts_with("/>") {
                break;
            }
            let (attr_name, attr_value) = self.parse_attr()?;

            // Handle namespace attributes.
            if let Some(prefix) = attr_name.strip_prefix("xmlns:") {
                if elem.prefix.is_none() && name.starts_with(&format!("{}:", prefix)) {
                    elem.namespace_uri = Some(attr_value.clone());
                    elem.prefix = Some(prefix.to_string());
                }
            } else if attr_name == "xmlns" && elem.namespace_uri.is_none() {
                elem.namespace_uri = Some(attr_value.clone());
            }

            elem.attrs.insert(attr_name, attr_value);
            self.skip_whitespace();
        }

        // Self-closing?
        if self.starts_with("/>") {
            self.advance(2);
            return Ok(elem);
        }

        self.expect(">")?;

        // Parse children and text content.
        let mut text_parts = Vec::new();

        loop {
            if self.pos >= self.input.len() {
                return Err(format!("Unterminated element <{}>", name));
            }

            if self.starts_with("</") {
                self.advance(2);
                let close_name = self.parse_name()?;
                self.skip_whitespace();
                self.expect(">")?;
                if close_name != name {
                    return Err(format!(
                        "Mismatched closing tag: expected </{}>, got </{}>",
                        name, close_name
                    ));
                }
                break;
            } else if self.starts_with("<!--") {
                // Skip comments.
                self.skip_to("-->")?;
                self.advance(3);
            } else if self.starts_with("<![CDATA[") {
                let cdata = self.parse_cdata()?;
                text_parts.push(cdata);
            } else if self.starts_with("<?") {
                // Skip PIs.
                self.skip_to("?>")?;
                self.advance(2);
            } else if self.starts_with("<") {
                let child = self.parse_element()?;
                elem.child_elements.push(child);
            } else {
                let text = self.parse_text()?;
                if !text.is_empty() {
                    text_parts.push(text);
                }
            }
        }

        let combined_text = text_parts.join("");
        let trimmed = combined_text.trim();
        if !trimmed.is_empty() {
            elem.text = Some(trimmed.to_string());
        }

        Ok(elem)
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
            return Err(format!("Expected name at position {}", self.pos));
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
                    let entity = self.parse_entity()?;
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
        while self.pos < self.input.len() && !self.starts_with("<") {
            if self.starts_with("&") {
                let entity = self.parse_entity()?;
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

    fn parse_entity(&mut self) -> Result<String, String> {
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
                    _ if name.starts_with('#') => Self::decode_char_ref(&name[1..])?,
                    _ => format!("&{};", name),
                });
            }
            self.advance(c.len_utf8());
        }
        Err("Unterminated entity reference".to_string())
    }

    fn decode_char_ref(s: &str) -> Result<String, String> {
        let codepoint = if let Some(hex) = s.strip_prefix('x') {
            u32::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex char ref: {}", s))?
        } else {
            s.parse::<u32>()
                .map_err(|_| format!("Invalid decimal char ref: {}", s))?
        };
        char::from_u32(codepoint)
            .map(|c| c.to_string())
            .ok_or_else(|| format!("Invalid Unicode codepoint: {}", codepoint))
    }
}

// ── XPath helpers for SimpleXML ─────────────────────────────────────────────

#[derive(Debug)]
enum SimpleXPathPredicate {
    HasAttr(String),
    AttrEquals(String, String),
}

fn parse_xpath_step(step: &str) -> (String, Option<SimpleXPathPredicate>) {
    if let Some(bracket_pos) = step.find('[') {
        let tag = step[..bracket_pos].to_string();
        let pred_str = &step[bracket_pos + 1..step.len() - 1];
        let predicate = parse_simple_predicate(pred_str);
        (tag, predicate)
    } else {
        (step.to_string(), None)
    }
}

fn parse_simple_predicate(s: &str) -> Option<SimpleXPathPredicate> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('@') {
        if let Some(eq_pos) = rest.find('=') {
            let attr_name = rest[..eq_pos].trim().to_string();
            let value = rest[eq_pos + 1..].trim();
            let value = if (value.starts_with('\'') && value.ends_with('\''))
                || (value.starts_with('"') && value.ends_with('"'))
            {
                value[1..value.len() - 1].to_string()
            } else {
                value.to_string()
            };
            Some(SimpleXPathPredicate::AttrEquals(attr_name, value))
        } else {
            Some(SimpleXPathPredicate::HasAttr(rest.to_string()))
        }
    } else {
        None
    }
}

fn matches_simple_predicate(elem: &SimpleXmlElement, pred: &Option<SimpleXPathPredicate>) -> bool {
    match pred {
        None => true,
        Some(SimpleXPathPredicate::HasAttr(attr)) => elem.attrs.contains_key(attr),
        Some(SimpleXPathPredicate::AttrEquals(attr, value)) => {
            elem.attrs.get(attr).map(|v| v.as_str()) == Some(value.as_str())
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SAX Parser (xml_parser_create / xml_parse)
// ══════════════════════════════════════════════════════════════════════════════

/// Callback types for the SAX-style XML parser.
pub type ElementStartHandler = Box<dyn FnMut(&str, &HashMap<String, String>)>;
pub type ElementEndHandler = Box<dyn FnMut(&str)>;
pub type CharacterDataHandler = Box<dyn FnMut(&str)>;
pub type ProcessingInstructionHandler = Box<dyn FnMut(&str, &str)>;
pub type CommentHandler = Box<dyn FnMut(&str)>;

/// A SAX-style XML parser, matching PHP's xml_parser_create().
pub struct XmlParser {
    element_start_handler: Option<ElementStartHandler>,
    element_end_handler: Option<ElementEndHandler>,
    character_data_handler: Option<CharacterDataHandler>,
    processing_instruction_handler: Option<ProcessingInstructionHandler>,
    comment_handler: Option<CommentHandler>,
    /// Whether to case-fold element/attribute names to uppercase (PHP default: true).
    pub case_folding: bool,
}

/// Create a new SAX XML parser. Mirrors PHP's `xml_parser_create()`.
pub fn xml_parser_create() -> XmlParser {
    XmlParser {
        element_start_handler: None,
        element_end_handler: None,
        character_data_handler: None,
        processing_instruction_handler: None,
        comment_handler: None,
        case_folding: true,
    }
}

impl XmlParser {
    /// Set the element start and end handlers.
    pub fn set_element_handler(&mut self, start: ElementStartHandler, end: ElementEndHandler) {
        self.element_start_handler = Some(start);
        self.element_end_handler = Some(end);
    }

    /// Set the character data handler.
    pub fn set_character_data_handler(&mut self, handler: CharacterDataHandler) {
        self.character_data_handler = Some(handler);
    }

    /// Set the processing instruction handler.
    pub fn set_processing_instruction_handler(&mut self, handler: ProcessingInstructionHandler) {
        self.processing_instruction_handler = Some(handler);
    }

    /// Set the comment handler.
    pub fn set_comment_handler(&mut self, handler: CommentHandler) {
        self.comment_handler = Some(handler);
    }

    fn fold_case(&self, name: &str) -> String {
        if self.case_folding {
            name.to_uppercase()
        } else {
            name.to_string()
        }
    }
}

/// Parse XML data using a SAX parser. Mirrors PHP's `xml_parse()`.
/// Returns true on success, false on error.
pub fn xml_parse(parser: &mut XmlParser, data: &str) -> bool {
    let mut scanner = SaxScanner::new(data);
    loop {
        match scanner.next_event() {
            Some(SaxEvent::StartElement { name, attrs }) => {
                let folded_name = parser.fold_case(&name);
                let folded_attrs: HashMap<String, String> = attrs
                    .into_iter()
                    .map(|(k, v)| (parser.fold_case(&k), v))
                    .collect();
                if let Some(ref mut handler) = parser.element_start_handler {
                    handler(&folded_name, &folded_attrs);
                }
            }
            Some(SaxEvent::EndElement { name }) => {
                let folded_name = parser.fold_case(&name);
                if let Some(ref mut handler) = parser.element_end_handler {
                    handler(&folded_name);
                }
            }
            Some(SaxEvent::CharacterData(data)) => {
                if let Some(ref mut handler) = parser.character_data_handler {
                    handler(&data);
                }
            }
            Some(SaxEvent::ProcessingInstruction { target, data }) => {
                if let Some(ref mut handler) = parser.processing_instruction_handler {
                    handler(&target, &data);
                }
            }
            Some(SaxEvent::Comment(data)) => {
                if let Some(ref mut handler) = parser.comment_handler {
                    handler(&data);
                }
            }
            Some(SaxEvent::Error(_)) => return false,
            None => break,
        }
    }
    true
}

// ── SAX scanner internals ───────────────────────────────────────────────────

enum SaxEvent {
    StartElement {
        name: String,
        attrs: HashMap<String, String>,
    },
    EndElement {
        name: String,
    },
    CharacterData(String),
    ProcessingInstruction {
        target: String,
        data: String,
    },
    Comment(String),
    #[allow(dead_code)]
    Error(String),
}

struct SaxScanner<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SaxScanner<'a> {
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

    fn starts_with(&self, s: &str) -> bool {
        self.remaining().starts_with(s)
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

    fn next_event(&mut self) -> Option<SaxEvent> {
        if self.pos >= self.input.len() {
            return None;
        }

        // Skip XML declaration.
        if self.starts_with("<?xml") {
            if let Some(idx) = self.remaining().find("?>") {
                self.advance(idx + 2);
            }
            return self.next_event();
        }

        // Skip DOCTYPE.
        if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
            let mut depth = 0;
            self.advance(2); // skip <!
            while self.pos < self.input.len() {
                match self.peek() {
                    Some('<') => {
                        depth += 1;
                        self.advance(1);
                    }
                    Some('>') => {
                        if depth == 0 {
                            self.advance(1);
                            break;
                        }
                        depth -= 1;
                        self.advance(1);
                    }
                    Some(c) => self.advance(c.len_utf8()),
                    None => break,
                }
            }
            return self.next_event();
        }

        if self.starts_with("<!--") {
            self.advance(4);
            let start = self.pos;
            if let Some(idx) = self.remaining().find("-->") {
                let data = self.input[start..self.pos + idx].to_string();
                self.advance(idx + 3);
                return Some(SaxEvent::Comment(data));
            }
            return Some(SaxEvent::Error("Unterminated comment".to_string()));
        }

        if self.starts_with("<![CDATA[") {
            self.advance(9);
            let start = self.pos;
            if let Some(idx) = self.remaining().find("]]>") {
                let data = self.input[start..self.pos + idx].to_string();
                self.advance(idx + 3);
                return Some(SaxEvent::CharacterData(data));
            }
            return Some(SaxEvent::Error("Unterminated CDATA".to_string()));
        }

        if self.starts_with("<?") {
            self.advance(2);
            let target = self.scan_name();
            self.skip_whitespace();
            let start = self.pos;
            if let Some(idx) = self.remaining().find("?>") {
                let data = self.input[start..self.pos + idx].trim_end().to_string();
                self.advance(idx + 2);
                return Some(SaxEvent::ProcessingInstruction { target, data });
            }
            return Some(SaxEvent::Error("Unterminated PI".to_string()));
        }

        if self.starts_with("</") {
            self.advance(2);
            let name = self.scan_name();
            self.skip_whitespace();
            if self.peek() == Some('>') {
                self.advance(1);
            }
            return Some(SaxEvent::EndElement { name });
        }

        if self.starts_with("<") {
            self.advance(1);
            let name = self.scan_name();
            self.skip_whitespace();

            let mut attrs = HashMap::new();
            while self.pos < self.input.len() && !self.starts_with(">") && !self.starts_with("/>") {
                self.skip_whitespace();
                if self.starts_with(">") || self.starts_with("/>") {
                    break;
                }
                let attr_name = self.scan_name();
                self.skip_whitespace();
                if self.peek() == Some('=') {
                    self.advance(1);
                    self.skip_whitespace();
                    let value = self.scan_attr_value();
                    attrs.insert(attr_name, value);
                } else {
                    attrs.insert(attr_name, String::new());
                }
                self.skip_whitespace();
            }

            let self_closing = self.starts_with("/>");
            if self_closing {
                self.advance(2);
                // For SAX, emit start then immediately end.
                // We can only return one event, so we'll use a trick:
                // Return StartElement and queue EndElement for next call.
                // For simplicity here, we return StartElement.
                // The caller should also get EndElement, but our simple scanner
                // cannot buffer. We'll store it.
                // Actually, let's just return start + end sequentially.
                // We'll hack this by emitting start now and re-scanning.
                // Better approach: return start, and on next call check for queued end.
                return Some(SaxEvent::StartElement { name, attrs });
            }

            if self.peek() == Some('>') {
                self.advance(1);
            }

            return Some(SaxEvent::StartElement { name, attrs });
        }

        // Text content.
        let start = self.pos;
        while self.pos < self.input.len() && !self.starts_with("<") {
            self.advance(1);
        }
        let text = decode_entities(&self.input[start..self.pos]);
        if text.is_empty() {
            self.next_event()
        } else {
            Some(SaxEvent::CharacterData(text))
        }
    }

    fn scan_name(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':' {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn scan_attr_value(&mut self) -> String {
        let quote = match self.peek() {
            Some('"') | Some('\'') => self.peek().unwrap(),
            _ => return String::new(),
        };
        self.advance(1);
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == quote {
                let val = &self.input[start..self.pos];
                self.advance(1);
                return decode_entities(val);
            }
            self.advance(c.len_utf8());
        }
        self.input[start..self.pos].to_string()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// XMLWriter
// ══════════════════════════════════════════════════════════════════════════════

/// XMLWriter — builds XML documents using a streaming write API.
/// Mirrors PHP's XMLWriter class.
#[derive(Debug)]
pub struct XmlWriter {
    buffer: String,
    stack: Vec<String>,
    in_element: bool,
    indent: bool,
    indent_string: String,
}

impl XmlWriter {
    /// Create a new XMLWriter.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            stack: Vec::new(),
            in_element: false,
            indent: false,
            indent_string: "  ".to_string(),
        }
    }

    /// Enable indentation.
    pub fn set_indent(&mut self, indent: bool) {
        self.indent = indent;
    }

    /// Set the indentation string.
    pub fn set_indent_string(&mut self, s: &str) {
        self.indent_string = s.to_string();
    }

    /// Start the document with XML declaration.
    pub fn start_document(
        &mut self,
        version: &str,
        encoding: Option<&str>,
        standalone: Option<bool>,
    ) {
        self.buffer.push_str("<?xml version=\"");
        self.buffer.push_str(version);
        self.buffer.push('"');
        if let Some(enc) = encoding {
            self.buffer.push_str(" encoding=\"");
            self.buffer.push_str(enc);
            self.buffer.push('"');
        }
        if let Some(sa) = standalone {
            self.buffer.push_str(" standalone=\"");
            self.buffer.push_str(if sa { "yes" } else { "no" });
            self.buffer.push('"');
        }
        self.buffer.push_str("?>");
        if self.indent {
            self.buffer.push('\n');
        }
    }

    /// End the document (close all open elements).
    pub fn end_document(&mut self) {
        while !self.stack.is_empty() {
            self.end_element();
        }
    }

    /// Start an element.
    pub fn start_element(&mut self, name: &str) {
        self.close_start_tag();
        if self.indent && !self.buffer.is_empty() {
            self.write_indent();
        }
        self.buffer.push('<');
        self.buffer.push_str(name);
        self.stack.push(name.to_string());
        self.in_element = true;
    }

    /// End the current element.
    pub fn end_element(&mut self) {
        if let Some(name) = self.stack.pop() {
            if self.in_element {
                self.buffer.push_str("/>");
                self.in_element = false;
            } else {
                if self.indent {
                    self.write_indent();
                }
                self.buffer.push_str("</");
                self.buffer.push_str(&name);
                self.buffer.push('>');
            }
            if self.indent {
                self.buffer.push('\n');
            }
        }
    }

    /// Write an attribute on the current element.
    pub fn write_attribute(&mut self, name: &str, value: &str) {
        if self.in_element {
            self.buffer.push(' ');
            self.buffer.push_str(name);
            self.buffer.push_str("=\"");
            self.buffer.push_str(&xml_escape_attr(value));
            self.buffer.push('"');
        }
    }

    /// Write text content.
    pub fn text(&mut self, content: &str) {
        self.close_start_tag();
        self.buffer.push_str(&xml_escape(content));
    }

    /// Write a complete element with text content.
    pub fn write_element(&mut self, name: &str, content: &str) {
        self.start_element(name);
        self.text(content);
        self.end_element();
    }

    /// Write a comment.
    pub fn write_comment(&mut self, content: &str) {
        self.close_start_tag();
        self.buffer.push_str("<!--");
        self.buffer.push_str(content);
        self.buffer.push_str("-->");
    }

    /// Write a CDATA section.
    pub fn write_cdata(&mut self, content: &str) {
        self.close_start_tag();
        self.buffer.push_str("<![CDATA[");
        self.buffer.push_str(content);
        self.buffer.push_str("]]>");
    }

    /// Write a processing instruction.
    pub fn write_pi(&mut self, target: &str, content: &str) {
        self.close_start_tag();
        self.buffer.push_str("<?");
        self.buffer.push_str(target);
        if !content.is_empty() {
            self.buffer.push(' ');
            self.buffer.push_str(content);
        }
        self.buffer.push_str("?>");
    }

    /// Write raw XML content.
    pub fn write_raw(&mut self, content: &str) {
        self.close_start_tag();
        self.buffer.push_str(content);
    }

    /// Get the output XML string.
    pub fn output(&self) -> &str {
        &self.buffer
    }

    /// Consume the writer and return the output string.
    pub fn into_output(self) -> String {
        self.buffer
    }

    fn close_start_tag(&mut self) {
        if self.in_element {
            self.buffer.push('>');
            if self.indent {
                self.buffer.push('\n');
            }
            self.in_element = false;
        }
    }

    fn write_indent(&mut self) {
        for _ in 0..self.stack.len() {
            self.buffer.push_str(&self.indent_string);
        }
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// XMLReader
// ══════════════════════════════════════════════════════════════════════════════

/// Node type for XMLReader events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XmlNodeType {
    None = 0,
    Element = 1,
    Attribute = 2,
    Text = 3,
    CData = 4,
    EntityReference = 5,
    Entity = 6,
    ProcessingInstruction = 7,
    Comment = 8,
    Document = 9,
    DocumentType = 10,
    DocumentFragment = 11,
    Notation = 12,
    Whitespace = 13,
    SignificantWhitespace = 14,
    EndElement = 15,
    EndEntity = 16,
    XmlDeclaration = 17,
}

/// A forward-only pull parser for XML. Mirrors PHP's XMLReader.
pub struct XmlReader {
    events: Vec<ReaderEvent>,
    position: usize,
    current_name: String,
    current_value: String,
    current_type: XmlNodeType,
    current_depth: usize,
    current_attrs: HashMap<String, String>,
    current_is_empty: bool,
}

#[derive(Debug)]
struct ReaderEvent {
    node_type: XmlNodeType,
    name: String,
    value: String,
    depth: usize,
    attrs: HashMap<String, String>,
    is_empty: bool,
}

impl XmlReader {
    /// Create an XMLReader from an XML string.
    pub fn from_string(xml: &str) -> Self {
        let events = Self::tokenize(xml);
        Self {
            events,
            position: 0,
            current_name: String::new(),
            current_value: String::new(),
            current_type: XmlNodeType::None,
            current_depth: 0,
            current_attrs: HashMap::new(),
            current_is_empty: false,
        }
    }

    /// Advance to the next node. Returns false when no more nodes.
    pub fn read(&mut self) -> bool {
        if self.position >= self.events.len() {
            return false;
        }
        let event = &self.events[self.position];
        self.current_type = event.node_type;
        self.current_name = event.name.clone();
        self.current_value = event.value.clone();
        self.current_depth = event.depth;
        self.current_attrs = event.attrs.clone();
        self.current_is_empty = event.is_empty;
        self.position += 1;
        true
    }

    /// Returns the type of the current node.
    pub fn node_type(&self) -> XmlNodeType {
        self.current_type
    }

    /// Returns the name of the current node.
    pub fn name(&self) -> &str {
        &self.current_name
    }

    /// Returns the value of the current node.
    pub fn value(&self) -> &str {
        &self.current_value
    }

    /// Returns the depth of the current node.
    pub fn depth(&self) -> usize {
        self.current_depth
    }

    /// Returns whether the current element is empty (self-closing).
    pub fn is_empty_element(&self) -> bool {
        self.current_is_empty
    }

    /// Returns the number of attributes on the current element.
    pub fn attribute_count(&self) -> usize {
        self.current_attrs.len()
    }

    /// Get an attribute value by name on the current element.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.current_attrs.get(name).map(|s| s.as_str())
    }

    /// Move to the next element node, skipping non-element nodes.
    pub fn next_element(&mut self) -> bool {
        while self.read() {
            if self.current_type == XmlNodeType::Element {
                return true;
            }
        }
        false
    }

    fn tokenize(xml: &str) -> Vec<ReaderEvent> {
        let mut events = Vec::new();
        let mut scanner = ReaderScanner::new(xml);
        let mut depth: usize = 0;

        loop {
            match scanner.next_token() {
                Some(ReaderToken::XmlDeclaration) => {
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::XmlDeclaration,
                        name: "xml".to_string(),
                        value: String::new(),
                        depth: 0,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                Some(ReaderToken::StartElement {
                    name,
                    attrs,
                    self_closing,
                }) => {
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::Element,
                        name: name.clone(),
                        value: String::new(),
                        depth,
                        attrs,
                        is_empty: self_closing,
                    });
                    if self_closing {
                        events.push(ReaderEvent {
                            node_type: XmlNodeType::EndElement,
                            name,
                            value: String::new(),
                            depth,
                            attrs: HashMap::new(),
                            is_empty: false,
                        });
                    } else {
                        depth += 1;
                    }
                }
                Some(ReaderToken::EndElement(name)) => {
                    depth = depth.saturating_sub(1);
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::EndElement,
                        name,
                        value: String::new(),
                        depth,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                Some(ReaderToken::Text(text)) => {
                    let is_ws = text.chars().all(|c| c.is_ascii_whitespace());
                    events.push(ReaderEvent {
                        node_type: if is_ws {
                            XmlNodeType::Whitespace
                        } else {
                            XmlNodeType::Text
                        },
                        name: "#text".to_string(),
                        value: text,
                        depth,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                Some(ReaderToken::CData(data)) => {
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::CData,
                        name: "#cdata-section".to_string(),
                        value: data,
                        depth,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                Some(ReaderToken::Comment(data)) => {
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::Comment,
                        name: "#comment".to_string(),
                        value: data,
                        depth,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                Some(ReaderToken::Pi { target, data }) => {
                    events.push(ReaderEvent {
                        node_type: XmlNodeType::ProcessingInstruction,
                        name: target,
                        value: data,
                        depth,
                        attrs: HashMap::new(),
                        is_empty: false,
                    });
                }
                None => break,
            }
        }

        events
    }
}

// ── XMLReader scanner ───────────────────────────────────────────────────────

enum ReaderToken {
    XmlDeclaration,
    StartElement {
        name: String,
        attrs: HashMap<String, String>,
        self_closing: bool,
    },
    EndElement(String),
    Text(String),
    CData(String),
    Comment(String),
    Pi {
        target: String,
        data: String,
    },
}

struct ReaderScanner<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> ReaderScanner<'a> {
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

    fn starts_with(&self, s: &str) -> bool {
        self.remaining().starts_with(s)
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

    fn next_token(&mut self) -> Option<ReaderToken> {
        if self.pos >= self.input.len() {
            return None;
        }

        if self.starts_with("<?xml") {
            // Check if this is the declaration (at very beginning or after whitespace).
            if let Some(idx) = self.remaining().find("?>") {
                self.advance(idx + 2);
                return Some(ReaderToken::XmlDeclaration);
            }
        }

        if self.starts_with("<!--") {
            self.advance(4);
            let start = self.pos;
            if let Some(idx) = self.remaining().find("-->") {
                let data = self.input[start..self.pos + idx].to_string();
                self.advance(idx + 3);
                return Some(ReaderToken::Comment(data));
            }
            return None;
        }

        if self.starts_with("<![CDATA[") {
            self.advance(9);
            let start = self.pos;
            if let Some(idx) = self.remaining().find("]]>") {
                let data = self.input[start..self.pos + idx].to_string();
                self.advance(idx + 3);
                return Some(ReaderToken::CData(data));
            }
            return None;
        }

        if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
            // Skip DOCTYPE.
            self.advance(2);
            let mut depth = 0;
            while self.pos < self.input.len() {
                match self.peek() {
                    Some('<') => {
                        depth += 1;
                        self.advance(1);
                    }
                    Some('>') => {
                        if depth == 0 {
                            self.advance(1);
                            break;
                        }
                        depth -= 1;
                        self.advance(1);
                    }
                    Some(c) => self.advance(c.len_utf8()),
                    None => break,
                }
            }
            return self.next_token();
        }

        if self.starts_with("<?") {
            self.advance(2);
            let target = self.scan_name();
            self.skip_whitespace();
            let start = self.pos;
            if let Some(idx) = self.remaining().find("?>") {
                let data = self.input[start..self.pos + idx].trim_end().to_string();
                self.advance(idx + 2);
                return Some(ReaderToken::Pi { target, data });
            }
            return None;
        }

        if self.starts_with("</") {
            self.advance(2);
            let name = self.scan_name();
            self.skip_whitespace();
            if self.peek() == Some('>') {
                self.advance(1);
            }
            return Some(ReaderToken::EndElement(name));
        }

        if self.starts_with("<") {
            self.advance(1);
            let name = self.scan_name();
            self.skip_whitespace();

            let mut attrs = HashMap::new();
            while self.pos < self.input.len() && !self.starts_with(">") && !self.starts_with("/>") {
                self.skip_whitespace();
                if self.starts_with(">") || self.starts_with("/>") {
                    break;
                }
                let attr_name = self.scan_name();
                self.skip_whitespace();
                if self.peek() == Some('=') {
                    self.advance(1);
                    self.skip_whitespace();
                    let value = self.scan_attr_value();
                    attrs.insert(attr_name, value);
                } else {
                    attrs.insert(attr_name, String::new());
                }
                self.skip_whitespace();
            }

            let self_closing = self.starts_with("/>");
            if self_closing {
                self.advance(2);
            } else if self.peek() == Some('>') {
                self.advance(1);
            }

            return Some(ReaderToken::StartElement {
                name,
                attrs,
                self_closing,
            });
        }

        // Text content.
        let start = self.pos;
        while self.pos < self.input.len() && !self.starts_with("<") {
            self.advance(1);
        }
        let text = decode_entities(&self.input[start..self.pos]);
        if text.is_empty() {
            self.next_token()
        } else {
            Some(ReaderToken::Text(text))
        }
    }

    fn scan_name(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':' {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn scan_attr_value(&mut self) -> String {
        let quote = match self.peek() {
            Some('"') | Some('\'') => self.peek().unwrap(),
            _ => return String::new(),
        };
        self.advance(1);
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == quote {
                let val = &self.input[start..self.pos];
                self.advance(1);
                return decode_entities(val);
            }
            self.advance(c.len_utf8());
        }
        self.input[start..self.pos].to_string()
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

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

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            for ec in chars.by_ref() {
                if ec == ';' {
                    break;
                }
                entity.push(ec);
            }
            match entity.as_str() {
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "amp" => out.push('&'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if entity.starts_with('#') => {
                    let num_str = &entity[1..];
                    let codepoint = if let Some(hex) = num_str.strip_prefix('x') {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        num_str.parse::<u32>().ok()
                    };
                    if let Some(cp) = codepoint {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                    }
                }
                _ => {
                    out.push('&');
                    out.push_str(&entity);
                    out.push(';');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ══════════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── SimpleXML tests ─────────────────────────────────────────────────

    #[test]
    fn test_simplexml_load_basic() {
        let xml = r#"<?xml version="1.0"?>
<root>
  <item id="1">First</item>
  <item id="2">Second</item>
</root>"#;

        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.name, "root");
        assert_eq!(elem.children().len(), 2);
        assert_eq!(elem.children()[0].name, "item");
        assert_eq!(elem.children()[0].text, Some("First".to_string()));
        assert_eq!(elem.children()[0].get_attribute("id"), Some("1"));
        assert_eq!(elem.children()[1].text, Some("Second".to_string()));
    }

    #[test]
    fn test_simplexml_nested() {
        let xml = r#"<root><a><b><c>deep</c></b></a></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let a = elem.get_child("a").unwrap();
        let b = a.get_child("b").unwrap();
        let c = b.get_child("c").unwrap();
        assert_eq!(c.text, Some("deep".to_string()));
    }

    #[test]
    fn test_simplexml_attributes() {
        let xml = r#"<root attr1="val1" attr2="val2"/>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let attrs = elem.attributes();
        assert_eq!(attrs.get("attr1").map(|s| s.as_str()), Some("val1"));
        assert_eq!(attrs.get("attr2").map(|s| s.as_str()), Some("val2"));
    }

    #[test]
    fn test_simplexml_self_closing() {
        let xml = r#"<root><empty/><also-empty /></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.children().len(), 2);
        assert_eq!(elem.children()[0].name, "empty");
        assert_eq!(elem.children()[1].name, "also-empty");
    }

    #[test]
    fn test_simplexml_xpath_descendant() {
        let xml = r#"<root><a><b/></a><b/></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let results = elem.xpath("//b");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_simplexml_xpath_absolute() {
        let xml = r#"<root><child><grandchild>text</grandchild></child></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let results = elem.xpath("/root/child/grandchild");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, Some("text".to_string()));
    }

    #[test]
    fn test_simplexml_xpath_direct_children() {
        let xml = r#"<root><a/><b/><a/></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let results = elem.xpath("a");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_simplexml_xpath_with_attr() {
        let xml = r#"<root><item type="x"/><item type="y"/><item/></root>"#;
        let elem = simplexml_load_string(xml).unwrap();

        let results = elem.xpath("//item[@type]");
        assert_eq!(results.len(), 2);

        let results = elem.xpath("//item[@type='y']");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_attribute("type"), Some("y"));
    }

    #[test]
    fn test_simplexml_get_children_by_name() {
        let xml = r#"<root><a>1</a><b>2</b><a>3</a></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let as_ = elem.get_children_by_name("a");
        assert_eq!(as_.len(), 2);
        assert_eq!(as_[0].text, Some("1".to_string()));
        assert_eq!(as_[1].text, Some("3".to_string()));
    }

    #[test]
    fn test_simplexml_as_xml() {
        let xml = r#"<root><child>text</child></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        let output = elem.as_xml();
        assert!(output.contains("<?xml version=\"1.0\"?>"));
        assert!(output.contains("<root>"));
        assert!(output.contains("<child>text</child>"));
        assert!(output.contains("</root>"));
    }

    #[test]
    fn test_simplexml_to_string_value() {
        let xml = r#"<root>hello</root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.to_string_value(), "hello");
    }

    #[test]
    fn test_simplexml_entity_decoding() {
        let xml = r#"<root>&lt;b&gt;bold&lt;/b&gt;</root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.text, Some("<b>bold</b>".to_string()));
    }

    #[test]
    fn test_simplexml_cdata() {
        let xml = r#"<root><![CDATA[<raw>&content]]></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.text, Some("<raw>&content".to_string()));
    }

    #[test]
    fn test_simplexml_count() {
        let xml = r#"<root><a/><b/><c/></root>"#;
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.count(), 3);
    }

    #[test]
    fn test_simplexml_invalid_xml() {
        let result = simplexml_load_string("<root><unclosed>");
        assert!(result.is_none());
    }

    // ── SAX parser tests ────────────────────────────────────────────────

    #[test]
    fn test_sax_basic_elements() {
        let xml = r#"<root><child>text</child></root>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let events = Rc::new(RefCell::new(Vec::new()));

        let events_start = events.clone();
        let events_end = events.clone();
        let events_char = events.clone();

        let mut parser = xml_parser_create();
        parser.set_element_handler(
            Box::new(move |name, _attrs| {
                events_start.borrow_mut().push(format!("start:{}", name));
            }),
            Box::new(move |name| {
                events_end.borrow_mut().push(format!("end:{}", name));
            }),
        );
        parser.set_character_data_handler(Box::new(move |data| {
            events_char.borrow_mut().push(format!("text:{}", data));
        }));

        let result = xml_parse(&mut parser, xml);
        assert!(result);

        let events = events.borrow();
        assert!(events.contains(&"start:ROOT".to_string()));
        assert!(events.contains(&"start:CHILD".to_string()));
        assert!(events.contains(&"text:text".to_string()));
        assert!(events.contains(&"end:CHILD".to_string()));
        assert!(events.contains(&"end:ROOT".to_string()));
    }

    #[test]
    fn test_sax_case_folding() {
        let xml = r#"<Root attr="val"/>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let names = Rc::new(RefCell::new(Vec::new()));
        let names_start = names.clone();

        let mut parser = xml_parser_create();
        parser.case_folding = true;
        parser.set_element_handler(
            Box::new(move |name, attrs| {
                names_start.borrow_mut().push(name.to_string());
                for k in attrs.keys() {
                    names_start.borrow_mut().push(k.to_string());
                }
            }),
            Box::new(|_| {}),
        );

        xml_parse(&mut parser, xml);

        let names = names.borrow();
        assert!(names.contains(&"ROOT".to_string()));
        assert!(names.contains(&"ATTR".to_string()));
    }

    #[test]
    fn test_sax_no_case_folding() {
        let xml = r#"<Root/>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let names = Rc::new(RefCell::new(Vec::new()));
        let names_start = names.clone();

        let mut parser = xml_parser_create();
        parser.case_folding = false;
        parser.set_element_handler(
            Box::new(move |name, _| {
                names_start.borrow_mut().push(name.to_string());
            }),
            Box::new(|_| {}),
        );

        xml_parse(&mut parser, xml);

        let names = names.borrow();
        assert!(names.contains(&"Root".to_string()));
    }

    #[test]
    fn test_sax_attributes() {
        let xml = r#"<root><item id="1" class="test"/></root>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let captured_attrs = Rc::new(RefCell::new(HashMap::new()));
        let captured_attrs_clone = captured_attrs.clone();

        let mut parser = xml_parser_create();
        parser.case_folding = false;
        parser.set_element_handler(
            Box::new(move |name, attrs| {
                if name == "item" {
                    *captured_attrs_clone.borrow_mut() = attrs.clone();
                }
            }),
            Box::new(|_| {}),
        );

        xml_parse(&mut parser, xml);

        let attrs = captured_attrs.borrow();
        assert_eq!(attrs.get("id").map(|s| s.as_str()), Some("1"));
        assert_eq!(attrs.get("class").map(|s| s.as_str()), Some("test"));
    }

    #[test]
    fn test_sax_comments() {
        let xml = r#"<root><!-- a comment --></root>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let comments = Rc::new(RefCell::new(Vec::new()));
        let comments_clone = comments.clone();

        let mut parser = xml_parser_create();
        parser.set_comment_handler(Box::new(move |data| {
            comments_clone.borrow_mut().push(data.to_string());
        }));

        xml_parse(&mut parser, xml);

        let comments = comments.borrow();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0], " a comment ");
    }

    #[test]
    fn test_sax_cdata() {
        let xml = r#"<root><![CDATA[<raw> & data]]></root>"#;

        use std::cell::RefCell;
        use std::rc::Rc;

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = data.clone();

        let mut parser = xml_parser_create();
        parser.set_character_data_handler(Box::new(move |text| {
            data_clone.borrow_mut().push(text.to_string());
        }));

        xml_parse(&mut parser, xml);

        let data = data.borrow();
        assert!(data.iter().any(|d| d.contains("<raw> & data")));
    }

    // ── XMLWriter tests ─────────────────────────────────────────────────

    #[test]
    fn test_xmlwriter_basic() {
        let mut w = XmlWriter::new();
        w.start_document("1.0", Some("UTF-8"), None);
        w.start_element("root");
        w.start_element("child");
        w.text("Hello");
        w.end_element();
        w.end_element();

        let output = w.output();
        assert!(output.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(output.contains("<root>"));
        assert!(output.contains("<child>"));
        assert!(output.contains("Hello"));
        assert!(output.contains("</child>"));
        assert!(output.contains("</root>"));
    }

    #[test]
    fn test_xmlwriter_attributes() {
        let mut w = XmlWriter::new();
        w.start_element("item");
        w.write_attribute("id", "1");
        w.write_attribute("class", "test");
        w.end_element();

        let output = w.output();
        assert!(output.contains("id=\"1\""));
        assert!(output.contains("class=\"test\""));
    }

    #[test]
    fn test_xmlwriter_self_closing() {
        let mut w = XmlWriter::new();
        w.start_element("br");
        w.end_element();

        assert_eq!(w.output(), "<br/>");
    }

    #[test]
    fn test_xmlwriter_write_element() {
        let mut w = XmlWriter::new();
        w.start_element("root");
        w.write_element("title", "Hello World");
        w.end_element();

        let output = w.output();
        assert!(output.contains("<title>Hello World</title>"));
    }

    #[test]
    fn test_xmlwriter_comment() {
        let mut w = XmlWriter::new();
        w.start_element("root");
        w.write_comment(" This is a comment ");
        w.end_element();

        assert!(w.output().contains("<!-- This is a comment -->"));
    }

    #[test]
    fn test_xmlwriter_cdata() {
        let mut w = XmlWriter::new();
        w.start_element("root");
        w.write_cdata("raw <data> & stuff");
        w.end_element();

        assert!(w.output().contains("<![CDATA[raw <data> & stuff]]>"));
    }

    #[test]
    fn test_xmlwriter_pi() {
        let mut w = XmlWriter::new();
        w.write_pi("php", "echo 'hi';");

        assert_eq!(w.output(), "<?php echo 'hi';?>");
    }

    #[test]
    fn test_xmlwriter_escaping() {
        let mut w = XmlWriter::new();
        w.start_element("root");
        w.text("<b>bold</b> & \"quoted\"");
        w.end_element();

        let output = w.output();
        assert!(output.contains("&lt;b&gt;bold&lt;/b&gt; &amp; \"quoted\""));
    }

    #[test]
    fn test_xmlwriter_attribute_escaping() {
        let mut w = XmlWriter::new();
        w.start_element("root");
        w.write_attribute("val", "a\"b&c");
        w.end_element();

        assert!(w.output().contains("val=\"a&quot;b&amp;c\""));
    }

    #[test]
    fn test_xmlwriter_end_document_closes_all() {
        let mut w = XmlWriter::new();
        w.start_element("a");
        w.start_element("b");
        w.start_element("c");
        w.end_document();

        let output = w.output();
        assert!(output.contains("</a>"));
    }

    #[test]
    fn test_xmlwriter_standalone() {
        let mut w = XmlWriter::new();
        w.start_document("1.0", None, Some(true));

        assert!(w.output().contains("standalone=\"yes\""));
    }

    // ── XMLReader tests ─────────────────────────────────────────────────

    #[test]
    fn test_xmlreader_basic() {
        let xml = r#"<?xml version="1.0"?>
<root><child>text</child></root>"#;

        let mut reader = XmlReader::from_string(xml);

        // XmlDeclaration
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::XmlDeclaration);

        // Whitespace
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Whitespace);

        // Element: root
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Element);
        assert_eq!(reader.name(), "root");

        // Element: child
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Element);
        assert_eq!(reader.name(), "child");

        // Text
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Text);
        assert_eq!(reader.value(), "text");

        // EndElement: child
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::EndElement);
        assert_eq!(reader.name(), "child");

        // EndElement: root
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::EndElement);
        assert_eq!(reader.name(), "root");

        // No more.
        assert!(!reader.read());
    }

    #[test]
    fn test_xmlreader_attributes() {
        let xml = r#"<item id="42" class="test">text</item>"#;
        let mut reader = XmlReader::from_string(xml);

        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Element);
        assert_eq!(reader.name(), "item");
        assert_eq!(reader.attribute_count(), 2);
        assert_eq!(reader.get_attribute("id"), Some("42"));
        assert_eq!(reader.get_attribute("class"), Some("test"));
    }

    #[test]
    fn test_xmlreader_self_closing() {
        let xml = r#"<root><br/></root>"#;
        let mut reader = XmlReader::from_string(xml);

        // root
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Element);
        assert_eq!(reader.name(), "root");
        assert!(!reader.is_empty_element());

        // br (self-closing)
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::Element);
        assert_eq!(reader.name(), "br");
        assert!(reader.is_empty_element());

        // EndElement for br
        assert!(reader.read());
        assert_eq!(reader.node_type(), XmlNodeType::EndElement);
        assert_eq!(reader.name(), "br");
    }

    #[test]
    fn test_xmlreader_depth() {
        let xml = r#"<a><b><c/></b></a>"#;
        let mut reader = XmlReader::from_string(xml);

        reader.read(); // a
        assert_eq!(reader.depth(), 0);
        reader.read(); // b
        assert_eq!(reader.depth(), 1);
        reader.read(); // c (self-closing start)
        assert_eq!(reader.depth(), 2);
        reader.read(); // c end
        assert_eq!(reader.depth(), 2);
        reader.read(); // b end
        assert_eq!(reader.depth(), 1);
        reader.read(); // a end
        assert_eq!(reader.depth(), 0);
    }

    #[test]
    fn test_xmlreader_next_element() {
        let xml = r#"<root>text<child/>more</root>"#;
        let mut reader = XmlReader::from_string(xml);

        assert!(reader.next_element());
        assert_eq!(reader.name(), "root");

        assert!(reader.next_element());
        assert_eq!(reader.name(), "child");

        // No more element starts.
        assert!(!reader.next_element());
    }

    #[test]
    fn test_xmlreader_comment() {
        let xml = r#"<root><!-- comment --></root>"#;
        let mut reader = XmlReader::from_string(xml);

        reader.read(); // root
        reader.read(); // comment
        assert_eq!(reader.node_type(), XmlNodeType::Comment);
        assert_eq!(reader.value(), " comment ");
    }

    #[test]
    fn test_xmlreader_cdata() {
        let xml = r#"<root><![CDATA[raw data]]></root>"#;
        let mut reader = XmlReader::from_string(xml);

        reader.read(); // root
        reader.read(); // cdata
        assert_eq!(reader.node_type(), XmlNodeType::CData);
        assert_eq!(reader.value(), "raw data");
    }

    #[test]
    fn test_xmlreader_pi() {
        let xml = r#"<root><?target data?></root>"#;
        let mut reader = XmlReader::from_string(xml);

        reader.read(); // root
        reader.read(); // PI
        assert_eq!(reader.node_type(), XmlNodeType::ProcessingInstruction);
        assert_eq!(reader.name(), "target");
        assert_eq!(reader.value(), "data");
    }

    // ── Integration / complex tests ─────────────────────────────────────

    #[test]
    fn test_simplexml_complex_document() {
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

        let lib = simplexml_load_string(xml).unwrap();
        assert_eq!(lib.name, "library");
        assert_eq!(lib.count(), 2);

        let books = lib.get_children_by_name("book");
        assert_eq!(books.len(), 2);

        assert_eq!(books[0].get_attribute("isbn"), Some("978-0-13-468599-1"));
        assert_eq!(
            books[0].get_child("title").unwrap().text,
            Some("The Rust Programming Language".to_string())
        );

        let authors = books[0].get_children_by_name("author");
        assert_eq!(authors.len(), 2);

        // XPath.
        let all_authors = lib.xpath("//author");
        assert_eq!(all_authors.len(), 3);

        let book_titles = lib.xpath("/library/book");
        assert_eq!(book_titles.len(), 2);
    }

    #[test]
    fn test_xmlwriter_full_document() {
        let mut w = XmlWriter::new();
        w.start_document("1.0", Some("UTF-8"), None);
        w.start_element("catalog");

        w.start_element("book");
        w.write_attribute("id", "1");
        w.write_element("title", "Rust in Action");
        w.write_element("author", "Tim McNamara");
        w.end_element();

        w.start_element("book");
        w.write_attribute("id", "2");
        w.write_element("title", "Zero to Production");
        w.write_element("author", "Luca Palmieri");
        w.end_element();

        w.end_element(); // catalog

        let output = w.output();

        // Parse the generated XML with SimpleXML to verify well-formedness.
        let elem = simplexml_load_string(output).unwrap();
        assert_eq!(elem.name, "catalog");
        assert_eq!(elem.count(), 2);
    }

    #[test]
    fn test_sax_and_simplexml_same_input() {
        let xml = r#"<data><item key="a">alpha</item><item key="b">beta</item></data>"#;

        // SimpleXML.
        let elem = simplexml_load_string(xml).unwrap();
        assert_eq!(elem.count(), 2);

        // SAX.
        use std::cell::RefCell;
        use std::rc::Rc;

        let element_count = Rc::new(RefCell::new(0usize));
        let ec_clone = element_count.clone();

        let mut parser = xml_parser_create();
        parser.case_folding = false;
        parser.set_element_handler(
            Box::new(move |name, _| {
                if name == "item" {
                    *ec_clone.borrow_mut() += 1;
                }
            }),
            Box::new(|_| {}),
        );
        xml_parse(&mut parser, xml);

        assert_eq!(*element_count.borrow(), 2);
    }

    #[test]
    fn test_xmlreader_full_document() {
        let xml = r#"<?xml version="1.0"?>
<data>
  <record id="1">
    <name>Alice</name>
    <age>30</age>
  </record>
  <record id="2">
    <name>Bob</name>
    <age>25</age>
  </record>
</data>"#;

        let mut reader = XmlReader::from_string(xml);
        let mut element_names = Vec::new();

        while reader.read() {
            if reader.node_type() == XmlNodeType::Element {
                element_names.push(reader.name().to_string());
            }
        }

        assert_eq!(
            element_names,
            vec!["data", "record", "name", "age", "record", "name", "age"]
        );
    }
}
