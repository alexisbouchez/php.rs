//! PHP soap extension implementation for php.rs
//!
//! Provides SOAP web services client and server functionality.
//! Reference: php-src/ext/soap/
//!
//! This is a pure Rust implementation that provides the full API surface.
//! Network operations are stubbed for testing.

use std::collections::HashMap;

// SOAP version constants
pub const SOAP_1_1: i32 = 1;
pub const SOAP_1_2: i32 = 2;

// SOAP encoding constants
pub const SOAP_ENCODED: i32 = 1;
pub const SOAP_LITERAL: i32 = 2;

// SOAP style constants
pub const SOAP_RPC: i32 = 1;
pub const SOAP_DOCUMENT: i32 = 2;

// SOAP authentication constants
pub const SOAP_AUTHENTICATION_BASIC: i32 = 0;
pub const SOAP_AUTHENTICATION_DIGEST: i32 = 1;

// SOAP compression constants
pub const SOAP_COMPRESSION_ACCEPT: i32 = 32;
pub const SOAP_COMPRESSION_GZIP: i32 = 0;
pub const SOAP_COMPRESSION_DEFLATE: i32 = 16;

/// Error/fault type for SOAP operations.
#[derive(Debug, Clone, PartialEq)]
pub struct SoapFault {
    /// Fault code
    pub faultcode: String,
    /// Fault string (human-readable description)
    pub faultstring: String,
    /// Fault actor (URI of the service that generated the fault)
    pub faultactor: String,
    /// Detail (application-specific error information)
    pub detail: String,
}

impl SoapFault {
    /// Create a new SoapFault.
    pub fn new(faultcode: &str, faultstring: &str) -> Self {
        SoapFault {
            faultcode: faultcode.to_string(),
            faultstring: faultstring.to_string(),
            faultactor: String::new(),
            detail: String::new(),
        }
    }

    /// Create a new SoapFault with full details.
    pub fn with_details(
        faultcode: &str,
        faultstring: &str,
        faultactor: &str,
        detail: &str,
    ) -> Self {
        SoapFault {
            faultcode: faultcode.to_string(),
            faultstring: faultstring.to_string(),
            faultactor: faultactor.to_string(),
            detail: detail.to_string(),
        }
    }
}

impl std::fmt::Display for SoapFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SoapFault: [{}] {}", self.faultcode, self.faultstring)
    }
}

/// SOAP header element.
#[derive(Debug, Clone, PartialEq)]
pub struct SoapHeader {
    /// Namespace URI
    pub namespace: String,
    /// Header element name
    pub name: String,
    /// Header data
    pub data: String,
    /// Whether the header must be understood by the receiver
    pub must_understand: bool,
    /// Actor URI
    pub actor: String,
}

impl SoapHeader {
    /// Create a new SoapHeader.
    pub fn new(namespace: &str, name: &str, data: &str) -> Self {
        SoapHeader {
            namespace: namespace.to_string(),
            name: name.to_string(),
            data: data.to_string(),
            must_understand: false,
            actor: String::new(),
        }
    }
}

/// SOAP parameter for function calls.
#[derive(Debug, Clone, PartialEq)]
pub struct SoapParam {
    /// Parameter name
    pub name: String,
    /// Parameter data (serialized as string)
    pub data: String,
}

impl SoapParam {
    /// Create a new SoapParam.
    pub fn new(name: &str, data: &str) -> Self {
        SoapParam {
            name: name.to_string(),
            data: data.to_string(),
        }
    }
}

/// SOAP variable with type info.
#[derive(Debug, Clone, PartialEq)]
pub struct SoapVar {
    /// Data value
    pub data: String,
    /// XSD encoding type
    pub encoding: i32,
    /// Type name
    pub type_name: String,
    /// Type namespace
    pub type_namespace: String,
}

impl SoapVar {
    /// Create a new SoapVar.
    pub fn new(data: &str, encoding: i32) -> Self {
        SoapVar {
            data: data.to_string(),
            encoding,
            type_name: String::new(),
            type_namespace: String::new(),
        }
    }
}

/// Options for creating SOAP clients and servers.
#[derive(Debug, Clone)]
pub struct SoapOptions {
    /// SOAP version (SOAP_1_1 or SOAP_1_2)
    pub soap_version: i32,
    /// Encoding style (SOAP_ENCODED or SOAP_LITERAL)
    pub encoding: i32,
    /// Call style (SOAP_RPC or SOAP_DOCUMENT)
    pub style: i32,
    /// Service location URL
    pub location: String,
    /// Service URI
    pub uri: String,
    /// Whether to trace requests/responses
    pub trace: bool,
    /// HTTP authentication login
    pub login: String,
    /// HTTP authentication password
    pub password: String,
    /// Connection timeout in seconds
    pub connection_timeout: i32,
    /// Additional options
    pub extra: HashMap<String, String>,
}

impl Default for SoapOptions {
    fn default() -> Self {
        SoapOptions {
            soap_version: SOAP_1_1,
            encoding: SOAP_ENCODED,
            style: SOAP_RPC,
            location: String::new(),
            uri: String::new(),
            trace: false,
            login: String::new(),
            password: String::new(),
            connection_timeout: 30,
            extra: HashMap::new(),
        }
    }
}

/// SOAP response from a function call.
#[derive(Debug, Clone)]
pub struct SoapResponse {
    /// Response data
    pub data: String,
    /// Response headers
    pub headers: Vec<SoapHeader>,
}

/// SOAP client for making web service calls.
#[derive(Debug, Clone)]
pub struct SoapClient {
    /// WSDL URL (None for non-WSDL mode)
    pub wsdl: Option<String>,
    /// Service location
    pub location: String,
    /// Service URI
    pub uri: String,
    /// SOAP style
    pub style: i32,
    /// SOAP use/encoding
    pub use_: i32,
    /// Client options
    pub options: SoapOptions,
    /// Available functions (from WSDL)
    functions: Vec<String>,
    /// Available types (from WSDL)
    types: Vec<String>,
    /// Last request XML
    last_request: Option<String>,
    /// Last response XML
    last_response: Option<String>,
    /// Last request headers
    last_request_headers: Option<String>,
    /// Last response headers
    last_response_headers: Option<String>,
    /// SOAP headers to send
    soap_headers: Vec<SoapHeader>,
}

impl SoapClient {
    /// Create a new SOAP client.
    ///
    /// PHP signature: SoapClient::__construct(?string $wsdl, array $options = [])
    pub fn new(wsdl: Option<&str>, options: &SoapOptions) -> Self {
        SoapClient {
            wsdl: wsdl.map(|s| s.to_string()),
            location: options.location.clone(),
            uri: options.uri.clone(),
            style: options.style,
            use_: options.encoding,
            options: options.clone(),
            functions: Vec::new(),
            types: Vec::new(),
            last_request: None,
            last_response: None,
            last_request_headers: None,
            last_response_headers: None,
            soap_headers: Vec::new(),
        }
    }

    /// Call a SOAP function.
    ///
    /// PHP signature: SoapClient::__soapCall(string $name, array $args, ...): mixed
    pub fn call(&mut self, function: &str, args: &[SoapParam]) -> Result<SoapResponse, SoapFault> {
        if function.is_empty() {
            return Err(SoapFault::new("Client", "Function name cannot be empty"));
        }

        // Build SOAP request envelope
        let soap_ns = if self.options.soap_version == SOAP_1_2 {
            "http://www.w3.org/2003/05/soap-envelope"
        } else {
            "http://schemas.xmlsoap.org/soap/envelope/"
        };

        let mut params_xml = String::new();
        for param in args {
            params_xml.push_str(&format!("<{}>{}</{}>", param.name, param.data, param.name));
        }

        let mut headers_xml = String::new();
        if !self.soap_headers.is_empty() {
            headers_xml.push_str("<soap:Header>");
            for header in &self.soap_headers {
                headers_xml.push_str(&format!(
                    "<ns1:{} xmlns:ns1=\"{}\">{}</ns1:{}>",
                    header.name, header.namespace, header.data, header.name
                ));
            }
            headers_xml.push_str("</soap:Header>");
        }

        let request_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <soap:Envelope xmlns:soap=\"{}\">\
            {}\
            <soap:Body>\
            <{}>{}</{}>\
            </soap:Body>\
            </soap:Envelope>",
            soap_ns, headers_xml, function, params_xml, function
        );

        self.last_request = Some(request_xml);
        self.last_request_headers = Some(format!(
            "POST {} HTTP/1.1\r\nContent-Type: text/xml\r\n",
            self.location
        ));

        // Stub response
        let response_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <soap:Envelope xmlns:soap=\"{}\">\
            <soap:Body>\
            <{}Response>\
            <result>stub response</result>\
            </{}Response>\
            </soap:Body>\
            </soap:Envelope>",
            soap_ns, function, function
        );

        self.last_response = Some(response_xml);
        self.last_response_headers =
            Some("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n".to_string());

        Ok(SoapResponse {
            data: "stub response".to_string(),
            headers: Vec::new(),
        })
    }

    /// Get list of available SOAP functions.
    ///
    /// PHP signature: SoapClient::__getFunctions(): ?array
    pub fn get_functions(&self) -> Vec<String> {
        self.functions.clone()
    }

    /// Get list of available SOAP types.
    ///
    /// PHP signature: SoapClient::__getTypes(): ?array
    pub fn get_types(&self) -> Vec<String> {
        self.types.clone()
    }

    /// Get the last SOAP request XML.
    ///
    /// PHP signature: SoapClient::__getLastRequest(): ?string
    pub fn get_last_request(&self) -> Option<String> {
        self.last_request.clone()
    }

    /// Get the last SOAP response XML.
    ///
    /// PHP signature: SoapClient::__getLastResponse(): ?string
    pub fn get_last_response(&self) -> Option<String> {
        self.last_response.clone()
    }

    /// Get the last request headers.
    ///
    /// PHP signature: SoapClient::__getLastRequestHeaders(): ?string
    pub fn get_last_request_headers(&self) -> Option<String> {
        self.last_request_headers.clone()
    }

    /// Get the last response headers.
    ///
    /// PHP signature: SoapClient::__getLastResponseHeaders(): ?string
    pub fn get_last_response_headers(&self) -> Option<String> {
        self.last_response_headers.clone()
    }

    /// Set SOAP headers for subsequent calls.
    ///
    /// PHP signature: SoapClient::__setSoapHeaders(SoapHeader|array|null $headers = null): bool
    pub fn set_soap_headers(&mut self, headers: Vec<SoapHeader>) -> bool {
        self.soap_headers = headers;
        true
    }

    /// Add functions to the function list (for testing/WSDL parsing).
    pub fn add_function(&mut self, function: &str) {
        self.functions.push(function.to_string());
    }

    /// Add types to the type list (for testing/WSDL parsing).
    pub fn add_type(&mut self, type_: &str) {
        self.types.push(type_.to_string());
    }
}

/// SOAP server for handling incoming SOAP requests.
#[derive(Debug, Clone)]
pub struct SoapServer {
    /// WSDL URL (None for non-WSDL mode)
    pub wsdl: Option<String>,
    /// Registered functions
    pub functions: Vec<String>,
    /// Class name for handling requests
    pub class_name: Option<String>,
    /// Server options
    pub options: SoapOptions,
    /// Pending faults
    faults: Vec<SoapFault>,
}

impl SoapServer {
    /// Create a new SOAP server.
    ///
    /// PHP signature: SoapServer::__construct(?string $wsdl, array $options = [])
    pub fn new(wsdl: Option<&str>, options: &SoapOptions) -> Self {
        SoapServer {
            wsdl: wsdl.map(|s| s.to_string()),
            functions: Vec::new(),
            class_name: None,
            options: options.clone(),
            faults: Vec::new(),
        }
    }

    /// Register a function to handle SOAP requests.
    ///
    /// PHP signature: SoapServer::addFunction(string|array $functions): void
    pub fn add_function(&mut self, function: &str) {
        if !self.functions.contains(&function.to_string()) {
            self.functions.push(function.to_string());
        }
    }

    /// Set the class to handle SOAP requests.
    ///
    /// PHP signature: SoapServer::setClass(string $class, mixed ...$args): void
    pub fn set_class(&mut self, class_name: &str) {
        self.class_name = Some(class_name.to_string());
    }

    /// Handle a SOAP request.
    ///
    /// PHP signature: SoapServer::handle(?string $request = null): void
    pub fn handle(&self, request: &str) -> String {
        // Check for pending faults
        if let Some(fault) = self.faults.last() {
            let soap_ns = if self.options.soap_version == SOAP_1_2 {
                "http://www.w3.org/2003/05/soap-envelope"
            } else {
                "http://schemas.xmlsoap.org/soap/envelope/"
            };
            return format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <soap:Envelope xmlns:soap=\"{}\">\
                <soap:Body>\
                <soap:Fault>\
                <faultcode>{}</faultcode>\
                <faultstring>{}</faultstring>\
                </soap:Fault>\
                </soap:Body>\
                </soap:Envelope>",
                soap_ns, fault.faultcode, fault.faultstring
            );
        }

        // Parse function name from request (basic extraction)
        let function_name = extract_function_name(request);

        let soap_ns = if self.options.soap_version == SOAP_1_2 {
            "http://www.w3.org/2003/05/soap-envelope"
        } else {
            "http://schemas.xmlsoap.org/soap/envelope/"
        };

        if let Some(func) = &function_name {
            if self.functions.contains(func)
                || self.class_name.is_some()
                || self.functions.iter().any(|f| f == "SOAP_FUNCTIONS_ALL")
            {
                return format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <soap:Envelope xmlns:soap=\"{}\">\
                    <soap:Body>\
                    <{}Response>\
                    <result>handled</result>\
                    </{}Response>\
                    </soap:Body>\
                    </soap:Envelope>",
                    soap_ns, func, func
                );
            }
        }

        // Function not found
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <soap:Envelope xmlns:soap=\"{}\">\
            <soap:Body>\
            <soap:Fault>\
            <faultcode>Server</faultcode>\
            <faultstring>Function not found</faultstring>\
            </soap:Fault>\
            </soap:Body>\
            </soap:Envelope>",
            soap_ns
        )
    }

    /// Issue a SOAP fault.
    ///
    /// PHP signature: SoapServer::fault(string $code, string $string, ...): void
    pub fn fault(&mut self, code: &str, string: &str) {
        self.faults.push(SoapFault::new(code, string));
    }
}

/// Extract function name from a SOAP request XML (basic parsing).
fn extract_function_name(request: &str) -> Option<String> {
    // Look for <Body> then the first element inside it
    if let Some(body_start) = request
        .find("<soap:Body>")
        .or_else(|| request.find("<Body>"))
    {
        let after_body = &request[body_start..];
        // Skip past the Body tag
        if let Some(gt) = after_body.find('>') {
            let after_tag = &after_body[gt + 1..];
            let trimmed = after_tag.trim_start();
            if let Some(rest) = trimmed.strip_prefix('<') {
                // Extract tag name (possibly with namespace prefix)
                let end = rest.find([' ', '>', '/']).unwrap_or(rest.len());
                let tag = &rest[..end];
                // Remove namespace prefix
                let name = if let Some(pos) = tag.find(':') {
                    &tag[pos + 1..]
                } else {
                    tag
                };
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soap_client_creation() {
        let options = SoapOptions {
            location: "http://example.com/service".to_string(),
            uri: "http://example.com/ns".to_string(),
            ..SoapOptions::default()
        };
        let client = SoapClient::new(None, &options);
        assert!(client.wsdl.is_none());
        assert_eq!(client.location, "http://example.com/service");
        assert_eq!(client.uri, "http://example.com/ns");
    }

    #[test]
    fn test_soap_client_with_wsdl() {
        let options = SoapOptions::default();
        let client = SoapClient::new(Some("http://example.com/service.wsdl"), &options);
        assert_eq!(
            client.wsdl,
            Some("http://example.com/service.wsdl".to_string())
        );
    }

    #[test]
    fn test_soap_client_call() {
        let options = SoapOptions {
            location: "http://example.com/service".to_string(),
            uri: "http://example.com/ns".to_string(),
            ..SoapOptions::default()
        };
        let mut client = SoapClient::new(None, &options);

        let params = vec![SoapParam::new("name", "John")];
        let result = client.call("GetUser", &params);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.data, "stub response");
    }

    #[test]
    fn test_soap_client_call_empty_function() {
        let options = SoapOptions::default();
        let mut client = SoapClient::new(None, &options);
        let result = client.call("", &[]);
        assert!(result.is_err());
        let fault = result.unwrap_err();
        assert_eq!(fault.faultcode, "Client");
    }

    #[test]
    fn test_soap_client_last_request_response() {
        let options = SoapOptions {
            location: "http://example.com/service".to_string(),
            ..SoapOptions::default()
        };
        let mut client = SoapClient::new(None, &options);

        assert!(client.get_last_request().is_none());
        assert!(client.get_last_response().is_none());

        let params = vec![SoapParam::new("id", "42")];
        client.call("GetItem", &params).unwrap();

        let request = client.get_last_request().unwrap();
        assert!(request.contains("GetItem"));
        assert!(request.contains("<id>42</id>"));

        let response = client.get_last_response().unwrap();
        assert!(response.contains("GetItemResponse"));

        assert!(client.get_last_request_headers().is_some());
        assert!(client.get_last_response_headers().is_some());
    }

    #[test]
    fn test_soap_client_soap12() {
        let options = SoapOptions {
            soap_version: SOAP_1_2,
            location: "http://example.com/service".to_string(),
            ..SoapOptions::default()
        };
        let mut client = SoapClient::new(None, &options);
        client.call("Test", &[]).unwrap();

        let request = client.get_last_request().unwrap();
        assert!(request.contains("http://www.w3.org/2003/05/soap-envelope"));
    }

    #[test]
    fn test_soap_client_headers() {
        let options = SoapOptions {
            location: "http://example.com/service".to_string(),
            ..SoapOptions::default()
        };
        let mut client = SoapClient::new(None, &options);

        let headers = vec![SoapHeader::new(
            "http://example.com/auth",
            "AuthToken",
            "abc123",
        )];
        assert!(client.set_soap_headers(headers));

        client.call("SecureMethod", &[]).unwrap();
        let request = client.get_last_request().unwrap();
        assert!(request.contains("AuthToken"));
        assert!(request.contains("abc123"));
    }

    #[test]
    fn test_soap_client_functions_and_types() {
        let options = SoapOptions::default();
        let mut client = SoapClient::new(None, &options);

        assert!(client.get_functions().is_empty());
        assert!(client.get_types().is_empty());

        client.add_function("GetUser");
        client.add_function("SetUser");
        client.add_type("UserType");

        assert_eq!(client.get_functions().len(), 2);
        assert_eq!(client.get_types().len(), 1);
    }

    #[test]
    fn test_soap_server_creation() {
        let options = SoapOptions::default();
        let server = SoapServer::new(Some("http://example.com/service.wsdl"), &options);
        assert_eq!(
            server.wsdl,
            Some("http://example.com/service.wsdl".to_string())
        );
        assert!(server.functions.is_empty());
        assert!(server.class_name.is_none());
    }

    #[test]
    fn test_soap_server_add_function() {
        let options = SoapOptions::default();
        let mut server = SoapServer::new(None, &options);
        server.add_function("HandleRequest");
        server.add_function("HandleRequest"); // duplicate
        assert_eq!(server.functions.len(), 1);
        assert_eq!(server.functions[0], "HandleRequest");
    }

    #[test]
    fn test_soap_server_set_class() {
        let options = SoapOptions::default();
        let mut server = SoapServer::new(None, &options);
        server.set_class("MyServiceHandler");
        assert_eq!(server.class_name, Some("MyServiceHandler".to_string()));
    }

    #[test]
    fn test_soap_server_handle() {
        let options = SoapOptions::default();
        let mut server = SoapServer::new(None, &options);
        server.add_function("GetUser");

        let request = r#"<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <GetUser><id>1</id></GetUser>
        </soap:Body>
        </soap:Envelope>"#;

        let response = server.handle(request);
        assert!(response.contains("GetUserResponse"));
        assert!(response.contains("handled"));
    }

    #[test]
    fn test_soap_server_handle_unknown_function() {
        let options = SoapOptions::default();
        let server = SoapServer::new(None, &options);

        let request = r#"<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <UnknownFunc/>
        </soap:Body>
        </soap:Envelope>"#;

        let response = server.handle(request);
        assert!(response.contains("Fault"));
        assert!(response.contains("Function not found"));
    }

    #[test]
    fn test_soap_server_fault() {
        let options = SoapOptions::default();
        let mut server = SoapServer::new(None, &options);
        server.fault("Server", "Internal error");

        let response =
            server.handle("<soap:Envelope><soap:Body><Test/></soap:Body></soap:Envelope>");
        assert!(response.contains("Fault"));
        assert!(response.contains("Internal error"));
    }

    #[test]
    fn test_soap_fault_display() {
        let fault = SoapFault::new("Client", "Invalid argument");
        assert_eq!(format!("{}", fault), "SoapFault: [Client] Invalid argument");
    }

    #[test]
    fn test_soap_param_and_var() {
        let param = SoapParam::new("username", "admin");
        assert_eq!(param.name, "username");
        assert_eq!(param.data, "admin");

        let var = SoapVar::new("42", 101);
        assert_eq!(var.data, "42");
        assert_eq!(var.encoding, 101);
    }

    #[test]
    fn test_soap_options_default() {
        let options = SoapOptions::default();
        assert_eq!(options.soap_version, SOAP_1_1);
        assert_eq!(options.encoding, SOAP_ENCODED);
        assert_eq!(options.style, SOAP_RPC);
        assert_eq!(options.connection_timeout, 30);
        assert!(!options.trace);
    }
}
