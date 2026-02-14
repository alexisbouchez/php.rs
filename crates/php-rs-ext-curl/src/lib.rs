//! PHP curl extension implementation for php.rs
//!
//! Provides the curl_* family of functions for HTTP client operations.
//! Uses ureq for real HTTP networking.

use std::time::{Duration, Instant};

/// Common CURLOPT_* option constants matching PHP's values.
pub mod constants {
    pub const CURLOPT_URL: u32 = 10002;
    pub const CURLOPT_RETURNTRANSFER: u32 = 19913;
    pub const CURLOPT_POST: u32 = 47;
    pub const CURLOPT_POSTFIELDS: u32 = 10015;
    pub const CURLOPT_HTTPHEADER: u32 = 10023;
    pub const CURLOPT_TIMEOUT: u32 = 13;
    pub const CURLOPT_FOLLOWLOCATION: u32 = 52;
    pub const CURLOPT_SSL_VERIFYPEER: u32 = 64;
    pub const CURLOPT_USERAGENT: u32 = 10018;
    pub const CURLOPT_CUSTOMREQUEST: u32 = 10036;
    pub const CURLOPT_CONNECTTIMEOUT: u32 = 78;
    pub const CURLOPT_HEADER: u32 = 42;
    pub const CURLOPT_NOBODY: u32 = 44;

    pub const CURLINFO_HTTP_CODE: u32 = 2097154;
    pub const CURLINFO_TOTAL_TIME: u32 = 3145731;
    pub const CURLINFO_CONTENT_TYPE: u32 = 1048594;
    pub const CURLINFO_EFFECTIVE_URL: u32 = 1048577;
    pub const CURLINFO_HEADER_SIZE: u32 = 2097163;

    pub const CURLE_OK: u32 = 0;
    pub const CURLE_UNSUPPORTED_PROTOCOL: u32 = 1;
    pub const CURLE_URL_MALFORMAT: u32 = 3;
    pub const CURLE_COULDNT_RESOLVE_HOST: u32 = 6;
    pub const CURLE_COULDNT_CONNECT: u32 = 7;
    pub const CURLE_OPERATION_TIMEDOUT: u32 = 28;
    pub const CURLE_SSL_CONNECT_ERROR: u32 = 35;

    /// Resolve a PHP CURL constant name to its numeric value.
    pub fn from_name(name: &str) -> Option<u32> {
        match name {
            "CURLOPT_URL" => Some(CURLOPT_URL),
            "CURLOPT_RETURNTRANSFER" => Some(CURLOPT_RETURNTRANSFER),
            "CURLOPT_POST" => Some(CURLOPT_POST),
            "CURLOPT_POSTFIELDS" => Some(CURLOPT_POSTFIELDS),
            "CURLOPT_HTTPHEADER" => Some(CURLOPT_HTTPHEADER),
            "CURLOPT_TIMEOUT" => Some(CURLOPT_TIMEOUT),
            "CURLOPT_FOLLOWLOCATION" => Some(CURLOPT_FOLLOWLOCATION),
            "CURLOPT_SSL_VERIFYPEER" => Some(CURLOPT_SSL_VERIFYPEER),
            "CURLOPT_USERAGENT" => Some(CURLOPT_USERAGENT),
            "CURLOPT_CUSTOMREQUEST" => Some(CURLOPT_CUSTOMREQUEST),
            "CURLOPT_CONNECTTIMEOUT" => Some(CURLOPT_CONNECTTIMEOUT),
            "CURLOPT_HEADER" => Some(CURLOPT_HEADER),
            "CURLOPT_NOBODY" => Some(CURLOPT_NOBODY),
            "CURLINFO_HTTP_CODE" | "CURLINFO_RESPONSE_CODE" => Some(CURLINFO_HTTP_CODE),
            "CURLINFO_TOTAL_TIME" => Some(CURLINFO_TOTAL_TIME),
            "CURLINFO_CONTENT_TYPE" => Some(CURLINFO_CONTENT_TYPE),
            "CURLINFO_EFFECTIVE_URL" => Some(CURLINFO_EFFECTIVE_URL),
            "CURLINFO_HEADER_SIZE" => Some(CURLINFO_HEADER_SIZE),
            "CURLE_OK" => Some(CURLE_OK),
            "CURLE_UNSUPPORTED_PROTOCOL" => Some(CURLE_UNSUPPORTED_PROTOCOL),
            "CURLE_URL_MALFORMAT" => Some(CURLE_URL_MALFORMAT),
            "CURLE_COULDNT_RESOLVE_HOST" => Some(CURLE_COULDNT_RESOLVE_HOST),
            "CURLE_COULDNT_CONNECT" => Some(CURLE_COULDNT_CONNECT),
            "CURLE_OPERATION_TIMEDOUT" => Some(CURLE_OPERATION_TIMEDOUT),
            "CURLE_SSL_CONNECT_ERROR" => Some(CURLE_SSL_CONNECT_ERROR),
            _ => None,
        }
    }
}

/// Options that can be set on a curl handle via curl_setopt.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlOpt {
    Url,
    ReturnTransfer,
    Post,
    PostFields,
    HttpHeader,
    Timeout,
    FollowLocation,
    SslVerifyPeer,
    UserAgent,
    CustomRequest,
    ConnectTimeout,
    Header,
    Nobody,
}

impl CurlOpt {
    /// Convert a PHP CURLOPT_* constant to the enum variant.
    pub fn from_constant(constant: u32) -> Option<CurlOpt> {
        match constant {
            constants::CURLOPT_URL => Some(CurlOpt::Url),
            constants::CURLOPT_RETURNTRANSFER => Some(CurlOpt::ReturnTransfer),
            constants::CURLOPT_POST => Some(CurlOpt::Post),
            constants::CURLOPT_POSTFIELDS => Some(CurlOpt::PostFields),
            constants::CURLOPT_HTTPHEADER => Some(CurlOpt::HttpHeader),
            constants::CURLOPT_TIMEOUT => Some(CurlOpt::Timeout),
            constants::CURLOPT_FOLLOWLOCATION => Some(CurlOpt::FollowLocation),
            constants::CURLOPT_SSL_VERIFYPEER => Some(CurlOpt::SslVerifyPeer),
            constants::CURLOPT_USERAGENT => Some(CurlOpt::UserAgent),
            constants::CURLOPT_CUSTOMREQUEST => Some(CurlOpt::CustomRequest),
            constants::CURLOPT_CONNECTTIMEOUT => Some(CurlOpt::ConnectTimeout),
            constants::CURLOPT_HEADER => Some(CurlOpt::Header),
            constants::CURLOPT_NOBODY => Some(CurlOpt::Nobody),
            _ => None,
        }
    }
}

/// Values that can be passed to curl_setopt or returned from curl_getinfo.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlValue {
    Bool(bool),
    Long(i64),
    Str(String),
    Double(f64),
    Array(Vec<String>),
    Null,
}

/// Options for curl_getinfo.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlInfoOpt {
    HttpCode,
    TotalTime,
    ContentType,
    EffectiveUrl,
    HeaderSize,
}

impl CurlInfoOpt {
    /// Convert a PHP CURLINFO_* constant to the enum variant.
    pub fn from_constant(constant: u32) -> Option<CurlInfoOpt> {
        match constant {
            constants::CURLINFO_HTTP_CODE => Some(CurlInfoOpt::HttpCode),
            constants::CURLINFO_TOTAL_TIME => Some(CurlInfoOpt::TotalTime),
            constants::CURLINFO_CONTENT_TYPE => Some(CurlInfoOpt::ContentType),
            constants::CURLINFO_EFFECTIVE_URL => Some(CurlInfoOpt::EffectiveUrl),
            constants::CURLINFO_HEADER_SIZE => Some(CurlInfoOpt::HeaderSize),
            _ => None,
        }
    }
}

/// Result of executing a curl request.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlResult {
    /// Response body (when CURLOPT_RETURNTRANSFER is set).
    Body(String),
    /// Boolean result (when CURLOPT_RETURNTRANSFER is not set).
    Bool(bool),
    /// An error occurred.
    Error(String),
}

/// A curl handle representing a single transfer, analogous to PHP's CurlHandle.
#[derive(Debug, Clone)]
pub struct CurlHandle {
    pub url: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub post_fields: Option<String>,
    pub timeout: u64,
    pub connect_timeout: u64,
    pub follow_redirects: bool,
    pub return_transfer: bool,
    pub ssl_verify_peer: bool,
    pub user_agent: Option<String>,
    pub include_header: bool,
    pub nobody: bool,
    pub response_code: u16,
    pub response_body: String,
    pub response_headers: Vec<(String, String)>,
    pub error: Option<String>,
    pub error_no: u32,
    pub total_time: f64,
    pub content_type: Option<String>,
}

/// Initialize a new curl handle, optionally setting the URL.
///
/// Equivalent to PHP's `curl_init(?string $url = null): CurlHandle`.
pub fn curl_init(url: Option<&str>) -> CurlHandle {
    CurlHandle {
        url: url.map(|s| s.to_string()),
        method: "GET".to_string(),
        headers: Vec::new(),
        post_fields: None,
        timeout: 0,
        connect_timeout: 0,
        follow_redirects: false,
        return_transfer: false,
        ssl_verify_peer: true,
        user_agent: None,
        include_header: false,
        nobody: false,
        response_code: 0,
        response_body: String::new(),
        response_headers: Vec::new(),
        error: None,
        error_no: constants::CURLE_OK,
        total_time: 0.0,
        content_type: None,
    }
}

/// Set an option on a curl handle.
///
/// Equivalent to PHP's `curl_setopt(CurlHandle $handle, int $option, mixed $value): bool`.
pub fn curl_setopt(handle: &mut CurlHandle, option: CurlOpt, value: CurlValue) -> bool {
    match option {
        CurlOpt::Url => {
            if let CurlValue::Str(url) = value {
                handle.url = Some(url);
                true
            } else {
                false
            }
        }
        CurlOpt::ReturnTransfer => {
            if let CurlValue::Bool(v) = value {
                handle.return_transfer = v;
                true
            } else if let CurlValue::Long(v) = value {
                handle.return_transfer = v != 0;
                true
            } else {
                false
            }
        }
        CurlOpt::Post => {
            if let CurlValue::Bool(v) = value {
                if v {
                    handle.method = "POST".to_string();
                }
                true
            } else if let CurlValue::Long(v) = value {
                if v != 0 {
                    handle.method = "POST".to_string();
                }
                true
            } else {
                false
            }
        }
        CurlOpt::PostFields => {
            if let CurlValue::Str(fields) = value {
                handle.post_fields = Some(fields);
                handle.method = "POST".to_string();
                true
            } else {
                false
            }
        }
        CurlOpt::HttpHeader => {
            if let CurlValue::Array(headers) = value {
                handle.headers.clear();
                for header in headers {
                    if let Some(pos) = header.find(':') {
                        let name = header[..pos].trim().to_string();
                        let val = header[pos + 1..].trim().to_string();
                        handle.headers.push((name, val));
                    }
                }
                true
            } else {
                false
            }
        }
        CurlOpt::Timeout => {
            if let CurlValue::Long(t) = value {
                handle.timeout = t as u64;
                true
            } else {
                false
            }
        }
        CurlOpt::ConnectTimeout => {
            if let CurlValue::Long(t) = value {
                handle.connect_timeout = t as u64;
                true
            } else {
                false
            }
        }
        CurlOpt::FollowLocation => {
            if let CurlValue::Bool(v) = value {
                handle.follow_redirects = v;
                true
            } else if let CurlValue::Long(v) = value {
                handle.follow_redirects = v != 0;
                true
            } else {
                false
            }
        }
        CurlOpt::SslVerifyPeer => {
            if let CurlValue::Bool(v) = value {
                handle.ssl_verify_peer = v;
                true
            } else if let CurlValue::Long(v) = value {
                handle.ssl_verify_peer = v != 0;
                true
            } else {
                false
            }
        }
        CurlOpt::UserAgent => {
            if let CurlValue::Str(ua) = value {
                handle.user_agent = Some(ua);
                true
            } else {
                false
            }
        }
        CurlOpt::CustomRequest => {
            if let CurlValue::Str(method) = value {
                handle.method = method;
                true
            } else {
                false
            }
        }
        CurlOpt::Header => {
            if let CurlValue::Bool(v) = value {
                handle.include_header = v;
                true
            } else if let CurlValue::Long(v) = value {
                handle.include_header = v != 0;
                true
            } else {
                false
            }
        }
        CurlOpt::Nobody => {
            if let CurlValue::Bool(v) = value {
                handle.nobody = v;
                true
            } else if let CurlValue::Long(v) = value {
                handle.nobody = v != 0;
                true
            } else {
                false
            }
        }
    }
}

/// Execute the curl transfer using real HTTP via ureq.
///
/// Equivalent to PHP's `curl_exec(CurlHandle $handle): string|bool`.
pub fn curl_exec(handle: &mut CurlHandle) -> CurlResult {
    // Validate URL is set
    let url = match &handle.url {
        Some(url) => url.clone(),
        None => {
            handle.error_no = constants::CURLE_URL_MALFORMAT;
            handle.error = Some("No URL set".to_string());
            return CurlResult::Error("No URL set".to_string());
        }
    };

    // Only http:// and https:// are supported
    if !url.starts_with("http://") && !url.starts_with("https://") {
        handle.error_no = constants::CURLE_UNSUPPORTED_PROTOCOL;
        handle.error = Some(format!("Protocol not supported: {}", url));
        return CurlResult::Error(format!("Protocol not supported: {}", url));
    }

    let start = Instant::now();

    // Build agent with configured timeouts and redirect policy
    let mut config_builder = ureq::Agent::config_builder();
    config_builder = config_builder.http_status_as_error(false);

    if handle.timeout > 0 {
        config_builder = config_builder.timeout_global(Some(Duration::from_secs(handle.timeout)));
    }
    if handle.connect_timeout > 0 {
        config_builder =
            config_builder.timeout_connect(Some(Duration::from_secs(handle.connect_timeout)));
    }
    if handle.follow_redirects {
        config_builder = config_builder.max_redirects(10);
    } else {
        config_builder = config_builder.max_redirects(0);
    }

    let agent: ureq::Agent = config_builder.build().into();

    // CURLOPT_NOBODY forces HEAD method
    let method = if handle.nobody {
        "HEAD"
    } else {
        handle.method.as_str()
    };

    // Build request, apply headers, and execute.
    // POST/PUT/PATCH use .send() (supports body), others use .call().
    let response_result = match method {
        "POST" | "PUT" | "PATCH" => {
            let mut req = match method {
                "PUT" => agent.put(&url),
                "PATCH" => agent.patch(&url),
                _ => agent.post(&url),
            };
            if let Some(ref ua) = handle.user_agent {
                req = req.header("User-Agent", ua.as_str());
            }
            for (name, value) in &handle.headers {
                req = req.header(name.as_str(), value.as_str());
            }
            let body = handle.post_fields.as_deref().unwrap_or("");
            req.send(body.as_bytes())
        }
        _ => {
            let mut req = match method {
                "HEAD" => agent.head(&url),
                "DELETE" => agent.delete(&url),
                "OPTIONS" => agent.options(&url),
                _ => agent.get(&url),
            };
            if let Some(ref ua) = handle.user_agent {
                req = req.header("User-Agent", ua.as_str());
            }
            for (name, value) in &handle.headers {
                req = req.header(name.as_str(), value.as_str());
            }
            req.call()
        }
    };

    match response_result {
        Ok(mut response) => {
            handle.response_code = response.status().as_u16();
            handle.content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            handle.response_headers.clear();

            if handle.nobody {
                handle.response_body = String::new();
            } else {
                handle.response_body = response.body_mut().read_to_string().unwrap_or_default();
            }

            handle.error = None;
            handle.error_no = constants::CURLE_OK;
            handle.total_time = start.elapsed().as_secs_f64();

            if handle.return_transfer {
                CurlResult::Body(handle.response_body.clone())
            } else {
                CurlResult::Bool(true)
            }
        }
        Err(e) => {
            handle.total_time = start.elapsed().as_secs_f64();
            let (error_no, error_msg) = map_ureq_error(&e);
            handle.error_no = error_no;
            handle.error = Some(error_msg.clone());
            handle.response_code = 0;
            CurlResult::Error(error_msg)
        }
    }
}

/// Map ureq errors to CURLE_* error codes.
fn map_ureq_error(e: &ureq::Error) -> (u32, String) {
    match e {
        ureq::Error::HostNotFound => (
            constants::CURLE_COULDNT_RESOLVE_HOST,
            format!("Could not resolve host: {}", e),
        ),
        ureq::Error::ConnectionFailed => (
            constants::CURLE_COULDNT_CONNECT,
            format!("Failed to connect: {}", e),
        ),
        ureq::Error::Timeout(_) => (
            constants::CURLE_OPERATION_TIMEDOUT,
            "Operation timed out".to_string(),
        ),
        ureq::Error::BadUri(_) => (
            constants::CURLE_URL_MALFORMAT,
            format!("URL malformed: {}", e),
        ),
        _ => (constants::CURLE_COULDNT_CONNECT, format!("{}", e)),
    }
}

/// Close a curl handle and free resources.
///
/// Equivalent to PHP's `curl_close(CurlHandle $handle): void`.
pub fn curl_close(handle: &mut CurlHandle) {
    handle.url = None;
    handle.headers.clear();
    handle.post_fields = None;
    handle.response_body.clear();
    handle.response_headers.clear();
    handle.error = None;
    handle.error_no = constants::CURLE_OK;
}

/// Get information about the last transfer.
///
/// Equivalent to PHP's `curl_getinfo(CurlHandle $handle, ?int $option = null): mixed`.
pub fn curl_getinfo(handle: &CurlHandle, opt: CurlInfoOpt) -> CurlValue {
    match opt {
        CurlInfoOpt::HttpCode => CurlValue::Long(handle.response_code as i64),
        CurlInfoOpt::TotalTime => CurlValue::Double(handle.total_time),
        CurlInfoOpt::ContentType => match &handle.content_type {
            Some(ct) => CurlValue::Str(ct.clone()),
            None => CurlValue::Null,
        },
        CurlInfoOpt::EffectiveUrl => match &handle.url {
            Some(url) => CurlValue::Str(url.clone()),
            None => CurlValue::Str(String::new()),
        },
        CurlInfoOpt::HeaderSize => CurlValue::Long(0),
    }
}

/// Return the last error number for the handle.
///
/// Equivalent to PHP's `curl_errno(CurlHandle $handle): int`.
pub fn curl_errno(handle: &CurlHandle) -> u32 {
    handle.error_no
}

/// Return the last error message for the handle.
///
/// Equivalent to PHP's `curl_error(CurlHandle $handle): string`.
pub fn curl_error(handle: &CurlHandle) -> String {
    handle.error.clone().unwrap_or_default()
}

/// A multi-handle for concurrent curl requests.
///
/// Equivalent to PHP's CurlMultiHandle.
#[derive(Debug)]
pub struct CurlMulti {
    handles: Vec<CurlHandle>,
}

impl CurlMulti {
    /// Create a new multi-handle.
    ///
    /// Equivalent to PHP's `curl_multi_init(): CurlMultiHandle`.
    pub fn new() -> Self {
        CurlMulti {
            handles: Vec::new(),
        }
    }

    /// Add a handle to the multi-handle.
    ///
    /// Equivalent to PHP's `curl_multi_add_handle(CurlMultiHandle $multi, CurlHandle $handle): int`.
    pub fn add_handle(&mut self, handle: CurlHandle) {
        self.handles.push(handle);
    }

    /// Remove a handle from the multi-handle by index.
    ///
    /// Equivalent to PHP's `curl_multi_remove_handle(CurlMultiHandle $multi, CurlHandle $handle): int`.
    pub fn remove_handle(&mut self, index: usize) -> Option<CurlHandle> {
        if index < self.handles.len() {
            Some(self.handles.remove(index))
        } else {
            None
        }
    }

    /// Get the number of handles.
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Execute all handles and return their results.
    ///
    /// Equivalent to PHP's `curl_multi_exec(CurlMultiHandle $multi, int &$still_running): int`.
    pub fn exec(&mut self) -> Vec<CurlResult> {
        let mut results = Vec::with_capacity(self.handles.len());
        for handle in &mut self.handles {
            results.push(curl_exec(handle));
        }
        results
    }
}

impl Default for CurlMulti {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curl_init_without_url() {
        let handle = curl_init(None);
        assert!(handle.url.is_none());
        assert_eq!(handle.method, "GET");
        assert!(!handle.return_transfer);
        assert!(handle.ssl_verify_peer);
        assert_eq!(handle.error_no, constants::CURLE_OK);
    }

    #[test]
    fn test_curl_init_with_url() {
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(handle.url, Some("http://example.com".to_string()));
        assert_eq!(handle.method, "GET");
    }

    #[test]
    fn test_curl_setopt_url() {
        let mut handle = curl_init(None);
        let result = curl_setopt(
            &mut handle,
            CurlOpt::Url,
            CurlValue::Str("http://example.com".to_string()),
        );
        assert!(result);
        assert_eq!(handle.url, Some("http://example.com".to_string()));
    }

    #[test]
    fn test_curl_setopt_return_transfer() {
        let mut handle = curl_init(None);
        assert!(!handle.return_transfer);
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        assert!(handle.return_transfer);
    }

    #[test]
    fn test_curl_setopt_return_transfer_long() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Long(1));
        assert!(handle.return_transfer);
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Long(0));
        assert!(!handle.return_transfer);
    }

    #[test]
    fn test_curl_setopt_post() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::Post, CurlValue::Bool(true));
        assert_eq!(handle.method, "POST");
    }

    #[test]
    fn test_curl_setopt_post_fields() {
        let mut handle = curl_init(None);
        curl_setopt(
            &mut handle,
            CurlOpt::PostFields,
            CurlValue::Str("key=value".to_string()),
        );
        assert_eq!(handle.post_fields, Some("key=value".to_string()));
        assert_eq!(handle.method, "POST");
    }

    #[test]
    fn test_curl_setopt_http_header() {
        let mut handle = curl_init(None);
        curl_setopt(
            &mut handle,
            CurlOpt::HttpHeader,
            CurlValue::Array(vec![
                "Content-Type: application/json".to_string(),
                "Authorization: Bearer token123".to_string(),
            ]),
        );
        assert_eq!(handle.headers.len(), 2);
        assert_eq!(
            handle.headers[0],
            ("Content-Type".to_string(), "application/json".to_string())
        );
        assert_eq!(
            handle.headers[1],
            ("Authorization".to_string(), "Bearer token123".to_string())
        );
    }

    #[test]
    fn test_curl_setopt_timeout() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::Timeout, CurlValue::Long(30));
        assert_eq!(handle.timeout, 30);
    }

    #[test]
    fn test_curl_setopt_follow_location() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::FollowLocation, CurlValue::Bool(true));
        assert!(handle.follow_redirects);
    }

    #[test]
    fn test_curl_setopt_ssl_verify_peer() {
        let mut handle = curl_init(None);
        assert!(handle.ssl_verify_peer);
        curl_setopt(&mut handle, CurlOpt::SslVerifyPeer, CurlValue::Bool(false));
        assert!(!handle.ssl_verify_peer);
    }

    #[test]
    fn test_curl_setopt_user_agent() {
        let mut handle = curl_init(None);
        curl_setopt(
            &mut handle,
            CurlOpt::UserAgent,
            CurlValue::Str("php-rs/0.1".to_string()),
        );
        assert_eq!(handle.user_agent, Some("php-rs/0.1".to_string()));
    }

    #[test]
    fn test_curl_setopt_custom_request() {
        let mut handle = curl_init(None);
        curl_setopt(
            &mut handle,
            CurlOpt::CustomRequest,
            CurlValue::Str("PUT".to_string()),
        );
        assert_eq!(handle.method, "PUT");
    }

    #[test]
    fn test_curl_setopt_header() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::Header, CurlValue::Bool(true));
        assert!(handle.include_header);
    }

    #[test]
    fn test_curl_setopt_nobody() {
        let mut handle = curl_init(None);
        curl_setopt(&mut handle, CurlOpt::Nobody, CurlValue::Bool(true));
        assert!(handle.nobody);
    }

    #[test]
    fn test_curl_setopt_invalid_value_type() {
        let mut handle = curl_init(None);
        let result = curl_setopt(&mut handle, CurlOpt::Url, CurlValue::Bool(true));
        assert!(!result);
    }

    #[test]
    fn test_curl_exec_no_url() {
        let mut handle = curl_init(None);
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_eq!(handle.error_no, constants::CURLE_URL_MALFORMAT);
    }

    #[test]
    fn test_curl_exec_invalid_protocol() {
        let mut handle = curl_init(Some("gopher://example.com"));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_eq!(handle.error_no, constants::CURLE_UNSUPPORTED_PROTOCOL);
    }

    #[test]
    fn test_curl_exec_ftp_not_supported() {
        let mut handle = curl_init(Some("ftp://example.com"));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_eq!(handle.error_no, constants::CURLE_UNSUPPORTED_PROTOCOL);
    }

    #[test]
    fn test_curl_exec_dns_failure() {
        let mut handle = curl_init(Some("http://this-domain-does-not-exist.invalid"));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_ne!(handle.error_no, constants::CURLE_OK);
        assert_eq!(handle.response_code, 0);
        assert!(handle.total_time >= 0.0);
    }

    #[test]
    fn test_curl_exec_connection_refused() {
        let mut handle = curl_init(Some("http://127.0.0.1:1"));
        curl_setopt(&mut handle, CurlOpt::Timeout, CurlValue::Long(2));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_ne!(handle.error_no, constants::CURLE_OK);
    }

    #[test]
    #[ignore] // requires network access
    fn test_curl_exec_real_http_get() {
        let mut handle = curl_init(Some("http://example.com"));
        let result = curl_exec(&mut handle);
        assert_eq!(result, CurlResult::Bool(true));
        assert_eq!(handle.response_code, 200);
    }

    #[test]
    #[ignore] // requires network access
    fn test_curl_exec_real_http_return_transfer() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        let result = curl_exec(&mut handle);
        if let CurlResult::Body(body) = result {
            assert!(!body.is_empty());
        } else {
            panic!("Expected Body result");
        }
        assert_eq!(handle.response_code, 200);
    }

    #[test]
    fn test_curl_getinfo_effective_url() {
        let handle = curl_init(Some("http://example.com"));
        let info = curl_getinfo(&handle, CurlInfoOpt::EffectiveUrl);
        assert_eq!(info, CurlValue::Str("http://example.com".to_string()));
    }

    #[test]
    fn test_curl_getinfo_defaults() {
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(
            curl_getinfo(&handle, CurlInfoOpt::HttpCode),
            CurlValue::Long(0)
        );
        assert_eq!(
            curl_getinfo(&handle, CurlInfoOpt::TotalTime),
            CurlValue::Double(0.0)
        );
        assert_eq!(
            curl_getinfo(&handle, CurlInfoOpt::ContentType),
            CurlValue::Null
        );
    }

    #[test]
    fn test_curl_errno_and_error() {
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(curl_errno(&handle), constants::CURLE_OK);
        assert_eq!(curl_error(&handle), "");
    }

    #[test]
    fn test_curl_errno_after_error() {
        let mut handle = curl_init(None);
        curl_exec(&mut handle);
        assert_ne!(curl_errno(&handle), constants::CURLE_OK);
        assert!(!curl_error(&handle).is_empty());
    }

    #[test]
    fn test_curl_close() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_setopt(
            &mut handle,
            CurlOpt::UserAgent,
            CurlValue::Str("test".to_string()),
        );
        curl_close(&mut handle);
        assert!(handle.url.is_none());
        assert!(handle.headers.is_empty());
        assert!(handle.response_body.is_empty());
        assert_eq!(handle.error_no, constants::CURLE_OK);
    }

    #[test]
    fn test_curl_opt_from_constant() {
        assert_eq!(
            CurlOpt::from_constant(constants::CURLOPT_URL),
            Some(CurlOpt::Url)
        );
        assert_eq!(
            CurlOpt::from_constant(constants::CURLOPT_RETURNTRANSFER),
            Some(CurlOpt::ReturnTransfer)
        );
        assert_eq!(
            CurlOpt::from_constant(constants::CURLOPT_POST),
            Some(CurlOpt::Post)
        );
        assert_eq!(
            CurlOpt::from_constant(constants::CURLOPT_TIMEOUT),
            Some(CurlOpt::Timeout)
        );
        assert_eq!(CurlOpt::from_constant(99999), None);
    }

    #[test]
    fn test_curl_info_opt_from_constant() {
        assert_eq!(
            CurlInfoOpt::from_constant(constants::CURLINFO_HTTP_CODE),
            Some(CurlInfoOpt::HttpCode)
        );
        assert_eq!(
            CurlInfoOpt::from_constant(constants::CURLINFO_TOTAL_TIME),
            Some(CurlInfoOpt::TotalTime)
        );
        assert_eq!(CurlInfoOpt::from_constant(99999), None);
    }

    #[test]
    fn test_curl_multi_new() {
        let multi = CurlMulti::new();
        assert_eq!(multi.handle_count(), 0);
    }

    #[test]
    fn test_curl_multi_add_handle() {
        let mut multi = CurlMulti::new();
        let handle = curl_init(Some("http://example.com"));
        multi.add_handle(handle);
        assert_eq!(multi.handle_count(), 1);
    }

    #[test]
    fn test_curl_multi_remove_handle() {
        let mut multi = CurlMulti::new();
        multi.add_handle(curl_init(Some("http://example.com/1")));
        multi.add_handle(curl_init(Some("http://example.com/2")));
        assert_eq!(multi.handle_count(), 2);

        let removed = multi.remove_handle(0);
        assert!(removed.is_some());
        assert_eq!(
            removed.unwrap().url,
            Some("http://example.com/1".to_string())
        );
        assert_eq!(multi.handle_count(), 1);
    }

    #[test]
    fn test_curl_multi_remove_invalid_index() {
        let mut multi = CurlMulti::new();
        let removed = multi.remove_handle(5);
        assert!(removed.is_none());
    }

    #[test]
    fn test_curl_multi_exec_error_handling() {
        let mut multi = CurlMulti::new();

        let mut h1 = curl_init(Some("http://this-domain-does-not-exist.invalid/1"));
        curl_setopt(&mut h1, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        multi.add_handle(h1);

        let results = multi.exec();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CurlResult::Error(_)));
    }

    #[test]
    fn test_curl_multi_default() {
        let multi = CurlMulti::default();
        assert_eq!(multi.handle_count(), 0);
    }

    #[test]
    fn test_full_workflow_setup() {
        // Test the full curl workflow setup (options, not execution)
        let mut handle = curl_init(Some("https://api.example.com/data"));
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        curl_setopt(&mut handle, CurlOpt::Post, CurlValue::Bool(true));
        curl_setopt(
            &mut handle,
            CurlOpt::PostFields,
            CurlValue::Str("{\"key\":\"value\"}".to_string()),
        );
        curl_setopt(
            &mut handle,
            CurlOpt::HttpHeader,
            CurlValue::Array(vec!["Content-Type: application/json".to_string()]),
        );
        curl_setopt(&mut handle, CurlOpt::Timeout, CurlValue::Long(30));
        curl_setopt(&mut handle, CurlOpt::SslVerifyPeer, CurlValue::Bool(false));

        assert_eq!(handle.method, "POST");
        assert_eq!(handle.timeout, 30);
        assert!(!handle.ssl_verify_peer);
        assert!(handle.return_transfer);
        assert_eq!(handle.post_fields, Some("{\"key\":\"value\"}".to_string()));
        assert_eq!(handle.headers.len(), 1);

        curl_close(&mut handle);
    }

    #[test]
    #[ignore] // requires network access
    fn test_full_workflow_real_http() {
        let mut handle = curl_init(Some("https://httpbin.org/post"));
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        curl_setopt(
            &mut handle,
            CurlOpt::PostFields,
            CurlValue::Str("key=value".to_string()),
        );
        curl_setopt(&mut handle, CurlOpt::Timeout, CurlValue::Long(10));

        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Body(_)));
        assert_eq!(curl_errno(&handle), constants::CURLE_OK);
        assert_eq!(handle.response_code, 200);

        curl_close(&mut handle);
    }
}
