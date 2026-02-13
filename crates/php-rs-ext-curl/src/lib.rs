//! PHP curl extension implementation for php.rs
//!
//! Provides the curl_* family of functions for HTTP client operations.
//! This is a pure Rust implementation that stubs network calls while
//! implementing the full API surface for compatibility.

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

/// Execute the curl transfer.
///
/// Equivalent to PHP's `curl_exec(CurlHandle $handle): string|bool`.
///
/// Currently a stub: validates the URL and returns a simulated response.
/// Real HTTP networking will be added when an HTTP client dependency is introduced.
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

    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("ftp://") {
        handle.error_no = constants::CURLE_UNSUPPORTED_PROTOCOL;
        handle.error = Some(format!("Protocol not supported: {}", url));
        return CurlResult::Error(format!("Protocol not supported: {}", url));
    }

    // Stub: simulate a successful response
    // In a real implementation, this would perform the HTTP request.
    handle.response_code = 200;
    handle.response_body = String::new();
    handle.response_headers = vec![("Content-Type".to_string(), "text/html".to_string())];
    handle.content_type = Some("text/html".to_string());
    handle.total_time = 0.001;
    handle.error = None;
    handle.error_no = constants::CURLE_OK;

    if handle.return_transfer {
        CurlResult::Body(handle.response_body.clone())
    } else {
        CurlResult::Bool(true)
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
    fn test_curl_exec_returns_bool_by_default() {
        let mut handle = curl_init(Some("http://example.com"));
        let result = curl_exec(&mut handle);
        assert_eq!(result, CurlResult::Bool(true));
        assert_eq!(handle.response_code, 200);
    }

    #[test]
    fn test_curl_exec_returns_body_with_return_transfer() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_setopt(&mut handle, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Body(_)));
    }

    #[test]
    fn test_curl_getinfo_http_code() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_exec(&mut handle);
        let info = curl_getinfo(&handle, CurlInfoOpt::HttpCode);
        assert_eq!(info, CurlValue::Long(200));
    }

    #[test]
    fn test_curl_getinfo_total_time() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_exec(&mut handle);
        let info = curl_getinfo(&handle, CurlInfoOpt::TotalTime);
        if let CurlValue::Double(t) = info {
            assert!(t >= 0.0);
        } else {
            panic!("Expected Double value");
        }
    }

    #[test]
    fn test_curl_getinfo_content_type() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_exec(&mut handle);
        let info = curl_getinfo(&handle, CurlInfoOpt::ContentType);
        assert_eq!(info, CurlValue::Str("text/html".to_string()));
    }

    #[test]
    fn test_curl_getinfo_effective_url() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_exec(&mut handle);
        let info = curl_getinfo(&handle, CurlInfoOpt::EffectiveUrl);
        assert_eq!(info, CurlValue::Str("http://example.com".to_string()));
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
        curl_exec(&mut handle);
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
    fn test_curl_multi_exec() {
        let mut multi = CurlMulti::new();

        let mut h1 = curl_init(Some("http://example.com/1"));
        curl_setopt(&mut h1, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        multi.add_handle(h1);

        let mut h2 = curl_init(Some("http://example.com/2"));
        curl_setopt(&mut h2, CurlOpt::ReturnTransfer, CurlValue::Bool(true));
        multi.add_handle(h2);

        let results = multi.exec();
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], CurlResult::Body(_)));
        assert!(matches!(results[1], CurlResult::Body(_)));
    }

    #[test]
    fn test_curl_multi_default() {
        let multi = CurlMulti::default();
        assert_eq!(multi.handle_count(), 0);
    }

    #[test]
    fn test_full_workflow() {
        // Simulate a typical curl workflow
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

        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Body(_)));
        assert_eq!(curl_errno(&handle), constants::CURLE_OK);
        assert_eq!(curl_error(&handle), "");

        let code = curl_getinfo(&handle, CurlInfoOpt::HttpCode);
        assert_eq!(code, CurlValue::Long(200));

        curl_close(&mut handle);
    }
}
