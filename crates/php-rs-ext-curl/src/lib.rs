//! PHP curl extension implementation for php.rs
//!
//! Provides the curl_* family of functions for HTTP client operations.
//! Uses ureq for real HTTP networking.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Common CURLOPT_* option constants matching PHP's values.
pub mod constants {
    // Options
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
    pub const CURLOPT_COOKIE: u32 = 10022;
    pub const CURLOPT_COOKIEFILE: u32 = 10031;
    pub const CURLOPT_COOKIEJAR: u32 = 10082;
    pub const CURLOPT_PROXY: u32 = 10004;
    pub const CURLOPT_PROXYPORT: u32 = 59;
    pub const CURLOPT_PROXYTYPE: u32 = 101;
    pub const CURLOPT_PROXYUSERPWD: u32 = 10006;
    pub const CURLOPT_SSL_VERIFYHOST: u32 = 81;
    pub const CURLOPT_CAINFO: u32 = 10065;
    pub const CURLOPT_SSLCERT: u32 = 10025;
    pub const CURLOPT_SSLKEY: u32 = 10087;
    pub const CURLOPT_ENCODING: u32 = 10102;
    pub const CURLOPT_USERPWD: u32 = 10005;
    pub const CURLOPT_HTTPGET: u32 = 80;
    pub const CURLOPT_PUT: u32 = 54;
    pub const CURLOPT_INFILE: u32 = 10009;
    pub const CURLOPT_INFILESIZE: u32 = 14;
    pub const CURLOPT_UPLOAD: u32 = 46;
    pub const CURLOPT_MAXREDIRS: u32 = 68;
    pub const CURLOPT_REFERER: u32 = 10016;
    pub const CURLOPT_VERBOSE: u32 = 41;
    pub const CURLOPT_TIMEOUT_MS: u32 = 155;
    pub const CURLOPT_CONNECTTIMEOUT_MS: u32 = 156;
    pub const CURLOPT_HTTP_VERSION: u32 = 84;
    pub const CURLOPT_PORT: u32 = 3;
    pub const CURLOPT_SAFE_UPLOAD: u32 = 10000; // PHP internal

    // Info
    pub const CURLINFO_HTTP_CODE: u32 = 2097154;
    pub const CURLINFO_RESPONSE_CODE: u32 = 2097154;
    pub const CURLINFO_TOTAL_TIME: u32 = 3145731;
    pub const CURLINFO_CONTENT_TYPE: u32 = 1048594;
    pub const CURLINFO_EFFECTIVE_URL: u32 = 1048577;
    pub const CURLINFO_HEADER_SIZE: u32 = 2097163;
    pub const CURLINFO_NAMELOOKUP_TIME: u32 = 3145732;
    pub const CURLINFO_CONNECT_TIME: u32 = 3145733;
    pub const CURLINFO_PRETRANSFER_TIME: u32 = 3145734;
    pub const CURLINFO_STARTTRANSFER_TIME: u32 = 3145745;
    pub const CURLINFO_REDIRECT_COUNT: u32 = 2097172;
    pub const CURLINFO_REDIRECT_TIME: u32 = 3145747;
    pub const CURLINFO_REDIRECT_URL: u32 = 1048607;
    pub const CURLINFO_SIZE_UPLOAD: u32 = 3145735;
    pub const CURLINFO_SIZE_DOWNLOAD: u32 = 3145736;
    pub const CURLINFO_SPEED_UPLOAD: u32 = 3145738;
    pub const CURLINFO_SPEED_DOWNLOAD: u32 = 3145737;
    pub const CURLINFO_REQUEST_SIZE: u32 = 2097164;
    pub const CURLINFO_SSL_VERIFYRESULT: u32 = 2097165;
    pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: u32 = 3145743;
    pub const CURLINFO_CONTENT_LENGTH_UPLOAD: u32 = 3145744;
    pub const CURLINFO_PRIMARY_IP: u32 = 1048608;
    pub const CURLINFO_PRIMARY_PORT: u32 = 2097192;
    pub const CURLINFO_LOCAL_IP: u32 = 1048617;
    pub const CURLINFO_LOCAL_PORT: u32 = 2097194;

    // Error codes
    pub const CURLE_OK: u32 = 0;
    pub const CURLE_UNSUPPORTED_PROTOCOL: u32 = 1;
    pub const CURLE_URL_MALFORMAT: u32 = 3;
    pub const CURLE_COULDNT_RESOLVE_HOST: u32 = 6;
    pub const CURLE_COULDNT_CONNECT: u32 = 7;
    pub const CURLE_OPERATION_TIMEDOUT: u32 = 28;
    pub const CURLE_SSL_CONNECT_ERROR: u32 = 35;
    pub const CURLE_GOT_NOTHING: u32 = 52;

    // Multi error codes
    pub const CURLM_OK: u32 = 0;
    pub const CURLM_CALL_MULTI_PERFORM: u32 = 0xFFFF_FFFE; // -1 as u32
    pub const CURLM_BAD_HANDLE: u32 = 2;

    // Proxy types
    pub const CURLPROXY_HTTP: u32 = 0;
    pub const CURLPROXY_SOCKS4: u32 = 4;
    pub const CURLPROXY_SOCKS5: u32 = 5;

    // Share lock types
    pub const CURL_LOCK_DATA_COOKIE: u32 = 2;
    pub const CURL_LOCK_DATA_DNS: u32 = 3;
    pub const CURL_LOCK_DATA_SSL_SESSION: u32 = 4;
    pub const CURLSHOPT_SHARE: u32 = 1;
    pub const CURLSHOPT_UNSHARE: u32 = 2;

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
            "CURLOPT_COOKIE" => Some(CURLOPT_COOKIE),
            "CURLOPT_COOKIEFILE" => Some(CURLOPT_COOKIEFILE),
            "CURLOPT_COOKIEJAR" => Some(CURLOPT_COOKIEJAR),
            "CURLOPT_PROXY" => Some(CURLOPT_PROXY),
            "CURLOPT_PROXYPORT" => Some(CURLOPT_PROXYPORT),
            "CURLOPT_PROXYTYPE" => Some(CURLOPT_PROXYTYPE),
            "CURLOPT_PROXYUSERPWD" => Some(CURLOPT_PROXYUSERPWD),
            "CURLOPT_SSL_VERIFYHOST" => Some(CURLOPT_SSL_VERIFYHOST),
            "CURLOPT_CAINFO" => Some(CURLOPT_CAINFO),
            "CURLOPT_SSLCERT" => Some(CURLOPT_SSLCERT),
            "CURLOPT_SSLKEY" => Some(CURLOPT_SSLKEY),
            "CURLOPT_ENCODING" => Some(CURLOPT_ENCODING),
            "CURLOPT_USERPWD" => Some(CURLOPT_USERPWD),
            "CURLOPT_HTTPGET" => Some(CURLOPT_HTTPGET),
            "CURLOPT_PUT" => Some(CURLOPT_PUT),
            "CURLOPT_UPLOAD" => Some(CURLOPT_UPLOAD),
            "CURLOPT_MAXREDIRS" => Some(CURLOPT_MAXREDIRS),
            "CURLOPT_REFERER" => Some(CURLOPT_REFERER),
            "CURLOPT_VERBOSE" => Some(CURLOPT_VERBOSE),
            "CURLOPT_TIMEOUT_MS" => Some(CURLOPT_TIMEOUT_MS),
            "CURLOPT_CONNECTTIMEOUT_MS" => Some(CURLOPT_CONNECTTIMEOUT_MS),
            "CURLOPT_HTTP_VERSION" => Some(CURLOPT_HTTP_VERSION),
            "CURLOPT_PORT" => Some(CURLOPT_PORT),
            "CURLOPT_SAFE_UPLOAD" => Some(CURLOPT_SAFE_UPLOAD),
            "CURLINFO_HTTP_CODE" | "CURLINFO_RESPONSE_CODE" => Some(CURLINFO_HTTP_CODE),
            "CURLINFO_TOTAL_TIME" => Some(CURLINFO_TOTAL_TIME),
            "CURLINFO_CONTENT_TYPE" => Some(CURLINFO_CONTENT_TYPE),
            "CURLINFO_EFFECTIVE_URL" => Some(CURLINFO_EFFECTIVE_URL),
            "CURLINFO_HEADER_SIZE" => Some(CURLINFO_HEADER_SIZE),
            "CURLINFO_NAMELOOKUP_TIME" => Some(CURLINFO_NAMELOOKUP_TIME),
            "CURLINFO_CONNECT_TIME" => Some(CURLINFO_CONNECT_TIME),
            "CURLINFO_PRETRANSFER_TIME" => Some(CURLINFO_PRETRANSFER_TIME),
            "CURLINFO_STARTTRANSFER_TIME" => Some(CURLINFO_STARTTRANSFER_TIME),
            "CURLINFO_REDIRECT_COUNT" => Some(CURLINFO_REDIRECT_COUNT),
            "CURLINFO_REDIRECT_TIME" => Some(CURLINFO_REDIRECT_TIME),
            "CURLINFO_REDIRECT_URL" => Some(CURLINFO_REDIRECT_URL),
            "CURLINFO_SIZE_UPLOAD" => Some(CURLINFO_SIZE_UPLOAD),
            "CURLINFO_SIZE_DOWNLOAD" => Some(CURLINFO_SIZE_DOWNLOAD),
            "CURLINFO_SPEED_UPLOAD" => Some(CURLINFO_SPEED_UPLOAD),
            "CURLINFO_SPEED_DOWNLOAD" => Some(CURLINFO_SPEED_DOWNLOAD),
            "CURLINFO_REQUEST_SIZE" => Some(CURLINFO_REQUEST_SIZE),
            "CURLINFO_SSL_VERIFYRESULT" => Some(CURLINFO_SSL_VERIFYRESULT),
            "CURLINFO_CONTENT_LENGTH_DOWNLOAD" => Some(CURLINFO_CONTENT_LENGTH_DOWNLOAD),
            "CURLINFO_CONTENT_LENGTH_UPLOAD" => Some(CURLINFO_CONTENT_LENGTH_UPLOAD),
            "CURLINFO_PRIMARY_IP" => Some(CURLINFO_PRIMARY_IP),
            "CURLINFO_PRIMARY_PORT" => Some(CURLINFO_PRIMARY_PORT),
            "CURLINFO_LOCAL_IP" => Some(CURLINFO_LOCAL_IP),
            "CURLINFO_LOCAL_PORT" => Some(CURLINFO_LOCAL_PORT),
            "CURLE_OK" => Some(CURLE_OK),
            "CURLE_UNSUPPORTED_PROTOCOL" => Some(CURLE_UNSUPPORTED_PROTOCOL),
            "CURLE_URL_MALFORMAT" => Some(CURLE_URL_MALFORMAT),
            "CURLE_COULDNT_RESOLVE_HOST" => Some(CURLE_COULDNT_RESOLVE_HOST),
            "CURLE_COULDNT_CONNECT" => Some(CURLE_COULDNT_CONNECT),
            "CURLE_OPERATION_TIMEDOUT" => Some(CURLE_OPERATION_TIMEDOUT),
            "CURLE_SSL_CONNECT_ERROR" => Some(CURLE_SSL_CONNECT_ERROR),
            "CURLE_GOT_NOTHING" => Some(CURLE_GOT_NOTHING),
            "CURLM_OK" => Some(CURLM_OK),
            "CURLM_CALL_MULTI_PERFORM" => Some(CURLM_CALL_MULTI_PERFORM),
            "CURLM_BAD_HANDLE" => Some(CURLM_BAD_HANDLE),
            "CURLPROXY_HTTP" => Some(CURLPROXY_HTTP),
            "CURLPROXY_SOCKS4" => Some(CURLPROXY_SOCKS4),
            "CURLPROXY_SOCKS5" => Some(CURLPROXY_SOCKS5),
            "CURL_LOCK_DATA_COOKIE" => Some(CURL_LOCK_DATA_COOKIE),
            "CURL_LOCK_DATA_DNS" => Some(CURL_LOCK_DATA_DNS),
            "CURL_LOCK_DATA_SSL_SESSION" => Some(CURL_LOCK_DATA_SSL_SESSION),
            "CURLSHOPT_SHARE" => Some(CURLSHOPT_SHARE),
            "CURLSHOPT_UNSHARE" => Some(CURLSHOPT_UNSHARE),
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
    /// Array of key-value pairs for multipart form data.
    AssocArray(Vec<(String, String)>),
    Null,
}

/// A file to upload via CURLFile.
#[derive(Debug, Clone, PartialEq)]
pub struct CurlFile {
    pub path: String,
    pub mime_type: String,
    pub post_filename: String,
}

/// Proxy configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CurlProxy {
    pub url: Option<String>,
    pub port: u16,
    pub proxy_type: u32,
    pub userpwd: Option<String>,
}

/// SSL/TLS configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct CurlSslConfig {
    pub verify_peer: bool,
    pub verify_host: u32,
    pub cainfo: Option<String>,
    pub sslcert: Option<String>,
    pub sslkey: Option<String>,
}

impl Default for CurlSslConfig {
    fn default() -> Self {
        Self {
            verify_peer: true,
            verify_host: 2,
            cainfo: None,
            sslcert: None,
            sslkey: None,
        }
    }
}

/// Cookie jar for persistent cookie storage.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CookieJar {
    /// Cookies stored as name=value pairs keyed by domain.
    pub cookies: HashMap<String, Vec<(String, String)>>,
    /// File to read initial cookies from.
    pub cookie_file: Option<String>,
    /// File to save cookies to on close.
    pub cookie_jar: Option<String>,
    /// Raw cookie string set via CURLOPT_COOKIE.
    pub cookie_string: Option<String>,
}

impl CookieJar {
    /// Load cookies from the cookie file (Netscape format).
    pub fn load_from_file(&mut self) {
        if let Some(ref path) = self.cookie_file {
            if let Ok(contents) = std::fs::read_to_string(path) {
                for line in contents.lines() {
                    if line.starts_with('#') || line.trim().is_empty() {
                        continue;
                    }
                    // Netscape cookie format: domain \t flag \t path \t secure \t expiry \t name \t value
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 7 {
                        let domain = parts[0].to_string();
                        let name = parts[5].to_string();
                        let value = parts[6].to_string();
                        self.cookies.entry(domain).or_default().push((name, value));
                    }
                }
            }
        }
    }

    /// Save cookies to the jar file.
    pub fn save_to_file(&self) {
        if let Some(ref path) = self.cookie_jar {
            let mut output = String::from("# Netscape HTTP Cookie File\n");
            for (domain, cookies) in &self.cookies {
                for (name, value) in cookies {
                    output.push_str(&format!(
                        "{}\tFALSE\t/\tFALSE\t0\t{}\t{}\n",
                        domain, name, value
                    ));
                }
            }
            let _ = std::fs::write(path, output);
        }
    }

    /// Get cookie header string for a given URL.
    pub fn get_cookie_header(&self, url: &str) -> Option<String> {
        let mut all_cookies = Vec::new();

        // Add cookies from CURLOPT_COOKIE
        if let Some(ref cs) = self.cookie_string {
            all_cookies.push(cs.clone());
        }

        // Add cookies from jar matching the domain
        if let Some(domain) = extract_domain(url) {
            for (jar_domain, cookies) in &self.cookies {
                if domain.ends_with(jar_domain.trim_start_matches('.')) || *jar_domain == domain {
                    let pairs: Vec<String> = cookies
                        .iter()
                        .map(|(n, v)| format!("{}={}", n, v))
                        .collect();
                    if !pairs.is_empty() {
                        all_cookies.push(pairs.join("; "));
                    }
                }
            }
        }

        if all_cookies.is_empty() {
            None
        } else {
            Some(all_cookies.join("; "))
        }
    }

    /// Parse Set-Cookie headers from response and store them.
    pub fn store_from_response(&mut self, url: &str, headers: &[(String, String)]) {
        let domain = extract_domain(url).unwrap_or_default();
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("set-cookie") {
                // Parse "name=value; path=/; ..."
                if let Some(cookie_part) = value.split(';').next() {
                    if let Some(eq_pos) = cookie_part.find('=') {
                        let cname = cookie_part[..eq_pos].trim().to_string();
                        let cvalue = cookie_part[eq_pos + 1..].trim().to_string();
                        let entry = self.cookies.entry(domain.clone()).or_default();
                        // Replace existing cookie with same name
                        if let Some(pos) = entry.iter().position(|(n, _)| *n == cname) {
                            entry[pos] = (cname, cvalue);
                        } else {
                            entry.push((cname, cvalue));
                        }
                    }
                }
            }
        }
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let url = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    Some(url.split('/').next()?.split(':').next()?.to_string())
}

/// A curl handle representing a single transfer.
#[derive(Debug, Clone)]
pub struct CurlHandle {
    pub url: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub post_fields: Option<String>,
    /// Multipart form data fields.
    pub multipart_fields: Vec<(String, MultipartValue)>,
    pub timeout: u64,
    pub timeout_ms: u64,
    pub connect_timeout: u64,
    pub connect_timeout_ms: u64,
    pub follow_redirects: bool,
    pub max_redirects: i64,
    pub return_transfer: bool,
    pub ssl: CurlSslConfig,
    pub user_agent: Option<String>,
    pub include_header: bool,
    pub nobody: bool,
    pub proxy: CurlProxy,
    pub cookie_jar: CookieJar,
    pub userpwd: Option<String>,
    pub referer: Option<String>,
    pub encoding: Option<String>,
    pub upload: bool,
    pub upload_data: Option<Vec<u8>>,
    pub infilesize: i64,
    pub port: u16,
    pub verbose: bool,
    // Response state
    pub response_code: u16,
    pub response_body: String,
    pub response_headers: Vec<(String, String)>,
    pub response_header_text: String,
    pub error: Option<String>,
    pub error_no: u32,
    // Timing info
    pub total_time: f64,
    pub namelookup_time: f64,
    pub connect_time: f64,
    pub pretransfer_time: f64,
    pub starttransfer_time: f64,
    pub redirect_time: f64,
    pub redirect_count: u32,
    pub redirect_url: Option<String>,
    // Transfer sizes
    pub size_upload: f64,
    pub size_download: f64,
    pub speed_upload: f64,
    pub speed_download: f64,
    pub request_size: i64,
    pub content_type: Option<String>,
    pub content_length_download: f64,
    pub content_length_upload: f64,
    pub primary_ip: Option<String>,
    pub primary_port: u16,
    pub local_ip: Option<String>,
    pub local_port: u16,
    pub ssl_verify_result: i64,
}

/// A value in a multipart form upload.
#[derive(Debug, Clone, PartialEq)]
pub enum MultipartValue {
    /// Plain string value.
    Str(String),
    /// File upload (path, mime_type, post_filename).
    File(CurlFile),
}

/// Initialize a new curl handle.
pub fn curl_init(url: Option<&str>) -> CurlHandle {
    CurlHandle {
        url: url.map(|s| s.to_string()),
        method: "GET".to_string(),
        headers: Vec::new(),
        post_fields: None,
        multipart_fields: Vec::new(),
        timeout: 0,
        timeout_ms: 0,
        connect_timeout: 0,
        connect_timeout_ms: 0,
        follow_redirects: false,
        max_redirects: -1,
        return_transfer: false,
        ssl: CurlSslConfig::default(),
        user_agent: None,
        include_header: false,
        nobody: false,
        proxy: CurlProxy::default(),
        cookie_jar: CookieJar::default(),
        userpwd: None,
        referer: None,
        encoding: None,
        upload: false,
        upload_data: None,
        infilesize: -1,
        port: 0,
        verbose: false,
        response_code: 0,
        response_body: String::new(),
        response_headers: Vec::new(),
        response_header_text: String::new(),
        error: None,
        error_no: constants::CURLE_OK,
        total_time: 0.0,
        namelookup_time: 0.0,
        connect_time: 0.0,
        pretransfer_time: 0.0,
        starttransfer_time: 0.0,
        redirect_time: 0.0,
        redirect_count: 0,
        redirect_url: None,
        size_upload: 0.0,
        size_download: 0.0,
        speed_upload: 0.0,
        speed_download: 0.0,
        request_size: 0,
        content_type: None,
        content_length_download: -1.0,
        content_length_upload: -1.0,
        primary_ip: None,
        primary_port: 0,
        local_ip: None,
        local_port: 0,
        ssl_verify_result: 0,
    }
}

/// Set an option on a curl handle by constant ID.
pub fn curl_setopt_raw(handle: &mut CurlHandle, option: u32, value: CurlValue) -> bool {
    match option {
        constants::CURLOPT_URL => {
            if let CurlValue::Str(url) = value {
                handle.url = Some(url);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_RETURNTRANSFER => {
            handle.return_transfer = to_bool(&value);
            true
        }
        constants::CURLOPT_POST => {
            if to_bool(&value) {
                handle.method = "POST".to_string();
            }
            true
        }
        constants::CURLOPT_POSTFIELDS => match value {
            CurlValue::Str(fields) => {
                handle.post_fields = Some(fields);
                handle.multipart_fields.clear();
                handle.method = "POST".to_string();
                true
            }
            CurlValue::AssocArray(fields) => {
                handle.multipart_fields = fields
                    .into_iter()
                    .map(|(k, v)| (k, MultipartValue::Str(v)))
                    .collect();
                handle.post_fields = None;
                handle.method = "POST".to_string();
                true
            }
            _ => false,
        },
        constants::CURLOPT_HTTPHEADER => {
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
        constants::CURLOPT_TIMEOUT => {
            handle.timeout = to_long(&value) as u64;
            true
        }
        constants::CURLOPT_TIMEOUT_MS => {
            handle.timeout_ms = to_long(&value) as u64;
            true
        }
        constants::CURLOPT_CONNECTTIMEOUT => {
            handle.connect_timeout = to_long(&value) as u64;
            true
        }
        constants::CURLOPT_CONNECTTIMEOUT_MS => {
            handle.connect_timeout_ms = to_long(&value) as u64;
            true
        }
        constants::CURLOPT_FOLLOWLOCATION => {
            handle.follow_redirects = to_bool(&value);
            true
        }
        constants::CURLOPT_MAXREDIRS => {
            handle.max_redirects = to_long(&value);
            true
        }
        constants::CURLOPT_SSL_VERIFYPEER => {
            handle.ssl.verify_peer = to_bool(&value);
            true
        }
        constants::CURLOPT_SSL_VERIFYHOST => {
            handle.ssl.verify_host = to_long(&value) as u32;
            true
        }
        constants::CURLOPT_CAINFO => {
            if let CurlValue::Str(path) = value {
                handle.ssl.cainfo = Some(path);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_SSLCERT => {
            if let CurlValue::Str(path) = value {
                handle.ssl.sslcert = Some(path);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_SSLKEY => {
            if let CurlValue::Str(path) = value {
                handle.ssl.sslkey = Some(path);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_USERAGENT => {
            if let CurlValue::Str(ua) = value {
                handle.user_agent = Some(ua);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_CUSTOMREQUEST => {
            if let CurlValue::Str(method) = value {
                handle.method = method;
                true
            } else {
                false
            }
        }
        constants::CURLOPT_HEADER => {
            handle.include_header = to_bool(&value);
            true
        }
        constants::CURLOPT_NOBODY => {
            handle.nobody = to_bool(&value);
            true
        }
        constants::CURLOPT_COOKIE => {
            if let CurlValue::Str(cookie) = value {
                handle.cookie_jar.cookie_string = Some(cookie);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_COOKIEFILE => {
            if let CurlValue::Str(path) = value {
                handle.cookie_jar.cookie_file = Some(path);
                handle.cookie_jar.load_from_file();
                true
            } else {
                false
            }
        }
        constants::CURLOPT_COOKIEJAR => {
            if let CurlValue::Str(path) = value {
                handle.cookie_jar.cookie_jar = Some(path);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_PROXY => {
            if let CurlValue::Str(proxy) = value {
                handle.proxy.url = Some(proxy);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_PROXYPORT => {
            handle.proxy.port = to_long(&value) as u16;
            true
        }
        constants::CURLOPT_PROXYTYPE => {
            handle.proxy.proxy_type = to_long(&value) as u32;
            true
        }
        constants::CURLOPT_PROXYUSERPWD => {
            if let CurlValue::Str(userpwd) = value {
                handle.proxy.userpwd = Some(userpwd);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_USERPWD => {
            if let CurlValue::Str(userpwd) = value {
                handle.userpwd = Some(userpwd);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_REFERER => {
            if let CurlValue::Str(referer) = value {
                handle.referer = Some(referer);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_ENCODING => {
            if let CurlValue::Str(enc) = value {
                handle.encoding = Some(enc);
                true
            } else {
                false
            }
        }
        constants::CURLOPT_HTTPGET => {
            if to_bool(&value) {
                handle.method = "GET".to_string();
            }
            true
        }
        constants::CURLOPT_PUT => {
            if to_bool(&value) {
                handle.method = "PUT".to_string();
            }
            true
        }
        constants::CURLOPT_UPLOAD => {
            handle.upload = to_bool(&value);
            if handle.upload {
                handle.method = "PUT".to_string();
            }
            true
        }
        constants::CURLOPT_INFILESIZE => {
            handle.infilesize = to_long(&value);
            true
        }
        constants::CURLOPT_PORT => {
            handle.port = to_long(&value) as u16;
            true
        }
        constants::CURLOPT_VERBOSE => {
            handle.verbose = to_bool(&value);
            true
        }
        // Unknown options are silently accepted (PHP compat)
        _ => true,
    }
}

fn to_bool(v: &CurlValue) -> bool {
    match v {
        CurlValue::Bool(b) => *b,
        CurlValue::Long(l) => *l != 0,
        CurlValue::Str(s) => !s.is_empty() && s != "0",
        _ => false,
    }
}

fn to_long(v: &CurlValue) -> i64 {
    match v {
        CurlValue::Long(l) => *l,
        CurlValue::Bool(b) => *b as i64,
        CurlValue::Double(d) => *d as i64,
        CurlValue::Str(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Execute the curl transfer using real HTTP via ureq.
pub fn curl_exec(handle: &mut CurlHandle) -> CurlResult {
    let url = match &handle.url {
        Some(url) => url.clone(),
        None => {
            handle.error_no = constants::CURLE_URL_MALFORMAT;
            handle.error = Some("No URL set".to_string());
            return CurlResult::Error("No URL set".to_string());
        }
    };

    if !url.starts_with("http://") && !url.starts_with("https://") {
        handle.error_no = constants::CURLE_UNSUPPORTED_PROTOCOL;
        handle.error = Some(format!("Protocol not supported: {}", url));
        return CurlResult::Error(format!("Protocol not supported: {}", url));
    }

    let start = Instant::now();

    // Build agent with configured timeouts and redirect policy
    let mut config_builder = ureq::Agent::config_builder();
    config_builder = config_builder.http_status_as_error(false);

    // Timeout: prefer ms if set, else seconds
    let global_timeout = if handle.timeout_ms > 0 {
        Some(Duration::from_millis(handle.timeout_ms))
    } else if handle.timeout > 0 {
        Some(Duration::from_secs(handle.timeout))
    } else {
        None
    };
    if let Some(t) = global_timeout {
        config_builder = config_builder.timeout_global(Some(t));
    }

    let connect_timeout = if handle.connect_timeout_ms > 0 {
        Some(Duration::from_millis(handle.connect_timeout_ms))
    } else if handle.connect_timeout > 0 {
        Some(Duration::from_secs(handle.connect_timeout))
    } else {
        None
    };
    if let Some(t) = connect_timeout {
        config_builder = config_builder.timeout_connect(Some(t));
    }

    let max_redir = if handle.follow_redirects {
        if handle.max_redirects >= 0 {
            handle.max_redirects as u32
        } else {
            10
        }
    } else {
        0
    };
    config_builder = config_builder.max_redirects(max_redir);

    // Proxy support
    if let Some(ref proxy_url) = handle.proxy.url {
        let proxy_str = if handle.proxy.port > 0 {
            format!("{}:{}", proxy_url, handle.proxy.port)
        } else {
            proxy_url.clone()
        };
        if let Ok(proxy) = ureq::Proxy::new(&proxy_str) {
            config_builder = config_builder.proxy(Some(proxy));
        }
    }

    let agent: ureq::Agent = config_builder.build().into();

    // CURLOPT_NOBODY forces HEAD method
    let method = if handle.nobody {
        "HEAD"
    } else {
        handle.method.as_str()
    };

    // Build and execute request
    let response_result = match method {
        "POST" | "PUT" | "PATCH" => {
            let mut req = match method {
                "PUT" => agent.put(&url),
                "PATCH" => agent.patch(&url),
                _ => agent.post(&url),
            };
            req = apply_common_headers(handle, req);

            // Multipart form data
            if !handle.multipart_fields.is_empty() {
                let boundary = format!("----PhpRsBoundary{}", start.elapsed().as_nanos());
                let mut body = Vec::new();
                for (name, mval) in &handle.multipart_fields {
                    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                    match mval {
                        MultipartValue::Str(val) => {
                            body.extend_from_slice(
                                format!(
                                    "Content-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                                    name, val
                                )
                                .as_bytes(),
                            );
                        }
                        MultipartValue::File(file) => {
                            let filename = if file.post_filename.is_empty() {
                                std::path::Path::new(&file.path)
                                    .file_name()
                                    .map(|f| f.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "file".to_string())
                            } else {
                                file.post_filename.clone()
                            };
                            body.extend_from_slice(
                                format!(
                                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                                    name, filename, file.mime_type
                                )
                                .as_bytes(),
                            );
                            if let Ok(data) = std::fs::read(&file.path) {
                                body.extend_from_slice(&data);
                            }
                            body.extend_from_slice(b"\r\n");
                        }
                    }
                }
                body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
                handle.size_upload = body.len() as f64;
                req = req.header(
                    "Content-Type",
                    &format!("multipart/form-data; boundary={}", boundary),
                );
                req.send(&body[..])
            } else if handle.upload {
                // File upload via PUT
                let data = handle.upload_data.clone().unwrap_or_default();
                handle.size_upload = data.len() as f64;
                req.send(&data[..])
            } else {
                // Regular POST body
                let body = handle.post_fields.as_deref().unwrap_or("");
                handle.size_upload = body.len() as f64;
                req.send(body.as_bytes())
            }
        }
        _ => {
            let mut req = match method {
                "HEAD" => agent.head(&url),
                "DELETE" => agent.delete(&url),
                "OPTIONS" => agent.options(&url),
                _ => agent.get(&url),
            };
            req = apply_common_headers(handle, req);
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

            // Collect response headers
            handle.response_headers.clear();
            let mut header_text = format!(
                "HTTP/1.1 {} {}\r\n",
                response.status().as_u16(),
                response.status().as_str()
            );
            for name in response.headers().keys() {
                if let Some(val) = response.headers().get(name) {
                    if let Ok(val_str) = val.to_str() {
                        let name_str = name.as_str().to_string();
                        header_text.push_str(&format!("{}: {}\r\n", name_str, val_str));
                        handle
                            .response_headers
                            .push((name_str, val_str.to_string()));
                    }
                }
            }
            header_text.push_str("\r\n");
            handle.response_header_text = header_text;

            // Content-Length
            if let Some(cl) = response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<f64>().ok())
            {
                handle.content_length_download = cl;
            }

            // Store cookies from response
            handle
                .cookie_jar
                .store_from_response(&url, &handle.response_headers.clone());

            if handle.nobody {
                handle.response_body = String::new();
            } else {
                handle.response_body = response.body_mut().read_to_string().unwrap_or_default();
                handle.size_download = handle.response_body.len() as f64;
            }

            handle.error = None;
            handle.error_no = constants::CURLE_OK;
            let elapsed = start.elapsed().as_secs_f64();
            handle.total_time = elapsed;
            handle.starttransfer_time = elapsed;
            if elapsed > 0.0 {
                handle.speed_download = handle.size_download / elapsed;
                handle.speed_upload = handle.size_upload / elapsed;
            }

            let mut result_body = String::new();
            if handle.include_header {
                result_body.push_str(&handle.response_header_text);
            }
            result_body.push_str(&handle.response_body);

            if handle.return_transfer {
                CurlResult::Body(result_body)
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

fn apply_common_headers<B>(
    handle: &CurlHandle,
    mut req: ureq::RequestBuilder<B>,
) -> ureq::RequestBuilder<B> {
    if let Some(ref ua) = handle.user_agent {
        req = req.header("User-Agent", ua.as_str());
    }
    if let Some(ref referer) = handle.referer {
        req = req.header("Referer", referer.as_str());
    }
    if let Some(ref enc) = handle.encoding {
        req = req.header("Accept-Encoding", enc.as_str());
    }
    // Basic auth
    if let Some(ref userpwd) = handle.userpwd {
        if let Some(colon_pos) = userpwd.find(':') {
            let user = &userpwd[..colon_pos];
            let pass = &userpwd[colon_pos + 1..];
            use std::io::Write;
            let mut buf = Vec::new();
            write!(buf, "{}:{}", user, pass).ok();
            let encoded = base64_encode(&buf);
            req = req.header("Authorization", &format!("Basic {}", encoded));
        }
    }
    // Cookies
    if let Some(ref url) = handle.url {
        if let Some(cookie_header) = handle.cookie_jar.get_cookie_header(url) {
            req = req.header("Cookie", &cookie_header);
        }
    }
    for (name, value) in &handle.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    req
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
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
pub fn curl_close(handle: &mut CurlHandle) {
    // Save cookies to jar file before closing
    handle.cookie_jar.save_to_file();
    handle.url = None;
    handle.headers.clear();
    handle.post_fields = None;
    handle.multipart_fields.clear();
    handle.response_body.clear();
    handle.response_headers.clear();
    handle.error = None;
    handle.error_no = constants::CURLE_OK;
}

/// Get information about the last transfer.
pub fn curl_getinfo(handle: &CurlHandle, opt: Option<u32>) -> CurlInfoResult {
    match opt {
        None => {
            // Return all info as an associative array
            let mut info = HashMap::new();
            info.insert(
                "url".to_string(),
                CurlValue::Str(handle.url.clone().unwrap_or_default()),
            );
            info.insert(
                "http_code".to_string(),
                CurlValue::Long(handle.response_code as i64),
            );
            info.insert(
                "content_type".to_string(),
                match &handle.content_type {
                    Some(ct) => CurlValue::Str(ct.clone()),
                    None => CurlValue::Null,
                },
            );
            info.insert(
                "total_time".to_string(),
                CurlValue::Double(handle.total_time),
            );
            info.insert(
                "namelookup_time".to_string(),
                CurlValue::Double(handle.namelookup_time),
            );
            info.insert(
                "connect_time".to_string(),
                CurlValue::Double(handle.connect_time),
            );
            info.insert(
                "pretransfer_time".to_string(),
                CurlValue::Double(handle.pretransfer_time),
            );
            info.insert(
                "starttransfer_time".to_string(),
                CurlValue::Double(handle.starttransfer_time),
            );
            info.insert(
                "redirect_count".to_string(),
                CurlValue::Long(handle.redirect_count as i64),
            );
            info.insert(
                "redirect_time".to_string(),
                CurlValue::Double(handle.redirect_time),
            );
            info.insert(
                "redirect_url".to_string(),
                CurlValue::Str(handle.redirect_url.clone().unwrap_or_default()),
            );
            info.insert(
                "size_upload".to_string(),
                CurlValue::Double(handle.size_upload),
            );
            info.insert(
                "size_download".to_string(),
                CurlValue::Double(handle.size_download),
            );
            info.insert(
                "speed_upload".to_string(),
                CurlValue::Double(handle.speed_upload),
            );
            info.insert(
                "speed_download".to_string(),
                CurlValue::Double(handle.speed_download),
            );
            info.insert(
                "request_size".to_string(),
                CurlValue::Long(handle.request_size),
            );
            info.insert(
                "header_size".to_string(),
                CurlValue::Long(handle.response_header_text.len() as i64),
            );
            info.insert(
                "ssl_verify_result".to_string(),
                CurlValue::Long(handle.ssl_verify_result),
            );
            info.insert(
                "content_length_download".to_string(),
                CurlValue::Double(handle.content_length_download),
            );
            info.insert(
                "content_length_upload".to_string(),
                CurlValue::Double(handle.content_length_upload),
            );
            info.insert(
                "primary_ip".to_string(),
                CurlValue::Str(handle.primary_ip.clone().unwrap_or_default()),
            );
            info.insert(
                "primary_port".to_string(),
                CurlValue::Long(handle.primary_port as i64),
            );
            info.insert(
                "local_ip".to_string(),
                CurlValue::Str(handle.local_ip.clone().unwrap_or_default()),
            );
            info.insert(
                "local_port".to_string(),
                CurlValue::Long(handle.local_port as i64),
            );
            CurlInfoResult::All(info)
        }
        Some(opt_val) => {
            let val = match opt_val {
                constants::CURLINFO_HTTP_CODE => CurlValue::Long(handle.response_code as i64),
                constants::CURLINFO_TOTAL_TIME => CurlValue::Double(handle.total_time),
                constants::CURLINFO_CONTENT_TYPE => match &handle.content_type {
                    Some(ct) => CurlValue::Str(ct.clone()),
                    None => CurlValue::Null,
                },
                constants::CURLINFO_EFFECTIVE_URL => {
                    CurlValue::Str(handle.url.clone().unwrap_or_default())
                }
                constants::CURLINFO_HEADER_SIZE => {
                    CurlValue::Long(handle.response_header_text.len() as i64)
                }
                constants::CURLINFO_NAMELOOKUP_TIME => CurlValue::Double(handle.namelookup_time),
                constants::CURLINFO_CONNECT_TIME => CurlValue::Double(handle.connect_time),
                constants::CURLINFO_PRETRANSFER_TIME => CurlValue::Double(handle.pretransfer_time),
                constants::CURLINFO_STARTTRANSFER_TIME => {
                    CurlValue::Double(handle.starttransfer_time)
                }
                constants::CURLINFO_REDIRECT_COUNT => CurlValue::Long(handle.redirect_count as i64),
                constants::CURLINFO_REDIRECT_TIME => CurlValue::Double(handle.redirect_time),
                constants::CURLINFO_REDIRECT_URL => {
                    CurlValue::Str(handle.redirect_url.clone().unwrap_or_default())
                }
                constants::CURLINFO_SIZE_UPLOAD => CurlValue::Double(handle.size_upload),
                constants::CURLINFO_SIZE_DOWNLOAD => CurlValue::Double(handle.size_download),
                constants::CURLINFO_SPEED_UPLOAD => CurlValue::Double(handle.speed_upload),
                constants::CURLINFO_SPEED_DOWNLOAD => CurlValue::Double(handle.speed_download),
                constants::CURLINFO_REQUEST_SIZE => CurlValue::Long(handle.request_size),
                constants::CURLINFO_SSL_VERIFYRESULT => CurlValue::Long(handle.ssl_verify_result),
                constants::CURLINFO_CONTENT_LENGTH_DOWNLOAD => {
                    CurlValue::Double(handle.content_length_download)
                }
                constants::CURLINFO_CONTENT_LENGTH_UPLOAD => {
                    CurlValue::Double(handle.content_length_upload)
                }
                constants::CURLINFO_PRIMARY_IP => {
                    CurlValue::Str(handle.primary_ip.clone().unwrap_or_default())
                }
                constants::CURLINFO_PRIMARY_PORT => CurlValue::Long(handle.primary_port as i64),
                constants::CURLINFO_LOCAL_IP => {
                    CurlValue::Str(handle.local_ip.clone().unwrap_or_default())
                }
                constants::CURLINFO_LOCAL_PORT => CurlValue::Long(handle.local_port as i64),
                _ => CurlValue::Bool(false),
            };
            CurlInfoResult::Single(val)
        }
    }
}

/// Result of curl_getinfo.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlInfoResult {
    Single(CurlValue),
    All(HashMap<String, CurlValue>),
}

/// Result of executing a curl request.
#[derive(Debug, Clone, PartialEq)]
pub enum CurlResult {
    Body(String),
    Bool(bool),
    Error(String),
}

/// Return the last error number.
pub fn curl_errno(handle: &CurlHandle) -> u32 {
    handle.error_no
}

/// Return the last error message.
pub fn curl_error(handle: &CurlHandle) -> String {
    handle.error.clone().unwrap_or_default()
}

/// Reset a curl handle to its initial state (keeping the handle alive).
pub fn curl_reset(handle: &mut CurlHandle) {
    *handle = curl_init(None);
}

/// Copy a curl handle.
pub fn curl_copy_handle(handle: &CurlHandle) -> CurlHandle {
    handle.clone()
}

/// Return the curl version string.
pub fn curl_version() -> String {
    "php-rs-curl/1.0 ureq/3".to_string()
}

/// Set multiple options at once.
pub fn curl_setopt_array(handle: &mut CurlHandle, options: &[(u32, CurlValue)]) -> bool {
    for (opt, val) in options {
        if !curl_setopt_raw(handle, *opt, val.clone()) {
            return false;
        }
    }
    true
}

/// Return a string describing the given error code.
pub fn curl_strerror(errno: u32) -> String {
    match errno {
        constants::CURLE_OK => "No error".to_string(),
        constants::CURLE_UNSUPPORTED_PROTOCOL => "Unsupported protocol".to_string(),
        constants::CURLE_URL_MALFORMAT => "URL using bad/illegal format or missing URL".to_string(),
        constants::CURLE_COULDNT_RESOLVE_HOST => "Couldn't resolve host name".to_string(),
        constants::CURLE_COULDNT_CONNECT => "Failed to connect() to host or proxy".to_string(),
        constants::CURLE_OPERATION_TIMEDOUT => "Connection timed out".to_string(),
        constants::CURLE_SSL_CONNECT_ERROR => "SSL connect error".to_string(),
        constants::CURLE_GOT_NOTHING => "Server returned nothing".to_string(),
        _ => format!("Unknown error ({})", errno),
    }
}

// ===========================================================================
// Multi handle
// ===========================================================================

/// A multi-handle for concurrent curl requests.
#[derive(Debug)]
pub struct CurlMulti {
    handles: Vec<(i64, CurlHandle)>,
    /// Results from the last exec, keyed by handle ID.
    results: HashMap<i64, CurlResult>,
    /// Messages pending to be read.
    msg_queue: Vec<CurlMultiMsg>,
}

/// A message from a multi-handle execution.
#[derive(Debug, Clone)]
pub struct CurlMultiMsg {
    pub handle_id: i64,
    pub result: u32,
}

impl CurlMulti {
    pub fn new() -> Self {
        CurlMulti {
            handles: Vec::new(),
            results: HashMap::new(),
            msg_queue: Vec::new(),
        }
    }

    /// Add a handle. Returns 0 (CURLM_OK) on success.
    pub fn add_handle(&mut self, id: i64, handle: CurlHandle) -> u32 {
        self.handles.push((id, handle));
        constants::CURLM_OK
    }

    /// Remove a handle by ID. Returns the handle if found.
    pub fn remove_handle(&mut self, id: i64) -> Option<CurlHandle> {
        if let Some(pos) = self.handles.iter().position(|(hid, _)| *hid == id) {
            Some(self.handles.remove(pos).1)
        } else {
            None
        }
    }

    /// Execute all handles and return (still_running, error_code).
    pub fn exec(&mut self) -> (i32, u32) {
        self.results.clear();
        self.msg_queue.clear();
        for (id, handle) in &mut self.handles {
            let result = curl_exec(handle);
            let errno = handle.error_no;
            self.results.insert(*id, result);
            self.msg_queue.push(CurlMultiMsg {
                handle_id: *id,
                result: errno,
            });
        }
        (0, constants::CURLM_OK) // 0 still running after synchronous exec
    }

    /// Read info about completed transfers.
    pub fn info_read(&mut self) -> Option<CurlMultiMsg> {
        if self.msg_queue.is_empty() {
            None
        } else {
            Some(self.msg_queue.remove(0))
        }
    }

    /// Get handle count.
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Get a mutable reference to a handle by ID.
    pub fn get_handle_mut(&mut self, id: i64) -> Option<&mut CurlHandle> {
        self.handles
            .iter_mut()
            .find(|(hid, _)| *hid == id)
            .map(|(_, h)| h)
    }
}

impl Default for CurlMulti {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Share handle
// ===========================================================================

/// A share handle for sharing data between curl handles.
#[derive(Debug, Default)]
pub struct CurlShare {
    pub share_cookies: bool,
    pub share_dns: bool,
    pub share_ssl: bool,
    pub cookie_jar: CookieJar,
}

impl CurlShare {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a share option.
    pub fn setopt(&mut self, option: u32, value: u32) -> u32 {
        match option {
            constants::CURLSHOPT_SHARE => {
                match value {
                    constants::CURL_LOCK_DATA_COOKIE => self.share_cookies = true,
                    constants::CURL_LOCK_DATA_DNS => self.share_dns = true,
                    constants::CURL_LOCK_DATA_SSL_SESSION => self.share_ssl = true,
                    _ => {}
                }
                constants::CURLE_OK
            }
            constants::CURLSHOPT_UNSHARE => {
                match value {
                    constants::CURL_LOCK_DATA_COOKIE => self.share_cookies = false,
                    constants::CURL_LOCK_DATA_DNS => self.share_dns = false,
                    constants::CURL_LOCK_DATA_SSL_SESSION => self.share_ssl = false,
                    _ => {}
                }
                constants::CURLE_OK
            }
            _ => 1, // error
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curl_init_without_url() {
        let handle = curl_init(None);
        assert!(handle.url.is_none());
        assert_eq!(handle.method, "GET");
        assert!(!handle.return_transfer);
        assert!(handle.ssl.verify_peer);
        assert_eq!(handle.error_no, constants::CURLE_OK);
    }

    #[test]
    fn test_curl_init_with_url() {
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(handle.url, Some("http://example.com".to_string()));
    }

    #[test]
    fn test_curl_setopt_raw_url() {
        let mut handle = curl_init(None);
        assert!(curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_URL,
            CurlValue::Str("http://example.com".to_string())
        ));
        assert_eq!(handle.url, Some("http://example.com".to_string()));
    }

    #[test]
    fn test_curl_setopt_raw_return_transfer() {
        let mut handle = curl_init(None);
        assert!(curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_RETURNTRANSFER,
            CurlValue::Bool(true)
        ));
        assert!(handle.return_transfer);
    }

    #[test]
    fn test_curl_setopt_raw_post() {
        let mut handle = curl_init(None);
        curl_setopt_raw(&mut handle, constants::CURLOPT_POST, CurlValue::Bool(true));
        assert_eq!(handle.method, "POST");
    }

    #[test]
    fn test_curl_setopt_raw_post_fields() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_POSTFIELDS,
            CurlValue::Str("key=value".to_string()),
        );
        assert_eq!(handle.post_fields, Some("key=value".to_string()));
        assert_eq!(handle.method, "POST");
    }

    #[test]
    fn test_curl_setopt_raw_multipart() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_POSTFIELDS,
            CurlValue::AssocArray(vec![
                ("name".to_string(), "Alice".to_string()),
                ("age".to_string(), "30".to_string()),
            ]),
        );
        assert_eq!(handle.multipart_fields.len(), 2);
        assert_eq!(handle.method, "POST");
        assert!(handle.post_fields.is_none());
    }

    #[test]
    fn test_curl_setopt_raw_http_header() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_HTTPHEADER,
            CurlValue::Array(vec!["Content-Type: application/json".to_string()]),
        );
        assert_eq!(handle.headers.len(), 1);
        assert_eq!(
            handle.headers[0],
            ("Content-Type".to_string(), "application/json".to_string())
        );
    }

    #[test]
    fn test_curl_setopt_raw_cookie() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_COOKIE,
            CurlValue::Str("foo=bar; baz=qux".to_string()),
        );
        assert_eq!(
            handle.cookie_jar.cookie_string,
            Some("foo=bar; baz=qux".to_string())
        );
    }

    #[test]
    fn test_curl_setopt_raw_proxy() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_PROXY,
            CurlValue::Str("http://proxy.example.com".to_string()),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_PROXYPORT,
            CurlValue::Long(8080),
        );
        assert_eq!(
            handle.proxy.url,
            Some("http://proxy.example.com".to_string())
        );
        assert_eq!(handle.proxy.port, 8080);
    }

    #[test]
    fn test_curl_setopt_raw_ssl_options() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_SSL_VERIFYPEER,
            CurlValue::Bool(false),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_SSL_VERIFYHOST,
            CurlValue::Long(0),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_CAINFO,
            CurlValue::Str("/path/to/ca.pem".to_string()),
        );
        assert!(!handle.ssl.verify_peer);
        assert_eq!(handle.ssl.verify_host, 0);
        assert_eq!(handle.ssl.cainfo, Some("/path/to/ca.pem".to_string()));
    }

    #[test]
    fn test_curl_setopt_raw_userpwd() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_USERPWD,
            CurlValue::Str("user:pass".to_string()),
        );
        assert_eq!(handle.userpwd, Some("user:pass".to_string()));
    }

    #[test]
    fn test_curl_setopt_raw_upload() {
        let mut handle = curl_init(None);
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_UPLOAD,
            CurlValue::Bool(true),
        );
        assert!(handle.upload);
        assert_eq!(handle.method, "PUT");
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
    fn test_curl_exec_dns_failure() {
        let mut handle = curl_init(Some("http://this-domain-does-not-exist.invalid"));
        let result = curl_exec(&mut handle);
        assert!(matches!(result, CurlResult::Error(_)));
        assert_ne!(handle.error_no, constants::CURLE_OK);
        assert!(handle.total_time >= 0.0);
    }

    #[test]
    fn test_curl_getinfo_all() {
        let handle = curl_init(Some("http://example.com"));
        let info = curl_getinfo(&handle, None);
        match info {
            CurlInfoResult::All(map) => {
                assert!(map.contains_key("url"));
                assert!(map.contains_key("http_code"));
                assert!(map.contains_key("total_time"));
                assert!(map.contains_key("content_type"));
                assert!(map.contains_key("size_download"));
                assert!(map.contains_key("speed_download"));
                assert!(map.contains_key("redirect_count"));
                assert!(map.contains_key("ssl_verify_result"));
                assert!(map.contains_key("primary_ip"));
                assert!(map.contains_key("local_port"));
            }
            _ => panic!("Expected All variant"),
        }
    }

    #[test]
    fn test_curl_getinfo_single() {
        let handle = curl_init(Some("http://example.com"));
        match curl_getinfo(&handle, Some(constants::CURLINFO_EFFECTIVE_URL)) {
            CurlInfoResult::Single(CurlValue::Str(url)) => {
                assert_eq!(url, "http://example.com");
            }
            _ => panic!("Expected string value"),
        }
    }

    #[test]
    fn test_curl_errno_and_error() {
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(curl_errno(&handle), constants::CURLE_OK);
        assert_eq!(curl_error(&handle), "");
    }

    #[test]
    fn test_curl_reset() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_setopt_raw(&mut handle, constants::CURLOPT_TIMEOUT, CurlValue::Long(30));
        curl_reset(&mut handle);
        assert!(handle.url.is_none());
        assert_eq!(handle.timeout, 0);
    }

    #[test]
    fn test_curl_copy_handle() {
        let mut handle = curl_init(Some("http://example.com"));
        curl_setopt_raw(&mut handle, constants::CURLOPT_TIMEOUT, CurlValue::Long(30));
        let copy = curl_copy_handle(&handle);
        assert_eq!(copy.url, handle.url);
        assert_eq!(copy.timeout, handle.timeout);
    }

    #[test]
    fn test_curl_version() {
        let ver = curl_version();
        assert!(ver.contains("php-rs-curl"));
    }

    #[test]
    fn test_curl_strerror() {
        assert_eq!(curl_strerror(constants::CURLE_OK), "No error");
        assert!(curl_strerror(constants::CURLE_COULDNT_RESOLVE_HOST).contains("resolve"));
        assert!(curl_strerror(constants::CURLE_OPERATION_TIMEDOUT).contains("timed out"));
    }

    #[test]
    fn test_curl_setopt_array() {
        let mut handle = curl_init(None);
        let result = curl_setopt_array(
            &mut handle,
            &[
                (
                    constants::CURLOPT_URL,
                    CurlValue::Str("http://example.com".to_string()),
                ),
                (constants::CURLOPT_RETURNTRANSFER, CurlValue::Bool(true)),
                (constants::CURLOPT_TIMEOUT, CurlValue::Long(30)),
            ],
        );
        assert!(result);
        assert_eq!(handle.url, Some("http://example.com".to_string()));
        assert!(handle.return_transfer);
        assert_eq!(handle.timeout, 30);
    }

    #[test]
    fn test_curl_multi_new() {
        let multi = CurlMulti::new();
        assert_eq!(multi.handle_count(), 0);
    }

    #[test]
    fn test_curl_multi_add_remove() {
        let mut multi = CurlMulti::new();
        let handle = curl_init(Some("http://example.com"));
        assert_eq!(multi.add_handle(1, handle), constants::CURLM_OK);
        assert_eq!(multi.handle_count(), 1);

        let removed = multi.remove_handle(1);
        assert!(removed.is_some());
        assert_eq!(multi.handle_count(), 0);
    }

    #[test]
    fn test_curl_multi_exec_errors() {
        let mut multi = CurlMulti::new();
        let h = curl_init(Some("http://this-does-not-exist.invalid"));
        multi.add_handle(1, h);
        let (still_running, err) = multi.exec();
        assert_eq!(still_running, 0);
        assert_eq!(err, constants::CURLM_OK);
        let msg = multi.info_read();
        assert!(msg.is_some());
        assert_ne!(msg.unwrap().result, constants::CURLE_OK);
    }

    #[test]
    fn test_curl_share() {
        let mut share = CurlShare::new();
        assert!(!share.share_cookies);
        share.setopt(constants::CURLSHOPT_SHARE, constants::CURL_LOCK_DATA_COOKIE);
        assert!(share.share_cookies);
        share.setopt(
            constants::CURLSHOPT_UNSHARE,
            constants::CURL_LOCK_DATA_COOKIE,
        );
        assert!(!share.share_cookies);
    }

    #[test]
    fn test_cookie_jar() {
        let mut jar = CookieJar::default();
        jar.cookie_string = Some("sid=abc123".to_string());
        let header = jar.get_cookie_header("http://example.com/path");
        assert_eq!(header, Some("sid=abc123".to_string()));
    }

    #[test]
    fn test_cookie_jar_store_from_response() {
        let mut jar = CookieJar::default();
        jar.store_from_response(
            "http://example.com/path",
            &[("Set-Cookie".to_string(), "token=xyz; path=/".to_string())],
        );
        let header = jar.get_cookie_header("http://example.com/other");
        assert!(header.is_some());
        assert!(header.unwrap().contains("token=xyz"));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("http://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://api.example.com:8080/path"),
            Some("api.example.com".to_string())
        );
        assert_eq!(extract_domain("ftp://nope"), None);
    }

    #[test]
    fn test_full_workflow_setup() {
        let mut handle = curl_init(Some("https://api.example.com/data"));
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_RETURNTRANSFER,
            CurlValue::Bool(true),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_POSTFIELDS,
            CurlValue::Str("{\"key\":\"value\"}".to_string()),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_HTTPHEADER,
            CurlValue::Array(vec!["Content-Type: application/json".to_string()]),
        );
        curl_setopt_raw(&mut handle, constants::CURLOPT_TIMEOUT, CurlValue::Long(30));
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_SSL_VERIFYPEER,
            CurlValue::Bool(false),
        );
        curl_setopt_raw(
            &mut handle,
            constants::CURLOPT_COOKIE,
            CurlValue::Str("session=abc".to_string()),
        );

        assert_eq!(handle.method, "POST");
        assert_eq!(handle.timeout, 30);
        assert!(!handle.ssl.verify_peer);
        assert!(handle.return_transfer);
        assert_eq!(
            handle.cookie_jar.cookie_string,
            Some("session=abc".to_string())
        );

        curl_close(&mut handle);
    }
}
