//! PHP URI extension (PHP 8.4+).
//!
//! Implements RFC 3986 URI parsing and manipulation, providing the `Uri\Rfc3986Uri`
//! class and the `Uri\WhatWgUri` class.
//! Reference: php-src/ext/uri/

use std::fmt;

// ---------------------------------------------------------------------------
// UriError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct UriError {
    pub message: String,
}

impl UriError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "URI error: {}", self.message)
    }
}

impl std::error::Error for UriError {}

// ---------------------------------------------------------------------------
// Uri — RFC 3986 URI representation
// ---------------------------------------------------------------------------

/// A parsed URI according to RFC 3986.
///
/// ```text
/// scheme://user:password@host:port/path?query#fragment
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Uri {
    /// The scheme component (e.g., "http", "https", "ftp").
    pub scheme: Option<String>,
    /// The user-info component (before the `@`).
    pub user: Option<String>,
    /// The password component (after `user:` before `@`).
    pub password: Option<String>,
    /// The host component.
    pub host: Option<String>,
    /// The port component.
    pub port: Option<u16>,
    /// The path component (always present, may be empty).
    pub path: String,
    /// The query component (after `?`).
    pub query: Option<String>,
    /// The fragment component (after `#`).
    pub fragment: Option<String>,
}

impl Uri {
    /// Parse a URI string according to RFC 3986.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let mut uri = Uri::default();
        let mut rest = input;

        // Parse scheme
        if let Some(colon_pos) = rest.find(':') {
            let potential_scheme = &rest[..colon_pos];
            if !potential_scheme.is_empty()
                && potential_scheme
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic())
                    .unwrap_or(false)
                && potential_scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            {
                uri.scheme = Some(potential_scheme.to_lowercase());
                rest = &rest[colon_pos + 1..];
            }
        }

        // Parse authority (after //)
        if rest.starts_with("//") {
            rest = &rest[2..];
            // Find end of authority
            let auth_end = rest
                .find('/')
                .or_else(|| rest.find('?'))
                .or_else(|| rest.find('#'))
                .unwrap_or(rest.len());
            let authority = &rest[..auth_end];
            rest = &rest[auth_end..];

            // Parse userinfo@host:port
            let (userinfo_part, hostport) = if let Some(at_pos) = authority.rfind('@') {
                (Some(&authority[..at_pos]), &authority[at_pos + 1..])
            } else {
                (None, authority)
            };

            // Parse userinfo
            if let Some(userinfo) = userinfo_part {
                if let Some(colon) = userinfo.find(':') {
                    uri.user = Some(userinfo[..colon].to_string());
                    uri.password = Some(userinfo[colon + 1..].to_string());
                } else {
                    uri.user = Some(userinfo.to_string());
                }
            }

            // Parse host:port
            // Handle IPv6: [::1]:port
            if hostport.starts_with('[') {
                if let Some(bracket_end) = hostport.find(']') {
                    uri.host = Some(hostport[..bracket_end + 1].to_string());
                    let after_bracket = &hostport[bracket_end + 1..];
                    if let Some(port_str) = after_bracket.strip_prefix(':') {
                        uri.port = port_str.parse().ok();
                    }
                } else {
                    uri.host = Some(hostport.to_string());
                }
            } else if let Some(colon) = hostport.rfind(':') {
                let potential_port = &hostport[colon + 1..];
                if let Ok(port) = potential_port.parse::<u16>() {
                    uri.host = Some(hostport[..colon].to_string());
                    uri.port = Some(port);
                } else {
                    uri.host = Some(hostport.to_string());
                }
            } else if !hostport.is_empty() {
                uri.host = Some(hostport.to_string());
            }
        }

        // Parse path
        let (path_str, after_path) = if let Some(q) = rest.find('?') {
            (&rest[..q], &rest[q..])
        } else if let Some(f) = rest.find('#') {
            (&rest[..f], &rest[f..])
        } else {
            (rest, "")
        };
        uri.path = path_str.to_string();
        rest = after_path;

        // Parse query
        if let Some(stripped) = rest.strip_prefix('?') {
            rest = stripped;
            if let Some(f) = rest.find('#') {
                uri.query = Some(rest[..f].to_string());
                rest = &rest[f..];
            } else {
                uri.query = Some(rest.to_string());
                rest = "";
            }
        }

        // Parse fragment
        if let Some(stripped) = rest.strip_prefix('#') {
            uri.fragment = Some(stripped.to_string());
        }

        Ok(uri)
    }

    /// Reconstruct the URI as a string.
    pub fn to_string(&self) -> String {
        let mut s = String::new();

        if let Some(ref scheme) = self.scheme {
            s.push_str(scheme);
            s.push(':');
        }

        if self.host.is_some() {
            s.push_str("//");
            if let Some(ref user) = self.user {
                s.push_str(user);
                if let Some(ref password) = self.password {
                    s.push(':');
                    s.push_str(password);
                }
                s.push('@');
            }
            if let Some(ref host) = self.host {
                s.push_str(host);
            }
            if let Some(port) = self.port {
                s.push(':');
                s.push_str(&port.to_string());
            }
        }

        s.push_str(&self.path);

        if let Some(ref query) = self.query {
            s.push('?');
            s.push_str(query);
        }

        if let Some(ref fragment) = self.fragment {
            s.push('#');
            s.push_str(fragment);
        }

        s
    }

    /// Get the authority component: `[userinfo@]host[:port]`.
    pub fn authority(&self) -> Option<String> {
        self.host.as_ref().map(|host| {
            let mut auth = String::new();
            if let Some(ref user) = self.user {
                auth.push_str(user);
                if let Some(ref password) = self.password {
                    auth.push(':');
                    auth.push_str(password);
                }
                auth.push('@');
            }
            auth.push_str(host);
            if let Some(port) = self.port {
                auth.push(':');
                auth.push_str(&port.to_string());
            }
            auth
        })
    }

    /// Resolve a reference URI against this base URI (RFC 3986 Section 5).
    pub fn resolve(&self, reference: &Uri) -> Uri {
        if reference.scheme.is_some() {
            // Reference has its own scheme — use it directly
            return reference.clone();
        }

        let mut target = Uri::default();
        target.scheme = self.scheme.clone();

        if reference.host.is_some() {
            target.host = reference.host.clone();
            target.port = reference.port;
            target.user = reference.user.clone();
            target.password = reference.password.clone();
            target.path = remove_dot_segments(&reference.path);
            target.query = reference.query.clone();
        } else {
            target.host = self.host.clone();
            target.port = self.port;
            target.user = self.user.clone();
            target.password = self.password.clone();

            if reference.path.is_empty() {
                target.path = self.path.clone();
                target.query = reference.query.clone().or_else(|| self.query.clone());
            } else {
                if reference.path.starts_with('/') {
                    target.path = remove_dot_segments(&reference.path);
                } else {
                    let base_path = if self.host.is_some() && self.path.is_empty() {
                        format!("/{}", reference.path)
                    } else if let Some(last_slash) = self.path.rfind('/') {
                        format!("{}{}", &self.path[..last_slash + 1], reference.path)
                    } else {
                        reference.path.clone()
                    };
                    target.path = remove_dot_segments(&base_path);
                }
                target.query = reference.query.clone();
            }
        }

        target.fragment = reference.fragment.clone();
        target
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// ---------------------------------------------------------------------------
// Helper: remove dot segments from a path (RFC 3986 Section 5.2.4)
// ---------------------------------------------------------------------------

fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {}
            ".." => {
                output.pop();
            }
            s => output.push(s),
        }
    }

    let result = output.join("/");
    if path.starts_with('/') && !result.starts_with('/') {
        format!("/{}", result)
    } else {
        result
    }
}

// ---------------------------------------------------------------------------
// Percent-encoding helpers
// ---------------------------------------------------------------------------

/// Percent-encode a string component.
pub fn percent_encode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => {
                output.push('%');
                output.push_str(&format!("{:02X}", byte));
            }
        }
    }
    output
}

/// Decode percent-encoded sequences in a string.
pub fn percent_decode(input: &str) -> String {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                output.push(byte);
                i += 3;
                continue;
            }
        }
        output.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_uri() {
        let uri = Uri::parse("https://user:pass@example.com:8080/path?q=1#frag").unwrap();
        assert_eq!(uri.scheme, Some("https".to_string()));
        assert_eq!(uri.user, Some("user".to_string()));
        assert_eq!(uri.password, Some("pass".to_string()));
        assert_eq!(uri.host, Some("example.com".to_string()));
        assert_eq!(uri.port, Some(8080));
        assert_eq!(uri.path, "/path");
        assert_eq!(uri.query, Some("q=1".to_string()));
        assert_eq!(uri.fragment, Some("frag".to_string()));
    }

    #[test]
    fn test_parse_simple() {
        let uri = Uri::parse("http://example.com/").unwrap();
        assert_eq!(uri.scheme, Some("http".to_string()));
        assert_eq!(uri.host, Some("example.com".to_string()));
        assert_eq!(uri.path, "/");
        assert!(uri.port.is_none());
    }

    #[test]
    fn test_parse_relative() {
        let uri = Uri::parse("/path/to/resource").unwrap();
        assert!(uri.scheme.is_none());
        assert!(uri.host.is_none());
        assert_eq!(uri.path, "/path/to/resource");
    }

    #[test]
    fn test_parse_ipv6() {
        let uri = Uri::parse("http://[::1]:8080/test").unwrap();
        assert_eq!(uri.host, Some("[::1]".to_string()));
        assert_eq!(uri.port, Some(8080));
    }

    #[test]
    fn test_to_string() {
        let uri = Uri::parse("https://example.com:443/path?key=val#sec").unwrap();
        assert_eq!(uri.to_string(), "https://example.com:443/path?key=val#sec");
    }

    #[test]
    fn test_authority() {
        let uri = Uri::parse("https://user:pass@host:443/").unwrap();
        assert_eq!(uri.authority(), Some("user:pass@host:443".to_string()));
    }

    #[test]
    fn test_resolve_absolute() {
        let base = Uri::parse("http://a/b/c/d;p?q").unwrap();
        let ref_uri = Uri::parse("g:h").unwrap();
        let target = base.resolve(&ref_uri);
        assert_eq!(target.to_string(), "g:h");
    }

    #[test]
    fn test_resolve_relative_path() {
        let base = Uri::parse("http://a/b/c/d").unwrap();
        let ref_uri = Uri::parse("../g").unwrap();
        let target = base.resolve(&ref_uri);
        assert_eq!(target.path, "/b/g");
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a+b=c"), "a%2Bb%3Dc");
        assert_eq!(percent_encode("safe-_.~"), "safe-_.~");
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a%2Bb%3Dc"), "a+b=c");
        assert_eq!(percent_decode("no%encoding"), "no%encoding"); // invalid % sequence kept
    }

    #[test]
    fn test_remove_dot_segments() {
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("/a/b/../c"), "/a/c");
    }

    #[test]
    fn test_parse_query_only() {
        let uri = Uri::parse("?query=1").unwrap();
        assert_eq!(uri.query, Some("query=1".to_string()));
        assert!(uri.path.is_empty());
    }

    #[test]
    fn test_parse_fragment_only() {
        let uri = Uri::parse("#section").unwrap();
        assert_eq!(uri.fragment, Some("section".to_string()));
    }

    #[test]
    fn test_parse_no_port() {
        let uri = Uri::parse("http://example.com/path").unwrap();
        assert!(uri.port.is_none());
        assert_eq!(uri.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_default_uri() {
        let uri = Uri::default();
        assert!(uri.scheme.is_none());
        assert!(uri.host.is_none());
        assert!(uri.path.is_empty());
    }
}
