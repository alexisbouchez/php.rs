//! PHP ldap extension implementation for php.rs
//!
//! Provides LDAP directory access functions.
//! Reference: php-src/ext/ldap/
//!
//! This is a pure Rust implementation that provides the full API surface
//! for compatibility. Network operations are stubbed for testing.

use std::collections::HashMap;

// LDAP option constants
pub const LDAP_OPT_PROTOCOL_VERSION: i32 = 17;
pub const LDAP_OPT_REFERRALS: i32 = 8;
pub const LDAP_OPT_TIMELIMIT: i32 = 4;

// LDAP escape flags
pub const LDAP_ESCAPE_FILTER: i32 = 1;
pub const LDAP_ESCAPE_DN: i32 = 2;

// LDAP protocol versions
pub const LDAP_VERSION2: i32 = 2;
pub const LDAP_VERSION3: i32 = 3;

/// Error type for LDAP operations.
#[derive(Debug, Clone, PartialEq)]
pub enum LdapError {
    /// Connection failed
    ConnectionFailed(String),
    /// Not bound (authentication required)
    NotBound,
    /// Invalid DN
    InvalidDn(String),
    /// Entry not found
    NotFound(String),
    /// Operation failed
    OperationFailed(String),
    /// Invalid filter syntax
    InvalidFilter(String),
    /// Protocol error
    ProtocolError(i32, String),
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapError::ConnectionFailed(msg) => write!(f, "LDAP connection failed: {}", msg),
            LdapError::NotBound => write!(f, "LDAP not bound"),
            LdapError::InvalidDn(dn) => write!(f, "Invalid DN: {}", dn),
            LdapError::NotFound(msg) => write!(f, "Not found: {}", msg),
            LdapError::OperationFailed(msg) => write!(f, "Operation failed: {}", msg),
            LdapError::InvalidFilter(msg) => write!(f, "Invalid filter: {}", msg),
            LdapError::ProtocolError(code, msg) => {
                write!(f, "Protocol error {}: {}", code, msg)
            }
        }
    }
}

/// Represents an LDAP connection.
#[derive(Debug, Clone)]
pub struct LdapConnection {
    /// Host the connection is to
    pub host: String,
    /// Port number
    pub port: u16,
    /// Whether the connection is bound (authenticated)
    pub bound: bool,
    /// LDAP protocol version (2 or 3)
    pub protocol_version: i32,
    /// Connection options
    pub options: HashMap<i32, i32>,
    /// Last error code
    pub last_error_code: i32,
    /// Last error message
    pub last_error_message: String,
    /// In-memory directory entries for testing
    pub entries: HashMap<String, HashMap<String, Vec<String>>>,
}

/// Represents an LDAP entry.
#[derive(Debug, Clone, PartialEq)]
pub struct LdapEntry {
    /// Distinguished Name
    pub dn: String,
    /// Attributes and their values
    pub attributes: HashMap<String, Vec<String>>,
}

/// Represents an LDAP search result.
#[derive(Debug, Clone)]
pub struct LdapSearchResult {
    /// Entries matching the search
    pub entries: Vec<LdapEntry>,
    /// Number of entries
    pub count: i32,
}

/// Connect to an LDAP server.
///
/// Returns an LdapConnection on success.
/// PHP signature: ldap_connect(?string $uri = null, int $port = 389): LDAP\Connection|false
pub fn ldap_connect(host: &str, port: u16) -> Result<LdapConnection, LdapError> {
    if host.is_empty() {
        return Err(LdapError::ConnectionFailed(
            "Host cannot be empty".to_string(),
        ));
    }

    Ok(LdapConnection {
        host: host.to_string(),
        port,
        bound: false,
        protocol_version: LDAP_VERSION3,
        options: HashMap::new(),
        last_error_code: 0,
        last_error_message: String::new(),
        entries: HashMap::new(),
    })
}

/// Bind to an LDAP directory.
///
/// PHP signature: ldap_bind(LDAP\Connection $ldap, ?string $dn = null, ?string $password = null): bool
pub fn ldap_bind(conn: &mut LdapConnection, dn: &str, password: &str) -> bool {
    // Anonymous bind if both empty
    if dn.is_empty() && password.is_empty() {
        conn.bound = true;
        conn.last_error_code = 0;
        conn.last_error_message = String::new();
        return true;
    }

    // Simple validation: DN should contain at least one =
    if !dn.is_empty() && !dn.contains('=') {
        conn.last_error_code = 34; // LDAP_INVALID_DN_SYNTAX
        conn.last_error_message = "Invalid DN syntax".to_string();
        return false;
    }

    // Stub: accept any non-empty password
    if !password.is_empty() {
        conn.bound = true;
        conn.last_error_code = 0;
        conn.last_error_message = String::new();
        true
    } else {
        conn.last_error_code = 49; // LDAP_INVALID_CREDENTIALS
        conn.last_error_message = "Invalid credentials".to_string();
        false
    }
}

/// Unbind from an LDAP directory.
///
/// PHP signature: ldap_unbind(LDAP\Connection $ldap): bool
pub fn ldap_unbind(conn: &mut LdapConnection) -> bool {
    conn.bound = false;
    conn.last_error_code = 0;
    conn.last_error_message = String::new();
    true
}

/// Search LDAP directory.
///
/// PHP signature: ldap_search(LDAP\Connection $ldap, ...): LDAP\Result|array|false
pub fn ldap_search(
    conn: &LdapConnection,
    base_dn: &str,
    filter: &str,
    attributes: &[&str],
) -> Result<LdapSearchResult, LdapError> {
    if !conn.bound {
        return Err(LdapError::NotBound);
    }

    // Basic filter validation
    if !filter.is_empty() && filter.starts_with('(') && !filter.ends_with(')') {
        return Err(LdapError::InvalidFilter(filter.to_string()));
    }

    // Search in-memory entries
    let mut results = Vec::new();
    for (dn, attrs) in &conn.entries {
        // Check if entry is under the base DN
        if !dn.ends_with(base_dn) && dn != base_dn {
            continue;
        }

        // Basic filter matching: support (attr=value) style
        if !filter.is_empty() && filter != "(objectClass=*)" {
            let filter_inner = filter.trim_start_matches('(').trim_end_matches(')');
            if let Some((attr, val)) = filter_inner.split_once('=') {
                let attr_lower = attr.to_lowercase();
                let matches = attrs.iter().any(|(k, values)| {
                    k.to_lowercase() == attr_lower
                        && (val == "*" || values.iter().any(|v| v == val))
                });
                if !matches {
                    continue;
                }
            }
        }

        // Filter attributes if specified
        let filtered_attrs = if attributes.is_empty() {
            attrs.clone()
        } else {
            attrs
                .iter()
                .filter(|(k, _)| {
                    attributes
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(k.as_str()))
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        results.push(LdapEntry {
            dn: dn.clone(),
            attributes: filtered_attrs,
        });
    }

    let count = results.len() as i32;
    Ok(LdapSearchResult {
        entries: results,
        count,
    })
}

/// Count entries in a search result.
///
/// PHP signature: ldap_count_entries(LDAP\Connection $ldap, LDAP\Result $result): int
pub fn ldap_count_entries(_conn: &LdapConnection, result: &LdapSearchResult) -> i32 {
    result.count
}

/// Get the first entry from a search result.
///
/// PHP signature: ldap_first_entry(LDAP\Connection $ldap, LDAP\Result $result): LDAP\ResultEntry|false
pub fn ldap_first_entry(result: &LdapSearchResult) -> Option<&LdapEntry> {
    result.entries.first()
}

/// Get the next entry from a search result.
///
/// PHP signature: ldap_next_entry(LDAP\Connection $ldap, LDAP\ResultEntry $entry): LDAP\ResultEntry|false
pub fn ldap_next_entry<'a>(
    result: &'a LdapSearchResult,
    entry: &LdapEntry,
) -> Option<&'a LdapEntry> {
    let pos = result.entries.iter().position(|e| e.dn == entry.dn)?;
    result.entries.get(pos + 1)
}

/// Get the DN of an entry.
///
/// PHP signature: ldap_get_dn(LDAP\Connection $ldap, LDAP\ResultEntry $entry): string|false
pub fn ldap_get_dn(entry: &LdapEntry) -> String {
    entry.dn.clone()
}

/// Get the attributes of an entry.
///
/// PHP signature: ldap_get_attributes(LDAP\Connection $ldap, LDAP\ResultEntry $entry): array
pub fn ldap_get_attributes(entry: &LdapEntry) -> HashMap<String, Vec<String>> {
    entry.attributes.clone()
}

/// Get the values for a specific attribute of an entry.
///
/// PHP signature: ldap_get_values(LDAP\Connection $ldap, LDAP\ResultEntry $entry, string $attribute): array|false
pub fn ldap_get_values(entry: &LdapEntry, attribute: &str) -> Vec<String> {
    entry
        .attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(attribute))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Add an entry to the LDAP directory.
///
/// PHP signature: ldap_add(LDAP\Connection $ldap, string $dn, array $entry, ?array $controls = null): bool
pub fn ldap_add(conn: &mut LdapConnection, dn: &str, entry: &HashMap<String, Vec<String>>) -> bool {
    if !conn.bound {
        conn.last_error_code = 1;
        conn.last_error_message = "Not bound".to_string();
        return false;
    }

    if dn.is_empty() || !dn.contains('=') {
        conn.last_error_code = 34;
        conn.last_error_message = "Invalid DN syntax".to_string();
        return false;
    }

    if conn.entries.contains_key(dn) {
        conn.last_error_code = 68; // LDAP_ALREADY_EXISTS
        conn.last_error_message = "Already exists".to_string();
        return false;
    }

    conn.entries.insert(dn.to_string(), entry.clone());
    conn.last_error_code = 0;
    conn.last_error_message = String::new();
    true
}

/// Modify an entry in the LDAP directory.
///
/// PHP signature: ldap_modify(LDAP\Connection $ldap, string $dn, array $entry, ?array $controls = null): bool
pub fn ldap_modify(
    conn: &mut LdapConnection,
    dn: &str,
    entry: &HashMap<String, Vec<String>>,
) -> bool {
    if !conn.bound {
        conn.last_error_code = 1;
        conn.last_error_message = "Not bound".to_string();
        return false;
    }

    if let Some(existing) = conn.entries.get_mut(dn) {
        for (key, values) in entry {
            existing.insert(key.clone(), values.clone());
        }
        conn.last_error_code = 0;
        conn.last_error_message = String::new();
        true
    } else {
        conn.last_error_code = 32; // LDAP_NO_SUCH_OBJECT
        conn.last_error_message = "No such object".to_string();
        false
    }
}

/// Delete an entry from the LDAP directory.
///
/// PHP signature: ldap_delete(LDAP\Connection $ldap, string $dn, ?array $controls = null): bool
pub fn ldap_delete(conn: &mut LdapConnection, dn: &str) -> bool {
    if !conn.bound {
        conn.last_error_code = 1;
        conn.last_error_message = "Not bound".to_string();
        return false;
    }

    if conn.entries.remove(dn).is_some() {
        conn.last_error_code = 0;
        conn.last_error_message = String::new();
        true
    } else {
        conn.last_error_code = 32; // LDAP_NO_SUCH_OBJECT
        conn.last_error_message = "No such object".to_string();
        false
    }
}

/// Set an LDAP option.
///
/// PHP signature: ldap_set_option(LDAP\Connection|null $ldap, int $option, mixed $value): bool
pub fn ldap_set_option(conn: &mut LdapConnection, option: i32, value: i32) -> bool {
    match option {
        LDAP_OPT_PROTOCOL_VERSION => {
            if value == LDAP_VERSION2 || value == LDAP_VERSION3 {
                conn.protocol_version = value;
                conn.options.insert(option, value);
                true
            } else {
                false
            }
        }
        LDAP_OPT_REFERRALS | LDAP_OPT_TIMELIMIT => {
            conn.options.insert(option, value);
            true
        }
        _ => false,
    }
}

/// Get the last error message.
///
/// PHP signature: ldap_error(LDAP\Connection $ldap): string
pub fn ldap_error(conn: &LdapConnection) -> String {
    if conn.last_error_code == 0 {
        "Success".to_string()
    } else {
        conn.last_error_message.clone()
    }
}

/// Get the last error number.
///
/// PHP signature: ldap_errno(LDAP\Connection $ldap): int
pub fn ldap_errno(conn: &LdapConnection) -> i32 {
    conn.last_error_code
}

/// Escape a string for use in LDAP filters or DNs.
///
/// PHP signature: ldap_escape(string $value, string $ignore = "", int $flags = 0): string
pub fn ldap_escape(value: &str, ignore: &str, flags: i32) -> String {
    let mut result = String::with_capacity(value.len() * 3);

    for ch in value.chars() {
        if ignore.contains(ch) {
            result.push(ch);
            continue;
        }

        let should_escape = if flags & LDAP_ESCAPE_FILTER != 0 {
            // Filter special chars: * ( ) \ NUL
            matches!(ch, '*' | '(' | ')' | '\\' | '\0')
        } else if flags & LDAP_ESCAPE_DN != 0 {
            // DN special chars: , + " \ < > ; # = (and leading/trailing spaces)
            matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '#' | '=')
        } else {
            // Both filter and DN special chars
            matches!(
                ch,
                '*' | '(' | ')' | '\\' | '\0' | ',' | '+' | '"' | '<' | '>' | ';' | '#' | '='
            )
        };

        if should_escape {
            // Escape as \HH hex
            for byte in ch.to_string().as_bytes() {
                result.push_str(&format!("\\{:02x}", byte));
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_connect() {
        let conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert_eq!(conn.host, "ldap.example.com");
        assert_eq!(conn.port, 389);
        assert!(!conn.bound);
        assert_eq!(conn.protocol_version, LDAP_VERSION3);
    }

    #[test]
    fn test_ldap_connect_empty_host() {
        let result = ldap_connect("", 389);
        assert!(result.is_err());
        assert!(matches!(result, Err(LdapError::ConnectionFailed(_))));
    }

    #[test]
    fn test_ldap_bind_anonymous() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert!(ldap_bind(&mut conn, "", ""));
        assert!(conn.bound);
    }

    #[test]
    fn test_ldap_bind_authenticated() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert!(ldap_bind(&mut conn, "cn=admin,dc=example,dc=com", "secret"));
        assert!(conn.bound);
        assert_eq!(ldap_errno(&conn), 0);
    }

    #[test]
    fn test_ldap_bind_invalid_dn() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert!(!ldap_bind(&mut conn, "invalid-dn", "secret"));
        assert!(!conn.bound);
        assert_eq!(ldap_errno(&conn), 34);
    }

    #[test]
    fn test_ldap_unbind() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");
        assert!(conn.bound);
        assert!(ldap_unbind(&mut conn));
        assert!(!conn.bound);
    }

    #[test]
    fn test_ldap_add_and_search() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry = HashMap::new();
        entry.insert("cn".to_string(), vec!["John Doe".to_string()]);
        entry.insert(
            "objectClass".to_string(),
            vec!["person".to_string(), "top".to_string()],
        );
        entry.insert("mail".to_string(), vec!["john@example.com".to_string()]);

        assert!(ldap_add(&mut conn, "cn=John Doe,dc=example,dc=com", &entry));

        let result = ldap_search(&conn, "dc=example,dc=com", "(objectClass=*)", &[]).unwrap();
        assert_eq!(ldap_count_entries(&conn, &result), 1);

        let first = ldap_first_entry(&result).unwrap();
        assert_eq!(ldap_get_dn(first), "cn=John Doe,dc=example,dc=com");

        let attrs = ldap_get_attributes(first);
        assert!(attrs.contains_key("cn"));
        assert_eq!(attrs["cn"], vec!["John Doe".to_string()]);
    }

    #[test]
    fn test_ldap_add_duplicate() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry = HashMap::new();
        entry.insert("cn".to_string(), vec!["Test".to_string()]);

        assert!(ldap_add(&mut conn, "cn=Test,dc=example,dc=com", &entry));
        assert!(!ldap_add(&mut conn, "cn=Test,dc=example,dc=com", &entry));
        assert_eq!(ldap_errno(&conn), 68);
    }

    #[test]
    fn test_ldap_modify() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry = HashMap::new();
        entry.insert("cn".to_string(), vec!["Original".to_string()]);
        ldap_add(&mut conn, "cn=Original,dc=example,dc=com", &entry);

        let mut mods = HashMap::new();
        mods.insert("mail".to_string(), vec!["updated@example.com".to_string()]);
        assert!(ldap_modify(
            &mut conn,
            "cn=Original,dc=example,dc=com",
            &mods
        ));

        let result = ldap_search(&conn, "dc=example,dc=com", "(objectClass=*)", &[]).unwrap();
        let first = ldap_first_entry(&result).unwrap();
        let mail = ldap_get_values(first, "mail");
        assert_eq!(mail, vec!["updated@example.com".to_string()]);
    }

    #[test]
    fn test_ldap_delete() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry = HashMap::new();
        entry.insert("cn".to_string(), vec!["ToDelete".to_string()]);
        ldap_add(&mut conn, "cn=ToDelete,dc=example,dc=com", &entry);

        assert!(ldap_delete(&mut conn, "cn=ToDelete,dc=example,dc=com"));
        assert!(!ldap_delete(&mut conn, "cn=ToDelete,dc=example,dc=com"));
        assert_eq!(ldap_errno(&conn), 32);
    }

    #[test]
    fn test_ldap_search_not_bound() {
        let conn = ldap_connect("ldap.example.com", 389).unwrap();
        let result = ldap_search(&conn, "dc=example,dc=com", "(objectClass=*)", &[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(LdapError::NotBound)));
    }

    #[test]
    fn test_ldap_search_with_filter() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry1 = HashMap::new();
        entry1.insert("cn".to_string(), vec!["Alice".to_string()]);
        entry1.insert("department".to_string(), vec!["Engineering".to_string()]);
        ldap_add(&mut conn, "cn=Alice,dc=example,dc=com", &entry1);

        let mut entry2 = HashMap::new();
        entry2.insert("cn".to_string(), vec!["Bob".to_string()]);
        entry2.insert("department".to_string(), vec!["Marketing".to_string()]);
        ldap_add(&mut conn, "cn=Bob,dc=example,dc=com", &entry2);

        let result =
            ldap_search(&conn, "dc=example,dc=com", "(department=Engineering)", &[]).unwrap();
        assert_eq!(result.count, 1);
        let first = ldap_first_entry(&result).unwrap();
        assert_eq!(ldap_get_values(first, "cn"), vec!["Alice".to_string()]);
    }

    #[test]
    fn test_ldap_search_with_attribute_filter() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut entry = HashMap::new();
        entry.insert("cn".to_string(), vec!["Charlie".to_string()]);
        entry.insert("mail".to_string(), vec!["charlie@example.com".to_string()]);
        entry.insert("phone".to_string(), vec!["555-1234".to_string()]);
        ldap_add(&mut conn, "cn=Charlie,dc=example,dc=com", &entry);

        let result = ldap_search(
            &conn,
            "dc=example,dc=com",
            "(objectClass=*)",
            &["cn", "mail"],
        )
        .unwrap();
        let first = ldap_first_entry(&result).unwrap();
        let attrs = ldap_get_attributes(first);
        assert!(attrs.contains_key("cn"));
        assert!(attrs.contains_key("mail"));
        assert!(!attrs.contains_key("phone"));
    }

    #[test]
    fn test_ldap_next_entry() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        ldap_bind(&mut conn, "", "");

        let mut e1 = HashMap::new();
        e1.insert("cn".to_string(), vec!["First".to_string()]);
        ldap_add(&mut conn, "cn=First,dc=example,dc=com", &e1);

        let mut e2 = HashMap::new();
        e2.insert("cn".to_string(), vec!["Second".to_string()]);
        ldap_add(&mut conn, "cn=Second,dc=example,dc=com", &e2);

        let result = ldap_search(&conn, "dc=example,dc=com", "(objectClass=*)", &[]).unwrap();
        assert_eq!(result.count, 2);

        let first = ldap_first_entry(&result).unwrap();
        let second = ldap_next_entry(&result, first);
        assert!(second.is_some());

        let second = second.unwrap();
        let third = ldap_next_entry(&result, second);
        assert!(third.is_none());
    }

    #[test]
    fn test_ldap_set_option_protocol_version() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert!(ldap_set_option(
            &mut conn,
            LDAP_OPT_PROTOCOL_VERSION,
            LDAP_VERSION3
        ));
        assert_eq!(conn.protocol_version, LDAP_VERSION3);

        assert!(ldap_set_option(
            &mut conn,
            LDAP_OPT_PROTOCOL_VERSION,
            LDAP_VERSION2
        ));
        assert_eq!(conn.protocol_version, LDAP_VERSION2);

        // Invalid version
        assert!(!ldap_set_option(&mut conn, LDAP_OPT_PROTOCOL_VERSION, 99));
    }

    #[test]
    fn test_ldap_set_option_referrals() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert!(ldap_set_option(&mut conn, LDAP_OPT_REFERRALS, 0));
        assert_eq!(conn.options[&LDAP_OPT_REFERRALS], 0);
    }

    #[test]
    fn test_ldap_error_and_errno() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        assert_eq!(ldap_error(&conn), "Success");
        assert_eq!(ldap_errno(&conn), 0);

        ldap_bind(&mut conn, "invalid-dn", "secret");
        assert_eq!(ldap_errno(&conn), 34);
        assert_eq!(ldap_error(&conn), "Invalid DN syntax");
    }

    #[test]
    fn test_ldap_escape_filter() {
        assert_eq!(
            ldap_escape("test*value", "", LDAP_ESCAPE_FILTER),
            "test\\2avalue"
        );
        assert_eq!(
            ldap_escape("(test)", "", LDAP_ESCAPE_FILTER),
            "\\28test\\29"
        );
        assert_eq!(
            ldap_escape("back\\slash", "", LDAP_ESCAPE_FILTER),
            "back\\5cslash"
        );
        assert_eq!(
            ldap_escape("null\0byte", "", LDAP_ESCAPE_FILTER),
            "null\\00byte"
        );
    }

    #[test]
    fn test_ldap_escape_dn() {
        assert_eq!(
            ldap_escape("test,value", "", LDAP_ESCAPE_DN),
            "test\\2cvalue"
        );
        assert_eq!(ldap_escape("a+b", "", LDAP_ESCAPE_DN), "a\\2bb");
        assert_eq!(ldap_escape("a\"b", "", LDAP_ESCAPE_DN), "a\\22b");
        assert_eq!(ldap_escape("a=b", "", LDAP_ESCAPE_DN), "a\\3db");
    }

    #[test]
    fn test_ldap_escape_with_ignore() {
        assert_eq!(
            ldap_escape("test*value*end", "*", LDAP_ESCAPE_FILTER),
            "test*value*end"
        );
        assert_eq!(ldap_escape("a,b,c", ",", LDAP_ESCAPE_DN), "a,b,c");
    }

    #[test]
    fn test_ldap_operations_without_bind() {
        let mut conn = ldap_connect("ldap.example.com", 389).unwrap();
        let entry = HashMap::new();
        assert!(!ldap_add(&mut conn, "cn=test,dc=example,dc=com", &entry));
        assert!(!ldap_modify(&mut conn, "cn=test,dc=example,dc=com", &entry));
        assert!(!ldap_delete(&mut conn, "cn=test,dc=example,dc=com"));
    }
}
