//! PHP snmp extension implementation for php.rs
//!
//! Provides SNMP protocol functions for network management.
//! Reference: php-src/ext/snmp/
//!
//! This is a pure Rust implementation that provides the full API surface.
//! Network operations are stubbed for testing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

// SNMP version constants
pub const SNMP_VERSION_1: i32 = 0;
pub const SNMP_VERSION_2C: i32 = 1;
pub const SNMP_VERSION_3: i32 = 3;

// ASN.1 value type constants
pub const ASN_INTEGER: char = 'i';
pub const ASN_OCTET_STR: char = 's';
pub const ASN_OBJECT_ID: char = 'o';
pub const ASN_COUNTER: char = 'c';
pub const ASN_GAUGE: char = 'g';
pub const ASN_TIMETICKS: char = 't';
pub const ASN_IPADDRESS: char = 'a';
pub const ASN_COUNTER64: char = 'C';
pub const ASN_UNSIGNED: char = 'u';

// Quick print mode (global state matching PHP behavior)
static QUICK_PRINT: AtomicBool = AtomicBool::new(false);

/// Error type for SNMP operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SnmpError {
    /// Connection/session error
    ConnectionError(String),
    /// Timeout
    Timeout,
    /// OID not found
    NoSuchObject(String),
    /// Invalid OID format
    InvalidOid(String),
    /// Generic SNMP error
    GenericError(String),
    /// Authentication error (SNMPv3)
    AuthenticationError(String),
}

impl std::fmt::Display for SnmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnmpError::ConnectionError(msg) => write!(f, "SNMP connection error: {}", msg),
            SnmpError::Timeout => write!(f, "SNMP request timeout"),
            SnmpError::NoSuchObject(oid) => write!(f, "No such object: {}", oid),
            SnmpError::InvalidOid(oid) => write!(f, "Invalid OID: {}", oid),
            SnmpError::GenericError(msg) => write!(f, "SNMP error: {}", msg),
            SnmpError::AuthenticationError(msg) => write!(f, "SNMP auth error: {}", msg),
        }
    }
}

/// Represents an SNMP session.
#[derive(Debug, Clone)]
pub struct SnmpSession {
    /// Target host
    pub host: String,
    /// Community string (v1/v2c)
    pub community: String,
    /// SNMP version
    pub version: i32,
    /// Timeout in microseconds
    pub timeout: i64,
    /// Number of retries
    pub retries: i32,
    /// SNMPv3 security level
    pub security_level: String,
    /// SNMPv3 security name
    pub security_name: String,
    /// SNMPv3 auth protocol
    pub auth_protocol: String,
    /// SNMPv3 auth passphrase
    pub auth_passphrase: String,
    /// SNMPv3 priv protocol
    pub priv_protocol: String,
    /// SNMPv3 priv passphrase
    pub priv_passphrase: String,
    /// In-memory MIB data for testing
    pub mib_data: HashMap<String, SnmpValue>,
}

/// Represents an SNMP value.
#[derive(Debug, Clone, PartialEq)]
pub struct SnmpValue {
    /// Object identifier
    pub oid: String,
    /// Type identifier (ASN.1 type character)
    pub type_id: char,
    /// String representation of value
    pub value: String,
}

impl SnmpSession {
    /// Create a new SNMPv1 session.
    pub fn new_v1(host: &str, community: &str) -> Self {
        Self::new(host, community, SNMP_VERSION_1)
    }

    /// Create a new SNMPv2c session.
    pub fn new_v2c(host: &str, community: &str) -> Self {
        Self::new(host, community, SNMP_VERSION_2C)
    }

    /// Create a new session with the given version.
    pub fn new(host: &str, community: &str, version: i32) -> Self {
        SnmpSession {
            host: host.to_string(),
            community: community.to_string(),
            version,
            timeout: 1000000,
            retries: 3,
            security_level: String::new(),
            security_name: String::new(),
            auth_protocol: String::new(),
            auth_passphrase: String::new(),
            priv_protocol: String::new(),
            priv_passphrase: String::new(),
            mib_data: HashMap::new(),
        }
    }

    /// Create a new SNMPv3 session.
    pub fn new_v3(
        host: &str,
        security_name: &str,
        security_level: &str,
        auth_protocol: &str,
        auth_passphrase: &str,
        priv_protocol: &str,
        priv_passphrase: &str,
    ) -> Self {
        SnmpSession {
            host: host.to_string(),
            community: String::new(),
            version: SNMP_VERSION_3,
            timeout: 1000000,
            retries: 3,
            security_level: security_level.to_string(),
            security_name: security_name.to_string(),
            auth_protocol: auth_protocol.to_string(),
            auth_passphrase: auth_passphrase.to_string(),
            priv_protocol: priv_protocol.to_string(),
            priv_passphrase: priv_passphrase.to_string(),
            mib_data: HashMap::new(),
        }
    }

    /// Add test data to the session MIB.
    pub fn add_test_data(&mut self, oid: &str, type_id: char, value: &str) {
        self.mib_data.insert(
            oid.to_string(),
            SnmpValue {
                oid: oid.to_string(),
                type_id,
                value: value.to_string(),
            },
        );
    }
}

/// Validate an OID string.
fn validate_oid(oid: &str) -> Result<(), SnmpError> {
    if oid.is_empty() {
        return Err(SnmpError::InvalidOid("empty OID".to_string()));
    }
    let oid_trimmed = oid.trim_start_matches('.');
    for part in oid_trimmed.split('.') {
        if part.parse::<u64>().is_err() {
            return Err(SnmpError::InvalidOid(oid.to_string()));
        }
    }
    Ok(())
}

/// Format an SNMP value for display.
fn format_value(val: &SnmpValue) -> String {
    if snmp_get_quick_print() {
        val.value.clone()
    } else {
        let type_name = match val.type_id {
            ASN_INTEGER => "INTEGER",
            ASN_OCTET_STR => "STRING",
            ASN_OBJECT_ID => "OID",
            ASN_COUNTER => "Counter32",
            ASN_GAUGE => "Gauge32",
            ASN_TIMETICKS => "Timeticks",
            ASN_IPADDRESS => "IpAddress",
            ASN_COUNTER64 => "Counter64",
            ASN_UNSIGNED => "Unsigned32",
            _ => "Unknown",
        };
        format!("{}: {}", type_name, val.value)
    }
}

/// Get an SNMP value.
///
/// PHP signature: snmp_get(SNMP $session, string|array $objectId): mixed
pub fn snmp_get(session: &SnmpSession, oid: &str) -> Result<SnmpValue, SnmpError> {
    validate_oid(oid)?;

    if session.host.is_empty() {
        return Err(SnmpError::ConnectionError("No host specified".to_string()));
    }

    session
        .mib_data
        .get(oid)
        .cloned()
        .ok_or_else(|| SnmpError::NoSuchObject(oid.to_string()))
}

/// Get the next SNMP value (lexicographically after the given OID).
///
/// PHP signature: snmp_getnext(SNMP $session, string|array $objectId): mixed
pub fn snmp_getnext(session: &SnmpSession, oid: &str) -> Result<SnmpValue, SnmpError> {
    validate_oid(oid)?;

    if session.host.is_empty() {
        return Err(SnmpError::ConnectionError("No host specified".to_string()));
    }

    let mut oids: Vec<&String> = session.mib_data.keys().collect();
    oids.sort();

    for mib_oid in &oids {
        if mib_oid.as_str() > oid {
            return Ok(session.mib_data[mib_oid.as_str()].clone());
        }
    }

    Err(SnmpError::NoSuchObject(format!(
        "No next OID after {}",
        oid
    )))
}

/// Walk an SNMP subtree.
///
/// PHP signature: snmp_walk(SNMP $session, string|array $objectId): array|false
pub fn snmp_walk(session: &SnmpSession, oid: &str) -> Result<Vec<SnmpValue>, SnmpError> {
    validate_oid(oid)?;

    if session.host.is_empty() {
        return Err(SnmpError::ConnectionError("No host specified".to_string()));
    }

    let prefix = if oid.ends_with('.') {
        oid.to_string()
    } else {
        format!("{}.", oid)
    };

    let mut results: Vec<SnmpValue> = session
        .mib_data
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix) || *k == oid)
        .map(|(_, v)| v.clone())
        .collect();

    results.sort_by(|a, b| a.oid.cmp(&b.oid));
    Ok(results)
}

/// Set an SNMP value.
///
/// PHP signature: snmp_set(SNMP $session, string|array $objectId, ...): bool
pub fn snmp_set(session: &mut SnmpSession, oid: &str, type_: char, value: &str) -> bool {
    if validate_oid(oid).is_err() || session.host.is_empty() {
        return false;
    }

    session.mib_data.insert(
        oid.to_string(),
        SnmpValue {
            oid: oid.to_string(),
            type_id: type_,
            value: value.to_string(),
        },
    );
    true
}

// --- Convenience functions (PHP procedural API) ---

/// PHP signature: snmpget(string $hostname, string $community, string $object_id, ...): string|false
pub fn snmpget(host: &str, community: &str, oid: &str) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v1(host, community);
    snmp_get(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmpgetnext(string $hostname, string $community, string $object_id, ...): string|false
pub fn snmpgetnext(host: &str, community: &str, oid: &str) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v1(host, community);
    snmp_getnext(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmpwalk(string $hostname, string $community, string $object_id, ...): array|false
pub fn snmpwalk(host: &str, community: &str, oid: &str) -> Result<Vec<String>, SnmpError> {
    let session = SnmpSession::new_v1(host, community);
    snmp_walk(&session, oid).map(|vals| vals.iter().map(format_value).collect())
}

/// PHP signature: snmpset(string $hostname, string $community, string $object_id, ...): bool
pub fn snmpset(host: &str, community: &str, oid: &str, type_: char, value: &str) -> bool {
    let mut session = SnmpSession::new_v1(host, community);
    snmp_set(&mut session, oid, type_, value)
}

// --- SNMPv2c convenience functions ---

/// PHP signature: snmp2_get(string $hostname, string $community, string $object_id, ...): string|false
pub fn snmp2_get(host: &str, community: &str, oid: &str) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v2c(host, community);
    snmp_get(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmp2_getnext(string $hostname, string $community, string $object_id, ...): string|false
pub fn snmp2_getnext(host: &str, community: &str, oid: &str) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v2c(host, community);
    snmp_getnext(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmp2_walk(string $hostname, string $community, string $object_id, ...): array|false
pub fn snmp2_walk(host: &str, community: &str, oid: &str) -> Result<Vec<String>, SnmpError> {
    let session = SnmpSession::new_v2c(host, community);
    snmp_walk(&session, oid).map(|vals| vals.iter().map(format_value).collect())
}

/// PHP signature: snmp2_set(string $hostname, string $community, string $object_id, ...): bool
pub fn snmp2_set(host: &str, community: &str, oid: &str, type_: char, value: &str) -> bool {
    let mut session = SnmpSession::new_v2c(host, community);
    snmp_set(&mut session, oid, type_, value)
}

// --- SNMPv3 convenience functions ---

/// PHP signature: snmp3_get(string $hostname, string $security_name, ...): string|false
#[allow(clippy::too_many_arguments)]
pub fn snmp3_get(
    host: &str,
    security_name: &str,
    security_level: &str,
    auth_protocol: &str,
    auth_passphrase: &str,
    priv_protocol: &str,
    priv_passphrase: &str,
    oid: &str,
) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v3(
        host,
        security_name,
        security_level,
        auth_protocol,
        auth_passphrase,
        priv_protocol,
        priv_passphrase,
    );
    snmp_get(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmp3_getnext(string $hostname, string $security_name, ...): string|false
#[allow(clippy::too_many_arguments)]
pub fn snmp3_getnext(
    host: &str,
    security_name: &str,
    security_level: &str,
    auth_protocol: &str,
    auth_passphrase: &str,
    priv_protocol: &str,
    priv_passphrase: &str,
    oid: &str,
) -> Result<String, SnmpError> {
    let session = SnmpSession::new_v3(
        host,
        security_name,
        security_level,
        auth_protocol,
        auth_passphrase,
        priv_protocol,
        priv_passphrase,
    );
    snmp_getnext(&session, oid).map(|v| format_value(&v))
}

/// PHP signature: snmp3_walk(string $hostname, string $security_name, ...): array|false
#[allow(clippy::too_many_arguments)]
pub fn snmp3_walk(
    host: &str,
    security_name: &str,
    security_level: &str,
    auth_protocol: &str,
    auth_passphrase: &str,
    priv_protocol: &str,
    priv_passphrase: &str,
    oid: &str,
) -> Result<Vec<String>, SnmpError> {
    let session = SnmpSession::new_v3(
        host,
        security_name,
        security_level,
        auth_protocol,
        auth_passphrase,
        priv_protocol,
        priv_passphrase,
    );
    snmp_walk(&session, oid).map(|vals| vals.iter().map(format_value).collect())
}

/// PHP signature: snmp3_set(string $hostname, string $security_name, ...): bool
#[allow(clippy::too_many_arguments)]
pub fn snmp3_set(
    host: &str,
    security_name: &str,
    security_level: &str,
    auth_protocol: &str,
    auth_passphrase: &str,
    priv_protocol: &str,
    priv_passphrase: &str,
    oid: &str,
    type_: char,
    value: &str,
) -> bool {
    let mut session = SnmpSession::new_v3(
        host,
        security_name,
        security_level,
        auth_protocol,
        auth_passphrase,
        priv_protocol,
        priv_passphrase,
    );
    snmp_set(&mut session, oid, type_, value)
}

/// Get the current quick_print setting.
///
/// PHP signature: snmp_get_quick_print(): bool
pub fn snmp_get_quick_print() -> bool {
    QUICK_PRINT.load(Ordering::Relaxed)
}

/// Set the quick_print mode.
///
/// PHP signature: snmp_set_quick_print(bool $quick_print): true
pub fn snmp_set_quick_print(enable: bool) {
    QUICK_PRINT.store(enable, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_session() -> SnmpSession {
        let mut session = SnmpSession::new_v1("localhost", "public");
        session.add_test_data(".1.3.6.1.2.1.1.1.0", ASN_OCTET_STR, "Linux test 5.4.0");
        session.add_test_data(".1.3.6.1.2.1.1.3.0", ASN_TIMETICKS, "123456");
        session.add_test_data(".1.3.6.1.2.1.1.5.0", ASN_OCTET_STR, "testhost");
        session.add_test_data(".1.3.6.1.2.1.2.1.0", ASN_INTEGER, "3");
        session.add_test_data(".1.3.6.1.2.1.2.2.1.1.1", ASN_INTEGER, "1");
        session.add_test_data(".1.3.6.1.2.1.2.2.1.1.2", ASN_INTEGER, "2");
        session.add_test_data(".1.3.6.1.2.1.2.2.1.1.3", ASN_INTEGER, "3");
        session
    }

    #[test]
    fn test_snmp_get() {
        let session = setup_session();
        let result = snmp_get(&session, ".1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(result.oid, ".1.3.6.1.2.1.1.1.0");
        assert_eq!(result.type_id, ASN_OCTET_STR);
        assert_eq!(result.value, "Linux test 5.4.0");
    }

    #[test]
    fn test_snmp_get_not_found() {
        let session = setup_session();
        let result = snmp_get(&session, ".1.3.6.1.2.1.99.0");
        assert!(result.is_err());
        assert!(matches!(result, Err(SnmpError::NoSuchObject(_))));
    }

    #[test]
    fn test_snmp_get_invalid_oid() {
        let session = setup_session();
        let result = snmp_get(&session, "invalid.oid.string");
        assert!(result.is_err());
        assert!(matches!(result, Err(SnmpError::InvalidOid(_))));
    }

    #[test]
    fn test_snmp_getnext() {
        let session = setup_session();
        let result = snmp_getnext(&session, ".1.3.6.1.2.1.1.1.0").unwrap();
        // Should return the next OID after .1.3.6.1.2.1.1.1.0
        assert!(result.oid.as_str() > ".1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_snmp_walk() {
        let session = setup_session();
        let results = snmp_walk(&session, ".1.3.6.1.2.1.2.2.1.1").unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].value, "1");
        assert_eq!(results[1].value, "2");
        assert_eq!(results[2].value, "3");
    }

    #[test]
    fn test_snmp_walk_empty() {
        let session = setup_session();
        let results = snmp_walk(&session, ".1.3.6.1.99").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_snmp_set() {
        let mut session = setup_session();
        assert!(snmp_set(
            &mut session,
            ".1.3.6.1.2.1.1.5.0",
            ASN_OCTET_STR,
            "newhost"
        ));
        let result = snmp_get(&session, ".1.3.6.1.2.1.1.5.0").unwrap();
        assert_eq!(result.value, "newhost");
    }

    #[test]
    fn test_snmp_session_versions() {
        let v1 = SnmpSession::new_v1("host", "public");
        assert_eq!(v1.version, SNMP_VERSION_1);

        let v2c = SnmpSession::new_v2c("host", "public");
        assert_eq!(v2c.version, SNMP_VERSION_2C);

        let v3 = SnmpSession::new_v3(
            "host", "user", "authPriv", "SHA", "authpass", "AES", "privpass",
        );
        assert_eq!(v3.version, SNMP_VERSION_3);
        assert_eq!(v3.security_name, "user");
        assert_eq!(v3.auth_protocol, "SHA");
    }

    #[test]
    fn test_snmp_quick_print() {
        // Reset state
        snmp_set_quick_print(false);
        assert!(!snmp_get_quick_print());

        snmp_set_quick_print(true);
        assert!(snmp_get_quick_print());

        // Reset back
        snmp_set_quick_print(false);
    }

    #[test]
    fn test_format_value_with_quick_print() {
        let val = SnmpValue {
            oid: ".1.3.6.1.2.1.1.1.0".to_string(),
            type_id: ASN_OCTET_STR,
            value: "test value".to_string(),
        };

        snmp_set_quick_print(false);
        assert_eq!(format_value(&val), "STRING: test value");

        snmp_set_quick_print(true);
        assert_eq!(format_value(&val), "test value");

        // Reset
        snmp_set_quick_print(false);
    }

    #[test]
    fn test_format_value_types() {
        snmp_set_quick_print(false);

        let int_val = SnmpValue {
            oid: ".1.0".to_string(),
            type_id: ASN_INTEGER,
            value: "42".to_string(),
        };
        assert_eq!(format_value(&int_val), "INTEGER: 42");

        let counter_val = SnmpValue {
            oid: ".1.0".to_string(),
            type_id: ASN_COUNTER,
            value: "1000".to_string(),
        };
        assert_eq!(format_value(&counter_val), "Counter32: 1000");

        let ticks_val = SnmpValue {
            oid: ".1.0".to_string(),
            type_id: ASN_TIMETICKS,
            value: "99999".to_string(),
        };
        assert_eq!(format_value(&ticks_val), "Timeticks: 99999");
    }

    #[test]
    fn test_validate_oid() {
        assert!(validate_oid(".1.3.6.1.2.1.1.1.0").is_ok());
        assert!(validate_oid("1.3.6.1").is_ok());
        assert!(validate_oid("").is_err());
        assert!(validate_oid("abc").is_err());
        assert!(validate_oid(".1.abc.3").is_err());
    }

    #[test]
    fn test_snmp_empty_host() {
        let session = SnmpSession::new_v1("", "public");
        let result = snmp_get(&session, ".1.3.6.1.2.1.1.1.0");
        assert!(result.is_err());
        assert!(matches!(result, Err(SnmpError::ConnectionError(_))));
    }

    #[test]
    fn test_snmpset_convenience() {
        assert!(snmpset(
            "localhost",
            "private",
            ".1.3.6.1.2.1.1.5.0",
            ASN_OCTET_STR,
            "newname"
        ));
    }

    #[test]
    fn test_snmp2_functions() {
        // v2c convenience functions create sessions with correct version
        let session = SnmpSession::new_v2c("localhost", "public");
        assert_eq!(session.version, SNMP_VERSION_2C);
        // snmp2_set should succeed for valid OID
        assert!(snmp2_set(
            "localhost",
            "private",
            ".1.3.6.1.2.1.1.5.0",
            ASN_OCTET_STR,
            "test"
        ));
    }

    #[test]
    fn test_snmp3_set() {
        assert!(snmp3_set(
            "localhost",
            "user",
            "authPriv",
            "SHA",
            "authpass",
            "AES",
            "privpass",
            ".1.3.6.1.2.1.1.5.0",
            ASN_OCTET_STR,
            "test"
        ));
    }
}
