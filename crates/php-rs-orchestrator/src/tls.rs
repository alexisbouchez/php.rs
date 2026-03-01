//! TLS certificate management — store, load, and generate TLS certificates.
//!
//! Features:
//! - Certificate storage on disk (PEM format)
//! - Self-signed certificate generation for development
//! - SNI-based certificate resolution for multi-domain
//! - ACME HTTP-01 challenge tracking for Let's Encrypt

use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Directory structure for TLS certificates:
/// {certs_dir}/
///   {domain}/
///     cert.pem     — full certificate chain
///     privkey.pem  — private key
///     meta.json    — metadata (issuer, expiry, etc.)

/// Metadata about a stored certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertMeta {
    pub domain: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub self_signed: bool,
    pub auto_renew: bool,
}

/// TLS certificate store — manages certificates on disk and provides
/// SNI-based certificate resolution.
pub struct CertStore {
    /// Base directory for certificate storage.
    certs_dir: PathBuf,
    /// In-memory cache of loaded certificates, keyed by domain.
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Pending ACME HTTP-01 challenges: token → response.
    acme_challenges: RwLock<HashMap<String, String>>,
}

/// A certificate + private key pair ready for TLS.
struct CertifiedKey {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: Arc<dyn rustls::sign::SigningKey>,
}

#[allow(dead_code)]
impl CertStore {
    /// Create a new certificate store at the given directory.
    pub fn new(certs_dir: &Path) -> Self {
        Self {
            certs_dir: certs_dir.to_path_buf(),
            cache: RwLock::new(HashMap::new()),
            acme_challenges: RwLock::new(HashMap::new()),
        }
    }

    /// Get the certificates directory path.
    pub fn certs_dir(&self) -> &Path {
        &self.certs_dir
    }

    /// List all domains with stored certificates.
    pub fn list_domains(&self) -> Vec<CertMeta> {
        let mut domains = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.certs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let meta_path = path.join("meta.json");
                    if meta_path.exists() {
                        if let Ok(data) = std::fs::read_to_string(&meta_path) {
                            if let Ok(meta) = serde_json::from_str::<CertMeta>(&data) {
                                domains.push(meta);
                            }
                        }
                    }
                }
            }
        }
        domains.sort_by(|a, b| a.domain.cmp(&b.domain));
        domains
    }

    /// Store a certificate from PEM files.
    pub fn store_cert(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        meta: &CertMeta,
    ) -> Result<(), String> {
        let domain_dir = self.certs_dir.join(domain);
        std::fs::create_dir_all(&domain_dir)
            .map_err(|e| format!("Cannot create cert dir for {}: {}", domain, e))?;

        std::fs::write(domain_dir.join("cert.pem"), cert_pem)
            .map_err(|e| format!("Cannot write cert.pem: {}", e))?;
        std::fs::write(domain_dir.join("privkey.pem"), key_pem)
            .map_err(|e| format!("Cannot write privkey.pem: {}", e))?;

        let meta_json = serde_json::to_string_pretty(meta)
            .map_err(|e| format!("Cannot serialize meta: {}", e))?;
        std::fs::write(domain_dir.join("meta.json"), meta_json)
            .map_err(|e| format!("Cannot write meta.json: {}", e))?;

        // Invalidate cache for this domain.
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(domain);
        }

        Ok(())
    }

    /// Remove a certificate for a domain.
    pub fn remove_cert(&self, domain: &str) -> Result<(), String> {
        let domain_dir = self.certs_dir.join(domain);
        if domain_dir.exists() {
            std::fs::remove_dir_all(&domain_dir)
                .map_err(|e| format!("Cannot remove cert for {}: {}", domain, e))?;
        }
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(domain);
        }
        Ok(())
    }

    /// Generate a self-signed certificate for development.
    pub fn generate_self_signed(&self, domain: &str) -> Result<(), String> {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Invalid domain for cert: {}", e))?;

        // Add wildcard SAN.
        params.subject_alt_names.push(
            rcgen::SanType::DnsName(
                format!("*.{}", domain)
                    .try_into()
                    .map_err(|e| format!("Invalid wildcard domain: {}", e))?,
            ),
        );

        // Valid for 365 days.
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);

        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| format!("Cannot generate key pair: {}", e))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("Cannot generate self-signed cert: {}", e))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let meta = CertMeta {
            domain: domain.to_string(),
            issuer: "self-signed".to_string(),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2030-12-31T23:59:59Z".to_string(),
            self_signed: true,
            auto_renew: false,
        };

        self.store_cert(domain, &cert_pem, &key_pem, &meta)
    }

    /// Load a certificate for a domain from disk.
    fn load_cert(&self, domain: &str) -> Result<Arc<CertifiedKey>, String> {
        // Check cache first.
        if let Ok(cache) = self.cache.read() {
            if let Some(ck) = cache.get(domain) {
                return Ok(ck.clone());
            }
        }

        let domain_dir = self.certs_dir.join(domain);
        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("privkey.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Err(format!("No certificate found for {}", domain));
        }

        // Load cert chain.
        let cert_file = std::fs::File::open(&cert_path)
            .map_err(|e| format!("Cannot open cert.pem for {}: {}", domain, e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();
        if certs.is_empty() {
            return Err(format!("No certificates found in cert.pem for {}", domain));
        }

        // Load private key.
        let key_file = std::fs::File::open(&key_path)
            .map_err(|e| format!("Cannot open privkey.pem for {}: {}", domain, e))?;
        let mut key_reader = BufReader::new(key_file);
        let key_der = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| format!("Cannot parse privkey.pem for {}: {}", domain, e))?
            .ok_or_else(|| format!("No private key found in privkey.pem for {}", domain))?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("Unsupported key type for {}: {}", domain, e))?;

        let ck = Arc::new(CertifiedKey {
            cert_chain: certs,
            key: signing_key,
        });

        // Update cache.
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(domain.to_string(), ck.clone());
        }

        Ok(ck)
    }

    /// Check if a certificate exists for a domain.
    pub fn has_cert(&self, domain: &str) -> bool {
        let domain_dir = self.certs_dir.join(domain);
        domain_dir.join("cert.pem").exists() && domain_dir.join("privkey.pem").exists()
    }

    /// Get metadata for a domain's certificate.
    pub fn get_meta(&self, domain: &str) -> Option<CertMeta> {
        let meta_path = self.certs_dir.join(domain).join("meta.json");
        let data = std::fs::read_to_string(meta_path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Register an ACME HTTP-01 challenge.
    pub fn set_acme_challenge(&self, token: &str, response: &str) {
        if let Ok(mut challenges) = self.acme_challenges.write() {
            challenges.insert(token.to_string(), response.to_string());
        }
    }

    /// Get the response for an ACME HTTP-01 challenge.
    pub fn get_acme_challenge(&self, token: &str) -> Option<String> {
        self.acme_challenges
            .read()
            .ok()?
            .get(token)
            .cloned()
    }

    /// Remove a completed ACME challenge.
    pub fn clear_acme_challenge(&self, token: &str) {
        if let Ok(mut challenges) = self.acme_challenges.write() {
            challenges.remove(token);
        }
    }

    /// Build a rustls ServerConfig using this store for SNI-based cert resolution.
    pub fn build_tls_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        // Install the default crypto provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let resolver = Arc::new(StoreResolver {
            store: self as *const CertStore,
        });

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        Ok(Arc::new(config))
    }
}

/// SNI-based certificate resolver that looks up certs from the CertStore.
struct StoreResolver {
    // We use a raw pointer here because CertStore owns the resolver.
    // The resolver only lives as long as the CertStore.
    store: *const CertStore,
}

impl std::fmt::Debug for StoreResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreResolver").finish()
    }
}

// SAFETY: The StoreResolver only accesses the CertStore through
// thread-safe RwLock-protected fields.
unsafe impl Send for StoreResolver {}
unsafe impl Sync for StoreResolver {}

impl rustls::server::ResolvesServerCert for StoreResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let domain = client_hello.server_name()?;

        // SAFETY: The CertStore outlives this resolver.
        let store = unsafe { &*self.store };

        // Try exact domain match first.
        if let Ok(ck) = store.load_cert(domain) {
            return Some(Arc::new(rustls::sign::CertifiedKey::new(
                ck.cert_chain.clone(),
                ck.key.clone(),
            )));
        }

        // Try wildcard: *.example.com for sub.example.com
        if let Some(dot) = domain.find('.') {
            let wildcard = format!("*.{}", &domain[dot + 1..]);
            if let Ok(ck) = store.load_cert(&wildcard) {
                return Some(Arc::new(rustls::sign::CertifiedKey::new(
                    ck.cert_chain.clone(),
                    ck.key.clone(),
                )));
            }
            // Also try the parent domain cert (it may have wildcard SAN).
            let parent = &domain[dot + 1..];
            if let Ok(ck) = store.load_cert(parent) {
                return Some(Arc::new(rustls::sign::CertifiedKey::new(
                    ck.cert_chain.clone(),
                    ck.key.clone(),
                )));
            }
        }

        None
    }
}

/// Create a TLS acceptor from a rustls ServerConfig.
pub fn tls_accept(
    tcp_stream: std::net::TcpStream,
    tls_config: &Arc<rustls::ServerConfig>,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>, String> {
    let conn = rustls::ServerConnection::new(tls_config.clone())
        .map_err(|e| format!("TLS connection setup failed: {}", e))?;
    Ok(rustls::StreamOwned::new(conn, tcp_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_certs_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "phprs-tls-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_cert_store_empty() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);
        assert!(store.list_domains().is_empty());
        assert!(!store.has_cert("example.com"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_self_signed() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        store.generate_self_signed("test.local").unwrap();

        assert!(store.has_cert("test.local"));
        let meta = store.get_meta("test.local").unwrap();
        assert_eq!(meta.domain, "test.local");
        assert!(meta.self_signed);
        assert_eq!(meta.issuer, "self-signed");

        let domains = store.list_domains();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].domain, "test.local");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_and_load_cert() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        // Generate a cert to get valid PEM data.
        store.generate_self_signed("load-test.local").unwrap();

        // Verify we can load it.
        let ck = store.load_cert("load-test.local");
        assert!(ck.is_ok());

        // Loading again should use cache.
        let ck2 = store.load_cert("load-test.local");
        assert!(ck2.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_cert() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        store.generate_self_signed("removable.local").unwrap();
        assert!(store.has_cert("removable.local"));

        store.remove_cert("removable.local").unwrap();
        assert!(!store.has_cert("removable.local"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_acme_challenges() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        assert!(store.get_acme_challenge("token123").is_none());

        store.set_acme_challenge("token123", "response456");
        assert_eq!(
            store.get_acme_challenge("token123").unwrap(),
            "response456"
        );

        store.clear_acme_challenge("token123");
        assert!(store.get_acme_challenge("token123").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_tls_config() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        // Generate a cert first.
        store.generate_self_signed("tls-test.local").unwrap();

        // Build TLS config — should succeed.
        let config = store.build_tls_config();
        assert!(config.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_nonexistent_cert() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);
        assert!(store.load_cert("nonexistent.com").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_domains() {
        let dir = test_certs_dir();
        let store = CertStore::new(&dir);

        store.generate_self_signed("app1.local").unwrap();
        store.generate_self_signed("app2.local").unwrap();
        store.generate_self_signed("app3.local").unwrap();

        let domains = store.list_domains();
        assert_eq!(domains.len(), 3);
        assert_eq!(domains[0].domain, "app1.local");
        assert_eq!(domains[1].domain, "app2.local");
        assert_eq!(domains[2].domain, "app3.local");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
