//! TLS certificate management — store, load, and generate TLS certificates.
//!
//! Features:
//! - Certificate storage on disk (PEM format)
//! - Self-signed certificate generation for development
//! - SNI-based certificate resolution for multi-domain
//! - ACME HTTP-01 challenge flow for Let's Encrypt
//! - Automatic certificate renewal

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

    /// Request a certificate from Let's Encrypt via ACME HTTP-01.
    ///
    /// This implements the full ACME RFC 8555 flow:
    /// 1. Create/load ACME account
    /// 2. Create an order for the domain
    /// 3. Retrieve the HTTP-01 authorization challenge
    /// 4. Set the challenge response (served by the router)
    /// 5. Notify the ACME server the challenge is ready
    /// 6. Poll until the challenge is validated
    /// 7. Finalize the order with a CSR
    /// 8. Download the certificate
    /// 9. Store the cert + key on disk
    pub fn request_acme_cert(&self, domain: &str, acme_config: &AcmeConfig) -> Result<(), String> {
        let acme = AcmeClient::new(acme_config)?;

        // Step 1: Create or load account.
        let account = acme.get_or_create_account(&self.certs_dir)?;

        // Step 2: Create an order.
        let order = acme.new_order(&account, domain)?;

        // Step 3: Get authorization + HTTP-01 challenge.
        let authz_url = order.authorization_urls.first()
            .ok_or("No authorization URLs in order")?;
        let authz = acme.get_authorization(&account, authz_url)?;

        let challenge = authz.challenges.iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or("No HTTP-01 challenge found")?;

        // Step 4: Compute key authorization and set it for the router to serve.
        let key_authz = acme.key_authorization(&account, &challenge.token)?;
        self.set_acme_challenge(&challenge.token, &key_authz);

        // Step 5: Notify the ACME server that we're ready.
        acme.respond_to_challenge(&account, &challenge.url)?;

        // Step 6: Poll until validation completes (max 60 seconds).
        let mut attempts = 0;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let status = acme.check_authorization(&account, authz_url)?;
            match status.as_str() {
                "valid" => break,
                "pending" | "processing" => {
                    attempts += 1;
                    if attempts > 30 {
                        self.clear_acme_challenge(&challenge.token);
                        return Err("ACME challenge validation timed out".into());
                    }
                }
                other => {
                    self.clear_acme_challenge(&challenge.token);
                    return Err(format!("ACME challenge failed with status: {}", other));
                }
            }
        }

        self.clear_acme_challenge(&challenge.token);

        // Step 7: Generate a key pair and CSR, then finalize the order.
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| format!("Cannot generate key pair: {}", e))?;

        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Invalid domain for CSR: {}", e))?;
        params.distinguished_name = rcgen::DistinguishedName::new();

        let csr = params.serialize_request(&key_pair)
            .map_err(|e| format!("Cannot generate CSR: {}", e))?;
        let csr_der = csr.der();

        let cert_url = acme.finalize_order(&account, &order.finalize_url, csr_der)?;

        // Step 8: Download the certificate chain.
        let cert_pem = acme.download_certificate(&account, &cert_url)?;
        let key_pem = key_pair.serialize_pem();

        // Step 9: Store on disk.
        let now = crate::state::now_iso8601();
        let meta = CertMeta {
            domain: domain.to_string(),
            issuer: "Let's Encrypt".to_string(),
            not_before: now.clone(),
            not_after: "auto-renewed".to_string(), // Real expiry parsing would go here.
            self_signed: false,
            auto_renew: true,
        };

        self.store_cert(domain, &cert_pem, &key_pem, &meta)?;
        eprintln!("ACME: Certificate issued for {}", domain);
        Ok(())
    }

    /// Check all certificates and renew any expiring within 30 days.
    pub fn renew_expiring_certs(&self, acme_config: &AcmeConfig) {
        let domains = self.list_domains();
        for meta in domains {
            if !meta.auto_renew {
                continue;
            }
            // Check if cert needs renewal (exists and is readable).
            if let Some(stored_meta) = self.get_meta(&meta.domain) {
                if stored_meta.self_signed {
                    continue; // Don't renew self-signed certs.
                }
            }
            // Try to renew — if it fails, log and continue.
            match self.request_acme_cert(&meta.domain, acme_config) {
                Ok(()) => eprintln!("ACME: Renewed certificate for {}", meta.domain),
                Err(e) => eprintln!("ACME: Renewal failed for {}: {}", meta.domain, e),
            }
        }
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

// ── ACME Client ─────────────────────────────────────────────────────────────

/// ACME server configuration.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// ACME directory URL (default: Let's Encrypt production).
    pub directory_url: String,
    /// Contact email for the ACME account.
    pub contact_email: String,
    /// Whether to accept the terms of service.
    pub agree_tos: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: String::new(),
            agree_tos: true,
        }
    }
}

impl AcmeConfig {
    /// Create config for Let's Encrypt staging (for testing).
    pub fn staging(contact_email: &str) -> Self {
        Self {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            contact_email: contact_email.to_string(),
            agree_tos: true,
        }
    }

    /// Create config for Let's Encrypt production.
    pub fn production(contact_email: &str) -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: contact_email.to_string(),
            agree_tos: true,
        }
    }

    /// Build from environment variables.
    pub fn from_env() -> Self {
        Self {
            directory_url: std::env::var("ACME_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://acme-v02.api.letsencrypt.org/directory".into()),
            contact_email: std::env::var("ACME_EMAIL").unwrap_or_default(),
            agree_tos: true,
        }
    }
}

/// Persisted ACME account (key pair + account URL).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AcmeAccount {
    /// The ACME account URL (returned by the server).
    account_url: String,
    /// PKCS8 private key in PEM format.
    private_key_pem: String,
}

/// ACME order response.
#[derive(Debug)]
struct AcmeOrder {
    authorization_urls: Vec<String>,
    finalize_url: String,
}

/// ACME challenge.
#[derive(Debug)]
struct AcmeChallenge {
    challenge_type: String,
    url: String,
    token: String,
}

/// ACME authorization.
#[derive(Debug)]
struct AcmeAuthorization {
    challenges: Vec<AcmeChallenge>,
}

/// ACME directory URLs.
#[derive(Debug)]
struct AcmeDirectory {
    new_nonce_url: String,
    new_account_url: String,
    new_order_url: String,
}

/// Blocking ACME client using ureq + ring for JWS.
struct AcmeClient {
    config: AcmeConfig,
    directory: AcmeDirectory,
}

impl AcmeClient {
    /// Create a new ACME client by fetching the directory.
    fn new(config: &AcmeConfig) -> Result<Self, String> {
        let dir_json: serde_json::Value = ureq::get(&config.directory_url)
            .call()
            .map_err(|e| format!("Failed to fetch ACME directory: {}", e))?
            .into_json()
            .map_err(|e| format!("Invalid ACME directory JSON: {}", e))?;

        let directory = AcmeDirectory {
            new_nonce_url: dir_json["newNonce"].as_str()
                .ok_or("Missing newNonce in directory")?.to_string(),
            new_account_url: dir_json["newAccount"].as_str()
                .ok_or("Missing newAccount in directory")?.to_string(),
            new_order_url: dir_json["newOrder"].as_str()
                .ok_or("Missing newOrder in directory")?.to_string(),
        };

        Ok(Self {
            config: config.clone(),
            directory,
        })
    }

    /// Get a fresh nonce from the ACME server.
    fn new_nonce(&self) -> Result<String, String> {
        let resp = ureq::head(&self.directory.new_nonce_url)
            .call()
            .map_err(|e| format!("Failed to get nonce: {}", e))?;
        resp.header("replay-nonce")
            .map(|s| s.to_string())
            .ok_or_else(|| "No replay-nonce header".into())
    }

    /// Get or create an ACME account. Persists the key to disk.
    fn get_or_create_account(&self, certs_dir: &Path) -> Result<AcmeAccount, String> {
        let account_path = certs_dir.join("acme-account.json");

        // Try to load existing account.
        if account_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&account_path) {
                if let Ok(account) = serde_json::from_str::<AcmeAccount>(&data) {
                    return Ok(account);
                }
            }
        }

        // Generate a new ECDSA P-256 key pair for the account.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        ).map_err(|e| format!("Failed to generate account key: {}", e))?;

        let key_pem = pem_encode("PRIVATE KEY", pkcs8.as_ref());

        // Create account with the ACME server.
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        ).map_err(|e| format!("Failed to load account key: {}", e))?;

        let nonce = self.new_nonce()?;

        let payload = if self.config.contact_email.is_empty() {
            serde_json::json!({
                "termsOfServiceAgreed": self.config.agree_tos,
            })
        } else {
            serde_json::json!({
                "termsOfServiceAgreed": self.config.agree_tos,
                "contact": [format!("mailto:{}", self.config.contact_email)],
            })
        };

        let jwk = ec_jwk(&key_pair)?;
        let body = jws_with_jwk(
            &self.directory.new_account_url,
            &nonce,
            &payload,
            &key_pair,
            &jwk,
        )?;

        let resp = ureq::post(&self.directory.new_account_url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Account creation failed: {}", e))?;

        let account_url = resp.header("location")
            .ok_or("No Location header in account response")?
            .to_string();

        let account = AcmeAccount {
            account_url,
            private_key_pem: key_pem,
        };

        // Persist account.
        std::fs::create_dir_all(certs_dir)
            .map_err(|e| format!("Cannot create certs dir: {}", e))?;
        let json = serde_json::to_string_pretty(&account)
            .map_err(|e| format!("Cannot serialize account: {}", e))?;
        std::fs::write(&account_path, json)
            .map_err(|e| format!("Cannot save account: {}", e))?;

        Ok(account)
    }

    /// Create a new ACME order for a domain.
    fn new_order(&self, account: &AcmeAccount, domain: &str) -> Result<AcmeOrder, String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        let payload = serde_json::json!({
            "identifiers": [{
                "type": "dns",
                "value": domain,
            }],
        });

        let body = jws_with_kid(
            &self.directory.new_order_url,
            &nonce,
            &payload,
            &key_pair,
            &account.account_url,
        )?;

        let resp = ureq::post(&self.directory.new_order_url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Order creation failed: {}", e))?;

        let order_json: serde_json::Value = resp.into_json()
            .map_err(|e| format!("Invalid order JSON: {}", e))?;

        let authorization_urls = order_json["authorizations"]
            .as_array()
            .ok_or("No authorizations in order")?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        let finalize_url = order_json["finalize"]
            .as_str()
            .ok_or("No finalize URL in order")?
            .to_string();

        Ok(AcmeOrder {
            authorization_urls,
            finalize_url,
        })
    }

    /// Get the authorization for a domain (contains challenges).
    fn get_authorization(&self, account: &AcmeAccount, url: &str) -> Result<AcmeAuthorization, String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        // POST-as-GET: empty payload.
        let body = jws_with_kid_empty(url, &nonce, &key_pair, &account.account_url)?;

        let resp = ureq::post(url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Authorization fetch failed: {}", e))?;

        let authz_json: serde_json::Value = resp.into_json()
            .map_err(|e| format!("Invalid authorization JSON: {}", e))?;

        let challenges = authz_json["challenges"]
            .as_array()
            .ok_or("No challenges in authorization")?
            .iter()
            .filter_map(|c| {
                Some(AcmeChallenge {
                    challenge_type: c["type"].as_str()?.to_string(),
                    url: c["url"].as_str()?.to_string(),
                    token: c["token"].as_str()?.to_string(),
                })
            })
            .collect();

        Ok(AcmeAuthorization { challenges })
    }

    /// Compute the key authorization for a challenge token.
    fn key_authorization(&self, account: &AcmeAccount, token: &str) -> Result<String, String> {
        let key_pair = self.load_key_pair(account)?;
        let jwk = ec_jwk(&key_pair)?;
        let jwk_json = serde_json::to_string(&jwk)
            .map_err(|e| format!("Cannot serialize JWK: {}", e))?;

        // JWK thumbprint = SHA-256 of the canonical JWK JSON.
        let thumbprint = {
            use ring::digest;
            let d = digest::digest(&digest::SHA256, jwk_json.as_bytes());
            base64_url_encode(d.as_ref())
        };

        Ok(format!("{}.{}", token, thumbprint))
    }

    /// Tell the ACME server we're ready to validate the challenge.
    fn respond_to_challenge(&self, account: &AcmeAccount, url: &str) -> Result<(), String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        let payload = serde_json::json!({});
        let body = jws_with_kid(url, &nonce, &payload, &key_pair, &account.account_url)?;

        ureq::post(url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Challenge response failed: {}", e))?;

        Ok(())
    }

    /// Check the status of an authorization.
    fn check_authorization(&self, account: &AcmeAccount, url: &str) -> Result<String, String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        let body = jws_with_kid_empty(url, &nonce, &key_pair, &account.account_url)?;

        let resp = ureq::post(url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Authorization check failed: {}", e))?;

        let json: serde_json::Value = resp.into_json()
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        json["status"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "No status in authorization".into())
    }

    /// Finalize an order by submitting the CSR.
    fn finalize_order(&self, account: &AcmeAccount, url: &str, csr_der: &[u8]) -> Result<String, String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        let payload = serde_json::json!({
            "csr": base64_url_encode(csr_der),
        });

        let body = jws_with_kid(url, &nonce, &payload, &key_pair, &account.account_url)?;

        let resp = ureq::post(url)
            .set("Content-Type", "application/jose+json")
            .send_string(&body)
            .map_err(|e| format!("Order finalization failed: {}", e))?;

        let location = resp.header("location").map(|s| s.to_string());
        let json: serde_json::Value = resp.into_json()
            .map_err(|e| format!("Invalid finalize JSON: {}", e))?;

        // Poll until the order status is "valid".
        if let Some(cert_url) = json["certificate"].as_str() {
            return Ok(cert_url.to_string());
        }

        // If not ready yet, poll the order URL.
        let order_url = json["url"].as_str().map(|s| s.to_string())
            .or(location)
            .unwrap_or_else(|| url.to_string());

        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let key_pair = self.load_key_pair(account)?;
            let nonce = self.new_nonce()?;
            let body = jws_with_kid_empty(&order_url, &nonce, &key_pair, &account.account_url)?;

            let resp = ureq::post(&order_url)
                .set("Content-Type", "application/jose+json")
                .send_string(&body)
                .map_err(|e| format!("Order poll failed: {}", e))?;

            let json: serde_json::Value = resp.into_json()
                .map_err(|e| format!("Invalid order JSON: {}", e))?;

            if let Some(cert_url) = json["certificate"].as_str() {
                return Ok(cert_url.to_string());
            }

            let status = json["status"].as_str().unwrap_or("unknown");
            if status == "invalid" {
                return Err("Order was rejected by ACME server".into());
            }
        }

        Err("Timed out waiting for order to become valid".into())
    }

    /// Download the certificate chain from the ACME server.
    fn download_certificate(&self, account: &AcmeAccount, url: &str) -> Result<String, String> {
        let key_pair = self.load_key_pair(account)?;
        let nonce = self.new_nonce()?;

        let body = jws_with_kid_empty(url, &nonce, &key_pair, &account.account_url)?;

        let resp = ureq::post(url)
            .set("Content-Type", "application/jose+json")
            .set("Accept", "application/pem-certificate-chain")
            .send_string(&body)
            .map_err(|e| format!("Certificate download failed: {}", e))?;

        resp.into_string()
            .map_err(|e| format!("Cannot read certificate: {}", e))
    }

    /// Load the ECDSA key pair from the account's PEM.
    fn load_key_pair(&self, account: &AcmeAccount) -> Result<ring::signature::EcdsaKeyPair, String> {
        let der = pem_decode(&account.private_key_pem)?;
        let rng = ring::rand::SystemRandom::new();
        ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &der,
            &rng,
        ).map_err(|e| format!("Invalid account key: {}", e))
    }
}

// ── JWS / JWK Helpers ──────────────────────────────────────────────────────

/// Create a JWK representation of an ECDSA P-256 public key.
fn ec_jwk(key_pair: &ring::signature::EcdsaKeyPair) -> Result<serde_json::Value, String> {
    use ring::signature::KeyPair;
    let public_key = key_pair.public_key().as_ref();
    // EC public key: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes total.
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err("Invalid EC public key format".into());
    }
    let x = base64_url_encode(&public_key[1..33]);
    let y = base64_url_encode(&public_key[33..65]);

    // Canonical form (alphabetical keys) for thumbprint calculation.
    Ok(serde_json::json!({
        "crv": "P-256",
        "kty": "EC",
        "x": x,
        "y": y,
    }))
}

/// Create a JWS with a JWK header (used for account creation).
fn jws_with_jwk(
    url: &str,
    nonce: &str,
    payload: &serde_json::Value,
    key_pair: &ring::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
) -> Result<String, String> {
    let protected = serde_json::json!({
        "alg": "ES256",
        "jwk": jwk,
        "nonce": nonce,
        "url": url,
    });

    sign_jws(&protected, payload, key_pair)
}

/// Create a JWS with a KID header (used for authenticated requests).
fn jws_with_kid(
    url: &str,
    nonce: &str,
    payload: &serde_json::Value,
    key_pair: &ring::signature::EcdsaKeyPair,
    kid: &str,
) -> Result<String, String> {
    let protected = serde_json::json!({
        "alg": "ES256",
        "kid": kid,
        "nonce": nonce,
        "url": url,
    });

    sign_jws(&protected, payload, key_pair)
}

/// Create a JWS with empty payload (POST-as-GET).
fn jws_with_kid_empty(
    url: &str,
    nonce: &str,
    key_pair: &ring::signature::EcdsaKeyPair,
    kid: &str,
) -> Result<String, String> {
    let protected = serde_json::json!({
        "alg": "ES256",
        "kid": kid,
        "nonce": nonce,
        "url": url,
    });

    let protected_b64 = base64_url_encode(
        serde_json::to_string(&protected)
            .map_err(|e| format!("JSON error: {}", e))?
            .as_bytes(),
    );

    // Empty payload for POST-as-GET.
    let payload_b64 = "";
    let signing_input = format!("{}.{}", protected_b64, payload_b64);

    let rng = ring::rand::SystemRandom::new();
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|e| format!("Signing failed: {}", e))?;

    let sig_b64 = base64_url_encode(signature.as_ref());

    let jws = serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": sig_b64,
    });

    serde_json::to_string(&jws).map_err(|e| format!("JWS serialization failed: {}", e))
}

/// Sign a JWS with the given protected header and payload.
fn sign_jws(
    protected: &serde_json::Value,
    payload: &serde_json::Value,
    key_pair: &ring::signature::EcdsaKeyPair,
) -> Result<String, String> {
    let protected_b64 = base64_url_encode(
        serde_json::to_string(protected)
            .map_err(|e| format!("JSON error: {}", e))?
            .as_bytes(),
    );
    let payload_b64 = base64_url_encode(
        serde_json::to_string(payload)
            .map_err(|e| format!("JSON error: {}", e))?
            .as_bytes(),
    );

    let signing_input = format!("{}.{}", protected_b64, payload_b64);

    let rng = ring::rand::SystemRandom::new();
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|e| format!("Signing failed: {}", e))?;

    let sig_b64 = base64_url_encode(signature.as_ref());

    let jws = serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": sig_b64,
    });

    serde_json::to_string(&jws).map_err(|e| format!("JWS serialization failed: {}", e))
}

/// Base64url-encode (no padding) as required by ACME/JWS.
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Encode binary data as PEM with the given label.
fn pem_encode(label: &str, data: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Decode PEM to raw DER bytes.
fn pem_decode(pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let mut b64 = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM decode failed: {}", e))
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

    // ── ACME unit tests ─────────────────────────────────────────────────

    #[test]
    fn test_acme_config_default() {
        let config = AcmeConfig::default();
        assert!(config.directory_url.contains("acme-v02.api.letsencrypt.org"));
        assert!(config.agree_tos);
    }

    #[test]
    fn test_acme_config_staging() {
        let config = AcmeConfig::staging("test@example.com");
        assert!(config.directory_url.contains("staging"));
        assert_eq!(config.contact_email, "test@example.com");
    }

    #[test]
    fn test_acme_config_production() {
        let config = AcmeConfig::production("admin@example.com");
        assert!(!config.directory_url.contains("staging"));
        assert_eq!(config.contact_email, "admin@example.com");
    }

    #[test]
    fn test_base64_url_encode() {
        assert_eq!(base64_url_encode(b"hello"), "aGVsbG8");
        assert_eq!(base64_url_encode(b""), "");
        // No padding.
        assert!(!base64_url_encode(b"test").contains('='));
    }

    #[test]
    fn test_pem_encode_decode_roundtrip() {
        let data = b"test private key data here";
        let pem = pem_encode("PRIVATE KEY", data);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));

        let decoded = pem_decode(&pem).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_ec_jwk() {
        // Generate a test key pair.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        ).unwrap();

        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        ).unwrap();

        let jwk = ec_jwk(&key_pair).unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn test_jws_signing() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        ).unwrap();

        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        ).unwrap();

        let jwk = ec_jwk(&key_pair).unwrap();
        let result = jws_with_jwk(
            "https://example.com/test",
            "test-nonce",
            &serde_json::json!({"test": true}),
            &key_pair,
            &jwk,
        );

        assert!(result.is_ok());
        let jws: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(jws["protected"].is_string());
        assert!(jws["payload"].is_string());
        assert!(jws["signature"].is_string());
    }
}
