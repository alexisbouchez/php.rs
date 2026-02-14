use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::repository::{PackageSearchResult, Repository};
use crate::package::Package;
use crate::semver::MultiConstraint;

/// Repository backed by a Composer v2 API (like Packagist).
pub struct ComposerRepository {
    url: String,
    packages_cache: std::sync::RwLock<HashMap<String, Vec<Package>>>,
    cache_dir: Option<PathBuf>,
}

impl ComposerRepository {
    pub fn new(url: &str) -> Self {
        ComposerRepository {
            url: url.trim_end_matches('/').to_string(),
            packages_cache: std::sync::RwLock::new(HashMap::new()),
            cache_dir: None,
        }
    }

    /// Default Packagist repository.
    pub fn packagist() -> Self {
        Self::new("https://repo.packagist.org")
    }

    /// Set the local cache directory for metadata caching.
    pub fn with_cache_dir(mut self, dir: &Path) -> Self {
        self.cache_dir = Some(dir.to_path_buf());
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetch package metadata from the Composer v2 API.
    /// Uses the lazy provider URL: {url}/p2/{package}.json
    pub fn fetch_package_metadata(&self, name: &str) -> Result<Vec<Package>, String> {
        // Check in-memory cache
        if let Ok(cache) = self.packages_cache.read() {
            if let Some(packages) = cache.get(name) {
                return Ok(packages.clone());
            }
        }

        // Check on-disk cache
        if let Some(cached) = self.read_disk_cache(name) {
            if let Ok(mut cache) = self.packages_cache.write() {
                cache.insert(name.to_string(), cached.clone());
            }
            return Ok(cached);
        }

        // Fetch from v2 API (synchronous wrapper)
        let url = format!("{}/p2/{}.json", self.url, name);
        let packages = self.fetch_v2_metadata(&url, name)?;

        // Write to disk cache
        self.write_disk_cache(name, &packages);

        // Update in-memory cache
        if let Ok(mut cache) = self.packages_cache.write() {
            cache.insert(name.to_string(), packages.clone());
        }

        Ok(packages)
    }

    /// Fetch metadata from the v2 API endpoint.
    fn fetch_v2_metadata(&self, url: &str, name: &str) -> Result<Vec<Package>, String> {
        // Use a blocking HTTP client since Repository trait is sync
        let response = reqwest::blocking::Client::new()
            .get(url)
            .header("User-Agent", "php-rs-composer/0.1.0")
            .send()
            .map_err(|e| format!("Failed to fetch {}: {}", url, e))?;

        if !response.status().is_success() {
            return Err(format!("HTTP {} when fetching {}", response.status(), url));
        }

        let json: serde_json::Value = response
            .json()
            .map_err(|e| format!("Failed to parse JSON from {}: {}", url, e))?;

        // v2 format: { "packages": { "vendor/name": [ { version objects } ] } }
        let packages_json = json
            .get("packages")
            .and_then(|p| p.get(name))
            .and_then(|v| v.as_array());

        match packages_json {
            Some(versions) => {
                let mut packages = Vec::new();
                for ver in versions {
                    match serde_json::from_value::<Package>(ver.clone()) {
                        Ok(pkg) => packages.push(pkg),
                        Err(_) => continue, // Skip unparseable versions
                    }
                }
                Ok(packages)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Read cached package metadata from disk.
    fn read_disk_cache(&self, name: &str) -> Option<Vec<Package>> {
        let cache_dir = self.cache_dir.as_ref()?;
        let cache_file = cache_dir
            .join("repo")
            .join(Self::cache_key(&self.url))
            .join(format!("{}.json", name.replace('/', "~")));

        if !cache_file.exists() {
            return None;
        }

        // Check TTL (1 hour)
        if let Ok(meta) = cache_file.metadata() {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    if elapsed.as_secs() > 3600 {
                        return None; // Expired
                    }
                }
            }
        }

        let content = std::fs::read_to_string(&cache_file).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Write package metadata to disk cache.
    fn write_disk_cache(&self, name: &str, packages: &[Package]) {
        let Some(cache_dir) = &self.cache_dir else {
            return;
        };

        let cache_path = cache_dir.join("repo").join(Self::cache_key(&self.url));

        if std::fs::create_dir_all(&cache_path).is_err() {
            return;
        }

        let cache_file = cache_path.join(format!("{}.json", name.replace('/', "~")));
        if let Ok(json) = serde_json::to_string(packages) {
            let _ = std::fs::write(cache_file, json);
        }
    }

    fn cache_key(url: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Search packages via the Packagist search API.
    pub fn search_api(&self, query: &str) -> Result<Vec<PackageSearchResult>, String> {
        let url = format!("{}/search.json?q={}", self.url, urlencoded(query));

        let response = reqwest::blocking::Client::new()
            .get(&url)
            .header("User-Agent", "php-rs-composer/0.1.0")
            .send()
            .map_err(|e| format!("Failed to search: {}", e))?;

        let json: serde_json::Value = response
            .json()
            .map_err(|e| format!("Failed to parse search results: {}", e))?;

        let results = json
            .get("results")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let name = item.get("name")?.as_str()?.to_string();
                        let description = item
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(|s| s.to_string());
                        Some(PackageSearchResult { name, description })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(results)
    }
}

fn urlencoded(s: &str) -> String {
    s.replace(' ', "+").replace('&', "%26").replace('=', "%3D")
}

impl Repository for ComposerRepository {
    fn name(&self) -> &str {
        "composer"
    }

    fn find_packages(&self, name: &str, _constraint: Option<&MultiConstraint>) -> Vec<Package> {
        match self.fetch_package_metadata(name) {
            Ok(packages) => packages,
            Err(_) => Vec::new(),
        }
    }

    fn has_package(&self, name: &str) -> bool {
        match self.fetch_package_metadata(name) {
            Ok(packages) => !packages.is_empty(),
            Err(_) => false,
        }
    }

    fn search(&self, query: &str) -> Vec<PackageSearchResult> {
        self.search_api(query).unwrap_or_default()
    }
}
