use std::path::Path;

use serde::{Deserialize, Serialize};

use super::package::Package;

/// Lock file data (composer.lock).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    #[serde(rename = "_readme")]
    pub readme: Vec<String>,
    #[serde(rename = "content-hash")]
    pub content_hash: String,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(default, rename = "packages-dev")]
    pub packages_dev: Vec<Package>,
    #[serde(default)]
    pub aliases: Vec<serde_json::Value>,
    #[serde(default, rename = "minimum-stability")]
    pub minimum_stability: String,
    #[serde(default, rename = "stability-flags")]
    pub stability_flags: serde_json::Value,
    #[serde(default, rename = "prefer-stable")]
    pub prefer_stable: bool,
    #[serde(default, rename = "prefer-lowest")]
    pub prefer_lowest: bool,
    #[serde(default)]
    pub platform: serde_json::Value,
    #[serde(default, rename = "platform-dev")]
    pub platform_dev: serde_json::Value,
    #[serde(
        default,
        rename = "plugin-api-version",
        skip_serializing_if = "Option::is_none"
    )]
    pub plugin_api_version: Option<String>,
}

/// Manages reading and writing composer.lock files.
pub struct Locker {
    lock_path: std::path::PathBuf,
}

impl Locker {
    pub fn new(lock_path: &Path) -> Self {
        Locker {
            lock_path: lock_path.to_path_buf(),
        }
    }

    /// Check if a lock file exists.
    pub fn is_locked(&self) -> bool {
        self.lock_path.exists()
    }

    /// Read and parse the lock file.
    pub fn read(&self) -> Result<LockFile, String> {
        let content = std::fs::read_to_string(&self.lock_path)
            .map_err(|e| format!("Failed to read lock file: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse lock file: {}", e))
    }

    /// Write a lock file.
    pub fn write(&self, lock: &LockFile) -> Result<(), String> {
        let content = serde_json::to_string_pretty(lock)
            .map_err(|e| format!("Failed to serialize lock file: {}", e))?;
        std::fs::write(&self.lock_path, content)
            .map_err(|e| format!("Failed to write lock file: {}", e))
    }

    /// Compute the content hash for a composer.json.
    pub fn compute_content_hash(composer_json: &serde_json::Value) -> String {
        use sha2::{Digest, Sha256};

        // Composer hashes a normalized JSON of specific fields
        let mut relevant = serde_json::Map::new();
        let fields = [
            "name",
            "version",
            "require",
            "require-dev",
            "conflict",
            "replace",
            "provide",
            "minimum-stability",
            "prefer-stable",
            "repositories",
            "extra",
        ];

        if let Some(obj) = composer_json.as_object() {
            for field in &fields {
                if let Some(val) = obj.get(*field) {
                    relevant.insert(field.to_string(), val.clone());
                }
            }
        }

        let json = serde_json::to_string(&serde_json::Value::Object(relevant)).unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
