use super::repository::{PackageSearchResult, Repository};
use crate::package::Package;
use crate::semver::MultiConstraint;

/// Repository that provides platform packages (php, ext-*).
/// Detects the php-rs version and loaded extensions.
pub struct PlatformRepository {
    packages: Vec<Package>,
}

impl PlatformRepository {
    pub fn new() -> Self {
        let mut repo = PlatformRepository {
            packages: Vec::new(),
        };
        repo.detect_platform();
        repo
    }

    /// Create with a specific PHP version and extension list.
    pub fn with_config(php_version: &str, extensions: &[&str]) -> Self {
        let mut packages = Vec::new();

        let mut php = Package::new("php", php_version);
        php.description = Some("The PHP interpreter (php-rs)".to_string());
        packages.push(php);

        // Also provide php-64bit on 64-bit systems
        if cfg!(target_pointer_width = "64") {
            let mut php64 = Package::new("php-64bit", php_version);
            php64.description = Some("64-bit PHP (php-rs)".to_string());
            packages.push(php64);
        }

        for ext in extensions {
            let mut pkg = Package::new(&format!("ext-{}", ext), php_version);
            pkg.description = Some(format!("PHP extension: {}", ext));
            packages.push(pkg);
        }

        // Composer runtime/plugin API
        let mut runtime_api = Package::new("composer-runtime-api", "2.2.0");
        runtime_api.description = Some("Composer runtime API".to_string());
        packages.push(runtime_api);

        let mut plugin_api = Package::new("composer-plugin-api", "2.6.0");
        plugin_api.description = Some("Composer plugin API".to_string());
        packages.push(plugin_api);

        PlatformRepository { packages }
    }

    /// Detect platform capabilities from the php-rs runtime.
    fn detect_platform(&mut self) {
        // php-rs targets PHP 8.6
        let php_version = "8.6.0";

        // Extensions that php-rs provides natively
        let extensions = [
            "json",
            "date",
            "pcre",
            "ctype",
            "tokenizer",
            "mbstring",
            "filter",
            "hash",
            "spl",
            "standard",
            "reflection",
            "posix",
            "session",
            "xml",
            "dom",
            "simplexml",
            "xmlreader",
            "xmlwriter",
            "phar",
            "fileinfo",
            "iconv",
            "pdo",
            "curl",
            "openssl",
            "zlib",
            "bcmath",
            "gmp",
            "intl",
            "sodium",
        ];

        *self = Self::with_config(php_version, &extensions);
    }
}

impl Default for PlatformRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl Repository for PlatformRepository {
    fn name(&self) -> &str {
        "platform"
    }

    fn find_packages(&self, name: &str, _constraint: Option<&MultiConstraint>) -> Vec<Package> {
        self.packages
            .iter()
            .filter(|p| p.name == name)
            .cloned()
            .collect()
    }

    fn has_package(&self, name: &str) -> bool {
        self.packages.iter().any(|p| p.name == name)
    }

    fn search(&self, query: &str) -> Vec<PackageSearchResult> {
        self.packages
            .iter()
            .filter(|p| p.name.contains(query))
            .map(|p| PackageSearchResult {
                name: p.name.clone(),
                description: p.description.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_has_php() {
        let repo = PlatformRepository::new();
        assert!(repo.has_package("php"));
    }

    #[test]
    fn test_platform_has_extensions() {
        let repo = PlatformRepository::new();
        assert!(repo.has_package("ext-json"));
        assert!(repo.has_package("ext-mbstring"));
        assert!(repo.has_package("ext-pcre"));
        assert!(repo.has_package("ext-openssl"));
    }

    #[test]
    fn test_platform_has_composer_api() {
        let repo = PlatformRepository::new();
        assert!(repo.has_package("composer-runtime-api"));
        assert!(repo.has_package("composer-plugin-api"));
    }

    #[test]
    fn test_platform_search() {
        let repo = PlatformRepository::new();
        let results = repo.search("ext-");
        assert!(results.len() > 10);
    }

    #[test]
    fn test_custom_platform() {
        let repo = PlatformRepository::with_config("8.2.0", &["json", "pdo"]);
        assert!(repo.has_package("php"));
        assert!(repo.has_package("ext-json"));
        assert!(repo.has_package("ext-pdo"));
        assert!(!repo.has_package("ext-mbstring"));

        let php = repo.find_packages("php", None);
        assert_eq!(php[0].version, "8.2.0");
    }
}
