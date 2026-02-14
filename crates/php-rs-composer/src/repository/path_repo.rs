use super::repository::{PackageSearchResult, Repository};
use crate::package::Package;
use crate::semver::MultiConstraint;

/// Repository that loads packages from a local filesystem path.
pub struct PathRepository {
    path: std::path::PathBuf,
    packages: Vec<Package>,
}

impl PathRepository {
    pub fn new(path: &std::path::Path) -> Self {
        PathRepository {
            path: path.to_path_buf(),
            packages: Vec::new(),
        }
    }

    /// Scan the directory for composer.json files.
    pub fn scan(&mut self) -> Result<(), String> {
        let composer_json = self.path.join("composer.json");
        if composer_json.exists() {
            let pkg = crate::package::PackageLoader::load_from_file(&composer_json)?;
            self.packages.push(pkg);
        }
        Ok(())
    }
}

impl Repository for PathRepository {
    fn name(&self) -> &str {
        "path"
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
