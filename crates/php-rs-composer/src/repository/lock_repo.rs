use super::repository::{PackageSearchResult, Repository};
use crate::package::Package;
use crate::semver::MultiConstraint;

/// Repository that loads packages from an existing composer.lock.
pub struct LockRepository {
    packages: Vec<Package>,
}

impl LockRepository {
    pub fn new(packages: Vec<Package>) -> Self {
        LockRepository { packages }
    }
}

impl Repository for LockRepository {
    fn name(&self) -> &str {
        "lock"
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

    fn search(&self, _query: &str) -> Vec<PackageSearchResult> {
        Vec::new()
    }
}
