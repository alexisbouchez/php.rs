use super::repository::{PackageSearchResult, Repository};
use crate::package::Package;
use crate::semver::MultiConstraint;

/// Repository that scans a VCS (git/svn) repository for tags/branches.
pub struct VcsRepository {
    url: String,
    vcs_type: String,
    packages: Vec<Package>,
}

impl VcsRepository {
    pub fn new(url: &str, vcs_type: &str) -> Self {
        VcsRepository {
            url: url.to_string(),
            vcs_type: vcs_type.to_string(),
            packages: Vec::new(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn vcs_type(&self) -> &str {
        &self.vcs_type
    }
}

impl Repository for VcsRepository {
    fn name(&self) -> &str {
        "vcs"
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
