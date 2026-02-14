use crate::package::Package;
use crate::semver::MultiConstraint;

/// Trait for package repositories.
pub trait Repository: Send + Sync {
    /// Get the repository name/type for display.
    fn name(&self) -> &str;

    /// Find all versions of a package matching a constraint.
    fn find_packages(&self, name: &str, constraint: Option<&MultiConstraint>) -> Vec<Package>;

    /// Check if a package exists in this repository.
    fn has_package(&self, name: &str) -> bool;

    /// Search packages by keyword (for `composer search`).
    fn search(&self, query: &str) -> Vec<PackageSearchResult>;
}

/// Search result for repository search.
#[derive(Debug, Clone)]
pub struct PackageSearchResult {
    pub name: String,
    pub description: Option<String>,
}

/// Aggregates multiple repositories with priority ordering.
pub struct RepositorySet {
    repositories: Vec<Box<dyn Repository>>,
}

impl RepositorySet {
    pub fn new() -> Self {
        RepositorySet {
            repositories: Vec::new(),
        }
    }

    pub fn add(&mut self, repo: Box<dyn Repository>) {
        self.repositories.push(repo);
    }

    /// Find packages across all repositories, respecting priority.
    pub fn find_packages(&self, name: &str, constraint: Option<&MultiConstraint>) -> Vec<Package> {
        let mut result = Vec::new();
        for repo in &self.repositories {
            result.extend(repo.find_packages(name, constraint));
        }
        result
    }

    /// Search across all repositories.
    pub fn search(&self, query: &str) -> Vec<PackageSearchResult> {
        let mut results = Vec::new();
        for repo in &self.repositories {
            results.extend(repo.search(query));
        }
        results
    }
}

impl Default for RepositorySet {
    fn default() -> Self {
        Self::new()
    }
}
