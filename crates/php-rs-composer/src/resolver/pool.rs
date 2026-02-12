use crate::package::Package;
use crate::semver::{MultiConstraint, VersionParser};
use std::collections::HashMap;

/// Pool of all available package versions.
/// Each package version gets a unique integer ID (1-indexed).
/// Positive = install, negative = do not install.
#[derive(Debug)]
pub struct Pool {
    /// All packages, indexed by pool ID (1-indexed, so index 0 = ID 1).
    packages: Vec<Package>,
    /// Package name → list of pool IDs for all versions.
    name_index: HashMap<String, Vec<usize>>,
}

impl Pool {
    pub fn new() -> Self {
        Pool {
            packages: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Add a package to the pool. Returns its pool ID (1-indexed).
    pub fn add(&mut self, package: Package) -> usize {
        let id = self.packages.len() + 1;
        self.name_index
            .entry(package.name.clone())
            .or_default()
            .push(id);
        self.packages.push(package);
        id
    }

    /// Get a package by pool ID.
    pub fn package(&self, id: usize) -> Option<&Package> {
        if id == 0 || id > self.packages.len() {
            None
        } else {
            Some(&self.packages[id - 1])
        }
    }

    /// Get all pool IDs for packages with the given name.
    pub fn packages_by_name(&self, name: &str) -> &[usize] {
        self.name_index.get(name).map_or(&[], |v| v.as_slice())
    }

    /// Find all package IDs matching name and constraint.
    pub fn what_provides(&self, name: &str, constraint: Option<&MultiConstraint>) -> Vec<usize> {
        let ids = self.packages_by_name(name);
        if let Some(constraint) = constraint {
            ids.iter()
                .copied()
                .filter(|&id| {
                    if let Some(pkg) = self.package(id) {
                        if let Ok(ver) = VersionParser::normalize(&pkg.version) {
                            constraint.matches_version(&ver)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                })
                .collect()
        } else {
            ids.to_vec()
        }
    }

    /// Total number of packages in the pool.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}
