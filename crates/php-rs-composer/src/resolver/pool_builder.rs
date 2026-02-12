use super::pool::Pool;
use crate::package::Package;
use crate::repository::RepositorySet;

/// Builds a Pool from repositories.
pub struct PoolBuilder;

impl PoolBuilder {
    /// Build a pool from a set of repositories, loading all packages.
    pub fn build(repo_set: &RepositorySet, root_requires: &[(String, String)]) -> Pool {
        let mut pool = Pool::new();

        // Add all required packages and their transitive deps
        let mut to_load: Vec<String> = root_requires.iter().map(|(n, _)| n.clone()).collect();
        let mut loaded = std::collections::HashSet::new();

        while let Some(name) = to_load.pop() {
            if loaded.contains(&name) {
                continue;
            }
            loaded.insert(name.clone());

            let packages = repo_set.find_packages(&name, None);
            for pkg in &packages {
                pool.add(pkg.clone());
                // Queue transitive dependencies
                for dep_name in pkg.require.keys() {
                    if !loaded.contains(dep_name) {
                        to_load.push(dep_name.clone());
                    }
                }
            }
        }

        pool
    }

    /// Build a pool from a flat list of packages (for testing).
    pub fn build_from_packages(packages: Vec<Package>) -> Pool {
        let mut pool = Pool::new();
        for pkg in packages {
            pool.add(pkg);
        }
        pool
    }
}
