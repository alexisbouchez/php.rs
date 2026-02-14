use std::path::Path;

use crate::config::Config;
use crate::downloader::DownloadManager;
use crate::package::Package;
use crate::repository::ComposerRepository;
use crate::semver::{MultiConstraint, Stability, Version, VersionParser};

use super::install;

/// Execute `composer create-project`.
pub fn execute(
    _config: &Config,
    package: &str,
    directory: Option<&str>,
    version: Option<&str>,
) -> Result<(), String> {
    let short_name = package.split('/').nth(1).unwrap_or(package);
    let dir = directory.unwrap_or(short_name);
    let target = Path::new(dir);

    if target.exists() {
        return Err(format!(
            "Project directory \"{}\" already exists.",
            target.display()
        ));
    }

    println!(
        "Creating project from {} {}...",
        package,
        version.unwrap_or("(latest)")
    );

    // 1. Fetch all versions from Packagist
    let config = Config::new(target);
    let repo = ComposerRepository::packagist().with_cache_dir(&config.cache_dir);

    println!("  - Searching for {}...", package);
    let packages = repo.fetch_package_metadata(package)?;
    if packages.is_empty() {
        return Err(format!(
            "Could not find package {} on packagist.org",
            package
        ));
    }

    // 2. Select best matching version
    let constraint = match version {
        Some(v) => VersionParser::parse_constraints(v)?,
        None => MultiConstraint::MatchAll,
    };

    let selected = select_best_version(&packages, &constraint, true)?;
    println!("  - Installing {} ({})", selected.name, selected.version);

    // 3. Download and extract
    let dm = DownloadManager::new(&config.cache_dir);
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;
    rt.block_on(dm.download(&selected, target))?;

    // 4. Run composer install in the new project directory
    println!("  - Installing dependencies...");
    let project_config = Config::new(target);
    if project_config.composer_json_path().exists() {
        install::execute(&project_config)?;
    }

    println!("Project {} created successfully in {}/", package, dir);
    Ok(())
}

/// Select the best matching version from a list of packages.
///
/// - Filters by version constraint
/// - Prefers stable versions when `prefer_stable` is true
/// - Returns the highest matching version
fn select_best_version(
    packages: &[Package],
    constraint: &MultiConstraint,
    prefer_stable: bool,
) -> Result<Package, String> {
    let mut candidates: Vec<(&Package, Version)> = Vec::new();

    for pkg in packages {
        let parsed = match VersionParser::normalize(&pkg.version) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !constraint.matches_version(&parsed) {
            continue;
        }

        candidates.push((pkg, parsed));
    }

    if candidates.is_empty() {
        return Err("Could not find a version matching the constraint.".to_string());
    }

    // Sort: highest version first
    candidates.sort_by(|a, b| b.1.cmp(&a.1));

    if prefer_stable {
        // Prefer the highest stable version if one exists
        if let Some((pkg, _)) = candidates
            .iter()
            .find(|(_, v)| v.stability == Stability::Stable)
        {
            return Ok((*pkg).clone());
        }
    }

    // Otherwise return the highest version
    Ok(candidates[0].0.clone())
}
