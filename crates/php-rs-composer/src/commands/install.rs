use crate::autoload::AutoloadGenerator;
use crate::config::Config;
use crate::downloader::DownloadManager;
use crate::installer::InstallationManager;
use crate::json::JsonFile;
use crate::package::{LockFile, Locker, Package, PackageLoader};
use crate::repository::{ComposerRepository, RepositorySet};
use crate::resolver::{DefaultPolicy, Operation, PoolBuilder, Problem, Solver, Transaction};

/// Execute `composer install`.
pub fn execute(config: &Config) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();
    let json_file = JsonFile::new(&composer_json_path);

    if !json_file.exists() {
        return Err("No composer.json found in the current directory.".to_string());
    }

    let json = json_file.read()?;
    let root_package = PackageLoader::load_from_json(&json)?;

    let lock_path = config.composer_lock_path();
    let locker = Locker::new(&lock_path);

    // If lock file exists, install from lock
    if locker.is_locked() {
        let lock = locker.read()?;
        println!("Installing dependencies from lock file (composer.lock)...");

        let vendor_dir = config.vendor_path();
        let installer = InstallationManager::new(&vendor_dir);

        // Build transaction from lock file
        let mut operations = Vec::new();
        for pkg in &lock.packages {
            operations.push(Operation::Install(pkg.clone()));
        }
        let transaction = Transaction::new(operations);

        installer.execute(&transaction)?;

        // Download packages
        download_packages(&transaction, &vendor_dir, &config.cache_dir)?;

        // Generate autoloader
        let generator = AutoloadGenerator::new(&vendor_dir);
        generator.generate(&lock.packages, &root_package)?;

        println!("Generating autoload files...");
        println!("Done.");
        return Ok(());
    }

    // No lock file: resolve dependencies from Packagist
    println!("No lock file found. Resolving dependencies...");

    let requires: Vec<(String, String)> = root_package
        .require
        .iter()
        .filter(|(k, _)| !is_platform_package(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Build repository set with Packagist
    let mut repo_set = RepositorySet::new();
    let packagist = ComposerRepository::packagist().with_cache_dir(&config.cache_dir);
    repo_set.add(Box::new(packagist));

    println!("Loading packages from packagist.org...");
    let pool = PoolBuilder::build(&repo_set, &requires);
    println!("Resolving {} packages...", pool.len());

    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&requires);

    match solver.solve() {
        Ok(transaction) => {
            let vendor_dir = config.vendor_path();
            let installer = InstallationManager::new(&vendor_dir);
            installer.execute(&transaction)?;

            // Download packages
            download_packages(&transaction, &vendor_dir, &config.cache_dir)?;

            // Write lock file
            let lock_packages: Vec<Package> = transaction
                .operations
                .iter()
                .filter_map(|op: &Operation| {
                    let pkg = op.package();
                    // Don't include platform packages in lock file
                    if pkg.name.starts_with("ext-")
                        || pkg.name == "php"
                        || pkg.name == "php-64bit"
                        || pkg.name.starts_with("composer-")
                    {
                        None
                    } else {
                        Some(pkg.clone())
                    }
                })
                .collect();

            let lock_file = LockFile {
                readme: vec![
                    "This file locks the dependencies of your project to a known state".to_string(),
                ],
                content_hash: Locker::compute_content_hash(&json),
                packages: lock_packages.clone(),
                packages_dev: Vec::new(),
                aliases: Vec::new(),
                minimum_stability: config.minimum_stability.clone(),
                stability_flags: serde_json::json!({}),
                prefer_stable: config.prefer_stable,
                prefer_lowest: false,
                platform: serde_json::json!({}),
                platform_dev: serde_json::json!({}),
                plugin_api_version: Some("2.6.0".to_string()),
            };
            locker.write(&lock_file)?;

            let generator = AutoloadGenerator::new(&vendor_dir);
            generator.generate(&lock_packages, &root_package)?;

            println!("Generating autoload files...");
            println!("Done.");
            Ok(())
        }
        Err(problems) => {
            let mut msg = String::from(
                "Your requirements could not be resolved to an installable set of packages.\n\n",
            );
            for problem in &problems {
                let p: &Problem = problem;
                msg.push_str(&p.to_string_pretty());
                msg.push('\n');
            }
            Err(msg)
        }
    }
}

/// Download all packages in a transaction to the vendor directory.
fn download_packages(
    transaction: &Transaction,
    vendor_dir: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<(), String> {
    let dm = DownloadManager::new(cache_dir);

    let downloads: Vec<(Package, std::path::PathBuf)> = transaction
        .operations
        .iter()
        .filter_map(|op| {
            let pkg = op.package();
            // Only download packages that have dist/source info
            if pkg.dist.is_some() || pkg.source.is_some() {
                Some((pkg.clone(), vendor_dir.join(&pkg.name)))
            } else {
                None
            }
        })
        .collect();

    if downloads.is_empty() {
        return Ok(());
    }

    println!("Downloading {} packages...", downloads.len());

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;

    let total = downloads.len();
    rt.block_on(dm.download_parallel(
        &downloads,
        Some(&|done, _total, name| {
            println!("  ({}/{}) Downloaded {}", done, total, name);
        }),
    ))
}

/// Check if a package name is a platform package (php, ext-*, composer-*-api).
fn is_platform_package(name: &str) -> bool {
    name == "php"
        || name == "php-64bit"
        || name.starts_with("ext-")
        || name == "composer-plugin-api"
        || name == "composer-runtime-api"
}
