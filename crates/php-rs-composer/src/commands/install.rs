use crate::autoload::AutoloadGenerator;
use crate::config::Config;
use crate::installer::InstallationManager;
use crate::json::JsonFile;
use crate::package::{Locker, Package, PackageLoader};
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

        // Generate autoloader
        let generator = AutoloadGenerator::new(&vendor_dir);
        generator.generate(&lock.packages, &root_package)?;

        println!("Generating autoload files...");
        println!("Done.");
        return Ok(());
    }

    // No lock file: resolve dependencies
    println!("No lock file found. Resolving dependencies...");

    let requires: Vec<(String, String)> = root_package
        .require
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Build pool from repositories (currently empty - needs repo implementation)
    let pool = PoolBuilder::build_from_packages(Vec::new());
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&requires);

    match solver.solve() {
        Ok(transaction) => {
            let vendor_dir = config.vendor_path();
            let installer = InstallationManager::new(&vendor_dir);
            installer.execute(&transaction)?;

            // Write lock file
            let lock_packages: Vec<Package> = transaction
                .operations
                .iter()
                .map(|op: &Operation| op.package().clone())
                .collect();

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
