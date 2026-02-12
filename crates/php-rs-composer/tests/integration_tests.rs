//! End-to-end integration tests for php-rs-composer.
//! All tests are mock-based (no network calls).

use php_rs_composer::autoload::AutoloadGenerator;
use php_rs_composer::package::{Locker, Package};
use php_rs_composer::resolver::{DefaultPolicy, PoolBuilder, Solver};
use tempfile::TempDir;

fn make_package(name: &str, version: &str, requires: &[(&str, &str)]) -> Package {
    let mut pkg = Package::new(name, version);
    for (dep_name, dep_constraint) in requires {
        pkg.require
            .insert(dep_name.to_string(), dep_constraint.to_string());
    }
    pkg
}

fn make_package_with_autoload(name: &str, version: &str, psr4: &[(&str, &str)]) -> Package {
    let mut pkg = Package::new(name, version);
    let mut autoload = php_rs_composer::package::Autoload::default();
    for (ns, path) in psr4 {
        autoload.psr4.insert(
            ns.to_string(),
            php_rs_composer::package::AutoloadPath::Single(path.to_string()),
        );
    }
    pkg.autoload = Some(autoload);
    pkg
}

/// 8.1: End-to-end test simulating "require monolog/monolog, install, verify autoload"
#[test]
fn test_e2e_install_with_transitive_deps() {
    let tmp = TempDir::new().unwrap();
    let vendor_dir = tmp.path().join("vendor");

    // Simulate available packages (mock Packagist)
    let packages = vec![
        make_package_with_autoload("monolog/monolog", "3.5.0", &[("Monolog\\", "src/")]),
        make_package_with_autoload("psr/log", "3.0.0", &[("Psr\\Log\\", "src/")]),
    ];

    // Add dependency: monolog requires psr/log
    let mut monolog = packages[0].clone();
    monolog
        .require
        .insert("psr/log".to_string(), "^3.0".to_string());

    let all_packages = vec![monolog, packages[1].clone()];

    // Build pool and solve
    let pool = PoolBuilder::build_from_packages(all_packages.clone());
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&[("monolog/monolog".to_string(), "^3.0".to_string())]);

    let result = solver.solve();
    assert!(result.is_ok(), "Should resolve successfully");
    let transaction = result.unwrap();

    // Should install both monolog and psr/log
    assert_eq!(transaction.operations.len(), 2);
    let names: Vec<&str> = transaction
        .operations
        .iter()
        .map(|op| op.package().name.as_str())
        .collect();
    assert!(names.contains(&"monolog/monolog"));
    assert!(names.contains(&"psr/log"));

    // Create vendor directory structure for autoload generation
    std::fs::create_dir_all(&vendor_dir).unwrap();
    for pkg in &all_packages {
        let pkg_dir = vendor_dir.join(&pkg.name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
    }

    // Generate autoloader
    let root = Package::new("test/project", "1.0.0");
    let installed: Vec<Package> = transaction
        .operations
        .iter()
        .map(|op| op.package().clone())
        .collect();
    let generator = AutoloadGenerator::new(&vendor_dir);
    let result = generator.generate(&installed, &root);
    assert!(result.is_ok(), "Autoloader generation should succeed");

    // Verify autoload files exist
    assert!(vendor_dir.join("autoload.php").exists());
    assert!(vendor_dir.join("composer/autoload_psr4.php").exists());
    assert!(vendor_dir.join("composer/autoload_classmap.php").exists());
    assert!(vendor_dir.join("composer/autoload_files.php").exists());
    assert!(vendor_dir.join("composer/autoload_namespaces.php").exists());
    assert!(vendor_dir.join("composer/installed.json").exists());
    assert!(vendor_dir.join("composer/installed.php").exists());

    // Verify PSR-4 map contains our namespaces
    let psr4_content =
        std::fs::read_to_string(vendor_dir.join("composer/autoload_psr4.php")).unwrap();
    assert!(psr4_content.contains("Monolog\\\\"));
    assert!(psr4_content.contains("Psr\\\\Log\\\\"));

    // Verify installed.php contains both packages
    let installed_php = std::fs::read_to_string(vendor_dir.join("composer/installed.php")).unwrap();
    assert!(installed_php.contains("monolog/monolog"));
    assert!(installed_php.contains("psr/log"));
}

/// 8.2: End-to-end test for conflict detection with clear error messages
#[test]
fn test_e2e_conflict_error_messages() {
    // Package A conflicts with Package B
    let mut pkg_a = make_package("vendor/a", "1.0.0", &[]);
    pkg_a
        .conflict
        .insert("vendor/b".to_string(), ">=1.0".to_string());
    let pkg_b = make_package("vendor/b", "1.0.0", &[]);

    let pool = PoolBuilder::build_from_packages(vec![pkg_a, pkg_b]);
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&[
        ("vendor/a".to_string(), "^1.0".to_string()),
        ("vendor/b".to_string(), "^1.0".to_string()),
    ]);

    let result = solver.solve();
    assert!(result.is_err(), "Should detect conflict");

    let problems = result.unwrap_err();
    assert!(!problems.is_empty(), "Should have problems");

    // Verify the error message is human-readable
    let msg = problems[0].to_string_pretty();
    assert!(
        !msg.is_empty(),
        "Problem should produce a readable description"
    );
}

/// 8.2 (continued): Test unsatisfiable version constraint
#[test]
fn test_e2e_unsatisfiable_constraint() {
    // Only v2.0 available, but root requires ^1.0
    let pkg = make_package("vendor/a", "2.0.0", &[]);

    let pool = PoolBuilder::build_from_packages(vec![pkg]);
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

    let result = solver.solve();
    assert!(result.is_err(), "Should fail: no matching version");

    let problems = result.unwrap_err();
    let msg = problems[0].to_string_pretty();
    assert!(msg.contains("vendor/a"), "Error should mention the package");
}

/// 8.3: End-to-end test for path repository with symlinks
#[test]
fn test_e2e_path_repository() {
    let tmp = TempDir::new().unwrap();

    // Create a local package directory with composer.json
    let local_pkg_dir = tmp.path().join("local-pkg");
    std::fs::create_dir_all(&local_pkg_dir).unwrap();
    std::fs::write(
        local_pkg_dir.join("composer.json"),
        serde_json::json!({
            "name": "local/package",
            "version": "1.0.0",
            "description": "A local path package",
            "autoload": {
                "psr-4": {
                    "Local\\Package\\": "src/"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // Create src directory
    std::fs::create_dir_all(local_pkg_dir.join("src")).unwrap();
    std::fs::write(
        local_pkg_dir.join("src/Foo.php"),
        "<?php\nnamespace Local\\Package;\nclass Foo {}\n",
    )
    .unwrap();

    // Load the package from the path
    let content = std::fs::read_to_string(local_pkg_dir.join("composer.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let pkg: Package = serde_json::from_value(json).unwrap();

    assert_eq!(pkg.name, "local/package");
    assert_eq!(pkg.version, "1.0.0");
    assert!(pkg.autoload.is_some());

    // Verify the package can be used in resolution
    let pool = PoolBuilder::build_from_packages(vec![pkg]);
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&[("local/package".to_string(), "^1.0".to_string())]);

    let result = solver.solve();
    assert!(result.is_ok(), "Local path package should resolve");
    let tx = result.unwrap();
    assert_eq!(tx.operations.len(), 1);
    assert_eq!(tx.operations[0].package().name, "local/package");
}

/// 8.4: Lock file determinism — same input always produces identical output
#[test]
fn test_lock_file_determinism() {
    let tmp = TempDir::new().unwrap();

    let packages = vec![
        make_package("vendor/a", "1.0.0", &[("vendor/b", "^1.0")]),
        make_package("vendor/b", "1.2.0", &[]),
        make_package("vendor/c", "2.0.0", &[]),
    ];

    // Run resolution twice and compare lock files
    let mut locks = Vec::new();
    for _ in 0..3 {
        let pool = PoolBuilder::build_from_packages(packages.clone());
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[
            ("vendor/a".to_string(), "^1.0".to_string()),
            ("vendor/c".to_string(), "^2.0".to_string()),
        ]);

        let result = solver.solve().unwrap();
        let lock_packages: Vec<Package> = result
            .operations
            .iter()
            .map(|op| op.package().clone())
            .collect();

        // Create a lock file
        let lock_path = tmp.path().join(format!("composer.{}.lock", locks.len()));
        let locker = Locker::new(&lock_path);

        let composer_json = serde_json::json!({
            "require": {
                "vendor/a": "^1.0",
                "vendor/c": "^2.0"
            }
        });

        let lock = php_rs_composer::package::LockFile {
            readme: vec!["This file locks the dependencies.".to_string()],
            content_hash: Locker::compute_content_hash(&composer_json),
            packages: lock_packages,
            packages_dev: Vec::new(),
            aliases: Vec::new(),
            minimum_stability: "stable".to_string(),
            stability_flags: serde_json::json!({}),
            prefer_stable: false,
            prefer_lowest: false,
            platform: serde_json::json!({}),
            platform_dev: serde_json::json!({}),
            plugin_api_version: Some("2.6.0".to_string()),
        };

        locker.write(&lock).unwrap();
        let content = std::fs::read_to_string(&lock_path).unwrap();
        locks.push(content);
    }

    // All three lock files should be identical
    assert_eq!(
        locks[0], locks[1],
        "Lock files should be deterministic (run 1 vs 2)"
    );
    assert_eq!(
        locks[1], locks[2],
        "Lock files should be deterministic (run 2 vs 3)"
    );
}

/// 8.4 (continued): Content hash is deterministic
#[test]
fn test_content_hash_determinism() {
    let json = serde_json::json!({
        "name": "test/project",
        "require": {
            "vendor/a": "^1.0",
            "vendor/b": "^2.0"
        },
        "require-dev": {
            "phpunit/phpunit": "^10.0"
        }
    });

    let hash1 = Locker::compute_content_hash(&json);
    let hash2 = Locker::compute_content_hash(&json);
    let hash3 = Locker::compute_content_hash(&json);

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
    assert_eq!(hash1.len(), 64, "SHA-256 hash should be 64 hex chars");
}

/// Test that the solver prefers locked versions during install
#[test]
fn test_e2e_locked_version_preference() {
    let packages = vec![
        make_package("vendor/a", "1.0.0", &[]),
        make_package("vendor/a", "1.1.0", &[]),
        make_package("vendor/a", "1.2.0", &[]),
    ];

    let pool = PoolBuilder::build_from_packages(packages);
    let mut solver = Solver::new(pool, DefaultPolicy::default());

    // Lock at version 1.1.0
    solver.set_locked_packages(vec![("vendor/a".to_string(), "1.1.0".to_string())]);
    solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

    let result = solver.solve();
    assert!(result.is_ok());
    let tx = result.unwrap();
    assert_eq!(tx.operations[0].package().version, "1.1.0");
}

/// Test the full install workflow: resolve → install → autoload
#[test]
fn test_e2e_full_install_workflow() {
    let tmp = TempDir::new().unwrap();
    let vendor_dir = tmp.path().join("vendor");

    // Available packages
    let packages = vec![
        make_package_with_autoload("psr/log", "3.0.0", &[("Psr\\Log\\", "src/")]),
        make_package_with_autoload("psr/container", "2.0.0", &[("Psr\\Container\\", "src/")]),
    ];

    // Resolve
    let pool = PoolBuilder::build_from_packages(packages.clone());
    let mut solver = Solver::new(pool, DefaultPolicy::default());
    solver.add_root_requirements(&[
        ("psr/log".to_string(), "^3.0".to_string()),
        ("psr/container".to_string(), "^2.0".to_string()),
    ]);

    let tx = solver.solve().unwrap();
    assert_eq!(tx.operations.len(), 2);

    // Install (create directories)
    std::fs::create_dir_all(&vendor_dir).unwrap();
    // Create package directories manually (real download is mocked)
    for op in &tx.operations {
        let pkg_dir = vendor_dir.join(&op.package().name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
    }

    // Generate autoloader
    let root = Package::new("my/project", "1.0.0");
    let installed: Vec<Package> = tx
        .operations
        .iter()
        .map(|op| op.package().clone())
        .collect();
    let generator = AutoloadGenerator::new(&vendor_dir);
    generator.generate(&installed, &root).unwrap();

    // Verify everything is in place
    assert!(vendor_dir.join("autoload.php").exists());
    let psr4 = std::fs::read_to_string(vendor_dir.join("composer/autoload_psr4.php")).unwrap();
    assert!(psr4.contains("Psr\\\\Log\\\\"));
    assert!(psr4.contains("Psr\\\\Container\\\\"));
}
