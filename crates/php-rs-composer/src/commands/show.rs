use crate::config::Config;
use crate::package::Locker;

/// Execute `composer show`.
pub fn execute(config: &Config, package: Option<&str>) -> Result<(), String> {
    let lock_path = config.composer_lock_path();
    let locker = Locker::new(&lock_path);

    if !locker.is_locked() {
        println!("No packages installed.");
        return Ok(());
    }

    let lock = locker.read()?;

    if let Some(name) = package {
        // Show details for a specific package
        let pkg = lock
            .packages
            .iter()
            .chain(lock.packages_dev.iter())
            .find(|p| p.name == name);

        if let Some(pkg) = pkg {
            println!("name     : {}", pkg.name);
            println!("version  : {}", pkg.version);
            if let Some(desc) = &pkg.description {
                println!("descrip. : {}", desc);
            }
            if !pkg.require.is_empty() {
                println!("requires:");
                for (name, constraint) in &pkg.require {
                    println!("  {} {}", name, constraint);
                }
            }
        } else {
            return Err(format!("Package {} not found.", name));
        }
    } else {
        // List all installed packages
        for pkg in &lock.packages {
            println!(
                "{} {}{}",
                pkg.name,
                pkg.version,
                pkg.description
                    .as_ref()
                    .map(|d| format!(" {}", d))
                    .unwrap_or_default()
            );
        }
    }

    Ok(())
}
