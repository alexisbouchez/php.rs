use crate::autoload::AutoloadGenerator;
use crate::config::Config;
use crate::json::JsonFile;
use crate::package::{Locker, PackageLoader};

/// Execute `composer dump-autoload`.
pub fn execute(config: &Config) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();
    let json_file = JsonFile::new(&composer_json_path);

    if !json_file.exists() {
        return Err("No composer.json found.".to_string());
    }

    let json = json_file.read()?;
    let root_package = PackageLoader::load_from_json(&json)?;

    let lock_path = config.composer_lock_path();
    let locker = Locker::new(&lock_path);

    let packages = if locker.is_locked() {
        let lock = locker.read()?;
        lock.packages
    } else {
        Vec::new()
    };

    let vendor_dir = config.vendor_path();
    let generator = AutoloadGenerator::new(&vendor_dir);
    generator.generate(&packages, &root_package)?;

    println!("Generated autoload files.");
    Ok(())
}
