use crate::config::Config;
use crate::json::JsonFile;

/// Execute `composer init`.
pub fn execute(
    config: &Config,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();

    if composer_json_path.exists() {
        return Err("composer.json already exists in this directory.".to_string());
    }

    let pkg_name = name.unwrap_or("vendor/project");
    let pkg_desc = description.unwrap_or("A new Composer project");

    let json = serde_json::json!({
        "name": pkg_name,
        "description": pkg_desc,
        "type": "project",
        "require": {},
        "autoload": {
            "psr-4": {}
        },
        "minimum-stability": "stable",
        "prefer-stable": true
    });

    let json_file = JsonFile::new(&composer_json_path);
    json_file.write(&json)?;

    println!("Created composer.json in {}", config.working_dir.display());
    Ok(())
}
