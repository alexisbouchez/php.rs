use crate::config::Config;
use crate::json::JsonFile;

/// Execute `composer remove`.
pub fn execute(config: &Config, packages: &[String], dev: bool) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();
    let json_file = JsonFile::new(&composer_json_path);

    if !json_file.exists() {
        return Err("No composer.json found.".to_string());
    }

    let mut json = json_file.read()?;
    let section = if dev { "require-dev" } else { "require" };

    for name in packages {
        if let Some(obj) = json.as_object_mut() {
            if let Some(req) = obj.get_mut(section) {
                if let Some(req_obj) = req.as_object_mut() {
                    if req_obj.remove(name).is_some() {
                        println!("  - Removing {} from {}", name, section);
                    } else {
                        println!("  - {} not found in {}", name, section);
                    }
                }
            }
        }
    }

    json_file.write(&json)?;

    // Re-resolve and update
    super::install::execute(config)
}
