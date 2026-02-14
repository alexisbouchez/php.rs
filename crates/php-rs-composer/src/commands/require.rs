use crate::config::Config;
use crate::json::JsonFile;

/// Execute `composer require`.
pub fn execute(config: &Config, packages: &[String], dev: bool) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();
    let json_file = JsonFile::new(&composer_json_path);

    let mut json = if json_file.exists() {
        json_file.read()?
    } else {
        serde_json::json!({
            "require": {}
        })
    };

    let section = if dev { "require-dev" } else { "require" };

    for pkg_spec in packages {
        let (name, constraint) = parse_package_spec(pkg_spec)?;
        println!(
            "Using version {} for {}",
            constraint.as_deref().unwrap_or("*"),
            name
        );

        if let Some(obj) = json.as_object_mut() {
            let req = obj.entry(section).or_insert_with(|| serde_json::json!({}));
            if let Some(req_obj) = req.as_object_mut() {
                req_obj.insert(
                    name.clone(),
                    serde_json::Value::String(
                        constraint.clone().unwrap_or_else(|| "*".to_string()),
                    ),
                );
            }
        }

        println!("  - Adding {} to {}", name, section);
    }

    // Write updated composer.json
    json_file.write(&json)?;

    // Run install
    super::install::execute(config)
}

fn parse_package_spec(spec: &str) -> Result<(String, Option<String>), String> {
    // "vendor/package:^1.0" or "vendor/package ^1.0" or just "vendor/package"
    if let Some((name, constraint)) = spec.split_once(':') {
        Ok((name.to_string(), Some(constraint.to_string())))
    } else if let Some((name, constraint)) = spec.split_once(' ') {
        Ok((name.to_string(), Some(constraint.to_string())))
    } else {
        Ok((spec.to_string(), None))
    }
}
