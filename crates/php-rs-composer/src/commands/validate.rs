use crate::config::Config;
use crate::json::JsonFile;

/// Execute `composer validate`.
pub fn execute(config: &Config) -> Result<(), String> {
    let composer_json_path = config.composer_json_path();
    let json_file = JsonFile::new(&composer_json_path);

    if !json_file.exists() {
        return Err(format!("{} does not exist.", composer_json_path.display()));
    }

    match json_file.validate() {
        Ok(()) => {
            println!("{} is valid.", composer_json_path.display());
            Ok(())
        }
        Err(warnings) => {
            println!(
                "{} is valid, but has warnings:",
                composer_json_path.display()
            );
            for w in &warnings {
                println!("  - {}", w);
            }
            Ok(())
        }
    }
}
