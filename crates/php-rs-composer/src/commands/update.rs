use crate::config::Config;

/// Execute `composer update`.
pub fn execute(config: &Config, packages: &[String]) -> Result<(), String> {
    if packages.is_empty() {
        println!("Loading composer repositories...");
        println!("Updating dependencies...");
    } else {
        println!("Updating: {}", packages.join(", "));
    }

    // TODO: Re-resolve dependencies and update lock file
    let _ = config;
    println!("Nothing to update.");
    Ok(())
}
