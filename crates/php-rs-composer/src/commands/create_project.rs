use crate::config::Config;

/// Execute `composer create-project`.
pub fn execute(
    _config: &Config,
    package: &str,
    directory: Option<&str>,
    version: Option<&str>,
) -> Result<(), String> {
    let dir = directory.unwrap_or_else(|| package.split('/').nth(1).unwrap_or(package));

    println!(
        "Creating project from {} {}...",
        package,
        version.unwrap_or("(latest)")
    );
    println!("  - Installing to {}/", dir);

    // TODO: Download package, extract, run install
    println!("create-project is not yet fully implemented.");

    Ok(())
}
