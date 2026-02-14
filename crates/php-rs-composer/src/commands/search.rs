use crate::config::Config;
use crate::repository::ComposerRepository;

/// Execute `composer search`.
pub fn execute(_config: &Config, query: &str) -> Result<(), String> {
    if query.is_empty() {
        return Err("Please provide a search query.".to_string());
    }

    println!("Searching for: {}", query);

    let repo = ComposerRepository::packagist();
    let results = repo.search_api(query)?;

    if results.is_empty() {
        println!("No packages found matching \"{}\".", query);
        return Ok(());
    }

    for result in &results {
        if let Some(desc) = &result.description {
            println!("{} - {}", result.name, desc);
        } else {
            println!("{}", result.name);
        }
    }

    Ok(())
}
