use super::package::Package;

/// Load packages from JSON data.
pub struct PackageLoader;

impl PackageLoader {
    /// Load a package from a composer.json value.
    pub fn load_from_json(json: &serde_json::Value) -> Result<Package, String> {
        serde_json::from_value(json.clone()).map_err(|e| format!("Failed to parse package: {}", e))
    }

    /// Load a package from a composer.json file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Package, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
        Self::load_from_json(&json)
    }
}
