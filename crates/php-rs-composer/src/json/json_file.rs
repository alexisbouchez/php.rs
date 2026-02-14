use std::path::{Path, PathBuf};

/// Read and write JSON files with validation.
pub struct JsonFile {
    path: PathBuf,
}

impl JsonFile {
    pub fn new(path: &Path) -> Self {
        JsonFile {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Read and parse the JSON file.
    pub fn read(&self) -> Result<serde_json::Value, String> {
        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("Failed to read {}: {}", self.path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", self.path.display(), e))
    }

    /// Write a JSON value to file with pretty formatting.
    pub fn write(&self, value: &serde_json::Value) -> Result<(), String> {
        let content = serde_json::to_string_pretty(value)
            .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
        // Ensure trailing newline
        let content = if content.ends_with('\n') {
            content
        } else {
            format!("{}\n", content)
        };
        std::fs::write(&self.path, content)
            .map_err(|e| format!("Failed to write {}: {}", self.path.display(), e))
    }

    /// Validate that the file contains valid JSON.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        match self.read() {
            Ok(value) => {
                let mut warnings = Vec::new();
                if let Some(obj) = value.as_object() {
                    if !obj.contains_key("name") {
                        warnings.push("Missing 'name' field".to_string());
                    }
                    if !obj.contains_key("description") {
                        warnings.push("Missing 'description' field".to_string());
                    }
                } else {
                    return Err(vec!["Root must be a JSON object".to_string()]);
                }
                if warnings.is_empty() {
                    Ok(())
                } else {
                    Err(warnings)
                }
            }
            Err(e) => Err(vec![e]),
        }
    }
}
