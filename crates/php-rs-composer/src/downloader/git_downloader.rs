use std::path::Path;

/// Downloads packages via git clone.
pub struct GitDownloader;

impl GitDownloader {
    pub async fn download(&self, url: &str, reference: &str, target: &Path) -> Result<(), String> {
        // Clone the repository
        let output = tokio::process::Command::new("git")
            .args(["clone", "--depth", "1", url, &target.to_string_lossy()])
            .output()
            .await
            .map_err(|e| format!("Failed to run git clone: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "git clone failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Checkout specific reference
        if !reference.is_empty() {
            let output = tokio::process::Command::new("git")
                .args(["checkout", reference])
                .current_dir(target)
                .output()
                .await
                .map_err(|e| format!("Failed to run git checkout: {}", e))?;

            if !output.status.success() {
                return Err(format!(
                    "git checkout failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        // Remove .git directory to save space
        let git_dir = target.join(".git");
        if git_dir.exists() {
            std::fs::remove_dir_all(&git_dir).ok();
        }

        Ok(())
    }
}
