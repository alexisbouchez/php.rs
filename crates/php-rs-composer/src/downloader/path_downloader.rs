use std::path::Path;

/// Downloads packages by symlinking or copying local paths.
pub struct PathDownloader;

impl PathDownloader {
    pub fn download(&self, source: &Path, target: &Path, symlink: bool) -> Result<(), String> {
        if symlink {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(source, target).map_err(|e| {
                    format!(
                        "Failed to symlink {} -> {}: {}",
                        target.display(),
                        source.display(),
                        e
                    )
                })?;
            }
            #[cfg(not(unix))]
            {
                Self::copy_recursive(source, target)?;
            }
        } else {
            Self::copy_recursive(source, target)?;
        }
        Ok(())
    }

    fn copy_recursive(src: &Path, dst: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dst)
            .map_err(|e| format!("Failed to create {}: {}", dst.display(), e))?;

        for entry in std::fs::read_dir(src)
            .map_err(|e| format!("Failed to read {}: {}", src.display(), e))?
        {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                Self::copy_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path).map_err(|e| {
                    format!(
                        "Failed to copy {} to {}: {}",
                        src_path.display(),
                        dst_path.display(),
                        e
                    )
                })?;
            }
        }
        Ok(())
    }
}
