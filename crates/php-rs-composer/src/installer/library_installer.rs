use crate::package::Package;
use std::path::{Path, PathBuf};

/// Installs library packages to vendor/{name}/.
pub struct LibraryInstaller {
    vendor_dir: PathBuf,
}

impl LibraryInstaller {
    pub fn new(vendor_dir: &Path) -> Self {
        LibraryInstaller {
            vendor_dir: vendor_dir.to_path_buf(),
        }
    }

    pub fn install(&self, package: &Package, source_dir: &Path) -> Result<(), String> {
        let target = self.vendor_dir.join(&package.name);
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("Failed to create {}: {}", target.display(), e))?;
        // Copy files from source to target
        copy_dir_recursive(source_dir, &target)
    }

    pub fn uninstall(&self, package: &Package) -> Result<(), String> {
        let target = self.vendor_dir.join(&package.name);
        if target.exists() {
            std::fs::remove_dir_all(&target)
                .map_err(|e| format!("Failed to remove {}: {}", target.display(), e))?;
        }
        Ok(())
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("Failed to create {}: {}", dst.display(), e))?;

    let entries =
        std::fs::read_dir(src).map_err(|e| format!("Failed to read {}: {}", src.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
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
