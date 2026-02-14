use crate::package::Package;
use std::path::{Path, PathBuf};

/// Installs binary scripts by creating symlinks in vendor/bin/.
pub struct BinaryInstaller {
    bin_dir: PathBuf,
}

impl BinaryInstaller {
    pub fn new(vendor_dir: &Path) -> Self {
        BinaryInstaller {
            bin_dir: vendor_dir.join("bin"),
        }
    }

    pub fn install(&self, package: &Package, install_path: &Path) -> Result<(), String> {
        if package.bin.is_empty() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.bin_dir)
            .map_err(|e| format!("Failed to create bin dir: {}", e))?;

        for bin in &package.bin {
            let source = install_path.join(bin);
            let target = self.bin_dir.join(
                Path::new(bin)
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new(bin)),
            );

            #[cfg(unix)]
            {
                if target.exists() {
                    std::fs::remove_file(&target).ok();
                }
                std::os::unix::fs::symlink(&source, &target).map_err(|e| {
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
                std::fs::copy(&source, &target).map_err(|e| {
                    format!(
                        "Failed to copy {} to {}: {}",
                        source.display(),
                        target.display(),
                        e
                    )
                })?;
            }
        }

        Ok(())
    }

    pub fn uninstall(&self, package: &Package) -> Result<(), String> {
        for bin in &package.bin {
            let target = self.bin_dir.join(
                Path::new(bin)
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new(bin)),
            );
            if target.exists() {
                std::fs::remove_file(&target)
                    .map_err(|e| format!("Failed to remove {}: {}", target.display(), e))?;
            }
        }
        Ok(())
    }
}
