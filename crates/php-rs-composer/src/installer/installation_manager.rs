use crate::resolver::{Operation, Transaction};
use std::path::{Path, PathBuf};

/// Orchestrates installation/update/removal operations.
pub struct InstallationManager {
    vendor_dir: PathBuf,
}

impl InstallationManager {
    pub fn new(vendor_dir: &Path) -> Self {
        InstallationManager {
            vendor_dir: vendor_dir.to_path_buf(),
        }
    }

    /// Execute all operations in a transaction.
    pub fn execute(&self, transaction: &Transaction) -> Result<(), String> {
        for op in &transaction.operations {
            match op {
                Operation::Install(pkg) => {
                    let target = self.vendor_dir.join(&pkg.name);
                    std::fs::create_dir_all(&target)
                        .map_err(|e| format!("Failed to create {}: {}", target.display(), e))?;
                    println!("  - {}", op);
                }
                Operation::Update { from: _, to } => {
                    let target = self.vendor_dir.join(&to.name);
                    println!("  - {}", op);
                    let _ = target; // TODO: actual update
                }
                Operation::Uninstall(pkg) => {
                    let target = self.vendor_dir.join(&pkg.name);
                    if target.exists() {
                        std::fs::remove_dir_all(&target)
                            .map_err(|e| format!("Failed to remove {}: {}", target.display(), e))?;
                    }
                    println!("  - {}", op);
                }
            }
        }
        Ok(())
    }
}
