use crate::package::Package;

/// Installer for metapackages (virtual packages with no files).
pub struct MetapackageInstaller;

impl MetapackageInstaller {
    pub fn install(&self, package: &Package) -> Result<(), String> {
        // Metapackages have no files to install
        let _ = package;
        Ok(())
    }

    pub fn uninstall(&self, package: &Package) -> Result<(), String> {
        let _ = package;
        Ok(())
    }
}
