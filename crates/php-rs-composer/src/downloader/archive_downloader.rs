use std::path::{Path, PathBuf};

/// Downloads and extracts archive files (zip, tar.gz).
pub struct ArchiveDownloader {
    cache_dir: PathBuf,
}

impl ArchiveDownloader {
    pub fn new(cache_dir: &Path) -> Self {
        ArchiveDownloader {
            cache_dir: cache_dir.to_path_buf(),
        }
    }

    /// Download an archive from URL and extract to target directory.
    pub async fn download(
        &self,
        url: &str,
        target: &Path,
        expected_shasum: Option<&str>,
    ) -> Result<(), String> {
        // Check cache first
        let cache_key = Self::cache_key(url);
        let cache_path = self.cache_dir.join("files").join(&cache_key);

        if !cache_path.exists() {
            // Download
            std::fs::create_dir_all(cache_path.parent().unwrap())
                .map_err(|e| format!("Failed to create cache dir: {}", e))?;

            let client = reqwest::Client::new();
            let response = client
                .get(url)
                .header("User-Agent", "php-rs-composer/0.1.0")
                .send()
                .await
                .map_err(|e| format!("Failed to download {}: {}", url, e))?;

            if !response.status().is_success() {
                return Err(format!(
                    "HTTP {} when downloading {}",
                    response.status(),
                    url
                ));
            }

            let bytes = response
                .bytes()
                .await
                .map_err(|e| format!("Failed to read response: {}", e))?;

            // Verify checksum if provided (skip empty checksums)
            if let Some(expected) = expected_shasum.filter(|s| !s.is_empty()) {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let actual = format!("{:x}", hasher.finalize());
                if actual != expected {
                    return Err(format!(
                        "Checksum mismatch for {}: expected {}, got {}",
                        url, expected, actual
                    ));
                }
            }

            std::fs::write(&cache_path, &bytes)
                .map_err(|e| format!("Failed to write cache: {}", e))?;
        }

        // Extract
        Self::extract(&cache_path, target)
    }

    fn extract(archive_path: &Path, target: &Path) -> Result<(), String> {
        std::fs::create_dir_all(target)
            .map_err(|e| format!("Failed to create target dir: {}", e))?;

        let ext = archive_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "zip" => Self::extract_zip(archive_path, target),
            "gz" | "tgz" => Self::extract_tar_gz(archive_path, target),
            _ => Err(format!("Unknown archive format: {}", ext)),
        }
    }

    fn extract_zip(archive_path: &Path, target: &Path) -> Result<(), String> {
        let file = std::fs::File::open(archive_path)
            .map_err(|e| format!("Failed to open archive: {}", e))?;
        let mut archive =
            zip::ZipArchive::new(file).map_err(|e| format!("Failed to read zip: {}", e))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;

            // Strip first directory component (packages are usually wrapped in a dir)
            let name = file.name().to_string();
            let path_parts: Vec<&str> = name.split('/').collect();
            if path_parts.len() <= 1 {
                continue;
            }
            let relative = path_parts[1..].join("/");
            if relative.is_empty() {
                continue;
            }

            let outpath = target.join(&relative);

            if file.is_dir() {
                std::fs::create_dir_all(&outpath).ok();
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let mut outfile = std::fs::File::create(&outpath)
                    .map_err(|e| format!("Failed to create {}: {}", outpath.display(), e))?;
                std::io::copy(&mut file, &mut outfile)
                    .map_err(|e| format!("Failed to extract {}: {}", relative, e))?;
            }
        }

        Ok(())
    }

    fn extract_tar_gz(archive_path: &Path, target: &Path) -> Result<(), String> {
        let file = std::fs::File::open(archive_path)
            .map_err(|e| format!("Failed to open archive: {}", e))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz);

        archive
            .unpack(target)
            .map_err(|e| format!("Failed to extract tar.gz: {}", e))?;

        Ok(())
    }

    fn cache_key(url: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Extract file extension from URL (strip query params first)
        let path_part = url.split('?').next().unwrap_or(url);
        let ext = if path_part.ends_with(".tar.gz") {
            ".tar.gz"
        } else if path_part.ends_with(".tgz") {
            ".tgz"
        } else if let Some(pos) = path_part.rfind('.') {
            let candidate = &path_part[pos..];
            if candidate.len() <= 5 {
                candidate
            } else {
                ".zip"
            }
        } else {
            ".zip"
        };

        format!("{}{}", hash, ext)
    }
}
