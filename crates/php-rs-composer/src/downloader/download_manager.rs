use super::archive_downloader::ArchiveDownloader;
use super::git_downloader::GitDownloader;
use super::path_downloader::PathDownloader;
use crate::package::Package;
use std::path::{Path, PathBuf};

/// Routes packages to the appropriate downloader.
pub struct DownloadManager {
    cache_dir: PathBuf,
    archive: ArchiveDownloader,
    git: GitDownloader,
    #[allow(dead_code)]
    path: PathDownloader,
    max_concurrent: usize,
}

impl DownloadManager {
    pub fn new(cache_dir: &Path) -> Self {
        DownloadManager {
            cache_dir: cache_dir.to_path_buf(),
            archive: ArchiveDownloader::new(cache_dir),
            git: GitDownloader,
            path: PathDownloader,
            max_concurrent: 12,
        }
    }

    /// Set maximum concurrent downloads.
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max;
    }

    /// Download a single package to a target directory.
    pub async fn download(&self, package: &Package, target: &Path) -> Result<(), String> {
        // Prefer dist over source
        if let Some(dist) = &package.dist {
            match dist.dist_type.as_str() {
                "zip" | "tar" | "gzip" | "xz" => {
                    return self
                        .archive
                        .download(&dist.url, target, dist.shasum.as_deref())
                        .await;
                }
                _ => {}
            }
        }

        if let Some(source) = &package.source {
            match source.source_type.as_str() {
                "git" => {
                    return self
                        .git
                        .download(&source.url, &source.reference, target)
                        .await;
                }
                _ => {}
            }
        }

        Err(format!(
            "No download source available for {} {}",
            package.name, package.version
        ))
    }

    /// Download multiple packages in parallel with progress reporting.
    pub async fn download_parallel(
        &self,
        downloads: &[(Package, PathBuf)],
        progress: Option<&dyn Fn(usize, usize, &str)>,
    ) -> Result<(), String> {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let total = downloads.len();
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();

        for (pkg, target) in downloads {
            let sem = semaphore.clone();
            let pkg = pkg.clone();
            let pkg_name = pkg.name.clone();
            let target = target.clone();
            let completed = completed.clone();
            let cache_dir = self.cache_dir.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;

                let dm = DownloadManager::new(&cache_dir);
                let result = dm.download(&pkg, &target).await;

                completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                result
            });

            handles.push((pkg_name, handle));
        }

        let mut errors = Vec::new();
        for (name, handle) in handles {
            match handle.await {
                Ok(Ok(())) => {
                    let done = completed.load(std::sync::atomic::Ordering::Relaxed);
                    if let Some(progress_fn) = progress {
                        progress_fn(done, total, &name);
                    }
                }
                Ok(Err(e)) => errors.push(format!("{}: {}", name, e)),
                Err(e) => errors.push(format!("{}: task failed: {}", name, e)),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Failed to download {} packages:\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            ))
        }
    }
}
