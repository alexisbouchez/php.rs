//! Deployment flow — extract slugs, manage releases, zero-downtime deploys.
//!
//! Deployment steps:
//! 1. Extract tarball to /apps/{app_id}/releases/{version}/
//! 2. Symlink /apps/{app_id}/current → new release
//! 3. Start new app process pointing to new release
//! 4. Wait for /_ready
//! 5. Stop old process (SIGTERM)
//! 6. Clean up old releases (keep last N)

use std::path::Path;
use std::time::Duration;

use crate::process::{self, StartResult};
use crate::state::{self, AppState, PlatformState, Release};

/// Number of old releases to keep after cleanup.
const KEEP_RELEASES: usize = 5;

/// Deploy a tarball to an app.
pub fn deploy(
    state: &mut PlatformState,
    app_name: &str,
    tarball_path: &str,
    ready_timeout: Duration,
) -> Result<u64, String> {
    // Verify tarball exists.
    if !Path::new(tarball_path).exists() {
        return Err(format!("Tarball not found: {}", tarball_path));
    }

    let app = state.apps.get(app_name)
        .ok_or_else(|| format!("App '{}' not found", app_name))?
        .clone();

    // Determine next version.
    let version = app.releases.iter().map(|r| r.version).max().unwrap_or(0) + 1;

    // Create release directory.
    let releases_dir = state.app_releases_dir(app_name);
    let release_dir = releases_dir.join(version.to_string());
    std::fs::create_dir_all(&release_dir)
        .map_err(|e| format!("Cannot create release dir {}: {}", release_dir.display(), e))?;

    // Extract tarball.
    extract_tarball(tarball_path, &release_dir)?;

    // Update symlink: current → new release.
    let current_link = state.app_current_link(app_name);
    update_symlink(&release_dir, &current_link)?;

    // Record the old PID before restarting.
    let old_pid = app.pid;

    // Update app state to point to new release.
    let app = state.apps.get_mut(app_name).unwrap();
    app.root = current_link.to_string_lossy().to_string();
    app.releases.push(Release {
        version,
        path: release_dir.to_string_lossy().to_string(),
        deployed_at: state::now_iso8601(),
    });
    app.current_release = Some(version);

    // Start new process with updated root.
    let new_app = app.clone();
    match process::start_app(&new_app) {
        StartResult::Started(pid) => {
            let app = state.apps.get_mut(app_name).unwrap();
            app.pid = Some(pid);
            eprintln!("  New process started (PID {})", pid);
        }
        StartResult::Failed(e) => {
            return Err(format!("Failed to start new process: {}", e));
        }
        StartResult::AlreadyRunning(_) => {
            // Shouldn't happen since we're deploying a new version.
            // Stop the old one and start fresh.
        }
    }

    // Wait for the new process to become ready.
    let new_app = state.apps.get(app_name).unwrap();
    eprintln!("  Waiting for app to become ready...");
    if !process::wait_for_ready(new_app, ready_timeout) {
        // New process didn't become ready — roll back.
        let app = state.apps.get(app_name).unwrap();
        if let Some(pid) = app.pid {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
        }
        let app = state.apps.get_mut(app_name).unwrap();
        app.pid = old_pid.map(|p| p);
        return Err("New process did not become ready within timeout. Rolled back.".into());
    }
    eprintln!("  App is ready!");

    // Stop the old process.
    if let Some(old_pid) = old_pid {
        if state::process_alive(old_pid) {
            eprintln!("  Stopping old process (PID {})...", old_pid);
            let old_app = AppState {
                pid: Some(old_pid),
                ..new_app.clone()
            };
            process::stop_app(&old_app, Duration::from_secs(10));
        }
    }

    // Cleanup old releases.
    cleanup_releases(state, app_name);

    // Save state.
    state.save()?;

    Ok(version)
}

/// Extract a tarball to a destination directory.
fn extract_tarball(tarball_path: &str, dest: &Path) -> Result<(), String> {
    let status = std::process::Command::new("tar")
        .args([
            "xzf",
            tarball_path,
            "-C",
            &dest.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    if !status.success() {
        return Err(format!("tar extraction failed with status {}", status));
    }
    Ok(())
}

/// Atomically update a symlink (remove old, create new).
fn update_symlink(target: &Path, link: &Path) -> Result<(), String> {
    // Remove existing symlink or file.
    if link.exists() || link.symlink_metadata().is_ok() {
        std::fs::remove_file(link)
            .or_else(|_| std::fs::remove_dir(link))
            .map_err(|e| format!("Cannot remove old symlink {}: {}", link.display(), e))?;
    }

    // Create parent directory if needed.
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {}", parent.display(), e))?;
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link)
        .map_err(|e| format!("Cannot create symlink {} → {}: {}", link.display(), target.display(), e))?;

    #[cfg(not(unix))]
    return Err("Symlinks only supported on Unix".into());

    Ok(())
}

/// Remove old releases, keeping the most recent N.
fn cleanup_releases(state: &mut PlatformState, app_name: &str) {
    let app = match state.apps.get_mut(app_name) {
        Some(a) => a,
        None => return,
    };

    if app.releases.len() <= KEEP_RELEASES {
        return;
    }

    // Sort by version ascending.
    app.releases.sort_by_key(|r| r.version);

    // Remove oldest releases beyond the keep count.
    let to_remove = app.releases.len() - KEEP_RELEASES;
    let removed: Vec<Release> = app.releases.drain(..to_remove).collect();

    for release in &removed {
        let path = Path::new(&release.path);
        if path.exists() {
            if let Err(e) = std::fs::remove_dir_all(path) {
                eprintln!("  Warning: cannot remove old release {}: {}", release.path, e);
            } else {
                eprintln!("  Cleaned up release v{}", release.version);
            }
        }
    }
}

/// Deploy from a local directory (no tarball — just point to existing source).
pub fn deploy_local(
    state: &mut PlatformState,
    app_name: &str,
    source_dir: &str,
) -> Result<(), String> {
    let app = state.apps.get_mut(app_name)
        .ok_or_else(|| format!("App '{}' not found", app_name))?;

    let path = Path::new(source_dir);
    if !path.exists() {
        return Err(format!("Directory not found: {}", source_dir));
    }

    app.root = path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();

    state.save()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_extract_tarball_not_found() {
        let dir = std::env::temp_dir().join("phprs-test-extract");
        let _ = std::fs::create_dir_all(&dir);
        let result = extract_tarball("/nonexistent/file.tar.gz", &dir);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_symlink() {
        let dir = std::env::temp_dir().join("phprs-test-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("target_dir");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("test.txt"), "hello").unwrap();

        let link = dir.join("current");
        update_symlink(&target, &link).unwrap();

        assert!(link.exists());
        assert!(link.join("test.txt").exists());

        // Update to a new target.
        let target2 = dir.join("target_dir_2");
        std::fs::create_dir_all(&target2).unwrap();
        std::fs::write(target2.join("test2.txt"), "world").unwrap();

        update_symlink(&target2, &link).unwrap();
        assert!(link.join("test2.txt").exists());
        assert!(!link.join("test.txt").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_releases() {
        let mut state = PlatformState {
            apps: HashMap::new(),
            next_port: 8001,
            apps_dir: std::env::temp_dir().join("phprs-test-cleanup").to_string_lossy().to_string(),
        };
        state.apps.insert("myapp".into(), AppState {
            name: "myapp".into(),
            root: "/tmp".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port: 8001,
            pid: None,
            env: HashMap::new(),
            workers: 0,
            created_at: "2024-01-01T00:00:00Z".into(),
            releases: (1..=10).map(|i| Release {
                version: i,
                path: format!("/nonexistent/release/{}", i),
                deployed_at: "2024-01-01T00:00:00Z".into(),
            }).collect(),
            current_release: Some(10),
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });

        cleanup_releases(&mut state, "myapp");
        assert_eq!(state.apps["myapp"].releases.len(), KEEP_RELEASES);
        // Should keep versions 6-10.
        assert_eq!(state.apps["myapp"].releases[0].version, 6);
        assert_eq!(state.apps["myapp"].releases[4].version, 10);
    }

    #[test]
    fn test_deploy_local() {
        let dir = std::env::temp_dir().join(format!("phprs-test-deploy-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state_dir_path = dir.join("state");
        let source_dir = dir.join("source");
        std::fs::create_dir_all(&state_dir_path).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("index.php"), "<?php echo 'hi';").unwrap();

        let state_file = state_dir_path.join("state.json");
        let mut state = PlatformState::load_from(&state_file);
        state.apps_dir = dir.join("apps").to_string_lossy().to_string();
        let port = state.allocate_port();
        state.apps.insert("localapp".into(), AppState {
            name: "localapp".into(),
            root: "/old/path".into(),
            entry: "index.php".into(),
            docroot: ".".into(),
            port,
            pid: None,
            env: HashMap::new(),
            workers: 0,
            created_at: state::now_iso8601(),
            releases: vec![],
            current_release: None,
        scaling: Default::default(),
        instances: vec![],
        cron_jobs: vec![],
        worker_configs: vec![],
        });
        state.save_to(&state_file).unwrap();

        deploy_local(&mut state, "localapp", source_dir.to_str().unwrap()).unwrap();
        let app = &state.apps["localapp"];
        assert!(app.root.contains("phprs-test-deploy-local"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
