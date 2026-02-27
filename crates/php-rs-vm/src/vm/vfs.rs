//! Virtual filesystem abstraction — extracted from vm.rs.
//!
//! Delegates to VFS when available, otherwise to std::fs (native only).

use super::{Vm, VmResult};
use crate::value::{PhpArray, Value};

impl Vm {
    // === Filesystem helper methods ===
    // These delegate to VFS when available, otherwise to std::fs (native only).

    /// Read a file's contents as bytes.
    pub(crate) fn vm_read_file(&self, path: &str) -> std::io::Result<Vec<u8>> {
        // php://input — return raw request body
        if path == "php://input" {
            return Ok(self
                .raw_input_body
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec());
        }
        if let Some(ref vfs) = self.vfs {
            let vfs = vfs
                .read()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            Ok(vfs.read_file(path)?.to_vec())
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::fs::read(path)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Read a file's contents as a PHP string (binary-safe).
    /// Tries UTF-8 first (for source code, text files); falls back to Latin-1
    /// mapping for binary files (images, etc.) so no data is lost.
    pub(crate) fn vm_read_to_string(&self, path: &str) -> std::io::Result<String> {
        let bytes = self.vm_read_file(path)?;
        match String::from_utf8(bytes) {
            Ok(s) => Ok(s),
            Err(e) => Ok(e.into_bytes().iter().map(|&b| b as char).collect()),
        }
    }

    /// Write data to a file.
    pub(crate) fn vm_write_file(&self, path: &str, data: &[u8]) -> std::io::Result<()> {
        if let Some(ref vfs) = self.vfs {
            let mut vfs = vfs
                .write()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.write_file(path, data)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::fs::write(path, data)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Check if a path exists.
    pub(crate) fn vm_file_exists(&self, path: &str) -> bool {
        if let Some(ref vfs) = self.vfs {
            if let Ok(vfs) = vfs.read() {
                return vfs.exists(path);
            }
            false
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::path::Path::new(path).exists()
            }
            #[cfg(target_arch = "wasm32")]
            {
                false
            }
        }
    }

    /// Check if a path is a file.
    pub(crate) fn vm_is_file(&self, path: &str) -> bool {
        if let Some(ref vfs) = self.vfs {
            if let Ok(vfs) = vfs.read() {
                return vfs.is_file(path);
            }
            false
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::path::Path::new(path).is_file()
            }
            #[cfg(target_arch = "wasm32")]
            {
                false
            }
        }
    }

    /// Check if a path is a directory.
    pub(crate) fn vm_is_dir(&self, path: &str) -> bool {
        if let Some(ref vfs) = self.vfs {
            if let Ok(vfs) = vfs.read() {
                return vfs.is_dir(path);
            }
            false
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::path::Path::new(path).is_dir()
            }
            #[cfg(target_arch = "wasm32")]
            {
                false
            }
        }
    }

    /// Read directory entries.
    pub(crate) fn vm_read_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
        if let Some(ref vfs) = self.vfs {
            let vfs = vfs
                .read()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.read_dir(path)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let mut entries = Vec::new();
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    if let Some(name) = entry.file_name().to_str() {
                        entries.push(name.to_string());
                    }
                }
                Ok(entries)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Remove a file.
    pub(crate) fn vm_remove_file(&self, path: &str) -> std::io::Result<()> {
        if let Some(ref vfs) = self.vfs {
            let mut vfs = vfs
                .write()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.remove_file(path)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::fs::remove_file(path)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Create a directory.
    pub(crate) fn vm_mkdir(&self, path: &str, recursive: bool) -> std::io::Result<()> {
        if let Some(ref vfs) = self.vfs {
            let mut vfs = vfs
                .write()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.mkdir(path, recursive)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                if recursive {
                    std::fs::create_dir_all(path)
                } else {
                    std::fs::create_dir(path)
                }
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Remove a directory.
    pub(crate) fn vm_rmdir(&self, path: &str) -> std::io::Result<()> {
        if let Some(ref vfs) = self.vfs {
            let mut vfs = vfs
                .write()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.rmdir(path)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::fs::remove_dir(path)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Rename a file or directory.
    pub(crate) fn vm_rename(&self, from: &str, to: &str) -> std::io::Result<()> {
        if let Some(ref vfs) = self.vfs {
            let mut vfs = vfs
                .write()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.rename(from, to)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::fs::rename(from, to)
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Get file metadata (size).
    pub(crate) fn vm_file_size(&self, path: &str) -> std::io::Result<u64> {
        if let Some(ref vfs) = self.vfs {
            let vfs = vfs
                .read()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "VFS lock poisoned"))?;
            vfs.file_size(path)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            {
                Ok(std::fs::metadata(path)?.len())
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "No filesystem available",
                ))
            }
        }
    }

    /// Get partial output accumulated so far (useful for displaying output even on error).
    /// Returns only committed (non-buffered) output.
    pub fn get_output(&self) -> &str {
        &self.output
    }

    /// Set $_SESSION in the main (bottom-most) frame's CVs.
    pub(crate) fn set_session_cv(&mut self, data: crate::value::PhpArray) {
        if let Some(frame) = self.call_stack.first_mut() {
            if let Some(oa) = self.op_arrays.first() {
                if let Some(idx) = oa.vars.iter().position(|v| v == "_SESSION") {
                    if idx < frame.cvs.len() {
                        frame.cvs[idx] = Value::Array(data);
                    }
                }
            }
        }
    }

    /// Read $_SESSION from the main (bottom-most) frame's CVs.
    pub(crate) fn get_session_cv(&self) -> Option<crate::value::PhpArray> {
        let frame = self.call_stack.first()?;
        let oa = self.op_arrays.first()?;
        let idx = oa.vars.iter().position(|v| v == "_SESSION")?;
        match frame.cvs.get(idx) {
            Some(Value::Array(a)) => Some(a.clone()),
            _ => None,
        }
    }

    /// Generate a random session ID (32 hex chars).
    pub(crate) fn generate_session_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        // Mix time + a counter to avoid collisions
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{:016x}{:016x}", t as u64, c)
    }

    /// Return the session file path for the given ID.
    pub(crate) fn session_file_path(&self, id: &str) -> String {
        format!(
            "{}/sess_{}",
            self.session_save_path.trim_end_matches('/'),
            id
        )
    }
}
