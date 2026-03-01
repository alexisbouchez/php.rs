//! Opcode cache serialization — save and load compiled op arrays to/from disk.
//!
//! This module provides functions to serialize a collection of compiled
//! [`ZOpArray`]s to disk and load them back, skipping the parse + compile
//! phases entirely. The cache format is a JSON file containing a map of
//! file paths to their compiled op arrays along with source file mtimes
//! for invalidation.

use crate::ZOpArray;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single cached entry: the file's modification time and its compiled op array.
#[derive(Serialize, Deserialize)]
pub struct CachedOpArray {
    /// Source file modification time (seconds since epoch).
    pub mtime: u64,
    /// The compiled opcode array.
    pub op_array: ZOpArray,
}

/// The full opcache file: a map of file paths to cached entries.
#[derive(Serialize, Deserialize)]
pub struct OpcacheFile {
    /// Version marker for forward compatibility.
    pub version: u32,
    /// Cached entries keyed by absolute file path.
    pub entries: HashMap<String, CachedOpArray>,
}

impl OpcacheFile {
    /// Create a new empty opcache file.
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
        }
    }

    /// Add a compiled op array to the cache.
    pub fn add(&mut self, file_path: String, mtime: u64, op_array: ZOpArray) {
        self.entries.insert(
            file_path,
            CachedOpArray { mtime, op_array },
        );
    }

    /// Save the cache to a file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize opcache: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write opcache to {}: {}", path.display(), e))
    }

    /// Load the cache from a file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read opcache from {}: {}", path.display(), e))?;
        let cache: OpcacheFile = serde_json::from_slice(&data)
            .map_err(|e| format!("Failed to deserialize opcache: {}", e))?;
        if cache.version != 1 {
            return Err(format!(
                "Unsupported opcache version: {} (expected 1)",
                cache.version
            ));
        }
        Ok(cache)
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for OpcacheFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile all PHP files in a directory tree and save to an opcache file.
///
/// Walks the directory recursively, compiles each `.php` file, and stores
/// the result in the opcache. Returns the number of files compiled.
pub fn compile_directory(root: &Path, output: &Path) -> Result<usize, String> {
    let mut cache = OpcacheFile::new();
    let mut count = 0;

    walk_php_files(root, &mut |file_path| {
        let abs_path = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf());
        let path_str = abs_path.to_string_lossy().to_string();

        let mtime = std::fs::metadata(&abs_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let source = match std::fs::read_to_string(&abs_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: cannot read {}: {}", path_str, e);
                return;
            }
        };

        match crate::compile_file(&source, &path_str) {
            Ok(op_array) => {
                cache.add(path_str, mtime, op_array);
                count += 1;
            }
            Err(e) => {
                eprintln!("Warning: compilation error in {}: {}", abs_path.display(), e);
            }
        }
    })?;

    cache.save(output)?;
    Ok(count)
}

/// Walk a directory tree and call `f` for each `.php` file found.
fn walk_php_files(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("Cannot read directory {}: {}", dir.display(), e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip vendor and hidden directories for performance.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "vendor" || name.starts_with('.') {
                continue;
            }
            walk_php_files(&path, f)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "php" {
                f(&path);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile, ZOpArray};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "phprs-opcache-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_opcache_roundtrip() {
        let dir = test_dir();
        let cache_path = dir.join("opcache.json");

        // Compile a simple PHP script.
        let source = "<?php echo 'Hello';";
        let op_array = compile(source).unwrap();

        // Save to cache.
        let mut cache = OpcacheFile::new();
        cache.add("/tmp/test.php".into(), 1234567890, op_array.clone());
        cache.save(&cache_path).unwrap();

        // Load from cache.
        let loaded = OpcacheFile::load(&cache_path).unwrap();
        assert_eq!(loaded.len(), 1);

        let entry = loaded.entries.get("/tmp/test.php").unwrap();
        assert_eq!(entry.mtime, 1234567890);
        assert_eq!(entry.op_array.opcodes.len(), op_array.opcodes.len());
        assert_eq!(entry.op_array.literals.len(), op_array.literals.len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opcache_multiple_entries() {
        let dir = test_dir();
        let cache_path = dir.join("opcache.json");

        let mut cache = OpcacheFile::new();
        for i in 0..5 {
            let source = format!("<?php echo {};", i);
            let oa = compile(&source).unwrap();
            cache.add(format!("/tmp/test{}.php", i), 100 + i as u64, oa);
        }

        assert_eq!(cache.len(), 5);
        cache.save(&cache_path).unwrap();

        let loaded = OpcacheFile::load(&cache_path).unwrap();
        assert_eq!(loaded.len(), 5);
        assert!(loaded.entries.contains_key("/tmp/test0.php"));
        assert!(loaded.entries.contains_key("/tmp/test4.php"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opcache_empty() {
        let dir = test_dir();
        let cache_path = dir.join("empty.json");

        let cache = OpcacheFile::new();
        assert!(cache.is_empty());
        cache.save(&cache_path).unwrap();

        let loaded = OpcacheFile::load(&cache_path).unwrap();
        assert!(loaded.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opcache_with_functions() {
        let dir = test_dir();
        let cache_path = dir.join("funcs.json");

        let source = r#"<?php
function greet($name) {
    return "Hello, " . $name;
}
echo greet("World");
"#;
        let oa = compile(source).unwrap();
        assert!(!oa.dynamic_func_defs.is_empty());

        let mut cache = OpcacheFile::new();
        cache.add("/tmp/funcs.php".into(), 9999, oa.clone());
        cache.save(&cache_path).unwrap();

        let loaded = OpcacheFile::load(&cache_path).unwrap();
        let entry = loaded.entries.get("/tmp/funcs.php").unwrap();
        assert_eq!(
            entry.op_array.dynamic_func_defs.len(),
            oa.dynamic_func_defs.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opcache_with_classes() {
        let dir = test_dir();
        let cache_path = dir.join("classes.json");

        let source = r#"<?php
class Greeter {
    public string $name;
    public function greet(): string {
        return "Hello, " . $this->name;
    }
}
$g = new Greeter();
$g->name = "World";
echo $g->greet();
"#;
        let oa = compile(source).unwrap();
        assert!(!oa.class_metadata.is_empty());

        let mut cache = OpcacheFile::new();
        cache.add("/tmp/classes.php".into(), 5555, oa.clone());
        cache.save(&cache_path).unwrap();

        let loaded = OpcacheFile::load(&cache_path).unwrap();
        let entry = loaded.entries.get("/tmp/classes.php").unwrap();
        assert_eq!(
            entry.op_array.class_metadata.len(),
            oa.class_metadata.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compile_directory() {
        let dir = test_dir();
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();

        // Create some PHP files.
        std::fs::write(src_dir.join("index.php"), "<?php echo 'index';").unwrap();
        std::fs::write(src_dir.join("util.php"), "<?php function f() {}").unwrap();
        std::fs::write(src_dir.join("readme.txt"), "not php").unwrap();

        let cache_path = dir.join("opcache.json");
        let count = compile_directory(&src_dir, &cache_path).unwrap();
        assert_eq!(count, 2);

        let loaded = OpcacheFile::load(&cache_path).unwrap();
        assert_eq!(loaded.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opcache_load_nonexistent() {
        let result = OpcacheFile::load(Path::new("/nonexistent/opcache.json"));
        assert!(result.is_err());
    }
}
