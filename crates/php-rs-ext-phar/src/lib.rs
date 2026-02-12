//! PHP phar extension.
//!
//! Implements PHP Archive (PHAR) creation, reading, and extraction.
//! Reference: php-src/ext/phar/
//!
//! PHAR format: stub (PHP code) + manifest + file entries + signature.

use std::collections::HashMap;
use std::fmt;

// ── Constants ───────────────────────────────────────────────────────────────

/// Default PHAR stub that bootstraps the archive.
pub const DEFAULT_STUB: &str = "<?php __HALT_COMPILER(); ?>\r\n";

/// PHAR signature types.
pub const PHAR_SIG_MD5: u32 = 0x0001;
pub const PHAR_SIG_SHA1: u32 = 0x0002;
pub const PHAR_SIG_SHA256: u32 = 0x0004;
pub const PHAR_SIG_SHA512: u32 = 0x0008;

/// Compression flags.
pub const PHAR_COMPRESS_NONE: u32 = 0x0000;
pub const PHAR_COMPRESS_GZ: u32 = 0x1000;
pub const PHAR_COMPRESS_BZ2: u32 = 0x2000;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PharError {
    /// The archive file could not be found/opened.
    FileNotFound(String),
    /// The archive is corrupt or invalid.
    InvalidArchive(String),
    /// The requested entry does not exist.
    EntryNotFound(String),
    /// Extraction failed.
    ExtractionFailed(String),
    /// Stub is invalid.
    InvalidStub(String),
    /// I/O error.
    IoError(String),
}

impl fmt::Display for PharError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PharError::FileNotFound(path) => write!(f, "phar: file not found: {}", path),
            PharError::InvalidArchive(msg) => write!(f, "phar: invalid archive: {}", msg),
            PharError::EntryNotFound(name) => write!(f, "phar: entry not found: {}", name),
            PharError::ExtractionFailed(msg) => write!(f, "phar: extraction failed: {}", msg),
            PharError::InvalidStub(msg) => write!(f, "phar: invalid stub: {}", msg),
            PharError::IoError(msg) => write!(f, "phar: I/O error: {}", msg),
        }
    }
}

// ── PharEntry ───────────────────────────────────────────────────────────────

/// A single entry (file) within a PHAR archive.
#[derive(Debug, Clone)]
pub struct PharEntry {
    /// The local path within the archive.
    pub filename: String,
    /// The uncompressed size in bytes.
    pub uncompressed_size: usize,
    /// The compressed size in bytes (same as uncompressed if not compressed).
    pub compressed_size: usize,
    /// CRC32 checksum of the uncompressed content.
    pub crc32: u32,
    /// The file content (uncompressed).
    pub content: Vec<u8>,
    /// Whether this entry is compressed.
    pub is_compressed: bool,
    /// Compression flags.
    pub compression_flags: u32,
    /// Unix timestamp of last modification.
    pub timestamp: u32,
}

impl PharEntry {
    /// Create a new uncompressed entry.
    pub fn new(filename: &str, content: &[u8]) -> Self {
        let crc = simple_crc32(content);
        PharEntry {
            filename: filename.to_string(),
            uncompressed_size: content.len(),
            compressed_size: content.len(),
            crc32: crc,
            content: content.to_vec(),
            is_compressed: false,
            compression_flags: PHAR_COMPRESS_NONE,
            timestamp: 0,
        }
    }
}

// ── PharArchive ─────────────────────────────────────────────────────────────

/// A PHP Archive (PHAR).
#[derive(Debug, Clone)]
pub struct PharArchive {
    /// The archive filename.
    pub filename: String,
    /// The PHP stub code.
    pub stub: String,
    /// File entries indexed by local path.
    pub entries: HashMap<String, PharEntry>,
    /// API version string.
    pub api_version: String,
    /// Whether the archive is read-only.
    pub is_readonly: bool,
    /// Signature type.
    pub signature_type: u32,
}

impl PharArchive {
    /// Phar::new() -- Create a new (empty) PHAR archive.
    pub fn new(filename: &str) -> Result<Self, PharError> {
        if filename.is_empty() {
            return Err(PharError::InvalidArchive(
                "filename cannot be empty".to_string(),
            ));
        }
        Ok(PharArchive {
            filename: filename.to_string(),
            stub: DEFAULT_STUB.to_string(),
            entries: HashMap::new(),
            api_version: "1.1.0".to_string(),
            is_readonly: false,
            signature_type: PHAR_SIG_SHA1,
        })
    }

    /// Add a file entry to the archive.
    pub fn add_file(&mut self, local_name: &str, content: &[u8]) {
        let entry = PharEntry::new(local_name, content);
        self.entries.insert(local_name.to_string(), entry);
    }

    /// Get a file entry from the archive.
    pub fn get_file(&self, local_name: &str) -> Option<&PharEntry> {
        self.entries.get(local_name)
    }

    /// Remove a file entry from the archive.
    pub fn remove_file(&mut self, local_name: &str) -> bool {
        self.entries.remove(local_name).is_some()
    }

    /// Get the number of entries in the archive.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Get the current stub.
    pub fn get_stub(&self) -> &str {
        &self.stub
    }

    /// Set the stub. The stub must contain `__HALT_COMPILER()`.
    pub fn set_stub(&mut self, stub: &str) -> Result<(), PharError> {
        if !stub.contains("__HALT_COMPILER()") {
            return Err(PharError::InvalidStub(
                "stub must contain __HALT_COMPILER()".to_string(),
            ));
        }
        self.stub = stub.to_string();
        Ok(())
    }

    /// Check whether the archive is valid (has a valid stub and consistent entries).
    pub fn is_valid(&self) -> bool {
        if !self.stub.contains("__HALT_COMPILER()") {
            return false;
        }
        // Verify CRC32 for all entries
        for entry in self.entries.values() {
            let computed_crc = simple_crc32(&entry.content);
            if computed_crc != entry.crc32 {
                return false;
            }
        }
        true
    }

    /// Extract all files to a directory. Returns the list of extracted paths.
    ///
    /// In this in-memory implementation, we collect the extraction results
    /// rather than writing to the filesystem.
    pub fn extract_to(&self, directory: &str) -> Result<Vec<(String, Vec<u8>)>, PharError> {
        if directory.is_empty() {
            return Err(PharError::ExtractionFailed(
                "directory cannot be empty".to_string(),
            ));
        }

        let mut extracted = Vec::new();
        for (name, entry) in &self.entries {
            let path = if directory.ends_with('/') {
                format!("{}{}", directory, name)
            } else {
                format!("{}/{}", directory, name)
            };
            extracted.push((path, entry.content.clone()));
        }
        Ok(extracted)
    }

    /// Get a list of all entry filenames.
    pub fn list_files(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Phar::running() -- Returns the filename of the currently executing PHAR.
    ///
    /// In our implementation this is a static method that returns an empty string
    /// when not running inside a PHAR.
    pub fn running() -> String {
        String::new()
    }

    /// Serialize the archive to bytes (simplified PHAR format).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        // Write stub
        output.extend_from_slice(self.stub.as_bytes());

        // Write manifest
        let manifest = self.build_manifest();
        // Manifest length (4 bytes, LE)
        output.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        output.extend_from_slice(&manifest);

        // Write file contents
        for name in self.list_files() {
            if let Some(entry) = self.entries.get(name) {
                output.extend_from_slice(&entry.content);
            }
        }

        output
    }

    /// Build the manifest portion of the PHAR.
    fn build_manifest(&self) -> Vec<u8> {
        let mut manifest = Vec::new();

        // Number of files (4 bytes LE)
        manifest.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        // API version (2 bytes)
        manifest.extend_from_slice(&[0x11, 0x00]); // 1.1.0

        // Global flags (4 bytes)
        manifest.extend_from_slice(&0u32.to_le_bytes());

        // Alias length (4 bytes) + alias
        manifest.extend_from_slice(&0u32.to_le_bytes());

        // Metadata length (4 bytes)
        manifest.extend_from_slice(&0u32.to_le_bytes());

        // Per-file entries
        for name in self.list_files() {
            if let Some(entry) = self.entries.get(name) {
                // Filename length (4 bytes) + filename
                let name_bytes = name.as_bytes();
                manifest.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                manifest.extend_from_slice(name_bytes);
                // Uncompressed size (4 bytes)
                manifest.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
                // Timestamp (4 bytes)
                manifest.extend_from_slice(&entry.timestamp.to_le_bytes());
                // Compressed size (4 bytes)
                manifest.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
                // CRC32 (4 bytes)
                manifest.extend_from_slice(&entry.crc32.to_le_bytes());
                // Flags (4 bytes)
                manifest.extend_from_slice(&entry.compression_flags.to_le_bytes());
                // Metadata length (4 bytes)
                manifest.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        manifest
    }
}

// ── CRC32 ───────────────────────────────────────────────────────────────────

/// Simple CRC32 implementation (IEEE/ISO 3309).
fn simple_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phar_new() {
        let phar = PharArchive::new("test.phar").unwrap();
        assert_eq!(phar.filename, "test.phar");
        assert_eq!(phar.count(), 0);
        assert!(phar.get_stub().contains("__HALT_COMPILER()"));
    }

    #[test]
    fn test_phar_new_empty_filename() {
        let result = PharArchive::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_phar_add_and_get_file() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("index.php", b"<?php echo 'hello'; ?>");
        assert_eq!(phar.count(), 1);

        let entry = phar.get_file("index.php").unwrap();
        assert_eq!(entry.filename, "index.php");
        assert_eq!(entry.content, b"<?php echo 'hello'; ?>");
        assert_eq!(entry.uncompressed_size, 22);
        assert!(!entry.is_compressed);
    }

    #[test]
    fn test_phar_get_file_nonexistent() {
        let phar = PharArchive::new("test.phar").unwrap();
        assert!(phar.get_file("nope.php").is_none());
    }

    #[test]
    fn test_phar_remove_file() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("a.php", b"a");
        phar.add_file("b.php", b"b");
        assert_eq!(phar.count(), 2);

        assert!(phar.remove_file("a.php"));
        assert_eq!(phar.count(), 1);
        assert!(phar.get_file("a.php").is_none());
        assert!(phar.get_file("b.php").is_some());

        // Removing nonexistent returns false
        assert!(!phar.remove_file("nonexistent.php"));
    }

    #[test]
    fn test_phar_set_stub() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        let custom_stub = "#!/usr/bin/php\n<?php __HALT_COMPILER(); ?>\n";
        assert!(phar.set_stub(custom_stub).is_ok());
        assert_eq!(phar.get_stub(), custom_stub);
    }

    #[test]
    fn test_phar_set_stub_invalid() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        let result = phar.set_stub("<?php echo 'no halt'; ?>");
        assert!(result.is_err());
        assert!(matches!(result, Err(PharError::InvalidStub(_))));
    }

    #[test]
    fn test_phar_is_valid() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("test.txt", b"hello world");
        assert!(phar.is_valid());
    }

    #[test]
    fn test_phar_is_valid_corrupt_crc() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("test.txt", b"hello world");
        // Corrupt the CRC
        phar.entries.get_mut("test.txt").unwrap().crc32 = 0xDEADBEEF;
        assert!(!phar.is_valid());
    }

    #[test]
    fn test_phar_extract_to() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("src/main.php", b"<?php main();");
        phar.add_file("lib/util.php", b"<?php util();");

        let extracted = phar.extract_to("/tmp/output").unwrap();
        assert_eq!(extracted.len(), 2);

        // Check that paths are correctly built
        let paths: Vec<&str> = extracted.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"/tmp/output/src/main.php"));
        assert!(paths.contains(&"/tmp/output/lib/util.php"));
    }

    #[test]
    fn test_phar_extract_to_empty_dir() {
        let phar = PharArchive::new("test.phar").unwrap();
        let result = phar.extract_to("");
        assert!(result.is_err());
    }

    #[test]
    fn test_phar_list_files() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("c.php", b"c");
        phar.add_file("a.php", b"a");
        phar.add_file("b.php", b"b");

        let files = phar.list_files();
        assert_eq!(files, vec!["a.php", "b.php", "c.php"]);
    }

    #[test]
    fn test_phar_running() {
        assert_eq!(PharArchive::running(), "");
    }

    #[test]
    fn test_phar_to_bytes_roundtrip() {
        let mut phar = PharArchive::new("test.phar").unwrap();
        phar.add_file("hello.txt", b"Hello, PHAR!");

        let bytes = phar.to_bytes();
        // Should start with the stub
        assert!(bytes.starts_with(DEFAULT_STUB.as_bytes()));
        // Should contain our file content
        assert!(bytes.windows(12).any(|w| w == b"Hello, PHAR!"));
    }

    #[test]
    fn test_phar_crc32() {
        // Known CRC32 value for "Hello, World!"
        let crc = simple_crc32(b"Hello, World!");
        // This should be 0xEC4AC3D0 for standard CRC32
        assert_eq!(crc, 0xEC4AC3D0);
    }

    #[test]
    fn test_phar_multiple_operations() {
        let mut phar = PharArchive::new("app.phar").unwrap();

        // Add files
        phar.add_file("index.php", b"<?php require 'vendor/autoload.php';");
        phar.add_file("src/App.php", b"<?php class App {}");
        assert_eq!(phar.count(), 2);

        // Overwrite a file
        phar.add_file("index.php", b"<?php require_once 'bootstrap.php';");
        assert_eq!(phar.count(), 2);

        let entry = phar.get_file("index.php").unwrap();
        assert_eq!(entry.content, b"<?php require_once 'bootstrap.php';");
    }

    #[test]
    fn test_phar_entry_crc_consistent() {
        let entry = PharEntry::new("test.txt", b"content");
        assert_eq!(entry.crc32, simple_crc32(b"content"));
        assert_eq!(entry.uncompressed_size, 7);
        assert_eq!(entry.compressed_size, 7);
    }
}
