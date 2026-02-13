//! PHP zip extension.
//!
//! Implements ZIP archive handling (creation, reading, extraction).
//! Reference: php-src/ext/zip/
//!
//! Implements local file headers, central directory, and end of central directory
//! structures for the ZIP format. Supports STORE (no compression) method.

use std::collections::HashMap;
use std::fmt;

// ── Constants ───────────────────────────────────────────────────────────────

/// Compression method: stored (no compression).
pub const ZIP_CM_STORE: u16 = 0;
/// Compression method: deflate.
pub const ZIP_CM_DEFLATE: u16 = 8;

/// ZIP local file header signature.
pub const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034B50;
/// ZIP central directory file header signature.
pub const ZIP_CENTRAL_DIR_SIG: u32 = 0x02014B50;
/// ZIP end of central directory record signature.
pub const ZIP_END_CENTRAL_DIR_SIG: u32 = 0x06054B50;

/// Error constants matching PHP's ZipArchive::ER_* constants.
pub const ZIP_ER_OK: i32 = 0;
pub const ZIP_ER_NOENT: i32 = 9;
pub const ZIP_ER_EXISTS: i32 = 10;
pub const ZIP_ER_INVAL: i32 = 18;
pub const ZIP_ER_MEMORY: i32 = 14;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ZipError {
    /// File not found.
    FileNotFound(String),
    /// Invalid archive.
    InvalidArchive(String),
    /// Entry not found.
    EntryNotFound(String),
    /// Extraction failed.
    ExtractionFailed(String),
    /// CRC mismatch.
    CrcMismatch { expected: u32, actual: u32 },
    /// I/O error.
    IoError(String),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipError::FileNotFound(path) => write!(f, "No such file: {}", path),
            ZipError::InvalidArchive(msg) => write!(f, "Invalid ZIP archive: {}", msg),
            ZipError::EntryNotFound(name) => write!(f, "Entry not found: {}", name),
            ZipError::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
            ZipError::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected {:08X}, got {:08X}",
                    expected, actual
                )
            }
            ZipError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

// ── ZipStat ─────────────────────────────────────────────────────────────────

/// Statistics for a single ZIP entry (analogous to PHP's ZipArchive::statName result).
#[derive(Debug, Clone, PartialEq)]
pub struct ZipStat {
    /// Entry name.
    pub name: String,
    /// Index within the archive.
    pub index: usize,
    /// Uncompressed size.
    pub size: usize,
    /// Compressed size.
    pub comp_size: usize,
    /// CRC32 checksum.
    pub crc: u32,
    /// Compression method.
    pub comp_method: u16,
    /// Last modification time (Unix timestamp).
    pub mtime: u32,
}

// ── ZipEntry ────────────────────────────────────────────────────────────────

/// A single file entry within a ZIP archive.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// The file name (path within the archive).
    pub name: String,
    /// Uncompressed size.
    pub size: usize,
    /// Compressed size (same as size for STORE method).
    pub compressed_size: usize,
    /// CRC32 of uncompressed data.
    pub crc32: u32,
    /// Compression method (ZIP_CM_STORE or ZIP_CM_DEFLATE).
    pub method: u16,
    /// File content (uncompressed).
    pub content: Vec<u8>,
    /// Last modification time (Unix timestamp).
    pub mtime: u32,
    /// Comment for this entry.
    pub comment: String,
}

// ── ZipArchive ──────────────────────────────────────────────────────────────

/// A ZIP archive, analogous to PHP's ZipArchive class.
#[derive(Debug, Clone)]
pub struct ZipArchive {
    /// Archive filename (may be empty for in-memory archives).
    pub filename: String,
    /// Ordered list of entry names (preserves insertion order).
    entry_names: Vec<String>,
    /// Map from entry name to entry data.
    entries: HashMap<String, ZipEntry>,
    /// Archive comment.
    pub comment: String,
    /// Whether the archive is open.
    is_open: bool,
}

impl ZipArchive {
    /// ZipArchive::open() -- Open or create a new ZIP archive.
    pub fn open(filename: &str) -> Result<Self, ZipError> {
        if filename.is_empty() {
            return Err(ZipError::InvalidArchive("filename is empty".to_string()));
        }
        Ok(ZipArchive {
            filename: filename.to_string(),
            entry_names: Vec::new(),
            entries: HashMap::new(),
            comment: String::new(),
            is_open: true,
        })
    }

    /// Create a new empty in-memory ZIP archive.
    pub fn new() -> Self {
        ZipArchive {
            filename: String::new(),
            entry_names: Vec::new(),
            entries: HashMap::new(),
            comment: String::new(),
            is_open: true,
        }
    }

    /// addFromString() -- Add a file to the archive from a string/bytes.
    pub fn add_from_string(&mut self, name: &str, content: &[u8]) {
        let crc = crc32(content);
        let entry = ZipEntry {
            name: name.to_string(),
            size: content.len(),
            compressed_size: content.len(),
            crc32: crc,
            method: ZIP_CM_STORE,
            content: content.to_vec(),
            mtime: 0,
            comment: String::new(),
        };

        if self.entries.contains_key(name) {
            // Replace existing entry
            self.entries.insert(name.to_string(), entry);
        } else {
            self.entry_names.push(name.to_string());
            self.entries.insert(name.to_string(), entry);
        }
    }

    /// getFromName() -- Read a file from the archive by name.
    pub fn get_from_name(&self, name: &str) -> Option<Vec<u8>> {
        self.entries.get(name).map(|e| e.content.clone())
    }

    /// getFromIndex() -- Read a file from the archive by index.
    pub fn get_from_index(&self, index: usize) -> Option<Vec<u8>> {
        self.entry_names
            .get(index)
            .and_then(|name| self.entries.get(name))
            .map(|e| e.content.clone())
    }

    /// deleteName() -- Delete an entry by name.
    pub fn delete_name(&mut self, name: &str) -> bool {
        if self.entries.remove(name).is_some() {
            self.entry_names.retain(|n| n != name);
            true
        } else {
            false
        }
    }

    /// numFiles() -- Get the number of entries.
    pub fn num_files(&self) -> usize {
        self.entry_names.len()
    }

    /// statName() -- Get entry statistics by name.
    pub fn stat_name(&self, name: &str) -> Option<ZipStat> {
        let index = self.entry_names.iter().position(|n| n == name)?;
        let entry = self.entries.get(name)?;
        Some(ZipStat {
            name: entry.name.clone(),
            index,
            size: entry.size,
            comp_size: entry.compressed_size,
            crc: entry.crc32,
            comp_method: entry.method,
            mtime: entry.mtime,
        })
    }

    /// statIndex() -- Get entry statistics by index.
    pub fn stat_index(&self, index: usize) -> Option<ZipStat> {
        let name = self.entry_names.get(index)?;
        let entry = self.entries.get(name)?;
        Some(ZipStat {
            name: entry.name.clone(),
            index,
            size: entry.size,
            comp_size: entry.compressed_size,
            crc: entry.crc32,
            comp_method: entry.method,
            mtime: entry.mtime,
        })
    }

    /// getNameIndex() -- Get the name of an entry by index.
    pub fn get_name_index(&self, index: usize) -> Option<&str> {
        self.entry_names.get(index).map(|s| s.as_str())
    }

    /// renameName() -- Rename an entry.
    pub fn rename_name(&mut self, old_name: &str, new_name: &str) -> bool {
        if let Some(mut entry) = self.entries.remove(old_name) {
            entry.name = new_name.to_string();
            self.entries.insert(new_name.to_string(), entry);
            if let Some(pos) = self.entry_names.iter().position(|n| n == old_name) {
                self.entry_names[pos] = new_name.to_string();
            }
            true
        } else {
            false
        }
    }

    /// setCompressionName() -- Set the compression method for an entry.
    pub fn set_compression_name(&mut self, name: &str, method: u16) -> bool {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.method = method;
            true
        } else {
            false
        }
    }

    /// close() -- Close the archive.
    pub fn close(&mut self) -> bool {
        self.is_open = false;
        true
    }

    /// extractTo() -- Extract entries to a destination directory.
    ///
    /// If `entries` is None, all entries are extracted. If Some, only the named entries.
    /// Returns a list of (path, content) pairs rather than writing to disk.
    pub fn extract_to(
        &self,
        destination: &str,
        filter: Option<&[&str]>,
    ) -> Result<Vec<(String, Vec<u8>)>, ZipError> {
        if destination.is_empty() {
            return Err(ZipError::ExtractionFailed(
                "destination is empty".to_string(),
            ));
        }

        let mut extracted = Vec::new();
        let names_to_extract: Vec<&str> = match filter {
            Some(names) => names.to_vec(),
            None => self.entry_names.iter().map(|s| s.as_str()).collect(),
        };

        for name in names_to_extract {
            let entry = self
                .entries
                .get(name)
                .ok_or_else(|| ZipError::EntryNotFound(name.to_string()))?;

            let path = if destination.ends_with('/') {
                format!("{}{}", destination, name)
            } else {
                format!("{}/{}", destination, name)
            };
            extracted.push((path, entry.content.clone()));
        }

        Ok(extracted)
    }

    /// setArchiveComment() -- Set the archive comment.
    pub fn set_archive_comment(&mut self, comment: &str) {
        self.comment = comment.to_string();
    }

    /// getArchiveComment() -- Get the archive comment.
    pub fn get_archive_comment(&self) -> &str {
        &self.comment
    }

    /// Serialize the archive to ZIP format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        let mut central_dir = Vec::new();
        let mut local_offsets = Vec::new();

        // Write local file headers + data
        for name in &self.entry_names {
            let entry = match self.entries.get(name) {
                Some(e) => e,
                None => continue,
            };

            local_offsets.push(output.len() as u32);

            // Local file header
            output.extend_from_slice(&ZIP_LOCAL_FILE_HEADER_SIG.to_le_bytes());
            output.extend_from_slice(&20u16.to_le_bytes()); // version needed
            output.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
            output.extend_from_slice(&entry.method.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes()); // mod time
            output.extend_from_slice(&0u16.to_le_bytes()); // mod date
            output.extend_from_slice(&entry.crc32.to_le_bytes());
            output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
            output.extend_from_slice(&(entry.size as u32).to_le_bytes());
            let name_bytes = name.as_bytes();
            output.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            output.extend_from_slice(name_bytes);
            output.extend_from_slice(&entry.content);
        }

        // Build central directory
        let central_dir_offset = output.len() as u32;
        for (i, name) in self.entry_names.iter().enumerate() {
            let entry = match self.entries.get(name) {
                Some(e) => e,
                None => continue,
            };

            central_dir.extend_from_slice(&ZIP_CENTRAL_DIR_SIG.to_le_bytes());
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // flags
            central_dir.extend_from_slice(&entry.method.to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central_dir.extend_from_slice(&entry.crc32.to_le_bytes());
            central_dir.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
            central_dir.extend_from_slice(&(entry.size as u32).to_le_bytes());
            let name_bytes = name.as_bytes();
            central_dir.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // comment length
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central_dir.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central_dir.extend_from_slice(&local_offsets[i].to_le_bytes());
            central_dir.extend_from_slice(name_bytes);
        }

        output.extend_from_slice(&central_dir);

        // End of central directory record
        let central_dir_size = central_dir.len() as u32;
        let num_entries = self.entry_names.len() as u16;
        output.extend_from_slice(&ZIP_END_CENTRAL_DIR_SIG.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes()); // disk number
        output.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        output.extend_from_slice(&num_entries.to_le_bytes());
        output.extend_from_slice(&num_entries.to_le_bytes());
        output.extend_from_slice(&central_dir_size.to_le_bytes());
        output.extend_from_slice(&central_dir_offset.to_le_bytes());
        let comment_bytes = self.comment.as_bytes();
        output.extend_from_slice(&(comment_bytes.len() as u16).to_le_bytes());
        output.extend_from_slice(comment_bytes);

        output
    }
}

impl Default for ZipArchive {
    fn default() -> Self {
        Self::new()
    }
}

// ── CRC32 ───────────────────────────────────────────────────────────────────

/// Compute CRC32 (IEEE 802.3) for the given data.
pub fn crc32(data: &[u8]) -> u32 {
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
    fn test_zip_open() {
        let archive = ZipArchive::open("test.zip").unwrap();
        assert_eq!(archive.filename, "test.zip");
        assert_eq!(archive.num_files(), 0);
    }

    #[test]
    fn test_zip_open_empty_filename() {
        let result = ZipArchive::open("");
        assert!(result.is_err());
    }

    #[test]
    fn test_zip_add_and_get() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("hello.txt", b"Hello, World!");
        assert_eq!(archive.num_files(), 1);

        let content = archive.get_from_name("hello.txt").unwrap();
        assert_eq!(content, b"Hello, World!");
    }

    #[test]
    fn test_zip_get_from_index() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("a.txt", b"AAA");
        archive.add_from_string("b.txt", b"BBB");

        assert_eq!(archive.get_from_index(0).unwrap(), b"AAA");
        assert_eq!(archive.get_from_index(1).unwrap(), b"BBB");
        assert!(archive.get_from_index(2).is_none());
    }

    #[test]
    fn test_zip_get_nonexistent() {
        let archive = ZipArchive::new();
        assert!(archive.get_from_name("nope.txt").is_none());
    }

    #[test]
    fn test_zip_delete_name() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("a.txt", b"A");
        archive.add_from_string("b.txt", b"B");
        archive.add_from_string("c.txt", b"C");

        assert!(archive.delete_name("b.txt"));
        assert_eq!(archive.num_files(), 2);
        assert!(archive.get_from_name("b.txt").is_none());

        // Remaining entries preserve order
        assert_eq!(archive.get_name_index(0), Some("a.txt"));
        assert_eq!(archive.get_name_index(1), Some("c.txt"));
    }

    #[test]
    fn test_zip_delete_nonexistent() {
        let mut archive = ZipArchive::new();
        assert!(!archive.delete_name("nope.txt"));
    }

    #[test]
    fn test_zip_stat_name() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("data.bin", b"some data here");

        let stat = archive.stat_name("data.bin").unwrap();
        assert_eq!(stat.name, "data.bin");
        assert_eq!(stat.index, 0);
        assert_eq!(stat.size, 14);
        assert_eq!(stat.comp_size, 14);
        assert_eq!(stat.comp_method, ZIP_CM_STORE);
    }

    #[test]
    fn test_zip_stat_index() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("first.txt", b"1");
        archive.add_from_string("second.txt", b"22");

        let stat = archive.stat_index(1).unwrap();
        assert_eq!(stat.name, "second.txt");
        assert_eq!(stat.size, 2);

        assert!(archive.stat_index(99).is_none());
    }

    #[test]
    fn test_zip_rename() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("old.txt", b"content");

        assert!(archive.rename_name("old.txt", "new.txt"));
        assert!(archive.get_from_name("old.txt").is_none());
        assert_eq!(archive.get_from_name("new.txt").unwrap(), b"content");
        assert_eq!(archive.num_files(), 1);
    }

    #[test]
    fn test_zip_rename_nonexistent() {
        let mut archive = ZipArchive::new();
        assert!(!archive.rename_name("nope.txt", "new.txt"));
    }

    #[test]
    fn test_zip_set_compression() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("data.txt", b"data");

        assert!(archive.set_compression_name("data.txt", ZIP_CM_DEFLATE));
        let stat = archive.stat_name("data.txt").unwrap();
        assert_eq!(stat.comp_method, ZIP_CM_DEFLATE);
    }

    #[test]
    fn test_zip_close() {
        let mut archive = ZipArchive::new();
        assert!(archive.close());
    }

    #[test]
    fn test_zip_extract_all() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("a.txt", b"AAA");
        archive.add_from_string("dir/b.txt", b"BBB");

        let extracted = archive.extract_to("/tmp/out", None).unwrap();
        assert_eq!(extracted.len(), 2);

        let paths: Vec<&str> = extracted.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"/tmp/out/a.txt"));
        assert!(paths.contains(&"/tmp/out/dir/b.txt"));
    }

    #[test]
    fn test_zip_extract_filtered() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("a.txt", b"AAA");
        archive.add_from_string("b.txt", b"BBB");
        archive.add_from_string("c.txt", b"CCC");

        let extracted = archive
            .extract_to("/tmp/out", Some(&["a.txt", "c.txt"]))
            .unwrap();
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn test_zip_extract_empty_destination() {
        let archive = ZipArchive::new();
        let result = archive.extract_to("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_zip_archive_comment() {
        let mut archive = ZipArchive::new();
        archive.set_archive_comment("Test archive");
        assert_eq!(archive.get_archive_comment(), "Test archive");
    }

    #[test]
    fn test_zip_to_bytes_valid_structure() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("test.txt", b"Hello");

        let bytes = archive.to_bytes();
        // Should start with local file header signature
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ZIP_LOCAL_FILE_HEADER_SIG
        );

        // Should end with end of central directory
        // Find EOCD signature
        let mut found_eocd = false;
        for i in 0..bytes.len() - 3 {
            let sig = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            if sig == ZIP_END_CENTRAL_DIR_SIG {
                found_eocd = true;
                break;
            }
        }
        assert!(found_eocd);
    }

    #[test]
    fn test_zip_crc32() {
        assert_eq!(crc32(b"Hello, World!"), 0xEC4AC3D0);
        assert_eq!(crc32(b""), 0x00000000);
    }

    #[test]
    fn test_zip_overwrite_entry() {
        let mut archive = ZipArchive::new();
        archive.add_from_string("file.txt", b"original");
        archive.add_from_string("file.txt", b"updated");

        assert_eq!(archive.num_files(), 1);
        assert_eq!(archive.get_from_name("file.txt").unwrap(), b"updated");
    }
}
