//! PHP bz2 extension.
//!
//! Implements bzip2 compression/decompression functions.
//! Reference: php-src/ext/bz2/
//!
//! NOTE: This is a stub implementation using a store-only approach.
//! The API matches PHP's bz2 functions, but compression is not performed.
//! TODO: Integrate a full bz2 algorithm (e.g., the `bzip2` crate) for real compression.

use std::fmt;

/// BZ2 magic header bytes.
const BZ2_MAGIC: &[u8] = b"BZ";

/// BZ2 version byte for our stub.
const BZ2_VERSION: u8 = b'h';

/// Error type for bz2 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bz2Error {
    /// Input data is not valid bz2 data.
    InvalidData,
    /// Data is truncated.
    DataTruncated,
    /// Block size is invalid.
    InvalidBlockSize,
    /// I/O error occurred.
    IoError(String),
    /// Decompression failed.
    DecompressFailed(String),
}

impl fmt::Display for Bz2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bz2Error::InvalidData => write!(f, "Invalid bz2 data"),
            Bz2Error::DataTruncated => write!(f, "Data truncated"),
            Bz2Error::InvalidBlockSize => write!(f, "Invalid block size"),
            Bz2Error::IoError(e) => write!(f, "I/O error: {}", e),
            Bz2Error::DecompressFailed(e) => write!(f, "Decompression failed: {}", e),
        }
    }
}

/// bzcompress -- Compress a string into bzip2 encoded data.
///
/// `block_size` specifies the blocksize used during compression (1-9, default 4).
/// `work_factor` controls how the compression phase behaves (0-250, default 0).
///
/// NOTE: This is a stub implementation that wraps data with a bz2-like header
/// but does not actually perform bzip2 compression.
/// TODO: Use a proper bz2 compression library for real compression.
pub fn bzcompress(data: &[u8], block_size: u32, _work_factor: u32) -> Vec<u8> {
    let block_size = if block_size == 0 || block_size > 9 {
        4
    } else {
        block_size
    };

    // Build a store-only "bz2" format:
    // [BZ][h][block_size_char][4-byte length][data][4-byte checksum]
    let mut result = Vec::with_capacity(data.len() + 14);

    // Header
    result.extend_from_slice(BZ2_MAGIC);
    result.push(BZ2_VERSION);
    result.push(b'0' + block_size as u8);

    // Store the original data length as 4 bytes (big-endian)
    let len = data.len() as u32;
    result.extend_from_slice(&len.to_be_bytes());

    // Store the raw data
    result.extend_from_slice(data);

    // Simple checksum (sum of all bytes mod 2^32)
    let checksum = data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    result.extend_from_slice(&checksum.to_be_bytes());

    result
}

/// bzdecompress -- Decompresses bzip2 encoded data.
///
/// If `small` is true, an alternative decompression algorithm that uses less memory
/// is selected (not relevant for our stub implementation).
///
/// NOTE: This is a stub implementation that only handles data compressed by our
/// stub bzcompress function. TODO: Use a proper bz2 decompression library.
pub fn bzdecompress(data: &[u8], _small: bool) -> Result<Vec<u8>, Bz2Error> {
    // Minimum header size: BZ(2) + h(1) + block_size(1) + length(4) + checksum(4) = 12
    if data.len() < 12 {
        return Err(Bz2Error::DataTruncated);
    }

    // Verify magic bytes
    if &data[0..2] != BZ2_MAGIC {
        return Err(Bz2Error::InvalidData);
    }

    // Verify version
    if data[2] != BZ2_VERSION {
        return Err(Bz2Error::InvalidData);
    }

    // Verify block size
    let block_size_char = data[3];
    if !(b'1'..=b'9').contains(&block_size_char) {
        return Err(Bz2Error::InvalidBlockSize);
    }

    // Read original data length
    let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

    // Check we have enough data
    if data.len() < 8 + len + 4 {
        return Err(Bz2Error::DataTruncated);
    }

    // Extract the stored data
    let stored_data = &data[8..8 + len];

    // Verify checksum
    let stored_checksum = u32::from_be_bytes([
        data[8 + len],
        data[8 + len + 1],
        data[8 + len + 2],
        data[8 + len + 3],
    ]);
    let computed_checksum = stored_data
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));

    if stored_checksum != computed_checksum {
        return Err(Bz2Error::DecompressFailed("Checksum mismatch".to_string()));
    }

    Ok(stored_data.to_vec())
}

/// A bz2 file handle for reading/writing bzip2 compressed files.
///
/// Wraps file operations with bz2 compression/decompression.
/// TODO: Implement actual streaming bz2 compression/decompression.
pub struct BzFile {
    /// The underlying data buffer.
    buffer: Vec<u8>,
    /// Current read position.
    position: usize,
    /// Whether the file is open for writing.
    writable: bool,
    /// Whether the file is open.
    is_open: bool,
    /// Block size for compression.
    block_size: u32,
}

impl BzFile {
    /// Create a new BzFile for writing.
    pub fn open_write(block_size: u32) -> Self {
        BzFile {
            buffer: Vec::new(),
            position: 0,
            writable: true,
            is_open: true,
            block_size: if block_size == 0 || block_size > 9 {
                4
            } else {
                block_size
            },
        }
    }

    /// Create a new BzFile for reading from compressed data.
    pub fn open_read(compressed_data: &[u8]) -> Result<Self, Bz2Error> {
        let data = bzdecompress(compressed_data, false)?;
        Ok(BzFile {
            buffer: data,
            position: 0,
            writable: false,
            is_open: true,
            block_size: 4,
        })
    }

    /// Check if the file handle is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }
}

/// bzopen equivalent -- Open a bz2 file for reading or writing.
pub fn bzopen_write(block_size: u32) -> BzFile {
    BzFile::open_write(block_size)
}

/// bzopen equivalent -- Open a bz2 file for reading from compressed data.
pub fn bzopen_read(data: &[u8]) -> Result<BzFile, Bz2Error> {
    BzFile::open_read(data)
}

/// bzread -- Read from a bz2 file.
///
/// Reads up to `length` bytes from the bz2 file.
pub fn bzread(file: &mut BzFile, length: usize) -> Result<Vec<u8>, Bz2Error> {
    if !file.is_open {
        return Err(Bz2Error::IoError("File is not open".to_string()));
    }
    if file.writable {
        return Err(Bz2Error::IoError(
            "Cannot read from a write-only file".to_string(),
        ));
    }

    let remaining = file.buffer.len() - file.position;
    let to_read = length.min(remaining);
    let data = file.buffer[file.position..file.position + to_read].to_vec();
    file.position += to_read;
    Ok(data)
}

/// bzwrite -- Write to a bz2 file.
///
/// Writes data to the bz2 file.
pub fn bzwrite(file: &mut BzFile, data: &[u8]) -> Result<usize, Bz2Error> {
    if !file.is_open {
        return Err(Bz2Error::IoError("File is not open".to_string()));
    }
    if !file.writable {
        return Err(Bz2Error::IoError(
            "Cannot write to a read-only file".to_string(),
        ));
    }

    file.buffer.extend_from_slice(data);
    Ok(data.len())
}

/// bzclose -- Close a bz2 file.
///
/// If the file was opened for writing, returns the compressed data.
pub fn bzclose(file: &mut BzFile) -> Result<Option<Vec<u8>>, Bz2Error> {
    if !file.is_open {
        return Err(Bz2Error::IoError("File is already closed".to_string()));
    }

    file.is_open = false;

    if file.writable {
        let compressed = bzcompress(&file.buffer, file.block_size, 0);
        Ok(Some(compressed))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bzcompress_basic() {
        let data = b"Hello, World!";
        let compressed = bzcompress(data, 4, 0);

        // Check header
        assert_eq!(&compressed[0..2], BZ2_MAGIC);
        assert_eq!(compressed[2], BZ2_VERSION);
        assert_eq!(compressed[3], b'4'); // block size
    }

    #[test]
    fn test_bzdecompress_basic() {
        let data = b"Hello, World!";
        let compressed = bzcompress(data, 4, 0);
        let decompressed = bzdecompress(&compressed, false).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let compressed = bzcompress(data, 4, 0);
        let decompressed = bzdecompress(&compressed, false).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let compressed = bzcompress(&data, 9, 0);
        let decompressed = bzdecompress(&compressed, false).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzdecompress_invalid_magic() {
        let data = b"XX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(bzdecompress(data, false), Err(Bz2Error::InvalidData));
    }

    #[test]
    fn test_bzdecompress_truncated() {
        let data = b"BZh9";
        assert_eq!(bzdecompress(data, false), Err(Bz2Error::DataTruncated));
    }

    #[test]
    fn test_block_size_clamping() {
        // Block size 0 should be clamped to 4
        let compressed = bzcompress(b"test", 0, 0);
        assert_eq!(compressed[3], b'4');

        // Block size 10 should be clamped to 4
        let compressed = bzcompress(b"test", 10, 0);
        assert_eq!(compressed[3], b'4');

        // Block size 1 should be preserved
        let compressed = bzcompress(b"test", 1, 0);
        assert_eq!(compressed[3], b'1');
    }

    #[test]
    fn test_bzfile_write_read() {
        let mut file = bzopen_write(4);
        assert!(file.is_open());

        bzwrite(&mut file, b"Hello, ").unwrap();
        bzwrite(&mut file, b"World!").unwrap();

        let compressed = bzclose(&mut file).unwrap().unwrap();
        assert!(!file.is_open());

        let mut reader = bzopen_read(&compressed).unwrap();
        let data = bzread(&mut reader, 1024).unwrap();
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_bzread_partial() {
        let original = b"Hello, World!";
        let compressed = bzcompress(original, 4, 0);
        let mut reader = bzopen_read(&compressed).unwrap();

        let chunk1 = bzread(&mut reader, 5).unwrap();
        assert_eq!(chunk1, b"Hello");

        let chunk2 = bzread(&mut reader, 100).unwrap();
        assert_eq!(chunk2, b", World!");

        // Reading past end returns empty
        let chunk3 = bzread(&mut reader, 100).unwrap();
        assert!(chunk3.is_empty());
    }

    #[test]
    fn test_bzfile_error_conditions() {
        let mut file = bzopen_write(4);

        // Cannot read from a write-only file
        assert!(bzread(&mut file, 10).is_err());

        let compressed = bzcompress(b"test", 4, 0);
        let mut reader = bzopen_read(&compressed).unwrap();

        // Cannot write to a read-only file
        assert!(bzwrite(&mut reader, b"data").is_err());

        // Close and try operations on closed file
        bzclose(&mut reader).unwrap();
        assert!(bzread(&mut reader, 10).is_err());
    }

    #[test]
    fn test_checksum_mismatch() {
        let mut compressed = bzcompress(b"Hello", 4, 0);
        // Corrupt the last byte (part of checksum)
        let last = compressed.len() - 1;
        compressed[last] ^= 0xFF;
        assert!(bzdecompress(&compressed, false).is_err());
    }
}
