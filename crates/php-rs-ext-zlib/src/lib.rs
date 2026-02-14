//! PHP zlib extension.
//!
//! Implements zlib/gzip compression and decompression functions.
//! Reference: php-src/ext/zlib/
//!
//! Uses flate2 for real DEFLATE compression.

use flate2::read::{
    DeflateDecoder, DeflateEncoder, GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder,
};
use flate2::Compression;
use std::fmt;
use std::io::Read;

/// ZLIB encoding constants matching PHP's definitions.
pub const ZLIB_ENCODING_RAW: i32 = -15;
pub const ZLIB_ENCODING_GZIP: i32 = 31;
pub const ZLIB_ENCODING_DEFLATE: i32 = 15;

/// Force constants for zlib_encode.
pub const ZLIB_NO_FLUSH: i32 = 0;
pub const ZLIB_PARTIAL_FLUSH: i32 = 1;
pub const ZLIB_SYNC_FLUSH: i32 = 2;
pub const ZLIB_FULL_FLUSH: i32 = 3;
pub const ZLIB_FINISH: i32 = 4;

/// Compression level constants.
pub const ZLIB_DEFAULT_COMPRESSION: i32 = -1;
pub const ZLIB_NO_COMPRESSION: i32 = 0;
pub const ZLIB_BEST_SPEED: i32 = 1;
pub const ZLIB_BEST_COMPRESSION: i32 = 9;

/// Error type for zlib operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZlibError {
    /// Invalid compressed data.
    InvalidData,
    /// Data is truncated or incomplete.
    DataTruncated,
    /// Invalid compression level.
    InvalidLevel(i32),
    /// Invalid encoding.
    InvalidEncoding(i32),
    /// CRC checksum mismatch.
    ChecksumMismatch,
    /// Data too large.
    DataTooLarge,
    /// Decompression error.
    DecompressError(String),
}

impl fmt::Display for ZlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZlibError::InvalidData => write!(f, "Invalid compressed data"),
            ZlibError::DataTruncated => write!(f, "Data truncated"),
            ZlibError::InvalidLevel(l) => write!(f, "Invalid compression level: {}", l),
            ZlibError::InvalidEncoding(e) => write!(f, "Invalid encoding: {}", e),
            ZlibError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            ZlibError::DataTooLarge => write!(f, "Data too large"),
            ZlibError::DecompressError(e) => write!(f, "Decompression error: {}", e),
        }
    }
}

/// Compute CRC-32 checksum.
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
    crc ^ 0xFFFFFFFF
}

fn to_compression(level: i32) -> Compression {
    match level {
        ZLIB_DEFAULT_COMPRESSION => Compression::default(),
        0 => Compression::none(),
        1 => Compression::fast(),
        9 => Compression::best(),
        n if (1..=9).contains(&n) => Compression::new(n as u32),
        _ => Compression::default(),
    }
}

/// gzcompress -- Compress data with zlib encoding (RFC 1950).
pub fn gzcompress(data: &[u8], level: i32) -> Vec<u8> {
    let compression = to_compression(level);
    let mut encoder = ZlibEncoder::new(data, compression);
    let mut result = Vec::new();
    encoder.read_to_end(&mut result).unwrap_or(0);
    result
}

/// gzuncompress -- Uncompress a zlib-compressed string.
pub fn gzuncompress(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| ZlibError::DecompressError(e.to_string()))?;
    Ok(result)
}

/// gzdeflate -- Compress data with raw DEFLATE encoding (no header/footer).
pub fn gzdeflate(data: &[u8], level: i32) -> Vec<u8> {
    let compression = to_compression(level);
    let mut encoder = DeflateEncoder::new(data, compression);
    let mut result = Vec::new();
    encoder.read_to_end(&mut result).unwrap_or(0);
    result
}

/// gzinflate -- Uncompress raw DEFLATE data.
pub fn gzinflate(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| ZlibError::DecompressError(e.to_string()))?;
    Ok(result)
}

/// gzencode -- Compress data with gzip encoding (RFC 1952).
pub fn gzencode(data: &[u8], level: i32) -> Vec<u8> {
    let compression = to_compression(level);
    let mut encoder = GzEncoder::new(data, compression);
    let mut result = Vec::new();
    encoder.read_to_end(&mut result).unwrap_or(0);
    result
}

/// gzdecode -- Decode a gzip compressed string.
pub fn gzdecode(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut decoder = GzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| ZlibError::DecompressError(e.to_string()))?;
    Ok(result)
}

/// zlib_encode -- Compress data with specified encoding.
pub fn zlib_encode(data: &[u8], encoding: i32, level: i32) -> Result<Vec<u8>, ZlibError> {
    match encoding {
        ZLIB_ENCODING_RAW => Ok(gzdeflate(data, level)),
        ZLIB_ENCODING_GZIP => Ok(gzencode(data, level)),
        ZLIB_ENCODING_DEFLATE => Ok(gzcompress(data, level)),
        _ => Err(ZlibError::InvalidEncoding(encoding)),
    }
}

/// zlib_decode -- Decode compressed data. Auto-detects format.
pub fn zlib_decode(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    if data.len() < 2 {
        return Err(ZlibError::DataTruncated);
    }

    if data[0] == 0x1F && data[1] == 0x8B {
        gzdecode(data)
    } else if data[0] == 0x78 {
        gzuncompress(data)
    } else {
        gzinflate(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_basic() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b"Hello, World!"), 0xEC4AC3D0);
    }

    #[test]
    fn test_gzcompress_decompress() {
        let data = b"Hello, World!";
        let compressed = gzcompress(data, ZLIB_DEFAULT_COMPRESSION);
        assert!(compressed.len() > 0);
        let decompressed = gzuncompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzcompress_actually_compresses() {
        // Highly compressible data
        let data: Vec<u8> = vec![b'a'; 10000];
        let compressed = gzcompress(&data, ZLIB_DEFAULT_COMPRESSION);
        assert!(
            compressed.len() < data.len(),
            "Compressed size {} should be less than original size {}",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn test_gzdeflate_inflate() {
        let data = b"Hello, World!";
        let deflated = gzdeflate(data, ZLIB_DEFAULT_COMPRESSION);
        let inflated = gzinflate(&deflated).unwrap();
        assert_eq!(inflated, data);
    }

    #[test]
    fn test_gzencode_decode() {
        let data = b"Hello, World!";
        let encoded = gzencode(data, ZLIB_DEFAULT_COMPRESSION);

        // Verify gzip header
        assert_eq!(encoded[0], 0x1F);
        assert_eq!(encoded[1], 0x8B);
        assert_eq!(encoded[2], 0x08);

        let decoded = gzdecode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_zlib_encode_decode() {
        let data = b"Test data for zlib encoding";

        for &encoding in &[ZLIB_ENCODING_RAW, ZLIB_ENCODING_DEFLATE, ZLIB_ENCODING_GZIP] {
            let encoded = zlib_encode(data, encoding, ZLIB_DEFAULT_COMPRESSION).unwrap();
            let decoded = zlib_decode(&encoded).unwrap();
            assert_eq!(decoded, data.to_vec(), "Failed for encoding {}", encoding);
        }
    }

    #[test]
    fn test_zlib_encode_invalid_encoding() {
        assert!(zlib_encode(b"test", 99, 0).is_err());
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";

        let compressed = gzcompress(data, 0);
        let decompressed = gzuncompress(&compressed).unwrap();
        assert_eq!(decompressed, data);

        let encoded = gzencode(data, 0);
        let decoded = gzdecode(&encoded).unwrap();
        assert_eq!(decoded, data);

        let deflated = gzdeflate(data, 0);
        let inflated = gzinflate(&deflated).unwrap();
        assert_eq!(inflated, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data: Vec<u8> = (0..100000).map(|i| (i % 256) as u8).collect();

        let compressed = gzcompress(&data, ZLIB_DEFAULT_COMPRESSION);
        assert!(compressed.len() < data.len());
        let decompressed = gzuncompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzuncompress_invalid() {
        assert!(gzuncompress(b"not valid data").is_err());
    }

    #[test]
    fn test_gzdecode_invalid() {
        assert!(gzdecode(b"not valid gzip").is_err());
    }

    #[test]
    fn test_zlib_format_header() {
        let compressed = gzcompress(b"test", ZLIB_DEFAULT_COMPRESSION);
        // CMF byte should indicate deflate (CM=8)
        assert_eq!(compressed[0] & 0x0F, 8);
        // CMF+FLG should be divisible by 31
        let cmf_flg = (compressed[0] as u16) * 256 + (compressed[1] as u16);
        assert_eq!(cmf_flg % 31, 0);
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Hello, World! This is a test of compression levels.";

        let no_comp = gzcompress(data, ZLIB_NO_COMPRESSION);
        let best_speed = gzcompress(data, ZLIB_BEST_SPEED);
        let best_comp = gzcompress(data, ZLIB_BEST_COMPRESSION);

        // All should roundtrip correctly
        assert_eq!(gzuncompress(&no_comp).unwrap(), data);
        assert_eq!(gzuncompress(&best_speed).unwrap(), data);
        assert_eq!(gzuncompress(&best_comp).unwrap(), data);
    }
}
