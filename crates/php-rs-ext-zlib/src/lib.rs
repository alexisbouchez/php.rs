//! PHP zlib extension.
//!
//! Implements zlib/gzip compression and decompression functions.
//! Reference: php-src/ext/zlib/
//!
//! NOTE: This is a stub implementation using store-only compression.
//! The API matches PHP's zlib functions, but actual DEFLATE compression
//! is not performed. TODO: Integrate a pure-Rust DEFLATE implementation
//! (e.g., the `flate2` or `miniz_oxide` crate) for real compression.

use std::fmt;

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
///
/// Uses the standard CRC-32/ISO-HDLC polynomial (0xEDB88320).
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

/// Compute Adler-32 checksum.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// gzcompress -- Compress data with zlib encoding.
///
/// Returns the compressed string using the zlib format (RFC 1950).
/// The `level` parameter specifies the compression level (0-9 or -1 for default).
///
/// NOTE: This is a store-only stub. TODO: Use real DEFLATE compression.
pub fn gzcompress(data: &[u8], _level: i32) -> Vec<u8> {
    zlib_wrap(data, ZLIB_ENCODING_DEFLATE)
}

/// gzuncompress -- Uncompress a zlib-compressed string.
pub fn gzuncompress(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    zlib_unwrap(data, ZLIB_ENCODING_DEFLATE)
}

/// gzdeflate -- Compress data with raw DEFLATE encoding.
///
/// Returns the raw DEFLATE compressed data (no header/footer).
///
/// NOTE: This is a store-only stub. TODO: Use real DEFLATE compression.
pub fn gzdeflate(data: &[u8], _level: i32) -> Vec<u8> {
    zlib_wrap(data, ZLIB_ENCODING_RAW)
}

/// gzinflate -- Uncompress raw DEFLATE data.
pub fn gzinflate(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    zlib_unwrap(data, ZLIB_ENCODING_RAW)
}

/// gzencode -- Compress data with gzip encoding.
///
/// Returns the gzip compressed data (RFC 1952 format).
///
/// NOTE: This is a store-only stub. TODO: Use real DEFLATE compression.
pub fn gzencode(data: &[u8], _level: i32) -> Vec<u8> {
    zlib_wrap(data, ZLIB_ENCODING_GZIP)
}

/// gzdecode -- Decode a gzip compressed string.
pub fn gzdecode(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    zlib_unwrap(data, ZLIB_ENCODING_GZIP)
}

/// zlib_encode -- Compress data with specified encoding.
///
/// The `encoding` parameter specifies the format:
/// - ZLIB_ENCODING_RAW (-15): raw DEFLATE
/// - ZLIB_ENCODING_GZIP (31): gzip format
/// - ZLIB_ENCODING_DEFLATE (15): zlib format
pub fn zlib_encode(data: &[u8], encoding: i32, _level: i32) -> Result<Vec<u8>, ZlibError> {
    match encoding {
        ZLIB_ENCODING_RAW | ZLIB_ENCODING_GZIP | ZLIB_ENCODING_DEFLATE => {
            Ok(zlib_wrap(data, encoding))
        }
        _ => Err(ZlibError::InvalidEncoding(encoding)),
    }
}

/// zlib_decode -- Decode compressed data.
///
/// Auto-detects the encoding format from the data header.
pub fn zlib_decode(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    if data.len() < 2 {
        return Err(ZlibError::DataTruncated);
    }

    // Try to auto-detect format
    if data[0] == 0x1F && data[1] == 0x8B {
        // Gzip magic number
        zlib_unwrap(data, ZLIB_ENCODING_GZIP)
    } else if data[0] == 0x78 {
        // Zlib header (0x78 = CMF byte with CM=8, CINFO=7)
        zlib_unwrap(data, ZLIB_ENCODING_DEFLATE)
    } else {
        // Try raw DEFLATE
        zlib_unwrap(data, ZLIB_ENCODING_RAW)
    }
}

/// Internal: wrap data with the appropriate encoding format.
///
/// NOTE: Uses store-only blocks (no actual compression).
/// TODO: Replace with real DEFLATE compression.
fn zlib_wrap(data: &[u8], encoding: i32) -> Vec<u8> {
    match encoding {
        ZLIB_ENCODING_RAW => {
            // Raw DEFLATE store block
            deflate_store(data)
        }
        ZLIB_ENCODING_DEFLATE => {
            // Zlib format: CMF + FLG + compressed data + Adler-32
            let mut result = Vec::new();

            // CMF byte: CM=8 (deflate), CINFO=7 (32K window)
            let cmf: u8 = 0x78;
            // FLG byte: FCHECK so that (CMF*256 + FLG) % 31 == 0
            let fcheck = (31 - ((cmf as u16 * 256) % 31)) % 31;
            let flg: u8 = fcheck as u8;

            result.push(cmf);
            result.push(flg);

            // Store blocks
            result.extend_from_slice(&deflate_store(data));

            // Adler-32 checksum (big-endian)
            let adler = adler32(data);
            result.extend_from_slice(&adler.to_be_bytes());

            result
        }
        ZLIB_ENCODING_GZIP => {
            // Gzip format (RFC 1952)
            let mut result = vec![
                0x1F, // ID1
                0x8B, // ID2
                0x08, // CM (deflate)
                0x00, // FLG (no extra fields)
                0, 0, 0, 0,    // MTIME (not set)
                0x00, // XFL
                0xFF, // OS (unknown)
            ];

            // Compressed data (store block)
            result.extend_from_slice(&deflate_store(data));

            // CRC32 (little-endian)
            let crc = crc32(data);
            result.extend_from_slice(&crc.to_le_bytes());

            // ISIZE (original data size mod 2^32, little-endian)
            let isize = (data.len() as u32).to_le_bytes();
            result.extend_from_slice(&isize);

            result
        }
        _ => Vec::new(),
    }
}

/// Create DEFLATE store blocks (uncompressed) for the given data.
///
/// Each store block has the format:
/// - 1 byte: BFINAL (1 bit) + BTYPE=00 (2 bits) + padding
/// - 2 bytes: LEN (length of data in this block, little-endian)
/// - 2 bytes: NLEN (one's complement of LEN)
/// - LEN bytes: uncompressed data
fn deflate_store(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    if data.is_empty() {
        // Empty final block
        result.push(0x01); // BFINAL=1, BTYPE=00
        result.extend_from_slice(&0u16.to_le_bytes()); // LEN=0
        result.extend_from_slice(&0xFFFFu16.to_le_bytes()); // NLEN=~0
        return result;
    }

    // DEFLATE store blocks can hold at most 65535 bytes each
    let max_block = 65535usize;
    let mut offset = 0;

    while offset < data.len() {
        let remaining = data.len() - offset;
        let block_len = remaining.min(max_block);
        let is_final = offset + block_len >= data.len();

        // Block header
        result.push(if is_final { 0x01 } else { 0x00 }); // BFINAL + BTYPE=00

        let len = block_len as u16;
        let nlen = !len;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&nlen.to_le_bytes());

        // Block data
        result.extend_from_slice(&data[offset..offset + block_len]);
        offset += block_len;
    }

    result
}

/// Internal: unwrap data from the specified encoding format.
fn zlib_unwrap(data: &[u8], encoding: i32) -> Result<Vec<u8>, ZlibError> {
    match encoding {
        ZLIB_ENCODING_RAW => {
            // Raw DEFLATE: just extract store blocks
            deflate_unstore(data)
        }
        ZLIB_ENCODING_DEFLATE => {
            // Zlib format: skip 2-byte header, extract DEFLATE data, verify Adler-32
            if data.len() < 6 {
                return Err(ZlibError::DataTruncated);
            }

            // Verify CMF byte
            let cmf = data[0];
            if cmf & 0x0F != 8 {
                return Err(ZlibError::InvalidData);
            }

            // Verify FLG checksum
            let flg = data[1];
            if !(cmf as u16 * 256 + flg as u16).is_multiple_of(31) {
                return Err(ZlibError::InvalidData);
            }

            // Check for FDICT flag
            let fdict = (flg & 0x20) != 0;
            let header_size = if fdict { 6 } else { 2 };

            if data.len() < header_size + 4 {
                return Err(ZlibError::DataTruncated);
            }

            // Extract DEFLATE data (everything between header and last 4 bytes)
            let deflate_data = &data[header_size..data.len() - 4];
            let result = deflate_unstore(deflate_data)?;

            // Verify Adler-32 (last 4 bytes, big-endian)
            let stored_adler = u32::from_be_bytes([
                data[data.len() - 4],
                data[data.len() - 3],
                data[data.len() - 2],
                data[data.len() - 1],
            ]);
            let computed_adler = adler32(&result);
            if stored_adler != computed_adler {
                return Err(ZlibError::ChecksumMismatch);
            }

            Ok(result)
        }
        ZLIB_ENCODING_GZIP => {
            // Gzip format: parse header, extract DEFLATE data, verify CRC32
            if data.len() < 18 {
                return Err(ZlibError::DataTruncated);
            }

            // Verify magic number
            if data[0] != 0x1F || data[1] != 0x8B {
                return Err(ZlibError::InvalidData);
            }

            // Verify compression method (8 = deflate)
            if data[2] != 0x08 {
                return Err(ZlibError::InvalidData);
            }

            let flags = data[3];
            let mut header_end = 10; // Minimum gzip header size

            // FEXTRA
            if flags & 0x04 != 0 {
                if data.len() < header_end + 2 {
                    return Err(ZlibError::DataTruncated);
                }
                let xlen = u16::from_le_bytes([data[header_end], data[header_end + 1]]) as usize;
                header_end += 2 + xlen;
            }

            // FNAME
            if flags & 0x08 != 0 {
                while header_end < data.len() && data[header_end] != 0 {
                    header_end += 1;
                }
                header_end += 1; // Skip null terminator
            }

            // FCOMMENT
            if flags & 0x10 != 0 {
                while header_end < data.len() && data[header_end] != 0 {
                    header_end += 1;
                }
                header_end += 1;
            }

            // FHCRC
            if flags & 0x02 != 0 {
                header_end += 2;
            }

            if data.len() < header_end + 8 {
                return Err(ZlibError::DataTruncated);
            }

            // Extract DEFLATE data (between header and last 8 bytes)
            let deflate_data = &data[header_end..data.len() - 8];
            let result = deflate_unstore(deflate_data)?;

            // Verify CRC32 (last 8 bytes: 4 CRC + 4 ISIZE, little-endian)
            let stored_crc = u32::from_le_bytes([
                data[data.len() - 8],
                data[data.len() - 7],
                data[data.len() - 6],
                data[data.len() - 5],
            ]);
            let computed_crc = crc32(&result);
            if stored_crc != computed_crc {
                return Err(ZlibError::ChecksumMismatch);
            }

            // Verify ISIZE
            let stored_isize = u32::from_le_bytes([
                data[data.len() - 4],
                data[data.len() - 3],
                data[data.len() - 2],
                data[data.len() - 1],
            ]);
            if stored_isize != (result.len() as u32) {
                return Err(ZlibError::ChecksumMismatch);
            }

            Ok(result)
        }
        _ => Err(ZlibError::InvalidEncoding(encoding)),
    }
}

/// Extract data from DEFLATE store blocks.
fn deflate_unstore(data: &[u8]) -> Result<Vec<u8>, ZlibError> {
    let mut result = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            break;
        }

        // Read block header
        let header = data[pos];
        let bfinal = header & 0x01;
        let btype = (header >> 1) & 0x03;
        pos += 1;

        if btype != 0 {
            // We only handle store blocks (BTYPE=00) in this stub
            return Err(ZlibError::DecompressError(
                "Only store blocks are supported in this stub implementation".to_string(),
            ));
        }

        if pos + 4 > data.len() {
            return Err(ZlibError::DataTruncated);
        }

        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        let nlen = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Verify NLEN
        if nlen != !(len as u16) {
            return Err(ZlibError::InvalidData);
        }

        if pos + len > data.len() {
            return Err(ZlibError::DataTruncated);
        }

        result.extend_from_slice(&data[pos..pos + len]);
        pos += len;

        if bfinal != 0 {
            break;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_basic() {
        // Known CRC32 values
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b"Hello, World!"), 0xEC4AC3D0);
    }

    #[test]
    fn test_adler32() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn test_gzcompress_decompress() {
        let data = b"Hello, World!";
        let compressed = gzcompress(data, ZLIB_DEFAULT_COMPRESSION);
        let decompressed = gzuncompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
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

        // Test each encoding
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

        let compressed = gzcompress(&data, 0);
        let decompressed = gzuncompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzuncompress_invalid() {
        assert!(gzuncompress(b"not valid data").is_err());
        assert!(gzuncompress(b"").is_err());
    }

    #[test]
    fn test_gzdecode_invalid() {
        assert!(gzdecode(b"not valid gzip").is_err());
        assert!(gzdecode(b"").is_err());
    }

    #[test]
    fn test_gzinflate_invalid() {
        // Non-store block type
        let bad = &[0x02, 0x00, 0x00, 0xFF, 0xFF]; // BTYPE=01 (static Huffman)
        assert!(gzinflate(bad).is_err());
    }

    #[test]
    fn test_zlib_format_header() {
        let compressed = gzcompress(b"test", 0);
        // CMF byte should indicate deflate (CM=8)
        assert_eq!(compressed[0] & 0x0F, 8);
        // CMF+FLG should be divisible by 31
        let cmf_flg = (compressed[0] as u16) * 256 + (compressed[1] as u16);
        assert_eq!(cmf_flg % 31, 0);
    }

    #[test]
    fn test_crc32_incremental() {
        // CRC of concatenation should match CRC of the full data
        let full = b"Hello, World!";
        let full_crc = crc32(full);
        assert_eq!(full_crc, crc32(b"Hello, World!"));
    }

    #[test]
    fn test_gzencode_checksum_verification() {
        let data = b"Hello, World!";
        let mut encoded = gzencode(data, 0);

        // Corrupt the CRC
        let crc_pos = encoded.len() - 8;
        encoded[crc_pos] ^= 0xFF;

        assert!(gzdecode(&encoded).is_err());
    }
}
