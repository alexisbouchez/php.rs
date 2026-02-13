//! PHP exif extension.
//!
//! Implements image metadata (EXIF) reading functions.
//! Reference: php-src/ext/exif/
//!
//! Parses JPEG EXIF APP1 marker with basic TIFF header + IFD entries.

use std::collections::HashMap;
use std::fmt;

// ── Image type constants (matching PHP) ─────────────────────────────────────

/// Image types returned by exif_imagetype(), matching PHP's IMAGETYPE_* constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum ImageType {
    GIF = 1,
    JPEG = 2,
    PNG = 3,
    SWF = 4,
    PSD = 5,
    BMP = 6,
    TIFF_II = 7,
    TIFF_MM = 8,
    JPC = 9,
    JP2 = 10,
    WBMP = 15,
    XBM = 16,
    ICO = 17,
    WEBP = 18,
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ExifError {
    /// The file is not a recognized image format.
    NotAnImage,
    /// The EXIF data is malformed.
    MalformedExif(String),
    /// File could not be read.
    FileNotFound(String),
    /// The image format does not support EXIF (e.g., PNG, GIF).
    ExifNotSupported,
}

impl fmt::Display for ExifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExifError::NotAnImage => write!(f, "Not a recognized image format"),
            ExifError::MalformedExif(msg) => write!(f, "Malformed EXIF data: {}", msg),
            ExifError::FileNotFound(path) => write!(f, "File not found: {}", path),
            ExifError::ExifNotSupported => {
                write!(f, "This image format does not support EXIF data")
            }
        }
    }
}

// ── EXIF tag IDs ────────────────────────────────────────────────────────────

pub const TAG_IMAGE_WIDTH: u16 = 0x0100;
pub const TAG_IMAGE_HEIGHT: u16 = 0x0101;
pub const TAG_BITS_PER_SAMPLE: u16 = 0x0102;
pub const TAG_COMPRESSION: u16 = 0x0103;
pub const TAG_MAKE: u16 = 0x010F;
pub const TAG_MODEL: u16 = 0x0110;
pub const TAG_ORIENTATION: u16 = 0x0112;
pub const TAG_X_RESOLUTION: u16 = 0x011A;
pub const TAG_Y_RESOLUTION: u16 = 0x011B;
pub const TAG_RESOLUTION_UNIT: u16 = 0x0128;
pub const TAG_SOFTWARE: u16 = 0x0131;
pub const TAG_DATETIME: u16 = 0x0132;
pub const TAG_ARTIST: u16 = 0x013B;
pub const TAG_COPYRIGHT: u16 = 0x8298;
pub const TAG_EXIF_IFD_POINTER: u16 = 0x8769;
pub const TAG_GPS_IFD_POINTER: u16 = 0x8825;
pub const TAG_EXPOSURE_TIME: u16 = 0x829A;
pub const TAG_F_NUMBER: u16 = 0x829D;
pub const TAG_ISO_SPEED: u16 = 0x8827;
pub const TAG_DATE_TIME_ORIGINAL: u16 = 0x9003;
pub const TAG_DATE_TIME_DIGITIZED: u16 = 0x9004;
pub const TAG_SHUTTER_SPEED: u16 = 0x9201;
pub const TAG_APERTURE: u16 = 0x9202;
pub const TAG_FOCAL_LENGTH: u16 = 0x920A;
pub const TAG_COLOR_SPACE: u16 = 0xA001;
pub const TAG_PIXEL_X_DIMENSION: u16 = 0xA002;
pub const TAG_PIXEL_Y_DIMENSION: u16 = 0xA003;

// ── ExifData struct ─────────────────────────────────────────────────────────

/// Parsed EXIF data from an image.
#[derive(Debug, Clone, Default)]
pub struct ExifData {
    pub make: Option<String>,
    pub model: Option<String>,
    pub orientation: Option<u16>,
    pub datetime: Option<String>,
    pub datetime_original: Option<String>,
    pub datetime_digitized: Option<String>,
    pub exposure_time: Option<String>,
    pub f_number: Option<String>,
    pub iso_speed: Option<u32>,
    pub focal_length: Option<String>,
    pub software: Option<String>,
    pub artist: Option<String>,
    pub copyright: Option<String>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub color_space: Option<u16>,
    pub pixel_x_dimension: Option<u32>,
    pub pixel_y_dimension: Option<u32>,
    /// Raw tag values (tag_id -> string representation).
    pub tags: HashMap<u16, String>,
}

// ── exif_tagname ────────────────────────────────────────────────────────────

/// exif_tagname() -- Get the tag name for a given EXIF tag ID.
pub fn exif_tagname(tag_id: u16) -> Option<&'static str> {
    match tag_id {
        TAG_IMAGE_WIDTH => Some("ImageWidth"),
        TAG_IMAGE_HEIGHT => Some("ImageLength"),
        TAG_BITS_PER_SAMPLE => Some("BitsPerSample"),
        TAG_COMPRESSION => Some("Compression"),
        TAG_MAKE => Some("Make"),
        TAG_MODEL => Some("Model"),
        TAG_ORIENTATION => Some("Orientation"),
        TAG_X_RESOLUTION => Some("XResolution"),
        TAG_Y_RESOLUTION => Some("YResolution"),
        TAG_RESOLUTION_UNIT => Some("ResolutionUnit"),
        TAG_SOFTWARE => Some("Software"),
        TAG_DATETIME => Some("DateTime"),
        TAG_ARTIST => Some("Artist"),
        TAG_COPYRIGHT => Some("Copyright"),
        TAG_EXIF_IFD_POINTER => Some("ExifIFDPointer"),
        TAG_GPS_IFD_POINTER => Some("GPSInfoIFDPointer"),
        TAG_EXPOSURE_TIME => Some("ExposureTime"),
        TAG_F_NUMBER => Some("FNumber"),
        TAG_ISO_SPEED => Some("ISOSpeedRatings"),
        TAG_DATE_TIME_ORIGINAL => Some("DateTimeOriginal"),
        TAG_DATE_TIME_DIGITIZED => Some("DateTimeDigitized"),
        TAG_SHUTTER_SPEED => Some("ShutterSpeedValue"),
        TAG_APERTURE => Some("ApertureValue"),
        TAG_FOCAL_LENGTH => Some("FocalLength"),
        TAG_COLOR_SPACE => Some("ColorSpace"),
        TAG_PIXEL_X_DIMENSION => Some("ExifImageWidth"),
        TAG_PIXEL_Y_DIMENSION => Some("ExifImageLength"),
        _ => None,
    }
}

// ── exif_imagetype ──────────────────────────────────────────────────────────

/// exif_imagetype() -- Determine the image type from the magic bytes.
pub fn exif_imagetype(data: &[u8]) -> Option<ImageType> {
    if data.len() < 3 {
        return None;
    }

    // JPEG: \xFF\xD8\xFF
    if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some(ImageType::JPEG);
    }

    // PNG: \x89PNG
    if data.len() >= 4 && data[0] == 0x89 && &data[1..4] == b"PNG" {
        return Some(ImageType::PNG);
    }

    // GIF: GIF87a or GIF89a
    if data.len() >= 6 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
        return Some(ImageType::GIF);
    }

    // BMP: BM
    if data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D {
        return Some(ImageType::BMP);
    }

    // TIFF: II\x2A\x00 (little-endian) or MM\x00\x2A (big-endian)
    if data.len() >= 4 {
        if data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00 {
            return Some(ImageType::TIFF_II);
        }
        if data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A {
            return Some(ImageType::TIFF_MM);
        }
    }

    // WebP: RIFF....WEBP
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(ImageType::WEBP);
    }

    // PSD: 8BPS
    if data.len() >= 4 && &data[..4] == b"8BPS" {
        return Some(ImageType::PSD);
    }

    None
}

// ── EXIF parsing from raw bytes ─────────────────────────────────────────────

/// Byte order for TIFF headers.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ByteOrder {
    LittleEndian,
    BigEndian,
}

fn read_u16(data: &[u8], offset: usize, order: ByteOrder) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(match order {
        ByteOrder::LittleEndian => u16::from_le_bytes([data[offset], data[offset + 1]]),
        ByteOrder::BigEndian => u16::from_be_bytes([data[offset], data[offset + 1]]),
    })
}

fn read_u32(data: &[u8], offset: usize, order: ByteOrder) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(match order {
        ByteOrder::LittleEndian => u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]),
        ByteOrder::BigEndian => u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]),
    })
}

/// Read an ASCII string from TIFF data.
fn read_ascii(data: &[u8], offset: usize, count: u32) -> Option<String> {
    let end = offset + count as usize;
    if end > data.len() {
        return None;
    }
    let slice = &data[offset..end];
    // Remove trailing null bytes
    let trimmed = slice
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect::<Vec<u8>>();
    String::from_utf8(trimmed).ok()
}

/// Read a rational (two u32: numerator/denominator) and return as string.
fn read_rational(data: &[u8], offset: usize, order: ByteOrder) -> Option<String> {
    let num = read_u32(data, offset, order)?;
    let den = read_u32(data, offset + 4, order)?;
    if den == 0 {
        return Some(format!("{}/0", num));
    }
    Some(format!("{}/{}", num, den))
}

/// TIFF IFD types.
const TIFF_TYPE_BYTE: u16 = 1;
const TIFF_TYPE_ASCII: u16 = 2;
const TIFF_TYPE_SHORT: u16 = 3;
const TIFF_TYPE_LONG: u16 = 4;
const TIFF_TYPE_RATIONAL: u16 = 5;

/// Parse IFD entries from a TIFF blob and fill ExifData.
fn parse_ifd(
    tiff_data: &[u8],
    ifd_offset: usize,
    order: ByteOrder,
    exif: &mut ExifData,
    depth: u32,
) {
    if depth > 4 {
        return; // Prevent infinite recursion
    }

    let entry_count = match read_u16(tiff_data, ifd_offset, order) {
        Some(c) => c as usize,
        None => return,
    };

    for i in 0..entry_count {
        let entry_offset = ifd_offset + 2 + i * 12;
        if entry_offset + 12 > tiff_data.len() {
            break;
        }

        let tag = match read_u16(tiff_data, entry_offset, order) {
            Some(t) => t,
            None => continue,
        };
        let data_type = match read_u16(tiff_data, entry_offset + 2, order) {
            Some(t) => t,
            None => continue,
        };
        let count = match read_u32(tiff_data, entry_offset + 4, order) {
            Some(c) => c,
            None => continue,
        };

        // Value/offset field is at entry_offset + 8 (4 bytes)
        let value_offset_field = entry_offset + 8;

        // Determine the actual data offset
        let data_size = match data_type {
            TIFF_TYPE_BYTE => count as usize,
            TIFF_TYPE_ASCII => count as usize,
            TIFF_TYPE_SHORT => count as usize * 2,
            TIFF_TYPE_LONG => count as usize * 4,
            TIFF_TYPE_RATIONAL => count as usize * 8,
            _ => count as usize,
        };

        let data_offset = if data_size <= 4 {
            value_offset_field
        } else {
            match read_u32(tiff_data, value_offset_field, order) {
                Some(o) => o as usize,
                None => continue,
            }
        };

        // Read the value based on tag
        match tag {
            TAG_MAKE => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.make = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_MODEL => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.model = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_ORIENTATION => {
                if let Some(v) = read_u16(tiff_data, data_offset, order) {
                    exif.orientation = Some(v);
                    exif.tags.insert(tag, v.to_string());
                }
            }
            TAG_DATETIME => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.datetime = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_DATE_TIME_ORIGINAL => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.datetime_original = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_DATE_TIME_DIGITIZED => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.datetime_digitized = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_EXPOSURE_TIME => {
                if let Some(s) = read_rational(tiff_data, data_offset, order) {
                    exif.exposure_time = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_F_NUMBER => {
                if let Some(s) = read_rational(tiff_data, data_offset, order) {
                    exif.f_number = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_ISO_SPEED => {
                if let Some(v) = read_u16(tiff_data, data_offset, order) {
                    exif.iso_speed = Some(v as u32);
                    exif.tags.insert(tag, v.to_string());
                }
            }
            TAG_FOCAL_LENGTH => {
                if let Some(s) = read_rational(tiff_data, data_offset, order) {
                    exif.focal_length = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_SOFTWARE => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.software = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_ARTIST => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.artist = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_COPYRIGHT => {
                if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                    exif.copyright = Some(s.clone());
                    exif.tags.insert(tag, s);
                }
            }
            TAG_IMAGE_WIDTH => {
                let v = if data_type == TIFF_TYPE_SHORT {
                    read_u16(tiff_data, data_offset, order).map(|v| v as u32)
                } else {
                    read_u32(tiff_data, data_offset, order)
                };
                if let Some(val) = v {
                    exif.image_width = Some(val);
                    exif.tags.insert(tag, val.to_string());
                }
            }
            TAG_IMAGE_HEIGHT => {
                let v = if data_type == TIFF_TYPE_SHORT {
                    read_u16(tiff_data, data_offset, order).map(|v| v as u32)
                } else {
                    read_u32(tiff_data, data_offset, order)
                };
                if let Some(val) = v {
                    exif.image_height = Some(val);
                    exif.tags.insert(tag, val.to_string());
                }
            }
            TAG_COLOR_SPACE => {
                if let Some(v) = read_u16(tiff_data, data_offset, order) {
                    exif.color_space = Some(v);
                    exif.tags.insert(tag, v.to_string());
                }
            }
            TAG_PIXEL_X_DIMENSION => {
                let v = if data_type == TIFF_TYPE_SHORT {
                    read_u16(tiff_data, data_offset, order).map(|v| v as u32)
                } else {
                    read_u32(tiff_data, data_offset, order)
                };
                if let Some(val) = v {
                    exif.pixel_x_dimension = Some(val);
                    exif.tags.insert(tag, val.to_string());
                }
            }
            TAG_PIXEL_Y_DIMENSION => {
                let v = if data_type == TIFF_TYPE_SHORT {
                    read_u16(tiff_data, data_offset, order).map(|v| v as u32)
                } else {
                    read_u32(tiff_data, data_offset, order)
                };
                if let Some(val) = v {
                    exif.pixel_y_dimension = Some(val);
                    exif.tags.insert(tag, val.to_string());
                }
            }
            TAG_EXIF_IFD_POINTER => {
                // Sub-IFD pointer
                if let Some(sub_offset) = read_u32(tiff_data, data_offset, order) {
                    parse_ifd(tiff_data, sub_offset as usize, order, exif, depth + 1);
                }
            }
            _ => {
                // Store unknown tags as raw values
                if data_type == TIFF_TYPE_ASCII {
                    if let Some(s) = read_ascii(tiff_data, data_offset, count) {
                        exif.tags.insert(tag, s);
                    }
                } else if data_type == TIFF_TYPE_SHORT {
                    if let Some(v) = read_u16(tiff_data, data_offset, order) {
                        exif.tags.insert(tag, v.to_string());
                    }
                } else if data_type == TIFF_TYPE_LONG {
                    if let Some(v) = read_u32(tiff_data, data_offset, order) {
                        exif.tags.insert(tag, v.to_string());
                    }
                }
            }
        }
    }
}

/// exif_read_data() -- Parse EXIF data from raw image bytes.
///
/// Currently supports JPEG (APP1 marker) and TIFF files.
pub fn exif_read_data(data: &[u8]) -> Result<ExifData, ExifError> {
    if data.len() < 4 {
        return Err(ExifError::NotAnImage);
    }

    // JPEG?
    if data[0] == 0xFF && data[1] == 0xD8 {
        return parse_jpeg_exif(data);
    }

    // TIFF?
    if (data[0] == 0x49 && data[1] == 0x49) || (data[0] == 0x4D && data[1] == 0x4D) {
        return parse_tiff_exif(data);
    }

    Err(ExifError::ExifNotSupported)
}

/// Parse EXIF from a JPEG's APP1 marker.
fn parse_jpeg_exif(data: &[u8]) -> Result<ExifData, ExifError> {
    // Scan for APP1 marker (0xFF 0xE1)
    let mut pos = 2; // Skip SOI
    while pos + 4 < data.len() {
        if data[pos] != 0xFF {
            return Err(ExifError::MalformedExif("Expected marker".to_string()));
        }
        let marker = data[pos + 1];
        let length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if marker == 0xE1 {
            // APP1 found
            let app1_data = &data[pos + 4..];
            // Check for "Exif\0\0" header
            if app1_data.len() >= 6 && &app1_data[..6] == b"Exif\0\0" {
                let tiff_data = &app1_data[6..];
                return parse_tiff_exif(tiff_data);
            }
        }

        pos += 2 + length;
    }

    // No EXIF found — return empty data (not an error in PHP)
    Ok(ExifData::default())
}

/// Parse EXIF from a TIFF blob.
fn parse_tiff_exif(data: &[u8]) -> Result<ExifData, ExifError> {
    if data.len() < 8 {
        return Err(ExifError::MalformedExif(
            "TIFF header too short".to_string(),
        ));
    }

    let order = if data[0] == 0x49 && data[1] == 0x49 {
        ByteOrder::LittleEndian
    } else if data[0] == 0x4D && data[1] == 0x4D {
        ByteOrder::BigEndian
    } else {
        return Err(ExifError::MalformedExif("Invalid byte order".to_string()));
    };

    // Verify magic number 42
    let magic = read_u16(data, 2, order).unwrap_or(0);
    if magic != 42 {
        return Err(ExifError::MalformedExif(
            "Invalid TIFF magic number".to_string(),
        ));
    }

    // Get IFD0 offset
    let ifd0_offset = read_u32(data, 4, order).unwrap_or(0) as usize;
    if ifd0_offset >= data.len() {
        return Err(ExifError::MalformedExif(
            "IFD0 offset out of range".to_string(),
        ));
    }

    let mut exif = ExifData::default();
    parse_ifd(data, ifd0_offset, order, &mut exif, 0);

    Ok(exif)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exif_tagname_known() {
        assert_eq!(exif_tagname(TAG_MAKE), Some("Make"));
        assert_eq!(exif_tagname(TAG_MODEL), Some("Model"));
        assert_eq!(exif_tagname(TAG_ORIENTATION), Some("Orientation"));
        assert_eq!(exif_tagname(TAG_DATETIME), Some("DateTime"));
        assert_eq!(exif_tagname(TAG_EXPOSURE_TIME), Some("ExposureTime"));
        assert_eq!(exif_tagname(TAG_FOCAL_LENGTH), Some("FocalLength"));
        assert_eq!(exif_tagname(TAG_ISO_SPEED), Some("ISOSpeedRatings"));
    }

    #[test]
    fn test_exif_tagname_unknown() {
        assert_eq!(exif_tagname(0xFFFF), None);
        assert_eq!(exif_tagname(0x0000), None);
    }

    #[test]
    fn test_exif_imagetype_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(exif_imagetype(&data), Some(ImageType::JPEG));
    }

    #[test]
    fn test_exif_imagetype_png() {
        let data = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(exif_imagetype(&data), Some(ImageType::PNG));
    }

    #[test]
    fn test_exif_imagetype_gif() {
        assert_eq!(exif_imagetype(b"GIF89a..."), Some(ImageType::GIF));
        assert_eq!(exif_imagetype(b"GIF87a..."), Some(ImageType::GIF));
    }

    #[test]
    fn test_exif_imagetype_bmp() {
        let data = [0x42, 0x4D, 0x00, 0x00];
        assert_eq!(exif_imagetype(&data), Some(ImageType::BMP));
    }

    #[test]
    fn test_exif_imagetype_tiff_le() {
        let data = [0x49, 0x49, 0x2A, 0x00];
        assert_eq!(exif_imagetype(&data), Some(ImageType::TIFF_II));
    }

    #[test]
    fn test_exif_imagetype_tiff_be() {
        let data = [0x4D, 0x4D, 0x00, 0x2A];
        assert_eq!(exif_imagetype(&data), Some(ImageType::TIFF_MM));
    }

    #[test]
    fn test_exif_imagetype_webp() {
        let mut data = vec![0u8; 12];
        data[..4].copy_from_slice(b"RIFF");
        data[8..12].copy_from_slice(b"WEBP");
        assert_eq!(exif_imagetype(&data), Some(ImageType::WEBP));
    }

    #[test]
    fn test_exif_imagetype_unknown() {
        assert_eq!(exif_imagetype(b"???"), None);
    }

    #[test]
    fn test_exif_imagetype_too_short() {
        assert_eq!(exif_imagetype(b"AB"), None);
    }

    #[test]
    fn test_parse_tiff_le_basic() {
        // Construct a minimal TIFF with one IFD entry: Make = "Test"
        let mut data = Vec::new();
        // TIFF header: II (little-endian), magic 42, IFD0 offset = 8
        data.extend_from_slice(b"II");
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        // IFD0 at offset 8: 1 entry
        data.extend_from_slice(&1u16.to_le_bytes()); // entry count

        // Entry: tag=0x010F (Make), type=ASCII(2), count=5, value offset = 22
        data.extend_from_slice(&TAG_MAKE.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        data.extend_from_slice(&5u32.to_le_bytes()); // count (includes null)
        data.extend_from_slice(&22u32.to_le_bytes()); // offset to data

        // Next IFD pointer (0 = none)
        // But first let's pad to offset 22
        // Current offset = 8 + 2 + 12 = 22, perfect
        data.extend_from_slice(b"Test\0");

        let result = exif_read_data(&data).unwrap();
        assert_eq!(result.make, Some("Test".to_string()));
    }

    #[test]
    fn test_parse_tiff_be_basic() {
        // Construct a minimal big-endian TIFF with Model tag
        let mut data = Vec::new();
        // TIFF header: MM (big-endian), magic 42, IFD0 offset = 8
        data.extend_from_slice(b"MM");
        data.extend_from_slice(&42u16.to_be_bytes());
        data.extend_from_slice(&8u32.to_be_bytes());
        // IFD0 at offset 8: 1 entry
        data.extend_from_slice(&1u16.to_be_bytes());

        // Entry: tag=0x0110 (Model), type=ASCII(2), count=8, offset=22
        data.extend_from_slice(&TAG_MODEL.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes()); // ASCII
        data.extend_from_slice(&8u32.to_be_bytes()); // count
        data.extend_from_slice(&22u32.to_be_bytes()); // offset

        // Data at offset 22
        data.extend_from_slice(b"Canon5D\0");

        let result = exif_read_data(&data).unwrap();
        assert_eq!(result.model, Some("Canon5D".to_string()));
    }

    #[test]
    fn test_parse_tiff_orientation() {
        let mut data = Vec::new();
        data.extend_from_slice(b"II");
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());

        // Orientation: tag=0x0112, type=SHORT(3), count=1, value=6
        data.extend_from_slice(&TAG_ORIENTATION.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes()); // SHORT
        data.extend_from_slice(&1u32.to_le_bytes()); // count
                                                     // For SHORT data <= 4 bytes, value is inline
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(&[0, 0]); // padding

        let result = exif_read_data(&data).unwrap();
        assert_eq!(result.orientation, Some(6));
    }

    #[test]
    fn test_exif_not_supported() {
        // PNG does not support EXIF (in our implementation)
        let data = [0x89, b'P', b'N', b'G'];
        let result = exif_read_data(&data);
        assert!(matches!(result, Err(ExifError::ExifNotSupported)));
    }

    #[test]
    fn test_exif_too_short() {
        let result = exif_read_data(b"AB");
        assert!(matches!(result, Err(ExifError::NotAnImage)));
    }

    #[test]
    fn test_jpeg_no_exif() {
        // Minimal JPEG with no APP1
        let data = [0xFF, 0xD8, 0xFF, 0xD9]; // SOI + EOI
        let result = exif_read_data(&data);
        // Should return Ok with empty data (PHP behavior)
        assert!(result.is_ok());
        let exif = result.unwrap();
        assert!(exif.make.is_none());
    }
}
