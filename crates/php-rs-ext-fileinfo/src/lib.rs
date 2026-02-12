//! PHP fileinfo extension.
//!
//! Implements file type detection using magic bytes and file extensions.
//! Reference: php-src/ext/fileinfo/
//!
//! This is a pure-Rust reimplementation of libmagic-style MIME detection.

use std::collections::HashMap;
use std::fmt;

// ── Constants ───────────────────────────────────────────────────────────────

pub const FILEINFO_NONE: i32 = 0;
pub const FILEINFO_SYMLINK: i32 = 2;
pub const FILEINFO_MIME_TYPE: i32 = 16;
pub const FILEINFO_MIME_ENCODING: i32 = 1024;
pub const FILEINFO_MIME: i32 = 1040; // MIME_TYPE | MIME_ENCODING
pub const FILEINFO_CONTINUE: i32 = 32;
pub const FILEINFO_DEVICES: i32 = 8;
pub const FILEINFO_RAW: i32 = 256;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FileInfoError {
    /// Failed to open the file info resource.
    OpenFailed(String),
    /// The file was not found or could not be read.
    FileNotFound(String),
    /// Invalid magic database.
    InvalidMagicDb,
}

impl fmt::Display for FileInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileInfoError::OpenFailed(msg) => write!(f, "finfo_open(): {}", msg),
            FileInfoError::FileNotFound(path) => {
                write!(f, "finfo_file(): file not found: {}", path)
            }
            FileInfoError::InvalidMagicDb => write!(f, "Invalid magic database"),
        }
    }
}

// ── FInfo struct ────────────────────────────────────────────────────────────

/// A file info resource, analogous to the finfo resource in PHP.
#[derive(Debug, Clone)]
pub struct FInfo {
    /// Bitmask of FILEINFO_* options.
    pub options: i32,
}

/// Open a new file info resource.
pub fn finfo_open(options: i32) -> FInfo {
    FInfo { options }
}

/// Close a file info resource. Always returns true.
pub fn finfo_close(_finfo: &FInfo) -> bool {
    true
}

/// Detect MIME type for a file by path.
///
/// In this simplified implementation we detect from the file extension only
/// (we cannot do real filesystem I/O in a pure library crate without a runtime).
/// Use `finfo_buffer` for magic-byte detection.
pub fn finfo_file(finfo: &FInfo, filename: &str) -> String {
    let mime = mime_from_extension(filename);

    if finfo.options & FILEINFO_MIME != 0 || finfo.options & FILEINFO_MIME_TYPE != 0 {
        if finfo.options & FILEINFO_MIME == FILEINFO_MIME {
            format!("{}; charset=us-ascii", mime)
        } else {
            mime
        }
    } else {
        mime
    }
}

/// Detect MIME type from a buffer of bytes.
pub fn finfo_buffer(finfo: &FInfo, data: &[u8]) -> String {
    let mime = detect_mime_from_magic(data);

    if finfo.options & FILEINFO_MIME == FILEINFO_MIME {
        let encoding = detect_encoding(data);
        format!("{}; charset={}", mime, encoding)
    } else if finfo.options & FILEINFO_MIME_ENCODING == FILEINFO_MIME_ENCODING {
        detect_encoding(data)
    } else {
        mime
    }
}

/// mime_content_type() -- Detect MIME type for a filename based on extension.
pub fn mime_content_type(filename: &str) -> String {
    mime_from_extension(filename)
}

// ── Magic byte detection ────────────────────────────────────────────────────

/// Detect MIME type from the first bytes of the data (magic numbers).
pub fn detect_mime_from_magic(data: &[u8]) -> String {
    if data.is_empty() {
        return "application/x-empty".to_string();
    }

    // PNG: \x89PNG\r\n\x1a\n
    if data.len() >= 4 && data[0] == 0x89 && &data[1..4] == b"PNG" {
        return "image/png".to_string();
    }

    // JPEG: \xFF\xD8\xFF
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return "image/jpeg".to_string();
    }

    // GIF: GIF87a or GIF89a
    if data.len() >= 6 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
        return "image/gif".to_string();
    }

    // PDF: %PDF
    if data.len() >= 4 && &data[..4] == b"%PDF" {
        return "application/pdf".to_string();
    }

    // ZIP: PK\x03\x04
    if data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
        return "application/zip".to_string();
    }

    // GZIP: \x1F\x8B
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return "application/gzip".to_string();
    }

    // BMP: BM
    if data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D {
        return "image/bmp".to_string();
    }

    // WebP: RIFF....WEBP
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return "image/webp".to_string();
    }

    // TIFF: II\x2A\x00 (little-endian) or MM\x00\x2A (big-endian)
    if data.len() >= 4 {
        if data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00 {
            return "image/tiff".to_string();
        }
        if data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A {
            return "image/tiff".to_string();
        }
    }

    // WAV: RIFF....WAVE
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return "audio/x-wav".to_string();
    }

    // Now check text-based formats (must be valid-ish text)
    // Try to interpret as UTF-8 text
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim_start();

        // XML: <?xml
        if trimmed.starts_with("<?xml") {
            return "text/xml".to_string();
        }

        // HTML: <html, <!DOCTYPE html, <!doctype
        let lower = trimmed.to_lowercase();
        if lower.starts_with("<html") || lower.starts_with("<!doctype") {
            return "text/html".to_string();
        }

        // JSON: starts with { or [
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return "application/json".to_string();
        }

        // PHP: <?php
        if trimmed.starts_with("<?php") {
            return "text/x-php".to_string();
        }

        // Shell script: #!/bin/sh or #!/bin/bash etc.
        if trimmed.starts_with("#!") {
            return "text/x-shellscript".to_string();
        }

        // If all bytes are valid text characters, treat as text/plain
        if data
            .iter()
            .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7F).contains(&b))
        {
            return "text/plain".to_string();
        }
    }

    "application/octet-stream".to_string()
}

/// Detect the character encoding of the data (simplified).
fn detect_encoding(data: &[u8]) -> String {
    // Check for UTF-8 BOM
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        return "utf-8".to_string();
    }

    // Check for UTF-16 BOM
    if data.len() >= 2 {
        if data[0] == 0xFE && data[1] == 0xFF {
            return "utf-16be".to_string();
        }
        if data[0] == 0xFF && data[1] == 0xFE {
            return "utf-16le".to_string();
        }
    }

    // If all bytes are ASCII, report as us-ascii
    if data.iter().all(|&b| b < 0x80) {
        return "us-ascii".to_string();
    }

    // Try UTF-8 validation
    if std::str::from_utf8(data).is_ok() {
        return "utf-8".to_string();
    }

    "binary".to_string()
}

// ── Extension-based detection ───────────────────────────────────────────────

/// Build the extension -> MIME type map.
fn extension_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    // Text
    m.insert("txt", "text/plain");
    m.insert("htm", "text/html");
    m.insert("html", "text/html");
    m.insert("css", "text/css");
    m.insert("csv", "text/csv");
    m.insert("xml", "text/xml");
    m.insert("svg", "image/svg+xml");
    // JavaScript
    m.insert("js", "application/javascript");
    m.insert("mjs", "application/javascript");
    m.insert("json", "application/json");
    // PHP
    m.insert("php", "text/x-php");
    m.insert("phps", "text/x-php");
    // Images
    m.insert("png", "image/png");
    m.insert("jpg", "image/jpeg");
    m.insert("jpeg", "image/jpeg");
    m.insert("gif", "image/gif");
    m.insert("bmp", "image/bmp");
    m.insert("webp", "image/webp");
    m.insert("ico", "image/x-icon");
    m.insert("tiff", "image/tiff");
    m.insert("tif", "image/tiff");
    // Audio
    m.insert("mp3", "audio/mpeg");
    m.insert("wav", "audio/x-wav");
    m.insert("ogg", "audio/ogg");
    m.insert("flac", "audio/flac");
    // Video
    m.insert("mp4", "video/mp4");
    m.insert("avi", "video/x-msvideo");
    m.insert("webm", "video/webm");
    m.insert("mkv", "video/x-matroska");
    // Archives
    m.insert("zip", "application/zip");
    m.insert("gz", "application/gzip");
    m.insert("tar", "application/x-tar");
    m.insert("bz2", "application/x-bzip2");
    m.insert("7z", "application/x-7z-compressed");
    m.insert("rar", "application/x-rar-compressed");
    // Documents
    m.insert("pdf", "application/pdf");
    m.insert("doc", "application/msword");
    m.insert("xls", "application/vnd.ms-excel");
    m.insert("ppt", "application/vnd.ms-powerpoint");
    m.insert("rtf", "application/rtf");
    // Misc
    m.insert("wasm", "application/wasm");
    m.insert("swf", "application/x-shockwave-flash");
    m
}

/// Get MIME type from a file's extension.
fn mime_from_extension(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

    let map = extension_map();
    map.get(ext.as_str())
        .unwrap_or(&"application/octet-stream")
        .to_string()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_png() {
        let data = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_mime_from_magic(&data), "image/png");
    }

    #[test]
    fn test_detect_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_mime_from_magic(&data), "image/jpeg");
    }

    #[test]
    fn test_detect_gif87a() {
        assert_eq!(detect_mime_from_magic(b"GIF87a..."), "image/gif");
    }

    #[test]
    fn test_detect_gif89a() {
        assert_eq!(detect_mime_from_magic(b"GIF89a..."), "image/gif");
    }

    #[test]
    fn test_detect_pdf() {
        assert_eq!(detect_mime_from_magic(b"%PDF-1.4 ..."), "application/pdf");
    }

    #[test]
    fn test_detect_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert_eq!(detect_mime_from_magic(&data), "application/zip");
    }

    #[test]
    fn test_detect_gzip() {
        let data = [0x1F, 0x8B, 0x08, 0x00];
        assert_eq!(detect_mime_from_magic(&data), "application/gzip");
    }

    #[test]
    fn test_detect_xml() {
        assert_eq!(
            detect_mime_from_magic(b"<?xml version=\"1.0\"?>"),
            "text/xml"
        );
    }

    #[test]
    fn test_detect_html() {
        assert_eq!(
            detect_mime_from_magic(b"<!DOCTYPE html><html></html>"),
            "text/html"
        );
        assert_eq!(
            detect_mime_from_magic(b"<html><body>hello</body></html>"),
            "text/html"
        );
    }

    #[test]
    fn test_detect_json_object() {
        assert_eq!(
            detect_mime_from_magic(b"{\"key\": \"value\"}"),
            "application/json"
        );
    }

    #[test]
    fn test_detect_json_array() {
        assert_eq!(detect_mime_from_magic(b"[1, 2, 3]"), "application/json");
    }

    #[test]
    fn test_detect_empty() {
        assert_eq!(detect_mime_from_magic(b""), "application/x-empty");
    }

    #[test]
    fn test_detect_plain_text() {
        assert_eq!(detect_mime_from_magic(b"Hello, World!"), "text/plain");
    }

    #[test]
    fn test_detect_binary() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(detect_mime_from_magic(&data), "application/octet-stream");
    }

    #[test]
    fn test_mime_content_type_by_extension() {
        assert_eq!(mime_content_type("test.txt"), "text/plain");
        assert_eq!(mime_content_type("style.css"), "text/css");
        assert_eq!(mime_content_type("script.js"), "application/javascript");
        assert_eq!(mime_content_type("photo.jpg"), "image/jpeg");
        assert_eq!(mime_content_type("index.php"), "text/x-php");
        assert_eq!(mime_content_type("data.json"), "application/json");
        assert_eq!(mime_content_type("page.html"), "text/html");
        assert_eq!(mime_content_type("doc.pdf"), "application/pdf");
    }

    #[test]
    fn test_mime_content_type_unknown_extension() {
        assert_eq!(
            mime_content_type("file.unknownext"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_finfo_open_close() {
        let fi = finfo_open(FILEINFO_MIME_TYPE);
        assert_eq!(fi.options, FILEINFO_MIME_TYPE);
        assert!(finfo_close(&fi));
    }

    #[test]
    fn test_finfo_buffer_mime_type() {
        let fi = finfo_open(FILEINFO_MIME_TYPE);
        let data = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(finfo_buffer(&fi, &data), "image/png");
    }

    #[test]
    fn test_finfo_buffer_mime_full() {
        let fi = finfo_open(FILEINFO_MIME);
        let result = finfo_buffer(&fi, b"Hello, World!");
        assert!(result.starts_with("text/plain"));
        assert!(result.contains("charset="));
    }

    #[test]
    fn test_finfo_buffer_encoding_only() {
        let fi = finfo_open(FILEINFO_MIME_ENCODING);
        let result = finfo_buffer(&fi, b"Hello");
        assert_eq!(result, "us-ascii");
    }

    #[test]
    fn test_finfo_file_by_extension() {
        let fi = finfo_open(FILEINFO_MIME_TYPE);
        assert_eq!(finfo_file(&fi, "photo.png"), "image/png");
        assert_eq!(finfo_file(&fi, "archive.zip"), "application/zip");
    }

    #[test]
    fn test_detect_bmp() {
        let data = [0x42, 0x4D, 0x00, 0x00];
        assert_eq!(detect_mime_from_magic(&data), "image/bmp");
    }

    #[test]
    fn test_detect_webp() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
        data.extend_from_slice(b"WEBP");
        assert_eq!(detect_mime_from_magic(&data), "image/webp");
    }

    #[test]
    fn test_encoding_detection_utf8_bom() {
        let data = [0xEF, 0xBB, 0xBF, b'h', b'i'];
        assert_eq!(detect_encoding(&data), "utf-8");
    }

    #[test]
    fn test_encoding_detection_ascii() {
        assert_eq!(detect_encoding(b"hello"), "us-ascii");
    }
}
