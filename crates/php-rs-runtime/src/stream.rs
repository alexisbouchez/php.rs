//! PHP stream wrapper system.
//!
//! Implements the stream abstraction layer: file://, php://stdin, php://stdout,
//! php://memory, php://temp, and the StreamWrapper registration API.
//!
//! Reference: php-src/main/streams/streams.c, php-src/main/streams/php_stream_context.h

use std::collections::HashMap;
use std::io::{self, Read, Write};

/// Stream open mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    Read,
    Write,
    Append,
    ReadWrite,
    ReadWriteCreate,
}

impl StreamMode {
    /// Parse a PHP fopen() mode string.
    pub fn from_php_mode(mode: &str) -> Option<Self> {
        // Strip binary/text mode flags — Rust doesn't distinguish
        let mode = mode.replace(['b', 't'], "");
        match mode.as_str() {
            "r" => Some(StreamMode::Read),
            "w" => Some(StreamMode::Write),
            "a" => Some(StreamMode::Append),
            "r+" => Some(StreamMode::ReadWrite),
            "w+" | "a+" | "x" | "x+" | "c" | "c+" => Some(StreamMode::ReadWriteCreate),
            _ => None,
        }
    }

    /// Check if this mode allows reading.
    pub fn is_readable(self) -> bool {
        matches!(
            self,
            StreamMode::Read | StreamMode::ReadWrite | StreamMode::ReadWriteCreate
        )
    }

    /// Check if this mode allows writing.
    pub fn is_writable(self) -> bool {
        matches!(
            self,
            StreamMode::Write
                | StreamMode::Append
                | StreamMode::ReadWrite
                | StreamMode::ReadWriteCreate
        )
    }
}

/// A PHP stream — abstraction over file, network, memory, etc.
pub struct PhpStream {
    /// The wrapper that opened this stream.
    pub wrapper: String,
    /// The original URI used to open this stream.
    pub uri: String,
    /// The mode this stream was opened with.
    pub mode: StreamMode,
    /// The backing storage.
    storage: StreamStorage,
    /// Current read/write position.
    position: usize,
    /// Whether the stream has reached EOF.
    eof: bool,
}

enum StreamStorage {
    /// In-memory buffer (php://memory, php://temp).
    Memory(Vec<u8>),
    /// File on disk.
    File(std::fs::File),
}

impl PhpStream {
    /// Create an in-memory stream.
    pub fn memory() -> Self {
        Self {
            wrapper: "php".to_string(),
            uri: "php://memory".to_string(),
            mode: StreamMode::ReadWrite,
            storage: StreamStorage::Memory(Vec::new()),
            position: 0,
            eof: false,
        }
    }

    /// Create an in-memory stream with pre-loaded data.
    pub fn from_memory(uri: String, data: Vec<u8>, mode: StreamMode) -> Self {
        Self {
            wrapper: "vfs".to_string(),
            uri,
            mode,
            storage: StreamStorage::Memory(data),
            position: 0,
            eof: false,
        }
    }

    /// Create a stream from a file.
    pub fn from_file(uri: String, file: std::fs::File, mode: StreamMode) -> Self {
        Self {
            wrapper: "file".to_string(),
            uri,
            mode,
            storage: StreamStorage::File(file),
            position: 0,
            eof: false,
        }
    }

    /// Read up to `length` bytes.
    pub fn read(&mut self, length: usize) -> io::Result<Vec<u8>> {
        if !self.mode.is_readable() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Stream not opened for reading",
            ));
        }

        match &mut self.storage {
            StreamStorage::Memory(buf) => {
                let available = buf.len().saturating_sub(self.position);
                let to_read = length.min(available);
                if to_read == 0 {
                    self.eof = true;
                    return Ok(Vec::new());
                }
                let data = buf[self.position..self.position + to_read].to_vec();
                self.position += to_read;
                if self.position >= buf.len() {
                    self.eof = true;
                }
                Ok(data)
            }
            StreamStorage::File(file) => {
                let mut buf = vec![0u8; length];
                let n = file.read(&mut buf)?;
                buf.truncate(n);
                if n == 0 {
                    self.eof = true;
                }
                self.position += n;
                Ok(buf)
            }
        }
    }

    /// Write data to the stream.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.mode.is_writable() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Stream not opened for writing",
            ));
        }

        match &mut self.storage {
            StreamStorage::Memory(buf) => {
                if self.position >= buf.len() {
                    buf.extend_from_slice(data);
                } else {
                    let end = self.position + data.len();
                    if end > buf.len() {
                        buf.resize(end, 0);
                    }
                    buf[self.position..end].copy_from_slice(data);
                }
                self.position += data.len();
                self.eof = false;
                Ok(data.len())
            }
            StreamStorage::File(file) => {
                let n = file.write(data)?;
                self.position += n;
                Ok(n)
            }
        }
    }

    /// Get the current position (ftell).
    pub fn tell(&self) -> usize {
        self.position
    }

    /// Seek to a position (fseek).
    pub fn seek(&mut self, position: usize) -> io::Result<()> {
        match &self.storage {
            StreamStorage::Memory(buf) => {
                self.position = position.min(buf.len());
                self.eof = false;
                Ok(())
            }
            StreamStorage::File(file) => {
                use std::io::Seek;
                let mut file = file;
                file.seek(io::SeekFrom::Start(position as u64))?;
                self.position = position;
                self.eof = false;
                Ok(())
            }
        }
    }

    /// Check if EOF has been reached.
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// Get all contents as a string (file_get_contents equivalent for memory streams).
    pub fn get_contents(&self) -> Option<String> {
        match &self.storage {
            StreamStorage::Memory(buf) => String::from_utf8(buf.clone()).ok(),
            StreamStorage::File(_) => None, // Would need to read the whole file
        }
    }

    /// Close the stream.
    pub fn close(self) {
        // File will be closed on drop; memory freed.
        drop(self);
    }
}

/// Stream wrapper trait — extensions implement this to provide custom schemes.
///
/// E.g., file://, http://, ftp://, php://, data://, compress.zlib://
pub trait StreamWrapper: Send + Sync {
    /// The scheme this wrapper handles (e.g., "file", "php", "http").
    fn scheme(&self) -> &str;

    /// Open a stream for the given URI.
    fn open(&self, uri: &str, mode: StreamMode) -> io::Result<PhpStream>;

    /// Check if a path/URI exists (for file_exists, is_file, etc.).
    fn stat(&self, _uri: &str) -> io::Result<StreamStat> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stat not supported",
        ))
    }

    /// Delete a file (unlink).
    fn unlink(&self, _uri: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unlink not supported",
        ))
    }

    /// Rename a file.
    fn rename(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "rename not supported",
        ))
    }

    /// Create a directory.
    fn mkdir(&self, _uri: &str, _recursive: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mkdir not supported",
        ))
    }

    /// Remove a directory.
    fn rmdir(&self, _uri: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "rmdir not supported",
        ))
    }
}

/// File stat result.
#[derive(Debug, Clone)]
pub struct StreamStat {
    /// File size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Whether this is a regular file.
    pub is_file: bool,
    /// Last modification time (Unix timestamp).
    pub mtime: u64,
    /// Last access time.
    pub atime: u64,
    /// Creation time.
    pub ctime: u64,
    /// File permissions (Unix mode).
    pub mode: u32,
}

/// The file:// stream wrapper (default).
pub struct FileStreamWrapper;

impl StreamWrapper for FileStreamWrapper {
    fn scheme(&self) -> &str {
        "file"
    }

    fn open(&self, uri: &str, mode: StreamMode) -> io::Result<PhpStream> {
        // Strip file:// prefix if present
        let path = uri.strip_prefix("file://").unwrap_or(uri);

        let file = match mode {
            StreamMode::Read => std::fs::File::open(path)?,
            StreamMode::Write => std::fs::File::create(path)?,
            StreamMode::Append => std::fs::OpenOptions::new().append(true).open(path)?,
            StreamMode::ReadWrite => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?,
            StreamMode::ReadWriteCreate => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?,
        };

        Ok(PhpStream::from_file(uri.to_string(), file, mode))
    }

    fn stat(&self, uri: &str) -> io::Result<StreamStat> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let metadata = std::fs::metadata(path)?;

        Ok(StreamStat {
            size: metadata.len(),
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            mtime: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            atime: 0,
            ctime: 0,
            mode: 0o644,
        })
    }

    fn unlink(&self, uri: &str) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        std::fs::remove_file(path)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let from = from.strip_prefix("file://").unwrap_or(from);
        let to = to.strip_prefix("file://").unwrap_or(to);
        std::fs::rename(from, to)
    }

    fn mkdir(&self, uri: &str, recursive: bool) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        if recursive {
            std::fs::create_dir_all(path)
        } else {
            std::fs::create_dir(path)
        }
    }

    fn rmdir(&self, uri: &str) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        std::fs::remove_dir(path)
    }
}

/// Stream notification callback type.
/// Matches PHP's stream_notification_callback signature:
/// (notification_code, severity, message, message_code, bytes_transferred, bytes_max)
pub type StreamNotificationCallback = Box<dyn Fn(i32, i32, &str, i32, i64, i64) + Send + Sync>;

/// Stream notification codes (matching PHP constants).
pub const STREAM_NOTIFY_RESOLVE: i32 = 1;
pub const STREAM_NOTIFY_CONNECT: i32 = 2;
pub const STREAM_NOTIFY_AUTH_REQUIRED: i32 = 3;
pub const STREAM_NOTIFY_MIME_TYPE_IS: i32 = 4;
pub const STREAM_NOTIFY_FILE_SIZE_IS: i32 = 5;
pub const STREAM_NOTIFY_REDIRECTED: i32 = 6;
pub const STREAM_NOTIFY_PROGRESS: i32 = 7;
pub const STREAM_NOTIFY_COMPLETED: i32 = 8;
pub const STREAM_NOTIFY_FAILURE: i32 = 9;
pub const STREAM_NOTIFY_AUTH_RESULT: i32 = 10;

/// Stream notification severity levels.
pub const STREAM_NOTIFY_SEVERITY_INFO: i32 = 0;
pub const STREAM_NOTIFY_SEVERITY_WARN: i32 = 1;
pub const STREAM_NOTIFY_SEVERITY_ERR: i32 = 2;

/// A stream context with options, params, and optional notification callback.
pub struct StreamContextData {
    /// Wrapper-specific options: [wrapper_name][option_name] = value_string
    pub options: HashMap<String, HashMap<String, String>>,
    /// Additional parameters.
    pub params: HashMap<String, String>,
    /// Optional notification callback.
    pub notification: Option<StreamNotificationCallback>,
}

impl StreamContextData {
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
            params: HashMap::new(),
            notification: None,
        }
    }

    /// Set a wrapper-level option.
    pub fn set_option(&mut self, wrapper: &str, key: &str, value: &str) {
        self.options
            .entry(wrapper.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    /// Get a wrapper-level option.
    pub fn get_option(&self, wrapper: &str, key: &str) -> Option<&str> {
        self.options
            .get(wrapper)
            .and_then(|m| m.get(key))
            .map(|s| s.as_str())
    }

    /// Set notification callback.
    pub fn set_notification(&mut self, cb: StreamNotificationCallback) {
        self.notification = Some(cb);
    }

    /// Fire a notification event.
    pub fn notify(
        &self,
        code: i32,
        severity: i32,
        message: &str,
        msg_code: i32,
        bytes_transferred: i64,
        bytes_max: i64,
    ) {
        if let Some(ref cb) = self.notification {
            cb(
                code,
                severity,
                message,
                msg_code,
                bytes_transferred,
                bytes_max,
            );
        }
    }
}

impl Default for StreamContextData {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StreamContextData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamContextData")
            .field("options", &self.options)
            .field("params", &self.params)
            .field("has_notification", &self.notification.is_some())
            .finish()
    }
}

/// Stream filter trait — transforms data passing through a stream.
pub trait StreamFilter: Send + Sync {
    /// The filter name (e.g., "string.toupper", "convert.base64-encode").
    fn name(&self) -> &str;

    /// Filter data passing through.
    /// Returns the transformed data.
    fn filter(&self, data: &[u8]) -> Vec<u8>;
}

/// Built-in stream filter: convert.base64-encode
pub struct Base64EncodeFilter;
impl StreamFilter for Base64EncodeFilter {
    fn name(&self) -> &str {
        "convert.base64-encode"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        simple_base64_encode(data).into_bytes()
    }
}

/// Built-in stream filter: convert.base64-decode
pub struct Base64DecodeFilter;
impl StreamFilter for Base64DecodeFilter {
    fn name(&self) -> &str {
        "convert.base64-decode"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        simple_base64_decode(&String::from_utf8_lossy(data))
    }
}

/// Built-in stream filter: string.toupper
pub struct ToUpperFilter;
impl StreamFilter for ToUpperFilter {
    fn name(&self) -> &str {
        "string.toupper"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        String::from_utf8_lossy(data).to_uppercase().into_bytes()
    }
}

/// Built-in stream filter: string.tolower
pub struct ToLowerFilter;
impl StreamFilter for ToLowerFilter {
    fn name(&self) -> &str {
        "string.tolower"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        String::from_utf8_lossy(data).to_lowercase().into_bytes()
    }
}

/// Built-in stream filter: string.rot13
pub struct Rot13Filter;
impl StreamFilter for Rot13Filter {
    fn name(&self) -> &str {
        "string.rot13"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&b| match b {
                b'a'..=b'm' | b'A'..=b'M' => b + 13,
                b'n'..=b'z' | b'N'..=b'Z' => b - 13,
                _ => b,
            })
            .collect()
    }
}

/// Built-in stream filter: string.strip_tags
pub struct StripTagsFilter;
impl StreamFilter for StripTagsFilter {
    fn name(&self) -> &str {
        "string.strip_tags"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        let s = String::from_utf8_lossy(data);
        let mut result = String::new();
        let mut in_tag = false;
        for ch in s.chars() {
            if ch == '<' {
                in_tag = true;
            } else if ch == '>' {
                in_tag = false;
            } else if !in_tag {
                result.push(ch);
            }
        }
        result.into_bytes()
    }
}

/// Built-in stream filter: convert.quoted-printable-encode
pub struct QpEncodeFilter;
impl StreamFilter for QpEncodeFilter {
    fn name(&self) -> &str {
        "convert.quoted-printable-encode"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        let mut result = String::new();
        for &b in data {
            if (b == b'\t') || (b == b' ') || (b >= 33 && b <= 126 && b != b'=') {
                result.push(b as char);
            } else {
                result.push_str(&format!("={:02X}", b));
            }
        }
        result.into_bytes()
    }
}

/// Built-in stream filter: convert.quoted-printable-decode
pub struct QpDecodeFilter;
impl StreamFilter for QpDecodeFilter {
    fn name(&self) -> &str {
        "convert.quoted-printable-decode"
    }
    fn filter(&self, data: &[u8]) -> Vec<u8> {
        let s = String::from_utf8_lossy(data);
        let mut result = Vec::new();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '=' && i + 2 < chars.len() {
                let hex: String = chars[i + 1..i + 3].iter().collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                    i += 3;
                    continue;
                }
            }
            let mut buf = [0u8; 4];
            let encoded = chars[i].encode_utf8(&mut buf);
            result.extend_from_slice(encoded.as_bytes());
            i += 1;
        }
        result
    }
}

/// Stream filter registry — manages available filter types.
pub struct StreamFilterRegistry {
    filters: HashMap<String, Box<dyn StreamFilter>>,
}

impl StreamFilterRegistry {
    /// Create with built-in filters.
    pub fn new() -> Self {
        let mut reg = Self {
            filters: HashMap::new(),
        };
        reg.register(Box::new(Base64EncodeFilter));
        reg.register(Box::new(Base64DecodeFilter));
        reg.register(Box::new(ToUpperFilter));
        reg.register(Box::new(ToLowerFilter));
        reg.register(Box::new(Rot13Filter));
        reg.register(Box::new(StripTagsFilter));
        reg.register(Box::new(QpEncodeFilter));
        reg.register(Box::new(QpDecodeFilter));
        reg
    }

    /// Register a stream filter.
    pub fn register(&mut self, filter: Box<dyn StreamFilter>) {
        self.filters.insert(filter.name().to_string(), filter);
    }

    /// Apply a named filter to data.
    pub fn apply(&self, name: &str, data: &[u8]) -> Option<Vec<u8>> {
        self.filters.get(name).map(|f| f.filter(data))
    }

    /// Apply a chain of filters sequentially.
    pub fn apply_chain(&self, names: &[String], mut data: Vec<u8>) -> Vec<u8> {
        for name in names {
            if let Some(filtered) = self.apply(name, &data) {
                data = filtered;
            }
        }
        data
    }

    /// List registered filter names.
    pub fn registered_filters(&self) -> Vec<&str> {
        self.filters.keys().map(|k| k.as_str()).collect()
    }

    /// Check if a filter name is registered.
    pub fn has_filter(&self, name: &str) -> bool {
        self.filters.contains_key(name)
    }
}

impl Default for StreamFilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The glob:// stream wrapper — provides directory listing via glob patterns.
pub struct GlobStreamWrapper;

impl StreamWrapper for GlobStreamWrapper {
    fn scheme(&self) -> &str {
        "glob"
    }

    fn open(&self, uri: &str, _mode: StreamMode) -> io::Result<PhpStream> {
        // Strip glob:// prefix
        let pattern = uri.strip_prefix("glob://").unwrap_or(uri);

        // Perform glob matching using a simple implementation
        let entries = simple_glob(pattern)?;

        // Return entries as newline-separated in a memory stream
        let content = entries.join("\n");
        Ok(PhpStream::from_memory(
            uri.to_string(),
            content.into_bytes(),
            StreamMode::Read,
        ))
    }
}

/// Simple glob pattern matching (supports * and ? wildcards).
fn simple_glob(pattern: &str) -> io::Result<Vec<String>> {
    use std::path::Path;

    let path = Path::new(pattern);
    let parent = path.parent().unwrap_or(Path::new("."));
    let file_pattern = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut results = Vec::new();

    if !parent.exists() {
        return Ok(results);
    }

    let entries = std::fs::read_dir(parent)?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if glob_match(&file_pattern, &name) {
            results.push(entry.path().to_string_lossy().to_string());
        }
    }

    results.sort();
    Ok(results)
}

/// Simple glob pattern match (supports *, ?, and character classes [abc]).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    glob_match_inner(&pattern, &text)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    match pattern[0] {
        '*' => {
            // Try matching the rest of pattern with every suffix of text
            for i in 0..=text.len() {
                if glob_match_inner(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if text.is_empty() {
                false
            } else {
                glob_match_inner(&pattern[1..], &text[1..])
            }
        }
        '[' => {
            // Character class
            if text.is_empty() {
                return false;
            }
            if let Some(end) = pattern.iter().position(|&c| c == ']') {
                let class = &pattern[1..end];
                let negate = !class.is_empty() && (class[0] == '!' || class[0] == '^');
                let class = if negate { &class[1..] } else { class };
                let mut matched = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == '-' {
                        // Range: [a-z]
                        if text[0] >= class[i] && text[0] <= class[i + 2] {
                            matched = true;
                        }
                        i += 3;
                    } else {
                        if text[0] == class[i] {
                            matched = true;
                        }
                        i += 1;
                    }
                }
                if negate {
                    matched = !matched;
                }
                if matched {
                    glob_match_inner(&pattern[end + 1..], &text[1..])
                } else {
                    false
                }
            } else {
                // No closing bracket — treat as literal
                !text.is_empty()
                    && pattern[0] == text[0]
                    && glob_match_inner(&pattern[1..], &text[1..])
            }
        }
        c => {
            if text.is_empty() || c != text[0] {
                false
            } else {
                glob_match_inner(&pattern[1..], &text[1..])
            }
        }
    }
}

/// Registry of stream wrappers.
pub struct StreamRegistry {
    wrappers: HashMap<String, Box<dyn StreamWrapper>>,
}

impl StreamRegistry {
    /// Create a new registry with default wrappers (file://, glob://).
    pub fn new() -> Self {
        let mut reg = Self {
            wrappers: HashMap::new(),
        };
        reg.register(Box::new(FileStreamWrapper));
        reg.register(Box::new(GlobStreamWrapper));
        reg
    }

    /// Register a stream wrapper.
    pub fn register(&mut self, wrapper: Box<dyn StreamWrapper>) {
        self.wrappers.insert(wrapper.scheme().to_string(), wrapper);
    }

    /// Unregister a stream wrapper.
    pub fn unregister(&mut self, scheme: &str) -> bool {
        self.wrappers.remove(scheme).is_some()
    }

    /// Register a custom wrapper by scheme name (for stream_wrapper_register).
    pub fn register_custom(&mut self, scheme: String, wrapper: Box<dyn StreamWrapper>) -> bool {
        if self.wrappers.contains_key(&scheme) {
            return false; // Already registered
        }
        self.wrappers.insert(scheme, wrapper);
        true
    }

    /// Open a stream by URI.
    pub fn open(&self, uri: &str, mode: StreamMode) -> io::Result<PhpStream> {
        let (scheme, _path) = if let Some(pos) = uri.find("://") {
            (&uri[..pos], &uri[pos + 3..])
        } else {
            ("file", uri)
        };

        let wrapper = self.wrappers.get(scheme).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("No stream wrapper registered for scheme '{}'", scheme),
            )
        })?;

        wrapper.open(uri, mode)
    }

    /// Get registered wrapper names.
    pub fn registered_wrappers(&self) -> Vec<&str> {
        self.wrappers.keys().map(|k| k.as_str()).collect()
    }

    /// Check if a wrapper is registered for a scheme.
    pub fn has_wrapper(&self, scheme: &str) -> bool {
        self.wrappers.contains_key(scheme)
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple base64 encoding (self-contained, no external dependencies).
fn simple_base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Simple base64 decoding.
fn simple_base64_decode(input: &str) -> Vec<u8> {
    fn char_val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut result = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = char_val(chunk[0]).unwrap_or(0);
        let b = char_val(chunk[1]).unwrap_or(0);
        result.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = char_val(chunk[2]).unwrap_or(0);
            result.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 && chunk[3] != b'=' {
                let d = char_val(chunk[3]).unwrap_or(0);
                result.push((((c & 0x3) << 6) | d) as u8);
            }
        }
    }
    result
}

/// Stream wrapper backed by a VirtualFileSystem.
///
/// Implements the file:// scheme for WASM environments where the real filesystem
/// is not available, delegating all operations to an in-memory VFS.
pub struct VfsStreamWrapper {
    vfs: std::sync::Arc<std::sync::RwLock<crate::vfs::VirtualFileSystem>>,
}

impl VfsStreamWrapper {
    /// Create a new VFS-backed stream wrapper.
    pub fn new(vfs: std::sync::Arc<std::sync::RwLock<crate::vfs::VirtualFileSystem>>) -> Self {
        Self { vfs }
    }
}

impl StreamWrapper for VfsStreamWrapper {
    fn scheme(&self) -> &str {
        "file"
    }

    fn open(&self, uri: &str, mode: StreamMode) -> io::Result<PhpStream> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let vfs = self
            .vfs
            .read()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;

        match mode {
            StreamMode::Read => {
                let data = vfs.read_file(path)?.to_vec();
                Ok(PhpStream::from_memory(uri.to_string(), data, mode))
            }
            StreamMode::Write | StreamMode::ReadWriteCreate => {
                // Start with empty buffer; caller writes then we flush on close
                Ok(PhpStream::from_memory(uri.to_string(), Vec::new(), mode))
            }
            StreamMode::Append => {
                let existing = vfs.read_file(path).unwrap_or(&[]).to_vec();
                let mut stream = PhpStream::from_memory(uri.to_string(), existing.clone(), mode);
                stream.position = existing.len();
                Ok(stream)
            }
            StreamMode::ReadWrite => {
                let data = vfs.read_file(path).unwrap_or(&[]).to_vec();
                Ok(PhpStream::from_memory(uri.to_string(), data, mode))
            }
        }
    }

    fn stat(&self, uri: &str) -> io::Result<StreamStat> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let vfs = self
            .vfs
            .read()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;

        if !vfs.exists(path) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Not found"));
        }

        let size = if vfs.is_file(path) {
            vfs.file_size(path).unwrap_or(0)
        } else {
            0
        };

        Ok(StreamStat {
            size,
            is_dir: vfs.is_dir(path),
            is_file: vfs.is_file(path),
            mtime: 0,
            atime: 0,
            ctime: 0,
            mode: 0o644,
        })
    }

    fn unlink(&self, uri: &str) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let mut vfs = self
            .vfs
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;
        vfs.remove_file(path)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let from = from.strip_prefix("file://").unwrap_or(from);
        let to = to.strip_prefix("file://").unwrap_or(to);
        let mut vfs = self
            .vfs
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;
        vfs.rename(from, to)
    }

    fn mkdir(&self, uri: &str, recursive: bool) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let mut vfs = self
            .vfs
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;
        vfs.mkdir(path, recursive)
    }

    fn rmdir(&self, uri: &str) -> io::Result<()> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let mut vfs = self
            .vfs
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "VFS lock poisoned"))?;
        vfs.rmdir(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_mode_parse() {
        assert_eq!(StreamMode::from_php_mode("r"), Some(StreamMode::Read));
        assert_eq!(StreamMode::from_php_mode("rb"), Some(StreamMode::Read));
        assert_eq!(StreamMode::from_php_mode("w"), Some(StreamMode::Write));
        assert_eq!(StreamMode::from_php_mode("wb"), Some(StreamMode::Write));
        assert_eq!(StreamMode::from_php_mode("a"), Some(StreamMode::Append));
        assert_eq!(StreamMode::from_php_mode("r+"), Some(StreamMode::ReadWrite));
        assert_eq!(
            StreamMode::from_php_mode("r+b"),
            Some(StreamMode::ReadWrite)
        );
        assert_eq!(StreamMode::from_php_mode("z"), None);
    }

    #[test]
    fn test_stream_mode_capabilities() {
        assert!(StreamMode::Read.is_readable());
        assert!(!StreamMode::Read.is_writable());
        assert!(!StreamMode::Write.is_readable());
        assert!(StreamMode::Write.is_writable());
        assert!(StreamMode::ReadWrite.is_readable());
        assert!(StreamMode::ReadWrite.is_writable());
        assert!(StreamMode::Append.is_writable());
        assert!(!StreamMode::Append.is_readable());
    }

    #[test]
    fn test_memory_stream_write_read() {
        let mut stream = PhpStream::memory();
        stream.write(b"Hello, World!").unwrap();
        assert_eq!(stream.tell(), 13);

        stream.seek(0).unwrap();
        let data = stream.read(5).unwrap();
        assert_eq!(&data, b"Hello");
        assert_eq!(stream.tell(), 5);

        let rest = stream.read(100).unwrap();
        assert_eq!(&rest, b", World!");
        assert!(stream.eof());
    }

    #[test]
    fn test_memory_stream_get_contents() {
        let mut stream = PhpStream::memory();
        stream.write(b"test content").unwrap();
        assert_eq!(stream.get_contents(), Some("test content".to_string()));
    }

    #[test]
    fn test_memory_stream_overwrite() {
        let mut stream = PhpStream::memory();
        stream.write(b"AAAA").unwrap();
        stream.seek(0).unwrap();
        stream.write(b"BB").unwrap();
        assert_eq!(stream.get_contents(), Some("BBAA".to_string()));
    }

    #[test]
    fn test_memory_stream_read_only_prevents_write() {
        let mut stream = PhpStream {
            wrapper: "php".to_string(),
            uri: "php://memory".to_string(),
            mode: StreamMode::Read,
            storage: StreamStorage::Memory(b"readonly".to_vec()),
            position: 0,
            eof: false,
        };

        assert!(stream.write(b"nope").is_err());
        let data = stream.read(8).unwrap();
        assert_eq!(&data, b"readonly");
    }

    #[test]
    fn test_stream_registry_default() {
        let reg = StreamRegistry::new();
        let wrappers = reg.registered_wrappers();
        assert!(wrappers.contains(&"file"));
    }

    #[test]
    fn test_stream_registry_unknown_scheme() {
        let reg = StreamRegistry::new();
        let result = reg.open("ftp://example.com/file.txt", StreamMode::Read);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_stream_wrapper_open_nonexistent() {
        let wrapper = FileStreamWrapper;
        let result = wrapper.open("/nonexistent/path/file.txt", StreamMode::Read);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_stream_read_write() {
        use std::io::Write;
        // Create a temp file
        let dir = std::env::temp_dir();
        let path = dir.join("php_rs_stream_test.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"file contents").unwrap();
        }

        let wrapper = FileStreamWrapper;
        let mut stream = wrapper
            .open(path.to_str().unwrap(), StreamMode::Read)
            .unwrap();
        let data = stream.read(100).unwrap();
        assert_eq!(&data, b"file contents");

        // Clean up
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_stream_filter_registry_builtins() {
        let reg = StreamFilterRegistry::new();
        let filters = reg.registered_filters();
        assert!(filters.len() >= 8);
        assert!(reg.has_filter("convert.base64-encode"));
        assert!(reg.has_filter("convert.base64-decode"));
        assert!(reg.has_filter("string.toupper"));
        assert!(reg.has_filter("string.tolower"));
        assert!(reg.has_filter("string.rot13"));
        assert!(reg.has_filter("string.strip_tags"));
        assert!(reg.has_filter("convert.quoted-printable-encode"));
        assert!(reg.has_filter("convert.quoted-printable-decode"));
    }

    #[test]
    fn test_stream_filter_apply() {
        let reg = StreamFilterRegistry::new();
        let result = reg.apply("string.toupper", b"hello world").unwrap();
        assert_eq!(&result, b"HELLO WORLD");

        let result = reg.apply("string.rot13", b"hello").unwrap();
        assert_eq!(&result, b"uryyb");
    }

    #[test]
    fn test_stream_filter_chain() {
        let reg = StreamFilterRegistry::new();
        let names = vec![
            "string.toupper".to_string(),
            "convert.base64-encode".to_string(),
        ];
        let result = reg.apply_chain(&names, b"hello".to_vec());
        // "HELLO" base64-encoded = "SEVMTE8="
        assert_eq!(String::from_utf8_lossy(&result), "SEVMTE8=");
    }

    #[test]
    fn test_stream_context_options() {
        let mut ctx = StreamContextData::new();
        ctx.set_option("http", "method", "POST");
        ctx.set_option("http", "header", "Content-Type: application/json");
        assert_eq!(ctx.get_option("http", "method"), Some("POST"));
        assert_eq!(
            ctx.get_option("http", "header"),
            Some("Content-Type: application/json")
        );
        assert_eq!(ctx.get_option("ftp", "method"), None);
    }

    #[test]
    fn test_stream_context_notification() {
        use std::sync::atomic::{AtomicI32, Ordering};
        use std::sync::Arc;

        let called_code = Arc::new(AtomicI32::new(0));
        let called_code_clone = called_code.clone();

        let mut ctx = StreamContextData::new();
        ctx.set_notification(Box::new(
            move |code, _sev, _msg, _msg_code, _bytes, _max| {
                called_code_clone.store(code, Ordering::SeqCst);
            },
        ));

        ctx.notify(
            STREAM_NOTIFY_PROGRESS,
            STREAM_NOTIFY_SEVERITY_INFO,
            "",
            0,
            100,
            1000,
        );
        assert_eq!(called_code.load(Ordering::SeqCst), STREAM_NOTIFY_PROGRESS);
    }

    #[test]
    fn test_glob_match_basic() {
        assert!(glob_match("*.txt", "file.txt"));
        assert!(glob_match("*.txt", "another.txt"));
        assert!(!glob_match("*.txt", "file.rs"));
        assert!(glob_match("file.*", "file.txt"));
        assert!(glob_match("file.*", "file.rs"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("?ello", "hello"));
        assert!(!glob_match("?ello", "ello"));
    }

    #[test]
    fn test_glob_match_character_class() {
        assert!(glob_match("[abc]", "a"));
        assert!(glob_match("[abc]", "b"));
        assert!(!glob_match("[abc]", "d"));
        assert!(glob_match("[a-z]", "m"));
        assert!(!glob_match("[a-z]", "M"));
        assert!(glob_match("[!a-z]", "M"));
        assert!(!glob_match("[!a-z]", "m"));
    }

    #[test]
    fn test_stream_registry_includes_glob() {
        let reg = StreamRegistry::new();
        let wrappers = reg.registered_wrappers();
        assert!(wrappers.contains(&"file"));
        assert!(wrappers.contains(&"glob"));
    }

    #[test]
    fn test_stream_registry_custom_wrapper() {
        struct CustomWrapper;
        impl StreamWrapper for CustomWrapper {
            fn scheme(&self) -> &str {
                "custom"
            }
            fn open(&self, uri: &str, _mode: StreamMode) -> io::Result<PhpStream> {
                Ok(PhpStream::from_memory(
                    uri.to_string(),
                    b"custom data".to_vec(),
                    StreamMode::Read,
                ))
            }
        }

        let mut reg = StreamRegistry::new();
        assert!(reg.register_custom("custom".to_string(), Box::new(CustomWrapper)));
        // Second registration of same scheme should fail
        struct CustomWrapper2;
        impl StreamWrapper for CustomWrapper2 {
            fn scheme(&self) -> &str {
                "custom"
            }
            fn open(&self, _uri: &str, _mode: StreamMode) -> io::Result<PhpStream> {
                unreachable!()
            }
        }
        assert!(!reg.register_custom("custom".to_string(), Box::new(CustomWrapper2)));

        // Open should work
        let mut stream = reg.open("custom://test", StreamMode::Read).unwrap();
        let data = stream.read(100).unwrap();
        assert_eq!(&data, b"custom data");
    }

    #[test]
    fn test_glob_wrapper_via_registry() {
        let dir = std::env::temp_dir();
        let test_file = dir.join("php_rs_glob_test_12345.txt");
        std::fs::write(&test_file, "test").unwrap();

        let reg = StreamRegistry::new();
        let pattern = format!("glob://{}/*_glob_test_*.txt", dir.to_string_lossy());
        let result = reg.open(&pattern, StreamMode::Read);
        assert!(result.is_ok());

        std::fs::remove_file(&test_file).unwrap();
    }
}
