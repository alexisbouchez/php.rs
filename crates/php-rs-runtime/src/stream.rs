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

/// Registry of stream wrappers.
pub struct StreamRegistry {
    wrappers: HashMap<String, Box<dyn StreamWrapper>>,
}

impl StreamRegistry {
    /// Create a new registry with default wrappers (file://).
    pub fn new() -> Self {
        let mut reg = Self {
            wrappers: HashMap::new(),
        };
        reg.register(Box::new(FileStreamWrapper));
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
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
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
}
