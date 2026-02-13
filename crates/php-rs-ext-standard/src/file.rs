//! PHP file functions.
//!
//! Reference: php-src/ext/standard/file.c, filestat.c, dir.c

use std::io::{self, BufRead, Read, Seek, Write};
use std::path::Path;

// ── 8.5.1: Core file I/O ────────────────────────────────────────────────────

/// file_get_contents() — Read entire file into a string.
pub fn php_file_get_contents(filename: &str) -> io::Result<String> {
    std::fs::read_to_string(filename)
}

/// file_put_contents() — Write data to a file.
/// Returns number of bytes written.
pub fn php_file_put_contents(filename: &str, data: &str, append: bool) -> io::Result<usize> {
    let mut opts = std::fs::OpenOptions::new();
    if append {
        opts.create(true).append(true);
    } else {
        opts.create(true).write(true).truncate(true);
    }
    let mut file = opts.open(filename)?;
    file.write_all(data.as_bytes())?;
    Ok(data.len())
}

/// file() — Read entire file into an array (one line per element).
pub fn php_file(filename: &str, skip_empty_lines: bool) -> io::Result<Vec<String>> {
    let content = std::fs::read_to_string(filename)?;
    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    if skip_empty_lines {
        Ok(lines.into_iter().filter(|l| !l.is_empty()).collect())
    } else {
        Ok(lines)
    }
}

// ── 8.5.5: File existence & type checks ──────────────────────────────────────

/// file_exists() — Check whether a file or directory exists.
pub fn php_file_exists(filename: &str) -> bool {
    Path::new(filename).exists()
}

/// is_file() — Tells whether the filename is a regular file.
pub fn php_is_file(filename: &str) -> bool {
    Path::new(filename).is_file()
}

/// is_dir() — Tells whether the filename is a directory.
pub fn php_is_dir(filename: &str) -> bool {
    Path::new(filename).is_dir()
}

/// is_readable() — Tells whether a file exists and is readable.
pub fn php_is_readable(filename: &str) -> bool {
    std::fs::File::open(filename).is_ok()
}

/// is_writable() / is_writeable() — Tells whether the filename is writable.
pub fn php_is_writable(filename: &str) -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open(filename)
        .is_ok()
}

// ── 8.5.6: File stat info ────────────────────────────────────────────────────

/// filesize() — Gets file size.
pub fn php_filesize(filename: &str) -> io::Result<u64> {
    Ok(std::fs::metadata(filename)?.len())
}

/// filemtime() — Gets file modification time (Unix timestamp).
pub fn php_filemtime(filename: &str) -> io::Result<u64> {
    let meta = std::fs::metadata(filename)?;
    Ok(meta
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0))
}

// ── 8.5.7: File manipulation ─────────────────────────────────────────────────

/// mkdir() — Makes directory.
pub fn php_mkdir(pathname: &str, recursive: bool) -> io::Result<()> {
    if recursive {
        std::fs::create_dir_all(pathname)
    } else {
        std::fs::create_dir(pathname)
    }
}

/// rmdir() — Removes directory.
pub fn php_rmdir(dirname: &str) -> io::Result<()> {
    std::fs::remove_dir(dirname)
}

/// rename() — Renames a file or directory.
pub fn php_rename(from: &str, to: &str) -> io::Result<()> {
    std::fs::rename(from, to)
}

/// unlink() — Deletes a file.
pub fn php_unlink(filename: &str) -> io::Result<()> {
    std::fs::remove_file(filename)
}

/// copy() — Copies file.
pub fn php_copy(source: &str, dest: &str) -> io::Result<u64> {
    std::fs::copy(source, dest)
}

// ── 8.5.8: Directory reading ─────────────────────────────────────────────────

/// scandir() — List files and directories inside the specified path.
pub fn php_scandir(directory: &str) -> io::Result<Vec<String>> {
    let mut entries: Vec<String> = std::fs::read_dir(directory)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    entries.sort();
    // PHP includes . and ..
    let mut result = vec![".".to_string(), "..".to_string()];
    result.append(&mut entries);
    Ok(result)
}

// ── 8.5.9: Temp files ───────────────────────────────────────────────────────

/// sys_get_temp_dir() — Returns directory path used for temporary files.
pub fn php_sys_get_temp_dir() -> String {
    std::env::temp_dir().to_string_lossy().to_string()
}

/// tempnam() — Create file with unique file name.
pub fn php_tempnam(dir: &str, prefix: &str) -> io::Result<String> {
    let dir = Path::new(dir);
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Directory does not exist",
        ));
    }

    // Generate unique filename
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let filename = format!("{}{}", prefix, timestamp);
    let path = dir.join(filename);

    // Create the file
    std::fs::File::create(&path)?;
    Ok(path.to_string_lossy().to_string())
}

// ── 8.5.10: Path functions ───────────────────────────────────────────────────

/// dirname() — Returns a parent directory's path.
pub fn php_dirname(path: &str, levels: usize) -> String {
    let mut p = Path::new(path);
    for _ in 0..levels {
        if let Some(parent) = p.parent() {
            p = parent;
        } else {
            break;
        }
    }
    p.to_string_lossy().to_string()
}

/// basename() — Returns trailing name component of path.
pub fn php_basename(path: &str, suffix: Option<&str>) -> String {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if let Some(suffix) = suffix {
        if name.ends_with(suffix) {
            return name[..name.len() - suffix.len()].to_string();
        }
    }

    name
}

/// pathinfo() — Returns information about a file path.
pub fn php_pathinfo(path: &str) -> PathInfo {
    let p = Path::new(path);
    PathInfo {
        dirname: p
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string()),
        basename: p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        extension: p
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default(),
        filename: p
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    }
}

/// realpath() — Returns canonicalized absolute pathname.
pub fn php_realpath(path: &str) -> io::Result<String> {
    std::fs::canonicalize(path).map(|p| p.to_string_lossy().to_string())
}

/// Result of pathinfo().
#[derive(Debug, Clone, PartialEq)]
pub struct PathInfo {
    pub dirname: String,
    pub basename: String,
    pub extension: String,
    pub filename: String,
}

// ── File handle operations ───────────────────────────────────────────────────

/// A PHP file handle wrapping std::fs::File.
pub struct FileHandle {
    file: std::fs::File,
    eof: bool,
}

impl FileHandle {
    /// fopen() — Opens file.
    pub fn open(filename: &str, mode: &str) -> io::Result<Self> {
        let file = match mode {
            "r" | "rb" => std::fs::File::open(filename)?,
            "w" | "wb" => std::fs::File::create(filename)?,
            "a" | "ab" => std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(filename)?,
            "r+" | "r+b" | "rb+" => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(filename)?,
            "w+" | "w+b" | "wb+" => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(filename)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid mode: {}", mode),
                ))
            }
        };
        Ok(Self { file, eof: false })
    }

    /// fread() — Binary-safe file read.
    pub fn read(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        let n = self.file.read(&mut buf)?;
        buf.truncate(n);
        if n == 0 {
            self.eof = true;
        }
        Ok(buf)
    }

    /// fwrite() — Binary-safe file write.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.file.write(data)
    }

    /// fgets() — Gets line from file pointer.
    pub fn gets(&mut self) -> io::Result<Option<String>> {
        let mut reader = io::BufReader::new(&self.file);
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            self.eof = true;
            return Ok(None);
        }
        Ok(Some(line))
    }

    /// feof() — Tests for end-of-file.
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// fseek() — Seeks on a file pointer.
    pub fn seek(&mut self, offset: i64, whence: SeekWhence) -> io::Result<()> {
        let pos = match whence {
            SeekWhence::Set => io::SeekFrom::Start(offset as u64),
            SeekWhence::Cur => io::SeekFrom::Current(offset),
            SeekWhence::End => io::SeekFrom::End(offset),
        };
        self.file.seek(pos)?;
        self.eof = false;
        Ok(())
    }

    /// ftell() — Returns the current position of the file read/write pointer.
    pub fn tell(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    /// rewind() — Rewinds the position of a file pointer.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.file.seek(io::SeekFrom::Start(0))?;
        self.eof = false;
        Ok(())
    }

    /// fflush() — Flushes the output to a file.
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// ftruncate() — Truncates a file to a given length.
    pub fn truncate(&mut self, size: u64) -> io::Result<()> {
        self.file.set_len(size)
    }
}

/// Seek whence constants.
#[derive(Debug, Clone, Copy)]
pub enum SeekWhence {
    Set, // SEEK_SET
    Cur, // SEEK_CUR
    End, // SEEK_END
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("php_rs_test_{}", name))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn test_file_get_put_contents() {
        let path = temp_path("get_put.txt");
        php_file_put_contents(&path, "hello world", false).unwrap();
        let contents = php_file_get_contents(&path).unwrap();
        assert_eq!(contents, "hello world");

        // Append
        php_file_put_contents(&path, " more", true).unwrap();
        let contents = php_file_get_contents(&path).unwrap();
        assert_eq!(contents, "hello world more");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_file() {
        let path = temp_path("file_lines.txt");
        php_file_put_contents(&path, "line1\nline2\n\nline3", false).unwrap();
        let lines = php_file(&path, false).unwrap();
        assert_eq!(lines.len(), 4);

        let lines = php_file(&path, true).unwrap();
        assert_eq!(lines.len(), 3); // Empty line skipped

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_file_exists() {
        let path = temp_path("exists.txt");
        assert!(!php_file_exists(&path));
        php_file_put_contents(&path, "test", false).unwrap();
        assert!(php_file_exists(&path));
        assert!(php_is_file(&path));
        assert!(!php_is_dir(&path));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_mkdir_rmdir() {
        let path = temp_path("testdir_mk");
        let _ = std::fs::remove_dir_all(&path); // Clean up from previous runs
        php_mkdir(&path, false).unwrap();
        assert!(php_is_dir(&path));
        php_rmdir(&path).unwrap();
        assert!(!php_is_dir(&path));
    }

    #[test]
    fn test_rename_copy_unlink() {
        let a = temp_path("rename_a.txt");
        let b = temp_path("rename_b.txt");
        let c = temp_path("rename_c.txt");

        php_file_put_contents(&a, "data", false).unwrap();
        php_rename(&a, &b).unwrap();
        assert!(!php_file_exists(&a));
        assert!(php_file_exists(&b));

        php_copy(&b, &c).unwrap();
        assert!(php_file_exists(&c));
        assert_eq!(php_file_get_contents(&c).unwrap(), "data");

        php_unlink(&b).unwrap();
        php_unlink(&c).unwrap();
    }

    #[test]
    fn test_filesize() {
        let path = temp_path("size.txt");
        php_file_put_contents(&path, "12345", false).unwrap();
        assert_eq!(php_filesize(&path).unwrap(), 5);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_scandir() {
        let dir = temp_path("scandir_test");
        let _ = std::fs::remove_dir_all(&dir);
        php_mkdir(&dir, false).unwrap();
        php_file_put_contents(&format!("{}/a.txt", dir), "a", false).unwrap();
        php_file_put_contents(&format!("{}/b.txt", dir), "b", false).unwrap();

        let entries = php_scandir(&dir).unwrap();
        assert!(entries.contains(&".".to_string()));
        assert!(entries.contains(&"..".to_string()));
        assert!(entries.contains(&"a.txt".to_string()));
        assert!(entries.contains(&"b.txt".to_string()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_dirname_basename() {
        assert_eq!(php_dirname("/foo/bar/baz.php", 1), "/foo/bar");
        assert_eq!(php_dirname("/foo/bar/baz.php", 2), "/foo");
        assert_eq!(php_basename("/foo/bar/baz.php", None), "baz.php");
        assert_eq!(php_basename("/foo/bar/baz.php", Some(".php")), "baz");
    }

    #[test]
    fn test_pathinfo() {
        let info = php_pathinfo("/foo/bar/baz.php");
        assert_eq!(info.dirname, "/foo/bar");
        assert_eq!(info.basename, "baz.php");
        assert_eq!(info.extension, "php");
        assert_eq!(info.filename, "baz");
    }

    #[test]
    fn test_sys_get_temp_dir() {
        let dir = php_sys_get_temp_dir();
        assert!(!dir.is_empty());
        assert!(php_is_dir(&dir));
    }

    #[test]
    fn test_file_handle_read_write() {
        let path = temp_path("fh_test.txt");
        {
            let mut fh = FileHandle::open(&path, "w+").unwrap();
            fh.write(b"hello world").unwrap();
            fh.rewind().unwrap();
            let data = fh.read(5).unwrap();
            assert_eq!(&data, b"hello");
            assert_eq!(fh.tell().unwrap(), 5);
            assert!(!fh.eof());
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_file_handle_seek() {
        let path = temp_path("fh_seek.txt");
        {
            let mut fh = FileHandle::open(&path, "w+").unwrap();
            fh.write(b"abcdefghij").unwrap();
            fh.seek(3, SeekWhence::Set).unwrap();
            assert_eq!(fh.tell().unwrap(), 3);
            let data = fh.read(3).unwrap();
            assert_eq!(&data, b"def");
        }
        std::fs::remove_file(&path).unwrap();
    }
}
