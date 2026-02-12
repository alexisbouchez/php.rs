//! PHP ftp extension.
//!
//! Implements FTP client functions as a state machine without actual network I/O.
//! Reference: php-src/ext/ftp/
//!
//! Since FTP requires network connectivity, this implementation models the
//! FTP protocol state machine and virtual filesystem for testing purposes.

use std::collections::HashMap;
use std::fmt;

// ── Constants ───────────────────────────────────────────────────────────────

/// FTP transfer modes.
pub const FTP_ASCII: i32 = 1;
pub const FTP_BINARY: i32 = 2;

/// FTP auto-seek modes.
pub const FTP_AUTOSEEK: i32 = 1;
pub const FTP_AUTORESUME: i32 = -1;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FtpError {
    /// Connection failed.
    ConnectionFailed(String),
    /// Login failed (bad credentials).
    LoginFailed(String),
    /// Not connected.
    NotConnected,
    /// Not logged in.
    NotLoggedIn,
    /// Command failed.
    CommandFailed(String),
    /// File not found.
    FileNotFound(String),
    /// Directory not found.
    DirectoryNotFound(String),
    /// Permission denied.
    PermissionDenied,
    /// Timeout.
    Timeout,
}

impl fmt::Display for FtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FtpError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            FtpError::LoginFailed(msg) => write!(f, "Login failed: {}", msg),
            FtpError::NotConnected => write!(f, "Not connected to FTP server"),
            FtpError::NotLoggedIn => write!(f, "Not logged in"),
            FtpError::CommandFailed(msg) => write!(f, "FTP command failed: {}", msg),
            FtpError::FileNotFound(path) => write!(f, "File not found: {}", path),
            FtpError::DirectoryNotFound(path) => write!(f, "Directory not found: {}", path),
            FtpError::PermissionDenied => write!(f, "Permission denied"),
            FtpError::Timeout => write!(f, "Connection timed out"),
        }
    }
}

// ── FTP virtual filesystem entry ────────────────────────────────────────────

#[derive(Debug, Clone)]
enum FsEntry {
    File { content: Vec<u8>, size: i64 },
    Directory,
}

// ── FtpConnection ───────────────────────────────────────────────────────────

/// State of an FTP connection.
#[derive(Debug, Clone, PartialEq)]
pub enum FtpState {
    /// Not connected.
    Disconnected,
    /// Connected but not authenticated.
    Connected,
    /// Authenticated and ready.
    LoggedIn,
}

/// Represents an FTP connection, including connection state and a virtual
/// filesystem for testing.
#[derive(Debug, Clone)]
pub struct FtpConnection {
    /// The remote host.
    pub host: String,
    /// The remote port.
    pub port: u16,
    /// Connection timeout in seconds.
    pub timeout: u32,
    /// Current connection state.
    pub state: FtpState,
    /// Current working directory on the server.
    pub cwd: String,
    /// Whether passive mode is enabled.
    pub passive: bool,
    /// The username used for login.
    pub username: String,
    /// Transfer mode (ASCII or binary).
    pub transfer_mode: i32,
    /// Virtual filesystem for testing (path -> entry).
    filesystem: HashMap<String, FsEntry>,
}

impl FtpConnection {
    fn ensure_logged_in(&self) -> Result<(), FtpError> {
        match self.state {
            FtpState::Disconnected => Err(FtpError::NotConnected),
            FtpState::Connected => Err(FtpError::NotLoggedIn),
            FtpState::LoggedIn => Ok(()),
        }
    }

    /// Resolve a path relative to cwd into an absolute path.
    fn resolve_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            normalize_path(path)
        } else if self.cwd == "/" {
            normalize_path(&format!("/{}", path))
        } else {
            normalize_path(&format!("{}/{}", self.cwd, path))
        }
    }
}

/// Normalize a path (remove trailing slashes, collapse double slashes).
fn normalize_path(path: &str) -> String {
    let mut result = path.replace("//", "/");
    while result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// ftp_connect() -- Open an FTP connection.
///
/// In our implementation, this always succeeds (simulates a successful TCP connection).
pub fn ftp_connect(host: &str, port: u16, timeout: u32) -> Result<FtpConnection, FtpError> {
    if host.is_empty() {
        return Err(FtpError::ConnectionFailed("empty host".to_string()));
    }

    let mut fs = HashMap::new();
    // Initialize with root directory
    fs.insert("/".to_string(), FsEntry::Directory);

    Ok(FtpConnection {
        host: host.to_string(),
        port,
        timeout,
        state: FtpState::Connected,
        cwd: "/".to_string(),
        passive: false,
        username: String::new(),
        transfer_mode: FTP_BINARY,
        filesystem: fs,
    })
}

/// ftp_login() -- Log into an FTP server.
///
/// In our simulation, login always succeeds unless the connection is not established.
pub fn ftp_login(
    conn: &mut FtpConnection,
    username: &str,
    _password: &str,
) -> Result<bool, FtpError> {
    if conn.state == FtpState::Disconnected {
        return Err(FtpError::NotConnected);
    }
    conn.username = username.to_string();
    conn.state = FtpState::LoggedIn;
    Ok(true)
}

/// ftp_pwd() -- Returns the current directory name.
pub fn ftp_pwd(conn: &FtpConnection) -> Result<String, FtpError> {
    conn.ensure_logged_in()?;
    Ok(conn.cwd.clone())
}

/// ftp_chdir() -- Change the current directory.
pub fn ftp_chdir(conn: &mut FtpConnection, directory: &str) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(directory);

    // Check if directory exists in virtual filesystem
    match conn.filesystem.get(&target) {
        Some(FsEntry::Directory) => {
            conn.cwd = target;
            Ok(true)
        }
        _ => Err(FtpError::DirectoryNotFound(directory.to_string())),
    }
}

/// ftp_mkdir() -- Create a directory.
pub fn ftp_mkdir(conn: &mut FtpConnection, directory: &str) -> Result<String, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(directory);
    if conn.filesystem.contains_key(&target) {
        return Err(FtpError::CommandFailed(format!(
            "directory already exists: {}",
            directory
        )));
    }

    conn.filesystem.insert(target.clone(), FsEntry::Directory);
    Ok(target)
}

/// ftp_rmdir() -- Remove a directory.
pub fn ftp_rmdir(conn: &mut FtpConnection, directory: &str) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(directory);
    match conn.filesystem.get(&target) {
        Some(FsEntry::Directory) => {
            // Check if directory is root
            if target == "/" {
                return Err(FtpError::PermissionDenied);
            }
            conn.filesystem.remove(&target);
            Ok(true)
        }
        _ => Err(FtpError::DirectoryNotFound(directory.to_string())),
    }
}

/// ftp_nlist() -- Returns a list of filenames in the specified directory.
pub fn ftp_nlist(conn: &FtpConnection, directory: &str) -> Result<Vec<String>, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(directory);
    let prefix = if target == "/" {
        "/".to_string()
    } else {
        format!("{}/", target)
    };

    let mut names = Vec::new();
    for path in conn.filesystem.keys() {
        if path == &target {
            continue;
        }
        if path.starts_with(&prefix) {
            // Only direct children (no further slashes after prefix)
            let remainder = &path[prefix.len()..];
            if !remainder.contains('/') && !remainder.is_empty() {
                names.push(remainder.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// ftp_rawlist() -- Returns a detailed list of files in a directory.
///
/// Returns entries in Unix `ls -l` style format.
pub fn ftp_rawlist(conn: &FtpConnection, directory: &str) -> Result<Vec<String>, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(directory);
    let prefix = if target == "/" {
        "/".to_string()
    } else {
        format!("{}/", target)
    };

    let mut lines = Vec::new();
    for (path, entry) in &conn.filesystem {
        if path == &target {
            continue;
        }
        if path.starts_with(&prefix) {
            let remainder = &path[prefix.len()..];
            if !remainder.contains('/') && !remainder.is_empty() {
                let line = match entry {
                    FsEntry::Directory => {
                        format!("drwxr-xr-x 2 ftp ftp 4096 Jan 01 00:00 {}", remainder)
                    }
                    FsEntry::File { size, .. } => {
                        format!("-rw-r--r-- 1 ftp ftp {} Jan 01 00:00 {}", size, remainder)
                    }
                };
                lines.push(line);
            }
        }
    }
    lines.sort();
    Ok(lines)
}

/// ftp_put() -- Upload a file to the FTP server.
///
/// In our simulation, stores the content in the virtual filesystem.
pub fn ftp_put(conn: &mut FtpConnection, remote: &str, content: &[u8]) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(remote);
    conn.filesystem.insert(
        target,
        FsEntry::File {
            content: content.to_vec(),
            size: content.len() as i64,
        },
    );
    Ok(true)
}

/// ftp_get() -- Download a file from the FTP server.
///
/// In our simulation, reads from the virtual filesystem.
pub fn ftp_get(conn: &FtpConnection, remote: &str) -> Result<Vec<u8>, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(remote);
    match conn.filesystem.get(&target) {
        Some(FsEntry::File { content, .. }) => Ok(content.clone()),
        _ => Err(FtpError::FileNotFound(remote.to_string())),
    }
}

/// ftp_delete() -- Delete a file on the FTP server.
pub fn ftp_delete(conn: &mut FtpConnection, path: &str) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(path);
    match conn.filesystem.get(&target) {
        Some(FsEntry::File { .. }) => {
            conn.filesystem.remove(&target);
            Ok(true)
        }
        Some(FsEntry::Directory) => Err(FtpError::CommandFailed(
            "cannot delete a directory with ftp_delete".to_string(),
        )),
        None => Err(FtpError::FileNotFound(path.to_string())),
    }
}

/// ftp_rename() -- Rename a file or directory on the FTP server.
pub fn ftp_rename(
    conn: &mut FtpConnection,
    old_name: &str,
    new_name: &str,
) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    let old_path = conn.resolve_path(old_name);
    let new_path = conn.resolve_path(new_name);

    if let Some(entry) = conn.filesystem.remove(&old_path) {
        conn.filesystem.insert(new_path, entry);
        Ok(true)
    } else {
        Err(FtpError::FileNotFound(old_name.to_string()))
    }
}

/// ftp_size() -- Returns the size of a remote file.
pub fn ftp_size(conn: &FtpConnection, remote: &str) -> Result<i64, FtpError> {
    conn.ensure_logged_in()?;

    let target = conn.resolve_path(remote);
    match conn.filesystem.get(&target) {
        Some(FsEntry::File { size, .. }) => Ok(*size),
        Some(FsEntry::Directory) => Ok(-1), // PHP returns -1 for directories
        None => Err(FtpError::FileNotFound(remote.to_string())),
    }
}

/// ftp_close() -- Close an FTP connection.
pub fn ftp_close(conn: &mut FtpConnection) -> bool {
    conn.state = FtpState::Disconnected;
    true
}

/// ftp_pasv() -- Turn passive mode on or off.
pub fn ftp_pasv(conn: &mut FtpConnection, pasv: bool) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;
    conn.passive = pasv;
    Ok(true)
}

/// ftp_systype() -- Returns the system type identifier.
pub fn ftp_systype(conn: &FtpConnection) -> Result<String, FtpError> {
    conn.ensure_logged_in()?;
    Ok("UNIX".to_string())
}

/// ftp_cdup() -- Change to the parent directory.
pub fn ftp_cdup(conn: &mut FtpConnection) -> Result<bool, FtpError> {
    conn.ensure_logged_in()?;

    if conn.cwd == "/" {
        return Ok(true); // Already at root
    }

    // Go up one level
    if let Some(pos) = conn.cwd.rfind('/') {
        let parent = if pos == 0 {
            "/".to_string()
        } else {
            conn.cwd[..pos].to_string()
        };
        conn.cwd = parent;
    }
    Ok(true)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_connection() -> FtpConnection {
        let mut conn = ftp_connect("ftp.example.com", 21, 30).unwrap();
        ftp_login(&mut conn, "user", "pass").unwrap();
        conn
    }

    #[test]
    fn test_ftp_connect() {
        let conn = ftp_connect("ftp.example.com", 21, 30).unwrap();
        assert_eq!(conn.host, "ftp.example.com");
        assert_eq!(conn.port, 21);
        assert_eq!(conn.timeout, 30);
        assert_eq!(conn.state, FtpState::Connected);
    }

    #[test]
    fn test_ftp_connect_empty_host() {
        let result = ftp_connect("", 21, 30);
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_login() {
        let mut conn = ftp_connect("ftp.example.com", 21, 30).unwrap();
        let result = ftp_login(&mut conn, "user", "pass").unwrap();
        assert!(result);
        assert_eq!(conn.state, FtpState::LoggedIn);
        assert_eq!(conn.username, "user");
    }

    #[test]
    fn test_ftp_login_disconnected() {
        let mut conn = ftp_connect("ftp.example.com", 21, 30).unwrap();
        conn.state = FtpState::Disconnected;
        let result = ftp_login(&mut conn, "user", "pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_pwd() {
        let conn = setup_connection();
        assert_eq!(ftp_pwd(&conn).unwrap(), "/");
    }

    #[test]
    fn test_ftp_mkdir_and_chdir() {
        let mut conn = setup_connection();

        let created = ftp_mkdir(&mut conn, "uploads").unwrap();
        assert_eq!(created, "/uploads");

        let result = ftp_chdir(&mut conn, "uploads").unwrap();
        assert!(result);
        assert_eq!(ftp_pwd(&conn).unwrap(), "/uploads");
    }

    #[test]
    fn test_ftp_mkdir_already_exists() {
        let mut conn = setup_connection();
        ftp_mkdir(&mut conn, "test").unwrap();
        let result = ftp_mkdir(&mut conn, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_chdir_nonexistent() {
        let mut conn = setup_connection();
        let result = ftp_chdir(&mut conn, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_rmdir() {
        let mut conn = setup_connection();
        ftp_mkdir(&mut conn, "temp").unwrap();
        assert!(ftp_rmdir(&mut conn, "temp").unwrap());
    }

    #[test]
    fn test_ftp_rmdir_nonexistent() {
        let mut conn = setup_connection();
        let result = ftp_rmdir(&mut conn, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_put_get() {
        let mut conn = setup_connection();
        let data = b"Hello, FTP!";
        ftp_put(&mut conn, "hello.txt", data).unwrap();

        let content = ftp_get(&conn, "hello.txt").unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn test_ftp_get_nonexistent() {
        let conn = setup_connection();
        let result = ftp_get(&conn, "nonexistent.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_delete() {
        let mut conn = setup_connection();
        ftp_put(&mut conn, "temp.txt", b"data").unwrap();
        assert!(ftp_delete(&mut conn, "temp.txt").unwrap());
        assert!(ftp_get(&conn, "temp.txt").is_err());
    }

    #[test]
    fn test_ftp_delete_nonexistent() {
        let mut conn = setup_connection();
        let result = ftp_delete(&mut conn, "nope.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_ftp_rename() {
        let mut conn = setup_connection();
        ftp_put(&mut conn, "old.txt", b"content").unwrap();

        assert!(ftp_rename(&mut conn, "old.txt", "new.txt").unwrap());
        assert!(ftp_get(&conn, "old.txt").is_err());
        assert_eq!(ftp_get(&conn, "new.txt").unwrap(), b"content");
    }

    #[test]
    fn test_ftp_size() {
        let mut conn = setup_connection();
        ftp_put(&mut conn, "data.bin", b"12345").unwrap();
        assert_eq!(ftp_size(&conn, "data.bin").unwrap(), 5);
    }

    #[test]
    fn test_ftp_nlist() {
        let mut conn = setup_connection();
        ftp_put(&mut conn, "a.txt", b"a").unwrap();
        ftp_put(&mut conn, "b.txt", b"b").unwrap();
        ftp_mkdir(&mut conn, "subdir").unwrap();

        let list = ftp_nlist(&conn, "/").unwrap();
        assert_eq!(list, vec!["a.txt", "b.txt", "subdir"]);
    }

    #[test]
    fn test_ftp_rawlist() {
        let mut conn = setup_connection();
        ftp_put(&mut conn, "file.txt", b"data").unwrap();
        ftp_mkdir(&mut conn, "dir").unwrap();

        let list = ftp_rawlist(&conn, "/").unwrap();
        assert_eq!(list.len(), 2);
        // Directory entry should start with 'd'
        let dir_entry = list.iter().find(|l| l.contains("dir")).unwrap();
        assert!(dir_entry.starts_with('d'));
        // File entry should start with '-'
        let file_entry = list.iter().find(|l| l.contains("file.txt")).unwrap();
        assert!(file_entry.starts_with('-'));
    }

    #[test]
    fn test_ftp_pasv() {
        let mut conn = setup_connection();
        assert!(!conn.passive);

        ftp_pasv(&mut conn, true).unwrap();
        assert!(conn.passive);

        ftp_pasv(&mut conn, false).unwrap();
        assert!(!conn.passive);
    }

    #[test]
    fn test_ftp_close() {
        let mut conn = setup_connection();
        assert!(ftp_close(&mut conn));
        assert_eq!(conn.state, FtpState::Disconnected);
    }

    #[test]
    fn test_ftp_operations_require_login() {
        let conn = ftp_connect("ftp.example.com", 21, 30).unwrap();
        // Not logged in, just connected
        assert!(ftp_pwd(&conn).is_err());
    }

    #[test]
    fn test_ftp_cdup() {
        let mut conn = setup_connection();
        ftp_mkdir(&mut conn, "level1").unwrap();
        ftp_chdir(&mut conn, "level1").unwrap();
        assert_eq!(ftp_pwd(&conn).unwrap(), "/level1");

        ftp_cdup(&mut conn).unwrap();
        assert_eq!(ftp_pwd(&conn).unwrap(), "/");
    }

    #[test]
    fn test_ftp_cdup_at_root() {
        let mut conn = setup_connection();
        ftp_cdup(&mut conn).unwrap();
        assert_eq!(ftp_pwd(&conn).unwrap(), "/");
    }

    #[test]
    fn test_ftp_systype() {
        let conn = setup_connection();
        assert_eq!(ftp_systype(&conn).unwrap(), "UNIX");
    }

    #[test]
    fn test_ftp_nested_directories() {
        let mut conn = setup_connection();
        ftp_mkdir(&mut conn, "a").unwrap();
        ftp_chdir(&mut conn, "a").unwrap();
        ftp_mkdir(&mut conn, "b").unwrap();
        ftp_chdir(&mut conn, "b").unwrap();
        assert_eq!(ftp_pwd(&conn).unwrap(), "/a/b");

        ftp_put(&mut conn, "file.txt", b"nested").unwrap();
        assert_eq!(ftp_get(&conn, "file.txt").unwrap(), b"nested");
        assert_eq!(ftp_size(&conn, "file.txt").unwrap(), 6);
    }
}
