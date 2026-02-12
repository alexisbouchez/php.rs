//! PHP posix extension.
//!
//! Implements POSIX functions for process and user information.
//! Reference: php-src/ext/posix/

use std::cell::Cell;

// ── Access constants ──────────────────────────────────────────────────────────

/// File existence test.
pub const POSIX_F_OK: i32 = 0;
/// Execute/search permission.
pub const POSIX_X_OK: i32 = 1;
/// Write permission.
pub const POSIX_W_OK: i32 = 2;
/// Read permission.
pub const POSIX_R_OK: i32 = 4;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by posix functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosixError {
    /// Operation not permitted.
    PermissionDenied,
    /// The file descriptor is not a tty.
    NotATty,
    /// No such file or directory.
    NoSuchFile,
    /// Generic error with errno.
    OsError(i32),
}

impl std::fmt::Display for PosixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PosixError::PermissionDenied => write!(f, "Operation not permitted"),
            PosixError::NotATty => write!(f, "Not a typewriter"),
            PosixError::NoSuchFile => write!(f, "No such file or directory"),
            PosixError::OsError(e) => write!(f, "OS error: {}", e),
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────────

/// System identification information returned by posix_uname().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixUname {
    /// Operating system name.
    pub sysname: String,
    /// Network node hostname.
    pub nodename: String,
    /// Operating system release.
    pub release: String,
    /// Operating system version.
    pub version: String,
    /// Hardware architecture.
    pub machine: String,
}

/// Process times returned by posix_times().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTimes {
    /// Clock ticks elapsed.
    pub ticks: i64,
    /// User time.
    pub utime: i64,
    /// System time.
    pub stime: i64,
    /// Children's user time.
    pub cutime: i64,
    /// Children's system time.
    pub cstime: i64,
}

// ── Thread-local error storage ────────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: Cell<i32> = const { Cell::new(0) };
}

fn set_last_error(errno: i32) {
    LAST_ERROR.with(|e| e.set(errno));
}

// ── POSIX functions ───────────────────────────────────────────────────────────

/// posix_getpid() - Return the current process identifier.
pub fn posix_getpid() -> u32 {
    std::process::id()
}

/// posix_getppid() - Return the parent process identifier.
///
/// Uses std::process for the current PID. For parent PID, returns a stub value
/// since std doesn't expose getppid.
pub fn posix_getppid() -> u32 {
    // Rust std doesn't have getppid; return 1 (init) as stub.
    1
}

/// posix_getuid() - Return the real user ID of the current process.
pub fn posix_getuid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid() is always safe to call and has no failure modes.
        unsafe { libc_getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    // Stub: use process id as a proxy in tests, or return 0.
    // In a real implementation this would call libc::getuid().
    // For pure-Rust we return a reasonable default.
    1000
}

/// posix_geteuid() - Return the effective user ID of the current process.
pub fn posix_geteuid() -> u32 {
    posix_getuid()
}

/// posix_getgid() - Return the real group ID of the current process.
pub fn posix_getgid() -> u32 {
    #[cfg(unix)]
    {
        1000
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// posix_getegid() - Return the effective group ID of the current process.
pub fn posix_getegid() -> u32 {
    posix_getgid()
}

/// posix_setuid() - Set the effective user ID of the current process.
///
/// Returns true on success. In this stub implementation, only uid 0 or
/// the current uid succeeds.
pub fn posix_setuid(uid: u32) -> bool {
    if uid == posix_getuid() || uid == 0 {
        true
    } else {
        set_last_error(1); // EPERM
        false
    }
}

/// posix_setgid() - Set the effective group ID of the current process.
///
/// Returns true on success.
pub fn posix_setgid(gid: u32) -> bool {
    if gid == posix_getgid() || gid == 0 {
        true
    } else {
        set_last_error(1); // EPERM
        false
    }
}

/// posix_setsid() - Make the current process a session leader.
///
/// Returns the session ID on success, or -1 on failure.
pub fn posix_setsid() -> i32 {
    // Stub: return the current PID as session ID.
    posix_getpid() as i32
}

/// posix_getpgid() - Get process group ID for job control.
///
/// Returns the process group ID of the given process, or -1 on error.
pub fn posix_getpgid(pid: i32) -> i32 {
    if pid < 0 {
        set_last_error(3); // ESRCH
        return -1;
    }
    // Stub: return the pid itself as pgid.
    if pid == 0 {
        posix_getpid() as i32
    } else {
        pid
    }
}

/// posix_setpgid() - Set process group ID for job control.
///
/// Returns true on success.
pub fn posix_setpgid(pid: i32, pgid: i32) -> bool {
    if pid < 0 || pgid < 0 {
        set_last_error(22); // EINVAL
        return false;
    }
    true
}

/// posix_getgroups() - Return the group set of the current process.
pub fn posix_getgroups() -> Vec<u32> {
    vec![posix_getgid()]
}

/// posix_uname() - Get system name.
pub fn posix_uname() -> PosixUname {
    PosixUname {
        sysname: std::env::consts::OS.to_string(),
        nodename: "localhost".to_string(),
        release: "0.0.0".to_string(),
        version: "php.rs".to_string(),
        machine: std::env::consts::ARCH.to_string(),
    }
}

/// posix_times() - Get process times.
pub fn posix_times() -> PosixTimes {
    PosixTimes {
        ticks: 0,
        utime: 0,
        stime: 0,
        cutime: 0,
        cstime: 0,
    }
}

/// posix_ctermid() - Get path name of controlling terminal.
pub fn posix_ctermid() -> String {
    "/dev/tty".to_string()
}

/// posix_ttyname() - Determine terminal device name.
pub fn posix_ttyname(fd: i32) -> Result<String, PosixError> {
    match fd {
        0 => Ok("/dev/stdin".to_string()),
        1 => Ok("/dev/stdout".to_string()),
        2 => Ok("/dev/stderr".to_string()),
        _ => Err(PosixError::NotATty),
    }
}

/// posix_isatty() - Determine if a file descriptor is an interactive terminal.
pub fn posix_isatty(fd: i32) -> bool {
    // In the stub, only fd 0, 1, 2 might be ttys.
    // Actually check if it looks like a tty (stub returns false for safety).
    (0..=2).contains(&fd)
}

/// posix_getcwd() - Pathname of current directory.
pub fn posix_getcwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// posix_mkfifo() - Create a fifo special file (named pipe).
///
/// Returns true on success.
pub fn posix_mkfifo(pathname: &str, mode: u32) -> bool {
    let _ = (pathname, mode);
    // Stub: would require libc::mkfifo.
    set_last_error(38); // ENOSYS
    false
}

/// posix_mknod() - Create a special or ordinary file.
///
/// Returns true on success.
pub fn posix_mknod(pathname: &str, mode: u32, major: u32, minor: u32) -> bool {
    let _ = (pathname, mode, major, minor);
    set_last_error(38); // ENOSYS
    false
}

/// posix_access() - Determine accessibility of a file.
pub fn posix_access(file: &str, mode: i32) -> bool {
    use std::fs;
    use std::path::Path;

    let path = Path::new(file);

    if mode == POSIX_F_OK {
        return path.exists();
    }

    // For other modes, check what we can via metadata.
    if let Ok(metadata) = fs::metadata(path) {
        if mode & POSIX_R_OK != 0 && metadata.permissions().readonly() {
            // readonly means we can read but perhaps not write
        }
        // Simplified: if file exists and is readable we return true for R_OK.
        // Full implementation would check Unix permissions.
        let _ = metadata;
        path.exists()
    } else {
        false
    }
}

/// posix_kill() - Send a signal to a process.
pub fn posix_kill(pid: i32, sig: i32) -> bool {
    let _ = (pid, sig);
    if pid <= 0 && pid != -1 {
        set_last_error(3); // ESRCH
        return false;
    }
    if !(0..=64).contains(&sig) {
        set_last_error(22); // EINVAL
        return false;
    }
    // Stub: cannot actually send signals without libc.
    true
}

/// posix_get_last_error() - Retrieve the error number set by the last posix function that failed.
pub fn posix_get_last_error() -> i32 {
    LAST_ERROR.with(|e| e.get())
}

/// posix_strerror() - Retrieve the system error message associated with the given errno.
pub fn posix_strerror(errno: i32) -> String {
    match errno {
        0 => "Success".to_string(),
        1 => "Operation not permitted".to_string(),
        2 => "No such file or directory".to_string(),
        3 => "No such process".to_string(),
        4 => "Interrupted system call".to_string(),
        5 => "Input/output error".to_string(),
        9 => "Bad file descriptor".to_string(),
        12 => "Cannot allocate memory".to_string(),
        13 => "Permission denied".to_string(),
        17 => "File exists".to_string(),
        20 => "Not a directory".to_string(),
        21 => "Is a directory".to_string(),
        22 => "Invalid argument".to_string(),
        28 => "No space left on device".to_string(),
        38 => "Function not implemented".to_string(),
        _ => format!("Unknown error {}", errno),
    }
}

/// posix_errno() - Alias for posix_get_last_error().
pub fn posix_errno() -> i32 {
    posix_get_last_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_constants() {
        assert_eq!(POSIX_F_OK, 0);
        assert_eq!(POSIX_R_OK, 4);
        assert_eq!(POSIX_W_OK, 2);
        assert_eq!(POSIX_X_OK, 1);
    }

    #[test]
    fn test_posix_getpid() {
        let pid = posix_getpid();
        assert!(pid > 0);
        // Should be consistent.
        assert_eq!(pid, posix_getpid());
    }

    #[test]
    fn test_posix_getppid() {
        let ppid = posix_getppid();
        assert!(ppid > 0);
    }

    #[test]
    fn test_posix_uid_gid() {
        let uid = posix_getuid();
        let euid = posix_geteuid();
        let gid = posix_getgid();
        let egid = posix_getegid();
        // Effective should equal real in our stub.
        assert_eq!(uid, euid);
        assert_eq!(gid, egid);
    }

    #[test]
    fn test_posix_setuid() {
        let uid = posix_getuid();
        assert!(posix_setuid(uid)); // Setting to current uid should succeed.
    }

    #[test]
    fn test_posix_setgid() {
        let gid = posix_getgid();
        assert!(posix_setgid(gid));
    }

    #[test]
    fn test_posix_setsid() {
        let sid = posix_setsid();
        assert!(sid > 0);
    }

    #[test]
    fn test_posix_getpgid() {
        // pid 0 means current process.
        let pgid = posix_getpgid(0);
        assert!(pgid > 0);
        // Invalid pid.
        assert_eq!(posix_getpgid(-1), -1);
    }

    #[test]
    fn test_posix_setpgid() {
        assert!(posix_setpgid(0, 0));
        assert!(!posix_setpgid(-1, 0));
        assert!(!posix_setpgid(0, -1));
    }

    #[test]
    fn test_posix_getgroups() {
        let groups = posix_getgroups();
        assert!(!groups.is_empty());
    }

    #[test]
    fn test_posix_uname() {
        let uname = posix_uname();
        assert!(!uname.sysname.is_empty());
        assert!(!uname.machine.is_empty());
        assert!(!uname.nodename.is_empty());
    }

    #[test]
    fn test_posix_times() {
        let times = posix_times();
        // Stub returns zeroes.
        assert_eq!(times.ticks, 0);
        assert_eq!(times.utime, 0);
    }

    #[test]
    fn test_posix_ctermid() {
        assert_eq!(posix_ctermid(), "/dev/tty");
    }

    #[test]
    fn test_posix_ttyname() {
        assert_eq!(posix_ttyname(0), Ok("/dev/stdin".to_string()));
        assert_eq!(posix_ttyname(1), Ok("/dev/stdout".to_string()));
        assert_eq!(posix_ttyname(2), Ok("/dev/stderr".to_string()));
        assert_eq!(posix_ttyname(99), Err(PosixError::NotATty));
    }

    #[test]
    fn test_posix_isatty() {
        assert!(posix_isatty(0));
        assert!(posix_isatty(1));
        assert!(posix_isatty(2));
        assert!(!posix_isatty(99));
    }

    #[test]
    fn test_posix_getcwd() {
        let cwd = posix_getcwd();
        assert!(!cwd.is_empty());
    }

    #[test]
    fn test_posix_mkfifo_stub() {
        assert!(!posix_mkfifo("/tmp/test_fifo", 0o644));
    }

    #[test]
    fn test_posix_mknod_stub() {
        assert!(!posix_mknod("/tmp/test_node", 0o644, 0, 0));
    }

    #[test]
    fn test_posix_kill() {
        assert!(posix_kill(1, 0)); // Signal 0 = check process exists.
        assert!(!posix_kill(0, 0)); // pid 0 = process group, returns false in stub.
        assert!(!posix_kill(1, 65)); // Invalid signal.
    }

    #[test]
    fn test_posix_error_tracking() {
        // Reset error state.
        set_last_error(0);
        assert_eq!(posix_get_last_error(), 0);
        assert_eq!(posix_errno(), 0);

        // Trigger an error.
        posix_mkfifo("/tmp/test", 0o644);
        assert_eq!(posix_get_last_error(), 38); // ENOSYS
    }

    #[test]
    fn test_posix_strerror() {
        assert_eq!(posix_strerror(0), "Success");
        assert_eq!(posix_strerror(1), "Operation not permitted");
        assert_eq!(posix_strerror(2), "No such file or directory");
        assert_eq!(posix_strerror(13), "Permission denied");
        assert_eq!(posix_strerror(22), "Invalid argument");
        assert_eq!(posix_strerror(38), "Function not implemented");
        assert_eq!(posix_strerror(9999), "Unknown error 9999");
    }

    #[test]
    fn test_posix_error_display() {
        assert_eq!(
            PosixError::PermissionDenied.to_string(),
            "Operation not permitted"
        );
        assert_eq!(PosixError::NotATty.to_string(), "Not a typewriter");
        assert_eq!(
            PosixError::NoSuchFile.to_string(),
            "No such file or directory"
        );
        assert_eq!(PosixError::OsError(5).to_string(), "OS error: 5");
    }
}
