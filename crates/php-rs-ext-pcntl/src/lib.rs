//! PHP pcntl extension.
//!
//! Implements process control functions.
//! Reference: php-src/ext/pcntl/

use std::collections::HashMap;

// ── Signal constants ──────────────────────────────────────────────────────────

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;

// ── Wait option constants ─────────────────────────────────────────────────────

pub const WNOHANG: i32 = 1;
pub const WUNTRACED: i32 = 2;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by pcntl functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcntlError {
    /// The operation is not permitted.
    PermissionDenied,
    /// The specified process was not found.
    ProcessNotFound,
    /// The signal number is invalid.
    InvalidSignal,
    /// Generic OS error with errno.
    OsError(i32),
    /// The function is not supported on this platform.
    NotSupported,
}

impl std::fmt::Display for PcntlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcntlError::PermissionDenied => write!(f, "Permission denied"),
            PcntlError::ProcessNotFound => write!(f, "No such process"),
            PcntlError::InvalidSignal => write!(f, "Invalid signal"),
            PcntlError::OsError(e) => write!(f, "OS error: {}", e),
            PcntlError::NotSupported => write!(f, "Not supported on this platform"),
        }
    }
}

// ── Signal handler type ───────────────────────────────────────────────────────

/// Represents a signal handler, matching PHP's pcntl_signal() handler parameter.
#[derive(Clone)]
pub enum SignalHandler {
    /// SIG_DFL — the default signal handler.
    Default,
    /// SIG_IGN — ignore the signal.
    Ignore,
    /// A user-defined handler function.
    Handler(fn(i32)),
}

impl std::fmt::Debug for SignalHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalHandler::Default => write!(f, "SIG_DFL"),
            SignalHandler::Ignore => write!(f, "SIG_IGN"),
            SignalHandler::Handler(_) => write!(f, "Handler(fn)"),
        }
    }
}

impl PartialEq for SignalHandler {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SignalHandler::Default, SignalHandler::Default) => true,
            (SignalHandler::Ignore, SignalHandler::Ignore) => true,
            (SignalHandler::Handler(a), SignalHandler::Handler(b)) => *a as usize == *b as usize,
            _ => false,
        }
    }
}

// ── Thread-local signal handler storage ───────────────────────────────────────

use std::cell::RefCell;

thread_local! {
    static SIGNAL_HANDLERS: RefCell<HashMap<i32, SignalHandler>> = RefCell::new(HashMap::new());
    static PENDING_SIGNALS: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
    static ASYNC_SIGNALS: RefCell<bool> = const { RefCell::new(false) };
}

// ── Process control functions ─────────────────────────────────────────────────

/// pcntl_fork() - Forks the current process.
///
/// Returns the PID of the child to the parent, 0 to the child, or -1 on failure.
/// This is a stub that returns -1 (fork not available in pure Rust without unsafe/libc).
pub fn pcntl_fork() -> i32 {
    // Stub: real fork requires libc. Return -1 indicating failure.
    -1
}

/// pcntl_waitpid() - Waits on or returns the status of a forked child.
///
/// Returns (pid, status). Returns (-1, 0) on failure.
pub fn pcntl_waitpid(pid: i32, options: i32) -> (i32, i32) {
    // Stub: no child processes available in this context.
    let _ = (pid, options);
    (-1, 0)
}

/// pcntl_wait() - Waits on or returns the status of a forked child.
///
/// Returns (pid, status). Returns (-1, 0) on failure.
pub fn pcntl_wait(options: i32) -> (i32, i32) {
    pcntl_waitpid(-1, options)
}

/// pcntl_signal() - Installs a signal handler.
///
/// Returns true on success.
pub fn pcntl_signal(signo: i32, handler: SignalHandler) -> bool {
    if signo == SIGKILL || signo == SIGSTOP {
        // Cannot catch or ignore SIGKILL/SIGSTOP.
        return false;
    }
    if !(1..=64).contains(&signo) {
        return false;
    }
    SIGNAL_HANDLERS.with(|handlers| {
        handlers.borrow_mut().insert(signo, handler);
    });
    true
}

/// pcntl_signal_dispatch() - Calls signal handlers for pending signals.
///
/// Returns true on success.
pub fn pcntl_signal_dispatch() -> bool {
    let signals: Vec<i32> = PENDING_SIGNALS.with(|ps| {
        let mut pending = ps.borrow_mut();
        let signals = pending.clone();
        pending.clear();
        signals
    });

    SIGNAL_HANDLERS.with(|handlers| {
        let handlers = handlers.borrow();
        for sig in signals {
            if let Some(handler) = handlers.get(&sig) {
                match handler {
                    SignalHandler::Handler(f) => f(sig),
                    SignalHandler::Default | SignalHandler::Ignore => {}
                }
            }
        }
    });

    true
}

/// pcntl_alarm() - Sets an alarm signal after the given number of seconds.
///
/// Returns the number of seconds remaining from the previous alarm, or 0 if none.
/// This is a stub that always returns 0.
pub fn pcntl_alarm(seconds: u32) -> u32 {
    let _ = seconds;
    0
}

/// pcntl_exec() - Executes a program, replacing the current process.
///
/// This is a stub that always returns false (exec not available without libc).
pub fn pcntl_exec(path: &str, args: &[String], envs: Option<&HashMap<String, String>>) -> bool {
    let _ = (path, args, envs);
    false
}

/// pcntl_getpriority() - Get the priority of a process.
///
/// Returns the priority on success.
pub fn pcntl_getpriority(pid: i32) -> Result<i32, PcntlError> {
    if pid < 0 {
        return Err(PcntlError::ProcessNotFound);
    }
    // Stub: return default nice value 0.
    Ok(0)
}

/// pcntl_setpriority() - Change the priority of a process.
///
/// Returns true on success.
pub fn pcntl_setpriority(priority: i32, pid: i32) -> bool {
    let _ = (priority, pid);
    // Stub: always succeed for valid inputs.
    pid >= 0 && (-20..=20).contains(&priority)
}

// ── Status examination macros ─────────────────────────────────────────────────

/// WIFEXITED - Returns true if the child terminated normally.
///
/// A process terminates normally if the low 7 bits of the status are 0.
pub fn pcntl_wifexited(status: i32) -> bool {
    (status & 0x7F) == 0
}

/// WIFSTOPPED - Returns true if the child is currently stopped.
///
/// A process is stopped if the low byte of status equals 0x7F.
pub fn pcntl_wifstopped(status: i32) -> bool {
    (status & 0xFF) == 0x7F
}

/// WIFSIGNALED - Returns true if the child was terminated by a signal.
///
/// A process was signaled if ((status & 0x7F) + 1) >> 1 > 0.
pub fn pcntl_wifsignaled(status: i32) -> bool {
    (((status & 0x7F) + 1) >> 1) > 0
}

/// WEXITSTATUS - Returns the exit code of a normally terminated child.
pub fn pcntl_wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xFF
}

/// WTERMSIG - Returns the signal that caused the child to terminate.
pub fn pcntl_wtermsig(status: i32) -> i32 {
    status & 0x7F
}

/// WSTOPSIG - Returns the signal that caused the child to stop.
pub fn pcntl_wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xFF
}

/// pcntl_async_signals() - Enable/disable async signal handling.
///
/// When called with `None`, returns the current state.
/// When called with `Some(enable)`, sets the state and returns the previous state.
pub fn pcntl_async_signals(enable: Option<bool>) -> bool {
    ASYNC_SIGNALS.with(|async_sig| {
        let mut current = async_sig.borrow_mut();
        match enable {
            None => *current,
            Some(val) => {
                let prev = *current;
                *current = val;
                prev
            }
        }
    })
}

/// pcntl_unshare() - Dissociates parts of the process execution context.
///
/// Linux-only. Returns false on non-Linux or on failure.
pub fn pcntl_unshare(flags: i32) -> bool {
    let _ = flags;
    // Not supported outside Linux.
    false
}

// ── Helper: Enqueue a pending signal (for testing) ────────────────────────────

/// Enqueue a pending signal for dispatch. This simulates signal delivery.
pub fn enqueue_pending_signal(signo: i32) {
    PENDING_SIGNALS.with(|ps| {
        ps.borrow_mut().push(signo);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_constants() {
        assert_eq!(SIGTERM, 15);
        assert_eq!(SIGINT, 2);
        assert_eq!(SIGKILL, 9);
        assert_eq!(SIGUSR1, 10);
        assert_eq!(SIGUSR2, 12);
        assert_eq!(SIGCHLD, 17);
    }

    #[test]
    fn test_pcntl_fork_returns_negative_one() {
        // Stub always returns -1
        assert_eq!(pcntl_fork(), -1);
    }

    #[test]
    fn test_pcntl_waitpid_returns_failure() {
        let (pid, status) = pcntl_waitpid(1234, 0);
        assert_eq!(pid, -1);
        assert_eq!(status, 0);
    }

    #[test]
    fn test_pcntl_wait_returns_failure() {
        let (pid, status) = pcntl_wait(WNOHANG);
        assert_eq!(pid, -1);
        assert_eq!(status, 0);
    }

    #[test]
    fn test_pcntl_signal_install_handler() {
        fn my_handler(_sig: i32) {}
        assert!(pcntl_signal(SIGUSR1, SignalHandler::Handler(my_handler)));
        assert!(pcntl_signal(SIGTERM, SignalHandler::Ignore));
        assert!(pcntl_signal(SIGINT, SignalHandler::Default));
    }

    #[test]
    fn test_pcntl_signal_cannot_catch_sigkill_sigstop() {
        assert!(!pcntl_signal(SIGKILL, SignalHandler::Ignore));
        assert!(!pcntl_signal(SIGSTOP, SignalHandler::Ignore));
    }

    #[test]
    fn test_pcntl_signal_invalid_signal() {
        assert!(!pcntl_signal(0, SignalHandler::Default));
        assert!(!pcntl_signal(65, SignalHandler::Default));
        assert!(!pcntl_signal(-1, SignalHandler::Default));
    }

    #[test]
    fn test_pcntl_signal_dispatch() {
        use std::cell::Cell;
        thread_local! {
            static CALLED: Cell<bool> = const { Cell::new(false) };
        }

        fn handler(_sig: i32) {
            CALLED.with(|c| c.set(true));
        }

        pcntl_signal(SIGUSR1, SignalHandler::Handler(handler));
        enqueue_pending_signal(SIGUSR1);
        pcntl_signal_dispatch();

        CALLED.with(|c| assert!(c.get()));
    }

    #[test]
    fn test_pcntl_alarm_stub() {
        assert_eq!(pcntl_alarm(5), 0);
    }

    #[test]
    fn test_pcntl_exec_stub() {
        assert!(!pcntl_exec("/bin/ls", &[], None));
    }

    #[test]
    fn test_pcntl_getpriority() {
        assert_eq!(pcntl_getpriority(0), Ok(0));
        assert_eq!(pcntl_getpriority(-1), Err(PcntlError::ProcessNotFound));
    }

    #[test]
    fn test_pcntl_setpriority() {
        assert!(pcntl_setpriority(0, 0));
        assert!(pcntl_setpriority(-20, 0));
        assert!(pcntl_setpriority(20, 0));
        assert!(!pcntl_setpriority(21, 0));
        assert!(!pcntl_setpriority(-21, 0));
        assert!(!pcntl_setpriority(0, -1));
    }

    #[test]
    fn test_wifexited() {
        // Normal exit with code 0: status = 0x0000
        assert!(pcntl_wifexited(0x0000));
        // Normal exit with code 1: status = 0x0100
        assert!(pcntl_wifexited(0x0100));
        // Killed by signal 9: status = 0x0009
        assert!(!pcntl_wifexited(0x0009));
    }

    #[test]
    fn test_wexitstatus() {
        // Exit code 0: status = 0x0000
        assert_eq!(pcntl_wexitstatus(0x0000), 0);
        // Exit code 1: status = 0x0100
        assert_eq!(pcntl_wexitstatus(0x0100), 1);
        // Exit code 42: status = 0x2A00
        assert_eq!(pcntl_wexitstatus(0x2A00), 42);
        // Exit code 255: status = 0xFF00
        assert_eq!(pcntl_wexitstatus(0xFF00), 255);
    }

    #[test]
    fn test_wifsignaled() {
        // Killed by signal 9 (SIGKILL): status = 9
        assert!(pcntl_wifsignaled(9));
        // Killed by signal 15 (SIGTERM): status = 15
        assert!(pcntl_wifsignaled(15));
        // Normal exit: status = 0
        assert!(!pcntl_wifsignaled(0));
    }

    #[test]
    fn test_wtermsig() {
        // Killed by SIGKILL (9)
        assert_eq!(pcntl_wtermsig(9), 9);
        // Killed by SIGTERM (15)
        assert_eq!(pcntl_wtermsig(15), 15);
    }

    #[test]
    fn test_wifstopped() {
        // Stopped by SIGSTOP: status = 0x137F (signal 19 in high byte, 0x7F low)
        let status = (19 << 8) | 0x7F;
        assert!(pcntl_wifstopped(status));
        // Normal exit
        assert!(!pcntl_wifstopped(0));
    }

    #[test]
    fn test_wstopsig() {
        // Stopped by SIGTSTP (20): status = (20 << 8) | 0x7F
        let status = (20 << 8) | 0x7F;
        assert_eq!(pcntl_wstopsig(status), 20);
    }

    #[test]
    fn test_pcntl_async_signals() {
        // Default is false
        assert!(!pcntl_async_signals(None));
        // Enable
        assert!(!pcntl_async_signals(Some(true))); // returns previous (false)
        assert!(pcntl_async_signals(None)); // now true
                                            // Disable
        assert!(pcntl_async_signals(Some(false))); // returns previous (true)
        assert!(!pcntl_async_signals(None)); // now false
    }

    #[test]
    fn test_pcntl_unshare_not_supported() {
        assert!(!pcntl_unshare(0));
    }

    #[test]
    fn test_pcntl_error_display() {
        assert_eq!(
            PcntlError::PermissionDenied.to_string(),
            "Permission denied"
        );
        assert_eq!(PcntlError::ProcessNotFound.to_string(), "No such process");
        assert_eq!(PcntlError::InvalidSignal.to_string(), "Invalid signal");
        assert_eq!(PcntlError::OsError(22).to_string(), "OS error: 22");
        assert_eq!(
            PcntlError::NotSupported.to_string(),
            "Not supported on this platform"
        );
    }
}
