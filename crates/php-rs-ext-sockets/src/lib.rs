//! PHP sockets extension.
//!
//! Implements low-level socket API functions.
//! Reference: php-src/ext/sockets/
//!
//! This is a structural/state-tracking implementation. Actual network I/O
//! would require integration with std::net or a lower-level library.

use std::cell::Cell;
use std::collections::HashMap;

// ── Socket constants ──────────────────────────────────────────────────────────

/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;
/// Local communication (Unix domain sockets).
pub const AF_UNIX: i32 = 1;

/// Stream socket (TCP).
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket (UDP).
pub const SOCK_DGRAM: i32 = 2;
/// Raw socket.
pub const SOCK_RAW: i32 = 3;

/// Socket-level options.
pub const SOL_SOCKET: i32 = 1;
/// TCP-level options.
pub const SOL_TCP: i32 = 6;
/// UDP-level options.
pub const SOL_UDP: i32 = 17;

/// Allow address reuse.
pub const SO_REUSEADDR: i32 = 2;
/// Allow port reuse.
pub const SO_REUSEPORT: i32 = 15;
/// Keep connections alive.
pub const SO_KEEPALIVE: i32 = 9;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Linger on close if data present.
pub const SO_LINGER: i32 = 13;
/// Receive timeout.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout.
pub const SO_SNDTIMEO: i32 = 21;
/// Socket error.
pub const SO_ERROR: i32 = 4;
/// Socket type.
pub const SO_TYPE: i32 = 3;
/// Disable Nagle's algorithm.
pub const TCP_NODELAY: i32 = 1;

/// IP protocol.
pub const IPPROTO_IP: i32 = 0;
/// TCP protocol.
pub const IPPROTO_TCP: i32 = 6;
/// UDP protocol.
pub const IPPROTO_UDP: i32 = 17;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by socket functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketError {
    /// Invalid socket domain.
    InvalidDomain,
    /// Invalid socket type.
    InvalidType,
    /// Socket creation failed.
    CreateFailed,
    /// The socket is not connected.
    NotConnected,
    /// The socket is already bound.
    AlreadyBound,
    /// The socket is already connected.
    AlreadyConnected,
    /// The socket is already listening.
    AlreadyListening,
    /// The socket is not bound.
    NotBound,
    /// The socket is not listening.
    NotListening,
    /// Connection refused.
    ConnectionRefused,
    /// Address already in use.
    AddressInUse,
    /// Generic OS error with errno.
    OsError(i32),
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::InvalidDomain => write!(f, "Invalid socket domain"),
            SocketError::InvalidType => write!(f, "Invalid socket type"),
            SocketError::CreateFailed => write!(f, "Socket creation failed"),
            SocketError::NotConnected => write!(f, "Socket is not connected"),
            SocketError::AlreadyBound => write!(f, "Socket is already bound"),
            SocketError::AlreadyConnected => write!(f, "Socket is already connected"),
            SocketError::AlreadyListening => write!(f, "Socket is already listening"),
            SocketError::NotBound => write!(f, "Socket is not bound"),
            SocketError::NotListening => write!(f, "Socket is not listening"),
            SocketError::ConnectionRefused => write!(f, "Connection refused"),
            SocketError::AddressInUse => write!(f, "Address already in use"),
            SocketError::OsError(e) => write!(f, "Socket error: {}", e),
        }
    }
}

// ── Socket data structure ─────────────────────────────────────────────────────

/// Represents a PHP socket resource.
#[derive(Debug, Clone)]
pub struct PhpSocket {
    /// The address family (AF_INET, AF_INET6, AF_UNIX).
    pub domain: i32,
    /// The socket type (SOCK_STREAM, SOCK_DGRAM).
    pub socket_type: i32,
    /// The protocol number.
    pub protocol: i32,
    /// Whether the socket has been bound to an address.
    pub is_bound: bool,
    /// Whether the socket is listening for connections.
    pub is_listening: bool,
    /// Whether the socket is connected to a remote peer.
    pub is_connected: bool,
    /// The local address and port, if bound.
    pub local_addr: Option<(String, u16)>,
    /// The remote address and port, if connected.
    pub remote_addr: Option<(String, u16)>,
    /// Socket options stored as key-value pairs (level, optname) -> value.
    options: HashMap<(i32, i32), i32>,
    /// Whether the socket has been closed.
    pub is_closed: bool,
    /// Backlog for listening sockets.
    pub backlog: i32,
    /// Internal read buffer for testing.
    read_buffer: Vec<u8>,
    /// Internal write buffer for testing.
    write_buffer: Vec<u8>,
    /// Last error code.
    last_error: i32,
}

// ── Thread-local error storage ────────────────────────────────────────────────

thread_local! {
    static LAST_SOCKET_ERROR: Cell<i32> = const { Cell::new(0) };
}

// ── Socket functions ──────────────────────────────────────────────────────────

/// socket_create() - Create a socket (endpoint for communication).
///
/// Returns a new PhpSocket on success.
pub fn socket_create(domain: i32, type_: i32, protocol: i32) -> Result<PhpSocket, SocketError> {
    // Validate domain.
    if domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX {
        LAST_SOCKET_ERROR.with(|e| e.set(97)); // EAFNOSUPPORT
        return Err(SocketError::InvalidDomain);
    }

    // Validate socket type.
    if type_ != SOCK_STREAM && type_ != SOCK_DGRAM && type_ != SOCK_RAW {
        LAST_SOCKET_ERROR.with(|e| e.set(94)); // ESOCKTNOSUPPORT
        return Err(SocketError::InvalidType);
    }

    Ok(PhpSocket {
        domain,
        socket_type: type_,
        protocol,
        is_bound: false,
        is_listening: false,
        is_connected: false,
        local_addr: None,
        remote_addr: None,
        options: HashMap::new(),
        is_closed: false,
        backlog: 0,
        read_buffer: Vec::new(),
        write_buffer: Vec::new(),
        last_error: 0,
    })
}

/// socket_bind() - Binds a name to a socket.
///
/// Returns true on success.
pub fn socket_bind(socket: &mut PhpSocket, address: &str, port: u16) -> bool {
    if socket.is_closed {
        socket.last_error = 9; // EBADF
        LAST_SOCKET_ERROR.with(|e| e.set(9));
        return false;
    }
    if socket.is_bound {
        socket.last_error = 22; // EINVAL
        LAST_SOCKET_ERROR.with(|e| e.set(22));
        return false;
    }
    socket.local_addr = Some((address.to_string(), port));
    socket.is_bound = true;
    true
}

/// socket_listen() - Listens for a connection on a socket.
///
/// Returns true on success.
pub fn socket_listen(socket: &mut PhpSocket, backlog: i32) -> bool {
    if socket.is_closed {
        socket.last_error = 9; // EBADF
        LAST_SOCKET_ERROR.with(|e| e.set(9));
        return false;
    }
    if !socket.is_bound {
        socket.last_error = 22; // EINVAL
        LAST_SOCKET_ERROR.with(|e| e.set(22));
        return false;
    }
    if socket.socket_type != SOCK_STREAM {
        socket.last_error = 95; // EOPNOTSUPP
        LAST_SOCKET_ERROR.with(|e| e.set(95));
        return false;
    }
    socket.is_listening = true;
    socket.backlog = backlog;
    true
}

/// socket_accept() - Accepts a connection on a socket.
///
/// Returns a new PhpSocket representing the accepted connection.
/// In this stub, returns a socket that appears connected.
pub fn socket_accept(socket: &PhpSocket) -> Result<PhpSocket, SocketError> {
    if socket.is_closed {
        LAST_SOCKET_ERROR.with(|e| e.set(9)); // EBADF
        return Err(SocketError::CreateFailed);
    }
    if !socket.is_listening {
        LAST_SOCKET_ERROR.with(|e| e.set(22)); // EINVAL
        return Err(SocketError::NotListening);
    }

    // Stub: return a connected socket.
    Ok(PhpSocket {
        domain: socket.domain,
        socket_type: socket.socket_type,
        protocol: socket.protocol,
        is_bound: false,
        is_listening: false,
        is_connected: true,
        local_addr: socket.local_addr.clone(),
        remote_addr: Some(("127.0.0.1".to_string(), 0)),
        options: HashMap::new(),
        is_closed: false,
        backlog: 0,
        read_buffer: Vec::new(),
        write_buffer: Vec::new(),
        last_error: 0,
    })
}

/// socket_connect() - Initiates a connection on a socket.
///
/// Returns true on success.
pub fn socket_connect(socket: &mut PhpSocket, address: &str, port: u16) -> bool {
    if socket.is_closed {
        socket.last_error = 9; // EBADF
        LAST_SOCKET_ERROR.with(|e| e.set(9));
        return false;
    }
    if socket.is_connected {
        socket.last_error = 106; // EISCONN
        LAST_SOCKET_ERROR.with(|e| e.set(106));
        return false;
    }
    socket.remote_addr = Some((address.to_string(), port));
    socket.is_connected = true;
    true
}

/// socket_read() - Reads a maximum of length bytes from a socket.
///
/// Returns the data read. In this stub, returns from the internal buffer.
pub fn socket_read(socket: &PhpSocket, length: usize) -> Vec<u8> {
    if socket.is_closed || !socket.is_connected {
        return Vec::new();
    }
    let available = std::cmp::min(length, socket.read_buffer.len());
    socket.read_buffer[..available].to_vec()
}

/// socket_write() - Write to a socket.
///
/// Returns the number of bytes written.
pub fn socket_write(socket: &mut PhpSocket, data: &[u8]) -> usize {
    if socket.is_closed || !socket.is_connected {
        return 0;
    }
    socket.write_buffer.extend_from_slice(data);
    data.len()
}

/// socket_close() - Closes a socket resource.
pub fn socket_close(socket: &mut PhpSocket) {
    socket.is_closed = true;
    socket.is_connected = false;
    socket.is_listening = false;
    socket.read_buffer.clear();
    socket.write_buffer.clear();
}

/// socket_select() - Runs the select() system call on the given arrays of sockets.
///
/// Returns the number of sockets with activity, or -1 on error.
/// This is a stub that returns 0 (no activity/timeout).
pub fn socket_select(
    read: &mut [&PhpSocket],
    write: &mut [&PhpSocket],
    except: &mut [&PhpSocket],
    tv_sec: i64,
) -> i32 {
    let _ = (read, write, except, tv_sec);
    // Stub: no actual select() available.
    0
}

/// socket_set_option() - Sets socket options for the socket.
///
/// Returns true on success.
pub fn socket_set_option(socket: &mut PhpSocket, level: i32, optname: i32, optval: i32) -> bool {
    if socket.is_closed {
        socket.last_error = 9; // EBADF
        LAST_SOCKET_ERROR.with(|e| e.set(9));
        return false;
    }
    socket.options.insert((level, optname), optval);
    true
}

/// socket_get_option() - Gets socket options for the socket.
///
/// Returns the option value, or -1 if not set.
pub fn socket_get_option(socket: &PhpSocket, level: i32, optname: i32) -> i32 {
    if socket.is_closed {
        LAST_SOCKET_ERROR.with(|e| e.set(9)); // EBADF
        return -1;
    }

    // Special case: SO_TYPE returns the socket type.
    if level == SOL_SOCKET && optname == SO_TYPE {
        return socket.socket_type;
    }

    // Special case: SO_ERROR returns and clears the last error.
    if level == SOL_SOCKET && optname == SO_ERROR {
        return socket.last_error;
    }

    socket.options.get(&(level, optname)).copied().unwrap_or(0)
}

/// socket_last_error() - Returns the last error on the socket.
///
/// If no socket is provided, returns the global last error.
pub fn socket_last_error(socket: Option<&PhpSocket>) -> i32 {
    match socket {
        Some(s) => s.last_error,
        None => LAST_SOCKET_ERROR.with(|e| e.get()),
    }
}

/// socket_strerror() - Return a string describing a socket error.
pub fn socket_strerror(errno: i32) -> String {
    match errno {
        0 => "Success".to_string(),
        9 => "Bad file descriptor".to_string(),
        13 => "Permission denied".to_string(),
        22 => "Invalid argument".to_string(),
        88 => "Socket operation on non-socket".to_string(),
        93 => "Protocol not supported".to_string(),
        94 => "Socket type not supported".to_string(),
        95 => "Operation not supported".to_string(),
        97 => "Address family not supported by protocol".to_string(),
        98 => "Address already in use".to_string(),
        99 => "Cannot assign requested address".to_string(),
        104 => "Connection reset by peer".to_string(),
        106 => "Transport endpoint is already connected".to_string(),
        107 => "Transport endpoint is not connected".to_string(),
        110 => "Connection timed out".to_string(),
        111 => "Connection refused".to_string(),
        _ => format!("Unknown error {}", errno),
    }
}

/// socket_getpeername() - Queries the remote side of the given socket.
///
/// Returns the address and port of the peer, or None if not connected.
pub fn socket_getpeername(socket: &PhpSocket) -> Option<(String, u16)> {
    if socket.is_closed || !socket.is_connected {
        LAST_SOCKET_ERROR.with(|e| e.set(107)); // ENOTCONN
        return None;
    }
    socket.remote_addr.clone()
}

/// socket_getsockname() - Queries the local side of the given socket.
///
/// Returns the address and port of the local side, or None if not bound.
pub fn socket_getsockname(socket: &PhpSocket) -> Option<(String, u16)> {
    if socket.is_closed {
        LAST_SOCKET_ERROR.with(|e| e.set(9)); // EBADF
        return None;
    }
    socket.local_addr.clone()
}

/// Inject data into a socket's read buffer for testing purposes.
pub fn test_inject_read_data(socket: &mut PhpSocket, data: &[u8]) {
    socket.read_buffer.extend_from_slice(data);
}

/// Get the data written to a socket's write buffer for testing purposes.
pub fn test_get_write_data(socket: &PhpSocket) -> Vec<u8> {
    socket.write_buffer.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_constants() {
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(SO_REUSEADDR, 2);
    }

    #[test]
    fn test_socket_create() {
        let socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(socket.domain, AF_INET);
        assert_eq!(socket.socket_type, SOCK_STREAM);
        assert_eq!(socket.protocol, 0);
        assert!(!socket.is_bound);
        assert!(!socket.is_listening);
        assert!(!socket.is_connected);
        assert!(!socket.is_closed);
    }

    #[test]
    fn test_socket_create_invalid_domain() {
        let result = socket_create(999, SOCK_STREAM, 0);
        assert!(matches!(result, Err(SocketError::InvalidDomain)));
    }

    #[test]
    fn test_socket_create_invalid_type() {
        let result = socket_create(AF_INET, 999, 0);
        assert!(matches!(result, Err(SocketError::InvalidType)));
    }

    #[test]
    fn test_socket_bind() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert!(socket_bind(&mut socket, "0.0.0.0", 8080));
        assert!(socket.is_bound);
        assert_eq!(socket.local_addr, Some(("0.0.0.0".to_string(), 8080)));
    }

    #[test]
    fn test_socket_bind_already_bound() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert!(socket_bind(&mut socket, "0.0.0.0", 8080));
        assert!(!socket_bind(&mut socket, "0.0.0.0", 9090));
    }

    #[test]
    fn test_socket_listen() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_bind(&mut socket, "0.0.0.0", 8080);
        assert!(socket_listen(&mut socket, 128));
        assert!(socket.is_listening);
        assert_eq!(socket.backlog, 128);
    }

    #[test]
    fn test_socket_listen_without_bind() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert!(!socket_listen(&mut socket, 128));
    }

    #[test]
    fn test_socket_listen_udp_fails() {
        let mut socket = socket_create(AF_INET, SOCK_DGRAM, 0).unwrap();
        socket_bind(&mut socket, "0.0.0.0", 8080);
        assert!(!socket_listen(&mut socket, 128));
    }

    #[test]
    fn test_socket_accept() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_bind(&mut socket, "0.0.0.0", 8080);
        socket_listen(&mut socket, 128);

        let accepted = socket_accept(&socket).unwrap();
        assert!(accepted.is_connected);
        assert_eq!(accepted.domain, AF_INET);
        assert_eq!(accepted.local_addr, Some(("0.0.0.0".to_string(), 8080)));
    }

    #[test]
    fn test_socket_accept_not_listening() {
        let socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        let result = socket_accept(&socket);
        assert!(matches!(result, Err(SocketError::NotListening)));
    }

    #[test]
    fn test_socket_connect() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert!(socket_connect(&mut socket, "127.0.0.1", 80));
        assert!(socket.is_connected);
        assert_eq!(socket.remote_addr, Some(("127.0.0.1".to_string(), 80)));
    }

    #[test]
    fn test_socket_connect_already_connected() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_connect(&mut socket, "127.0.0.1", 80);
        assert!(!socket_connect(&mut socket, "127.0.0.1", 8080));
    }

    #[test]
    fn test_socket_read_write() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_connect(&mut socket, "127.0.0.1", 80);

        // Inject test data.
        test_inject_read_data(&mut socket, b"Hello from server");
        let data = socket_read(&socket, 1024);
        assert_eq!(data, b"Hello from server");

        // Write data.
        let written = socket_write(&mut socket, b"Hello from client");
        assert_eq!(written, 17);
        assert_eq!(test_get_write_data(&socket), b"Hello from client");
    }

    #[test]
    fn test_socket_read_not_connected() {
        let socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        let data = socket_read(&socket, 1024);
        assert!(data.is_empty());
    }

    #[test]
    fn test_socket_close() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_connect(&mut socket, "127.0.0.1", 80);
        assert!(socket.is_connected);

        socket_close(&mut socket);
        assert!(socket.is_closed);
        assert!(!socket.is_connected);
    }

    #[test]
    fn test_socket_set_get_option() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();

        assert!(socket_set_option(&mut socket, SOL_SOCKET, SO_REUSEADDR, 1));
        assert_eq!(socket_get_option(&socket, SOL_SOCKET, SO_REUSEADDR), 1);

        // SO_TYPE should return the socket type.
        assert_eq!(socket_get_option(&socket, SOL_SOCKET, SO_TYPE), SOCK_STREAM);
    }

    #[test]
    fn test_socket_last_error() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(socket_last_error(Some(&socket)), 0);

        // Trigger an error.
        socket_listen(&mut socket, 128); // Not bound, will fail.
        assert_ne!(socket_last_error(Some(&socket)), 0);
    }

    #[test]
    fn test_socket_strerror() {
        assert_eq!(socket_strerror(0), "Success");
        assert_eq!(socket_strerror(9), "Bad file descriptor");
        assert_eq!(socket_strerror(98), "Address already in use");
        assert_eq!(socket_strerror(111), "Connection refused");
        assert_eq!(socket_strerror(9999), "Unknown error 9999");
    }

    #[test]
    fn test_socket_getpeername() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(socket_getpeername(&socket), None);

        socket_connect(&mut socket, "192.168.1.1", 443);
        assert_eq!(
            socket_getpeername(&socket),
            Some(("192.168.1.1".to_string(), 443))
        );
    }

    #[test]
    fn test_socket_getsockname() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(socket_getsockname(&socket), None);

        socket_bind(&mut socket, "0.0.0.0", 3000);
        assert_eq!(
            socket_getsockname(&socket),
            Some(("0.0.0.0".to_string(), 3000))
        );
    }

    #[test]
    fn test_socket_operations_on_closed_socket() {
        let mut socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        socket_close(&mut socket);

        assert!(!socket_bind(&mut socket, "0.0.0.0", 8080));
        assert!(!socket_listen(&mut socket, 128));
        assert!(!socket_connect(&mut socket, "127.0.0.1", 80));
        assert!(socket_read(&socket, 1024).is_empty());
        assert_eq!(socket_write(&mut socket, b"data"), 0);
    }

    #[test]
    fn test_socket_error_display() {
        assert_eq!(
            SocketError::InvalidDomain.to_string(),
            "Invalid socket domain"
        );
        assert_eq!(SocketError::InvalidType.to_string(), "Invalid socket type");
        assert_eq!(
            SocketError::CreateFailed.to_string(),
            "Socket creation failed"
        );
        assert_eq!(
            SocketError::NotConnected.to_string(),
            "Socket is not connected"
        );
        assert_eq!(
            SocketError::NotListening.to_string(),
            "Socket is not listening"
        );
        assert_eq!(
            SocketError::ConnectionRefused.to_string(),
            "Connection refused"
        );
        assert_eq!(
            SocketError::AddressInUse.to_string(),
            "Address already in use"
        );
        assert_eq!(SocketError::OsError(42).to_string(), "Socket error: 42");
    }

    #[test]
    fn test_socket_create_all_valid_combinations() {
        // AF_INET + SOCK_STREAM
        assert!(socket_create(AF_INET, SOCK_STREAM, 0).is_ok());
        // AF_INET + SOCK_DGRAM
        assert!(socket_create(AF_INET, SOCK_DGRAM, 0).is_ok());
        // AF_INET6 + SOCK_STREAM
        assert!(socket_create(AF_INET6, SOCK_STREAM, 0).is_ok());
        // AF_UNIX + SOCK_STREAM
        assert!(socket_create(AF_UNIX, SOCK_STREAM, 0).is_ok());
        // AF_INET + SOCK_RAW
        assert!(socket_create(AF_INET, SOCK_RAW, 0).is_ok());
    }

    #[test]
    fn test_socket_select_stub() {
        let socket = socket_create(AF_INET, SOCK_STREAM, 0).unwrap();
        let result = socket_select(&mut [&socket], &mut [], &mut [], 0);
        assert_eq!(result, 0); // Stub returns 0.
    }
}
