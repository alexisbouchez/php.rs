//! PHP sysvmsg extension.
//!
//! Implements System V message queue functions using thread-local HashMap as backing store.
//! Reference: php-src/ext/sysvmsg/

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by sysvmsg functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysvMsgError {
    /// The queue could not be created.
    CreateFailed,
    /// The queue was not found.
    NotFound,
    /// Message too large for the given buffer.
    MessageTooLarge,
    /// No message of the desired type is available.
    NoMessage,
    /// Generic error.
    Error(String),
}

impl std::fmt::Display for SysvMsgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysvMsgError::CreateFailed => write!(f, "Failed to create message queue"),
            SysvMsgError::NotFound => write!(f, "Message queue not found"),
            SysvMsgError::MessageTooLarge => write!(f, "Message too large"),
            SysvMsgError::NoMessage => write!(f, "No message available"),
            SysvMsgError::Error(msg) => write!(f, "sysvmsg error: {}", msg),
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────────

/// A single message in a System V message queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysvMessage {
    /// The message type (mtype). Must be > 0.
    pub mtype: i64,
    /// The message data.
    pub data: Vec<u8>,
}

/// A System V message queue.
#[derive(Debug, Clone)]
pub struct SysvMessageQueue {
    /// The IPC key for this queue.
    pub key: i64,
    /// The messages in the queue.
    pub messages: VecDeque<SysvMessage>,
    /// Permission bits.
    pub perms: i32,
}

/// Queue information for msg_set_queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgQueueInfo {
    /// Maximum number of bytes in the queue.
    pub msg_qbytes: usize,
}

/// Queue statistics returned by msg_stat_queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgQueueStat {
    /// Number of messages in the queue.
    pub msg_qnum: usize,
    /// Maximum number of bytes allowed in the queue.
    pub msg_qbytes: usize,
    /// PID of last msgsnd.
    pub msg_lspid: u32,
    /// PID of last msgrcv.
    pub msg_lrpid: u32,
}

// ── IPC_NOWAIT flag ───────────────────────────────────────────────────────────

/// Non-blocking flag for msg_receive.
pub const MSG_IPC_NOWAIT: i32 = 1;
/// Do not wait if the queue is full.
pub const MSG_NOERROR: i32 = 2;

// ── Thread-local queue storage ────────────────────────────────────────────────

thread_local! {
    static MSG_QUEUES: RefCell<HashMap<i64, SysvMessageQueue>> = RefCell::new(HashMap::new());
    static QUEUE_MAX_BYTES: RefCell<HashMap<i64, usize>> = RefCell::new(HashMap::new());
}

// ── Message queue functions ───────────────────────────────────────────────────

/// msg_get_queue() - Create or attach to a message queue.
pub fn msg_get_queue(key: i64, perms: i32) -> Result<SysvMessageQueue, SysvMsgError> {
    MSG_QUEUES.with(|queues| {
        let mut queues = queues.borrow_mut();
        let queue = queues.entry(key).or_insert_with(|| SysvMessageQueue {
            key,
            messages: VecDeque::new(),
            perms,
        });
        Ok(queue.clone())
    })
}

/// msg_send() - Send a message to a message queue.
///
/// Parameters:
/// - `queue`: The message queue to send to.
/// - `msgtype`: The message type (must be > 0).
/// - `message`: The message data.
/// - `serialize`: If true, serialize the message (stub: stored as-is).
/// - `blocking`: If true, block until the message can be sent.
pub fn msg_send(
    queue: &mut SysvMessageQueue,
    msgtype: i64,
    message: &[u8],
    _serialize: bool,
    _blocking: bool,
) -> bool {
    if msgtype <= 0 {
        return false;
    }

    let msg = SysvMessage {
        mtype: msgtype,
        data: message.to_vec(),
    };

    queue.messages.push_back(msg.clone());

    // Update the backing store.
    MSG_QUEUES.with(|queues| {
        let mut queues = queues.borrow_mut();
        if let Some(q) = queues.get_mut(&queue.key) {
            q.messages.push_back(msg);
        }
    });

    true
}

/// msg_receive() - Receive a message from a message queue.
///
/// Parameters:
/// - `queue`: The message queue.
/// - `desiredmsgtype`: 0 = any, >0 = exact type, <0 = type <= |desiredmsgtype|.
/// - `msgtype_out`: Will be set to the actual message type received.
/// - `maxsize`: Maximum size of message to receive.
/// - `message_out`: Will be set to the received message data.
/// - `_unserialize`: Whether to unserialize the message.
/// - `flags`: MSG_IPC_NOWAIT, MSG_NOERROR, etc.
///
/// Returns true if a message was received.
pub fn msg_receive(
    queue: &mut SysvMessageQueue,
    desiredmsgtype: i64,
    msgtype_out: &mut i64,
    maxsize: usize,
    message_out: &mut Vec<u8>,
    _unserialize: bool,
    flags: i32,
) -> bool {
    let result = MSG_QUEUES.with(|queues| {
        let mut queues = queues.borrow_mut();
        let q = match queues.get_mut(&queue.key) {
            Some(q) => q,
            None => return None,
        };

        let idx = if desiredmsgtype == 0 {
            // Any message.
            if q.messages.is_empty() {
                None
            } else {
                Some(0)
            }
        } else if desiredmsgtype > 0 {
            // Exact type match.
            q.messages.iter().position(|m| m.mtype == desiredmsgtype)
        } else {
            // Type <= |desiredmsgtype|.
            let abs_type = desiredmsgtype.unsigned_abs() as i64;
            q.messages.iter().position(|m| m.mtype <= abs_type)
        };

        if let Some(idx) = idx {
            let msg = q.messages.remove(idx).unwrap();
            if msg.data.len() > maxsize && (flags & MSG_NOERROR) == 0 {
                // Message too large; put it back.
                q.messages.insert(idx, msg);
                return Some(Err(SysvMsgError::MessageTooLarge));
            }
            Some(Ok(msg))
        } else if (flags & MSG_IPC_NOWAIT) != 0 {
            Some(Err(SysvMsgError::NoMessage))
        } else {
            // In blocking mode we'd wait, but in stub we just return no message.
            Some(Err(SysvMsgError::NoMessage))
        }
    });

    match result {
        Some(Ok(msg)) => {
            *msgtype_out = msg.mtype;
            if msg.data.len() > maxsize {
                *message_out = msg.data[..maxsize].to_vec();
            } else {
                *message_out = msg.data;
            }
            // Also update the local queue copy.
            if let Some(idx) = queue.messages.iter().position(|m| m.mtype == *msgtype_out) {
                queue.messages.remove(idx);
            }
            true
        }
        _ => false,
    }
}

/// msg_remove_queue() - Destroy a message queue.
pub fn msg_remove_queue(queue: &SysvMessageQueue) -> bool {
    MSG_QUEUES.with(|queues| {
        queues.borrow_mut().remove(&queue.key);
    });
    true
}

/// msg_set_queue() - Set information in the message queue data structure.
pub fn msg_set_queue(queue: &SysvMessageQueue, data: &MsgQueueInfo) -> bool {
    QUEUE_MAX_BYTES.with(|max_bytes| {
        max_bytes.borrow_mut().insert(queue.key, data.msg_qbytes);
    });
    true
}

/// msg_stat_queue() - Returns information from the message queue data structure.
pub fn msg_stat_queue(queue: &SysvMessageQueue) -> MsgQueueStat {
    let msg_qnum = MSG_QUEUES.with(|queues| {
        let queues = queues.borrow();
        queues
            .get(&queue.key)
            .map(|q| q.messages.len())
            .unwrap_or(0)
    });

    let msg_qbytes = QUEUE_MAX_BYTES.with(|max_bytes| {
        max_bytes.borrow().get(&queue.key).copied().unwrap_or(65536) // Default max bytes
    });

    MsgQueueStat {
        msg_qnum,
        msg_qbytes,
        msg_lspid: std::process::id(),
        msg_lrpid: 0,
    }
}

/// msg_queue_exists() - Check whether a message queue exists.
pub fn msg_queue_exists(key: i64) -> bool {
    MSG_QUEUES.with(|queues| queues.borrow().contains_key(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_key(key: i64) {
        MSG_QUEUES.with(|queues| {
            queues.borrow_mut().remove(&key);
        });
        QUEUE_MAX_BYTES.with(|mb| {
            mb.borrow_mut().remove(&key);
        });
    }

    #[test]
    fn test_msg_get_queue() {
        let key = 1000;
        cleanup_key(key);

        let queue = msg_get_queue(key, 0o666).unwrap();
        assert_eq!(queue.key, key);
        assert_eq!(queue.perms, 0o666);
        assert!(queue.messages.is_empty());

        cleanup_key(key);
    }

    #[test]
    fn test_msg_queue_exists() {
        let key = 1001;
        cleanup_key(key);

        assert!(!msg_queue_exists(key));
        let _queue = msg_get_queue(key, 0o666).unwrap();
        assert!(msg_queue_exists(key));

        cleanup_key(key);
    }

    #[test]
    fn test_msg_send_and_receive() {
        let key = 1002;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();

        // Send a message.
        assert!(msg_send(&mut queue, 1, b"Hello, World!", false, true));

        // Receive it.
        let mut msgtype: i64 = 0;
        let mut data: Vec<u8> = Vec::new();
        let received = msg_receive(&mut queue, 0, &mut msgtype, 1024, &mut data, false, 0);

        assert!(received);
        assert_eq!(msgtype, 1);
        assert_eq!(data, b"Hello, World!");

        cleanup_key(key);
    }

    #[test]
    fn test_msg_send_invalid_type() {
        let key = 1003;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();
        assert!(!msg_send(&mut queue, 0, b"test", false, true)); // type must be > 0
        assert!(!msg_send(&mut queue, -1, b"test", false, true));

        cleanup_key(key);
    }

    #[test]
    fn test_msg_receive_by_type() {
        let key = 1004;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();
        msg_send(&mut queue, 1, b"type1", false, true);
        msg_send(&mut queue, 2, b"type2", false, true);
        msg_send(&mut queue, 3, b"type3", false, true);

        // Receive type 2 specifically.
        let mut msgtype: i64 = 0;
        let mut data: Vec<u8> = Vec::new();
        let received = msg_receive(&mut queue, 2, &mut msgtype, 1024, &mut data, false, 0);

        assert!(received);
        assert_eq!(msgtype, 2);
        assert_eq!(data, b"type2");

        cleanup_key(key);
    }

    #[test]
    fn test_msg_receive_empty_queue() {
        let key = 1005;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();
        let mut msgtype: i64 = 0;
        let mut data: Vec<u8> = Vec::new();
        let received = msg_receive(
            &mut queue,
            0,
            &mut msgtype,
            1024,
            &mut data,
            false,
            MSG_IPC_NOWAIT,
        );
        assert!(!received);

        cleanup_key(key);
    }

    #[test]
    fn test_msg_remove_queue() {
        let key = 1006;
        cleanup_key(key);

        let queue = msg_get_queue(key, 0o666).unwrap();
        assert!(msg_queue_exists(key));
        assert!(msg_remove_queue(&queue));
        assert!(!msg_queue_exists(key));
    }

    #[test]
    fn test_msg_stat_queue() {
        let key = 1007;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();
        msg_send(&mut queue, 1, b"msg1", false, true);
        msg_send(&mut queue, 2, b"msg2", false, true);

        let stat = msg_stat_queue(&queue);
        assert_eq!(stat.msg_qnum, 2);
        assert_eq!(stat.msg_qbytes, 65536); // Default.
        assert!(stat.msg_lspid > 0);

        cleanup_key(key);
    }

    #[test]
    fn test_msg_set_queue() {
        let key = 1008;
        cleanup_key(key);

        let queue = msg_get_queue(key, 0o666).unwrap();
        let info = MsgQueueInfo { msg_qbytes: 131072 };
        assert!(msg_set_queue(&queue, &info));

        let stat = msg_stat_queue(&queue);
        assert_eq!(stat.msg_qbytes, 131072);

        cleanup_key(key);
    }

    #[test]
    fn test_msg_receive_negative_type() {
        let key = 1009;
        cleanup_key(key);

        let mut queue = msg_get_queue(key, 0o666).unwrap();
        msg_send(&mut queue, 1, b"type1", false, true);
        msg_send(&mut queue, 5, b"type5", false, true);
        msg_send(&mut queue, 3, b"type3", false, true);

        // desiredmsgtype = -3 means type <= 3.
        let mut msgtype: i64 = 0;
        let mut data: Vec<u8> = Vec::new();
        let received = msg_receive(&mut queue, -3, &mut msgtype, 1024, &mut data, false, 0);

        assert!(received);
        assert_eq!(msgtype, 1); // First message with type <= 3.
        assert_eq!(data, b"type1");

        cleanup_key(key);
    }

    #[test]
    fn test_msg_error_display() {
        assert_eq!(
            SysvMsgError::CreateFailed.to_string(),
            "Failed to create message queue"
        );
        assert_eq!(
            SysvMsgError::NotFound.to_string(),
            "Message queue not found"
        );
        assert_eq!(
            SysvMsgError::MessageTooLarge.to_string(),
            "Message too large"
        );
        assert_eq!(SysvMsgError::NoMessage.to_string(), "No message available");
        assert_eq!(
            SysvMsgError::Error("test".to_string()).to_string(),
            "sysvmsg error: test"
        );
    }
}
