//! PHP SPL extension — Standard PHP Library.
//!
//! Implements data structures, iterators, exceptions, and interfaces.
//! Reference: php-src/ext/spl/

// ── Data Structures ──────────────────────────────────────────────────────────

/// SplStack — LIFO (Last In, First Out) stack.
pub struct SplStack<T> {
    items: Vec<T>,
}

impl<T> SplStack<T> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn push(&mut self, value: T) {
        self.items.push(value);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    pub fn top(&self) -> Option<&T> {
        self.items.last()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }
}

impl<T> Default for SplStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// SplQueue — FIFO (First In, First Out) queue.
pub struct SplQueue<T> {
    items: std::collections::VecDeque<T>,
}

impl<T> SplQueue<T> {
    pub fn new() -> Self {
        Self {
            items: std::collections::VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, value: T) {
        self.items.push_back(value);
    }

    pub fn dequeue(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    pub fn bottom(&self) -> Option<&T> {
        self.items.front()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }
}

impl<T> Default for SplQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// SplPriorityQueue — Priority queue.
pub struct SplPriorityQueue<T> {
    items: Vec<(i64, T)>,
}

impl<T> SplPriorityQueue<T> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn insert(&mut self, value: T, priority: i64) {
        let pos = self
            .items
            .iter()
            .position(|(p, _)| *p < priority)
            .unwrap_or(self.items.len());
        self.items.insert(pos, (priority, value));
    }

    pub fn extract(&mut self) -> Option<T> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0).1)
        }
    }

    pub fn top(&self) -> Option<&T> {
        self.items.first().map(|(_, v)| v)
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }
}

impl<T> Default for SplPriorityQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// SplFixedArray — Fixed-size array with integer keys.
pub struct SplFixedArray<T: Default + Clone> {
    items: Vec<T>,
}

impl<T: Default + Clone> SplFixedArray<T> {
    pub fn new(size: usize) -> Self {
        Self {
            items: vec![T::default(); size],
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    pub fn set(&mut self, index: usize, value: T) -> bool {
        if index < self.items.len() {
            self.items[index] = value;
            true
        } else {
            false
        }
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }

    pub fn set_size(&mut self, size: usize) {
        self.items.resize(size, T::default());
    }
}

// ── SPL Exceptions hierarchy ─────────────────────────────────────────────────

/// SPL exception class names (for class registration).
pub const SPL_EXCEPTIONS: &[&str] = &[
    "LogicException",
    "BadFunctionCallException",
    "BadMethodCallException",
    "DomainException",
    "InvalidArgumentException",
    "LengthException",
    "OutOfRangeException",
    "RuntimeException",
    "OutOfBoundsException",
    "OverflowException",
    "RangeException",
    "UnderflowException",
    "UnexpectedValueException",
];

// ── SPL interfaces ───────────────────────────────────────────────────────────

/// SPL interface names.
pub const SPL_INTERFACES: &[&str] = &[
    "Countable",
    "Iterator",
    "IteratorAggregate",
    "ArrayAccess",
    "Serializable",
    "Stringable",
    "SplObserver",
    "SplSubject",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spl_stack() {
        let mut stack = SplStack::new();
        assert!(stack.is_empty());

        stack.push(1);
        stack.push(2);
        stack.push(3);
        assert_eq!(stack.count(), 3);
        assert_eq!(stack.top(), Some(&3));

        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert!(stack.is_empty());
    }

    #[test]
    fn test_spl_queue() {
        let mut queue = SplQueue::new();
        assert!(queue.is_empty());

        queue.enqueue("first");
        queue.enqueue("second");
        queue.enqueue("third");
        assert_eq!(queue.count(), 3);
        assert_eq!(queue.bottom(), Some(&"first"));

        assert_eq!(queue.dequeue(), Some("first"));
        assert_eq!(queue.dequeue(), Some("second"));
        assert_eq!(queue.dequeue(), Some("third"));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_spl_priority_queue() {
        let mut pq = SplPriorityQueue::new();
        pq.insert("low", 1);
        pq.insert("high", 10);
        pq.insert("medium", 5);

        assert_eq!(pq.count(), 3);
        assert_eq!(pq.top(), Some(&"high"));
        assert_eq!(pq.extract(), Some("high"));
        assert_eq!(pq.extract(), Some("medium"));
        assert_eq!(pq.extract(), Some("low"));
    }

    #[test]
    fn test_spl_fixed_array() {
        let mut arr = SplFixedArray::<i32>::new(5);
        assert_eq!(arr.count(), 5);
        assert_eq!(arr.get(0), Some(&0)); // Default

        assert!(arr.set(0, 42));
        assert_eq!(arr.get(0), Some(&42));
        assert!(!arr.set(10, 99)); // Out of bounds

        arr.set_size(3);
        assert_eq!(arr.count(), 3);
    }

    #[test]
    fn test_spl_exceptions_list() {
        assert!(SPL_EXCEPTIONS.contains(&"LogicException"));
        assert!(SPL_EXCEPTIONS.contains(&"RuntimeException"));
        assert!(SPL_EXCEPTIONS.contains(&"InvalidArgumentException"));
        assert_eq!(SPL_EXCEPTIONS.len(), 13);
    }

    #[test]
    fn test_spl_interfaces_list() {
        assert!(SPL_INTERFACES.contains(&"Countable"));
        assert!(SPL_INTERFACES.contains(&"Iterator"));
        assert!(SPL_INTERFACES.contains(&"ArrayAccess"));
    }
}
