//! PHP SPL extension — Standard PHP Library.
//!
//! Implements data structures, iterators, exceptions, and interfaces.
//! Reference: php-src/ext/spl/

use std::path::Path;

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

// ── SPL Iterators ────────────────────────────────────────────────────────────

/// ArrayIterator — iterate over an array of key-value pairs.
pub struct ArrayIterator<T> {
    items: Vec<(String, T)>,
    position: usize,
}

impl<T> ArrayIterator<T> {
    /// Create a new ArrayIterator from key-value pairs.
    pub fn new(items: Vec<(String, T)>) -> Self {
        Self { items, position: 0 }
    }

    /// Get the current value.
    pub fn current(&self) -> Option<&T> {
        self.items.get(self.position).map(|(_, v)| v)
    }

    /// Get the current key.
    pub fn key(&self) -> Option<&str> {
        self.items.get(self.position).map(|(k, _)| k.as_str())
    }

    /// Advance to the next element.
    pub fn next(&mut self) {
        self.position += 1;
    }

    /// Reset to the first element.
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.position < self.items.len()
    }
}

/// FilterIterator — abstract base for filtering iterators.
pub struct FilterIterator<T, F: Fn(&T) -> bool> {
    inner: ArrayIterator<T>,
    accept: F,
}

impl<T, F: Fn(&T) -> bool> FilterIterator<T, F> {
    /// Create a new FilterIterator.
    pub fn new(inner: ArrayIterator<T>, accept: F) -> Self {
        let mut fi = Self { inner, accept };
        fi.advance_to_accepted();
        fi
    }

    /// Get the current value (only accepted values).
    pub fn current(&self) -> Option<&T> {
        self.inner.current()
    }

    /// Get the current key.
    pub fn key(&self) -> Option<&str> {
        self.inner.key()
    }

    /// Advance to the next accepted element.
    pub fn next(&mut self) {
        self.inner.next();
        self.advance_to_accepted();
    }

    /// Reset to the first accepted element.
    pub fn rewind(&mut self) {
        self.inner.rewind();
        self.advance_to_accepted();
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.inner.valid()
    }

    /// Skip non-accepted items.
    fn advance_to_accepted(&mut self) {
        while self.inner.valid() {
            if let Some(val) = self.inner.current() {
                if (self.accept)(val) {
                    return;
                }
            }
            self.inner.next();
        }
    }
}

/// LimitIterator — iterate over a limited subset.
pub struct LimitIterator<T> {
    inner: ArrayIterator<T>,
    offset: usize,
    count: usize,
    position: usize,
}

impl<T> LimitIterator<T> {
    /// Create a new LimitIterator.
    pub fn new(inner: ArrayIterator<T>, offset: usize, count: usize) -> Self {
        let mut li = Self {
            inner,
            offset,
            count,
            position: 0,
        };
        li.rewind();
        li
    }

    /// Get the current value.
    pub fn current(&self) -> Option<&T> {
        if self.position < self.count {
            self.inner.current()
        } else {
            None
        }
    }

    /// Get the current key.
    pub fn key(&self) -> Option<&str> {
        if self.position < self.count {
            self.inner.key()
        } else {
            None
        }
    }

    /// Advance to the next element within the limit.
    pub fn next(&mut self) {
        if self.position < self.count {
            self.inner.next();
            self.position += 1;
        }
    }

    /// Reset to the first element (at offset).
    pub fn rewind(&mut self) {
        self.inner.rewind();
        for _ in 0..self.offset {
            self.inner.next();
        }
        self.position = 0;
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.position < self.count && self.inner.valid()
    }
}

/// AppendIterator — iterate over multiple iterators sequentially.
pub struct AppendIterator<T> {
    iterators: Vec<ArrayIterator<T>>,
    current_iter: usize,
}

impl<T> AppendIterator<T> {
    /// Create a new empty AppendIterator.
    pub fn new() -> Self {
        Self {
            iterators: Vec::new(),
            current_iter: 0,
        }
    }

    /// Append an iterator.
    pub fn append(&mut self, iter: ArrayIterator<T>) {
        self.iterators.push(iter);
    }

    /// Get the current value.
    pub fn current(&self) -> Option<&T> {
        if self.current_iter < self.iterators.len() {
            self.iterators[self.current_iter].current()
        } else {
            None
        }
    }

    /// Get the current key.
    pub fn key(&self) -> Option<&str> {
        if self.current_iter < self.iterators.len() {
            self.iterators[self.current_iter].key()
        } else {
            None
        }
    }

    /// Advance to the next element, crossing iterator boundaries.
    pub fn next(&mut self) {
        if self.current_iter < self.iterators.len() {
            self.iterators[self.current_iter].next();
            if !self.iterators[self.current_iter].valid() {
                self.current_iter += 1;
                // Rewind the next iterator if it exists
                if self.current_iter < self.iterators.len() {
                    self.iterators[self.current_iter].rewind();
                }
            }
        }
    }

    /// Reset to the beginning of the first iterator.
    pub fn rewind(&mut self) {
        self.current_iter = 0;
        if !self.iterators.is_empty() {
            self.iterators[0].rewind();
        }
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        if self.current_iter < self.iterators.len() {
            self.iterators[self.current_iter].valid()
        } else {
            false
        }
    }
}

impl<T> Default for AppendIterator<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// InfiniteIterator — repeats an iterator infinitely.
pub struct InfiniteIterator<T: Clone> {
    inner: Vec<(String, T)>,
    position: usize,
}

impl<T: Clone> InfiniteIterator<T> {
    /// Create a new InfiniteIterator from key-value pairs.
    pub fn new(items: Vec<(String, T)>) -> Self {
        Self {
            inner: items,
            position: 0,
        }
    }

    /// Get the current value.
    pub fn current(&self) -> Option<&T> {
        if self.inner.is_empty() {
            return None;
        }
        let idx = self.position % self.inner.len();
        Some(&self.inner[idx].1)
    }

    /// Get the current key.
    pub fn key(&self) -> Option<&str> {
        if self.inner.is_empty() {
            return None;
        }
        let idx = self.position % self.inner.len();
        Some(&self.inner[idx].0)
    }

    /// Advance to the next element (wraps around).
    pub fn next(&mut self) {
        if !self.inner.is_empty() {
            self.position += 1;
        }
    }

    /// Reset to the first element.
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Always returns true (infinite iteration), unless empty.
    pub fn valid(&self) -> bool {
        !self.inner.is_empty()
    }
}

/// A directory entry with its filename and full pathname stored separately.
///
/// `std::path::Path::file_name()` does not work correctly for "." and ".."
/// so we store the filename explicitly at collection time.
#[derive(Clone, Debug)]
struct DirEntry {
    /// The entry name (e.g. ".", "..", "file.txt").
    filename: String,
    /// The full pathname (e.g. "/tmp/dir/file.txt").
    pathname: String,
}

/// DirectoryIterator — iterates over entries in a single directory.
///
/// Reference: php-src/ext/spl/spl_directory.c
/// PHP's DirectoryIterator yields SplFileInfo objects for each entry
/// including "." and ".." (dot entries). Entries are yielded in the
/// order returned by the filesystem (readdir).
pub struct DirectoryIterator {
    /// The directory path being iterated.
    path: String,
    /// Collected directory entries.
    entries: Vec<DirEntry>,
    /// Current cursor position.
    position: usize,
}

impl DirectoryIterator {
    /// Open a directory for iteration.
    ///
    /// Returns an error if the path does not exist or is not a directory.
    pub fn new(path: &str) -> Result<Self, String> {
        let read_dir = std::fs::read_dir(path)
            .map_err(|e| format!("DirectoryIterator::__construct({}): {}", path, e))?;

        let sep = if path.ends_with('/') || path.ends_with('\\') {
            ""
        } else {
            "/"
        };

        let mut entries = Vec::new();
        // PHP includes "." and ".." — add them explicitly since read_dir omits them.
        entries.push(DirEntry {
            filename: ".".to_string(),
            pathname: format!("{}{}.", path, sep),
        });
        entries.push(DirEntry {
            filename: "..".to_string(),
            pathname: format!("{}{}..", path, sep),
        });

        for e in read_dir.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            let pname = e.path().to_string_lossy().to_string();
            entries.push(DirEntry {
                filename: fname,
                pathname: pname,
            });
        }

        Ok(Self {
            path: path.to_string(),
            entries,
            position: 0,
        })
    }

    /// Get the current entry as an SplFileInfo.
    pub fn current(&self) -> Option<SplFileInfo> {
        self.entries
            .get(self.position)
            .map(|e| SplFileInfo::new(&e.pathname))
    }

    /// Get the filename of the current entry (basename only).
    pub fn get_filename(&self) -> Option<String> {
        self.entries
            .get(self.position)
            .map(|e| e.filename.clone())
    }

    /// Get the current key (integer index).
    pub fn key(&self) -> usize {
        self.position
    }

    /// Advance to the next entry.
    pub fn next(&mut self) {
        self.position += 1;
    }

    /// Reset to the first entry.
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.position < self.entries.len()
    }

    /// Check if the current entry is a dot entry ("." or "..").
    pub fn is_dot(&self) -> bool {
        if let Some(name) = self.get_filename() {
            name == "." || name == ".."
        } else {
            false
        }
    }

    /// Get the directory path that was opened.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Get the full pathname of the current entry.
    pub fn get_pathname(&self) -> Option<&str> {
        self.entries
            .get(self.position)
            .map(|e| e.pathname.as_str())
    }

    /// Get the total number of entries (including "." and "..").
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

/// Flags for RecursiveDirectoryIterator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveDirectoryIteratorFlag {
    /// Default: return child iterators for subdirectories.
    None,
    /// Skip dot entries ("." and "..").
    SkipDots,
}

/// RecursiveDirectoryIterator — iterates over directory entries and can
/// descend into subdirectories.
///
/// Reference: php-src/ext/spl/spl_directory.c
/// This iterator yields entries from a single directory but provides a
/// `get_children()` method that returns a new RecursiveDirectoryIterator
/// for the current entry when it is a subdirectory.
pub struct RecursiveDirectoryIterator {
    /// The directory path being iterated.
    path: String,
    /// Collected directory entries.
    entries: Vec<DirEntry>,
    /// Current cursor position.
    position: usize,
    /// Whether to skip dot entries.
    skip_dots: bool,
}

impl RecursiveDirectoryIterator {
    /// Open a directory for recursive iteration.
    pub fn new(path: &str, flag: RecursiveDirectoryIteratorFlag) -> Result<Self, String> {
        let skip_dots = flag == RecursiveDirectoryIteratorFlag::SkipDots;

        let read_dir = std::fs::read_dir(path).map_err(|e| {
            format!(
                "RecursiveDirectoryIterator::__construct({}): {}",
                path, e
            )
        })?;

        let sep = if path.ends_with('/') || path.ends_with('\\') {
            ""
        } else {
            "/"
        };

        let mut entries = Vec::new();

        if !skip_dots {
            entries.push(DirEntry {
                filename: ".".to_string(),
                pathname: format!("{}{}.", path, sep),
            });
            entries.push(DirEntry {
                filename: "..".to_string(),
                pathname: format!("{}{}..", path, sep),
            });
        }

        for e in read_dir.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            let pname = e.path().to_string_lossy().to_string();
            entries.push(DirEntry {
                filename: fname,
                pathname: pname,
            });
        }

        Ok(Self {
            path: path.to_string(),
            entries,
            position: 0,
            skip_dots,
        })
    }

    /// Get the current entry as an SplFileInfo.
    pub fn current(&self) -> Option<SplFileInfo> {
        self.entries
            .get(self.position)
            .map(|e| SplFileInfo::new(&e.pathname))
    }

    /// Get the filename of the current entry.
    pub fn get_filename(&self) -> Option<String> {
        self.entries
            .get(self.position)
            .map(|e| e.filename.clone())
    }

    /// Get the current key (integer index).
    pub fn key(&self) -> usize {
        self.position
    }

    /// Advance to the next entry.
    pub fn next(&mut self) {
        self.position += 1;
    }

    /// Reset to the first entry.
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.position < self.entries.len()
    }

    /// Check if the current entry has children (is a non-dot directory).
    pub fn has_children(&self) -> bool {
        if let Some(entry) = self.entries.get(self.position) {
            if entry.filename == "." || entry.filename == ".." {
                return false;
            }
            Path::new(&entry.pathname).is_dir()
        } else {
            false
        }
    }

    /// Get a new RecursiveDirectoryIterator for the current subdirectory.
    ///
    /// Returns `None` if the current entry is not a directory or is a dot entry.
    pub fn get_children(&self) -> Option<Result<RecursiveDirectoryIterator, String>> {
        if !self.has_children() {
            return None;
        }
        let pathname = &self.entries[self.position].pathname;
        let flag = if self.skip_dots {
            RecursiveDirectoryIteratorFlag::SkipDots
        } else {
            RecursiveDirectoryIteratorFlag::None
        };
        Some(RecursiveDirectoryIterator::new(pathname, flag))
    }

    /// Get the full pathname of the current entry.
    pub fn get_pathname(&self) -> Option<&str> {
        self.entries
            .get(self.position)
            .map(|e| e.pathname.as_str())
    }

    /// Get the directory path that was opened.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Check if the current entry is a dot entry.
    pub fn is_dot(&self) -> bool {
        if let Some(name) = self.get_filename() {
            name == "." || name == ".."
        } else {
            false
        }
    }
}

/// Mode for RecursiveIteratorIterator traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveIteratorMode {
    /// Yield leaves only (files, not directories). This is the default.
    LeavesOnly,
    /// Yield the parent (directory) before its children.
    SelfFirst,
    /// Yield the parent (directory) after its children.
    ChildFirst,
}

/// RecursiveIteratorIterator — flattens a RecursiveDirectoryIterator into a
/// single linear sequence by recursively descending into subdirectories.
///
/// Reference: php-src/ext/spl/spl_iterators.c
/// In PHP this is generic over any RecursiveIterator; here we specialise on
/// RecursiveDirectoryIterator since that is the primary use case.
pub struct RecursiveIteratorIterator {
    /// Pre-collected flattened entries as (depth, pathname) pairs.
    entries: Vec<(usize, String)>,
    /// Current cursor position.
    position: usize,
    /// The traversal mode.
    mode: RecursiveIteratorMode,
}

impl RecursiveIteratorIterator {
    /// Create a new RecursiveIteratorIterator from a RecursiveDirectoryIterator.
    pub fn new(
        iter: &RecursiveDirectoryIterator,
        mode: RecursiveIteratorMode,
    ) -> Result<Self, String> {
        let mut entries = Vec::new();
        Self::collect_entries(&iter.path, iter.skip_dots, 0, mode, &mut entries)?;
        Ok(Self {
            entries,
            position: 0,
            mode,
        })
    }

    /// Recursively collect entries from the filesystem.
    fn collect_entries(
        path: &str,
        skip_dots: bool,
        depth: usize,
        mode: RecursiveIteratorMode,
        out: &mut Vec<(usize, String)>,
    ) -> Result<(), String> {
        let read_dir = std::fs::read_dir(path)
            .map_err(|e| format!("RecursiveIteratorIterator: {}", e))?;

        // Gather entries for this directory.
        let mut dir_entries: Vec<String> = Vec::new();
        for e in read_dir.flatten() {
            dir_entries.push(e.path().to_string_lossy().to_string());
        }
        // Sort for deterministic ordering in tests.
        dir_entries.sort();

        for entry_path in &dir_entries {
            let is_dir = Path::new(entry_path).is_dir();
            let name = Path::new(entry_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if skip_dots && (name == "." || name == "..") {
                continue;
            }

            if is_dir {
                match mode {
                    RecursiveIteratorMode::SelfFirst => {
                        out.push((depth, entry_path.clone()));
                        Self::collect_entries(entry_path, skip_dots, depth + 1, mode, out)?;
                    }
                    RecursiveIteratorMode::ChildFirst => {
                        Self::collect_entries(entry_path, skip_dots, depth + 1, mode, out)?;
                        out.push((depth, entry_path.clone()));
                    }
                    RecursiveIteratorMode::LeavesOnly => {
                        Self::collect_entries(entry_path, skip_dots, depth + 1, mode, out)?;
                    }
                }
            } else {
                out.push((depth, entry_path.clone()));
            }
        }

        Ok(())
    }

    /// Get the current entry as an SplFileInfo.
    pub fn current(&self) -> Option<SplFileInfo> {
        self.entries
            .get(self.position)
            .map(|(_, p)| SplFileInfo::new(p))
    }

    /// Get the filename of the current entry.
    pub fn get_filename(&self) -> Option<String> {
        self.entries.get(self.position).map(|(_, p)| {
            Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone())
        })
    }

    /// Get the full pathname of the current entry.
    pub fn get_pathname(&self) -> Option<&str> {
        self.entries.get(self.position).map(|(_, p)| p.as_str())
    }

    /// Get the current recursion depth (0-indexed).
    pub fn get_depth(&self) -> usize {
        self.entries
            .get(self.position)
            .map(|(d, _)| *d)
            .unwrap_or(0)
    }

    /// Get the current key (integer index).
    pub fn key(&self) -> usize {
        self.position
    }

    /// Advance to the next entry.
    pub fn next(&mut self) {
        self.position += 1;
    }

    /// Reset to the first entry.
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Check if the current position is valid.
    pub fn valid(&self) -> bool {
        self.position < self.entries.len()
    }

    /// Get the traversal mode.
    pub fn get_mode(&self) -> RecursiveIteratorMode {
        self.mode
    }

    /// Get the total number of entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

// ── SplFileInfo & SplFileObject ─────────────────────────────────────────────

/// SplFileInfo — file metadata.
pub struct SplFileInfo {
    path: String,
}

impl SplFileInfo {
    /// Create a new SplFileInfo for the given path.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Get the basename (filename with extension, without directory).
    pub fn get_basename(&self) -> String {
        Path::new(&self.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// Get the file extension.
    pub fn get_extension(&self) -> String {
        Path::new(&self.path)
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// Get the filename (same as basename).
    pub fn get_filename(&self) -> String {
        self.get_basename()
    }

    /// Get the path (directory part only).
    pub fn get_path(&self) -> &str {
        Path::new(&self.path)
            .parent()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
    }

    /// Get the full pathname.
    pub fn get_pathname(&self) -> &str {
        &self.path
    }

    /// Get the real (canonical) path, if it exists.
    pub fn get_real_path(&self) -> Option<String> {
        std::fs::canonicalize(&self.path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Get the file size in bytes.
    pub fn get_size(&self) -> Result<u64, String> {
        std::fs::metadata(&self.path)
            .map(|m| m.len())
            .map_err(|e| format!("Failed to get size: {}", e))
    }

    /// Get the file type: "file", "dir", or "link".
    pub fn get_type(&self) -> &str {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            if meta.file_type().is_symlink() {
                "link"
            } else if meta.is_dir() {
                "dir"
            } else {
                "file"
            }
        } else {
            "file"
        }
    }

    /// Check if the path is a directory.
    pub fn is_dir(&self) -> bool {
        Path::new(&self.path).is_dir()
    }

    /// Check if the path is a regular file.
    pub fn is_file(&self) -> bool {
        Path::new(&self.path).is_file()
    }

    /// Check if the path is a symbolic link.
    pub fn is_link(&self) -> bool {
        Path::new(&self.path).is_symlink()
    }

    /// Check if the path is readable.
    pub fn is_readable(&self) -> bool {
        // Simplified: if we can read metadata, it's readable
        std::fs::metadata(&self.path).is_ok()
    }

    /// Check if the path is writable.
    pub fn is_writable(&self) -> bool {
        // Simplified: try opening for write
        if Path::new(&self.path).exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&self.path)
                .is_ok()
        } else {
            false
        }
    }
}

/// SplFileObject — OOP file handle with line iteration.
pub struct SplFileObject {
    info: SplFileInfo,
    content: Option<String>,
    lines: Vec<String>,
    current_line: usize,
}

impl SplFileObject {
    /// Open and read a file.
    pub fn new(filename: &str) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(filename).map_err(|e| format!("Failed to open file: {}", e))?;
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        Ok(Self {
            info: SplFileInfo::new(filename),
            content: Some(content),
            lines,
            current_line: 0,
        })
    }

    /// Create an SplFileObject from in-memory content (for testing).
    pub fn from_content(filename: &str, content: &str) -> Self {
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        Self {
            info: SplFileInfo::new(filename),
            content: Some(content.to_string()),
            lines,
            current_line: 0,
        }
    }

    /// Get the current line.
    pub fn current_line(&self) -> Option<&str> {
        self.lines.get(self.current_line).map(|s| s.as_str())
    }

    /// Get the current line number (0-based).
    pub fn key(&self) -> usize {
        self.current_line
    }

    /// Advance to the next line.
    pub fn next(&mut self) {
        self.current_line += 1;
    }

    /// Reset to the first line.
    pub fn rewind(&mut self) {
        self.current_line = 0;
    }

    /// Check if the current line is valid.
    pub fn valid(&self) -> bool {
        self.current_line < self.lines.len()
    }

    /// Check if we are at end of file.
    pub fn eof(&self) -> bool {
        self.current_line >= self.lines.len()
    }

    /// Read the current line and advance (like fgets).
    pub fn fgets(&mut self) -> Option<String> {
        if self.current_line < self.lines.len() {
            let line = self.lines[self.current_line].clone();
            self.current_line += 1;
            Some(line)
        } else {
            None
        }
    }

    /// Read the current line as CSV fields and advance.
    pub fn fgetcsv(&mut self, delimiter: char) -> Option<Vec<String>> {
        if self.current_line >= self.lines.len() {
            return None;
        }

        let line = &self.lines[self.current_line];
        self.current_line += 1;

        let mut fields = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            if in_quotes {
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        // Escaped quote
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    field.push(ch);
                }
            } else if ch == '"' {
                in_quotes = true;
            } else if ch == delimiter {
                fields.push(field.clone());
                field.clear();
            } else {
                field.push(ch);
            }
        }
        fields.push(field);

        Some(fields)
    }

    /// Write data to the file (appends to content).
    pub fn fwrite(&mut self, data: &str) -> Result<usize, String> {
        let content = self.content.get_or_insert_with(String::new);
        content.push_str(data);
        // Re-split lines
        self.lines = content.lines().map(|l| l.to_string()).collect();
        Ok(data.len())
    }

    /// Get the underlying SplFileInfo.
    pub fn get_file_info(&self) -> &SplFileInfo {
        &self.info
    }
}

// ── SPL Autoloader ──────────────────────────────────────────────────────────

/// Autoload function names (actual registration happens in VM).
pub const SPL_AUTOLOAD_FUNCTIONS: &[&str] = &[
    "spl_autoload_register",
    "spl_autoload_unregister",
    "spl_autoload_functions",
    "spl_autoload_call",
    "spl_autoload_extensions",
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

    // ── ArrayIterator tests ─────────────────────────────────────────────────

    #[test]
    fn test_array_iterator_basic() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ];
        let mut iter = ArrayIterator::new(items);

        assert!(iter.valid());
        assert_eq!(iter.key(), Some("a"));
        assert_eq!(iter.current(), Some(&1));

        iter.next();
        assert_eq!(iter.key(), Some("b"));
        assert_eq!(iter.current(), Some(&2));

        iter.next();
        assert_eq!(iter.key(), Some("c"));
        assert_eq!(iter.current(), Some(&3));

        iter.next();
        assert!(!iter.valid());
    }

    #[test]
    fn test_array_iterator_rewind() {
        let items = vec![("x".to_string(), 10), ("y".to_string(), 20)];
        let mut iter = ArrayIterator::new(items);

        iter.next();
        assert_eq!(iter.current(), Some(&20));

        iter.rewind();
        assert_eq!(iter.current(), Some(&10));
        assert_eq!(iter.key(), Some("x"));
    }

    #[test]
    fn test_array_iterator_empty() {
        let iter: ArrayIterator<i32> = ArrayIterator::new(vec![]);
        assert!(!iter.valid());
        assert_eq!(iter.current(), None);
        assert_eq!(iter.key(), None);
    }

    // ── FilterIterator tests ────────────────────────────────────────────────

    #[test]
    fn test_filter_iterator() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
            ("d".to_string(), 4),
            ("e".to_string(), 5),
        ];
        let inner = ArrayIterator::new(items);
        let mut filter = FilterIterator::new(inner, |v| v % 2 == 0);

        assert!(filter.valid());
        assert_eq!(filter.current(), Some(&2));
        assert_eq!(filter.key(), Some("b"));

        filter.next();
        assert!(filter.valid());
        assert_eq!(filter.current(), Some(&4));
        assert_eq!(filter.key(), Some("d"));

        filter.next();
        assert!(!filter.valid());
    }

    #[test]
    fn test_filter_iterator_rewind() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ];
        let inner = ArrayIterator::new(items);
        let mut filter = FilterIterator::new(inner, |v| *v > 1);

        assert_eq!(filter.current(), Some(&2));
        filter.next();
        assert_eq!(filter.current(), Some(&3));

        filter.rewind();
        assert_eq!(filter.current(), Some(&2));
    }

    #[test]
    fn test_filter_iterator_no_matches() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 3),
            ("c".to_string(), 5),
        ];
        let inner = ArrayIterator::new(items);
        let filter = FilterIterator::new(inner, |v| v % 2 == 0);
        assert!(!filter.valid());
    }

    // ── LimitIterator tests ─────────────────────────────────────────────────

    #[test]
    fn test_limit_iterator() {
        let items = vec![
            ("0".to_string(), 10),
            ("1".to_string(), 20),
            ("2".to_string(), 30),
            ("3".to_string(), 40),
            ("4".to_string(), 50),
        ];
        let inner = ArrayIterator::new(items);
        let mut limit = LimitIterator::new(inner, 1, 2);

        assert!(limit.valid());
        assert_eq!(limit.current(), Some(&20));
        assert_eq!(limit.key(), Some("1"));

        limit.next();
        assert!(limit.valid());
        assert_eq!(limit.current(), Some(&30));

        limit.next();
        assert!(!limit.valid());
    }

    #[test]
    fn test_limit_iterator_rewind() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ];
        let inner = ArrayIterator::new(items);
        let mut limit = LimitIterator::new(inner, 0, 2);

        limit.next();
        assert_eq!(limit.current(), Some(&2));

        limit.rewind();
        assert_eq!(limit.current(), Some(&1));
    }

    // ── AppendIterator tests ────────────────────────────────────────────────

    #[test]
    fn test_append_iterator() {
        let iter1 = ArrayIterator::new(vec![("a".to_string(), 1), ("b".to_string(), 2)]);
        let iter2 = ArrayIterator::new(vec![("c".to_string(), 3), ("d".to_string(), 4)]);

        let mut append = AppendIterator::new();
        append.append(iter1);
        append.append(iter2);

        assert!(append.valid());
        assert_eq!(append.current(), Some(&1));

        append.next();
        assert_eq!(append.current(), Some(&2));

        append.next();
        // Should have crossed into second iterator
        assert_eq!(append.current(), Some(&3));

        append.next();
        assert_eq!(append.current(), Some(&4));

        append.next();
        assert!(!append.valid());
    }

    #[test]
    fn test_append_iterator_rewind() {
        let iter1 = ArrayIterator::new(vec![("a".to_string(), 1)]);
        let iter2 = ArrayIterator::new(vec![("b".to_string(), 2)]);

        let mut append = AppendIterator::new();
        append.append(iter1);
        append.append(iter2);

        append.next();
        append.next();
        assert!(!append.valid());

        append.rewind();
        assert!(append.valid());
        assert_eq!(append.current(), Some(&1));
    }

    #[test]
    fn test_append_iterator_empty() {
        let append: AppendIterator<i32> = AppendIterator::new();
        assert!(!append.valid());
    }

    // ── InfiniteIterator tests ──────────────────────────────────────────────

    #[test]
    fn test_infinite_iterator() {
        let items = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ];
        let mut inf = InfiniteIterator::new(items);

        assert!(inf.valid());
        assert_eq!(inf.current(), Some(&1));
        assert_eq!(inf.key(), Some("a"));

        inf.next();
        assert_eq!(inf.current(), Some(&2));

        inf.next();
        assert_eq!(inf.current(), Some(&3));

        // Wraps around
        inf.next();
        assert!(inf.valid());
        assert_eq!(inf.current(), Some(&1));
        assert_eq!(inf.key(), Some("a"));
    }

    #[test]
    fn test_infinite_iterator_rewind() {
        let items = vec![("x".to_string(), 42)];
        let mut inf = InfiniteIterator::new(items);

        inf.next();
        inf.next();
        inf.next();
        assert_eq!(inf.current(), Some(&42)); // wraps

        inf.rewind();
        assert_eq!(inf.current(), Some(&42));
    }

    #[test]
    fn test_infinite_iterator_empty() {
        let inf: InfiniteIterator<i32> = InfiniteIterator::new(vec![]);
        assert!(!inf.valid());
        assert_eq!(inf.current(), None);
    }

    // ── DirectoryIterator tests ─────────────────────────────────────────────

    #[test]
    fn test_directory_iterator_basic() {
        // Create a temporary directory with known contents.
        let dir = std::env::temp_dir().join("php_rs_spl_dir_iter_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.txt"), "a").unwrap();
        std::fs::write(dir.join("beta.txt"), "b").unwrap();

        let mut iter = DirectoryIterator::new(dir.to_str().unwrap()).unwrap();

        // Should be valid at the start.
        assert!(iter.valid());

        // Collect all filenames.
        let mut names = Vec::new();
        while iter.valid() {
            names.push(iter.get_filename().unwrap());
            iter.next();
        }

        // Must include "." and ".." plus the two files.
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"alpha.txt".to_string()));
        assert!(names.contains(&"beta.txt".to_string()));
        assert_eq!(names.len(), 4);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_iterator_is_dot() {
        let dir = std::env::temp_dir().join("php_rs_spl_dir_iter_dot_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), "x").unwrap();

        let mut iter = DirectoryIterator::new(dir.to_str().unwrap()).unwrap();

        let mut dot_count = 0;
        let mut non_dot_count = 0;
        while iter.valid() {
            if iter.is_dot() {
                dot_count += 1;
            } else {
                non_dot_count += 1;
            }
            iter.next();
        }

        assert_eq!(dot_count, 2); // "." and ".."
        assert_eq!(non_dot_count, 1); // "file.txt"

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_iterator_rewind() {
        let dir = std::env::temp_dir().join("php_rs_spl_dir_iter_rewind_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("one.txt"), "1").unwrap();

        let mut iter = DirectoryIterator::new(dir.to_str().unwrap()).unwrap();

        let first_name = iter.get_filename().unwrap();
        assert_eq!(iter.key(), 0);

        iter.next();
        iter.next();
        assert_eq!(iter.key(), 2);

        iter.rewind();
        assert_eq!(iter.key(), 0);
        assert_eq!(iter.get_filename().unwrap(), first_name);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_iterator_current_returns_file_info() {
        let dir = std::env::temp_dir().join("php_rs_spl_dir_iter_fileinfo_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.csv"), "a,b").unwrap();

        let mut iter = DirectoryIterator::new(dir.to_str().unwrap()).unwrap();

        // Skip dot entries.
        while iter.valid() && iter.is_dot() {
            iter.next();
        }

        // The current entry should be data.csv.
        let info = iter.current().unwrap();
        assert_eq!(info.get_basename(), "data.csv");
        assert!(info.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_iterator_nonexistent() {
        let result = DirectoryIterator::new("/nonexistent/path/that/does/not/exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_directory_iterator_count_and_path() {
        let dir = std::env::temp_dir().join("php_rs_spl_dir_iter_count_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("x.txt"), "").unwrap();
        std::fs::write(dir.join("y.txt"), "").unwrap();

        let iter = DirectoryIterator::new(dir.to_str().unwrap()).unwrap();
        // 2 dots + 2 files.
        assert_eq!(iter.count(), 4);
        assert_eq!(iter.get_path(), dir.to_str().unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── RecursiveDirectoryIterator tests ──────────────────────────────────────

    #[test]
    fn test_recursive_directory_iterator_basic() {
        let dir = std::env::temp_dir().join("php_rs_spl_rdi_basic_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("top.txt"), "t").unwrap();
        std::fs::write(dir.join("sub").join("inner.txt"), "i").unwrap();

        let mut iter = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut names = Vec::new();
        while iter.valid() {
            names.push(iter.get_filename().unwrap());
            iter.next();
        }

        // Should have top.txt and the sub directory (no dots).
        assert!(names.contains(&"top.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
        assert!(!names.contains(&".".to_string()));
        assert!(!names.contains(&"..".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_directory_iterator_with_dots() {
        let dir = std::env::temp_dir().join("php_rs_spl_rdi_dots_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), "").unwrap();

        let mut iter = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::None,
        )
        .unwrap();

        let mut names = Vec::new();
        while iter.valid() {
            names.push(iter.get_filename().unwrap());
            iter.next();
        }

        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"file.txt".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_directory_iterator_has_children() {
        let dir = std::env::temp_dir().join("php_rs_spl_rdi_children_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("child_dir")).unwrap();
        std::fs::write(dir.join("file.txt"), "").unwrap();

        let mut iter = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut found_dir_with_children = false;
        let mut found_file_without_children = false;
        while iter.valid() {
            let name = iter.get_filename().unwrap();
            if name == "child_dir" {
                assert!(iter.has_children());
                found_dir_with_children = true;
            }
            if name == "file.txt" {
                assert!(!iter.has_children());
                found_file_without_children = true;
            }
            iter.next();
        }

        assert!(found_dir_with_children);
        assert!(found_file_without_children);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_directory_iterator_get_children() {
        let dir = std::env::temp_dir().join("php_rs_spl_rdi_get_children_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        std::fs::write(dir.join("subdir").join("nested.txt"), "n").unwrap();

        let mut iter = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        // Find the "subdir" entry and get its children.
        while iter.valid() {
            if iter.get_filename().as_deref() == Some("subdir") {
                assert!(iter.has_children());
                let child_iter = iter.get_children().unwrap().unwrap();
                // The child iterator should contain "nested.txt".
                let mut child_names = Vec::new();
                let mut ci = child_iter;
                while ci.valid() {
                    child_names.push(ci.get_filename().unwrap());
                    ci.next();
                }
                assert!(child_names.contains(&"nested.txt".to_string()));
                break;
            }
            iter.next();
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_directory_iterator_rewind() {
        let dir = std::env::temp_dir().join("php_rs_spl_rdi_rewind_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "").unwrap();

        let mut iter = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let first = iter.get_filename().unwrap();
        iter.next();
        iter.rewind();
        assert_eq!(iter.get_filename().unwrap(), first);
        assert_eq!(iter.key(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_directory_iterator_nonexistent() {
        let result = RecursiveDirectoryIterator::new(
            "/nonexistent/dir",
            RecursiveDirectoryIteratorFlag::None,
        );
        assert!(result.is_err());
    }

    // ── RecursiveIteratorIterator tests ───────────────────────────────────────

    #[test]
    fn test_recursive_iterator_iterator_leaves_only() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_leaves_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("root.txt"), "r").unwrap();
        std::fs::write(dir.join("sub").join("leaf.txt"), "l").unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::LeavesOnly).unwrap();

        let mut names = Vec::new();
        while rii.valid() {
            names.push(rii.get_filename().unwrap());
            rii.next();
        }

        // LeavesOnly: only files, not directories.
        assert!(names.contains(&"root.txt".to_string()));
        assert!(names.contains(&"leaf.txt".to_string()));
        assert!(!names.contains(&"sub".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_self_first() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_self_first_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("adir")).unwrap();
        std::fs::write(dir.join("adir").join("file.txt"), "f").unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::SelfFirst).unwrap();

        let mut names = Vec::new();
        while rii.valid() {
            names.push(rii.get_filename().unwrap());
            rii.next();
        }

        // SelfFirst: directory appears, then its contents.
        assert!(names.contains(&"adir".to_string()));
        assert!(names.contains(&"file.txt".to_string()));
        let dir_pos = names.iter().position(|n| n == "adir").unwrap();
        let file_pos = names.iter().position(|n| n == "file.txt").unwrap();
        assert!(dir_pos < file_pos, "Directory should appear before its child");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_child_first() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_child_first_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bdir")).unwrap();
        std::fs::write(dir.join("bdir").join("inner.txt"), "i").unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::ChildFirst).unwrap();

        let mut names = Vec::new();
        while rii.valid() {
            names.push(rii.get_filename().unwrap());
            rii.next();
        }

        // ChildFirst: children appear before their parent directory.
        assert!(names.contains(&"bdir".to_string()));
        assert!(names.contains(&"inner.txt".to_string()));
        let dir_pos = names.iter().position(|n| n == "bdir").unwrap();
        let file_pos = names.iter().position(|n| n == "inner.txt").unwrap();
        assert!(file_pos < dir_pos, "Child should appear before its parent directory");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_depth() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_depth_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("l1").join("l2")).unwrap();
        std::fs::write(dir.join("top.txt"), "").unwrap();
        std::fs::write(dir.join("l1").join("mid.txt"), "").unwrap();
        std::fs::write(dir.join("l1").join("l2").join("deep.txt"), "").unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::LeavesOnly).unwrap();

        let mut depth_map = Vec::new();
        while rii.valid() {
            depth_map.push((rii.get_filename().unwrap(), rii.get_depth()));
            rii.next();
        }

        // Verify depths: top.txt at 0, mid.txt at 1, deep.txt at 2.
        for (name, depth) in &depth_map {
            match name.as_str() {
                "top.txt" => assert_eq!(*depth, 0),
                "mid.txt" => assert_eq!(*depth, 1),
                "deep.txt" => assert_eq!(*depth, 2),
                _ => panic!("Unexpected entry: {}", name),
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_rewind() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_rewind_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), "").unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let mut rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::LeavesOnly).unwrap();

        let first_name = rii.get_filename().unwrap();
        rii.next();
        rii.rewind();
        assert_eq!(rii.key(), 0);
        assert_eq!(rii.get_filename().unwrap(), first_name);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_empty_dir() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_empty_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::LeavesOnly).unwrap();

        assert!(!rii.valid());
        assert_eq!(rii.count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recursive_iterator_iterator_mode_accessor() {
        let dir = std::env::temp_dir().join("php_rs_spl_rii_mode_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let rdi = RecursiveDirectoryIterator::new(
            dir.to_str().unwrap(),
            RecursiveDirectoryIteratorFlag::SkipDots,
        )
        .unwrap();

        let rii =
            RecursiveIteratorIterator::new(&rdi, RecursiveIteratorMode::SelfFirst).unwrap();
        assert_eq!(rii.get_mode(), RecursiveIteratorMode::SelfFirst);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── SplFileInfo tests ───────────────────────────────────────────────────

    #[test]
    fn test_file_info_basename() {
        let info = SplFileInfo::new("/path/to/file.txt");
        assert_eq!(info.get_basename(), "file.txt");
    }

    #[test]
    fn test_file_info_extension() {
        let info = SplFileInfo::new("/path/to/file.txt");
        assert_eq!(info.get_extension(), "txt");
    }

    #[test]
    fn test_file_info_extension_none() {
        let info = SplFileInfo::new("/path/to/Makefile");
        assert_eq!(info.get_extension(), "");
    }

    #[test]
    fn test_file_info_filename() {
        let info = SplFileInfo::new("/path/to/file.php");
        assert_eq!(info.get_filename(), "file.php");
    }

    #[test]
    fn test_file_info_path() {
        let info = SplFileInfo::new("/path/to/file.txt");
        assert_eq!(info.get_path(), "/path/to");
    }

    #[test]
    fn test_file_info_pathname() {
        let info = SplFileInfo::new("/path/to/file.txt");
        assert_eq!(info.get_pathname(), "/path/to/file.txt");
    }

    #[test]
    fn test_file_info_nonexistent() {
        let info = SplFileInfo::new("/nonexistent/path/file.txt");
        assert!(!info.is_file());
        assert!(!info.is_dir());
        assert!(!info.is_link());
        assert_eq!(info.get_real_path(), None);
    }

    // ── SplFileObject tests ─────────────────────────────────────────────────

    #[test]
    fn test_file_object_from_content() {
        let mut fo = SplFileObject::from_content("test.txt", "line1\nline2\nline3");

        assert!(fo.valid());
        assert_eq!(fo.current_line(), Some("line1"));
        assert_eq!(fo.key(), 0);
        assert!(!fo.eof());

        fo.next();
        assert_eq!(fo.current_line(), Some("line2"));
        assert_eq!(fo.key(), 1);

        fo.next();
        assert_eq!(fo.current_line(), Some("line3"));

        fo.next();
        assert!(!fo.valid());
        assert!(fo.eof());
    }

    #[test]
    fn test_file_object_rewind() {
        let mut fo = SplFileObject::from_content("test.txt", "first\nsecond");

        fo.next();
        assert_eq!(fo.current_line(), Some("second"));

        fo.rewind();
        assert_eq!(fo.current_line(), Some("first"));
        assert_eq!(fo.key(), 0);
    }

    #[test]
    fn test_file_object_fgets() {
        let mut fo = SplFileObject::from_content("test.txt", "aaa\nbbb\nccc");

        assert_eq!(fo.fgets(), Some("aaa".to_string()));
        assert_eq!(fo.fgets(), Some("bbb".to_string()));
        assert_eq!(fo.fgets(), Some("ccc".to_string()));
        assert_eq!(fo.fgets(), None);
    }

    #[test]
    fn test_file_object_fgetcsv() {
        let mut fo =
            SplFileObject::from_content("test.csv", "name,age,city\nAlice,30,NYC\nBob,25,LA");

        let header = fo.fgetcsv(',').unwrap();
        assert_eq!(header, vec!["name", "age", "city"]);

        let row1 = fo.fgetcsv(',').unwrap();
        assert_eq!(row1, vec!["Alice", "30", "NYC"]);

        let row2 = fo.fgetcsv(',').unwrap();
        assert_eq!(row2, vec!["Bob", "25", "LA"]);

        assert_eq!(fo.fgetcsv(','), None);
    }

    #[test]
    fn test_file_object_fgetcsv_quoted() {
        let mut fo = SplFileObject::from_content(
            "test.csv",
            "\"hello, world\",simple,\"has \"\"quotes\"\"\"",
        );

        let row = fo.fgetcsv(',').unwrap();
        assert_eq!(row[0], "hello, world");
        assert_eq!(row[1], "simple");
        assert_eq!(row[2], "has \"quotes\"");
    }

    #[test]
    fn test_file_object_fwrite() {
        let mut fo = SplFileObject::from_content("test.txt", "initial");
        let written = fo.fwrite("\nappended").unwrap();
        assert_eq!(written, 9);

        fo.rewind();
        assert_eq!(fo.fgets(), Some("initial".to_string()));
        assert_eq!(fo.fgets(), Some("appended".to_string()));
    }

    #[test]
    fn test_file_object_get_file_info() {
        let fo = SplFileObject::from_content("/path/to/data.csv", "a,b,c");
        let info = fo.get_file_info();
        assert_eq!(info.get_basename(), "data.csv");
        assert_eq!(info.get_extension(), "csv");
    }

    // ── SPL Autoloader constants test ───────────────────────────────────────

    #[test]
    fn test_spl_autoload_functions_list() {
        assert!(SPL_AUTOLOAD_FUNCTIONS.contains(&"spl_autoload_register"));
        assert!(SPL_AUTOLOAD_FUNCTIONS.contains(&"spl_autoload_unregister"));
        assert!(SPL_AUTOLOAD_FUNCTIONS.contains(&"spl_autoload_functions"));
        assert!(SPL_AUTOLOAD_FUNCTIONS.contains(&"spl_autoload_call"));
        assert!(SPL_AUTOLOAD_FUNCTIONS.contains(&"spl_autoload_extensions"));
        assert_eq!(SPL_AUTOLOAD_FUNCTIONS.len(), 5);
    }
}
