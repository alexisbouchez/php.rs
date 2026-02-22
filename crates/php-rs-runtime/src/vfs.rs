//! Virtual filesystem for WASM and testing environments.
//!
//! Provides an in-memory filesystem that implements the same operations as `std::fs`,
//! enabling PHP file operations in environments without a real filesystem (e.g., WASM).

use std::collections::HashMap;
use std::io;

/// A node in the virtual filesystem tree.
#[derive(Debug, Clone)]
enum VfsNode {
    /// A regular file with its contents.
    File(Vec<u8>),
    /// A directory containing named children.
    Directory(HashMap<String, VfsNode>),
}

/// An in-memory virtual filesystem.
#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    root: VfsNode,
}

impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFileSystem {
    /// Create a new empty virtual filesystem with just a root directory.
    pub fn new() -> Self {
        Self {
            root: VfsNode::Directory(HashMap::new()),
        }
    }

    /// Write a file at the given path, creating parent directories as needed.
    pub fn write_file(&mut self, path: &str, contents: &[u8]) -> io::Result<()> {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot write to root",
            ));
        }

        // Ensure parent directories exist
        if parts.len() > 1 {
            let parent = parts[..parts.len() - 1].join("/");
            if !self.is_dir(&parent) {
                self.mkdir(&format!("/{}", parent), true)?;
            }
        }

        let filename = parts.last().unwrap().to_string();
        let parent_dir = self.navigate_mut(&parts[..parts.len() - 1])?;

        match parent_dir {
            VfsNode::Directory(entries) => {
                entries.insert(filename, VfsNode::File(contents.to_vec()));
                Ok(())
            }
            VfsNode::File(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Parent is not a directory",
            )),
        }
    }

    /// Read a file at the given path.
    pub fn read_file(&self, path: &str) -> io::Result<&[u8]> {
        let parts = Self::split_path(path);
        let node = self.navigate(&parts)?;
        match node {
            VfsNode::File(contents) => Ok(contents),
            VfsNode::Directory(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Is a directory",
            )),
        }
    }

    /// Check if a path exists (file or directory).
    pub fn exists(&self, path: &str) -> bool {
        let parts = Self::split_path(path);
        self.navigate(&parts).is_ok()
    }

    /// Check if a path is a regular file.
    pub fn is_file(&self, path: &str) -> bool {
        let parts = Self::split_path(path);
        matches!(self.navigate(&parts), Ok(VfsNode::File(_)))
    }

    /// Check if a path is a directory.
    pub fn is_dir(&self, path: &str) -> bool {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return true; // Root is always a directory
        }
        matches!(self.navigate(&parts), Ok(VfsNode::Directory(_)))
    }

    /// List the entries of a directory.
    pub fn read_dir(&self, path: &str) -> io::Result<Vec<String>> {
        let parts = Self::split_path(path);
        let node = if parts.is_empty() {
            &self.root
        } else {
            self.navigate(&parts)?
        };
        match node {
            VfsNode::Directory(entries) => {
                let mut names: Vec<String> = entries.keys().cloned().collect();
                names.sort();
                Ok(names)
            }
            VfsNode::File(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Not a directory",
            )),
        }
    }

    /// Remove a file.
    pub fn remove_file(&mut self, path: &str) -> io::Result<()> {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot remove root",
            ));
        }

        // Check it's actually a file
        if !self.is_file(path) {
            if self.is_dir(path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Is a directory",
                ));
            }
            return Err(io::Error::new(io::ErrorKind::NotFound, "File not found"));
        }

        let filename = parts.last().unwrap().to_string();
        let parent = self.navigate_mut(&parts[..parts.len() - 1])?;

        match parent {
            VfsNode::Directory(entries) => {
                entries.remove(&filename);
                Ok(())
            }
            VfsNode::File(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Parent is not a directory",
            )),
        }
    }

    /// Create a directory. If `recursive` is true, create parent directories as needed.
    pub fn mkdir(&mut self, path: &str, recursive: bool) -> io::Result<()> {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return Ok(()); // Root already exists
        }

        if recursive {
            let mut current = &mut self.root;
            for part in &parts {
                match current {
                    VfsNode::Directory(entries) => {
                        current = entries
                            .entry(part.to_string())
                            .or_insert_with(|| VfsNode::Directory(HashMap::new()));
                    }
                    VfsNode::File(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "A file exists at this path",
                        ));
                    }
                }
            }
            // Verify the final node is a directory
            if matches!(current, VfsNode::File(_)) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "A file exists at this path",
                ));
            }
            Ok(())
        } else {
            let dirname = parts.last().unwrap().to_string();
            let parent = self.navigate_mut(&parts[..parts.len() - 1])?;
            match parent {
                VfsNode::Directory(entries) => {
                    if entries.contains_key(&dirname) {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "Already exists",
                        ));
                    }
                    entries.insert(dirname, VfsNode::Directory(HashMap::new()));
                    Ok(())
                }
                VfsNode::File(_) => Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "Parent is not a directory",
                )),
            }
        }
    }

    /// Remove an empty directory.
    pub fn rmdir(&mut self, path: &str) -> io::Result<()> {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot remove root",
            ));
        }

        // Check it exists and is a directory
        if !self.is_dir(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Directory not found",
            ));
        }

        // Check it's empty
        if let Ok(entries) = self.read_dir(path) {
            if !entries.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Directory not empty",
                ));
            }
        }

        let dirname = parts.last().unwrap().to_string();
        let parent = self.navigate_mut(&parts[..parts.len() - 1])?;

        match parent {
            VfsNode::Directory(entries) => {
                entries.remove(&dirname);
                Ok(())
            }
            VfsNode::File(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Parent is not a directory",
            )),
        }
    }

    /// Rename / move a file or directory.
    pub fn rename(&mut self, from: &str, to: &str) -> io::Result<()> {
        // Read the node
        let from_parts = Self::split_path(from);
        if from_parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot rename root",
            ));
        }

        // Extract the node
        let node = {
            let from_name = from_parts.last().unwrap().to_string();
            let parent = self.navigate_mut(&from_parts[..from_parts.len() - 1])?;
            match parent {
                VfsNode::Directory(entries) => entries.remove(&from_name).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "Source not found")
                })?,
                VfsNode::File(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "Parent is not a directory",
                    ));
                }
            }
        };

        // Insert at the destination
        let to_parts = Self::split_path(to);
        if to_parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot rename to root",
            ));
        }

        let to_name = to_parts.last().unwrap().to_string();
        let to_parent = self.navigate_mut(&to_parts[..to_parts.len() - 1])?;
        match to_parent {
            VfsNode::Directory(entries) => {
                entries.insert(to_name, node);
                Ok(())
            }
            VfsNode::File(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Destination parent is not a directory",
            )),
        }
    }

    /// Get the size of a file in bytes.
    pub fn file_size(&self, path: &str) -> io::Result<u64> {
        let parts = Self::split_path(path);
        let node = self.navigate(&parts)?;
        match node {
            VfsNode::File(contents) => Ok(contents.len() as u64),
            VfsNode::Directory(_) => Ok(0),
        }
    }

    // === Internal helpers ===

    /// Split a path into components, filtering out empty strings and normalizing.
    fn split_path(path: &str) -> Vec<&str> {
        path.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect()
    }

    /// Navigate to a node by path components (immutable).
    fn navigate(&self, parts: &[&str]) -> io::Result<&VfsNode> {
        let mut current = &self.root;
        for part in parts {
            match current {
                VfsNode::Directory(entries) => {
                    current = entries.get(*part).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("'{}' not found", part),
                        )
                    })?;
                }
                VfsNode::File(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "Not a directory",
                    ));
                }
            }
        }
        Ok(current)
    }

    /// Navigate to a node by path components (mutable).
    fn navigate_mut(&mut self, parts: &[&str]) -> io::Result<&mut VfsNode> {
        let mut current = &mut self.root;
        for part in parts {
            match current {
                VfsNode::Directory(entries) => {
                    current = entries.get_mut(*part).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("'{}' not found", part),
                        )
                    })?;
                }
                VfsNode::File(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "Not a directory",
                    ));
                }
            }
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filesystem_is_empty_dir() {
        let vfs = VirtualFileSystem::new();
        assert!(vfs.is_dir("/"));
        assert!(!vfs.is_file("/"));
        assert!(vfs.exists("/"));
        assert_eq!(vfs.read_dir("/").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_write_and_read_file() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/hello.txt", b"Hello, World!").unwrap();
        assert_eq!(vfs.read_file("/hello.txt").unwrap(), b"Hello, World!");
        assert!(vfs.is_file("/hello.txt"));
        assert!(!vfs.is_dir("/hello.txt"));
        assert!(vfs.exists("/hello.txt"));
    }

    #[test]
    fn test_write_creates_parent_dirs() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/a/b/c.txt", b"deep").unwrap();
        assert!(vfs.is_dir("/a"));
        assert!(vfs.is_dir("/a/b"));
        assert!(vfs.is_file("/a/b/c.txt"));
        assert_eq!(vfs.read_file("/a/b/c.txt").unwrap(), b"deep");
    }

    #[test]
    fn test_overwrite_file() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/f.txt", b"old").unwrap();
        vfs.write_file("/f.txt", b"new").unwrap();
        assert_eq!(vfs.read_file("/f.txt").unwrap(), b"new");
    }

    #[test]
    fn test_read_nonexistent() {
        let vfs = VirtualFileSystem::new();
        assert!(vfs.read_file("/nope.txt").is_err());
        assert!(!vfs.exists("/nope.txt"));
        assert!(!vfs.is_file("/nope.txt"));
    }

    #[test]
    fn test_mkdir_and_read_dir() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/dir1", false).unwrap();
        vfs.write_file("/dir1/a.txt", b"a").unwrap();
        vfs.write_file("/dir1/b.txt", b"b").unwrap();

        let entries = vfs.read_dir("/dir1").unwrap();
        assert_eq!(entries, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn test_mkdir_recursive() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/x/y/z", true).unwrap();
        assert!(vfs.is_dir("/x"));
        assert!(vfs.is_dir("/x/y"));
        assert!(vfs.is_dir("/x/y/z"));
    }

    #[test]
    fn test_mkdir_non_recursive_fails_without_parent() {
        let mut vfs = VirtualFileSystem::new();
        assert!(vfs.mkdir("/x/y/z", false).is_err());
    }

    #[test]
    fn test_mkdir_already_exists() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/dir", false).unwrap();
        assert!(vfs.mkdir("/dir", false).is_err());
    }

    #[test]
    fn test_remove_file() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/rm.txt", b"delete me").unwrap();
        assert!(vfs.exists("/rm.txt"));
        vfs.remove_file("/rm.txt").unwrap();
        assert!(!vfs.exists("/rm.txt"));
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut vfs = VirtualFileSystem::new();
        assert!(vfs.remove_file("/nope.txt").is_err());
    }

    #[test]
    fn test_remove_directory_as_file_fails() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/dir", false).unwrap();
        assert!(vfs.remove_file("/dir").is_err());
    }

    #[test]
    fn test_rmdir_empty() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/empty_dir", false).unwrap();
        vfs.rmdir("/empty_dir").unwrap();
        assert!(!vfs.exists("/empty_dir"));
    }

    #[test]
    fn test_rmdir_non_empty_fails() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/dir", false).unwrap();
        vfs.write_file("/dir/f.txt", b"x").unwrap();
        assert!(vfs.rmdir("/dir").is_err());
    }

    #[test]
    fn test_rename_file() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/old.txt", b"content").unwrap();
        vfs.rename("/old.txt", "/new.txt").unwrap();
        assert!(!vfs.exists("/old.txt"));
        assert_eq!(vfs.read_file("/new.txt").unwrap(), b"content");
    }

    #[test]
    fn test_rename_directory() {
        let mut vfs = VirtualFileSystem::new();
        vfs.mkdir("/old_dir", false).unwrap();
        vfs.write_file("/old_dir/f.txt", b"data").unwrap();
        vfs.rename("/old_dir", "/new_dir").unwrap();
        assert!(!vfs.exists("/old_dir"));
        assert!(vfs.is_dir("/new_dir"));
        assert_eq!(vfs.read_file("/new_dir/f.txt").unwrap(), b"data");
    }

    #[test]
    fn test_file_size() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/sized.txt", b"12345").unwrap();
        assert_eq!(vfs.file_size("/sized.txt").unwrap(), 5);
    }

    #[test]
    fn test_read_dir_on_file_fails() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/f.txt", b"x").unwrap();
        assert!(vfs.read_dir("/f.txt").is_err());
    }

    #[test]
    fn test_read_dir_root() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/a.txt", b"a").unwrap();
        vfs.mkdir("/subdir", false).unwrap();
        let entries = vfs.read_dir("/").unwrap();
        assert_eq!(entries, vec!["a.txt", "subdir"]);
    }

    #[test]
    fn test_binary_file_contents() {
        let mut vfs = VirtualFileSystem::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        vfs.write_file("/bin.dat", &binary_data).unwrap();
        assert_eq!(vfs.read_file("/bin.dat").unwrap(), &binary_data[..]);
    }

    #[test]
    fn test_empty_file() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/empty.txt", b"").unwrap();
        assert_eq!(vfs.read_file("/empty.txt").unwrap(), b"");
        assert_eq!(vfs.file_size("/empty.txt").unwrap(), 0);
    }

    #[test]
    fn test_path_normalization() {
        let mut vfs = VirtualFileSystem::new();
        vfs.write_file("/a/./b.txt", b"ok").unwrap();
        assert_eq!(vfs.read_file("/a/b.txt").unwrap(), b"ok");
    }
}
