//! PHP autoloading system.
//!
//! Implements spl_autoload_register(), spl_autoload_unregister(),
//! spl_autoload_functions(), and the autoload queue.
//!
//! Reference: php-src/ext/spl/php_spl.c, php-src/Zend/zend_execute_API.c

/// An autoloader function — receives the fully-qualified class name,
/// returns the file path to include (or None if this loader can't handle it).
pub type AutoloadFn = Box<dyn Fn(&str) -> Option<String>>;

/// Entry in the autoload queue.
struct AutoloadEntry {
    /// Name for identification (e.g., function name or closure ID).
    name: String,
    /// The autoloader callback.
    callback: AutoloadFn,
}

/// The SPL autoload queue.
///
/// When PHP tries to use a class that hasn't been loaded yet, it iterates
/// through registered autoloaders until one succeeds.
pub struct AutoloadQueue {
    /// Registered autoloaders, called in order.
    loaders: Vec<AutoloadEntry>,
    /// Whether the default __autoload() function is registered.
    default_registered: bool,
}

impl AutoloadQueue {
    /// Create a new (empty) autoload queue.
    pub fn new() -> Self {
        Self {
            loaders: Vec::new(),
            default_registered: false,
        }
    }

    /// Register an autoloader (spl_autoload_register).
    ///
    /// - `name`: identifier for the autoloader (function name, closure ID)
    /// - `callback`: the autoloader function
    /// - `prepend`: if true, add to the front of the queue
    ///
    /// Returns false if an autoloader with this name is already registered.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        callback: AutoloadFn,
        prepend: bool,
    ) -> bool {
        let name = name.into();

        // Don't allow duplicate registrations
        if self.loaders.iter().any(|e| e.name == name) {
            return false;
        }

        let entry = AutoloadEntry { name, callback };

        if prepend {
            self.loaders.insert(0, entry);
        } else {
            self.loaders.push(entry);
        }

        true
    }

    /// Unregister an autoloader (spl_autoload_unregister).
    ///
    /// Returns true if the autoloader was found and removed.
    pub fn unregister(&mut self, name: &str) -> bool {
        let len = self.loaders.len();
        self.loaders.retain(|e| e.name != name);
        self.loaders.len() < len
    }

    /// Get the list of registered autoloader names (spl_autoload_functions).
    pub fn functions(&self) -> Vec<&str> {
        self.loaders.iter().map(|e| e.name.as_str()).collect()
    }

    /// Try to autoload a class by running through the queue.
    ///
    /// Returns the file path to include (from the first successful loader),
    /// or None if no loader can handle this class.
    pub fn try_load(&self, class_name: &str) -> Option<String> {
        for entry in &self.loaders {
            if let Some(path) = (entry.callback)(class_name) {
                return Some(path);
            }
        }
        None
    }

    /// Check if any autoloaders are registered.
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Get the number of registered autoloaders.
    pub fn len(&self) -> usize {
        self.loaders.len()
    }

    /// Set whether the default __autoload function is registered.
    pub fn set_default_registered(&mut self, registered: bool) {
        self.default_registered = registered;
    }

    /// Check if the default __autoload function is registered.
    pub fn is_default_registered(&self) -> bool {
        self.default_registered
    }

    /// Reset the autoload queue.
    pub fn reset(&mut self) {
        self.loaders.clear();
        self.default_registered = false;
    }
}

impl Default for AutoloadQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autoload_queue_empty() {
        let queue = AutoloadQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.try_load("SomeClass"), None);
    }

    #[test]
    fn test_register_and_try_load() {
        let mut queue = AutoloadQueue::new();
        queue.register(
            "my_autoloader",
            Box::new(|class_name: &str| {
                Some(format!("classes/{}.php", class_name.replace('\\', "/")))
            }),
            false,
        );

        assert_eq!(queue.len(), 1);
        assert_eq!(
            queue.try_load("App\\Models\\User"),
            Some("classes/App/Models/User.php".to_string())
        );
    }

    #[test]
    fn test_register_prepend() {
        let mut queue = AutoloadQueue::new();
        queue.register("first", Box::new(|_| Some("first.php".to_string())), false);
        queue.register(
            "prepended",
            Box::new(|_| Some("prepended.php".to_string())),
            true,
        );

        let names = queue.functions();
        assert_eq!(names, vec!["prepended", "first"]);

        // Prepended loader runs first
        assert_eq!(
            queue.try_load("Anything"),
            Some("prepended.php".to_string())
        );
    }

    #[test]
    fn test_register_duplicate_rejected() {
        let mut queue = AutoloadQueue::new();
        assert!(queue.register("loader", Box::new(|_| None), false));
        assert!(!queue.register("loader", Box::new(|_| None), false));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_unregister() {
        let mut queue = AutoloadQueue::new();
        queue.register("a", Box::new(|_| None), false);
        queue.register("b", Box::new(|_| None), false);
        assert_eq!(queue.len(), 2);

        assert!(queue.unregister("a"));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.functions(), vec!["b"]);

        assert!(!queue.unregister("nonexistent"));
    }

    #[test]
    fn test_try_load_falls_through() {
        let mut queue = AutoloadQueue::new();
        // First loader only handles App\* classes
        queue.register(
            "app_loader",
            Box::new(|class_name: &str| {
                if class_name.starts_with("App\\") {
                    Some(format!("src/{}.php", class_name))
                } else {
                    None
                }
            }),
            false,
        );
        // Second loader handles everything
        queue.register(
            "fallback",
            Box::new(|class_name: &str| Some(format!("vendor/{}.php", class_name))),
            false,
        );

        // App class handled by first loader
        assert_eq!(
            queue.try_load("App\\Foo"),
            Some("src/App\\Foo.php".to_string())
        );

        // Other class falls through to second loader
        assert_eq!(
            queue.try_load("External\\Bar"),
            Some("vendor/External\\Bar.php".to_string())
        );
    }

    #[test]
    fn test_functions_list() {
        let mut queue = AutoloadQueue::new();
        queue.register("loader_a", Box::new(|_| None), false);
        queue.register("loader_b", Box::new(|_| None), false);
        queue.register("loader_c", Box::new(|_| None), false);

        assert_eq!(queue.functions(), vec!["loader_a", "loader_b", "loader_c"]);
    }

    #[test]
    fn test_reset() {
        let mut queue = AutoloadQueue::new();
        queue.register("loader", Box::new(|_| None), false);
        queue.set_default_registered(true);

        queue.reset();
        assert!(queue.is_empty());
        assert!(!queue.is_default_registered());
    }

    #[test]
    fn test_default_autoload_flag() {
        let mut queue = AutoloadQueue::new();
        assert!(!queue.is_default_registered());
        queue.set_default_registered(true);
        assert!(queue.is_default_registered());
    }
}
