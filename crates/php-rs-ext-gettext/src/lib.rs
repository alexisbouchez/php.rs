//! PHP gettext extension.
//!
//! Implements i18n message translation functions.
//! Reference: php-src/ext/gettext/
//!
//! Since we do not parse `.mo` files, gettext returns the original message
//! (this is standard PHP behavior when no translation is found).

use std::cell::RefCell;
use std::collections::HashMap;

// ── Thread-local state ──────────────────────────────────────────────────────

thread_local! {
    /// The currently active text domain.
    static CURRENT_DOMAIN: RefCell<String> = RefCell::new("messages".to_string());
    /// Mapping from domain -> directory path.
    static DOMAIN_DIRS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    /// Mapping from domain -> codeset.
    static DOMAIN_CODESETS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

// ── LC_* category constants (matching POSIX) ────────────────────────────────

pub const LC_CTYPE: i32 = 0;
pub const LC_NUMERIC: i32 = 1;
pub const LC_TIME: i32 = 2;
pub const LC_COLLATE: i32 = 3;
pub const LC_MONETARY: i32 = 4;
pub const LC_MESSAGES: i32 = 5;
pub const LC_ALL: i32 = 6;

// ── Public API ──────────────────────────────────────────────────────────────

/// gettext() -- Look up a message in the current text domain.
///
/// Since no `.mo` file parsing is implemented, this returns the original message
/// (the standard PHP fallback when no translation is found).
pub fn gettext(message: &str) -> String {
    message.to_string()
}

/// ngettext() -- Plural form of gettext.
///
/// Returns `singular` if count == 1, otherwise `plural`.
pub fn ngettext(singular: &str, plural: &str, count: i64) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        plural.to_string()
    }
}

/// dgettext() -- Look up a message in a specific domain.
///
/// Override the current domain for this single lookup. Returns the original
/// message as a passthrough.
pub fn dgettext(_domain: &str, message: &str) -> String {
    message.to_string()
}

/// dngettext() -- Plural form of dgettext.
pub fn dngettext(_domain: &str, singular: &str, plural: &str, count: i64) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        plural.to_string()
    }
}

/// dcgettext() -- Look up a message in a specific domain and category.
///
/// The `category` argument (LC_MESSAGES, LC_CTYPE, etc.) is accepted but
/// has no effect in this stub implementation.
pub fn dcgettext(_domain: &str, message: &str, _category: i32) -> String {
    message.to_string()
}

/// textdomain() -- Set and/or get the current text domain.
///
/// If `domain` is non-empty, the current domain is set. Returns the (new) current domain.
pub fn textdomain(domain: &str) -> String {
    if !domain.is_empty() {
        CURRENT_DOMAIN.with(|d| {
            *d.borrow_mut() = domain.to_string();
        });
    }
    CURRENT_DOMAIN.with(|d| d.borrow().clone())
}

/// bindtextdomain() -- Set the path for a domain's message catalogs.
///
/// Returns the directory now associated with the domain.
pub fn bindtextdomain(domain: &str, directory: &str) -> String {
    DOMAIN_DIRS.with(|dirs| {
        dirs.borrow_mut()
            .insert(domain.to_string(), directory.to_string());
    });
    directory.to_string()
}

/// bind_textdomain_codeset() -- Set the codeset for a domain's message catalogs.
///
/// Returns the codeset now associated with the domain.
pub fn bind_textdomain_codeset(domain: &str, codeset: &str) -> String {
    DOMAIN_CODESETS.with(|cs| {
        cs.borrow_mut()
            .insert(domain.to_string(), codeset.to_string());
    });
    codeset.to_string()
}

/// Helper: Get the directory currently bound to a domain, if any.
pub fn get_domain_directory(domain: &str) -> Option<String> {
    DOMAIN_DIRS.with(|dirs| dirs.borrow().get(domain).cloned())
}

/// Helper: Get the codeset currently bound to a domain, if any.
pub fn get_domain_codeset(domain: &str) -> Option<String> {
    DOMAIN_CODESETS.with(|cs| cs.borrow().get(domain).cloned())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gettext_passthrough() {
        assert_eq!(gettext("Hello, world!"), "Hello, world!");
        assert_eq!(gettext(""), "");
    }

    #[test]
    fn test_ngettext_singular() {
        assert_eq!(ngettext("1 file", "%d files", 1), "1 file");
    }

    #[test]
    fn test_ngettext_plural() {
        assert_eq!(ngettext("1 file", "%d files", 0), "%d files");
        assert_eq!(ngettext("1 file", "%d files", 2), "%d files");
        assert_eq!(ngettext("1 file", "%d files", 100), "%d files");
    }

    #[test]
    fn test_ngettext_negative() {
        assert_eq!(ngettext("1 item", "%d items", -1), "%d items");
    }

    #[test]
    fn test_dgettext_passthrough() {
        assert_eq!(dgettext("myapp", "Save"), "Save");
    }

    #[test]
    fn test_dngettext() {
        assert_eq!(dngettext("myapp", "1 error", "%d errors", 1), "1 error");
        assert_eq!(dngettext("myapp", "1 error", "%d errors", 5), "%d errors");
    }

    #[test]
    fn test_dcgettext_passthrough() {
        assert_eq!(dcgettext("myapp", "Cancel", LC_MESSAGES), "Cancel");
    }

    #[test]
    fn test_textdomain_set_and_get() {
        // Set domain
        assert_eq!(textdomain("myapp"), "myapp");
        // Get current domain
        assert_eq!(textdomain(""), "myapp");
        // Change domain
        assert_eq!(textdomain("otherapp"), "otherapp");
        // Reset for other tests
        textdomain("messages");
    }

    #[test]
    fn test_bindtextdomain() {
        let dir = bindtextdomain("myapp", "/usr/share/locale");
        assert_eq!(dir, "/usr/share/locale");
        assert_eq!(
            get_domain_directory("myapp"),
            Some("/usr/share/locale".to_string())
        );
    }

    #[test]
    fn test_bind_textdomain_codeset() {
        let cs = bind_textdomain_codeset("myapp", "UTF-8");
        assert_eq!(cs, "UTF-8");
        assert_eq!(get_domain_codeset("myapp"), Some("UTF-8".to_string()));
    }

    #[test]
    fn test_get_domain_directory_missing() {
        assert_eq!(get_domain_directory("nonexistent_domain_xyz"), None);
    }

    #[test]
    fn test_bindtextdomain_overwrite() {
        bindtextdomain("test_domain", "/first/path");
        assert_eq!(
            get_domain_directory("test_domain"),
            Some("/first/path".to_string())
        );
        bindtextdomain("test_domain", "/second/path");
        assert_eq!(
            get_domain_directory("test_domain"),
            Some("/second/path".to_string())
        );
    }
}
