//! PHP runtime services
//!
//! This crate implements the PHP runtime layer:
//! - Error handling (E_ERROR, E_WARNING, E_NOTICE, etc.)
//! - INI system (php.ini parsing, ini_get/ini_set)
//! - Output buffering (ob_start, ob_end_flush, etc.)
//! - Stream wrappers (file://, php://)
//! - Superglobals ($_SERVER, $_GET, $_POST, etc.)
//! - Autoloading (spl_autoload_register)
//!
//! Equivalent to php-src/main/

pub mod autoload;
pub mod error;
pub mod ini;
pub mod output;
pub mod stream;
pub mod superglobals;

pub use autoload::AutoloadQueue;
pub use error::{ErrorHandler, ErrorLevel};
pub use ini::{IniEntry, IniPermission, IniSystem};
pub use output::OutputBuffer;
pub use stream::{PhpStream, StreamWrapper};
pub use superglobals::Superglobals;
