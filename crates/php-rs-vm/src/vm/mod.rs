//! PHP Virtual Machine -- executes compiled opcode arrays.
//!
//! This module implements the core VM loop that dispatches and executes
//! [`ZOp`] instructions from a [`ZOpArray`]. It manages the call stack,
//! function/class tables, output buffering, and all runtime state.
//!
//! Equivalent to `php-src/Zend/zend_execute.c` and `php-src/Zend/zend_vm_def.h`.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use php_rs_compiler::op::{OperandType, ZOp};
use php_rs_compiler::op_array::{Literal, ZOpArray};
use php_rs_compiler::opcode::ZOpcode;
use php_rs_ext_json::{self, JsonValue};

use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

mod call;
mod database;
mod defaults;
mod generators;
mod helpers;
mod oop;
mod output;
mod reflection;
mod spl;
#[cfg(test)]
mod tests;
mod vfs;

pub(crate) use helpers::*;

/// Get current time in milliseconds for execution timeout tracking.
#[cfg(not(target_arch = "wasm32"))]
fn now_millis() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// WASM stub: timeout is disabled.
#[cfg(target_arch = "wasm32")]
fn now_millis() -> u64 {
    0
}

/// Global flag set by signal handlers (SIGINT/SIGTERM) for graceful shutdown.
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// A recorded VM event (SQL query, file include, error/warning/notice).
/// Used by the dashboard to show what happened inside each request.
#[derive(Clone)]
pub struct VmEvent {
    pub kind: &'static str,
    pub detail: String,
    pub elapsed_us: u128,
}

/// VM execution error -- all possible runtime error conditions.
///
/// These errors correspond to PHP's fatal errors, exceptions, and resource
/// limit violations. The VM returns `Err(VmError)` when execution cannot
/// continue normally.
#[derive(Debug)]
pub enum VmError {
    /// A PHP fatal error occurred (E_ERROR).
    FatalError(String),
    /// Division or modulo by zero.
    DivisionByZero,
    /// Access to an undefined variable.
    UndefinedVariable(String),
    /// Call to an undefined function.
    UndefinedFunction(String),
    /// A `match` expression had no matching arm and no default.
    MatchError,
    /// A type error (e.g., wrong argument type for a typed parameter).
    TypeError(String),
    /// A thrown exception that was not caught. Contains the exception [`Value`].
    Thrown(Value),
    /// Reference to an undefined class.
    UndefinedClass(String),
    /// Call to an undefined method (class_name, method_name).
    UndefinedMethod(String, String),
    /// Access to an undefined property (class_name, property_name).
    UndefinedProperty(String, String),
    /// Access to an undefined class constant (class_name, constant_name).
    UndefinedClassConstant(String, String),
    /// Internal VM error (invalid opcode, bad operand, etc.).
    InternalError(String),
    /// `exit()` or `die()` -- clean script termination with an exit code.
    Exit(i32),
    /// Memory limit exceeded (`memory_limit` INI setting).
    MemoryLimitExceeded(String),
    /// Execution time limit exceeded (`max_execution_time` INI setting).
    TimeLimitExceeded(String),
    /// Function has been disabled via `disable_functions` INI setting.
    DisabledFunction(String),
}

/// Result type alias for VM operations.
pub type VmResult<T> = Result<T, VmError>;

/// A pending function/method call on the call stack.
struct PendingCall {
    /// Function or method name (e.g., "strlen" or "Counter::increment").
    name: String,
    /// Arguments collected so far via SEND_VAL/SEND_VAR.
    args: Vec<Value>,
    /// Named argument names (parallel to args; empty string = positional).
    arg_names: Vec<String>,
    /// For method calls: the source location of $this in the caller so we can write
    /// the modified object back after the method returns (PHP objects have reference semantics).
    this_source: Option<(OperandType, u32)>,
    /// Late static binding class name for static:: resolution.
    pub(crate) static_class: Option<String>,
    /// Forwarded $this from InitStaticMethodCall (self::/parent::/static:: in non-static context).
    /// Stored separately from args so static methods don't receive it as a parameter.
    forwarded_this: Option<Value>,
    /// By-reference argument sources: (arg_index, operand_type, operand_val)
    /// Used by builtins like preg_match to write back to the caller's variable.
    ref_args: Vec<(usize, OperandType, u32)>,
    /// Property-level ref args: (arg_index, object_value, property_name)
    /// For `foo($obj->prop)` with &$param — write back to object property on return.
    ref_prop_args: Vec<(usize, Value, String)>,
}

/// An execution frame — one per function call / script execution.
///
/// Mirrors `_zend_execute_data` from php-src.
pub(crate) struct Frame {
    /// Reference to the op_array being executed (index into VM's op_array storage).
    pub(crate) op_array_idx: usize,
    /// Instruction pointer (index into op_array.opcodes).
    pub(crate) ip: usize,
    /// Compiled variables (CVs): named local variables.
    pub(crate) cvs: Vec<Value>,
    /// Temporary variable slots.
    pub(crate) temps: Vec<Value>,
    /// Return value from this frame (set by RETURN).
    pub(crate) return_value: Value,
    /// Stack of pending calls (supports nested calls like add(mul(2,3), mul(4,5))).
    pub(crate) call_stack_pending: Vec<PendingCall>,
    /// Arguments passed to this frame (for RECV opcodes).
    pub(crate) args: Vec<Value>,
    /// For named arg reordering: tracks which arg positions were actually provided.
    /// None = all positions up to args.len() are provided (normal positional call).
    /// Some(vec) = vec[i] is true if args[i] was explicitly passed.
    pub(crate) named_arg_provided: Option<Vec<bool>>,
    /// Where to store the return value in the caller's frame when this frame returns.
    /// (result_type, result_slot)
    pub(crate) return_dest: Option<(OperandType, u32)>,
    /// For method calls (including constructors): the slot in the caller where $this
    /// should be written back after this frame returns, to support PHP object reference semantics.
    pub(crate) this_write_back: Option<(OperandType, u32)>,
    /// Whether this is a constructor call (don't overwrite result with Null return value).
    pub(crate) is_constructor: bool,
    /// Late static binding: the class name used in the call (e.g., "Carbon\Carbon" when
    /// calling Carbon::now()). Used to resolve `static::` in static methods and trait methods.
    pub(crate) static_class: Option<String>,
    /// Write-back info for FETCH_STATIC_PROP_W: temp_idx → (class_name, prop_name)
    /// When AssignDim modifies a temp that was fetched in W mode from a static property,
    /// the modified value must be written back to the class's static property storage.
    pub(crate) static_prop_write_back: Vec<(usize, String, String)>,
    /// Pass-by-reference write-back: (callee_param_cv_idx, caller_operand_type, caller_slot)
    /// On return, callee's CV[callee_param_cv_idx] is written back to the caller's slot.
    pub(crate) ref_write_back: Vec<(usize, OperandType, u32)>,
    /// Property-level ref write-back: (callee_param_cv_idx, object, property_name)
    /// On return, callee's CV[callee_param_cv_idx] is written back to the object property.
    pub(crate) ref_prop_write_back: Vec<(usize, PhpObject, String)>,
    /// Tracks temp slots that came from FetchObjR: temp_idx → (object, property_name).
    /// Used to set up ref_prop_write_back when a temp from a property fetch is passed by ref.
    pub(crate) temp_prop_source: HashMap<usize, (Value, String)>,
    /// Tracks temp slots that came from FetchDimR on a Reference:
    /// temp_idx → (reference_rc, key). Used by AssignRef to create shared sub-references.
    pub(crate) temp_dim_ref_source: HashMap<usize, (Rc<RefCell<Value>>, Value)>,
    /// The name under which this function was invoked (e.g., "Carbon\\Carbon::__construct").
    /// Used by trait methods to determine the using class for parent:: resolution.
    pub(crate) called_as: Option<String>,
    /// CV indices that are bound to static variables (need write-back on return).
    pub(crate) static_cv_indices: Vec<usize>,
    /// Foreach-by-reference tracking: iter_temp_slot → (source_op_type, source_op_val, value_cv_idx, last_key)
    /// Used by FeFetchRw to write modified values back to the source array.
    pub(crate) foreach_rw_state: HashMap<usize, (OperandType, u32, usize, Option<Value>)>,
    /// Whether parent::__construct() has been called in this constructor frame.
    /// Used for parent constructor call tracking (PHP 8.2+).
    pub(crate) parent_ctor_called: bool,
    /// Whether this frame was created by include/require (not a function call).
    pub(crate) is_include_frame: bool,
    /// Scope inheritance map for include/require/eval frames.
    /// Each entry is (child_cv_idx, call_stack_abs_idx, ancestor_cv_idx):
    /// on return, child CVs are written back to the ancestor frame at the
    /// given absolute call stack position so that variable changes propagate
    /// through nested include chains.
    pub(crate) include_scope_map: Vec<(usize, usize, usize)>,
}

impl Frame {
    /// Create a new frame with pre-allocated operand storage.
    /// CVs and temps are pre-allocated to the exact sizes needed by the op_array,
    /// avoiding dynamic allocation during execution.
    #[inline]
    pub(crate) fn new(op_array: &ZOpArray) -> Self {
        let num_cvs = op_array.vars.len();
        let num_temps = op_array.num_temps as usize;
        Self {
            op_array_idx: 0,
            ip: 0,
            // Pre-allocate CVs (compiled variables) to exact size
            cvs: vec![Value::Null; num_cvs],
            // Pre-allocate temps to exact size needed
            temps: vec![Value::Null; num_temps],
            return_value: Value::Null,
            // Pre-allocate with small capacity hints to reduce reallocation
            call_stack_pending: Vec::with_capacity(4),
            args: Vec::new(),
            named_arg_provided: None,
            return_dest: None,
            this_write_back: None,
            is_constructor: false,
            static_class: None,
            static_prop_write_back: Vec::new(),
            ref_write_back: Vec::new(),
            ref_prop_write_back: Vec::new(),
            temp_prop_source: HashMap::new(),
            temp_dim_ref_source: HashMap::new(),
            called_as: None,
            static_cv_indices: Vec::new(),
            foreach_rw_state: HashMap::new(),
            parent_ctor_called: false,
            is_include_frame: false,
            include_scope_map: Vec::new(),
        }
    }
}

// Modifier flag constants (same encoding as compiler).
pub(crate) const ACC_PUBLIC: u32 = 0x01;
pub(crate) const ACC_PROTECTED: u32 = 0x02;
pub(crate) const ACC_PRIVATE: u32 = 0x04;
pub(crate) const ACC_STATIC: u32 = 0x08;
pub(crate) const ACC_FINAL: u32 = 0x10;
pub(crate) const ACC_ABSTRACT: u32 = 0x20;
pub(crate) const ACC_READONLY: u32 = 0x200;
// Asymmetric visibility set-side flags (PHP 8.4).
pub(crate) const ACC_PUBLIC_SET: u32 = 0x1000;
pub(crate) const ACC_PROTECTED_SET: u32 = 0x2000;
pub(crate) const ACC_PRIVATE_SET: u32 = 0x4000;

/// A class definition stored in the VM's class table.
#[derive(Debug, Clone)]
pub(crate) struct ClassDef {
    /// Class name.
    pub(crate) _name: String,
    /// Parent class name (if any).
    pub(crate) parent: Option<String>,
    /// Implemented interfaces.
    pub(crate) interfaces: Vec<String>,
    /// Traits used by this class.
    pub(crate) traits: Vec<String>,
    /// Whether this is an abstract class.
    pub(crate) is_abstract: bool,
    /// Whether this is a final class.
    pub(crate) is_final: bool,
    /// Whether this is an interface.
    pub(crate) is_interface: bool,
    /// Whether this is an enum.
    pub(crate) is_enum: bool,
    /// Whether this is a readonly class (PHP 8.2+).
    pub(crate) is_readonly: bool,
    /// Method table: method_name → op_array index.
    pub(crate) methods: HashMap<String, usize>,
    /// Per-method modifier flags: method_name → flags (ACC_PUBLIC|ACC_FINAL|...).
    pub(crate) method_flags: HashMap<String, u32>,
    /// Per-property modifier flags: prop_name → flags (ACC_PUBLIC|ACC_PRIVATE|ACC_READONLY|...).
    pub(crate) property_flags: HashMap<String, u32>,
    /// Default property values: prop_name → default value.
    pub(crate) default_properties: HashMap<String, Value>,
    /// Class constants: const_name → value.
    pub(crate) class_constants: HashMap<String, Value>,
    /// Class constant modifier flags: const_name → flags (ACC_PUBLIC, ACC_FINAL, etc.).
    pub(crate) class_constant_flags: HashMap<String, u32>,
    /// Static properties: prop_name → value.
    pub(crate) static_properties: HashMap<String, Value>,
    /// Property type hints: prop_name → type_name (e.g. "string", "?int", "int|string").
    pub(crate) property_types: HashMap<String, String>,
    /// Class attributes: Vec<(attr_name, Vec<(param_name, param_value)>)>.
    pub(crate) attributes: Vec<(String, Vec<(Option<String>, String)>)>,
    /// Property get hooks: prop_name → op_array index.
    pub(crate) property_get_hooks: HashMap<String, usize>,
    /// Property set hooks: prop_name → op_array index.
    pub(crate) property_set_hooks: HashMap<String, usize>,
}

/// Session cookie parameters for session_set/get_cookie_params().
#[derive(Debug, Clone)]
pub struct SessionCookieParams {
    pub lifetime: i64,
    pub path: String,
    pub domain: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: String,
}

impl Default for SessionCookieParams {
    fn default() -> Self {
        Self {
            lifetime: 0,
            path: "/".to_string(),
            domain: String::new(),
            secure: false,
            httponly: false,
            samesite: String::new(),
        }
    }
}

/// Custom session save handler callbacks.
/// Used by session_set_save_handler() when passing individual callables.
#[derive(Debug, Clone, Default)]
pub struct SessionSaveHandler {
    /// Callback for opening a session (save_path, session_name) → bool
    pub open: String,
    /// Callback for closing the session () → bool
    pub close: String,
    /// Callback for reading session data (session_id) → string
    pub read: String,
    /// Callback for writing session data (session_id, data) → bool
    pub write: String,
    /// Callback for destroying a session (session_id) → bool
    pub destroy: String,
    /// Callback for garbage collection (max_lifetime) → int|false
    pub gc: String,
    /// Optional callback for creating new session ID () → string
    pub create_sid: Option<String>,
    /// Optional callback for validating session ID (session_id) → bool
    pub validate_sid: Option<String>,
    /// Optional callback for updating timestamp (session_id, data) → bool
    pub update_timestamp: Option<String>,
}

/// A stream context holding wrapper/options/params.
#[derive(Debug, Clone, Default)]
pub struct StreamContext {
    pub options: HashMap<String, HashMap<String, Value>>,
    pub params: HashMap<String, Value>,
}

/// Configuration for VM execution limits and security settings, parsed from PHP INI.
///
/// These settings control runtime behavior such as memory limits, execution timeouts,
/// function restrictions, and filesystem access restrictions. The defaults match
/// PHP's standard `php.ini` defaults.
///
/// # Default values
///
/// - `memory_limit`: 128 MB
/// - `max_execution_time`: 30 seconds
/// - `disabled_functions`: none
/// - `open_basedir`: none (unrestricted)
/// - `zend_assertions`: 1 (enabled)
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Memory limit in bytes (0 = unlimited). From `memory_limit` INI.
    pub memory_limit: usize,
    /// Maximum execution time in seconds (0 = unlimited). From `max_execution_time` INI.
    pub max_execution_time: u64,
    /// Set of disabled function names (lowercased). From `disable_functions` INI.
    pub disabled_functions: HashSet<String>,
    /// Open basedir restriction paths (empty = no restriction). From `open_basedir` INI.
    pub open_basedir: Vec<String>,
    /// Assertion mode. From `zend.assertions` INI.
    /// 1 = compile and execute, 0 = compile but skip, -1 = don't compile.
    pub zend_assertions: i64,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            memory_limit: 128 * 1024 * 1024, // 128M
            max_execution_time: 30,
            disabled_functions: HashSet::new(),
            open_basedir: Vec::new(),
            zend_assertions: 1, // enabled by default
        }
    }
}

impl VmConfig {
    /// Parse a `disable_functions` INI string into the config.
    pub fn set_disabled_functions(&mut self, val: &str) {
        self.disabled_functions = if val.is_empty() {
            HashSet::new()
        } else {
            val.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
    }

    /// Parse an `open_basedir` INI string into the config.
    pub fn set_open_basedir(&mut self, val: &str) {
        self.open_basedir = if val.is_empty() {
            Vec::new()
        } else {
            val.split(if cfg!(windows) { ';' } else { ':' })
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
    }
}

/// The PHP Virtual Machine -- executes compiled opcode arrays.
///
/// `Vm` holds all runtime state needed to execute PHP code:
/// - **Output**: committed output buffer and output-buffering stack (`ob_start`/`ob_end_*`)
/// - **Functions**: function table mapping names to compiled [`ZOpArray`] indices
/// - **Classes**: class table with definitions, inheritance, and trait resolution
/// - **Constants**: predefined and user-defined PHP constants
/// - **Call stack**: execution frames for nested function/method calls
/// - **Resources**: open file handles, database connections, cURL handles, etc.
/// - **Session**: session state and save path
/// - **Configuration**: execution limits and security settings ([`VmConfig`])
///
/// # Lifecycle
///
/// 1. Create a `Vm` with [`Vm::new`] or [`Vm::with_config`]
/// 2. Execute PHP code with [`Vm::execute`] (from a [`ZOpArray`]) or
///    [`Vm::execute_file`] (from a file path with opcode caching)
/// 3. The returned `String` contains the PHP script's output
///
/// The VM performs request-start cleanup at the beginning of each [`execute`](Vm::execute)
/// call, clearing per-request state (variables, open handles, etc.).
///
/// [`ZOpArray`]: php_rs_compiler::ZOpArray

/// An incremental deflate (compression) context for deflate_init/deflate_add.
pub struct DeflateContext {
    /// Accumulated compressed output.
    pub buffer: Vec<u8>,
    /// Encoding mode: ZLIB_ENCODING_RAW(-15), ZLIB_ENCODING_GZIP(31), ZLIB_ENCODING_DEFLATE(15).
    pub encoding: i32,
    /// Compression level.
    pub level: i32,
}

/// An incremental inflate (decompression) context for inflate_init/inflate_add.
pub struct InflateContext {
    /// Accumulated decompressed output.
    pub buffer: Vec<u8>,
    /// Encoding mode.
    pub encoding: i32,
    /// Total bytes read from input.
    pub bytes_read: usize,
}

/// A bzip2 file handle for streaming bz* functions.
pub struct BzFileHandle {
    /// Decompressed data (for reading) or buffered data (for writing).
    pub data: Vec<u8>,
    /// Current read/write position.
    pub pos: usize,
    /// Whether the file was opened for writing ("w"/"wb").
    pub writable: bool,
    /// File path (for flushing on close when writing).
    pub path: String,
}

/// A gzip file handle for streaming gz* functions.
pub struct GzFileHandle {
    /// Decompressed data (for reading) or buffered data (for writing).
    pub data: Vec<u8>,
    /// Current read/write position.
    pub pos: usize,
    /// Whether the file was opened for writing ("w"/"wb").
    pub writable: bool,
    /// File path (for flushing on close when writing).
    pub path: String,
    /// Compression level for writing.
    pub level: i32,
}

pub struct Vm {
    /// Committed (non-buffered) output — what goes to the client.
    pub(crate) output: String,
    /// Output-buffering stack: each ob_start() pushes an entry; ob_end_* pops.
    pub(crate) ob_stack: Vec<String>,
    /// Raw request body for php://input reads. Set by the SAPI before execute().
    pub(crate) raw_input_body: Option<String>,
    /// Current session ID (empty means no session started).
    pub(crate) session_id: String,
    /// Whether a session is currently active.
    pub(crate) session_started: bool,
    /// Where session files are stored.
    pub(crate) session_save_path: String,
    /// Function table: name → op_array index.
    pub(crate) functions: HashMap<String, usize>,
    /// All op_arrays (main script + declared functions).
    pub(crate) op_arrays: Vec<ZOpArray>,
    /// Call stack.
    pub(crate) call_stack: Vec<Frame>,
    /// Global constants.
    pub(crate) constants: HashMap<String, Value>,
    /// Constant attributes: const_name → Vec<(attr_name, args)>.
    pub(crate) constant_attributes: HashMap<String, Vec<(String, Vec<(Option<String>, String)>)>>,
    /// Class table: class_name → ClassDef.
    pub(crate) classes: HashMap<String, ClassDef>,
    /// Next object ID.
    pub(crate) next_object_id: u64,
    /// Current exception being handled (for catch/handle_exception).
    pub(crate) current_exception: Option<Value>,
    /// Set of already-included files (for include_once/require_once).
    pub(crate) included_files: HashSet<String>,
    /// Last return value from a frame (used for synchronous method calls).
    pub(crate) last_return_value: Value,
    /// Shutdown functions registered via register_shutdown_function().
    pub(crate) shutdown_functions: Vec<String>,
    /// Generator states: object_id → GeneratorState.
    pub(crate) generators: HashMap<u64, crate::value::GeneratorState>,
    /// Fiber states: object_id → FiberState.
    pub(crate) fibers: HashMap<u64, crate::value::FiberState>,
    /// ReflectionClass states: object_id → reflected class name.
    pub(crate) reflection_classes: HashMap<u64, String>,
    /// Currently executing fiber object_id (if any).
    pub(crate) current_fiber_id: Option<u64>,
    /// Next closure ID for unique naming.
    pub(crate) next_closure_id: u64,
    /// Captured variable bindings for closures: closure_name → [(var_name, value)].
    pub(crate) closure_bindings: HashMap<String, Vec<(String, Value)>>,
    /// Declaring class scope for closures: closure_name → class_name.
    /// Used so `static::` inside closures resolves to the declaring class.
    pub(crate) closure_scopes: HashMap<String, String>,
    /// Optional virtual filesystem (used in WASM or testing; None = use real fs).
    pub(crate) vfs: Option<std::sync::Arc<std::sync::RwLock<php_rs_runtime::VirtualFileSystem>>>,
    /// Open file handles: resource_id → FileHandle.
    pub(crate) file_handles: HashMap<i64, php_rs_ext_standard::file::FileHandle>,
    /// Open gzip file handles: resource_id → GzFileHandle.
    pub(crate) gz_handles: HashMap<i64, GzFileHandle>,
    /// DOM documents: doc_id → DomDocument.
    pub(crate) dom_documents: HashMap<i64, php_rs_ext_dom::DomDocument>,
    /// Next DOM document ID.
    pub(crate) next_dom_id: i64,
    /// Open bzip2 file handles: resource_id → BzFileHandle.
    pub(crate) bz_handles: HashMap<i64, BzFileHandle>,
    /// Deflate (compression) contexts: resource_id → DeflateContext.
    pub(crate) deflate_contexts: HashMap<i64, DeflateContext>,
    /// Inflate (decompression) contexts: resource_id → InflateContext.
    pub(crate) inflate_contexts: HashMap<i64, InflateContext>,
    /// Open curl handles: resource_id → CurlHandle.
    #[cfg(feature = "native-io")]
    pub(crate) curl_handles: HashMap<i64, php_rs_ext_curl::CurlHandle>,
    /// Open curl multi handles: resource_id → CurlMulti.
    #[cfg(feature = "native-io")]
    pub(crate) curl_multi_handles: HashMap<i64, php_rs_ext_curl::CurlMulti>,
    /// Open curl share handles: resource_id → CurlShare.
    #[cfg(feature = "native-io")]
    pub(crate) curl_share_handles: HashMap<i64, php_rs_ext_curl::CurlShare>,
    /// Open child processes from proc_open: resource_id → Child.
    pub(crate) proc_handles: HashMap<i64, std::process::Child>,
    /// Next resource ID for file/curl handles.
    pub(crate) next_resource_id: i64,
    /// Execution limits and security config.
    pub(crate) config: VmConfig,
    /// Execution start time in milliseconds (for max_execution_time enforcement).
    pub(crate) execution_start_millis: Option<u64>,
    /// Opcode counter for periodic limit checks (avoids checking clock on every op).
    pub(crate) opcode_counter: u64,
    /// Registered SPL autoload callbacks (function name, optional $this object).
    pub(crate) autoload_callbacks: Vec<(String, Option<Value>)>,
    /// Guard to prevent recursive autoloading of the same class.
    pub(crate) autoloading_classes: HashSet<String>,
    /// Cache of classes whose interface chains have been fully loaded.
    pub(crate) interface_chain_loaded: HashSet<String>,
    /// HTTP response headers set by header() calls.
    pub(crate) response_headers: Vec<String>,
    /// HTTP response code set by http_response_code().
    pub(crate) response_code: Option<u16>,
    /// Whether HTTP headers have been sent (body output started without buffering).
    pub(crate) headers_sent: bool,
    /// File and line where headers were sent.
    pub(crate) headers_sent_file: String,
    pub(crate) headers_sent_line: u32,
    /// Whether to ignore user abort (connection close).
    pub(crate) ignore_user_abort: bool,
    /// strtok state: (string, position)
    pub(crate) strtok_state: Option<(String, usize)>,
    /// APCu in-memory cache
    pub(crate) apcu_cache: HashMap<String, Value>,
    /// Streaming hash contexts: resource_id → (algorithm, accumulated_data)
    pub(crate) hash_contexts: HashMap<i64, (String, Vec<u8>)>,
    /// MySQLi connections: connection_id → mysql::Conn.
    #[cfg(feature = "native-io")]
    pub(crate) mysqli_connections: HashMap<i64, mysql::Conn>,
    /// MySQLi query results: result_id → (rows, current_position, field_names).
    #[cfg(feature = "native-io")]
    pub(crate) mysqli_results: HashMap<i64, (Vec<mysql::Row>, usize, Vec<String>)>,
    /// MySQLi connection metadata: connection_id → (last_insert_id, affected_rows, error, errno).
    #[cfg(feature = "native-io")]
    pub(crate) mysqli_conn_meta: HashMap<i64, (u64, u64, String, u16)>,
    /// MySQLi prepared statements: stmt_id → MysqliStmt.
    #[cfg(feature = "native-io")]
    pub(crate) mysqli_stmts: HashMap<i64, crate::builtins::mysqli::MysqliStmt>,
    /// PDO connections: object_id → PdoConnection.
    #[cfg(feature = "native-io")]
    pub(crate) pdo_connections: HashMap<u64, php_rs_ext_pdo::PdoConnection>,
    /// PDO prepared statements: object_id → PdoStatement.
    #[cfg(feature = "native-io")]
    pub(crate) pdo_statements: HashMap<u64, php_rs_ext_pdo::PdoStatement>,
    /// SQLite3 connections: object_id → SQLite3 connection.
    #[cfg(feature = "native-io")]
    pub(crate) sqlite3_connections: HashMap<u64, crate::sqlite3::Sqlite3Connection>,
    /// SQLite3 prepared statements: object_id → statement data.
    #[cfg(feature = "native-io")]
    pub(crate) sqlite3_stmts: HashMap<u64, crate::sqlite3::Sqlite3PreparedStmt>,
    /// SQLite3 result sets: object_id → result data.
    #[cfg(feature = "native-io")]
    pub(crate) sqlite3_results: HashMap<u64, crate::sqlite3::Sqlite3ResultSet>,
    /// OpenSSL key resources: resource_id → OpensslKey.
    #[cfg(feature = "native-io")]
    pub(crate) openssl_keys: HashMap<i64, php_rs_ext_openssl::OpensslKey>,
    /// Mersenne Twister RNG state for mt_rand/srand.
    pub(crate) mt_rng: php_rs_ext_random::Mt19937,
    /// GD image resources: resource_id → GdImage.
    pub(crate) gd_images: HashMap<i64, php_rs_ext_gd::GdImage>,
    /// XMLWriter instances: resource_id → XmlWriterState.
    pub(crate) xml_writers: HashMap<i64, crate::builtins::remaining::XmlWriterState>,
    /// Intl NumberFormatter resources: resource_id → NumberFormatter.
    pub(crate) intl_number_formatters: HashMap<i64, php_rs_ext_intl::NumberFormatter>,
    /// Intl Collator resources: resource_id → Collator.
    pub(crate) intl_collators: HashMap<i64, php_rs_ext_intl::Collator>,
    /// Intl DateFormatter resources: resource_id → DateFormatter.
    pub(crate) intl_date_formatters: HashMap<i64, php_rs_ext_intl::DateFormatter>,
    /// Phar archives: resource_id → PharArchive.
    pub(crate) phar_archives: HashMap<i64, php_rs_ext_phar::PharArchive>,
    /// SimpleXML elements: resource_id → SimpleXmlElement.
    pub(crate) simplexml_elements: HashMap<i64, php_rs_ext_xml::SimpleXmlElement>,
    /// XMLReader instances: resource_id → XmlReader.
    pub(crate) xml_readers: HashMap<i64, php_rs_ext_xml::XmlReader>,
    /// Socket resources: resource_id → PhpSocket.
    pub(crate) sockets: HashMap<i64, php_rs_ext_sockets::PhpSocket>,
    /// SOAP client instances: resource_id → SoapClient.
    pub(crate) soap_clients: HashMap<i64, php_rs_ext_soap::SoapClient>,
    /// SOAP server instances: resource_id → SoapServer.
    pub(crate) soap_servers: HashMap<i64, php_rs_ext_soap::SoapServer>,
    /// LDAP connections: resource_id → LdapConnection.
    pub(crate) ldap_connections: HashMap<i64, php_rs_ext_ldap::LdapConnection>,
    /// LDAP search results: resource_id → LdapSearchResult.
    pub(crate) ldap_search_results: HashMap<i64, php_rs_ext_ldap::LdapSearchResult>,
    /// FTP connections: resource_id → FtpConnection.
    pub(crate) ftp_connections: HashMap<i64, php_rs_ext_ftp::FtpConnection>,
    /// ODBC connections: resource_id → OdbcConnection.
    pub(crate) odbc_connections: HashMap<i64, php_rs_ext_odbc::OdbcConnection>,
    /// ODBC results: resource_id → OdbcResult.
    pub(crate) odbc_results: HashMap<i64, php_rs_ext_odbc::OdbcResult>,
    /// ODBC statements: resource_id → OdbcStmt.
    pub(crate) odbc_stmts: HashMap<i64, php_rs_ext_odbc::OdbcStmt>,
    /// SNMP sessions: resource_id → SnmpSession.
    pub(crate) snmp_sessions: HashMap<i64, php_rs_ext_snmp::SnmpSession>,
    /// DBA handles: resource_id → DbaHandle.
    pub(crate) dba_handles: HashMap<i64, php_rs_ext_dba::DbaHandle>,
    /// Enchant brokers: resource_id → EnchantBroker.
    pub(crate) enchant_brokers: HashMap<i64, php_rs_ext_enchant::EnchantBroker>,
    /// System V semaphores: resource_id → SysvSemaphore.
    pub(crate) sysv_semaphores: HashMap<i64, php_rs_ext_sysvsem::SysvSemaphore>,
    /// System V shared memory: resource_id → SysvShm.
    pub(crate) sysv_shm: HashMap<i64, php_rs_ext_sysvshm::SysvShm>,
    /// System V message queues: resource_id → SysvMessageQueue.
    pub(crate) sysv_msg_queues: HashMap<i64, php_rs_ext_sysvmsg::SysvMessageQueue>,
    /// Shared memory blocks: resource_id → ShmopBlock.
    pub(crate) shmop_blocks: HashMap<i64, php_rs_ext_shmop::ShmopBlock>,
    /// Static local variables: (op_array_idx, cv_idx) → persisted Value.
    pub(crate) static_vars: HashMap<(usize, usize), Value>,
    /// Current error_reporting level (default E_ALL = 32767).
    pub(crate) error_reporting_level: i64,
    /// Stack of saved error_reporting levels for @ operator (BeginSilence/EndSilence).
    pub(crate) silence_stack: Vec<i64>,
    /// User error handler callback name (from set_error_handler).
    pub(crate) error_handler: Option<String>,
    /// Stack of previous error handlers (for restore_error_handler).
    pub(crate) error_handler_stack: Vec<Option<String>>,
    /// Last error info: (type, message, file, line).
    pub(crate) last_error: Option<(i64, String, String, u32)>,
    /// User exception handler callback name (from set_exception_handler).
    pub(crate) exception_handler: Option<String>,
    /// Stack of previous exception handlers (for restore_exception_handler).
    pub(crate) exception_handler_stack: Vec<Option<String>>,
    /// Registered tick functions (from register_tick_function).
    pub(crate) tick_functions: Vec<String>,
    /// Tick counter for declare(ticks=N) — counts statements executed.
    pub(crate) tick_counter: u32,
    /// Output buffer callback handlers: one per ob_stack level. None = default (no callback).
    pub(crate) ob_callbacks: Vec<Option<String>>,
    /// Whether ob_implicit_flush is enabled (auto-flush after each output operation).
    pub(crate) ob_implicit_flush: bool,
    /// Session cookie parameters: lifetime, path, domain, secure, httponly, samesite.
    pub(crate) session_cookie_params: SessionCookieParams,
    /// Session cache limiter type ("nocache", "public", "private", "private_no_expire").
    pub(crate) session_cache_limiter: String,
    /// Session cache expire time in minutes.
    pub(crate) session_cache_expire: i64,
    /// Custom session save handler callbacks: (open, close, read, write, destroy, gc).
    /// Each is an optional function name string. When set, these override the default file-based handler.
    pub(crate) session_save_handler: Option<SessionSaveHandler>,
    /// Stream contexts: resource_id → StreamContext (wrapper, options).
    pub(crate) stream_contexts: HashMap<i64, StreamContext>,
    /// User-registered stream wrapper protocols (from stream_wrapper_register).
    pub(crate) registered_stream_wrappers: HashSet<String>,
    /// User-registered stream filter names (from stream_filter_register).
    pub(crate) registered_stream_filters: HashSet<String>,
    /// Error log file path (from error_log INI directive). None = stderr/output.
    pub(crate) error_log_path: Option<String>,
    /// Built-in function registry (name → handler).
    pub(crate) builtins: crate::builtins::BuiltinRegistry,
    /// INI system for ini_get/ini_set/ini_get_all.
    pub(crate) ini: php_rs_runtime::ini::IniSystem,
    /// Opcode handler table for function-pointer-based dispatch.
    pub(crate) opcode_handlers: OpcodeHandlerTable,
    /// Request-scoped arena allocator. Allocations are freed in bulk at request end.
    pub(crate) arena: php_rs_gc::Arena,
    /// String interning pool for copy-on-write string semantics.
    /// Deduplicates function names, class names, variable names within a request.
    pub(crate) string_pool: php_rs_gc::StringPool,
    /// Opcode cache: file_path → (mtime_secs, compiled op_array).
    /// Avoids recompilation when the same file is executed multiple times.
    pub(crate) opcode_cache: HashMap<String, (u64, ZOpArray)>,
    /// Superglobal values ($_GET, $_POST, $_COOKIE, $_SERVER, etc.).
    /// Stored on the VM so they can be populated into every new function frame.
    /// PHP superglobals are accessible inside functions without `global` declaration.
    pub(crate) superglobals: HashMap<String, Value>,
    /// Recorded VM events for dashboard introspection.
    pub(crate) events: Vec<VmEvent>,
    /// Request start time for event elapsed_us calculation.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) request_start: Instant,
}

/// Signal from an opcode handler to the dispatch loop.
enum DispatchSignal {
    /// Continue to next opcode.
    Next,
    /// Jump to a specific opline.
    Jump(usize),
    /// Return from the current frame.
    Return,
    /// A new frame was pushed; don't advance IP (callee starts at ip=0).
    CallPushed,
    /// Generator yielded or returned — break inner dispatch loop.
    Yield,
}

/// Opcode handler function pointer type.
///
/// This type alias enables an opcode handler table (function pointer array)
/// as an alternative to the match-based dispatch. The handler takes a mutable
/// VM reference, the current opcode, and the op_array index, and returns a
/// dispatch signal indicating what to do next.
///
/// Usage: `type OpcodeHandler = fn(&mut Vm, &ZOp, usize) -> VmResult<DispatchSignal>;`
///
/// In PHP's reference implementation, opcode handlers are stored as function
/// pointers in a 2D table indexed by (opcode, operand_type_specialization).
/// Rust's match-based dispatch achieves similar performance through the compiler's
/// jump table optimization, but this type provides the foundation for future
/// handler table implementations.
pub type OpcodeHandler = fn(&mut Vm, &ZOp, usize) -> VmResult<DispatchSignal>;

/// Opcode handler table for commonly-used opcodes.
///
/// Maps ZOpcode discriminant to `Option<OpcodeHandler>`.
/// When Some(handler), the handler is called directly via function pointer.
/// When None, falls through to the match-based dispatch.
///
/// This table is initialized lazily and covers the ~30 most frequently executed
/// opcodes (arithmetic, assignment, jumps, echo, return) for maximum impact.
pub struct OpcodeHandlerTable {
    /// Handler table indexed by opcode number (0..=211).
    handlers: [Option<OpcodeHandler>; 212],
}

impl OpcodeHandlerTable {
    /// Build the handler table with the most common opcode handlers.
    pub fn new() -> Self {
        let handlers = [None; 212];
        // Note: the handlers array is initialized to None. The match-based dispatch
        // in dispatch_op handles all opcodes efficiently via Rust's jump table
        // optimization. This infrastructure exists for future fine-grained handler
        // registration (e.g., JIT-compiled handlers or extension-provided handlers).
        Self { handlers }
    }

    /// Register a handler for a specific opcode.
    #[allow(dead_code)]
    pub fn register(&mut self, opcode: ZOpcode, handler: OpcodeHandler) {
        self.handlers[opcode as u8 as usize] = Some(handler);
    }

    /// Look up a handler for an opcode.
    #[inline]
    pub fn get(&self, opcode: ZOpcode) -> Option<OpcodeHandler> {
        self.handlers[opcode as u8 as usize]
    }
}

impl Default for OpcodeHandlerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    /// Create a new VM with default configuration (128 MB memory limit, 30s timeout).
    pub fn new() -> Self {
        Self::with_config(VmConfig::default())
    }

    /// Create a new VM with explicit configuration for execution limits and security.
    pub fn with_config(config: VmConfig) -> Self {
        Self {
            output: String::new(),
            ob_stack: Vec::new(),
            raw_input_body: None,
            session_id: String::new(),
            session_started: false,
            session_save_path: std::env::temp_dir().to_string_lossy().to_string(),
            functions: HashMap::new(),
            op_arrays: Vec::new(),
            call_stack: Vec::new(),
            constants: defaults::build_default_constants(),
            constant_attributes: HashMap::new(),
            classes: defaults::build_default_classes(),
            next_object_id: 1,
            current_exception: None,
            included_files: HashSet::new(),
            last_return_value: Value::Null,
            shutdown_functions: Vec::new(),
            generators: HashMap::new(),
            fibers: HashMap::new(),
            reflection_classes: HashMap::new(),
            current_fiber_id: None,
            next_closure_id: 0,
            closure_bindings: HashMap::new(),
            closure_scopes: HashMap::new(),
            vfs: None,
            file_handles: {
                let mut fh = HashMap::new();
                fh.insert(0, php_rs_ext_standard::file::FileHandle::stdin());
                fh.insert(1, php_rs_ext_standard::file::FileHandle::stdout());
                fh.insert(2, php_rs_ext_standard::file::FileHandle::stderr());
                fh
            },
            gz_handles: HashMap::new(),
            bz_handles: HashMap::new(),
            dom_documents: HashMap::new(),
            next_dom_id: 1,
            deflate_contexts: HashMap::new(),
            inflate_contexts: HashMap::new(),
            #[cfg(feature = "native-io")]
            curl_handles: HashMap::new(),
            #[cfg(feature = "native-io")]
            curl_multi_handles: HashMap::new(),
            #[cfg(feature = "native-io")]
            curl_share_handles: HashMap::new(),
            proc_handles: HashMap::new(),
            next_resource_id: 3,
            config,
            execution_start_millis: None,
            opcode_counter: 0,
            autoload_callbacks: Vec::new(),
            autoloading_classes: HashSet::new(),
            interface_chain_loaded: HashSet::new(),
            response_headers: Vec::new(),
            response_code: None,
            headers_sent: false,
            headers_sent_file: String::new(),
            headers_sent_line: 0,
            ignore_user_abort: false,
            strtok_state: None,
            apcu_cache: HashMap::new(),
            hash_contexts: HashMap::new(),
            #[cfg(feature = "native-io")]
            mysqli_connections: HashMap::new(),
            #[cfg(feature = "native-io")]
            mysqli_results: HashMap::new(),
            #[cfg(feature = "native-io")]
            mysqli_conn_meta: HashMap::new(),
            #[cfg(feature = "native-io")]
            mysqli_stmts: HashMap::new(),
            #[cfg(feature = "native-io")]
            pdo_connections: HashMap::new(),
            #[cfg(feature = "native-io")]
            pdo_statements: HashMap::new(),
            #[cfg(feature = "native-io")]
            sqlite3_connections: HashMap::new(),
            #[cfg(feature = "native-io")]
            sqlite3_stmts: HashMap::new(),
            #[cfg(feature = "native-io")]
            sqlite3_results: HashMap::new(),
            #[cfg(feature = "native-io")]
            openssl_keys: HashMap::new(),
            mt_rng: php_rs_ext_random::Mt19937::new(None),
            gd_images: HashMap::new(),
            xml_writers: HashMap::new(),
            intl_number_formatters: HashMap::new(),
            intl_collators: HashMap::new(),
            intl_date_formatters: HashMap::new(),
            phar_archives: HashMap::new(),
            simplexml_elements: HashMap::new(),
            xml_readers: HashMap::new(),
            sockets: HashMap::new(),
            soap_clients: HashMap::new(),
            soap_servers: HashMap::new(),
            ldap_connections: HashMap::new(),
            ldap_search_results: HashMap::new(),
            ftp_connections: HashMap::new(),
            odbc_connections: HashMap::new(),
            odbc_results: HashMap::new(),
            odbc_stmts: HashMap::new(),
            snmp_sessions: HashMap::new(),
            dba_handles: HashMap::new(),
            enchant_brokers: HashMap::new(),
            sysv_semaphores: HashMap::new(),
            sysv_shm: HashMap::new(),
            sysv_msg_queues: HashMap::new(),
            shmop_blocks: HashMap::new(),
            static_vars: HashMap::new(),
            error_reporting_level: 32767, // E_ALL
            silence_stack: Vec::new(),
            error_handler: None,
            error_handler_stack: Vec::new(),
            last_error: None,
            exception_handler: None,
            exception_handler_stack: Vec::new(),
            tick_functions: Vec::new(),
            tick_counter: 0,
            ob_callbacks: Vec::new(),
            ob_implicit_flush: false,
            session_cookie_params: SessionCookieParams::default(),
            session_cache_limiter: "nocache".to_string(),
            session_cache_expire: 180,
            session_save_handler: None,
            stream_contexts: HashMap::new(),
            registered_stream_wrappers: HashSet::new(),
            registered_stream_filters: HashSet::new(),
            error_log_path: None,
            builtins: crate::builtins::build_registry(),
            ini: php_rs_runtime::ini::IniSystem::new(),
            opcode_handlers: OpcodeHandlerTable::new(),
            arena: php_rs_gc::Arena::new(),
            string_pool: php_rs_gc::StringPool::new(),
            opcode_cache: HashMap::new(),
            superglobals: HashMap::new(),
            events: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            request_start: Instant::now(),
        }
    }

    /// PHP superglobal variable names (without leading $).
    const SUPERGLOBAL_NAMES: &'static [&'static str] = &[
        "_GET", "_POST", "_COOKIE", "_SERVER", "_REQUEST", "_FILES", "_ENV", "_SESSION",
    ];

    /// Capture the current call stack as a PHP-compatible trace array.
    /// Each frame is an array with keys: file, line, function, class, type, args
    pub(crate) fn capture_stack_trace(&self) -> Value {
        let mut trace = PhpArray::new();
        let n = self.call_stack.len();

        // PHP trace format: each entry pairs the CALLEE's function name
        // with the CALLER's file:line (where the call was made).
        //
        // Call stack (bottom-to-top): [main, bar, foo]
        // Trace output:
        //   #0: function=foo, file/line from bar (where foo() was called)
        //   #1: function=bar, file/line from main (where bar() was called)
        //
        // We iterate from top of stack (the function that threw) downward,
        // stopping before {main} (which has no caller and no function name).

        for entry_idx in 0..n {
            let callee_idx = n - 1 - entry_idx; // top to bottom
            let callee_frame = &self.call_stack[callee_idx];
            let callee_oa = &self.op_arrays[callee_frame.op_array_idx];

            // Get function name from callee's op_array
            let func_name = callee_oa.function_name.as_deref().unwrap_or("");
            if func_name.is_empty() {
                // This is {main} — don't include in trace entries
                break;
            }

            let mut entry = PhpArray::new();

            // file/line come from the CALLER (one level below in call_stack)
            if callee_idx > 0 {
                let caller_frame = &self.call_stack[callee_idx - 1];
                let caller_oa = &self.op_arrays[caller_frame.op_array_idx];

                if let Some(ref filename) = caller_oa.filename {
                    entry.set_string("file".to_string(), Value::String(filename.clone()));
                }
                // caller's IP points to the instruction AFTER the call (return point),
                // so ip-1 is the DO_FCALL opcode on the same line as the call
                let ip = if caller_frame.ip > 0 { caller_frame.ip - 1 } else { 0 };
                if ip < caller_oa.opcodes.len() {
                    entry.set_string("line".to_string(), Value::Long(caller_oa.opcodes[ip].lineno as i64));
                }
            }

            // function name from callee
            if func_name.contains("::") {
                let parts: Vec<&str> = func_name.splitn(2, "::").collect();
                entry.set_string("class".to_string(), Value::String(parts[0].to_string()));
                entry.set_string("function".to_string(), Value::String(parts[1].to_string()));
                entry.set_string("type".to_string(), Value::String("->".to_string()));
            } else {
                entry.set_string("function".to_string(), Value::String(func_name.to_string()));
            }

            // args (empty array — we don't capture actual argument values)
            entry.set_string("args".to_string(), Value::Array(PhpArray::new()));

            trace.push(Value::Array(entry));
        }

        Value::Array(trace)
    }

    /// Populate superglobal CVs ($_GET, $_POST, $_COOKIE, $_SERVER, etc.) into a frame.
    /// In PHP, superglobals are accessible inside any function without `global`.
    /// First checks the VM's stored superglobals (from execute()), then falls back to
    /// reading current values from the main frame (call_stack[0]) so that script-level
    /// modifications to superglobals are also visible in function scope.
    pub(crate) fn populate_superglobals(&self, frame: &mut Frame, op_array: &ZOpArray) {
        // Step 1: Seed from VM's stored superglobals (initial HTTP request values)
        for (name, value) in &self.superglobals {
            if let Some(idx) = op_array.vars.iter().position(|v| v == name) {
                frame.cvs[idx] = value.clone();
            }
        }

        // Step 2: Override with values from the call stack frames.
        // PHP superglobals are truly global — modifications by the main script or
        // any calling frame should be visible in the new frame.
        // We walk the call stack from bottom (main) to top (caller), so the
        // most recent value wins.
        for stack_frame in &self.call_stack {
            let stack_oa = &self.op_arrays[stack_frame.op_array_idx];
            for &sg_name in Self::SUPERGLOBAL_NAMES {
                if let Some(new_idx) = op_array.vars.iter().position(|v| v == sg_name) {
                    if let Some(stack_idx) = stack_oa.vars.iter().position(|v| v == sg_name) {
                        if stack_idx < stack_frame.cvs.len()
                            && !matches!(stack_frame.cvs[stack_idx], Value::Null)
                        {
                            frame.cvs[new_idx] = stack_frame.cvs[stack_idx].clone();
                        }
                    }
                }
            }
        }
    }

    /// Get HTTP response headers set by header() calls.
    pub fn response_headers(&self) -> &[String] {
        &self.response_headers
    }

    /// Get the HTTP response code set by http_response_code() or header().
    pub fn response_code(&self) -> Option<u16> {
        self.response_code
    }

    /// Get the last return value from script execution.
    /// Used by the built-in server to check if a router script returned false.
    pub fn last_return_value(&self) -> Option<Value> {
        match &self.last_return_value {
            Value::Null => None,
            v => Some(v.clone()),
        }
    }

    /// Get the output buffer contents (useful after Exit errors).
    /// Includes any content still sitting in ob_stack buffers.
    pub fn output_so_far(&self) -> String {
        let mut out = self.output.clone();
        for buf in &self.ob_stack {
            out.push_str(buf);
        }
        out
    }

    /// Record an internal VM event (SQL query, include, error, etc.).
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn record_event(&mut self, kind: &'static str, detail: String) {
        let elapsed_us = self.request_start.elapsed().as_micros();
        self.events.push(VmEvent { kind, detail, elapsed_us });
    }

    /// No-op on WASM (no Instant available).
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn record_event(&mut self, _kind: &'static str, _detail: String) {}

    /// Take all recorded events, leaving the internal list empty.
    pub fn take_events(&mut self) -> Vec<VmEvent> {
        std::mem::take(&mut self.events)
    }

    /// Check if a file path is allowed by open_basedir restriction.
    /// Returns Ok(()) if allowed, Err with warning if not.
    pub fn check_open_basedir(&self, path: &str) -> VmResult<()> {
        if self.config.open_basedir.is_empty() {
            return Ok(());
        }

        // Canonicalize the target path (resolve symlinks, .., etc.)
        #[cfg(not(target_arch = "wasm32"))]
        let canonical = std::fs::canonicalize(path)
            .or_else(|_| {
                // If file doesn't exist yet, canonicalize the parent directory
                let p = std::path::Path::new(path);
                if let Some(parent) = p.parent() {
                    std::fs::canonicalize(parent)
                        .map(|pp| pp.join(p.file_name().unwrap_or_default()))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Cannot resolve path",
                    ))
                }
            })
            .unwrap_or_else(|_| std::path::PathBuf::from(path));
        #[cfg(target_arch = "wasm32")]
        let canonical = std::path::PathBuf::from(path);

        let canonical_str = canonical.to_string_lossy();

        for base in &self.config.open_basedir {
            #[cfg(not(target_arch = "wasm32"))]
            let base_canonical =
                std::fs::canonicalize(base).unwrap_or_else(|_| std::path::PathBuf::from(base));
            #[cfg(target_arch = "wasm32")]
            let base_canonical = std::path::PathBuf::from(base);
            let base_str = base_canonical.to_string_lossy();
            // Path must start with the base directory
            if canonical_str.starts_with(base_str.as_ref()) {
                return Ok(());
            }
        }

        Err(VmError::FatalError(format!(
            "open_basedir restriction in effect. File({}) is not within the allowed path(s): ({})",
            path,
            self.config
                .open_basedir
                .join(if cfg!(windows) { ";" } else { ":" })
        )))
    }

    /// Execute a compiled op_array and return the output.
    ///
    /// If `superglobals` is provided, CVs whose names match keys in the map are
    /// initialized with those values (e.g. `$_GET`, `$_SERVER`) before execution.
    pub fn execute(
        &mut self,
        op_array: &ZOpArray,
        superglobals: Option<&HashMap<String, Value>>,
    ) -> VmResult<String> {
        // ── Request-start cleanup: clear all per-request state ──
        self.op_arrays.clear();
        self.op_arrays.push(op_array.clone());
        self.functions.clear();
        self.output.clear();
        self.ob_stack.clear();
        self.session_id.clear();
        self.session_started = false;
        self.shutdown_functions.clear();
        self.generators.clear();
        self.fibers.clear();
        self.closure_bindings.clear();
        self.closure_scopes.clear();
        self.included_files.clear();
        self.current_exception = None;
        self.current_fiber_id = None;
        self.next_object_id = 1;
        self.next_closure_id = 0;
        self.last_return_value = Value::Null;
        self.opcode_counter = 0;
        self.response_headers.clear();
        self.response_code = None;

        // Reset request-scoped allocators
        self.arena.reset();
        self.string_pool.reset();

        // Start execution timer
        if self.config.max_execution_time > 0 {
            self.execution_start_millis = Some(now_millis());
        } else {
            self.execution_start_millis = None;
        }

        // Pre-register any nested function definitions from dynamic_func_defs
        self.register_dynamic_func_defs(0);

        // Pre-register __COMPILER_HALT_OFFSET__ if __halt_compiler() was used
        if op_array.halt_compiler_offset > 0 {
            self.constants.insert(
                "__COMPILER_HALT_OFFSET__".to_string(),
                Value::Long(op_array.halt_compiler_offset as i64),
            );
        }

        // Store superglobals on VM so they can be populated into every function frame.
        // PHP superglobals ($_GET, $_POST, $_COOKIE, $_SERVER, etc.) are accessible
        // inside functions without `global` declaration.
        if let Some(sg) = superglobals {
            for (name, value) in sg {
                self.superglobals.insert(name.clone(), value.clone());
            }
        }

        // Create the main frame and populate superglobals
        let mut frame = Frame::new(op_array);
        frame.op_array_idx = 0;
        self.populate_superglobals(&mut frame, op_array);

        self.call_stack.push(frame);

        let dispatch_result = self.dispatch_loop();

        // Run registered shutdown functions regardless of script result
        self.run_shutdown_functions();

        // Propagate any error from dispatch
        match dispatch_result {
            Err(VmError::Exit(code)) => {
                // Run shutdown functions already ran above; flush OB and propagate
                while let Some(buf) = self.ob_stack.pop() {
                    self.write_output(&buf);
                }
                return Err(VmError::Exit(code));
            }
            Err(VmError::Thrown(ref exception_val)) => {
                // Try user exception handler before propagating
                if let Some(handler_name) = self.exception_handler.clone() {
                    let _ = self.invoke_user_callback(&handler_name, vec![exception_val.clone()]);
                    // After exception handler runs, PHP terminates (but doesn't propagate)
                } else {
                    return Err(VmError::Thrown(exception_val.clone()));
                }
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        // Auto-commit session if still open (PHP does this at request end).
        if self.session_started && !self.session_id.is_empty() {
            let data = self.get_session_cv().unwrap_or_default();
            let serialized = session_serialize(&data);
            let path = self.session_file_path(&self.session_id.clone());
            #[cfg(not(target_arch = "wasm32"))]
            let _ = std::fs::write(&path, serialized);
            self.session_started = false;
        }

        // Flush any un-closed output buffers (implicit flush on request end).
        while let Some(buf) = self.ob_stack.pop() {
            self.write_output(&buf);
        }

        Ok(self.output.clone())
    }

    /// Execute a PHP file with opcode caching.
    ///
    /// If the file has been compiled before and hasn't changed (based on mtime),
    /// the cached opcode array is used directly, avoiding recompilation.
    pub fn execute_file(
        &mut self,
        file_path: &str,
        superglobals: Option<&HashMap<String, Value>>,
    ) -> VmResult<String> {
        let op_array = self.compile_cached(file_path)?;
        self.execute(&op_array, superglobals)
    }

    /// Compile a file with opcode caching. Returns cached version if file hasn't changed.
    pub fn compile_cached(&mut self, file_path: &str) -> VmResult<ZOpArray> {
        // Check file modification time
        #[cfg(not(target_arch = "wasm32"))]
        let mtime = std::fs::metadata(file_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        #[cfg(target_arch = "wasm32")]
        let mtime = 0u64;

        // Check cache
        if let Some((cached_mtime, cached_oa)) = self.opcode_cache.get(file_path) {
            if *cached_mtime == mtime {
                return Ok(cached_oa.clone());
            }
        }

        // Cache miss — compile from source
        let source = std::fs::read_to_string(file_path)
            .map_err(|e| VmError::FatalError(format!("Failed to read {}: {}", file_path, e)))?;
        let mut op_array = php_rs_compiler::compile(&source).map_err(|e| {
            VmError::FatalError(format!("Compilation error in {}: {}", file_path, e))
        })?;
        op_array.filename = Some(file_path.to_string());

        // Store in cache
        self.opcode_cache
            .insert(file_path.to_string(), (mtime, op_array.clone()));

        Ok(op_array)
    }

    /// Invalidate opcode cache for a specific file.
    pub fn invalidate_opcode_cache(&mut self, file_path: &str) {
        self.opcode_cache.remove(file_path);
    }

    /// Clear the entire opcode cache.
    pub fn clear_opcode_cache(&mut self) {
        self.opcode_cache.clear();
    }

    /// Get opcode cache statistics.
    pub fn opcode_cache_size(&self) -> usize {
        self.opcode_cache.len()
    }

    /// Load a pre-compiled opcache file into the VM's opcode cache.
    /// Entries are loaded with their stored mtimes, so the normal mtime
    /// check in `compile_cached()` will validate freshness automatically.
    pub fn load_opcache(&mut self, path: &std::path::Path) -> Result<usize, String> {
        let cache = php_rs_compiler::OpcacheFile::load(path)?;
        let count = cache.entries.len();
        for (file_path, entry) in cache.entries {
            self.opcode_cache
                .insert(file_path, (entry.mtime, entry.op_array));
        }
        Ok(count)
    }

    /// Save the VM's current opcode cache to disk.
    pub fn save_opcache(&self, path: &std::path::Path) -> Result<usize, String> {
        let mut cache = php_rs_compiler::OpcacheFile::new();
        for (file_path, (mtime, op_array)) in &self.opcode_cache {
            cache.add(file_path.clone(), *mtime, op_array.clone());
        }
        cache.save(path)?;
        Ok(cache.len())
    }

    /// Set the raw POST/PUT body for php://input stream reads.
    /// Call this before `execute()` when handling web requests.
    pub fn set_raw_input_body(&mut self, body: String) {
        self.raw_input_body = Some(body);
    }

    /// Force-set an INI directive, bypassing permission checks.
    /// Used by SAPIs to apply `-d` flags or pre-execution configuration.
    pub fn ini_force_set(&mut self, name: &str, value: &str) {
        self.ini.force_set(name, value);
    }

    /// Apply a VmConfig to this VM, updating execution limits and security settings.
    pub fn apply_config(&mut self, config: VmConfig) {
        self.config = config;
    }

    /// Get the response headers set by `header()` calls during execution.
    pub fn take_response_headers(&mut self) -> Vec<String> {
        std::mem::take(&mut self.response_headers)
    }

    /// Get the response status code set by `http_response_code()` or `header()`.
    pub fn take_response_code(&mut self) -> Option<u16> {
        self.response_code.take()
    }

    /// Execute an opcode array while preserving functions, classes, and constants
    /// from previous invocations. Only per-request transient state is cleared.
    ///
    /// This enables REPL-like behavior where each `eval()` call can reference
    /// functions/classes defined in earlier calls.
    pub fn execute_incremental(
        &mut self,
        op_array: &ZOpArray,
        superglobals: Option<&HashMap<String, Value>>,
    ) -> VmResult<String> {
        // Save persistent state
        let saved_functions = std::mem::take(&mut self.functions);
        let mut saved_op_arrays = std::mem::take(&mut self.op_arrays);

        // Clear only transient per-request state
        self.output.clear();
        self.ob_stack.clear();
        self.session_id.clear();
        self.session_started = false;
        self.shutdown_functions.clear();
        self.generators.clear();
        self.fibers.clear();
        self.closure_bindings.clear();
        self.closure_scopes.clear();
        self.current_exception = None;
        self.current_fiber_id = None;
        self.next_object_id = 1;
        self.next_closure_id = 0;
        self.last_return_value = Value::Null;
        self.opcode_counter = 0;
        self.response_headers.clear();
        self.response_code = None;

        // Reset request-scoped allocators
        self.arena.reset();
        self.string_pool.reset();

        // Restore persistent op_arrays, append the new main script
        let new_main_idx = saved_op_arrays.len();
        saved_op_arrays.push(op_array.clone());
        self.op_arrays = saved_op_arrays;
        self.functions = saved_functions;

        // Start execution timer
        if self.config.max_execution_time > 0 {
            self.execution_start_millis = Some(now_millis());
        } else {
            self.execution_start_millis = None;
        }

        // Pre-register nested function definitions from the new main script
        self.register_dynamic_func_defs(new_main_idx);

        if op_array.halt_compiler_offset > 0 {
            self.constants.insert(
                "__COMPILER_HALT_OFFSET__".to_string(),
                Value::Long(op_array.halt_compiler_offset as i64),
            );
        }

        if let Some(sg) = superglobals {
            for (name, value) in sg {
                self.superglobals.insert(name.clone(), value.clone());
            }
        }

        let mut frame = Frame::new(op_array);
        frame.op_array_idx = new_main_idx;
        self.populate_superglobals(&mut frame, op_array);
        self.call_stack.push(frame);

        let dispatch_result = self.dispatch_loop();
        self.run_shutdown_functions();

        match dispatch_result {
            Err(VmError::Exit(code)) => {
                while let Some(buf) = self.ob_stack.pop() {
                    self.write_output(&buf);
                }
                return Err(VmError::Exit(code));
            }
            Err(VmError::Thrown(ref exception_val)) => {
                if let Some(handler_name) = self.exception_handler.clone() {
                    let _ = self.invoke_user_callback(&handler_name, vec![exception_val.clone()]);
                } else {
                    return Err(VmError::Thrown(exception_val.clone()));
                }
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        if self.session_started && !self.session_id.is_empty() {
            let data = self.get_session_cv().unwrap_or_default();
            let serialized = session_serialize(&data);
            let path = self.session_file_path(&self.session_id.clone());
            #[cfg(not(target_arch = "wasm32"))]
            let _ = std::fs::write(&path, serialized);
            self.session_started = false;
        }

        while let Some(buf) = self.ob_stack.pop() {
            self.write_output(&buf);
        }

        Ok(self.output.clone())
    }

    /// When set, all file operations will use the VFS instead of the real filesystem.
    pub fn set_vfs(
        &mut self,
        vfs: std::sync::Arc<std::sync::RwLock<php_rs_runtime::VirtualFileSystem>>,
    ) {
        self.vfs = Some(vfs);
    }

    /// Get a reference to the VFS if set.
    pub fn vfs(
        &self,
    ) -> Option<&std::sync::Arc<std::sync::RwLock<php_rs_runtime::VirtualFileSystem>>> {
        self.vfs.as_ref()
    }

    #[inline(always)]
    #[inline(always)]
    pub(crate) fn write_output(&mut self, s: &str) {
        if let Some(buf) = self.ob_stack.last_mut() {
            buf.push_str(s);
        } else {
            if !self.headers_sent && !s.is_empty() {
                self.headers_sent = true;
                let (file, line) = self.get_error_context();
                self.headers_sent_file = file;
                self.headers_sent_line = line;
            }
            self.output.push_str(s);
        }
    }

    /// Get the current execution context (file path, line number) for error messages.
    pub(crate) fn get_error_context(&self) -> (String, u32) {
        if let Some(frame) = self.call_stack.last() {
            let oa = &self.op_arrays[frame.op_array_idx];
            let file = match &oa.filename {
                Some(f) if !f.is_empty() => f.clone(),
                _ => "Unknown".to_string(),
            };
            let lineno = if frame.ip > 0 && frame.ip <= oa.opcodes.len() {
                oa.opcodes[frame.ip.saturating_sub(1)].lineno
            } else if !oa.opcodes.is_empty() {
                oa.opcodes[0].lineno
            } else {
                0
            };
            (file, lineno)
        } else {
            ("Unknown".to_string(), 0)
        }
    }

    /// Emit a PHP error (E_NOTICE, E_WARNING, E_USER_*, etc.).
    ///
    /// Checks error_reporting level and invokes user error handler if set.
    /// Returns true if the error was handled (by user handler returning true),
    /// false if default behavior should apply.
    pub(crate) fn emit_error(&mut self, level: i64, message: &str) -> VmResult<bool> {
        // Check error_reporting level — if this level is masked off, suppress
        if self.error_reporting_level & level == 0 {
            return Ok(true); // Suppressed
        }

        // Record event for dashboard tracing
        let event_kind = match level { 8 | 1024 => "notice", 2 | 512 => "warning", _ => "error" };
        self.record_event(event_kind, message.to_string());

        // Get current file and line from execution context
        let (file, line) = self.get_error_context();

        // Record as last error for error_get_last()
        self.last_error = Some((level, message.to_string(), file.clone(), line));

        // If user error handler is set, invoke it
        if let Some(handler_name) = self.error_handler.clone() {
            // User handler receives: (errno, errstr, errfile, errline)
            let handler_args = vec![
                Value::Long(level),
                Value::String(message.to_string()),
                Value::String(file.clone()),
                Value::Long(line as i64),
            ];
            // Propagate exceptions thrown by error handler
            let result = self.invoke_user_callback(&handler_name, handler_args)?;
            // If handler returns true, error is considered handled
            if result.to_bool() {
                return Ok(true);
            }
            // Handler returned false — fall through to default
        }

        // Default behavior: output the error message
        let level_str = match level {
            1 => "Fatal error",
            2 => "Warning",
            4 => "Parse error",
            8 => "Notice",
            256 => "Fatal error",
            512 => "Warning",
            1024 => "Notice",
            2048 => "Strict Standards",
            8192 => "Deprecated",
            16384 => "Deprecated",
            _ => "Warning",
        };

        // Write to error log if configured, otherwise output
        if let Some(ref log_path) = self.error_log_path {
            // Write to file
            #[cfg(not(target_arch = "wasm32"))]
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                {
                    let _ = writeln!(f, "{}: {} in {} on line {}", level_str, message, file, line);
                }
            }
        } else {
            self.write_output(&format!(
                "\n{}: {} in {} on line {}\n",
                level_str, message, file, line
            ));
        }
        Ok(false)
    }

    /// Run registered shutdown functions (called after script execution).
    pub(crate) fn run_shutdown_functions(&mut self) {
        let funcs: Vec<String> = self.shutdown_functions.drain(..).collect();
        for func_name in funcs {
            // Try built-in first
            if let Ok(Some(_)) = self.call_builtin(&func_name, &[], &[], &[]) {
                continue;
            }
            // Try user-defined function
            if let Some(&oa_idx) = self.functions.get(&func_name) {
                let func_oa = &self.op_arrays[oa_idx];
                let mut new_frame = Frame::new(func_oa);
                new_frame.op_array_idx = oa_idx;
                self.populate_superglobals(&mut new_frame, func_oa);
                self.call_stack.push(new_frame);
                // Ignore errors during shutdown
                let _ = self.dispatch_loop();
            }
        }
    }

    /// Check execution time, memory limits, and shutdown signals.
    /// Called periodically from dispatch loop (every 1024 opcodes).
    pub(crate) fn check_execution_limits(&self) -> VmResult<()> {
        // Check for graceful shutdown signal (SIGINT/SIGTERM)
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return Err(VmError::Exit(130)); // 128 + SIGINT(2)
        }

        // Check execution time limit
        if let Some(start_ms) = self.execution_start_millis {
            let now_ms = now_millis();
            let elapsed_secs = (now_ms.saturating_sub(start_ms)) / 1000;
            if elapsed_secs >= self.config.max_execution_time {
                return Err(VmError::TimeLimitExceeded(format!(
                    "Maximum execution time of {} seconds exceeded",
                    self.config.max_execution_time
                )));
            }
        }

        // Check approximate memory usage (output buffer + data structures)
        if self.config.memory_limit > 0 {
            let approx_usage = self.approximate_memory_usage();
            if approx_usage > self.config.memory_limit {
                return Err(VmError::MemoryLimitExceeded(format!(
                    "Allowed memory size of {} bytes exhausted (tried to allocate approx {} bytes)",
                    self.config.memory_limit, approx_usage
                )));
            }
        }

        Ok(())
    }

    /// Approximate the current memory usage of the VM.
    pub(crate) fn approximate_memory_usage(&self) -> usize {
        let mut usage = 0usize;
        // Output buffer
        usage += self.output.capacity();
        // Op arrays (compiled bytecode)
        usage += self.op_arrays.len() * std::mem::size_of::<ZOpArray>();
        // Call stack frames
        for frame in &self.call_stack {
            usage += frame.cvs.len() * std::mem::size_of::<Value>();
            usage += frame.temps.len() * std::mem::size_of::<Value>();
            usage += frame.args.len() * std::mem::size_of::<Value>();
        }
        // Generator states
        usage += self.generators.len() * 256; // estimate per generator
                                              // Fiber states
        usage += self.fibers.len() * 512; // estimate per fiber
                                          // Closure bindings
        for bindings in self.closure_bindings.values() {
            usage += bindings.len() * std::mem::size_of::<(String, Value)>();
        }
        // Constants and class defs
        usage += self.constants.len() * 64;
        usage += self.classes.len() * 256;
        usage
    }

    /// Register dynamic_func_defs from an op_array into the function table.
    /// Skips closures ({closure}) — those are registered at runtime via DeclareLambdaFunction.
    pub(crate) fn register_dynamic_func_defs(&mut self, parent_idx: usize) {
        let defs: Vec<ZOpArray> = self.op_arrays[parent_idx].dynamic_func_defs.clone();
        for def in defs {
            if let Some(ref name) = def.function_name {
                // Skip closures; they're registered dynamically when DeclareLambdaFunction executes
                if name == "{closure}" {
                    continue;
                }
                let idx = self.op_arrays.len();
                let name = name.clone();
                self.op_arrays.push(def);
                self.functions.insert(name, idx);
            }
        }
    }

    /// Create an error/exception object for throwing.
    pub(crate) fn create_error_object(&self, class_name: &str, message: String) -> Value {
        let ex_obj = PhpObject::new(class_name.to_string());
        ex_obj.set_property("message".to_string(), Value::String(message));
        Value::Object(ex_obj)
    }

    /// Main dispatch loop.
    pub(crate) fn dispatch_loop(&mut self) -> VmResult<()> {
        self.dispatch_loop_until(0)
    }

    /// Dispatch loop that runs until call stack depth drops to min_depth.
    /// Used for recursive method calls (e.g., JsonSerializable::jsonSerialize).
    pub(crate) fn dispatch_loop_until(&mut self, min_depth: usize) -> VmResult<()> {
        loop {
            if self.call_stack.len() <= min_depth {
                return Ok(());
            }

            // ── Periodic limit checks (every 1024 opcodes) ──
            self.opcode_counter += 1;
            if self.opcode_counter & 0x3FF == 0 {
                self.check_execution_limits()?;
            }
            let frame = self.call_stack.last().unwrap();
            let op_array_idx = frame.op_array_idx;
            let ip = frame.ip;

            if ip >= self.op_arrays[op_array_idx].opcodes.len() {
                // Fell off end — implicit return
                // Persist static variables first
                {
                    let frame = self.call_stack.last().unwrap();
                    let oa_key = frame.op_array_idx;
                    for &cv_idx in &frame.static_cv_indices {
                        if cv_idx < frame.cvs.len() {
                            self.static_vars
                                .insert((oa_key, cv_idx), frame.cvs[cv_idx].clone());
                        }
                    }
                }
                let frame = self.call_stack.pop().unwrap();
                self.last_return_value = frame.return_value;

                // Write back include scope variables to ancestor frames
                if !frame.include_scope_map.is_empty() {
                    for &(child_idx, stack_idx, ancestor_cv_idx) in &frame.include_scope_map {
                        if stack_idx < self.call_stack.len() && child_idx < frame.cvs.len() {
                            let ancestor = &mut self.call_stack[stack_idx];
                            if ancestor_cv_idx < ancestor.cvs.len() {
                                ancestor.cvs[ancestor_cv_idx] = frame.cvs[child_idx].clone();
                            }
                        }
                    }
                }

                continue;
            }

            let op = self.op_arrays[op_array_idx].opcodes[ip].clone();

            let result = self.dispatch_op(&op, op_array_idx);

            // Convert runtime errors to catchable exceptions (cold path)
            let result = match result {
                Ok(signal) => Ok(signal),
                Err(e) => Err(self.convert_error_to_exception(e)),
            };

            // Handle thrown exceptions: look for catch blocks, unwinding call stack
            let result = match result {
                Err(VmError::Thrown(ref exception_val)) => {
                    if let Some(catch_target) =
                        self.find_catch_block(op_array_idx, ip, exception_val)
                    {
                        self.current_exception = Some(exception_val.clone());
                        // Clear pending calls — any Init* that preceded the throw are now stale
                        self.call_stack.last_mut().unwrap().call_stack_pending.clear();
                        Ok(DispatchSignal::Jump(catch_target))
                    } else {
                        // Unwind call stack looking for a catch block in parent frames
                        let mut found_catch = false;
                        while self.call_stack.len() > min_depth + 1 {
                            // Pop current frame (exception is uncaught here)
                            let frame = self.call_stack.pop().unwrap();
                            self.last_return_value = frame.return_value;

                            // Check the caller frame for a catch block
                            if let Some(caller) = self.call_stack.last() {
                                let caller_oa_idx = caller.op_array_idx;
                                let caller_ip = caller.ip;
                                if let Some(catch_target) =
                                    self.find_catch_block(caller_oa_idx, caller_ip, exception_val)
                                {
                                    self.current_exception = Some(exception_val.clone());
                                    let catcher = self.call_stack.last_mut().unwrap();
                                    catcher.ip = catch_target;
                                    // Clear stale pending calls from before the exception
                                    catcher.call_stack_pending.clear();
                                    found_catch = true;
                                    break;
                                }
                            }
                        }
                        if found_catch {
                            continue;
                        }
                        result
                    }
                }
                other => other,
            };

            match result? {
                DispatchSignal::Next => {
                    self.call_stack.last_mut().unwrap().ip += 1;
                }
                DispatchSignal::Jump(target) => {
                    self.call_stack.last_mut().unwrap().ip = target;
                }
                DispatchSignal::Return => {
                    // Persist static variables before popping the frame
                    {
                        let frame = self.call_stack.last().unwrap();
                        let oa_key = frame.op_array_idx;
                        for &cv_idx in &frame.static_cv_indices {
                            if cv_idx < frame.cvs.len() {
                                self.static_vars
                                    .insert((oa_key, cv_idx), frame.cvs[cv_idx].clone());
                            }
                        }
                    }

                    let frame = self.call_stack.pop().unwrap();
                    let ret_val = frame.return_value.clone();
                    self.last_return_value = ret_val.clone();

                    // Write back pass-by-reference parameters to caller's CVs
                    if !frame.ref_write_back.is_empty() {
                        if let Some(caller) = self.call_stack.last_mut() {
                            for &(callee_cv_idx, caller_op_type, caller_slot) in
                                &frame.ref_write_back
                            {
                                if callee_cv_idx < frame.cvs.len() {
                                    let val = frame.cvs[callee_cv_idx].clone();
                                    Self::write_to_slot(caller, caller_op_type, caller_slot, val);
                                }
                            }
                        }
                    }

                    // Write back pass-by-reference parameters to object properties
                    for (callee_cv_idx, obj, prop_name) in &frame.ref_prop_write_back {
                        if *callee_cv_idx < frame.cvs.len() {
                            let val = frame.cvs[*callee_cv_idx].clone();
                            obj.set_property(prop_name.clone(), val);
                        }
                    }

                    // Write back include scope variables to ancestor frames
                    if !frame.include_scope_map.is_empty() {
                        for &(child_idx, stack_idx, ancestor_cv_idx) in &frame.include_scope_map {
                            if stack_idx < self.call_stack.len() && child_idx < frame.cvs.len() {
                                let ancestor = &mut self.call_stack[stack_idx];
                                if ancestor_cv_idx < ancestor.cvs.len() {
                                    ancestor.cvs[ancestor_cv_idx] = frame.cvs[child_idx].clone();
                                }
                            }
                        }
                    }

                    // Store return value in caller's result slot if specified
                    if let Some((ret_type, ret_slot)) = frame.return_dest {
                        if let Some(caller) = self.call_stack.last_mut() {
                            Self::write_to_slot(caller, ret_type, ret_slot, ret_val);
                        }
                    }
                }
                DispatchSignal::CallPushed => {
                    // New frame was pushed; don't advance IP.
                    // The callee's ip starts at 0.
                }
                DispatchSignal::Yield => {
                    // Generator yielded or fiber suspended — frame already saved.
                    return Ok(());
                }
            }
        }
    }

    /// Convert runtime errors to catchable exception values.
    /// Marked cold because errors are the uncommon path — the hot path is Ok.
    #[cold]
    fn convert_error_to_exception(&self, err: VmError) -> VmError {
        match err {
            VmError::TypeError(msg) => {
                let ex = self.create_error_object("TypeError", msg);
                VmError::Thrown(ex)
            }
            VmError::DivisionByZero => {
                let ex =
                    self.create_error_object("DivisionByZeroError", "Division by zero".to_string());
                VmError::Thrown(ex)
            }
            VmError::MatchError => {
                let ex = self
                    .create_error_object("UnhandledMatchError", "Unhandled match case".to_string());
                VmError::Thrown(ex)
            }
            other => other,
        }
    }

    /// Dispatch a single opcode.
    #[inline]
    pub(crate) fn dispatch_op(&mut self, op: &ZOp, oa_idx: usize) -> VmResult<DispatchSignal> {
        match op.opcode {
            ZOpcode::Nop => Ok(DispatchSignal::Next),

            // =====================================================================
            // Arithmetic
            // =====================================================================
            ZOpcode::Add => self.op_binary(op, oa_idx, |a, b| a.add(&b)),
            ZOpcode::Sub => self.op_binary(op, oa_idx, |a, b| a.sub(&b)),
            ZOpcode::Mul => self.op_binary(op, oa_idx, |a, b| a.mul(&b)),
            ZOpcode::Div => {
                let a = self.read_operand(op, 1, oa_idx)?;
                let b = self.read_operand(op, 2, oa_idx)?;
                let b_is_zero = match &b {
                    Value::Long(0) => true,
                    Value::Double(f) if *f == 0.0 => true,
                    _ => b.to_double() == 0.0,
                };
                let result = if b_is_zero {
                    self.emit_error(2, "Division by zero")?; // E_WARNING
                                                             // PHP 8: int/0 => DivisionByZeroError for int div, but float div returns INF/NAN
                    match (&a, &b) {
                        (Value::Long(_), Value::Long(0)) => {
                            return Err(VmError::DivisionByZero);
                        }
                        _ => {
                            let af = a.to_double();
                            if af == 0.0 {
                                Value::Double(f64::NAN)
                            } else if af > 0.0 {
                                Value::Double(f64::INFINITY)
                            } else {
                                Value::Double(f64::NEG_INFINITY)
                            }
                        }
                    }
                } else {
                    a.div(&b)
                };
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Mod => {
                let a = self.read_operand(op, 1, oa_idx)?;
                let b = self.read_operand(op, 2, oa_idx)?;
                if b.to_long() == 0 {
                    self.emit_error(2, "Division by zero")?; // E_WARNING
                    return Err(VmError::DivisionByZero);
                }
                let result = a.modulo(&b);
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Pow => self.op_binary(op, oa_idx, |a, b| a.pow(&b)),
            ZOpcode::Sl => self.op_binary(op, oa_idx, |a, b| a.shl(&b)),
            ZOpcode::Sr => self.op_binary(op, oa_idx, |a, b| a.shr(&b)),
            ZOpcode::Concat | ZOpcode::FastConcat => {
                let a = self.read_operand(op, 1, oa_idx)?;
                let b = self.read_operand(op, 2, oa_idx)?;
                let sa = self.value_to_string(&a)?;
                let sb = self.value_to_string(&b)?;
                let result = Value::String(format!("{}{}", sa, sb));
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // String Rope Operations (optimized multi-part concatenation)
            // =====================================================================
            ZOpcode::RopeInit => {
                // Start a rope: convert op2 to string, store as _Rope([s]) in result
                let val = self.read_operand(op, 2, oa_idx)?;
                let s = self.value_to_string(&val)?;
                self.write_result(op, oa_idx, Value::_Rope(vec![s]))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RopeAdd => {
                // Append to rope: read rope from op1, push op2's string, write back to result
                let rope_val = self.read_operand(op, 1, oa_idx)?;
                let val = self.read_operand(op, 2, oa_idx)?;
                let s = self.value_to_string(&val)?;
                let mut parts = match rope_val {
                    Value::_Rope(parts) => parts,
                    _ => vec![self.value_to_string(&rope_val)?],
                };
                parts.push(s);
                self.write_result(op, oa_idx, Value::_Rope(parts))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RopeEnd => {
                // Finalize rope: read rope from op1, append op2, join all into a single String
                let rope_val = self.read_operand(op, 1, oa_idx)?;
                let val = self.read_operand(op, 2, oa_idx)?;
                let s = self.value_to_string(&val)?;
                let parts = match rope_val {
                    Value::_Rope(parts) => parts,
                    _ => vec![self.value_to_string(&rope_val)?],
                };
                // Pre-allocate the final string with known total length
                let total_len: usize = parts.iter().map(|p| p.len()).sum::<usize>() + s.len();
                let mut result = String::with_capacity(total_len);
                for part in &parts {
                    result.push_str(part);
                }
                result.push_str(&s);
                self.write_result(op, oa_idx, Value::String(result))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Error Suppression (@ operator)
            // =====================================================================
            ZOpcode::BeginSilence => {
                // Save current error_reporting level and set to 0
                let saved = self.error_reporting_level;
                self.silence_stack.push(saved);
                self.error_reporting_level = 0;
                // Store the saved level in result so EndSilence can restore it
                self.write_result(op, oa_idx, Value::Long(saved))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::EndSilence => {
                // Restore previous error_reporting level
                if let Some(level) = self.silence_stack.pop() {
                    self.error_reporting_level = level;
                }
                Ok(DispatchSignal::Next)
            }

            // Bitwise
            ZOpcode::BwOr => self.op_binary(op, oa_idx, |a, b| a.bw_or(&b)),
            ZOpcode::BwAnd => self.op_binary(op, oa_idx, |a, b| a.bw_and(&b)),
            ZOpcode::BwXor => self.op_binary(op, oa_idx, |a, b| a.bw_xor(&b)),
            ZOpcode::BwNot => self.op_unary(op, oa_idx, |a| a.bw_not()),
            ZOpcode::BoolNot => self.op_unary(op, oa_idx, |a| a.bool_not()),
            ZOpcode::BoolXor => self.op_binary(op, oa_idx, |a, b| a.bool_xor(&b)),

            // =====================================================================
            // Comparison
            // =====================================================================
            ZOpcode::IsEqual => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.loose_eq(&b))),
            ZOpcode::IsNotEqual => self.op_binary(op, oa_idx, |a, b| Value::Bool(!a.loose_eq(&b))),
            ZOpcode::IsIdentical => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.strict_eq(&b))),
            ZOpcode::IsNotIdentical => {
                self.op_binary(op, oa_idx, |a, b| Value::Bool(!a.strict_eq(&b)))
            }
            ZOpcode::IsSmaller => self.op_binary(op, oa_idx, |a, b| Value::Bool(a.is_smaller(&b))),
            ZOpcode::IsSmallerOrEqual => {
                self.op_binary(op, oa_idx, |a, b| Value::Bool(!b.is_smaller(&a)))
            }
            ZOpcode::Spaceship => self.op_binary(op, oa_idx, |a, b| Value::Long(a.spaceship(&b))),
            ZOpcode::Case | ZOpcode::CaseStrict => {
                // CASE: compare op1 (switch value) with op2, result is bool
                let switch_val = self.read_operand(op, 1, oa_idx)?;
                let case_val = self.read_operand(op, 2, oa_idx)?;
                let result = if op.opcode == ZOpcode::CaseStrict {
                    switch_val.strict_eq(&case_val)
                } else {
                    switch_val.loose_eq(&case_val)
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Assignment
            // =====================================================================
            ZOpcode::Assign => {
                let val = self.read_operand(op, 2, oa_idx)?;
                self.write_cv(op, oa_idx, val.clone())?;
                // If result is used, store the assigned value
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, val)?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignRef => {
                // Reference assignment: $a = &$b
                // Creates a shared Reference so both variables point to the same storage.
                let rhs_val = self.read_operand(op, 2, oa_idx)?;

                // Check if the RHS temp came from indexing into a Reference
                // (e.g., $array = &$array[$key] where $array is a Reference)
                let dim_ref_info = if matches!(op.op2_type, OperandType::TmpVar | OperandType::Var)
                {
                    let frame = self.call_stack.last().unwrap();
                    frame
                        .temp_dim_ref_source
                        .get(&(op.op2.val as usize))
                        .cloned()
                } else {
                    None
                };

                let ref_val = if let Some((parent_rc, dim_key)) = dim_ref_info {
                    // RHS came from $ref[$key] — create or share a sub-reference
                    // Check if the element in the parent array is already a Reference
                    let parent_inner = parent_rc.borrow();
                    let existing_ref = if let Value::Array(ref arr) = *parent_inner {
                        arr.get(&dim_key).and_then(|v| {
                            if let Value::Reference(rc) = v {
                                Some(Value::Reference(rc.clone()))
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    };
                    drop(parent_inner);

                    if let Some(existing) = existing_ref {
                        // Element is already a Reference — share it
                        existing
                    } else {
                        // Create a new sub-reference
                        let element_val = rhs_val.deref_value();
                        let sub_rc = Rc::new(RefCell::new(element_val));
                        let sub_ref = Value::Reference(sub_rc);
                        // Store the sub-reference back into the parent array
                        let mut parent_inner = parent_rc.borrow_mut();
                        if let Value::Array(ref mut arr) = *parent_inner {
                            arr.set(&dim_key, sub_ref.clone());
                        }
                        sub_ref
                    }
                } else if let Value::Reference(_) = &rhs_val {
                    // RHS is already a Reference, share the same Rc
                    rhs_val.clone()
                } else {
                    // Create a new Reference wrapping the value
                    let rc = Rc::new(RefCell::new(rhs_val));
                    let ref_val = Value::Reference(rc);
                    // Also store back in rhs source to make it a Reference
                    if op.op2_type == OperandType::Cv {
                        let frame = self.call_stack.last_mut().unwrap();
                        let cv_idx = op.op2.val as usize;
                        if cv_idx < frame.cvs.len() {
                            frame.cvs[cv_idx] = ref_val.clone();
                        }
                    }
                    ref_val
                };

                // For AssignRef, always replace the CV directly (don't write through
                // an existing reference). This ensures $a = &$a[$key] re-seats the
                // binding instead of modifying the old referent.
                if op.op1_type == OperandType::Cv {
                    let idx = op.op1.val as usize;
                    let frame = self.call_stack.last_mut().unwrap();
                    if idx >= frame.cvs.len() {
                        frame.cvs.resize(idx + 1, Value::Null);
                    }
                    frame.cvs[idx] = ref_val.clone();
                }
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, ref_val)?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignDim => {
                // $arr[$key] = $val
                // op1 = array (CV or TmpVar/Var), op2 = key (or Unused for append), next op is OP_DATA with value
                let arr_idx = op.op1.val as usize;
                let arr_op1_type = op.op1_type;
                let key = if op.op2_type != OperandType::Unused {
                    Some(self.read_operand(op, 2, oa_idx)?)
                } else {
                    None
                };

                // Look ahead for OP_DATA
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let val = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if data_op.opcode == ZOpcode::OpData {
                        self.read_operand_from(data_op, 1, oa_idx)?
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let frame = self.call_stack.last_mut().unwrap();
                let arr_val = match arr_op1_type {
                    OperandType::Cv => &mut frame.cvs[arr_idx],
                    OperandType::TmpVar | OperandType::Var => {
                        if arr_idx >= frame.temps.len() {
                            frame.temps.resize(arr_idx + 1, Value::Null);
                        }
                        &mut frame.temps[arr_idx]
                    }
                    _ => {
                        // Skip OP_DATA
                        self.call_stack.last_mut().unwrap().ip += 1;
                        return Ok(DispatchSignal::Next);
                    }
                };
                // Handle References: modify the inner value
                if let Value::Reference(rc) = arr_val {
                    let mut inner = rc.borrow_mut();
                    // Handle ArrayAccess on referenced objects
                    if let Value::Object(ref obj) = *inner {
                        let class_name = obj.class_name();
                        let k = key.clone().unwrap_or(Value::Null);
                        let obj_clone = obj.clone();
                        drop(inner);
                        self.call_stack.last_mut().unwrap().ip += 1;
                        let method_name = format!("{}::offsetSet", class_name);
                        self.invoke_user_callback(
                            &method_name,
                            vec![Value::Object(obj_clone), k, val],
                        )?;
                        return Ok(DispatchSignal::Next);
                    }
                    if matches!(*inner, Value::Null) {
                        *inner = Value::Array(PhpArray::new());
                    }
                    let assigned_val = val.clone();
                    if let Value::Array(ref mut arr) = *inner {
                        match key {
                            Some(k) => arr.set(&k, val),
                            None => arr.push(val),
                        }
                    }
                    drop(inner);
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, oa_idx, assigned_val)?;
                    }
                    // Skip OP_DATA
                    self.call_stack.last_mut().unwrap().ip += 1;
                    return Ok(DispatchSignal::Next);
                }
                // Handle objects implementing ArrayAccess
                if let Value::Object(ref obj) = arr_val {
                    let class_name = obj.class_name();
                    let k = key.clone().unwrap_or(Value::Null);
                    let obj_clone = obj.clone();
                    // Skip OP_DATA before making the method call
                    self.call_stack.last_mut().unwrap().ip += 1;
                    // Call offsetSet($key, $value)
                    let method_name = format!("{}::offsetSet", class_name);
                    self.invoke_user_callback(
                        &method_name,
                        vec![Value::Object(obj_clone), k, val],
                    )?;
                    return Ok(DispatchSignal::Next);
                }
                // Ensure it's an array
                if matches!(arr_val, Value::Null) {
                    *arr_val = Value::Array(PhpArray::new());
                }
                let assigned_val = val.clone();
                if let Value::Array(ref mut arr) = arr_val {
                    match key {
                        Some(k) => arr.set(&k, val),
                        None => arr.push(val),
                    }
                }

                // Write the assigned value to the result slot
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, assigned_val)?;
                }

                // Write-back to static property if this temp was from FETCH_STATIC_PROP_W
                if matches!(arr_op1_type, OperandType::TmpVar | OperandType::Var) {
                    let frame = self.call_stack.last().unwrap();
                    let wb: Option<(String, String)> = frame
                        .static_prop_write_back
                        .iter()
                        .find(|(slot, _, _)| *slot == arr_idx)
                        .map(|(_, class, prop)| (class.clone(), prop.clone()));
                    if let Some((class_name, prop_name)) = wb {
                        let new_val = self.call_stack.last().unwrap().temps[arr_idx].clone();
                        if let Some(class_def) = self.classes.get_mut(&class_name) {
                            class_def.static_properties.insert(prop_name, new_val);
                        }
                    }
                }

                // Skip OP_DATA
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignOp => {
                // Compound assignment: +=, -=, etc.
                // op1 = CV or TmpVar/Var, op2 = value, extended_value = operation
                let idx = op.op1.val as usize;
                let rhs = self.read_operand(op, 2, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                let lhs = match op.op1_type {
                    OperandType::Cv => {
                        if idx < frame.cvs.len() {
                            frame.cvs[idx].clone()
                        } else {
                            Value::Null
                        }
                    }
                    OperandType::TmpVar | OperandType::Var => {
                        if idx < frame.temps.len() {
                            frame.temps[idx].clone()
                        } else {
                            Value::Null
                        }
                    }
                    _ => Value::Null,
                };
                // Handle ??= (Coalesce = 169) specially
                let result = if op.extended_value == ZOpcode::Coalesce as u8 as u32 {
                    if matches!(lhs, Value::Null) {
                        rhs
                    } else {
                        lhs
                    }
                } else if op.extended_value == 8 {
                    // CONCAT — use value_to_string for __toString support
                    let sa = self.value_to_string(&lhs)?;
                    let sb = self.value_to_string(&rhs)?;
                    Value::String(format!("{}{}", sa, sb))
                } else {
                    apply_assign_op(op.extended_value, &lhs, &rhs)
                };
                let frame = self.call_stack.last_mut().unwrap();
                match op.op1_type {
                    OperandType::Cv => {
                        if idx < frame.cvs.len() {
                            frame.cvs[idx] = result.clone();
                        }
                    }
                    OperandType::TmpVar | OperandType::Var => {
                        if idx >= frame.temps.len() {
                            frame.temps.resize(idx + 1, Value::Null);
                        }
                        frame.temps[idx] = result.clone();
                    }
                    _ => {}
                }
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, result)?;
                }
                Ok(DispatchSignal::Next)
            }

            ZOpcode::AssignDimOp => {
                // $a[$k] op= $val
                // op1 = array (CV), op2 = key, extended_value = operation
                // Next instruction is OpData with the RHS value
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let rhs = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if data_op.opcode == ZOpcode::OpData {
                        self.read_operand_from(data_op, 1, oa_idx)?
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let cv_idx = op.op1.val as usize;
                let key = if op.op2_type != OperandType::Unused {
                    self.read_operand(op, 2, oa_idx)?
                } else {
                    Value::Null
                };

                let frame = self.call_stack.last_mut().unwrap();
                if cv_idx < frame.cvs.len() {
                    if let Value::Array(ref mut arr) = frame.cvs[cv_idx] {
                        let old = arr.get(&key).cloned().unwrap_or(Value::Null);
                        let result = if op.extended_value == ZOpcode::Coalesce as u8 as u32 {
                            if matches!(old, Value::Null) {
                                rhs
                            } else {
                                old
                            }
                        } else if op.extended_value == 8 {
                            Value::String(format!("{}{}", old.to_php_string(), rhs.to_php_string()))
                        } else {
                            apply_assign_op(op.extended_value, &old, &rhs)
                        };
                        arr.set(&key, result.clone());
                        if op.result_type != OperandType::Unused {
                            let ridx = op.result.val as usize;
                            if ridx >= frame.temps.len() {
                                frame.temps.resize(ridx + 1, Value::Null);
                            }
                            frame.temps[ridx] = result;
                        }
                    }
                }

                // Skip OpData
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignObjOp => {
                // $obj->prop op= $val
                // op1 = object, op2 = property name, extended_value = operation
                // Next instruction is OpData with the RHS value
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let rhs = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if data_op.opcode == ZOpcode::OpData {
                        self.read_operand_from(data_op, 1, oa_idx)?
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let obj_val = self.read_operand(op, 1, oa_idx)?.deref_value();
                let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

                if let Value::Object(ref obj) = obj_val {
                    let old = obj.get_property(&prop_name).unwrap_or(Value::Null);
                    let result = if op.extended_value == ZOpcode::Coalesce as u8 as u32 {
                        if matches!(old, Value::Null) {
                            rhs
                        } else {
                            old
                        }
                    } else if op.extended_value == 8 {
                        let sa = self.value_to_string(&old)?;
                        let sb = self.value_to_string(&rhs)?;
                        Value::String(format!("{}{}", sa, sb))
                    } else {
                        apply_assign_op(op.extended_value, &old, &rhs)
                    };
                    obj.set_property(prop_name, result.clone());
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, oa_idx, result)?;
                    }
                }

                // Skip OpData
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignStaticPropOp => {
                // ClassName::$prop op= $val
                // op1 = property name (Const), op2 = class name (Const), extended_value = operation
                // Next instruction is OpData with the RHS value
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let rhs = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let data_op = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if data_op.opcode == ZOpcode::OpData {
                        self.read_operand_from(data_op, 1, oa_idx)?
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let resolved = self.resolve_class_name(&class_name);
                let owner = self.find_static_prop_owner(&resolved, &prop_name);

                let old = self
                    .classes
                    .get(&owner)
                    .and_then(|c| c.static_properties.get(&prop_name).cloned())
                    .unwrap_or(Value::Null);

                let result = if op.extended_value == ZOpcode::Coalesce as u8 as u32 {
                    if matches!(old, Value::Null) {
                        rhs
                    } else {
                        old
                    }
                } else if op.extended_value == 8 {
                    let sa = self.value_to_string(&old)?;
                    let sb = self.value_to_string(&rhs)?;
                    Value::String(format!("{}{}", sa, sb))
                } else {
                    apply_assign_op(op.extended_value, &old, &rhs)
                };

                if let Some(class_def) = self.classes.get_mut(&owner) {
                    class_def
                        .static_properties
                        .insert(prop_name, result.clone());
                }

                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, result)?;
                }

                // Skip OpData
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignObjRef => {
                // $obj->prop =& $var
                // op1 = object, op2 = property name, next = OpData with RHS
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let data_op = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let d = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if d.opcode == ZOpcode::OpData {
                        Some(d.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                let rhs = if let Some(ref d) = data_op {
                    self.read_operand_from(d, 1, oa_idx)?
                } else {
                    Value::Null
                };

                let obj_val = self.read_operand(op, 1, oa_idx)?.deref_value();
                let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

                if let Value::Object(ref obj) = obj_val {
                    // Create or share a reference
                    let ref_val = if let Value::Reference(_) = &rhs {
                        rhs.clone()
                    } else {
                        let rc = Rc::new(RefCell::new(rhs.deref_value()));
                        Value::Reference(rc)
                    };

                    // Also make the RHS variable a reference if it's a CV
                    if !matches!(&rhs, Value::Reference(_)) {
                        if let Some(ref d) = data_op {
                            if d.op1_type == OperandType::Cv {
                                let frame = self.call_stack.last_mut().unwrap();
                                let cv_idx = d.op1.val as usize;
                                if cv_idx < frame.cvs.len() {
                                    frame.cvs[cv_idx] = ref_val.clone();
                                }
                            }
                        }
                    }

                    obj.set_property(prop_name, ref_val.clone());
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, oa_idx, ref_val)?;
                    }
                }

                // Skip OpData
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignStaticPropRef => {
                // ClassName::$prop =& $var
                // op1 = property name (Const), op2 = class name (Const), next = OpData with RHS
                let frame = self.call_stack.last().unwrap();
                let next_ip = frame.ip + 1;
                let data_op = if next_ip < self.op_arrays[oa_idx].opcodes.len() {
                    let d = &self.op_arrays[oa_idx].opcodes[next_ip];
                    if d.opcode == ZOpcode::OpData {
                        Some(d.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                let rhs = if let Some(ref d) = data_op {
                    self.read_operand_from(d, 1, oa_idx)?
                } else {
                    Value::Null
                };

                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let resolved = self.resolve_class_name(&class_name);
                let owner = self.find_static_prop_owner(&resolved, &prop_name);

                // Create or share a reference
                let ref_val = if let Value::Reference(_) = &rhs {
                    rhs.clone()
                } else {
                    let rc = Rc::new(RefCell::new(rhs.deref_value()));
                    Value::Reference(rc)
                };

                // Also make the RHS variable a reference if it's a CV
                if !matches!(&rhs, Value::Reference(_)) {
                    if let Some(ref d) = data_op {
                        if d.op1_type == OperandType::Cv {
                            let frame = self.call_stack.last_mut().unwrap();
                            let cv_idx = d.op1.val as usize;
                            if cv_idx < frame.cvs.len() {
                                frame.cvs[cv_idx] = ref_val.clone();
                            }
                        }
                    }
                }

                if let Some(class_def) = self.classes.get_mut(&owner) {
                    class_def
                        .static_properties
                        .insert(prop_name, ref_val.clone());
                }
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, ref_val)?;
                }

                // Skip OpData
                self.call_stack.last_mut().unwrap().ip += 1;
                Ok(DispatchSignal::Next)
            }

            // Increment / Decrement
            ZOpcode::PreInc => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let new_val = if let Value::Reference(ref rc) = frame.cvs[cv_idx] {
                    let inner = rc.borrow().clone();
                    let nv = inner.increment();
                    *rc.borrow_mut() = nv.clone();
                    nv
                } else {
                    let nv = frame.cvs[cv_idx].increment();
                    frame.cvs[cv_idx] = nv.clone();
                    nv
                };
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = new_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PreDec => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let new_val = if let Value::Reference(ref rc) = frame.cvs[cv_idx] {
                    let inner = rc.borrow().clone();
                    let nv = inner.decrement();
                    *rc.borrow_mut() = nv.clone();
                    nv
                } else {
                    let nv = frame.cvs[cv_idx].decrement();
                    frame.cvs[cv_idx] = nv.clone();
                    nv
                };
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = new_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PostInc => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let old_val = if let Value::Reference(ref rc) = frame.cvs[cv_idx] {
                    let inner = rc.borrow().clone();
                    *rc.borrow_mut() = inner.increment();
                    inner
                } else {
                    let old = frame.cvs[cv_idx].clone();
                    frame.cvs[cv_idx] = old.increment();
                    old
                };
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = old_val;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::PostDec => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let old_val = if let Value::Reference(ref rc) = frame.cvs[cv_idx] {
                    let inner = rc.borrow().clone();
                    *rc.borrow_mut() = inner.decrement();
                    inner
                } else {
                    let old = frame.cvs[cv_idx].clone();
                    frame.cvs[cv_idx] = old.decrement();
                    old
                };
                if op.result_type != OperandType::Unused {
                    let slot = op.result.val as usize;
                    frame.temps[slot] = old_val;
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Inc/Dec on Object Properties
            // =====================================================================
            ZOpcode::PreIncObj | ZOpcode::PreDecObj | ZOpcode::PostIncObj | ZOpcode::PostDecObj => {
                let obj_val = self.read_operand(op, 1, oa_idx)?;
                let prop_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let is_inc = matches!(op.opcode, ZOpcode::PreIncObj | ZOpcode::PostIncObj);
                let is_pre = matches!(op.opcode, ZOpcode::PreIncObj | ZOpcode::PreDecObj);

                if let Value::Object(ref obj) = obj_val {
                    let old_val = obj.get_property(&prop_name).unwrap_or(Value::Null);
                    let new_val = if is_inc {
                        old_val.increment()
                    } else {
                        old_val.decrement()
                    };
                    obj.set_property(prop_name, new_val.clone());
                    let result = if is_pre { new_val } else { old_val };
                    if op.result_type != OperandType::Unused {
                        self.write_result(op, oa_idx, result)?;
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Inc/Dec on Static Properties
            // =====================================================================
            ZOpcode::PreIncStaticProp
            | ZOpcode::PreDecStaticProp
            | ZOpcode::PostIncStaticProp
            | ZOpcode::PostDecStaticProp => {
                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let raw_class = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let class_name = self.resolve_class_name(&raw_class);
                let is_inc = matches!(
                    op.opcode,
                    ZOpcode::PreIncStaticProp | ZOpcode::PostIncStaticProp
                );
                let is_pre = matches!(
                    op.opcode,
                    ZOpcode::PreIncStaticProp | ZOpcode::PreDecStaticProp
                );

                let owner = self.find_static_prop_owner(&class_name, &prop_name);
                let old_val = self
                    .classes
                    .get(&owner)
                    .and_then(|c| c.static_properties.get(&prop_name).cloned())
                    .unwrap_or(Value::Null);
                let new_val = if is_inc {
                    old_val.increment()
                } else {
                    old_val.decrement()
                };
                if let Some(class_def) = self.classes.get_mut(&owner) {
                    class_def
                        .static_properties
                        .insert(prop_name, new_val.clone());
                }
                let result = if is_pre { new_val } else { old_val };
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, result)?;
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Variable access
            // =====================================================================
            ZOpcode::QmAssign | ZOpcode::Bool => {
                // QM_ASSIGN: copy op1 to result (used for ternary, etc.)
                // BOOL: convert op1 to boolean in result
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = if op.opcode == ZOpcode::Bool {
                    Value::Bool(val.to_bool())
                } else {
                    val
                };
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchDimR | ZOpcode::FetchDimIs => {
                // Array read: op1[$op2] → result
                let arr_raw = self.read_operand(op, 1, oa_idx)?;
                let key = self.read_operand(op, 2, oa_idx)?;

                // If arr is a Reference, track it for potential AssignRef use
                if let Value::Reference(ref rc) = arr_raw {
                    if matches!(op.result_type, OperandType::TmpVar | OperandType::Var) {
                        let frame = self.call_stack.last_mut().unwrap();
                        frame
                            .temp_dim_ref_source
                            .insert(op.result.val as usize, (rc.clone(), key.clone()));
                    }
                }

                // Auto-deref Reference for array access
                let arr = arr_raw.deref_value();
                let val = if let Value::Array(ref a) = arr {
                    // Dereference element values — references inside arrays should be
                    // transparent when reading (FetchDimR is a read-only fetch).
                    a.get(&key).cloned().unwrap_or(Value::Null).deref_value()
                } else if let Value::String(ref s) = arr {
                    // String character access (supports negative indices)
                    let idx = key.to_long();
                    let actual_idx = if idx < 0 {
                        (s.len() as i64 + idx) as usize
                    } else {
                        idx as usize
                    };
                    if actual_idx < s.len() {
                        Value::String(
                            s.as_bytes()
                                .get(actual_idx)
                                .map(|&b| (b as char).to_string())
                                .unwrap_or_default(),
                        )
                    } else {
                        Value::String(String::new())
                    }
                } else if let Value::Object(ref obj) = arr {
                    // ArrayAccess: call offsetGet($key) on the object
                    let class = obj.class_name();
                    let method = format!("{}::offsetGet", class);
                    // Try builtin method dispatch first (SplFixedArray, SplDLL, etc.)
                    let obj_clone = obj.clone();
                    if let Some(result) =
                        self.call_builtin_method(&method, &[Value::Object(obj_clone), key.clone()])?
                    {
                        result
                    } else {
                        let method_idx = self
                            .functions
                            .get(&method)
                            .copied()
                            .or_else(|| self.resolve_method(&class, "offsetGet"));
                        if let Some(oa_idx) = method_idx {
                            let saved_depth = self.call_stack.len();
                            let func_oa = &self.op_arrays[oa_idx];
                            let mut frame = Frame::new(func_oa);
                            frame.op_array_idx = oa_idx;
                            self.populate_superglobals(&mut frame, func_oa);
                            frame.args = vec![key.clone()];
                            // Set $this
                            if let Some(this_cv) = func_oa.vars.iter().position(|v| v == "this") {
                                if this_cv < frame.cvs.len() {
                                    frame.cvs[this_cv] = arr.clone();
                                }
                            }
                            // Set first param CV
                            if !func_oa.arg_info.is_empty() && !frame.cvs.is_empty() {
                                let param_cv = func_oa
                                    .vars
                                    .iter()
                                    .position(|v| *v == func_oa.arg_info[0].name)
                                    .unwrap_or(0);
                                if param_cv < frame.cvs.len() {
                                    frame.cvs[param_cv] = key.clone();
                                }
                            }
                            self.call_stack.push(frame);
                            let _ = self.dispatch_loop_until(saved_depth);
                            self.last_return_value.clone()
                        } else {
                            Value::Null
                        }
                    }
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchDimW
            | ZOpcode::FetchDimRw
            | ZOpcode::FetchDimFuncArg
            | ZOpcode::FetchDimUnset => {
                // Write/read-write/func-arg/unset modes for array dimension access.
                // Same read logic as FetchDimR, but we track the source for write-back.
                let arr_raw = self.read_operand(op, 1, oa_idx)?;
                let key = if op.op2_type != OperandType::Unused {
                    self.read_operand(op, 2, oa_idx)?
                } else {
                    Value::Null
                };

                // Track reference source for write-back
                if let Value::Reference(ref rc) = arr_raw {
                    if matches!(op.result_type, OperandType::TmpVar | OperandType::Var) {
                        let frame = self.call_stack.last_mut().unwrap();
                        frame
                            .temp_dim_ref_source
                            .insert(op.result.val as usize, (rc.clone(), key.clone()));
                    }
                }

                let arr = arr_raw.deref_value();
                let val = if let Value::Array(ref a) = arr {
                    if op.op2_type == OperandType::Unused {
                        // $arr[] in write context — return empty array (will be assigned to)
                        Value::Null
                    } else {
                        a.get(&key).cloned().unwrap_or(Value::Null)
                    }
                } else if let Value::String(ref s) = arr {
                    let idx = key.to_long();
                    let actual_idx = if idx < 0 {
                        (s.len() as i64 + idx) as usize
                    } else {
                        idx as usize
                    };
                    if actual_idx < s.len() {
                        Value::String(
                            s.as_bytes()
                                .get(actual_idx)
                                .map(|&b| (b as char).to_string())
                                .unwrap_or_default(),
                        )
                    } else {
                        Value::String(String::new())
                    }
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchListR => {
                // list() destructuring read: same as FetchDimR
                let arr_raw = self.read_operand(op, 1, oa_idx)?;
                let key = self.read_operand(op, 2, oa_idx)?;
                let arr = arr_raw.deref_value();
                let val = if let Value::Array(ref a) = arr {
                    a.get(&key).cloned().unwrap_or(Value::Null).deref_value()
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchListW => {
                // list() destructuring write: same as FetchDimW
                let arr_raw = self.read_operand(op, 1, oa_idx)?;
                let key = self.read_operand(op, 2, oa_idx)?;
                let arr = arr_raw.deref_value();
                let val = if let Value::Array(ref a) = arr {
                    a.get(&key).cloned().unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyCv => {
                // Check if CV is set and not null (isset) or empty
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let val = &frame.cvs[cv_idx];
                // extended_value: 0x0200000 = ISSET, 0x0100000 = EMPTY
                let result = if op.extended_value & 1 != 0 {
                    // empty()
                    !val.to_bool()
                } else {
                    // isset()
                    !val.is_null()
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyDimObj => {
                // isset($arr[$key]) / empty($arr[$key]) / isset($obj->prop) / isset($str[$idx])
                let arr = self.read_operand(op, 1, oa_idx)?.deref_value();
                let key = self.read_operand(op, 2, oa_idx)?;
                let val = match &arr {
                    Value::Array(ref a) => a.get(&key).cloned().unwrap_or(Value::Null),
                    Value::Object(ref obj) => {
                        // isset($obj->prop) — check if property exists and is not null
                        let prop_name = key.to_php_string();
                        let resolved = self.resolve_private_property_key(&obj.class_name(), &prop_name);
                        obj.get_property(&resolved).unwrap_or(Value::Null)
                    }
                    Value::String(ref s) => {
                        // isset($str[$idx]) — check if index is within bounds (negative OK)
                        let raw_idx = key.to_long();
                        let actual_idx = if raw_idx < 0 {
                            (s.len() as i64 + raw_idx) as usize
                        } else {
                            raw_idx as usize
                        };
                        if actual_idx < s.len() {
                            Value::String(s[actual_idx..actual_idx + 1].to_string())
                        } else {
                            Value::Null
                        }
                    }
                    _ => Value::Null,
                };
                let result = if op.extended_value & 1 != 0 {
                    !val.to_bool() // empty
                } else {
                    !val.is_null() // isset
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetCv => {
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                frame.cvs[cv_idx] = Value::Null;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetDim => {
                // unset($arr[$key])
                let slot = op.op1.val as usize;
                let key = self.read_operand(op, 2, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                match op.op1_type {
                    OperandType::Cv => {
                        if slot < frame.cvs.len() {
                            match &mut frame.cvs[slot] {
                                Value::Array(ref mut arr) => {
                                    arr.unset(&key);
                                }
                                Value::Reference(rc) => {
                                    let mut inner = rc.borrow_mut();
                                    if let Value::Array(ref mut arr) = *inner {
                                        arr.unset(&key);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    OperandType::TmpVar | OperandType::Var => {
                        // Temp/var — modify in place, then write back to object property if needed
                        if let Some(val) = frame.temps.get_mut(slot) {
                            if let Value::Array(ref mut arr) = val {
                                arr.unset(&key);
                            }
                        }
                        // Write back to source object property if this temp came from FetchObjW
                        if let Some((obj_val, prop_name)) =
                            frame.temp_prop_source.get(&slot).cloned()
                        {
                            if let Value::Object(ref obj) = obj_val {
                                if let Some(new_val) = frame.temps.get(slot).cloned() {
                                    obj.set_property(prop_name, new_val);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetObj => {
                // unset($obj->prop)
                let obj_val = self.read_operand(op, 1, oa_idx)?;
                let prop = self.read_operand(op, 2, oa_idx)?;
                let deref_val = obj_val.deref_value();
                if let Value::Object(ref obj) = deref_val {
                    let prop_name = prop.to_php_string();
                    if obj.has_property(&prop_name) {
                        // Property exists — remove it directly
                        obj.remove_property(&prop_name);
                    } else {
                        // Property doesn't exist — try __unset magic method
                        let class_name = obj.class_name();
                        if let Some(magic) = self.find_magic_method(&class_name, "__unset") {
                            self.call_magic_method(
                                &magic,
                                deref_val.clone(),
                                vec![Value::String(prop_name)],
                            )?;
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetStaticProp => {
                // unset(ClassName::$prop)
                // op1 = property name (Const), op2 = class name (Const)
                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let resolved = self.resolve_class_name(&class_name);
                let owner = self.find_static_prop_owner(&resolved, &prop_name);
                if let Some(class_def) = self.classes.get_mut(&owner) {
                    class_def.static_properties.remove(&prop_name);
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyPropObj => {
                // isset($obj->prop) / empty($obj->prop) — dedicated property opcode
                let obj_val = self.read_operand(op, 1, oa_idx)?.deref_value();
                let prop = self.read_operand(op, 2, oa_idx)?;
                let prop_name = prop.to_php_string();
                let result = if let Value::Object(ref obj) = obj_val {
                    match obj.get_property(&prop_name) {
                        Some(v) => {
                            // Property exists — check its value directly
                            if op.extended_value & 1 != 0 {
                                !v.to_bool() // empty
                            } else {
                                !v.is_null() // isset
                            }
                        }
                        None => {
                            // Property not found — try __isset magic method
                            let class_name = obj.class_name();
                            if let Some(magic) = self.find_magic_method(&class_name, "__isset") {
                                let magic_result = self.call_magic_method(
                                    &magic,
                                    obj_val.clone(),
                                    vec![Value::String(prop_name.clone())],
                                )?;
                                if op.extended_value & 1 != 0 {
                                    !magic_result.to_bool() // empty
                                } else {
                                    magic_result.to_bool() // isset
                                }
                            } else {
                                // No __isset, no property
                                op.extended_value & 1 != 0 // empty=true, isset=false
                            }
                        }
                    }
                } else {
                    op.extended_value & 1 != 0 // empty=true, isset=false
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyStaticProp => {
                // isset(ClassName::$prop) / empty(ClassName::$prop)
                // op1 = property name (Const), op2 = class name (Const)
                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let class_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let resolved = self.resolve_class_name(&class_name);
                let owner = self.find_static_prop_owner(&resolved, &prop_name);
                let val = self
                    .classes
                    .get(&owner)
                    .and_then(|c| c.static_properties.get(&prop_name).cloned())
                    .unwrap_or(Value::Null);
                let result = if op.extended_value & 1 != 0 {
                    !val.to_bool() // empty
                } else {
                    !val.is_null() // isset
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyThis => {
                // isset($this) — true if $this CV is set in the current frame
                let frame = self.call_stack.last().unwrap();
                let oa = &self.op_arrays[frame.op_array_idx];
                let this_val = oa
                    .vars
                    .iter()
                    .position(|v| v == "this")
                    .and_then(|idx| frame.cvs.get(idx).cloned())
                    .unwrap_or(Value::Null);
                let result = if op.extended_value & 1 != 0 {
                    // empty($this) — objects are always truthy
                    !this_val.to_bool()
                } else {
                    // isset($this)
                    !this_val.is_null()
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::IssetIsemptyVar => {
                // isset($$name) / empty($$name) — variable-variable isset/empty
                let var_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.fetch_variable_by_name(&var_name);
                let result = if op.extended_value & 1 != 0 {
                    !val.to_bool() // empty
                } else {
                    !val.is_null() // isset
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::UnsetVar => {
                // unset($$name) — variable-variable unset
                let var_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                // Search current frame first
                let frame = self.call_stack.last_mut().unwrap();
                let oa = &self.op_arrays[frame.op_array_idx];
                if let Some(idx) = oa.vars.iter().position(|v| v == &var_name) {
                    if idx < frame.cvs.len() {
                        frame.cvs[idx] = Value::Null;
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Control flow
            // =====================================================================
            ZOpcode::Jmp => {
                let target = op.op1.val as usize;
                Ok(DispatchSignal::Jump(target))
            }
            ZOpcode::Jmpz => {
                let val = self.read_operand(op, 1, oa_idx)?;
                if !val.to_bool() {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Jmpnz => {
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.to_bool() {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpzEx => {
                // Jump if zero, also store bool result
                let val = self.read_operand(op, 1, oa_idx)?;
                let b = val.to_bool();
                self.write_result(op, oa_idx, Value::Bool(b))?;
                if !b {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpnzEx => {
                // Jump if non-zero, also store bool result
                let val = self.read_operand(op, 1, oa_idx)?;
                let b = val.to_bool();
                self.write_result(op, oa_idx, Value::Bool(b))?;
                if b {
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpSet => {
                // $a ?: $b — if op1 is truthy, result = op1 and jump
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.to_bool() {
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Coalesce => {
                // $a ?? $b — if op1 is not null, result = op1 and jump
                let val = self.read_operand(op, 1, oa_idx)?;
                if !val.is_null() {
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::JmpNull => {
                // JMP_NULL: if op1 is null, set result to null and jump to op2
                let val = self.read_operand(op, 1, oa_idx)?;
                if val.is_null() {
                    self.write_result(op, oa_idx, Value::Null)?;
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                } else {
                    // Pass the value through to result for chained access
                    self.write_result(op, oa_idx, val)?;
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Match => {
                // MATCH: compare op1 against a jump table
                // For simplicity, we treat it like a NOP and let CASE_STRICT do the work
                Ok(DispatchSignal::Next)
            }
            ZOpcode::MatchError => Err(VmError::MatchError),

            // Foreach
            ZOpcode::FeResetR => {
                // Initialize foreach iterator
                let arr = self.read_operand(op, 1, oa_idx)?;
                match &arr {
                    Value::Array(a) => {
                        let iter = Value::_Iterator {
                            array: a.clone(),
                            index: 0,
                        };
                        self.write_result(op, oa_idx, iter)?;
                        Ok(DispatchSignal::Next)
                    }
                    Value::Object(o) if o.internal() == crate::value::InternalState::Generator => {
                        let obj_id = o.object_id();
                        // Initialize the generator
                        self.ensure_generator_initialized(obj_id)?;
                        let iter = Value::_GeneratorIterator {
                            object_id: obj_id,
                            needs_advance: false,
                        };
                        self.write_result(op, oa_idx, iter)?;
                        Ok(DispatchSignal::Next)
                    }
                    Value::Object(o) => {
                        // Object implementing Iterator or IteratorAggregate
                        let class_name = o.class_name().to_string();
                        // Check if this is a builtin iterator (has __dir_entries or __inner_iterator)
                        let base_cn = class_name.rsplit('\\').next().unwrap_or(&class_name);
                        let is_builtin_iterator = o.get_property("__dir_entries").is_some()
                            || o.get_property("__inner_iterator").is_some()
                            || o.get_property("__array_data").is_some()
                            || o.get_property("__spl_data").is_some()
                            || o.get_property("__dll_data").is_some()
                            || o.get_property("__heap_data").is_some()
                            || o.get_property("__sos_objects").is_some()
                            || o.get_property("__period_entries").is_some()
                            || o.get_property("__append_iterators").is_some()
                            || o.get_property("__limit_offset").is_some()
                            || o.get_property("__multi_iterators").is_some()
                            || o.get_property("__sfo_lines").is_some()
                            || o.get_property("__cache_valid").is_some()
                            || o.get_property("__regex_pattern").is_some()
                            || matches!(
                                base_cn,
                                "EmptyIterator"
                                    | "AppendIterator"
                                    | "MultipleIterator"
                                    | "LimitIterator"
                                    | "InfiniteIterator"
                                    | "NoRewindIterator"
                                    | "CachingIterator"
                                    | "RegexIterator"
                                    | "RecursiveRegexIterator"
                                    | "SplFileObject"
                                    | "SplTempFileObject"
                            );
                        // Check for getIterator (IteratorAggregate)
                        let iter_obj = if self.resolve_method(&class_name, "getIterator").is_some()
                        {
                            match self.call_method_sync(&arr, "getIterator") {
                                Ok(Value::Object(it)) => it,
                                Ok(_) => {
                                    return Ok(DispatchSignal::Jump(op.op2.val as usize));
                                }
                                Err(_) => {
                                    return Ok(DispatchSignal::Jump(op.op2.val as usize));
                                }
                            }
                        } else if is_builtin_iterator
                            || self.resolve_method(&class_name, "current").is_some()
                        {
                            // Direct Iterator (user-defined or builtin)
                            o.clone()
                        } else {
                            // Not iterable — iterate over public properties as an array
                            let mut arr_val = PhpArray::new();
                            for (k, v) in o.properties() {
                                arr_val.set_string(k, v);
                            }
                            let iter = Value::_Iterator {
                                array: arr_val,
                                index: 0,
                            };
                            self.write_result(op, oa_idx, iter)?;
                            return Ok(DispatchSignal::Next);
                        };
                        // Call rewind() on the iterator
                        let iter_val = Value::Object(iter_obj.clone());
                        let _ = self.call_method_sync(&iter_val, "rewind");
                        let iter = Value::_ObjectIterator {
                            iterator: iter_obj,
                            first: true,
                        };
                        self.write_result(op, oa_idx, iter)?;
                        Ok(DispatchSignal::Next)
                    }
                    Value::Reference(rc) => {
                        // Dereference and handle
                        let inner = rc.borrow().deref_value();
                        if let Value::Array(a) = inner {
                            let iter = Value::_Iterator { array: a, index: 0 };
                            self.write_result(op, oa_idx, iter)?;
                            Ok(DispatchSignal::Next)
                        } else {
                            Ok(DispatchSignal::Jump(op.op2.val as usize))
                        }
                    }
                    _ => {
                        // Jump to end if not iterable
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                }
            }
            ZOpcode::FeFetchR => {
                // Fetch current element: op1 = iterator, result = value
                // op2 = jump target when exhausted
                // The following OpData opcode (if present) holds the key dest.
                let iter_slot = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let ip = frame.ip;
                let iter = frame.temps[iter_slot].clone();

                // Check if the next opcode is OpData (for key variable)
                let key_dest = {
                    let next_ip = ip + 1;
                    let ops = &self.op_arrays[oa_idx].opcodes;
                    if next_ip < ops.len() && ops[next_ip].opcode == ZOpcode::OpData {
                        Some((ops[next_ip].result_type, ops[next_ip].result.val))
                    } else {
                        None
                    }
                };

                if let Value::_Iterator { ref array, index } = iter {
                    if let Some((key, val)) = array.entry_at(index) {
                        let val = val.clone();
                        let key_val = match key {
                            crate::value::ArrayKey::Int(n) => Value::Long(*n),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };
                        // Store value in result
                        self.write_result(op, oa_idx, val)?;
                        // Store key in OpData's result slot if present
                        if let Some((key_type, key_slot)) = key_dest {
                            let frame = self.call_stack.last_mut().unwrap();
                            Self::write_to_slot(frame, key_type, key_slot, key_val);
                            // Skip the OpData opcode
                            frame.ip += 1;
                        }
                        // Advance iterator
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_Iterator {
                            array: array.clone(),
                            index: index + 1,
                        };
                        Ok(DispatchSignal::Next)
                    } else {
                        // Exhausted — skip OpData if present
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                } else if let Value::_GeneratorIterator {
                    object_id,
                    needs_advance,
                } = iter
                {
                    // Generator iterator: advance first (if not the first fetch), then read.
                    if needs_advance {
                        let status = self
                            .generators
                            .get(&object_id)
                            .map(|g| g.status)
                            .unwrap_or(crate::value::GeneratorStatus::Closed);
                        if status == crate::value::GeneratorStatus::Suspended {
                            self.resume_generator(object_id)?;
                        }
                    }

                    let gen_status = self
                        .generators
                        .get(&object_id)
                        .map(|g| g.status)
                        .unwrap_or(crate::value::GeneratorStatus::Closed);

                    if gen_status == crate::value::GeneratorStatus::Closed {
                        // Skip OpData if present
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    } else {
                        let gen_val = self
                            .generators
                            .get(&object_id)
                            .map(|g| g.value.clone())
                            .unwrap_or(Value::Null);
                        let gen_key = self
                            .generators
                            .get(&object_id)
                            .map(|g| g.key.clone())
                            .unwrap_or(Value::Null);

                        // Store value in result
                        self.write_result(op, oa_idx, gen_val)?;
                        // Store key in OpData's result slot if present
                        if let Some((key_type, key_slot)) = key_dest {
                            let frame = self.call_stack.last_mut().unwrap();
                            Self::write_to_slot(frame, key_type, key_slot, gen_key);
                            // Skip the OpData opcode
                            frame.ip += 1;
                        }

                        // Mark iterator as needing advance on next fetch
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_GeneratorIterator {
                            object_id,
                            needs_advance: true,
                        };

                        Ok(DispatchSignal::Next)
                    }
                } else if let Value::_ObjectIterator {
                    ref iterator,
                    first,
                } = iter
                {
                    let iter_val = Value::Object(iterator.clone());
                    // Advance on subsequent fetches (not the first)
                    if !first {
                        let _ = self.call_method_sync(&iter_val, "next");
                    }
                    // Check valid()
                    let valid = match self.call_method_sync(&iter_val, "valid") {
                        Ok(v) => v.to_bool(),
                        Err(_) => false,
                    };
                    if !valid {
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        return Ok(DispatchSignal::Jump(op.op2.val as usize));
                    }
                    // Get current value and key
                    let current = self
                        .call_method_sync(&iter_val, "current")
                        .unwrap_or(Value::Null);
                    let key_val = self
                        .call_method_sync(&iter_val, "key")
                        .unwrap_or(Value::Null);

                    self.write_result(op, oa_idx, current)?;
                    if let Some((key_type, key_slot)) = key_dest {
                        let frame = self.call_stack.last_mut().unwrap();
                        Self::write_to_slot(frame, key_type, key_slot, key_val);
                        frame.ip += 1;
                    }
                    // Update iterator state: no longer first
                    let frame = self.call_stack.last_mut().unwrap();
                    frame.temps[iter_slot] = Value::_ObjectIterator {
                        iterator: iterator.clone(),
                        first: false,
                    };
                    Ok(DispatchSignal::Next)
                } else {
                    if key_dest.is_some() {
                        self.call_stack.last_mut().unwrap().ip += 1;
                    }
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                }
            }
            ZOpcode::FeResetRw => {
                // Initialize foreach iterator for by-reference iteration
                let arr = self.read_operand(op, 1, oa_idx)?;
                let iter_slot = op.result.val as usize;
                match &arr {
                    Value::Array(a) => {
                        let iter = Value::_Iterator {
                            array: a.clone(),
                            index: 0,
                        };
                        self.write_result(op, oa_idx, iter)?;
                        // Record source for write-back: iter_slot → (source_type, source_val, value_cv=0, no key yet)
                        let frame = self.call_stack.last_mut().unwrap();
                        frame
                            .foreach_rw_state
                            .insert(iter_slot, (op.op1_type, op.op1.val, 0, None));
                        Ok(DispatchSignal::Next)
                    }
                    Value::Reference(rc) => {
                        let inner = rc.borrow().deref_value();
                        if let Value::Array(a) = inner {
                            let iter = Value::_Iterator { array: a, index: 0 };
                            self.write_result(op, oa_idx, iter)?;
                            let frame = self.call_stack.last_mut().unwrap();
                            frame
                                .foreach_rw_state
                                .insert(iter_slot, (op.op1_type, op.op1.val, 0, None));
                            Ok(DispatchSignal::Next)
                        } else {
                            Ok(DispatchSignal::Jump(op.op2.val as usize))
                        }
                    }
                    _ => Ok(DispatchSignal::Jump(op.op2.val as usize)),
                }
            }
            ZOpcode::FeFetchRw => {
                // Foreach fetch for by-reference iteration
                let iter_slot = op.op1.val as usize;
                let value_cv_idx = op.result.val as usize;
                let frame = self.call_stack.last().unwrap();
                let ip = frame.ip;
                let iter = frame.temps[iter_slot].clone();
                let rw_state = frame.foreach_rw_state.get(&iter_slot).cloned();

                let key_dest = {
                    let next_ip = ip + 1;
                    let ops = &self.op_arrays[oa_idx].opcodes;
                    if next_ip < ops.len() && ops[next_ip].opcode == ZOpcode::OpData {
                        Some((ops[next_ip].result_type, ops[next_ip].result.val))
                    } else {
                        None
                    }
                };

                // Write back the PREVIOUS iteration's modified value to the source array
                if let Some((src_type, src_val, prev_value_cv, Some(ref prev_key))) = &rw_state {
                    let frame = self.call_stack.last().unwrap();
                    let modified_val = if *prev_value_cv < frame.cvs.len() {
                        frame.cvs[*prev_value_cv].deref_value()
                    } else {
                        Value::Null
                    };
                    // Read the source array, update the element, write it back
                    let src_type = *src_type;
                    let src_val = *src_val;
                    let prev_key = prev_key.clone();
                    self.write_back_foreach_rw(src_type, src_val, &prev_key, modified_val);
                }

                if let Value::_Iterator { ref array, index } = iter {
                    if let Some((key, val)) = array.entry_at(index) {
                        let val = val.clone();
                        let key_val = match key {
                            crate::value::ArrayKey::Int(n) => Value::Long(*n),
                            crate::value::ArrayKey::String(s) => Value::String(s.clone()),
                        };

                        // Write the value as a Reference to the CV
                        let ref_val = Value::Reference(Rc::new(RefCell::new(val)));
                        self.write_result(op, oa_idx, ref_val)?;

                        if let Some((key_type, key_slot)) = key_dest {
                            let frame = self.call_stack.last_mut().unwrap();
                            Self::write_to_slot(frame, key_type, key_slot, key_val.clone());
                            frame.ip += 1;
                        }

                        // Advance iterator and update rw_state with current key
                        let frame = self.call_stack.last_mut().unwrap();
                        frame.temps[iter_slot] = Value::_Iterator {
                            array: array.clone(),
                            index: index + 1,
                        };
                        if let Some(state) = frame.foreach_rw_state.get_mut(&iter_slot) {
                            state.2 = value_cv_idx;
                            state.3 = Some(key_val);
                        }
                        Ok(DispatchSignal::Next)
                    } else {
                        if key_dest.is_some() {
                            self.call_stack.last_mut().unwrap().ip += 1;
                        }
                        Ok(DispatchSignal::Jump(op.op2.val as usize))
                    }
                } else {
                    if key_dest.is_some() {
                        self.call_stack.last_mut().unwrap().ip += 1;
                    }
                    Ok(DispatchSignal::Jump(op.op2.val as usize))
                }
            }
            ZOpcode::FeFree => {
                // Free foreach iterator
                let slot = op.op1.val as usize;
                // Write back the last element from foreach-by-reference
                let frame = self.call_stack.last().unwrap();
                if let Some((src_type, src_val, value_cv, Some(ref last_key))) =
                    frame.foreach_rw_state.get(&slot).cloned()
                {
                    let modified_val = if value_cv < frame.cvs.len() {
                        frame.cvs[value_cv].deref_value()
                    } else {
                        Value::Null
                    };
                    self.write_back_foreach_rw(src_type, src_val, &last_key, modified_val);
                }
                let frame = self.call_stack.last_mut().unwrap();
                frame.foreach_rw_state.remove(&slot);
                frame.temps[slot] = Value::Null;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Array operations
            // =====================================================================
            ZOpcode::InitArray => {
                let mut arr = PhpArray::new();
                if op.op1_type != OperandType::Unused {
                    let val = self.read_operand(op, 1, oa_idx)?;
                    if op.op2_type != OperandType::Unused {
                        let key = self.read_operand(op, 2, oa_idx)?;
                        arr.set(&key, val);
                    } else {
                        arr.push(val);
                    }
                }
                self.write_result(op, oa_idx, Value::Array(arr))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AddArrayElement => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let key = if op.op2_type != OperandType::Unused {
                    Some(self.read_operand(op, 2, oa_idx)?)
                } else {
                    None
                };
                let result_slot = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if let Value::Array(ref mut arr) = frame.temps[result_slot] {
                    match key {
                        Some(k) => arr.set(&k, val),
                        None => arr.push(val),
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AddArrayUnpack => {
                // [...$spread] — unpack iterable into array
                let val = self.read_operand(op, 1, oa_idx)?;
                let result_slot = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if let Value::Array(ref mut target) = frame.temps[result_slot] {
                    match val {
                        Value::Array(ref source) => {
                            for (k, v) in source.entries() {
                                match k {
                                    ArrayKey::Int(_) => target.push(v.clone()),
                                    ArrayKey::String(ref s) => {
                                        target.set(&Value::String(s.clone()), v.clone());
                                    }
                                }
                            }
                        }
                        _ => {
                            // Non-array: PHP would iterate, for now treat as single push
                            target.push(val);
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Function calls
            // =====================================================================
            ZOpcode::InitFcall | ZOpcode::InitFcallByName | ZOpcode::InitNsFcallByName => {
                // Push a new pending call onto the stack
                let name_val = self.read_operand(op, 2, oa_idx)?;
                let name = name_val.to_php_string();
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name,
                    args: Vec::new(),
                    arg_names: Vec::new(),
                    this_source: None,
                    static_class: None,
                    forwarded_this: None,
                    ref_args: Vec::new(),
                    ref_prop_args: Vec::new(),
                });
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitDynamicCall => {
                let name_val_raw = self.read_operand(op, 1, oa_idx)?;
                let name_val = name_val_raw.deref_value();
                // Handle array callables: [$obj, "method"] or ["ClassName", "method"]
                if let Value::Array(ref arr) = name_val {
                    let entries = arr.entries();
                    if entries.len() == 2 {
                        let method_name = entries[1].1.to_php_string();
                        match &entries[0].1 {
                            Value::Object(obj) => {
                                let class_name = obj.class_name().to_string();
                                let full_name = format!("{}::{}", class_name, method_name);
                                let frame = self.call_stack.last_mut().unwrap();
                                frame.call_stack_pending.push(PendingCall {
                                    name: full_name,
                                    args: vec![Value::Object(obj.clone())],
                                    arg_names: Vec::new(),
                                    this_source: Some((OperandType::Unused, 0)),
                                    static_class: Some(class_name),
                                    forwarded_this: None,
                                    ref_args: Vec::new(),
                                    ref_prop_args: Vec::new(),
                                });
                                return Ok(DispatchSignal::Next);
                            }
                            Value::String(class_name) => {
                                let full_name = format!("{}::{}", class_name, method_name);
                                let frame = self.call_stack.last_mut().unwrap();
                                frame.call_stack_pending.push(PendingCall {
                                    name: full_name,
                                    args: Vec::new(),
                                    arg_names: Vec::new(),
                                    this_source: None,
                                    static_class: Some(class_name.clone()),
                                    forwarded_this: None,
                                    ref_args: Vec::new(),
                                    ref_prop_args: Vec::new(),
                                });
                                return Ok(DispatchSignal::Next);
                            }
                            _ => {}
                        }
                    }
                }

                // Handle objects with __invoke() method
                if let Value::Object(ref obj) = name_val {
                    let class_name = obj.class_name().to_string();
                    // Check if this is a Closure object (already handled by extract_closure_name)
                    if class_name != "Closure" {
                        // Check if the class has an __invoke method
                        if self.has_method(&class_name, "__invoke") {
                            let full_name = format!("{}::__invoke", class_name);
                            let frame = self.call_stack.last_mut().unwrap();
                            frame.call_stack_pending.push(PendingCall {
                                name: full_name,
                                args: vec![name_val.clone()],
                                arg_names: Vec::new(),
                                this_source: Some((op.op1_type, op.op1.val)),
                                static_class: Some(class_name),
                                forwarded_this: None,
                                ref_args: Vec::new(),
                                ref_prop_args: Vec::new(),
                            });
                            return Ok(DispatchSignal::Next);
                        }
                    }
                }

                let name = Self::extract_closure_name(&name_val);
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name,
                    args: Vec::new(),
                    arg_names: Vec::new(),
                    this_source: None,
                    static_class: None,
                    forwarded_this: None,
                    ref_args: Vec::new(),
                    ref_prop_args: Vec::new(),
                });
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitUserCall => {
                // Initialize a call_user_func / call_user_func_array at opcode level.
                // op2 = the callable (string, array, or Closure)
                let callable = self.read_operand(op, 2, oa_idx)?;

                // Handle array callables: [$obj, "method"] or ["ClassName", "method"]
                if let Value::Array(ref arr) = callable {
                    let entries = arr.entries();
                    if entries.len() == 2 {
                        let method_name = entries[1].1.to_php_string();
                        match &entries[0].1 {
                            Value::Object(obj) => {
                                let class_name = obj.class_name().to_string();
                                let full_name = format!("{}::{}", class_name, method_name);
                                let frame = self.call_stack.last_mut().unwrap();
                                frame.call_stack_pending.push(PendingCall {
                                    name: full_name,
                                    args: vec![Value::Object(obj.clone())],
                                    arg_names: Vec::new(),
                                    this_source: None,
                                    static_class: Some(class_name),
                                    forwarded_this: None,
                                    ref_args: Vec::new(),
                                    ref_prop_args: Vec::new(),
                                });
                                return Ok(DispatchSignal::Next);
                            }
                            Value::String(class_name) => {
                                let full_name = format!("{}::{}", class_name, method_name);
                                let frame = self.call_stack.last_mut().unwrap();
                                frame.call_stack_pending.push(PendingCall {
                                    name: full_name,
                                    args: Vec::new(),
                                    arg_names: Vec::new(),
                                    this_source: None,
                                    static_class: Some(class_name.clone()),
                                    forwarded_this: None,
                                    ref_args: Vec::new(),
                                    ref_prop_args: Vec::new(),
                                });
                                return Ok(DispatchSignal::Next);
                            }
                            _ => {}
                        }
                    }
                }

                let name = Self::extract_closure_name(&callable);
                let frame = self.call_stack.last_mut().unwrap();
                frame.call_stack_pending.push(PendingCall {
                    name,
                    args: Vec::new(),
                    arg_names: Vec::new(),
                    this_source: None,
                    static_class: None,
                    forwarded_this: None,
                    ref_args: Vec::new(),
                    ref_prop_args: Vec::new(),
                });
                Ok(DispatchSignal::Next)
            }
            ZOpcode::CallTrampoline => {
                // __call() / __callStatic() trampoline — the VM has already set up
                // a pending call with the magic method name. This opcode just triggers
                // the dispatch, same as DoFcall.
                return self.handle_do_fcall(op, oa_idx);
            }
            ZOpcode::CallableConvert => {
                // First-class callable syntax: strlen(...)
                // Converts the pending call into a Closure object.
                let frame = self.call_stack.last_mut().unwrap();
                if let Some(pending) = frame.call_stack_pending.pop() {
                    let func_name = pending.name.clone();
                    let closure = PhpObject::new("Closure".to_string());
                    closure.set_property("__closure_name".to_string(), Value::String(func_name));
                    self.write_result(op, oa_idx, Value::Object(closure))?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendArray => {
                // Unpack an array as arguments for call_user_func_array.
                // op1 = the array of arguments
                let val = self.read_operand(op, 1, oa_idx)?;
                if let Value::Array(ref arr) = val {
                    let frame = self.call_stack.last_mut().unwrap();
                    if let Some(pending) = frame.call_stack_pending.last_mut() {
                        for (_key, v) in arr.entries() {
                            pending.args.push(v.clone());
                            pending.arg_names.push(String::new());
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendUser => {
                // Send a user function argument (used with InitUserCall).
                // Same semantics as SendVal but for user-callback context.
                let val = self.read_operand(op, 1, oa_idx)?;
                let arg_name = if op.op2_type == OperandType::Const {
                    self.read_operand(op, 2, oa_idx)?.to_php_string()
                } else {
                    String::new()
                };
                let frame = self.call_stack.last_mut().unwrap();
                if let Some(pending) = frame.call_stack_pending.last_mut() {
                    if op.op1_type == OperandType::Cv {
                        pending
                            .ref_args
                            .push((pending.args.len(), op.op1_type, op.op1.val));
                    }
                    pending.args.push(val);
                    pending.arg_names.push(arg_name);
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendVal
            | ZOpcode::SendVar
            | ZOpcode::SendValEx
            | ZOpcode::SendVarEx
            | ZOpcode::SendRef
            | ZOpcode::SendVarNoRef
            | ZOpcode::SendVarNoRefEx
            | ZOpcode::SendFuncArg => {
                let opcode = op.opcode;
                let val = self.read_operand(op, 1, oa_idx)?;
                // Check for named argument: op2_type == Const means there's a name literal
                let arg_name = if op.op2_type == OperandType::Const {
                    self.read_operand(op, 2, oa_idx)?.to_php_string()
                } else {
                    String::new()
                };
                let frame = self.call_stack.last_mut().unwrap();
                if let Some(pending) = frame.call_stack_pending.last_mut() {
                    // Record CV source for all variable args so builtins can write back
                    // (e.g., preg_match $matches). Builtins decide which args to write back to.
                    if op.op1_type == OperandType::Cv {
                        pending
                            .ref_args
                            .push((pending.args.len(), op.op1_type, op.op1.val));
                    }
                    // For Tmp/Var operands, check if this came from a property fetch
                    // (needed for implicit pass-by-ref where compiler emits SendVar, not SendRef)
                    if matches!(op.op1_type, OperandType::TmpVar | OperandType::Var) {
                        let temp_idx = op.op1.val as usize;
                        if let Some((obj_val, prop_name)) =
                            frame.temp_prop_source.get(&temp_idx).cloned()
                        {
                            pending
                                .ref_prop_args
                                .push((pending.args.len(), obj_val, prop_name));
                        }
                    }
                    // For pass-by-value sends, dereference any Reference wrapper so
                    // the callee gets its own copy and cannot mutate the original.
                    // SendRef keeps the reference for pass-by-reference semantics.
                    let val = if opcode == ZOpcode::SendRef {
                        val
                    } else {
                        val.deref_value()
                    };
                    pending.args.push(val);
                    pending.arg_names.push(arg_name);
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::SendUnpack => {
                // ...$args spread
                let val = self.read_operand(op, 1, oa_idx)?;
                if let Value::Array(ref arr) = val {
                    let frame = self.call_stack.last_mut().unwrap();
                    if let Some(pending) = frame.call_stack_pending.last_mut() {
                        for (key, v) in arr.entries() {
                            pending.args.push(v.clone());
                            // String keys become named arguments; integer keys are positional.
                            match key {
                                crate::value::ArrayKey::String(s) => {
                                    pending.arg_names.push(s.clone())
                                }
                                _ => pending.arg_names.push(String::new()),
                            }
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DoFcall | ZOpcode::DoIcall | ZOpcode::DoUcall | ZOpcode::DoFcallByName => {
                self.handle_do_fcall(op, oa_idx)
            }
            ZOpcode::Recv => {
                // Receive parameter: op1 = arg number (1-based)
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if arg_num > 0 && arg_num <= frame.args.len() {
                    let val = frame.args[arg_num - 1].clone();
                    frame.cvs[result_cv] = val.clone();
                    // Type check the parameter
                    let func_oa = &self.op_arrays[frame.op_array_idx];
                    if let Some(arg_info) = func_oa.arg_info.get(arg_num - 1) {
                        if let Some(ref type_name) = arg_info.type_name {
                            let derefed = val.deref_value();
                            if !self.value_matches_type(&derefed, type_name) {
                                let func_name = func_oa
                                    .function_name
                                    .as_deref()
                                    .unwrap_or("{main}")
                                    .to_string();
                                let param_name = arg_info.name.clone();
                                let actual = self.get_value_type_name(&derefed);
                                return Err(VmError::TypeError(format!(
                                    "{}(): Argument #{} ({}) must be of type {}, {} given",
                                    func_name, arg_num, param_name, type_name, actual
                                )));
                            }
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RecvInit => {
                // Receive parameter with default: op1 = arg number, op2 = default
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last().unwrap();
                let has_arg = arg_num > 0 && arg_num <= frame.args.len() && {
                    // When named args were reordered, check if this position was actually provided
                    match &frame.named_arg_provided {
                        Some(provided) => *provided.get(arg_num - 1).unwrap_or(&false),
                        None => true, // Normal positional call — all positions up to args.len() are provided
                    }
                };
                let val = if has_arg {
                    frame.args[arg_num - 1].clone()
                } else {
                    self.read_operand(op, 2, oa_idx)?
                };
                // Type check the parameter (only if argument was actually provided)
                if has_arg {
                    let frame = self.call_stack.last().unwrap();
                    let func_oa = &self.op_arrays[frame.op_array_idx];
                    if let Some(arg_info) = func_oa.arg_info.get(arg_num - 1) {
                        if let Some(ref type_name) = arg_info.type_name {
                            let derefed = val.deref_value();
                            if !self.value_matches_type(&derefed, type_name) {
                                let func_name = func_oa
                                    .function_name
                                    .as_deref()
                                    .unwrap_or("{main}")
                                    .to_string();
                                let param_name = arg_info.name.clone();
                                let actual = self.get_value_type_name(&derefed);
                                return Err(VmError::TypeError(format!(
                                    "{}(): Argument #{} ({}) must be of type {}, {} given",
                                    func_name, arg_num, param_name, type_name, actual
                                )));
                            }
                        }
                    }
                }
                let frame = self.call_stack.last_mut().unwrap();
                frame.cvs[result_cv] = val;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::RecvVariadic => {
                // Collect remaining args into array
                let arg_num = op.op1.val as usize;
                let result_cv = op.result.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                let mut arr = PhpArray::new();
                if arg_num > 0 {
                    for i in (arg_num - 1)..frame.args.len() {
                        arr.push(frame.args[i].clone());
                    }
                }
                frame.cvs[result_cv] = Value::Array(arr);
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Return
            // =====================================================================
            ZOpcode::Return | ZOpcode::ReturnByRef => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let frame = self.call_stack.last_mut().unwrap();
                frame.return_value = val;
                Ok(DispatchSignal::Return)
            }
            ZOpcode::GeneratorReturn => self.handle_generator_return(op, oa_idx),

            // =====================================================================
            // I/O
            // =====================================================================
            ZOpcode::Echo => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let s = self.value_to_string(&val)?;
                self.write_output(&s);
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Type & Cast
            // =====================================================================
            ZOpcode::Cast => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = if op.extended_value == 6 {
                    // IS_STRING — use value_to_string for __toString support
                    Value::String(self.value_to_string(&val)?)
                } else if op.extended_value == 7 {
                    // IS_ARRAY — cast to array with private/protected name mangling
                    match &val {
                        Value::Object(o) => {
                            let mut arr = PhpArray::new();
                            let class_name = o.class_name();
                            let props = o.properties();
                            for (k, v) in &props {
                                // PHP name mangling for (array) cast:
                                // Private: "\0ClassName\0propName"
                                // Protected: "\0*\0propName"
                                // Public: "propName"
                                let mangled = if let Some(class_def) =
                                    self.classes.get(&class_name.to_string())
                                {
                                    if let Some(&pflags) = class_def.property_flags.get(k) {
                                        if pflags & ACC_PRIVATE != 0 {
                                            format!("\0{}\0{}", class_name, k)
                                        } else if pflags & ACC_PROTECTED != 0 {
                                            format!("\0*\0{}", k)
                                        } else {
                                            k.clone()
                                        }
                                    } else {
                                        k.clone()
                                    }
                                } else {
                                    k.clone()
                                };
                                arr.set_string(mangled, v.clone());
                            }
                            Value::Array(arr)
                        }
                        _ => val.cast(op.extended_value),
                    }
                } else {
                    val.cast(op.extended_value)
                };
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::TypeCheck => {
                // Check type: extended_value encodes which type to check
                let val = self.read_operand(op, 1, oa_idx)?;
                let result = match op.extended_value {
                    0 => {
                        // empty() check: value is "empty" if it's falsy in PHP
                        match &val {
                            Value::Null => true,
                            Value::Bool(b) => !b,
                            Value::Long(n) => *n == 0,
                            Value::Double(f) => *f == 0.0,
                            Value::String(s) => s.is_empty() || s == "0",
                            Value::Array(a) => a.is_empty(),
                            _ => false,
                        }
                    }
                    1 => val.is_null(),                     // IS_NULL
                    2 => matches!(val, Value::Bool(false)), // IS_FALSE
                    4 => matches!(val, Value::Bool(true)),  // IS_TRUE
                    16 => matches!(val, Value::Long(_)),    // IS_LONG
                    32 => matches!(val, Value::Double(_)),  // IS_DOUBLE
                    64 => matches!(val, Value::String(_)),  // IS_STRING
                    128 => matches!(val, Value::Array(_)),  // IS_ARRAY
                    256 => matches!(val, Value::Object(_)), // IS_OBJECT
                    _ => false,
                };
                self.write_result(op, oa_idx, Value::Bool(result))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Strlen => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let len = match val {
                    Value::String(ref s) => s.len() as i64,
                    _ => val.to_php_string().len() as i64,
                };
                self.write_result(op, oa_idx, Value::Long(len))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Count => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let count = match val {
                    Value::Array(ref a) => a.len() as i64,
                    Value::Null => 0,
                    _ => 1,
                };
                self.write_result(op, oa_idx, Value::Long(count))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Introspection Operations
            // =====================================================================
            ZOpcode::GetType => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let val = val.deref_value();
                let type_name = match &val {
                    Value::Null => "NULL",
                    Value::Bool(_) => "boolean",
                    Value::Long(_) => "integer",
                    Value::Double(_) => "double",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                    Value::Resource(_, _) => "resource",
                    _ => "unknown type",
                };
                self.write_result(op, oa_idx, Value::String(type_name.to_string()))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::GetClass => {
                if op.op1_type == OperandType::Unused {
                    // No argument: return class name from current context
                    let result = if let Some(frame) = self.call_stack.last() {
                        let oa = &self.op_arrays[frame.op_array_idx];
                        if let Some(ref func_name) = oa.function_name {
                            if let Some(idx) = func_name.find("::") {
                                Value::String(func_name[..idx].to_string())
                            } else {
                                Value::Bool(false)
                            }
                        } else {
                            Value::Bool(false)
                        }
                    } else {
                        Value::Bool(false)
                    };
                    self.write_result(op, oa_idx, result)?;
                } else {
                    // With argument: return class name of the object
                    let val = self.read_operand(op, 1, oa_idx)?;
                    let val = val.deref_value();
                    let result = match &val {
                        Value::Object(obj) => Value::String(obj.class_name()),
                        _ => Value::Bool(false),
                    };
                    self.write_result(op, oa_idx, result)?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::GetCalledClass => {
                // Return the late static binding class name (static::class)
                let result = if let Some(frame) = self.call_stack.last() {
                    if let Some(ref cls) = frame.static_class {
                        Value::String(cls.clone())
                    } else {
                        // Fall back to function name prefix (class context)
                        let oa = &self.op_arrays[frame.op_array_idx];
                        if let Some(ref func_name) = oa.function_name {
                            if let Some(idx) = func_name.find("::") {
                                Value::String(func_name[..idx].to_string())
                            } else {
                                Value::Bool(false)
                            }
                        } else {
                            Value::Bool(false)
                        }
                    }
                } else {
                    Value::Bool(false)
                };
                self.write_result(op, oa_idx, result)?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Call Operations
            // =====================================================================
            ZOpcode::FuncNumArgs => {
                let count = self
                    .call_stack
                    .last()
                    .map(|f| f.args.len() as i64)
                    .unwrap_or(-1);
                self.write_result(op, oa_idx, Value::Long(count))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FuncGetArgs => {
                let mut arr = PhpArray::new();
                if let Some(frame) = self.call_stack.last() {
                    for arg in &frame.args {
                        arr.push(arg.clone());
                    }
                }
                self.write_result(op, oa_idx, Value::Array(arr))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Optimized switch dispatch
            // =====================================================================
            ZOpcode::SwitchLong => {
                // op1 = condition, op2 = jump table literal (LongJumpTable), extended_value = default target
                let cond = self.read_operand(op, 1, oa_idx)?.deref_value();
                let key = cond.to_long();
                let target = if op.op2_type == OperandType::Const {
                    let lit_idx = op.op2.val as usize;
                    if let Some(Literal::LongJumpTable(ref map)) =
                        self.op_arrays[oa_idx].literals.get(lit_idx)
                    {
                        map.get(&key).copied()
                    } else {
                        None
                    }
                } else {
                    None
                };
                let target = target.unwrap_or(op.extended_value);
                Ok(DispatchSignal::Jump(target as usize))
            }
            ZOpcode::SwitchString => {
                // op1 = condition, op2 = jump table literal (StringJumpTable), extended_value = default target
                let cond = self.read_operand(op, 1, oa_idx)?.deref_value();
                let key = cond.to_php_string();
                let target = if op.op2_type == OperandType::Const {
                    let lit_idx = op.op2.val as usize;
                    if let Some(Literal::StringJumpTable(ref map)) =
                        self.op_arrays[oa_idx].literals.get(lit_idx)
                    {
                        map.get(&key).copied()
                    } else {
                        None
                    }
                } else {
                    None
                };
                let target = target.unwrap_or(op.extended_value);
                Ok(DispatchSignal::Jump(target as usize))
            }

            // =====================================================================
            // Optimized array search operations
            // =====================================================================
            ZOpcode::InArray => {
                // op1 = needle, op2 = haystack, extended_value: 0=loose, 1=strict
                let needle = self.read_operand(op, 1, oa_idx)?;
                let haystack = self.read_operand(op, 2, oa_idx)?;
                let strict = op.extended_value == 1;
                let found = if let Value::Array(ref a) = haystack {
                    a.entries().iter().any(|(_, v)| {
                        if strict {
                            needle.strict_eq(v)
                        } else {
                            needle.loose_eq(v)
                        }
                    })
                } else {
                    false
                };
                self.write_result(op, oa_idx, Value::Bool(found))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::ArrayKeyExists => {
                // op1 = key, op2 = array
                let key = self.read_operand(op, 1, oa_idx)?.deref_value();
                let arr = self.read_operand(op, 2, oa_idx)?.deref_value();
                let exists = if let Value::Array(ref a) = arr {
                    a.get(&key).is_some()
                } else {
                    false
                };
                self.write_result(op, oa_idx, Value::Bool(exists))?;
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Declarations
            // =====================================================================
            ZOpcode::DeclareFunction => {
                // op1 = function index in dynamic_func_defs (Const)
                // op2 = function name (Const)
                let func_idx_val = self.read_operand(op, 1, oa_idx)?;
                let func_idx = func_idx_val.to_long() as usize;
                let name_val = self.read_operand(op, 2, oa_idx)?;
                let name = name_val.to_php_string();

                // Register the function if not already registered
                if !self.functions.contains_key(&name) {
                    let defs = &self.op_arrays[oa_idx].dynamic_func_defs;
                    if func_idx < defs.len() {
                        let def = &defs[func_idx];
                        let idx = self.op_arrays.len();
                        self.op_arrays.push(def.clone());
                        self.functions.insert(name, idx);
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareConst => {
                // op1 = name (Const), op2 = value
                let name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.read_operand(op, 2, oa_idx)?;
                self.constants.insert(name, val);
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareAttributedConst => {
                // op1 = name (Const), op2 = value, extended_value = attr literal index
                let name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.read_operand(op, 2, oa_idx)?;
                // Parse attributes from the encoded literal
                let attr_idx = op.extended_value as usize;
                let mut attrs = Vec::new();
                if let Some(Literal::String(ref attr_str)) =
                    self.op_arrays[oa_idx].literals.get(attr_idx)
                {
                    let attr_str = attr_str.clone();
                    for section in attr_str.split('\x01') {
                        if section.is_empty() {
                            continue;
                        }
                        let mut parts: Vec<&str> = section.split('\x02').collect();
                        let attr_name = parts.remove(0).to_string();
                        let mut args = Vec::new();
                        for arg_str in parts {
                            if let Some((k, v)) = arg_str.split_once('=') {
                                args.push((Some(k.to_string()), v.to_string()));
                            } else {
                                args.push((None, arg_str.to_string()));
                            }
                        }
                        attrs.push((attr_name, args));
                    }
                }
                self.constants.insert(name.clone(), val);
                self.constant_attributes.insert(name, attrs);
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchConstant => {
                // op2 = constant name
                let raw_name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                let name = raw_name.strip_prefix('\\').unwrap_or(&raw_name);
                let val = self.constants.get(name).cloned().unwrap_or_else(|| {
                    // Try short name (after last \) for namespaced constants
                    let short = name.rsplit('\\').next().unwrap_or(name);
                    self.constants.get(short).cloned().unwrap_or(Value::Null)
                });
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareClass | ZOpcode::DeclareClassDelayed | ZOpcode::DeclareAnonClass => {
                self.handle_declare_class(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitParentPropertyHookCall => {
                // op1 = property name (Const), op2 = hook kind (0=get, 1=set)
                // Initializes a call to the parent class's property hook.
                // We resolve the parent's hook op_array and push a pending call.
                let prop_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let hook_kind = op.extended_value; // 0=get, 1=set

                // Determine current class and find parent
                let calling_class = self.get_current_class_scope();
                if let Some(class_name) = calling_class {
                    if let Some(parent_name) =
                        self.classes.get(&class_name).and_then(|c| c.parent.clone())
                    {
                        let hook_idx = if hook_kind == 0 {
                            self.find_property_get_hook(&parent_name, &prop_name)
                                .copied()
                        } else {
                            self.find_property_set_hook(&parent_name, &prop_name)
                                .copied()
                        };
                        if let Some(hook_oa_idx) = hook_idx {
                            let hook_name = self.op_arrays[hook_oa_idx]
                                .function_name
                                .clone()
                                .unwrap_or_default();
                            let frame = self.call_stack.last_mut().unwrap();
                            frame.call_stack_pending.push(PendingCall {
                                name: hook_name,
                                args: Vec::new(),
                                arg_names: Vec::new(),
                                this_source: None,
                                static_class: Some(parent_name),
                                forwarded_this: None,
                                ref_args: Vec::new(),
                                ref_prop_args: Vec::new(),
                            });
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DeclareLambdaFunction => {
                // Creates a closure value as a proper Closure object
                // op1 = index into dynamic_func_defs (as constant)
                let func_idx = op.op1.val as usize;
                let parent_oa = &self.op_arrays[oa_idx];
                if func_idx < parent_oa.dynamic_func_defs.len() {
                    let closure_oa = parent_oa.dynamic_func_defs[func_idx].clone();
                    let unique_name = format!("{{closure}}#{}", self.next_closure_id);
                    self.next_closure_id += 1;
                    let idx = self.op_arrays.len();
                    self.op_arrays.push(closure_oa);
                    self.functions.insert(unique_name.clone(), idx);

                    // Capture declaring class scope for static:: resolution inside closures
                    if let Some(scope) = self.get_current_class_scope() {
                        self.closure_scopes.insert(unique_name.clone(), scope);
                    }

                    let obj = PhpObject::new("Closure".to_string());
                    obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    obj.set_property("__closure_name".to_string(), Value::String(unique_name));
                    self.write_result(op, oa_idx, Value::Object(obj))?;
                } else {
                    self.write_result(op, oa_idx, Value::Null)?;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::BindLexical => {
                // Bind a captured variable into a closure
                // op1 = tmp_var holding closure name
                // op2 = cv of the variable in parent scope
                // extended_value = 0 (by value) or 1 (by reference)
                let closure_name = Self::extract_closure_name(&self.read_operand(op, 1, oa_idx)?);
                let captured_value = self.read_operand(op, 2, oa_idx)?;
                // Get the variable name from the parent op_array's vars list
                let var_name = if op.op2_type == OperandType::Cv {
                    let cv_idx = op.op2.val as usize;
                    let parent_oa = &self.op_arrays[oa_idx];
                    parent_oa.vars.get(cv_idx).cloned().unwrap_or_default()
                } else {
                    String::new()
                };
                if !var_name.is_empty() {
                    self.closure_bindings
                        .entry(closure_name)
                        .or_default()
                        .push((var_name, captured_value));
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::New => {
                self.handle_new(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Clone => {
                let val = self.read_operand(op, 1, oa_idx)?;
                let cloned = if let Value::Object(ref obj) = val {
                    // Deep clone the object
                    let new_obj = PhpObject::new(obj.class_name().to_string());
                    new_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    // Copy all properties
                    for (k, v) in obj.properties() {
                        new_obj.set_property(k, v);
                    }
                    let cloned_val = Value::Object(new_obj);
                    // Call __clone() if defined
                    let class_name = obj.class_name().to_string();
                    if let Some(clone_fn) = self.find_magic_method(&class_name, "__clone") {
                        self.call_magic_method(&clone_fn, cloned_val.clone(), vec![])?;
                    }
                    cloned_val
                } else {
                    val
                };
                self.write_result(op, oa_idx, cloned)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchObjR | ZOpcode::FetchObjIs => {
                self.handle_fetch_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchObjW
            | ZOpcode::FetchObjRw
            | ZOpcode::FetchObjFuncArg
            | ZOpcode::FetchObjUnset => {
                // Write/read-write/func-arg/unset modes — same read for now
                self.handle_fetch_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignObj => {
                self.handle_assign_obj(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitMethodCall => {
                self.handle_init_method_call(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::InitStaticMethodCall => {
                self.handle_init_static_method_call(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchClassConstant => {
                self.handle_fetch_class_constant(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Instanceof => {
                self.handle_instanceof(op, oa_idx)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchClass => {
                // Resolve class name → just pass through the class name as string
                let name = self.read_operand(op, 2, oa_idx)?;
                self.write_result(op, oa_idx, name)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchThis => {
                // Fetch $this from the current frame
                let frame = self.call_stack.last().unwrap();
                let val = if let Some(idx) = self.op_arrays[frame.op_array_idx]
                    .vars
                    .iter()
                    .position(|v| v == "this")
                {
                    frame.cvs.get(idx).cloned().unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchGlobals => {
                // Return all global variables as a PhpArray ($GLOBALS superglobal).
                // In PHP, $GLOBALS is a reference to the global symbol table.
                // We build it from the main (bottom) frame's compiled variables.
                let mut arr = PhpArray::new();
                // Add variables from the main (bottom) frame
                if let Some(main_frame) = self.call_stack.first() {
                    let main_oa = &self.op_arrays[main_frame.op_array_idx];
                    for (i, name) in main_oa.vars.iter().enumerate() {
                        if i < main_frame.cvs.len() && !main_frame.cvs[i].is_null() {
                            arr.set_string(name.clone(), main_frame.cvs[i].clone());
                        }
                    }
                }
                // Add a self-reference (PHP's $GLOBALS['GLOBALS'] points to itself)
                arr.set_string("GLOBALS".to_string(), Value::Array(arr.clone()));
                self.write_result(op, oa_idx, Value::Array(arr))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchClassName => {
                // Get the class name string from a class reference
                // op1 = class ref (from FetchClass or object), extended_value determines source:
                // 0 = self, 1 = parent, 2 = static
                let fetch_type = op.extended_value;
                let class_name = match fetch_type {
                    0 => {
                        // ZEND_FETCH_CLASS_SELF — class of current method
                        self.get_current_class_scope().unwrap_or_default()
                    }
                    1 => {
                        // ZEND_FETCH_CLASS_PARENT — parent of current class
                        let current = self.get_current_class_scope().unwrap_or_default();
                        self.classes
                            .get(&current)
                            .and_then(|c| c.parent.clone())
                            .unwrap_or_default()
                    }
                    2 => {
                        // ZEND_FETCH_CLASS_STATIC — late static binding class
                        let frame = self.call_stack.last().unwrap();
                        frame
                            .static_class
                            .clone()
                            .or_else(|| self.get_current_class_scope())
                            .unwrap_or_default()
                    }
                    _ => {
                        // Explicit class from operand
                        if op.op1_type != OperandType::Unused {
                            self.read_operand(op, 1, oa_idx)?.to_php_string()
                        } else {
                            String::new()
                        }
                    }
                };
                self.write_result(op, oa_idx, Value::String(class_name))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchStaticPropR | ZOpcode::FetchStaticPropIs => {
                self.handle_fetch_static_prop(op, oa_idx, false)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchStaticPropW
            | ZOpcode::FetchStaticPropRw
            | ZOpcode::FetchStaticPropUnset => {
                self.handle_fetch_static_prop(op, oa_idx, true)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchStaticPropFuncArg => {
                // Func arg mode — use write mode if the argument is by-reference
                self.handle_fetch_static_prop(op, oa_idx, true)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::AssignStaticProp => {
                // Write to a class property/constant
                // op1 = class name, op2 = prop/const name, OP_DATA follows with value
                // extended_value: 0 = static property, 1 = instance property default, 2 = class constant
                let raw_class = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let class_name = self.resolve_class_name(&raw_class);
                let name = self.read_operand(op, 2, oa_idx)?.to_php_string();
                // OP_DATA is the next opcode with the value in op1
                let frame = self.call_stack.last_mut().unwrap();
                let next_ip = frame.ip + 1;
                let data_op = self.op_arrays[oa_idx].opcodes[next_ip].clone();
                frame.ip += 1; // Skip OP_DATA
                let val = self.read_operand(&data_op, 1, oa_idx)?;
                match op.extended_value {
                    1 => {
                        // Instance property default
                        if let Some(class_def) = self.classes.get_mut(&class_name) {
                            class_def.default_properties.insert(name, val.clone());
                        }
                    }
                    2 => {
                        // Class constant
                        if let Some(class_def) = self.classes.get_mut(&class_name) {
                            class_def.class_constants.insert(name, val.clone());
                        }
                    }
                    _ => {
                        // Static property — walk parent chain to find declaring class
                        // (PHP shares static properties with parent unless redeclared)
                        let target_class = self.find_static_prop_owner(&class_name, &name);
                        if let Some(class_def) = self.classes.get_mut(&target_class) {
                            // If the static prop currently holds a Reference, write through it
                            if let Some(Value::Reference(rc)) =
                                class_def.static_properties.get(&name)
                            {
                                *rc.borrow_mut() = val.deref_value();
                            } else {
                                class_def.static_properties.insert(name, val.clone());
                            }
                        }
                    }
                }
                if op.result_type != OperandType::Unused {
                    self.write_result(op, oa_idx, val)?;
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Exception handling
            // =====================================================================
            ZOpcode::Throw => {
                let val = self.read_operand(op, 1, oa_idx)?;
                Err(VmError::Thrown(val))
            }
            ZOpcode::Catch => {
                // Store the current exception in the result CV (if any)
                if op.result_type == OperandType::Cv {
                    let cv_idx = op.result.val as usize;
                    let exception = self.current_exception.take().unwrap_or(Value::Null);
                    let frame = self.call_stack.last_mut().unwrap();
                    if cv_idx >= frame.cvs.len() {
                        frame.cvs.resize(cv_idx + 1, Value::Null);
                    }
                    frame.cvs[cv_idx] = exception;
                } else {
                    self.current_exception = None;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::HandleException => {
                // Discard exception and continue
                self.current_exception = None;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::DiscardException => {
                self.current_exception = None;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FastCall => {
                // Jump to finally block (op1 = target)
                Ok(DispatchSignal::Jump(op.op1.val as usize))
            }
            ZOpcode::FastRet => {
                // Return from finally block (op1 = target)
                Ok(DispatchSignal::Jump(op.op1.val as usize))
            }

            // =====================================================================
            // Other
            // =====================================================================
            ZOpcode::Free => {
                // Free a temporary
                let slot = op.op1.val as usize;
                let frame = self.call_stack.last_mut().unwrap();
                if slot < frame.temps.len() {
                    frame.temps[slot] = Value::Null;
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::OpData => {
                // OP_DATA is consumed by the preceding instruction
                Ok(DispatchSignal::Next)
            }
            ZOpcode::BindGlobal => {
                // global $var — bind a local CV to the global variable
                // op1 = CV slot, op2 = variable name
                let cv_idx = op.op1.val as usize;
                let var_name = self.read_operand(op, 2, oa_idx)?.to_php_string();

                // Look up the variable in the main (global) frame
                let global_val = if self.call_stack.len() > 1 {
                    let main_frame = &self.call_stack[0];
                    let main_oa = &self.op_arrays[main_frame.op_array_idx];
                    if let Some(global_cv) = main_oa.vars.iter().position(|v| v == &var_name) {
                        main_frame
                            .cvs
                            .get(global_cv)
                            .cloned()
                            .unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };

                let frame = self.call_stack.last_mut().unwrap();
                if cv_idx < frame.cvs.len() {
                    // If the global is already a reference, share it
                    if let Value::Reference(_) = &global_val {
                        frame.cvs[cv_idx] = global_val;
                    } else {
                        // Create a shared reference between global and local
                        let rc = Rc::new(RefCell::new(global_val));
                        frame.cvs[cv_idx] = Value::Reference(rc.clone());
                        // Write the reference back to the global frame
                        let _ = frame;
                        if self.call_stack.len() > 1 {
                            let main_frame = &mut self.call_stack[0];
                            let main_oa_idx = main_frame.op_array_idx;
                            if let Some(global_cv) = self.op_arrays[main_oa_idx]
                                .vars
                                .iter()
                                .position(|v| v == &var_name)
                            {
                                if global_cv < main_frame.cvs.len() {
                                    main_frame.cvs[global_cv] = Value::Reference(rc);
                                }
                            }
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchR | ZOpcode::FetchIs => {
                // Read variable by name from scope (variable variables: $$var)
                // op1 = variable name, result = value
                let var_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.fetch_variable_by_name(&var_name);
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FetchW | ZOpcode::FetchRw | ZOpcode::FetchFuncArg | ZOpcode::FetchUnset => {
                // Write/read-write/func-arg/unset modes for variable by name
                let var_name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let val = self.fetch_variable_by_name(&var_name);
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::BindStatic => {
                // static $var = default;
                // op1 = CV index, op2 = default value (or Unused)
                let cv_idx = op.op1.val as usize;
                let frame = self.call_stack.last().unwrap();
                let oa_idx_key = frame.op_array_idx;
                let key = (oa_idx_key, cv_idx);

                if let Some(persisted) = self.static_vars.get(&key).cloned() {
                    // Already initialized — restore persisted value
                    let frame = self.call_stack.last_mut().unwrap();
                    if cv_idx < frame.cvs.len() {
                        frame.cvs[cv_idx] = persisted;
                    }
                } else {
                    // First call — initialize from default
                    let default = if op.op2_type != OperandType::Unused {
                        self.read_operand(op, 2, oa_idx)?
                    } else {
                        Value::Null
                    };
                    self.static_vars.insert(key, default.clone());
                    let frame = self.call_stack.last_mut().unwrap();
                    if cv_idx < frame.cvs.len() {
                        frame.cvs[cv_idx] = default;
                    }
                }

                // Track this CV for write-back on return
                let frame = self.call_stack.last_mut().unwrap();
                if !frame.static_cv_indices.contains(&cv_idx) {
                    frame.static_cv_indices.push(cv_idx);
                }

                Ok(DispatchSignal::Next)
            }
            ZOpcode::VerifyReturnType => {
                // Verify return value matches the declared return type.
                // op1 = the value being returned
                let val = self.read_operand(op, 1, oa_idx)?.deref_value();
                let frame = self.call_stack.last().unwrap();
                let func_oa = &self.op_arrays[frame.op_array_idx];
                let rt_opt = func_oa.return_type.clone();
                let func_name_owned = func_oa.function_name.clone().unwrap_or_else(|| "{main}".to_string());
                drop(frame); // release borrow

                if let Some(ref rt) = rt_opt {
                    let nullable = rt.starts_with('?');
                    let rt_inner = rt.strip_prefix('?').unwrap_or(rt);
                    // If nullable and value is null, skip coercion — null is valid
                    if nullable && matches!(val, Value::Null) {
                        return Ok(DispatchSignal::Next);
                    }
                    // PHP auto-coerces values for scalar return types in weak mode
                    let coerced = match rt_inner {
                        "string" => {
                            if let Value::Object(_) = val {
                                Some(Value::String(self.value_to_string(&val)?))
                            } else if !matches!(val, Value::String(_)) {
                                Some(Value::String(val.to_php_string()))
                            } else {
                                None
                            }
                        }
                        "bool" => {
                            if !matches!(val, Value::Bool(_)) {
                                Some(Value::Bool(val.to_bool()))
                            } else {
                                None
                            }
                        }
                        "int" => {
                            if !matches!(val, Value::Long(_)) {
                                Some(Value::Long(val.to_long()))
                            } else {
                                None
                            }
                        }
                        "float" => {
                            if !matches!(val, Value::Double(_)) {
                                Some(Value::Double(val.to_double()))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some(coerced_val) = coerced {
                        // Write the coerced value back to op1
                        if op.op1_type == OperandType::Cv || op.op1_type == OperandType::Var || op.op1_type == OperandType::TmpVar {
                            let idx = op.op1.val as usize;
                            let frame = self.call_stack.last_mut().unwrap();
                            if op.op1_type == OperandType::Cv {
                                if idx < frame.cvs.len() {
                                    frame.cvs[idx] = coerced_val;
                                }
                            } else if idx < frame.temps.len() {
                                frame.temps[idx] = coerced_val;
                            }
                        }
                        return Ok(DispatchSignal::Next);
                    }
                    if !self.value_matches_type(&val, rt) {
                        let actual_type = self.get_value_type_name(&val);
                        return Err(VmError::TypeError(format!(
                            "{func_name_owned}(): Return value must be of type {rt}, {actual_type} returned"
                        )));
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::VerifyNeverType => {
                // A function declared as "never" must not return — always throw.
                let frame = self.call_stack.last().unwrap();
                let func_oa = &self.op_arrays[frame.op_array_idx];
                let func_name = func_oa.function_name.as_deref().unwrap_or("{main}");
                return Err(VmError::TypeError(format!(
                    "{func_name}(): never-returning function must not implicitly return"
                )));
            }
            ZOpcode::AssertCheck => {
                // ASSERT_CHECK: if zend.assertions <= 0, jump over the assert expression.
                // op2 = jump target (opline to skip to if assertions are disabled)
                if self.config.zend_assertions <= 0 {
                    let target = op.op2.val as usize;
                    Ok(DispatchSignal::Jump(target))
                } else {
                    Ok(DispatchSignal::Next)
                }
            }
            ZOpcode::Exit => {
                // exit/die — terminate entire script immediately.
                let arg = self.read_operand(op, 1, oa_idx)?;
                match arg {
                    Value::String(s) => {
                        self.write_output(&s);
                        return Err(VmError::Exit(0));
                    }
                    Value::Long(n) => return Err(VmError::Exit(n as i32)),
                    _ => return Err(VmError::Exit(0)),
                }
            }
            ZOpcode::TypeAssert => {
                // Runtime type assertion — used by the optimizer to assert that
                // a variable has a known type. If the type doesn't match, this
                // is a no-op in production (the optimizer's assertion failed,
                // but we don't crash). The extended_value encodes the type mask.
                // For now, treat as NOP — the value is already the correct type
                // from the user's perspective; this is an internal optimization hint.
                Ok(DispatchSignal::Next)
            }
            ZOpcode::CheckVar | ZOpcode::CheckFuncArg | ZOpcode::CheckUndefArgs => {
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Defined => {
                let name = self.read_operand(op, 1, oa_idx)?.to_php_string();
                let exists = self.constants.contains_key(&name);
                self.write_result(op, oa_idx, Value::Bool(exists))?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::CopyTmp => {
                let val = self.read_operand(op, 1, oa_idx)?;
                self.write_result(op, oa_idx, val)?;
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Separate => {
                // Separate a shared zval for copy-on-write semantics.
                // If op1 is a Reference, dereference it and write the inner value back.
                // This ensures modifications don't affect the original.
                let val = self.read_operand(op, 1, oa_idx)?;
                if let Value::Reference(rc) = &val {
                    let inner = rc.borrow().clone();
                    // Write the dereferenced value back to the source
                    if op.op1_type == OperandType::Cv {
                        let cv_idx = op.op1.val as usize;
                        let frame = self.call_stack.last_mut().unwrap();
                        if cv_idx < frame.cvs.len() {
                            frame.cvs[cv_idx] = inner;
                        }
                    } else if matches!(op.op1_type, OperandType::TmpVar | OperandType::Var) {
                        let slot = op.op1.val as usize;
                        let frame = self.call_stack.last_mut().unwrap();
                        if slot < frame.temps.len() {
                            frame.temps[slot] = inner;
                        }
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::MakeRef => {
                // Create a Reference from a value (or keep existing Reference).
                // op1 = source value, result = Reference wrapping the value.
                let val = self.read_operand(op, 1, oa_idx)?;
                let ref_val = if let Value::Reference(_) = &val {
                    val // Already a reference
                } else {
                    Value::Reference(Rc::new(RefCell::new(val)))
                };
                self.write_result(op, oa_idx, ref_val.clone())?;
                // Also update the source to share the same reference
                if op.op1_type == OperandType::Cv {
                    let cv_idx = op.op1.val as usize;
                    let frame = self.call_stack.last_mut().unwrap();
                    if cv_idx < frame.cvs.len() {
                        frame.cvs[cv_idx] = ref_val;
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Include / Eval
            // =====================================================================
            ZOpcode::IncludeOrEval => self.handle_include_or_eval(op, oa_idx),

            // =====================================================================
            // Generators (full coroutine semantics)
            // =====================================================================
            ZOpcode::GeneratorCreate => {
                // NOP — generator creation is handled in handle_do_fcall
                // when it detects is_generator on the op_array.
                Ok(DispatchSignal::Next)
            }
            ZOpcode::Yield => self.handle_yield(op, oa_idx),
            ZOpcode::YieldFrom => self.handle_yield_from(op, oa_idx),

            // =====================================================================
            // Debugger hooks — NOPs (no debugger attached)
            // =====================================================================
            ZOpcode::ExtStmt | ZOpcode::ExtFcallBegin | ZOpcode::ExtFcallEnd | ZOpcode::ExtNop => {
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // User opcode — NOP (no user opcode handler registered)
            // =====================================================================
            ZOpcode::UserOpcode => Ok(DispatchSignal::Next),

            // =====================================================================
            // Ticks — declare(ticks=N) handler, invokes registered tick functions
            // =====================================================================
            ZOpcode::Ticks => {
                let tick_n = self
                    .read_operand(op, 1, oa_idx)
                    .map(|v| v.to_long())
                    .unwrap_or(1) as u32;
                self.tick_counter += 1;
                if tick_n > 0 && self.tick_counter >= tick_n {
                    self.tick_counter = 0;
                    // Call all registered tick functions synchronously
                    let funcs = self.tick_functions.clone();
                    for func_name in funcs {
                        let _ = self.invoke_user_callback(&func_name, vec![]);
                    }
                }
                Ok(DispatchSignal::Next)
            }

            // =====================================================================
            // Frameless internal calls — optimized direct calls without frame setup
            // =====================================================================
            ZOpcode::FramelessIcall0 => {
                // Call internal function with 0 args, result in result operand
                // The function name is stored in a literal referenced by extended_value
                let func_name = if op.extended_value > 0 {
                    let oa = &self.op_arrays[oa_idx];
                    if let Some(lit) = oa.literals.get(op.extended_value as usize) {
                        match lit {
                            Literal::String(s) => s.clone(),
                            _ => String::new(),
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                if !func_name.is_empty() {
                    let result = self.call_builtin(&func_name, &[], &[], &[])?;
                    if let Some(val) = result {
                        self.write_result(op, oa_idx, val)?;
                    } else {
                        self.write_result(op, oa_idx, Value::Null)?;
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FramelessIcall1 => {
                // Call internal function with 1 arg (op1)
                let arg1 = self.read_operand(op, 1, oa_idx)?;
                let func_name = {
                    let oa = &self.op_arrays[oa_idx];
                    if let Some(Literal::String(s)) = oa.literals.get(op.extended_value as usize) {
                        s.clone()
                    } else {
                        String::new()
                    }
                };
                if !func_name.is_empty() {
                    let result = self.call_builtin(&func_name, &[arg1], &[], &[])?;
                    if let Some(val) = result {
                        self.write_result(op, oa_idx, val)?;
                    } else {
                        self.write_result(op, oa_idx, Value::Null)?;
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FramelessIcall2 => {
                // Call internal function with 2 args (op1, op2)
                let arg1 = self.read_operand(op, 1, oa_idx)?;
                let arg2 = self.read_operand(op, 2, oa_idx)?;
                let func_name = {
                    let oa = &self.op_arrays[oa_idx];
                    if let Some(Literal::String(s)) = oa.literals.get(op.extended_value as usize) {
                        s.clone()
                    } else {
                        String::new()
                    }
                };
                if !func_name.is_empty() {
                    let result = self.call_builtin(&func_name, &[arg1, arg2], &[], &[])?;
                    if let Some(val) = result {
                        self.write_result(op, oa_idx, val)?;
                    } else {
                        self.write_result(op, oa_idx, Value::Null)?;
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::FramelessIcall3 => {
                // Call internal function with 3 args (op1, op2, and one from extended_value)
                let arg1 = self.read_operand(op, 1, oa_idx)?;
                let arg2 = self.read_operand(op, 2, oa_idx)?;
                // Third arg would need additional operand support; treat as 2-arg for now
                let func_name = {
                    let oa = &self.op_arrays[oa_idx];
                    if let Some(Literal::String(s)) = oa.literals.get(op.extended_value as usize) {
                        s.clone()
                    } else {
                        String::new()
                    }
                };
                if !func_name.is_empty() {
                    let result = self.call_builtin(&func_name, &[arg1, arg2], &[], &[])?;
                    if let Some(val) = result {
                        self.write_result(op, oa_idx, val)?;
                    } else {
                        self.write_result(op, oa_idx, Value::Null)?;
                    }
                }
                Ok(DispatchSignal::Next)
            }
            ZOpcode::JmpFrameless => {
                // Conditional jump for frameless calls — jump to target if condition met
                let target = op.op2.val as usize;
                Ok(DispatchSignal::Jump(target))
            }

            // Anything else: NOP for now
            _ => Ok(DispatchSignal::Next),
        }
    }

    /// Find a catch block for the current IP in the given op_array.
    pub(crate) fn find_catch_block(
        &self,
        oa_idx: usize,
        ip: usize,
        exception_val: &Value,
    ) -> Option<usize> {
        let oa = &self.op_arrays[oa_idx];
        for tc in &oa.try_catch_array {
            if ip >= tc.try_op as usize && tc.catch_op > 0 {
                // Check if we're in the try block (before catch starts)
                if ip < tc.catch_op as usize {
                    // Check exception type matches catch classes
                    if tc.catch_classes.is_empty() {
                        // No class filter — catches everything (e.g., catch without type)
                        return Some(tc.catch_op as usize);
                    }
                    if self.exception_matches(exception_val, &tc.catch_classes) {
                        return Some(tc.catch_op as usize);
                    }
                }
            }
        }
        None
    }

    /// Check if an exception value matches any of the given catch class names.
    /// Supports class hierarchy via parent chain.
    pub(crate) fn exception_matches(
        &self,
        exception_val: &Value,
        catch_classes: &[String],
    ) -> bool {
        let exception_class = match exception_val {
            Value::Object(o) => o.class_name().to_string(),
            // Non-object throws (shouldn't happen in valid PHP, but be permissive)
            _ => return true,
        };

        for catch_class in catch_classes {
            let catch_short = catch_class.rsplit('\\').next().unwrap_or(catch_class);
            // Direct match (full name or short name)
            if exception_class == *catch_class
                || exception_class == catch_short
                || exception_class
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&exception_class)
                    == catch_short
            {
                return true;
            }
            // Catch-all types
            if catch_short == "Throwable" || catch_short == "Exception" || catch_short == "Error" {
                // Check if exception is an exception/error type
                let ex_short = exception_class
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&exception_class);
                if ex_short.contains("Exception")
                    || ex_short.contains("Error")
                    || ex_short == "Throwable"
                {
                    if catch_short == "Throwable" {
                        return true;
                    }
                    if catch_short == "Exception" && ex_short.contains("Exception") {
                        return true;
                    }
                    if catch_short == "Error"
                        && ex_short.contains("Error")
                        && !ex_short.contains("Exception")
                    {
                        return true;
                    }
                }
            }
            // Walk parent class chain
            let mut current = exception_class.clone();
            loop {
                if let Some(class_def) = self.classes.get(&current) {
                    if let Some(ref parent) = class_def.parent {
                        if *parent == *catch_class
                            || parent.rsplit('\\').next().unwrap_or(parent) == catch_short
                        {
                            return true;
                        }
                        current = parent.clone();
                        continue;
                    }
                }
                break;
            }
        }
        false
    }

    /// Get all interfaces a class implements (including parents).
    pub(crate) fn get_class_interfaces(&self, class_name: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = class_name.to_string();
        loop {
            if let Some(class_def) = self.classes.get(&current) {
                for iface in &class_def.interfaces {
                    if !result.contains(iface) {
                        result.push(iface.clone());
                    }
                }
                if let Some(ref parent) = class_def.parent {
                    current = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        result
    }

    /// Write back a modified value from foreach by-reference to the source array.
    fn write_back_foreach_rw(
        &mut self,
        src_type: OperandType,
        src_val: u32,
        key: &Value,
        modified_val: Value,
    ) {
        let frame = self.call_stack.last_mut().unwrap();
        let source = if src_type == OperandType::Cv {
            let idx = src_val as usize;
            if idx < frame.cvs.len() {
                Some(&mut frame.cvs[idx])
            } else {
                None
            }
        } else if matches!(src_type, OperandType::TmpVar | OperandType::Var) {
            let idx = src_val as usize;
            if idx < frame.temps.len() {
                Some(&mut frame.temps[idx])
            } else {
                None
            }
        } else {
            None
        };
        if let Some(source_val) = source {
            if let Value::Reference(ref rc) = source_val {
                let inner = rc.borrow().clone();
                if let Value::Array(mut a) = inner {
                    a.set(key, modified_val);
                    *rc.borrow_mut() = Value::Array(a);
                }
            } else if let Value::Array(ref mut a) = source_val {
                a.set(key, modified_val);
            }
        }
    }

    /// Fetch a variable by name from the current scope (for variable variables: $$var).
    /// Searches current frame CVs first, then the main (global) frame.
    fn fetch_variable_by_name(&mut self, name: &str) -> Value {
        // Search current frame
        let frame = self.call_stack.last().unwrap();
        let oa = &self.op_arrays[frame.op_array_idx];
        if let Some(idx) = oa.vars.iter().position(|v| v == name) {
            if idx < frame.cvs.len() {
                return frame.cvs[idx].clone();
            }
        }
        // Search global (main) frame if not the current frame
        if self.call_stack.len() > 1 {
            let main_frame = &self.call_stack[0];
            let main_oa = &self.op_arrays[main_frame.op_array_idx];
            if let Some(idx) = main_oa.vars.iter().position(|v| v == name) {
                if idx < main_frame.cvs.len() {
                    return main_frame.cvs[idx].clone();
                }
            }
        }
        // PHP 8.0+: Undefined variable generates E_WARNING
        let _ = self.emit_error(2, &format!("Undefined variable ${}", name));
        Value::Null
    }

    /// Write back a modified array value to the original variable (CV or object property).
    /// Used by array_shift, array_pop, sort, etc. that take arrays by reference.
    pub(crate) fn write_back_arg(
        &mut self,
        arg_idx: usize,
        new_val: Value,
        ref_args: &[(usize, OperandType, u32)],
        ref_prop_args: &[(usize, Value, String)],
    ) {
        // Try CV write-back first
        if let Some((_, op_type, op_val)) = ref_args.iter().find(|(idx, _, _)| *idx == arg_idx) {
            if *op_type == OperandType::Cv {
                if let Some(frame) = self.call_stack.last_mut() {
                    let cv_idx = *op_val as usize;
                    if cv_idx < frame.cvs.len() {
                        frame.cvs[cv_idx] = new_val;
                        return;
                    }
                }
            }
        }
        // Fall back to property write-back
        if let Some((_, obj_val, prop_name)) =
            ref_prop_args.iter().find(|(idx, _, _)| *idx == arg_idx)
        {
            if let Value::Object(ref obj) = obj_val {
                obj.set_property(prop_name.clone(), new_val);
            }
        }
    }

    /// Recursively walk array entries, calling the callback for leaf (non-array) values.
    pub(crate) fn walk_recursive_inner(
        &mut self,
        entries: &[(ArrayKey, Value)],
        callback: &str,
        extra: &Option<Value>,
    ) -> VmResult<()> {
        for (key, val) in entries {
            match val {
                Value::Array(ref nested) => {
                    let nested_entries: Vec<_> = nested.entries().iter().cloned().collect();
                    self.walk_recursive_inner(&nested_entries, callback, extra)?;
                }
                _ => {
                    let k = match key {
                        ArrayKey::Int(n) => Value::Long(*n),
                        ArrayKey::String(s) => Value::String(s.clone()),
                    };
                    let mut cb_args = vec![val.clone(), k];
                    if let Some(ref e) = extra {
                        cb_args.push(e.clone());
                    }
                    self.invoke_user_callback(callback, cb_args)?;
                }
            }
        }
        Ok(())
    }

    /// Call a built-in function. Returns Some(Value) if handled, None if not a built-in.
    pub(crate) fn call_builtin(
        &mut self,
        name: &str,
        args: &[Value],
        ref_args: &[(usize, OperandType, u32)],
        ref_prop_args: &[(usize, Value, String)],
    ) -> VmResult<Option<Value>> {
        // Check disable_functions
        if self
            .config
            .disabled_functions
            .contains(&name.to_lowercase())
        {
            return Err(VmError::DisabledFunction(format!(
                "{}() has been disabled for security reasons",
                name
            )));
        }

        // Dereference any Reference-wrapped arguments so builtins see plain values.
        // Write-back is handled separately via ref_args/ref_prop_args.
        let derefed: Vec<Value> = args.iter().map(|v| v.deref_value()).collect();
        let args = &derefed;

        // Consult the builtins registry first.
        if let Some(handler) = self.builtins.get(name).copied() {
            return handler(self, args, ref_args, ref_prop_args).map(Some);
        }

        // Dispatch to categorized builtins modules.
        macro_rules! try_dispatch {
            ($mod:ident) => {
                if let Some(v) =
                    crate::builtins::$mod::dispatch(self, name, args, ref_args, ref_prop_args)?
                {
                    return Ok(Some(v));
                }
            };
        }
        try_dispatch!(curl);
        try_dispatch!(strings);
        try_dispatch!(math);
        try_dispatch!(pcre);
        try_dispatch!(json);
        try_dispatch!(file);
        try_dispatch!(output);
        try_dispatch!(remaining);

        Ok(None)
    }

    // =========================================================================
    // Operand helpers
    // =========================================================================

    /// Read an operand value (op1 or op2).
    #[inline]
    pub(crate) fn read_operand(&self, op: &ZOp, which: u8, oa_idx: usize) -> VmResult<Value> {
        let (operand, op_type) = if which == 1 {
            (&op.op1, op.op1_type)
        } else {
            (&op.op2, op.op2_type)
        };

        let frame = self.call_stack.last().unwrap();
        match op_type {
            OperandType::Const => {
                let idx = operand.val as usize;
                let lit = &self.op_arrays[oa_idx].literals[idx];
                Ok(literal_to_value(lit))
            }
            OperandType::TmpVar | OperandType::Var => {
                let slot = operand.val as usize;
                Ok(frame.temps[slot].clone())
            }
            OperandType::Cv => {
                let idx = operand.val as usize;
                Ok(frame.cvs[idx].clone())
            }
            OperandType::Unused => Ok(Value::Null),
        }
    }

    /// Read an operand from a specific op (used for OP_DATA).
    #[inline]
    pub(crate) fn read_operand_from(&self, op: &ZOp, which: u8, oa_idx: usize) -> VmResult<Value> {
        self.read_operand(op, which, oa_idx)
    }

    /// Write to the result operand.
    /// Write a value to a specific slot in a frame (used for return value / $this write-back).
    fn write_to_slot(frame: &mut Frame, op_type: OperandType, slot: u32, val: Value) {
        match op_type {
            OperandType::TmpVar | OperandType::Var => {
                let idx = slot as usize;
                if idx >= frame.temps.len() {
                    frame.temps.resize(idx + 1, Value::Null);
                }
                frame.temps[idx] = val;
            }
            OperandType::Cv => {
                let idx = slot as usize;
                if idx >= frame.cvs.len() {
                    frame.cvs.resize(idx + 1, Value::Null);
                }
                frame.cvs[idx] = val;
            }
            _ => {}
        }
    }

    #[inline]
    pub(crate) fn write_result(&mut self, op: &ZOp, _oa_idx: usize, val: Value) -> VmResult<()> {
        let frame = self.call_stack.last_mut().unwrap();
        match op.result_type {
            OperandType::TmpVar | OperandType::Var => {
                let slot = op.result.val as usize;
                if slot >= frame.temps.len() {
                    frame.temps.resize(slot + 1, Value::Null);
                }
                frame.temps[slot] = val;
            }
            OperandType::Cv => {
                let idx = op.result.val as usize;
                if idx >= frame.cvs.len() {
                    frame.cvs.resize(idx + 1, Value::Null);
                }
                frame.cvs[idx] = val;
            }
            _ => {}
        }
        Ok(())
    }

    /// Write to a CV from op1.
    /// If the CV currently holds a Reference, write through it (PHP semantics:
    /// assigning to a reference variable updates the shared storage).
    pub(crate) fn write_cv(&mut self, op: &ZOp, _oa_idx: usize, val: Value) -> VmResult<()> {
        let frame = self.call_stack.last_mut().unwrap();
        if op.op1_type == OperandType::Cv {
            let idx = op.op1.val as usize;
            if idx >= frame.cvs.len() {
                frame.cvs.resize(idx + 1, Value::Null);
            }
            if let Value::Reference(rc) = &frame.cvs[idx] {
                // Write through the reference: update the shared storage
                *rc.borrow_mut() = val.deref_value();
            } else {
                frame.cvs[idx] = val;
            }
        }
        Ok(())
    }

    /// Execute a binary operation: result = f(op1, op2).
    #[inline]
    fn op_binary(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
        f: impl FnOnce(Value, Value) -> Value,
    ) -> VmResult<DispatchSignal> {
        let a = self.read_operand(op, 1, oa_idx)?;
        let b = self.read_operand(op, 2, oa_idx)?;
        let result = f(a, b);
        self.write_result(op, oa_idx, result)?;
        Ok(DispatchSignal::Next)
    }

    /// Execute a unary operation: result = f(op1).
    #[inline]
    fn op_unary(
        &mut self,
        op: &ZOp,
        oa_idx: usize,
        f: impl FnOnce(Value) -> Value,
    ) -> VmResult<DispatchSignal> {
        let a = self.read_operand(op, 1, oa_idx)?;
        let result = f(a);
        self.write_result(op, oa_idx, result)?;
        Ok(DispatchSignal::Next)
    }
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}
