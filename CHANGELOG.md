# Changelog

All notable changes to php.rs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

**Core Interpreter (Phases 0-5)**

- Cargo workspace with 85 crates covering the full PHP interpreter pipeline
- ZVal 16-byte tagged union matching PHP's zval layout, with all PHP type variants
- ZString with Arc-based refcounting, DJBX33A hashing, and string interning pool
- ZArray with packed mode (Vec-backed for consecutive integer keys) and hash mode (Robin Hood open addressing)
- ZObject with ClassEntry, property storage, and method lookup
- ZReference with refcount and wrapped ZVal semantics
- ZResource with type id, pointer, and destructor
- Full type coercion system (int, float, string, bool, null, array) matching PHP semantics bit-for-bit
- Hand-written lexer (re2c-equivalent) with double-quoted string interpolation
- Recursive descent parser producing a full PHP 8.6 AST
- AST-to-opcode compiler
- Virtual machine executor with all 212 opcodes implemented, including:
  - Arithmetic, bitwise, comparison, and logical operators
  - String rope opcodes (RopeInit/RopeAdd/RopeEnd)
  - Object property and static property access, isset/unset
  - Array operations (InArray, ArrayKeyExists, AddArrayUnpack)
  - Function call machinery (FuncNumArgs, FuncGetArgs, named arguments, spread)
  - Error suppression (BeginSilence/EndSilence)
  - Introspection (GetClass, GetCalledClass, GetType)
  - Type verification (VerifyReturnType, VerifyNeverType, AssertCheck)
  - Switch dispatch (SwitchLong, SwitchString)
  - Static local variables (BindStatic)
- Complete OOP system: classes, interfaces, abstract classes, enums, traits, inheritance, property type invariance
- Fiber support for cooperative multitasking
- DNF (Disjunctive Normal Form) types
- goto/label control flow
- declare/halt_compiler directives
- Backtick execution operator
- Strict types enforcement
- Error handling matching PHP error levels (E_NOTICE, E_WARNING, E_ERROR, E_PARSE)
- Object reference semantics via Rc<RefCell<>>
- $GLOBALS superglobal support
- PHPT test file parser and runner (--TEST--, --FILE--, --EXPECT--, --EXPECTF--, --SKIPIF--, --INI--, --ENV--, --ARGS--, --CLEAN--)
- Criterion benchmark harness

**Parser and Compiler (Phase 6)**

- Property hooks compilation (get/set) as separate ZOpArrays with recursion guards
- Asymmetric visibility parsing and enforcement (public private(set), protected(set))
- InitParentPropertyHookCall opcode for parent:: hook dispatch
- DeclareAttributedConst opcode for PHP 8.5 attributed constants
- Attributes on functions, methods, and parameters with target validation (Attribute::TARGET_*)
- Named arguments with spread operator support (func(...$args, name: $val))

**Standard Library (Phase 7)**

- list() and short array destructuring ([...] = $array) via FetchListR/FetchListW opcodes
- Stream functions: stream_filter_append/prepend, stream_socket_client/server, stream_select, stream_set_blocking/timeout, stream_wrapper_register
- proc_open with full descriptor spec (pipes, files), proc_close, proc_get_status, proc_terminate, proc_nice
- php://input stream support
- Real output buffering with ob_stack (ob_start, ob_get_contents, ob_end_flush, ob_start callbacks)
- Real file-backed PHP sessions
- 99.7% PHP standard library coverage (2225/2231 functions) across array, string, file, math, and more

**Extensions (Phase 8)**

- PCRE extension: preg_match, preg_match_all, preg_replace, preg_split with full regex support
- JSON extension: json_encode, json_decode
- mbstring extension for multibyte string operations
- DateTime and DateTimeImmutable classes
- SPL: iterator classes (ArrayIterator, DirectoryIterator, etc.) and data structures (SplStack, SplQueue, SplPriorityQueue, SplFixedArray)
- bcmath extension for arbitrary precision arithmetic
- filter extension (filter_var, filter_input)
- calendar extension
- gd extension: pure Rust image creation and manipulation (imagecreatetruecolor, imagecreate, imagesetpixel, imageline, Bresenham-style drawing)
- intl extension: NumberFormatter, Collator, DateFormatter, Normalizer, Transliterator
- PDO with PostgreSQL and MySQL drivers, full SQLite3 class support
- cURL extension with real HTTP networking via ureq, CURLOPT/CURLINFO/CURLE constants
- openssl extension with real digest and password hashing (bcrypt, PBKDF2)
- sodium extension with real cryptographic operations
- random extension
- hash extension (SHA384/512, HMAC)
- zlib/flate2 compression
- pack/unpack for binary data serialization
- 26 stub extensions wired to real implementations

**SAPI Layer (Phase 10)**

- CLI SAPI as the main binary
- FPM SAPI with:
  - Full FastCGI request/response cycle with superglobal injection ($_SERVER, $_GET, $_POST, $_COOKIE, $_REQUEST, $_ENV, $_FILES)
  - Pool modes: static, dynamic, and ondemand with configurable worker scaling
  - Thread-based worker pool with mpsc channel dispatch and graceful shutdown
  - Status page (pm.status_path) in plain text and JSON formats, plus ping page
  - Slow log with request timing and configurable threshold
  - php-fpm.conf INI-style parser with full directive support
- Built-in web server (-S) with:
  - Router script support (returns false to fall through to static files)
  - Concurrent request handling via thread pool (default 4 workers)
  - Access logging with ISO 8601 timestamps and response timing
- Embeddable library SAPI
- WebAssembly target for running PHP in the browser
- Docker support with PostgreSQL and MySQL

**Tooling**

- Composer support: dependency resolution, create-project, run-script
- Laravel framework compatibility
- CI via GitHub Actions
- Criterion benchmarks for echo loops, array operations, function calls, object creation, string concatenation

### Changed

**Runtime and VM Structure (Phases 9, 11, 12)**

- INI system, stream layer, and session handling integrated into runtime crate
- PHPT test runner infrastructure hardened for compatibility testing
- VM refactored: call_builtin match arms extracted into builtins/ submodules
- Parent constructor call tracking ($this before parent::__construct) with Frame.parent_ctor_called flag

### Performance

- Hot loop optimization: error conversion extracted to #[cold] path, dispatch_op remains #[inline] for jump table optimization
- Arena allocator for request-scoped memory with 256KB bump-pointer chunks, integrated into VM and reset at request start
- Packed array optimization: O(1) indexed access for sequential 0..n keys, hash indexes built lazily for arrays >16 entries
- Copy-on-write for strings and arrays: clone is O(1) Rc bump, deep copy deferred to first mutation via Rc::make_mut
- StringPool with FNV-1a hashing for Rc<str> interning, integrated into VM and reset per request
- Opcode cache: file-to-compiled-oparray cache with mtime-based invalidation, avoiding recompilation of unchanged files
- Benchmark suite comparing against PHP-src for echo loops (1M iterations), array operations (sort/map/filter), function call overhead, object creation, and string concatenation
