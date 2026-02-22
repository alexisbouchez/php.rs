<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://www.php.net/images/logos/new-php-logo.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://www.php.net/images/logos/new-php-logo.svg">
    <img alt="php.rs" src="https://www.php.net/images/logos/new-php-logo.svg" height="128">
  </picture>
</p>

<h1 align="center">php.rs</h1>

<p align="center">
  <strong>A ground-up rewrite of the PHP interpreter in pure Rust.</strong><br>
  Targeting bit-for-bit compatibility with PHP 8.6.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#wasm-playground">WASM Playground</a> &middot;
  <a href="#composer">Composer</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#extensions">Extensions</a> &middot;
  <a href="#building">Building</a> &middot;
  <a href="#testing">Testing</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/alexisbouchez/php-rs/actions"><img src="https://img.shields.io/github/actions/workflow/status/alexisbouchez/php-rs/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/PHP-8.6-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP 8.6">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust 2021">
</p>

---

## Why?

PHP powers millions of websites worldwide and has a mature ecosystem. **php.rs** reimagines the PHP interpreter using Rust.

**Goals:**

- **Memory safety.** Rust's ownership system provides guarantees at compile time, reducing runtime errors.
- **Modern tooling.** `cargo build` for building, `cargo test` for testing. Cross-compilation works out of the box.
- **Full compatibility.** Bit-for-bit output compatibility with PHP 8.6. Same type coercion, same error messages, same edge cases. Your existing PHP code runs identically.
- **Embeddable.** Link `php-rs` into any Rust application as a library. Run PHP from Rust, or extend PHP with Rust.

This is not a transpiler, a subset, or a "PHP-inspired" language. It is PHP: the complete interpreter, compiler, and standard library, reimplemented in 100,000+ lines of Rust.

---

## Quick Start

### Install from source

```bash
git clone https://github.com/alexisbouchez/php-rs.git
cd php-rs
cargo build --release
```

The binary lands at `./target/release/php-rs-sapi-cli`.

### Run PHP

```bash
# Execute inline code
./target/release/php-rs-sapi-cli -r 'echo "Hello from Rust!\n";'

# Execute a file
./target/release/php-rs-sapi-cli script.php

# Start the built-in web server
./target/release/php-rs-sapi-cli -S localhost:8080

# Interactive REPL
./target/release/php-rs-sapi-cli -a

# Syntax check (lint)
./target/release/php-rs-sapi-cli -l script.php

# Show loaded modules
./target/release/php-rs-sapi-cli -m
```

### CLI Reference

```
Usage: php-rs [options] [-f] <file> [--] [args...]
       php-rs [options] -r <code> [--] [args...]
       php-rs [options] -S <addr>:<port> [-t <docroot>]
       php-rs [options] [-a]

Options:
  -a              Interactive mode (REPL)
  -c <path>       Look for php.ini in this directory
  -n              No configuration file
  -d key[=value]  Define INI entry
  -f <file>       Parse and execute file
  -r <code>       Execute PHP code without <?php tags
  -l              Syntax check only (lint)
  -S <addr:port>  Start built-in web server
  -t <docroot>    Document root for -S
  -s              Output HTML syntax-highlighted source
  -w              Output source with stripped comments
  -v              Version information
  -m              Show compiled-in modules
  -i              PHP information (phpinfo)
  -h, --help      Show help
```

### Docker

Run php.rs in Docker with PostgreSQL and MySQL support:

```bash
# Build the image
docker build -t php-rs .

# Run inline code
docker run --rm php-rs -r 'echo "Hello from Docker!\n";'

# Run a PHP file (mount current directory)
docker run --rm -v $(pwd):/var/www php-rs /var/www/script.php

# Start with databases (PostgreSQL + MySQL)
docker-compose up -d

# Execute with database access
docker-compose run --rm php-rs -r '
$pdo = new PDO("pgsql:host=postgres;dbname=phpdb", "phpuser", "phppass");
echo "Connected to PostgreSQL!\n";
'
```

**What's included:**
- Multi-stage build (150MB runtime image)
- PostgreSQL driver (PDO + libpq)
- MySQL driver (mysqli)
- SQLite (built-in)
- docker-compose with PostgreSQL 16 + MySQL 8.0

**Database connections:**
```php
// PostgreSQL
$pdo = new PDO("pgsql:host=postgres;dbname=phpdb", "phpuser", "phppass");

// MySQL
$mysqli = mysqli_connect("mysql", "phpuser", "phppass", "phpdb");

// SQLite
$pdo = new PDO("sqlite::memory:");
```

### WASM Playground

Run PHP directly in the browser — no server required. php.rs compiles to WebAssembly:

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM binary
wasm-pack build crates/php-rs-sapi-wasm --target web --release --out-dir ../../pkg

# Serve the playground
npx serve .
# Open http://localhost:3000/examples/playground/
```

**Using from JavaScript/TypeScript:**

```js
import init, { PhpWasm } from '@php-rs/wasm';

await init();
const php = new PhpWasm();

// Execute PHP code
const output = php.eval('<?php echo "Hello from WASM!";');
console.log(output); // "Hello from WASM!"

// Virtual filesystem
php.write_file('/app.php', new TextEncoder().encode('<?php echo 42 + 8;'));
const result = php.exec_file('/app.php');
console.log(result); // "50"

// Tokenize PHP for editor tooling
const tokens = JSON.parse(php.tokenize('<?php echo "hi";'));

// Parse PHP to AST
const ast = php.parse('<?php $x = 1 + 2;');

// Reset VM state (keeps VFS)
php.reset();
```

**What's included in the WASM build:**
- Full PHP interpreter (~3 MB `.wasm`)
- In-memory virtual filesystem
- Tokenizer and parser for editor tooling
- INI and environment variable configuration
- 20 pure-Rust extensions (json, hash, pcre, mbstring, date, spl, bcmath, zlib, and more)

**What's excluded (requires native I/O):**
- Network extensions (curl, mysqli, pdo, sockets)
- Process control (pcntl, posix)
- System extensions (shmop, sysvmsg)

### Composer

php.rs includes a built-in Composer-compatible package manager:

```bash
# Create a new project from a package
./target/release/php-rs composer create-project laravel/laravel my-app

# Install dependencies from composer.json
./target/release/php-rs composer install

# Add a dependency
./target/release/php-rs composer require monolog/monolog

# Remove a dependency
./target/release/php-rs composer remove monolog/monolog

# Update dependencies
./target/release/php-rs composer update

# Search packages on Packagist
./target/release/php-rs composer search http client

# Show installed packages
./target/release/php-rs composer show

# Initialize a new composer.json
./target/release/php-rs composer init

# Validate composer.json
./target/release/php-rs composer validate

# Regenerate autoload files
./target/release/php-rs composer dump-autoload
```

The package manager resolves dependencies from [Packagist](https://packagist.org), downloads archives in parallel, generates PSR-4 autoload files, and writes `composer.lock` for reproducible installs -- all implemented in pure Rust with no dependency on the PHP Composer binary.

---

## Architecture

php.rs faithfully replicates the layered architecture of the official PHP interpreter:

```
                         +-----------------------+
    Your PHP Code  --->  |      SAPI Layer       |  CLI, FPM, Embed
                         +-----------------------+
                         |    Runtime Services    |  INI, streams, output buffering
                         +-----------------------+
                         |     Zend Engine        |  Lexer -> Parser -> Compiler -> VM
                         +-----------------------+
                         |     Extensions         |  standard, json, pcre, curl, ...
                         +-----------------------+
```

The execution pipeline mirrors PHP exactly:

```
 Source Code
     |
     v
 +---------+     +--------+     +----------+     +----+
 |  Lexer  | --> | Parser | --> | Compiler | --> | VM |  --> Output
 +---------+     +--------+     +----------+     +----+
  Tokens          AST            Opcodes          Execute
```

### Crate Map

The project is organized as a Cargo workspace with **68 crates** across 4 layers:

#### Core Engine (7 crates)

| Crate | Purpose | LOC |
|-------|---------|-----|
| `php-rs-types` | `ZVal` (16-byte tagged union), `ZString`, `ZArray`, `ZObject` | 6,700 |
| `php-rs-lexer` | Tokenizer (hand-written, re2c-equivalent) | 1,000 |
| `php-rs-parser` | Recursive descent parser producing AST | 6,800 |
| `php-rs-compiler` | AST to opcode array compilation | 5,960 |
| `php-rs-vm` | Virtual machine executor, 212 opcodes | 16,800 |
| `php-rs-gc` | Garbage collector with cycle detection | 500+ |
| `php-rs-runtime` | INI system, output buffering, error handling, streams | 2,660 |

#### Extensions (56 crates)

Every PHP extension is its own crate: `php-rs-ext-standard`, `php-rs-ext-json`, `php-rs-ext-curl`, etc. See [Extensions](#extensions) for the full list.

#### Server APIs (4 crates)

| Crate | Purpose |
|-------|---------|
| `php-rs-sapi-cli` | Command-line interface, built-in web server, REPL |
| `php-rs-sapi-fpm` | FastCGI Process Manager |
| `php-rs-sapi-embed` | Embeddable library for Rust applications |
| `php-rs-sapi-wasm` | WebAssembly target for browsers and Node.js |

#### Tooling (2 crates)

| Crate | Purpose |
|-------|---------|
| `php-rs-composer` | Composer package manager integration |
| `php-rs` | Workspace root, integration tests, PHPT runner |

---

## Features

### Language Features

php.rs implements the complete PHP 8.6 language:

**Types & Values**
- Scalar types: `int`, `float`, `string`, `bool`, `null`
- Compound types: `array`, `object`, `callable`
- Union types (`int|string`), intersection types (`A&B`), nullable (`?int`)
- `never`, `void`, `mixed`, `self`, `static`, `parent`
- Type coercion following PHP's exact juggling rules

**Control Flow**
- `if`/`elseif`/`else`, `switch`/`case`, `match` expressions
- `while`, `do-while`, `for`, `foreach`
- `break`, `continue` with levels
- `return`, `goto`/labels
- `try`/`catch`/`finally`, `throw`

**Functions**
- Named functions, anonymous functions (closures)
- Arrow functions (`fn($x) => $x * 2`)
- Variadic parameters (`...$args`)
- Named arguments
- First-class callable syntax (`strlen(...)`)
- Generators (`yield`, `yield from`)
- Fibers

**Object-Oriented Programming**
- Classes, abstract classes, final classes, readonly classes
- Interfaces, traits, enums (backed and unit)
- Inheritance, multiple trait use, trait conflict resolution
- Constructors, destructors, magic methods
- Property hooks, typed properties, readonly properties
- Constructor promotion
- Visibility modifiers (public, protected, private)
- Static methods and properties
- Constants, class constants, enum cases
- `instanceof`, `clone`, `new` in expressions

**Other**
- Namespaces, `use` imports (classes, functions, constants)
- String interpolation (`"Hello $name"`, `"Hello {$obj->name}"`)
- Heredoc and Nowdoc syntax
- List assignments (`[$a, $b] = $arr`)
- Spread operator in arrays and function calls
- Null coalescing (`??`), null coalescing assignment (`??=`)
- Spaceship operator (`<=>`)
- Error suppression (`@`)
- Include/require/include_once/require_once

### Virtual Machine

The VM implements all **212 PHP opcodes** with a computed-goto-style dispatch loop:

- Arithmetic: `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`
- Bitwise: `BW_AND`, `BW_OR`, `BW_XOR`, `BW_NOT`, `SL`, `SR`
- Comparison: `IS_EQUAL`, `IS_IDENTICAL`, `IS_SMALLER`, `SPACESHIP`
- Assignment: `ASSIGN`, `ASSIGN_OP`, `ASSIGN_DIM`, `ASSIGN_OBJ`
- Control flow: `JMP`, `JMPZ`, `JMPNZ`, `SWITCH_LONG`, `MATCH`
- Functions: `INIT_FCALL`, `SEND_VAL`, `DO_FCALL`, `RETURN`
- OOP: `NEW`, `INIT_METHOD_CALL`, `FETCH_OBJ_R`, `FETCH_CLASS`
- Arrays: `INIT_ARRAY`, `ADD_ARRAY_ELEMENT`, `FE_RESET`, `FE_FETCH`
- Generators: `YIELD`, `YIELD_FROM`, `GENERATOR_RETURN`
- Fibers: `FIBER_SUSPEND`
- And 190+ more...

### Type System

`ZVal` is exactly 16 bytes, matching PHP's internal `zval` layout:

```
+-------------------+-------------------+
|    Value (8B)     |  Type + Flags (8B)|
+-------------------+-------------------+
```

- **ZString**: Reference-counted with interning for identifiers
- **ZArray**: Dual-mode (packed vector for `0..n` integer keys, hash table otherwise)
- **ZObject**: Property table with class pointer
- **Arena allocation**: Request-scoped bulk deallocation

### Garbage Collector

- Reference counting for immediate cleanup
- Cycle detection for circular references
- Request-scoped arena: bulk-free at request end

---

## Extensions

56 PHP extensions reimplemented in pure Rust (no C FFI):

### Core

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **standard** | 199 | Arrays, strings, math, file I/O, variables, misc |
| **spl** | 114 | Standard PHP Library (iterators, data structures, exceptions) |
| **reflection** | 88 | Runtime reflection API |
| **date** | 36 | Date/time manipulation |
| **pcre** | 8 | Perl-compatible regular expressions |
| **json** | 6 | JSON encoding and decoding |
| **filter** | 5 | Data filtering and validation |
| **tokenizer** | 3 | PHP source tokenization |

### Cryptography & Security

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **openssl** | 12 | OpenSSL cryptographic operations |
| **sodium** | 18 | Modern cryptography (libsodium) |
| **hash** | 7 | Hashing algorithms (SHA-384/512, HMAC, etc.) |

### Database

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **pdo** | 24 | Database abstraction layer |
| **pdo-mysql** | 5 | MySQL PDO driver |
| **pdo-pgsql** | 5 | PostgreSQL PDO driver |
| **mysqli** | 27 | MySQL improved interface |
| **mysqlnd** | 16 | MySQL native driver |
| **sqlite3** | 25 | SQLite3 interface |
| **odbc** | 21 | ODBC database connectivity |
| **dba** | 17 | Database abstraction (DBM-style) |

### Text & Encoding

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **mbstring** | 11 | Multibyte string handling (UTF-8, etc.) |
| **ctype** | 11 | Character type checking |
| **iconv** | 9 | Character encoding conversion |
| **intl** | 24 | Internationalization (ICU) |
| **gettext** | 10 | Localization/translation |

### Networking

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **curl** | 15 | HTTP client (backed by `ureq`) |
| **sockets** | 17 | Low-level socket operations |
| **ftp** | 17 | FTP client |
| **soap** | 21 | SOAP web services |
| **ldap** | 11 | LDAP directory access |
| **snmp** | 23 | SNMP protocol |

### Compression

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **zlib** | 9 | Deflate/gzip compression (`flate2`) |
| **bz2** | 10 | Bzip2 compression |
| **zip** | 18 | ZIP archive handling |
| **phar** | 13 | PHP Archive format |

### XML & Document

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **dom** | 43 | XML DOM manipulation |
| **xml** | 43 | Expat XML parsing |
| **xsl** | 12 | XSLT transformations |
| **tidy** | 12 | HTML cleaning and repair |

### Math

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **bcmath** | 10 | Arbitrary-precision arithmetic |
| **gmp** | 25 | GNU Multiple Precision arithmetic |

### Image

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **gd** | 26 | Image creation and manipulation |
| **exif** | 3 | EXIF metadata reading |

### System

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **posix** | 25 | POSIX system functions |
| **pcntl** | 18 | Process control |
| **session** | 27 | Session management |
| **random** | 13 | Cryptographically secure random |
| **fileinfo** | 6 | File type detection |
| **shmop** | 4 | Shared memory |
| **opcache** | - | Opcode caching |

### IPC

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **sysvmsg** | 7 | System V message queues |
| **sysvsem** | 4 | System V semaphores |
| **sysvshm** | 7 | System V shared memory |

### Other

| Extension | Functions | Description |
|-----------|-----------|-------------|
| **ffi** | 14 | Foreign Function Interface |
| **readline** | 4 | Interactive line editing |
| **calendar** | 14 | Calendar conversion |
| **enchant** | 7 | Spell checking |

---

## Building

### Prerequisites

- **Rust 1.70+** (2021 edition)
- That's it. No `autoconf`, no `bison`, no `re2c`, no system libraries.

### Build Commands

```bash
# Build everything (debug)
cargo build

# Build optimized release binary
cargo build --release

# Build a specific crate
cargo build -p php-rs-vm

# Check without building (faster feedback)
cargo check

# Format code
cargo fmt --all

# Lint
cargo clippy --all-targets --all-features
```

### Makefile Shortcuts

```bash
make build         # cargo build
make check         # cargo check
make test          # cargo test
make fmt           # cargo fmt --all
make lint          # cargo clippy
make bench         # cargo bench -p php-rs-vm
make clean         # cargo clean
make help          # show all targets
```

---

## Testing

php.rs uses a multi-layered testing strategy:

### Unit Tests

**1,039 unit tests** across the core engine:

| Crate | Tests |
|-------|-------|
| Types | 276 |
| Lexer | 217 |
| VM | 161 |
| Compiler | 159 |
| Parser | 127 |
| Runtime | 73 |
| GC | 25 |

```bash
# Run all tests
cargo test

# Test a specific crate
cargo test -p php-rs-vm

# Test a specific function
cargo test -p php-rs-parser test_if_else_parsing

# Verbose output
cargo test -- --nocapture
```

### PHPT Compatibility Tests

The official PHP test suite (`php-src/tests/`) contains **21,000+ PHPT test files**. php.rs includes a PHPT test runner that executes these directly:

```bash
# Run all PHPT tests
cargo test -p php-rs --test phpt_runner

# Run tests for a specific directory
PHPT_DIR=php-src/tests/lang cargo test -p php-rs --test phpt_runner
```

PHPT format support: `--TEST--`, `--FILE--`, `--EXPECT--`, `--EXPECTF--`, `--SKIPIF--`, `--INI--`, `--ENV--`, `--ARGS--`.

### Benchmarks

Criterion-based benchmarks measure real-world performance:

```bash
cargo bench -p php-rs-vm
```

Benchmarks include:
- Recursive Fibonacci
- Array sorting (1,000 elements)
- String concatenation (1,000 iterations)
- Class instantiation (100 objects)
- Function call overhead (1,000 calls)
- Arithmetic loops (10,000 iterations)

### CI Pipeline

Every push and PR runs on GitHub Actions:

- **Test Suite** &mdash; `cargo test --all-targets --all-features`
- **Format Check** &mdash; `cargo fmt --all -- --check`
- **Clippy Lints** &mdash; `cargo clippy -- -D warnings`
- **Miri** &mdash; Unsafe code verification on `php-rs-types` and `php-rs-gc`
- **AddressSanitizer** &mdash; Memory safety checks on core crates (nightly)

---

## Embedding php.rs

Use `php-rs-sapi-embed` to run PHP from your Rust application:

```rust
use php_rs_sapi_embed::PhpEmbed;

fn main() {
    let mut php = PhpEmbed::new();
    php.execute("echo 'Hello from embedded PHP!';");
}
```

---

## Project Status

**Active development.** The core interpreter pipeline is functional end-to-end:

- Lexer, parser, compiler, and VM are operational
- 212 VM opcodes implemented
- 56 extensions with 1,500+ built-in functions
- 1,039 unit tests passing
- CLI, FPM, Embed, and WASM SAPIs available
- Built-in development web server
- PHPT compatibility testing against official PHP test suite
- CI with tests, linting, Miri, and AddressSanitizer

### What Works

- Full expression evaluation with PHP type juggling
- Control flow (if/else, loops, switch, match, try/catch)
- Functions (named, anonymous, arrow, variadic, generators, fibers)
- Classes (inheritance, interfaces, traits, enums, readonly)
- Namespaces, autoloading, include/require
- String interpolation, heredoc/nowdoc
- Array operations (packed and hash modes)
- File I/O, networking (curl via ureq), compression (zlib)
- Cryptography (hash, openssl, sodium)
- JSON, PCRE, date/time, multibyte strings
- Garbage collection with cycle detection
- Built-in web server (`-S`)
- Interactive REPL (`-a`)
- Composer package manager (`create-project`, `install`, `require`, `update`)

---

## Development Methodology

php.rs follows strict **Test-Driven Development (TDD)**:

1. **Red** &mdash; Write a failing test derived from PHP's official test suite
2. **Green** &mdash; Implement the minimum code to pass
3. **Refactor** &mdash; Clean up while keeping tests green

The canonical reference is `php-src/` (the official PHP interpreter source), cloned into the repository. When behavior is ambiguous, we run the PHP code against the reference interpreter and match the output exactly.

---

## Contributing

Contributions are welcome. The project follows a strict workflow:

1. Find or create an issue for the feature/bug
2. Write a failing test first (check `php-src/tests/` for reference behavior)
3. Implement the minimum code to pass
4. Ensure `cargo test`, `cargo fmt --all`, and `cargo clippy` all pass
5. Submit a PR

### Useful References

| What | Where |
|------|-------|
| PHP type system | `php-src/Zend/zend_types.h` |
| VM opcodes (212) | `php-src/Zend/zend_vm_opcodes.h` |
| VM handlers | `php-src/Zend/zend_vm_def.h` |
| Compiler | `php-src/Zend/zend_compile.c` |
| Parser grammar | `php-src/Zend/zend_language_parser.y` |
| Lexer | `php-src/Zend/zend_language_scanner.l` |
| Array functions | `php-src/ext/standard/array.c` |
| String functions | `php-src/ext/standard/string.c` |

---

## License

[MIT](LICENSE) &copy; 2026 Alexis Bouchez
