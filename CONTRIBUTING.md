# Contributing to php.rs

Thank you for your interest in contributing to php.rs, a ground-up rewrite of the PHP 8.6 interpreter in Rust. This document covers everything you need to get started.

## Getting Started

### Prerequisites

- **Rust 1.70+** (2021 edition) -- install via [rustup](https://rustup.rs/)
- **Git** -- to clone the repository and the PHP reference source

No other system dependencies are required. There is no need for `autoconf`, `bison`, `re2c`, or any C libraries.

### Setup

```bash
git clone https://github.com/alexisbouchez/php-rs.git
cd php-rs
cargo build
cargo test  # verify everything works
```

The CLI binary is built at `./target/debug/php-rs-sapi-cli` (or `./target/release/php-rs-sapi-cli` with `--release`).

## Development Workflow

php.rs follows strict **Test-Driven Development (TDD)** with a Red-Green-Refactor cycle:

1. **Red** -- Write a failing test that captures the exact PHP behavior. Tests are often derived from `.phpt` files in `php-src/tests/`.
2. **Green** -- Implement the minimum code required to make the test pass.
3. **Refactor** -- Clean up the implementation while keeping all tests green.

### Essential Commands

```bash
cargo build                              # build everything
cargo build -p php-rs-vm                 # build a specific crate
cargo test                               # run all tests
cargo test -p php-rs-types               # test a specific crate
cargo test -p php-rs-parser test_if_else # run a single test by name
cargo test -- --nocapture                # verbose output
cargo check                              # check without building
cargo clippy --all-targets --all-features # lint
cargo fmt --all                          # format
cargo bench -p php-rs-vm                 # benchmarks
```

### PHPT Compatibility Tests

The reference PHP test suite (`php-src/tests/`) contains 21,000+ test files:

```bash
cargo test -p php-rs --test phpt_runner                              # all PHPT tests
PHPT_DIR=php-src/tests/lang cargo test -p php-rs --test phpt_runner  # specific directory
```

## Code Style

### Naming Conventions

- Public types mirroring PHP internals use a `Z` prefix: `ZVal`, `ZString`, `ZArray`, `ZObject`, `ZOp`, `ZOpArray`.
- Opcode handlers are individual functions: `fn op_add(frame: &mut Frame) -> VmResult`.
- PHP error levels map to a Rust enum: `E_NOTICE`, `E_WARNING`, `E_ERROR`, `E_PARSE`, etc.
- Prefer Rust `enum` for PHP types -- they map naturally to PHP's tagged union zvals.

### Test Placement

- **Unit tests** go in `#[cfg(test)]` modules within the same file, not in separate test files.
- **Integration tests** (PHPT-based) go in the `tests/` directory.

### Unsafe Code

No `unsafe` block without an accompanying `// SAFETY:` comment explaining the invariant:

```rust
// SAFETY: `ptr` is non-null, properly aligned, and its lifetime
// is bounded by the arena allocator's request scope.
unsafe { &*ptr }
```

### Formatting and Linting

All code must pass these checks with no warnings before submission:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
```

## PR Process

### Branch Naming

Use descriptive branch names with a prefix: `feat/`, `fix/`, `refactor/`, or `test/`.

Examples: `feat/array-splice-function`, `fix/float-coercion-negative-zero`, `test/phpt-match-expressions`.

### Commit Messages

Use the imperative mood with a type prefix:

- `feat: implement array_splice() with all overloads`
- `fix: correct float-to-int coercion for negative zero`
- `test: add PHPT-derived tests for match expressions`

### What to Include in a PR

1. **Failing tests first.** Every PR should include tests that demonstrate the behavior being added or fixed.
2. **Minimal implementation.** Only the code necessary to make the tests pass.
3. **All checks passing.** `cargo test`, `cargo fmt --all -- --check`, and `cargo clippy` must all succeed.
4. **A clear description** of what the PR does and which PHP behavior it targets.

## Deriving Tests from PHP Source

The reference PHP test suite lives at `php-src/tests/` and `php-src/ext/*/tests/`. Tests use the `.phpt` format:

```
--TEST--
Description of the test
--FILE--
<?php
echo 1 + 2;
?>
--EXPECT--
3
```

Key sections: `--TEST--` (description), `--FILE--` (PHP code), `--EXPECT--` (exact output), `--EXPECTF--` (output with format specifiers like `%s`, `%d`), `--SKIPIF--` (skip condition), `--INI--` (settings), `--ENV--`, `--ARGS--`.

To translate a `.phpt` file into a Rust test: write a test that compiles and executes the same PHP code and asserts the same output. Place unit tests in `#[cfg(test)]` modules within the relevant crate.

When behavior is ambiguous, run the PHP code against the reference interpreter (`php-src/sapi/cli/php`) and match the output exactly.

## Extension Development

Each PHP extension is its own crate under `crates/php-rs-ext-*/` (56 total). Every extension implements the `PhpExtension` trait with four lifecycle hooks:

- `module_init` -- called once when the module is loaded
- `module_shutdown` -- called once when the module is unloaded
- `request_init` -- called at the start of each request
- `request_shutdown` -- called at the end of each request

### Adding a New Extension

1. Create a new crate: `crates/php-rs-ext-<name>/`
2. Implement the `PhpExtension` trait and register all functions
3. Write tests derived from `php-src/ext/<name>/tests/`
4. Wire the extension into the SAPI crates so it loads at startup

All extensions must be **pure Rust** -- no C FFI bindings to existing PHP extensions. Do not implement deprecated PHP features (e.g., `mysql_*` functions, `each()`).

## Architecture Overview

The interpreter follows the same layered architecture as the official PHP implementation:

```
Source Code --> Lexer --> Parser --> Compiler --> VM --> Output
               tokens    AST       opcodes     execute
```

### Crate Structure

| Layer | Crate | Purpose |
|-------|-------|---------|
| Types | `php-rs-types` | `ZVal` (16-byte tagged union), `ZString`, `ZArray`, `ZObject` |
| Lexer | `php-rs-lexer` | Hand-written tokenizer (re2c-equivalent) |
| Parser | `php-rs-parser` | Recursive descent parser producing AST |
| Compiler | `php-rs-compiler` | AST to opcode array compilation |
| VM | `php-rs-vm` | Virtual machine executor with 212 opcodes |
| GC | `php-rs-gc` | Garbage collector with cycle detection |
| Runtime | `php-rs-runtime` | INI system, output buffering, error handling, streams |
| Extensions | `php-rs-ext-*` | One crate per extension (standard, json, pcre, curl, etc.) |
| SAPIs | `php-rs-sapi-*` | Server API bindings (CLI, FPM, Embed, WASM) |

### Key Reference Files in php-src/

| What | Where |
|------|-------|
| Type system (zval layout) | `php-src/Zend/zend_types.h` |
| VM opcodes (212) | `php-src/Zend/zend_vm_opcodes.h` |
| VM handler definitions | `php-src/Zend/zend_vm_def.h` |
| Compiler (AST to opcodes) | `php-src/Zend/zend_compile.c` |
| Parser grammar | `php-src/Zend/zend_language_parser.y` |
| Lexer definition | `php-src/Zend/zend_language_scanner.l` |
| Standard library functions | `php-src/ext/standard/basic_functions.c` |

## Reporting Issues

### Bug Reports

Please include: (1) the PHP code that produces incorrect output, (2) expected output from the reference PHP 8.6 interpreter, (3) actual output from php.rs, (4) your Rust toolchain version (`rustc --version`), and (5) your OS and platform.

### Feature Requests

Feature requests are welcome. If requesting support for a specific PHP function or behavior, include a link to the PHP documentation and, if possible, the corresponding `.phpt` test files from `php-src/`.

## License

By contributing to php.rs, you agree that your contributions will be licensed under the [MIT License](LICENSE).
