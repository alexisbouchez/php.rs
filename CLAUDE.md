# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**php.rs** is a ground-up rewrite of the PHP interpreter in Rust, targeting full compatibility with PHP 8.6. The reference implementation lives at `php-src/` (cloned from https://github.com/php/php-src). We follow strict TDD: every behavior is tested before implemented.

## Architecture

The PHP interpreter has a layered architecture we replicate in Rust:

```
┌──────────────────────────────────────┐
│  SAPI Layer (CLI, FPM, CGI, Embed)   │  ← Server API bindings
├──────────────────────────────────────┤
│  Main Layer (INI, streams, variables)│  ← PHP runtime services
├──────────────────────────────────────┤
│  Zend Engine (VM, compiler, GC)      │  ← Core interpreter
├──────────────────────────────────────┤
│  Extensions (standard, json, pcre…)  │  ← Built-in + loadable modules
└──────────────────────────────────────┘
```

### Crate Structure

- `crates/php-rs-types/` — Value types: `ZVal` (16-byte tagged union), `ZString` (refcounted + interned), `ZArray` (packed + hash dual-mode), `ZObject`
- `crates/php-rs-lexer/` — Tokenizer (re2c-equivalent, hand-written in Rust)
- `crates/php-rs-parser/` — Parser producing AST (Bison-equivalent, recursive descent)
- `crates/php-rs-compiler/` — AST → opcode array compilation
- `crates/php-rs-vm/` — Virtual machine executor (212 opcodes, computed-goto-style dispatch)
- `crates/php-rs-gc/` — Garbage collector with cycle detection + request-scoped arena
- `crates/php-rs-runtime/` — INI system, output buffering, error handling, stream wrappers
- `crates/php-rs-ext-standard/` — ext/standard: 551 built-in functions (array_*, str_*, file_*, math)
- `crates/php-rs-ext-*/` — One crate per extension (json, pcre, date, dom, pdo, spl, etc.)
- `crates/php-rs-sapi-cli/` — CLI SAPI (main binary)
- `crates/php-rs-sapi-fpm/` — FPM SAPI
- `crates/php-rs-sapi-embed/` — Embeddable library SAPI
- `php-rs/` — Workspace root, integration tests, PHPT test runner

## Build & Test Commands

```bash
# Build everything
cargo build

# Build a specific crate
cargo build -p php-rs-vm

# Run all unit tests
cargo test

# Run tests for a specific crate
cargo test -p php-rs-types

# Run a single test by name
cargo test -p php-rs-parser test_if_else_parsing

# Run PHPT compatibility tests (against reference PHP test suite)
cargo test -p php-rs --test phpt_runner

# Run PHPT tests for a specific directory
PHPT_DIR=php-src/tests/lang cargo test -p php-rs --test phpt_runner

# Run with verbose output
cargo test -- --nocapture

# Check without building
cargo check

# Lint
cargo clippy --all-targets --all-features

# Format
cargo fmt --all

# Benchmarks
cargo bench -p php-rs-vm
```

## TODO.txt — Mandatory Task Tracking

**`TODO.txt` at the repository root is the single source of truth for project progress.** This is non-negotiable:

- **Before starting any work**, read `TODO.txt` to find the current task and phase.
- **After completing a task**, update `TODO.txt` immediately: change `[ ]` to `[x]` for the finished item.
- **Never skip ahead** to a later phase while earlier phases have unchecked items (unless explicitly told to by the user).
- **If a task is in progress**, mark it `[~]`. If blocked, mark it `[!]` and add a note explaining why.
- **When adding new work** discovered during implementation (e.g., an edge case that needs its own test), add it as a new sub-item under the relevant phase in `TODO.txt`.
- **At the start of every session**, read `TODO.txt` and report what phase/task we're on.

The file uses this format:
```
[ ] Not started
[~] In progress
[x] Done
[!] Blocked
```

## Development Methodology: TDD, Small Steps

**Every PR follows Red-Green-Refactor:**
1. **Red** — Write a failing test that captures the exact PHP behavior (often derived from a `.phpt` file in `php-src/tests/`)
2. **Green** — Implement the minimum code to pass the test
3. **Refactor** — Clean up while keeping tests green

### Deriving Tests from PHP Source

The reference PHP test suite uses `.phpt` format:
```
--TEST--
Description
--FILE--
<?php ... ?>
--EXPECT--
expected output
```
Sections: `--TEST--`, `--FILE--`, `--EXPECT--`, `--EXPECTF--` (format specifiers: `%s`, `%d`, `%f`), `--SKIPIF--`, `--INI--`, `--ENV--`, `--ARGS--`, `--POST--`, `--CLEAN--`.

When implementing a feature, find relevant `.phpt` files in `php-src/tests/` and `php-src/ext/*/tests/` and translate them to Rust tests first.

### Compatibility Rules

- Bit-for-bit output compatibility with PHP 8.6 for all non-deprecated behaviors
- Same type coercion rules, same operator semantics, same error messages
- When in doubt, write a PHP script, run it with `php-src/sapi/cli/php`, and match the output
- Reference: `php-src/Zend/zend_vm_opcodes.h` (212 opcodes), `php-src/Zend/zend_types.h` (type system)

## Key Reference Files in php-src/

| What | Where |
|------|-------|
| Type system (zval layout) | `php-src/Zend/zend_types.h` |
| All 212 VM opcodes | `php-src/Zend/zend_vm_opcodes.h` |
| VM handler definitions | `php-src/Zend/zend_vm_def.h` (302 KB, human-readable) |
| Generated VM dispatch | `php-src/Zend/zend_vm_execute.h` (3.8 MB) |
| Compiler (AST→opcodes) | `php-src/Zend/zend_compile.c` (384 KB) |
| Lexer definition | `php-src/Zend/zend_language_scanner.l` |
| Parser grammar | `php-src/Zend/zend_language_parser.y` |
| HashTable implementation | `php-src/Zend/zend_hash.c` |
| Memory allocator | `php-src/Zend/zend_alloc.c` |
| GC cycle collector | `php-src/Zend/zend_gc.c` |
| OOP inheritance | `php-src/Zend/zend_inheritance.c` |
| Standard functions | `php-src/ext/standard/basic_functions.c` |
| Array functions | `php-src/ext/standard/array.c` |
| String functions | `php-src/ext/standard/string.c` |

## Coding Conventions

- All public types that mirror PHP internals get a `Z` prefix: `ZVal`, `ZString`, `ZArray`, `ZObject`, `ZOp`, `ZOpArray`
- Use `#[cfg(test)]` modules in each file, not separate test files, for unit tests
- Integration tests (PHPT-based) go in `tests/`
- Prefer `enum` for PHP types — Rust enums map naturally to PHP's tagged union zvals
- Use `Arc<str>` or a custom interned string pool for string interning (not `String`)
- Arena allocation for request-scoped memory: everything allocated during a request is freed in bulk at request end
- No `unsafe` without a `// SAFETY:` comment explaining the invariant
- Every opcode handler is a separate function: `fn op_add(frame: &mut Frame) -> VmResult`
- Match PHP's error levels: `E_NOTICE`, `E_WARNING`, `E_ERROR`, `E_PARSE`, etc. as a Rust enum
- Extensions implement the `PhpExtension` trait with lifecycle hooks: `module_init`, `module_shutdown`, `request_init`, `request_shutdown`

## Performance Considerations

- `ZVal` must be exactly 16 bytes (8-byte value union + 8-byte type/flags) — same as PHP's zval
- HashTable uses open addressing with Robin Hood hashing; packed arrays (consecutive integer keys 0..n) use a Vec-like backing
- The VM hot loop must avoid allocation; pre-allocate the operand stack
- String interning is critical for performance — function names, variable names, class names are all interned
- Use `#[inline]` on opcode handlers and type-check fast paths
- Benchmark against PHP-src regularly: `echo` loops, array operations, function call overhead, object creation

## Ralph Loop (Autonomous Mode)

This project uses an autonomous loop (`ralph.sh`) that invokes Claude Code headless (`-p`) to work through `TODO.txt` one item at a time. When running inside Ralph:

- You receive instructions from `.claude/ralph-prompt.md` — follow them exactly.
- Your **last line of output** MUST be a status code: `RALPH_OK`, `RALPH_FAIL`, `RALPH_BLOCKED`, or `RALPH_DONE`.
- Work on exactly ONE `[ ]` item per invocation. Do not batch.
- Always run `cargo test`, `cargo fmt --all`, `cargo clippy --all-targets` before finishing.
- Commit completed work: `git add -A && git commit -m "[Phase.Item] description"`.
- Logs are saved to `.ralph-logs/`. If you see previous iteration failures there, learn from them.

Run Ralph: `./ralph.sh` (or `./ralph.sh --max 10 --model opus --budget 8`)

## What NOT To Do

- Do not implement deprecated PHP features (e.g., `mysql_*` functions, `each()`, short open tags logic unless `short_open_tag=On`)
- Do not write C FFI bindings to existing PHP extensions — reimplement in pure Rust
- Do not attempt multi-file changes without tests passing at each step
- Do not optimize before correctness is proven by tests
- Do not skip the 74 extensions — they ARE the standard library; PHP without them is useless
