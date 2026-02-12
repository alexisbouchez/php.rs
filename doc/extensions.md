# Extension Development Guide

This guide explains how to create a new PHP extension for php.rs.

## Overview

Each PHP extension is a separate Rust crate under `crates/php-rs-ext-<name>/`. Extensions implement the `PhpExtension` trait and register their functions with the VM.

## Creating a New Extension

### 1. Create the crate

```bash
cargo init crates/php-rs-ext-myext --lib
```

### 2. Add dependencies to `Cargo.toml`

```toml
[package]
name = "php-rs-ext-myext"
version = "0.1.0"
edition = "2021"

[dependencies]
# No dependencies on php-rs-vm — extensions are standalone
```

### 3. Add to workspace

In the root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing crates ...
    "crates/php-rs-ext-myext",
]
```

### 4. Implement the extension

```rust
// crates/php-rs-ext-myext/src/lib.rs

/// My extension module info.
pub struct MyExtInfo;

impl MyExtInfo {
    pub fn name() -> &'static str {
        "myext"
    }

    pub fn version() -> &'static str {
        "1.0.0"
    }
}

/// myext_hello() — Returns a greeting string.
pub fn myext_hello(name: &str) -> String {
    format!("Hello, {}!", name)
}

/// myext_add(int $a, int $b) — Adds two integers.
pub fn myext_add(a: i64, b: i64) -> i64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_myext_hello() {
        assert_eq!(myext_hello("World"), "Hello, World!");
    }

    #[test]
    fn test_myext_add() {
        assert_eq!(myext_add(2, 3), 5);
    }
}
```

### 5. Register with the VM

In `crates/php-rs-vm/Cargo.toml`, add the dependency:

```toml
php-rs-ext-myext = { path = "../php-rs-ext-myext" }
```

Then wire the functions into the VM dispatch. There are two approaches:

**A) HashMap registry** (for functions with standard signatures):

In `crates/php-rs-vm/src/builtins/misc.rs` (or a new file):

```rust
use crate::value::Value;
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

fn php_myext_hello(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    Ok(Value::String(php_rs_ext_myext::myext_hello(&name)))
}

// Register in build_builtins():
r.insert("myext_hello", php_myext_hello);
```

**B) Dispatch module** (for complex functions needing pattern matching):

Create `crates/php-rs-vm/src/builtins/myext.rs`:

```rust
use crate::value::Value;
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

pub(crate) fn dispatch(
    vm: &mut Vm,
    name: &str,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Option<Value>> {
    match name {
        "myext_hello" => {
            let name = args.first().map(|v| v.to_php_string()).unwrap_or_default();
            Ok(Some(Value::String(php_rs_ext_myext::myext_hello(&name))))
        }
        "myext_add" => {
            let a = args.first().map(|v| v.to_long()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_long()).unwrap_or(0);
            Ok(Some(Value::Long(php_rs_ext_myext::myext_add(a, b))))
        }
        _ => Ok(None),
    }
}
```

Then add to `crates/php-rs-vm/src/vm/mod.rs` in `call_builtin()`:

```rust
try_dispatch!(myext);
```

### 6. Add integration tests

In `crates/php-rs-vm/src/vm/tests.rs`:

```rust
#[test]
fn test_myext_hello() {
    let output = run_php(r#"<?php echo myext_hello("World"); ?>"#);
    assert_eq!(output, "Hello, World!");
}

#[test]
fn test_myext_add() {
    let output = run_php(r#"<?php echo myext_add(2, 3); ?>"#);
    assert_eq!(output, "5");
}
```

## Extension Conventions

- **Naming**: Crate name is `php-rs-ext-<phpname>` (e.g., `php-rs-ext-json` for ext/json)
- **Functions**: PHP function names map directly to Rust functions (e.g., `json_encode` → `php_json_encode`)
- **Classes**: PHP classes use the VM's OOP system — register via `class_defs` in the VM
- **Constants**: Register in the VM's `constants` HashMap
- **Resources**: Use `vm.next_resource_id` to allocate resource IDs, store handles in a HashMap on the VM
- **Error handling**: Use `VmResult<Value>` — return `Err(VmError::...)` for fatal errors, emit warnings via `vm.emit_warning()`
- **Testing**: Always write tests first (TDD), derive from `.phpt` files in `php-src/ext/<name>/tests/`

## Existing Extensions Reference

| Extension | Crate | Functions | Notes |
|-----------|-------|-----------|-------|
| standard | php-rs-ext-standard | 551 | Array, string, file, math functions |
| json | php-rs-ext-json | 4 | json_encode, json_decode, etc. |
| pcre | php-rs-ext-pcre | 6 | preg_match, preg_replace, etc. |
| date | php-rs-ext-date | 20+ | DateTime, DateInterval, etc. |
| mbstring | php-rs-ext-mbstring | 30+ | Multibyte string functions |
| gd | php-rs-ext-gd | 40+ | Image creation/manipulation |
| intl | php-rs-ext-intl | 20+ | NumberFormatter, Collator, etc. |
| pdo | php-rs-ext-pdo | 10+ | PDO database abstraction |
| spl | Built into VM | 50+ | Iterators, data structures, autoloading |
