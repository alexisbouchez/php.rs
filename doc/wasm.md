# WASM Build Guide

Build php.rs for WebAssembly to run PHP in browsers and Node.js.

## Prerequisites

```bash
# Install wasm-pack
cargo install wasm-pack

# Install wasm32 target
rustup target add wasm32-unknown-unknown
```

## Building

### Browser target (recommended)

```bash
wasm-pack build crates/php-rs-sapi-wasm --target web --release --out-dir ../../pkg
```

### Node.js target

```bash
wasm-pack build crates/php-rs-sapi-wasm --target nodejs --release --out-dir ../../pkg
```

### Minimal build (no native-io features)

```bash
cargo build --target wasm32-unknown-unknown --release \
    -p php-rs-sapi-wasm --no-default-features
```

The `--no-default-features` flag disables:
- File system access (uses virtual filesystem instead)
- Network I/O (sockets, cURL)
- Process execution (exec, proc_open)
- Database drivers (MySQL, PostgreSQL)

## Output

After building, the `pkg/` directory contains:

```
pkg/
├── php_rs_sapi_wasm_bg.wasm    # ~3 MB compiled WASM binary
├── php_rs_sapi_wasm_bg.wasm.d.ts
├── php_rs_sapi_wasm.js          # JS glue code
├── php_rs_sapi_wasm.d.ts        # TypeScript definitions
└── package.json
```

## Browser Usage

```html
<script type="module">
import init, { PhpWasm } from './pkg/php_rs_sapi_wasm.js';

async function main() {
    await init();
    const php = new PhpWasm();

    const output = php.eval('<?php echo "Hello from WASM!"; ?>');
    console.log(output); // "Hello from WASM!"

    // Run a complete script
    const result = php.run(`<?php
        $arr = [3, 1, 4, 1, 5];
        sort($arr);
        echo json_encode($arr);
    ?>`);
    console.log(result); // [1,1,3,4,5]
}

main();
</script>
```

## Node.js Usage

```javascript
const { PhpWasm } = require('./pkg/php_rs_sapi_wasm.js');

const php = new PhpWasm();
console.log(php.eval('<?php echo phpversion(); ?>'));
```

## What's Included

The WASM build includes:
- Full PHP interpreter (lexer, parser, compiler, VM)
- All 212 VM opcodes
- Complete type system (arrays, objects, closures, generators, fibers)
- Standard library functions (string, array, math, date, json, pcre, mbstring)
- OOP with traits, interfaces, enums, property hooks
- Virtual filesystem for file operations

## What's Excluded

Due to WASM sandboxing:
- No real filesystem access (use virtual filesystem API)
- No network I/O (no sockets, no cURL)
- No process execution
- No database connections
- No OpenSSL/Sodium crypto (use Web Crypto API instead)

## Size Optimization

For smaller WASM binaries:

```toml
# In Cargo.toml [profile.release]
[profile.release]
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit
strip = true         # Strip debug info
```

Typical sizes:
- Default release: ~3 MB
- Size-optimized: ~2 MB
- With wasm-opt: ~1.5 MB

```bash
# Post-process with wasm-opt (from binaryen)
wasm-opt -Oz pkg/php_rs_sapi_wasm_bg.wasm -o pkg/php_rs_sapi_wasm_bg.wasm
```

## Playground

The `examples/playground/` directory contains a web-based PHP playground using the WASM build. See the [WASM Playground section](../README.md#wasm-playground) in the README.
