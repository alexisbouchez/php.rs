# php.rs Architecture

## Pipeline Overview

```
                          PHP Source Code
                                │
                                ▼
                    ┌───────────────────────┐
                    │       Lexer           │  php-rs-lexer
                    │   (Tokenizer)         │  Hand-written, re2c equivalent
                    │                       │  Produces Token stream
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │       Parser          │  php-rs-parser
                    │  (Recursive Descent)  │  Bison equivalent
                    │                       │  Produces AST
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │      Compiler         │  php-rs-compiler
                    │   (AST → Opcodes)     │  Equivalent to zend_compile.c
                    │                       │  Produces ZOpArray
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Virtual Machine     │  php-rs-vm
                    │   (Opcode Executor)   │  212 opcodes
                    │   Computed-goto style │  dispatch_op() hot loop
                    └───────────┬───────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            ┌───────────┐ ┌─────────┐ ┌──────────┐
            │ Extensions│ │ Runtime │ │   GC     │
            │ (std,json │ │ (INI,   │ │ (cycle   │
            │  pcre...) │ │  output │ │  detect, │
            │           │ │  buffer)│ │  arena)  │
            └───────────┘ └─────────┘ └──────────┘
```

## Crate Dependency Graph

```
php-rs-sapi-cli ──┐
php-rs-sapi-fpm ──┤
php-rs-sapi-embed─┤
php-rs-sapi-wasm──┘
        │
        ▼
    php-rs-vm ──────────────────┐
        │                       │
        ├──→ php-rs-compiler    │
        │       │               │
        │       ▼               ▼
        │   php-rs-parser   php-rs-ext-standard
        │       │           php-rs-ext-json
        │       ▼           php-rs-ext-pcre
        │   php-rs-lexer    php-rs-ext-date
        │                   php-rs-ext-dom
        ▼                   php-rs-ext-pdo
    php-rs-types            php-rs-ext-spl
        │                   php-rs-ext-gd
        ▼                   php-rs-ext-intl
    php-rs-gc               ... (74 total)
        │
        ▼
    php-rs-runtime (INI, streams, output buffering)
```

## Key Data Structures

### ZVal (16 bytes)

```
┌────────────────────────────────────┐
│ Value (8 bytes)                    │
│   Long:   i64                      │
│   Double: f64                      │
│   String: pointer to ZString       │
│   Array:  pointer to ZArray        │
│   Object: pointer to ZObject       │
│   Bool:   0 or 1                   │
│   Null:   0                        │
├────────────────────────────────────┤
│ Type + Flags (8 bytes)             │
│   type_info: u8 (IS_UNDEF..RESOURCE)│
│   flags: reference counting, etc.  │
└────────────────────────────────────┘
```

### PhpArray (Dual-mode)

```
Packed Mode (consecutive int keys 0..n):
┌───────────────────────────────┐
│ is_packed: true               │
│ entries: Vec<(Key, Value)>    │  ← O(1) indexed access
│ int_index: None (lazy)        │
│ str_index: None (lazy)        │
└───────────────────────────────┘

Hash Mode (mixed/string keys):
┌───────────────────────────────┐
│ is_packed: false              │
│ entries: Vec<(Key, Value)>    │  ← insertion order
│ int_index: HashMap<i64, pos>  │  ← O(1) lookup
│ str_index: HashMap<str, pos>  │  ← O(1) lookup
└───────────────────────────────┘
```

### VM Execution Model

```
┌────────────────────────────────────┐
│              Vm                    │
│  ┌────────────────────────────┐    │
│  │    Call Stack               │    │
│  │  ┌──────────────────────┐  │    │
│  │  │ Frame N (current)    │  │    │
│  │  │  - cvs[] (variables) │  │    │
│  │  │  - temps[] (scratch) │  │    │
│  │  │  - ip (instr pointer)│  │    │
│  │  ├──────────────────────┤  │    │
│  │  │ Frame N-1            │  │    │
│  │  ├──────────────────────┤  │    │
│  │  │ ...                  │  │    │
│  │  └──────────────────────┘  │    │
│  └────────────────────────────┘    │
│                                    │
│  ┌────────────────────────────┐    │
│  │ Op Arrays (compiled code)  │    │
│  │  [0]: main script          │    │
│  │  [1]: function foo()       │    │
│  │  [2]: MyClass::bar()       │    │
│  └────────────────────────────┘    │
│                                    │
│  ┌────────────────────────────┐    │
│  │ Extension Registry         │    │
│  │  ext-standard (551 funcs)  │    │
│  │  ext-json, ext-pcre, ...   │    │
│  └────────────────────────────┘    │
└────────────────────────────────────┘
```

## Opcode Dispatch

The VM dispatch loop (`dispatch_op`) uses a match statement that compiles to a jump table:

```rust
loop {
    let op = &ops[ip];
    match op.opcode {
        Opcode::Add => op_add(frame),
        Opcode::Sub => op_sub(frame),
        Opcode::Echo => op_echo(frame),
        // ... 212 opcodes total
    }
    ip += 1;
}
```

Each opcode handler is a separate `#[inline]` function for optimal code generation.

## Memory Management

- **Arena allocator**: Request-scoped bump allocation (256KB chunks), reset at request end
- **String interning**: Function names, variable names, class names stored in StringPool (FNV-1a hashing)
- **Copy-on-write**: Arrays use Rc<PhpArrayInner>, clone is O(1) Rc bump
- **Opcode cache**: Compiled ZOpArrays cached by file path with mtime-based invalidation

## SAPI Layer

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  CLI SAPI   │  │  FPM SAPI   │  │ Embed SAPI  │  │ WASM SAPI   │
│  (php-rs)   │  │  (php-fpm)  │  │  (library)  │  │  (browser)  │
│             │  │             │  │             │  │             │
│ stdin/out   │  │ FastCGI     │  │ Rust API    │  │ JS API      │
│ argv/argc   │  │ workers     │  │ execute()   │  │ eval()      │
│ exit code   │  │ pool mgmt   │  │ call()      │  │ run()       │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
        │                │                │                │
        └────────────────┴────────────────┴────────────────┘
                                  │
                           ┌──────┴──────┐
                           │   php-rs-vm │
                           └─────────────┘
```
