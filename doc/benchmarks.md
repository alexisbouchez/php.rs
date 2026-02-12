# Benchmark Comparison: php.rs vs PHP-src

## Running Benchmarks

### php.rs (Criterion)

```bash
# Run all benchmarks
cargo bench -p php-rs-vm

# Run a specific benchmark
cargo bench -p php-rs-vm -- echo_loop
```

### PHP-src reference

```bash
# Run PHP comparison scripts
cd benches/php
./run_all.sh /usr/bin/php
```

### Side-by-side comparison

```bash
# Run both and compare
./benches/php/run_all.sh php ./target/release/php-rs
```

## Benchmark Suite

| Benchmark | Description | php.rs Function | PHP Script |
|-----------|-------------|-----------------|------------|
| Echo loop (1M) | `for ($i=0; $i<1000000; $i++) echo "";` | `echo_loop_1M` | `bench_echo_loop.php` |
| Array operations | sort, map, filter on 1000 elements | `array_map_filter_sort_1000` | `bench_array_ops.php` |
| Array create/access | Create + read 10K array elements | `array_create_access_10k` | `bench_array_ops.php` |
| String keys | Array with 1000 string keys | `array_string_keys_1000` | `bench_array_ops.php` |
| CoW array | Clone + mutate 100 arrays | `array_cow_clone_mutate_100` | `bench_array_ops.php` |
| Function calls | 1000 recursive calls | `function_calls_1000` | `bench_function_calls.php` |
| Object creation | 100 class instantiations | `class_instantiation_100` | `bench_object_creation.php` |
| String concat | 1000 concatenations | `string_concat_1000` | `bench_string_concat.php` |
| String functions | 100 str_replace + strtolower cycles | `string_functions_100` | `bench_string_concat.php` |

## Performance Optimizations

php.rs includes several performance optimizations that narrow the gap with PHP-src:

### Hot Loop Optimization (Phase 13.06)
- Error conversion extracted to `#[cold]` function
- Happy path avoids error-handling code entirely
- `dispatch_op` remains `#[inline]` for jump table optimization

### Arena Allocator (Phase 13.07)
- Bump-pointer allocation with 256KB chunks
- Request-scoped: everything freed in bulk at request end
- Zero-cost deallocation (just reset the pointer)

### Packed Array (Phase 13.08)
- Arrays with consecutive integer keys 0..n use direct Vec indexing
- O(1) read/write vs O(log n) hash lookup
- Hash indexes built lazily for arrays >16 entries

### Copy-on-Write (Phase 13.09)
- Array clone is O(1) via Rc refcount bump
- Deep copy deferred to first mutation (`Rc::make_mut`)
- String interning pool with FNV-1a hashing

### Opcode Cache (Phase 13.10)
- Compiled ZOpArrays cached by file path
- File mtime-based invalidation (recompile if file changed)
- Eliminates re-parsing and re-compilation on repeated includes

## Measuring Your Own Code

To benchmark a specific PHP script:

```bash
# Build in release mode
cargo build --release -p php-rs-sapi-cli

# Time a PHP script with php.rs
time ./target/release/php-rs your_script.php

# Compare with PHP-src
time php your_script.php
```

For reproducible microbenchmarks, add a new Criterion benchmark in `crates/php-rs-vm/benches/`:

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_test", |b| {
        b.iter(|| {
            let mut vm = Vm::new(VmConfig::default());
            vm.execute_source("<?php /* your code */ ?>");
        });
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```
