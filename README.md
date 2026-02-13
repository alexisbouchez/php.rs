# php.rs

PHP 8.6 interpreter rewritten in Rust. Reference: [php-src](https://github.com/php/php-src).

## Build & run

```bash
cargo build
./target/debug/php-rs -r "echo 'Hello, world';"
./target/debug/php-rs script.php
```

## Test

```bash
cargo test
make test          # same, via Makefile
make test-phpt     # PHPT compatibility tests (requires php-src clone)
```

## Docs

See [CLAUDE.md](CLAUDE.md) for architecture, crate layout, and development workflow.
