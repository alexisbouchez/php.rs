# php.rs — Makefile
# Convenience targets for build, test, lint, and PHPT runs.
# See CLAUDE.md for full project and cargo command reference.

.PHONY: all build release install uninstall check test test-verbose test-phpt fmt lint clippy bench clean help

# Default: build everything
all: build

# Build all crates
build:
	cargo build

# Build optimized release binary
release:
	cargo build -p php-rs-sapi-cli --release

# Install to /usr/local/bin (or PREFIX=/custom/path)
# Use: sudo make install  (if installing to /usr/local)
PREFIX ?= /usr/local
install: release
	mkdir -p $(PREFIX)/bin
	cp target/release/php-rs $(PREFIX)/bin/php-rs
	chmod 755 $(PREFIX)/bin/php-rs

# Uninstall
uninstall:
	rm -f $(PREFIX)/bin/php-rs

# Check without building artifacts
check:
	cargo check

# Run all unit tests
test:
	cargo test

# Run tests with verbose output (no capture)
test-verbose:
	cargo test -- --nocapture

# Run PHPT compatibility tests (requires php-src clone).
# Optionally restrict to a directory: make test-phpt PHPT_DIR=php-src/tests/lang
test-phpt:
	$(if $(PHPT_DIR),PHPT_DIR=$(PHPT_DIR) cargo test -p php-rs --test phpt_runner,cargo test -p php-rs --test phpt_runner)

# Format all code
fmt:
	cargo fmt --all

# Lint with Clippy (all targets, all features)
lint: clippy
clippy:
	cargo clippy --all-targets --all-features

# Run benchmarks (VM crate by default; override with BENCH_PKG=...)
bench:
	cargo bench -p $(or $(BENCH_PKG),php-rs-vm)

# Remove build artifacts
clean:
	cargo clean

# Build a specific crate: make build-pkg PACKAGE=php-rs-vm
build-pkg:
	@if [ -z "$(PACKAGE)" ]; then echo "Usage: make build-pkg PACKAGE=crate-name"; exit 1; fi
	cargo build -p $(PACKAGE)

# Test a specific crate: make test-pkg PACKAGE=php-rs-parser [TEST=test_name]
test-pkg:
	@if [ -z "$(PACKAGE)" ]; then echo "Usage: make test-pkg PACKAGE=crate-name [TEST=test_name]"; exit 1; fi
	cargo test -p $(PACKAGE) $(if $(TEST),-- $(TEST),)

# Show this help
help:
	@echo "php.rs Makefile targets:"
	@echo "  all, build     Build all crates (debug)"
	@echo "  release        Build optimized release binary"
	@echo "  install        Install to /usr/local/bin (PREFIX=/custom/path)"
	@echo "  uninstall      Remove installed binary"
	@echo "  check          Check without building"
	@echo "  test           Run all unit tests"
	@echo "  test-verbose   Run tests with --nocapture"
	@echo "  test-phpt      Run PHPT tests (optional: PHPT_DIR=php-src/tests/lang)"
	@echo "  fmt            Format code (cargo fmt --all)"
	@echo "  lint, clippy   Run Clippy"
	@echo "  bench          Benchmarks (optional: BENCH_PKG=php-rs-vm)"
	@echo "  clean          Remove build artifacts"
	@echo "  build-pkg      Build one crate: make build-pkg PACKAGE=php-rs-vm"
	@echo "  test-pkg       Test one crate: make test-pkg PACKAGE=php-rs-types [TEST=name]"
	@echo "  help           Show this help"
