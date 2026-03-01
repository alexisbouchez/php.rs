#!/usr/bin/env bash
# Build the WASM binary using wasm-pack, then copy to the npm package.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$PACKAGE_DIR/../.." && pwd)"
WASM_CRATE="$REPO_ROOT/crates/php-rs-sapi-wasm"

echo "Building WASM binary..."
wasm-pack build "$WASM_CRATE" \
  --target web \
  --release \
  --out-dir "$PACKAGE_DIR/wasm" \
  --out-name php_rs_sapi_wasm

# Remove wasm-pack's generated package.json (we have our own)
rm -f "$PACKAGE_DIR/wasm/package.json"
rm -f "$PACKAGE_DIR/wasm/.gitignore"

WASM_SIZE=$(wc -c < "$PACKAGE_DIR/wasm/php_rs_sapi_wasm_bg.wasm" | tr -d ' ')
echo "WASM binary size: $(( WASM_SIZE / 1024 ))KB"

if [ "$WASM_SIZE" -gt 3145728 ]; then
  echo "WARNING: WASM binary exceeds 3MB target ($WASM_SIZE bytes)"
fi

echo "WASM build complete."
