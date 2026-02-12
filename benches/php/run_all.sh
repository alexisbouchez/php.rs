#!/usr/bin/env bash
# Run all PHP benchmarks and compare php-src vs php.rs
#
# Usage: ./run_all.sh [php_binary] [phprs_binary]
#   php_binary:  path to reference PHP (default: php)
#   phprs_binary: path to php.rs CLI (default: cargo run -p php-rs-sapi-cli --)

set -euo pipefail
cd "$(dirname "$0")"

PHP="${1:-php}"
PHPRS="${2:-}"

echo "=== PHP Benchmark Comparison ==="
echo ""

for bench in bench_*.php; do
    name="${bench%.php}"
    name="${name#bench_}"
    printf "%-25s" "$name"

    # PHP-src timing
    if command -v "$PHP" &>/dev/null; then
        php_time=$( { time "$PHP" "$bench" > /dev/null; } 2>&1 | grep real | awk '{print $2}')
        printf "  php-src: %s" "$php_time"
    else
        printf "  php-src: (not found)"
    fi

    # php.rs timing (via Criterion benchmarks — use cargo bench for proper measurement)
    printf "  (use 'cargo bench -p php-rs-vm' for php.rs timings)"
    echo ""
done

echo ""
echo "For accurate php.rs benchmarks, run: cargo bench -p php-rs-vm"
