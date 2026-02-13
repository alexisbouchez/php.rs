// Criterion benchmarks for php-rs-vm
//
// Benchmarks real PHP code compiled and executed through the full pipeline:
// lexer → parser → compiler → VM execution.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use php_rs_vm::Vm;

/// Helper: compile PHP source to an op_array.
fn compile(source: &str) -> php_rs_compiler::op_array::ZOpArray {
    php_rs_compiler::compile(source).expect("benchmark source must compile")
}

/// Helper: compile + execute PHP, return output.
fn run(source: &str) -> String {
    let oa = compile(source);
    let mut vm = Vm::new();
    vm.execute(&oa, None).expect("benchmark must execute")
}

// ─── Fibonacci (recursive) ──────────────────────────────────────────────────

fn bench_fibonacci(c: &mut Criterion) {
    let source = r#"<?php
function fib($n) {
    if ($n <= 1) return $n;
    return fib($n - 1) + fib($n - 2);
}
echo fib(20);
"#;
    // Pre-compile once; benchmark compile+execute
    c.bench_function("fibonacci_20", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });

    // Benchmark execution only (pre-compiled)
    let oa = compile(source);
    c.bench_function("fibonacci_20_exec_only", |b| {
        b.iter(|| {
            let mut vm = Vm::new();
            black_box(vm.execute(&oa, None).unwrap());
        });
    });
}

// ─── Array sorting ──────────────────────────────────────────────────────────

fn bench_array_sort(c: &mut Criterion) {
    let source = r#"<?php
$arr = [];
for ($i = 1000; $i > 0; $i--) {
    $arr[] = $i;
}
sort($arr);
echo $arr[0] . " " . $arr[999];
"#;
    c.bench_function("array_sort_1000", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

// ─── String manipulation ────────────────────────────────────────────────────

fn bench_string_concat(c: &mut Criterion) {
    let source = r#"<?php
$s = "";
for ($i = 0; $i < 1000; $i++) {
    $s .= "x";
}
echo strlen($s);
"#;
    c.bench_function("string_concat_1000", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

fn bench_string_functions(c: &mut Criterion) {
    let source = r#"<?php
$s = str_repeat("Hello World ", 100);
for ($i = 0; $i < 100; $i++) {
    $upper = strtoupper($s);
    $lower = strtolower($s);
    $len = strlen($s);
}
echo $len;
"#;
    c.bench_function("string_functions_100", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

// ─── Class instantiation ────────────────────────────────────────────────────

fn bench_class_instantiation(c: &mut Criterion) {
    let source = r#"<?php
class Point {
    public $x;
    public $y;
    public function __construct($x, $y) {
        $this->x = $x;
        $this->y = $y;
    }
    public function distance($other) {
        $dx = $this->x - $other->x;
        $dy = $this->y - $other->y;
        return sqrt($dx * $dx + $dy * $dy);
    }
}
$sum = 0;
for ($i = 0; $i < 100; $i++) {
    $a = new Point($i, $i * 2);
    $b = new Point($i * 3, $i * 4);
    $sum = $sum + $a->distance($b);
}
echo intval($sum);
"#;
    c.bench_function("class_instantiation_100", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

// ─── Function call overhead ─────────────────────────────────────────────────

fn bench_function_calls(c: &mut Criterion) {
    let source = r#"<?php
function add($a, $b) { return $a + $b; }
$sum = 0;
for ($i = 0; $i < 1000; $i++) {
    $sum = add($sum, $i);
}
echo $sum;
"#;
    c.bench_function("function_calls_1000", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

// ─── Arithmetic loop ────────────────────────────────────────────────────────

fn bench_arithmetic_loop(c: &mut Criterion) {
    let source = r#"<?php
$x = 0;
for ($i = 0; $i < 10000; $i++) {
    $x = $x + $i * 2 - 1;
}
echo $x;
"#;
    c.bench_function("arithmetic_loop_10k", |b| {
        b.iter(|| {
            black_box(run(source));
        });
    });
}

// ─── Compile-only benchmark ─────────────────────────────────────────────────

fn bench_compile_only(c: &mut Criterion) {
    let source = r#"<?php
function fib($n) {
    if ($n <= 1) return $n;
    return fib($n - 1) + fib($n - 2);
}
class Foo {
    public $x;
    public function bar($y) {
        return $this->x + $y;
    }
}
for ($i = 0; $i < 100; $i++) {
    $arr[] = $i * 2;
}
echo "done";
"#;
    c.bench_function("compile_medium_script", |b| {
        b.iter(|| {
            black_box(compile(source));
        });
    });
}

criterion_group!(
    benches,
    bench_fibonacci,
    bench_array_sort,
    bench_string_concat,
    bench_string_functions,
    bench_class_instantiation,
    bench_function_calls,
    bench_arithmetic_loop,
    bench_compile_only
);
criterion_main!(benches);
