<?php
$x = "hello";

// Test 1: (!$x) instanceof Closure
$r1 = (!$x) instanceof Closure;
echo "r1 ((!x) instanceof Closure) = " . ($r1 ? "true" : "false") . "\n"; // false

// Test 2: !($x instanceof Closure)
$r2 = !($x instanceof Closure);
echo "r2 (!(x instanceof Closure)) = " . ($r2 ? "true" : "false") . "\n"; // true

// Test 3: ! $x instanceof Closure  (depends on precedence)
$r3 = ! $x instanceof Closure;
echo "r3 (! x instanceof Closure) = " . ($r3 ? "true" : "false") . "\n";
