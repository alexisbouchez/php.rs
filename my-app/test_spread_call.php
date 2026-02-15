<?php

// Test 1: spread in regular function call
function test($a, $b) { return $a + $b; }
$args = [1, 2];
echo "Regular spread: " . test(...$args) . "\n";

// Test 2: variable function call with spread
$fn = 'test';
echo "Var func spread: " . $fn(...$args) . "\n";

// Test 3: variable as callable with spread
$callable = function($a, $b) { return $a * $b; };
echo "Closure spread: " . $callable(...$args) . "\n";
