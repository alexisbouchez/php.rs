<?php

// Test Closure::bind with class scope (third arg)
class Foo {
    private $x = 10;
}

echo "Test 1: Closure::bind(fn, null, null)\n";
$c1 = \Closure::bind(function() { return 42; }, null, null);
echo "Type: " . gettype($c1) . "\n";
echo "Result: " . $c1() . "\n";

echo "\nTest 2: Closure::bind(fn, null, ClassName::class)\n";
$c2 = \Closure::bind(function() { return 43; }, null, Foo::class);
echo "Type: " . gettype($c2) . "\n";
echo "Is callable: " . (is_callable($c2) ? "YES" : "NO") . "\n";
if (is_callable($c2)) {
    echo "Result: " . $c2() . "\n";
}

echo "\nTest 3: Closure::bind with use and class scope\n";
$val = 99;
$c3 = \Closure::bind(function() use ($val) { return $val; }, null, Foo::class);
echo "Type: " . gettype($c3) . "\n";
if (is_callable($c3)) {
    echo "Result: " . $c3() . "\n";
}

echo "\nTest 4: Closure::bind setting private property\n";
$obj = new Foo();
$c4 = \Closure::bind(function() use ($obj) {
    $obj->x = 42;
}, null, Foo::class);
echo "Type: " . gettype($c4) . "\n";
if (is_callable($c4)) {
    $c4();
    echo "Done\n";
}
