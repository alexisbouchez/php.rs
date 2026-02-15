<?php

// Simulate the exact structure
// Load just the trait file
require __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';

// Now check if it's registered
echo "EnumeratesValues trait:\n";
echo "  class_exists: " . (class_exists('Illuminate\Support\Traits\EnumeratesValues', false) ? "YES" : "NO") . "\n";

// Check what the compiler registered
echo "\nTrying to use it in a class:\n";

namespace Test123;

use Illuminate\Support\Traits\EnumeratesValues;

class Foo {
    use EnumeratesValues;

    public $items = [];

    public function test() {
        return $this->getArrayableItems([1, 2, 3]);
    }
}

$f = new Foo();
echo "Result: ";
print_r($f->test());
echo "\n";
