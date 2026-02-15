<?php

// Load trait
require __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';

// Is it registered?
echo "trait_exists check (string match):\n";

// Try to use it in a simple class
namespace TestNS;

use Illuminate\Support\Traits\EnumeratesValues;

class SimpleCollection {
    use EnumeratesValues;

    protected $items = [];

    public function __construct($items = []) {
        $this->items = $items;
    }

    public function all() {
        return $this->items;
    }
}

echo "Creating SimpleCollection...\n";
$c = new SimpleCollection([1, 2, 3]);
echo "Created\n";
echo "Calling getArrayableItems...\n";
$result = $c->getArrayableItems([4, 5, 6]);
echo "Result: ";
print_r($result);
