<?php

// Load Conditionable first (since EnumeratesValues uses it)
require __DIR__ . '/vendor/illuminate/conditionable/Traits/Conditionable.php';
echo "Conditionable loaded\n";

// Load EnumeratesValues
require __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';
echo "EnumeratesValues loaded\n";

// Simple class
class TestCol {
    use \Illuminate\Support\Traits\EnumeratesValues;
    protected $items = [];
    public function __construct($items = []) {
        $this->items = $items;
    }
    public function all() {
        return $this->items;
    }
    public function test() {
        return $this->getArrayableItems([1,2,3]);
    }
}

echo "Creating TestCol...\n";
$c = new TestCol();
echo "Created\n";
$r = $c->test();
echo "Result: ";
print_r($r);
