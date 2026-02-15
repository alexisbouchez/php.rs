<?php

// Test: does the trait file parse without errors?
echo "Before require\n";
require __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';
echo "After require\n";

// Try to see if any methods were compiled
// Create a minimal class using it via FQ name
class ParseTest {
    use \Illuminate\Support\Traits\EnumeratesValues;
    protected $items = [];
    public function all() { return $this->items; }
}
echo "Class defined\n";

// List methods via get_class_methods
$methods = get_class_methods('ParseTest');
echo "Methods: " . count($methods) . "\n";
if (is_array($methods)) {
    foreach ($methods as $m) {
        echo "  - $m\n";
    }
}
