<?php

require __DIR__ . '/MiniTrait.php';

class TestCol2 {
    use \Illuminate\Support\Traits\MiniEnumeratesValues;
    protected $items = [];
    public function __construct($items = []) {
        $this->items = $items;
    }
    public function all() {
        return $this->items;
    }
}

$c = new TestCol2([1, 2, 3]);
echo "getArrayableItems: ";
print_r($c->getArrayableItems([4, 5]));
echo "\ntoArray: ";
print_r($c->toArray());
echo "\n";
