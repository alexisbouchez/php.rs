<?php
// Benchmark 13.04: Object creation
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
echo intval($sum) . "\n";
