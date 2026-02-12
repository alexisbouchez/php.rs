<?php
// Benchmark 13.03: Function call overhead
function add($a, $b) { return $a + $b; }
$sum = 0;
for ($i = 0; $i < 1000; $i++) {
    $sum = add($sum, $i);
}
echo $sum . "\n";
