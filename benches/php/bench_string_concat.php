<?php
// Benchmark 13.05: String concatenation
$s = "";
for ($i = 0; $i < 1000; $i++) {
    $s .= "x";
}
echo strlen($s) . "\n";
