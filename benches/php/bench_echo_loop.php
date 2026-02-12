<?php
// Benchmark 13.01: Echo loop (1M iterations)
ob_start();
for ($i = 0; $i < 1000000; $i++) {
    echo "x";
}
$len = ob_get_length();
ob_end_clean();
echo $len . "\n";
