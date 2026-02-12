<?php
// Benchmark 13.02: Array operations (sort, map, filter)
$arr = range(1, 1000);
$mapped = array_map(function($x) { return $x * 2; }, $arr);
$filtered = array_filter($mapped, function($x) { return $x > 500; });
sort($filtered);
echo count($filtered) . "\n";
