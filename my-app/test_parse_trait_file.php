<?php

echo "Parsing trait file...\n";
$code = file_get_contents(__DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php');
echo "File size: " . strlen($code) . "\n";
echo "Contains 'trait EnumeratesValues': " . (strpos($code, 'trait EnumeratesValues') !== false ? "YES" : "NO") . "\n";

echo "\nRequiring file...\n";
require __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';
echo "Required OK\n";
