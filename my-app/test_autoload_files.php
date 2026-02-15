<?php

echo "Loading autoloader...\n";
require __DIR__.'/vendor/autoload.php';
echo "Autoloader loaded\n";

echo "Checking join_paths exists: ";
$exists = function_exists('Illuminate\Filesystem\join_paths');
echo $exists ? "YES" : "NO";
echo "\n";

if ($exists) {
    $result = \Illuminate\Filesystem\join_paths('/foo', 'bar', 'baz');
    echo "join_paths result: $result\n";
}

echo "Checking collect exists: ";
echo function_exists('collect') ? "YES" : "NO";
echo "\n";

echo "Checking app exists: ";
echo function_exists('app') ? "YES" : "NO";
echo "\n";
