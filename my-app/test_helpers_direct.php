<?php

echo "Requiring helpers.php directly...\n";
require __DIR__ . '/vendor/laravel/framework/src/Illuminate/Collections/helpers.php';
echo "Done\n";

echo "collect exists: " . (function_exists('collect') ? "YES" : "NO") . "\n";
echo "value exists: " . (function_exists('value') ? "YES" : "NO") . "\n";
