<?php

echo "Loading autoloader first...\n";
require __DIR__ . '/vendor/autoload.php';
echo "Autoloader loaded\n";

echo "\nNow manually requiring helpers.php...\n";
require __DIR__ . '/vendor/laravel/framework/src/Illuminate/Collections/helpers.php';
echo "helpers.php loaded\n";

echo "collect exists: " . (function_exists('collect') ? "YES" : "NO") . "\n";
echo "value exists: " . (function_exists('value') ? "YES" : "NO") . "\n";
echo "head exists: " . (function_exists('head') ? "YES" : "NO") . "\n";
