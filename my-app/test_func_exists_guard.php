<?php

// Test: function definition inside if (!function_exists()) guard
echo "Test 1: function_exists guard\n";
if (! function_exists('my_func')) {
    function my_func() {
        return 42;
    }
}
echo "my_func exists: " . (function_exists('my_func') ? "YES" : "NO") . "\n";
if (function_exists('my_func')) {
    echo "my_func(): " . my_func() . "\n";
}

// Test 2: with return type
echo "\nTest 2: with return type\n";
if (! function_exists('my_typed_func')) {
    function my_typed_func(): string {
        return "hello";
    }
}
echo "my_typed_func exists: " . (function_exists('my_typed_func') ? "YES" : "NO") . "\n";

// Test 3: require a file that defines a function inside if guard
echo "\nTest 3: require file\n";
file_put_contents(__DIR__ . '/test_helper_func.php', '<?php
if (! function_exists(\'helper_func\')) {
    function helper_func() {
        return "from helper";
    }
}
');
require __DIR__ . '/test_helper_func.php';
echo "helper_func exists: " . (function_exists('helper_func') ? "YES" : "NO") . "\n";
