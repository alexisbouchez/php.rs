<?php

// Test 1: namespaced function_exists
echo "Test 1: function_exists for namespaced functions\n";
namespace Illuminate\Filesystem;
function join_paths_test($a, $b) { return $a . '/' . $b; }
echo "Defined join_paths_test\n";
$result = function_exists('Illuminate\Filesystem\join_paths_test');
echo "function_exists result: ";
echo $result ? "true" : "false";
echo "\n";
