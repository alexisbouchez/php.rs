<?php

// Test $GLOBALS
echo "Test GLOBALS:\n";
$GLOBALS['test_key'] = 'hello';
echo "Set GLOBALS['test_key'] = 'hello'\n";
echo "Read: " . $GLOBALS['test_key'] . "\n";
echo "empty check: " . (empty($GLOBALS['test_key']) ? "empty" : "not empty") . "\n";

// Test Closure::bind with static
echo "\nTest Closure::bind static:\n";
$fn = \Closure::bind(static function ($a, $b) {
    return $a . ' + ' . $b;
}, null, null);
echo "Closure created: " . (is_callable($fn) ? "yes" : "no") . "\n";
$result = $fn('x', 'y');
echo "Result: $result\n";

// Test require inside closure
echo "\nTest require inside closure:\n";
$reqFn = \Closure::bind(static function ($file) {
    require $file;
}, null, null);

// Create a tiny test file to require
file_put_contents(__DIR__ . '/test_required_file.php', '<?php echo "Required file loaded!\n";');
$reqFn(__DIR__ . '/test_required_file.php');
