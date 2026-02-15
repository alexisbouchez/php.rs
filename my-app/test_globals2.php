<?php

// Test 1: Simple GLOBALS from closure
echo "Test 1: Simple GLOBALS from closure\n";
$fn = function() {
    $GLOBALS['simple'] = 'hello';
};
$fn();
echo "  GLOBALS['simple']: " . (isset($GLOBALS['simple']) ? $GLOBALS['simple'] : "NOT SET") . "\n";

// Test 2: GLOBALS from nested function
echo "\nTest 2: GLOBALS from function\n";
function set_global() {
    $GLOBALS['from_func'] = 'world';
}
set_global();
echo "  GLOBALS['from_func']: " . (isset($GLOBALS['from_func']) ? $GLOBALS['from_func'] : "NOT SET") . "\n";

// Test 3: Nested array assignment
echo "\nTest 3: Nested GLOBALS array\n";
$GLOBALS['data'] = array();
$GLOBALS['data']['x'] = 1;
echo "  GLOBALS['data']['x']: " . (isset($GLOBALS['data']['x']) ? $GLOBALS['data']['x'] : "NOT SET") . "\n";
echo "  GLOBALS['data'] type: " . gettype($GLOBALS['data']) . "\n";

// Test 4: Auto-creating nested array
echo "\nTest 4: Auto-create nested GLOBALS\n";
$GLOBALS['auto']['key'] = 'value';
echo "  GLOBALS['auto']['key']: " . (isset($GLOBALS['auto']['key']) ? $GLOBALS['auto']['key'] : "NOT SET") . "\n";
