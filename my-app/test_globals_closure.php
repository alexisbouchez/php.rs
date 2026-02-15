<?php

// Test $GLOBALS inside a closure called from a class static method
class Tester {
    public static function run() {
        echo "Inside static method:\n";

        $fn = \Closure::bind(static function ($key, $val) {
            echo "  Inside closure, setting GLOBALS[$key]\n";
            $GLOBALS['test_data'][$key] = $val;
            echo "  Set done\n";
        }, null, null);

        $fn('a', 1);
        $fn('b', 2);

        echo "\nCheck GLOBALS:\n";
        echo "  isset: " . (isset($GLOBALS['test_data']) ? "YES" : "NO") . "\n";
        if (isset($GLOBALS['test_data'])) {
            echo "  count: " . count($GLOBALS['test_data']) . "\n";
        }
    }
}

Tester::run();

echo "\nAt top level:\n";
echo "  isset: " . (isset($GLOBALS['test_data']) ? "YES" : "NO") . "\n";

// Also test empty() on nested GLOBALS
echo "\nTest empty on nested GLOBALS:\n";
$GLOBALS['__test'] = array();
echo "  empty(\$GLOBALS['__test']['x']): " . (empty($GLOBALS['__test']['x']) ? "true" : "false") . "\n";
$GLOBALS['__test']['x'] = true;
echo "  After set, empty: " . (empty($GLOBALS['__test']['x']) ? "true" : "false") . "\n";
