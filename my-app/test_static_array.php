<?php

// Test: static property with __DIR__ concatenation in array
class TestClass {
    public static $items = array(
        'a' => 'one',
        'b' => 'two',
        'c' => 'three',
    );
}

echo "Count: " . count(TestClass::$items) . "\n";
foreach (TestClass::$items as $k => $v) {
    echo "  $k => $v\n";
}

// Test with __DIR__ concat
class TestClass2 {
    public static $files = array(
        'key1' => __DIR__ . '/foo.php',
        'key2' => __DIR__ . '/bar.php',
        'key3' => __DIR__ . '/baz.php',
    );
}

echo "\nWith __DIR__ concat:\n";
echo "Count: " . count(TestClass2::$files) . "\n";
foreach (TestClass2::$files as $k => $v) {
    echo "  $k => $v\n";
}

// Test with dot-dot paths like Composer uses
class TestClass3 {
    public static $files = array(
        'key1' => __DIR__ . '/..' . '/foo.php',
        'key2' => __DIR__ . '/..' . '/bar.php',
    );
}

echo "\nWith __DIR__ . '/..' . '/':\n";
echo "Count: " . count(TestClass3::$files) . "\n";
foreach (TestClass3::$files as $k => $v) {
    echo "  $k => $v\n";
}
