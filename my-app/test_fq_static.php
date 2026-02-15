<?php

namespace Foo;

class Bar {
    public static $items = array('a', 'b', 'c');
}

// Access from global scope - works
echo "Global scope, unqualified:\n";
$val = \Foo\Bar::$items;
echo "  type: " . gettype($val) . ", count: " . count($val) . "\n";

class Baz {
    public static function test() {
        // Access with leading backslash from inside class method
        echo "\nFrom class method, FQ:\n";
        $val = \Foo\Bar::$items;
        echo "  type: " . gettype($val) . ", count: " . count($val) . "\n";

        // Access without leading backslash
        echo "\nFrom class method, relative:\n";
        $val2 = Bar::$items;
        echo "  type: " . gettype($val2) . ", count: " . count($val2) . "\n";
    }
}

Baz::test();

// Same but from global namespace class
namespace;

class GlobalClass {
    public static function test() {
        echo "\nFrom global ns class, FQ:\n";
        $val = \Foo\Bar::$items;
        echo "  type: " . gettype($val) . ", count: " . count($val) . "\n";
    }
}

GlobalClass::test();
