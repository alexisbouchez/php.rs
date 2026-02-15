<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';

// At top level
echo "Top level:\n";
$f1 = $cls::$files;
echo "  type: " . gettype($f1) . "\n";
echo "  count: " . count($f1) . "\n";
echo "  is_array: " . (is_array($f1) ? "YES" : "NO") . "\n";

// Inside a function
function test() {
    $cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
    echo "\nInside function:\n";
    $f2 = $cls::$files;
    echo "  type: " . gettype($f2) . "\n";
    echo "  count: " . count($f2) . "\n";
    echo "  is_array: " . (is_array($f2) ? "YES" : "NO") . "\n";
}
test();

// Inside a static method
class Tester {
    public static function run() {
        $cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
        echo "\nInside static method:\n";
        $f3 = $cls::$files;
        echo "  type: " . gettype($f3) . "\n";
        echo "  count: " . count($f3) . "\n";
        echo "  is_array: " . (is_array($f3) ? "YES" : "NO") . "\n";
    }
}
Tester::run();

// With FQ name
class Tester2 {
    public static function run() {
        echo "\nInside static method (FQ):\n";
        $f4 = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::$files;
        echo "  type: " . gettype($f4) . "\n";
        echo "  count: " . count($f4) . "\n";
        echo "  is_array: " . (is_array($f4) ? "YES" : "NO") . "\n";
    }
}
Tester2::run();
