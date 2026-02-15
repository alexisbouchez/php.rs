<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';

echo "Before anything:\n";
echo "  files count: " . count($cls::$files) . "\n";
echo "  prefixLengthsPsr4 count: " . count($cls::$prefixLengthsPsr4) . "\n";
echo "  prefixDirsPsr4 count: " . count($cls::$prefixDirsPsr4) . "\n";
echo "  classMap count: " . count($cls::$classMap) . "\n";

$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));

echo "\nAfter ClassLoader creation:\n";
echo "  files count: " . count($cls::$files) . "\n";

echo "\nAssigning prefixLengthsPsr4...\n";
$loader->prefixLengthsPsr4 = $cls::$prefixLengthsPsr4;
echo "  files count: " . count($cls::$files) . "\n";

echo "\nAssigning prefixDirsPsr4...\n";
$loader->prefixDirsPsr4 = $cls::$prefixDirsPsr4;
echo "  files count: " . count($cls::$files) . "\n";

echo "\nAssigning classMap...\n";
$loader->classMap = $cls::$classMap;
echo "  files count: " . count($cls::$files) . "\n";
