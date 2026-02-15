<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

$filesToLoad = $cls::$files;
foreach ($filesToLoad as $fileIdentifier => $file) {
    require $file;
}

echo "Test: Can we load EnumeratesValues trait?\n";
$traitClass = 'Illuminate\Support\Traits\EnumeratesValues';
echo "Class/trait exists: " . (class_exists($traitClass) ? "YES" : "NO") . "\n";

// Try to find the file
$file = $loader->findFile($traitClass);
echo "findFile: " . ($file ? $file : "NOT FOUND") . "\n";

// Try loading it directly
if ($file) {
    require_once $file;
    echo "After require, exists: " . (class_exists($traitClass, false) ? "YES" : "NO") . "\n";
}
