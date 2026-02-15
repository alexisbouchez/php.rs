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

// Try loading the trait file directly first
echo "Loading trait file directly:\n";
$traitFile = __DIR__ . '/vendor/illuminate/collections/Traits/EnumeratesValues.php';
echo "  File exists: " . (file_exists($traitFile) ? "YES" : "NO") . "\n";
require_once $traitFile;
echo "  Loaded OK\n";

// Now try Collection
echo "\nLoading Collection:\n";
$collFile = __DIR__ . '/vendor/illuminate/collections/Collection.php';
echo "  File exists: " . (file_exists($collFile) ? "YES" : "NO") . "\n";
require_once $collFile;
echo "  Loaded OK\n";

echo "Collection class_exists: " . (class_exists('Illuminate\Support\Collection', false) ? "YES" : "NO") . "\n";
