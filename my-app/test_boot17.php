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

echo "Files loaded\n";

// Load Application manually using direct require
$file = $loader->findFile('Illuminate\Foundation\Application');
require_once $file;
echo "Application loaded\n";

// Try creating - using a string class name to avoid compile-time resolution
$className = 'Illuminate\Foundation\Application';
$app = new $className('/tmp/test');
echo "Created: " . get_class($app) . "\n";
