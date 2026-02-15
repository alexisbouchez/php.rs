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

echo "Autoloader fully loaded\n";
echo "collect: " . (function_exists('collect') ? "YES" : "NO") . "\n";
echo "app: " . (function_exists('app') ? "YES" : "NO") . "\n";

echo "\nLoading bootstrap/app.php...\n";
$app = require_once __DIR__ . '/bootstrap/app.php';
echo "App type: " . gettype($app) . "\n";
if (is_object($app)) {
    echo "App class: " . get_class($app) . "\n";
}
