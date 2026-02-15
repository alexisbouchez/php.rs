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

echo "A\n";

// Try Application::configure step by step
echo "B: checking Application class\n";
echo "class_exists: " . (class_exists('Illuminate\Foundation\Application') ? "YES" : "NO") . "\n";

echo "C: calling configure\n";
$basePath = dirname(__DIR__);
echo "basePath: $basePath\n";

$builder = \Illuminate\Foundation\Application::configure(basePath: $basePath);
echo "D: configure returned " . gettype($builder) . "\n";
