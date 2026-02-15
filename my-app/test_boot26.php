<?php

echo "START\n";

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

echo "AUTOLOADER LOADED\n";

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

echo "LOADER REGISTERED\n";

$filesToLoad = $cls::$files;
foreach ($filesToLoad as $fid => $f) {
    echo "Loading: $f\n";
    require $f;
}

echo "FILES LOADED\n";

$file = $loader->findFile('Illuminate\Foundation\Application');
echo "App file: $file\n";
require_once $file;
echo "APP FILE LOADED\n";

$cn = 'Illuminate\Foundation\Application';
echo "ABOUT TO NEW\n";
$app = new $cn('/tmp/test');
echo "CREATED: " . get_class($app) . "\n";
