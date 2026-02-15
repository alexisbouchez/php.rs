<?php

fwrite(STDERR, "START\n");

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

$filesToLoad = $cls::$files;
foreach ($filesToLoad as $fid => $f) {
    require $f;
}

fwrite(STDERR, "FILES LOADED\n");

$file = $loader->findFile('Illuminate\Foundation\Application');
require_once $file;
fwrite(STDERR, "APP FILE LOADED\n");

$cn = 'Illuminate\Foundation\Application';
fwrite(STDERR, "ABOUT TO NEW\n");
$app = new $cn('/tmp/test');
fwrite(STDERR, "CREATED\n");
