<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';

$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

echo "Autoloader registered\n";

$filesToLoad = $cls::$files;
echo "Loading " . count($filesToLoad) . " files\n";

$count = 0;
foreach ($filesToLoad as $fileIdentifier => $file) {
    $count++;
    echo "  [$count] Loading: $file\n";
    require $file;
    echo "  [$count] OK\n";
}

echo "All files loaded\n";
