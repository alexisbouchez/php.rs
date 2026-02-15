<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

$filesToLoad = $cls::$files;
$requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
        require $file;
    }
}, null, null);
foreach ($filesToLoad as $fileIdentifier => $file) {
    $requireFile($fileIdentifier, $file);
}

echo "Creating Application...\n";
$app = new \Illuminate\Foundation\Application(dirname(__DIR__));
echo "Application created: " . get_class($app) . "\n";
