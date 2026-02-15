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

echo "Files loaded OK\n";

// Try loading Application.php manually
echo "Loading Application.php...\n";
$file = $loader->findFile('Illuminate\Foundation\Application');
echo "File: $file\n";
require_once $file;
echo "Loaded\n";
echo "class_exists: " . (class_exists('Illuminate\Foundation\Application', false) ? "YES" : "NO") . "\n";

// NOW try instantiating
echo "Step 2: new Application\n";
$basePath = dirname(__DIR__);
echo "basePath: $basePath\n";
$app = new \Illuminate\Foundation\Application($basePath);
echo "CREATED: " . get_class($app) . "\n";
