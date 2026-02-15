<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);
echo "Autoloader ready\n";

// Load files using the EXACT same pattern as autoload_real.php
$filesToLoad = $cls::$files;
$requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
        require $file;
    }
}, null, null);

$count = 0;
foreach ($filesToLoad as $fileIdentifier => $file) {
    $count++;
    $requireFile($fileIdentifier, $file);
}
echo "Loaded $count files\n";

echo "Checking Application...\n";
echo "class_exists: " . (class_exists('Illuminate\Foundation\Application') ? "YES" : "NO") . "\n";
