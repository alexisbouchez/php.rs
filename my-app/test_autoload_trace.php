<?php

echo "Step 1: Loading autoload_real.php\n";
require __DIR__ . '/vendor/composer/autoload_real.php';

echo "Step 2: Loading platform_check.php\n";
require __DIR__ . '/vendor/composer/platform_check.php';

echo "Step 3: Loading ClassLoader\n";
require __DIR__ . '/vendor/composer/ClassLoader.php';

echo "Step 4: Loading autoload_static.php\n";
require __DIR__ . '/vendor/composer/autoload_static.php';

echo "Step 5: Getting files list\n";
$filesToLoad = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::$files;
echo "Files count: " . count($filesToLoad) . "\n";

echo "Step 6: Loading files with closure\n";
$count = 0;
$requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
        require $file;
    }
}, null, null);

foreach ($filesToLoad as $fileIdentifier => $file) {
    echo "  Loading [$count]: $file\n";
    $requireFile($fileIdentifier, $file);
    $count = $count + 1;
    echo "  Loaded OK\n";
}

echo "Step 7: Check join_paths\n";
echo "  exists: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
