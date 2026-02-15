<?php

echo "Step 1: require platform_check\n";
require __DIR__ . '/vendor/composer/platform_check.php';

echo "Step 2: require ClassLoader\n";
require __DIR__ . '/vendor/composer/ClassLoader.php';

echo "Step 3: create ClassLoader\n";
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));

echo "Step 4: require autoload_static\n";
require __DIR__ . '/vendor/composer/autoload_static.php';

echo "Step 5: get initializer\n";
$init = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::getInitializer($loader);
echo "Initializer type: " . gettype($init) . "\n";
echo "Is callable: " . (is_callable($init) ? "YES" : "NO") . "\n";

echo "Step 6: call_user_func initializer\n";
call_user_func($init);
echo "Step 6 done\n";

echo "Step 7: register loader\n";
$loader->register(true);
echo "Step 7 done\n";

echo "Step 8: get files\n";
$filesToLoad = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::$files;
echo "Files count: " . count($filesToLoad) . "\n";

echo "Step 9: create requireFile closure\n";
$requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
        require $file;
    }
}, null, null);
echo "Closure created: " . (is_callable($requireFile) ? "YES" : "NO") . "\n";

echo "Step 10: iterate and load files\n";
$count = 0;
foreach ($filesToLoad as $fileIdentifier => $file) {
    $count++;
    echo "  File $count: $fileIdentifier => $file\n";
    $requireFile($fileIdentifier, $file);
    echo "  Loaded OK\n";
    if ($count >= 3) {
        echo "  (stopping at 3 for test)\n";
        break;
    }
}
echo "Iterated $count files\n";

echo "Step 11: check functions\n";
echo "  join_paths: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
echo "  GLOBALS set: " . (isset($GLOBALS['__composer_autoload_files']) ? "YES" : "NO") . "\n";
