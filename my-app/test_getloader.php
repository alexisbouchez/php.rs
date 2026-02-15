<?php

// Replicate exact getLoader() flow

echo "Step 1: require platform_check\n";
require __DIR__ . '/vendor/composer/platform_check.php';

echo "Step 2: spl_autoload_register for ClassLoader\n";
spl_autoload_register(function($class) {
    echo "  autoload called for: $class\n";
    if ('Composer\Autoload\ClassLoader' === $class) {
        require __DIR__ . '/vendor/composer/ClassLoader.php';
    }
}, true, true);

echo "Step 3: new ClassLoader\n";
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
echo "  loader created\n";

echo "Step 4: spl_autoload_unregister\n";
// Note: original uses array('ClassName', 'method') but we'll skip that

echo "Step 5: require autoload_static\n";
require __DIR__ . '/vendor/composer/autoload_static.php';

echo "Step 6: getInitializer + call_user_func\n";
$init = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::getInitializer($loader);
call_user_func($init);
echo "  done\n";

echo "Step 7: register\n";
$loader->register(true);
echo "  done\n";

echo "Step 8: get files\n";
$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$filesToLoad = $cls::$files;
echo "  count: " . count($filesToLoad) . "\n";

echo "Step 9: create closure and load files\n";
$requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
        require $file;
    }
}, null, null);

$count = 0;
foreach ($filesToLoad as $fileIdentifier => $file) {
    $count++;
    if ($count <= 2) {
        echo "  Loading: $file\n";
    }
    $requireFile($fileIdentifier, $file);
}
echo "  Loaded $count files\n";

echo "Step 10: check functions\n";
echo "  join_paths: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
echo "  collect: " . (function_exists('collect') ? "YES" : "NO") . "\n";
