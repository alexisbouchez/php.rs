<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';

$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));

echo "Before getInitializer:\n";
echo "  files count: " . count($cls::$files) . "\n";

$init = $cls::getInitializer($loader);
echo "\nAfter getInitializer:\n";
echo "  init type: " . gettype($init) . "\n";
echo "  files count: " . count($cls::$files) . "\n";

call_user_func($init);
echo "\nAfter call_user_func(init):\n";
echo "  files count: " . count($cls::$files) . "\n";

$loader->register(true);
echo "\nAfter register:\n";
echo "  files count: " . count($cls::$files) . "\n";

// Now try the foreach
$filesToLoad = $cls::$files;
echo "\nfilesToLoad count: " . count($filesToLoad) . "\n";

$i = 0;
foreach ($filesToLoad as $k => $v) {
    $i++;
    if ($i <= 3) echo "  [$k] => $v\n";
}
echo "Total iterated: $i\n";
