<?php

echo "START\n";

require __DIR__ . '/vendor/composer/ClassLoader.php';
echo "1\n";

require __DIR__ . '/vendor/composer/autoload_static.php';
echo "2\n";

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
echo "3\n";

$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);
echo "4\n";

$filesToLoad = $cls::$files;
foreach ($filesToLoad as $fid => $f) {
    require $f;
}
echo "5\n";

$file = $loader->findFile('Illuminate\Foundation\Application');
echo "6: $file\n";

require_once $file;
echo "7\n";

$cn = 'Illuminate\Foundation\Application';
$app = new $cn('/tmp/test');
echo "8\n";
