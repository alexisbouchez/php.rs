<?php

require __DIR__ . '/vendor/composer/ClassLoader.php';
require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
$loader = new \Composer\Autoload\ClassLoader(dirname(__DIR__ . '/vendor'));
$init = $cls::getInitializer($loader);
call_user_func($init);
$loader->register(true);

$filesToLoad = $cls::$files;
foreach ($filesToLoad as $fileIdentifier => $file) {
    require $file;
}

echo "Autoloader ready\n";

// Step by step reproduction of bootstrap/app.php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

echo "Step 1: Application::configure\n";
$builder = Application::configure(basePath: dirname(__DIR__));
echo "  type: " . gettype($builder) . "\n";
if (is_object($builder)) {
    echo "  class: " . get_class($builder) . "\n";
}

echo "Step 2: withRouting\n";
$builder2 = $builder->withRouting(
    web: __DIR__.'/../routes/web.php',
    commands: __DIR__.'/../routes/console.php',
    health: '/up',
);
echo "  type: " . gettype($builder2) . "\n";

echo "Step 3: withMiddleware\n";
$builder3 = $builder2->withMiddleware(function (Middleware $middleware): void {
    //
});
echo "  type: " . gettype($builder3) . "\n";

echo "Step 4: withExceptions\n";
$builder4 = $builder3->withExceptions(function (Exceptions $exceptions): void {
    //
});
echo "  type: " . gettype($builder4) . "\n";

echo "Step 5: create\n";
$app = $builder4->create();
echo "  type: " . gettype($app) . "\n";
if (is_object($app)) {
    echo "  class: " . get_class($app) . "\n";
}
