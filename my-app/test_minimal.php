<?php
require __DIR__ . '/vendor/autoload.php';

$app = new Illuminate\Foundation\Application(dirname(__DIR__));
$builder = new Illuminate\Foundation\Configuration\ApplicationBuilder($app);
$builder = $builder->withKernels()->withEvents()->withCommands()->withProviders();
echo "A: configure chain done, app=" . get_class($builder->app) . "\n";

$builder = $builder->withRouting(
    web: __DIR__ . '/../routes/web.php',
    commands: __DIR__ . '/../routes/console.php',
    health: '/up',
);
echo "B: withRouting done\n";

$builder = $builder->withMiddleware(function ($middleware) {
    // no-op
});
echo "C: withMiddleware done\n";

$builder = $builder->withExceptions(function ($exceptions) {
    // no-op
});
echo "D: withExceptions done\n";

$app = $builder->create();
echo "E: create() done, app=" . get_class($app) . "\n";
