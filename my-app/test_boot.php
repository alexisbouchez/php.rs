<?php
echo "START\n";
require __DIR__ . '/vendor/autoload.php';
echo "AUTOLOAD OK\n";

$app = require __DIR__ . '/bootstrap/app.php';
echo "A: App bootstrapped: " . get_class($app) . "\n";

// Try to resolve the HTTP kernel
$kernel = $app->make('Illuminate\Contracts\Http\Kernel');
echo "B: Kernel resolved: " . get_class($kernel) . "\n";

// Try to handle a request
$request = Illuminate\Http\Request::capture();
echo "C: Request captured: " . get_class($request) . "\n";

$response = $kernel->handle($request);
echo "D: Response status: " . $response->getStatusCode() . "\n";
echo "E: Response body length: " . strlen($response->getContent()) . "\n";
