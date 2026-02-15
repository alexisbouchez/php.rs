<?php
require __DIR__ . '/vendor/autoload.php';
$app = require __DIR__ . '/bootstrap/app.php';

echo "configPath: " . $app->configPath() . "\n";
echo "getCachedConfigPath: " . $app->getCachedConfigPath() . "\n";
echo "basePath: " . $app->basePath() . "\n";
