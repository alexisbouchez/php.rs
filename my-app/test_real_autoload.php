<?php

// Use the ACTUAL autoload_real.php but add debug output
require __DIR__ . '/vendor/composer/autoload_real.php';
echo "autoload_real loaded\n";

$result = ComposerAutoloaderInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::getLoader();
echo "getLoader returned: " . gettype($result) . "\n";

// Check
echo "join_paths: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
echo "collect: " . (function_exists('collect') ? "YES" : "NO") . "\n";
echo "GLOBALS set: " . (isset($GLOBALS['__composer_autoload_files']) ? "YES" : "NO") . "\n";
if (isset($GLOBALS['__composer_autoload_files'])) {
    echo "GLOBALS count: " . count($GLOBALS['__composer_autoload_files']) . "\n";
}
