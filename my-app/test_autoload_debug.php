<?php

echo "=== Direct autoloader test ===\n";
require __DIR__ . '/vendor/autoload.php';
echo "Autoloader returned\n";

// Check if join_paths function exists now
echo "join_paths exists: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
echo "collect exists: " . (function_exists('collect') ? "YES" : "NO") . "\n";

// Check GLOBALS
echo "GLOBALS autoload_files set: " . (isset($GLOBALS['__composer_autoload_files']) ? "YES" : "NO") . "\n";
if (isset($GLOBALS['__composer_autoload_files'])) {
    echo "GLOBALS autoload_files count: " . count($GLOBALS['__composer_autoload_files']) . "\n";
}

// Check the static class is loaded
$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';
echo "Static class exists: " . (class_exists($cls, false) ? "YES" : "NO") . "\n";
if (class_exists($cls, false)) {
    echo "Static files count: " . count($cls::$files) . "\n";
}
