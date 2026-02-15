<?php

require __DIR__ . '/vendor/composer/autoload_static.php';

$cls = 'Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693';

// Check if class exists
echo "Class exists: " . (class_exists($cls, false) ? "YES" : "NO") . "\n";

// Access the property
$files = $cls::$files;
echo "Type: " . gettype($files) . "\n";
echo "Count: " . count($files) . "\n";

// Try to print first few
$i = 0;
foreach ($files as $k => $v) {
    echo "  [$k] => $v\n";
    $i++;
    if ($i >= 3) break;
}
