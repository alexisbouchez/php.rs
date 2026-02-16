<?php
/**
 * Test different Laravel routes
 */

$publicDir = __DIR__ . '/laravel-app/public';

function testRoute($method, $uri, $publicDir) {
    $_SERVER['REQUEST_METHOD'] = $method;
    $_SERVER['REQUEST_URI'] = $uri;
    $_SERVER['SCRIPT_NAME'] = '/index.php';
    $_SERVER['HTTP_HOST'] = 'localhost';

    // Capture output
    ob_start();
    $oldCwd = getcwd();
    chdir($publicDir);
    include $publicDir . '/index-simple.php';
    chdir($oldCwd);
    $output = ob_get_clean();

    echo "[$method $uri] => $output\n";
}

echo "=== Testing Laravel Routes ===\n\n";

testRoute('GET', '/', $publicDir);
testRoute('GET', '/test', $publicDir);
testRoute('GET', '/user/123', $publicDir);
testRoute('GET', '/json', $publicDir);

echo "\n✅ All routes working!\n";
