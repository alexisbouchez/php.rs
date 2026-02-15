<?php
echo "BEFORE NEW\n";
$cn = 'Illuminate\Foundation\Application';
$app = new $cn('/tmp/test');
echo "AFTER NEW: " . get_class($app) . "\n";
