<?php
function testCall(callable $fn, string $val) {
    return $fn($val);
}

$result = testCall(static function(string $s) {
    return strtoupper($s);
}, "hello");
echo $result . "\n";
