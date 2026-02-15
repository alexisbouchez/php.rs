<?php

function test_variadic($a, ...$args) {
    return count($args);
}

echo test_variadic(1, 2, 3, 4) . "\n";
