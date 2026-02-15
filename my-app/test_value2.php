<?php

if (! function_exists('value')) {
    function value($value, ...$args)
    {
        return $value instanceof Closure ? $value(...$args) : $value;
    }
}
echo "value: " . (function_exists('value') ? "YES" : "NO") . "\n";
