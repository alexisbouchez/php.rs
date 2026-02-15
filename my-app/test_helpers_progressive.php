<?php

use Illuminate\Support\Arr;
use Illuminate\Support\Collection;

if (! function_exists('collect')) {
    function collect($value = []): Collection
    {
        return new Collection($value);
    }
}
echo "collect: " . (function_exists('collect') ? "YES" : "NO") . "\n";

if (! function_exists('data_fill')) {
    function data_fill(&$target, $key, $value)
    {
        return data_set($target, $key, $value, false);
    }
}
echo "data_fill: " . (function_exists('data_fill') ? "YES" : "NO") . "\n";

if (! function_exists('value')) {
    function value($value, ...$args)
    {
        return $value instanceof Closure ? $value(...$args) : $value;
    }
}
echo "value: " . (function_exists('value') ? "YES" : "NO") . "\n";

if (! function_exists('head')) {
    function head($array)
    {
        return empty($array) ? false : array_first($array);
    }
}
echo "head: " . (function_exists('head') ? "YES" : "NO") . "\n";
