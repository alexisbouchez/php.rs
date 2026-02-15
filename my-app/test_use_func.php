<?php

use Illuminate\Support\Collection;

if (! function_exists('collect')) {
    function collect($value = []) {
        return "test";
    }
}

echo "collect exists: " . (function_exists('collect') ? "YES" : "NO") . "\n";
