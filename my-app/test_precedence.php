<?php
$type = null;
// PHP precedence: instanceof is higher than !
// So "! $type instanceof ReflectionNamedType" is "!($type instanceof ReflectionNamedType)"
$r1 = !$type instanceof stdClass;
echo "r1=" . ($r1 ? "true" : "false") . "\n"; // should be true

// But our parser may treat it as "(!$type) instanceof stdClass"
$r2 = (!$type) instanceof stdClass;
echo "r2=" . ($r2 ? "true" : "false") . "\n"; // should be false
