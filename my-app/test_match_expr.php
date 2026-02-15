<?php

$x = 5;
$result = match (true) {
    $x > 10 => "big",
    $x > 3 => "medium",
    default => "small",
};
echo $result . "\n";
