<?php
$x = null;
if (!($x instanceof stdClass) || $x->foo()) {
    echo "short-circuited correctly\n";
}
