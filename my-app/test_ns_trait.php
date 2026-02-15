<?php

// File 1 content (simulating require of a namespace trait)
require __DIR__ . '/TestTrait2.php';
require __DIR__ . '/TestClass2.php';

$obj = new \App\MyClass();
echo $obj->test() . "\n";
