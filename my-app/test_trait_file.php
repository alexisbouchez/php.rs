<?php

require __DIR__ . '/TestTrait.php';
require __DIR__ . '/TestClass.php';

$obj = new \Test\TestClass();
echo "Result: ";
print_r($obj->run());
echo "\n";
