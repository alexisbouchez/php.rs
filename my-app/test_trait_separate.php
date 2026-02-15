<?php

require __DIR__ . '/TestTraitNS.php';

namespace My\Classes;

use My\Traits\Helper;

class Foo {
    use Helper;

    public function test() {
        return $this->help();
    }
}

$obj = new \My\Classes\Foo();
echo $obj->test() . "\n";
