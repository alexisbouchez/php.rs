<?php

// Simpler test: trait in different namespace, accessed via use import
namespace My\Traits;

trait Helper {
    public function help() { return "helped"; }
}

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
