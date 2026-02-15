<?php

namespace Test;

trait MyTrait {
    protected function helper() {
        return "from trait";
    }
}

class MyClass {
    use MyTrait;

    public function test() {
        return $this->helper();
    }
}

$obj = new MyClass();
echo $obj->test() . "\n";
