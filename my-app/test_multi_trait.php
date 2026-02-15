<?php

trait TraitA {
    public function fromA() { return "A"; }
}

trait TraitB {
    public function fromB() { return "B"; }
}

trait TraitC {
    public function fromC() { return "C"; }
}

class MultiTrait {
    use TraitA, TraitB, TraitC;
}

$obj = new MultiTrait();
echo $obj->fromA() . "\n";
echo $obj->fromB() . "\n";
echo $obj->fromC() . "\n";
