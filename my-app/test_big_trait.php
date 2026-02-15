<?php

require __DIR__ . '/BigTrait.php';

namespace Big;

class User {
    use BigTrait;
    public function test() { return $this->methodC(); }
}

$u = new User();
echo $u->methodA() . "\n";
echo $u->methodB() . "\n";
echo $u->test() . "\n";
echo $u->methodD() . "\n";
echo $u->methodE() . "\n";
