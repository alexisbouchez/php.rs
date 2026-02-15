<?php

namespace Foo;

use function strlen;

trait Bar {
    public function test() { return "from trait"; }
    public function test2() { return "also from trait"; }
}

namespace Baz;

class Qux {
    use \Foo\Bar;
}

$q = new Qux();
echo $q->test() . "\n";
echo $q->test2() . "\n";
