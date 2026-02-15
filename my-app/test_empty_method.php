<?php

trait TestEmpty {
    public static function empty() {
        return "empty!";
    }
    public function other() {
        return "other";
    }
}

class Foo {
    use TestEmpty;
}

echo Foo::empty() . "\n";
$f = new Foo();
echo $f->other() . "\n";
