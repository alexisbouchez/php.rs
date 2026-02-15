<?php

namespace App;

use App\Traits\Greetable;

class MyClass {
    use Greetable;

    public function test() {
        return $this->greet();
    }
}
