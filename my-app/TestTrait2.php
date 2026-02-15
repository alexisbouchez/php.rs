<?php

namespace App\Traits;

trait Greetable {
    protected function greet() {
        return "hello from trait";
    }
}
