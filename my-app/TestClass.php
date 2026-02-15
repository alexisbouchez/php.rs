<?php

namespace Test;

class TestClass {
    use TestTrait;

    public function run() {
        return $this->getItems();
    }
}
