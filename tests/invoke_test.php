<?php

// Test 1: Basic __invoke()
class BasicInvoke {
    public function __invoke() {
        return "Basic invoke works!";
    }
}

$obj = new BasicInvoke();
echo "Test 1: " . $obj() . "\n";

// Test 2: __invoke() with arguments
class InvokeWithArgs {
    public function __invoke($a, $b) {
        return "Sum: " . ($a + $b);
    }
}

$calc = new InvokeWithArgs();
echo "Test 2: " . $calc(10, 20) . "\n";

// Test 3: Laravel pattern (new Class)()
class LaravelPattern {
    private $message;

    public function __construct($msg) {
        $this->message = $msg;
    }

    public function __invoke() {
        return $this->message;
    }
}

echo "Test 3: " . (new LaravelPattern("Laravel pattern works!"))() . "\n";

// Test 4: Closure vs __invoke()
$closure = function() { return "This is a closure"; };
$invokable = new BasicInvoke();

echo "Test 4a: " . $closure() . "\n";
echo "Test 4b: " . $invokable() . "\n";

echo "\n✅ All __invoke() tests passed!\n";
