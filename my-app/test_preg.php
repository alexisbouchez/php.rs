<?php
// Test 1: Basic preg_match with captures
$result = preg_match('/(\w+)\s+(\w+)/', 'Hello World', $matches);
echo "Test 1: result=$result\n";
echo "matches[0]=" . $matches[0] . "\n";
echo "matches[1]=" . $matches[1] . "\n";
echo "matches[2]=" . $matches[2] . "\n";

// Test 2: preg_match with offset
$str = "xxxx=Hello";
$result2 = preg_match('/=(\w+)/', $str, $m2, 0, 3);
echo "\nTest 2: result=$result2\n";
echo "m2[0]=" . $m2[0] . "\n";
echo "m2[1]=" . $m2[1] . "\n";

// Test 3: preg_match with no match
$result3 = preg_match('/zzz/', 'abc', $m3);
echo "\nTest 3: result=$result3\n";

// Test 4: Dotenv-style regex with () delimiters and A flag
$content = "APP_NAME=Laravel";
$offset = 0;
$regex = '(^[A-Z_]+=)A';
$result4 = preg_match($regex, $content, $m4, 0, $offset);
echo "\nTest 4: result=$result4\n";
if ($result4) {
    echo "m4[0]=" . $m4[0] . "\n";
}
