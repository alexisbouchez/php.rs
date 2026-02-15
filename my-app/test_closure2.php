<?php
class Regex {
    public static function split(string $pattern, string $subject) {
        return self::pregAndWrap(static function (string $subject) use ($pattern) {
            return preg_split($pattern, $subject);
        }, $subject);
    }

    private static function pregAndWrap(callable $operation, string $subject) {
        $result = $operation($subject);
        return $result;
    }
}

$result = Regex::split('/,/', 'a,b,c');
print_r($result);
