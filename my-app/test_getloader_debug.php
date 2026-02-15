<?php

// Exact copy of getLoader with debug
class DebugAutoloader {
    private static $loader;

    public static function loadClassLoader($class) {
        if ('Composer\Autoload\ClassLoader' === $class) {
            require __DIR__ . '/vendor/composer/ClassLoader.php';
        }
    }

    public static function getLoader() {
        echo "  A: check self::loader\n";
        if (null !== self::$loader) {
            echo "  A: returning cached\n";
            return self::$loader;
        }

        echo "  B: require platform_check\n";
        require __DIR__ . '/vendor/composer/platform_check.php';

        echo "  C: spl_autoload_register\n";
        spl_autoload_register(array('DebugAutoloader', 'loadClassLoader'), true, true);

        echo "  D: new ClassLoader\n";
        self::$loader = $loader = new \Composer\Autoload\ClassLoader(\dirname(__DIR__));
        echo "  D: loader class: " . get_class($loader) . "\n";

        echo "  E: spl_autoload_unregister\n";
        spl_autoload_unregister(array('DebugAutoloader', 'loadClassLoader'));

        echo "  F: require autoload_static\n";
        require __DIR__ . '/vendor/composer/autoload_static.php';

        echo "  G: getInitializer\n";
        $init = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::getInitializer($loader);
        echo "  G: init type: " . gettype($init) . "\n";

        echo "  H: call_user_func\n";
        call_user_func($init);
        echo "  H: done\n";

        echo "  I: register\n";
        $loader->register(true);
        echo "  I: done\n";

        echo "  J: get files\n";
        $filesToLoad = \Composer\Autoload\ComposerStaticInitb7f597c8f05365e00751f793e847b12b2e319b147b8e06f7697db67340932693::$files;
        echo "  J: count: " . count($filesToLoad) . "\n";

        echo "  K: create closure\n";
        $requireFile = \Closure::bind(static function ($fileIdentifier, $file) {
            if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
                $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
                require $file;
            }
        }, null, null);
        echo "  K: callable: " . (is_callable($requireFile) ? "YES" : "NO") . "\n";

        echo "  L: foreach\n";
        $count = 0;
        foreach ($filesToLoad as $fileIdentifier => $file) {
            $count++;
            $requireFile($fileIdentifier, $file);
        }
        echo "  L: loaded $count files\n";

        echo "  M: return\n";
        return $loader;
    }
}

echo "Calling getLoader:\n";
$result = DebugAutoloader::getLoader();
echo "Returned: " . gettype($result) . "\n";
echo "join_paths: " . (function_exists('Illuminate\Filesystem\join_paths') ? "YES" : "NO") . "\n";
