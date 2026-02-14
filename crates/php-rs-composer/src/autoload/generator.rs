use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::package::Package;

/// Generates PHP autoload files in vendor/composer/.
pub struct AutoloadGenerator {
    vendor_dir: PathBuf,
    authoritative: bool,
}

impl AutoloadGenerator {
    pub fn new(vendor_dir: &Path) -> Self {
        AutoloadGenerator {
            vendor_dir: vendor_dir.to_path_buf(),
            authoritative: false,
        }
    }

    /// Enable authoritative classmap mode (classmap-authoritative).
    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    /// Generate all autoload files for the given installed packages.
    pub fn generate(&self, packages: &[Package], root_package: &Package) -> Result<(), String> {
        let composer_dir = self.vendor_dir.join("composer");
        std::fs::create_dir_all(&composer_dir)
            .map_err(|e| format!("Failed to create composer dir: {}", e))?;

        let (psr4_map, psr0_map, classmap_dirs, files) =
            self.collect_autoload_info(packages, root_package);

        // Scan classmap directories to find class definitions
        let classmap = self.scan_classmap_dirs(&classmap_dirs);

        self.generate_autoload_php()?;
        self.generate_psr4(&composer_dir, &psr4_map)?;
        self.generate_psr0(&composer_dir, &psr0_map)?;
        self.generate_classmap_php(&composer_dir, &classmap)?;
        self.generate_files(&composer_dir, &files)?;
        self.generate_class_loader_php(&composer_dir)?;
        self.generate_autoload_real_php(&composer_dir)?;
        self.generate_installed_json(&composer_dir, packages)?;
        self.generate_installed_php(&composer_dir, packages, root_package)?;

        Ok(())
    }

    fn collect_autoload_info(
        &self,
        packages: &[Package],
        root_package: &Package,
    ) -> (
        BTreeMap<String, Vec<String>>,
        BTreeMap<String, Vec<String>>,
        Vec<PathBuf>,
        Vec<String>,
    ) {
        let mut psr4_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut psr0_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut classmap_dirs = Vec::new();
        let mut files = Vec::new();

        for pkg in packages {
            let base_path = format!("$vendorDir . '/{}'", pkg.name);
            let abs_base = self.vendor_dir.join(&pkg.name);
            if let Some(autoload) = &pkg.autoload {
                for (ns, paths) in &autoload.psr4 {
                    for p in paths.paths() {
                        psr4_map
                            .entry(ns.clone())
                            .or_default()
                            .push(format!("{} . '/{}'", base_path, p));
                    }
                }
                for (ns, paths) in &autoload.psr0 {
                    for p in paths.paths() {
                        psr0_map
                            .entry(ns.clone())
                            .or_default()
                            .push(format!("{} . '/{}'", base_path, p));
                    }
                }
                for dir in &autoload.classmap {
                    classmap_dirs.push(abs_base.join(dir));
                }
                for file in &autoload.files {
                    files.push(format!("{} . '/{}'", base_path, file));
                }
            }
        }

        if let Some(autoload) = &root_package.autoload {
            let base = "$baseDir";
            let abs_base = self.vendor_dir.parent().unwrap_or(Path::new("."));
            for (ns, paths) in &autoload.psr4 {
                for p in paths.paths() {
                    psr4_map
                        .entry(ns.clone())
                        .or_default()
                        .push(format!("{} . '/{}'", base, p));
                }
            }
            for (ns, paths) in &autoload.psr0 {
                for p in paths.paths() {
                    psr0_map
                        .entry(ns.clone())
                        .or_default()
                        .push(format!("{} . '/{}'", base, p));
                }
            }
            for dir in &autoload.classmap {
                classmap_dirs.push(abs_base.join(dir));
            }
        }

        (psr4_map, psr0_map, classmap_dirs, files)
    }

    /// Scan directories for PHP class/interface/trait/enum definitions.
    fn scan_classmap_dirs(&self, dirs: &[PathBuf]) -> BTreeMap<String, String> {
        let mut classmap = BTreeMap::new();

        for dir in dirs {
            if dir.is_file() {
                self.scan_php_file(dir, &mut classmap);
            } else if dir.is_dir() {
                self.scan_dir_recursive(dir, &mut classmap);
            }
        }

        classmap
    }

    fn scan_dir_recursive(&self, dir: &Path, classmap: &mut BTreeMap<String, String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.scan_dir_recursive(&path, classmap);
            } else if path.extension().map_or(false, |e| e == "php") {
                self.scan_php_file(&path, classmap);
            }
        }
    }

    fn scan_php_file(&self, path: &Path, classmap: &mut BTreeMap<String, String>) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let relative = self.make_relative_path(path);

        // Simple regex-based class/interface/trait/enum detection
        let re = regex::Regex::new(
            r"(?m)^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait|enum)\s+(\w+)",
        )
        .unwrap();

        let ns_re = regex::Regex::new(r"(?m)^\s*namespace\s+([\w\\]+)\s*;").unwrap();

        let namespace = ns_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        for cap in re.captures_iter(&content) {
            if let Some(class_name) = cap.get(1) {
                let fqcn = match &namespace {
                    Some(ns) => format!("{}\\{}", ns, class_name.as_str()),
                    None => class_name.as_str().to_string(),
                };
                classmap.insert(fqcn, relative.clone());
            }
        }
    }

    fn make_relative_path(&self, path: &Path) -> String {
        let vendor_parent = self.vendor_dir.parent().unwrap_or(Path::new("."));

        if let Ok(rel) = path.strip_prefix(vendor_parent) {
            format!("$baseDir . '/{}'", rel.display())
        } else if let Ok(rel) = path.strip_prefix(&self.vendor_dir) {
            format!("$vendorDir . '/{}'", rel.display())
        } else {
            format!("'{}'", path.display())
        }
    }

    fn generate_autoload_php(&self) -> Result<(), String> {
        let content = r#"<?php

// autoload.php @generated by php-rs-composer

require_once __DIR__ . '/composer/autoload_real.php';

return ComposerAutoloaderInit::getLoader();
"#;
        std::fs::write(self.vendor_dir.join("autoload.php"), content)
            .map_err(|e| format!("Failed to write autoload.php: {}", e))
    }

    fn generate_psr4(
        &self,
        composer_dir: &Path,
        psr4_map: &BTreeMap<String, Vec<String>>,
    ) -> Result<(), String> {
        let mut lines = vec![
            "<?php".to_string(),
            String::new(),
            "// autoload_psr4.php @generated by php-rs-composer".to_string(),
            String::new(),
            "$vendorDir = dirname(__DIR__);".to_string(),
            "$baseDir = dirname($vendorDir);".to_string(),
            String::new(),
            "return array(".to_string(),
        ];

        for (ns, paths) in psr4_map {
            if paths.len() == 1 {
                lines.push(format!(
                    "    '{}' => array({}),",
                    escape_php_key(ns),
                    paths[0]
                ));
            } else {
                lines.push(format!("    '{}' => array(", escape_php_key(ns)));
                for p in paths {
                    lines.push(format!("        {},", p));
                }
                lines.push("    ),".to_string());
            }
        }

        lines.push(");".to_string());
        lines.push(String::new());

        std::fs::write(composer_dir.join("autoload_psr4.php"), lines.join("\n"))
            .map_err(|e| format!("Failed to write autoload_psr4.php: {}", e))
    }

    fn generate_psr0(
        &self,
        composer_dir: &Path,
        psr0_map: &BTreeMap<String, Vec<String>>,
    ) -> Result<(), String> {
        let mut lines = vec![
            "<?php".to_string(),
            String::new(),
            "// autoload_namespaces.php @generated by php-rs-composer".to_string(),
            String::new(),
            "$vendorDir = dirname(__DIR__);".to_string(),
            "$baseDir = dirname($vendorDir);".to_string(),
            String::new(),
            "return array(".to_string(),
        ];

        for (ns, paths) in psr0_map {
            if paths.len() == 1 {
                lines.push(format!(
                    "    '{}' => array({}),",
                    escape_php_key(ns),
                    paths[0]
                ));
            } else {
                lines.push(format!("    '{}' => array(", escape_php_key(ns)));
                for p in paths {
                    lines.push(format!("        {},", p));
                }
                lines.push("    ),".to_string());
            }
        }

        lines.push(");".to_string());
        lines.push(String::new());

        std::fs::write(
            composer_dir.join("autoload_namespaces.php"),
            lines.join("\n"),
        )
        .map_err(|e| format!("Failed to write autoload_namespaces.php: {}", e))
    }

    fn generate_classmap_php(
        &self,
        composer_dir: &Path,
        classmap: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        let mut lines = vec![
            "<?php".to_string(),
            String::new(),
            "// autoload_classmap.php @generated by php-rs-composer".to_string(),
            String::new(),
            "$vendorDir = dirname(__DIR__);".to_string(),
            "$baseDir = dirname($vendorDir);".to_string(),
            String::new(),
            "return array(".to_string(),
        ];

        for (class, path) in classmap {
            lines.push(format!("    '{}' => {},", escape_php_key(class), path));
        }

        lines.push(");".to_string());
        lines.push(String::new());

        std::fs::write(composer_dir.join("autoload_classmap.php"), lines.join("\n"))
            .map_err(|e| format!("Failed to write autoload_classmap.php: {}", e))
    }

    fn generate_files(&self, composer_dir: &Path, files: &[String]) -> Result<(), String> {
        let mut lines = vec![
            "<?php".to_string(),
            String::new(),
            "// autoload_files.php @generated by php-rs-composer".to_string(),
            String::new(),
            "$vendorDir = dirname(__DIR__);".to_string(),
            "$baseDir = dirname($vendorDir);".to_string(),
            String::new(),
            "return array(".to_string(),
        ];

        for (i, file) in files.iter().enumerate() {
            lines.push(format!("    '{}' => {},", Self::file_id(i), file));
        }

        lines.push(");".to_string());
        lines.push(String::new());

        std::fs::write(composer_dir.join("autoload_files.php"), lines.join("\n"))
            .map_err(|e| format!("Failed to write autoload_files.php: {}", e))
    }

    /// Generate vendor/composer/installed.json (list of installed packages).
    fn generate_installed_json(
        &self,
        composer_dir: &Path,
        packages: &[Package],
    ) -> Result<(), String> {
        let installed = serde_json::json!({
            "packages": packages,
            "dev": true,
            "dev-package-names": []
        });

        let content = serde_json::to_string_pretty(&installed)
            .map_err(|e| format!("Failed to serialize installed.json: {}", e))?;

        std::fs::write(
            composer_dir.join("installed.json"),
            format!("{}\n", content),
        )
        .map_err(|e| format!("Failed to write installed.json: {}", e))
    }

    /// Generate vendor/composer/installed.php (PHP array of installed packages).
    fn generate_installed_php(
        &self,
        composer_dir: &Path,
        packages: &[Package],
        root_package: &Package,
    ) -> Result<(), String> {
        let mut lines = vec![
            "<?php return array(".to_string(),
            "    'root' => array(".to_string(),
            format!("        'name' => '{}',", root_package.name),
            format!("        'pretty_version' => '{}',", root_package.version),
            "        'version' => 'dev-main',".to_string(),
            format!("        'reference' => NULL,"),
            "        'type' => 'project',".to_string(),
            format!("        'install_path' => __DIR__ . '/../../',"),
            "        'aliases' => array(),".to_string(),
            "        'dev' => true,".to_string(),
            "    ),".to_string(),
            "    'versions' => array(".to_string(),
        ];

        // Root package entry
        lines.push(format!("        '{}' => array(", root_package.name));
        lines.push(format!(
            "            'pretty_version' => '{}',",
            root_package.version
        ));
        lines.push("            'version' => 'dev-main',".to_string());
        lines.push("            'reference' => NULL,".to_string());
        lines.push(format!(
            "            'type' => '{}',",
            root_package.package_type
        ));
        lines.push("            'install_path' => __DIR__ . '/../../',".to_string());
        lines.push("            'aliases' => array(),".to_string());
        lines.push("            'dev_requirement' => false,".to_string());
        lines.push("        ),".to_string());

        // Installed packages
        for pkg in packages {
            lines.push(format!("        '{}' => array(", pkg.name));
            lines.push(format!(
                "            'pretty_version' => '{}',",
                pkg.version
            ));
            lines.push(format!(
                "            'version' => '{}',",
                pkg.version_normalized.as_str().trim().to_string()
            ));
            let reference = pkg
                .source
                .as_ref()
                .map(|s| format!("'{}'", s.reference))
                .unwrap_or_else(|| "NULL".to_string());
            lines.push(format!("            'reference' => {},", reference));
            lines.push(format!("            'type' => '{}',", pkg.package_type));
            lines.push(format!(
                "            'install_path' => __DIR__ . '/../{}',",
                pkg.name
            ));
            lines.push("            'aliases' => array(),".to_string());
            lines.push("            'dev_requirement' => false,".to_string());
            lines.push("        ),".to_string());
        }

        lines.push("    ),".to_string());
        lines.push(");".to_string());
        lines.push(String::new());

        std::fs::write(composer_dir.join("installed.php"), lines.join("\n"))
            .map_err(|e| format!("Failed to write installed.php: {}", e))
    }

    /// Generate vendor/composer/ClassLoader.php — the Composer autoloader class.
    fn generate_class_loader_php(&self, composer_dir: &Path) -> Result<(), String> {
        let content = r#"<?php

namespace Composer\Autoload;

class ClassLoader
{
    private $prefixesPsr4 = array();
    private $fallbackDirsPsr4 = array();
    private $prefixesPsr0 = array();
    private $fallbackDirsPsr0 = array();
    private $classMap = array();
    private $classMapAuthoritative = false;
    private $registered = false;

    public function getPrefixesPsr4()
    {
        return $this->prefixesPsr4;
    }

    public function getClassMap()
    {
        return $this->classMap;
    }

    public function addClassMap(array $classMap)
    {
        if ($this->classMap) {
            $this->classMap = array_merge($this->classMap, $classMap);
        } else {
            $this->classMap = $classMap;
        }
    }

    public function add($prefix, $paths, $prepend = false)
    {
        $paths = (array) $paths;
        if (!$prefix) {
            if ($prepend) {
                $this->fallbackDirsPsr0 = array_merge($paths, $this->fallbackDirsPsr0);
            } else {
                $this->fallbackDirsPsr0 = array_merge($this->fallbackDirsPsr0, $paths);
            }
            return;
        }

        $first = $prefix[0];
        if (!isset($this->prefixesPsr0[$first][$prefix])) {
            $this->prefixesPsr0[$first][$prefix] = $paths;
            return;
        }
        if ($prepend) {
            $this->prefixesPsr0[$first][$prefix] = array_merge($paths, $this->prefixesPsr0[$first][$prefix]);
        } else {
            $this->prefixesPsr0[$first][$prefix] = array_merge($this->prefixesPsr0[$first][$prefix], $paths);
        }
    }

    public function addPsr4($prefix, $paths, $prepend = false)
    {
        $paths = (array) $paths;
        if (!$prefix) {
            if ($prepend) {
                $this->fallbackDirsPsr4 = array_merge($paths, $this->fallbackDirsPsr4);
            } else {
                $this->fallbackDirsPsr4 = array_merge($this->fallbackDirsPsr4, $paths);
            }
            return;
        }

        if (!isset($this->prefixesPsr4[$prefix])) {
            $length = strlen($prefix);
            if ('\\' !== $prefix[$length - 1]) {
                // error
                return;
            }
            $this->prefixesPsr4[$prefix] = $paths;
            return;
        }
        if ($prepend) {
            $this->prefixesPsr4[$prefix] = array_merge($paths, $this->prefixesPsr4[$prefix]);
        } else {
            $this->prefixesPsr4[$prefix] = array_merge($this->prefixesPsr4[$prefix], $paths);
        }
    }

    public function setPsr4($prefix, $paths)
    {
        if (!$prefix) {
            $this->fallbackDirsPsr4 = (array) $paths;
        } else {
            $this->prefixesPsr4[$prefix] = (array) $paths;
        }
    }

    public function setClassMapAuthoritative($classMapAuthoritative)
    {
        $this->classMapAuthoritative = $classMapAuthoritative;
    }

    public function isClassMapAuthoritative()
    {
        return $this->classMapAuthoritative;
    }

    public function register($prepend = false)
    {
        if ($this->registered) {
            return;
        }
        spl_autoload_register(array($this, 'loadClass'), true, $prepend);
        $this->registered = true;
    }

    public function unregister()
    {
        spl_autoload_unregister(array($this, 'loadClass'));
        $this->registered = false;
    }

    public function loadClass($class)
    {
        if ($file = $this->findFile($class)) {
            include $file;
            return true;
        }
        return false;
    }

    public function findFile($class)
    {
        // class map lookup
        if (isset($this->classMap[$class])) {
            return $this->classMap[$class];
        }
        if ($this->classMapAuthoritative) {
            return false;
        }

        // PSR-4 lookup
        $logicalPathPsr4 = strtr($class, '\\', DIRECTORY_SEPARATOR) . '.php';

        $first = $class[0];
        foreach ($this->prefixesPsr4 as $prefix => $dirs) {
            if (strpos($class, $prefix) === 0) {
                $length = strlen($prefix);
                foreach ($dirs as $dir) {
                    $file = $dir . DIRECTORY_SEPARATOR . substr($logicalPathPsr4, $length);
                    if (file_exists($file)) {
                        return $file;
                    }
                }
            }
        }

        // PSR-4 fallback dirs
        foreach ($this->fallbackDirsPsr4 as $dir) {
            if (file_exists($file = $dir . DIRECTORY_SEPARATOR . $logicalPathPsr4)) {
                return $file;
            }
        }

        // PSR-0 lookup
        if (false !== ($pos = strrpos($class, '\\'))) {
            $logicalPathPsr0 = substr($logicalPathPsr4, 0, $pos + 1)
                . strtr(substr($logicalPathPsr4, $pos + 1), '_', DIRECTORY_SEPARATOR);
        } else {
            $logicalPathPsr0 = strtr($class, '_', DIRECTORY_SEPARATOR) . '.php';
        }

        foreach ($this->prefixesPsr0 as $prefixGroup) {
            foreach ($prefixGroup as $prefix => $dirs) {
                if (0 === strpos($class, $prefix)) {
                    foreach ($dirs as $dir) {
                        if (file_exists($file = $dir . DIRECTORY_SEPARATOR . $logicalPathPsr0)) {
                            return $file;
                        }
                    }
                }
            }
        }

        // PSR-0 fallback dirs
        foreach ($this->fallbackDirsPsr0 as $dir) {
            if (file_exists($file = $dir . DIRECTORY_SEPARATOR . $logicalPathPsr0)) {
                return $file;
            }
        }

        return false;
    }
}
"#;
        std::fs::write(composer_dir.join("ClassLoader.php"), content)
            .map_err(|e| format!("Failed to write ClassLoader.php: {}", e))
    }

    /// Generate vendor/composer/autoload_real.php — the bootstrap that wires everything together.
    fn generate_autoload_real_php(&self, composer_dir: &Path) -> Result<(), String> {
        let content = r#"<?php

class ComposerAutoloaderInit
{
    private static $loader;

    public static function getLoader()
    {
        if (null !== self::$loader) {
            return self::$loader;
        }

        require __DIR__ . '/ClassLoader.php';

        self::$loader = $loader = new \Composer\Autoload\ClassLoader();

        $map = require __DIR__ . '/autoload_psr4.php';
        foreach ($map as $namespace => $path) {
            $loader->addPsr4($namespace, $path);
        }

        $map = require __DIR__ . '/autoload_namespaces.php';
        foreach ($map as $namespace => $path) {
            $loader->add($namespace, $path);
        }

        $classMap = require __DIR__ . '/autoload_classmap.php';
        if ($classMap) {
            $loader->addClassMap($classMap);
        }

        $loader->register(true);

        $includeFiles = require __DIR__ . '/autoload_files.php';
        foreach ($includeFiles as $fileIdentifier => $file) {
            require $file;
        }

        return $loader;
    }
}
"#;
        std::fs::write(composer_dir.join("autoload_real.php"), content)
            .map_err(|e| format!("Failed to write autoload_real.php: {}", e))
    }

    fn file_id(index: usize) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(index.to_string().as_bytes());
        format!("{:x}", hasher.finalize())[..32].to_string()
    }
}

/// Escape a PHP array key (backslashes need doubling).
fn escape_php_key(s: &str) -> String {
    s.replace('\\', "\\\\")
}
