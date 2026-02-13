//! PHP CLI SAPI — command-line interface for php.rs
//!
//! Equivalent to php-src/sapi/cli/php_cli.c
//!
//! Usage: php-rs [options] [-f] <file> [--] [args...]
//!        php-rs [options] -r <code> [--] [args...]
//!        php-rs [options] < script.php
//!
//! Options:
//!   -r <code>    Run PHP <code> without <?php tags
//!   -f <file>    Parse and execute <file>
//!   -l <file>    Syntax check only (lint)
//!   -d key=val   Define INI entry
//!   -c <path>    Look for php.ini in <path>
//!   -n           No php.ini file
//!   -v           Version information
//!   -m           Show compiled-in modules
//!   -i           PHP information (phpinfo)
//!   -w <file>    Output source with stripped comments/whitespace
//!   -s <file>    Output source with syntax highlighting (HTML)
//!   -a           Run interactively (REPL)
//!   -h, --help   Display this help message

use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use php_rs_runtime::{IniSystem, Superglobals};
use php_rs_vm::{PhpArray, Value};
use std::collections::HashMap;

mod server;

// ── CLI option parsing ──────────────────────────────────────────────────────

/// Parsed CLI options.
#[allow(dead_code)] // script_args will be used when $argv is wired up
struct CliOptions {
    /// Mode of operation.
    mode: CliMode,
    /// INI overrides from -d flags.
    ini_overrides: Vec<(String, String)>,
    /// Path to php.ini (from -c).
    ini_path: Option<String>,
    /// Whether to skip php.ini (from -n).
    no_ini: bool,
    /// Extra arguments after -- (available as $argv).
    script_args: Vec<String>,
}

/// What the CLI is doing.
enum CliMode {
    /// Execute a file: php-rs file.php
    RunFile(String),
    /// Execute inline code: php-rs -r 'code'
    RunCode(String),
    /// Lint a file: php-rs -l file.php
    Lint(String),
    /// Show version: php-rs -v
    Version,
    /// Show modules: php-rs -m
    Modules,
    /// Show phpinfo: php-rs -i
    Info,
    /// Strip comments: php-rs -w file.php
    Strip(String),
    /// Syntax highlight: php-rs -s file.php
    SyntaxHighlight(String),
    /// Interactive mode: php-rs -a
    Interactive,
    /// Built-in web server: php-rs -S localhost:8080
    Server {
        listen: String,
        docroot: Option<String>,
        router: Option<String>,
    },
    /// Read from stdin: echo 'code' | php-rs
    Stdin,
    /// Show help: php-rs -h / --help
    Help,
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    let mut mode: Option<CliMode> = None;
    let mut ini_overrides = Vec::new();
    let mut ini_path = None;
    let mut no_ini = false;
    let mut script_args = Vec::new();
    let mut server_listen: Option<String> = None;
    let mut server_docroot: Option<String> = None;
    let mut i = 1; // skip argv[0]
    let mut past_separator = false;

    while i < args.len() {
        if past_separator {
            script_args.push(args[i].clone());
            i += 1;
            continue;
        }

        match args[i].as_str() {
            "--" => {
                past_separator = true;
                i += 1;
            }
            "-r" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -r requires an argument".to_string());
                }
                mode = Some(CliMode::RunCode(args[i].clone()));
                i += 1;
            }
            "-f" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -f requires an argument".to_string());
                }
                mode = Some(CliMode::RunFile(args[i].clone()));
                i += 1;
            }
            "-l" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -l requires an argument".to_string());
                }
                mode = Some(CliMode::Lint(args[i].clone()));
                i += 1;
            }
            "-w" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -w requires an argument".to_string());
                }
                mode = Some(CliMode::Strip(args[i].clone()));
                i += 1;
            }
            "-s" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -s requires an argument".to_string());
                }
                mode = Some(CliMode::SyntaxHighlight(args[i].clone()));
                i += 1;
            }
            "-d" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -d requires an argument".to_string());
                }
                let entry = &args[i];
                if let Some(eq_pos) = entry.find('=') {
                    ini_overrides
                        .push((entry[..eq_pos].to_string(), entry[eq_pos + 1..].to_string()));
                } else {
                    ini_overrides.push((entry.clone(), "1".to_string()));
                }
                i += 1;
            }
            "-c" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -c requires an argument".to_string());
                }
                ini_path = Some(args[i].clone());
                i += 1;
            }
            "-n" => {
                no_ini = true;
                i += 1;
            }
            "-v" | "--version" => {
                mode = Some(CliMode::Version);
                i += 1;
            }
            "-m" => {
                mode = Some(CliMode::Modules);
                i += 1;
            }
            "-i" => {
                mode = Some(CliMode::Info);
                i += 1;
            }
            "-a" => {
                mode = Some(CliMode::Interactive);
                i += 1;
            }
            "-S" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -S requires an argument (e.g., localhost:8080)".to_string());
                }
                server_listen = Some(args[i].clone());
                i += 1;
            }
            "-t" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -t requires an argument".to_string());
                }
                server_docroot = Some(args[i].clone());
                i += 1;
            }
            "-h" | "--help" | "-?" => {
                mode = Some(CliMode::Help);
                i += 1;
            }
            arg if arg.starts_with('-') => {
                return Err(format!("Unknown option: {}", arg));
            }
            _ => {
                // If -S was given, bare argument is router script
                if server_listen.is_some() && mode.is_none() {
                    mode = Some(CliMode::Server {
                        listen: String::new(), // filled below
                        docroot: None,
                        router: Some(args[i].clone()),
                    });
                    i += 1;
                } else {
                    // Bare argument = filename
                    mode = Some(CliMode::RunFile(args[i].clone()));
                    i += 1;
                    // Remaining args go to script_args
                    while i < args.len() {
                        script_args.push(args[i].clone());
                        i += 1;
                    }
                }
            }
        }
    }

    // If -S was given, build the Server mode
    if let Some(listen) = server_listen {
        let router = match &mode {
            Some(CliMode::Server { router, .. }) => router.clone(),
            _ => None,
        };
        mode = Some(CliMode::Server {
            listen,
            docroot: server_docroot,
            router: router.map(|r| r.to_string()),
        });
    }

    // Default: if no mode set and stdin is not a tty, read from stdin
    let mode = mode.unwrap_or(CliMode::Stdin);

    Ok(CliOptions {
        mode,
        ini_overrides,
        ini_path,
        no_ini,
        script_args,
    })
}

// ── Version & info ──────────────────────────────────────────────────────────

const PHP_RS_VERSION: &str = "0.1.0";
const PHP_COMPAT_VERSION: &str = "8.6.0-dev";

fn print_version() {
    println!(
        "php.rs {} (cli) — PHP {} compatible",
        PHP_RS_VERSION, PHP_COMPAT_VERSION
    );
    println!("Rust-based PHP interpreter");
    println!("Copyright (c) php.rs contributors");
}

fn print_help() {
    println!(
        "Usage: php-rs [options] [-f] <file> [--] [args...]
       php-rs [options] -r <code> [--] [args...]
       php-rs [options] -S <addr>:<port> [-t docroot] [router.php]
       php-rs [options] < script.php

Options:
  -r <code>    Run PHP <code> without using script tags <?..?>
  -f <file>    Parse and execute <file>
  -l <file>    Syntax check only (lint)
  -S <addr>    Run with built-in web server
  -t <docroot> Specify document root for built-in web server (default: cwd)
  -d key=val   Define INI entry
  -c <path>    Look for php.ini file in <path>
  -n           No php.ini file will be used
  -v           Version number
  -m           Show compiled in modules
  -i           PHP information
  -w <file>    Output source with stripped comments and whitespace
  -s <file>    Output HTML syntax highlighted source
  -a           Run interactively (REPL)
  -h, --help   This help

  args...      Arguments passed to script (available via $argv/$argc)"
    );
}

fn print_modules() {
    println!("[PHP Modules]");
    let modules = [
        "Core",
        "ctype",
        "date",
        "filter",
        "hash",
        "json",
        "mbstring",
        "pcre",
        "spl",
        "standard",
        "tokenizer",
    ];
    for m in &modules {
        println!("{}", m);
    }
    println!();
    println!("[Zend Modules]");
    println!();
}

fn print_phpinfo() {
    println!("phpinfo()");
    println!("php.rs Version => {}", PHP_RS_VERSION);
    println!("PHP Compatibility => {}", PHP_COMPAT_VERSION);
    println!();
    println!("System => {} {}", env::consts::OS, env::consts::ARCH);
    println!("Build Date => {}", env!("CARGO_PKG_VERSION"));
    println!("Server API => Command Line Interface");
    println!();
    println!("Configuration File (php.ini) Path => (none)");
    println!();
    print_modules();
}

// ── Compilation & execution ─────────────────────────────────────────────────

/// Build VM superglobal bindings from runtime Superglobals and CLI argv.
/// $_SERVER gets argc (int) and argv (array of strings) set from the given argv slice.
/// Keys use the compiler's CV names (variable name without leading $: _GET, _SERVER, etc.).
fn superglobals_for_vm(sg: &Superglobals, argv: &[String]) -> HashMap<String, Value> {
    let mut map = HashMap::new();

    // CV names match parser output (leading $ stripped): _GET, _SERVER, etc.
    map.insert(
        "_GET".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.get)),
    );
    map.insert(
        "_POST".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.post)),
    );
    map.insert(
        "_ENV".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.env)),
    );
    map.insert(
        "_COOKIE".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.cookie)),
    );
    map.insert(
        "_FILES".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.files)),
    );
    map.insert(
        "_REQUEST".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.request)),
    );
    map.insert(
        "_SESSION".to_string(),
        Value::Array(PhpArray::from_string_map(&sg.session)),
    );

    // $_SERVER: string map + argc (int) and argv (array of strings)
    let mut server = PhpArray::from_string_map(&sg.server);
    server.set_string("argc".to_string(), Value::Long(argv.len() as i64));
    let mut argv_arr = PhpArray::new();
    for arg in argv {
        argv_arr.push(Value::String(arg.clone()));
    }
    server.set_string("argv".to_string(), Value::Array(argv_arr));
    map.insert("_SERVER".to_string(), Value::Array(server));

    map
}

/// Compile and execute PHP source code, returning the exit code.
/// `script_path` is the script name (e.g. "test.php" or "-" for stdin/-r).
/// `argv` is the full argument list for this run (script path + script args), used for $_SERVER['argv'] and argc.
fn execute_php(source: &str, ini: &IniSystem, script_path: &str, argv: &[String]) -> i32 {
    let _ = ini; // Will be used when VM integrates INI

    // Compile
    let op_array = match php_rs_compiler::compile(source) {
        Ok(oa) => oa,
        Err(e) => {
            eprintln!("{}", e);
            return 255;
        }
    };

    // Build superglobals for this request
    let mut sg = Superglobals::new();
    sg.populate_env();
    sg.populate_server_cli(script_path, argv);
    sg.build_request("GP");
    let sg_map = superglobals_for_vm(&sg, argv);

    // Execute
    let mut vm = php_rs_vm::Vm::new();
    match vm.execute(&op_array, Some(&sg_map)) {
        Ok(output) => {
            print!("{}", output);
            0
        }
        Err(e) => {
            eprintln!("Fatal error: {:?}", e);
            255
        }
    }
}

/// Execute PHP and return (exit_code, stdout). Used by tests to assert on output.
fn execute_php_capture(
    source: &str,
    ini: &IniSystem,
    script_path: &str,
    argv: &[String],
) -> (i32, String) {
    let _ = ini;
    let op_array = match php_rs_compiler::compile(source) {
        Ok(oa) => oa,
        Err(e) => {
            eprintln!("{}", e);
            return (255, String::new());
        }
    };
    let mut sg = Superglobals::new();
    sg.populate_env();
    sg.populate_server_cli(script_path, argv);
    sg.build_request("GP");
    let sg_map = superglobals_for_vm(&sg, argv);
    let mut vm = php_rs_vm::Vm::new();
    match vm.execute(&op_array, Some(&sg_map)) {
        Ok(output) => (0, output),
        Err(e) => {
            eprintln!("Fatal error: {:?}", e);
            (255, String::new())
        }
    }
}

/// Lint (syntax check) PHP source code.
fn lint_php(source: &str, filename: &str) -> i32 {
    match php_rs_compiler::compile(source) {
        Ok(_) => {
            println!("No syntax errors detected in {}", filename);
            0
        }
        Err(e) => {
            eprintln!("{}", e);
            255
        }
    }
}

/// Read a file to string, handling errors.
fn read_file(path: &str) -> Result<String, i32> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(e) => {
            eprintln!("Could not open input file: {}: {}", path, e);
            Err(1)
        }
    }
}

/// Read stdin to string.
fn read_stdin() -> Result<String, i32> {
    let mut buf = String::new();
    match io::stdin().read_to_string(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) => {
            eprintln!("Failed to read from stdin: {}", e);
            Err(1)
        }
    }
}

/// Set up the INI system with defaults and CLI overrides.
fn setup_ini(opts: &CliOptions) -> IniSystem {
    let mut ini = IniSystem::new();

    // Load php.ini if applicable
    if !opts.no_ini {
        if let Some(ref path) = opts.ini_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                ini.parse_ini_string(&content);
            }
        }
        // TODO: search default paths for php.ini
    }

    // Apply -d overrides
    for (key, value) in &opts.ini_overrides {
        ini.set(key, value);
    }

    ini
}

// ── Interactive REPL ────────────────────────────────────────────────────────

fn run_interactive() -> i32 {
    println!(
        "Interactive shell — php.rs {} (PHP {} compatible)",
        PHP_RS_VERSION, PHP_COMPAT_VERSION
    );
    println!("Type PHP code (without <?php tags). Ctrl+D to exit.");
    println!();

    let stdin = io::stdin();
    let mut line = String::new();

    loop {
        eprint!("php > ");
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => {
                // EOF
                eprintln!();
                return 0;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Wrap in <?php tags for the compiler
                let source = format!("<?php {}", trimmed);
                let op_array = match php_rs_compiler::compile(&source) {
                    Ok(oa) => oa,
                    Err(e) => {
                        eprintln!("{}", e);
                        continue;
                    }
                };

                let mut vm = php_rs_vm::Vm::new();
                match vm.execute(&op_array, None) {
                    Ok(output) => {
                        if !output.is_empty() {
                            print!("{}", output);
                            // Add newline if output doesn't end with one
                            if !output.ends_with('\n') {
                                println!();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Fatal error: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                return 1;
            }
        }
    }
}

// ── Strip & highlight (simplified) ──────────────────────────────────────────

/// Strip comments and extra whitespace from PHP source.
fn strip_source(source: &str) -> String {
    // Simple approach: use the lexer to tokenize and rebuild without comments
    use php_rs_compiler::compile;
    // If it doesn't parse, return original
    if compile(source).is_err() {
        return source.to_string();
    }
    // Simple comment stripper: remove // and /* */ comments, preserve strings
    let mut result = String::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let quote = bytes[i];
                result.push(quote as char);
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        result.push(bytes[i] as char);
                        i += 1;
                    }
                    result.push(bytes[i] as char);
                    i += 1;
                }
                if i < bytes.len() {
                    result.push(bytes[i] as char);
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                // Line comment — skip to end of line
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' if i + 1 < bytes.len() && bytes[i + 1] != b'[' => {
                // # comment — skip to end of line
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                // Block comment — skip to */
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2; // skip */
                }
            }
            _ => {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    result
}

/// Simple HTML syntax highlighting for PHP source.
fn syntax_highlight(source: &str) -> String {
    let mut html = String::from("<code><span style=\"color: #000000\">\n");
    // Simplified: just HTML-escape and wrap in <code>
    for ch in source.chars() {
        match ch {
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '&' => html.push_str("&amp;"),
            '"' => html.push_str("&quot;"),
            '\n' => html.push_str("<br />\n"),
            _ => html.push(ch),
        }
    }
    html.push_str("</span>\n</code>");
    html
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("php-rs: {}", e);
            eprintln!("Try 'php-rs --help' for usage information.");
            process::exit(1);
        }
    };

    let ini = setup_ini(&opts);

    let exit_code = match opts.mode {
        CliMode::Version => {
            print_version();
            0
        }
        CliMode::Help => {
            print_help();
            0
        }
        CliMode::Modules => {
            print_modules();
            0
        }
        CliMode::Info => {
            print_phpinfo();
            0
        }
        CliMode::Interactive => run_interactive(),
        CliMode::Server {
            listen,
            docroot,
            router,
        } => {
            let docroot = docroot
                .map(PathBuf::from)
                .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let router = router.map(PathBuf::from);
            server::run_server(server::ServerConfig {
                listen,
                docroot,
                router,
            })
        }
        CliMode::RunCode(code) => {
            // -r wraps in <?php automatically
            let source = format!("<?php {}", code);
            let argv: Vec<String> = std::iter::once("-".to_string())
                .chain(opts.script_args.clone())
                .collect();
            execute_php(&source, &ini, "-", &argv)
        }
        CliMode::RunFile(path) => match read_file(&path) {
            Ok(source) => {
                let argv: Vec<String> = std::iter::once(path.clone())
                    .chain(opts.script_args.clone())
                    .collect();
                execute_php(&source, &ini, &path, &argv)
            }
            Err(code) => code,
        },
        CliMode::Lint(path) => match read_file(&path) {
            Ok(source) => lint_php(&source, &path),
            Err(code) => code,
        },
        CliMode::Strip(path) => match read_file(&path) {
            Ok(source) => {
                print!("{}", strip_source(&source));
                0
            }
            Err(code) => code,
        },
        CliMode::SyntaxHighlight(path) => match read_file(&path) {
            Ok(source) => {
                print!("{}", syntax_highlight(&source));
                0
            }
            Err(code) => code,
        },
        CliMode::Stdin => match read_stdin() {
            Ok(source) => execute_php(&source, &ini, "-", &["-".to_string()]),
            Err(code) => code,
        },
    };

    process::exit(exit_code);
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Argument parsing tests ──

    #[test]
    fn test_parse_version() {
        let args = vec!["php-rs".into(), "-v".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Version));
    }

    #[test]
    fn test_parse_help() {
        let args = vec!["php-rs".into(), "--help".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Help));
    }

    #[test]
    fn test_parse_run_code() {
        let args = vec!["php-rs".into(), "-r".into(), "echo 42;".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::RunCode(ref s) if s == "echo 42;"));
    }

    #[test]
    fn test_parse_run_file() {
        let args = vec!["php-rs".into(), "test.php".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::RunFile(ref s) if s == "test.php"));
    }

    #[test]
    fn test_parse_run_file_with_f_flag() {
        let args = vec!["php-rs".into(), "-f".into(), "test.php".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::RunFile(ref s) if s == "test.php"));
    }

    #[test]
    fn test_parse_lint() {
        let args = vec!["php-rs".into(), "-l".into(), "test.php".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Lint(ref s) if s == "test.php"));
    }

    #[test]
    fn test_parse_ini_override() {
        let args = vec![
            "php-rs".into(),
            "-d".into(),
            "error_reporting=E_ALL".into(),
            "-r".into(),
            "echo 1;".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.ini_overrides.len(), 1);
        assert_eq!(opts.ini_overrides[0].0, "error_reporting");
        assert_eq!(opts.ini_overrides[0].1, "E_ALL");
    }

    #[test]
    fn test_parse_ini_override_no_value() {
        let args = vec![
            "php-rs".into(),
            "-d".into(),
            "display_errors".into(),
            "-v".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.ini_overrides[0].1, "1");
    }

    #[test]
    fn test_parse_no_ini() {
        let args = vec!["php-rs".into(), "-n".into(), "-v".into()];
        let opts = parse_args(&args).unwrap();
        assert!(opts.no_ini);
    }

    #[test]
    fn test_parse_config_path() {
        let args = vec![
            "php-rs".into(),
            "-c".into(),
            "/etc/php.ini".into(),
            "-v".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.ini_path.as_deref(), Some("/etc/php.ini"));
    }

    #[test]
    fn test_parse_modules() {
        let args = vec!["php-rs".into(), "-m".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Modules));
    }

    #[test]
    fn test_parse_script_args() {
        let args = vec![
            "php-rs".into(),
            "test.php".into(),
            "arg1".into(),
            "arg2".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::RunFile(ref s) if s == "test.php"));
        assert_eq!(opts.script_args, vec!["arg1", "arg2"]);
    }

    #[test]
    fn test_parse_separator() {
        let args = vec![
            "php-rs".into(),
            "-r".into(),
            "echo 1;".into(),
            "--".into(),
            "extra".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.script_args, vec!["extra"]);
    }

    #[test]
    fn test_parse_unknown_option() {
        let args = vec!["php-rs".into(), "-z".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn test_parse_missing_argument() {
        let args = vec!["php-rs".into(), "-r".into()];
        assert!(parse_args(&args).is_err());
    }

    // ── End-to-end execution tests ──

    fn default_argv() -> Vec<String> {
        vec!["-".to_string()]
    }

    #[test]
    fn test_execute_hello_world() {
        let code = execute_php(
            "<?php echo \"Hello, World!\n\";",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_echo_number() {
        let code = execute_php("<?php echo 42;", &IniSystem::new(), "-", &default_argv());
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_variable_assignment() {
        let code = execute_php(
            "<?php $x = 10; echo $x;",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_arithmetic() {
        let code = execute_php(
            "<?php echo 2 + 3 * 4;",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_string_concat() {
        let code = execute_php(
            "<?php echo \"Hello\" . \" \" . \"World\";",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_if_else() {
        let code = execute_php(
            "<?php $x = 5; if ($x > 3) { echo \"yes\"; } else { echo \"no\"; }",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_while_loop() {
        let code = execute_php(
            "<?php $i = 0; while ($i < 5) { echo $i; $i = $i + 1; }",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_function() {
        let code = execute_php(
            "<?php function add($a, $b) { return $a + $b; } echo add(3, 4);",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn test_execute_parse_error() {
        let code = execute_php("<?php echo (;", &IniSystem::new(), "-", &default_argv());
        assert_eq!(code, 255);
    }

    #[test]
    fn test_execute_r_flag_wrapping() {
        // -r wraps in <?php, so code shouldn't include it
        let source = format!("<?php {}", "echo 42;");
        let code = execute_php(&source, &IniSystem::new(), "-", &default_argv());
        assert_eq!(code, 0);
    }

    // ── Superglobal tests ──

    #[test]
    fn test_superglobal_server_argc_argv() {
        // argv = ["-", "a", "b"] => argc = 3, argv[0] = "-", argv[1] = "a", argv[2] = "b"
        let argv = vec!["-".to_string(), "a".to_string(), "b".to_string()];
        let (code, out) = execute_php_capture(
            "<?php echo $_SERVER['argc'];",
            &IniSystem::new(),
            "-",
            &argv,
        );
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "3");
    }

    #[test]
    fn test_superglobal_server_argv_array() {
        let argv = vec![
            "script.php".to_string(),
            "one".to_string(),
            "two".to_string(),
        ];
        let (code, out) = execute_php_capture(
            "<?php $a = $_SERVER['argv']; echo $a[0].','.$a[1].','.$a[2];",
            &IniSystem::new(),
            "script.php",
            &argv,
        );
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "script.php,one,two");
    }

    #[test]
    fn test_superglobal_server_script_filename() {
        let argv = vec!["/path/to/script.php".to_string()];
        let (code, out) = execute_php_capture(
            "<?php echo $_SERVER['SCRIPT_FILENAME'];",
            &IniSystem::new(),
            "/path/to/script.php",
            &argv,
        );
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "/path/to/script.php");
    }

    #[test]
    fn test_superglobal_get_empty_then_assign() {
        // $_GET is pre-filled (empty for CLI); script can read and assign
        let (code, out) = execute_php_capture(
            "<?php $_GET['x'] = 'y'; echo $_GET['x'];",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "y");
    }

    #[test]
    fn test_superglobal_env_available() {
        // $_ENV is populated from process environment
        std::env::set_var("PHP_RS_SUPERGLOBAL_TEST", "env_ok");
        let (code, out) = execute_php_capture(
            "<?php echo isset($_ENV['PHP_RS_SUPERGLOBAL_TEST']) ? $_ENV['PHP_RS_SUPERGLOBAL_TEST'] : 'missing';",
            &IniSystem::new(),
            "-",
            &default_argv(),
        );
        std::env::remove_var("PHP_RS_SUPERGLOBAL_TEST");
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "env_ok");
    }

    #[test]
    fn test_lint_valid() {
        let code = lint_php("<?php echo 42;", "test.php");
        assert_eq!(code, 0);
    }

    #[test]
    fn test_lint_invalid() {
        let code = lint_php("<?php echo (;", "test.php");
        assert_eq!(code, 255);
    }

    #[test]
    fn test_strip_source() {
        let source = "<?php\n// comment\necho 42; /* block */\n";
        let stripped = strip_source(source);
        assert!(!stripped.contains("// comment"));
        assert!(!stripped.contains("/* block */"));
        assert!(stripped.contains("echo 42;"));
    }

    #[test]
    fn test_strip_preserves_strings() {
        let source = "<?php echo \"// not a comment\";";
        let stripped = strip_source(source);
        assert!(stripped.contains("// not a comment"));
    }

    #[test]
    fn test_syntax_highlight_produces_html() {
        let source = "<?php echo 42;";
        let html = syntax_highlight(source);
        assert!(html.contains("<code>"));
        assert!(html.contains("</code>"));
        assert!(html.contains("echo 42;"));
    }

    #[test]
    fn test_stdin_default_mode() {
        let args = vec!["php-rs".into()];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Stdin));
    }

    // ── Server argument parsing tests ──

    #[test]
    fn test_parse_server() {
        let args = vec!["php-rs".into(), "-S".into(), "localhost:8080".into()];
        let opts = parse_args(&args).unwrap();
        assert!(
            matches!(opts.mode, CliMode::Server { ref listen, ref docroot, ref router }
                if listen == "localhost:8080" && docroot.is_none() && router.is_none())
        );
    }

    #[test]
    fn test_parse_server_with_docroot() {
        let args = vec![
            "php-rs".into(),
            "-S".into(),
            "0.0.0.0:9000".into(),
            "-t".into(),
            "/var/www".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(
            matches!(opts.mode, CliMode::Server { ref listen, ref docroot, .. }
                if listen == "0.0.0.0:9000" && docroot.as_deref() == Some("/var/www"))
        );
    }

    #[test]
    fn test_parse_server_with_router() {
        let args = vec![
            "php-rs".into(),
            "-S".into(),
            "localhost:8080".into(),
            "router.php".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(matches!(opts.mode, CliMode::Server { ref router, .. }
                if router.as_deref() == Some("router.php")));
    }

    #[test]
    fn test_parse_server_with_docroot_and_router() {
        let args = vec![
            "php-rs".into(),
            "-S".into(),
            "localhost:8080".into(),
            "-t".into(),
            "/srv/www".into(),
            "router.php".into(),
        ];
        let opts = parse_args(&args).unwrap();
        assert!(
            matches!(opts.mode, CliMode::Server { ref listen, ref docroot, ref router }
                if listen == "localhost:8080"
                && docroot.as_deref() == Some("/srv/www")
                && router.as_deref() == Some("router.php"))
        );
    }

    #[test]
    fn test_parse_server_missing_addr() {
        let args = vec!["php-rs".into(), "-S".into()];
        assert!(parse_args(&args).is_err());
    }
}
