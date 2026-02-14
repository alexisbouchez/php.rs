use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser, Debug)]
#[command(
    name = "composer",
    about = "Composer - PHP Dependency Manager (php-rs)"
)]
pub struct Cli {
    /// Set the working directory
    #[arg(short = 'd', long = "working-dir", global = true)]
    pub working_dir: Option<PathBuf>,

    /// Increase verbosity
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable ANSI colors
    #[arg(long = "no-ansi", global = true)]
    pub no_ansi: bool,

    #[command(subcommand)]
    pub command: ComposerCommand,
}

#[derive(Subcommand, Debug)]
pub enum ComposerCommand {
    /// Install project dependencies from composer.lock or composer.json
    Install,

    /// Update dependencies to their latest versions
    Update {
        /// Packages to update (all if empty)
        packages: Vec<String>,
    },

    /// Add a package to require and install it
    Require {
        /// Package(s) to require (e.g., "vendor/package:^1.0")
        packages: Vec<String>,

        /// Add to require-dev instead of require
        #[arg(long)]
        dev: bool,
    },

    /// Remove a package from require and uninstall it
    Remove {
        /// Package(s) to remove
        packages: Vec<String>,

        /// Remove from require-dev instead of require
        #[arg(long)]
        dev: bool,
    },

    /// Regenerate autoload files
    #[command(name = "dump-autoload", alias = "dumpautoload")]
    DumpAutoload,

    /// Show information about installed packages
    Show {
        /// Specific package to show details for
        package: Option<String>,
    },

    /// Validate composer.json
    Validate,

    /// Create a new composer.json in the current directory
    Init {
        /// Package name
        #[arg(long)]
        name: Option<String>,

        /// Package description
        #[arg(long)]
        description: Option<String>,
    },

    /// Create a new project from a package
    CreateProject {
        /// Package to create project from
        package: String,

        /// Directory to create project in
        directory: Option<String>,

        /// Version constraint
        #[arg(long)]
        version: Option<String>,
    },

    /// Search for packages on Packagist
    Search {
        /// Search query
        query: Vec<String>,
    },

    /// Run a script defined in composer.json
    #[command(name = "run-script", alias = "run")]
    RunScript {
        /// Script name to run (omit to list all scripts)
        script: Option<String>,

        /// Additional arguments passed to the script
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Run the Composer CLI from raw command-line arguments.
/// Accepts the arguments after "composer" (e.g., ["install", "--verbose"]).
pub fn run(args: Vec<String>) -> Result<(), String> {
    // Prepend "composer" so clap sees a proper argv[0]
    let mut full_args = vec!["composer".to_string()];
    full_args.extend(args.clone());

    match Cli::try_parse_from(full_args) {
        Ok(cli) => run_cli(cli),
        Err(e) => {
            // If clap doesn't recognize the subcommand, try running it as a script.
            // Real Composer allows `composer dev` as shorthand for `composer run-script dev`.
            if !args.is_empty() && !args[0].starts_with('-') {
                let script_name = &args[0];
                // Extract global flags that appear before the script name
                let working_dir = args
                    .iter()
                    .position(|a| a == "-d" || a == "--working-dir")
                    .and_then(|i| args.get(i + 1))
                    .map(|d| std::path::PathBuf::from(d));
                let dir = working_dir.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
                });
                let config = Config::new(&dir);

                // Check if this script actually exists in composer.json before trying
                if script_exists(&config, script_name) {
                    let extra_args: Vec<String> = args[1..]
                        .iter()
                        .filter(|a| {
                            *a != "-d" && *a != "--working-dir" && *a != "-v" && *a != "--verbose"
                        })
                        .cloned()
                        .collect();
                    return crate::commands::run_script::execute(&config, script_name, &extra_args);
                }
            }
            Err(e.to_string())
        }
    }
}

/// Check if a script name exists in composer.json.
fn script_exists(config: &Config, name: &str) -> bool {
    let json_path = config.composer_json_path();
    let json_file = crate::json::JsonFile::new(&json_path);
    let Ok(root) = json_file.read() else {
        return false;
    };
    root.get("scripts").and_then(|s| s.get(name)).is_some()
}

/// Run the Composer CLI from a parsed Cli struct.
pub fn run_cli(args: Cli) -> Result<(), String> {
    let working_dir = args
        .working_dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let config = Config::new(&working_dir);

    match args.command {
        ComposerCommand::Install => crate::commands::install::execute(&config),
        ComposerCommand::Update { packages } => {
            crate::commands::update::execute(&config, &packages)
        }
        ComposerCommand::Require { packages, dev } => {
            crate::commands::require::execute(&config, &packages, dev)
        }
        ComposerCommand::Remove { packages, dev } => {
            crate::commands::remove::execute(&config, &packages, dev)
        }
        ComposerCommand::DumpAutoload => crate::commands::dump_autoload::execute(&config),
        ComposerCommand::Show { package } => {
            crate::commands::show::execute(&config, package.as_deref())
        }
        ComposerCommand::Validate => crate::commands::validate::execute(&config),
        ComposerCommand::Init { name, description } => {
            crate::commands::init::execute(&config, name.as_deref(), description.as_deref())
        }
        ComposerCommand::CreateProject {
            package,
            directory,
            version,
        } => crate::commands::create_project::execute(
            &config,
            &package,
            directory.as_deref(),
            version.as_deref(),
        ),
        ComposerCommand::Search { query } => {
            let q = query.join(" ");
            crate::commands::search::execute(&config, &q)
        }
        ComposerCommand::RunScript { script, args } => match script {
            Some(name) => crate::commands::run_script::execute(&config, &name, &args),
            None => crate::commands::run_script::list_scripts(&config),
        },
    }
}
