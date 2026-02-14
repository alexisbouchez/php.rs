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
}

/// Run the Composer CLI from raw command-line arguments.
/// Accepts the arguments after "composer" (e.g., ["install", "--verbose"]).
pub fn run(args: Vec<String>) -> Result<(), String> {
    // Prepend "composer" so clap sees a proper argv[0]
    let mut full_args = vec!["composer".to_string()];
    full_args.extend(args);

    let cli = Cli::try_parse_from(full_args).map_err(|e| e.to_string())?;
    run_cli(cli)
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
    }
}
