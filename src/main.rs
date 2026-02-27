use clap::{Parser, Subcommand};
use modules::scanner::{DiffMode, OutputFormat, ScanOpts};

mod modules;
mod utils;

#[derive(Parser)]
#[command(name = "oxide-ci")]
#[command(about = "A high-performance DevOps CLI tool in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scans the current directory for hardcoded secrets and PII
    Scan {
        /// Output format: text (default), json, sarif
        #[arg(long, default_value = "text")]
        format: String,
        /// Only scan git-staged files (git diff --cached)
        #[arg(long)]
        staged: bool,
        /// Only scan files changed since the given commit (e.g. --since HEAD~1)
        #[arg(long)]
        since: Option<String>,
    },
    /// Validates Kubernetes YAML manifests for resource limits and security issues
    Lint {
        /// Directory to scan for Kubernetes manifests (overrides config)
        #[arg(short, long)]
        dir: Option<String>,
    },
    /// Parses an LCOV coverage file and fails if total coverage is below threshold
    Coverage {
        /// Path to the LCOV file (overrides config)
        #[arg(short, long)]
        file: Option<String>,
        /// Minimum coverage threshold percentage (overrides config)
        #[arg(short, long)]
        min: Option<f64>,
    },
    /// Installs oxide-ci as a git pre-commit hook
    InstallHooks {
        /// Overwrite an existing hook without prompting
        #[arg(long)]
        force: bool,
    },
    /// Audits project dependencies for known vulnerabilities via the OSV database
    Audit,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = utils::config::load();

    match cli.command {
        Commands::Scan {
            format,
            staged,
            since,
        } => {
            let output_format = match format.as_str() {
                "json" => OutputFormat::Json,
                "sarif" => OutputFormat::Sarif,
                _ => OutputFormat::Text,
            };
            let diff = if staged {
                Some(DiffMode::Staged)
            } else {
                since.map(DiffMode::Since)
            };
            modules::scanner::run_scan(ScanOpts {
                format: output_format,
                diff,
                config: &cfg.scan,
            })?;
        }
        Commands::Lint { dir } => {
            let target = dir.unwrap_or(cfg.lint.target_dir);
            modules::k8s_lint::run_lint(&target)?;
        }
        Commands::Coverage { file, min } => {
            let lcov_file = file.unwrap_or(cfg.coverage.file);
            let threshold = min.unwrap_or(cfg.coverage.min);
            modules::coverage::run_coverage(&lcov_file, threshold)?;
        }
        Commands::InstallHooks { force } => {
            modules::hooks::run_install_hooks(force)?;
        }
        Commands::Audit => {
            modules::audit::run_audit()?;
        }
    }

    Ok(())
}
