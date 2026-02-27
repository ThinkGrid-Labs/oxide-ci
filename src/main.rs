use clap::{Parser, Subcommand};

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
    /// Scans the current directory for hardcoded secrets
    Scan,
    /// Validates if Kubernetes YAML files in a directory have resource limits defined
    Lint,
    /// Parses an LCOV file and exits with code 1 if total coverage is below a user-provided threshold
    Coverage {
        /// The path to the LCOV file
        #[arg(short, long, default_value = "coverage/lcov.info")]
        file: String,
        /// The minimum coverage threshold percentage
        #[arg(short, long, default_value_t = 80.0)]
        min: f64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan => {
            modules::scanner::run_scan()?;
        }
        Commands::Lint => {
            modules::k8s_lint::run_lint()?;
        }
        Commands::Coverage { file, min } => {
            modules::coverage::run_coverage(file, *min)?;
        }
    }

    Ok(())
}
