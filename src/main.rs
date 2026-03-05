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
        /// Scan the entire git commit history for secrets (slow on large repos).
        /// Use `# oxide-ci: ignore` on individual lines to suppress false positives.
        #[arg(long)]
        history: bool,
        /// Post findings as a GitHub Check Run with per-line annotations and a PR review
        /// comment. Requires GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA env vars.
        /// No-op when env vars are absent.
        #[arg(long)]
        annotate: bool,
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
    /// Audits web performance via Google PageSpeed Insights (Lighthouse)
    Lighthouse {
        /// URL to audit (overrides config)
        #[arg(long)]
        url: Option<String>,
        /// Device strategy: mobile (default) or desktop (overrides config)
        #[arg(long)]
        strategy: Option<String>,
        /// Minimum Performance score 0–100 (overrides config)
        #[arg(long)]
        min_performance: Option<u8>,
        /// Minimum Accessibility score 0–100 (overrides config)
        #[arg(long)]
        min_accessibility: Option<u8>,
        /// Minimum Best Practices score 0–100 (overrides config)
        #[arg(long)]
        min_best_practices: Option<u8>,
        /// Minimum SEO score 0–100 (overrides config)
        #[arg(long)]
        min_seo: Option<u8>,
        /// Google PageSpeed Insights API key (overrides config and PAGESPEED_API_KEY env var)
        #[arg(long)]
        key: Option<String>,
    },
    /// Parses a Reassure performance report and gates on regressions
    Reassure {
        /// Path to current.perf file (overrides config)
        #[arg(long)]
        current: Option<String>,
        /// Path to baseline.perf file (overrides config; absence triggers report-only mode)
        #[arg(long)]
        baseline: Option<String>,
        /// Percentage mean-time increase allowed before failure (overrides config)
        #[arg(long)]
        threshold: Option<f64>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = utils::config::load();

    match cli.command {
        Commands::Scan {
            format,
            staged,
            since,
            history,
            annotate,
        } => {
            let output_format = match format.as_str() {
                "json" => OutputFormat::Json,
                "sarif" => OutputFormat::Sarif,
                _ => OutputFormat::Text,
            };
            let diff = if history {
                Some(DiffMode::History)
            } else if staged {
                Some(DiffMode::Staged)
            } else {
                since.map(DiffMode::Since)
            };
            if annotate && let Some(env) = modules::github::detect_github_env() {
                let opts = ScanOpts {
                    format: output_format.clone(),
                    diff,
                    config: &cfg.scan,
                    sast_config: &cfg.sast,
                };
                let findings = modules::scanner::collect_findings(&opts)?;
                if let Err(e) = modules::github::annotate(&findings, &env) {
                    eprintln!("oxide-ci: warning: GitHub annotation failed: {}", e);
                }
                return modules::scanner::emit_findings(&findings, &output_format);
            }
            modules::scanner::run_scan(ScanOpts {
                format: output_format,
                diff,
                config: &cfg.scan,
                sast_config: &cfg.sast,
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
        Commands::Lighthouse {
            url,
            strategy,
            min_performance,
            min_accessibility,
            min_best_practices,
            min_seo,
            key,
        } => {
            use modules::perf_lighthouse::{LighthouseOpts, LighthouseThresholds};

            let resolved_url = url.or_else(|| cfg.lighthouse.url.clone()).ok_or_else(|| {
                anyhow::anyhow!(
                    "No URL specified. Pass --url <URL> or set [lighthouse] url in .oxideci.toml"
                )
            })?;

            modules::perf_lighthouse::run_lighthouse(LighthouseOpts {
                url: &resolved_url,
                strategy: &strategy.unwrap_or(cfg.lighthouse.strategy),
                thresholds: LighthouseThresholds {
                    performance: min_performance.unwrap_or(cfg.lighthouse.min_performance),
                    accessibility: min_accessibility.unwrap_or(cfg.lighthouse.min_accessibility),
                    best_practices: min_best_practices.unwrap_or(cfg.lighthouse.min_best_practices),
                    seo: min_seo.unwrap_or(cfg.lighthouse.min_seo),
                },
                api_key: key.or(cfg.lighthouse.api_key),
            })?;
        }
        Commands::Reassure {
            current,
            baseline,
            threshold,
        } => {
            use modules::reassure::ReassureOpts;

            let current_path = current.unwrap_or(cfg.reassure.current);
            let baseline_path = baseline.unwrap_or(cfg.reassure.baseline);
            let resolved_threshold = threshold.unwrap_or(cfg.reassure.threshold);

            // Only pass baseline if the file actually exists or was explicitly specified
            let baseline_opt = if std::path::Path::new(&baseline_path).exists() {
                Some(baseline_path.as_str())
            } else {
                None
            };

            modules::reassure::run_reassure(ReassureOpts {
                current: &current_path,
                baseline: baseline_opt,
                threshold: resolved_threshold,
            })?;
        }
    }

    Ok(())
}
