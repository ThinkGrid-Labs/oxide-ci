use clap::{Parser, Subcommand};
use modules::scanner::{DiffMode, OutputFormat, ScanOpts};

mod modules;
mod utils;

#[derive(Parser)]
#[command(name = "greengate")]
#[command(about = "A high-performance DevOps CLI tool in Rust", long_about = None)]
struct Cli {
    /// Apply a preset quality profile: strict, relaxed, or ci
    #[arg(long, global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scans the current directory for hardcoded secrets and PII
    Scan {
        /// Output format: text (default), json, sarif, junit, gitlab
        #[arg(long, default_value = "text")]
        format: String,
        /// Only scan git-staged files (git diff --cached)
        #[arg(long)]
        staged: bool,
        /// Only scan files changed since the given commit (e.g. --since HEAD~1)
        #[arg(long)]
        since: Option<String>,
        /// Scan the entire git commit history for secrets (slow on large repos).
        #[arg(long)]
        history: bool,
        /// Post findings as a GitHub Check Run with per-line annotations and a PR review
        /// comment. Requires GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA env vars.
        /// No-op when env vars are absent.
        #[arg(long)]
        annotate: bool,
        /// Save current findings as the baseline (writes .greengate-baseline.json)
        #[arg(long)]
        update_baseline: bool,
        /// Only fail on findings not present in the saved baseline
        #[arg(long)]
        since_baseline: bool,
        /// Enrich each finding with git blame info (author + commit)
        #[arg(long)]
        blame: bool,
    },
    /// Validates Kubernetes YAML manifests for resource limits and security issues
    Lint {
        /// Directory to scan for Kubernetes manifests (overrides config)
        #[arg(short, long)]
        dir: Option<String>,
    },
    /// Lints a Dockerfile for best-practice violations
    DockerLint {
        /// Path to the Dockerfile (overrides config)
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Parses an LCOV or Cobertura XML coverage file and fails if below threshold
    Coverage {
        /// Path to the coverage file (overrides config)
        #[arg(short, long)]
        file: Option<String>,
        /// Minimum coverage threshold percentage (overrides config)
        #[arg(short, long)]
        min: Option<f64>,
    },
    /// Installs greengate as a git pre-commit hook
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
    /// Interactive wizard that generates a .greengate.toml config file
    Init {
        /// Overwrite an existing .greengate.toml without prompting
        #[arg(long)]
        force: bool,
    },
    /// Re-runs scan automatically whenever source files change
    Watch {
        /// Only scan git-staged files on each change
        #[arg(long)]
        staged: bool,
        /// Poll interval in milliseconds (default: 2000)
        #[arg(long, default_value = "2000")]
        interval: u64,
    },
    /// Runs all pipeline steps defined in .greengate.toml in order
    Run,
    /// Validates .greengate.toml and prints all resolved configuration values
    CheckConfig,
    /// Generates a CycloneDX 1.5 SBOM from the project's lock file
    Sbom {
        /// Write SBOM to a file instead of stdout
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cfg = utils::config::load();

    // Apply profile overrides on top of the loaded config
    if let Some(ref profile) = cli.profile {
        utils::config::apply_profile(&mut cfg, profile);
    }

    match cli.command {
        Commands::Scan {
            format,
            staged,
            since,
            history,
            annotate,
            update_baseline,
            since_baseline,
            blame,
        } => {
            let output_format = match format.as_str() {
                "json" => OutputFormat::Json,
                "sarif" => OutputFormat::Sarif,
                "junit" => OutputFormat::Junit,
                "gitlab" => OutputFormat::Gitlab,
                _ => OutputFormat::Text,
            };
            let diff = if history {
                Some(DiffMode::History)
            } else if staged {
                Some(DiffMode::Staged)
            } else {
                since.map(DiffMode::Since)
            };

            let opts = ScanOpts {
                format: output_format.clone(),
                diff,
                config: &cfg.scan,
                sast_config: &cfg.sast,
            };
            let mut findings = modules::scanner::collect_findings(&opts)?;

            // Enrich with git blame if requested
            if blame {
                modules::scanner::enrich_with_blame(&mut findings);
            }

            // Baseline: save mode
            if update_baseline {
                modules::baseline::save_baseline(&findings)?;
                return modules::scanner::emit_findings(&findings, &output_format);
            }

            // Baseline: compare mode — only fail on new findings
            if since_baseline {
                let baseline = modules::baseline::load_baseline()?;
                let new_findings: Vec<&modules::scanner::Finding> =
                    modules::baseline::filter_new_findings(&findings, &baseline);
                let suppressed = findings.len() - new_findings.len();
                modules::baseline::print_baseline_summary(
                    findings.len(),
                    new_findings.len(),
                    suppressed,
                );
                if !new_findings.is_empty() {
                    let owned: Vec<modules::scanner::Finding> = new_findings
                        .into_iter()
                        .map(|f| modules::scanner::Finding {
                            path: f.path.clone(),
                            rule_id: f.rule_id.clone(),
                            line: f.line,
                            commit: f.commit.clone(),
                            severity: f.severity.clone(),
                            blame: f.blame.clone(),
                        })
                        .collect();
                    return modules::scanner::emit_findings(&owned, &output_format);
                }
                return Ok(());
            }

            // Normal scan path
            if annotate
                && let Some(env) = modules::github::detect_github_env()
                && let Err(e) = modules::github::annotate(&findings, &env)
            {
                eprintln!("greengate: warning: GitHub annotation failed: {}", e);
            }
            modules::scanner::emit_findings(&findings, &output_format)?;
        }
        Commands::Lint { dir } => {
            let target = dir.unwrap_or(cfg.lint.target_dir);
            modules::k8s_lint::run_lint(&target)?;
        }
        Commands::DockerLint { file } => {
            let dockerfile = file.unwrap_or(cfg.docker.dockerfile);
            modules::docker_lint::run_docker_lint(&dockerfile)?;
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
                    "No URL specified. Pass --url <URL> or set [lighthouse] url in .greengate.toml"
                )
            })?;

            modules::perf_lighthouse::run_lighthouse(LighthouseOpts {
                url: &resolved_url,
                strategy: &strategy.unwrap_or(cfg.lighthouse.strategy),
                thresholds: LighthouseThresholds {
                    performance: min_performance.unwrap_or(cfg.lighthouse.min_performance),
                    accessibility: min_accessibility.unwrap_or(cfg.lighthouse.min_accessibility),
                    best_practices: min_best_practices
                        .unwrap_or(cfg.lighthouse.min_best_practices),
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
        Commands::Init { force } => {
            modules::init::run_init(force)?;
        }
        Commands::Watch { staged, interval } => {
            modules::watch::run_watch(modules::watch::WatchOpts {
                staged,
                interval_ms: interval,
            })?;
        }
        Commands::Run => {
            modules::pipeline::run_pipeline(&cfg)?;
        }
        Commands::CheckConfig => {
            modules::check_config::run_check_config()?;
        }
        Commands::Sbom { output } => {
            modules::sbom::run_sbom(output.as_deref())?;
        }
    }

    Ok(())
}
