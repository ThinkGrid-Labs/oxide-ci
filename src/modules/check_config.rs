use crate::utils::{config::Config, terminal};
use anyhow::Result;

/// Validate and display the resolved `.oxideci.toml` configuration.
///
/// - Exits with an error if the file exists but cannot be parsed.
/// - Prints all resolved values so users can verify overrides are applied correctly.
pub fn run_check_config() -> Result<()> {
    let path = std::path::Path::new(".oxideci.toml");

    if !path.exists() {
        terminal::warn("No .oxideci.toml found — all commands will use built-in defaults.");
        terminal::info("Run `oxide-ci init` to generate a config file.");
        print_defaults();
        return Ok(());
    }

    let content = std::fs::read_to_string(path)?;

    // Parse and report any TOML/serde errors with a clear message.
    let cfg: Config = toml::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            ".oxideci.toml is invalid:\n\n  {}\n\nRun `oxide-ci init --force` to regenerate it.",
            e
        )
    })?;

    terminal::success(".oxideci.toml is valid.");
    eprintln!();
    eprintln!("Resolved configuration:");
    eprintln!();

    // ── Scan ──────────────────────────────────────────────────────────────────
    eprintln!("[scan]");
    eprintln!("  entropy             = {}", cfg.scan.entropy);
    eprintln!("  entropy_threshold   = {}", cfg.scan.entropy_threshold);
    eprintln!("  entropy_min_length  = {}", cfg.scan.entropy_min_length);
    eprintln!(
        "  extra_patterns      = {} custom pattern(s)",
        cfg.scan.extra_patterns.len()
    );
    for p in &cfg.scan.extra_patterns {
        eprintln!("    • {} = {}", p.name, p.regex);
    }
    eprintln!(
        "  exclude_patterns    = {} pattern(s)",
        cfg.scan.exclude_patterns.len()
    );
    for pat in &cfg.scan.exclude_patterns {
        eprintln!("    • {}", pat);
    }

    // ── SAST ──────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[sast]");
    eprintln!("  enabled             = {}", cfg.sast.enabled);
    eprintln!("  max_function_lines  = {}", cfg.sast.max_function_lines);
    eprintln!("  max_parameters      = {}", cfg.sast.max_parameters);
    eprintln!("  max_nesting_depth   = {}", cfg.sast.max_nesting_depth);
    eprintln!(
        "  disabled_rules      = {} rule(s)",
        cfg.sast.disabled_rules.len()
    );
    for r in &cfg.sast.disabled_rules {
        eprintln!("    • {}", r);
    }
    eprintln!(
        "  custom_rules        = {} rule(s)",
        cfg.sast.custom_rules.len()
    );
    for r in &cfg.sast.custom_rules {
        eprintln!("    • {}", r.id);
    }

    // ── Coverage ──────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[coverage]");
    eprintln!("  file                = {}", cfg.coverage.file);
    eprintln!("  min                 = {}%", cfg.coverage.min);

    // ── Lint ──────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[lint]");
    eprintln!("  target_dir          = {}", cfg.lint.target_dir);

    // ── Docker ────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[docker]");
    eprintln!("  dockerfile          = {}", cfg.docker.dockerfile);

    // ── Lighthouse ────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[lighthouse]");
    eprintln!(
        "  url                 = {}",
        cfg.lighthouse.url.as_deref().unwrap_or("(not set)")
    );
    eprintln!("  strategy            = {}", cfg.lighthouse.strategy);
    eprintln!("  min_performance     = {}", cfg.lighthouse.min_performance);
    eprintln!(
        "  min_accessibility   = {}",
        cfg.lighthouse.min_accessibility
    );
    eprintln!(
        "  min_best_practices  = {}",
        cfg.lighthouse.min_best_practices
    );
    eprintln!("  min_seo             = {}", cfg.lighthouse.min_seo);

    // ── Reassure ──────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[reassure]");
    eprintln!("  current             = {}", cfg.reassure.current);
    eprintln!("  baseline            = {}", cfg.reassure.baseline);
    eprintln!("  threshold           = {}%", cfg.reassure.threshold);

    // ── Pipeline ──────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("[pipeline]");
    eprintln!(
        "  steps               = {} step(s)",
        cfg.pipeline.steps.len()
    );
    for s in &cfg.pipeline.steps {
        eprintln!("    • {}", s);
    }

    eprintln!();
    terminal::success("Config check passed.");
    Ok(())
}

fn print_defaults() {
    eprintln!();
    eprintln!("Default values that will be used:");
    eprintln!("  [scan]     entropy=true, threshold=4.5, min_length=20");
    eprintln!(
        "  [sast]     enabled=true, max_function_lines=50, max_parameters=5, max_nesting_depth=4"
    );
    eprintln!("  [coverage] file=coverage/lcov.info, min=80%");
    eprintln!("  [lint]     target_dir=.");
    eprintln!("  [docker]   dockerfile=Dockerfile");
    eprintln!("  [lighthouse] strategy=mobile, min_performance=80, min_accessibility=90");
    eprintln!("  [reassure] threshold=15%");
}
