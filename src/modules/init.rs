/// `greengate init` — interactive wizard that generates `.greengate.toml`.
///
/// Asks a few questions about the project and writes a tailored config file.
/// Aborts cleanly if the file already exists (unless --force is passed).
use anyhow::Result;
use std::io::{self, BufRead, Write};

pub fn run_init(force: bool) -> Result<()> {
    let config_path = std::path::Path::new(".greengate.toml");

    if config_path.exists() && !force {
        anyhow::bail!(
            ".greengate.toml already exists. Run `greengate init --force` to overwrite."
        );
    }

    eprintln!("greengate init — generating .greengate.toml");
    eprintln!("Press Enter to accept the default shown in [brackets].\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    macro_rules! ask {
        ($prompt:expr, $default:expr) => {{
            eprint!("  {} [{}]: ", $prompt, $default);
            io::stderr().flush().ok();
            let input = lines.next().transpose()?.unwrap_or_default();
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                $default.to_string()
            } else {
                trimmed
            }
        }};
    }

    macro_rules! ask_bool {
        ($prompt:expr, $default:expr) => {{
            let default_str = if $default { "Y/n" } else { "y/N" };
            eprint!("  {} [{}]: ", $prompt, default_str);
            io::stderr().flush().ok();
            let input = lines.next().transpose()?.unwrap_or_default();
            let trimmed = input.trim().to_lowercase();
            match trimmed.as_str() {
                "y" | "yes" => true,
                "n" | "no" => false,
                _ => $default,
            }
        }};
    }

    // ── Scan ──────────────────────────────────────────────────────────────────
    eprintln!("[ Secret & SAST Scanning ]");
    let entropy_enabled = ask_bool!("Enable entropy-based secret detection?", true);
    let entropy_threshold = ask!("Entropy threshold (higher = fewer false positives)", "4.5");
    eprintln!();

    // ── Coverage ──────────────────────────────────────────────────────────────
    eprintln!("[ Coverage Gate ]");
    let coverage_file = ask!("LCOV file path", "coverage/lcov.info");
    let coverage_min = ask!("Minimum coverage %", "80");
    eprintln!();

    // ── K8s lint ──────────────────────────────────────────────────────────────
    eprintln!("[ Kubernetes Lint ]");
    let lint_dir = ask!("Kubernetes manifests directory", "./k8s");
    eprintln!();

    // ── Docker lint ───────────────────────────────────────────────────────────
    eprintln!("[ Docker Lint ]");
    let docker_file = ask!("Dockerfile path (leave blank to skip)", "");
    eprintln!();

    // ── Lighthouse ────────────────────────────────────────────────────────────
    eprintln!("[ Lighthouse / PageSpeed ]");
    let lighthouse_url = ask!("URL to audit (leave blank to skip)", "");
    let lighthouse_min_perf = ask!("Minimum Performance score (0-100)", "80");
    let lighthouse_strategy = ask!("Device strategy (mobile/desktop)", "mobile");
    eprintln!();

    // ── Reassure ──────────────────────────────────────────────────────────────
    eprintln!("[ Reassure React Performance ]");
    let reassure_current = ask!("Path to current.perf", "output/current.perf");
    let reassure_baseline = ask!("Path to baseline.perf", "output/baseline.perf");
    let reassure_threshold = ask!("Allowed regression % before failure", "15");
    eprintln!();

    // ── Pipeline ──────────────────────────────────────────────────────────────
    eprintln!("[ Pipeline Runner ]");
    let run_pipeline = ask_bool!("Generate a default pipeline (greengate run)?", true);
    eprintln!();

    // ── Build TOML ────────────────────────────────────────────────────────────
    let mut toml = String::new();

    toml.push_str(&format!(
        "[scan]\n\
         entropy = {}\n\
         entropy_threshold = {}\n\
         entropy_min_length = 20\n\n",
        entropy_enabled, entropy_threshold
    ));

    toml.push_str(&format!(
        "[coverage]\n\
         file = \"{}\"\n\
         min = {}\n\n",
        coverage_file, coverage_min
    ));

    toml.push_str(&format!(
        "[lint]\n\
         target_dir = \"{}\"\n\n",
        lint_dir
    ));

    if !docker_file.is_empty() {
        toml.push_str(&format!(
            "[docker]\n\
             dockerfile = \"{}\"\n\n",
            docker_file
        ));
    }

    if !lighthouse_url.is_empty() {
        toml.push_str(&format!(
            "[lighthouse]\n\
             url = \"{}\"\n\
             strategy = \"{}\"\n\
             min_performance = {}\n\
             min_accessibility = 90\n\
             min_best_practices = 80\n\
             min_seo = 80\n\n",
            lighthouse_url, lighthouse_strategy, lighthouse_min_perf
        ));
    }

    toml.push_str(&format!(
        "[reassure]\n\
         current = \"{}\"\n\
         baseline = \"{}\"\n\
         threshold = {}\n\n",
        reassure_current, reassure_baseline, reassure_threshold
    ));

    if run_pipeline {
        let mut steps: Vec<&str> = vec!["scan", "audit", "coverage"];
        if !docker_file.is_empty() {
            steps.push("docker-lint");
        }
        if !lighthouse_url.is_empty() {
            steps.push("lighthouse");
        }

        toml.push_str("[pipeline]\nsteps = [\n");
        for step in &steps {
            toml.push_str(&format!("  \"{}\",\n", step));
        }
        toml.push_str("]\n\n");
    }

    std::fs::write(config_path, &toml)?;

    eprintln!("✅ .greengate.toml written successfully.");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  greengate scan          # scan for secrets & SAST issues");
    eprintln!("  greengate audit         # check dependencies for CVEs");
    eprintln!("  greengate coverage      # gate on test coverage");
    if !docker_file.is_empty() {
        eprintln!("  greengate docker-lint   # lint your Dockerfile");
    }
    if run_pipeline {
        eprintln!("  greengate run           # run all pipeline steps in order");
    }
    eprintln!("  greengate install-hooks # install git pre-commit hook");

    Ok(())
}
