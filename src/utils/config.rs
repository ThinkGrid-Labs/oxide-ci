use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub coverage: CoverageConfig,
    #[serde(default)]
    pub lint: LintConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub lighthouse: LighthouseConfig,
    #[serde(default)]
    pub reassure: ReassureConfig,
    #[serde(default)]
    pub sast: SastConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
}

/// A user-defined tree-sitter query rule from `.oxideci.toml`.
#[derive(Deserialize, Clone)]
pub struct CustomSastRule {
    /// Unique rule ID reported in findings, e.g. "MY/NoConsoleLog"
    pub id: String,
    /// tree-sitter S-expression query. Must contain a @match capture.
    pub query: String,
}

/// SAST settings loaded from `.oxideci.toml` under `[sast]`.
#[derive(Deserialize, Clone)]
pub struct SastConfig {
    /// Master switch — set to false to disable all SAST checks (default: true)
    #[serde(default = "default_sast_enabled")]
    pub enabled: bool,
    /// Rule IDs to skip, e.g. ["SAST/EvalUsage", "SAST/SetTimeout"]
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Max lines in a function body before SMELL/LongFunction fires (default: 50)
    #[serde(default = "default_max_function_lines")]
    pub max_function_lines: usize,
    /// Max parameters before SMELL/TooManyParameters fires (default: 5)
    #[serde(default = "default_max_parameters")]
    pub max_parameters: usize,
    /// Max nesting depth before SMELL/DeepNesting fires (default: 4)
    #[serde(default = "default_max_nesting_depth")]
    pub max_nesting_depth: usize,
    /// User-defined tree-sitter query rules (default: [])
    #[serde(default)]
    pub custom_rules: Vec<CustomSastRule>,
}

impl Default for SastConfig {
    fn default() -> Self {
        Self {
            enabled: default_sast_enabled(),
            disabled_rules: Vec::new(),
            max_function_lines: default_max_function_lines(),
            max_parameters: default_max_parameters(),
            max_nesting_depth: default_max_nesting_depth(),
            custom_rules: Vec::new(),
        }
    }
}

fn default_sast_enabled() -> bool {
    true
}
fn default_max_function_lines() -> usize {
    50
}
fn default_max_parameters() -> usize {
    5
}
fn default_max_nesting_depth() -> usize {
    4
}

/// Per-scan settings loaded from `.oxideci.toml`.
/// `#[derive(Default)]` is not used because the entropy fields require non-zero defaults
/// that cannot be expressed with Rust's `Default` trait directly; use helper fns instead.
#[derive(Deserialize, Clone)]
pub struct ScanConfig {
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub extra_patterns: Vec<ExtraPattern>,
    /// Enable Shannon entropy detection for high-entropy tokens (default: true)
    #[serde(default = "default_entropy_enabled")]
    pub entropy: bool,
    /// Minimum entropy score for base64-like tokens to be flagged (default: 4.5)
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Minimum token length (chars) before entropy is checked (default: 20)
    #[serde(default = "default_entropy_min_length")]
    pub entropy_min_length: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            exclude_patterns: Vec::new(),
            extra_patterns: Vec::new(),
            entropy: default_entropy_enabled(),
            entropy_threshold: default_entropy_threshold(),
            entropy_min_length: default_entropy_min_length(),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct ExtraPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Deserialize, Clone)]
pub struct CoverageConfig {
    #[serde(default = "default_coverage_min")]
    pub min: f64,
    #[serde(default = "default_lcov_file")]
    pub file: String,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            min: default_coverage_min(),
            file: default_lcov_file(),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct LintConfig {
    #[serde(default = "default_target_dir")]
    pub target_dir: String,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            target_dir: default_target_dir(),
        }
    }
}

// ── Lighthouse config ─────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct LighthouseConfig {
    /// URL to audit (required for `oxide-ci lighthouse` unless passed via CLI)
    #[serde(default)]
    pub url: Option<String>,
    /// Device strategy: "mobile" (default) or "desktop"
    #[serde(default = "default_lighthouse_strategy")]
    pub strategy: String,
    #[serde(default = "default_lighthouse_perf")]
    pub min_performance: u8,
    #[serde(default = "default_lighthouse_a11y")]
    pub min_accessibility: u8,
    #[serde(default = "default_lighthouse_bp")]
    pub min_best_practices: u8,
    #[serde(default = "default_lighthouse_seo")]
    pub min_seo: u8,
    /// Google PageSpeed Insights API key (optional; can also set PAGESPEED_API_KEY env var)
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            url: None,
            strategy: default_lighthouse_strategy(),
            min_performance: default_lighthouse_perf(),
            min_accessibility: default_lighthouse_a11y(),
            min_best_practices: default_lighthouse_bp(),
            min_seo: default_lighthouse_seo(),
            api_key: None,
        }
    }
}

// ── Reassure config ───────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct ReassureConfig {
    /// Path to Reassure current.perf file
    #[serde(default = "default_reassure_current")]
    pub current: String,
    /// Path to Reassure baseline.perf file (optional)
    #[serde(default = "default_reassure_baseline")]
    pub baseline: String,
    /// Percentage mean-time increase allowed before flagging a regression
    #[serde(default = "default_reassure_threshold")]
    pub threshold: f64,
}

impl Default for ReassureConfig {
    fn default() -> Self {
        Self {
            current: default_reassure_current(),
            baseline: default_reassure_baseline(),
            threshold: default_reassure_threshold(),
        }
    }
}

// ── Default value fns ─────────────────────────────────────────────────────────

fn default_entropy_enabled() -> bool {
    true
}
fn default_entropy_threshold() -> f64 {
    4.5
}
fn default_entropy_min_length() -> usize {
    20
}
fn default_coverage_min() -> f64 {
    80.0
}
fn default_lcov_file() -> String {
    "coverage/lcov.info".to_string()
}
fn default_target_dir() -> String {
    ".".to_string()
}
fn default_lighthouse_strategy() -> String {
    "mobile".to_string()
}
fn default_lighthouse_perf() -> u8 {
    80
}
fn default_lighthouse_a11y() -> u8 {
    90
}
fn default_lighthouse_bp() -> u8 {
    80
}
fn default_lighthouse_seo() -> u8 {
    80
}
fn default_reassure_current() -> String {
    "output/current.perf".to_string()
}
fn default_reassure_baseline() -> String {
    "output/baseline.perf".to_string()
}
fn default_reassure_threshold() -> f64 {
    15.0
}

// ── Docker config ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct DockerConfig {
    /// Path to the Dockerfile to lint (default: "Dockerfile")
    #[serde(default = "default_dockerfile")]
    pub dockerfile: String,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            dockerfile: default_dockerfile(),
        }
    }
}

fn default_dockerfile() -> String {
    "Dockerfile".to_string()
}

// ── Pipeline config ───────────────────────────────────────────────────────────

#[derive(Deserialize, Clone, Default)]
pub struct PipelineConfig {
    /// Ordered list of steps to run with `oxide-ci run`.
    /// Each entry is a command string, e.g. "scan", "coverage --min 80".
    #[serde(default)]
    pub steps: Vec<String>,
}

/// Load `.oxideci.toml` from the current directory, falling back to defaults.
pub fn load() -> Config {
    let path = std::path::Path::new(".oxideci.toml");
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(cfg) => {
                    eprintln!("ℹ️  Loaded config from .oxideci.toml");
                    return cfg;
                }
                Err(e) => eprintln!("⚠️  Failed to parse .oxideci.toml: {}", e),
            },
            Err(e) => eprintln!("⚠️  Failed to read .oxideci.toml: {}", e),
        }
    }
    Config::default()
}

/// Apply a named profile on top of an already-loaded config.
///
/// Profiles adjust thresholds without requiring a config file change:
///   `strict`  — tighter quality gates (higher coverage, lower entropy threshold)
///   `relaxed` — looser gates (lower coverage, higher entropy threshold)
///   `ci`      — CI-optimised: strict gates + SAST enabled, no interactive output
pub fn apply_profile(cfg: &mut Config, profile: &str) {
    match profile {
        "strict" => {
            // Raise coverage threshold to 90 % if not already higher
            if cfg.coverage.min < 90.0 {
                cfg.coverage.min = 90.0;
            }
            // Lower entropy threshold → more sensitive secret detection
            if cfg.scan.entropy_threshold > 3.5 {
                cfg.scan.entropy_threshold = 3.5;
            }
            // Ensure SAST is on
            cfg.sast.enabled = true;
            // Stricter Lighthouse scores
            if cfg.lighthouse.min_performance < 90 {
                cfg.lighthouse.min_performance = 90;
            }
            if cfg.lighthouse.min_accessibility < 95 {
                cfg.lighthouse.min_accessibility = 95;
            }
        }
        "relaxed" => {
            // Lower coverage threshold to 70 % if not already lower
            if cfg.coverage.min > 70.0 {
                cfg.coverage.min = 70.0;
            }
            // Raise entropy threshold → fewer false positives
            if cfg.scan.entropy_threshold < 5.0 {
                cfg.scan.entropy_threshold = 5.0;
            }
        }
        "ci" => {
            // Same as strict, but also disable code-smell rules that produce noise in CI
            if cfg.coverage.min < 80.0 {
                cfg.coverage.min = 80.0;
            }
            cfg.sast.enabled = true;
            // Code smell rules are optional noise in CI — disable if not already set
            for rule in &["SMELL/LongFunction", "SMELL/TooManyParameters", "SMELL/DeepNesting"] {
                if !cfg.sast.disabled_rules.iter().any(|r| r == rule) {
                    cfg.sast.disabled_rules.push(rule.to_string());
                }
            }
        }
        other => {
            eprintln!("⚠️  Unknown profile '{}'. Valid profiles: strict, relaxed, ci", other);
        }
    }
}
