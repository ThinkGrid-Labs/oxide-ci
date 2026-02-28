use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub coverage: CoverageConfig,
    #[serde(default)]
    pub lint: LintConfig,
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
