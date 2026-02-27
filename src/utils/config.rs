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

#[derive(Deserialize, Default, Clone)]
pub struct ScanConfig {
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub extra_patterns: Vec<ExtraPattern>,
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
