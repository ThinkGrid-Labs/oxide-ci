/// Scan baseline — save a snapshot of current findings and use it to suppress
/// known issues, so CI only fails on *new* findings introduced by a PR/commit.
///
/// Workflow:
///   1. `oxide-ci scan --update-baseline`  → writes `.oxide-baseline.json`
///   2. `oxide-ci scan --since-baseline`   → only fails on findings absent from baseline
use crate::modules::scanner::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

const BASELINE_FILE: &str = ".oxide-baseline.json";

/// Stable fingerprint stored in the baseline.
/// Uses path + rule + line so individual line shifts don't invalidate the whole file.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct BaselineEntry {
    pub path: String,
    pub rule_id: String,
    pub line: usize,
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        Self {
            path: f.path.display().to_string(),
            rule_id: f.rule_id.clone(),
            line: f.line,
        }
    }
}

/// Persist findings to `.oxide-baseline.json`.
pub fn save_baseline(findings: &[Finding]) -> Result<()> {
    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from).collect();
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(BASELINE_FILE, json)?;
    eprintln!(
        "✅ Baseline saved: {} finding(s) written to {}",
        entries.len(),
        BASELINE_FILE
    );
    Ok(())
}

/// Load previously-saved baseline entries.
pub fn load_baseline() -> Result<Vec<BaselineEntry>> {
    if !Path::new(BASELINE_FILE).exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(BASELINE_FILE)?;
    let entries: Vec<BaselineEntry> = serde_json::from_str(&content)?;
    Ok(entries)
}

/// Return only findings that are *not* present in the baseline.
///
/// Uses a set of (path, rule_id, line) fingerprints. The comparison is
/// line-exact intentionally — if the same secret moves to a different line it
/// should be reviewed again.
pub fn filter_new_findings<'a>(
    findings: &'a [Finding],
    baseline: &[BaselineEntry],
) -> Vec<&'a Finding> {
    let known: std::collections::HashSet<BaselineEntry> = baseline.iter().cloned().collect();

    findings
        .iter()
        .filter(|f| !known.contains(&BaselineEntry::from(*f)))
        .collect()
}

/// Print a summary comparing current vs baseline.
pub fn print_baseline_summary(total: usize, new_count: usize, suppressed: usize) {
    if suppressed > 0 {
        eprintln!(
            "ℹ️  Baseline: {} total finding(s), {} suppressed by baseline, {} new",
            total, suppressed, new_count
        );
    }
}
