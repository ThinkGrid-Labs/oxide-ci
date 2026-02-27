use crate::utils::terminal;
use anyhow::{Context, Result};

struct FileRecord {
    path: String,
    hit: u64,
    found: u64,
}

pub fn run_coverage(file: &str, min: f64) -> Result<()> {
    terminal::info(&format!(
        "Analyzing coverage file: {} (threshold: {:.1}%)",
        file, min
    ));

    let content =
        std::fs::read_to_string(file).with_context(|| format!("Cannot read LCOV file: {}", file))?;

    let mut records: Vec<FileRecord> = Vec::new();
    let mut current_path = String::new();
    let mut current_hit: u64 = 0;
    let mut current_found: u64 = 0;

    for line in content.lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            current_path = path.to_string();
            current_hit = 0;
            current_found = 0;
        } else if let Some(val) = line.strip_prefix("LH:") {
            current_hit = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("LF:") {
            current_found = val.trim().parse::<u64>().unwrap_or(0);
        } else if line == "end_of_record" {
            if !current_path.is_empty() {
                records.push(FileRecord {
                    path: current_path.clone(),
                    hit: current_hit,
                    found: current_found,
                });
            }
        }
    }

    if records.is_empty() {
        anyhow::bail!("No coverage records found in '{}'", file);
    }

    let total_hit: u64 = records.iter().map(|r| r.hit).sum();
    let total_found: u64 = records.iter().map(|r| r.found).sum();

    if total_found == 0 {
        anyhow::bail!("LCOV file '{}' has no line data (LF: 0)", file);
    }

    // Per-file breakdown (only show files below threshold)
    let mut below: Vec<&FileRecord> = records
        .iter()
        .filter(|r| r.found > 0)
        .filter(|r| (r.hit as f64 / r.found as f64) * 100.0 < min)
        .collect();
    below.sort_by(|a, b| {
        let pct_a = a.hit as f64 / a.found as f64;
        let pct_b = b.hit as f64 / b.found as f64;
        pct_a.partial_cmp(&pct_b).unwrap()
    });

    if !below.is_empty() {
        eprintln!("\n  Files below threshold ({:.1}%):", min);
        for r in &below {
            let pct = (r.hit as f64 / r.found as f64) * 100.0;
            eprintln!("    {:.1}%  {}", pct, r.path);
        }
        eprintln!();
    }

    let coverage_pct = (total_hit as f64 / total_found as f64) * 100.0;
    let files_scanned = records.len();

    if coverage_pct < min {
        terminal::warn(&format!(
            "Coverage {:.1}% is below threshold {:.1}% ({} files, {}/{} lines covered)",
            coverage_pct, min, files_scanned, total_hit, total_found
        ));
        anyhow::bail!(
            "Coverage gate failed: {:.1}% < {:.1}%",
            coverage_pct,
            min
        );
    }

    terminal::success(&format!(
        "Coverage {:.1}% meets threshold {:.1}% ({} files, {}/{} lines covered)",
        coverage_pct, min, files_scanned, total_hit, total_found
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_lcov(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_passes_above_threshold() {
        let lcov = write_lcov(
            "SF:src/main.rs\nLH:90\nLF:100\nend_of_record\n",
        );
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_ok(), "expected pass at 90% with threshold 80%");
    }

    #[test]
    fn test_fails_below_threshold() {
        let lcov = write_lcov(
            "SF:src/main.rs\nLH:50\nLF:100\nend_of_record\n",
        );
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_err(), "expected fail at 50% with threshold 80%");
    }

    #[test]
    fn test_aggregates_multiple_files() {
        // file1: 80/100 = 80%, file2: 80/100 = 80% => total 160/200 = 80%
        let lcov = write_lcov(
            "SF:src/a.rs\nLH:80\nLF:100\nend_of_record\nSF:src/b.rs\nLH:80\nLF:100\nend_of_record\n",
        );
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_errors_on_missing_file() {
        let result = super::run_coverage("/nonexistent/lcov.info", 80.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_errors_on_empty_lcov() {
        let lcov = write_lcov("# no data\n");
        let result = super::run_coverage(lcov.path().to_str().unwrap(), 80.0);
        assert!(result.is_err());
    }
}
