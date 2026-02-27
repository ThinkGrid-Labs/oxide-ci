use crate::utils::{files, terminal};
use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use std::fs;

// Simple patterns for demonstration
const PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", r"(?i)AKIA[0-9A-Z]{16}"),
    (
        "AWS Secret Key",
        r"(?i)(?P<secret>aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40})",
    ),
    ("Generic PII (SSN)", r"\b\d{3}-\d{2}-\d{4}\b"),
    (
        "Generic PII (Email)",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ),
];

pub fn run_scan() -> Result<()> {
    terminal::info("Starting secret and PII scan...");

    let walker = files::get_parallel_walker("./");
    let regexes: Vec<(String, Regex)> = PATTERNS
        .iter()
        .map(|(name, pattern)| (name.to_string(), Regex::new(pattern).unwrap()))
        .collect();

    // Collect files
    let mut files_to_scan = Vec::new();
    for entry in walker {
        if let Ok(e) = entry {
            if e.file_type().map_or(false, |ft| ft.is_file()) {
                files_to_scan.push(e.into_path());
            }
        }
    }

    let bar = terminal::create_progress_bar(files_to_scan.len() as u64);

    let findings: Vec<_> = files_to_scan
        .par_iter()
        .flat_map(|path| {
            let mut file_findings = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                for (name, regex) in &regexes {
                    if regex.is_match(&content) {
                        file_findings.push((path.clone(), name.clone()));
                    }
                }
            }
            bar.inc(1);
            file_findings
        })
        .collect();

    bar.finish_with_message("Scan completed.");

    if findings.is_empty() {
        terminal::success("No secrets or PII found!");
    } else {
        terminal::warn(&format!("Found {} potential issues:", findings.len()));
        for (path, name) in findings {
            println!("  - [{}] in {}", name, path.display());
        }
    }

    Ok(())
}
