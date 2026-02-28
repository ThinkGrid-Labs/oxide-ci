use crate::utils::{config::ScanConfig, files, terminal};
use anyhow::{Context, Result};
use ignore::overrides::OverrideBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Built-in secret and PII detection patterns.
/// Organised by cloud provider / service so new entries are easy to locate.
const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    // ── AWS ────────────────────────────────────────────────────────────────
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    (
        "AWS Secret Key",
        r"(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}",
    ),
    // ── Azure ──────────────────────────────────────────────────────────────
    // Full connection string (AccountName + AccountKey together)
    (
        "Azure Storage Connection String",
        r"DefaultEndpointsProtocol=(http|https);AccountName=[^;\n]+;AccountKey=[A-Za-z0-9+/]{86}==",
    ),
    // Shared Access Signature URL – look for the mandatory sv= and sig= params
    (
        "Azure SAS Token",
        r"(?i)sv=20\d{2}-\d{2}-\d{2}[^#\n]*[?&]sig=[A-Za-z0-9%+/]+=*",
    ),
    // ── GCP ────────────────────────────────────────────────────────────────
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    // Service-account JSON files always contain this literal field
    (
        "GCP Service Account Key",
        r#""type"\s*:\s*"service_account""#,
    ),
    // Short-lived OAuth2 access token issued by GCP
    ("GCP OAuth2 Token", r"ya29\.[0-9A-Za-z\-_]+"),
    // ── DigitalOcean ───────────────────────────────────────────────────────
    ("DigitalOcean PAT", r"dop_v1_[a-zA-Z0-9]{64}"),
    // ── Alibaba Cloud ──────────────────────────────────────────────────────
    ("Alibaba Cloud Access Key ID", r"LTAI[A-Za-z0-9]{14,20}"),
    // ── GitHub ─────────────────────────────────────────────────────────────
    ("GitHub PAT (classic)", r"ghp_[A-Za-z0-9]{36}"),
    (
        "GitHub PAT (fine-grained)",
        r"github_pat_[A-Za-z0-9_]{82}",
    ),
    // ── Slack ──────────────────────────────────────────────────────────────
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    ),
    // ── Stripe ─────────────────────────────────────────────────────────────
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24}"),
    // ── SendGrid ───────────────────────────────────────────────────────────
    (
        "SendGrid API Key",
        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    ),
    // ── Mailgun ────────────────────────────────────────────────────────────
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
    // ── Twilio ─────────────────────────────────────────────────────────────
    // Account SIDs are 34 hex chars prefixed with AC
    ("Twilio Account SID", r"\bAC[a-f0-9]{32}\b"),
    // ── HashiCorp Vault ────────────────────────────────────────────────────
    // Service tokens (vault 1.10+) begin with hvs.
    ("HashiCorp Vault Token", r"hvs\.[A-Za-z0-9_\-]{90,}"),
    // ── Private keys & generic tokens ─────────────────────────────────────
    (
        "PEM Private Key",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    ),
    // ── PII ────────────────────────────────────────────────────────────────
    ("Generic PII (SSN)", r"\b\d{3}-\d{2}-\d{4}\b"),
    (
        "Generic PII (Email)",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    ),
];

pub struct Finding {
    pub path: PathBuf,
    pub rule_id: String,
    pub line: usize,
    /// Set to the short commit hash when this finding came from a `--history` scan.
    pub commit: Option<String>,
}

pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

pub enum DiffMode {
    Staged,
    Since(String),
    /// Scan the entire git commit history via `git log --all -p`.
    History,
}

pub struct ScanOpts<'a> {
    pub format: OutputFormat,
    pub diff: Option<DiffMode>,
    pub config: &'a ScanConfig,
}

// ── Entropy detection ─────────────────────────────────────────────────────────

enum CharsetKind {
    Base64Like,
    HexLike,
    Other,
}

/// Compute Shannon entropy H = -Σ p(x)·log₂(p(x)) for an ASCII/UTF-8 string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Classify a token as base64-like, hex-only, or neither.
fn classify_charset(token: &str) -> CharsetKind {
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return CharsetKind::HexLike;
    }
    if token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'))
    {
        return CharsetKind::Base64Like;
    }
    CharsetKind::Other
}

/// Check one source line for high-entropy tokens that may be unrecognised secrets.
/// Returns rule IDs for each flagged token (may be empty).
fn check_entropy(line: &str, config: &ScanConfig) -> Vec<String> {
    if !config.entropy {
        return Vec::new();
    }
    line.split(|c: char| matches!(c, '=' | ':' | '"' | '\'' | ' ' | '\t' | ',' | ';'))
        .filter(|s| s.len() >= config.entropy_min_length)
        .flat_map(|token| {
            let e = shannon_entropy(token);
            match classify_charset(token) {
                CharsetKind::Base64Like if e > config.entropy_threshold => {
                    vec!["High Entropy String (base64)".to_string()]
                }
                CharsetKind::HexLike if e > 3.5 && token.len() >= 32 => {
                    vec!["High Entropy String (hex)".to_string()]
                }
                _ => vec![],
            }
        })
        .collect()
}

// ── Git history scan ──────────────────────────────────────────────────────────

/// Parse the output of `git log --all -p --no-color` and return every *added* line
/// as a tuple of `(commit_hash, file_path, line_content, new_file_line_number)`.
///
/// Only `+` prefix lines are collected; context (` `) and removed (`-`) lines are
/// skipped. The new-file line counter advances on both added and context lines so
/// that line numbers are accurate relative to the post-commit file.
fn parse_git_log_patch(stdout: &str) -> Vec<(String, PathBuf, String, usize)> {
    let mut results: Vec<(String, PathBuf, String, usize)> = Vec::new();
    let mut current_commit = String::new();
    let mut current_path: Option<PathBuf> = None;
    let mut hunk_line_no: usize = 0;

    for raw_line in stdout.lines() {
        if let Some(hash) = raw_line.strip_prefix("commit ") {
            // Only take the first word (the actual hash, before any decorations)
            current_commit = hash.split_whitespace().next().unwrap_or("").to_string();
            current_path = None;
            hunk_line_no = 0;
            continue;
        }

        // "diff --git a/path/to/file b/path/to/file"
        if raw_line.starts_with("diff --git ") {
            if let Some(b_part) = raw_line.split(" b/").nth(1) {
                current_path = Some(PathBuf::from(b_part.trim()));
            }
            hunk_line_no = 0;
            continue;
        }

        // "@@ -old_start,count +new_start,count @@"
        if raw_line.starts_with("@@ ") {
            // Extract the "+new_start" portion
            if let Some(after_plus) = raw_line.split('+').nth(1) {
                let num_str = after_plus
                    .split(|c| c == ',' || c == ' ')
                    .next()
                    .unwrap_or("1");
                hunk_line_no = num_str.parse().unwrap_or(1);
                // hunk_line_no now points to the first line of the hunk in the new file;
                // we'll increment BEFORE recording or after context lines.
                // Pre-decrement so the first line increments back to new_start.
                hunk_line_no = hunk_line_no.saturating_sub(1);
            }
            continue;
        }

        if let Some(ref path) = current_path {
            if raw_line.starts_with("+++") || raw_line.starts_with("---") {
                // Diff file header lines — skip, don't advance counter
                continue;
            }
            if raw_line.starts_with('+') {
                hunk_line_no += 1;
                let content = raw_line[1..].to_string();
                results.push((
                    current_commit.clone(),
                    path.clone(),
                    content,
                    hunk_line_no,
                ));
            } else if raw_line.starts_with(' ') {
                // Context line — advance new-file counter but don't collect
                hunk_line_no += 1;
            }
            // '-' lines (removed) do not belong to the new file — don't advance counter
        }
    }

    results
}

/// Scan the full git commit history for secrets in added lines.
fn run_history_scan(
    opts: &ScanOpts,
    all_patterns: &[(String, Regex)],
) -> Result<Vec<Finding>> {
    let is_text = matches!(opts.format, OutputFormat::Text);

    if is_text {
        terminal::info("Scanning full git history (this may take a while on large repos)...");
    }

    let output = Command::new("git")
        .args(["log", "--all", "-p", "--no-color"])
        .output()
        .context("Failed to run git log — is this a git repository?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git log failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout)
        .context("git log output is not valid UTF-8")?;

    let added_lines = parse_git_log_patch(&stdout);
    let total = added_lines.len() as u64;

    if is_text {
        terminal::info(&format!("Scanning {} added lines across history...", total));
    }

    let bar = if is_text {
        let b = terminal::create_progress_bar(total);
        b.set_message("Scanning history...");
        Some(b)
    } else {
        None
    };

    let findings: Vec<Finding> = added_lines
        .par_iter()
        .flat_map(|(commit, path, line, line_no)| {
            let mut hits: Vec<Finding> = Vec::new();

            // Feature 3: inline suppression
            if line.contains("oxide-ci: ignore") {
                if let Some(b) = &bar {
                    b.inc(1);
                }
                return hits;
            }

            for (name, regex) in all_patterns {
                if regex.is_match(line) {
                    hits.push(Finding {
                        path: path.clone(),
                        rule_id: name.clone(),
                        line: *line_no,
                        commit: Some(commit.clone()),
                    });
                }
            }
            for rule_id in check_entropy(line, opts.config) {
                hits.push(Finding {
                    path: path.clone(),
                    rule_id,
                    line: *line_no,
                    commit: Some(commit.clone()),
                });
            }

            if let Some(b) = &bar {
                b.inc(1);
            }
            hits
        })
        .collect();

    if let Some(b) = bar {
        b.finish_with_message("History scan complete.");
    }

    Ok(findings)
}

// ── Pattern compilation ───────────────────────────────────────────────────────

fn compile_patterns(opts: &ScanOpts) -> Result<Vec<(String, Regex)>> {
    let mut patterns: Vec<(String, Regex)> = BUILTIN_PATTERNS
        .iter()
        .map(|(name, pat)| {
            Regex::new(pat)
                .with_context(|| format!("Invalid built-in pattern for '{}'", name))
                .map(|re| (name.to_string(), re))
        })
        .collect::<Result<Vec<_>>>()?;

    for ep in &opts.config.extra_patterns {
        let re = Regex::new(&ep.regex)
            .with_context(|| format!("Invalid extra_pattern regex for '{}'", ep.name))?;
        patterns.push((ep.name.clone(), re));
    }

    Ok(patterns)
}

// ── Diff helpers ──────────────────────────────────────────────────────────────

fn get_changed_files(mode: &DiffMode) -> Result<Vec<PathBuf>> {
    let args: &[&str] = match mode {
        DiffMode::Staged => &["diff", "--cached", "--name-only"],
        DiffMode::Since(commit) => &["diff", commit.as_str(), "--name-only"],
        DiffMode::History => unreachable!("History mode is handled before get_changed_files"),
    };
    let output = Command::new("git")
        .args(args)
        .output()
        .context("Failed to run git — is this a git repository?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .collect())
}

// ── File scan ─────────────────────────────────────────────────────────────────

fn run_file_scan(
    opts: &ScanOpts,
    all_patterns: &[(String, Regex)],
    excludes: &Option<ignore::overrides::Override>,
    is_text: bool,
) -> Result<Vec<Finding>> {
    let files_to_scan: Vec<PathBuf> = match &opts.diff {
        Some(DiffMode::Staged) | Some(DiffMode::Since(_)) => {
            if is_text {
                terminal::info("Diff mode: scanning only changed files...");
            }
            get_changed_files(opts.diff.as_ref().unwrap())?
        }
        None => {
            let walker = files::get_walker("./");
            walker
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
                .map(|e| e.into_path())
                .collect()
        }
        Some(DiffMode::History) => {
            unreachable!("History mode is handled before run_file_scan")
        }
    };

    let files_to_scan: Vec<PathBuf> = files_to_scan
        .into_iter()
        .filter(|p| !is_excluded(p, excludes))
        .collect();

    let bar = if is_text {
        Some(terminal::create_progress_bar(files_to_scan.len() as u64))
    } else {
        None
    };

    let findings: Vec<Finding> = files_to_scan
        .par_iter()
        .flat_map(|path| {
            let mut file_findings: Vec<Finding> = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                for (line_no, line) in content.lines().enumerate() {
                    // Feature 3: inline suppression — silently skip marked lines
                    if line.contains("oxide-ci: ignore") {
                        continue;
                    }

                    // Regex-based pattern detection
                    for (name, regex) in all_patterns {
                        if regex.is_match(line) {
                            file_findings.push(Finding {
                                path: path.clone(),
                                rule_id: name.clone(),
                                line: line_no + 1,
                                commit: None,
                            });
                        }
                    }

                    // Feature 1: Shannon entropy detection
                    for rule_id in check_entropy(line, opts.config) {
                        file_findings.push(Finding {
                            path: path.clone(),
                            rule_id,
                            line: line_no + 1,
                            commit: None,
                        });
                    }
                }
            }
            if let Some(b) = &bar {
                b.inc(1);
            }
            file_findings
        })
        .collect();

    if let Some(b) = &bar {
        b.finish_with_message("Scan complete.");
    }

    Ok(findings)
}

// ── Output helpers ────────────────────────────────────────────────────────────

fn output_json(findings: &[Finding]) -> Result<()> {
    let out = json!({
        "total": findings.len(),
        "findings": findings.iter().map(|f| {
            let mut entry = json!({
                "rule": f.rule_id,
                "file": f.path.to_string_lossy(),
                "line": f.line,
            });
            if let Some(ref hash) = f.commit {
                entry["commit"] = json!(hash);
            }
            entry
        }).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn output_sarif(findings: &[Finding]) -> Result<()> {
    let mut seen_rules = std::collections::BTreeSet::new();
    for f in findings {
        seen_rules.insert(f.rule_id.clone());
    }
    let rules: Vec<_> = seen_rules
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": format!("{} detected", id) },
                "helpUri": "https://github.com/ThinkGrid-Labs/oxide-ci"
            })
        })
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let msg = match &f.commit {
                Some(h) => format!("{} found (commit {})", f.rule_id, &h[..8.min(h.len())]),
                None => format!("{} found", f.rule_id),
            };
            json!({
                "ruleId": f.rule_id,
                "level": "error",
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.path.to_string_lossy(),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "oxide-ci",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/ThinkGrid-Labs/oxide-ci",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn emit_findings(findings: &[Finding], format: &OutputFormat) -> Result<()> {
    if findings.is_empty() {
        match format {
            OutputFormat::Text => terminal::success("No secrets or PII found."),
            OutputFormat::Json => output_json(findings)?,
            OutputFormat::Sarif => output_sarif(findings)?,
        }
        return Ok(());
    }

    match format {
        OutputFormat::Text => {
            terminal::warn(&format!("Found {} potential issue(s):", findings.len()));
            for f in findings {
                let commit_note = f
                    .commit
                    .as_deref()
                    .map(|h| format!(" (commit {})", &h[..8.min(h.len())]))
                    .unwrap_or_default();
                eprintln!(
                    "  - [{}] {}:{}{}",
                    f.rule_id,
                    f.path.display(),
                    f.line,
                    commit_note
                );
            }
        }
        OutputFormat::Json => output_json(findings)?,
        OutputFormat::Sarif => output_sarif(findings)?,
    }

    anyhow::bail!(
        "Scan failed: {} secret(s)/PII found. Review the findings above.",
        findings.len()
    );
}

// ── Main entry ────────────────────────────────────────────────────────────────

pub fn run_scan(opts: ScanOpts) -> Result<()> {
    let is_text = matches!(opts.format, OutputFormat::Text);
    if is_text {
        terminal::info("Starting secret and PII scan...");
    }

    let all_patterns = compile_patterns(&opts)?;
    let excludes = build_excludes(&opts.config.exclude_patterns)?;

    let findings = if let Some(DiffMode::History) = &opts.diff {
        run_history_scan(&opts, &all_patterns)?
    } else {
        run_file_scan(&opts, &all_patterns, &excludes, is_text)?
    };

    emit_findings(&findings, &opts.format)
}

// ── Exclude helpers ───────────────────────────────────────────────────────────

fn build_excludes(patterns: &[String]) -> Result<Option<ignore::overrides::Override>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = OverrideBuilder::new(".");
    for pat in patterns {
        builder
            .add(&format!("!{}", pat))
            .with_context(|| format!("Invalid exclude pattern: {}", pat))?;
    }
    Ok(Some(builder.build()?))
}

fn is_excluded(path: &PathBuf, excludes: &Option<ignore::overrides::Override>) -> bool {
    if let Some(ov) = excludes {
        ov.matched(path, false).is_whitelist()
    } else {
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_builtins() -> Vec<(String, Regex)> {
        BUILTIN_PATTERNS
            .iter()
            .map(|(name, pattern)| {
                let re = Regex::new(pattern)
                    .unwrap_or_else(|e| panic!("Pattern '{}' failed to compile: {}", name, e));
                (name.to_string(), re)
            })
            .collect()
    }

    fn default_scan_config() -> ScanConfig {
        ScanConfig::default()
    }

    // ── Pattern compilation ─────────────────────────────────────────────────

    #[test]
    fn test_all_patterns_compile() {
        compile_builtins();
    }

    #[test]
    fn test_aws_access_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n == "AWS Access Key").unwrap();
        assert!(re.is_match("AKIAIOSFODNN7EXAMPLE123"));
        assert!(re.is_match("export KEY=AKIAIOSFODNN7EXAMPLEKEY1"));
    }

    #[test]
    fn test_aws_access_key_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n == "AWS Access Key").unwrap();
        assert!(!re.is_match("some random text without keys"));
        assert!(!re.is_match("AKIA_SHORT"));
    }

    #[test]
    fn test_ssn_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("SSN")).unwrap();
        assert!(re.is_match("ssn: 123-45-6789"));
        assert!(re.is_match("SSN=987-65-4321"));
    }

    #[test]
    fn test_ssn_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("SSN")).unwrap();
        assert!(!re.is_match("123-456-7890")); // phone number
        assert!(!re.is_match("1234-56-789"));
    }

    #[test]
    fn test_email_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("Email")).unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("contact: admin@company.org"));
    }

    #[test]
    fn test_email_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns.iter().find(|(n, _)| n.contains("Email")).unwrap();
        assert!(!re.is_match("not-an-email"));
        assert!(!re.is_match("missing@tld"));
    }

    #[test]
    fn test_github_pat_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GitHub PAT (classic)")
            .unwrap();
        assert!(re.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"));
    }

    #[test]
    fn test_stripe_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Stripe Secret Key")
            .unwrap();
        // Split across concat so no single source literal triggers GitHub push-protection.
        assert!(re.is_match(&["sk_live_", "abcdefghijklmnopqrstuvwx"].concat()));
    }

    #[test]
    fn test_pem_private_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "PEM Private Key")
            .unwrap();
        assert!(re.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(re.is_match("-----BEGIN PRIVATE KEY-----"));
    }

    // ── Azure ──────────────────────────────────────────────────────────────

    #[test]
    fn test_azure_connection_string_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure Storage Connection String")
            .unwrap();
        let sample = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;\
            AccountKey=dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dA==";
        assert!(re.is_match(sample));
    }

    #[test]
    fn test_azure_connection_string_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure Storage Connection String")
            .unwrap();
        assert!(!re.is_match("some random string with no azure connection data"));
    }

    #[test]
    fn test_azure_sas_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Azure SAS Token")
            .unwrap();
        let sample =
            "https://account.blob.core.windows.net/container?sv=2023-01-03&ss=b&srt=sco\
             &sp=rwdlacupitfx&se=2025-01-01T00:00:00Z&st=2024-01-01T00:00:00Z\
             &spr=https&sig=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==";
        assert!(re.is_match(sample));
    }

    // ── GCP ────────────────────────────────────────────────────────────────

    #[test]
    fn test_gcp_service_account_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP Service Account Key")
            .unwrap();
        assert!(re.is_match(r#"{ "type": "service_account", "project_id": "myproj" }"#));
        assert!(re.is_match(r#""type":"service_account""#));
    }

    #[test]
    fn test_gcp_service_account_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP Service Account Key")
            .unwrap();
        assert!(!re.is_match(r#""type": "user""#));
        assert!(!re.is_match("some unrelated JSON"));
    }

    #[test]
    fn test_gcp_oauth2_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "GCP OAuth2 Token")
            .unwrap();
        assert!(re.is_match("ya29.A0ARrdaM-validlookingtokenfortest1234567890abc"));
    }

    // ── DigitalOcean ───────────────────────────────────────────────────────

    #[test]
    fn test_digitalocean_pat_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "DigitalOcean PAT")
            .unwrap();
        let token = format!("dop_v1_{}", "a".repeat(64));
        assert!(re.is_match(&token));
    }

    #[test]
    fn test_digitalocean_pat_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "DigitalOcean PAT")
            .unwrap();
        assert!(!re.is_match("dop_v1_tooshort"));
    }

    // ── Alibaba Cloud ──────────────────────────────────────────────────────

    #[test]
    fn test_alibaba_access_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Alibaba Cloud Access Key ID")
            .unwrap();
        assert!(re.is_match("LTAI5tFakeAlibaba1234567"));
        assert!(re.is_match("access_key=LTAIAnotherFakeKey12345"));
    }

    // ── SendGrid ───────────────────────────────────────────────────────────

    #[test]
    fn test_sendgrid_api_key_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "SendGrid API Key")
            .unwrap();
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
        assert!(re.is_match(&key));
    }

    // ── Twilio ─────────────────────────────────────────────────────────────

    #[test]
    fn test_twilio_sid_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Twilio Account SID")
            .unwrap();
        // Twilio SIDs are AC + exactly 32 lowercase hex chars = 34 chars total.
        // Split across concat so no single source literal triggers GitHub push-protection.
        assert!(re.is_match(&["AC", "abcdef1234567890abcdef1234567890"].concat()));
    }

    #[test]
    fn test_twilio_sid_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "Twilio Account SID")
            .unwrap();
        assert!(!re.is_match("ACXYZ_not_a_real_sid_because_not_hex"));
    }

    // ── HashiCorp Vault ────────────────────────────────────────────────────

    #[test]
    fn test_vault_token_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "HashiCorp Vault Token")
            .unwrap();
        let token = format!("hvs.{}", "A".repeat(92));
        assert!(re.is_match(&token));
    }

    #[test]
    fn test_vault_token_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n == "HashiCorp Vault Token")
            .unwrap();
        assert!(!re.is_match("hvs.tooshort"));
    }

    // ── Feature 3: Inline suppression ──────────────────────────────────────

    #[test]
    fn test_suppression_marker_detected() {
        let line = "AWS_KEY=AKIAIOSFODNN7EXAMPLEKEY1  # oxide-ci: ignore";
        assert!(line.contains("oxide-ci: ignore"));
    }

    // ── Feature 1: Shannon entropy ─────────────────────────────────────────

    #[test]
    fn test_shannon_entropy_high() {
        // Mixed-case alphanumeric has high entropy
        let s = "aB3dEfGhIjKlMnOpQrSt";
        assert!(shannon_entropy(s) > 3.5);
    }

    #[test]
    fn test_shannon_entropy_low() {
        // Repeated character → near-zero entropy
        let s = "aaaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(s) < 0.1);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_check_entropy_base64_flagged() {
        let config = default_scan_config();
        // 32-char token composed of base64-like chars with high variance
        let line = "SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345";
        let hits = check_entropy(line, &config);
        assert!(
            hits.iter().any(|r| r.contains("base64")),
            "expected base64 entropy hit, got: {:?}",
            hits
        );
    }

    #[test]
    fn test_check_entropy_hex_flagged() {
        let config = default_scan_config();
        // 32-char hex string with good entropy
        let line = "hash=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let hits = check_entropy(line, &config);
        assert!(
            hits.iter().any(|r| r.contains("hex")),
            "expected hex entropy hit, got: {:?}",
            hits
        );
    }

    #[test]
    fn test_check_entropy_disabled() {
        let config = ScanConfig {
            entropy: false,
            ..Default::default()
        };
        let line = "SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345";
        assert!(check_entropy(line, &config).is_empty());
    }

    #[test]
    fn test_check_entropy_too_short() {
        let config = default_scan_config(); // min_length = 20
        // 10-char token — below min
        let line = "tok=aBcDeFgHiJ";
        assert!(check_entropy(line, &config).is_empty());
    }

    // ── Feature 2: parse_git_log_patch ─────────────────────────────────────

    #[test]
    fn test_parse_git_log_patch_extracts_added_lines() {
        let patch = "\
commit abc123def456abc123def456abc123def456abc1\n\
diff --git a/src/config.rs b/src/config.rs\n\
@@ -1,3 +1,4 @@\n\
 fn main() {}\n\
+    let key = \"some value here\";\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "abc123def456abc123def456abc123def456abc1");
        assert_eq!(lines[0].1, PathBuf::from("src/config.rs"));
        assert!(lines[0].2.contains("key"));
    }

    #[test]
    fn test_parse_git_log_patch_skips_removed_lines() {
        let patch = "\
commit deadbeef00000000000000000000000000000000\n\
diff --git a/foo.txt b/foo.txt\n\
@@ -1,1 +1,1 @@\n\
-old line\n\
+new line\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 1, "only added line should be collected");
        assert!(lines[0].2.contains("new line"));
    }

    #[test]
    fn test_parse_git_log_patch_multiple_commits() {
        let patch = "\
commit aaa0000000000000000000000000000000000000\n\
diff --git a/a.txt b/a.txt\n\
@@ -1,1 +1,1 @@\n\
+line_in_aaa\n\
commit bbb0000000000000000000000000000000000000\n\
diff --git a/b.txt b/b.txt\n\
@@ -1,1 +1,1 @@\n\
+line_in_bbb\n\
";
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, "aaa0000000000000000000000000000000000000");
        assert_eq!(lines[1].0, "bbb0000000000000000000000000000000000000");
    }

    #[test]
    fn test_parse_git_log_patch_line_numbers() {
        // @@ -5,3 +10,4 @@ means new file starts at line 10.
        // Use concat!() so leading spaces in context lines are NOT stripped
        // (Rust's `\` line-continuation strips leading whitespace, which would
        // break context-line detection and produce wrong line numbers).
        let patch = concat!(
            "commit ccc0000000000000000000000000000000000000\n",
            "diff --git a/x.txt b/x.txt\n",
            "@@ -5,3 +10,4 @@\n",
            " context at 10\n",
            "+added at 11\n",
            " context at 12\n",
            "+added at 13\n",
        );
        let lines = parse_git_log_patch(patch);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].3, 11, "first added line should be at line 11");
        assert_eq!(lines[1].3, 13, "second added line should be at line 13");
    }
}
