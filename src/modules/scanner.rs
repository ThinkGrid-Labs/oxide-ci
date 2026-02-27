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
    // The two params may be anywhere in the query string so we use .* between them
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
}

pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

pub enum DiffMode {
    Staged,
    Since(String),
}

pub struct ScanOpts<'a> {
    pub format: OutputFormat,
    pub diff: Option<DiffMode>,
    pub config: &'a ScanConfig,
}

// ── Diff helpers ─────────────────────────────────────────────────────────────

fn get_changed_files(mode: &DiffMode) -> Result<Vec<PathBuf>> {
    let args: &[&str] = match mode {
        DiffMode::Staged => &["diff", "--cached", "--name-only"],
        DiffMode::Since(commit) => &["diff", commit.as_str(), "--name-only"],
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

// ── Output helpers ────────────────────────────────────────────────────────────

fn output_json(findings: &[Finding]) -> Result<()> {
    let out = json!({
        "total": findings.len(),
        "findings": findings.iter().map(|f| json!({
            "rule": f.rule_id,
            "file": f.path.to_string_lossy(),
            "line": f.line,
        })).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn output_sarif(findings: &[Finding]) -> Result<()> {
    // Deduplicate rule IDs for the rules table
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
            json!({
                "ruleId": f.rule_id,
                "level": "error",
                "message": { "text": format!("{} found", f.rule_id) },
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

// ── Main entry ────────────────────────────────────────────────────────────────

pub fn run_scan(opts: ScanOpts) -> Result<()> {
    let is_text = matches!(opts.format, OutputFormat::Text);
    if is_text {
        terminal::info("Starting secret and PII scan...");
    }

    // Build regex list: builtins + user-defined extras
    let mut all_patterns: Vec<(String, Regex)> = BUILTIN_PATTERNS
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
        all_patterns.push((ep.name.clone(), re));
    }

    // Build exclude override set
    let excludes = build_excludes(&opts.config.exclude_patterns)?;

    // Collect files to scan
    let files_to_scan: Vec<PathBuf> = match &opts.diff {
        Some(mode) => {
            terminal::info("Diff mode: scanning only changed files...");
            get_changed_files(mode)?
        }
        None => {
            let walker = files::get_walker("./");
            walker
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
                .map(|e| e.into_path())
                .collect()
        }
    };

    // Apply exclude patterns
    let files_to_scan: Vec<PathBuf> = files_to_scan
        .into_iter()
        .filter(|p| !is_excluded(p, &excludes))
        .collect();

    let bar = if is_text {
        Some(terminal::create_progress_bar(files_to_scan.len() as u64))
    } else {
        None
    };

    let findings: Vec<Finding> = files_to_scan
        .par_iter()
        .flat_map(|path| {
            let mut file_findings = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                for (line_no, line) in content.lines().enumerate() {
                    for (name, regex) in &all_patterns {
                        if regex.is_match(line) {
                            file_findings.push(Finding {
                                path: path.clone(),
                                rule_id: name.clone(),
                                line: line_no + 1,
                            });
                        }
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

    if findings.is_empty() {
        if is_text {
            terminal::success("No secrets or PII found.");
        } else {
            match opts.format {
                OutputFormat::Json => output_json(&findings)?,
                OutputFormat::Sarif => output_sarif(&findings)?,
                OutputFormat::Text => {}
            }
        }
        return Ok(());
    }

    // Emit findings in requested format
    match opts.format {
        OutputFormat::Text => {
            terminal::warn(&format!("Found {} potential issue(s):", findings.len()));
            for f in &findings {
                eprintln!("  - [{}] {}:{}", f.rule_id, f.path.display(), f.line);
            }
        }
        OutputFormat::Json => output_json(&findings)?,
        OutputFormat::Sarif => output_sarif(&findings)?,
    }

    anyhow::bail!(
        "Scan failed: {} secret(s)/PII found. Review the findings above.",
        findings.len()
    );
}

// ── Exclude helpers ───────────────────────────────────────────────────────────

fn build_excludes(patterns: &[String]) -> Result<Option<ignore::overrides::Override>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = OverrideBuilder::new(".");
    for pat in patterns {
        // Prefix with `!` to negate (mark as ignored/excluded)
        builder
            .add(&format!("!{}", pat))
            .with_context(|| format!("Invalid exclude pattern: {}", pat))?;
    }
    Ok(Some(builder.build()?))
}

fn is_excluded(path: &PathBuf, excludes: &Option<ignore::overrides::Override>) -> bool {
    if let Some(ov) = excludes {
        // matched() returns Some(glob) when the override matches; we added `!` negations
        // so a match means "exclude this path"
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
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n.contains("SSN"))
            .unwrap();
        assert!(re.is_match("ssn: 123-45-6789"));
        assert!(re.is_match("SSN=987-65-4321"));
    }

    #[test]
    fn test_ssn_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n.contains("SSN"))
            .unwrap();
        assert!(!re.is_match("123-456-7890")); // phone number
        assert!(!re.is_match("1234-56-789"));
    }

    #[test]
    fn test_email_matches() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n.contains("Email"))
            .unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("contact: admin@company.org"));
    }

    #[test]
    fn test_email_no_false_positive() {
        let patterns = compile_builtins();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| n.contains("Email"))
            .unwrap();
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
        let key = format!(
            "SG.{}.{}",
            "a".repeat(22),
            "b".repeat(43)
        );
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
        // Must be exactly 32 hex chars after AC — uppercase letters are invalid hex
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
        // Too short
        assert!(!re.is_match("hvs.tooshort"));
    }
}
