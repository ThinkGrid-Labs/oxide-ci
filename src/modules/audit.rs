use crate::utils::terminal;
use anyhow::{Context, Result};
use serde_json::{json, Value};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    ecosystem: &'static str,
}

#[derive(Debug)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub vuln_id: String,
    pub summary: String,
}

// ── Lock-file parsers ─────────────────────────────────────────────────────────

/// Parse `Cargo.lock` (TOML) and return crates.io packages.
fn parse_cargo_lock(content: &str) -> Vec<Package> {
    let Ok(value) = content.parse::<toml::Value>() else {
        return Vec::new();
    };

    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?.to_string();
            let version = pkg.get("version")?.as_str()?.to_string();
            // Only include packages from crates.io registry
            let source = pkg.get("source").and_then(|s| s.as_str()).unwrap_or("");
            if source.contains("crates.io-index") || source.is_empty() {
                Some(Package {
                    name,
                    version,
                    ecosystem: "crates.io",
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `package-lock.json` (npm v2/v3) and return npm packages.
fn parse_package_lock(content: &str) -> Vec<Package> {
    let Ok(root) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let Some(packages) = root.get("packages").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|(key, val)| {
            // Skip the root package entry (empty string key)
            if key.is_empty() {
                return None;
            }
            // Extract the package name from the path key (e.g. "node_modules/express")
            let name = key.trim_start_matches("node_modules/").to_string();
            let version = val.get("version")?.as_str()?.to_string();
            Some(Package {
                name,
                version,
                ecosystem: "npm",
            })
        })
        .collect()
}

/// Parse `requirements.txt` — only `==` pinned versions are auditable.
fn parse_requirements_txt(content: &str) -> Vec<Package> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            // Only handle == pinned versions
            let mut parts = line.splitn(2, "==");
            let name = parts.next()?.trim().to_string();
            let version = parts.next()?.trim().to_string();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(Package {
                name,
                version,
                ecosystem: "PyPI",
            })
        })
        .collect()
}

// ── OSV API ───────────────────────────────────────────────────────────────────

fn query_osv(packages: &[Package]) -> Result<Vec<Vulnerability>> {
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "version": p.version,
                "package": {
                    "name": p.name,
                    "ecosystem": p.ecosystem
                }
            })
        })
        .collect();

    let body = json!({ "queries": queries });

    let response = ureq::post(OSV_BATCH_URL)
        .set("Content-Type", "application/json")
        .send_string(&serde_json::to_string(&body)?)
        .context("Failed to reach OSV API — check your network connection")?;

    let result: Value = serde_json::from_reader(response.into_reader())
        .context("Failed to parse OSV API response")?;

    let empty = vec![];
    let results: &Vec<Value> = result
        .get("results")
        .and_then(|r: &Value| r.as_array())
        .unwrap_or(&empty);

    let mut vulns = Vec::new();
    for (i, result_entry) in results.iter().enumerate() {
        let pkg = &packages[i];
        let vuln_array: &Vec<Value> = match result_entry
            .get("vulns")
            .and_then(|v: &Value| v.as_array())
        {
            Some(a) => a,
            None => continue,
        };
        for vuln in vuln_array {
            let id = vuln
                .get("id")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let summary = vuln
                .get("summary")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("No summary available")
                .to_string();
            vulns.push(Vulnerability {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                vuln_id: id,
                summary,
            });
        }
    }

    Ok(vulns)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_audit() -> Result<()> {
    // Detect which lock file is present
    let (lockfile, packages) = if std::path::Path::new("Cargo.lock").exists() {
        let content = std::fs::read_to_string("Cargo.lock")
            .context("Cannot read Cargo.lock")?;
        let pkgs = parse_cargo_lock(&content);
        ("Cargo.lock (crates.io)", pkgs)
    } else if std::path::Path::new("package-lock.json").exists() {
        let content = std::fs::read_to_string("package-lock.json")
            .context("Cannot read package-lock.json")?;
        let pkgs = parse_package_lock(&content);
        ("package-lock.json (npm)", pkgs)
    } else if std::path::Path::new("requirements.txt").exists() {
        let content = std::fs::read_to_string("requirements.txt")
            .context("Cannot read requirements.txt")?;
        let pkgs = parse_requirements_txt(&content);
        ("requirements.txt (PyPI)", pkgs)
    } else {
        anyhow::bail!(
            "No supported lock file found. Supported: Cargo.lock, package-lock.json, requirements.txt"
        );
    };

    terminal::info(&format!(
        "Auditing {} packages from {} via OSV...",
        packages.len(),
        lockfile
    ));

    if packages.is_empty() {
        terminal::info("No packages to audit.");
        return Ok(());
    }

    // OSV batch API supports up to 1000 queries; chunk if needed
    let bar = terminal::create_progress_bar(1);
    bar.set_message("Querying OSV API...");

    let mut all_vulns: Vec<Vulnerability> = Vec::new();
    for chunk in packages.chunks(1000) {
        match query_osv(chunk) {
            Ok(vulns) => all_vulns.extend(vulns),
            Err(e) => {
                bar.finish_and_clear();
                terminal::warn(&format!("OSV API error: {} — skipping audit.", e));
                return Ok(());
            }
        }
    }

    bar.finish_and_clear();

    if all_vulns.is_empty() {
        terminal::success(&format!(
            "No known vulnerabilities found in {} packages.",
            packages.len()
        ));
        return Ok(());
    }

    terminal::warn(&format!(
        "Found {} vulnerability/-ies in {} packages:",
        all_vulns.len(),
        packages.len()
    ));
    for v in &all_vulns {
        eprintln!(
            "  [{}] {}@{} — {}",
            v.vuln_id, v.package, v.version, v.summary
        );
    }

    anyhow::bail!(
        "Audit failed: {} known vulnerability/-ies found.",
        all_vulns.len()
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_lock_basic() {
        let content = r#"
version = 3

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"
"#;
        let pkgs = parse_cargo_lock(content);
        // local-crate has no source so is included; anyhow has crates.io source
        assert!(pkgs.iter().any(|p| p.name == "anyhow" && p.version == "1.0.86"));
    }

    #[test]
    fn test_parse_package_lock_basic() {
        let content = r#"
{
  "packages": {
    "": { "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.0" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#;
        let pkgs = parse_package_lock(content);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "express" && p.version == "4.18.0"));
    }

    #[test]
    fn test_parse_requirements_txt_pinned_only() {
        let content = "Django==4.2.0\nrequests>=2.28.0\nflask==2.3.2\n# comment\n";
        let pkgs = parse_requirements_txt(content);
        // Only == pinned ones: Django and flask
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "Django" && p.version == "4.2.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "2.3.2"));
    }

    #[test]
    fn test_parse_requirements_txt_skips_comments() {
        let content = "# this is a comment\n\nrequests==2.28.2\n";
        let pkgs = parse_requirements_txt(content);
        assert_eq!(pkgs.len(), 1);
    }
}
