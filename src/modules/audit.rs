use crate::utils::{files, terminal};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    ecosystem: &'static str,
    /// Which lock file this package was parsed from.
    source_file: PathBuf,
}

#[derive(Debug)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub vuln_id: String,
    pub summary: String,
    pub source_file: PathBuf,
}

// ── Lock-file parsers ─────────────────────────────────────────────────────────

/// Parse `Cargo.lock` (TOML) and return crates.io packages.
fn parse_cargo_lock(content: &str, source: PathBuf) -> Vec<Package> {
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
            let src = pkg.get("source").and_then(|s| s.as_str()).unwrap_or("");
            if src.contains("crates.io-index") || src.is_empty() {
                Some(Package {
                    name,
                    version,
                    ecosystem: "crates.io",
                    source_file: source.clone(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `package-lock.json` (npm v2/v3) and return npm packages.
fn parse_package_lock(content: &str, source: PathBuf) -> Vec<Package> {
    let Ok(root) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let Some(packages) = root.get("packages").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|(key, val)| {
            if key.is_empty() {
                return None;
            }
            let name = key.trim_start_matches("node_modules/").to_string();
            let version = val.get("version")?.as_str()?.to_string();
            Some(Package {
                name,
                version,
                ecosystem: "npm",
                source_file: source.clone(),
            })
        })
        .collect()
}

/// Parse `requirements.txt` — only `==` pinned versions are auditable.
fn parse_requirements_txt(content: &str, source: PathBuf) -> Vec<Package> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
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
                source_file: source.clone(),
            })
        })
        .collect()
}

/// Parse `go.sum` and return Go packages.
///
/// Format per line: `<module> <version>[/go.mod] <hash>`
///
/// Lines whose version field ends with `/go.mod` are module verification records
/// (not actual dependencies) and are skipped. Only one entry per module@version
/// is returned (the non-/go.mod line).
fn parse_go_sum(content: &str, source: PathBuf) -> Vec<Package> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                return None;
            }
            let mut fields = line.splitn(3, ' ');
            let module = fields.next()?.trim();
            let version = fields.next()?.trim();
            // Skip the /go.mod verification lines — they reference module metadata, not the module itself
            if version.ends_with("/go.mod") || module.is_empty() {
                return None;
            }
            Some(Package {
                name: module.to_string(),
                version: version.to_string(),
                ecosystem: "Go",
                source_file: source.clone(),
            })
        })
        .collect()
}

// ── Lock-file discovery ───────────────────────────────────────────────────────

/// Walk the entire directory tree and collect packages from ALL supported lock files.
///
/// Supported: `Cargo.lock`, `package-lock.json`, `requirements.txt`, `go.sum`
///
/// Unlike the old single-file detection, this walks the whole repo so monorepos
/// with multiple sub-projects are fully covered.
fn collect_all_lockfiles(root: &Path) -> Result<Vec<Package>> {
    let mut all: Vec<Package> = Vec::new();

    for entry in files::get_walker(root).filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip binary / unreadable files gracefully
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let pkgs: Vec<Package> = match file_name {
            "Cargo.lock" => parse_cargo_lock(&content, path.clone()),
            "package-lock.json" => parse_package_lock(&content, path.clone()),
            "requirements.txt" => parse_requirements_txt(&content, path.clone()),
            "go.sum" => parse_go_sum(&content, path.clone()),
            _ => continue,
        };

        if !pkgs.is_empty() {
            terminal::info(&format!(
                "Found {} package(s) in {}",
                pkgs.len(),
                path.display()
            ));
        }
        all.extend(pkgs);
    }

    Ok(all)
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
                source_file: pkg.source_file.clone(),
            });
        }
    }

    Ok(vulns)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_audit() -> Result<()> {
    let root = std::path::Path::new(".");

    // Walk the entire repo for all supported lock files
    let all_packages = collect_all_lockfiles(root)?;

    if all_packages.is_empty() {
        anyhow::bail!(
            "No supported lock files found. Supported: Cargo.lock, package-lock.json, requirements.txt, go.sum"
        );
    }

    terminal::info(&format!(
        "Found {} package entries across all lock files. Deduplicating...",
        all_packages.len()
    ));

    // Deduplicate by (name, version, ecosystem) — keeps first occurrence for source_file display
    let mut seen: HashSet<(String, String, &'static str)> = HashSet::new();
    let unique: Vec<&Package> = all_packages
        .iter()
        .filter(|p| seen.insert((p.name.clone(), p.version.clone(), p.ecosystem)))
        .collect();

    terminal::info(&format!(
        "Auditing {} unique package(s) via OSV...",
        unique.len()
    ));

    // Clone into owned Vec for chunked queries (query_osv takes &[Package])
    let to_query: Vec<Package> = unique
        .iter()
        .map(|p| Package {
            name: p.name.clone(),
            version: p.version.clone(),
            ecosystem: p.ecosystem,
            source_file: p.source_file.clone(),
        })
        .collect();

    // OSV batch API supports up to 1000 queries; chunk if needed
    let bar = terminal::create_progress_bar(1);
    bar.set_message("Querying OSV API...");

    let mut all_vulns: Vec<Vulnerability> = Vec::new();
    for chunk in to_query.chunks(1000) {
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
            "No known vulnerabilities found in {} unique package(s).",
            unique.len()
        ));
        return Ok(());
    }

    terminal::warn(&format!(
        "Found {} vulnerability/-ies across {} unique package(s):",
        all_vulns.len(),
        unique.len()
    ));
    for v in &all_vulns {
        eprintln!(
            "  [{}] {}@{} (from {}) — {}",
            v.vuln_id,
            v.package,
            v.version,
            v.source_file.display(),
            v.summary
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

    // ── Cargo.lock ─────────────────────────────────────────────────────────

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
        let pkgs = parse_cargo_lock(content, PathBuf::from("Cargo.lock"));
        assert!(pkgs.iter().any(|p| p.name == "anyhow" && p.version == "1.0.86"));
    }

    #[test]
    fn test_parse_cargo_lock_source_file_preserved() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let source = PathBuf::from("sub/project/Cargo.lock");
        let pkgs = parse_cargo_lock(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── package-lock.json ──────────────────────────────────────────────────

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
        let pkgs = parse_package_lock(content, PathBuf::from("package-lock.json"));
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "express" && p.version == "4.18.0"));
    }

    // ── requirements.txt ──────────────────────────────────────────────────

    #[test]
    fn test_parse_requirements_txt_pinned_only() {
        let content = "Django==4.2.0\nrequests>=2.28.0\nflask==2.3.2\n# comment\n";
        let pkgs = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "Django" && p.version == "4.2.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "2.3.2"));
    }

    #[test]
    fn test_parse_requirements_txt_skips_comments() {
        let content = "# this is a comment\n\nrequests==2.28.2\n";
        let pkgs = parse_requirements_txt(content, PathBuf::from("requirements.txt"));
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn test_parse_requirements_txt_source_file_preserved() {
        let content = "Django==4.2.0\n";
        let source = PathBuf::from("services/api/requirements.txt");
        let pkgs = parse_requirements_txt(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── go.sum ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_go_sum_basic() {
        let content = "\
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnzf3MoPlaT00ZchkJ6MB6SBSJ0+CY0s3f5E=\n\
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPGd8YAYS9Oks18D/DM3wRJQ9R0T2tZP4f+qSmfHfX4=\n\
golang.org/x/net v0.12.0 h1:something=\n\
";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        // /go.mod line must be skipped → 2 packages, not 3
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "github.com/gin-gonic/gin" && p.version == "v1.9.1"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "golang.org/x/net" && p.version == "v0.12.0"));
    }

    #[test]
    fn test_parse_go_sum_skips_go_mod_lines() {
        let content = "mod.example.com/foo v1.0.0/go.mod h1:abc=\n";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        assert!(pkgs.is_empty(), "version ending with /go.mod must be skipped");
    }

    #[test]
    fn test_parse_go_sum_ecosystem_is_go() {
        let content = "example.com/bar v2.1.0 h1:xyz=\n";
        let pkgs = parse_go_sum(content, PathBuf::from("go.sum"));
        assert!(!pkgs.is_empty());
        assert_eq!(pkgs[0].ecosystem, "Go");
    }

    #[test]
    fn test_parse_go_sum_empty() {
        let pkgs = parse_go_sum("", PathBuf::from("go.sum"));
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_go_sum_source_file_preserved() {
        let content = "github.com/foo/bar v1.0.0 h1:abc=\n";
        let source = PathBuf::from("subdir/go.sum");
        let pkgs = parse_go_sum(content, source.clone());
        assert_eq!(pkgs[0].source_file, source);
    }

    // ── Deduplication ──────────────────────────────────────────────────────

    #[test]
    fn test_deduplication_across_lockfiles() {
        // Same package appearing in two different lock files
        let pkgs = vec![
            Package {
                name: "anyhow".into(),
                version: "1.0.86".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("Cargo.lock"),
            },
            Package {
                name: "anyhow".into(),
                version: "1.0.86".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("subdir/Cargo.lock"),
            },
            Package {
                name: "serde".into(),
                version: "1.0.0".into(),
                ecosystem: "crates.io",
                source_file: PathBuf::from("Cargo.lock"),
            },
        ];

        let mut seen: HashSet<(String, String, &'static str)> = HashSet::new();
        let unique: Vec<_> = pkgs
            .iter()
            .filter(|p| seen.insert((p.name.clone(), p.version.clone(), p.ecosystem)))
            .collect();

        assert_eq!(unique.len(), 2, "anyhow should be deduplicated to one entry");
    }
}
