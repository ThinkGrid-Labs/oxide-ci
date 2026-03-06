use anyhow::{Context, Result};
use serde_json::json;

/// A parsed package entry used for SBOM generation.
struct SbomPackage {
    name: String,
    version: String,
    #[allow(dead_code)]
    ecosystem: &'static str,
    purl: String,
}

// ── Lock-file parsers ─────────────────────────────────────────────────────────

fn parse_cargo_lock(content: &str) -> Vec<SbomPackage> {
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
            let purl = format!("pkg:cargo/{}@{}", name, version);
            Some(SbomPackage {
                name,
                version,
                ecosystem: "crates.io",
                purl,
            })
        })
        .collect()
}

fn parse_package_lock(content: &str) -> Vec<SbomPackage> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(content) else {
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
            let purl = format!("pkg:npm/{}@{}", name, version);
            Some(SbomPackage {
                name,
                version,
                ecosystem: "npm",
                purl,
            })
        })
        .collect()
}

fn parse_requirements_txt(content: &str) -> Vec<SbomPackage> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            if let Some(idx) = line.find("==") {
                let name = line[..idx].trim().to_string();
                let version = line[idx + 2..].trim().to_string();
                let purl = format!("pkg:pypi/{}@{}", name.to_lowercase(), version);
                Some(SbomPackage {
                    name,
                    version,
                    ecosystem: "PyPI",
                    purl,
                })
            } else {
                None
            }
        })
        .collect()
}

fn parse_go_sum(content: &str) -> Vec<SbomPackage> {
    let mut seen = std::collections::HashSet::new();
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            let module = parts[0];
            let ver_raw = parts[1];
            // go.sum entries may have "/go.mod" suffix — skip those, keep the plain version
            if ver_raw.ends_with("/go.mod") {
                return None;
            }
            let version = ver_raw.trim_start_matches('v').to_string();
            if !seen.insert(format!("{}@{}", module, version)) {
                return None;
            }
            let purl = format!("pkg:golang/{}@{}", module, version);
            Some(SbomPackage {
                name: module.to_string(),
                version,
                ecosystem: "Go",
                purl,
            })
        })
        .collect()
}

// ── Lock-file detection ───────────────────────────────────────────────────────

const LOCK_FILES: &[(&str, &str)] = &[
    ("Cargo.lock", "cargo"),
    ("package-lock.json", "npm"),
    ("requirements.txt", "pypi"),
    ("go.sum", "go"),
];

fn detect_and_parse() -> Result<(Vec<SbomPackage>, String)> {
    for (filename, kind) in LOCK_FILES {
        if std::path::Path::new(filename).exists() {
            let content = std::fs::read_to_string(filename)
                .with_context(|| format!("Failed to read {}", filename))?;
            let packages = match *kind {
                "cargo" => parse_cargo_lock(&content),
                "npm" => parse_package_lock(&content),
                "pypi" => parse_requirements_txt(&content),
                "go" => parse_go_sum(&content),
                _ => Vec::new(),
            };
            return Ok((packages, filename.to_string()));
        }
    }
    anyhow::bail!(
        "No supported lock file found. Supported: Cargo.lock, package-lock.json, requirements.txt, go.sum"
    )
}

// ── CycloneDX output ──────────────────────────────────────────────────────────

pub fn run_sbom(output_file: Option<&str>) -> Result<()> {
    let (packages, source) = detect_and_parse()?;
    crate::utils::terminal::info(&format!(
        "Generating SBOM from {} ({} package(s))...",
        source,
        packages.len()
    ));

    let components: Vec<_> = packages
        .iter()
        .map(|p| {
            json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                "scope": "required"
            })
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:oxide-ci-{}", now),
        "version": 1,
        "metadata": {
            "timestamp": format_timestamp(now),
            "tools": [{
                "vendor": "ThinkGrid Labs",
                "name": "oxide-ci",
                "version": env!("CARGO_PKG_VERSION")
            }]
        },
        "components": components
    });

    let json_str = serde_json::to_string_pretty(&sbom)?;

    if let Some(path) = output_file {
        std::fs::write(path, &json_str)
            .with_context(|| format!("Failed to write SBOM to {}", path))?;
        crate::utils::terminal::success(&format!(
            "SBOM written to {} ({} components, CycloneDX 1.5).",
            path,
            packages.len()
        ));
    } else {
        println!("{}", json_str);
    }

    Ok(())
}

fn format_timestamp(unix: u64) -> String {
    // Simple ISO-8601 approximation without chrono dependency.
    // Computes YYYY-MM-DDTHH:MM:SSZ from a Unix timestamp.
    let secs = unix % 60;
    let mins = (unix / 60) % 60;
    let hours = (unix / 3600) % 24;
    let days_since_epoch = unix / 86400;

    // Days since Unix epoch → rough Gregorian date (good until 2100)
    let mut year: u64 = 1970;
    let mut days = days_since_epoch;
    loop {
        let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month: u64 = 1;
    for md in &month_days {
        if days < *md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}
