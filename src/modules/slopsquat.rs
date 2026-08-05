//! Slopsquat / hallucinated-package guard.
//!
//! The AI-era supply-chain attack: an LLM invents a plausible-sounding but
//! non-existent package name, an attacker registers it (a "slopsquat"), and a
//! coding agent installs it. Classic typosquat detection compares against a list
//! of popular names by edit distance — but a hallucinated name is often *novel*,
//! not close to any real package, so edit distance misses it entirely.
//!
//! This guard scores registry **metadata** instead: for a package that is being
//! newly introduced (not already pinned in the project's lock file), a genuine
//! dependency is usually old and widely downloaded, while a slopsquat is
//! brand-new and barely downloaded. Those signals — plus "does it exist at all"
//! — are ecosystem-agnostic, so the scoring is shared and only the metadata
//! fetch differs per registry (crates.io wired first; npm/PyPI slot in later).

/// Ecosystem-agnostic package facts pulled from a registry.
#[derive(Debug, Clone)]
pub struct PackageMeta {
    /// Whether the registry resolves the package at all.
    pub exists: bool,
    /// Days since the package was first published, if known.
    pub age_days: Option<u64>,
    /// Total downloads (adoption proxy), if known.
    pub downloads: Option<u64>,
    /// Whether the package declares a source repository.
    pub has_repository: bool,
}

/// Ordered so that `High > Medium > Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suspicion {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct SlopReport {
    pub package: String,
    pub suspicion: Suspicion,
    pub reasons: Vec<String>,
    /// Short tag for the finding class: "SLOPSQUAT" or "DEP-CONFUSION".
    pub kind: &'static str,
}

/// Tunable thresholds (surfaced via `[supply_chain]` in `.greengate.toml`).
pub struct SlopConfig {
    /// A package younger than this many days is treated as suspicious.
    pub min_age_days: u64,
    /// A package with fewer total downloads than this is treated as suspicious.
    pub min_downloads: u64,
}

/// Score a single package. **Pure** — no network, so it is fully unit-testable.
///
/// `in_lockfile` means the package is already pinned in the project (previously
/// vetted), which short-circuits to `Low`: we only scrutinise names an agent is
/// introducing for the first time.
pub fn score(pkg: &str, meta: &PackageMeta, in_lockfile: bool, cfg: &SlopConfig) -> SlopReport {
    let mut reasons: Vec<String> = Vec::new();

    if in_lockfile {
        return SlopReport {
            package: pkg.to_string(),
            suspicion: Suspicion::Low,
            reasons,
            kind: "SLOPSQUAT",
        };
    }

    // Resolves to nothing on the registry → most likely a pure hallucination.
    if !meta.exists {
        reasons.push("does not exist on the registry (possible hallucinated name)".to_string());
        return SlopReport {
            package: pkg.to_string(),
            suspicion: Suspicion::High,
            reasons,
            kind: "SLOPSQUAT",
        };
    }

    let mut points: u32 = 0;

    match meta.age_days {
        Some(age) if age < cfg.min_age_days => {
            points += 2;
            reasons.push(format!("registered {age} day(s) ago (very new)"));
        }
        _ => {}
    }

    match meta.downloads {
        Some(dl) if dl < cfg.min_downloads => {
            points += 1;
            reasons.push(format!("{dl} total download(s) (low adoption)"));
        }
        _ => {}
    }

    if !meta.has_repository {
        points += 1;
        reasons.push("no source repository declared".to_string());
    }

    // Context note (not itself a point) — clarifies why the package was checked.
    reasons.push("newly introduced — not present in your lock file".to_string());

    let suspicion = match points {
        0 => Suspicion::Low,
        1..=2 => Suspicion::Medium,
        _ => Suspicion::High,
    };

    SlopReport {
        package: pkg.to_string(),
        suspicion,
        reasons,
        kind: "SLOPSQUAT",
    }
}

/// A package name is "internal" when it matches one of the caller's declared
/// private-package patterns. Each pattern may be an exact name, an npm scope
/// (`@myco` → matches `@myco/anything`), or a `prefix-*` wildcard. Matching is
/// case-insensitive.
pub fn matches_internal(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    patterns.iter().any(|raw| {
        let p = raw.trim().to_ascii_lowercase();
        if let Some(prefix) = p.strip_suffix('*') {
            lower.starts_with(prefix)
        } else if p.starts_with('@') && !p.contains('/') {
            // Bare scope: match the scope root or anything under it.
            lower == p || lower.starts_with(&format!("{p}/"))
        } else {
            lower == p
        }
    })
}

// ── Registry metadata fetch ─────────────────────────────────────────────────

const USER_AGENT: &str =
    "greengate-supply-chain-gate (https://github.com/greengate-dev/greengate)";

/// Package registries the guard understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pypi,
}

impl Ecosystem {
    /// Short label used in gate output ("cargo" / "npm" / "pip").
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pip",
        }
    }
    /// Where a user should verify the real package name.
    pub fn registry_hint(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "https://crates.io",
            Ecosystem::Npm => "https://www.npmjs.com",
            Ecosystem::Pypi => "https://pypi.org",
        }
    }
}

enum Fetched {
    Json(serde_json::Value),
    NotFound,
    Unavailable,
}

/// GET a URL as JSON, distinguishing a definitive 404 from an "unavailable"
/// (network / transport / parse) outcome so the caller can fail **open** on the
/// latter — an offline or air-gapped install is never blocked by a hiccup.
fn get_json(url: &str) -> Fetched {
    match ureq::get(url).set("User-Agent", USER_AGENT).call() {
        Ok(resp) => match serde_json::from_reader(resp.into_reader()) {
            Ok(v) => Fetched::Json(v),
            Err(_) => Fetched::Unavailable,
        },
        Err(ureq::Error::Status(404, _)) => Fetched::NotFound,
        Err(_) => Fetched::Unavailable,
    }
}

fn not_found() -> PackageMeta {
    PackageMeta {
        exists: false,
        age_days: None,
        downloads: None,
        has_repository: false,
    }
}

/// Fetch metadata from the registry for `eco`. `Some(meta)` on a definitive
/// answer (including 404 → `exists: false`); `None` when unreachable (fail open).
pub fn fetch(eco: Ecosystem, name: &str) -> Option<PackageMeta> {
    match eco {
        Ecosystem::Cargo => fetch_crates(name),
        Ecosystem::Npm => fetch_npm(name),
        Ecosystem::Pypi => fetch_pypi(name),
    }
}

// crates.io — https://crates.io/api/v1/crates/<name>
fn parse_crates(v: &serde_json::Value) -> PackageMeta {
    let c = &v["crate"];
    PackageMeta {
        exists: true,
        age_days: c["created_at"].as_str().and_then(age_days_from_iso),
        downloads: c["downloads"].as_u64(),
        has_repository: c["repository"].as_str().is_some_and(|s| !s.is_empty()),
    }
}

pub fn fetch_crates(name: &str) -> Option<PackageMeta> {
    match get_json(&format!("https://crates.io/api/v1/crates/{name}")) {
        Fetched::Json(v) => Some(parse_crates(&v)),
        Fetched::NotFound => Some(not_found()),
        Fetched::Unavailable => None,
    }
}

// npm — https://registry.npmjs.org/<name>  (adoption via the downloads API)
fn parse_npm(v: &serde_json::Value) -> PackageMeta {
    PackageMeta {
        exists: true,
        age_days: v["time"]["created"].as_str().and_then(age_days_from_iso),
        downloads: None, // filled from the downloads API by fetch_npm
        has_repository: !v["repository"].is_null(),
    }
}

pub fn fetch_npm(name: &str) -> Option<PackageMeta> {
    let encoded = name.replace('/', "%2F"); // scoped @scope/name
    match get_json(&format!("https://registry.npmjs.org/{encoded}")) {
        Fetched::Json(v) => {
            let mut meta = parse_npm(&v);
            if let Fetched::Json(d) = get_json(&format!(
                "https://api.npmjs.org/downloads/point/last-year/{encoded}"
            )) {
                meta.downloads = d["downloads"].as_u64();
            }
            Some(meta)
        }
        Fetched::NotFound => Some(not_found()),
        Fetched::Unavailable => None,
    }
}

// PyPI — https://pypi.org/pypi/<name>/json  (adoption via pypistats)
fn parse_pypi(v: &serde_json::Value) -> PackageMeta {
    // Age = earliest upload across all release files (ISO strings sort chronologically).
    let mut earliest: Option<String> = None;
    if let Some(releases) = v["releases"].as_object() {
        for files in releases.values() {
            for f in files.as_array().into_iter().flatten() {
                let Some(t) = f["upload_time_iso_8601"]
                    .as_str()
                    .or_else(|| f["upload_time"].as_str())
                else {
                    continue;
                };
                if earliest.as_deref().is_none_or(|e| t < e) {
                    earliest = Some(t.to_string());
                }
            }
        }
    }
    let info = &v["info"];
    let has_repo = info["project_urls"]
        .as_object()
        .is_some_and(|m| !m.is_empty())
        || info["home_page"].as_str().is_some_and(|s| !s.is_empty());
    PackageMeta {
        exists: true,
        age_days: earliest.as_deref().and_then(age_days_from_iso),
        downloads: None,
        has_repository: has_repo,
    }
}

pub fn fetch_pypi(name: &str) -> Option<PackageMeta> {
    match get_json(&format!("https://pypi.org/pypi/{name}/json")) {
        Fetched::Json(v) => {
            let mut meta = parse_pypi(&v);
            let norm = name.to_lowercase().replace('_', "-");
            if let Fetched::Json(d) =
                get_json(&format!("https://pypistats.org/api/packages/{norm}/recent"))
            {
                meta.downloads = d["data"]["last_month"].as_u64();
            }
            Some(meta)
        }
        Fetched::NotFound => Some(not_found()),
        Fetched::Unavailable => None,
    }
}

// ── Orchestration (shared by every install wrapper) ──────────────────────────

/// Policy for a single install-wrapper pre-flight: slopsquat thresholds plus the
/// caller's declared internal-package patterns (for dependency-confusion).
pub struct GuardPolicy {
    pub slop: SlopConfig,
    /// Private package names/scopes/prefixes owned by the caller. When one of
    /// these *also* resolves on the public registry, that's a dependency-confusion
    /// risk. Empty = the confusion check is skipped entirely.
    pub internal_patterns: Vec<String>,
}

/// Screen every requested, non-allowlisted package. Two checks share one registry
/// lookup per package:
///
/// * **Dependency confusion** — an *internal* name (matches `internal_patterns`)
///   that also resolves on the public registry is HIGH risk.
/// * **Slopsquat** — an *external* name is scored on registry metadata.
///
/// Returns only actionable (non-`Low`) reports; warns and skips on an unreachable
/// registry (fail open).
pub fn guard(
    eco: Ecosystem,
    names: &[String],
    allow: &[String],
    in_lockfile: &dyn Fn(&str) -> bool,
    policy: &GuardPolicy,
) -> Vec<SlopReport> {
    let mut reports = Vec::new();
    for raw in names {
        let name = raw.trim();
        if name.is_empty() || allow.iter().any(|a| a.eq_ignore_ascii_case(name)) {
            continue;
        }
        let internal = matches_internal(name, &policy.internal_patterns);
        match fetch(eco, name) {
            Some(meta) if internal => {
                // Internal name present on the PUBLIC registry → confusion risk.
                if meta.exists {
                    reports.push(SlopReport {
                        package: name.to_string(),
                        suspicion: Suspicion::High,
                        reasons: vec![format!(
                            "declared internal, but '{name}' also resolves on the public {} registry — dependency-confusion risk",
                            eco.label()
                        )],
                        kind: "DEP-CONFUSION",
                    });
                }
            }
            Some(meta) => {
                let r = score(name, &meta, in_lockfile(name), &policy.slop);
                if r.suspicion != Suspicion::Low {
                    reports.push(r);
                }
            }
            None => crate::utils::terminal::warn(&format!(
                "supply-chain: {} registry unreachable — skipped guard for '{name}'",
                eco.label()
            )),
        }
    }
    reports
}

/// Print the gate output for `reports` and return how many are HIGH (blocking).
pub fn print_reports(eco: Ecosystem, reports: &[SlopReport]) -> usize {
    if reports.is_empty() {
        return 0;
    }
    eprintln!();
    eprintln!(
        "⚠️  Zero-Trust Supply Chain Gate ({}): {} package(s) flagged before install:",
        eco.label(),
        reports.len()
    );
    eprintln!();
    for r in reports {
        eprintln!(
            "  [{}] '{}' — {:?} suspicion",
            r.kind, r.package, r.suspicion
        );
        for reason in &r.reasons {
            eprintln!("       · {reason}");
        }
    }
    eprintln!();
    eprintln!(
        "  Verify the exact package at {} before installing — if an AI assistant suggested the name, double-check it exists and is the one you mean.",
        eco.registry_hint()
    );
    eprintln!();
    reports
        .iter()
        .filter(|r| r.suspicion == Suspicion::High)
        .count()
}

/// Extract explicitly-requested package names from an npm/yarn/pnpm/bun command.
/// Returns empty for lockfile installs (`npm ci`, bare `npm install`) — those
/// only touch already-pinned dependencies.
pub fn npm_packages_from_args(args: &[String]) -> Vec<String> {
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str());
    if !matches!(sub, Some("install" | "i" | "add")) {
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut skipped_sub = false;
    for a in args {
        if a.starts_with('-') {
            continue;
        }
        if !skipped_sub {
            skipped_sub = true; // drop the subcommand token itself
            continue;
        }
        names.push(strip_npm_version(a));
    }
    names
}

fn strip_npm_version(spec: &str) -> String {
    if let Some(rest) = spec.strip_prefix('@') {
        // scoped: @scope/name@version → @scope/name
        if let Some(slash) = rest.find('/') {
            let name_part = rest[slash + 1..].split('@').next().unwrap_or("");
            return format!("@{}/{}", &rest[..slash], name_part);
        }
        return spec.to_string();
    }
    spec.split('@').next().unwrap_or(spec).to_string()
}

// ── Date math (no external date dependency) ──────────────────────────────────

/// Days since the Unix epoch for a proleptic-Gregorian civil date.
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse a leading `YYYY-MM-DD` out of an ISO-8601 timestamp and return the
/// number of whole days between then and now (0 if the date is in the future or
/// unparseable-but-present).
fn age_days_from_iso(iso: &str) -> Option<u64> {
    let date = iso.split('T').next()?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let now_days = now_secs / 86_400;
    let created_days = days_from_civil(y, m, d);
    Some((now_days - created_days).max(0) as u64)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SlopConfig {
        SlopConfig {
            min_age_days: 90,
            min_downloads: 1000,
        }
    }

    #[test]
    fn nonexistent_package_is_high() {
        let meta = PackageMeta {
            exists: false,
            age_days: None,
            downloads: None,
            has_repository: false,
        };
        let r = score("totally-made-up-lib", &meta, false, &cfg());
        assert_eq!(r.suspicion, Suspicion::High);
        assert!(r.reasons.iter().any(|s| s.contains("does not exist")));
    }

    #[test]
    fn brand_new_and_low_downloads_is_high() {
        let meta = PackageMeta {
            exists: true,
            age_days: Some(6),
            downloads: Some(12),
            has_repository: true,
        };
        assert_eq!(
            score("fast-json-parser", &meta, false, &cfg()).suspicion,
            Suspicion::High
        );
    }

    #[test]
    fn brand_new_but_otherwise_ok_is_medium() {
        let meta = PackageMeta {
            exists: true,
            age_days: Some(10),
            downloads: Some(50_000),
            has_repository: true,
        };
        assert_eq!(
            score("newish", &meta, false, &cfg()).suspicion,
            Suspicion::Medium
        );
    }

    #[test]
    fn old_popular_package_is_low() {
        let meta = PackageMeta {
            exists: true,
            age_days: Some(3000),
            downloads: Some(500_000_000),
            has_repository: true,
        };
        assert_eq!(
            score("serde", &meta, false, &cfg()).suspicion,
            Suspicion::Low
        );
    }

    #[test]
    fn already_in_lockfile_is_trusted_even_if_new() {
        // A newly-registered package we've already vetted (it's pinned) is not re-flagged.
        let meta = PackageMeta {
            exists: true,
            age_days: Some(2),
            downloads: Some(1),
            has_repository: false,
        };
        assert_eq!(
            score("internal-crate", &meta, true, &cfg()).suspicion,
            Suspicion::Low
        );
    }

    #[test]
    fn age_days_from_iso_parses_and_is_nonnegative() {
        // A date far in the past yields a large positive age.
        let age = age_days_from_iso("2015-04-15T18:36:24.000000+00:00").unwrap();
        assert!(age > 3000, "expected a multi-thousand-day age, got {age}");
        // A far-future date clamps to 0 rather than going negative.
        assert_eq!(age_days_from_iso("2999-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn days_from_civil_epoch_reference() {
        // 1970-01-01 is day 0 of the Unix epoch.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    fn npm_join(a: &[&str]) -> String {
        npm_packages_from_args(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).join(",")
    }

    #[test]
    fn npm_arg_extraction() {
        assert_eq!(npm_join(&["install", "react"]), "react");
        assert_eq!(npm_join(&["i", "-D", "typescript"]), "typescript");
        assert_eq!(
            npm_join(&["add", "@scope/pkg@1.2", "lodash@4"]),
            "@scope/pkg,lodash"
        );
        // Lockfile installs and non-install subcommands name no packages.
        assert_eq!(npm_join(&["ci"]), "");
        assert_eq!(npm_join(&["install"]), "");
        assert_eq!(npm_join(&["run", "build"]), "");
    }

    #[test]
    fn parse_pypi_extracts_earliest_upload_and_repo() {
        let v = serde_json::json!({
            "info": { "project_urls": { "Source": "https://github.com/x/y" }, "home_page": "" },
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
                "0.1.0": [{"upload_time_iso_8601": "2015-06-15T00:00:00.000000Z"}]
            }
        });
        let m = parse_pypi(&v);
        assert!(m.exists && m.has_repository);
        assert!(m.age_days.unwrap() > 3000, "earliest release is 2015");
    }

    #[test]
    fn internal_pattern_matching() {
        let pats = vec![
            "@mycorp".to_string(),
            "acme-internal-utils".to_string(),
            "acme-secret-*".to_string(),
        ];
        assert!(matches_internal("@mycorp/logger", &pats)); // scope
        assert!(matches_internal("@MyCorp", &pats)); // scope root, case-insensitive
        assert!(matches_internal("acme-internal-utils", &pats)); // exact
        assert!(matches_internal("acme-secret-db", &pats)); // prefix wildcard
        assert!(!matches_internal("react", &pats));
        assert!(!matches_internal("@othercorp/x", &pats));
    }

    #[test]
    fn parse_npm_reads_created_and_repo() {
        let v = serde_json::json!({
            "time": { "created": "2011-09-05T00:00:00.000Z" },
            "repository": { "type": "git", "url": "git+https://github.com/x/y.git" }
        });
        let m = parse_npm(&v);
        assert!(m.exists && m.has_repository);
        assert!(m.age_days.unwrap() > 4000, "created in 2011");
    }
}
