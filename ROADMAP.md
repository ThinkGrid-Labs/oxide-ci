# OxideCI Roadmap

This document tracks planned features by release milestone.
Completed items are checked off; upcoming items describe the intended behaviour.

---

## v0.2.0 — Smarter Scanning ✅

All features below are shipped in this release.

- [x] **Shannon Entropy Detection** — Identifies high-entropy tokens (base64/hex) that don't match any named pattern but are statistically likely to be secrets. Configurable threshold and minimum token length via `.oxideci.toml`.
- [x] **Git History Scan** (`oxide-ci scan --history`) — Runs `git log --all -p` and scans every added line across the full commit history. Secrets that were committed and later deleted are surfaced with their commit hash.
- [x] **Inline Suppression** (`# oxide-ci: ignore`) — Mark any line with `# oxide-ci: ignore` or `// oxide-ci: ignore` to silently skip it. Works for both regex and entropy findings.
- [x] **Multi-lock-file Audit** — Walks the entire repository tree instead of stopping at the first lock file found. Monorepos with multiple sub-projects are fully audited in one pass.
- [x] **Go Module Support** — Parses `go.sum` files and queries the OSV `Go` ecosystem for known CVEs. Skips `/go.mod` verification lines automatically.
- [x] **yarn.lock support** — Parses both Yarn v1 (classic) and v2/v3 (Berry) lock formats. Scoped packages (`@babel/core`) and multi-specifier entries handled. Workspace/link/file dependencies skipped.
- [x] **pnpm-lock.yaml support** — Parses pnpm v5–v9 lock formats. Handles leading-slash keys (v5–v8), plain keys (v9), scoped packages, and peer-dep version suffixes. Only the `packages:` section is read; `snapshots:` is ignored.

---

## v0.3.0 — Depth and Breadth

### Secret Scanning
- **Allowlist / Baseline** — Persist accepted findings to `.oxideci-baseline.json`. Only *new* findings (not in the baseline) fail CI, enabling gradual remediation without blocking deployments.
- **SARIF `suppressions` array** — Emit suppressed findings with a `suppressionKind: "inSource"` annotation so GitHub Advanced Security shows them as suppressed rather than missing.
- **Config schema validation** — Emit a clear error when `.oxideci.toml` has unknown keys instead of silently ignoring them.

### Output Formats
- **JUnit XML** (`--format junit`) — Output compatible with Jenkins, GitLab CI test reports, and most CI dashboards.

### Dependency Audit
- **Python `poetry.lock`** — Parse Poetry's TOML-based lock format for the PyPI ecosystem.
- **Ruby `Gemfile.lock`** — Parse Bundler lock files for the RubyGems ecosystem.
- **Maven support** — Parse `pom.xml` (via `mvn dependency:list` output) for the Maven ecosystem.
- **`audit --json`** — Machine-readable vulnerability output, mirroring `scan --format json`.

### K8s Linting
- **Additional rules** — `privileged: true` containers, `hostNetwork: true`, `hostPath` volume mounts, deprecated API versions (`extensions/v1beta1`, etc.), missing `NetworkPolicy`.

---

## v1.0.0 — Production Hardening

### Performance
- **Incremental cache** — Store scan results in `.oxideci-cache/` keyed by file content hash. Unchanged files are skipped entirely, dramatically speeding up repeat scans on large repos.

### Extensibility
- **Plugin system** — Load external `.so`/`.dylib` pattern packs at runtime (e.g., for organisation-specific token formats) without forking or recompiling oxide-ci.

### Compliance
- **SBOM export** — Generate a CycloneDX or SPDX Software Bill of Materials from discovered lock files. Satisfies EO-14028 and emerging EU CRA requirements.

### Deployment
- **Windows native CI** — Validated on `windows-latest` runners. Hooks use PowerShell equivalents where Unix permissions APIs are unavailable.
- **Configurable OSV endpoint** (`audit.osv_url` in config) — Point at a self-hosted OSV mirror for air-gapped environments.
- **Authenticated OSV API** — Optional API key for higher OSV rate limits in large monorepo scans.

### Usability
- **Severity filtering** (`--min-severity critical|high|medium`) — Filter audit output to only fail CI on vulnerabilities at or above a given CVSS severity.
- **Per-finding remediation hints** — Surface the fixed version (from OSV `affected[].ranges[].fixed`) alongside each vulnerability.
