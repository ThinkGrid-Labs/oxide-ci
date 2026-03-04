# OxideCI

> A blazing-fast, language-agnostic DevOps CLI built in Rust — secret scanning, Kubernetes linting, coverage gates, dependency auditing, web performance auditing, and React component regression detection in a single zero-dependency binary.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/ThinkGrid-Labs/oxide-ci/ci.yml?branch=main)](https://github.com/ThinkGrid-Labs/oxide-ci/actions)

---

## Table of Contents

- [Why OxideCI?](#why-oxideci)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [scan](#scan--secret--pii-scanning)
  - [lint](#lint--kubernetes-manifest-linting)
  - [coverage](#coverage--coverage-threshold-gate)
  - [audit](#audit--dependency-vulnerability-audit)
  - [install-hooks](#install-hooks--git-pre-commit-hook)
  - [lighthouse](#lighthouse--web-performance-audit)
  - [reassure](#reassure--react-component-performance-gate)
- [Secret Detection Patterns](#secret-detection-patterns)
- [Configuration File](#configuration-file-oxidecitorml)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)
- [React Native](#react-native)
- [Contributing](#contributing)

---

## Why OxideCI?

Most DevOps quality tools are either slow, require a runtime (Node, Python, Java), or solve only one problem. OxideCI packages five essential CI gates into a single compiled Rust binary:

| Problem | OxideCI command |
|---|---|
| Hardcoded secrets pushed to git | `oxide-ci scan` |
| Kubernetes manifests missing resource limits | `oxide-ci lint` |
| Test coverage silently dropping | `oxide-ci coverage` |
| Vulnerable dependencies shipping to production | `oxide-ci audit` |
| Secrets committed before anyone notices | `oxide-ci install-hooks` |
| Web Lighthouse score regressing between deploys | `oxide-ci lighthouse` |
| React component render performance regressing | `oxide-ci reassure` |

**Key advantages:**

- **Zero runtime dependencies** — drop a single binary into any CI pipeline, Docker image, or developer machine. No Node, Python, or JVM required.
- **Blazing fast** — parallel file scanning via `rayon` across all CPU cores. Typical repos scan in under a second.
- **Cloud-provider agnostic** — detects secrets across AWS, Azure, GCP, DigitalOcean, Alibaba Cloud, Stripe, GitHub, Twilio, and more.
- **gitignore-aware** — uses the `ignore` crate to automatically skip files in `.gitignore`, so you never scan `node_modules/` or `target/` by accident.
- **CI-native output** — `--format sarif` produces SARIF 2.1.0 output that GitHub Advanced Security displays as inline PR annotations with zero extra config.
- **Configurable** — a single `.oxideci.toml` file sets defaults for all commands; CLI flags always override it.

---

## Features

| Feature | Status |
|---|---|
| Secret & PII scanning (23 built-in patterns) | ✅ |
| Custom extra patterns via config | ✅ |
| Exclude paths via glob patterns | ✅ |
| Git diff / staged-only / full history scanning | ✅ |
| JSON & SARIF 2.1.0 output | ✅ |
| Kubernetes manifest linting (5 rules) | ✅ |
| LCOV coverage threshold gate | ✅ |
| Dependency audit via OSV API | ✅ |
| Git pre-commit hook installer | ✅ |
| Web performance audit via PageSpeed Insights | ✅ |
| React component performance gate (Reassure) | ✅ |
| `.oxideci.toml` config file | ✅ |
| Respects `.gitignore` | ✅ |

---

## Installation

### Recommended: Pre-compiled binary

**macOS (Apple Silicon / M1+):**
```bash
curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-macos-arm64 \
  -o /usr/local/bin/oxide-ci && chmod +x /usr/local/bin/oxide-ci
```

**macOS (Intel):**
```bash
curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-macos-amd64 \
  -o /usr/local/bin/oxide-ci && chmod +x /usr/local/bin/oxide-ci
```

**Linux (x64):**
```bash
curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
  -o /usr/local/bin/oxide-ci && chmod +x /usr/local/bin/oxide-ci
```

### Build from source (requires Rust 1.70+)
```bash
cargo install --git https://github.com/ThinkGrid-Labs/oxide-ci
```

### Verify installation
```
$ oxide-ci --version
oxide-ci 0.1.0

$ oxide-ci --help
A high-performance DevOps CLI tool in Rust

Usage: oxide-ci <COMMAND>

Commands:
  scan           Scans the current directory for hardcoded secrets and PII
  lint           Validates Kubernetes YAML manifests for resource limits and security issues
  coverage       Parses an LCOV coverage file and fails if total coverage is below threshold
  audit          Audits project dependencies for known vulnerabilities via the OSV database
  install-hooks  Installs oxide-ci as a git pre-commit hook
  lighthouse     Audits web performance via Google PageSpeed Insights (Lighthouse)
  reassure       Parses a Reassure performance report and gates on regressions
  help           Print this message or the help of the given subcommand(s)
```

---

## Quick Start

```bash
# Scan for secrets in current repo
oxide-ci scan

# Lint all Kubernetes YAML files
oxide-ci lint --dir ./k8s

# Enforce 80% minimum coverage
oxide-ci coverage --file coverage/lcov.info --min 80

# Audit dependencies for CVEs
oxide-ci audit

# Install as a git hook (runs on every commit)
oxide-ci install-hooks

# Gate on Lighthouse web performance scores
oxide-ci lighthouse --url https://yourapp.com

# Gate on React component performance regressions (after `reassure measure`)
oxide-ci reassure
```

---

## Commands

### `scan` — Secret & PII Scanning

Recursively scans every file in the current directory for hardcoded secrets, credentials, and PII using 20 built-in regex patterns. Respects `.gitignore` automatically.

```
oxide-ci scan [OPTIONS]

Options:
  --format <FORMAT>    Output format: text (default), json, sarif
  --staged             Only scan git-staged files (git diff --cached)
  --since <COMMIT>     Only scan files changed since the given commit
  -h, --help           Print help
```

**Examples:**

```bash
# Full scan, human-readable output
oxide-ci scan

# Only scan what you're about to commit (fast, perfect for pre-commit)
oxide-ci scan --staged

# Only scan files changed in the last commit
oxide-ci scan --since HEAD~1

# Output SARIF for GitHub Advanced Security PR annotations
oxide-ci scan --format sarif > results.sarif

# Output JSON for custom tooling
oxide-ci scan --format json | jq '.findings[].rule'
```

**Sample output (text):**
```
ℹ️  Starting secret and PII scan...
⚠️  Found 2 potential issue(s):
  - [AWS Access Key] src/config.rs:14
  - [GCP Service Account Key] credentials/service_account.json:3
Error: Scan failed: 2 secret(s)/PII found. Review the findings above.
```

**Sample output (`--format json`):**
```json
{
  "total": 2,
  "findings": [
    { "rule": "AWS Access Key", "file": "src/config.rs", "line": 14 },
    { "rule": "GCP Service Account Key", "file": "credentials/service_account.json", "line": 3 }
  ]
}
```

---

### `lint` — Kubernetes Manifest Linting

Validates Kubernetes workload YAML files (`Deployment`, `DaemonSet`, `StatefulSet`, `Job`, `CronJob`) against security and reliability best practices. Supports multi-document YAML files (`---` separator).

```
oxide-ci lint [OPTIONS]

Options:
  -d, --dir <DIR>    Directory to scan for Kubernetes manifests [default: . or lint.target_dir from config]
  -h, --help         Print help
```

**Rules enforced:**

| Rule ID | Description | Applies to |
|---|---|---|
| `no-latest-image` | Container image uses `:latest` tag or no tag at all | All workloads |
| `no-resource-limits` | `resources.limits` block is entirely missing | All workloads |
| `no-cpu-limit` | `resources.limits.cpu` is not set | All workloads |
| `no-memory-limit` | `resources.limits.memory` is not set | All workloads |
| `run-as-root` | `securityContext.runAsUser` is `0` | All workloads |
| `no-readiness-probe` | `readinessProbe` is not defined | Deployment, DaemonSet, StatefulSet |
| `no-liveness-probe` | `livenessProbe` is not defined | Deployment, DaemonSet, StatefulSet |

> **Note:** `Job` and `CronJob` are intentionally exempt from probe checks — they run to completion and don't need readiness/liveness probes.

**Examples:**

```bash
# Lint manifests in the current directory
oxide-ci lint

# Lint a specific directory
oxide-ci lint --dir ./infrastructure/k8s

# Use the target_dir from .oxideci.toml
oxide-ci lint
```

**Sample output:**
```
ℹ️  Linting Kubernetes manifests in './k8s'...
⚠️  Found 3 issue(s) across 2 file(s):
  [no-latest-image] k8s/api.yaml (container: api) — Image 'myapp:latest' uses an unpinned or :latest tag
  [no-memory-limit] k8s/api.yaml (container: api) — resources.limits.memory is not set
  [no-readiness-probe] k8s/worker.yaml (container: worker) — readinessProbe is not defined
Error: K8s lint failed: 3 issue(s) found.
```

**Example of a fully compliant manifest:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:1.4.2          # pinned tag
        resources:
          limits:
            cpu: "500m"             # cpu limit set
            memory: "256Mi"         # memory limit set
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
```

---

### `coverage` — Coverage Threshold Gate

Parses a standard LCOV coverage report and fails with exit code 1 if the total line coverage is below the specified minimum. Shows per-file breakdown of files below the threshold.

```
oxide-ci coverage [OPTIONS]

Options:
  -f, --file <FILE>    Path to the LCOV file [default: coverage/lcov.info or coverage.file from config]
  -m, --min <MIN>      Minimum coverage threshold percentage [default: 80 or coverage.min from config]
  -h, --help           Print help
```

**Examples:**

```bash
# Check coverage meets 80% (default)
oxide-ci coverage --file coverage/lcov.info

# Enforce a stricter 90% gate
oxide-ci coverage --file coverage/lcov.info --min 90

# Read defaults from .oxideci.toml
oxide-ci coverage
```

**Generating LCOV reports by language:**

```bash
# Rust (cargo-llvm-cov)
cargo llvm-cov --lcov --output-path coverage/lcov.info

# JavaScript / TypeScript (Jest)
jest --coverage --coverageReporters=lcov

# Python (pytest-cov)
pytest --cov=. --cov-report=lcov:coverage/lcov.info

# Go (go test)
go test ./... -coverprofile=coverage/lcov.info
```

**Sample output:**
```
ℹ️  Analyzing coverage file: coverage/lcov.info (threshold: 80.0%)

  Files below threshold (80.0%):
    61.2%  src/handlers/auth.rs
    72.4%  src/utils/parser.rs

⚠️  Coverage 74.8% is below threshold 80.0% (12 files, 748/1000 lines covered)
Error: Coverage gate failed: 74.8% < 80.0%
```

---

### `audit` — Dependency Vulnerability Audit

Automatically detects your project's lock file, parses all pinned dependencies, and queries the [OSV (Open Source Vulnerabilities)](https://osv.dev) database in a single batch request. Works with Rust, Node.js, and Python projects.

```
oxide-ci audit

Options:
  -h, --help    Print help
```

**Supported lock files (checked in order):**

| Lock file | Ecosystem | Notes |
|---|---|---|
| `Cargo.lock` | `crates.io` | All registry packages |
| `package-lock.json` | `npm` | v2/v3 format (`packages` map) |
| `requirements.txt` | `PyPI` | Only `==` pinned versions |

**Examples:**

```bash
# Rust project
oxide-ci audit

# Node.js project (auto-detected)
oxide-ci audit

# Python project (auto-detected)
oxide-ci audit
```

**Sample output:**
```
ℹ️  Auditing 312 packages from Cargo.lock (crates.io) via OSV...
⚠️  Found 2 vulnerability/-ies in 312 packages:
  [GHSA-jfh8-c2jp-hdmh] openssl@0.10.55 — Use-after-free in X.509 certificate verification
  [CVE-2023-26964]       h2@0.3.15 — Denial of Service via CONTINUATION frames
Error: Audit failed: 2 known vulnerability/-ies found.
```

> **Note:** The audit command requires internet access to reach `https://api.osv.dev`. On network errors it warns and exits 0, so it won't block CI pipelines with no outbound access.

---

### `install-hooks` — Git Pre-commit Hook

Installs oxide-ci as a git pre-commit hook that automatically runs `scan --staged` before every `git commit`, catching secrets before they ever reach the remote.

```
oxide-ci install-hooks [OPTIONS]

Options:
  --force    Overwrite an existing hook without prompting
  -h, --help Print help
```

**What it installs** (written to `.git/hooks/pre-commit`):
```sh
#!/bin/sh
# oxide-ci pre-commit hook (auto-installed)
# Scans only staged files for secrets and PII before every commit.
oxide-ci scan --staged
```

**Examples:**

```bash
# Install (safe — will not overwrite an existing hook)
oxide-ci install-hooks

# Overwrite an existing hook
oxide-ci install-hooks --force
```

**Sample output:**
```
✅ Pre-commit hook installed at /your/repo/.git/hooks/pre-commit
ℹ️  oxide-ci scan --staged will now run before every commit.
```

> **Tip:** Combine with `oxide-ci scan --staged` in CI for a two-layer defence: developers catch issues locally before pushing, and CI catches anything that slips through.

---

---

### `lighthouse` — Web Performance Audit

Fetches your deployed URL from the [Google PageSpeed Insights API v5](https://developers.google.com/speed/docs/insights/v5/get-started) (which runs a real Lighthouse audit server-side) and gates on scores for four categories: Performance, Accessibility, Best Practices, and SEO. No Node.js required — it's a pure HTTPS call via the same HTTP client used by `audit`.

```
oxide-ci lighthouse [OPTIONS]

Options:
  --url <URL>                  URL to audit (overrides config)
  --strategy <STRATEGY>        Device strategy: mobile (default) or desktop (overrides config)
  --min-performance <N>        Minimum Performance score 0–100 [default: 80]
  --min-accessibility <N>      Minimum Accessibility score 0–100 [default: 90]
  --min-best-practices <N>     Minimum Best Practices score 0–100 [default: 80]
  --min-seo <N>                Minimum SEO score 0–100 [default: 80]
  --key <KEY>                  Google PageSpeed Insights API key (overrides PAGESPEED_API_KEY env var)
  -h, --help                   Print help
```

**Examples:**

```bash
# Audit with default thresholds (mobile strategy)
oxide-ci lighthouse --url https://yourapp.com

# Desktop audit with a stricter performance threshold
oxide-ci lighthouse --url https://yourapp.com --strategy desktop --min-performance 90

# Use an API key for higher quota (unauthenticated quota: a few requests/day)
oxide-ci lighthouse --url https://yourapp.com --key AIza...

# Read URL and thresholds from .oxideci.toml
oxide-ci lighthouse
```

**API key:** The PageSpeed Insights API works without a key for occasional runs (development, infrequent CI). For production CI pipelines that run on every PR, create a free key in the [Google Cloud Console](https://console.cloud.google.com/apis/library/pagespeedonline.googleapis.com) and pass it via the `PAGESPEED_API_KEY` environment variable:

```bash
export PAGESPEED_API_KEY=AIza...
oxide-ci lighthouse --url https://yourapp.com
```

**Sample output:**
```
ℹ️  Running Lighthouse audit: https://yourapp.com (mobile)

  Performance:       87  ✅  (min: 80)
  Accessibility:     95  ✅  (min: 90)
  Best Practices:    75  ❌  (min: 80)
  SEO:               98  ✅  (min: 80)

Error: Lighthouse failed: 1 category/-ies below threshold.
```

**Configuration (`.oxideci.toml`):**

```toml
[lighthouse]
url = "https://yourapp.com"
strategy = "mobile"          # mobile | desktop
min_performance   = 80
min_accessibility = 90
min_best_practices = 80
min_seo = 80
# api_key = ""               # prefer PAGESPEED_API_KEY env var
```

> **Note:** `lighthouse` audits a live, publicly reachable URL. It is best placed in a post-deploy CI step, not in a PR build where the URL may not yet be reachable. For PR-level feedback, consider running it against a preview/staging URL.

---

### `reassure` — React Component Performance Gate

Parses the JSON performance report produced by [Reassure](https://github.com/callstack/reassure) (`reassure measure`) and fails CI if any component's mean render time regresses beyond a configurable threshold, or if the number of renders increases.

Reassure measures real component performance by running each test scenario many times (default 10 iterations × 5 runs). The output is a `.perf` JSON file that oxide-ci reads directly — no Node.js required at gate time.

```
oxide-ci reassure [OPTIONS]

Options:
  --current <PATH>    Path to current.perf file [default: output/current.perf]
  --baseline <PATH>   Path to baseline.perf file [default: output/baseline.perf]
  --threshold <N>     % mean-time increase allowed before failure [default: 15]
  -h, --help          Print help
```

**Typical CI workflow:**

```bash
# 1. In your frontend project, run Reassure to produce current.perf
npx reassure measure

# 2. Gate on regressions with oxide-ci
oxide-ci reassure

# 3. To compare against a saved baseline, first save it:
cp output/current.perf output/baseline.perf   # after a known-good run
# Then on subsequent runs, oxide-ci compares current vs baseline automatically
```

**Regression rules:**

| Condition | Result |
|---|---|
| `meanTime` increased by more than `threshold`% | ❌ fail |
| `renders` count increased vs baseline | ❌ fail |
| No `baseline.perf` found | Report-only (informational, no failure) |
| New component with no baseline entry | Listed as `new`, not flagged |

**Sample output (with baseline):**
```
ℹ️  Parsing Reassure report: output/current.perf
ℹ️  Baseline found: output/baseline.perf

  Component                                 Mean (ms)  Renders  Δ Mean     Δ Renders
  ────────────────────────────────────────────────────────────────────────────────────
  ProductList render                            15.4      2.3    +2.1%      ─
  HeavyList render                              42.1      3.0    +21.3% ❌  ─
  SearchBox render                               8.9      1.0    -5.2%      ─
  NewComponent render                            6.3      1.0    new        ─

Error: Reassure failed: 1 component(s) exceed the 15.0% regression threshold.
```

**Sample output (no baseline — report-only mode):**
```
ℹ️  Parsing Reassure report: output/current.perf
⚠️  Baseline file not found — running in report-only mode.

  Component                                 Mean (ms)  Renders
  ─────────────────────────────────────────────────────────────
  ProductList render                            15.4      2.3
  HeavyList render                              42.1      3.0
  SearchBox render                               8.9      1.0

ℹ️  No baseline provided — metrics reported above (no gating applied).
```

**Configuration (`.oxideci.toml`):**

```toml
[reassure]
current   = "output/current.perf"
baseline  = "output/baseline.perf"
threshold = 15.0               # % mean-time regression allowed
```

**Setting up Reassure in a React project:**

```bash
# Install
npm install --save-dev reassure

# Write a performance test (e.g. __perf__/ProductList.perf.tsx)
import { measureRenders } from 'reassure';
import { ProductList } from '../ProductList';

test('ProductList render', async () => {
  await measureRenders(<ProductList items={mockItems} />);
});

# Run measurement (generates output/current.perf)
npx reassure measure

# Then gate with oxide-ci
oxide-ci reassure --threshold 10
```

> **Tip:** Store `output/baseline.perf` in your repository (or as a CI artifact) after a confirmed good release. On every PR, oxide-ci compares the freshly measured `current.perf` against it and fails if performance has regressed.

## Secret Detection Patterns

OxideCI ships with 23 built-in patterns covering the most common cloud providers and services (including React Native / mobile-specific patterns). All patterns are applied per-line across every scanned file, and findings include the exact line number.

### AWS
| Rule ID | What it detects |
|---|---|
| `AWS Access Key` | IAM access key IDs (`AKIA…16 chars`) |
| `AWS Secret Key` | `aws_secret_access_key = …40 chars` in config files |

### Azure
| Rule ID | What it detects |
|---|---|
| `Azure Storage Connection String` | Full connection strings containing `DefaultEndpointsProtocol` + `AccountKey` |
| `Azure SAS Token` | Shared Access Signature URLs containing `sv=20XX-XX-XX` + `&sig=` |

### GCP / Google Cloud
| Rule ID | What it detects |
|---|---|
| `Google API Key` | Browser/server API keys (`AIza…35 chars`) |
| `GCP Service Account Key` | Service account JSON files (`"type": "service_account"`) |
| `GCP OAuth2 Token` | Short-lived access tokens (`ya29.…`) |

### DigitalOcean
| Rule ID | What it detects |
|---|---|
| `DigitalOcean PAT` | Personal access tokens (`dop_v1_…64 chars`) |

### Alibaba Cloud
| Rule ID | What it detects |
|---|---|
| `Alibaba Cloud Access Key ID` | Access key IDs (`LTAI…14-20 chars`) |

### GitHub
| Rule ID | What it detects |
|---|---|
| `GitHub PAT (classic)` | Classic personal access tokens (`ghp_…36 chars`) |
| `GitHub PAT (fine-grained)` | Fine-grained personal access tokens (`github_pat_…82 chars`) |

### Communication & Payments
| Rule ID | What it detects |
|---|---|
| `Slack Webhook` | Incoming webhook URLs (`hooks.slack.com/services/…`) |
| `Stripe Secret Key` | Live secret keys (`sk_live_…24 chars`) |
| `Stripe Publishable Key` | Live publishable keys (`pk_live_…24 chars`) |
| `SendGrid API Key` | API keys (`SG.22chars.43chars`) |
| `Mailgun API Key` | API keys (`key-…32 chars`) |
| `Twilio Account SID` | Account SIDs (`AC` + 32 lowercase hex chars) |

### Infrastructure
| Rule ID | What it detects |
|---|---|
| `HashiCorp Vault Token` | Service tokens (`hvs.…90+ chars`) |
| `PEM Private Key` | RSA, EC, DSA, OPENSSH private key headers |
| `JWT Token` | Three-part base64url tokens (`eyJ…`) |

### React Native / Mobile
| Rule ID | What it detects |
|---|---|
| `Expo Access Token` | EAS CLI robot/personal tokens (`expa_…40+ chars`) |
| `Sentry DSN` | Error reporting DSNs (ingest.sentry.io format) |
| `Mapbox Secret Token` | Secret tokens (`sk.eyJ…`); public tokens (`pk.eyJ…`) are not flagged |

### PII
| Rule ID | What it detects |
|---|---|
| `Generic PII (SSN)` | US Social Security Numbers (`XXX-XX-XXXX`) |
| `Generic PII (Email)` | Email addresses |

### Adding custom patterns

Use `extra_patterns` in `.oxideci.toml` to add your own patterns without forking:

```toml
[scan]
extra_patterns = [
  { name = "Internal API Token", regex = "myapp_[a-z0-9]{32}" },
  { name = "Database URL",       regex = "postgres://[^@]+@[^/]+" },
]
```

---

## Configuration File (`.oxideci.toml`)

Place `.oxideci.toml` in the root of your repository. CLI flags always override config file values.

```toml
[scan]
# Glob patterns for paths to skip during scanning
exclude_patterns = [
  "tests/**",
  "*.test.ts",
  "fixtures/**",
  "vendor/**",
]

# Extra patterns on top of the 20 built-ins
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
]

# Shannon entropy detection (flags high-entropy tokens like unrecognized API keys)
entropy = true
entropy_threshold = 4.5    # lower = more sensitive
entropy_min_length = 20    # ignore tokens shorter than this

[coverage]
# Default LCOV file path (overridden by --file)
file = "coverage/lcov.info"
# Default minimum threshold (overridden by --min)
min = 85.0

[lint]
# Default directory to scan for Kubernetes manifests (overridden by --dir)
target_dir = "./infrastructure/k8s"

[lighthouse]
# URL of the deployed app to audit (overridden by --url)
url = "https://yourapp.com"
# Device strategy: mobile (default) or desktop (overridden by --strategy)
strategy = "mobile"
# Per-category minimum scores 0–100 (overridden by --min-* flags)
min_performance   = 80
min_accessibility = 90
min_best_practices = 80
min_seo = 80
# API key (optional; prefer PAGESPEED_API_KEY env var)
# api_key = ""

[reassure]
# Path to Reassure current measurement file (overridden by --current)
current = "output/current.perf"
# Path to Reassure baseline file (overridden by --baseline)
# If absent, oxide-ci runs in report-only mode (no failure)
baseline = "output/baseline.perf"
# Maximum mean-time regression % before failing (overridden by --threshold)
threshold = 15.0
```

All fields are optional. Omitted values fall back to safe defaults. CLI flags always take precedence over config file values.

---

## Output Formats

The `scan` command supports three output formats via `--format`:

### `text` (default)
Human-readable output to stderr. Progress bar shows scan progress. Findings include file path and line number.

```bash
oxide-ci scan
```

### `json`
Machine-readable JSON written to stdout. Status messages and progress go to stderr (clean separation for piping).

```bash
oxide-ci scan --format json
oxide-ci scan --format json | jq '.findings[] | select(.rule | startswith("AWS"))'
```

```json
{
  "total": 1,
  "findings": [
    {
      "rule": "AWS Access Key",
      "file": "./src/config.rs",
      "line": 42
    }
  ]
}
```

### `sarif`
SARIF 2.1.0 JSON written to stdout. Upload directly to GitHub Advanced Security for inline PR annotations.

```bash
oxide-ci scan --format sarif > results.sarif
```

In GitHub Actions:
```yaml
- name: Secret Scan
  run: oxide-ci scan --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed — safe to proceed |
| `1` | Check failed (secrets found, lint issues, coverage below threshold, vulnerabilities detected) or tool error |

> CI pipelines can rely on the exit code directly — no parsing required.

---

## CI/CD Integration

### GitHub Actions — Full pipeline

```yaml
name: OxideCI Quality Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  # ── Security & code-quality gates ──────────────────────────────────────────
  oxide-ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OxideCI
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
            -o /usr/local/bin/oxide-ci
          chmod +x /usr/local/bin/oxide-ci

      - name: Secret & PII Scan
        run: oxide-ci scan

      - name: Secret Scan (SARIF for PR annotations)
        run: oxide-ci scan --format sarif > results.sarif
        if: always()
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
        continue-on-error: true

      - name: Kubernetes Lint
        run: oxide-ci lint --dir ./k8s

      - name: Coverage Gate
        run: oxide-ci coverage --file coverage/lcov.info --min 80

      - name: Dependency Audit
        run: oxide-ci audit

  # ── Performance gates (post-deploy) ────────────────────────────────────────
  # Run after deployment so the URL is live and Reassure has produced output/.
  perf:
    runs-on: ubuntu-latest
    # needs: [deploy]    # uncomment and set your deploy job name
    steps:
      - uses: actions/checkout@v4

      - name: Install OxideCI
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
            -o /usr/local/bin/oxide-ci
          chmod +x /usr/local/bin/oxide-ci

      # Lighthouse — gates on PageSpeed scores for the deployed URL.
      # Set LIGHTHOUSE_URL as a repository variable (Settings → Variables).
      # Set PAGESPEED_API_KEY as a repository secret for higher quota.
      - name: Lighthouse audit
        if: ${{ vars.LIGHTHOUSE_URL != '' }}
        env:
          PAGESPEED_API_KEY: ${{ secrets.PAGESPEED_API_KEY }}
        run: |
          oxide-ci lighthouse \
            --url "${{ vars.LIGHTHOUSE_URL }}" \
            --strategy mobile \
            --min-performance 80 \
            --min-accessibility 90

      # Reassure — gates on React component render regressions.
      # Your frontend test job should run `reassure measure` and upload
      # output/current.perf as an artifact, then download it here.
      - name: Download Reassure report
        uses: actions/download-artifact@v4
        with:
          name: reassure-report
          path: output/
        continue-on-error: true   # skip gracefully if artifact not found

      - name: Reassure performance gate
        if: hashFiles('output/current.perf') != ''
        run: oxide-ci reassure --threshold 15
```

### GitLab CI

```yaml
stages:
  - security
  - quality

variables:
  OXIDE_CI_URL: https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64

.install_oxide: &install_oxide
  before_script:
    - curl -sL $OXIDE_CI_URL -o /usr/local/bin/oxide-ci
    - chmod +x /usr/local/bin/oxide-ci

secret-scan:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci scan

k8s-lint:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci lint --dir ./k8s

coverage-gate:
  stage: quality
  <<: *install_oxide
  script:
    - oxide-ci coverage --file coverage/lcov.info --min 80

dependency-audit:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci audit
  allow_failure: true  # optional: don't block pipeline on network issues
```

### Bitbucket Pipelines

```yaml
image: ubuntu:22.04

pipelines:
  default:
    - step:
        name: OxideCI Security & Quality Gates
        script:
          - apt-get update -qq && apt-get install -y curl
          - curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64
              -o /usr/local/bin/oxide-ci
          - chmod +x /usr/local/bin/oxide-ci
          - oxide-ci scan
          - oxide-ci lint --dir ./k8s
          - oxide-ci coverage --file coverage/lcov.info --min 80
          - oxide-ci audit
```

### CircleCI

```yaml
version: 2.1

jobs:
  oxide-ci:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install OxideCI
          command: |
            curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
              -o /usr/local/bin/oxide-ci
            chmod +x /usr/local/bin/oxide-ci
      - run:
          name: Secret Scan
          command: oxide-ci scan
      - run:
          name: Kubernetes Lint
          command: oxide-ci lint --dir ./k8s
      - run:
          name: Coverage Gate
          command: oxide-ci coverage --file coverage/lcov.info --min 80
      - run:
          name: Dependency Audit
          command: oxide-ci audit

workflows:
  quality:
    jobs:
      - oxide-ci
```

### Pre-commit (local enforcement)

The fastest way to enforce secrets scanning locally — runs automatically on every `git commit`:

```bash
oxide-ci install-hooks
```

To remove the hook:
```bash
rm .git/hooks/pre-commit
```

---

## Architecture

```
oxide-ci/
├── src/
│   ├── main.rs                  # CLI entry point (clap)
│   ├── modules/
│   │   ├── scanner.rs           # Secret/PII scanning (rayon parallel)
│   │   ├── k8s_lint.rs          # Kubernetes manifest linter (serde_yaml)
│   │   ├── coverage.rs          # LCOV parser and threshold gate
│   │   ├── audit.rs             # OSV dependency audit (ureq)
│   │   ├── hooks.rs             # Git hook installer
│   │   ├── perf_lighthouse.rs   # PageSpeed Insights Lighthouse gate (ureq)
│   │   └── reassure.rs          # Reassure .perf report parser and gate
│   └── utils/
│       ├── config.rs            # .oxideci.toml loader (toml + serde)
│       ├── files.rs             # File walker (ignore crate)
│       └── terminal.rs          # Styled output + progress bars (indicatif)
└── tests/
    └── integration_test.rs      # End-to-end binary tests
```

**Dependencies:**

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `rayon` | CPU-bound parallelism (file scanning) |
| `ignore` | gitignore-aware file walking |
| `regex` | Secret pattern matching |
| `serde` + `serde_json` | JSON output (SARIF, audit) |
| `serde_yaml` | Kubernetes YAML parsing |
| `toml` | Config file parsing |
| `ureq` | HTTP client for OSV audit API |
| `indicatif` | Progress bars |
| `anyhow` | Error handling and propagation |

---

## React Native

oxide-ci works with React Native and Expo projects out of the box. npm, Yarn, and pnpm lock files are all supported for dependency auditing, and Reassure — which was originally built *for* React Native by Callstack — is a first-class citizen.

### Command compatibility

| Command | React Native support | Notes |
|---|---|---|
| `scan` | ✅ Full | Detects secrets in JS/TS, config files, and CI YAML; gitignore-aware (skips `node_modules/` automatically) |
| `audit` | ✅ Full | Reads `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`; queries OSV for npm CVEs |
| `coverage` | ✅ Full | Reads Jest LCOV output (`--coverageReporters=lcov`) |
| `install-hooks` | ✅ Full | Pre-commit hook works in any git repo |
| `reassure` | ✅ Full | Built for React Native; parses `output/current.perf` from `reassure measure` |
| `lint` | ⚠️ Optional | Only useful if the project has a Kubernetes backend |
| `lighthouse` | ⚠️ Web only | Audits a public URL; applicable if you ship a React Native Web build or marketing site |

> **Note on Bun:** `bun.lockb` is a binary format that oxide-ci cannot parse. If you use Bun, run `bun install --save-text-lockfile` to generate a `bun.lock` text file alongside it, or use the `package-lock.json` fallback (`bun install --backend=npm`).

---

### Recommended `.oxideci.toml` for React Native

```toml
[scan]
exclude_patterns = [
    # Build artifacts
    "android/build/**",
    "android/.gradle/**",
    "ios/build/**",
    "ios/Pods/**",
    # Expo cache and generated files
    ".expo/**",
    ".expo-shared/**",
    # Metro bundler cache
    ".metro-cache/**",
    # Test fixtures that intentionally contain fake patterns
    "__tests__/**",
    "__mocks__/**",
    # React Native generated
    "android/app/src/main/assets/index.android.bundle",
]

# Shannon entropy catches random API keys not matched by explicit rules.
# Tune down min_length for shorter RN-style tokens.
entropy = true
entropy_threshold = 4.5
entropy_min_length = 20

[coverage]
file = "coverage/lcov.info"
min = 80.0

[reassure]
current  = "output/current.perf"
baseline = "output/baseline.perf"
threshold = 15.0   # % mean render-time regression allowed
```

---

### React Native–specific secrets now detected

In addition to the 20 built-in cloud patterns, oxide-ci detects these patterns common in RN projects:

| Rule | What it detects |
|---|---|
| `Expo Access Token` | EAS CLI robot/personal tokens (`expa_…`) |
| `Sentry DSN` | Sentry error-reporting DSNs (quota exhaustion + event read risk) |
| `Mapbox Secret Token` | Mapbox secret tokens (`sk.eyJ…`); public tokens (`pk.eyJ…`) are not flagged |
| `Google API Key` | Firebase API keys (`AIza…`) — same prefix as GCP, already built-in |
| `GCP Service Account Key` | `google-services.json` leaks — already built-in |

---

### GitHub Actions — React Native pipeline

```yaml
name: React Native CI

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install oxide-ci
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
            -o /usr/local/bin/oxide-ci
          chmod +x /usr/local/bin/oxide-ci

      - name: Secret & PII scan
        run: oxide-ci scan

      - name: Dependency audit (npm CVEs via OSV)
        run: oxide-ci audit   # reads package-lock.json / yarn.lock / pnpm-lock.yaml

      - name: Coverage gate
        run: oxide-ci coverage   # reads coverage/lcov.info (generated by jest --coverage)

  perf:
    runs-on: ubuntu-latest
    needs: quality
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install dependencies
        run: yarn install --frozen-lockfile

      - name: Run Reassure measurement
        run: npx reassure measure
        # Produces output/current.perf

      - name: Install oxide-ci
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
            -o /usr/local/bin/oxide-ci
          chmod +x /usr/local/bin/oxide-ci

      - name: Reassure performance gate
        run: oxide-ci reassure --threshold 15
        # Fails if any component regresses > 15% vs baseline.perf
```

---

## Contributing

OxideCI is open source under the [MIT License](LICENSE). Contributions are welcome.

**Adding a new secret pattern:**

1. Add a `(&str, &str)` tuple to `BUILTIN_PATTERNS` in [src/modules/scanner.rs](src/modules/scanner.rs) inside the appropriate cloud provider section
2. Add a matching `#[test]` for both a positive match and a false-positive check
3. Run `cargo test` to verify

**Adding a new lint rule:**

1. Add a check in `check_manifest()` in [src/modules/k8s_lint.rs](src/modules/k8s_lint.rs)
2. Add a unit test in the `#[cfg(test)]` block

**Running tests:**

```bash
cargo test          # all unit + integration tests
cargo test scanner  # only scanner tests
cargo clippy        # lint
```

**Issues & feature requests:** [github.com/ThinkGrid-Labs/oxide-ci/issues](https://github.com/ThinkGrid-Labs/oxide-ci/issues)
