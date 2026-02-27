# OxideCI

> A blazing-fast, language-agnostic DevOps CLI built in Rust — secret scanning, Kubernetes linting, coverage gates, dependency auditing, and more in a single zero-dependency binary.

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
- [Secret Detection Patterns](#secret-detection-patterns)
- [Configuration File](#configuration-file-oxidecitorml)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)
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
| Secret & PII scanning (20 built-in patterns) | ✅ |
| Custom extra patterns via config | ✅ |
| Exclude paths via glob patterns | ✅ |
| Git diff / staged-only scanning | ✅ |
| JSON & SARIF 2.1.0 output | ✅ |
| Kubernetes manifest linting (5 rules) | ✅ |
| LCOV coverage threshold gate | ✅ |
| Dependency audit via OSV API | ✅ |
| Git pre-commit hook installer | ✅ |
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

## Secret Detection Patterns

OxideCI ships with 20 built-in patterns covering the most common cloud providers and services. All patterns are applied per-line across every scanned file, and findings include the exact line number.

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

[coverage]
# Default LCOV file path (overridden by --file)
file = "coverage/lcov.info"
# Default minimum threshold (overridden by --min)
min = 85.0

[lint]
# Default directory to scan for Kubernetes manifests (overridden by --dir)
target_dir = "./infrastructure/k8s"
```

All fields are optional. Omitted values fall back to their defaults.

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

jobs:
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
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Kubernetes Lint
        run: oxide-ci lint --dir ./k8s

      - name: Coverage Gate
        run: oxide-ci coverage --file coverage/lcov.info --min 80

      - name: Dependency Audit
        run: oxide-ci audit
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
│   ├── main.rs               # CLI entry point (clap)
│   ├── modules/
│   │   ├── scanner.rs        # Secret/PII scanning (rayon parallel)
│   │   ├── k8s_lint.rs       # Kubernetes manifest linter (serde_yaml)
│   │   ├── coverage.rs       # LCOV parser and threshold gate
│   │   ├── audit.rs          # OSV dependency audit (ureq)
│   │   └── hooks.rs          # Git hook installer
│   └── utils/
│       ├── config.rs         # .oxideci.toml loader (toml + serde)
│       ├── files.rs          # File walker (ignore crate)
│       └── terminal.rs       # Styled output + progress bars (indicatif)
└── tests/
    └── integration_test.rs   # End-to-end binary tests
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
