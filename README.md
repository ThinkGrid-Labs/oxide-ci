# OxideCI — Rust DevOps CLI: Secret Scanner, AST SAST, Kubernetes Linter & CI Quality Gates

> A blazing-fast DevOps CLI built in Rust — secret scanning, AST-based SAST for JS/TS/Python/Go, Kubernetes linting, Dockerfile linting, coverage gates, dependency auditing with offline cache, web performance auditing, React component regression detection, CycloneDX SBOM generation, scan baselines, a pipeline runner, config profiles, and an interactive setup wizard — in a single zero-dependency binary.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/ThinkGrid-Labs/oxide-ci/ci.yml?branch=main)](https://github.com/ThinkGrid-Labs/oxide-ci/actions)
[![GitHub release](https://img.shields.io/github/v/release/ThinkGrid-Labs/oxide-ci)](https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/oxide-ci)](https://crates.io/crates/oxide-ci)
[![Downloads](https://img.shields.io/crates/d/oxide-ci)](https://crates.io/crates/oxide-ci)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)](https://www.rust-lang.org)
[![GitHub Stars](https://img.shields.io/github/stars/ThinkGrid-Labs/oxide-ci?style=social)](https://github.com/ThinkGrid-Labs/oxide-ci/stargazers)

---

## Table of Contents

- [Why OxideCI?](#why-oxideci)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [scan](#scan--secret--pii-scanning)
    - [SAST for JS/TS/Python/Go](#sast-static-analysis-for-jstspythongo)
    - [GitHub Annotations](#github-check-run-annotations---annotate)
    - [Baseline mode](#baseline-mode---update-baseline--since-baseline)
  - [lint](#lint--kubernetes-manifest-linting)
  - [docker-lint](#docker-lint--dockerfile-linting)
  - [coverage](#coverage--coverage-threshold-gate)
  - [audit](#audit--dependency-vulnerability-audit)
  - [install-hooks](#install-hooks--git-pre-commit-hook)
  - [lighthouse](#lighthouse--web-performance-audit)
  - [reassure](#reassure--react-component-performance-gate)
  - [sbom](#sbom--sbom-generation)
  - [check-config](#check-config--validate-configuration)
  - [init](#init--interactive-setup-wizard)
  - [watch](#watch--live-file-watcher)
  - [run](#run--pipeline-runner)
- [Secret Detection Patterns](#secret-detection-patterns)
- [SAST Rules Reference](#sast-rules-reference)
- [Suppressing Findings](#suppressing-findings)
- [Configuration File](#configuration-file-oxidecitorml)
- [Config Profiles](#config-profiles)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)
- [React Native](#react-native)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Why OxideCI?

Most DevOps quality tools are either slow, require a runtime (Node, Python, Java), or solve only one problem. OxideCI packages essential CI gates into a single compiled Rust binary:

| Problem | OxideCI command |
|---|---|
| Hardcoded secrets pushed to git | `oxide-ci scan` |
| XSS, eval, command injection in JS/TS/Python/Go | `oxide-ci scan` (SAST) |
| Kubernetes manifests missing resource limits | `oxide-ci lint` |
| Dockerfile best-practice violations | `oxide-ci docker-lint` |
| Test coverage silently dropping | `oxide-ci coverage` |
| Vulnerable dependencies shipping to production | `oxide-ci audit` |
| Secrets committed before anyone notices | `oxide-ci install-hooks` |
| Web Lighthouse score regressing between deploys | `oxide-ci lighthouse` |
| React component render performance regressing | `oxide-ci reassure` |
| Existing findings flooding CI noise | `oxide-ci scan --since-baseline` |
| Unknown who introduced a secret | `oxide-ci scan --blame` |
| Need an SBOM for compliance | `oxide-ci sbom` |
| Config file has a syntax error | `oxide-ci check-config` |
| Running all gates with one command | `oxide-ci run` |
| Getting started without reading docs | `oxide-ci init` |

**Key advantages:**

- **Zero runtime dependencies** — drop a single binary into any CI pipeline, Docker image, or developer machine. No Node, Python, or JVM required.
- **Blazing fast** — parallel file scanning via `rayon` across all CPU cores. Typical repos scan in under a second.
- **AST-based SAST** — tree-sitter parses JS/TS/TSX/JSX/Python/Go into a real AST before pattern matching. Secrets are only flagged when they appear inside string literals, eliminating comment noise and false positives.
- **Cloud-provider agnostic** — detects secrets across AWS, Azure, GCP, DigitalOcean, Alibaba Cloud, Stripe, GitHub, Twilio, Expo, Sentry, Mapbox, and more.
- **gitignore-aware** — uses the `ignore` crate to automatically skip files in `.gitignore`, so you never scan `node_modules/` or `target/` by accident.
- **CI-native output** — `--format sarif` produces SARIF 2.1.0 output that GitHub Advanced Security displays as inline PR annotations with zero extra config.
- **Configurable** — a single `.oxideci.toml` file sets defaults for all commands; CLI flags always override it.

---

## Features

| Feature | Status |
|---|---|
| Secret & PII scanning (26 built-in patterns) | ✅ |
| Severity levels on every finding (critical / high / medium / low) | ✅ |
| AST-based SAST for JS/TS/TSX/JSX | ✅ |
| AST-based SAST for Python (eval, exec, pickle, subprocess, yaml.load) | ✅ |
| AST-based SAST for Go (unsafe, exec.Command, panic) | ✅ |
| String-literal scoping (no comment / JSX-text noise) | ✅ |
| Dangerous pattern detection (XSS, eval, command injection) | ✅ |
| Code smell / complexity rules (long functions, deep nesting, too many params) | ✅ |
| Custom SAST rules via config (tree-sitter S-expression queries) | ✅ |
| Custom extra patterns via config | ✅ |
| Exclude paths via glob patterns | ✅ |
| Inline suppression (`// oxide-ci: ignore`) | ✅ |
| Git diff / staged-only / full history scanning | ✅ |
| Git blame enrichment (`--blame`) | ✅ |
| JSON, SARIF 2.1.0, JUnit XML, GitLab SAST output formats | ✅ |
| GitHub Check Run annotations + rich PR summary comment (`--annotate`) | ✅ |
| Kubernetes manifest linting (7 rules) | ✅ |
| Dockerfile linting (8 rules) | ✅ |
| LCOV & Cobertura XML coverage threshold gate | ✅ |
| Dependency audit via OSV API (6 ecosystems) | ✅ |
| Offline OSV audit cache (24-hour TTL, air-gap friendly) | ✅ |
| CycloneDX 1.5 SBOM generation (`oxide-ci sbom`) | ✅ |
| Git pre-commit hook installer | ✅ |
| Web performance audit via PageSpeed Insights | ✅ |
| React component performance gate (Reassure) | ✅ |
| Scan baseline (suppress known findings in CI) | ✅ |
| Config profiles (`--profile strict\|relaxed\|ci`) | ✅ |
| Config validation (`oxide-ci check-config`) | ✅ |
| Pipeline runner (`oxide-ci run`) | ✅ |
| Interactive setup wizard (`oxide-ci init`) | ✅ |
| Live file watcher (`oxide-ci watch`) | ✅ |
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

**Windows (x64) — PowerShell:**
```powershell
Invoke-WebRequest -Uri "https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-windows-amd64.exe" `
  -OutFile "$env:USERPROFILE\.local\bin\oxide-ci.exe"
# Add $env:USERPROFILE\.local\bin to your PATH if not already present
```

### Build from source (requires Rust 1.85+)
```bash
cargo install --git https://github.com/ThinkGrid-Labs/oxide-ci
```

### Verify installation
```
$ oxide-ci --version
oxide-ci 0.2.6

$ oxide-ci --help
A high-performance DevOps CLI tool in Rust

Usage: oxide-ci [--profile <PROFILE>] <COMMAND>

Commands:
  scan           Scans the current directory for hardcoded secrets and PII
  lint           Validates Kubernetes YAML manifests for resource limits and security issues
  docker-lint    Lints a Dockerfile for best-practice violations
  coverage       Parses an LCOV or Cobertura XML coverage file and fails if below threshold
  audit          Audits project dependencies for known vulnerabilities via the OSV database
  install-hooks  Installs oxide-ci as a git pre-commit hook
  lighthouse     Audits web performance via Google PageSpeed Insights (Lighthouse)
  reassure       Parses a Reassure performance report and gates on regressions
  sbom           Generates a CycloneDX 1.5 SBOM from the project's lock file
  check-config   Validates .oxideci.toml and prints all resolved configuration values
  init           Interactive wizard that generates a .oxideci.toml config file
  watch          Re-runs scan automatically whenever source files change
  run            Runs all pipeline steps defined in .oxideci.toml in order
  help           Print this message or the help of the given subcommand(s)
```

---

## Quick Start

```bash
# Scan for secrets in current repo (includes SAST for JS/TS files)
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

Recursively scans every file in the current directory for hardcoded secrets, credentials, and PII using 26 built-in regex patterns. Respects `.gitignore` automatically.

For JavaScript, TypeScript, Python, and Go files the scanner automatically uses an AST-based pass (SAST) instead of plain regex. This eliminates false positives from comments and non-string content, and additionally flags dangerous API patterns. See [SAST for JS/TS/Python/Go](#sast-static-analysis-for-jstspythongo) below.

```
oxide-ci scan [OPTIONS]

Options:
  --format <FORMAT>    Output format: text (default), json, sarif, junit, gitlab
  --staged             Only scan git-staged files (git diff --cached)
  --since <COMMIT>     Only scan files changed since the given commit
  --history            Scan the entire git commit history (slow on large repos)
  --annotate           Post findings as a GitHub Check Run with per-line annotations
                       and a rich PR summary comment. Requires GITHUB_TOKEN,
                       GITHUB_REPOSITORY, and GITHUB_SHA env vars. No-op when absent.
  --update-baseline    Save current findings as the baseline (.oxide-baseline.json)
  --since-baseline     Only fail on findings not present in the saved baseline
  --blame              Enrich each finding with git blame info (author + commit)
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

# JUnit XML for Jenkins / Azure DevOps
oxide-ci scan --format junit > results.xml

# GitLab SAST Security Scanner JSON
oxide-ci scan --format gitlab > gl-sast-report.json

# Output JSON for custom tooling
oxide-ci scan --format json | jq '.findings[].rule'

# Enrich findings with git blame info (author + commit)
oxide-ci scan --blame

# Post findings directly to the GitHub Checks tab and a rich PR summary comment
GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }} \
GITHUB_REPOSITORY=owner/repo \
GITHUB_SHA=${{ github.sha }} \
oxide-ci scan --annotate
```

**Sample output (text):**
```
ℹ️  Starting secret and PII scan...
ℹ️  Running SAST checks...
ℹ️  SAST: scanning 14 file(s)...
⚠️  Found 3 potential issue(s):
  - [CRITICAL] [AWS Access Key] src/config.ts:14
  - [CRITICAL] [SAST/EvalUsage] src/utils/parser.js:42
  - [HIGH] [SAST/InnerHTMLAssignment] src/components/Widget.tsx:88
Error: Scan failed: 3 secret(s)/PII found. Review the findings above.
```

**Sample output (`--format json`):**
```json
{
  "total": 3,
  "findings": [
    { "rule": "AWS Access Key",           "file": "src/config.ts",            "line": 14, "severity": "critical" },
    { "rule": "SAST/EvalUsage",           "file": "src/utils/parser.js",      "line": 42, "severity": "critical" },
    { "rule": "SAST/InnerHTMLAssignment", "file": "src/components/Widget.tsx", "line": 88, "severity": "high" }
  ]
}
```

---

#### SAST: Static Analysis for JS/TS/Python/Go

When scanning `.js`, `.jsx`, `.ts`, `.tsx`, `.py`, or `.go` files, oxide-ci uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to parse each file into an AST before running any checks. This gives two important improvements over plain regex:

**1. String-literal scoping for secrets**

Secret and PII regex patterns are applied only against string literal values — not against comments, import declarations, or JSX text content. This means:

```ts
// AKIAIOSFODNN7EXAMPLE123   ← comment: NOT flagged ✅
const key = "AKIAIOSFODNN7EXAMPLE123";  // ← string literal: flagged ⚠️
const msg = `Contact us at admin@example.com`;  // ← template literal: flagged ⚠️
```

```tsx
// JSX text content is never flagged — only string attributes are:
<p>contact@example.com</p>           // ← JSX text: NOT flagged ✅
<Input placeholder="name@example.com" />  // ← string attribute: flagged ⚠️
```

**2. Dangerous pattern detection**

SAST also runs structural rules that detect dangerous API calls regardless of whether their arguments are string literals. These catch XSS sinks, code injection, command injection, and unsafe deserialization patterns that no regex can reliably find.

*JavaScript / TypeScript:*

| Rule ID | What it flags |
|---|---|
| `SAST/DangerouslySetInnerHTML` | `<div dangerouslySetInnerHTML={{__html: ...}} />` in TSX/JSX |
| `SAST/InnerHTMLAssignment` | `element.innerHTML = expr` |
| `SAST/OuterHTMLAssignment` | `element.outerHTML = expr` |
| `SAST/EvalUsage` | `eval(expr)` |
| `SAST/FunctionConstructor` | `new Function(...)` |
| `SAST/SetTimeoutString` | `setTimeout("code", delay)` — string as first arg |
| `SAST/SetIntervalString` | `setInterval("code", delay)` — string as first arg |
| `SAST/ChildProcessExec` | `child_process.exec(cmd)` |
| `SAST/ChildProcessExecSync` | `child_process.execSync(cmd)` |
| `SAST/ChildProcessSpawn` | `child_process.spawn(cmd, args)` |
| `SAST/ChildProcessExecFile` | `child_process.execFile(cmd)` |
| `SAST/DocumentWrite` | `document.write(expr)` |
| `SAST/DocumentWriteln` | `document.writeln(expr)` |

*Python:*

| Rule ID | What it flags |
|---|---|
| `SAST/PythonEval` | `eval(expr)` |
| `SAST/PythonExec` | `exec(code)` |
| `SAST/PythonPickle` | `pickle.load(f)` / `pickle.loads(data)` — unsafe deserialization |
| `SAST/PythonSubprocessShell` | Any call with `shell=True` — command injection risk |
| `SAST/PythonYamlLoad` | `yaml.load(data)` — use `yaml.safe_load` instead |

*Go:*

| Rule ID | What it flags |
|---|---|
| `SAST/GoUnsafe` | `import "unsafe"` — direct memory manipulation |
| `SAST/GoExecCommand` | `exec.Command(cmd, ...)` — possible command injection |
| `SAST/GoPanic` | `panic(...)` — unexpected process termination |

**3. Code smell / complexity rules** (JS/TS only)

Three additional rules flag maintainability issues at the function level:

| Rule ID | Trigger | Default threshold |
|---|---|---|
| `SMELL/LongFunction` | Function body exceeds `max_function_lines` lines | 50 lines |
| `SMELL/TooManyParameters` | Function has more than `max_parameters` parameters | 5 params |
| `SMELL/DeepNesting` | Control-flow depth exceeds `max_nesting_depth` inside a function | 4 levels |

Rule IDs include the measured value for immediate context — e.g. `SMELL/LongFunction (63 lines, max 50)`. Thresholds are configurable in `.oxideci.toml`:

```toml
[sast]
max_function_lines = 60   # default 50
max_parameters     = 6    # default 5
max_nesting_depth  = 5    # default 4
```

**4. Custom SAST rules**

Define project-specific rules using [tree-sitter S-expression queries](https://tree-sitter.github.io/tree-sitter/using-parsers/queries/). Each rule must include a `@match` capture that marks the outermost node to report:

```toml
[sast]
custom_rules = [
  # Flag any direct call to eval()
  { id = "CUSTOM/EvalCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"eval\") arguments: (_) @match)" },

  # Flag fetch() calls (useful for auditing outbound requests)
  { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]
```

Custom rules are validated at startup — invalid queries are skipped with a warning and never cause `oxide-ci scan` to crash. Custom rule IDs can be disabled with `disabled_rules` like any built-in rule.

> **Note:** SAST runs automatically when `oxide-ci scan` encounters a supported file — there is no separate command. Unsupported file types (`.rs`, `.yaml`, `.env`, etc.) use the regex scanner.

**Disabling SAST or individual rules:**

```toml
# .oxideci.toml

[sast]
# Set to false to disable SAST entirely and fall back to regex for all files
enabled = true

# Suppress specific rules that generate noise in your codebase
disabled_rules = [
    "SAST/ChildProcessExec",        # if you intentionally shell out in a Node script
    "SAST/DocumentWrite",           # if you have a legacy codebase that uses it
    "SAST/PythonSubprocessShell",   # if subprocess with shell=True is intentional
    "SMELL/LongFunction",           # if you have intentionally large generated files
]
```

**GitHub Check Run annotations + PR summary (`--annotate`):**

When running in GitHub Actions, pass `--annotate` to have oxide-ci post findings directly to the Checks tab with per-line annotations and a rich markdown summary comment on the pull request. The comment includes a severity breakdown and a per-finding table (capped at 20 rows). No SARIF upload step required.

```yaml
- name: Secret, PII & SAST Scan
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: oxide-ci scan --annotate
```

Required env vars (automatically set in GitHub Actions): `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_SHA`. When any env var is absent, `--annotate` is a no-op and the scan runs normally. A clean scan (no findings) posts a "No issues found" pass comment.

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
            cpu: "500m"
            memory: "256Mi"
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

Parses a coverage report and fails with exit code 1 if the total line coverage is below the specified minimum. Shows per-file breakdown of files below the threshold.

Two formats are supported and auto-detected by file extension (or by peeking at the file contents for ambiguous extensions):

| Format | Extension | Used by |
|---|---|---|
| **LCOV** | `.info` or no extension | Rust (cargo-llvm-cov), Jest, pytest-cov, Go |
| **Cobertura XML** | `.xml` | Python (coverage.py), Java (JaCoCo), .NET |

```
oxide-ci coverage [OPTIONS]

Options:
  -f, --file <FILE>    Path to the coverage file [default: coverage/lcov.info or coverage.file from config]
  -m, --min <MIN>      Minimum coverage threshold percentage [default: 80 or coverage.min from config]
  -h, --help           Print help
```

**Examples:**

```bash
# LCOV (Rust, Jest, pytest)
oxide-ci coverage --file coverage/lcov.info --min 80

# Cobertura XML (Python coverage.py, JaCoCo)
oxide-ci coverage --file coverage.xml --min 80

# Enforce a stricter 90% gate
oxide-ci coverage --file coverage/lcov.info --min 90

# Read defaults from .oxideci.toml
oxide-ci coverage
```

**Generating coverage reports by language:**

```bash
# Rust (cargo-llvm-cov) → LCOV
cargo llvm-cov --lcov --output-path coverage/lcov.info

# JavaScript / TypeScript (Jest) → LCOV
jest --coverage --coverageReporters=lcov

# Python (pytest-cov) → LCOV or Cobertura
pytest --cov=. --cov-report=lcov:coverage/lcov.info
pytest --cov=. --cov-report=xml:coverage.xml

# Go (go test) → LCOV
go test ./... -coverprofile=coverage/lcov.info

# Java (JaCoCo) → Cobertura XML
# Configure your build tool to output Cobertura format and pass the .xml file
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

Automatically detects your project's lock file, parses all pinned dependencies, and queries the [OSV (Open Source Vulnerabilities)](https://osv.dev) database in a single batch request. Works across six ecosystems.

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
| `yarn.lock` | `npm` | v1 (classic) and v2/Berry |
| `pnpm-lock.yaml` | `npm` | v5–v9 (slash and no-slash formats) |
| `requirements.txt` | `PyPI` | Only `==` pinned versions |
| `go.sum` | `Go` | All module checksums |

**Examples:**

```bash
# Rust project
oxide-ci audit

# Node.js project (npm, yarn, or pnpm — auto-detected)
oxide-ci audit

# Python project (auto-detected)
oxide-ci audit

# Go project (auto-detected)
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

> **Note:** Results are cached to `~/.cache/oxide-ci/osv/` with a 24-hour TTL. Subsequent runs reuse the cached response, making the audit fast and air-gap friendly after the first run. On network errors oxide-ci warns and exits 0, so it won't block CI pipelines with no outbound access.

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

---

### `sbom` — SBOM Generation

Generates a [CycloneDX 1.5](https://cyclonedx.org/specification/overview/) Software Bill of Materials from your project's lock file. No internet access required.

```
oxide-ci sbom [OPTIONS]

Options:
  -o, --output <FILE>    Write SBOM to a file instead of stdout
```

**Supported lock files** (checked in order): `Cargo.lock`, `package-lock.json`, `requirements.txt`, `go.sum`

```bash
# Print to stdout
oxide-ci sbom

# Write to a file
oxide-ci sbom --output sbom.json
```

Each component includes `name`, `version`, `purl` (Package URL), and `scope: required`. CycloneDX SBOMs are accepted by Dependency-Track, FOSSA, Grype, Trivy, and most enterprise compliance platforms.

---

### `check-config` — Validate Configuration

Reads `.oxideci.toml`, validates it, and prints all resolved configuration values. Useful before running CI to confirm that overrides are applied correctly.

```bash
oxide-ci check-config

# Preview merged values with a profile applied
oxide-ci --profile strict check-config
```

Exits 0 on valid config (or when no file exists, printing built-in defaults). Exits 1 if the file has a parse error.

---

## `docker-lint` — Dockerfile Linting

Checks a `Dockerfile` for best-practice violations across 8 rules.

```bash
oxide-ci docker-lint [--file <path>]
```

| Rule | What it catches |
|---|---|
| `no-latest-image` | `FROM node:latest` or untagged `FROM node` |
| `prefer-copy-over-add` | `ADD` where `COPY` is sufficient |
| `no-user-directive` | No `USER` instruction — runs as root by default |
| `no-root-user` | Explicit `USER root` or `USER 0` |
| `no-healthcheck` | Missing `HEALTHCHECK` instruction |
| `secret-in-env` | `ENV API_KEY=…`, `ENV PASSWORD=…` baked into the image layer |
| `apt-no-recommends` | `apt-get install` without `--no-install-recommends` |
| `apt-stale-cache` | `apt-get update` and `apt-get install` in separate `RUN` layers |

Configure the default path in `.oxideci.toml`:
```toml
[docker]
dockerfile = "Dockerfile"
```

---

## Baseline mode — `--update-baseline` / `--since-baseline`

In repositories with existing findings, baseline mode lets CI gate only on **new** findings introduced by a PR — without failing on pre-existing issues the team hasn't fixed yet.

**Step 1: Save a baseline** (run once on your main branch, commit the output)

```bash
oxide-ci scan --update-baseline
# writes .oxide-baseline.json
git add .oxide-baseline.json && git commit -m "chore: add oxide-ci scan baseline"
```

**Step 2: Use the baseline in CI** (PRs only fail on new findings)

```bash
oxide-ci scan --since-baseline
```

The baseline stores `(file, rule, line)` fingerprints. A secret that moves to a different line is treated as a new finding and re-reviewed.

---

## `init` — Interactive Setup Wizard

Generates a tailored `.oxideci.toml` by asking a few questions. The fastest way to get started.

```bash
oxide-ci init          # guided setup
oxide-ci init --force  # overwrite existing config
```

Example session:

```
oxide-ci init — generating .oxideci.toml

[ Secret & SAST Scanning ]
  Enable entropy-based secret detection? [Y/n]:
  Entropy threshold [4.5]:

[ Coverage Gate ]
  LCOV file path [coverage/lcov.info]:
  Minimum coverage % [80]:

[ Docker Lint ]
  Dockerfile path (leave blank to skip) []:

[ Pipeline Runner ]
  Generate a default pipeline (oxide-ci run)? [Y/n]:

✅ .oxideci.toml written successfully.
```

---

## `watch` — Live File Watcher

Re-runs the scan automatically every time a source file changes. Useful during active development.

```bash
oxide-ci watch                    # watch full working tree
oxide-ci watch --staged           # only scan staged files on change
oxide-ci watch --interval 500     # poll every 500ms
```

Unlike CI mode, `watch` **does not exit on findings** — it reports them and keeps watching so you can fix in-place.

---

## `run` — Pipeline Runner

Runs all quality gates in sequence using the steps defined in `.oxideci.toml`. First failure stops the pipeline.

```bash
oxide-ci run
```

Define your pipeline:

```toml
[pipeline]
steps = [
  "scan",
  "audit",
  "coverage --min 80",
  "lint --dir ./k8s",
  "docker-lint",
  "lighthouse",
]
```

Each step maps directly to an `oxide-ci` subcommand. Inline flags override config values for that step. Use `oxide-ci init` to generate a starter pipeline automatically.

---

## Secret Detection Patterns

OxideCI ships with 26 built-in patterns covering the most common cloud providers and services. All patterns are applied per-line for non-JS/TS files, and scoped to string literals for JS/TS/TSX/JSX files (no comment noise).

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
| `Google API Key` | Browser/server API keys (`AIza…35 chars`); also catches Firebase API keys |
| `GCP Service Account Key` | Service account JSON files (`"type": "service_account"`); also catches `google-services.json` |
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
| `Sentry DSN` | Error reporting DSNs (`https://key@o123.ingest.sentry.io/project`) |
| `Mapbox Secret Token` | Secret tokens (`sk.eyJ…`); public tokens (`pk.eyJ…`) are not flagged |

### PII
| Rule ID | What it detects |
|---|---|
| `Generic PII (SSN)` | US Social Security Numbers (`XXX-XX-XXXX`) |
| `Generic PII (Email)` | Email addresses |

### Shannon entropy detection

In addition to the named patterns, oxide-ci flags high-entropy tokens that don't match any known pattern — catching unrecognised API keys, random secrets, and opaque credentials:

```toml
[scan]
entropy           = true   # enable/disable (default: true)
entropy_threshold = 4.5    # Shannon entropy score; lower = more sensitive (default: 4.5)
entropy_min_length = 20    # minimum token length before entropy is checked (default: 20)
```

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

## SAST Rules Reference

Rules are checked on `.js`, `.jsx`, `.ts`, `.tsx`, `.py`, and `.go` files using tree-sitter AST queries. They fire on the structure of the code, not on string content.

### XSS sinks (JS/TS)

| Rule ID | Trigger | Risk |
|---|---|---|
| `SAST/DangerouslySetInnerHTML` | `<El dangerouslySetInnerHTML={{__html: v}} />` | XSS via React bypass |
| `SAST/InnerHTMLAssignment` | `el.innerHTML = expr` | DOM XSS |
| `SAST/OuterHTMLAssignment` | `el.outerHTML = expr` | DOM XSS |
| `SAST/DocumentWrite` | `document.write(expr)` | Legacy DOM XSS |
| `SAST/DocumentWriteln` | `document.writeln(expr)` | Legacy DOM XSS |

### Code injection (JS/TS)

| Rule ID | Trigger | Risk |
|---|---|---|
| `SAST/EvalUsage` | `eval(expr)` | Arbitrary code execution |
| `SAST/FunctionConstructor` | `new Function(...)` | Arbitrary code execution |
| `SAST/SetTimeoutString` | `setTimeout("string", delay)` | eval-equivalent |
| `SAST/SetIntervalString` | `setInterval("string", delay)` | eval-equivalent |

> `setTimeout` / `setInterval` are only flagged when the **first argument is a string or template literal**. Passing an arrow function or function reference is safe and not flagged.

### Command injection (Node.js)

| Rule ID | Trigger | Risk |
|---|---|---|
| `SAST/ChildProcessExec` | `cp.exec(cmd)` | OS command injection |
| `SAST/ChildProcessExecSync` | `cp.execSync(cmd)` | OS command injection |
| `SAST/ChildProcessSpawn` | `cp.spawn(cmd, args)` | OS command injection |
| `SAST/ChildProcessExecFile` | `cp.execFile(path)` | OS command injection |

> These rules fire on any `.exec()` / `.spawn()` / `.execFile()` / `.execSync()` member-expression call, regardless of which object it's called on. Adjust with `disabled_rules` if you have a legitimate use case.

### Python rules

| Rule ID | Trigger | Severity |
|---|---|---|
| `SAST/PythonEval` | `eval(expr)` | critical |
| `SAST/PythonExec` | `exec(code)` | critical |
| `SAST/PythonPickle` | `pickle.load(f)` / `pickle.loads(data)` | high |
| `SAST/PythonSubprocessShell` | Any call with `shell=True` keyword argument | high |
| `SAST/PythonYamlLoad` | `yaml.load(data)` — use `yaml.safe_load` instead | high |

### Go rules

| Rule ID | Trigger | Severity |
|---|---|---|
| `SAST/GoUnsafe` | `import "unsafe"` | high |
| `SAST/GoExecCommand` | `exec.Command(cmd, ...)` | high |
| `SAST/GoPanic` | `panic(...)` | medium |

### Code smell / complexity (JS/TS only)

| Rule ID | Trigger | Default |
|---|---|---|
| `SMELL/LongFunction` | Function body exceeds `max_function_lines` lines | 50 lines |
| `SMELL/TooManyParameters` | Function has more than `max_parameters` parameters | 5 params |
| `SMELL/DeepNesting` | Control-flow nesting depth exceeds `max_nesting_depth` | 4 levels |

Rule IDs embed the measured value — e.g. `SMELL/LongFunction (63 lines, max 50)` — so findings are self-explanatory without additional context. Thresholds are configurable per project in `.oxideci.toml`. See [Configuration File](#configuration-file-oxidecitorml) for details.

---

## Suppressing Findings

Add `// oxide-ci: ignore` on the same line as a finding to suppress it:

```ts
const legacyKey = "AKIAIOSFODNN7EXAMPLE123"; // oxide-ci: ignore
el.innerHTML = sanitizedHtml;                 // oxide-ci: ignore
eval(trustedAdminScript);                     // oxide-ci: ignore
```

Suppression works for both secret/PII findings and SAST dangerous-pattern findings. It is applied per-line — only the finding on that exact line is suppressed.

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

# Extra patterns on top of the 26 built-ins
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
]

# Shannon entropy detection (flags high-entropy tokens like unrecognized API keys)
entropy = true
entropy_threshold = 4.5    # lower = more sensitive
entropy_min_length = 20    # ignore tokens shorter than this

[sast]
# Set to false to disable SAST entirely for JS/TS files (falls back to plain regex)
enabled = true

# Suppress specific SAST rule IDs that generate noise in your codebase
disabled_rules = [
  # "SAST/ChildProcessExec",
  # "SAST/EvalUsage",
  # "SMELL/LongFunction",
]

# Code smell thresholds (defaults shown)
max_function_lines = 50   # flag functions longer than this many lines
max_parameters     = 5    # flag functions with more than this many parameters
max_nesting_depth  = 4    # flag control-flow nesting deeper than this inside a function

# Custom rules using tree-sitter S-expression queries
# Each rule must contain a @match capture marking the outermost node to report.
custom_rules = [
  # { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]

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

The `scan` command supports five output formats via `--format`:

### `text` (default)
Human-readable output to stderr with severity prefix on each finding.

```
  - [CRITICAL] [AWS Access Key] src/config.ts:14
  - [HIGH] [SAST/InnerHTMLAssignment] src/components/Widget.tsx:88
```

### `json`
Machine-readable JSON written to stdout. Includes `severity` field on every finding.

```json
{
  "total": 1,
  "findings": [
    { "rule": "SAST/EvalUsage", "file": "./src/utils.js", "line": 42, "severity": "critical" }
  ]
}
```

### `sarif`
SARIF 2.1.0 JSON written to stdout. Upload directly to GitHub Advanced Security for inline PR annotations.

```bash
oxide-ci scan --format sarif > results.sarif
```

### `junit`
JUnit XML written to stdout. Compatible with Jenkins, Azure DevOps, and CircleCI test report parsers.

```bash
oxide-ci scan --format junit > results.xml
```

### `gitlab`
GitLab SAST Security Scanner JSON (schema v15.0.6) written to stdout. Use as a GitLab security artifact to display findings in Merge Request security reports.

```yaml
# .gitlab-ci.yml
secret-scan:
  script: oxide-ci scan --format gitlab > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Config Profiles

Apply a named quality profile on top of your loaded config without editing `.oxideci.toml`. Pass `--profile` as a global flag before the subcommand:

```bash
oxide-ci --profile strict scan
oxide-ci --profile ci scan --staged
oxide-ci --profile relaxed coverage
```

| Profile | Effect |
|---|---|
| `strict` | Coverage ≥ 90%, entropy threshold 3.5 (more sensitive), Lighthouse performance ≥ 90 & accessibility ≥ 95, SAST enabled |
| `relaxed` | Coverage ≥ 70%, entropy threshold 5.0 (fewer false positives) |
| `ci` | Coverage ≥ 80%, SAST enabled, `SMELL/*` rules disabled to reduce noise in CI |

Profiles only modify the in-memory config — they never write to `.oxideci.toml`.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed — safe to proceed |
| `1` | Check failed (secrets found, SAST issues, lint issues, coverage below threshold, vulnerabilities detected) or tool error |

> CI pipelines can rely on the exit code directly — no parsing required.

---

## CI/CD Integration

### GitHub Actions — Full pipeline

```yaml
name: OxideCI Quality Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload and Check Runs
  checks: write            # required for --annotate (GitHub Check Runs)
  pull-requests: write     # required for --annotate (PR review comment)

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

      # Option A: Native GitHub Check Run annotations (no SARIF upload step needed)
      - name: Secret, PII & SAST Scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: oxide-ci scan --annotate

      # Option B: SARIF upload to GitHub Advanced Security (alternative to --annotate)
      # - name: Scan (SARIF for PR annotations)
      #   run: oxide-ci scan --format sarif > results.sarif
      #   if: always()
      #   continue-on-error: true
      # - name: Upload SARIF
      #   uses: github/codeql-action/upload-sarif@v4
      #   if: always()
      #   with:
      #     sarif_file: results.sarif
      #   continue-on-error: true

      - name: Kubernetes Lint
        run: oxide-ci lint --dir ./k8s

      - name: Coverage Gate
        run: oxide-ci coverage --file coverage/lcov.info --min 80

      - name: Dependency Audit
        run: oxide-ci audit

  # ── Performance gates (post-deploy) ────────────────────────────────────────
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

secret-and-sast-scan:
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
          name: Secret, PII & SAST Scan
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
│   │   ├── scanner.rs           # Secret/PII scanning (rayon parallel) + SAST orchestration
│   │   ├── sast.rs              # AST-based SAST for JS/TS/TSX/JSX (tree-sitter)
│   │   ├── github.rs            # GitHub Check Runs + PR review comment (--annotate)
│   │   ├── k8s_lint.rs          # Kubernetes manifest linter (serde_yaml)
│   │   ├── coverage.rs          # LCOV & Cobertura XML parser and threshold gate
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

**Scan pipeline for JS/TS files:**

```
collect_findings()
    │
    ├── non-JS/TS files ──→ run_regex_scan()    (rayon parallel, per-line regex + entropy)
    │
    └── JS/TS files ──────→ run_sast_scan()     (rayon parallel, tree-sitter per file)
                                │
                                ├── parse AST (tree-sitter)
                                ├── scan_string_literals()    ← secrets/PII scoped to string nodes
                                ├── scan_dangerous_patterns() ← 13 structural rules + custom rules
                                └── scan_complexity()         ← 3 code smell rules
                                                                 (long function, params, nesting)

emit_findings()     ← text / JSON / SARIF
    │
    └── --annotate ──→ github::annotate()   ← GitHub Check Run + PR comment (no-op if env absent)
```

**Dependencies:**

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `rayon` | CPU-bound parallelism (file scanning) |
| `ignore` | gitignore-aware file walking |
| `regex` | Secret pattern matching |
| `tree-sitter` | AST parsing engine |
| `tree-sitter-javascript` | JS/JSX grammar |
| `tree-sitter-typescript` | TS/TSX grammar |
| `streaming-iterator` | Required by tree-sitter 0.24 `QueryMatches` API |
| `serde` + `serde_json` | JSON output (SARIF, audit, GitHub API bodies) |
| `serde_yaml` | Kubernetes YAML parsing |
| `roxmltree` | Zero-copy Cobertura XML parsing |
| `toml` | Config file parsing |
| `ureq` | HTTP client (OSV audit, PageSpeed, GitHub APIs) |
| `indicatif` | Progress bars |
| `anyhow` | Error handling and propagation |

---

## React Native

oxide-ci works with React Native and Expo projects out of the box. npm, Yarn, and pnpm lock files are all supported for dependency auditing, SAST runs automatically on all JS/TS/TSX files, and Reassure — which was originally built *for* React Native by Callstack — is a first-class citizen.

### Command compatibility

| Command | React Native support | Notes |
|---|---|---|
| `scan` | ✅ Full | Secrets + PII + SAST on JS/TS/TSX files; gitignore-aware (skips `node_modules/` automatically) |
| `audit` | ✅ Full | Reads `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`; queries OSV for npm CVEs |
| `coverage` | ✅ Full | Reads Jest LCOV output (`--coverageReporters=lcov`) |
| `install-hooks` | ✅ Full | Pre-commit hook works in any git repo |
| `reassure` | ✅ Full | Built for React Native; parses `output/current.perf` from `reassure measure` |
| `lint` | ⚠️ Optional | Only useful if the project has a Kubernetes backend |
| `lighthouse` | ⚠️ Web only | Audits a public URL; applicable if you ship a React Native Web build or marketing site |

> **Note on Bun:** `bun.lockb` is a binary format that oxide-ci cannot parse. If you use Bun, run `bun install --save-text-lockfile` to generate a `bun.lock` text file alongside it, or use the `package-lock.json` fallback (`bun install --backend=npm`).

---

### React Native–specific secrets detected

In addition to the 23 built-in cloud patterns, oxide-ci detects these patterns common in RN projects (scoped to string literals in JS/TS files):

| Rule | What it detects |
|---|---|
| `Expo Access Token` | EAS CLI robot/personal tokens (`expa_…`) |
| `Sentry DSN` | Sentry error-reporting DSNs (quota exhaustion + event read risk) |
| `Mapbox Secret Token` | Mapbox secret tokens (`sk.eyJ…`); public tokens (`pk.eyJ…`) are not flagged |
| `Google API Key` | Firebase API keys (`AIza…`) — same prefix as GCP, already built-in |
| `GCP Service Account Key` | `google-services.json` leaks — already built-in |

### SAST in React Native projects

SAST is especially valuable in RN/Expo codebases because:

- **`dangerouslySetInnerHTML`** — `SAST/DangerouslySetInnerHTML` catches this in TSX/JSX files. React Native itself doesn't render HTML, but React Native Web builds do.
- **`eval`** — `SAST/EvalUsage` flags dynamic code evaluation in JS bundles. Metro bundler includes all JS in the final bundle, making eval a supply-chain risk.
- **Node.js build scripts** — `SAST/ChildProcessExec` / `SAST/ChildProcessSpawn` flags shell commands in custom Metro config, build scripts, and Expo plugins.

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
    # React Native generated bundle
    "android/app/src/main/assets/index.android.bundle",
]

# Shannon entropy catches random API keys not matched by explicit rules.
entropy = true
entropy_threshold = 4.5
entropy_min_length = 20

[sast]
enabled = true
# disabled_rules = []   # uncomment to suppress specific rules

[coverage]
file = "coverage/lcov.info"
min = 80.0

[reassure]
current  = "output/current.perf"
baseline = "output/baseline.perf"
threshold = 15.0
```

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

      - name: Secret, PII & SAST scan
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

## Troubleshooting

### SARIF upload fails with "Resource not accessible by integration"

```
Error: Resource not accessible by integration
```

This is **expected behaviour for private repositories**. Uploading SARIF results to the GitHub Security tab requires [GitHub Advanced Security (GHAS)](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security), which is:

- **Free** for public repositories
- **Paid add-on** for private repositories (part of GitHub Enterprise)

The `oxide-ci scan` step itself still runs and will fail the job if real secrets or SAST issues are found — your security gate is intact. The SARIF upload is only needed for inline PR annotations in the Security tab.

**Options:**

| Option | When to use |
|---|---|
| Keep `continue-on-error: true` (default) | Private repo, no GHAS — scan still blocks on findings |
| Enable GitHub Advanced Security | You have GitHub Enterprise or want inline PR annotations |
| Remove the SARIF upload steps | You don't need the Security tab integration |

---

### Too many false positives from lockfiles

Package managers store sha512 integrity hashes in lockfiles (`pnpm-lock.yaml`, `yarn.lock`, `package-lock.json`). These look like high-entropy secrets and will generate hundreds of false positives.

**Fix:** Exclude lockfiles in `.oxideci.toml`:

```toml
[scan]
exclude_patterns = [
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "Cargo.lock",   # sha256 checksums
]
```

---

### High-entropy false positives from SVGs and minified files

Compiled or generated files commonly contain base64-encoded data and high-entropy strings that are not secrets:

| File type | Reason flagged |
|---|---|
| `favicon.svg` | Embedded base64 image data |
| `pdf.worker.min.mjs` / `*.min.js` | Minified third-party library code |
| `*.chunk.js` | Webpack/Next.js build output |

**Fix:** Exclude public assets and minified files:

```toml
[scan]
exclude_patterns = [
    "**/public/**",       # static assets directory
    "**/*.min.js",
    "**/*.min.mjs",
    ".next/**",           # Next.js build output
    "dist/**",
    "build/**",
]
```

---

### Sentry config files flagged for PII (Email)

Sentry DSN URLs contain an `@` symbol (e.g. `https://abc123@o123.ingest.sentry.io/456`), which triggers the `Generic PII (Email)` pattern. In properly configured projects the DSN is loaded from an environment variable (`NEXT_PUBLIC_SENTRY_DSN`), so the source files contain no hardcoded secret.

**Fix:** Exclude Sentry and instrumentation config files:

```toml
[scan]
exclude_patterns = [
    "**/sentry.client.config.ts",
    "**/sentry.server.config.ts",
    "**/sentry.edge.config.ts",
    "**/instrumentation.ts",
]
```

> **Note:** If your Sentry DSN *is* hardcoded in these files, oxide-ci is correctly flagging it as a secret. Move it to an environment variable before excluding the file.

---

### Test fixtures flagged for PII (Email)

Test files commonly use placeholder addresses like `user@example.com` as input fixtures. These are not real PII.

**Fix:** Exclude test files and directories:

```toml
[scan]
exclude_patterns = [
    "**/*.test.ts",
    "**/*.test.tsx",
    "**/*.spec.ts",
    "**/*.spec.tsx",
    "**/__tests__/**",
]
```

---

### Emails in docs or UI components flagged as PII

The `Generic PII (Email)` pattern catches any email-shaped string. Contact addresses in footers, documentation, form placeholders, or help pages are intentional — not secrets.

**Fix:** Exclude the specific files or directories:

```toml
[scan]
exclude_patterns = [
    "docs/**",
    "*.md",
    "**/components/footer/**",
    "**/components/forms/**",   # input placeholder emails
    "**/app/**/help/**",        # contact emails on help pages
]
```

---

### `.oxideci.toml` itself is flagged

If your config file contains example emails in comments (e.g. `user@example.com`), oxide-ci will flag the config file itself. Exclude it:

```toml
[scan]
exclude_patterns = [
    ".oxideci.toml",
]
```

---

### SAST rule fires on intentional usage

Some SAST rules (e.g. `SAST/ChildProcessExec`) fire on any usage of a pattern, even when it's intentional in a build script or CLI tool. Two ways to handle this:

**Option 1 — Inline suppression** (preferred for isolated occurrences):
```js
child_process.exec(buildCmd, callback); // oxide-ci: ignore
```

**Option 2 — Disable the rule globally** (preferred when the pattern is widespread):
```toml
[sast]
disabled_rules = ["SAST/ChildProcessExec"]
```

---

### Reference `.oxideci.toml` for a Next.js / React monorepo

Copy this as a starting point and remove exclusions that don't apply to your project:

```toml
[scan]
exclude_patterns = [
    # Package manager lockfiles — sha512 integrity hashes, not secrets
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",

    # Public assets and minified files — base64 image data and bundled libraries
    "**/public/**",
    "**/*.min.js",
    "**/*.min.mjs",

    # Sentry / OpenTelemetry config — DSN URLs contain @ but are loaded from env vars
    "**/sentry.client.config.ts",
    "**/sentry.server.config.ts",
    "**/sentry.edge.config.ts",
    "**/instrumentation.ts",

    # Test fixtures — placeholder emails used as test input, not real PII
    "**/*.test.ts",
    "**/*.test.tsx",
    "**/*.spec.ts",
    "**/*.spec.tsx",
    "**/__tests__/**",

    # The config file itself — comments may contain example emails like user@example.com
    ".oxideci.toml",

    # Docs and markdown — example snippets and editorial emails
    "docs/**",
    "*.md",

    # Build output
    ".next/**",
    "dist/**",
    "build/**",
    ".git/**",
]

entropy = true
entropy_threshold = 4.5
entropy_min_length = 20

[sast]
enabled = true
# disabled_rules = ["SAST/ChildProcessExec"]
```

---

### CodeQL Action v3 deprecation warning

```
Warning: CodeQL Action v3 will be deprecated in December 2026.
```

Update the SARIF upload action in your workflow from `@v3` to `@v4`:

```yaml
# Before
uses: github/codeql-action/upload-sarif@v3

# After
uses: github/codeql-action/upload-sarif@v4
```

---

## Contributing

OxideCI is open source under the [MIT License](LICENSE). Contributions are welcome.

**Adding a new secret pattern:**

1. Add a `(&str, &str)` tuple to `BUILTIN_PATTERNS` in [src/modules/scanner.rs](src/modules/scanner.rs) inside the appropriate cloud provider section
2. Add a matching `#[test]` for both a positive match and a false-positive check
3. Run `cargo test` to verify

**Adding a new SAST rule:**

1. Add a `SastRule { id, query }` entry to `RULES` in [src/modules/sast.rs](src/modules/sast.rs)
2. Write the tree-sitter S-expression query — the `@match` capture marks the outermost node for location reporting
3. Add a unit test in the `#[cfg(test)]` block that asserts the rule fires and (if applicable) that a safe variant does not fire
4. Run `cargo test` to verify

**Adding a new lint rule:**

1. Add a check in `check_manifest()` in [src/modules/k8s_lint.rs](src/modules/k8s_lint.rs)
2. Add a unit test in the `#[cfg(test)]` block

**Running tests:**

```bash
cargo test          # all unit + integration tests
cargo test scanner  # only scanner tests
cargo test sast     # only SAST tests
cargo clippy        # lint
```

**Issues & feature requests:** [github.com/ThinkGrid-Labs/oxide-ci/issues](https://github.com/ThinkGrid-Labs/oxide-ci/issues)
