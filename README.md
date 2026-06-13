# greengate

**One binary. Zero runtimes. Every security and quality gate your CI pipeline needs.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/thinkgrid-labs/greengate/ci.yml?branch=main)](https://github.com/thinkgrid-labs/greengate/actions)
[![GitHub release](https://img.shields.io/github/v/release/thinkgrid-labs/greengate)](https://github.com/thinkgrid-labs/greengate/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/greengate)](https://crates.io/crates/greengate)
[![Downloads](https://img.shields.io/crates/d/greengate)](https://crates.io/crates/greengate)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)](https://www.rust-lang.org)

**[Docs](https://thinkgrid-labs.github.io/greengate)** · [Config Reference](https://thinkgrid-labs.github.io/greengate/reference/config) · [CI Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration) · [SAST Rules](https://thinkgrid-labs.github.io/greengate/reference/sast-rules)

---

Most teams accumulate a different tool for each concern: a secret scanner, a SAST runner, a CVE auditor, a coverage gate, a supply chain monitor, a CI config linter — each with its own runtime, its own config format, and its own way of breaking. greengate replaces all of them with a single compiled Rust binary you drop into any CI pipeline in under 30 seconds.

No Node. No Python. No JVM. No Docker. Just copy the binary and run.

---

## Contents

- [Why greengate?](#why-greengate)
- [What it does](#what-it-does)
- [Supported languages](#supported-languages)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Suppressing false positives](#suppressing-false-positives)
- [AI triage](#ai-triage)
- [SBOM attestation](#sbom-attestation)
- [GitHub Actions](#github-actions)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Contributing](#contributing)

---

## Why greengate?

**Security tools are fragmented.** A typical CI pipeline strings together `gitleaks`, `semgrep`, `npm audit`, `trivy`, `opa`, `pylint`, `jest --coverage` — each installed separately, each needing its own version pin, each producing output in a different format. When one of them breaks the build on a Friday you spend an hour figuring out which one.

**greengate is the alternative:** one tool, one config file, one exit code. Every gate — secrets, SAST, supply chain, coverage, complexity, CI config hygiene — runs in a single fast pass.

**Key properties:**
- **Single static binary** — ships as a single musl-linked executable for Linux, macOS, and Windows. Copy it to `/usr/local/bin` and it works.
- **AST-accurate SAST** — uses tree-sitter to parse real ASTs instead of fragile regex over source text. No false positives from comments or string literals.
- **Supply chain aware** — intercepts `npm`, `yarn`, `pnpm`, `bun`, `pip`, and `cargo` installs to detect typosquats, malicious postinstall scripts, and phantom executable drops before they can run.
- **CI-native output** — emits SARIF, JUnit XML, GitLab SAST JSON, and GitHub Check Run annotations with per-line findings. Plugs into Code Scanning, GitLab Security Dashboard, and SonarQube out of the box.
- **Zero configuration required** — sensible defaults work on any repo; `.greengate.toml` is optional.

---

## What it does

Commands are grouped by concern. Each runs standalone or as a step in `greengate run`.

### Secrets & Code Security

| Command | What it does |
|---|---|
| `greengate scan` | Scan for hardcoded secrets, PII, and SAST issues. 26 built-in secret patterns (AWS keys, GitHub tokens, private keys, JWTs, etc.) plus Shannon entropy detection for unrecognised credentials. AST-based SAST for unsafe patterns in JS/TS/Python/Go/Rust. |
| `greengate scan --fix` | Auto-redact detected secrets in-place — replaces matched values with `<REDACTED>`. Use `--dry-run` first to preview changes. |
| `greengate scan --history` | Scan the full git commit history for secrets (catches credentials that were committed then deleted). |
| `greengate scan --staged` | Scan only staged files — ideal as a pre-commit hook. |
| `greengate scan --format sarif` | Emit SARIF 2.1.0 for GitHub Code Scanning / SonarQube upload. Also supports `json`, `junit`, `gitlab`. |
| `greengate scan --triage` | Call an LLM to classify each finding as likely-real, likely-false-positive, or uncertain. Shows confidence % and a one-sentence reason. Supports Claude (default), any OpenAI-compatible API, or a local model via Ollama. |

### Supply Chain Protection

| Command | What it does |
|---|---|
| `greengate watch-install <pm> <args>` | Wrap any npm/yarn/pnpm/bun install. Three layers: pre-flight lifecycle script scan (entropy + network/eval patterns), runtime phantom-file detection (files created then deleted by postinstall), post-install exec-drop detection. |
| `greengate pip-install <args>` | Wrap `pip install`. Typosquat detection against the 60 most-downloaded PyPI packages, post-install `.dist-info/RECORD` Python source scan, executable-drop detection. Halts before pip runs if a typosquat is found. |
| `greengate cargo-add <args>` | Wrap `cargo add`. Typosquat detection against the 60 most-downloaded crates.io crates, `build.rs` static analysis for every newly added crate (network access, subprocess spawning, env exfiltration), transitive dependency explosion guard (> 50 new transitive deps triggers a warning). |

### Dependencies

| Command | What it does |
|---|---|
| `greengate audit` | Query the [OSV database](https://osv.dev) for known vulnerabilities in your project's dependencies. Supports `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `requirements.txt`, `go.sum`, `pom.xml`, and `*.csproj`. |
| `greengate sbom` | Generate a [CycloneDX 1.5](https://cyclonedx.org) SBOM from the project's lock file. |
| `greengate sbom --attest` | Generate a SBOM and sign it with [Sigstore](https://sigstore.dev) keyless signing. Produces a bundle file anchored in the Rekor public transparency log. No private key required. |
| `greengate sbom --verify <file>` | Verify a SBOM against a cosign bundle. Fails if the signature is invalid or the bundle is missing from the Rekor log. |

### Code Quality & Review

| Command | What it does |
|---|---|
| `greengate review` | Analyse a PR diff: Complexity Score (cyclomatic + cognitive) and new-code coverage gaps. Posts a GitHub Check Run with per-line annotations. Fails if complexity exceeds `complexity_budget` or new code coverage falls below `min_new_code_coverage`. |
| `greengate coverage` | Parse LCOV or Cobertura XML and fail if total coverage is below a configurable threshold. |
| `greengate tia` | Test Impact Analysis — use AST import parsing to determine exactly which test files are affected by a diff. Pipe the output directly into pytest, jest, or go test to skip unaffected tests. |
| `greengate reassure` | Parse a [Reassure](https://github.com/callstack/reassure) performance report and fail if any React component's mean render time regresses beyond a threshold. |

### Infrastructure & CI

| Command | What it does |
|---|---|
| `greengate ci-lint` | Lint GitHub Actions workflow files for security misconfigurations: unpinned action refs (`actions/checkout@v4` instead of a commit SHA), `pull_request_target` + PR checkout (script injection), expression injection in `run:` steps, and secrets leaked via environment variables. Emits SARIF for Code Scanning. |
| `greengate lint` | Kubernetes manifest linting — validates resource limits, security contexts, `latest` image tags, and missing probes. |
| `greengate docker-lint` | Dockerfile best-practice checks — `latest` base images, running as root, missing `HEALTHCHECK`, `ADD` instead of `COPY`, etc. |
| `greengate lighthouse` | Gate on Google PageSpeed Insights scores (Performance, Accessibility, Best Practices, SEO). |

### Workflow

| Command | What it does |
|---|---|
| `greengate run` | Run all pipeline steps defined in `[pipeline]` of `.greengate.toml` in order. One command to run every gate. |
| `greengate init` | Interactive wizard that generates `.greengate.toml`. Pass `--ci github-actions` to also scaffold a ready-to-use workflow and `dependabot.yml`. |
| `greengate install-hooks` | Install greengate as a git pre-commit hook (runs `scan --staged` on every commit). |
| `greengate watch` | Re-run `scan` automatically whenever source files change (file-watcher mode for local development). |
| `greengate check-config` | Validate `.greengate.toml` and print all resolved configuration values. |

### Observability

| Feature | How it works |
|---|---|
| **OTLP metrics export** | After each command, greengate POSTs structured metrics to any OpenTelemetry-compatible collector (Grafana, Datadog, Honeycomb, etc.) via OTLP HTTP/JSON. Configure `otlp_endpoint` in `[telemetry]`. |
| **Prometheus text format** | Writes a `.prom` file after each command. Point `node_exporter --collector.textfile.directory` at the same directory and metrics are scraped automatically. Configure `metrics_file` in `[telemetry]`. |

---

## Supported languages

### Secret scanning

Secret scanning uses regex patterns and Shannon entropy — it is **language-agnostic** and runs on any file type, including config files, `.env` files, shell scripts, and binary-adjacent formats.

### SAST (AST-based)

SAST uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to parse a real AST, so findings are accurate even when the pattern appears inside a comment or a string in another language.

| Language | File extensions | SAST rules |
|---|---|---|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `eval()`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `setTimeout(string)`, `child_process.exec` |
| TypeScript | `.ts`, `.tsx` | Same as JavaScript |
| Python | `.py` | `exec()`, `eval()`, `subprocess` with shell=True, `pickle.loads`, `yaml.load` (unsafe), `os.system` |
| Go | `.go` | `os/exec` command injection, `fmt.Sprintf` in SQL, `http.ListenAndServe` without TLS |
| Rust | `.rs` | `unsafe {}` blocks, `std::process::Command`, `.unwrap()` and `.expect()` in library code |

### Test Impact Analysis

TIA walks the import graph using AST parsing to find which test files transitively import a changed source file.

| Language | Import resolution |
|---|---|
| JavaScript / TypeScript | `import` / `require` (relative paths, bare specifiers) |
| Python | `import` / `from … import` |
| Go | `import "…"` (full package path) |

### Dependency audit (OSV)

| Ecosystem | Lock file |
|---|---|
| Node.js (npm) | `package-lock.json` |
| Node.js (Yarn) | `yarn.lock` |
| Node.js (pnpm) | `pnpm-lock.yaml` |
| Rust | `Cargo.lock` |
| Python | `requirements.txt` |
| Go | `go.sum` |
| Java (Maven) | `pom.xml` |
| .NET | `*.csproj` |

### Supply chain wrapping

| Package manager | Command | Typosquat detection | Script scanning | Exec-drop detection |
|---|---|---|---|---|
| npm / yarn / pnpm / bun | `greengate watch-install` | — | postinstall scripts | |
| pip | `greengate pip-install` | 60 popular PyPI packages | `.py` files via RECORD | venv `bin/` |
| Cargo | `greengate cargo-add` | 60 popular crates.io crates | `build.rs` | — |

### CI config linting

| Platform | File pattern |
|---|---|
| GitHub Actions | `.github/workflows/*.yml` |

---

## Installation

**macOS (Apple Silicon):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-aarch64-apple-darwin \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**macOS (Intel):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-x86_64-apple-darwin \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Linux (x64, musl — works in Alpine/Docker):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-x86_64-unknown-linux-musl \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Windows (x64) — PowerShell:**
```powershell
Invoke-WebRequest `
  -Uri "https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-x86_64-pc-windows-msvc.exe" `
  -OutFile "$env:USERPROFILE\.local\bin\greengate.exe"
```

**Build from source (Rust 1.85+):**
```bash
cargo install --git https://github.com/thinkgrid-labs/greengate
```

---

## Quick start

```bash
# Generate a .greengate.toml and a GitHub Actions workflow in one step
greengate init --ci github-actions

# Scan the current directory for secrets, PII, and SAST issues
greengate scan

# Preview what --fix would change (no files written)
greengate scan --dry-run

# Auto-redact detected secrets in-place
greengate scan --fix

# Audit dependencies for known CVEs (reads any supported lock file)
greengate audit

# Zero-trust npm install (static scan + runtime phantom-file watcher)
greengate watch-install npm ci

# Zero-trust pip install with typosquat detection
greengate pip-install -r requirements.txt

# Zero-trust cargo add with build.rs analysis
greengate cargo-add serde tokio

# Lint GitHub Actions workflows for security misconfigurations
greengate ci-lint

# Test impact analysis — run only affected tests
pytest $(greengate tia --base main)
npx jest $(greengate tia --base main --format newline)

# PR complexity score + coverage gaps (posts GitHub Check Run annotations)
greengate review --base main --coverage-file coverage/lcov.info --annotate

# Gate on 80% minimum coverage
greengate coverage --file coverage/lcov.info --min 80

# Lint Kubernetes manifests
greengate lint --dir ./k8s

# Triage findings with an LLM (requires ANTHROPIC_API_KEY)
greengate scan --triage

# Generate a CycloneDX SBOM
greengate sbom --output sbom.json

# Generate a SBOM and sign it with Sigstore keyless signing
greengate sbom --attest --output sbom.json

# Verify a SBOM against its cosign bundle
greengate sbom --verify sbom.json --bundle sbom.json.bundle.json

# Run all configured gates in order
greengate run

# Install as a git pre-commit hook
greengate install-hooks
```

---

## Suppressing false positives

### Inline suppression

Add `// greengate: ignore` on the same line as a finding to suppress it:

```javascript
const TEST_KEY = "AKIAIOSFODNN7EXAMPLE"; // greengate: ignore
```

### Next-line suppression

Put the comment on the line above to suppress the next line:

```python
# greengate: ignore
AWS_KEY = load_from_env("AWS_ACCESS_KEY_ID")
```

### Auto-redact

Use `--fix` to replace detected secrets with `<REDACTED>` in-place. Preview first with `--dry-run`:

```bash
greengate scan --dry-run   # preview changes
greengate scan --fix       # apply redactions
git diff                   # review before committing
```

### Baseline

Save current findings as an accepted baseline and only fail on *new* findings:

```bash
greengate scan --update-baseline   # save current state
greengate scan --since-baseline    # fail only on new findings
```

---

## AI triage

False positives are the #1 reason developers disable security tools. `--triage` sends each finding to an LLM along with its surrounding source code and asks: *"Is this a real issue or a false positive, and why?"*

```
⚠️  Found 3 potential issue(s) — 1 triaged as false positive(s) and auto-suppressed, 2 require attention:

  - [HIGH] [SAST/CommandInjection] ./src/admin/shell.rs:88
    → Triage: LIKELY REAL (94%) — User-controlled cmd flows into Command::new with no sanitization.

  - [HIGH] [Secret/AwsAccessKey] ./tests/fixtures/creds.rs:12 [AUTO-SUPPRESSED]
    → Triage: LIKELY FALSE POSITIVE (91%) — Matches canonical AWS example key in test fixture.

  - [MEDIUM] [SAST/EvalUsage] ./src/utils/eval.rs:44
    → Triage: UNCERTAIN (55%) — eval() usage but surrounding context does not clarify intent.

  Triage summary: 1 likely real · 1 uncertain · 1 false positive (suppressed: 1) · 0 unavailable
```

### Setup

Set the API key for your chosen model:

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (default)
export OPENAI_API_KEY=sk-...          # OpenAI-compatible
```

Then run:

```bash
greengate scan --triage
```

No additional dependencies — greengate calls the API directly using its built-in HTTP client.

### Configuration

```toml
[triage]
model                   = "claude-haiku-4-5-20251001"  # fast and cheap; accurate enough for triage
api_key_env             = "ANTHROPIC_API_KEY"           # env var that holds the key
auto_suppress_threshold = 0.0                           # 0 = annotate only; 0.9 = auto-suppress high-confidence FPs
context_lines           = 10                            # source lines before/after the finding sent as context
# endpoint = "http://localhost:11434/v1/chat/completions"  # Ollama or any OpenAI-compatible API
```

### `auto_suppress_threshold`

When set above `0.0`, findings where the LLM is at least that confident they are false positives are automatically suppressed — they appear in output tagged `[AUTO-SUPPRESSED]` but do not cause a non-zero exit code.

| Value | Behaviour |
|---|---|
| `0.0` (default) | Annotate all findings; never suppress. Safe for first use. |
| `0.90` | Suppress findings the LLM is ≥ 90% confident are false positives. |
| `1.0` | Only suppress when the LLM is 100% confident — effectively off. |

Start at `0.0` to see the triage output, then raise the threshold once you trust the results for your codebase.

### Local models via Ollama

Run triage entirely offline — no data leaves your machine:

```bash
ollama pull mistral
```

```toml
[triage]
model       = "mistral"
api_key_env = "UNUSED"                                           # Ollama doesn't require a key
endpoint    = "http://localhost:11434/v1/chat/completions"
```

Any model that supports the OpenAI `/v1/chat/completions` format works: Mistral, Llama 3, Phi-3, Gemma, etc.

### How triage errors are handled

- **API key missing** — prints a warning and falls through to normal scan output. Findings are never silently swallowed.
- **API call fails for one finding** — that finding shows `Triage: unavailable` and is counted as non-suppressed. The scan continues.
- **Triage errors never affect the scan exit code** — if LLM calls all fail, the exit code is determined entirely by the raw findings.

---

## SBOM attestation

Software Bill of Materials attestation lets you prove to customers, auditors, and your own security team that a published SBOM was generated by a specific, unmodified build — and that it hasn't been tampered with since.

greengate uses [Sigstore](https://sigstore.dev) **keyless signing** via the `cosign` CLI. There is no private key to manage or rotate: in CI the signing identity comes from the OIDC token issued by your CI provider (GitHub Actions, GitLab CI, etc.). The resulting signature is anchored in the [Rekor](https://rekor.sigstore.dev) public transparency log, making it auditable by anyone.

### Requirements

Install `cosign` once:

```bash
# macOS
brew install sigstore/tap/cosign

# GitHub Actions (add before the greengate step)
- uses: sigstore/cosign-installer@v3
```

### Sign a SBOM

```bash
# Generates sbom.json then signs it → writes sbom.json.bundle.json
greengate sbom --attest

# Custom paths
greengate sbom --attest --output dist/sbom.json --bundle dist/sbom.bundle.json
```

In GitHub Actions with `id-token: write` permission this runs fully non-interactively. Locally it opens a browser for a one-time OAuth flow.

The bundle file (`sbom.json.bundle.json`) contains:
- The signing certificate (your CI identity, e.g. `https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main`)
- The ECDSA signature over the SBOM content
- The Rekor transparency log entry ID and inclusion proof

Distribute both `sbom.json` and `sbom.json.bundle.json` alongside your release artifacts.

### Verify a SBOM

```bash
# Basic verification — validates the certificate chain and Rekor log entry
greengate sbom --verify sbom.json --bundle sbom.json.bundle.json

# Strict: require the SBOM to have been signed by your GitHub Actions workflow
greengate sbom --verify sbom.json \
  --bundle sbom.json.bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

Without `--certificate-oidc-issuer` / `--certificate-identity`, greengate accepts any valid Sigstore identity. For production pipelines, always pin both to your specific workflow URL.

### GitHub Actions — full release example

```yaml
permissions:
  contents: read
  id-token: write   # required for keyless Sigstore signing

steps:
  - uses: actions/checkout@v4

  - uses: sigstore/cosign-installer@v3

  - name: Install greengate
    run: |
      curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-x86_64-unknown-linux-musl \
        -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

  - name: Generate and attest SBOM
    run: greengate sbom --attest --output sbom.json

  - name: Upload SBOM and bundle as release assets
    uses: softprops/action-gh-release@v2
    with:
      files: |
        sbom.json
        sbom.json.bundle.json
```

Any consumer can then verify the SBOM without trusting you:

```bash
greengate sbom --verify sbom.json \
  --bundle sbom.json.bundle.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
```

### Config defaults

Set your expected issuer and identity once in `.greengate.toml` to avoid repeating them on every `--verify` call:

```toml
[sbom]
default_output    = "sbom.json"
expected_issuer   = "https://token.actions.githubusercontent.com"
expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
```

---

## Telemetry

greengate emits metrics after every command run. Both backends are **opt-in, optional, and independent** — telemetry errors are printed as warnings and never cause a command to fail.

### OTLP (OpenTelemetry)

```toml
[telemetry]
enabled       = true
otlp_endpoint = "http://localhost:4318"   # OTLP HTTP/JSON (port 4318, not gRPC 4317)
service_name  = "my-api"                  # attached as service.name resource attribute
```

Metrics are posted to `{otlp_endpoint}/v1/metrics` after each run. Compatible with:

| Backend | How to connect |
|---|---|
| **OpenTelemetry Collector** | Set `otlp_endpoint` to the collector's OTLP HTTP receiver |
| **Grafana Cloud** | Use the Grafana Agent OTLP endpoint, or the Cloud OTLP gateway URL |
| **Datadog** | Enable OTLP intake in the Datadog Agent (`otlp_config.receiver.protocols.http`) |
| **Honeycomb** | `https://api.honeycomb.io` with `api-key` header (set via collector) |
| **Self-hosted Grafana + Prometheus** | Use the Prometheus text format below instead |

### Prometheus text format

```toml
[telemetry]
enabled      = true
service_name = "my-api"
metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

Writes a `.prom` file with standard `# HELP` / `# TYPE` headers after each command. Add the containing directory to `node_exporter --collector.textfile.directory` and Prometheus will scrape it automatically.

### Metrics reference

| Metric | Type | Labels | Emitted by |
|---|---|---|---|
| `greengate_scan_findings_total` | counter | `severity`, `service` | `scan` |
| `greengate_scan_duration_ms` | gauge | `service` | `scan` |
| `greengate_command_duration_ms` | gauge | `command`, `success`, `service` | all commands |
| `greengate_command_success` | gauge | `command`, `service` | all commands |

**Example Grafana queries:**

```promql
# Finding rate over time
rate(greengate_scan_findings_total{severity="critical"}[7d])

# Commands failing in CI
greengate_command_success == 0

# Slowest commands
topk(5, greengate_command_duration_ms)
```

---

## GitHub Actions

The fastest setup: `greengate init --ci github-actions` writes a ready-to-use workflow. Or wire it in manually:

```yaml
name: greengate

on: [push, pull_request]

permissions:
  contents: read
  checks: write
  security-events: write

jobs:
  greengate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install greengate
        run: |
          curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-x86_64-unknown-linux-musl \
            -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

      # Scan for secrets/SAST and upload results to GitHub Code Scanning
      - name: Scan (SARIF)
        run: greengate scan --format sarif > greengate.sarif || true

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: greengate.sarif

      # Lint CI workflows for security misconfigurations
      - name: CI lint
        run: greengate ci-lint

      # Zero-trust install — catches supply chain attacks at install time
      - name: Zero-trust install
        run: greengate watch-install npm ci

      # Dependency CVE audit
      - name: Audit
        run: greengate audit

      # Coverage gate
      - name: Coverage
        run: greengate coverage --file coverage/lcov.info --min 80

      # PR complexity + coverage gaps (pull_request only)
      - name: Review
        if: github.event_name == 'pull_request'
        run: |
          greengate review \
            --base "${{ github.event.pull_request.base.sha }}" \
            --coverage-file coverage/lcov.info \
            --annotate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_SHA: ${{ github.sha }}
```

Or use the **composite action** (zero download boilerplate):

```yaml
- uses: ThinkGrid-Labs/greengate@v0
  with:
    profile: ci
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

> See [CI/CD Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration) for GitLab CI, Bitbucket Pipelines, and CircleCI examples.

---

## Configuration

Run `greengate init` for an interactive wizard, or create `.greengate.toml` manually. Every field is optional — greengate works with zero config.

```toml
[scan]
entropy             = true
entropy_threshold   = 4.5          # higher = fewer false positives
exclude_patterns    = ["tests/**", "*.test.ts", "fixtures/**"]

[sast]
enabled = true

[supply_chain]
block_phantom_scripts = true
enforce_sandbox       = true
allow_postinstall     = ["esbuild", "prisma", "@swc/core"]  # npm
allow_pip_packages    = ["grpcio"]                           # pip
allow_cargo_crates    = ["openssl"]                          # cargo

[coverage]
file = "coverage/lcov.info"
min  = 80.0

[review]
min_new_code_coverage = 80    # new lines must be covered at this % (PR gate)
complexity_budget     = 0     # 0 = warn only; > 0 = hard fail threshold

[tia]
test_patterns = [
  "**/*.test.ts",
  "**/*.test.js",
  "**/test_*.py",
  "**/*_test.go",
]

[pipeline]
steps = [
  "scan",
  "ci-lint",
  "audit",
  "coverage",
  "review --base main --coverage-file coverage/lcov.info",
]

[triage]
model                   = "claude-haiku-4-5-20251001"
api_key_env             = "ANTHROPIC_API_KEY"
auto_suppress_threshold = 0.0      # raise to 0.9 once you've reviewed triage output
context_lines           = 10
# endpoint = "http://localhost:11434/v1/chat/completions"  # Ollama

[sbom]
default_output    = "sbom.json"
# expected_issuer   = "https://token.actions.githubusercontent.com"
# expected_identity = "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"

[telemetry]
enabled       = true
otlp_endpoint = "http://localhost:4318"   # OTLP HTTP — remove if not using
# metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"  # Prometheus
service_name  = "my-service"
```

Full reference → [Configuration Reference](https://thinkgrid-labs.github.io/greengate/reference/config)

---

## Documentation

- [Getting Started](https://thinkgrid-labs.github.io/greengate/guide/getting-started)
- [CI/CD Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration)
- [Secret Patterns](https://thinkgrid-labs.github.io/greengate/reference/secret-patterns)
- [SAST Rules](https://thinkgrid-labs.github.io/greengate/reference/sast-rules)
- [Output Formats](https://thinkgrid-labs.github.io/greengate/reference/output-formats) — SARIF, JUnit, GitLab, JSON
- [Exit Codes](https://thinkgrid-labs.github.io/greengate/reference/exit-codes)
- [Roadmap](https://thinkgrid-labs.github.io/greengate/reference/roadmap)

---

## Contributing

greengate is open source under the [MIT License](LICENSE). Contributions welcome — especially new secret patterns, SAST rules, and CI platform support.

```bash
cargo test          # 255 unit + integration tests
cargo clippy        # lint
cargo fmt --check   # formatting
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, SAST rules, and run the full test suite.
