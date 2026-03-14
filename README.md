# GreenGate — Rust DevOps CLI for CI Quality Gates

> A blazing-fast DevOps CLI built in Rust — secret scanning, AST-based SAST, PR review intelligence, Kubernetes linting, coverage gates, dependency auditing, web performance, and more — in a single zero-dependency binary.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/thinkgrid-labs/greengate/ci.yml?branch=main)](https://github.com/thinkgrid-labs/greengate/actions)
[![GitHub release](https://img.shields.io/github/v/release/thinkgrid-labs/greengate)](https://github.com/thinkgrid-labs/greengate/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/greengate)](https://crates.io/crates/greengate)
[![Downloads](https://img.shields.io/crates/d/greengate)](https://crates.io/crates/greengate)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)](https://www.rust-lang.org)
[![GitHub Stars](https://img.shields.io/github/stars/thinkgrid-labs/greengate?style=social)](https://github.com/thinkgrid-labs/greengate/stargazers)

**[Documentation](https://thinkgrid-labs.github.io/greengate)** · [Commands](https://thinkgrid-labs.github.io/greengate/commands/scan) · [CI Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration) · [Config Reference](https://thinkgrid-labs.github.io/greengate/reference/config)

---

## What it does

| Command | Purpose |
|---|---|
| `greengate scan` | Secrets, PII & AST-based SAST for JS/TS/Python/Go |
| `greengate review` | PR Complexity Score + new-code coverage gaps |
| `greengate lint` | Kubernetes manifest linting |
| `greengate docker-lint` | Dockerfile best-practice checks |
| `greengate coverage` | LCOV / Cobertura coverage threshold gate |
| `greengate audit` | OSV dependency vulnerability audit |
| `greengate lighthouse` | PageSpeed Insights performance gate |
| `greengate reassure` | React component render regression gate |
| `greengate sbom` | CycloneDX 1.5 SBOM generation |
| `greengate run` | Run all quality gates from `.greengate.toml` |
| `greengate install-hooks` | Install as git pre-commit hook |

---

## Installation

**macOS (Apple Silicon):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-macos-arm64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**macOS (Intel):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-macos-amd64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Linux (x64):**
```bash
curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-linux-amd64 \
  -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate
```

**Windows (x64) — PowerShell:**
```powershell
Invoke-WebRequest -Uri "https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-windows-amd64.exe" `
  -OutFile "$env:USERPROFILE\.local\bin\greengate.exe"
```

**Build from source (Rust 1.85+):**
```bash
cargo install --git https://github.com/thinkgrid-labs/greengate
```

---

## Quick start

```bash
# Scan for secrets and run SAST
greengate scan

# Analyze a PR: complexity score + new-code coverage gaps
greengate review --base main --coverage-file coverage/lcov.info

# Enforce 80% minimum coverage
greengate coverage --file coverage/lcov.info --min 80

# Audit dependencies for known CVEs
greengate audit

# Lint Kubernetes manifests
greengate lint --dir ./k8s

# Install as a git pre-commit hook
greengate install-hooks

# Run all gates from config
greengate run
```

---

## GitHub Actions

```yaml
- name: Install GreenGate
  run: |
    curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Secret, PII & SAST scan
  run: greengate scan --annotate
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: PR review (complexity + coverage gaps)
  if: github.event_name == 'pull_request'
  run: |
    greengate review \
      --base "${{ github.event.pull_request.base.sha }}" \
      --coverage-file coverage/lcov.info \
      --min-coverage 80 \
      --annotate
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_SHA: ${{ github.sha }}

- name: Coverage gate
  run: greengate coverage --file coverage/lcov.info --min 80

- name: Dependency audit
  run: greengate audit
```

> See [CI/CD Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration) for full GitHub Actions, GitLab CI, Bitbucket, and CircleCI examples.

---

## Configuration

Create `.greengate.toml` in your repo root. All fields are optional:

```toml
[scan]
exclude_patterns = ["tests/**", "*.test.ts", "vendor/**"]
entropy = true
entropy_threshold = 4.5

[coverage]
file = "coverage/lcov.info"
min = 80.0

[review]
min_new_code_coverage = 80
complexity_budget = 0   # 0 = warn only; > 0 = hard fail threshold

[pipeline]
steps = ["scan", "review --base main --coverage-file coverage/lcov.info", "coverage", "audit"]
```

Full reference → [docs/reference/config](https://thinkgrid-labs.github.io/greengate/reference/config)

---

## Documentation

Full guides, command references, and CI examples live in the **[docs site](https://thinkgrid-labs.github.io/greengate)**:

- [Getting Started](https://thinkgrid-labs.github.io/greengate/guide/getting-started)
- [CI/CD Integration](https://thinkgrid-labs.github.io/greengate/guide/ci-integration)
- [Use Cases](https://thinkgrid-labs.github.io/greengate/guide/use-cases)
- **Commands:** [scan](https://thinkgrid-labs.github.io/greengate/commands/scan) · [review](https://thinkgrid-labs.github.io/greengate/commands/review) · [coverage](https://thinkgrid-labs.github.io/greengate/commands/coverage) · [audit](https://thinkgrid-labs.github.io/greengate/commands/audit) · [lint](https://thinkgrid-labs.github.io/greengate/commands/lint) · [docker-lint](https://thinkgrid-labs.github.io/greengate/commands/docker-lint) · [lighthouse](https://thinkgrid-labs.github.io/greengate/commands/lighthouse) · [reassure](https://thinkgrid-labs.github.io/greengate/commands/reassure) · [sbom](https://thinkgrid-labs.github.io/greengate/commands/sbom) · [run](https://thinkgrid-labs.github.io/greengate/commands/run)
- **Reference:** [Config](https://thinkgrid-labs.github.io/greengate/reference/config) · [Secret Patterns](https://thinkgrid-labs.github.io/greengate/reference/secret-patterns) · [SAST Rules](https://thinkgrid-labs.github.io/greengate/reference/sast-rules) · [Output Formats](https://thinkgrid-labs.github.io/greengate/reference/output-formats) · [Exit Codes](https://thinkgrid-labs.github.io/greengate/reference/exit-codes)

---

## Contributing

GreenGate is open source under the [MIT License](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for details on adding secret patterns, SAST rules, and running tests.

```bash
cargo test          # unit + integration tests
cargo clippy        # lint
cargo fmt --check   # formatting
```
