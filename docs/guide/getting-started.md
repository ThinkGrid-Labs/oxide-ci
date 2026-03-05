# Getting Started

OxideCI is a single compiled Rust binary — no runtime dependencies, no package managers to fight.

## Installation

### Pre-compiled binary (recommended)

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

### Build from source (requires Rust 1.85+)

```bash
cargo install --git https://github.com/ThinkGrid-Labs/oxide-ci
```

### Verify installation

```bash
oxide-ci --version
# oxide-ci 0.2.4
```

## Quick Start

```bash
# Scan for secrets and run SAST on JS/TS files
oxide-ci scan

# Lint all Kubernetes YAML files
oxide-ci lint --dir ./k8s

# Enforce 80% minimum test coverage
oxide-ci coverage --file coverage/lcov.info --min 80

# Audit dependencies for known CVEs
oxide-ci audit

# Install as a git pre-commit hook
oxide-ci install-hooks

# Gate on Lighthouse web performance scores
oxide-ci lighthouse --url https://yourapp.com

# Gate on React component performance regressions
oxide-ci reassure
```

## What OxideCI solves

| Problem | Command |
|---|---|
| Hardcoded secrets pushed to git | `oxide-ci scan` |
| XSS, eval, command injection in JS/TS | `oxide-ci scan` (SAST) |
| Kubernetes manifests missing resource limits | `oxide-ci lint` |
| Test coverage silently dropping | `oxide-ci coverage` |
| Vulnerable dependencies shipping to production | `oxide-ci audit` |
| Secrets committed before anyone notices | `oxide-ci install-hooks` |
| Lighthouse score regressing between deploys | `oxide-ci lighthouse` |
| React component render performance regressing | `oxide-ci reassure` |

## Next steps

- Set up a [configuration file](/reference/config) to share settings across all commands
- Integrate with [GitHub Actions or GitLab CI](/guide/ci-integration)
- Explore individual [command references](/commands/scan)
