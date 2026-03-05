# audit — Dependency Vulnerability Audit

Audits project dependencies for known vulnerabilities by querying the [OSV database](https://osv.dev) (Open Source Vulnerabilities). Supports 6 ecosystems and auto-detects the manifest file.

## Supported ecosystems

| Ecosystem | Manifest file |
|---|---|
| Rust | `Cargo.lock` |
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| Go | `go.sum` |
| Ruby | `Gemfile.lock` |
| .NET | `packages.lock.json` |

## Usage

```
oxide-ci audit [OPTIONS]

Options:
  -h, --help    Print help
```

## Examples

```bash
# Audit from the current directory (auto-detects manifest)
oxide-ci audit
```

## Sample output

```
ℹ️  Auditing dependencies via OSV...
⚠️  Found 2 vulnerability/ies:
  [GHSA-xxxx-yyyy-zzzz] openssl 0.10.55 — Use-after-free in X.509 certificate verification
  [GHSA-aaaa-bbbb-cccc] serde_json 1.0.85 — Stack overflow on deeply nested input
Error: Audit failed: 2 vulnerability/ies found.
```

## In GitHub Actions

```yaml
- name: Dependency Audit
  run: oxide-ci audit
```

Exits `0` when no vulnerabilities are found, `1` otherwise.
