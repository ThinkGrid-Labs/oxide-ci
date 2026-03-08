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

## Suppressing known-acceptable advisories

Some transitive dependency vulnerabilities cannot be fixed by upgrading a direct dependency — the affected package is pulled in by a tool (webpack, jest, turbo) that has not yet released a compatible upgrade. Blanket-suppressing entire packages is too broad; instead, suppress individual advisory IDs so that new advisories still fail the build.

Add an `[audit]` section to `.oxideci.toml`:

```toml
[audit]
# GHSA/CVE IDs to suppress.
# Document WHY each entry is acceptable in a comment above it.
# Re-evaluate when upstream tools release new major versions.
ignore_advisories = [
  # ajv@6.x — used internally by webpack/jest schema tooling.
  # No direct dependency; cannot be forced without breaking webpack APIs.
  "GHSA-2G4F-4PWH-QVX6",

  # minimatch — pulled by glob/jest/eslint across major versions.
  # Forcing a single version breaks dependents that rely on separate major APIs.
  "GHSA-23C5-XMQV-RM74",
  "GHSA-3PPC-4F35-3M26",

  # rollup@3.x — bundled inside vite/webpack dev dependencies.
  # Production builds do not ship rollup; upgrade path blocked by vite compat.
  "GHSA-MW96-CPMX-2VGC",
]
```

Suppressed advisories are shown as warnings (`[suppressed]`) in the output but do not fail the build. Only advisories not in `ignore_advisories` exit with code `1`.

## Examples

```bash
# Audit from the current directory (auto-detects manifest)
oxide-ci audit
```

## Sample output — findings present

```
ℹ️  Auditing dependencies via OSV...
⚠️  [suppressed] GHSA-2G4F-4PWH-QVX6 — ajv 6.12.6 (known acceptable transitive dep)
⚠️  Found 2 actionable vulnerability/ies:
  [GHSA-xxxx-yyyy-zzzz] openssl 0.10.55 — Use-after-free in X.509 certificate verification
  [GHSA-aaaa-bbbb-cccc] serde_json 1.0.85 — Stack overflow on deeply nested input
Error: Audit failed: 2 vulnerability/ies found.
```

## Sample output — all clear

```
ℹ️  Auditing dependencies via OSV...
✅ No actionable vulnerabilities found (2 suppressed).
```

## In GitHub Actions

```yaml
- name: Dependency Audit
  run: oxide-ci audit
```

Exits `0` when no actionable vulnerabilities are found, `1` otherwise.

## Workflow: handling unfixable transitive dependencies

1. Run `oxide-ci audit` and note the advisory IDs that fail.
2. For each failing advisory, check whether you control the affected package directly (i.e., it appears in your top-level `package.json` / `Cargo.toml`).
   - **Yes** — upgrade or pin to a patched version.
   - **No (transitive)** — check whether upgrading any *direct* dependency removes the transitive dep. If not, add the advisory ID to `ignore_advisories` with a comment explaining why.
3. Re-run `oxide-ci audit` to confirm only suppressed advisories remain.
4. Set a calendar reminder to re-evaluate suppressed advisories when the upstream tool releases a new major version.
