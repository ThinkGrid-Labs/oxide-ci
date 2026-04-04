# Roadmap

This page tracks planned features and the reasoning behind their prioritisation.

---

## Shipped

### v0.2.x — Supply chain: `watch-install`

`greengate watch-install` wraps any package manager (`npm`, `yarn`, `pnpm`, `bun`) and monitors `node_modules/` in real time during the install. It detects the two most common runtime attack signatures:

- **Phantom files** — postinstall scripts that write a binary, execute it, and delete it before the install finishes (dropper pattern, as seen in the 2025 axios-ecosystem compromise)
- **Executable drops** — new executable files placed in the project root that were not present before the install began

Controlled via `[supply_chain]` in `.greengate.toml`. See the [watch-install command reference](/commands/watch-install) for full details.

---

## Planned

### Feature 2 — `sandbox-install` (Zero-Trust Package Runner)

**Status:** Planned — implementation deferred pending architectural decision.

**What it does:**

`greengate sandbox-install` would go one level deeper than `watch-install`. Instead of observing what a package manager does on the host filesystem, it would run the entire install inside an isolated container, then extract only the verified output:

1. Pull a minimal `node:alpine` image via the Docker API
2. Mount the project's `package.json` / lock file read-only
3. Run `npm ci` (or equivalent) inside the container with `--network=none` (no outbound network access during install)
4. Cryptographically hash the container's `node_modules/` output and compare it against the expected dependency tree from the lock file
5. Extract only the verified `node_modules/` to the host

This provides a stronger guarantee than `watch-install` because:

| | `watch-install` | `sandbox-install` |
|---|---|---|
| Phantom file detection | Yes | Yes (no host filesystem to write to) |
| Network exfiltration during install | No | Yes — `--network=none` blocks it |
| Host process isolation | No | Yes — install never runs on host |
| Requires Docker | No | Yes |

**Why it is deferred:**

The primary implementation dependency, `bollard` (the Rust Docker API crate), is fully async and requires a `tokio` runtime. GreenGate is currently synchronous (`rayon`-based). Adding `tokio` is a non-trivial architectural change and binary size increase that needs careful consideration before v1.0.

Additionally, `sandbox-install` requires Docker to be running on the host — which breaks GreenGate's zero-runtime-dependency guarantee for that command. The plan is to make it gracefully fail with a clear error when Docker is not present, rather than requiring it globally.

**Tracking:** Contributions welcome. See [CONTRIBUTING.md](https://github.com/ThinkGrid-Labs/greengate/blob/main/CONTRIBUTING.md) for architecture guidance.

---

### Feature 3 — SBOM-based install verification

Cross-reference the post-install `node_modules/` tree against the project's CycloneDX SBOM (`greengate sbom`) to detect packages that installed without appearing in the declared dependency graph. Complements `watch-install` for detecting dependency confusion attacks.

---

### Feature 4 — `scan` improvements

- **Python taint tracking** — extend the existing JS/TS taint engine to Python (Flask/Django request sources → SQL/command injection sinks)
- **Go taint tracking** — similar, targeting `net/http` request sources
- **Rust SAST** — `unsafe` block detection, `std::process::Command` with unsanitised input

---

## Not planned

| Feature | Reason |
|---|---|
| Native Windows exec-drop detection (beyond extension heuristics) | Requires PE parsing or Windows API calls — out of scope for a CLI tool |
| CI/CD platform plugins (GitHub Action, GitLab Component) | Tracked separately from the core binary |
| Web UI / dashboard | Out of scope — GreenGate is intentionally a CLI/CI tool |
