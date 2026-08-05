# Changelog

All notable changes to greengate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Positioning greengate as the security & supply-chain gate for the AI-coding era.

### Added
- **Slopsquat / hallucinated-package guard** — a new pre-flight layer on every
  install wrapper (`cargo-add`, `pip-install`, `watch-install` for
  npm/yarn/pnpm/bun) that catches the AI-era attack where an LLM invents a
  package name, an attacker registers it, and an agent installs it. Edit-distance
  typosquat checks miss these novel names, so the guard scores registry metadata
  — existence, age, adoption, source repo — of any package an install
  *introduces* (already-pinned deps are trusted and skipped). HIGH suspicion
  blocks, MEDIUM warns; unreachable registries fail **open**. Configurable via
  `[supply_chain]` `slopsquat_check` / `slopsquat_min_age_days` /
  `slopsquat_min_downloads`.
- **Dependency-confusion detection** — declare your private package names, npm
  scopes (`@myco`), or `prefix-*` patterns in `[supply_chain] internal_packages`;
  if one of them *also* resolves on the public registry during an install, it's
  flagged as a dependency-confusion risk (shares the same pre-flight and registry
  lookup as the slopsquat guard).
- **`greengate provenance`** — reports the AI-authored vs human-authored split of
  a commit range (detected from `Co-Authored-By` / `Assisted-By` trailers and
  author identity), with a per-tool breakdown, and can fail the build when
  AI-generated code exceeds a share of new lines (`--max-ai-lines-pct`). Supports
  `--format text|json|sarif`.

## [0.3.3] - 2026-07-25

### Fixed
- **Broken install** — the README and composite action downloaded release
  binaries by Rust target-triple names (`greengate-x86_64-unknown-linux-musl`,
  …) that were never published, so every documented install path 404'd. All
  references now match the actual release asset names (`greengate-linux-amd64`,
  `greengate-macos-arm64`, `greengate-macos-amd64`, `greengate-windows-amd64.exe`).
- **Vulnerable dependencies** — upgraded `anyhow` to 1.0.104 and
  `crossbeam-epoch` to 0.9.20, resolving RUSTSEC-2026-0190 and RUSTSEC-2026-0204
  (surfaced by greengate's own dependency audit in CI).

### Added
- **`--version` / `-V` flag.**
- **Fewer secret-scan false positives.** Three precision filters that gate only
  the noisy heuristics — never the patterns that catch real secrets:
  - an allowlist for documented example, placeholder, and test credentials
    (applied to regex, entropy, and SAST string-literal detection);
  - entropy-noise recognizers for content hashes / git object ids, package
    integrity digests, and base64 data-URI payloads;
  - PEM key-body entropy suppression (private-key headers are still caught).

  On the new benchmark this raises precision from 55.6% to **90.9%** with recall
  held at **100%** (F1 71.4% → 95.2%).
- **Signed releases.** Every release binary is keyless-signed with Sigstore
  (`cosign sign-blob`) in the release workflow; a `.sig`/`.pem` bundle ships
  alongside each asset and verification is documented in the README.
- **Benchmark suite** (`bench/`) — a labeled corpus and stdlib-only harness that
  scores greengate and any installed competitors on secret-detection
  precision/recall/F1. Competitors absent from `PATH` are skipped, never
  fabricated.

### Changed
- README now leads with the install-time supply-chain gate — the capability
  incumbent CVE and secret scanners don't provide — rather than with breadth.
- `scan --fix` is de-emphasized in favour of suppression and baselines, with a
  clearer warning that it rewrites source in place.

[0.3.3]: https://github.com/greengate-dev/greengate/releases/tag/v0.3.3
