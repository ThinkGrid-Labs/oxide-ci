# Changelog

All notable changes to greengate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.3]: https://github.com/thinkgrid-labs/greengate/releases/tag/v0.3.3
