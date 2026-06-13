---
title: 'cargo-add — Zero-Trust Rust Supply Chain Gate'
description: 'Wrap cargo add with three-layer supply chain protection: typosquat detection against 60 popular crates, build.rs static analysis for every new crate, and transitive dependency explosion guard.'
---

# cargo-add — Zero-Trust Rust Supply Chain Gate

> **Intercept malicious crates before they execute build scripts on your machine.**

`greengate cargo-add` wraps `cargo add` with three independent layers of supply-chain security. Unlike npm, Cargo crates run `build.rs` at compile time — giving a malicious crate arbitrary code execution on every `cargo build`. This command blocks that attack vector.

## Usage

```bash
greengate cargo-add [OPTIONS] [CARGO_ARGS...]
```

All arguments are forwarded verbatim to `cargo add`:

```bash
# Add a single crate
greengate cargo-add serde

# Add with features
greengate cargo-add serde --features derive

# Add multiple crates
greengate cargo-add tokio anyhow clap

# Add a dev-dependency
greengate cargo-add --dev mockall
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--no-fail` | — | Report findings to stderr but exit 0. Useful for audit-only pipelines. |

## Three-layer architecture

### Layer 1 — Typosquat detection (pre-add)

Before `cargo add` runs, each crate name is compared against the 60 most-downloaded crates.io crates using Levenshtein distance. If the edit distance is ≤ 2, the operation is **halted before cargo runs**.

```
greengate cargo-add serd

Error: Possible typosquat: "serd" is 1 edit(s) away from "serde".
       Verify the crate name is correct before adding.
```

This catches attacks like `serd`, `tokio_`, `anyhoww`, `reqwest2`, etc.

### Layer 2 — `build.rs` static analysis (post-add)

After `cargo add` and `cargo fetch`, greengate locates the `build.rs` file for each newly added crate in `~/.cargo/registry/src/` and scans it for 25 suspicious signals:

| Category | Signals |
|---|---|
| Network access | `TcpStream::connect`, `reqwest`, `ureq`, `curl_sys`, `hyper` |
| Subprocess spawning | `Command::new`, `std::process::Command`, `process::exit` |
| Environment exfiltration | `std::env::var`, `env::vars()`, `HOME`, `AWS_`, `GITHUB_TOKEN` |
| Filesystem writes outside target | `std::fs::write`, `File::create` with absolute path |
| Dynamic code loading | `dlopen`, `libloading`, `unsafe extern "C"` |
| High entropy strings | Shannon entropy > 4.8 over any 64-char window |

### Layer 3 — Dependency explosion guard

After the add, greengate diffs `Cargo.lock` before and after. If more than **50 new transitive dependencies** were added, a warning is emitted. Adding a simple utility crate that pulls in 80 dependencies is a significant attack surface expansion.

```
⚠️  Dependency explosion: adding "fancy-logger" introduced 67 new transitive dependencies.
    Review Cargo.lock carefully before committing.
```

## Example output

**Typosquat detected (Layer 1):**

```
Error: Possible typosquat: "tokio_" is 1 edit(s) away from "tokio".
       Verify the crate name is correct before adding.
```

**Suspicious build.rs (Layer 2):**

```
⚠️  Supply chain scan: suspicious build.rs in "malicious-crate@0.1.0":
    Signals: TcpStream::connect, std::env::var("GITHUB_TOKEN"), Command::new

Error: Supply chain gate: suspicious build.rs detected — halting.
```

**Clean add:**

```
✅ cargo-add: no typosquats, suspicious build.rs, or dependency explosion detected.
```

## Configuration

```toml
[supply_chain]
# Crate names exempted from typosquat and build.rs scanning.
# Use for internal crates or crates with legitimately complex build scripts.
allow_cargo_crates = [
  # "openssl",     # has complex build.rs for system lib detection
  # "ring",        # cryptography crate with intentionally complex build
]
```

## CI usage

```yaml
# In a workflow that adds new dependencies
- name: Zero-trust cargo add
  run: greengate cargo-add serde tokio anyhow

# Audit-only (non-blocking)
- name: Supply chain audit
  run: greengate cargo-add --no-fail serde
```

## Why `build.rs` matters

Unlike npm postinstall scripts (which run at install time), Rust's `build.rs` runs at **every `cargo build`** — including in CI, on every developer's machine, and during release builds. A malicious `build.rs` can:

- Exfiltrate CI secrets (`GITHUB_TOKEN`, `AWS_*`, `CARGO_REGISTRY_TOKEN`)
- Modify generated code to introduce backdoors
- Make outbound network requests before your firewall rules can stop them
- Write files outside the build directory

`greengate cargo-add` scans the `build.rs` before you commit the `Cargo.lock`, when it's still easy to remove the dependency.
