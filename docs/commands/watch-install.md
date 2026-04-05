---
title: 'watch-install — Zero-Trust Supply Chain Gate'
description: 'Three-layer npm/yarn/pnpm/bun supply chain gate: pre-flight postinstall script scanning (entropy + eval/network signals), runtime phantom-file detection, and exec-drop analysis. Stops supply-chain attacks before they reach your machine.'
---

# watch-install — Zero-Trust Supply Chain Quality Gate

> **Intercept package installs before malicious code reaches your machine.**

`greengate watch-install` is a zero-trust quality gate that wraps any package manager and enforces three independent layers of supply-chain security. It catches both known attack patterns (CVE-tracked) and novel, behaviour-based attacks that vulnerability databases cannot see — including the class of attacks represented by the [2025 axios-ecosystem compromise](#background).

---

## Usage

```bash
greengate watch-install <PACKAGE_MANAGER> [ARGS...]
```

All arguments after the package manager name are forwarded verbatim:

```bash
# Drop-in for npm install
greengate watch-install npm install

# Frozen lockfile (CI)
greengate watch-install npm ci

# pnpm with flags
greengate watch-install pnpm install --frozen-lockfile

# yarn
greengate watch-install yarn install --immutable

# bun
greengate watch-install bun install
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--no-fail` | — | Report findings to stderr but exit 0. Useful for audit-only pipelines not yet blocking. |

---

## Three-layer architecture

### Layer 1 — Pre-flight static script scan

Before the install runs, `watch-install` scans every `preinstall`, `install`, and `postinstall` script found in present `node_modules/*/package.json` files for signals of malicious intent. The same scan runs again after the install completes on all packages — catching freshly downloaded packages too.

**Signals detected:**

| Category | Patterns |
|---|---|
| Dynamic code execution | `eval()`, `new Function()`, `vm.runInContext()`, `vm.runInNewContext()` |
| Obfuscation / Base64 | `Buffer.from(`, `atob()`, `btoa()` |
| Raw networking | `require('http')`, `require('https')`, `require('net')`, `require('dns')`, `require('tls')` |
| HTTP client libraries | `fetch(`, `axios`, `got(`, `request(`, `superagent` |
| Process / shell spawn | `child_process`, `execSync(`, `spawnSync(`, `exec(`, `spawn(`, `curl `, `wget ` |
| Env exfiltration | `process.env` |
| **High entropy** | Shannon entropy > 4.8 over any 64-char window — a reliable indicator of obfuscated or minified malicious payloads |

Finding any signal, or exceeding the entropy threshold, produces a `SCRIPT_THREAT` finding.

### Layer 2 — Runtime phantom-file detection

A 250 ms polling thread watches `node_modules/` while the package manager runs. If a file is written by a postinstall script and then deleted before the install exits — the classic dropper pattern — it is flagged as a `PHANTOM`.

```
postinstall → write binary → execute → unlink to hide evidence
```

This is the primary pattern used in the 2025 axios-ecosystem compromise.

### Layer 3 — Post-install executable-drop detection

After the install completes, any new executable file that appeared in the project root (outside `node_modules/`) that was not present before the install is flagged as an `EXEC_DROP`. Legitimate package managers never place executables outside `node_modules/`.

---

## Example output

**Script threat detected (Layer 1):**

```
⚠️  Zero-Trust Supply Chain Gate: 1 package(s) with suspicious lifecycle scripts:

  [SCRIPT_THREAT] malicious-utils (postinstall)
    Signals   : fetch(, process.env, eval()
    Entropy   : 5.91  (threshold 4.80 — likely obfuscated)

  Tip: inspect each flagged script manually. If the package is a known
  native build tool, add it to [supply_chain] allow_postinstall in .greengate.toml.

Error: Zero-Trust Supply Chain Gate: 1 newly installed package(s) with suspicious
lifecycle scripts detected — halting.
```

**Phantom detected (Layer 2):**

```
🚨 greengate watch-install: 1 suspicious event(s) detected:

  [PHANTOM   ] evil-pkg
               path: node_modules/evil-pkg/.postinstall

  Tip: if this package is a known native build tool (e.g. esbuild, swc),
  add it to [supply_chain] allow_postinstall in .greengate.toml to suppress.

Error: Zero-Trust Supply Chain Gate: 1 blocking runtime event(s) detected — halting.
```

**Clean install:**

```
✅ Zero-Trust Supply Chain Gate: clean — no phantom files, executable drops,
   or suspicious scripts detected.
```

---

## Configuration

All options live under `[supply_chain]` in `.greengate.toml`:

```toml
[supply_chain]
# Halt the install when any layer detects a threat (default: true).
block_phantom_scripts = true

# Also monitor the project root for new executables (Layer 3, default: true).
enforce_sandbox = true

# Packages whose postinstall scripts legitimately create temp files or make
# network calls (e.g. native build tools that compile .node addons).
# Findings from these packages are downgraded to warnings — they still appear
# in output for full audit trail but do not cause a non-zero exit.
allow_postinstall = ["esbuild", "prisma", "@swc/core"]
```

### allow_postinstall behaviour

Allowlisted packages still appear in output with `[allowlisted — warning only]`, providing a full audit trail. They do not trigger `block_phantom_scripts` failure across any of the three layers.

---

## CI usage

Replace your existing `npm install` / `npm ci` step:

```yaml
- name: Install GreenGate
  run: |
    curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Zero-Trust supply chain install
  run: greengate watch-install npm ci
```

For teams not yet ready to block on findings, start in audit-only mode:

```yaml
- name: Supply-chain audit (non-blocking)
  run: greengate watch-install --no-fail npm ci
```

---

## Layered defence with `audit`

`watch-install` and `greengate audit` are complementary, not redundant:

| Tool | When it runs | What it catches |
|---|---|---|
| `greengate audit` | Pre/post install | Known CVEs in the OSV database for your lock file |
| `greengate watch-install` | During and after install | Runtime dropper behaviour, obfuscated scripts, and exec-drops that CVE databases cannot see |

Run both for complete coverage:

```yaml
- run: greengate watch-install npm ci   # zero-trust gate: behaviour + static scan
- run: greengate audit                  # known CVE database check
```

---

## Background

In early 2025, the [axios](https://github.com/axios/axios) npm ecosystem was the subject of a supply-chain compromise discussion where attackers targeted postinstall hooks to execute and then self-delete malicious payloads. This attack pattern — write, execute, unlink — leaves no trace in `node_modules/` after the install finishes, making it invisible to static scanners and lock-file diffing tools.

Beyond dropper-style attacks, modern supply-chain attacks increasingly rely on obfuscated scripts that exfiltrate environment variables (CI secrets, tokens, cloud credentials) via HTTP requests made during install time. The Layer 1 static scan targets this exact vector.

---

## Limitations

- **Pure network exfiltration without file writes** — if a postinstall script sends data over the network without writing any file, there is no filesystem event for Layer 2 to observe. Layer 1 static scanning catches the network call pattern in the script source. Pair with network egress controls in CI for defence in depth.
- **Windows** — phantom detection works on Windows via `std::fs` polling, but exec-drop detection uses file-extension heuristics (`.exe`, `.bat`, `.cmd`, `.ps1`) rather than the execute bit.
- **Very fast droppers** — files created and deleted within a single 250 ms poll window may be missed by Layer 2. Layer 1 static scanning of the postinstall script provides a second line of defence for these cases.
- **Obfuscation at install time** — if a package downloads and decodes its malicious payload at runtime (not in the static script text), Layer 1 will not see it. Layer 2 runtime detection still applies.

See also: [Roadmap](/reference/roadmap) for planned `sandbox-install` with full network isolation.
