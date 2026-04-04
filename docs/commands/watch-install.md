# watch-install

> **Supply-chain protection for npm, yarn, pnpm, and bun installs.**

`greengate watch-install` wraps your package manager and monitors `node_modules/` in real time during the install. If a postinstall script creates a file and then deletes it before the install finishes — the classic dropper signature used in attacks like the [2025 axios compromise](#background) — the install is halted and the offending package is named.

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
| `--no-fail` | — | Report findings to stderr but exit 0. Useful for audit-only pipelines that are not yet blocking. |

---

## What it detects

### 1. Phantom files (`PHANTOM`)

A file is created inside `node_modules/` during a postinstall script and deleted before the install completes. This is the primary dropper signature:

```
postinstall → write binary to disk → execute → unlink to hide evidence
```

GreenGate polls `node_modules/` every 250 ms while the package manager runs. Any file that appears in one poll and disappears in a later poll is flagged.

### 2. Executable drops (`EXEC_DROP`)

A new executable file (one with the execute bit set on Unix, or a `.exe/.bat/.cmd/.ps1` extension on Windows) appears in the project root after the install completes that was not there before. Legitimate package managers never place executables outside `node_modules/`.

---

## Example output

**Phantom detected:**

```
🚨 greengate watch-install: 1 suspicious event(s) detected:

  [PHANTOM   ] evil-pkg
               path: node_modules/evil-pkg/.postinstall

  Tip: if this package is a known native build tool (e.g. esbuild, swc),
  add it to [supply_chain] allow_postinstall in .greengate.toml to suppress.

Error: watch-install: 1 blocking event(s) detected — halting.
```

**Clean install:**

```
✅ watch-install: clean — no phantom files or executable drops detected.
```

---

## Configuration

All options live under `[supply_chain]` in `.greengate.toml`:

```toml
[supply_chain]
# Halt the install when a phantom or exec-drop is detected (default: true).
block_phantom_scripts = true

# Also monitor the project root for new executables (default: true).
enforce_sandbox = true

# Packages whose postinstall scripts legitimately create temp files.
# Native build tools (esbuild, @swc/core, prisma) compile .node addons
# and may create intermediate files during the build. List them here to
# downgrade their findings to warnings instead of errors.
allow_postinstall = ["esbuild", "prisma", "@swc/core"]
```

### allow_postinstall behaviour

Packages on the allowlist still appear in the output with `[allowlisted — warning only]` so you have a full audit trail, but they do not cause `block_phantom_scripts` to trigger a non-zero exit.

---

## CI usage

Replace your existing `npm install` / `npm ci` step with `greengate watch-install`:

```yaml
- name: Install GreenGate
  run: |
    curl -sL https://github.com/thinkgrid-labs/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Supply-chain safe install
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
| `greengate audit` | Pre/post install | Known CVEs in OSV database for your lock file |
| `greengate watch-install` | During install | Runtime dropper behaviour that CVE databases cannot see |

Run both:

```yaml
- run: greengate watch-install npm ci   # catches runtime behaviour
- run: greengate audit                  # catches known CVEs
```

---

## Background

In early 2025, the [axios](https://github.com/axios/axios) npm package was the subject of a supply-chain compromise discussion where attackers targeted postinstall hooks to execute and then self-delete malicious payloads. This attack pattern — write, execute, unlink — leaves no trace in `node_modules/` after the install finishes, making it invisible to static scanners and lock-file diffing tools.

`watch-install` catches it because the file system events happen _during_ the install window, not after.

---

## Limitations

- **Pure network exfiltration** — if a postinstall script sends data over the network without writing any file, there is no filesystem event to observe. Pair with network egress controls in CI for defence in depth.
- **Windows** — phantom detection works on Windows via `std::fs` polling, but exec-drop detection uses file-extension heuristics (`.exe`, `.bat`, `.cmd`, `.ps1`) rather than the execute bit.
- **Very fast droppers** — files created and deleted within a single 250 ms poll window may be missed. This is the theoretical lower bound; real-world payloads take longer to download and execute.

See also: [Roadmap](/reference/roadmap) for planned sandbox-level isolation (`greengate sandbox-install`).
