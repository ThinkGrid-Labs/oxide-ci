---
title: 'pip-install — Zero-Trust Python Supply Chain Gate'
description: 'Wrap pip install with three-layer supply chain protection: typosquat detection against 60 popular PyPI packages, post-install Python source scanning via RECORD files, and executable-drop detection.'
---

# pip-install — Zero-Trust Python Supply Chain Gate

> **Intercept malicious PyPI packages before they reach your environment.**

`greengate pip-install` wraps `pip install` with three independent layers of supply-chain security. It catches typosquatted package names before pip runs, scans installed Python source files after pip finishes, and detects any unexpected executables dropped into your virtual environment.

## Usage

```bash
greengate pip-install [OPTIONS] [PIP_ARGS...]
```

All arguments are forwarded verbatim to pip:

```bash
# Drop-in for pip install
greengate pip-install requests flask==3.0.0

# Install from requirements file
greengate pip-install -r requirements.txt

# Install with extras
greengate pip-install "fastapi[standard]"

# Upgrade a package
greengate pip-install --upgrade django
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--pip <PATH>` | `pip` | Path to the pip executable to use (e.g. `pip3`, `.venv/bin/pip`) |
| `--no-fail` | — | Report findings to stderr but exit 0. Useful for audit-only pipelines. |

## Three-layer architecture

### Layer 1 — Typosquat detection (pre-install)

Before pip runs, each package name in the install arguments is compared against the 60 most-downloaded PyPI packages using Levenshtein distance. If the edit distance is ≤ 2, the install is **halted before pip executes**.

```
greengate pip-install reqeusts

Error: Possible typosquat: "reqeusts" is 2 edit(s) away from "requests".
       Verify the package name is correct before installing.
```

This catches attacks like `requets`, `reqeusts`, `djang0`, `flaskk`, `boto3_`, etc.

### Layer 2 — Post-install source scan

After pip installs the package, greengate reads the `.dist-info/RECORD` file to discover every file the package installed. Python source files (`.py`) are scanned for 25 suspicious signals:

| Category | Signals |
|---|---|
| Dynamic code execution | `eval(`, `exec(`, `compile(`, `__import__` |
| Obfuscation / encoding | `base64.b64decode`, `codecs.decode`, `zlib.decompress` |
| Network exfiltration | `urllib.request`, `http.client`, `socket.connect`, `requests.post` |
| Subprocess / shell | `subprocess.run`, `os.system`, `os.popen`, `pty.spawn` |
| Env var access | `os.environ`, `os.getenv` |
| High entropy strings | Shannon entropy > 4.8 over any 64-char window |

### Layer 3 — Executable-drop detection

After install, greengate checks your virtual environment's `bin/` (Unix) or `Scripts/` (Windows) directory for new executables that were not present before the install. Legitimate packages create named entry points — unexpected binaries or scripts are flagged.

## Example output

**Typosquat detected (Layer 1):**

```
Error: Possible typosquat: "reqeusts" is 2 edit(s) away from "requests".
       Verify the package name is correct before installing.
```

**Suspicious source file (Layer 2):**

```
⚠️  Supply chain scan found 1 suspicious file(s):

  [SUSPICIOUS] malicious-sdk/exfil.py
    Signals: requests.post, os.environ, base64.b64decode
    Entropy: 5.12 (threshold 4.80)

Error: Supply chain gate: suspicious Python source found after install.
```

**Clean install:**

```
✅ pip-install: no typosquats, suspicious source, or executable drops detected.
```

## Configuration

```toml
[supply_chain]
# PyPI package names exempted from typosquat and source scanning.
# Use for internal packages whose names are intentionally similar to popular ones.
allow_pip_packages = [
  # "my-internal-requests-wrapper",
]
```

## CI usage

```yaml
- name: Zero-trust pip install
  run: greengate pip-install -r requirements.txt

# With a specific pip
- name: Zero-trust pip install (venv)
  run: greengate pip-install --pip .venv/bin/pip -r requirements.txt

# Audit-only (non-blocking)
- name: Supply chain audit
  run: greengate pip-install --no-fail -r requirements.txt
```

## Pairing with `audit`

`pip-install` and `greengate audit` are complementary:

| Tool | What it catches |
|---|---|
| `greengate audit` | Known CVEs in installed packages (via OSV database) |
| `greengate pip-install` | Typosquats, obfuscated source, exec-drops — behaviour CVE databases cannot see |

Run both:

```bash
greengate pip-install -r requirements.txt   # zero-trust gate
greengate audit                             # known CVE check
```
