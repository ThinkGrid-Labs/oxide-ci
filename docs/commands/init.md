# init

Interactive wizard that generates a `.oxideci.toml` configuration file for your project.

## Usage

```bash
oxide-ci init [--force]
```

## Options

| Flag | Description |
|---|---|
| `--force` | Overwrite an existing `.oxideci.toml` without prompting |

## What it does

Asks a series of short questions about your project and writes a tailored `.oxideci.toml`. Press Enter to accept the default shown in `[brackets]`.

```
oxide-ci init — generating .oxideci.toml

[ Secret & SAST Scanning ]
  Enable entropy-based secret detection? [Y/n]:
  Entropy threshold (higher = fewer false positives) [4.5]:

[ Coverage Gate ]
  LCOV file path [coverage/lcov.info]:
  Minimum coverage % [80]:

[ Kubernetes Lint ]
  Kubernetes manifests directory [./k8s]:

[ Docker Lint ]
  Dockerfile path (leave blank to skip) []:

[ Lighthouse / PageSpeed ]
  URL to audit (leave blank to skip) []:
  ...

[ Pipeline Runner ]
  Generate a default pipeline (oxide-ci run)? [Y/n]:

✅ .oxideci.toml written successfully.
```

## Generated config

```toml
[scan]
entropy = true
entropy_threshold = 4.5
entropy_min_length = 20

[coverage]
file = "coverage/lcov.info"
min = 80

[lint]
target_dir = "./k8s"

[lighthouse]
url = "https://yourapp.com"
strategy = "mobile"
min_performance = 80
min_accessibility = 90
min_best_practices = 80
min_seo = 80

[reassure]
current = "output/current.perf"
baseline = "output/baseline.perf"
threshold = 15

[pipeline]
steps = [
  "scan",
  "audit",
  "coverage",
  "lighthouse",
]
```

## Updating an existing config

```bash
# Will fail if .oxideci.toml already exists
oxide-ci init

# Overwrite without prompting
oxide-ci init --force
```

## Next steps after init

Once `.oxideci.toml` exists, every subsequent `oxide-ci` invocation reads it automatically. Run the full pipeline with:

```bash
oxide-ci run
```
