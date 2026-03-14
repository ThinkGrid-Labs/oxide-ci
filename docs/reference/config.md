# Configuration File (.greengate.toml)

Place `.greengate.toml` in the root of your repository. CLI flags always override config file values. All fields are optional — omitted values fall back to built-in defaults.

## Full reference

```toml
[scan]
# Glob patterns for paths to exclude from scanning
exclude_patterns = [
  "tests/**",
  "*.test.ts",
  "fixtures/**",
  "vendor/**",
]

# Extra patterns added on top of the 26 built-ins
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
]

# Shannon entropy detection — flags high-entropy tokens not matched by named patterns
entropy = true
entropy_threshold = 4.5    # lower = more sensitive (default 4.5)
entropy_min_length = 20    # ignore tokens shorter than this (default 20)

[sast]
# Set to false to disable SAST entirely and fall back to regex for JS/TS files
enabled = true

# Suppress specific rule IDs
disabled_rules = [
  # "SAST/ChildProcessExec",
  # "SAST/EvalUsage",
  # "SMELL/LongFunction",
]

# Code smell thresholds
max_function_lines = 50   # flag functions longer than this many lines (default 50)
max_parameters     = 5    # flag functions with more parameters than this (default 5)
max_nesting_depth  = 4    # flag control-flow nesting deeper than this (default 4)

# Custom tree-sitter rules — each must include a @match capture
custom_rules = [
  # { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]

[coverage]
file = "coverage/lcov.info"    # default coverage file path
min  = 85.0                    # default minimum threshold %

[lint]
target_dir = "./infrastructure/k8s"    # default Kubernetes manifest directory

[lighthouse]
url              = "https://yourapp.com"
strategy         = "mobile"    # mobile or desktop
min_performance  = 80
min_accessibility = 90
min_best_practices = 80
min_seo          = 80
# api_key = ""                 # prefer PAGESPEED_API_KEY env var

[reassure]
current   = "output/current.perf"
baseline  = "output/baseline.perf"
threshold = 15.0               # maximum regression % before failing

[review]
# Minimum coverage required for newly added lines in a PR diff (default 80.0)
# Only enforced when --coverage-file is provided
min_new_code_coverage = 80.0

# Maximum Complexity Score before failing (default 0 = warn only)
# Set to a positive integer to fail the gate when the score exceeds this value
complexity_budget = 0

[audit]
# GHSA/CVE advisory IDs to suppress — use for known-acceptable transitive
# dependency vulnerabilities that cannot be fixed by upgrading a direct dep.
# Always document WHY each entry is acceptable in a comment above the ID.
# Re-evaluate when upstream tools release new major versions.
ignore_advisories = [
  # "GHSA-xxxx-yyyy-zzzz",   # affected-package — reason suppressed
]
```

## Precedence

CLI flag > `--profile` override > `.greengate.toml` > built-in default

## Profiles

Apply a named quality profile on top of your loaded config with the global `--profile` flag:

```bash
greengate --profile strict scan
greengate --profile ci scan --staged
```

| Profile | Effect |
|---|---|
| `strict` | Coverage ≥ 90%, entropy threshold 3.5 (more sensitive), Lighthouse performance ≥ 90, accessibility ≥ 95, SAST enabled |
| `relaxed` | Coverage ≥ 70%, entropy threshold 5.0 (fewer false positives) |
| `ci` | Coverage ≥ 80%, SAST enabled, code-smell rules (`SMELL/*`) disabled to reduce noise |

Profiles modify the in-memory config only — they never write to `.greengate.toml`.

## Inline suppression

Suppress a finding on a specific line using a comment:

```ts
const key = "AKIAIOSFODNN7EXAMPLE123"; // greengate: ignore
el.innerHTML = sanitizedHtml;           // greengate: ignore
```

Works for both secret/PII and SAST findings.
