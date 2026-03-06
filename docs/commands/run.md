# run

Runs all pipeline steps defined in `.oxideci.toml` in order. A failing step stops the pipeline immediately with a non-zero exit code.

## Usage

```bash
oxide-ci run
```

## Configuration

Define your pipeline steps in `.oxideci.toml`:

```toml
[pipeline]
steps = [
  "scan",
  "audit",
  "coverage --min 80",
  "lint --dir ./k8s",
  "docker-lint",
  "lighthouse",
  "reassure",
]
```

Each step is a string that maps to an `oxide-ci` subcommand, optionally followed by flags. All config values from `.oxideci.toml` are applied automatically — CLI overrides in the step string take precedence.

## Available steps

| Step | Equivalent command |
|---|---|
| `scan` | `oxide-ci scan` |
| `lint` | `oxide-ci lint` |
| `docker-lint` | `oxide-ci docker-lint` |
| `coverage` | `oxide-ci coverage` |
| `audit` | `oxide-ci audit` |
| `lighthouse` | `oxide-ci lighthouse` |
| `reassure` | `oxide-ci reassure` |

## Step flags

You can pass flags inline in the step string:

```toml
[pipeline]
steps = [
  "scan --staged",
  "coverage --min 90",
  "lint --dir ./manifests",
  "lighthouse --url https://staging.myapp.com --min-performance 85",
]
```

## Example output

```
ℹ️  Running pipeline: 4 step(s)

─── Step 1/4: scan ──────────────────────────────────────
ℹ️  Starting secret and PII scan...
✅ No secrets or PII found.
✅ Step 'scan' passed.

─── Step 2/4: audit ─────────────────────────────────────
ℹ️  Auditing dependencies for known CVEs...
✅ No known vulnerabilities found.
✅ Step 'audit' passed.

─── Step 3/4: coverage --min 80 ─────────────────────────
✅ Coverage: 84.2% (threshold: 80.0%)
✅ Step 'coverage' passed.

─── Step 4/4: docker-lint ───────────────────────────────
✅ Dockerfile passed all lint checks.
✅ Step 'docker-lint' passed.

✅ Pipeline passed (4 step(s)).
```

## CI usage

```yaml
- name: Install oxide-ci
  run: |
    curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
      -o /usr/local/bin/oxide-ci && chmod +x /usr/local/bin/oxide-ci

- name: Run quality gates
  run: oxide-ci run
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All steps passed |
| `1` | One or more steps failed |

## Notes

- Steps run sequentially; the first failure stops the pipeline
- If no `[pipeline]` section is defined in `.oxideci.toml`, the command exits with an error message instructing you to add one
- Use `oxide-ci init` to generate a starter config with a default pipeline
