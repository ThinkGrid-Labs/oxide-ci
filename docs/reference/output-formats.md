# Output Formats

The `scan` command supports three output formats via `--format`.

## text (default)

Human-readable output to stderr. A progress bar shows scan progress. Findings include file path and line number.

```bash
oxide-ci scan
```

## json

Machine-readable JSON written to stdout. Status messages and progress go to stderr, so you can pipe stdout cleanly.

```bash
oxide-ci scan --format json
oxide-ci scan --format json | jq '.findings[] | select(.rule | startswith("SAST"))'
```

```json
{
  "total": 1,
  "findings": [
    {
      "rule": "SAST/EvalUsage",
      "file": "./src/utils.js",
      "line": 42
    }
  ]
}
```

## sarif

SARIF 2.1.0 JSON written to stdout. Upload directly to GitHub Advanced Security for inline PR annotations.

```bash
oxide-ci scan --format sarif > results.sarif
```

In GitHub Actions:

```yaml
- name: Secret & SAST Scan
  run: oxide-ci scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```
