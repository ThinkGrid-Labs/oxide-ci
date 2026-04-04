---
title: 'Exit Codes'
description: 'GreenGate exit code reference: 0 for clean, 1 for findings or gate failure. Reliable for CI pipeline scripting without output parsing.'
---

# Exit Codes

All greengate commands follow a simple two-code convention. CI pipelines can rely on the exit code directly — no output parsing required.

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | Check failed (secrets found, SAST issues, lint violations, coverage below threshold, vulnerabilities detected, performance regression) or a tool/runtime error occurred |

## In CI pipelines

```yaml
- name: Secret Scan
  run: greengate scan
  # Step fails automatically when exit code is 1
```

To continue the pipeline after a failure (e.g. to upload SARIF even when issues exist):

```yaml
- name: Secret Scan
  run: greengate scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```
