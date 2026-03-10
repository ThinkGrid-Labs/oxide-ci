# Output Formats

The `scan` command supports five output formats via `--format`.

## text (default)

Human-readable output to stderr. A progress bar shows scan progress. Findings include file path and line number.

```bash
greengate scan
```

## json

Machine-readable JSON written to stdout. Status messages and progress go to stderr, so you can pipe stdout cleanly.

```bash
greengate scan --format json
greengate scan --format json | jq '.findings[] | select(.rule | startswith("SAST"))'
```

```json
{
  "total": 1,
  "findings": [
    {
      "rule": "SAST/EvalUsage",
      "file": "./src/utils.js",
      "line": 42,
      "severity": "critical"
    }
  ]
}
```

## sarif

SARIF 2.1.0 JSON written to stdout. Upload directly to GitHub Advanced Security for inline PR annotations.

```bash
greengate scan --format sarif > results.sarif
```

In GitHub Actions:

```yaml
- name: Secret & SAST Scan
  run: greengate scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## junit

JUnit XML written to stdout. Compatible with Jenkins, Azure DevOps, CircleCI, and any CI system that consumes JUnit test reports.

```bash
greengate scan --format junit > results.xml
```

Each finding becomes a `<testcase>` with a `<failure>` element. The suite name is `greengate` and the classname is the file path.

In Jenkins:
```groovy
sh 'greengate scan --format junit > results.xml || true'
junit 'results.xml'
```

In Azure DevOps:
```yaml
- script: greengate scan --format junit > results.xml
  continueOnError: true
- task: PublishTestResults@2
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: results.xml
```

## gitlab

GitLab SAST Security Scanner JSON (schema v15.0.6) written to stdout. Upload as a GitLab security artifact to display findings in Merge Request security reports.

```bash
greengate scan --format gitlab > gl-sast-report.json
```

In `.gitlab-ci.yml`:
```yaml
secret-scan:
  script:
    - greengate scan --format gitlab > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Severity mapping: `critical` → `Critical`, `high` → `High`, `medium` → `Medium`, `low` → `Low`.
