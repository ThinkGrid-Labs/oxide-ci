# reassure — React Component Performance Gate

Parses a [Reassure](https://github.com/callstack/reassure) performance measurement report and fails if any component's mean render time has regressed beyond the configured threshold compared to the baseline.

## Usage

```
oxide-ci reassure [OPTIONS]

Options:
  --current <FILE>      Path to current Reassure measurement file [default: output/current.perf]
  --baseline <FILE>     Path to baseline Reassure measurement file [default: output/baseline.perf]
  --threshold <N>       Maximum mean-time regression % before failing [default: 15.0]
  -h, --help            Print help
```

If `--baseline` is omitted and no baseline file is found, oxide-ci runs in **report-only mode** — it prints the current measurements but does not fail.

## Examples

```bash
# Gate with default 15% threshold
oxide-ci reassure

# Custom threshold
oxide-ci reassure --threshold 10

# Explicit file paths
oxide-ci reassure \
  --current output/current.perf \
  --baseline output/baseline.perf \
  --threshold 15
```

## Workflow in CI

1. Run `reassure measure` in your frontend test job
2. Upload `output/current.perf` as a CI artifact
3. Download it in a subsequent job and run `oxide-ci reassure`

```yaml
- name: Download Reassure report
  uses: actions/download-artifact@v4
  with:
    name: reassure-report
    path: output/
  continue-on-error: true

- name: Reassure performance gate
  if: hashFiles('output/current.perf') != ''
  run: oxide-ci reassure --threshold 15
```

## Sample output

```
ℹ️  Comparing Reassure report: output/current.perf vs output/baseline.perf
⚠️  Regressions found (threshold: 15.0%):
  Button: mean 12.4ms → 18.7ms (+51.0%)
  Modal:  mean 8.2ms  → 9.7ms  (+18.3%)
Error: Reassure gate failed: 2 component(s) exceeded the regression threshold.
```
