# CI/CD Integration

## GitHub Actions — Full pipeline

```yaml
name: OxideCI Quality Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload and Check Runs
  checks: write            # required for --annotate (GitHub Check Runs)
  pull-requests: write     # required for --annotate (PR review comment)

jobs:
  oxide-ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OxideCI
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 \
            -o /usr/local/bin/oxide-ci
          chmod +x /usr/local/bin/oxide-ci

      - name: Secret, PII & SAST Scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: oxide-ci scan --annotate

      - name: Kubernetes Lint
        run: oxide-ci lint --dir ./k8s

      - name: Coverage Gate
        run: oxide-ci coverage --file coverage/lcov.info --min 80

      - name: Dependency Audit
        run: oxide-ci audit
```

## GitHub Actions — SARIF upload (alternative)

If you prefer GitHub Advanced Security inline annotations over `--annotate`:

```yaml
- name: Scan (SARIF)
  run: oxide-ci scan --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## GitLab CI

```yaml
stages:
  - security
  - quality

.install_oxide: &install_oxide
  before_script:
    - curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64
        -o /usr/local/bin/oxide-ci
    - chmod +x /usr/local/bin/oxide-ci

secret-scan:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci scan

k8s-lint:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci lint --dir ./k8s

coverage-gate:
  stage: quality
  <<: *install_oxide
  script:
    - oxide-ci coverage --file coverage/lcov.info --min 80

dependency-audit:
  stage: security
  <<: *install_oxide
  script:
    - oxide-ci audit
```

## Git pre-commit hook

Install oxide-ci as a local pre-commit hook to catch secrets before they ever leave your machine:

```bash
oxide-ci install-hooks
```

This writes a `.git/hooks/pre-commit` script that runs `oxide-ci scan --staged` on every `git commit`.
