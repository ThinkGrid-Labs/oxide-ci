# CI/CD Integration

## GitHub Actions — Full pipeline

```yaml
name: GreenGate Quality Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload and Check Runs
  checks: write            # required for --annotate (GitHub Check Runs)
  pull-requests: write     # required for --annotate (PR review comment)

jobs:
  greengate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install GreenGate
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/greengate/releases/latest/download/greengate-linux-amd64 \
            -o /usr/local/bin/greengate
          chmod +x /usr/local/bin/greengate

      - name: Secret, PII & SAST Scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: greengate scan --annotate

      - name: Kubernetes Lint
        run: greengate lint --dir ./k8s

      - name: Coverage Gate
        run: greengate coverage --file coverage/lcov.info --min 80

      - name: Dependency Audit
        run: greengate audit
```

## GitHub Actions — SARIF upload (alternative)

If you prefer GitHub Advanced Security inline annotations over `--annotate`:

```yaml
- name: Scan (SARIF)
  run: greengate scan --format sarif > results.sarif
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
    - curl -sL https://github.com/ThinkGrid-Labs/greengate/releases/latest/download/greengate-linux-amd64
        -o /usr/local/bin/greengate
    - chmod +x /usr/local/bin/greengate

secret-scan:
  stage: security
  <<: *install_oxide
  script:
    - greengate scan

k8s-lint:
  stage: security
  <<: *install_oxide
  script:
    - greengate lint --dir ./k8s

coverage-gate:
  stage: quality
  <<: *install_oxide
  script:
    - greengate coverage --file coverage/lcov.info --min 80

dependency-audit:
  stage: security
  <<: *install_oxide
  script:
    - greengate audit
```

## Git pre-commit hook

Install greengate as a local pre-commit hook to catch secrets before they ever leave your machine:

```bash
greengate install-hooks
```

This writes a `.git/hooks/pre-commit` script that runs `greengate scan --staged` on every `git commit`.
