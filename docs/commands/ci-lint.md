---
title: 'ci-lint — GitHub Actions Security Linting'
description: 'Lint GitHub Actions workflow files for security misconfigurations: unpinned action refs, pull_request_target misuse, expression injection in run steps, and secrets leaked via env variables. Emits SARIF for Code Scanning.'
---

# ci-lint — GitHub Actions Security Linting

Lints GitHub Actions workflow files under `.github/workflows/` for security misconfigurations that can lead to CI pipeline poisoning, secret exfiltration, and privilege escalation.

CI pipeline attacks have become a primary supply chain vector — the [tj-actions/changed-files compromise](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3), the [Codecov bash uploader incident](https://about.codecov.io/security-update/), and the [reviewdog action compromise](https://github.com/reviewdog/action-setup/security/advisories/GHSA-5rjg-fvgr-3xxf) all exploited misconfigurations that `ci-lint` would flag.

## Usage

```bash
greengate ci-lint [OPTIONS]

Options:
  -h, --help    Print help
```

## Examples

```bash
# Lint all .github/workflows/*.yml files
greengate ci-lint

# Output SARIF for GitHub Code Scanning
greengate ci-lint --format sarif > ci-lint.sarif
```

## Rules

### CILINT/UnpinnedAction — Unpinned action ref (HIGH)

Using a mutable tag like `@v4` or `@main` means anyone who can push to that repo can silently change what code runs in your CI.

```yaml
# BAD — mutable tag, can be changed by the action author at any time
- uses: actions/checkout@v4

# GOOD — pinned to an immutable commit SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Fix: pin every `uses:` to a full commit SHA and add a comment showing the version for human readability.

### CILINT/PullRequestTargetCheckout — Dangerous pull_request_target + checkout (CRITICAL)

`pull_request_target` runs with write permissions and access to repository secrets. If you check out PR code in this context, an attacker can send a pull request with a malicious workflow modification and steal your secrets.

```yaml
# BAD — checks out untrusted PR code with write permissions
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

Fix: never check out PR code in a `pull_request_target` workflow. If you need to run tests on PR code, use a separate `pull_request` workflow that has no write permissions or secret access.

### CILINT/ExpressionInjection — Expression injection in run step (HIGH)

GitHub Actions expressions (`${{ ... }}`) are expanded before the shell interprets the `run:` script. Injecting attacker-controlled values like `github.event.pull_request.title` or `github.event.issue.body` directly into a `run:` step allows arbitrary command execution.

```yaml
# BAD — attacker controls github.event.pull_request.title
- run: echo "Processing PR: ${{ github.event.pull_request.title }}"

# GOOD — pass through an intermediate env var (shell safely quotes it)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Processing PR: $PR_TITLE"
```

Flagged expression sources: `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.issue.title`, `github.event.issue.body`, `github.head_ref`, `github.event.head_commit.message`.

### CILINT/SecretsInEnv — Secrets leaked via job-level env (MEDIUM)

Defining secrets at the `jobs.<job>.env` level makes them visible to every step in that job — including third-party actions and any commands that print environment variables.

```yaml
# BAD — secret visible to all steps including third-party actions
jobs:
  deploy:
    env:
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    steps:
      - uses: some-third-party/action@v1  # can read AWS_SECRET_ACCESS_KEY

# GOOD — scope the secret to the specific step that needs it
jobs:
  deploy:
    steps:
      - run: aws s3 sync ...
        env:
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Sample output

```
ℹ️  CI lint: scanning 3 workflow file(s) in .github/workflows/...
⚠️  Found 4 potential issue(s):
  - [HIGH]     [CILINT/UnpinnedAction]              .github/workflows/ci.yml:12
  - [HIGH]     [CILINT/UnpinnedAction]              .github/workflows/ci.yml:18
  - [CRITICAL] [CILINT/PullRequestTargetCheckout]   .github/workflows/release.yml:31
  - [HIGH]     [CILINT/ExpressionInjection]         .github/workflows/pr-check.yml:44
Error: CI lint failed: 4 issue(s) found.
```

## CI usage

```yaml
- name: Lint CI workflows
  run: greengate ci-lint

# Upload findings to GitHub Code Scanning
- name: CI lint (SARIF)
  run: greengate ci-lint --format sarif > ci-lint.sarif || true

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ci-lint.sarif
```

## Suppressing findings

Add `# greengate: ignore` on the line above the flagged line to suppress a specific finding:

```yaml
# greengate: ignore
- uses: actions/checkout@v4   # suppressed: internal repo, we control this action
```

Or disable a rule entirely in `.greengate.toml`:

```toml
[sast]
disabled_rules = ["CILINT/UnpinnedAction"]
```
