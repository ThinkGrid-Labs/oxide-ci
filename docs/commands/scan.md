# scan — Secret & PII Scanning

Recursively scans every file in the current directory for hardcoded secrets, credentials, and PII using 26 built-in regex patterns. Respects `.gitignore` automatically.

For JavaScript, TypeScript, TSX, and JSX files the scanner automatically runs an AST-based SAST pass using tree-sitter. This eliminates false positives from comments and JSX text, and additionally flags dangerous API patterns (XSS sinks, eval, command injection).

## Usage

```
oxide-ci scan [OPTIONS]

Options:
  --format <FORMAT>    Output format: text (default), json, sarif
  --staged             Only scan git-staged files (git diff --cached)
  --since <COMMIT>     Only scan files changed since the given commit
  --history            Scan the entire git commit history (slow on large repos)
  --annotate           Post findings as a GitHub Check Run with per-line
                       annotations and a PR review comment. Requires
                       GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA env vars.
  --update-baseline    Save current findings as the baseline (.oxide-baseline.json)
  --since-baseline     Only fail on findings not present in the saved baseline
  -h, --help           Print help
```

## Examples

```bash
# Full scan — human-readable output
oxide-ci scan

# Only scan what you're about to commit (fast, ideal for pre-commit)
oxide-ci scan --staged

# Only scan files changed since the last commit
oxide-ci scan --since HEAD~1

# Output SARIF for GitHub Advanced Security PR annotations
oxide-ci scan --format sarif > results.sarif

# Output JSON for custom tooling
oxide-ci scan --format json | jq '.findings[].rule'

# Post findings directly to the GitHub Checks tab
GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }} \
GITHUB_REPOSITORY=owner/repo \
GITHUB_SHA=${{ github.sha }} \
oxide-ci scan --annotate
```

## AST-Based SAST for JS/TS

When scanning `.js`, `.jsx`, `.ts`, or `.tsx` files, oxide-ci uses tree-sitter to parse each file into a real AST. This provides:

**1. String-literal scoping** — secret patterns only fire inside string and template literals, not comments or JSX text:

```ts
// AKIAIOSFODNN7EXAMPLE123       ← comment: NOT flagged
const key = "AKIAIOSFODNN7EXAMPLE123";  // ← string literal: flagged
```

```tsx
<p>contact@example.com</p>               // ← JSX text: NOT flagged
<Input placeholder="name@example.com" /> // ← string attribute: flagged
```

**2. Dangerous pattern detection** — 13 structural rules that catch XSS, eval, and command injection regardless of whether arguments are literals. See [SAST Rules](/reference/sast-rules) for the full list.

**3. Code smell rules** — flags long functions, too many parameters, and deep nesting. See [SAST Rules](/reference/sast-rules).

## Baseline mode

If your repository already has existing findings you can't fix immediately, the baseline workflow lets you suppress known findings and only fail on *new* ones introduced by a PR.

**Step 1: Save a baseline** (typically on your main branch)

```bash
oxide-ci scan --update-baseline
# Writes .oxide-baseline.json — commit this file
```

**Step 2: Gate on new findings only** (in CI, on every PR)

```bash
oxide-ci scan --since-baseline
# Only fails if new findings are introduced vs the baseline
```

The baseline file stores `(file, rule, line)` fingerprints. If a secret moves to a different line, it appears as a new finding and is re-reviewed.

```yaml
# GitHub Actions example
- name: Save baseline (main branch only)
  if: github.ref == 'refs/heads/main'
  run: oxide-ci scan --update-baseline && git add .oxide-baseline.json

- name: Gate on new secrets only (PRs)
  if: github.event_name == 'pull_request'
  run: oxide-ci scan --since-baseline
```

## Suppressing findings

Add `// oxide-ci: ignore` on the same line to suppress a specific finding:

```ts
const legacyKey = "AKIAIOSFODNN7EXAMPLE123"; // oxide-ci: ignore
el.innerHTML = sanitizedHtml;                 // oxide-ci: ignore
```

## Sample output

```
ℹ️  Starting secret and PII scan...
ℹ️  Running SAST checks...
⚠️  Found 3 potential issue(s):
  - [AWS Access Key] src/config.ts:14
  - [SAST/EvalUsage] src/utils/parser.js:42
  - [SAST/InnerHTMLAssignment] src/components/Widget.tsx:88
Error: Scan failed: 3 secret(s)/PII found.
```
