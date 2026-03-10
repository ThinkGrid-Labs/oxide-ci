# Use Cases & Scenarios

Real-world examples of how greengate fits into different team workflows.

---

## 1. SaaS startup — post-deploy Lighthouse health check

**Situation:** You ship helpdeck-landing to production on every merge to `main`. You want to know immediately if a deploy breaks your Lighthouse scores.

**How it works:** Run Lighthouse _after_ deploy so it tests the new live code.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
      - run: ./scripts/deploy.sh   # your deploy script

  lighthouse:
    needs: deploy                  # waits for deploy to finish
    runs-on: ubuntu-latest
    steps:
      - name: Install greengate
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/greengate/releases/latest/download/greengate-linux-amd64 \
            -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

      - name: Lighthouse post-deploy audit
        env:
          PAGESPEED_API_KEY: ${{ secrets.PAGESPEED_API_KEY }}
        run: |
          greengate lighthouse \
            --url https://yourapp.com \
            --min-performance 85 \
            --min-accessibility 90
```

**What it catches:** Image regressions, unoptimized bundles, missing meta tags, accidental `noindex` — after every production deploy.

---

## 2. SaaS startup — pre-merge gate with staging environment

**Situation:** You have a staging server. You want to block merges if a PR degrades performance _before_ it hits production.

**How it works:** Deploy to staging first, then run Lighthouse against the staging URL.

```yaml
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    outputs:
      url: ${{ steps.deploy.outputs.url }}
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
      - name: Deploy to staging
        id: deploy
        run: |
          ./scripts/deploy-staging.sh
          echo "url=https://staging.yourapp.com" >> $GITHUB_OUTPUT

  lighthouse-gate:
    needs: deploy-staging
    runs-on: ubuntu-latest
    steps:
      - name: Install greengate
        run: |
          curl -sL https://github.com/ThinkGrid-Labs/greengate/releases/latest/download/greengate-linux-amd64 \
            -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

      - name: Lighthouse pre-merge gate
        env:
          PAGESPEED_API_KEY: ${{ secrets.PAGESPEED_API_KEY }}
        run: |
          greengate lighthouse \
            --url "${{ needs.deploy-staging.outputs.url }}" \
            --strategy mobile \
            --min-performance 80 \
            --min-accessibility 90
```

**What it catches:** Regressions in the PR's code _before_ they merge to main.

---

## 3. Preventing secrets from being committed

**Situation:** A developer accidentally hardcodes an API key and pushes it. You want to catch this before it ever reaches the remote.

**Two-layer approach — local + CI:**

```bash
# Layer 1: catch it locally before git push
greengate install-hooks
```

This installs a pre-commit hook that scans staged files on every `git commit`. It fails the commit if a secret is detected.

```yaml
# Layer 2: catch it in CI as a safety net
- name: Secret scan
  run: greengate scan
```

**What it catches:** AWS keys, Stripe secrets, GitHub tokens, GCP service account JSON, `.env` values, high-entropy strings — 26 built-in patterns.

---

## 4. Kubernetes team — manifest quality gate

**Situation:** Your team ships microservices with Kubernetes manifests. You want to block deployments that are missing resource limits, health probes, or use the `latest` image tag.

```yaml
- name: Lint Kubernetes manifests
  run: greengate lint --dir ./k8s
```

**With `.greengate.toml`:**

```toml
[lint]
target_dir = "./k8s"
```

```bash
greengate lint   # reads config automatically
```

**What it catches:** Missing `resources.limits`, missing `livenessProbe`/`readinessProbe`, `image: nginx:latest` (unpinned), containers running as root.

---

## 5. Full security pipeline — Next.js / React app

**Situation:** You run a React frontend with a Node.js backend. You want secrets, SAST, dependency CVEs, and coverage all gated in one pipeline.

```yaml
- name: Secret & SAST scan
  run: greengate scan --annotate   # annotates PRs via GitHub Check Runs

- name: Dependency audit (OSV)
  run: greengate audit             # checks Cargo.lock / package-lock.json

- name: Coverage gate
  run: greengate coverage --file coverage/lcov.info --min 80

- name: React perf regression gate
  if: hashFiles('output/current.perf') != ''
  run: greengate reassure
```

**What it catches across the pipeline:**

| Step | Catches |
|---|---|
| `scan` | Hardcoded secrets, XSS, `eval()`, command injection in JS/TS |
| `audit` | Known CVEs in npm/Cargo dependencies |
| `coverage` | Test coverage silently dropping below threshold |
| `reassure` | React component render time regressing between PRs |

---

## 6. Solo developer — minimal setup

**Situation:** You're shipping solo, no staging environment. You want the basics without overhead.

**`.greengate.toml`:**
```toml
[scan]
entropy = true
entropy_threshold = 4.5

[coverage]
file = "coverage/lcov.info"
min = 70.0
```

**GitHub Actions:**
```yaml
- name: Install greengate
  run: |
    curl -sL https://github.com/ThinkGrid-Labs/greengate/releases/latest/download/greengate-linux-amd64 \
      -o /usr/local/bin/greengate && chmod +x /usr/local/bin/greengate

- name: Scan
  run: greengate scan

- name: Audit
  run: greengate audit

- name: Coverage
  run: greengate coverage
```

**Locally:**
```bash
greengate install-hooks   # catch secrets before they leave your machine
```

---

## Key principle: Lighthouse needs a deployed URL

Lighthouse tests whatever is **live at the URL you provide**. This means:

- Run it **after** your deploy step — not before
- For a merge gate, deploy to staging first, then test the staging URL
- For a health check, deploy to production, then test the production URL

The threshold you set (`--min-performance 80`) is your quality floor. If the deployed site scores below it, the pipeline fails.
