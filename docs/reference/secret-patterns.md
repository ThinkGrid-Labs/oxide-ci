# Secret Detection Patterns

greengate ships with 26 built-in regex patterns covering the most common cloud providers, SaaS platforms, and API services. All patterns are applied only to string literals (not comments or JSX text) when scanning JS/TS files.

## Built-in patterns

| Pattern name | What it detects |
|---|---|
| AWS Access Key | `AKIA...` access key IDs |
| AWS Secret Key | 40-character AWS secret access keys |
| AWS Session Token | Temporary STS session tokens |
| Azure Client Secret | Azure AD application secrets |
| Azure Storage Key | Azure storage account keys |
| GCP API Key | Google Cloud `AIza...` API keys |
| GCP Service Account JSON | Embedded service account credential blocks |
| DigitalOcean Personal Access Token | `dop_v1_...` tokens |
| Alibaba Cloud Access Key | `LTAI...` access key IDs |
| GitHub Personal Access Token | `ghp_...`, `github_pat_...` |
| GitHub OAuth Token | `gho_...` |
| GitHub App Token | `ghs_...`, `ghr_...` |
| Stripe Secret Key | `sk_live_...`, `sk_test_...` |
| Stripe Publishable Key | `pk_live_...`, `pk_test_...` |
| Twilio Account SID | `AC...` SIDs |
| Twilio Auth Token | 32-hex Twilio auth tokens |
| Expo Access Token | `expo_...` tokens |
| Sentry Auth Token | `sntrys_...` tokens |
| Mapbox Token | `pk.eyJ1...` tokens |
| Slack Bot Token | `xoxb-...` |
| Slack User Token | `xoxp-...` |
| Generic API Key | High-entropy values assigned to keys named `api_key`, `apikey`, `api-key` |
| Generic Secret | High-entropy values assigned to keys named `secret`, `password`, `passwd`, `pwd` |
| Private Key | `-----BEGIN ... PRIVATE KEY-----` blocks |
| Email Address (PII) | RFC 5322-compliant email addresses |
| IPv4 Address (PII) | Private-range IPv4 addresses in sensitive contexts |

## Adding custom patterns

```toml
# .greengate.toml
[scan]
extra_patterns = [
  { name = "Internal Service Token", regex = "svc_[a-z0-9]{40}" },
  { name = "Legacy API Key", regex = "legacy_[A-Za-z0-9]{32}" },
]
```

Custom patterns are applied in addition to the built-ins (not instead of them).

## Shannon entropy detection

Enable entropy-based detection to catch unrecognized high-entropy tokens (API keys, bearer tokens, random secrets) not covered by named patterns:

```toml
[scan]
entropy = true
entropy_threshold = 4.5    # bits per character — lower = more sensitive
entropy_min_length = 20    # ignore tokens shorter than this
```

## Excluding paths

```toml
[scan]
exclude_patterns = [
  "tests/**",
  "*.test.ts",
  "fixtures/**",
  "vendor/**",
]
```

## Suppressing individual findings

```ts
const key = "AKIAIOSFODNN7EXAMPLE123"; // greengate: ignore
```
