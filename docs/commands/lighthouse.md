# lighthouse — Web Performance Audit

Audits web performance via the [Google PageSpeed Insights API](https://developers.google.com/speed/docs/insights/v5/get-started) (Lighthouse). Fails if any score is below the configured minimum.

## Usage

```
greengate lighthouse [OPTIONS]

Options:
  --url <URL>                URL to audit [required or set in .greengate.toml]
  --strategy <STRATEGY>      mobile (default) or desktop
  --min-performance <N>      Minimum performance score 0–100 [default: 80]
  --min-accessibility <N>    Minimum accessibility score 0–100 [default: 90]
  --min-best-practices <N>   Minimum best-practices score 0–100 [default: 80]
  --min-seo <N>              Minimum SEO score 0–100 [default: 80]
  -h, --help                 Print help
```

## Examples

```bash
# Audit with default thresholds
greengate lighthouse --url https://yourapp.com

# Desktop strategy with custom thresholds
greengate lighthouse --url https://yourapp.com \
  --strategy desktop \
  --min-performance 90 \
  --min-accessibility 95

# Use defaults from .greengate.toml
greengate lighthouse
```

## API key

The PageSpeed Insights API has a default quota of 400 requests per day without an API key. For CI pipelines, set `PAGESPEED_API_KEY` as an environment variable or use `api_key` in `.greengate.toml` to increase quota.

```bash
PAGESPEED_API_KEY=your_key greengate lighthouse --url https://yourapp.com
```

## In GitHub Actions

```yaml
- name: Lighthouse audit
  env:
    PAGESPEED_API_KEY: ${{ secrets.PAGESPEED_API_KEY }}
  run: |
    greengate lighthouse \
      --url "${{ vars.LIGHTHOUSE_URL }}" \
      --strategy mobile \
      --min-performance 80 \
      --min-accessibility 90
```

## Sample output

```
ℹ️  Auditing https://yourapp.com (strategy: mobile)...
  Performance:     87
  Accessibility:   94
  Best Practices:  83
  SEO:             91
All Lighthouse checks passed.
```
