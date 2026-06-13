---
title: 'Telemetry & Metrics — OpenTelemetry & Prometheus'
description: 'greengate emits OTLP metrics after every command to any OpenTelemetry-compatible backend (Grafana, Datadog, Honeycomb) and writes Prometheus .prom files for node_exporter scraping.'
---

# Telemetry & Metrics

greengate emits structured metrics after every command run. Both backends are **opt-in, optional, and independent** — telemetry errors are printed as warnings and never cause a command to fail.

## Configuration

```toml
[telemetry]
enabled       = true
service_name  = "my-api"                  # attached as service.name resource attribute

# OTLP HTTP/JSON (port 4318, not gRPC 4317)
otlp_endpoint = "http://localhost:4318"   # remove this line to disable OTLP

# Prometheus text format (.prom file)
# metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

## OTLP export

Metrics are POSTed to `{otlp_endpoint}/v1/metrics` using OTLP HTTP/JSON after each command completes. This works with any OpenTelemetry-compatible collector.

| Backend | How to connect |
|---|---|
| **OpenTelemetry Collector** | Point `otlp_endpoint` at the collector's OTLP HTTP receiver (default port 4318) |
| **Grafana Cloud** | Use the Grafana Agent OTLP endpoint, or Grafana Cloud's OTLP gateway URL |
| **Datadog** | Enable OTLP intake in the Datadog Agent (`otlp_config.receiver.protocols.http`) |
| **Honeycomb** | Use the OpenTelemetry Collector as a proxy with your Honeycomb API key |
| **New Relic** | Use the OTel Collector exporter pointing at `otlp.nr-data.net:4317` |

::: tip Port 4318 vs 4317
greengate uses OTLP HTTP/JSON on port 4318, not gRPC on port 4317. Make sure your collector's HTTP receiver is enabled. In the OpenTelemetry Collector config:
```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
```
:::

## Prometheus text format

```toml
[telemetry]
metrics_file = "/var/lib/node_exporter/textfile/greengate.prom"
```

Writes a `.prom` file with standard `# HELP` / `# TYPE` headers after each command. Point `node_exporter --collector.textfile.directory` at the containing directory and Prometheus scrapes it automatically.

The file is **overwritten** on each command run, so it always reflects the most recent execution. Prometheus will see the latest value on its next scrape.

## Metrics reference

### Scan metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `greengate_scan_findings_total` | counter | `severity`, `service` | Number of findings by severity (`critical`, `high`, `medium`, `low`, `all`) |
| `greengate_scan_duration_ms` | gauge | `service` | Wall-clock time of the scan in milliseconds |

### Command metrics

Emitted after every command (`coverage`, `audit`, `ci-lint`, etc.):

| Metric | Type | Labels | Description |
|---|---|---|---|
| `greengate_command_duration_ms` | gauge | `command`, `success`, `service` | Wall-clock time of the command in milliseconds |
| `greengate_command_success` | gauge | `command`, `service` | `1` if the command exited successfully, `0` if it failed |

## Example Grafana queries

```promql
# Finding rate over the last 7 days
rate(greengate_scan_findings_total{severity="high"}[7d])

# Commands failing in CI (useful for alerting)
greengate_command_success == 0

# Slowest commands (performance monitoring)
topk(5, greengate_command_duration_ms)

# Scan findings trend per severity (stacked bar chart)
sum by (severity) (greengate_scan_findings_total)

# Coverage gate failure rate
(1 - greengate_command_success{command="coverage"}) * 100
```

## Example alert rule

```yaml
# Prometheus alerting rule — fire when high/critical findings appear
groups:
  - name: greengate
    rules:
      - alert: GreengateHighSeverityFindings
        expr: greengate_scan_findings_total{severity=~"critical|high"} > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "greengate found {{ $value }} high/critical finding(s)"
          description: "Service {{ $labels.service }} has security findings that need attention."
```

## Disabling telemetry

Set `enabled = false` in `.greengate.toml`:

```toml
[telemetry]
enabled = false
```

Or omit the `[telemetry]` section entirely — both OTLP and Prometheus output are disabled by default unless `otlp_endpoint` or `metrics_file` are set.
