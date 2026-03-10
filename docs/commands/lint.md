# lint — Kubernetes Manifest Linting

Validates Kubernetes workload YAML files (`Deployment`, `DaemonSet`, `StatefulSet`, `Job`, `CronJob`) against security and reliability best practices. Supports multi-document YAML files separated by `---`.

## Usage

```
greengate lint [OPTIONS]

Options:
  -d, --dir <DIR>    Directory to scan for manifests [default: . or lint.target_dir from config]
  -h, --help         Print help
```

## Examples

```bash
# Lint manifests in the current directory
greengate lint

# Lint a specific directory
greengate lint --dir ./infrastructure/k8s
```

## Rules enforced

| Rule ID | Description | Applies to |
|---|---|---|
| `no-latest-image` | Container image uses `:latest` tag or no tag | All workloads |
| `no-resource-limits` | `resources.limits` block is entirely missing | All workloads |
| `no-cpu-limit` | `resources.limits.cpu` is not set | All workloads |
| `no-memory-limit` | `resources.limits.memory` is not set | All workloads |
| `run-as-root` | `securityContext.runAsUser` is `0` | All workloads |
| `no-readiness-probe` | `readinessProbe` is not defined | Deployment, DaemonSet, StatefulSet |
| `no-liveness-probe` | `livenessProbe` is not defined | Deployment, DaemonSet, StatefulSet |

> `Job` and `CronJob` are intentionally exempt from probe checks — they run to completion and don't need readiness/liveness probes.

## Sample output

```
ℹ️  Linting Kubernetes manifests in './k8s'...
⚠️  Found 3 issue(s) across 2 file(s):
  [no-latest-image] k8s/api.yaml (container: api) — Image 'myapp:latest' uses an unpinned tag
  [no-memory-limit] k8s/api.yaml (container: api) — resources.limits.memory is not set
  [no-readiness-probe] k8s/worker.yaml (container: worker) — readinessProbe is not defined
Error: K8s lint failed: 3 issue(s) found.
```

## Example compliant manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:1.4.2
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
```
