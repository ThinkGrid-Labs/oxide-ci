---
title: 'sbom — SBOM Generation'
description: 'Generate a CycloneDX 1.5 Software Bill of Materials from Cargo.lock, package-lock.json, requirements.txt, or go.sum. No internet access required.'
---

# sbom — SBOM Generation

Generates a [CycloneDX 1.5](https://cyclonedx.org/specification/overview/) Software Bill of Materials (SBOM) from your project's lock file. No internet access required — the lock file is parsed locally.

## Usage

```
greengate sbom [OPTIONS]

Options:
  -o, --output <FILE>    Write SBOM to a file instead of stdout
  -h, --help             Print help
```

## Supported lock files

Checked in order — the first one found is used:

| Lock file | Ecosystem | purl format |
|---|---|---|
| `Cargo.lock` | crates.io | `pkg:cargo/<name>@<version>` |
| `package-lock.json` | npm | `pkg:npm/<name>@<version>` |
| `requirements.txt` | PyPI | `pkg:pypi/<name>@<version>` |
| `go.sum` | Go | `pkg:golang/<module>@<version>` |

## Examples

```bash
# Print SBOM to stdout (pipe to a tool or inspect)
greengate sbom

# Write SBOM to a file
greengate sbom --output sbom.json

# Pretty-print and inspect
greengate sbom | jq '.components[] | select(.name == "serde")'
```

## Output format

The output is a CycloneDX 1.5 JSON document:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:greengate-1710000000",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-06T12:00:00Z",
    "tools": [
      {
        "vendor": "ThinkGrid Labs",
        "name": "greengate",
        "version": "0.2.4"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "serde",
      "version": "1.0.210",
      "purl": "pkg:cargo/serde@1.0.210",
      "scope": "required"
    }
  ]
}
```

## CI usage

```yaml
# GitHub Actions — generate and archive SBOM
- name: Generate SBOM
  run: greengate sbom --output sbom.json

- name: Upload SBOM artifact
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

CycloneDX SBOMs are accepted by most enterprise security and compliance platforms (Dependency-Track, FOSSA, Grype, Trivy, etc.).
