---
layout: home

hero:
  name: greengate
  text: One binary. Zero runtimes. Every security and quality gate your CI pipeline needs.
  tagline: Most teams string together 6+ tools for secret scanning, SAST, supply chain, coverage, and CI linting — each with its own runtime and config format. greengate replaces all of them with a single compiled Rust binary you drop into any pipeline in under 30 seconds.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: Commands →
      link: /commands/scan
    - theme: alt
      text: View on GitHub
      link: https://github.com/thinkgrid-labs/greengate

features:
  - title: 🔒 Zero-Trust Supply Chain
    details: "Intercepts npm, yarn, pnpm, bun, pip, and cargo installs before malicious code reaches your machine. Three layers: pre-flight script scanning (entropy + network/eval signals), runtime phantom-file detection, and post-install exec-drop analysis. Catches the typosquatting, obfuscated postinstall, and build.rs attack vectors."
  - title: 🔍 Secret & SAST Scanning
    details: "26 built-in secret patterns (AWS, GitHub, Stripe, GCP, Azure, JWT, private keys…) plus Shannon entropy detection for unrecognised credentials. AST-based SAST via tree-sitter for JS, TS, Python, Go, and Rust — no false positives from comments or string literals in other languages."
  - title: 🤖 AI False-Positive Triage
    details: "greengate scan --triage sends each finding to an LLM with surrounding source context and classifies it as likely-real, likely-false-positive, or uncertain. Configurable auto-suppression threshold. Works with Claude, OpenAI, or any local model via Ollama — no data leaves your machine with local models."
  - title: 🛡️ CI Config Security Linting
    details: "greengate ci-lint scans GitHub Actions workflows for pipeline poisoning vectors: unpinned action refs, pull_request_target misuse, expression injection in run steps, and job-level secret leakage. Emits SARIF for Code Scanning."
  - title: 📋 SBOM + Sigstore Attestation
    details: "Generate CycloneDX 1.5 SBOMs from any lock file and sign them with Sigstore keyless signing — no private key required. Anchors the signature in the Rekor public transparency log. Covers SLSA Level 2+ and EU Cyber Resilience Act provenance requirements."
  - title: 📊 OpenTelemetry Metrics
    details: "Emits structured metrics after every command to any OTLP-compatible backend (Grafana, Datadog, Honeycomb) and writes Prometheus .prom files for node_exporter. Track finding rates, scan duration, and command success rates over time."
  - title: 🎯 Test Impact Analysis
    details: "Uses tree-sitter to walk import graphs across JS/TS, Python, and Go and determines exactly which tests are affected by a diff. Pipe output into pytest, jest, or go test to skip unaffected tests — cutting CI compute without sacrificing correctness."
  - title: 📐 PR Review Intelligence
    details: "Scores every PR with a Complexity Score (cyclomatic + cognitive) and cross-references newly added lines against LCOV/Cobertura coverage reports. Posts results as GitHub Check Run annotations. Fails if new-code coverage drops below threshold."
  - title: Zero Runtime Dependencies
    details: "A single musl-linked binary for Linux, macOS, and Windows. Copy it to /usr/local/bin and it works. No Node, Python, JVM, or Docker required. Drop it into Alpine-based CI images with zero setup overhead."
  - title: 🔎 Dependency Audit (OSV)
    details: "Queries the OSV vulnerability database for known CVEs across npm, Cargo, PyPI, Go, Maven, and NuGet. Suppress known-acceptable transitive advisories per-ID. Offline-capable."
  - title: ☸️ Kubernetes & Docker Linting
    details: "Validates Kubernetes manifests for missing resource limits, probes, unpinned images, and root containers. Audits Dockerfiles for unpinned base images, missing USER, missing HEALTHCHECK, and exposed dangerous ports."
  - title: 📈 Coverage Gates
    details: "Parses LCOV and Cobertura XML. Fails the build when line coverage drops below a configurable threshold. The review command goes further — it checks coverage only for newly added lines in a PR diff."
  - title: CI-Native Output
    details: "Five output formats: SARIF 2.1.0, JSON, JUnit XML, GitLab SAST, and plain text. GitHub Check Run annotations with per-line findings and rich PR summary comments. Plugs into Code Scanning, GitLab Security Dashboard, and SonarQube."
  - title: Web Performance
    details: "Lighthouse audits via the PageSpeed Insights API gate on performance, accessibility, best practices, and SEO scores. Fail the build when scores drop below configurable thresholds."
---
