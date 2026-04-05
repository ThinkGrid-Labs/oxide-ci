---
layout: home

hero:
  name: GreenGate
  text: Rust DevOps CLI for CI Quality Gates
  tagline: Zero-trust supply chain protection, secret scanning, AST-based SAST, test impact analysis, PR review intelligence, Kubernetes linting, coverage gates, and dependency auditing — single zero-dependency binary.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: watch-install →
      link: /commands/watch-install
    - theme: alt
      text: View on GitHub
      link: https://github.com/thinkgrid-labs/greengate

features:
  - title: 🔒 Zero-Trust Supply Chain Gate
    details: "greengate watch-install enforces three independent layers: (1) pre-flight static scan of postinstall scripts for network calls, eval(), process.env, and high-entropy obfuscated payloads; (2) 250ms runtime phantom-file detection; (3) post-install exec-drop detection. Catches the full spectrum of supply-chain attacks including the 2025 axios-ecosystem compromise pattern."
  - title: 🎯 Test Impact Analysis
    details: "greengate tia uses tree-sitter to parse import statements across your entire test suite and determines exactly which tests are affected by a diff. Pipe output directly into pytest, jest, or go test to run only what matters — cutting CI compute time without sacrificing correctness."
  - title: Zero Runtime Dependencies
    details: Drop a single compiled Rust binary into any CI pipeline, Docker image, or developer machine. No Node, Python, or JVM required.
  - title: AST-Based SAST + Taint Tracking
    details: tree-sitter parses JS/TS/TSX/JSX, Python, and Go into a real AST. For JS/TS, Tier-1 intra-procedural taint tracking traces user-controlled input through variable assignments to XSS and injection sinks. Confirmed chains are labelled [tainted]; sanitizer-backed values are suppressed automatically.
  - title: PR Review Intelligence
    details: "greengate review scores every PR with a Complexity Score (estimated review time) and cross-references newly added lines against your LCOV/Cobertura report — surfacing exactly which new lines are untested. Post results as GitHub Check Run annotations with one flag."
  - title: Blazing Fast
    details: Parallel file scanning via rayon across all CPU cores. Typical repositories scan in under a second.
  - title: Secret & PII Detection
    details: 26 built-in patterns covering AWS, Azure, GCP, Stripe, GitHub, Twilio, Expo, Sentry, Mapbox, and more.
  - title: Kubernetes Linting
    details: Validates workload manifests for missing resource limits, probes, unpinned images, and root containers.
  - title: Docker Linting
    details: Audits Dockerfiles for unpinned base images, ADD instead of COPY, missing USER, missing HEALTHCHECK, exposed dangerous ports, and more.
  - title: Coverage Gates
    details: Parses lcov.info and Cobertura XML. Fails the build when line coverage drops below a configurable threshold. The review command goes further — it checks coverage only for newly added lines in a PR diff. Zero external tools required.
  - title: Dependency Audit
    details: Queries the OSV vulnerability database for known CVEs across 6 ecosystems. Offline-capable with a local cache. Suppress known-acceptable transitive advisories per-ID via ignore_advisories in .greengate.toml.
  - title: Web Performance
    details: Lighthouse audits via the PageSpeed Insights API gate on performance, accessibility, best practices, and SEO scores.
  - title: Reassure Performance
    details: Compares React Native component render measurements against a baseline and fails when any component regresses beyond a threshold.
  - title: SBOM Generation
    details: Generates CycloneDX 1.5 JSON SBOMs from Cargo.lock, package-lock.json, requirements.txt, and go.sum. No internet access required.
  - title: CI-Native Output
    details: Five output formats — SARIF 2.1.0, JSON, JUnit XML, GitLab SAST, and plain text. Direct GitHub Check Run annotations with rich PR summary comments.
---
