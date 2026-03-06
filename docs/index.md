---
layout: home

hero:
  name: OxideCI
  text: Rust DevOps CLI for CI Quality Gates
  tagline: Secret scanning, AST-based SAST (JS/TS/Python/Go), Kubernetes linting, coverage gates, SBOM generation, dependency auditing, and web performance — single zero-dependency binary.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/ThinkGrid-Labs/oxide-ci

features:
  - title: Zero Runtime Dependencies
    details: Drop a single compiled Rust binary into any CI pipeline, Docker image, or developer machine. No Node, Python, or JVM required.
  - title: AST-Based SAST
    details: tree-sitter parses JS/TS/TSX/JSX, Python, and Go into a real AST before pattern matching, eliminating comment and false-positive noise. Detects eval, exec, pickle, subprocess, unsafe imports, and more.
  - title: Blazing Fast
    details: Parallel file scanning via rayon across all CPU cores. Typical repositories scan in under a second.
  - title: Secret & PII Detection
    details: 26 built-in patterns covering AWS, Azure, GCP, Stripe, GitHub, Twilio, Expo, Sentry, Mapbox, and more.
  - title: Kubernetes Linting
    details: Validates workload manifests for missing resource limits, probes, unpinned images, and root containers.
  - title: Docker Linting
    details: Audits Dockerfiles for unpinned base images, ADD instead of COPY, missing USER, missing HEALTHCHECK, exposed dangerous ports, and more.
  - title: Coverage Gates
    details: Parses lcov.info and fails the build when line coverage drops below a configurable threshold. Zero external tools required.
  - title: Dependency Audit
    details: Queries the OSV vulnerability database for known CVEs in your Cargo.lock. Offline-capable with a local cache.
  - title: Web Performance
    details: Lighthouse audits via the PageSpeed Insights API gate on performance, accessibility, best practices, and SEO scores.
  - title: Reassure Performance
    details: Compares React Native component render measurements against a baseline and fails when any component regresses beyond a threshold.
  - title: SBOM Generation
    details: Generates CycloneDX 1.5 JSON SBOMs from Cargo.lock, package-lock.json, requirements.txt, and go.sum. No internet access required.
  - title: CI-Native Output
    details: Five output formats — SARIF 2.1.0, JSON, JUnit XML, GitLab SAST, and plain text. Direct GitHub Check Run annotations with rich PR summary comments.
---
