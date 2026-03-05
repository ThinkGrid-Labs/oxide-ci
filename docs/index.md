---
layout: home

hero:
  name: OxideCI
  text: Rust DevOps CLI for CI Quality Gates
  tagline: Secret scanning, AST-based SAST, Kubernetes linting, coverage gates, dependency auditing, and web performance — single zero-dependency binary.
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
    details: tree-sitter parses JS/TS/TSX/JSX into a real AST before pattern matching, eliminating comment and JSX false positives.
  - title: Blazing Fast
    details: Parallel file scanning via rayon across all CPU cores. Typical repositories scan in under a second.
  - title: Secret & PII Detection
    details: 26 built-in patterns covering AWS, Azure, GCP, Stripe, GitHub, Twilio, Expo, Sentry, Mapbox, and more.
  - title: Kubernetes Linting
    details: Validates workload manifests for missing resource limits, probes, unpinned images, and root containers.
  - title: CI-Native Output
    details: SARIF 2.1.0 output for GitHub Advanced Security, JSON for custom tooling, and direct GitHub Check Run annotations.
---
