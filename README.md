# OxideCI

OxideCI is a blazing fast, language-agnostic DevOps CLI tool designed to enforce security, linting, and quality gates across all your projects.

## 🚀 Key Benefits

- **Language Agnostic**: Works perfectly whether your project is in Rust, Node.js, Python, or Go.
- **Blazing Fast**: Written in Rust, utilizing `rayon` for heavily parallelized multi-core execution (like regex scanning) and `tokio` for efficient asynchronous I/O operations.
- **Out-of-the-Box Smart Traverse**: Automatically respects your project's `.gitignore` rules when scanning files, saving you from writing complex path exclusion configurations.
- **All-in-One Binary**: A single, dependency-free compiled binary you can drop into any CI pipeline or run locally with ease. 

## 🛠 Installation & Usage

OxideCI is distributed as a standalone binary, making it entirely dependency-free for your CI pipelines. 

### Recommended: CI Pipeline (GitHub Actions / CI)
The fastest way to use OxideCI in your pipelines is to download the pre-compiled binary directly.

```yaml
# Example: GitHub Actions Pipeline
- name: Install OxideCI
  run: |
    curl -sL https://github.com/ThinkGrid-Labs/oxide-ci/releases/latest/download/oxide-ci-linux-amd64 -o /usr/local/bin/oxide-ci
    chmod +x /usr/local/bin/oxide-ci

- name: Run Secret Scan
  run: oxide-ci scan
```

### Alternative: Install via Cargo
If you already have a Rust environment, you can install the binary directly from source:
```bash
cargo install --git https://github.com/ThinkGrid-Labs/oxide-ci
oxide-ci --help
```

---

## 🚦 Commands

### 1. Secret & PII Scanning
Quickly scan your entire repository for hardcoded AWS keys, SSNs, emails, and other sensitive PII patterns.

```bash
# Scan the current directory
oxide-ci scan
```

### 2. Kubernetes Manifest Linting
Ensure your Kubernetes deployments are safe by validating that your YAML files have resource limits defined. *(WIP)*

```bash
# Lint Kubernetes files in the local directory
oxide-ci lint
```

### 3. Coverage Threshold Gates
Ensure your team doesn't drop their testing standards. Parse your locally generated coverage reports (like `lcov.info`) and automatically fail the CI job if coverage drops below a strict minimum threshold. *(WIP)*

```bash
# Verify coverage file meets 80% (default)
oxide-ci coverage --file path/to/lcov.info

# Set a custom threshold of 95%
oxide-ci coverage --file path/to/lcov.info --min 95
```

## 🏗 Architecture
OxideCI is built to be extensible:
* **Interface Layer**: Powered by `clap` for clean and robust CLI argument parsing.
* **Concurrency**: `rayon` for CPU-bound tasks and `tokio` for I/O bounds.
* **Traversal**: Uses the `ignore` crate for fast, parallel file system walking respecting git boundaries.

---

## 🤝 Open Source & Contributing

OxideCI is proudly Open Source under the [MIT License](LICENSE). Contributions, issues, and feature requests are welcome!

Visit the public repository at [ThinkGrid-Labs/oxide-ci](https://github.com/ThinkGrid-Labs/oxide-ci).
