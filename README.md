# OxideCI

A high-performance DevOps CLI tool built in Rust. OxideCI works across any language project to enforce security, linting, and quality gates using a blazing fast, modular architecture.

## Features

- **Blazing Fast**: Uses `rayon` for parallel CPU-bound tasks and `tokio` for async I/O.
- **Gitignore Aware**: Respects your project's `.gitignore` rules automatically out of the box using `ignore`.
- **Modular Architecture**: Designed to be extensible for all your CI/CD needs.

## Subcommands

* `scan`: Scans the current directory for hardcoded secrets (AWS keys, PII) using regex.
* `lint`: Validates if Kubernetes YAML files in a directory have resource limits defined *(WIP)*.
* `coverage`: Parses an LCOV file and exits with code 1 if total coverage is below a user-provided `--min` threshold *(WIP)*.

## Installation

Ensure you have [Rust and Cargo](https://rustup.rs/) installed, then run:

```bash
cargo build --release
```

You can find the produced binary in `target/release/oxide-ci`.

## Usage

Run the tool from the root of your project:

```bash
# Display help
cargo run -- --help

# Run secret scanning
cargo run -- scan

# Run kubernetes linting
cargo run -- lint

# Run coverage checks
cargo run -- coverage --file coverage/lcov.info --min 80
```

## Architecture

This project is built using a Hexagonal-inspired layout:

- **Interface Layer (Clap)**: Handles CLI arguments and help text.
- **Concurrency Layer (Rayon/Tokio)**: Powers the fast, concurrent execution.
- **Logic Modules**: Decoupled modules (`scanner`, `k8s_lint`, `coverage`) that contain the actual tool implementations.
