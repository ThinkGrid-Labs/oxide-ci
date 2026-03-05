# coverage — Coverage Threshold Gate

Parses a coverage report and fails with exit code 1 if total line coverage is below the specified minimum. Shows a per-file breakdown of files below the threshold.

Two formats are supported and auto-detected:

| Format | Extension | Used by |
|---|---|---|
| **LCOV** | `.info` or no extension | Rust (cargo-llvm-cov), Jest, pytest-cov, Go |
| **Cobertura XML** | `.xml` | Python (coverage.py), Java (JaCoCo), .NET |

## Usage

```
oxide-ci coverage [OPTIONS]

Options:
  -f, --file <FILE>    Path to the coverage file [default: coverage/lcov.info]
  -m, --min <MIN>      Minimum coverage threshold % [default: 80]
  -h, --help           Print help
```

## Examples

```bash
# LCOV (Rust, Jest, pytest, Go)
oxide-ci coverage --file coverage/lcov.info --min 80

# Cobertura XML (Python coverage.py, JaCoCo)
oxide-ci coverage --file coverage.xml --min 80

# Stricter 90% gate
oxide-ci coverage --file coverage/lcov.info --min 90

# Use defaults from .oxideci.toml
oxide-ci coverage
```

## Generating coverage reports

```bash
# Rust (cargo-llvm-cov)
cargo llvm-cov --lcov --output-path coverage/lcov.info

# Jest
jest --coverage --coverageReporters=lcov

# pytest
pytest --cov=. --cov-report=lcov:coverage/lcov.info
pytest --cov=. --cov-report=xml:coverage.xml

# Go
go test ./... -coverprofile=coverage/lcov.info
```

## Sample output

```
ℹ️  Analyzing coverage file: coverage/lcov.info (threshold: 80.0%)

  Files below threshold (80.0%):
    61.2%  src/handlers/auth.rs
    72.4%  src/utils/parser.rs

⚠️  Coverage 74.8% is below threshold 80.0% (12 files, 748/1000 lines covered)
Error: Coverage gate failed: 74.8% < 80.0%
```
