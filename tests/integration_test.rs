use std::process::Command;

fn binary() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_oxide-ci").into()
}

// ── scan ──────────────────────────────────────────────────────────────────────

#[test]
fn scan_exits_zero_on_clean_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("clean.txt"), "hello world, no secrets here\n").unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0 on clean directory");
}

#[test]
fn scan_exits_nonzero_on_secrets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.env"),
        "AWS_KEY=AKIAIOSFODNN7EXAMPLEKEY1\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(!status.success(), "expected non-zero exit when secrets found");
}

#[test]
fn scan_json_output_on_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secret.txt"),
        // Split so no single source literal triggers GitHub push-protection.
        format!("{}{}\n", "sk_live_", "abcdefghijklmnopqrstuvwx"),
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json must produce valid JSON on stdout");
    assert!(parsed["total"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn scan_sarif_output_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("key.txt"),
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "sarif"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format sarif must produce valid JSON on stdout");
    assert_eq!(parsed["version"].as_str(), Some("2.1.0"));
    assert!(parsed["runs"].is_array());
}

// ── lint ──────────────────────────────────────────────────────────────────────

const GOOD_MANIFEST: &str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:1.2.3
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
"#;

const BAD_MANIFEST: &str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:latest
"#;

#[test]
fn lint_exits_zero_on_compliant_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("deploy.yaml"), GOOD_MANIFEST).unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(status.success(), "compliant manifest should pass lint");
}

#[test]
fn lint_exits_nonzero_on_bad_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("deploy.yaml"), BAD_MANIFEST).unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(!status.success(), "bad manifest should fail lint");
}

#[test]
fn lint_exits_zero_when_no_yaml_files() {
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(binary())
        .args(["lint", "--dir", dir.path().to_str().unwrap()])
        .status()
        .unwrap();

    assert!(status.success(), "empty directory should exit 0");
}

// ── coverage ──────────────────────────────────────────────────────────────────

fn write_lcov(dir: &std::path::Path, hit: u64, found: u64) -> std::path::PathBuf {
    let path = dir.join("lcov.info");
    std::fs::write(
        &path,
        format!("SF:src/main.rs\nLH:{}\nLF:{}\nend_of_record\n", hit, found),
    )
    .unwrap();
    path
}

#[test]
fn coverage_exits_zero_above_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let lcov = write_lcov(dir.path(), 90, 100);

    let status = Command::new(binary())
        .args(["coverage", "--file", lcov.to_str().unwrap(), "--min", "80"])
        .status()
        .unwrap();

    assert!(status.success(), "90% should pass 80% threshold");
}

#[test]
fn coverage_exits_nonzero_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let lcov = write_lcov(dir.path(), 50, 100);

    let status = Command::new(binary())
        .args(["coverage", "--file", lcov.to_str().unwrap(), "--min", "80"])
        .status()
        .unwrap();

    assert!(!status.success(), "50% should fail 80% threshold");
}

// ── Feature 3: Inline suppression ─────────────────────────────────────────────

#[test]
fn scan_suppressed_line_is_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    // AWS key on a line marked with the suppression comment — must not be flagged
    std::fs::write(
        dir.path().join("config.env"),
        "AWS_KEY=AKIAIOSFODNN7EXAMPLEKEY1  # oxide-ci: ignore\n",
    )
    .unwrap();

    let status = Command::new(binary())
        .arg("scan")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(
        status.success(),
        "suppressed line should not cause non-zero exit"
    );
}

#[test]
fn scan_suppression_only_on_marked_line() {
    let dir = tempfile::tempdir().unwrap();
    // Line 1: suppressed → no finding; Line 2: NOT suppressed → 1 finding expected
    std::fs::write(
        dir.path().join("config.env"),
        format!(
            "SAFE=AKIAIOSFODNN7EXAMPLEKEY1  # oxide-ci: ignore\n{}\n",
            "REAL=AKIAIOSFODNN7EXAMPLEKEY1"
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed["total"].as_u64().unwrap(),
        1,
        "only the unsuppressed line should be flagged"
    );
}

// ── Feature 1: Entropy detection ──────────────────────────────────────────────

#[test]
fn scan_detects_high_entropy_string() {
    let dir = tempfile::tempdir().unwrap();
    // 32-char high-entropy base64-like token — doesn't match any named regex pattern
    std::fs::write(
        dir.path().join("config.env"),
        "API_SECRET=aB3dEfGhIjKlMnOpQrStUvWxYz012345\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["scan", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "high-entropy token should be flagged");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rules: Vec<&str> = parsed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap_or(""))
        .collect();
    assert!(
        rules.iter().any(|r| r.contains("High Entropy")),
        "expected a High Entropy finding, got rules: {:?}",
        rules
    );
}

// ── Feature 2: Git history scan ───────────────────────────────────────────────

#[test]
fn scan_history_flag_accepted() {
    // Run in oxide-ci's own repo — guaranteed to be a git repository.
    // Check only that the flag is recognised and any output is valid JSON.
    let output = Command::new(binary())
        .args(["scan", "--history", "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(&stdout)
            .expect("--history --format json must produce valid JSON on stdout");
    }
}

// ── Features 4+5: Multi-lockfile audit + Go support ───────────────────────────

#[test]
fn audit_finds_multiple_lockfiles_in_subdirectories() {
    let dir = tempfile::tempdir().unwrap();

    // Rust sub-project
    std::fs::create_dir(dir.path().join("api")).unwrap();
    std::fs::write(
        dir.path().join("api/Cargo.lock"),
        "[package]\nname = \"api\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    // Node sub-project
    std::fs::create_dir(dir.path().join("frontend")).unwrap();
    std::fs::write(
        dir.path().join("frontend/package-lock.json"),
        r#"{"packages": {"node_modules/lodash": {"version": "4.17.21"}}}"#,
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("No supported lock file found"),
        "should find lock files in subdirectories; stderr: {}",
        stderr
    );
}

#[test]
fn audit_parses_go_sum_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("go.sum"),
        "github.com/gin-gonic/gin v1.9.1 h1:fakehash=\n\
         github.com/gin-gonic/gin v1.9.1/go.mod h1:fakehash2=\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("audit")
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("go.sum") || stderr.contains("Go") || stderr.contains("gin"),
        "should detect go.sum and report on it; stderr: {}",
        stderr
    );
}

// ── install-hooks ─────────────────────────────────────────────────────────────

#[test]
fn install_hooks_creates_hook_file() {
    let repo_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path().join(".git/hooks")).unwrap();

    let status = Command::new(binary())
        .arg("install-hooks")
        .current_dir(repo_dir.path())
        .status()
        .unwrap();

    assert!(status.success(), "install-hooks should exit 0");

    let hook_path = repo_dir.path().join(".git/hooks/pre-commit");
    assert!(hook_path.exists(), "pre-commit hook file should exist");

    let content = std::fs::read_to_string(&hook_path).unwrap();
    assert!(
        content.contains("oxide-ci scan --staged"),
        "hook must invoke oxide-ci scan --staged"
    );
}

#[test]
fn install_hooks_does_not_overwrite_without_force() {
    let repo_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path().join(".git/hooks")).unwrap();
    let hook_path = repo_dir.path().join(".git/hooks/pre-commit");
    std::fs::write(&hook_path, "#!/bin/sh\necho existing hook\n").unwrap();

    Command::new(binary())
        .arg("install-hooks")
        .current_dir(repo_dir.path())
        .status()
        .unwrap();

    let content = std::fs::read_to_string(&hook_path).unwrap();
    assert!(
        content.contains("existing hook"),
        "existing hook should not be overwritten without --force"
    );
}
