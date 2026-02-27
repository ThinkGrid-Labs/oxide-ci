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
