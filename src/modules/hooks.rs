use crate::utils::terminal;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const HOOK_CONTENT: &str = r#"#!/bin/sh
# oxide-ci pre-commit hook (auto-installed)
# Scans only staged files for secrets and PII before every commit.
oxide-ci scan --staged
"#;

/// Walk up from `start` looking for a `.git` directory (max 10 levels).
fn find_git_dir(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    for _ in 0..10 {
        let candidate = current.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

pub fn run_install_hooks(force: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("Cannot determine current directory")?;
    let git_dir =
        find_git_dir(&cwd).context("No .git directory found — is this a git repository?")?;

    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Cannot create hooks directory: {}", hooks_dir.display()))?;

    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() && !force {
        terminal::warn(&format!(
            "Hook already exists at {}. Use --force to overwrite.",
            hook_path.display()
        ));
        return Ok(());
    }

    std::fs::write(&hook_path, HOOK_CONTENT)
        .with_context(|| format!("Cannot write hook to {}", hook_path.display()))?;

    // Set executable bit on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)
            .with_context(|| format!("Cannot set +x on {}", hook_path.display()))?;
    }

    terminal::success(&format!(
        "Pre-commit hook installed at {}",
        hook_path.display()
    ));
    terminal::info("oxide-ci scan --staged will now run before every commit.");
    Ok(())
}
