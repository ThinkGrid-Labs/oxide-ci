use crate::modules::scanner::Finding;
use anyhow::Result;

// ── Environment detection ─────────────────────────────────────────────────────

pub struct GitHubEnv {
    pub token: String,
    pub repository: String, // "owner/repo"
    pub sha: String,
}

/// Returns `Some(GitHubEnv)` when all three required env vars are present.
pub fn detect_github_env() -> Option<GitHubEnv> {
    let token = std::env::var("GITHUB_TOKEN").ok()?;
    let repository = std::env::var("GITHUB_REPOSITORY").ok()?;
    let sha = std::env::var("GITHUB_SHA").ok()?;
    Some(GitHubEnv {
        token,
        repository,
        sha,
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Create a GitHub Check Run, annotate it with findings (batched in chunks of
/// 50 per the API limit), mark it complete, and post a PR review comment.
///
/// Failures are non-fatal: the caller logs a warning and continues.
pub fn annotate(findings: &[Finding], env: &GitHubEnv) -> Result<()> {
    let (owner, repo) = env
        .repository
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("GITHUB_REPOSITORY is not in owner/repo format"))?;

    let check_id = create_check_run(owner, repo, &env.sha, &env.token)?;

    // GitHub limits 50 annotations per PATCH call.
    for chunk in findings.chunks(50) {
        update_check_run_annotations(owner, repo, check_id, chunk, &env.token)?;
    }

    complete_check_run(owner, repo, check_id, findings.len(), &env.token)?;

    if !findings.is_empty() {
        post_pr_summary_comment(owner, repo, &env.sha, findings.len(), &env.token)?;
    }

    Ok(())
}

// ── GitHub API helpers ────────────────────────────────────────────────────────

const API_BASE: &str = "https://api.github.com";

fn create_check_run(owner: &str, repo: &str, sha: &str, token: &str) -> Result<u64> {
    let url = format!("{}/repos/{}/{}/check-runs", API_BASE, owner, repo);
    let body = serde_json::json!({
        "name": "oxide-ci",
        "head_sha": sha,
        "status": "in_progress",
    });
    let resp = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub create check-run: {}", e))?;
    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| anyhow::anyhow!("GitHub create check-run parse: {}", e))?;
    json["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("GitHub API did not return a check run id"))
}

fn update_check_run_annotations(
    owner: &str,
    repo: &str,
    check_id: u64,
    chunk: &[Finding],
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let annotations: Vec<serde_json::Value> = chunk
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path.to_string_lossy(),
                "start_line": f.line,
                "end_line": f.line,
                "annotation_level": "warning",
                "title": &f.rule_id,
                "message": format!("[{}] Potential security issue detected.", f.rule_id),
            })
        })
        .collect();
    let body = serde_json::json!({
        "output": {
            "title": "oxide-ci scan",
            "summary": format!("{} finding(s)", chunk.len()),
            "annotations": annotations,
        }
    });
    ureq::request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub update check-run annotations: {}", e))?;
    Ok(())
}

fn complete_check_run(
    owner: &str,
    repo: &str,
    check_id: u64,
    total: usize,
    token: &str,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/{}/check-runs/{}",
        API_BASE, owner, repo, check_id
    );
    let conclusion = if total == 0 { "success" } else { "failure" };
    let body = serde_json::json!({
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "oxide-ci scan",
            "summary": format!("oxide-ci found {} issue(s).", total),
        }
    });
    ureq::request("PATCH", &url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub complete check-run: {}", e))?;
    Ok(())
}

fn post_pr_summary_comment(
    owner: &str,
    repo: &str,
    sha: &str,
    total: usize,
    token: &str,
) -> Result<()> {
    // Look up the PR number associated with this commit SHA.
    let commits_url = format!(
        "{}/repos/{}/{}/commits/{}/pulls",
        API_BASE, owner, repo, sha
    );
    let pr_number = match ureq::get(&commits_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call()
    {
        Ok(r) => {
            let json: serde_json::Value = r.into_json().unwrap_or(serde_json::Value::Null);
            json[0]["number"].as_u64()
        }
        Err(_) => None,
    };

    let Some(pr_number) = pr_number else {
        // Commit is not associated with an open PR — skip the review comment.
        return Ok(());
    };

    let comment_url = format!(
        "{}/repos/{}/{}/issues/{}/comments",
        API_BASE, owner, repo, pr_number
    );
    let body = serde_json::json!({
        "body": format!(
            "## oxide-ci scan summary\n\n\
             **{total} finding(s)** detected.\n\n\
             See the **Checks** tab for per-line annotations."
        )
    });
    ureq::post(&comment_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("GitHub post PR comment: {}", e))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_github_env_returns_some_with_all_vars() {
        // Scoped setup/teardown to avoid polluting other tests.
        let _g1 = ScopedEnv::set("GITHUB_TOKEN", "tok");
        let _g2 = ScopedEnv::set("GITHUB_REPOSITORY", "owner/repo");
        let _g3 = ScopedEnv::set("GITHUB_SHA", "abc123");
        assert!(detect_github_env().is_some());
    }

    #[test]
    fn detect_github_env_returns_none_on_missing_token() {
        let _g1 = ScopedEnv::remove("GITHUB_TOKEN");
        assert!(detect_github_env().is_none());
    }

    /// RAII guard that restores an env var on drop.
    struct ScopedEnv {
        key: &'static str,
        prev: Option<String>,
    }
    impl ScopedEnv {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: single-threaded test context
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }
        fn remove(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: single-threaded test context
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                // SAFETY: single-threaded test context
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }
}
