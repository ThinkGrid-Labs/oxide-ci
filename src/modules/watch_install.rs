//! `greengate watch-install` — wraps a package-manager install command and
//! monitors `node_modules/` in real-time for two supply-chain attack signatures:
//!
//! 1. **Phantom files** — a file is created inside `node_modules/` during a
//!    postinstall script and then deleted before the install finishes.  This is
//!    the textbook dropper pattern (write binary → execute → unlink to hide
//!    evidence).
//!
//! 2. **Executable drops** — a new executable file appears in the project root
//!    that was not present before the install began.  Legitimate package managers
//!    never place executables outside `node_modules/`.
//!
//! Implementation uses a 250 ms polling thread — zero extra dependencies.

use crate::utils::terminal;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

// ── Public types ──────────────────────────────────────────────────────────────

pub struct WatchInstallOpts {
    /// "npm", "yarn", "pnpm", or "bun"
    pub package_manager: String,
    /// Arguments forwarded verbatim to the package manager
    pub args: Vec<String>,
    /// Exit non-zero if any phantom file or executable drop is detected
    pub block_phantom_scripts: bool,
    /// Also monitor the project root for unexpected executable drops
    pub enforce_sandbox: bool,
    /// Package names whose postinstall scripts may legitimately create temp files
    pub allow_postinstall: Vec<String>,
}

#[derive(Debug)]
pub struct PhantomFinding {
    pub path: PathBuf,
    pub package: String,
    pub kind: FindingKind,
}

#[derive(Debug)]
pub enum FindingKind {
    /// Created inside node_modules/ during install, then deleted before it finished
    EphemeralFile,
    /// New executable file persisted in the project root after install completed
    ExecutableDrop,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_watch_install(opts: WatchInstallOpts) -> Result<()> {
    terminal::info(&format!(
        "watch-install: wrapping `{} {}`",
        opts.package_manager,
        opts.args.join(" "),
    ));

    // 1. Pre-install snapshots — taken before the child process starts so we
    //    have a clean baseline to diff against.
    let pre_modules = snapshot_dir("node_modules");
    let pre_root = snapshot_root_executables(".");

    // 2. Shared state updated by the polling thread.
    let state = Arc::new(Mutex::new(WatchState::new(pre_modules)));
    let done = Arc::new(AtomicBool::new(false));

    // 3. Background polling thread — checks node_modules/ every 250 ms.
    //    Started *before* the child process so we don't miss early events.
    let state_clone = Arc::clone(&state);
    let done_clone = Arc::clone(&done);
    let poll_thread = std::thread::spawn(move || {
        while !done_clone.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(250));
            let current = snapshot_dir("node_modules");
            state_clone.lock().unwrap().update(current);
        }
        // One final scan after the child exits to catch any last-moment events.
        let current = snapshot_dir("node_modules");
        state_clone.lock().unwrap().update(current);
    });

    // 4. Run the wrapped package manager and inherit its stdio so the developer
    //    sees normal install output.
    let pm_status = std::process::Command::new(&opts.package_manager)
        .args(&opts.args)
        .status();

    // 5. Signal the polling thread to stop and wait for it to finish its
    //    final scan before we read the accumulated findings.
    done.store(true, Ordering::Relaxed);
    let _ = poll_thread.join();

    // 6. Check whether the package manager itself reported an error.
    match &pm_status {
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to launch `{}`: {}. Is it installed and on PATH?",
                opts.package_manager,
                e
            ));
        }
        Ok(status) if !status.success() => {
            terminal::warn(&format!(
                "`{}` exited with non-zero status — install may be incomplete.",
                opts.package_manager
            ));
        }
        _ => {}
    }

    // 7. Collect all findings from the watcher (allowlisted findings are retained
    //    so they can be shown as warnings, but they do not trigger a failure).
    let mut watch_state = state.lock().unwrap();
    let mut findings: Vec<PhantomFinding> = watch_state.phantoms();

    // 8. Detect new executables in the project root (exec-drop detection).
    if opts.enforce_sandbox {
        let post_root = snapshot_root_executables(".");
        for path in post_root.keys() {
            if pre_root.contains_key(path) {
                continue; // existed before install
            }
            // Ignore generated lock files and the node_modules directory itself.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                "node_modules"
                    | "package-lock.json"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "bun.lockb"
            ) {
                continue;
            }
            if is_executable(path) {
                findings.push(PhantomFinding {
                    package: "<project-root>".to_string(),
                    path: path.clone(),
                    kind: FindingKind::ExecutableDrop,
                });
            }
        }
    }

    // 9. Emit all findings; allowlisted ones are shown as warnings only.
    report_findings(&findings, &opts.allow_postinstall);

    // Fail only on findings that are NOT covered by allow_postinstall.
    let blocking_count = findings
        .iter()
        .filter(|f| !is_allowlisted(&f.package, &opts.allow_postinstall))
        .count();

    if blocking_count > 0 && opts.block_phantom_scripts {
        return Err(anyhow::anyhow!(
            "watch-install: {} blocking event(s) detected — halting.",
            blocking_count
        ));
    }

    if findings.is_empty() {
        terminal::success("watch-install: clean — no phantom files or executable drops detected.");
    }

    Ok(())
}

// ── Watch state ───────────────────────────────────────────────────────────────

/// Tracks `node_modules/` across polls to identify phantom files.
struct WatchState {
    /// Files present in the most recent poll.
    prev: HashMap<PathBuf, SystemTime>,
    /// Files that existed *before* the install started — not flagged if deleted.
    pre_install: HashSet<PathBuf>,
    /// Files that appeared for the first time *after* the install started.
    created_since_start: HashSet<PathBuf>,
    /// Accumulated findings (create→delete pairs).
    phantom_list: Vec<PhantomFinding>,
}

impl WatchState {
    fn new(initial: HashMap<PathBuf, SystemTime>) -> Self {
        let pre_install: HashSet<PathBuf> = initial.keys().cloned().collect();
        Self {
            prev: initial,
            pre_install,
            created_since_start: HashSet::new(),
            phantom_list: Vec::new(),
        }
    }

    fn update(&mut self, current: HashMap<PathBuf, SystemTime>) {
        // Borrow prev/current as sets of path references for set arithmetic.
        let current_paths: HashSet<&PathBuf> = current.keys().collect();
        let prev_paths: HashSet<&PathBuf> = self.prev.keys().collect();

        // Files that appeared this poll and were not present before install.
        for path in current_paths.difference(&prev_paths) {
            if !self.pre_install.contains(*path) {
                self.created_since_start.insert((*path).clone());
            }
        }

        // Files that disappeared this poll — phantom if created after install started.
        for path in prev_paths.difference(&current_paths) {
            if self.created_since_start.remove(*path) {
                self.phantom_list.push(PhantomFinding {
                    package: package_from_path(path),
                    path: (*path).clone(),
                    kind: FindingKind::EphemeralFile,
                });
            }
        }

        self.prev = current;
    }

    /// Drain and return the accumulated phantom findings.
    fn phantoms(&mut self) -> Vec<PhantomFinding> {
        std::mem::take(&mut self.phantom_list)
    }
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

/// Returns `path → mtime` for every file under `dir`, recursively.
/// Returns an empty map if `dir` does not exist.
fn snapshot_dir(dir: &str) -> HashMap<PathBuf, SystemTime> {
    let mut map = HashMap::new();
    let root = Path::new(dir);
    if root.exists() {
        walk_dir(root, &mut map);
    }
    map
}

fn walk_dir(dir: &Path, map: &mut HashMap<PathBuf, SystemTime>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            walk_dir(&path, map);
        } else if ft.is_file()
            && let Ok(meta) = entry.metadata()
            && let Ok(mtime) = meta.modified()
        {
            map.insert(path, mtime);
        }
    }
}

/// Returns `path → mtime` for files directly in `dir` (non-recursive).
/// Used for project-root exec-drop detection.
fn snapshot_root_executables(dir: &str) -> HashMap<PathBuf, SystemTime> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return map;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && let Ok(meta) = std::fs::metadata(&path)
            && let Ok(mtime) = meta.modified()
        {
            map.insert(path, mtime);
        }
    }
    map
}

/// Extracts the npm package name from a `node_modules/…` path.
///
/// Examples:
/// - `node_modules/axios/scripts/evil.sh` → `axios`
/// - `node_modules/@scope/pkg/bin/run`   → `@scope/pkg`
/// - any other path                       → `<project-root>`
fn package_from_path(path: &Path) -> String {
    let components: Vec<_> = path.components().collect();
    let Some(pos) = components
        .iter()
        .position(|c| c.as_os_str() == "node_modules")
    else {
        return "<project-root>".to_string();
    };

    match components.get(pos + 1) {
        Some(first) if first.as_os_str().to_string_lossy().starts_with('@') => {
            // Scoped package: @scope/name
            let scope = first.as_os_str().to_string_lossy();
            let name = components
                .get(pos + 2)
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .unwrap_or_default();
            format!("{}/{}", scope, name)
        }
        Some(pkg) => pkg.as_os_str().to_string_lossy().into_owned(),
        None => "<unknown>".to_string(),
    }
}

fn is_allowlisted(package: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|a| a == package)
}

/// Returns `true` if `path` has the executable bit set (Unix) or an executable
/// extension (Windows).
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("exe") | Some("bat") | Some("cmd") | Some("ps1")
    )
}

// ── Output ────────────────────────────────────────────────────────────────────

fn report_findings(findings: &[PhantomFinding], allow_postinstall: &[String]) {
    if findings.is_empty() {
        return;
    }
    eprintln!();
    eprintln!(
        "🚨 greengate watch-install: {} suspicious event(s) detected:",
        findings.len()
    );
    eprintln!();
    for f in findings {
        let kind_label = match f.kind {
            FindingKind::EphemeralFile => "PHANTOM   ",
            FindingKind::ExecutableDrop => "EXEC_DROP ",
        };
        let hint = if is_allowlisted(&f.package, allow_postinstall) {
            " [allowlisted — warning only]"
        } else {
            ""
        };
        eprintln!("  [{}] {}{}", kind_label, f.package, hint);
        eprintln!("           path: {}", f.path.display());
    }
    eprintln!();
    eprintln!(
        "  Tip: if this package is a known native build tool (e.g. esbuild, swc),\n  \
         add it to [supply_chain] allow_postinstall in .greengate.toml to suppress."
    );
    eprintln!();
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a snapshot map from bare path strings (mtime is irrelevant for
    /// these tests so we always use UNIX_EPOCH).
    fn snap(paths: &[&str]) -> HashMap<PathBuf, SystemTime> {
        paths
            .iter()
            .map(|p| (PathBuf::from(p), SystemTime::UNIX_EPOCH))
            .collect()
    }

    fn allowlist(pkgs: &[&str]) -> Vec<String> {
        pkgs.iter().map(|s| s.to_string()).collect()
    }

    // ── package_from_path ────────────────────────────────────────────────────

    #[test]
    fn package_from_path_regular_package() {
        let p = PathBuf::from("node_modules/axios/lib/core/settle.js");
        assert_eq!(package_from_path(&p), "axios");
    }

    #[test]
    fn package_from_path_scoped_package() {
        let p = PathBuf::from("node_modules/@scope/pkg/index.js");
        assert_eq!(package_from_path(&p), "@scope/pkg");
    }

    #[test]
    fn package_from_path_no_node_modules_segment() {
        let p = PathBuf::from("src/main.rs");
        assert_eq!(package_from_path(&p), "<project-root>");
    }

    #[test]
    fn package_from_path_bare_node_modules() {
        // Path that ends exactly at node_modules with no package segment after it
        let p = PathBuf::from("node_modules");
        assert_eq!(package_from_path(&p), "<unknown>");
    }

    #[test]
    fn package_from_path_nested_node_modules() {
        // Hoisted deps can create node_modules inside node_modules in older npm versions
        let p = PathBuf::from("node_modules/outer/node_modules/inner/index.js");
        // Should return the package immediately after the first node_modules segment
        assert_eq!(package_from_path(&p), "outer");
    }

    // ── is_allowlisted ───────────────────────────────────────────────────────

    #[test]
    fn allowlist_returns_true_for_known_package() {
        assert!(is_allowlisted(
            "esbuild",
            &allowlist(&["esbuild", "prisma"])
        ));
    }

    #[test]
    fn allowlist_returns_false_for_unknown_package() {
        assert!(!is_allowlisted("evil-pkg", &allowlist(&["esbuild"])));
    }

    #[test]
    fn allowlist_empty_list_never_matches() {
        assert!(!is_allowlisted("anything", &[]));
    }

    // ── WatchState ───────────────────────────────────────────────────────────

    #[test]
    fn watch_state_starts_empty_with_no_phantoms() {
        let state = WatchState::new(snap(&["node_modules/pkg/index.js"]));
        assert!(state.phantom_list.is_empty());
        assert!(state.created_since_start.is_empty());
    }

    #[test]
    fn new_file_added_to_created_since_start() {
        let mut state = WatchState::new(snap(&[]));
        state.update(snap(&["node_modules/evil-pkg/backdoor"]));
        assert!(
            state
                .created_since_start
                .contains(&PathBuf::from("node_modules/evil-pkg/backdoor")),
            "new file must appear in created_since_start"
        );
        assert!(
            state.phantom_list.is_empty(),
            "file still present — not a phantom yet"
        );
    }

    #[test]
    fn pre_existing_file_deleted_is_not_a_phantom() {
        // The file existed before install — deleting it is not suspicious.
        let mut state = WatchState::new(snap(&["node_modules/pkg/index.js"]));
        state.update(snap(&[])); // pkg/index.js disappears
        assert!(
            state.phantom_list.is_empty(),
            "pre-existing file deletion must not be flagged"
        );
    }

    #[test]
    fn file_created_then_deleted_is_flagged_as_phantom() {
        let mut state = WatchState::new(snap(&[]));

        // Poll 1: file appears
        state.update(snap(&["node_modules/evil-pkg/backdoor"]));
        assert!(state.phantom_list.is_empty());

        // Poll 2: file disappears
        state.update(snap(&[]));

        let phantoms = state.phantoms();
        assert_eq!(phantoms.len(), 1);
        assert_eq!(phantoms[0].package, "evil-pkg");
        assert!(
            matches!(phantoms[0].kind, FindingKind::EphemeralFile),
            "kind must be EphemeralFile"
        );
    }

    #[test]
    fn file_that_persists_after_install_is_not_a_phantom() {
        let mut state = WatchState::new(snap(&[]));
        state.update(snap(&["node_modules/pkg/real-file.js"]));
        // File stays
        state.update(snap(&["node_modules/pkg/real-file.js"]));

        assert!(
            state.phantom_list.is_empty(),
            "persistent file must not be flagged"
        );
    }

    #[test]
    fn each_create_delete_cycle_produces_one_phantom() {
        // File appears, disappears, reappears, disappears — two separate phantom events.
        let mut state = WatchState::new(snap(&[]));

        state.update(snap(&["node_modules/pkg/run.sh"])); // create
        state.update(snap(&[])); // delete  → phantom #1
        state.update(snap(&["node_modules/pkg/run.sh"])); // create again
        state.update(snap(&[])); // delete  → phantom #2

        let phantoms = state.phantoms();
        assert_eq!(
            phantoms.len(),
            2,
            "two create-delete cycles must produce two phantom findings"
        );
    }

    #[test]
    fn multiple_packages_each_produce_own_phantom() {
        let mut state = WatchState::new(snap(&[]));

        state.update(snap(&[
            "node_modules/pkg-a/evil",
            "node_modules/pkg-b/evil",
        ]));
        state.update(snap(&[])); // both deleted

        let phantoms = state.phantoms();
        assert_eq!(phantoms.len(), 2);
        let packages: Vec<&str> = phantoms.iter().map(|p| p.package.as_str()).collect();
        assert!(packages.contains(&"pkg-a"));
        assert!(packages.contains(&"pkg-b"));
    }

    // ── is_executable (Unix only) ─────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn is_executable_returns_false_without_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644); // no exec bit
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(!is_executable(&path));
    }

    #[test]
    #[cfg(unix)]
    fn is_executable_returns_true_with_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(is_executable(&path));
    }

    #[test]
    #[cfg(not(unix))]
    fn is_executable_detects_windows_extensions() {
        assert!(is_executable(Path::new("run.exe")));
        assert!(is_executable(Path::new("script.bat")));
        assert!(is_executable(Path::new("cmd.cmd")));
        assert!(is_executable(Path::new("run.ps1")));
        assert!(!is_executable(Path::new("readme.txt")));
        assert!(!is_executable(Path::new("index.js")));
    }
}
