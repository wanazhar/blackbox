use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::command::{CommandFidelity, CommandMetadata};
use crate::core::event::{EventSource, SideEffect, TraceEvent};
use crate::core::run::Run;
use crate::replay::{events_from, ReplayEngine, ReplayOutcome, ReplayPolicy};

/// Directories never copied into a sandbox workspace.
const SEED_IGNORE: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".blackbox",
    ".cargo",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".venv",
    "venv",
    ".next",
];

/// Max files / total bytes when seeding a sandbox from the original cwd.
const SEED_MAX_FILES: usize = 5_000;
const SEED_MAX_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
const SEED_MAX_DEPTH: usize = 6;

/// Sandbox replay — re-execute allowed events inside a temporary workspace.
///
/// External and destructive side effects are blocked under the default
/// `ReplayPolicy::Sandbox`. Read and local-write process/tool commands
/// may run in the isolated directory.
///
/// By default the workspace is seeded with a shallow copy of the original
/// run cwd (noise dirs skipped) so `cat`/`ls` style commands see real files.
pub struct SandboxReplay {
    policy: ReplayPolicy,
    /// Optional override workspace (defaults to a fresh temp dir)
    workspace: Option<PathBuf>,
    /// When true (default), copy source project files into the workspace.
    seed_from_cwd: bool,
    /// Optional git commit from a checkpoint — restore tree via `git archive`.
    git_commit: Option<String>,
    /// Optional unified-diff text from checkpoint `git_diff_blob` (applied after archive).
    git_diff: Option<String>,
    /// When true (default), attempt git-commit restore when `git_commit` is set.
    restore_git: bool,
}

impl SandboxReplay {
    pub fn new() -> Self {
        Self {
            policy: ReplayPolicy::Sandbox,
            workspace: None,
            seed_from_cwd: true,
            git_commit: None,
            git_diff: None,
            restore_git: true,
        }
    }

    pub fn with_policy(mut self, policy: ReplayPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_workspace(mut self, path: PathBuf) -> Self {
        self.workspace = Some(path);
        self
    }

    pub fn without_seed(mut self) -> Self {
        self.seed_from_cwd = false;
        self
    }

    /// Restore workspace files from this git commit (best-effort `git archive`).
    pub fn with_git_commit(mut self, commit: Option<String>) -> Self {
        self.git_commit = commit;
        self
    }

    /// Apply checkpoint working-tree diff after git archive (best-effort).
    pub fn with_git_diff(mut self, diff: Option<String>) -> Self {
        self.git_diff = diff;
        self
    }

    pub fn without_git_restore(mut self) -> Self {
        self.restore_git = false;
        self
    }

    /// Returns true if the event's side effect is permitted under the current policy.
    fn is_allowed(&self, side_effect: &SideEffect) -> bool {
        match self.policy {
            ReplayPolicy::ReadOnly => matches!(side_effect, SideEffect::None | SideEffect::Read),
            ReplayPolicy::Sandbox => matches!(
                side_effect,
                SideEffect::None | SideEffect::Read | SideEffect::LocalWrite
            ),
            ReplayPolicy::Live => true,
        }
    }

    /// Extract a command for sandbox re-execution.
    ///
    /// Prefers exact/inferred [`CommandMetadata`]. Lossy whitespace-split
    /// reconstructions are returned with fidelity Lossy so the caller can
    /// refuse them under default sandbox policy.
    fn extract_command_meta(event: &TraceEvent) -> Option<CommandMetadata> {
        if let Some(meta) = CommandMetadata::from_event(event) {
            return Some(meta);
        }
        // Tool call with Bash/shell and only a string in input (no prior meta).
        if event.kind == "tool.call" {
            let name = event
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if matches!(name.as_str(), "bash" | "shell" | "run" | "execute" | "cmd") {
                if let Some(input) = event.metadata.get("input") {
                    if let Some(arr) = input.get("command").and_then(|c| c.as_array()) {
                        let argv: Vec<String> = arr
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        if !argv.is_empty() {
                            return Some(CommandMetadata::from_adapter_argv(argv, None));
                        }
                    }
                    if let Some(cmd) = input
                        .get("command")
                        .and_then(|c| c.as_str())
                        .or_else(|| input.get("cmd").and_then(|c| c.as_str()))
                    {
                        return Some(CommandMetadata::from_shell_source(cmd, Some("bash")));
                    }
                }
            }
        }
        // Legacy process string command → explicitly lossy.
        if event.source == EventSource::Process {
            if let Some(s) = event.metadata.get("command").and_then(|v| v.as_str()) {
                return Some(CommandMetadata::from_display_string(s));
            }
        }
        None
    }

    /// Extract argv for execution when fidelity is safe; otherwise None.
    fn extract_command(event: &TraceEvent) -> Option<(Vec<String>, CommandFidelity)> {
        let meta = Self::extract_command_meta(event)?;
        if let Some(argv) = meta.argv_for_execution() {
            return Some((argv.to_vec(), meta.fidelity));
        }
        // Return lossy argv only so caller can skip with a clear reason.
        if !meta.argv.is_empty() {
            return Some((meta.argv.clone(), meta.fidelity));
        }
        None
    }

    fn run_in_workspace(cmd: &[String], cwd: &Path) -> (i32, String, String) {
        if cmd.is_empty() {
            return (-1, String::new(), "empty command".into());
        }
        let output = Command::new(&cmd[0])
            .args(&cmd[1..])
            .current_dir(cwd)
            .output();
        match output {
            Ok(o) => (
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (-1, String::new(), e.to_string()),
        }
    }
}

impl Default for SandboxReplay {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that removes a temporary directory on drop (panic-safe).
/// Call `disarm()` on the success path to prevent cleanup.
struct TempDirGuard {
    path: Option<PathBuf>,
}

impl TempDirGuard {
    fn none() -> Self {
        Self { path: None }
    }

    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Prevent cleanup on drop (used on success path).
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_dir_all(&p);
            tracing::debug!("cleaned up temp sandbox dir: {}", p.display());
        }
    }
}

/// Sanitize a run ID for safe use in filesystem paths.
fn sanitize_run_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(8)
        .collect::<String>()
}

#[async_trait::async_trait]
impl ReplayEngine for SandboxReplay {
    fn name(&self) -> &'static str {
        "sandbox"
    }

    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        let slice = events_from(events, from_event_id);

        let mut cleanup_guard = TempDirGuard::none();
        // Create or use workspace
        let workspace = if let Some(ws) = &self.workspace {
            std::fs::create_dir_all(ws)?;
            ws.clone()
        } else {
            let dir =
                std::env::temp_dir().join(format!("blackbox-sandbox-{}", sanitize_run_id(&run.id)));
            std::fs::create_dir_all(&dir)?;
            cleanup_guard = TempDirGuard::new(dir.clone());
            dir
        };

        let mut git_restored = None;
        let mut git_diff_applied = None;
        if self.restore_git {
            if let Some(ref commit) = self.git_commit {
                match restore_git_tree(Path::new(&run.cwd), &workspace, commit) {
                    Ok(msg) => {
                        git_restored = Some(msg);
                        tracing::info!(commit = %commit, "sandbox: restored git tree via archive");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, commit = %commit, "sandbox: git restore failed");
                    }
                }
            }
            if let Some(ref diff) = self.git_diff {
                if !diff.trim().is_empty() {
                    match apply_git_diff(&workspace, diff) {
                        Ok(msg) => {
                            git_diff_applied = Some(msg);
                            tracing::info!("sandbox: applied checkpoint git diff");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "sandbox: git diff apply failed");
                        }
                    }
                }
            }
        }

        let seed_stats = if self.seed_from_cwd && self.policy != ReplayPolicy::Live {
            // Prefer git restore as the primary tree; seed fills when archive failed.
            if git_restored.is_some() {
                SeedStats::default()
            } else {
                match seed_workspace(Path::new(&run.cwd), &workspace) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "sandbox: seed from cwd failed");
                        SeedStats::default()
                    }
                }
            }
        } else {
            SeedStats::default()
        };

        // Context file from the original run
        let context = serde_json::json!({
            "source_run_id": run.id,
            "command": run.command,
            "original_cwd": run.cwd,
            "policy": format!("{:?}", self.policy),
            "event_count": slice.len(),
            "seeded_files": seed_stats.files,
            "seeded_bytes": seed_stats.bytes,
            "git_commit": self.git_commit,
            "git_restored": git_restored,
            "git_diff_applied": git_diff_applied,
        });
        std::fs::write(
            workspace.join(".blackbox-sandbox-context.json"),
            serde_json::to_string_pretty(&context)?,
        )?;

        println!("═══ Sandbox replay ═══");
        println!("workspace: {}", workspace.display());
        println!("policy:    {:?}", self.policy);
        if let Some(ref g) = git_restored {
            println!("git:       {g}");
        }
        if let Some(ref d) = git_diff_applied {
            println!("diff:      {d}");
        }
        if seed_stats.files > 0 {
            println!(
                "seeded:    {} files ({} bytes) from {}",
                seed_stats.files, seed_stats.bytes, run.cwd
            );
        }
        println!("{}", "─".repeat(72));

        let mut executed = 0usize;
        let mut skipped = 0usize;

        for event in slice {
            // Only attempt re-execution for process/tool events with a command
            let (cmd, fidelity) = match Self::extract_command(event) {
                Some(c) => c,
                None => continue,
            };

            // Block lossy command reconstruction under non-Live policies.
            // Display-string whitespace splits are ambiguous and unsafe.
            if self.policy != ReplayPolicy::Live && !fidelity.is_safe_for_sandbox() {
                println!(
                    "skip  seq={} kind={} cmd={:?} fidelity={} (lossy reconstruction blocked)",
                    event.sequence,
                    event.kind,
                    cmd,
                    fidelity.as_str()
                );
                tracing::warn!(
                    seq = event.sequence,
                    kind = %event.kind,
                    fidelity = fidelity.as_str(),
                    "sandbox: skipping lossy command reconstruction"
                );
                skipped += 1;
                continue;
            }

            // Re-classify shell tools as Unknown → treat as blocked unless policy Live
            let side = if event.side_effect == SideEffect::Unknown && event.kind == "tool.call" {
                // Bash is unknown — only allow under Live
                SideEffect::Unknown
            } else {
                event.side_effect.clone()
            };

            // R2-C3 / R2-H13: shell interpreters can execute arbitrary argv payloads
            // (e.g. `sh -c "rm -rf /"`). Block them under every policy except Live,
            // even when the event was mis-tagged as Read/LocalWrite.
            let shell_blocked = self.policy != ReplayPolicy::Live && is_shell_interpreter(&cmd);

            // For sandbox policy, allow Unknown only if it's a clearly read-only command
            let allowed = !shell_blocked
                && (self.is_allowed(&side)
                    || (self.policy == ReplayPolicy::Sandbox
                        && side == SideEffect::Unknown
                        && is_readonly_command(&cmd)));

            if !allowed {
                println!(
                    "skip  seq={} kind={} cmd={:?} side={:?} fidelity={}",
                    event.sequence,
                    event.kind,
                    cmd,
                    event.side_effect,
                    fidelity.as_str()
                );
                tracing::warn!(
                    seq = event.sequence,
                    kind = %event.kind,
                    side_effect = ?event.side_effect,
                    "sandbox: skipping event (side effect blocked)"
                );
                skipped += 1;
                continue;
            }

            let (code, stdout, stderr) = Self::run_in_workspace(&cmd, &workspace);
            println!(
                "exec  seq={} kind={} cmd={:?} exit={}",
                event.sequence, event.kind, cmd, code
            );
            if !stdout.trim().is_empty() {
                println!("      stdout: {}", truncate(stdout.trim(), 200));
            }
            if !stderr.trim().is_empty() {
                println!("      stderr: {}", truncate(stderr.trim(), 200));
            }
            tracing::info!(seq = event.sequence, exit = code, "sandbox: executed event");
            executed += 1;
        }

        let summary = format!(
            "re-executed {} command(s), skipped {}, in {}",
            executed,
            skipped,
            workspace.display()
        );
        println!("─── {} ───", summary);
        cleanup_guard.disarm();

        Ok(ReplayOutcome::Sandboxed {
            executed,
            skipped,
            workspace: workspace.display().to_string(),
            summary,
        })
    }
}

#[derive(Debug, Default, Clone)]
struct SeedStats {
    files: usize,
    bytes: u64,
}

/// Best-effort restore of a commit's tree into `workspace` using
/// `git -C source archive <commit> | tar -x -C workspace`.
///
/// Does not require copying `.git`. Fails if source is not a git repo or
/// the commit is missing. Not a full FS guarantee (untracked files absent).
pub fn restore_git_tree(source: &Path, workspace: &Path, commit: &str) -> anyhow::Result<String> {
    let commit = commit.trim();
    // Only full/abbreviated hex SHAs from checkpoints (no branch names / path injection).
    if commit.len() < 7 || commit.len() > 64 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("invalid git commit sha");
    }
    std::fs::create_dir_all(workspace)?;

    let archive = Command::new("git")
        .args(["-C", &source.to_string_lossy(), "archive", commit])
        .output()
        .map_err(|e| anyhow::anyhow!("git archive spawn failed: {e}"))?;
    if !archive.status.success() {
        let err = String::from_utf8_lossy(&archive.stderr);
        anyhow::bail!("git archive failed: {err}");
    }

    let mut tar = Command::new("tar")
        .args(["-x", "-C", &workspace.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("tar spawn failed: {e}"))?;

    if let Some(mut stdin) = tar.stdin.take() {
        use std::io::Write;
        stdin.write_all(&archive.stdout)?;
    }
    let out = tar.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("tar extract failed: {err}");
    }
    Ok(format!("git archive {commit} → {}", workspace.display()))
}

/// Strip blackbox capture banners and apply a unified diff to `workspace`.
///
/// Tries `git apply` first (if git is available), then `patch -p1`.
/// Best-effort — partial apply is not rolled back.
pub fn apply_git_diff(workspace: &Path, diff: &str) -> anyhow::Result<String> {
    let cleaned = strip_diff_banners(diff);
    if cleaned.trim().is_empty() {
        anyhow::bail!("empty diff after stripping banners");
    }
    // Cap size (matches capture limits roughly)
    if cleaned.len() > 8 * 1024 * 1024 {
        anyhow::bail!("diff too large to apply");
    }

    let patch_path = workspace.join(".blackbox-restore.patch");
    std::fs::write(&patch_path, &cleaned)?;

    // Prefer git apply --unsafe-paths -p1 in workspace (not necessarily a repo)
    let git = Command::new("git")
        .args([
            "apply",
            "--whitespace=nowarn",
            "--unsafe-paths",
            "-p1",
            &patch_path.to_string_lossy(),
        ])
        .current_dir(workspace)
        .output();

    if let Ok(out) = git {
        if out.status.success() {
            let _ = std::fs::remove_file(&patch_path);
            return Ok(format!("git apply ({} bytes)", cleaned.len()));
        }
        tracing::debug!(
            stderr = %String::from_utf8_lossy(&out.stderr),
            "git apply failed; trying patch"
        );
    }

    let patch = Command::new("patch")
        .args([
            "-p1",
            "--forward",
            "--batch",
            "-i",
            &patch_path.to_string_lossy(),
        ])
        .current_dir(workspace)
        .output();

    match patch {
        Ok(out) if out.status.success() => {
            let _ = std::fs::remove_file(&patch_path);
            Ok(format!("patch -p1 ({} bytes)", cleaned.len()))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("patch apply failed: {err}");
        }
        Err(e) => anyhow::bail!("patch spawn failed: {e}"),
    }
}

/// Capture stores diffs with human banners; strip them for `git apply`.
fn strip_diff_banners(diff: &str) -> String {
    let mut out = String::with_capacity(diff.len());
    for line in diff.lines() {
        if line.starts_with("--- Unstaged Changes ---")
            || line.starts_with("--- Staged Changes ---")
            || line.starts_with("--- Combined ---")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Shallow copy of project files into the sandbox (skips heavy/noise dirs).
fn seed_workspace(src: &Path, dst: &Path) -> anyhow::Result<SeedStats> {
    if !src.is_dir() {
        return Ok(SeedStats::default());
    }
    let mut stats = SeedStats::default();
    seed_walk(src, src, dst, 0, &mut stats)?;
    Ok(stats)
}

fn seed_walk(
    root: &Path,
    dir: &Path,
    dst_root: &Path,
    depth: usize,
    stats: &mut SeedStats,
) -> anyhow::Result<()> {
    if depth > SEED_MAX_DEPTH || stats.files >= SEED_MAX_FILES || stats.bytes >= SEED_MAX_BYTES {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        if stats.files >= SEED_MAX_FILES || stats.bytes >= SEED_MAX_BYTES {
            break;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if SEED_IGNORE.iter().any(|ig| *ig == name) {
            continue;
        }
        if name == "blackbox.db" || name.starts_with("blackbox.db-") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from(&name));
        let dest = dst_root.join(&rel);
        let ft = entry.file_type().ok();
        if ft.as_ref().map(|f| f.is_dir()).unwrap_or(false) {
            std::fs::create_dir_all(&dest)?;
            seed_walk(root, &path, dst_root, depth + 1, stats)?;
        } else if ft.as_ref().map(|f| f.is_file()).unwrap_or(false) {
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if stats.bytes + len > SEED_MAX_BYTES {
                continue;
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if std::fs::copy(&path, &dest).is_ok() {
                stats.files += 1;
                stats.bytes += len;
            }
        }
    }
    Ok(())
}

/// True when the command binary is a shell interpreter (basename match).
///
/// Accepts both bare names (`sh`) and paths (`/bin/bash`) so sandbox policy
/// cannot be bypassed via absolute paths.
fn is_shell_interpreter(cmd: &[String]) -> bool {
    let first = cmd.first().map(|s| s.as_str()).unwrap_or("");
    let base = std::path::Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first);
    matches!(base, "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh")
}

fn is_readonly_command(cmd: &[String]) -> bool {
    let joined = cmd.join(" ").to_lowercase();
    let first = cmd.first().map(|s| s.as_str()).unwrap_or("");

    // Block shell interpreters entirely — they can execute arbitrary commands
    // passed as arguments (e.g. `sh -c "rm -rf /"`), bypassing the side-effect
    // classification if the event was incorrectly tagged as Read/LocalWrite.
    if is_shell_interpreter(cmd) {
        return false;
    }

    matches!(
        first,
        "ls" | "cat"
            | "head"
            | "tail"
            | "pwd"
            | "echo"
            | "true"
            | "false"
            | "which"
            | "env"
            | "printenv"
            | "wc"
            | "grep"
            | "rg"
            | "find"
            | "stat"
            | "file"
    ) && !joined.contains("rm ")
        && !joined.contains(">")
        && !joined.contains("curl")
        && !joined.contains("wget")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};

    #[tokio::test]
    async fn sandbox_runs_readonly_echo() {
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.status = EventStatus::Success;
        ev.side_effect = SideEffect::Read;
        ev.metadata
            .insert("command".into(), serde_json::json!(["echo", "sandbox-ok"]));

        let ws = std::env::temp_dir().join(format!("bb-sbx-test-{}", uuid::Uuid::new_v4()));
        let mut engine = SandboxReplay::new()
            .with_workspace(ws.clone())
            .without_seed();
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed { executed, .. } => assert_eq!(executed, 1),
            other => panic!("unexpected {:?}", other),
        }
        assert!(ws.join(".blackbox-sandbox-context.json").exists());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn sandbox_seeds_source_files() {
        let src = std::env::temp_dir().join(format!("bb-seed-src-{}", uuid::Uuid::new_v4()));
        let ws = std::env::temp_dir().join(format!("bb-seed-ws-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("hello.txt"), b"seed-me").unwrap();

        let run = Run::new(
            vec!["cat".into(), "hello.txt".into()],
            src.to_string_lossy().into(),
        );
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.side_effect = SideEffect::Read;
        ev.metadata
            .insert("command".into(), serde_json::json!(["cat", "hello.txt"]));

        let mut engine = SandboxReplay::new().with_workspace(ws.clone());
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed { executed, .. } => assert_eq!(executed, 1),
            other => panic!("unexpected {:?}", other),
        }
        assert_eq!(
            std::fs::read_to_string(ws.join("hello.txt")).unwrap(),
            "seed-me"
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn sandbox_blocks_destructive() {
        let run = Run::new(vec!["rm".into()], "/tmp".into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.side_effect = SideEffect::Destructive;
        ev.metadata.insert(
            "command".into(),
            serde_json::json!(["rm", "-rf", "/tmp/nope"]),
        );

        let ws = std::env::temp_dir().join(format!("bb-sbx-block-{}", uuid::Uuid::new_v4()));
        let mut engine = SandboxReplay::new()
            .with_workspace(ws.clone())
            .without_seed();
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed {
                executed, skipped, ..
            } => {
                assert_eq!(executed, 0);
                assert_eq!(skipped, 1);
            }
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn is_readonly_blocks_shell_interpreters() {
        // R2-C3 / R2-H13: shell passthrough would allow `sh -c "rm -rf /"`
        // even when the event was mis-tagged as Read.
        assert!(is_shell_interpreter(&[
            "sh".into(),
            "-c".into(),
            "echo hi".into()
        ]));
        assert!(is_shell_interpreter(&[
            "/bin/bash".into(),
            "-c".into(),
            "rm -rf /".into()
        ]));
        assert!(is_shell_interpreter(&["zsh".into()]));
        assert!(!is_shell_interpreter(&["echo".into(), "hi".into()]));
        assert!(!is_readonly_command(&[
            "sh".into(),
            "-c".into(),
            "echo hi".into()
        ]));
        assert!(!is_readonly_command(&[
            "bash".into(),
            "-c".into(),
            "rm -rf /".into()
        ]));
        assert!(!is_readonly_command(&[
            "zsh".into(),
            "-c".into(),
            "true".into()
        ]));
        assert!(!is_readonly_command(&[
            "fish".into(),
            "-c".into(),
            "true".into()
        ]));
        assert!(!is_readonly_command(&[
            "dash".into(),
            "-c".into(),
            "true".into()
        ]));
        assert!(!is_readonly_command(&[
            "ksh".into(),
            "-c".into(),
            "true".into()
        ]));
        // Legitimate read-only tools still allowed
        assert!(is_readonly_command(&["echo".into(), "hi".into()]));
        assert!(is_readonly_command(&["cat".into(), "file.txt".into()]));
        assert!(is_readonly_command(&["ls".into(), "-la".into()]));
    }

    #[tokio::test]
    async fn sandbox_blocks_shell_even_if_tagged_read() {
        let run = Run::new(vec!["sh".into()], "/tmp".into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        // Mis-classified as Read — must still be blocked
        ev.side_effect = SideEffect::Read;
        ev.metadata.insert(
            "command".into(),
            serde_json::json!(["sh", "-c", "echo should-not-run"]),
        );

        let ws = std::env::temp_dir().join(format!("bb-sbx-shell-{}", uuid::Uuid::new_v4()));
        let mut engine = SandboxReplay::new()
            .with_workspace(ws.clone())
            .without_seed();
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed {
                executed, skipped, ..
            } => {
                assert_eq!(executed, 0, "shell must not execute under sandbox");
                assert_eq!(skipped, 1);
            }
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn sandbox_blocks_lossy_display_string_commands() {
        let run = Run::new(vec!["echo".into()], "/tmp".into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.side_effect = SideEffect::Read;
        // String form only — reconstructs via whitespace split → lossy
        ev.metadata
            .insert("command".into(), serde_json::json!("echo hello world"));

        let ws = std::env::temp_dir().join(format!("bb-sbx-lossy-{}", uuid::Uuid::new_v4()));
        let mut engine = SandboxReplay::new()
            .with_workspace(ws.clone())
            .without_seed();
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed {
                executed, skipped, ..
            } => {
                assert_eq!(executed, 0, "lossy commands must not execute");
                assert_eq!(skipped, 1);
            }
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn sandbox_executes_exact_argv_with_spaces() {
        let run = Run::new(vec!["echo".into()], "/tmp".into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.side_effect = SideEffect::Read;
        // Exact argv preserves "hello world" as one argument
        CommandMetadata::from_proc_argv(
            vec!["echo".into(), "hello world".into()],
            Some("/bin/echo".into()),
            None,
            crate::core::command::CaptureMethod::ProcCmdline,
        )
        .apply_to_event(&mut ev);

        let ws = std::env::temp_dir().join(format!("bb-sbx-exact-{}", uuid::Uuid::new_v4()));
        let mut engine = SandboxReplay::new()
            .with_workspace(ws.clone())
            .without_seed();
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed { executed, .. } => assert_eq!(executed, 1),
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn extract_command_meta_prefers_argv_over_display() {
        let mut ev = TraceEvent::new("r", EventSource::Process, "process.exec");
        ev.metadata.insert(
            "argv".into(),
            serde_json::json!(["grep", "hello world", "f.txt"]),
        );
        ev.metadata.insert(
            "command".into(),
            serde_json::json!("grep hello world f.txt"),
        );
        ev.metadata
            .insert("capture_method".into(), serde_json::json!("proc_poller"));
        let meta = SandboxReplay::extract_command_meta(&ev).unwrap();
        assert_eq!(meta.argv[1], "hello world");
        assert_eq!(meta.fidelity, CommandFidelity::Exact);
    }

    #[test]
    fn restore_git_tree_rejects_non_hex() {
        let dir = tempfile::tempdir().unwrap();
        let err = restore_git_tree(dir.path(), dir.path(), "../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn strip_diff_banners_removes_headers() {
        let raw = "--- Unstaged Changes ---\ndiff --git a/x b/x\n+hi\n";
        let c = strip_diff_banners(raw);
        assert!(!c.contains("Unstaged"));
        assert!(c.contains("diff --git"));
    }

    #[test]
    fn apply_git_diff_empty_fails() {
        let ws = tempfile::tempdir().unwrap();
        let err = apply_git_diff(ws.path(), "--- Unstaged Changes ---\n").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn restore_git_tree_from_repo_when_available() {
        // Best-effort: skip if not in a git repo or git/tar missing.
        let cwd = std::env::current_dir().unwrap();
        let rev = Command::new("git")
            .args(["-C", &cwd.to_string_lossy(), "rev-parse", "HEAD"])
            .output();
        let Ok(out) = rev else { return };
        if !out.status.success() {
            return;
        }
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if sha.len() < 7 {
            return;
        }
        let ws = tempfile::tempdir().unwrap();
        let msg = restore_git_tree(&cwd, ws.path(), &sha).expect("git archive restore");
        assert!(msg.contains(&sha[..7]));
        // Repo should have extracted something (Cargo.toml at least for this project)
        assert!(
            ws.path().join("Cargo.toml").exists() || ws.path().read_dir().unwrap().next().is_some(),
            "expected files from git archive"
        );
    }
}
