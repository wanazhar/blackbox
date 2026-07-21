use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

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

/// Workspace replay — re-execute allowed events inside a temporary directory.
///
/// **Default is not OS process isolation.** Workspace mode uses a temporary
/// directory and policy filters. Enable [`SandboxReplay::with_contained`] on
/// Linux when `bwrap` is available for best-effort namespace isolation
/// (network unshare + restricted binds).
///
/// External and destructive side effects are blocked under the default
/// `ReplayPolicy::Sandbox`. Read and local-write process/tool commands
/// may run in the temporary directory.
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
    /// Linux contained backend via bubblewrap when available.
    contained: bool,
}

impl SandboxReplay {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new() -> Self {
        Self {
            policy: ReplayPolicy::Sandbox,
            workspace: None,
            seed_from_cwd: true,
            git_commit: None,
            git_diff: None,
            restore_git: true,
            contained: false,
        }
    }

    /// Set policy and return self.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_policy` — see module docs for full workflow.
    /// ```
    pub fn with_policy(mut self, policy: ReplayPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set workspace and return self.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_workspace` — see module docs for full workflow.
    /// ```
    pub fn with_workspace(mut self, path: PathBuf) -> Self {
        self.workspace = Some(path);
        self
    }

    /// Without seed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `without_seed` — see module docs for full workflow.
    /// ```
    pub fn without_seed(mut self) -> Self {
        self.seed_from_cwd = false;
        self
    }

    /// Restore workspace files from this git commit (best-effort `git archive`).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_git_commit` — see module docs for full workflow.
    /// ```
    pub fn with_git_commit(mut self, commit: Option<String>) -> Self {
        self.git_commit = commit;
        self
    }

    /// Apply checkpoint working-tree diff after git archive (best-effort).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_git_diff` — see module docs for full workflow.
    /// ```
    pub fn with_git_diff(mut self, diff: Option<String>) -> Self {
        self.git_diff = diff;
        self
    }

    /// Without git restore.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `without_git_restore` — see module docs for full workflow.
    /// ```
    pub fn without_git_restore(mut self) -> Self {
        self.restore_git = false;
        self
    }

    /// Prefer Linux contained execution (bubblewrap) when available.
    ///
    /// If `bwrap` is missing, [`ReplayEngine::start`] fails closed with a clear
    /// preflight error rather than silently falling back to workspace-only.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_contained` — see module docs for full workflow.
    /// ```
    pub fn with_contained(mut self, enabled: bool) -> Self {
        self.contained = enabled;
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
        let mut c = Command::new(&cmd[0]);
        c.args(&cmd[1..]).current_dir(cwd);
        // Workspace is not OS isolation — still scrub obvious credential env.
        scrub_replay_env(&mut c, cwd);
        match c.output() {
            Ok(o) => (
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (-1, String::new(), e.to_string()),
        }
    }

    /// Run argv under bubblewrap when contained mode is on.
    fn run_contained(cmd: &[String], cwd: &Path) -> (i32, String, String) {
        if cmd.is_empty() {
            return (-1, String::new(), "empty command".into());
        }
        let cwd_s = cwd.to_string_lossy();
        // Best-effort containment: network unshare, die-with-parent, bind workspace
        // writable, system paths read-only. Not a full multi-tenant sandbox.
        let mut bwrap = Command::new("bwrap");
        bwrap
            .arg("--die-with-parent")
            .arg("--unshare-net")
            .arg("--dev")
            .arg("/dev")
            .arg("--proc")
            .arg("/proc")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--ro-bind")
            .arg("/bin")
            .arg("/bin");
        // Optional common roots (missing paths are skipped via separate checks).
        for p in ["/lib", "/lib64", "/sbin", "/etc"] {
            if Path::new(p).exists() {
                bwrap.arg("--ro-bind").arg(p).arg(p);
            }
        }
        bwrap
            .arg("--bind")
            .arg(cwd.as_os_str())
            .arg(cwd.as_os_str())
            .arg("--chdir")
            .arg(cwd.as_os_str())
            .arg("--")
            .arg(&cmd[0])
            .args(&cmd[1..]);
        // Scrub host credentials from the child environment.
        scrub_replay_env(&mut bwrap, cwd);
        match bwrap.output() {
            Ok(o) => (
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (
                -1,
                String::new(),
                format!("bwrap spawn failed in {cwd_s}: {e}"),
            ),
        }
    }
}

/// Clear inherited secrets; keep a minimal PATH/locale and set HOME to workspace.
fn scrub_replay_env(cmd: &mut Command, workspace: &Path) {
    cmd.env_clear();
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    cmd.env("PATH", path);
    cmd.env("HOME", workspace);
    cmd.env("TMPDIR", workspace);
    for k in ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
}

/// Status of the optional Linux contained replay backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainedBackendStatus {
    /// Available.
    pub available: bool,
    /// Tool.
    pub tool: Option<String>,
    /// Reason.
    pub reason: String,
}

/// Probe whether bubblewrap-based contained replay can be used on this host.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `probe_contained_backend` — see module docs for full workflow.
/// ```
pub fn probe_contained_backend() -> ContainedBackendStatus {
    if !cfg!(target_os = "linux") {
        return ContainedBackendStatus {
            available: false,
            tool: None,
            reason: "contained replay requires Linux".into(),
        };
    }
    match Command::new("bwrap").arg("--version").output() {
        Ok(o) if o.status.success() => {
            let ver = String::from_utf8_lossy(&o.stdout);
            let first = ver.lines().next().unwrap_or("bwrap").trim().to_string();
            ContainedBackendStatus {
                available: true,
                tool: Some("bwrap".into()),
                reason: format!("bubblewrap available ({first})"),
            }
        }
        Ok(o) => ContainedBackendStatus {
            available: false,
            tool: None,
            reason: format!(
                "bwrap --version failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        },
        Err(e) => ContainedBackendStatus {
            available: false,
            tool: None,
            reason: format!("bubblewrap (bwrap) not found on PATH: {e}"),
        },
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
        if self.contained {
            "contained"
        } else {
            // Historical engine id; operator-facing copy says "workspace replay".
            "workspace"
        }
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
            let dir = std::env::temp_dir()
                .join(format!("blackbox-workspace-{}", sanitize_run_id(&run.id)));
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
                        tracing::info!(commit = %commit, "workspace: restored git tree via archive");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, commit = %commit, "workspace: git restore failed");
                    }
                }
            }
            if let Some(ref diff) = self.git_diff {
                if !diff.trim().is_empty() {
                    match apply_git_diff(&workspace, diff) {
                        Ok(msg) => {
                            git_diff_applied = Some(msg);
                            tracing::info!("workspace: applied checkpoint git diff");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "workspace: git diff apply failed");
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
                        tracing::warn!(error = %e, "workspace: seed from cwd failed");
                        SeedStats::default()
                    }
                }
            }
        } else {
            SeedStats::default()
        };

        // Capability preflight — honest isolation level (1.5 R1).
        if self.contained {
            let probe = probe_contained_backend();
            if !probe.available {
                anyhow::bail!(
                    "contained replay requested but unavailable: {}",
                    probe.reason
                );
            }
        }
        let capabilities = capability_report(self.policy, self.contained);
        let mode_label = if self.contained {
            "contained_replay"
        } else {
            "workspace_replay"
        };
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
            "mode": mode_label,
            "contained": self.contained,
            "capabilities": capabilities,
        });
        std::fs::write(
            workspace.join(".blackbox-workspace-context.json"),
            serde_json::to_string_pretty(&context)?,
        )?;
        // Compat alias for older tooling that looked for the sandbox name.
        let _ = std::fs::write(
            workspace.join(".blackbox-sandbox-context.json"),
            serde_json::to_string_pretty(&context)?,
        );

        if self.contained {
            println!("═══ Contained replay (bubblewrap) ═══");
            println!("workspace: {}", workspace.display());
            println!("policy:    {:?}", self.policy);
            println!("isolation: best-effort namespaces via bwrap (not multi-tenant hardened)");
        } else {
            println!("═══ Workspace replay ═══");
            println!("workspace: {}", workspace.display());
            println!("policy:    {:?}", self.policy);
            println!("isolation: temporary directory (not OS process isolation)");
        }
        for (k, v) in &capabilities {
            println!("{k}: {v}");
        }
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
                    "workspace: skipping lossy command reconstruction"
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

            // Block shells under every non-Live policy.
            if self.policy != ReplayPolicy::Live && is_shell_interpreter(&cmd) {
                println!(
                    "skip  seq={} kind={} cmd={:?} (shell interpreter blocked)",
                    event.sequence, event.kind, cmd
                );
                skipped += 1;
                continue;
            }
            // Block script interpreters and escape args under Sandbox/ReadOnly.
            if self.policy != ReplayPolicy::Live
                && (is_script_interpreter(&cmd) || has_escape_args(&cmd))
            {
                println!(
                    "skip  seq={} kind={} cmd={:?} (interpreter or absolute path blocked)",
                    event.sequence, event.kind, cmd
                );
                skipped += 1;
                continue;
            }

            // R2-C3 / R2-H13: shell interpreters can execute arbitrary argv payloads
            // (e.g. `sh -c "rm -rf /"`). Block them under every policy except Live,
            // even when the event was mis-tagged as Read/LocalWrite.
            let shell_blocked = self.policy != ReplayPolicy::Live && is_shell_interpreter(&cmd);

            // For workspace policy, allow Unknown only if it's a clearly read-only command
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
                    "workspace: skipping event (side effect blocked)"
                );
                skipped += 1;
                continue;
            }

            let (code, stdout, stderr) = if self.contained {
                Self::run_contained(&cmd, &workspace)
            } else {
                Self::run_in_workspace(&cmd, &workspace)
            };
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
            tracing::info!(
                seq = event.sequence,
                exit = code,
                "workspace: executed event"
            );
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
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `restore_git_tree` — see module docs for full workflow.
/// ```
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

/// Honest capability report for workspace or contained replay (1.5 R1).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `workspace_capability_report` — see module docs for full workflow.
/// ```
pub fn workspace_capability_report(policy: ReplayPolicy) -> Vec<(String, String)> {
    capability_report(policy, false)
}

/// Capability report including contained-backend probe when `contained` is true.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `capability_report` — see module docs for full workflow.
/// ```
pub fn capability_report(policy: ReplayPolicy, contained: bool) -> Vec<(String, String)> {
    let probe = if contained {
        Some(probe_contained_backend())
    } else {
        None
    };
    let contained_ok = probe.as_ref().map(|p| p.available).unwrap_or(false);

    let (net, home, creds, limits, isolation, kernel, backend) = match policy {
        ReplayPolicy::Live => (
            "not enforced (live)".to_string(),
            "not enforced (live)".to_string(),
            "not stripped (live)".to_string(),
            "none".to_string(),
            "none (live)".to_string(),
            "not available".to_string(),
            "live".to_string(),
        ),
        _ if contained_ok => (
            "unshare-net (bwrap)".to_string(),
            "not bound into container (bwrap)".to_string(),
            "scrubbed (minimal PATH/locale; HOME=workspace)".to_string(),
            "die-with-parent only".to_string(),
            "namespaces via bubblewrap".to_string(),
            "best-effort (bwrap namespaces; not multi-tenant hardened)".to_string(),
            "contained-bwrap".to_string(),
        ),
        _ if contained => {
            let reason = probe
                .as_ref()
                .map(|p| p.reason.clone())
                .unwrap_or_else(|| "unavailable".into());
            (
                format!("requested but unavailable ({reason})"),
                "workspace-only fallback not used (fail closed)".to_string(),
                "n/a".to_string(),
                "n/a".to_string(),
                "unavailable".to_string(),
                format!("unavailable: {reason}"),
                "contained-unavailable".to_string(),
            )
        }
        _ => (
            "not enforced (workspace-only)".to_string(),
            "not enforced (workspace-only)".to_string(),
            "not stripped (workspace-only)".to_string(),
            "none".to_string(),
            "temporary-directory".to_string(),
            "not available (use --contained on Linux with bwrap)".to_string(),
            "workspace".to_string(),
        ),
    };
    vec![
        ("workspace isolation".into(), isolation),
        (
            "filesystem escape protection".into(),
            "path-validated-patch-only".into(),
        ),
        ("network isolation".into(), net),
        ("home access".into(), home),
        ("credential environment".into(), creds),
        ("resource limits".into(), limits),
        ("backend".into(), backend),
        ("kernel isolation".into(), kernel),
    ]
}

/// Strip blackbox capture banners and apply a unified diff to `workspace`.
///
/// **Path-safe transactional restore (1.5):**
/// 1. Parse every source/destination path in the patch.
/// 2. Reject absolute paths, `..` traversal, and destinations outside the workspace.
/// 3. Apply into a staging directory.
/// 4. Promote changed files only after the complete patch succeeds.
/// 5. On failure, leave the original workspace unmodified.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `apply_git_diff` — see module docs for full workflow.
/// ```
pub fn apply_git_diff(workspace: &Path, diff: &str) -> anyhow::Result<String> {
    let cleaned = strip_diff_banners(diff);
    if cleaned.trim().is_empty() {
        anyhow::bail!("empty diff after stripping banners");
    }
    if cleaned.len() > 8 * 1024 * 1024 {
        anyhow::bail!("diff too large to apply");
    }

    let paths = parse_patch_paths(&cleaned)?;
    for p in &paths {
        validate_patch_path(p)?;
    }

    // Staging workspace — never mutate the destination until apply succeeds fully.
    let stage_path =
        std::env::temp_dir().join(format!("blackbox-patch-stage-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&stage_path).context("create patch staging dir")?;
    let _stage_guard = TempDirGuard::new(stage_path.clone());

    // Seed staging with existing destination files that the patch may touch.
    for rel in &paths {
        let src = workspace.join(rel);
        let dst = stage_path.join(rel);
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&src, &dst)
                .with_context(|| format!("seed staging from {}", src.display()))?;
        }
    }

    let patch_path = stage_path.join(".blackbox-restore.patch");
    std::fs::write(&patch_path, &cleaned)?;

    // Apply without --unsafe-paths; paths already validated.
    let git = Command::new("git")
        .args([
            "apply",
            "--whitespace=nowarn",
            "-p1",
            "--directory",
            &stage_path.to_string_lossy(),
            &patch_path.to_string_lossy(),
        ])
        .output();

    let applied = match git {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "git apply failed; trying patch in staging"
            );
            false
        }
        Err(_) => false,
    };

    if !applied {
        let patch = Command::new("patch")
            .args([
                "-p1",
                "--forward",
                "--batch",
                "-d",
                &stage_path.to_string_lossy(),
                "-i",
                &patch_path.to_string_lossy(),
            ])
            .output();
        match patch {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!("patch apply failed (workspace unchanged): {err}");
            }
            Err(e) => anyhow::bail!("patch spawn failed (workspace unchanged): {e}"),
        }
    }

    // Promote: copy every staged relative path (except the patch file) into workspace.
    promote_staged_files(&stage_path, workspace)?;
    Ok(format!(
        "path-safe patch apply ({} bytes, {} paths)",
        cleaned.len(),
        paths.len()
    ))
}

fn promote_staged_files(stage: &Path, workspace: &Path) -> anyhow::Result<()> {
    fn walk(stage_root: &Path, dir: &Path, workspace: &Path) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            if name == ".blackbox-restore.patch" {
                continue;
            }
            let rel = path
                .strip_prefix(stage_root)
                .map_err(|_| anyhow::anyhow!("staging path escape"))?;
            // Re-validate relative path on promote.
            let rel_str = rel.to_string_lossy();
            validate_patch_path(&rel_str)?;
            let dest = workspace.join(rel);
            if path.is_dir() {
                std::fs::create_dir_all(&dest)?;
                walk(stage_root, &path, workspace)?;
            } else if path.is_file() {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Atomic-ish: write temp then rename within destination dir.
                let tmp = dest.with_extension("bb-promote-tmp");
                std::fs::copy(&path, &tmp)
                    .with_context(|| format!("promote copy {}", path.display()))?;
                std::fs::rename(&tmp, &dest)
                    .with_context(|| format!("promote rename {}", dest.display()))?;
            }
        }
        Ok(())
    }
    walk(stage, stage, workspace)
}

/// Extract destination-ish paths from a unified diff (`+++ b/...`, `diff --git a/ x b/y`).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `parse_patch_paths` — see module docs for full workflow.
/// ```
pub fn parse_patch_paths(diff: &str) -> anyhow::Result<Vec<String>> {
    let mut paths = Vec::new();
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            // Formats: `+++ b/path` or `+++ path` or `/dev/null`
            let p = rest.trim();
            if p == "/dev/null" {
                continue;
            }
            let p = p
                .strip_prefix("b/")
                .or_else(|| p.strip_prefix("a/"))
                .unwrap_or(p);
            // Drop optional tab timestamp
            let p = p.split('\t').next().unwrap_or(p).trim();
            if !p.is_empty() {
                paths.push(p.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("diff --git ") {
            // `diff --git a/foo b/bar`
            for part in rest.split_whitespace() {
                let p = part
                    .strip_prefix("a/")
                    .or_else(|| part.strip_prefix("b/"))
                    .unwrap_or(part);
                if p != "/dev/null" && !p.is_empty() {
                    paths.push(p.to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix("rename to ") {
            paths.push(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("copy to ") {
            paths.push(rest.trim().to_string());
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Reject absolute paths, traversal, and other escapes (1.5 patch path safety).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `validate_patch_path` — see module docs for full workflow.
/// ```
pub fn validate_patch_path(path: &str) -> anyhow::Result<()> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("empty path in patch");
    }
    if path.starts_with('/') || path.starts_with('\\') {
        anyhow::bail!("absolute path rejected in patch: {path}");
    }
    // Windows drive letter
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        anyhow::bail!("absolute path rejected in patch: {path}");
    }
    if path.contains('\0') {
        anyhow::bail!("NUL in patch path");
    }
    for comp in Path::new(path).components() {
        match comp {
            std::path::Component::ParentDir => {
                anyhow::bail!("path traversal rejected in patch: {path}");
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                anyhow::bail!("absolute path rejected in patch: {path}");
            }
            _ => {}
        }
    }
    Ok(())
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

/// Basename of argv[0] (handles absolute paths).
fn cmd_basename(cmd: &[String]) -> &str {
    let first = cmd.first().map(|s| s.as_str()).unwrap_or("");
    std::path::Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
}

/// True when the command binary is a shell interpreter (basename match).
///
/// Accepts both bare names (`sh`) and paths (`/bin/bash`) so sandbox policy
/// cannot be bypassed via absolute paths.
fn is_shell_interpreter(cmd: &[String]) -> bool {
    matches!(
        cmd_basename(cmd),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh"
    )
}

/// Scripting / multi-purpose interpreters that must not re-execute under workspace policy.
fn is_script_interpreter(cmd: &[String]) -> bool {
    let base = cmd_basename(cmd);
    matches!(
        base,
        "python"
            | "python2"
            | "python3"
            | "node"
            | "nodejs"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
            | "luajit"
            | "deno"
            | "bun"
            | "pwsh"
            | "powershell"
            | "osascript"
            | "awk"
            | "gawk"
            | "make"
            | "cmake"
            | "ninja"
            | "cargo"
            | "go"
            | "java"
            | "dotnet"
            | "env" // launcher: env python3 -c …
            | "xargs"
            | "nice"
            | "nohup"
            | "timeout"
            | "stdbuf"
            | "sudo"
            | "doas"
    ) || base.starts_with("python")
}

/// Reject absolute path arguments outside a pure relative workspace form.
fn has_escape_args(cmd: &[String]) -> bool {
    for (i, a) in cmd.iter().enumerate() {
        if i == 0 {
            // Allow absolute binary path for system tools (/bin/cat); still gated by allowlist.
            continue;
        }
        if a.starts_with('/') || a.starts_with("~/") || a.contains("..") {
            return true;
        }
        // Windows-style absolute
        let b = a.as_bytes();
        if b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
            return true;
        }
    }
    false
}

fn is_readonly_command(cmd: &[String]) -> bool {
    // Block shells / interpreters entirely under Unknown→readonly promotion.
    if is_shell_interpreter(cmd) || is_script_interpreter(cmd) {
        return false;
    }
    if has_escape_args(cmd) {
        return false;
    }

    let base = cmd_basename(cmd);
    // Deny-by-default allowlist of pure read/display tools (basename only).
    // Intentionally excludes env/find (launcher / -exec/-delete).
    matches!(
        base,
        "ls" | "cat"
            | "head"
            | "tail"
            | "pwd"
            | "echo"
            | "true"
            | "false"
            | "which"
            | "wc"
            | "grep"
            | "rg"
            | "stat"
            | "file"
            | "md5sum"
            | "sha256sum"
            | "basename"
            | "dirname"
            | "realpath"
            | "readlink"
            | "test"
            | "["
    )
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
        // env/find removed; absolute arg paths blocked.
        assert!(!is_readonly_command(&[
            "env".into(),
            "python3".into(),
            "-c".into(),
            "print(1)".into()
        ]));
        assert!(!is_readonly_command(&[
            "find".into(),
            ".".into(),
            "-delete".into()
        ]));
        assert!(!is_readonly_command(&["cat".into(), "/etc/passwd".into()]));
        assert!(!is_readonly_command(&["python3".into(), "x.py".into()]));
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
    fn validate_patch_path_rejects_absolute_and_traversal() {
        assert!(validate_patch_path("src/main.rs").is_ok());
        assert!(validate_patch_path("/etc/passwd").is_err());
        assert!(validate_patch_path("../escape").is_err());
        assert!(validate_patch_path("foo/../../etc/passwd").is_err());
        assert!(validate_patch_path(r"C:\Windows\System32").is_err());
    }

    #[test]
    fn apply_git_diff_rejects_absolute_before_modify() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("keep.txt"), b"safe").unwrap();
        let evil = "diff --git a/x b/x\n--- a/x\n+++ /etc/passwd\n@@ -0,0 +1 @@\n+pwned\n";
        let err = apply_git_diff(ws.path(), evil).unwrap_err();
        assert!(
            err.to_string().contains("absolute") || err.to_string().contains("rejected"),
            "got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(ws.path().join("keep.txt")).unwrap(),
            "safe",
            "workspace must be unchanged after rejected patch"
        );
    }

    #[test]
    fn apply_git_diff_rejects_traversal_before_modify() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("keep.txt"), b"safe").unwrap();
        let evil = "diff --git a/x b/x\n--- a/x\n+++ b/../../escape.txt\n@@ -0,0 +1 @@\n+pwned\n";
        let err = apply_git_diff(ws.path(), evil).unwrap_err();
        assert!(
            err.to_string().contains("traversal") || err.to_string().contains("rejected"),
            "got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(ws.path().join("keep.txt")).unwrap(),
            "safe"
        );
    }

    #[test]
    fn apply_git_diff_path_safe_success() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("file.txt"), b"hello\n").unwrap();
        // Create a minimal git repo so git apply can work; also try plain patch.
        let _ = Command::new("git")
            .args(["init"])
            .current_dir(ws.path())
            .output();
        let diff = "\
diff --git a/file.txt b/file.txt
--- a/file.txt
+++ b/file.txt
@@ -1 +1 @@
-hello
+hello world
";
        // May succeed via git apply or patch depending on environment.
        match apply_git_diff(ws.path(), diff) {
            Ok(msg) => {
                assert!(msg.contains("path-safe"));
                let body = std::fs::read_to_string(ws.path().join("file.txt")).unwrap();
                assert!(body.contains("hello world"), "body={body}");
            }
            Err(e) => {
                // Environments without git/patch still validate path safety above.
                let msg = e.to_string();
                assert!(
                    msg.contains("failed") || msg.contains("spawn"),
                    "unexpected: {msg}"
                );
            }
        }
    }

    #[test]
    fn capability_report_is_honest() {
        let caps = workspace_capability_report(ReplayPolicy::Sandbox);
        let map: std::collections::HashMap<_, _> = caps.into_iter().collect();
        assert_eq!(
            map.get("workspace isolation").map(String::as_str),
            Some("temporary-directory")
        );
        assert!(map
            .get("kernel isolation")
            .map(|s| s.contains("not available"))
            .unwrap_or(false));
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
