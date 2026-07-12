use std::path::{Path, PathBuf};
use std::process::Command;

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
}

impl SandboxReplay {
    pub fn new() -> Self {
        Self {
            policy: ReplayPolicy::Sandbox,
            workspace: None,
            seed_from_cwd: true,
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

    /// Extract a shell command from an event, if any.
    fn extract_command(event: &TraceEvent) -> Option<Vec<String>> {
        // Explicit command array in metadata
        if let Some(arr) = event.metadata.get("command").and_then(|v| v.as_array()) {
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !parts.is_empty() {
                return Some(parts);
            }
        }
        // String command
        if let Some(s) = event.metadata.get("command").and_then(|v| v.as_str()) {
            return Some(shell_split(s));
        }
        // Tool call with Bash/shell
        if event.kind == "tool.call" {
            let name = event
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if matches!(name.as_str(), "bash" | "shell" | "run" | "execute" | "cmd") {
                if let Some(input) = event.metadata.get("input") {
                    if let Some(cmd) = input.get("command").and_then(|c| c.as_str()) {
                        return Some(vec!["sh".into(), "-c".into(), cmd.to_string()]);
                    }
                    if let Some(cmd) = input.get("cmd").and_then(|c| c.as_str()) {
                        return Some(vec!["sh".into(), "-c".into(), cmd.to_string()]);
                    }
                }
            }
        }
        // process.spawned with command string
        if event.source == EventSource::Process {
            if let Some(s) = event.metadata.get("command").and_then(|v| v.as_str()) {
                return Some(shell_split(s));
            }
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

/// Minimal shell-ish split (whitespace; no quote handling beyond simplicity).
fn shell_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
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

        // Create or use workspace
        let workspace = if let Some(ref ws) = self.workspace {
            std::fs::create_dir_all(ws)?;
            ws.clone()
        } else {
            let dir = std::env::temp_dir().join(format!(
                "blackbox-sandbox-{}",
                &run.id[..8.min(run.id.len())]
            ));
            std::fs::create_dir_all(&dir)?;
            dir
        };

        let seed_stats = if self.seed_from_cwd && self.policy != ReplayPolicy::Live {
            match seed_workspace(Path::new(&run.cwd), &workspace) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "sandbox: seed from cwd failed");
                    SeedStats::default()
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
        });
        std::fs::write(
            workspace.join(".blackbox-sandbox-context.json"),
            serde_json::to_string_pretty(&context)?,
        )?;

        println!("═══ Sandbox replay ═══");
        println!("workspace: {}", workspace.display());
        println!("policy:    {:?}", self.policy);
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
            let cmd = match Self::extract_command(event) {
                Some(c) => c,
                None => continue,
            };

            // Re-classify shell tools as Unknown → treat as blocked unless policy Live
            let side = if event.side_effect == SideEffect::Unknown
                && event.kind == "tool.call"
            {
                // Bash is unknown — only allow under Live
                SideEffect::Unknown
            } else {
                event.side_effect.clone()
            };

            // For sandbox policy, allow Unknown shell only if it's a clearly read-only command
            let allowed = if self.is_allowed(&side) {
                true
            } else if self.policy == ReplayPolicy::Sandbox
                && side == SideEffect::Unknown
                && is_readonly_command(&cmd)
            {
                true
            } else {
                false
            };

            if !allowed {
                println!(
                    "skip  seq={} kind={} cmd={:?} side={:?}",
                    event.sequence, event.kind, cmd, event.side_effect
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
            tracing::info!(
                seq = event.sequence,
                exit = code,
                "sandbox: executed event"
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

fn is_readonly_command(cmd: &[String]) -> bool {
    let joined = cmd.join(" ").to_lowercase();
    let first = cmd.first().map(|s| s.as_str()).unwrap_or("");
    matches!(
        first,
        "ls" | "cat" | "head" | "tail" | "pwd" | "echo" | "true" | "false" | "which" | "env"
            | "printenv" | "wc" | "grep" | "rg" | "find" | "stat" | "file" | "sh"
    ) && !joined.contains("rm ")
        && !joined.contains(">")
        && !joined.contains("curl")
        && !joined.contains("wget")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
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
        ev.metadata.insert(
            "command".into(),
            serde_json::json!(["echo", "sandbox-ok"]),
        );

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

        let run = Run::new(vec!["cat".into(), "hello.txt".into()], src.to_string_lossy().into());
        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.command");
        ev.side_effect = SideEffect::Read;
        ev.metadata.insert(
            "command".into(),
            serde_json::json!(["cat", "hello.txt"]),
        );

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
}
