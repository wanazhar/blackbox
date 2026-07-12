use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::event::{EventSource, SideEffect, TraceEvent};
use crate::core::run::Run;
use crate::replay::{events_from, ReplayEngine, ReplayOutcome, ReplayPolicy};

/// Sandbox replay — re-execute allowed events inside a temporary workspace.
///
/// External and destructive side effects are blocked under the default
/// `ReplayPolicy::Sandbox`. Read and local-write process/tool commands
/// may run in the isolated directory.
pub struct SandboxReplay {
    policy: ReplayPolicy,
    /// Optional override workspace (defaults to a fresh temp dir)
    workspace: Option<PathBuf>,
}

impl SandboxReplay {
    pub fn new() -> Self {
        Self {
            policy: ReplayPolicy::Sandbox,
            workspace: None,
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

        // Seed workspace with a small context file from the original run
        let context = serde_json::json!({
            "source_run_id": run.id,
            "command": run.command,
            "original_cwd": run.cwd,
            "policy": format!("{:?}", self.policy),
            "event_count": slice.len(),
        });
        std::fs::write(
            workspace.join(".blackbox-sandbox-context.json"),
            serde_json::to_string_pretty(&context)?,
        )?;

        println!("═══ Sandbox replay ═══");
        println!("workspace: {}", workspace.display());
        println!("policy:    {:?}", self.policy);
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
        let mut engine = SandboxReplay::new().with_workspace(ws.clone());
        let outcome = engine.start(&run, &[ev], None).await.unwrap();
        match outcome {
            ReplayOutcome::Sandboxed { executed, .. } => assert_eq!(executed, 1),
            other => panic!("unexpected {:?}", other),
        }
        assert!(ws.join(".blackbox-sandbox-context.json").exists());
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
        let mut engine = SandboxReplay::new().with_workspace(ws.clone());
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
