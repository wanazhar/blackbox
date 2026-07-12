//! Sticky project state written after each run (daily-driver handoff).
//!
//! Path: `<project>/.blackbox/state.json`
//! Agents and humans discover the last outcome without scanning the DB first.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::run::{Run, RunStatus};
use crate::util::short_id;

/// Schema id for on-disk state.
pub const STATE_SCHEMA: &str = "blackbox.state/v1";

/// Compact pointer to a finished run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunPointer {
    pub id: String,
    pub short_id: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub name: Option<String>,
    pub command_preview: String,
    pub ended_at: Option<DateTime<Utc>>,
    pub adapter: Option<String>,
}

impl RunPointer {
    pub fn from_run(run: &Run) -> Self {
        let preview = if run.command.len() <= 4 {
            run.command.join(" ")
        } else {
            format!(
                "{} … ({} args)",
                run.command[..3].join(" "),
                run.command.len()
            )
        };
        Self {
            id: run.id.clone(),
            short_id: short_id(&run.id).to_string(),
            status: status_str(&run.status).to_string(),
            exit_code: run.exit_code,
            name: run.name.clone(),
            command_preview: preview,
            ended_at: run.ended_at,
            adapter: run.adapter.clone(),
        }
    }
}

/// Project sticky state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectState {
    pub schema: String,
    pub updated_at: DateTime<Utc>,
    pub last_run: Option<RunPointer>,
    /// Last non-success terminal status (Failed / Cancelled).
    pub last_failure: Option<RunPointer>,
    /// True when the latest completed run needs human/agent attention.
    pub attention_needed: bool,
    pub attention_reason: Option<String>,
}

impl Default for ProjectState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA.into(),
            updated_at: Utc::now(),
            last_run: None,
            last_failure: None,
            attention_needed: false,
            attention_reason: None,
        }
    }
}

impl ProjectState {
    pub fn path(root: &Path) -> PathBuf {
        root.join("state.json")
    }

    pub fn load(root: &Path) -> anyhow::Result<Option<Self>> {
        let p = Self::path(root);
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p)?;
        let state: ProjectState = serde_json::from_str(&text)?;
        Ok(Some(state))
    }

    pub fn save(&self, root: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(root)?;
        let p = Self::path(root);
        let tmp = root.join("state.json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// Merge a finished run into sticky state.
    pub fn record_run(&mut self, run: &Run) {
        let ptr = RunPointer::from_run(run);
        self.updated_at = Utc::now();
        self.last_run = Some(ptr.clone());

        match run.status {
            RunStatus::Failed | RunStatus::Cancelled => {
                self.last_failure = Some(ptr);
                self.attention_needed = true;
                self.attention_reason = Some(match run.status {
                    RunStatus::Failed => format!(
                        "last run {} failed (exit {:?})",
                        short_id(&run.id),
                        run.exit_code
                    ),
                    RunStatus::Cancelled => {
                        format!("last run {} was cancelled", short_id(&run.id))
                    }
                    _ => unreachable!(),
                });
            }
            RunStatus::Succeeded => {
                // Clear attention only when the *latest* run succeeded.
                self.attention_needed = false;
                self.attention_reason = None;
            }
            RunStatus::Running | RunStatus::Pending | RunStatus::Unknown => {
                // Leave attention as-is for incomplete/unknown.
            }
        }
    }
}

fn status_str(s: &RunStatus) -> &'static str {
    match s {
        RunStatus::Pending => "pending",
        RunStatus::Running => "running",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Unknown => "unknown",
    }
}

/// Agent-facing instructions written beside the store on `enable`.
pub fn agent_instructions_markdown() -> &'static str {
    r#"# blackbox — agent instructions

This project has **blackbox** ambient capture enabled (local flight recorder for agent runs).

## At session start

Prefer MCP tools if available: `blackbox_handoff` then work.
Otherwise:

```bash
blackbox handoff --json
# lightweight: blackbox status --json
```

If `attention.needed` is true, use the embedded `resume_pack` (or run):

```bash
blackbox context <run_id> --for-resume --json --max-tokens 4000
```

## While working

- Prefer harnesses in the project wrap list (`claude`, `codex`, `aider`, `cursor-agent`, `gemini`, `opencode`, `grok`, …) so shell wrappers record via `blackbox maybe-run`.
- Explicit: `blackbox run --name "…" -- <command>`.
- Auto-resume is on by default: a new run after a failure injects prior context (`BLACKBOX_RESUME_FILE`, `.blackbox/RESUME.md`). Disable with `BLACKBOX_AUTO_RESUME=0` or `--no-auto-resume`.
- Opt out of capture for one shell: `export BLACKBOX_OFF=1`.

## After a failure

```bash
blackbox postmortem latest --json
blackbox handoff --json
blackbox search "error" --json
```

## MCP

```bash
blackbox mcp   # stdio JSON-RPC tools: status, handoff, postmortem, context, runs, search, doctor
```

## Rules

- Secrets are redacted before write by default. Do not pass `--insecure-raw` / `--no-redact` unless the user explicitly requests it.
- Export/sync are redacted by default; never share unredacted traces without user consent.
- Store lives at `.blackbox/` (gitignored). Do not commit `*.db` or blob payloads.

## Machine contract

See `docs/agent-api.md` for the `blackbox.cli/v1` JSON envelope, MCP tools, and resume pack schema.
"#
}

/// Write agent instructions into `.blackbox/AGENT.md`.
pub fn write_agent_instructions(root: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    let path = root.join("AGENT.md");
    std::fs::write(&path, agent_instructions_markdown())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;

    #[test]
    fn record_failure_sets_attention() {
        let mut state = ProjectState::default();
        let mut run = Run::new(
            vec!["claude".into(), "-p".into(), "x".into()],
            "/tmp".into(),
        );
        run.status = RunStatus::Failed;
        run.exit_code = Some(1);
        run.ended_at = Some(Utc::now());
        state.record_run(&run);
        assert!(state.attention_needed);
        assert!(state.last_failure.is_some());
        assert_eq!(state.last_run.as_ref().unwrap().id, run.id);
    }

    #[test]
    fn success_clears_attention() {
        let mut state = ProjectState::default();
        let mut bad = Run::new(vec!["x".into()], "/tmp".into());
        bad.status = RunStatus::Failed;
        bad.exit_code = Some(2);
        state.record_run(&bad);
        assert!(state.attention_needed);

        let mut good = Run::new(vec!["y".into()], "/tmp".into());
        good.status = RunStatus::Succeeded;
        good.exit_code = Some(0);
        state.record_run(&good);
        assert!(!state.attention_needed);
        assert!(state.last_failure.is_some()); // historical failure kept
        assert_eq!(state.last_run.as_ref().unwrap().id, good.id);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(".blackbox");
        let mut state = ProjectState::default();
        let mut run = Run::new(vec!["echo".into()], "/tmp".into());
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        state.record_run(&run);
        state.save(&root).unwrap();
        let loaded = ProjectState::load(&root).unwrap().unwrap();
        assert_eq!(loaded.last_run.unwrap().id, run.id);
    }
}
