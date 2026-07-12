//! Resume / relaunch helpers for forked and completed runs.

use crate::adapters::claude::ClaudeAdapter;
use crate::adapters::codex::CodexAdapter;
use crate::adapters::harness::HarnessAdapter;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Resolve harness adapter id from run notes (`adapter:claude`, etc.).
pub fn adapter_id_from_run(run: &Run) -> Option<&str> {
    let notes = run.notes.as_deref()?;
    for part in notes.split(';') {
        let part = part.trim();
        if let Some(id) = part.strip_prefix("adapter:") {
            return Some(id);
        }
    }
    None
}

/// Session id from notes (`session:…`) or checkpoints / events.
pub fn discover_session(
    run: &Run,
    events: &[TraceEvent],
    checkpoints: &[Checkpoint],
) -> Option<String> {
    if let Some(notes) = &run.notes {
        for part in notes.split(';') {
            let part = part.trim();
            if let Some(sid) = part.strip_prefix("session:") {
                if !sid.is_empty() {
                    return Some(sid.to_string());
                }
            }
        }
    }
    for cp in checkpoints.iter().rev() {
        if let Some(ref sid) = cp.harness_session_id {
            if !sid.is_empty() {
                return Some(sid.clone());
            }
        }
    }
    // Adapter-specific parse of events
    let adapter: Box<dyn HarnessAdapter> = match adapter_id_from_run(run) {
        Some("claude") => Box::new(ClaudeAdapter::new()),
        Some("codex") => Box::new(CodexAdapter::new()),
        _ => {
            // Try both
            let claude = ClaudeAdapter::new();
            if let Some(s) = claude.discover_session_id(events) {
                return Some(s);
            }
            let codex = CodexAdapter::new();
            return codex.discover_session_id(events);
        }
    };
    adapter.discover_session_id(events)
}

/// Build a resume command if we know the harness + session.
pub fn resume_command(
    run: &Run,
    events: &[TraceEvent],
    checkpoints: &[Checkpoint],
) -> Option<Vec<String>> {
    let session = discover_session(run, events, checkpoints)?;
    match adapter_id_from_run(run) {
        Some("claude") => ClaudeAdapter::new().build_resume_command(&session),
        Some("codex") => CodexAdapter::new().build_resume_command(&session),
        _ => {
            // Heuristic from parent command
            if run
                .command
                .first()
                .map(|c| c.contains("claude"))
                .unwrap_or(false)
            {
                ClaudeAdapter::new().build_resume_command(&session)
            } else if run
                .command
                .first()
                .map(|c| c.contains("codex"))
                .unwrap_or(false)
            {
                CodexAdapter::new().build_resume_command(&session)
            } else {
                None
            }
        }
    }
}

/// Pretty-print a resume command line.
pub fn format_command(cmd: &[String]) -> String {
    cmd.iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{}\"", a)
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;

    #[test]
    fn adapter_from_notes() {
        let mut run = Run::new(vec!["claude".into()], "/tmp".into());
        run.notes = Some("adapter:claude; session:sess-1".into());
        assert_eq!(adapter_id_from_run(&run), Some("claude"));
        let cps: Vec<Checkpoint> = vec![];
        let cmd = resume_command(&run, &[], &cps).unwrap();
        assert_eq!(cmd, vec!["claude", "--resume", "sess-1"]);
    }
}
