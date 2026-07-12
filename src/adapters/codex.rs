use crate::adapters::harness::HarnessAdapter;
use crate::adapters::parse::{parse_codex_json_line, parse_plaintext};
use crate::adapters::{LaunchContext, PreparedLaunch, RunContext};
use crate::core::event::TraceEvent;

/// Adapter for Codex CLI agent harness.
///
/// Detects: `codex`, `codex ...`
///
/// Capabilities:
/// - stream-json / function_call parsing
/// - Session identification from output
/// - Transcript log location
/// - Resume command construction
pub struct CodexAdapter;

impl CodexAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn detect(&self, command: &[String]) -> bool {
        command.first().is_some_and(|c| {
            c.ends_with("codex") || c == "codex"
        })
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        let prepared = crate::adapters::launch::prepare_codex_command(command);
        if prepared != command {
            tracing::info!(
                original = ?command,
                prepared = ?prepared,
                "codex adapter: injected machine-readable flags"
            );
        }
        Some(PreparedLaunch {
            command: prepared,
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        let text = String::from_utf8_lossy(chunk);
        let mut events = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('{') {
                events.extend(parse_codex_json_line(run_id, line));
            } else {
                events.extend(parse_plaintext(run_id, line, "codex"));
            }
        }

        if !text.contains('\n') && !text.trim().starts_with('{') {
            events.extend(parse_plaintext(run_id, &text, "codex"));
        }

        events
    }

    fn discover_session_id(&self, events: &[TraceEvent]) -> Option<String> {
        for ev in events.iter().rev() {
            if ev.kind == "harness.session" {
                if let Some(sid) = ev
                    .metadata
                    .get("session_id")
                    .and_then(|v| v.as_str())
                {
                    return Some(sid.to_string());
                }
            }
            for key in ["preview", "normalized", "raw"] {
                if let Some(text) = ev.metadata.get(key).and_then(|v| v.as_str()) {
                    if let Some(sid) = crate::adapters::parse::extract_session_id(text) {
                        return Some(sid);
                    }
                }
            }
        }
        None
    }

    fn build_resume_command(&self, session_id: &str) -> Option<Vec<String>> {
        // Codex resume flag naming varies by version; use common form
        Some(vec![
            "codex".to_string(),
            "resume".to_string(),
            session_id.to_string(),
        ])
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("codex", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_codex() {
        let a = CodexAdapter::new();
        assert!(a.detect(&["codex".into(), "exec".into()]));
        assert!(!a.detect(&["claude".into()]));
    }

    #[test]
    fn parse_function_call() {
        let a = CodexAdapter::new();
        let chunk = br#"{"type":"function_call","name":"shell","arguments":{"cmd":"pwd"}}
"#;
        let events = a.parse_output("run-y", chunk);
        assert!(events.iter().any(|e| e.kind == "tool.call"));
    }

    #[test]
    fn resume_command() {
        let a = CodexAdapter::new();
        let cmd = a.build_resume_command("thread-1").unwrap();
        assert_eq!(cmd[0], "codex");
        assert!(cmd.contains(&"thread-1".to_string()));
    }

    #[test]
    fn prepare_exec_injects_json() {
        let a = CodexAdapter::new();
        let ctx = LaunchContext {
            project_dir: "/tmp".into(),
            environment: Default::default(),
            run_id: "r1".into(),
        };
        let prepared = a
            .prepare_launch(&["codex".into(), "exec".into(), "hi".into()], &ctx)
            .unwrap();
        assert!(prepared.command.iter().any(|c| c == "--json"));
    }
}
