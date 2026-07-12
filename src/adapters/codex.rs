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
        command.first().map_or(false, |c| {
            c.ends_with("codex") || c == "codex"
        })
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
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
            if let Some(raw) = ev.metadata.get("normalized").and_then(|v| v.as_str()) {
                if let Some(sid) = crate::adapters::parse::extract_session_id(raw) {
                    return Some(sid);
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
        let path = std::path::Path::new(&context.project_dir)
            .join(".codex")
            .join("logs");
        if path.exists() {
            vec![path.to_string_lossy().to_string()]
        } else {
            Vec::new()
        }
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
}
