use crate::adapters::harness::HarnessAdapter;
use crate::adapters::parse::{parse_claude_json_line, parse_plaintext};
use crate::adapters::{LaunchContext, PreparedLaunch, RunContext};
use crate::core::event::TraceEvent;

/// Adapter for Claude Code CLI agent harness.
///
/// Detects: `claude`, `claude ...`
///
/// Capabilities:
/// - stream-json / NDJSON tool_use & assistant parsing
/// - Session identification from output
/// - Transcript log location
/// - Resume command construction
pub struct ClaudeAdapter;

impl ClaudeAdapter {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClaudeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn detect(&self, command: &[String]) -> bool {
        command.first().is_some_and(|c| {
            std::path::Path::new(c)
                .file_name()
                .is_some_and(|n| n == "claude")
        })
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        let prepared = crate::adapters::launch::prepare_claude_command(command);
        if prepared != command {
            tracing::info!(
                original = ?command,
                prepared = ?prepared,
                "claude adapter: injected machine-readable flags"
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

        // Prefer line-oriented NDJSON
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('{') {
                events.extend(parse_claude_json_line(run_id, line));
            } else {
                events.extend(parse_plaintext(run_id, line, "claude"));
            }
        }

        events
    }

    fn discover_session_id(&self, events: &[TraceEvent]) -> Option<String> {
        for ev in events.iter().rev() {
            if ev.kind == "harness.session" {
                if let Some(sid) = ev.metadata.get("session_id").and_then(|v| v.as_str()) {
                    return Some(sid.to_string());
                }
            }
            // Fallback: search terminal previews / legacy text
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
        Some(vec![
            "claude".to_string(),
            "--resume".to_string(),
            session_id.to_string(),
        ])
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("claude", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_claude() {
        let a = ClaudeAdapter::new();
        assert!(a.detect(&["claude".into(), "-p".into(), "hi".into()]));
        assert!(!a.detect(&["codex".into()]));
    }

    #[test]
    fn parse_stream_json_tool() {
        let a = ClaudeAdapter::new();
        let chunk = br#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}
"#;
        let events = a.parse_output("run-x", chunk);
        assert!(events.iter().any(|e| e.kind == "tool.call"));
        assert_eq!(
            events
                .iter()
                .find(|e| e.kind == "tool.call")
                .unwrap()
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str()),
            Some("Bash")
        );
    }

    #[test]
    fn resume_command() {
        let a = ClaudeAdapter::new();
        let cmd = a.build_resume_command("sess-99").unwrap();
        assert_eq!(cmd, vec!["claude", "--resume", "sess-99"]);
    }

    #[test]
    fn prepare_print_injects_stream_json() {
        let a = ClaudeAdapter::new();
        let ctx = LaunchContext {
            project_dir: "/tmp".into(),
            environment: Default::default(),
            run_id: "r1".into(),
        };
        let prepared = a
            .prepare_launch(&["claude".into(), "-p".into(), "hi".into()], &ctx)
            .unwrap();
        assert!(prepared.command.iter().any(|c| c == "stream-json"));
    }

    #[test]
    fn discover_session() {
        let a = ClaudeAdapter::new();
        let events = a.parse_output(
            "run-x",
            br#"{"session_id":"sess-abcdef01","type":"system"}"#,
        );
        let sid = a.discover_session_id(&events);
        assert_eq!(sid.as_deref(), Some("sess-abcdef01"));
    }
}
