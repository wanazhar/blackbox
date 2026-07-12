use crate::adapters::harness::HarnessAdapter;
use crate::adapters::parse::{parse_claude_json_line, parse_plaintext};
use crate::adapters::{LaunchContext, PreparedLaunch};
use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};

/// Generic adapter for unrecognized commands and shell scripts.
///
/// Fallback that still understands common stream-json / NDJSON harness
/// lines (so piping agent output through `cat`/logs still yields tool
/// events), plus error banners and free-text tool mentions.
pub struct GenericAdapter;

impl GenericAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenericAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for GenericAdapter {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn detect(&self, _command: &[String]) -> bool {
        true
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
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // NDJSON / stream-json — reuse Claude-shaped parser
            if trimmed.starts_with('{') {
                let mut parsed = parse_claude_json_line(run_id, trimmed);
                for ev in &mut parsed {
                    if ev.kind == "harness.session" {
                        ev.metadata
                            .insert("harness".to_string(), serde_json::json!("generic"));
                    }
                }
                events.extend(parsed);
                continue;
            }

            events.extend(parse_plaintext(run_id, trimmed, "generic"));

            // Surface common error banners as structured events
            if trimmed.starts_with("error:")
                || trimmed.starts_with("Error:")
                || trimmed.starts_with("ERROR:")
                || trimmed.starts_with("fatal:")
                || trimmed.contains("Traceback (most recent call last)")
            {
                let mut ev = TraceEvent::new(run_id, EventSource::System, "process.error_banner");
                ev.status = EventStatus::Error;
                ev.side_effect = SideEffect::None;
                let preview = if trimmed.len() > 300 {
                    let end = trimmed.floor_char_boundary(300);
                    format!("{}...", &trimmed[..end])
                } else {
                    trimmed.to_string()
                };
                ev.metadata
                    .insert("message".to_string(), serde_json::json!(preview));
                events.push(ev);
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_error_banner() {
        let a = GenericAdapter::new();
        let events = a.parse_output("run-z", b"error: something broke\n");
        assert!(events.iter().any(|e| e.kind == "process.error_banner"));
    }

    #[test]
    fn parses_ndjson_tool_use() {
        let a = GenericAdapter::new();
        let chunk = br#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"x"}}]}}
"#;
        let events = a.parse_output("run-z", chunk);
        assert!(events.iter().any(|e| e.kind == "tool.call"));
    }
}
