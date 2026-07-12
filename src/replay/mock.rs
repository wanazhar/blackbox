use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use crate::replay::{ReplayEngine, ReplayOutcome};

/// Mock replay — known tool calls return their recorded outputs.
///
/// Original: `read_file("src/auth.ts")`
/// Mock: return the recorded contents from that event
///
/// The current filesystem remains unchanged.
/// This works best for structured tool calls.
pub struct MockReplay;

#[async_trait::async_trait]
impl ReplayEngine for MockReplay {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn start(
        &mut self,
        _run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        let start_idx = from_event_id
            .and_then(|id| events.iter().position(|e| e.id == id))
            .unwrap_or(0);

        let tool_events: Vec<&TraceEvent> = events[start_idx..]
            .iter()
            .filter(|e| e.source == EventSource::Tool)
            .collect();

        tracing::info!(
            total_tool_events = tool_events.len(),
            "mock: replaying tool events with recorded outputs"
        );

        for event in &tool_events {
            let tool_name = event
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let output_preview = event
                .output_blob
                .as_deref()
                .unwrap_or("(no output recorded)");

            let input_summary = event
                .metadata
                .get("input")
                .map(|v| v.to_string())
                .or_else(|| event.metadata.get("args").map(|v| v.to_string()))
                .unwrap_or_else(|| "(no input recorded)".to_string());

            tracing::info!(
                seq = event.sequence,
                tool = tool_name,
                input = %input_summary,
                output = output_preview,
                "mock: tool call replayed"
            );
        }

        tracing::info!(
            mocked = tool_events.len(),
            "mock replay complete"
        );

        Ok(ReplayOutcome::Completed)
    }
}
