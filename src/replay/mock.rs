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

        for event in &tool_events {
            tracing::info!(
                tool = ?event.metadata.get("tool_name"),
                "mock tool call"
            );
        }
        Ok(ReplayOutcome::Completed)
    }
}
