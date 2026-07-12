use crate::core::event::{EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::replay::{ReplayEngine, ReplayOutcome};

/// Timeline replay — no commands are executed.
///
/// The user watches the original run unfold from recorded events.
/// This is purely a visualization mode: events are displayed in
/// chronological order with their original timing.
pub struct TimelineReplay;

#[async_trait::async_trait]
impl ReplayEngine for TimelineReplay {
    fn name(&self) -> &'static str {
        "timeline"
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

        for event in &events[start_idx..] {
            tracing::info!(
                seq = event.sequence,
                kind = %event.kind,
                source = ?event.source,
                "timeline event"
            );
            if event.status == EventStatus::Error {
                tracing::warn!("event errored: {}", event.id);
            }
        }
        Ok(ReplayOutcome::Completed)
    }
}
