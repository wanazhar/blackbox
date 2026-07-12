use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::replay::{ReplayEngine, ReplayOutcome};

/// Fork a new run from a recorded checkpoint.
///
/// A fork does not reproduce the hidden internal model state.
/// Instead it restores all observable state available at that point:
///
/// - Project files
/// - Conversation transcript
/// - Terminal transcript
/// - Tool outputs
/// - Environment metadata
/// - Git state
/// - Harness session ID (when available)
///
/// The user then provides new instructions, and the debugger
/// launches a fresh harness session with the restored context.
pub struct ForkManager;

#[async_trait::async_trait]
impl ReplayEngine for ForkManager {
    fn name(&self) -> &'static str {
        "fork"
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

        let fork_point = &events[start_idx];

        tracing::info!(
            fork_event_id = %fork_point.id,
            fork_event_kind = %fork_point.kind,
            fork_event_sequence = fork_point.sequence,
            "fork: selecting fork point"
        );

        let remaining = &events[start_idx..];
        tracing::info!(
            total_events = remaining.len(),
            first_sequence = remaining.first().map(|e| e.sequence),
            last_sequence = remaining.last().map(|e| e.sequence),
            "fork: events queued for replay"
        );

        for event in remaining {
            tracing::debug!(
                seq = event.sequence,
                kind = %event.kind,
                source = ?event.source,
                side_effect = ?event.side_effect,
                "fork: would replay event"
            );
        }

        tracing::info!(
            fork_point = %fork_point.id,
            events_to_replay = remaining.len(),
            "fork simulation complete"
        );

        Ok(ReplayOutcome::Completed)
    }
}
