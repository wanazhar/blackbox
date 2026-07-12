use crate::core::event::{EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::replay::{events_from, ReplayEngine, ReplayOutcome};

/// Timeline replay — no commands are executed.
///
/// Prints a human-readable chronological timeline of the original run
/// to stdout. Purely observational.
pub struct TimelineReplay;

#[async_trait::async_trait]
impl ReplayEngine for TimelineReplay {
    fn name(&self) -> &'static str {
        "timeline"
    }

    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        let slice = events_from(events, from_event_id);

        println!("═══ Timeline replay ═══");
        println!(
            "Run {}  cmd={:?}  status={:?}",
            &run.id[..8.min(run.id.len())],
            run.command,
            run.status
        );
        println!(
            "{:<6} {:<12} {:<24} {:<10} {}",
            "SEQ", "SOURCE", "KIND", "STATUS", "TIME"
        );
        println!("{}", "─".repeat(80));

        let mut errors = 0u64;
        for event in slice {
            let status = match &event.status {
                EventStatus::Success => "ok",
                EventStatus::Error => {
                    errors += 1;
                    "ERR"
                }
                EventStatus::Running => "run",
                EventStatus::Pending => "pend",
                EventStatus::Cancelled => "canc",
                EventStatus::Unknown => "?",
            };
            println!(
                "{:<6} {:<12} {:<24} {:<10} {}",
                event.sequence,
                format!("{:?}", event.source),
                event.kind,
                status,
                event.started_at.format("%H:%M:%S%.3f"),
            );
            tracing::info!(
                seq = event.sequence,
                kind = %event.kind,
                source = ?event.source,
                "timeline event"
            );
        }

        let summary = format!(
            "{} events ({} errors) from seq {}",
            slice.len(),
            errors,
            slice.first().map(|e| e.sequence).unwrap_or(0)
        );
        println!("─── {} ───", summary);

        Ok(ReplayOutcome::Completed { summary })
    }
}
