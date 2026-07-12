use crate::core::event::{SideEffect, TraceEvent};
use crate::core::run::Run;
use crate::replay::{ReplayEngine, ReplayOutcome, ReplayPolicy};

/// Sandbox replay — repository checkpoint restored inside a
/// temporary workspace.
///
/// The filesystem state at the checkpoint is recreated in an
/// isolated directory. Commands may run again, but external
/// side effects are blocked or require approval.
#[allow(dead_code)]
pub struct SandboxReplay {
    policy: ReplayPolicy,
}

impl SandboxReplay {
    pub fn new() -> Self {
        Self {
            policy: ReplayPolicy::Sandbox,
        }
    }

    /// Returns true if the event's side effect is permitted under the current policy.
    fn is_allowed(&self, side_effect: &SideEffect) -> bool {
        match self.policy {
            ReplayPolicy::ReadOnly => matches!(side_effect, SideEffect::None | SideEffect::Read),
            ReplayPolicy::Sandbox => matches!(
                side_effect,
                SideEffect::None | SideEffect::Read | SideEffect::LocalWrite
            ),
            ReplayPolicy::Live => true,
        }
    }
}

#[async_trait::async_trait]
impl ReplayEngine for SandboxReplay {
    fn name(&self) -> &'static str {
        "sandbox"
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

        let remaining = &events[start_idx..];
        tracing::info!(
            policy = ?self.policy,
            total_events = remaining.len(),
            "sandbox: beginning filtered replay"
        );

        let mut executed = 0u64;
        let mut skipped = 0u64;

        for event in remaining {
            if self.is_allowed(&event.side_effect) {
                tracing::info!(
                    seq = event.sequence,
                    kind = %event.kind,
                    source = ?event.source,
                    side_effect = ?event.side_effect,
                    "sandbox: executing event"
                );
                executed += 1;
            } else {
                tracing::warn!(
                    seq = event.sequence,
                    kind = %event.kind,
                    source = ?event.source,
                    side_effect = ?event.side_effect,
                    "sandbox: skipping event (side effect blocked by policy)"
                );
                skipped += 1;
            }
        }

        tracing::info!(
            executed,
            skipped,
            "sandbox replay complete"
        );

        Ok(ReplayOutcome::Completed)
    }
}
