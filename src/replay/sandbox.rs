use crate::core::event::TraceEvent;
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
}

#[async_trait::async_trait]
impl ReplayEngine for SandboxReplay {
    fn name(&self) -> &'static str {
        "sandbox"
    }

    async fn start(
        &mut self,
        _run: &Run,
        _events: &[TraceEvent],
        _from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        anyhow::bail!("sandbox replay not yet implemented")
    }
}
