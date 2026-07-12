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
        _events: &[TraceEvent],
        _from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        anyhow::bail!("fork not yet implemented")
    }
}
