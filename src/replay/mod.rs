pub mod timeline;
pub mod mock;
pub mod sandbox;
pub mod fork;

use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Outcome of a replay operation.
#[derive(Debug)]
pub enum ReplayOutcome {
    Completed,
    Cancelled,
    Errored(String),
}

/// Replay policy for side effects during replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPolicy {
    /// Allow read-only operations only
    ReadOnly,
    /// Allow local writes in a sandbox
    Sandbox,
    /// Allow all operations (dangerous)
    Live,
}

/// A replay engine processes recorded events to recreate or
/// simulate a previous run.
#[async_trait::async_trait]
pub trait ReplayEngine: Send + 'static {
    fn name(&self) -> &'static str;

    /// Begin replaying a run from an optional starting event.
    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome>;
}
