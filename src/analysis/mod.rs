pub mod classifier;
pub mod correlator;
pub mod error_detector;

use crate::core::event::TraceEvent;

/// An analysis pass over recorded events.
///
/// Each pass reads a batch of events and optionally emits
/// derived events or enriches existing ones.
#[async_trait::async_trait]
pub trait AnalysisPass: Send + 'static {
    fn name(&self) -> &'static str;

    /// Analyze a batch of events and return any derived events.
    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>>;
}
