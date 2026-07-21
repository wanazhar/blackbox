pub mod anomalies;
pub mod causal;
/// Classifier module.
pub mod classifier;
/// Correlator module.
pub mod correlator;
/// Error detector module.
pub mod error_detector;
pub mod failure_fix;
pub mod ordering;
pub mod retry_waste;
pub mod turning_points;

pub use anomalies::{detect_anomalies, Anomaly};
pub use ordering::{occurrence_timeline, OrderingSummary};

use crate::core::event::TraceEvent;

/// An analysis pass over recorded events.
///
/// Each pass reads a batch of events and optionally emits
/// derived events or enriches existing ones.
#[async_trait::async_trait]
pub trait AnalysisPass: Send + 'static {
    /// Return the name.
    fn name(&self) -> &'static str;

    /// Analyze a batch of events and return any derived events.
    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>>;
}
