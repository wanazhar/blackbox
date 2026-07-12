use crate::analysis::AnalysisPass;
use crate::core::event::{Confidence, TraceEvent};

/// Correlates events across capture layers to establish causality.
///
/// A file modification shortly after a command is "strongly correlated"
/// but not necessarily confirmed. This pass assigns confidence levels
/// so the UI can show likely causal chains.
pub struct EventCorrelator;

impl EventCorrelator {
    pub fn new() -> Self {
        Self
    }

    /// Attempt to find the parent event for a given event.
    ///
    /// Uses temporal proximity, process ancestry, and known
    /// side-effect patterns to estimate causal relationships.
    pub fn find_parent(&self, event: &TraceEvent, events: &[TraceEvent]) -> Option<Confidence> {
        let pos = events.iter().position(|e| e.id == event.id)?;
        if pos == 0 {
            return None;
        }
        let prev = &events[pos - 1];
        let gap = event
            .started_at
            .signed_duration_since(prev.started_at)
            .num_milliseconds();

        if gap < 1000 {
            Some(Confidence::StronglyCorrelated)
        } else if gap < 5000 {
            Some(Confidence::WeaklyCorrelated)
        } else {
            Some(Confidence::Unknown)
        }
    }
}

#[async_trait::async_trait]
impl AnalysisPass for EventCorrelator {
    fn name(&self) -> &'static str {
        "correlator"
    }

    async fn analyze(&self, _events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        Ok(Vec::new())
    }
}
