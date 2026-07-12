use crate::analysis::AnalysisPass;
use crate::core::event::{Confidence, EventSource, TraceEvent};

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
    pub fn find_parent(&self, event: &TraceEvent, events: &[TraceEvent]) -> Option<(String, Confidence)> {
        let pos = events.iter().position(|e| e.id == event.id)?;
        if pos == 0 {
            return None;
        }

        // Prefer same-source previous event within a tight window,
        // otherwise any previous event within a wider window.
        let mut best: Option<(String, Confidence, i64)> = None;

        for prev in events[..pos].iter().rev() {
            let gap = event
                .started_at
                .signed_duration_since(prev.started_at)
                .num_milliseconds();

            // Don't look further back than 30s
            if gap > 30_000 {
                break;
            }

            let confidence = if prev.source == event.source && gap < 500 {
                Confidence::Confirmed
            } else if gap < 1000 {
                Confidence::StronglyCorrelated
            } else if gap < 5000 {
                Confidence::WeaklyCorrelated
            } else {
                Confidence::Unknown
            };

            // Cross-layer correlation boost: process → filesystem/git
            let cross_layer = matches!(
                (&prev.source, &event.source),
                (EventSource::Process, EventSource::Filesystem)
                    | (EventSource::Process, EventSource::Git)
                    | (EventSource::Terminal, EventSource::Process)
                    | (EventSource::System, _)
            );

            let confidence = if cross_layer && gap < 2000 {
                match confidence {
                    Confidence::Unknown => Confidence::WeaklyCorrelated,
                    Confidence::WeaklyCorrelated => Confidence::StronglyCorrelated,
                    other => other,
                }
            } else {
                confidence
            };

            if matches!(
                confidence,
                Confidence::Confirmed | Confidence::StronglyCorrelated | Confidence::WeaklyCorrelated
            ) {
                let score = match confidence {
                    Confidence::Confirmed => 3,
                    Confidence::StronglyCorrelated => 2,
                    Confidence::WeaklyCorrelated => 1,
                    Confidence::Unknown => 0,
                };
                let better = best
                    .as_ref()
                    .map(|(_, _, s)| score > *s)
                    .unwrap_or(true);
                if better {
                    best = Some((prev.id.clone(), confidence, score));
                }
                // Confirmed is good enough — stop
                if matches!(confidence, Confidence::Confirmed) {
                    break;
                }
            }
        }

        best.map(|(id, conf, _)| (id, conf))
    }
}

impl Default for EventCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for EventCorrelator {
    fn name(&self) -> &'static str {
        "correlator"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let mut derived = Vec::new();

        for event in events {
            if let Some((parent_id, confidence)) = self.find_parent(event, events) {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "parent_event_id".to_string(),
                    serde_json::Value::String(parent_id.clone()),
                );
                meta.insert(
                    "confidence".to_string(),
                    serde_json::Value::String(format!("{:?}", confidence)),
                );
                meta.insert(
                    "source_event_id".to_string(),
                    serde_json::Value::String(event.id.clone()),
                );
                meta.insert(
                    "source_kind".to_string(),
                    serde_json::Value::String(event.kind.clone()),
                );

                let mut derived_event =
                    TraceEvent::new(&event.run_id, EventSource::System, "analysis.correlation");
                derived_event.parent_event_id = Some(parent_id);
                derived_event.metadata = meta;
                derived.push(derived_event);
            }
        }

        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn find_parent_strong_correlation() {
        let corr = EventCorrelator::new();
        let t0 = Utc::now();
        let mut e1 = TraceEvent::new("run-1", EventSource::Process, "process.spawned");
        e1.started_at = t0;
        let mut e2 = TraceEvent::new("run-1", EventSource::Filesystem, "filesystem.snapshot");
        e2.started_at = t0 + Duration::milliseconds(200);

        let events = vec![e1, e2.clone()];
        let result = corr.find_parent(&e2, &events);
        assert!(result.is_some());
        let (_, conf) = result.unwrap();
        assert!(matches!(
            conf,
            Confidence::Confirmed | Confidence::StronglyCorrelated | Confidence::WeaklyCorrelated
        ));
    }

    #[tokio::test]
    async fn analyze_emits_correlations() {
        let corr = EventCorrelator::new();
        let t0 = Utc::now();
        let mut e1 = TraceEvent::new("run-1", EventSource::System, "environment.captured");
        e1.started_at = t0;
        let mut e2 = TraceEvent::new("run-1", EventSource::Terminal, "pty.started");
        e2.started_at = t0 + Duration::milliseconds(50);
        let mut e3 = TraceEvent::new("run-1", EventSource::Terminal, "terminal.output");
        e3.started_at = t0 + Duration::milliseconds(100);

        let derived = corr.analyze(&[e1, e2, e3]).await.unwrap();
        assert!(!derived.is_empty());
        assert!(derived.iter().all(|e| e.kind == "analysis.correlation"));
    }
}
