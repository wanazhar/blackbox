//! Analysis helpers that distinguish storage order from occurrence order (1.5 O1).

use serde::Serialize;

use crate::core::event::TraceEvent;
use crate::core::timing::{
    order_views, relate_occurrence, sort_by_occurrence, OrderView, OrderingRelation,
};

/// Pairwise occurrence relation for JSON/UI.
#[derive(Debug, Clone, Serialize)]
pub struct OrderingEdge {
    pub earlier_id: String,
    pub later_id: String,
    pub relation: String,
    pub storage_sequence_earlier: u64,
    pub storage_sequence_later: u64,
    /// True when storage sequence order disagrees with occurrence order.
    pub storage_order_differs: bool,
}

/// Summary for timeline/postmortem consumers.
#[derive(Debug, Clone, Serialize)]
pub struct OrderingSummary {
    pub events: Vec<OrderView>,
    /// Events sorted by inferred occurrence (storage sequence unchanged on originals).
    pub occurrence_order_ids: Vec<String>,
    pub storage_vs_occurrence_disagreements: usize,
    pub sample_edges: Vec<OrderingEdge>,
}

/// Build an occurrence-oriented timeline view without rewriting storage sequences.
pub fn occurrence_timeline(events: &[TraceEvent]) -> OrderingSummary {
    let views = order_views(events);
    let mut by_occurrence: Vec<&TraceEvent> = events.iter().collect();
    by_occurrence.sort_by_key(|e| crate::core::timing::occurrence_sort_key(e));
    let occurrence_order_ids: Vec<String> = by_occurrence.iter().map(|e| e.id.clone()).collect();

    let mut disagreements = 0usize;
    let mut sample_edges = Vec::new();

    // Sample adjacent pairs in occurrence order for disagreements with storage.
    for w in by_occurrence.windows(2) {
        let a = w[0];
        let b = w[1];
        let rel = relate_occurrence(a, b);
        let storage_differs = match rel {
            OrderingRelation::Before => a.sequence > b.sequence,
            OrderingRelation::After => a.sequence < b.sequence,
            _ => false,
        };
        if storage_differs {
            disagreements += 1;
        }
        if sample_edges.len() < 20
            && (storage_differs || matches!(rel, OrderingRelation::ConcurrentOrUncertain))
        {
            let (earlier, later, relation) = match rel {
                OrderingRelation::After => (b, a, OrderingRelation::Before),
                other => (a, b, other),
            };
            sample_edges.push(OrderingEdge {
                earlier_id: earlier.id.clone(),
                later_id: later.id.clone(),
                relation: relation.as_str().to_string(),
                storage_sequence_earlier: earlier.sequence,
                storage_sequence_later: later.sequence,
                storage_order_differs: storage_differs,
            });
        }
    }

    OrderingSummary {
        events: views,
        occurrence_order_ids,
        storage_vs_occurrence_disagreements: disagreements,
        sample_edges,
    }
}

/// Sort owned events by occurrence for analysis passes that need occurrence order.
pub fn events_in_occurrence_order(events: &[TraceEvent]) -> Vec<TraceEvent> {
    let mut v = events.to_vec();
    sort_by_occurrence(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};
    use crate::core::timing::{ClockSource, EventTiming};
    use chrono::{Duration, Utc};

    #[test]
    fn summary_flags_storage_disagreement() {
        let t0 = Utc::now();
        let mut early = TraceEvent::new("r", EventSource::Filesystem, "fs.modified");
        early.sequence = 5;
        early.started_at = t0;
        early.set_timing(&EventTiming {
            occurred_at_wall: Some(t0),
            clock_source: ClockSource::OsEvent,
            ..Default::default()
        });

        let mut late = TraceEvent::new("r", EventSource::Terminal, "terminal.output");
        late.sequence = 1; // ingested first
        late.started_at = t0 + Duration::milliseconds(200);
        late.set_timing(&EventTiming {
            occurred_at_wall: Some(late.started_at),
            clock_source: ClockSource::CaptureWall,
            ..Default::default()
        });

        let s = occurrence_timeline(&[late.clone(), early.clone()]);
        assert!(s.storage_vs_occurrence_disagreements >= 1);
        assert_eq!(s.occurrence_order_ids[0], early.id);
        assert_eq!(s.occurrence_order_ids[1], late.id);
    }
}
