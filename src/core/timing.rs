//! Event timing provenance and occurrence-order analysis (1.5 O1).
//!
//! Global `sequence` remains stable **storage / ingestion order**.
//! Occurrence order is inferred from timestamps when clocks are comparable;
//! otherwise relations stay `concurrent_or_uncertain` or `unknown`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::event::TraceEvent;

/// Metadata key for source-local sequence (u64).
pub const META_SOURCE_SEQUENCE: &str = "source_sequence";
/// Metadata object key for timing provenance.
pub const META_TIMING: &str = "timing";

/// Where wall-clock / monotonic stamps came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    /// Capture layer wall clock at emit time.
    #[default]
    CaptureWall,
    /// Process start / OS event time when available.
    OsEvent,
    /// Parsed from harness/native log timestamp.
    HarnessLog,
    /// Assigned only at EventWriter ingest.
    IngestOnly,
    /// Unknown or mixed.
    Unknown,
}

impl ClockSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CaptureWall => "capture_wall",
            Self::OsEvent => "os_event",
            Self::HarnessLog => "harness_log",
            Self::IngestOnly => "ingest_only",
            Self::Unknown => "unknown",
        }
    }
}

/// Timing provenance stored under `metadata.timing`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventTiming {
    /// Best estimate of when the observed action occurred (wall clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at_wall: Option<DateTime<Utc>>,
    /// Optional monotonic clock reading (ns) from the same host when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at_monotonic_ns: Option<u64>,
    /// When the capture layer observed the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// When the event entered the merge/ingest pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    /// When the EventWriter accepted the event for persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub clock_source: ClockSource,
    /// Uncertainty window for occurrence comparisons (milliseconds).
    #[serde(default)]
    pub ordering_uncertainty_ms: u64,
}

impl Default for EventTiming {
    fn default() -> Self {
        Self {
            occurred_at_wall: None,
            occurred_at_monotonic_ns: None,
            observed_at: None,
            received_at: None,
            ingested_at: None,
            clock_source: ClockSource::Unknown,
            ordering_uncertainty_ms: DEFAULT_UNCERTAINTY_MS,
        }
    }
}

/// Default uncertainty when only wall clocks are available without sync.
pub const DEFAULT_UNCERTAINTY_MS: u64 = 5;

/// How two events relate in **occurrence** time (not storage sequence).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderingRelation {
    Before,
    After,
    ConcurrentOrUncertain,
    Unknown,
}

impl OrderingRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::ConcurrentOrUncertain => "concurrent_or_uncertain",
            Self::Unknown => "unknown",
        }
    }
}

/// View distinguishing storage order from occurrence order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderView {
    pub event_id: String,
    pub storage_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
    pub source: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at_wall: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<DateTime<Utc>>,
    pub clock_source: String,
    pub ordering_uncertainty_ms: u64,
}

impl OrderView {
    pub fn from_event(ev: &TraceEvent) -> Self {
        let t = ev.timing();
        Self {
            event_id: ev.id.clone(),
            storage_sequence: ev.sequence,
            source_sequence: ev.source_sequence(),
            source: format!("{:?}", ev.source),
            kind: ev.kind.clone(),
            occurred_at_wall: t.occurred_at_wall.or(Some(ev.started_at)),
            ingested_at: t.ingested_at,
            clock_source: t.clock_source.as_str().to_string(),
            ordering_uncertainty_ms: t.ordering_uncertainty_ms,
        }
    }
}

/// Compare occurrence order of `a` vs `b` (is `a` before `b`?).
///
/// Does **not** use storage `sequence` alone as strict causality.
pub fn relate_occurrence(a: &TraceEvent, b: &TraceEvent) -> OrderingRelation {
    if a.id == b.id {
        return OrderingRelation::ConcurrentOrUncertain;
    }

    let ta = a.timing();
    let tb = b.timing();

    // Prefer monotonic when both present (same host assumption).
    if let (Some(ma), Some(mb)) = (ta.occurred_at_monotonic_ns, tb.occurred_at_monotonic_ns) {
        let ua = ta.ordering_uncertainty_ms.saturating_mul(1_000_000); // ns
        let ub = tb.ordering_uncertainty_ms.saturating_mul(1_000_000);
        let u = ua.max(ub);
        if ma + u < mb {
            return OrderingRelation::Before;
        }
        if mb + u < ma {
            return OrderingRelation::After;
        }
        return OrderingRelation::ConcurrentOrUncertain;
    }

    let wa = ta.occurred_at_wall.or(Some(a.started_at));
    let wb = tb.occurred_at_wall.or(Some(b.started_at));
    match (wa, wb) {
        (Some(ta_wall), Some(tb_wall)) => {
            // If either clock is ingest-only, occurrence is weak.
            if matches!(ta.clock_source, ClockSource::IngestOnly | ClockSource::Unknown)
                && matches!(tb.clock_source, ClockSource::IngestOnly | ClockSource::Unknown)
            {
                // Fall back to storage order only as uncertain proximity.
                return OrderingRelation::Unknown;
            }
            let u_ms = ta
                .ordering_uncertainty_ms
                .max(tb.ordering_uncertainty_ms)
                .max(DEFAULT_UNCERTAINTY_MS) as i64;
            let delta = ta_wall.signed_duration_since(tb_wall).num_milliseconds();
            // a - b: negative means a is earlier
            if delta < -u_ms {
                OrderingRelation::Before
            } else if delta > u_ms {
                OrderingRelation::After
            } else {
                OrderingRelation::ConcurrentOrUncertain
            }
        }
        _ => OrderingRelation::Unknown,
    }
}

/// Sort key for occurrence-oriented views (stable secondary keys).
pub fn occurrence_sort_key(ev: &TraceEvent) -> (i64, u64, u64) {
    let t = ev.timing();
    let wall = t
        .occurred_at_wall
        .unwrap_or(ev.started_at)
        .timestamp_millis();
    let src_seq = ev.source_sequence().unwrap_or(0);
    (wall, src_seq, ev.sequence)
}

/// Sort a slice by inferred occurrence order without changing storage sequence.
pub fn sort_by_occurrence(events: &mut [TraceEvent]) {
    events.sort_by_key(occurrence_sort_key);
}

/// Build order views for JSON/UI (storage vs occurrence fields).
pub fn order_views(events: &[TraceEvent]) -> Vec<OrderView> {
    events.iter().map(OrderView::from_event).collect()
}

/// Small bounded buffer that reorders by occurrence when clocks are comparable.
///
/// Emits events in occurrence order once the window fills or flushes. Storage
/// `sequence` is **not** rewritten — callers should assign sequence at ingest.
#[derive(Debug, Default)]
pub struct BoundedReorderBuffer {
    items: Vec<TraceEvent>,
    capacity: usize,
}

impl BoundedReorderBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&mut self, event: TraceEvent) -> Vec<TraceEvent> {
        self.items.push(event);
        if self.items.len() >= self.capacity {
            self.flush()
        } else {
            Vec::new()
        }
    }

    pub fn flush(&mut self) -> Vec<TraceEvent> {
        if self.items.is_empty() {
            return Vec::new();
        }
        let mut out = std::mem::take(&mut self.items);
        // Only reorder when every event has a non-ingest-only wall clock.
        let all_comparable = out.iter().all(|e| {
            let t = e.timing();
            !matches!(
                t.clock_source,
                ClockSource::IngestOnly | ClockSource::Unknown
            ) && (t.occurred_at_wall.is_some() || t.occurred_at_monotonic_ns.is_some())
        });
        if all_comparable {
            sort_by_occurrence(&mut out);
        }
        // else keep arrival order — do not invent strict ordering
        out
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};
    use chrono::Duration;

    fn ev(kind: &str, wall: DateTime<Utc>, clock: ClockSource) -> TraceEvent {
        let mut e = TraceEvent::new("r", EventSource::Terminal, kind);
        e.started_at = wall;
        let t = EventTiming {
            occurred_at_wall: Some(wall),
            observed_at: Some(wall),
            clock_source: clock,
            ordering_uncertainty_ms: 5,
            ..Default::default()
        };
        e.set_timing(&t);
        e
    }

    #[test]
    fn delayed_cross_layer_not_strict_from_storage_sequence() {
        let t0 = Utc::now();
        // B occurred first, but was ingested later (higher sequence).
        let mut early = ev("fs.modified", t0, ClockSource::OsEvent);
        early.sequence = 10;
        let mut late_obs = ev("terminal.output", t0 + Duration::milliseconds(100), ClockSource::CaptureWall);
        late_obs.sequence = 2; // ingested first

        // Occurrence: early before late_obs
        assert_eq!(
            relate_occurrence(&early, &late_obs),
            OrderingRelation::Before
        );
        // Storage sequence would falsely say late_obs before early — we must not.
        assert!(late_obs.sequence < early.sequence);
    }

    #[test]
    fn ingest_only_clocks_are_unknown() {
        let t0 = Utc::now();
        let mut a = ev("a", t0, ClockSource::IngestOnly);
        let mut b = ev("b", t0 + Duration::milliseconds(50), ClockSource::IngestOnly);
        a.sequence = 1;
        b.sequence = 2;
        assert_eq!(relate_occurrence(&a, &b), OrderingRelation::Unknown);
    }

    #[test]
    fn uncertainty_window_yields_concurrent() {
        let t0 = Utc::now();
        let a = ev("a", t0, ClockSource::CaptureWall);
        let b = ev("b", t0 + Duration::milliseconds(2), ClockSource::CaptureWall);
        assert_eq!(
            relate_occurrence(&a, &b),
            OrderingRelation::ConcurrentOrUncertain
        );
    }

    #[test]
    fn reorder_buffer_sorts_comparable_clocks() {
        let t0 = Utc::now();
        let mut buf = BoundedReorderBuffer::new(3);
        let mut a = ev("late", t0 + Duration::milliseconds(100), ClockSource::CaptureWall);
        a.set_source_sequence(1);
        let mut b = ev("early", t0, ClockSource::CaptureWall);
        b.set_source_sequence(2);
        assert!(buf.push(a).is_empty());
        assert!(buf.push(b).is_empty());
        let mut c = ev("mid", t0 + Duration::milliseconds(50), ClockSource::CaptureWall);
        c.set_source_sequence(3);
        let out = buf.push(c);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].kind, "early");
        assert_eq!(out[1].kind, "mid");
        assert_eq!(out[2].kind, "late");
    }

    #[test]
    fn reorder_keeps_arrival_when_clocks_weak() {
        let t0 = Utc::now();
        let mut buf = BoundedReorderBuffer::new(2);
        let a = ev("first", t0 + Duration::milliseconds(100), ClockSource::IngestOnly);
        let b = ev("second", t0, ClockSource::IngestOnly);
        assert!(buf.push(a).is_empty());
        let out = buf.push(b);
        assert_eq!(out[0].kind, "first");
        assert_eq!(out[1].kind, "second");
    }
}
