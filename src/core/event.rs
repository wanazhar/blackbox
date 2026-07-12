use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Source layer that produced a trace event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventSource {
    Human,
    Harness,
    Terminal,
    Process,
    Filesystem,
    Git,
    Tool,
    Network,
    Browser,
    System,
}

/// Execution status of an event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventStatus {
    Pending,
    Running,
    Success,
    Error,
    Cancelled,
    Unknown,
}

/// Safety classification for replay and audit decisions.
///
/// Conservative defaults: if a classification cannot be determined,
/// it should be marked `Unknown` rather than assumed safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SideEffect {
    /// Truly no observable side effect
    None,
    /// Reads data without modifying anything
    Read,
    /// Modifies the local repository or workspace
    #[serde(rename = "local-write")]
    LocalWrite,
    /// Modifies an external system (network, database, API)
    #[serde(rename = "external-write")]
    ExternalWrite,
    /// Destructive action (delete, drop, teardown)
    Destructive,
    /// Classification unknown — used as a safety prompt
    Unknown,
}

/// Confidence level for causal correlations between events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Confirmed,
    StronglyCorrelated,
    WeaklyCorrelated,
    Unknown,
}

/// A single recorded event in a run trace.
///
/// Every observable action — terminal I/O, process execution,
/// file modification, tool call, network request — becomes one
/// `TraceEvent`. Events form the universal substrate of the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Unique event identifier (UUID v4)
    pub id: String,

    /// Run this event belongs to
    pub run_id: String,

    /// Parent event in the causal chain, if known
    pub parent_event_id: Option<String>,

    /// Monotonically increasing sequence number within the run
    pub sequence: u64,

    /// Source capture layer
    pub source: EventSource,

    /// Event type discriminator
    ///
    /// Examples: "command", "file.modified", "tool.call",
    /// "human.input", "network.request", "git.diff"
    pub kind: String,

    /// When the event began
    pub started_at: DateTime<Utc>,

    /// When the event completed, if applicable
    pub ended_at: Option<DateTime<Utc>>,

    /// Wall-clock duration in milliseconds
    pub duration_ms: Option<u64>,

    /// Current event status
    pub status: EventStatus,

    /// Side-effect classification for replay safety
    pub side_effect: SideEffect,

    /// Reference to stored input/request payload blob
    pub input_blob: Option<String>,

    /// Reference to stored output/response payload blob
    pub output_blob: Option<String>,

    /// Reference to stored error payload blob
    pub error_blob: Option<String>,

    /// Arbitrary structured metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TraceEvent {
    /// Create a new event with auto-generated ID and current timestamp.
    pub fn new(run_id: &str, source: EventSource, kind: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            run_id: run_id.to_string(),
            parent_event_id: None,
            sequence: 0,
            source,
            kind: kind.to_string(),
            started_at: Utc::now(),
            ended_at: None,
            duration_ms: None,
            status: EventStatus::Pending,
            side_effect: SideEffect::Unknown,
            input_blob: None,
            output_blob: None,
            error_blob: None,
            metadata: HashMap::new(),
        }
    }

    /// Mark this event as completed with a status.
    pub fn finish(&mut self, status: EventStatus) {
        self.ended_at = Some(Utc::now());
        self.status = status;
        if let Some(end) = self.ended_at {
            self.duration_ms = Some(
                end.signed_duration_since(self.started_at)
                    .num_milliseconds()
                    .max(0) as u64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_correct_defaults() {
        let ev = TraceEvent::new("run-1", EventSource::Tool, "command");
        assert_eq!(ev.run_id, "run-1");
        assert_eq!(ev.source, EventSource::Tool);
        assert_eq!(ev.kind, "command");
        assert_eq!(ev.status, EventStatus::Pending);
        assert_eq!(ev.side_effect, SideEffect::Unknown);
        assert_eq!(ev.sequence, 0);
        assert!(ev.parent_event_id.is_none());
        assert!(ev.ended_at.is_none());
        assert!(ev.duration_ms.is_none());
        assert!(ev.input_blob.is_none());
        assert!(ev.output_blob.is_none());
        assert!(ev.error_blob.is_none());
        // ID is a valid UUID
        assert!(!ev.id.is_empty());
        assert!(ev.id.parse::<uuid::Uuid>().is_ok());
    }

    #[test]
    fn finish_sets_ended_at_and_duration() {
        let mut ev = TraceEvent::new("run-1", EventSource::Terminal, "io");
        ev.started_at = Utc::now() - chrono::Duration::milliseconds(150);
        ev.finish(EventStatus::Success);
        assert!(ev.ended_at.is_some());
        assert_eq!(ev.status, EventStatus::Success);
        let dur = ev.duration_ms.unwrap();
        // Allow a small tolerance for execution time
        assert!((140..=200).contains(&dur), "expected ~150ms, got {dur}");
    }

    #[test]
    fn finish_with_zero_duration() {
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "noop");
        let now = Utc::now();
        ev.started_at = now;
        // Finish immediately — duration should be 0 or very close
        ev.finish(EventStatus::Success);
        assert!(ev.ended_at.is_some());
        let dur = ev.duration_ms.unwrap();
        assert!(dur <= 10, "expected ~0ms, got {dur}");
    }

    #[test]
    fn finish_is_idempotent() {
        let mut ev = TraceEvent::new("run-1", EventSource::Human, "input");
        ev.started_at = Utc::now() - chrono::Duration::milliseconds(50);
        ev.finish(EventStatus::Success);
        let first_ended = ev.ended_at.unwrap();
        let _first_duration = ev.duration_ms;
        // Second call should overwrite (not panic), and ended_at should
        // be equal or later — but critically it stays Some.
        ev.finish(EventStatus::Error);
        assert!(ev.ended_at.is_some());
        assert!(ev.ended_at.unwrap() >= first_ended);
        assert_eq!(ev.status, EventStatus::Error);
        // duration may change slightly but must remain valid
        assert!(ev.duration_ms.is_some());
    }

    #[test]
    fn metadata_empty_by_default() {
        let ev = TraceEvent::new("run-1", EventSource::Filesystem, "read");
        assert!(ev.metadata.is_empty());
        assert_eq!(ev.metadata.len(), 0);
    }

    #[test]
    fn serde_round_trip() {
        let mut ev = TraceEvent::new("run-1", EventSource::Git, "commit");
        ev.status = EventStatus::Running;
        ev.side_effect = SideEffect::LocalWrite;
        ev.metadata
            .insert("key".to_string(), serde_json::json!("value"));
        let json = serde_json::to_string(&ev).unwrap();
        let de: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, ev.id);
        assert_eq!(de.run_id, ev.run_id);
        assert_eq!(de.source, ev.source);
        assert_eq!(de.kind, ev.kind);
        assert_eq!(de.status, ev.status);
        assert_eq!(de.side_effect, ev.side_effect);
        assert_eq!(de.sequence, ev.sequence);
        assert_eq!(de.metadata.get("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn event_source_serializes() {
        let sources = [
            (EventSource::Human, "\"Human\""),
            (EventSource::Harness, "\"Harness\""),
            (EventSource::Terminal, "\"Terminal\""),
            (EventSource::Process, "\"Process\""),
            (EventSource::Filesystem, "\"Filesystem\""),
            (EventSource::Git, "\"Git\""),
            (EventSource::Tool, "\"Tool\""),
            (EventSource::Network, "\"Network\""),
            (EventSource::Browser, "\"Browser\""),
            (EventSource::System, "\"System\""),
        ];
        for (variant, expected) in &sources {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected, "serialization mismatch for {variant:?}");
            let back: EventSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant, "round-trip mismatch for {variant:?}");
        }
    }

    #[test]
    fn event_status_serializes() {
        let statuses = [
            (EventStatus::Pending, "\"Pending\""),
            (EventStatus::Running, "\"Running\""),
            (EventStatus::Success, "\"Success\""),
            (EventStatus::Error, "\"Error\""),
            (EventStatus::Cancelled, "\"Cancelled\""),
            (EventStatus::Unknown, "\"Unknown\""),
        ];
        for (variant, expected) in &statuses {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected, "serialization mismatch for {variant:?}");
            let back: EventStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant, "round-trip mismatch for {variant:?}");
        }
    }

    #[test]
    fn side_effect_kebab_case() {
        let cases = [
            (SideEffect::None, "\"None\""),
            (SideEffect::Read, "\"Read\""),
            (SideEffect::LocalWrite, "\"local-write\""),
            (SideEffect::ExternalWrite, "\"external-write\""),
            (SideEffect::Destructive, "\"Destructive\""),
            (SideEffect::Unknown, "\"Unknown\""),
        ];
        for (variant, expected) in &cases {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected, "kebab-case mismatch for {variant:?}");
            let back: SideEffect = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant, "round-trip mismatch for {variant:?}");
        }
    }

    #[test]
    fn confidence_ordering() {
        // Variant declaration order: Confirmed < StronglyCorrelated < WeaklyCorrelated < Unknown
        assert!(Confidence::Confirmed < Confidence::StronglyCorrelated);
        assert!(Confidence::StronglyCorrelated < Confidence::WeaklyCorrelated);
        assert!(Confidence::WeaklyCorrelated < Confidence::Unknown);
        // Transitivity
        assert!(Confidence::Confirmed < Confidence::WeaklyCorrelated);
        assert!(Confidence::Confirmed < Confidence::Unknown);
        assert!(Confidence::StronglyCorrelated < Confidence::Unknown);
        // Equality
        assert_eq!(Confidence::Confirmed, Confidence::Confirmed);
        // Not equal across variants
        assert_ne!(Confidence::Confirmed, Confidence::Unknown);
    }
}
