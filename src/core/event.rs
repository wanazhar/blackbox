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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
                    .num_milliseconds() as u64,
            );
        }
    }
}
