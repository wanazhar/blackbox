//! Cursor-based pagination types for runs and events (1.5 P1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Opaque cursor for run listing (most recent first).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunPageCursor {
    /// Start timestamp.
    pub started_at: DateTime<Utc>,
    /// Unique identifier.
    pub id: String,
}

/// Filters applied when listing runs.
#[derive(Debug, Clone, Default)]
pub struct RunFilters {
    /// Substring match on status (e.g. "failed"); applied in SQL before LIMIT.
    pub status: Option<String>,
    /// Tag that must be present (exact match via `json_each`); applied in SQL before LIMIT.
    pub tag: Option<String>,
}

/// One page of runs.
#[derive(Debug, Clone, Serialize)]
pub struct RunPage {
    /// Runs.
    pub runs: Vec<Run>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Next cursor.
    pub next_cursor: Option<String>,
    /// Has more.
    pub has_more: bool,
}

/// Cursor for event listing by sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventPageCursor {
    /// Monotonic sequence number within the run.
    pub sequence: u64,
}

/// One page of events.
#[derive(Debug, Clone, Serialize)]
pub struct EventPage {
    /// Events.
    pub events: Vec<TraceEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Next cursor.
    pub next_cursor: Option<String>,
    /// Has more.
    pub has_more: bool,
}

/// Encode a run cursor as URL-safe base64 JSON.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `encode_run_cursor` — see module docs for full workflow.
/// ```
pub fn encode_run_cursor(c: &RunPageCursor) -> String {
    let json = serde_json::to_vec(c).unwrap_or_default();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json)
}

/// Decode run cursor.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `decode_run_cursor` — see module docs for full workflow.
/// ```
pub fn decode_run_cursor(s: &str) -> Option<RunPageCursor> {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Encode event cursor.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `encode_event_cursor` — see module docs for full workflow.
/// ```
pub fn encode_event_cursor(c: &EventPageCursor) -> String {
    let json = serde_json::to_vec(c).unwrap_or_default();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json)
}

/// Decode event cursor.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `decode_event_cursor` — see module docs for full workflow.
/// ```
pub fn decode_event_cursor(s: &str) -> Option<EventPageCursor> {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_cursor_round_trip() {
        let c = RunPageCursor {
            started_at: Utc::now(),
            id: "run-1".into(),
        };
        let enc = encode_run_cursor(&c);
        let dec = decode_run_cursor(&enc).unwrap();
        assert_eq!(dec.id, c.id);
        assert_eq!(dec.started_at, c.started_at);
    }

    #[test]
    fn event_cursor_round_trip() {
        let c = EventPageCursor { sequence: 42 };
        let enc = encode_event_cursor(&c);
        assert_eq!(decode_event_cursor(&enc).unwrap().sequence, 42);
    }
}
