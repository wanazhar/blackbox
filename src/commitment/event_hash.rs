//! Canonical per-event content hashes for the commitment chain.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::core::event::TraceEvent;
use crate::protocol::canonical_hash;

/// Fields included in an event's commitment hash.
///
/// Transport metadata and mutable store bookkeeping are excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHashInput {
    /// Event id.
    pub id: String,
    /// Run id.
    pub run_id: String,
    /// Recorder sequence.
    pub sequence: u64,
    /// Event kind.
    pub kind: String,
    /// Source layer as stable string.
    pub source: String,
    /// Status as stable string.
    pub status: String,
    /// Parent event id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    /// Input blob key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_blob: Option<String>,
    /// Output blob key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_blob: Option<String>,
    /// Error blob key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_blob: Option<String>,
    /// Selected metadata keys (sorted) — excludes transport-only keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl EventHashInput {
    /// Build from a [`TraceEvent`], dropping transport-only metadata keys.
    pub fn from_event(event: &TraceEvent) -> Self {
        let mut meta = serde_json::Map::new();
        let mut keys: Vec<&String> = event.metadata.keys().collect();
        keys.sort();
        for k in keys {
            if is_transport_metadata(k) {
                continue;
            }
            meta.insert(k.clone(), event.metadata[k].clone());
        }
        let metadata = if meta.is_empty() {
            None
        } else {
            Some(Value::Object(meta))
        };
        Self {
            id: event.id.clone(),
            run_id: event.run_id.clone(),
            sequence: event.sequence,
            kind: event.kind.clone(),
            source: format!("{:?}", event.source),
            status: format!("{:?}", event.status),
            parent_event_id: event.parent_event_id.clone(),
            input_blob: event.input_blob.clone(),
            output_blob: event.output_blob.clone(),
            error_blob: event.error_blob.clone(),
            metadata,
        }
    }

    /// Canonical hash of this input.
    pub fn hash(&self) -> String {
        let v = serde_json::to_value(self).unwrap_or(json!({}));
        canonical_hash(&v).unwrap_or_else(|_| hash_hex(b"invalid"))
    }
}

/// Content hash of a trace event for chaining.
pub fn event_content_hash(event: &TraceEvent) -> String {
    EventHashInput::from_event(event).hash()
}

/// SHA-256 hex of raw bytes.
pub fn hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn is_transport_metadata(key: &str) -> bool {
    key.starts_with("native.client_")
        || key == "spool_batch_id"
        || key == "transport_peer"
        || key == "connection_id"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};

    #[test]
    fn transport_metadata_excluded() {
        let mut a = TraceEvent::new("r", EventSource::Tool, "tool.call");
        a.sequence = 1;
        a.metadata.clear();
        a.metadata
            .insert("native.client_timestamp".into(), json!("t"));
        a.metadata.insert("tool_name".into(), json!("bash"));

        let mut b = a.clone();
        b.metadata.clear();
        b.metadata.insert("tool_name".into(), json!("bash"));
        // Only transport key differs — content hash must match.
        assert_eq!(event_content_hash(&a), event_content_hash(&b));
    }
}
