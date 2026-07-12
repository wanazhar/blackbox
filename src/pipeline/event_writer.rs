//! Single-writer event ingress with a monotonic sequence counter.
//!
//! All capture paths (PTY, git, fs, process, adapters) should funnel
//! through an `EventWriter` so sequence numbers and persistence stay consistent.
//!
//! Also deduplicates `tool.call` / `tool.result` when the same structured
//! event arrives from both the PTY stream and native harness logs.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::event::TraceEvent;
use crate::storage::TraceStore;

/// Owns the per-run sequence counter and persists events.
pub struct EventWriter {
    store: Arc<dyn TraceStore>,
    seq: AtomicU64,
    run_id: String,
    /// Fingerprints of tool.call / tool.result already written this run.
    tool_seen: Mutex<HashSet<String>>,
}

impl EventWriter {
    /// Create a writer starting at sequence `1` (0 reserved / unused).
    pub fn new(store: Arc<dyn TraceStore>, run_id: impl Into<String>) -> Self {
        Self::with_start(store, run_id, 1)
    }

    /// Create a writer that continues from `start` (next allocated sequence).
    pub fn with_start(store: Arc<dyn TraceStore>, run_id: impl Into<String>, start: u64) -> Self {
        Self {
            store,
            seq: AtomicU64::new(start.max(1)),
            run_id: run_id.into(),
            tool_seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Current next-sequence value (not yet assigned).
    pub fn next_sequence(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Assign the next sequence number without persisting.
    pub fn allocate_sequence(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Persist an event, assigning a sequence if `event.sequence == 0`.
    ///
    /// Duplicate tool.call/tool.result (same fingerprint) are skipped so
    /// PTY + native-log double delivery does not bloat the timeline.
    pub async fn write(&self, mut event: TraceEvent) -> anyhow::Result<TraceEvent> {
        if event.run_id.is_empty() {
            event.run_id = self.run_id.clone();
        }

        if let Some(fp) = tool_fingerprint(&event) {
            let mut seen = self
                .tool_seen
                .lock()
                .map_err(|e| anyhow::anyhow!("tool_seen lock poisoned: {}", e))?;
            if !seen.insert(fp.clone()) {
                tracing::debug!(
                    kind = %event.kind,
                    fingerprint = %fp,
                    "dedupe: skipping duplicate tool event"
                );
                // Still return the event (with seq 0) so callers know it was a dup
                event
                    .metadata
                    .insert("deduped".to_string(), serde_json::json!(true));
                return Ok(event);
            }
        }

        if event.sequence == 0 {
            event.sequence = self.allocate_sequence();
        }
        self.store.insert_event(&event).await?;
        Ok(event)
    }

    /// Clone for sharing across tasks (store is Arc; seq is shared via Arc\<EventWriter\>).
    pub fn store(&self) -> Arc<dyn TraceStore> {
        self.store.clone()
    }
}

/// Stable fingerprint for tool events used for cross-channel dedupe.
fn tool_fingerprint(event: &TraceEvent) -> Option<String> {
    if event.kind != "tool.call" && event.kind != "tool.result" {
        return None;
    }
    let tool_use_id = event
        .metadata
        .get("tool_use_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tool_name = event
        .metadata
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !tool_use_id.is_empty() {
        return Some(format!("{}:{}", event.kind, tool_use_id));
    }

    // Fallback: kind + name + compact input
    let input = event
        .metadata
        .get("input")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let input_key = if input.len() > 120 {
        format!("{}…", &input[..120])
    } else {
        input
    };
    if tool_name.is_empty() && input_key.is_empty() {
        return None;
    }
    Some(format!("{}:{}:{}", event.kind, tool_name, input_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;

    #[tokio::test]
    async fn dedupes_tool_call_by_use_id() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let writer = EventWriter::new(store.clone(), run.id.clone());

        let mut a = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        a.status = EventStatus::Running;
        a.metadata
            .insert("tool_use_id".into(), serde_json::json!("tu-1"));
        a.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));

        let mut b = a.clone();
        b.id = uuid::Uuid::new_v4().to_string();
        b.metadata
            .insert("native_log".into(), serde_json::json!("/tmp/x.jsonl"));

        let w1 = writer.write(a).await.unwrap();
        let w2 = writer.write(b).await.unwrap();
        assert!(w1.sequence > 0);
        assert_eq!(w2.sequence, 0);
        assert_eq!(
            w2.metadata.get("deduped").and_then(|v| v.as_bool()),
            Some(true)
        );

        let events = store.get_events(&run.id).await.unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "tool.call").count(), 1);
    }
}
