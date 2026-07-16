//! Single-writer event ingress with a monotonic sequence counter.
//!
//! All capture paths (PTY, git, fs, process, adapters) should funnel
//! through an `EventWriter` so sequence numbers and persistence stay consistent.
//!
//! Also deduplicates `tool.call` / `tool.result` when the same structured
//! event arrives from both the PTY stream and native harness logs.
//!
//! Tracks soft capture-health signals (write latency / lag) for daily-driver
//! trust: slow SQLite inserts surface as warnings rather than silent stall.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::core::event::TraceEvent;
use crate::storage::TraceStore;

/// Soft threshold: a single event persist above this is a lag sample.
/// Tuned above typical debug SQLite so only real store pressure warns.
const SLOW_WRITE_MS: u128 = 150;
/// Soft threshold: many slow writes imply capture is falling behind.
const LAG_WARN_COUNT: u64 = 12;
/// Cap tool-event fingerprint set so long tool-heavy runs don't grow unbounded.
const MAX_TOOL_FINGERPRINTS: usize = 50_000;

/// Snapshot of writer health for coverage / doctor.
#[derive(Debug, Clone, Default)]
pub struct WriterHealth {
    pub events_written: u64,
    pub events_deduped: u64,
    pub slow_writes: u64,
    pub max_write_ms: u64,
    pub total_write_ms: u64,
}

impl WriterHealth {
    /// Soft warning text when capture appears to lag under load.
    pub fn soft_warning(&self) -> Option<String> {
        if self.slow_writes >= LAG_WARN_COUNT {
            return Some(format!(
                "capture lag: {} slow event writes (max {}ms, avg {:.1}ms) — store may be falling behind",
                self.slow_writes,
                self.max_write_ms,
                if self.events_written > 0 {
                    self.total_write_ms as f64 / self.events_written as f64
                } else {
                    0.0
                }
            ));
        }
        if self.max_write_ms >= 750 {
            return Some(format!(
                "capture lag: peak event write {}ms (SQLite pressure)",
                self.max_write_ms
            ));
        }
        None
    }

    pub fn is_healthy(&self) -> bool {
        self.soft_warning().is_none()
    }
}

/// Owns the per-run sequence counter and persists events.
pub struct EventWriter {
    store: Arc<dyn TraceStore>,
    seq: AtomicU64,
    run_id: String,
    /// Fingerprints of tool.call / tool.result already written this run.
    tool_seen: Mutex<HashSet<String>>,
    /// Soft health counters.
    health: Mutex<WriterHealth>,
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
            health: Mutex::new(WriterHealth::default()),
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Current next-sequence value (not yet assigned).
    pub fn next_sequence(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Assign the next sequence number without persisting.
    pub fn allocate_sequence(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::AcqRel)
    }

    /// Soft capture-health snapshot for this writer.
    pub fn health_snapshot(&self) -> WriterHealth {
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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
            // M-09: Recover from mutex poison rather than propagating the error.
            let mut seen = self.tool_seen.lock().unwrap_or_else(|e| e.into_inner());
            if seen.contains(&fp) {
                tracing::debug!(
                    kind = %event.kind,
                    fingerprint = %fp,
                    "dedupe: skipping duplicate tool event"
                );
                event
                    .metadata
                    .insert("deduped".to_string(), serde_json::json!(true));
                if let Ok(mut h) = self.health.lock() {
                    h.events_deduped = h.events_deduped.saturating_add(1);
                }
                return Ok(event);
            }
            // Soft cap: if full, clear half (rare re-dupes acceptable after eviction).
            if seen.len() >= MAX_TOOL_FINGERPRINTS {
                let drop_n = seen.len() / 2;
                let to_drop: Vec<String> = seen.iter().take(drop_n).cloned().collect();
                for k in to_drop {
                    seen.remove(&k);
                }
                tracing::debug!(
                    dropped = drop_n,
                    remaining = seen.len(),
                    "tool fingerprint set capped; evicted oldest half"
                );
            }
            seen.insert(fp);
        }

        if event.sequence == 0 {
            event.sequence = self.allocate_sequence();
        }

        let t0 = Instant::now();
        self.store.insert_event(&event).await?;
        let ms = t0.elapsed().as_millis();

        if let Ok(mut h) = self.health.lock() {
            h.events_written = h.events_written.saturating_add(1);
            h.total_write_ms = h.total_write_ms.saturating_add(ms as u64);
            h.max_write_ms = h.max_write_ms.max(ms as u64);
            if ms >= SLOW_WRITE_MS {
                h.slow_writes = h.slow_writes.saturating_add(1);
                if h.slow_writes == LAG_WARN_COUNT || ms >= 500 {
                    tracing::warn!(
                        write_ms = ms as u64,
                        slow_writes = h.slow_writes,
                        "capture lag: event persist is slow"
                    );
                }
            }
        }

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

    // Fallback: kind + name + compact input (UTF-8 safe truncate)
    let input = event
        .metadata
        .get("input")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let input_key = crate::util::truncate(&input, 120);
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
        let h = writer.health_snapshot();
        assert_eq!(h.events_written, 1);
        assert_eq!(h.events_deduped, 1);
    }

    #[test]
    fn health_warning_on_many_slow_writes() {
        let h = WriterHealth {
            events_written: 40,
            events_deduped: 0,
            slow_writes: 12,
            max_write_ms: 200,
            total_write_ms: 3000,
        };
        assert!(h.soft_warning().unwrap().contains("capture lag"));
        assert!(!h.is_healthy());
    }
}
