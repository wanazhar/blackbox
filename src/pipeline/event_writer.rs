//! Single-writer event ingress with a monotonic sequence counter.
//!
//! All capture paths (PTY, git, fs, process, adapters) should funnel
//! through an `EventWriter` so sequence numbers and persistence stay consistent.
//!
//! Tool deduplication (1.5 D1): merge only when evidence shows the **same
//! observation** — stable tool-use ID, matching normalized payload, and
//! (typically) cross-source provenance within a narrow age window.
//! **ID-less** identical calls (e.g. two `cargo test` runs) are **never**
//! collapsed; both are stored so retry analysis sees every real attempt.
//!
//! Tracks soft capture-health signals (write latency / lag) for daily-driver
//! trust: slow SQLite inserts surface as warnings rather than silent stall.
//!
//! Live capture (1.5 S1) uses a bounded batch queue + dedicated writer via
//! [`EventWriter::new_batched`]; unit tests keep the synchronous path.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::core::event::{EventSource, TraceEvent};
use crate::pipeline::batch_ingest::{
    is_barrier_kind, BatchIngestConfig, BatchIngestHealth, BatchIngestor,
};
use crate::storage::TraceStore;

/// Soft threshold: a single event persist above this is a lag sample.
/// Tuned above typical debug SQLite so only real store pressure warns.
const SLOW_WRITE_MS: u128 = 150;
/// Soft threshold: many slow writes imply capture is falling behind.
const LAG_WARN_COUNT: u64 = 12;
/// Cap tool-event fingerprint LRU so long tool-heavy runs stay bounded.
const MAX_TOOL_FINGERPRINTS: usize = 50_000;
/// Only merge duplicates observed within this window.
const DUPLICATE_WINDOW: Duration = Duration::from_secs(30);

/// Snapshot of writer health for coverage / doctor.
#[derive(Debug, Clone, Default)]
pub struct WriterHealth {
    /// Events written.
    pub events_written: u64,
    /// Events deduped.
    pub events_deduped: u64,
    /// Slow writes.
    pub slow_writes: u64,
    /// Max write ms.
    pub max_write_ms: u64,
    /// Total write ms.
    pub total_write_ms: u64,
    /// Present when using batched ingest.
    pub batch: Option<BatchIngestHealth>,
}

impl WriterHealth {
    /// Soft warning text when capture appears to lag under load.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `soft_warning` — see module docs for full workflow.
    /// ```
    pub fn soft_warning(&self) -> Option<String> {
        if let Some(ref b) = self.batch {
            if b.write_failures > 0 {
                return Some(format!(
                    "capture lag: batch ingest write_failures={} (store may have lost events)",
                    b.write_failures
                ));
            }
            if b.queue_high_water >= 2_000 {
                return Some(format!(
                    "capture lag: batch queue high-water {} (ingest falling behind)",
                    b.queue_high_water
                ));
            }
            if b.max_flush_ms >= 750 {
                return Some(format!(
                    "capture lag: peak batch flush {}ms (SQLite pressure)",
                    b.max_flush_ms
                ));
            }
        }
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

    /// Return true if healthy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `is_healthy` — see module docs for full workflow.
    /// ```
    pub fn is_healthy(&self) -> bool {
        self.soft_warning().is_none()
    }
}

/// Age-bounded LRU of tool fingerprints already written this run.
struct ToolDedupeCache {
    /// Fingerprint → entry; order tracked separately for true LRU eviction.
    map: HashMap<String, DedupeEntry>,
    /// Oldest-first insertion/touch order of fingerprint keys.
    order: VecDeque<String>,
}

#[derive(Clone)]
struct DedupeEntry {
    event_id: String,
    payload_hash: String,
    provenances: Vec<String>,
    seen_at: Instant,
}

impl ToolDedupeCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, fp: &str) -> Option<&DedupeEntry> {
        self.map.get(fp)
    }

    fn insert(&mut self, fp: String, entry: DedupeEntry) {
        if self.map.contains_key(&fp) {
            // Move to back (most recent).
            if let Some(pos) = self.order.iter().position(|k| k == &fp) {
                self.order.remove(pos);
            }
        }
        self.order.push_back(fp.clone());
        self.map.insert(fp, entry);
        self.evict_if_needed();
    }

    fn touch_update(&mut self, fp: &str, entry: DedupeEntry) {
        if self.map.contains_key(fp) {
            if let Some(pos) = self.order.iter().position(|k| k == fp) {
                self.order.remove(pos);
            }
            self.order.push_back(fp.to_string());
            self.map.insert(fp.to_string(), entry);
        }
    }

    fn evict_if_needed(&mut self) {
        while self.map.len() > MAX_TOOL_FINGERPRINTS {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        // Age-based eviction of very old entries (keep map tight).
        let now = Instant::now();
        while let Some(front) = self.order.front() {
            let expired = self
                .map
                .get(front)
                .map(|e| now.duration_since(e.seen_at) > DUPLICATE_WINDOW * 4)
                .unwrap_or(true);
            if expired {
                if let Some(k) = self.order.pop_front() {
                    self.map.remove(&k);
                }
            } else {
                break;
            }
        }
    }
}

/// Owns the per-run sequence counter and persists events.
pub struct EventWriter {
    store: Arc<dyn TraceStore>,
    seq: AtomicU64,
    run_id: String,
    /// Age-bounded LRU of tool fingerprints already written this run.
    tool_seen: Mutex<ToolDedupeCache>,
    /// Soft health counters.
    health: Mutex<WriterHealth>,
    /// When set, events go through the dedicated batch writer.
    batch: Option<BatchIngestor>,
    /// Per-source local sequence counters (1.5 O1).
    source_seqs: Mutex<HashMap<&'static str, u64>>,
}

impl EventWriter {
    /// Create a synchronous writer starting at sequence `1` (0 reserved / unused).
    ///
    /// Prefer [`Self::new_batched`] for live capture so hot paths do not block
    /// on per-event SQLite transactions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new(store: Arc<dyn TraceStore>, run_id: impl Into<String>) -> Self {
        Self::with_start(store, run_id, 1)
    }

    /// Live-capture writer: bounded queue + micro-batch flushes (1.5 S1).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `new_batched` — see module docs for full workflow.
    /// ```
    pub fn new_batched(store: Arc<dyn TraceStore>, run_id: impl Into<String>) -> Self {
        Self::with_start_batched(store, run_id, 1, BatchIngestConfig::default())
    }

    /// Create a writer that continues from `start` (next allocated sequence).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_start` — see module docs for full workflow.
    /// ```
    pub fn with_start(store: Arc<dyn TraceStore>, run_id: impl Into<String>, start: u64) -> Self {
        Self {
            store,
            seq: AtomicU64::new(start.max(1)),
            run_id: run_id.into(),
            tool_seen: Mutex::new(ToolDedupeCache::new()),
            health: Mutex::new(WriterHealth::default()),
            batch: None,
            source_seqs: Mutex::new(HashMap::new()),
        }
    }

    /// Batched writer continuing from `start`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_start_batched` — see module docs for full workflow.
    /// ```
    pub fn with_start_batched(
        store: Arc<dyn TraceStore>,
        run_id: impl Into<String>,
        start: u64,
        config: BatchIngestConfig,
    ) -> Self {
        Self::with_start_batched_spool(store, run_id, start, config, None)
    }

    /// Batched writer with optional durable spool directory (1.6).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_start_batched_spool` — see module docs for full workflow.
    /// ```
    pub fn with_start_batched_spool(
        store: Arc<dyn TraceStore>,
        run_id: impl Into<String>,
        start: u64,
        config: BatchIngestConfig,
        spool: Option<Arc<crate::ingest::EventSpool>>,
    ) -> Self {
        let batch = BatchIngestor::spawn_with_spool(store.clone(), config, spool);
        Self {
            store,
            seq: AtomicU64::new(start.max(1)),
            run_id: run_id.into(),
            tool_seen: Mutex::new(ToolDedupeCache::new()),
            health: Mutex::new(WriterHealth::default()),
            batch: Some(batch),
            source_seqs: Mutex::new(HashMap::new()),
        }
    }

    /// Live-capture writer with durable spool when `spool_dir` is provided.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `new_batched_with_spool` — see module docs for full workflow.
    /// ```
    pub fn new_batched_with_spool(
        store: Arc<dyn TraceStore>,
        run_id: impl Into<String>,
        spool_dir: Option<&std::path::Path>,
    ) -> Self {
        let spool = spool_dir.and_then(|d| {
            crate::ingest::EventSpool::open(d)
                .map(Arc::new)
                .map_err(|e| {
                    tracing::warn!(error = %e, "durable spool open failed; continuing without");
                    e
                })
                .ok()
        });
        Self::with_start_batched_spool(store, run_id, 1, BatchIngestConfig::default(), spool)
    }

    fn allocate_source_sequence(&self, source: &EventSource) -> u64 {
        let key = match source {
            EventSource::Human => "Human",
            EventSource::Harness => "Harness",
            EventSource::Terminal => "Terminal",
            EventSource::Process => "Process",
            EventSource::Filesystem => "Filesystem",
            EventSource::Git => "Git",
            EventSource::Tool => "Tool",
            EventSource::Network => "Network",
            EventSource::Browser => "Browser",
            EventSource::System => "System",
        };
        let mut map = self.source_seqs.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        *n
    }

    /// Run id.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `run_id` — see module docs for full workflow.
    /// ```
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Current next-sequence value (not yet assigned).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `next_sequence` — see module docs for full workflow.
    /// ```
    pub fn next_sequence(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Assign the next sequence number without persisting.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `allocate_sequence` — see module docs for full workflow.
    /// ```
    pub fn allocate_sequence(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::AcqRel)
    }

    /// Soft capture-health snapshot for this writer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `health_snapshot` — see module docs for full workflow.
    /// ```
    pub fn health_snapshot(&self) -> WriterHealth {
        let mut h = self
            .health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(ref b) = self.batch {
            h.batch = Some(b.health_snapshot());
        }
        h
    }

    /// Whether this writer uses batched ingest.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `is_batched` — see module docs for full workflow.
    /// ```
    pub fn is_batched(&self) -> bool {
        self.batch.is_some()
    }

    /// Flush pending batched events (no-op for sync writers).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `flush` — see module docs for full workflow.
    /// ```
    pub async fn flush(&self) -> anyhow::Result<()> {
        if let Some(ref b) = self.batch {
            b.flush().await?;
        }
        Ok(())
    }

    /// Flush and stop the batch worker (no-op for sync writers).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `shutdown` — see module docs for full workflow.
    /// ```
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        if let Some(ref b) = self.batch {
            b.shutdown().await?;
        }
        Ok(())
    }

    /// Persist an event, assigning a sequence if `event.sequence == 0`.
    ///
    /// Tool dedupe (1.5 D1): only skip insert when a stable tool-use ID matches
    /// a prior event with the same kind + payload hash inside the duplicate
    /// window. ID-less tool calls always persist (legitimate retries).
    ///
    /// With batched ingest, non-barrier events return after queue accept;
    /// barrier kinds wait for durable flush.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `write` — see module docs for full workflow.
    /// ```
    pub async fn write(&self, mut event: TraceEvent) -> anyhow::Result<TraceEvent> {
        if event.run_id.is_empty() {
            event.run_id = self.run_id.clone();
        }

        if let Some(decision) = self.dedupe_decision(&event) {
            match decision {
                DedupeDecision::Skip {
                    original_id,
                    reason,
                    provenances,
                } => {
                    tracing::debug!(
                        kind = %event.kind,
                        original = %original_id,
                        reason = %reason,
                        "dedupe: skipping proven duplicate tool event"
                    );
                    event
                        .metadata
                        .insert("deduped".to_string(), serde_json::json!(true));
                    event
                        .metadata
                        .insert("duplicate_of".to_string(), serde_json::json!(original_id));
                    event
                        .metadata
                        .insert("duplicate_reason".to_string(), serde_json::json!(reason));
                    event.metadata.insert(
                        "capture_provenance".to_string(),
                        serde_json::json!(provenances),
                    );
                    // Annotate the kept event with merged provenance (best-effort).
                    // Flush first so the original is visible if still in the batch queue.
                    let _ = self.flush().await;
                    if let Ok(Some(mut kept)) = self.store.get_event(&original_id).await {
                        kept.metadata.insert(
                            "capture_provenance".to_string(),
                            serde_json::json!(provenances),
                        );
                        kept.metadata
                            .insert("duplicate_reason".to_string(), serde_json::json!(reason));
                        let _ = self.store.update_event(&kept).await;
                    }
                    if let Ok(mut h) = self.health.lock() {
                        h.events_deduped = h.events_deduped.saturating_add(1);
                    }
                    return Ok(event);
                }
            }
        }

        if event.sequence == 0 {
            event.sequence = self.allocate_sequence();
        }

        // Source-local sequence + ingest timestamps (1.5 O1).
        // Layers may pre-assign source_sequence; otherwise allocate per source.
        if event.source_sequence().is_none() {
            let src_seq = self.allocate_source_sequence(&event.source);
            event.set_source_sequence(src_seq);
        }
        event.stamp_ingested();

        // Record fingerprint when we accept the event for persist (before/after batch).
        if let Some((fp, payload_hash, prov)) = tool_dedupe_key(&event) {
            let mut cache = self.tool_seen.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(
                fp,
                DedupeEntry {
                    event_id: event.id.clone(),
                    payload_hash,
                    provenances: vec![prov],
                    seen_at: Instant::now(),
                },
            );
        }

        let t0 = Instant::now();
        if let Some(ref batch) = self.batch {
            let barrier = is_barrier_kind(&event.kind);
            batch.enqueue(event.clone(), barrier).await?;
        } else {
            self.store.insert_event(&event).await?;
        }
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

    fn dedupe_decision(&self, event: &TraceEvent) -> Option<DedupeDecision> {
        let (fp, payload_hash, prov) = tool_dedupe_key(event)?;
        let mut cache = self.tool_seen.lock().unwrap_or_else(|e| e.into_inner());
        let entry = cache.get(&fp)?.clone();

        // Outside the duplicate window → treat as a new attempt (e.g. reused id after long gap).
        if entry.seen_at.elapsed() > DUPLICATE_WINDOW {
            return None;
        }
        // Payload mismatch → do not merge (different observation).
        if entry.payload_hash != payload_hash {
            return None;
        }

        let mut provenances = entry.provenances.clone();
        if !provenances.iter().any(|p| p == &prov) {
            provenances.push(prov);
        }
        let reason = if provenances.len() > 1 {
            "same_tool_use_id_cross_source"
        } else {
            "same_tool_use_id_redeelivery"
        };

        // Touch LRU and update provenance list for subsequent merges.
        cache.touch_update(
            &fp,
            DedupeEntry {
                event_id: entry.event_id.clone(),
                payload_hash: entry.payload_hash.clone(),
                provenances: provenances.clone(),
                seen_at: entry.seen_at,
            },
        );

        Some(DedupeDecision::Skip {
            original_id: entry.event_id,
            reason: reason.to_string(),
            provenances,
        })
    }

    /// Clone for sharing across tasks (store is Arc; seq is shared via Arc\<EventWriter\>).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `store` — see module docs for full workflow.
    /// ```
    pub fn store(&self) -> Arc<dyn TraceStore> {
        self.store.clone()
    }
}

enum DedupeDecision {
    Skip {
        original_id: String,
        reason: String,
        provenances: Vec<String>,
    },
}

/// Build a dedupe key only for tool events that carry a stable tool-use ID.
///
/// Returns `(fingerprint, payload_hash, provenance)`.
/// Returns `None` for non-tool events and for ID-less tool calls (must not merge).
fn tool_dedupe_key(event: &TraceEvent) -> Option<(String, String, String)> {
    if event.kind != "tool.call" && event.kind != "tool.result" {
        return None;
    }
    let tool_use_id = event
        .metadata
        .get("tool_use_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if tool_use_id.is_empty() {
        // 1.5 D1: no stable ID → never dedupe (preserve legitimate retries).
        return None;
    }
    let payload_hash = normalized_payload_hash(event);
    let provenance = capture_provenance(event);
    let fp = format!("{}:{}", event.kind, tool_use_id);
    Some((fp, payload_hash, provenance))
}

fn capture_provenance(event: &TraceEvent) -> String {
    if event.metadata.contains_key("native_log")
        || event
            .metadata
            .get("from_native_log")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        return "native_log".into();
    }
    if event
        .metadata
        .get("from_pty")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event.metadata.contains_key("pty")
    {
        return "pty".into();
    }
    // Fall back to source layer name.
    format!("{:?}", event.source).to_ascii_lowercase()
}

fn normalized_payload_hash(event: &TraceEvent) -> String {
    use std::collections::BTreeMap;
    // Stable subset: tool_name + input/output (exclude provenance-only keys).
    let mut parts: BTreeMap<&str, String> = BTreeMap::new();
    for key in ["tool_name", "name", "input", "output", "result", "is_error"] {
        if let Some(v) = event.metadata.get(key) {
            parts.insert(key, v.to_string());
        }
    }
    let blob = serde_json::to_string(&parts).unwrap_or_default();
    // Cheap non-crypto digest is fine for in-process dedupe equality.
    format!("{:x}", simple_hash(&blob))
}

fn simple_hash(s: &str) -> u64 {
    // FNV-1a 64-bit
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;

    #[tokio::test]
    async fn dedupes_tool_call_by_use_id_cross_source() {
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
        a.metadata
            .insert("input".into(), serde_json::json!({"cmd": "ls"}));
        a.metadata
            .insert("from_pty".into(), serde_json::json!(true));

        let mut b = a.clone();
        b.id = uuid::Uuid::new_v4().to_string();
        b.metadata.remove("from_pty");
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
        assert_eq!(
            w2.metadata.get("duplicate_reason").and_then(|v| v.as_str()),
            Some("same_tool_use_id_cross_source")
        );

        let events = store.get_events(&run.id).await.unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "tool.call").count(), 1);
        let h = writer.health_snapshot();
        assert_eq!(h.events_written, 1);
        assert_eq!(h.events_deduped, 1);
    }

    #[tokio::test]
    async fn preserves_idless_identical_tool_calls() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let writer = EventWriter::new(store.clone(), run.id.clone());

        for _ in 0..2 {
            let mut a = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
            a.metadata
                .insert("tool_name".into(), serde_json::json!("Bash"));
            a.metadata
                .insert("input".into(), serde_json::json!({"cmd": "cargo test"}));
            // no tool_use_id
            writer.write(a).await.unwrap();
        }

        let events = store.get_events(&run.id).await.unwrap();
        assert_eq!(
            events.iter().filter(|e| e.kind == "tool.call").count(),
            2,
            "ID-less retries must both be stored"
        );
        let h = writer.health_snapshot();
        assert_eq!(h.events_written, 2);
        assert_eq!(h.events_deduped, 0);
    }

    #[tokio::test]
    async fn payload_mismatch_prevents_dedupe() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let writer = EventWriter::new(store.clone(), run.id.clone());

        let mut a = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        a.metadata
            .insert("tool_use_id".into(), serde_json::json!("tu-same"));
        a.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        a.metadata
            .insert("input".into(), serde_json::json!({"cmd": "ls"}));

        let mut b = a.clone();
        b.id = uuid::Uuid::new_v4().to_string();
        b.metadata
            .insert("input".into(), serde_json::json!({"cmd": "pwd"}));

        writer.write(a).await.unwrap();
        writer.write(b).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "tool.call").count(), 2);
    }

    #[test]
    fn health_warning_on_many_slow_writes() {
        let h = WriterHealth {
            events_written: 40,
            events_deduped: 0,
            slow_writes: 12,
            max_write_ms: 200,
            total_write_ms: 3000,
            batch: None,
        };
        assert!(h.soft_warning().unwrap().contains("capture lag"));
        assert!(!h.is_healthy());
    }

    #[tokio::test]
    async fn batched_write_and_flush() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let writer = EventWriter::new_batched(store.clone(), run.id.clone());
        assert!(writer.is_batched());

        for i in 0..40 {
            let mut e = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
            e.metadata.insert("i".into(), serde_json::json!(i));
            writer.write(e).await.unwrap();
        }
        // Barrier event must be durable before write returns.
        let done = TraceEvent::new(&run.id, EventSource::System, "run.completed");
        writer.write(done).await.unwrap();

        assert_eq!(store.count_events(&run.id).await.unwrap(), 41);
        let h = writer.health_snapshot();
        assert_eq!(h.events_written, 41);
        assert!(h.batch.is_some());
        writer.shutdown().await.unwrap();
    }
}
