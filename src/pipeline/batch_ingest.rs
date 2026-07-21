//! Bounded queue + dedicated micro-batch SQLite writer (1.5 S1).
//!
//! Capture producers enqueue events without blocking on per-event SQLite
//! transactions. A single background task flushes micro-batches on size,
//! time, barrier kinds, or explicit flush/shutdown.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use crate::core::event::TraceEvent;
use crate::storage::TraceStore;

/// Default micro-batch size (issue suggests 32–128).
pub const DEFAULT_BATCH_SIZE: usize = 64;
/// Default flush interval (issue suggests 5–20 ms).
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(10);
/// Bounded queue — full queue applies backpressure (no silent drops).
pub const DEFAULT_QUEUE_CAPACITY: usize = 4_096;

/// Configuration for [`BatchIngestor`].
#[derive(Debug, Clone)]
pub struct BatchIngestConfig {
    /// Max batch.
    pub max_batch: usize,
    /// Flush interval.
    pub flush_interval: Duration,
    /// Queue capacity.
    pub queue_capacity: usize,
}

impl Default for BatchIngestConfig {
    fn default() -> Self {
        Self {
            max_batch: DEFAULT_BATCH_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

/// Observable batch-ingest counters.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BatchIngestHealth {
    /// Events enqueued.
    pub events_enqueued: u64,
    /// Events flushed.
    pub events_flushed: u64,
    /// Batches.
    pub batches: u64,
    /// Barriers.
    pub barriers: u64,
    /// Max batch size.
    pub max_batch_size: u64,
    /// Max flush ms.
    pub max_flush_ms: u64,
    /// Total flush ms.
    pub total_flush_ms: u64,
    /// Queue high water.
    pub queue_high_water: u64,
    /// Write failures.
    pub write_failures: u64,
    /// Events accepted into the queue but not yet flushed (best-effort gauge).
    pub pending: u64,
    /// Lost events after a failed flush (cleared buffer; spool may still hold them).
    #[serde(default)]
    pub lost_events: u64,
    /// Spool append failures (disk full / permission).
    #[serde(default)]
    pub spool_failures: u64,
    /// Writer boundary: dedicated OS thread (1.6).
    #[serde(default)]
    pub dedicated_thread: bool,
}

/// Messages to the dedicated writer task.
enum IngestMsg {
    Event {
        event: Box<TraceEvent>,
        /// When set, flush through this event before completing the ack.
        barrier: bool,
        ack: Option<oneshot::Sender<anyhow::Result<()>>>,
    },
    Flush {
        ack: oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown {
        ack: oneshot::Sender<anyhow::Result<()>>,
    },
}

/// Cloneable handle that enqueues events into a dedicated batch writer.
#[derive(Clone)]
pub struct BatchIngestor {
    tx: mpsc::Sender<IngestMsg>,
    health: Arc<BatchIngestHealthShared>,
    queue_depth: Arc<AtomicU64>,
}

struct BatchIngestHealthShared {
    events_enqueued: AtomicU64,
    events_flushed: AtomicU64,
    batches: AtomicU64,
    barriers: AtomicU64,
    max_batch_size: AtomicU64,
    max_flush_ms: AtomicU64,
    total_flush_ms: AtomicU64,
    queue_high_water: AtomicU64,
    write_failures: AtomicU64,
    lost_events: AtomicU64,
    spool_failures: AtomicU64,
}

impl BatchIngestHealthShared {
    fn new() -> Self {
        Self {
            events_enqueued: AtomicU64::new(0),
            events_flushed: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            barriers: AtomicU64::new(0),
            max_batch_size: AtomicU64::new(0),
            max_flush_ms: AtomicU64::new(0),
            total_flush_ms: AtomicU64::new(0),
            queue_high_water: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            lost_events: AtomicU64::new(0),
            spool_failures: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, pending: u64) -> BatchIngestHealth {
        BatchIngestHealth {
            events_enqueued: self.events_enqueued.load(Ordering::Relaxed),
            events_flushed: self.events_flushed.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            barriers: self.barriers.load(Ordering::Relaxed),
            max_batch_size: self.max_batch_size.load(Ordering::Relaxed),
            max_flush_ms: self.max_flush_ms.load(Ordering::Relaxed),
            total_flush_ms: self.total_flush_ms.load(Ordering::Relaxed),
            queue_high_water: self.queue_high_water.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            pending,
            lost_events: self.lost_events.load(Ordering::Relaxed),
            spool_failures: self.spool_failures.load(Ordering::Relaxed),
            dedicated_thread: true,
        }
    }
}

impl BatchIngestor {
    /// Spawn a dedicated batch writer task and return a handle.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `spawn` — see module docs for full workflow.
    /// ```
    pub fn spawn(store: Arc<dyn TraceStore>, config: BatchIngestConfig) -> Self {
        Self::spawn_with_spool(store, config, None)
    }

    /// Spawn with optional durable spool (1.6). When set, events are appended to
    /// the spool before SQLite commit; producer acks mean recoverability.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `spawn_with_spool` — see module docs for full workflow.
    /// ```
    pub fn spawn_with_spool(
        store: Arc<dyn TraceStore>,
        config: BatchIngestConfig,
        spool: Option<Arc<crate::ingest::EventSpool>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(config.queue_capacity.max(8));
        let health = Arc::new(BatchIngestHealthShared::new());
        let queue_depth = Arc::new(AtomicU64::new(0));
        let health_w = health.clone();
        let depth_w = queue_depth.clone();
        // Dedicated OS thread + current-thread runtime so SQLite/spool I/O never
        // occupies a Tokio multi-thread worker (1.6 durable-ingest acceptance).
        std::thread::Builder::new()
            .name("blackbox-ingest".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build ingest runtime");
                        return;
                    }
                };
                rt.block_on(batch_writer_loop(
                    store, rx, config, health_w, depth_w, spool,
                ));
            })
            .expect("failed to spawn blackbox-ingest thread");
        Self {
            tx,
            health,
            queue_depth,
        }
    }

    /// Enqueue an event. When `barrier` is true, wait until it is durably flushed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `enqueue` — see module docs for full workflow.
    /// ```
    pub async fn enqueue(&self, event: TraceEvent, barrier: bool) -> anyhow::Result<()> {
        self.health.events_enqueued.fetch_add(1, Ordering::Relaxed);
        let depth = self.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        self.health
            .queue_high_water
            .fetch_max(depth, Ordering::Relaxed);

        if barrier {
            self.health.barriers.fetch_add(1, Ordering::Relaxed);
            let (ack_tx, ack_rx) = oneshot::channel();
            self.tx
                .send(IngestMsg::Event {
                    event: Box::new(event),
                    barrier: true,
                    ack: Some(ack_tx),
                })
                .await
                .map_err(|_| anyhow::anyhow!("batch ingest queue closed"))?;
            ack_rx
                .await
                .map_err(|_| anyhow::anyhow!("batch ingest worker dropped ack"))??;
            Ok(())
        } else {
            self.tx
                .send(IngestMsg::Event {
                    event: Box::new(event),
                    barrier: false,
                    ack: None,
                })
                .await
                .map_err(|_| anyhow::anyhow!("batch ingest queue closed"))?;
            Ok(())
        }
    }

    /// Flush all pending events and wait for durability.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `flush` — see module docs for full workflow.
    /// ```
    pub async fn flush(&self) -> anyhow::Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(IngestMsg::Flush { ack: ack_tx })
            .await
            .map_err(|_| anyhow::anyhow!("batch ingest queue closed"))?;
        ack_rx
            .await
            .map_err(|_| anyhow::anyhow!("batch ingest worker dropped flush ack"))?
    }

    /// Flush remaining events and stop the worker.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `shutdown` — see module docs for full workflow.
    /// ```
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        // Ignore send error if already shut down.
        if self
            .tx
            .send(IngestMsg::Shutdown { ack: ack_tx })
            .await
            .is_err()
        {
            return Ok(());
        }
        match ack_rx.await {
            Ok(r) => r,
            Err(_) => Ok(()),
        }
    }

    /// Health snapshot.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `health_snapshot` — see module docs for full workflow.
    /// ```
    pub fn health_snapshot(&self) -> BatchIngestHealth {
        self.health
            .snapshot(self.queue_depth.load(Ordering::Relaxed))
    }

    /// Queue depth.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `queue_depth` — see module docs for full workflow.
    /// ```
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }
}

/// Kinds that must be durably written before `write()` returns (1.5 barriers).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_barrier_kind` — see module docs for full workflow.
/// ```
pub fn is_barrier_kind(kind: &str) -> bool {
    matches!(
        kind,
        "run.started"
            | "run.completed"
            | "run.failed"
            | "run.cancelled"
            | "capture.layer.failed"
            | "capture.coverage"
            | "capture.warning"
            | "environment.captured"
    ) || kind.starts_with("checkpoint.")
}

async fn batch_writer_loop(
    store: Arc<dyn TraceStore>,
    mut rx: mpsc::Receiver<IngestMsg>,
    config: BatchIngestConfig,
    health: Arc<BatchIngestHealthShared>,
    queue_depth: Arc<AtomicU64>,
    spool: Option<Arc<crate::ingest::EventSpool>>,
) {
    let mut pending: Vec<TraceEvent> = Vec::with_capacity(config.max_batch);
    // Acks waiting for the next successful flush of current pending buffer.
    let mut pending_acks: Vec<oneshot::Sender<anyhow::Result<()>>> = Vec::new();
    let mut last_flush = Instant::now();
    let mut interval = tokio::time::interval(config.flush_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick completes immediately; skip so we don't flush empty.
    interval.tick().await;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    None => {
                        // Channel closed — final flush.
                        let _ = flush_pending(
                            store.as_ref(),
                            spool.as_deref(),
                            &mut pending,
                            &mut pending_acks,
                            &health,
                        )
                        .await;
                        break;
                    }
                    Some(IngestMsg::Event { event, barrier, ack }) => {
                        queue_depth.fetch_sub(1, Ordering::Relaxed);
                        pending.push(*event);
                        if let Some(a) = ack {
                            pending_acks.push(a);
                        }
                        let force = barrier || pending.len() >= config.max_batch;
                        if force {
                            if let Err(e) = flush_pending(
                                store.as_ref(),
                                spool.as_deref(),
                                &mut pending,
                                &mut pending_acks,
                                &health,
                            )
                            .await
                            {
                                tracing::error!(error = %e, "batch ingest flush failed");
                            }
                            last_flush = Instant::now();
                        }
                    }
                    Some(IngestMsg::Flush { ack }) => {
                        let result = flush_pending(
                            store.as_ref(),
                            spool.as_deref(),
                            &mut pending,
                            &mut pending_acks,
                            &health,
                        )
                        .await;
                        last_flush = Instant::now();
                        let _ = ack.send(result);
                    }
                    Some(IngestMsg::Shutdown { ack }) => {
                        let result = flush_pending(
                            store.as_ref(),
                            spool.as_deref(),
                            &mut pending,
                            &mut pending_acks,
                            &health,
                        )
                        .await;
                        let _ = ack.send(result);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !pending.is_empty() && last_flush.elapsed() >= config.flush_interval {
                    if let Err(e) = flush_pending(
                        store.as_ref(),
                        spool.as_deref(),
                        &mut pending,
                        &mut pending_acks,
                        &health,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "timed batch flush failed");
                    }
                    last_flush = Instant::now();
                }
            }
        }
    }
}

async fn flush_pending(
    store: &dyn TraceStore,
    spool: Option<&crate::ingest::EventSpool>,
    pending: &mut Vec<TraceEvent>,
    pending_acks: &mut Vec<oneshot::Sender<anyhow::Result<()>>>,
    health: &BatchIngestHealthShared,
) -> anyhow::Result<()> {
    if pending.is_empty() {
        // Still complete any stray acks.
        for ack in pending_acks.drain(..) {
            let _ = ack.send(Ok(()));
        }
        return Ok(());
    }
    let n = pending.len() as u64;
    let t0 = Instant::now();

    // Durable path: append to spool first so producer-visible success can be
    // recovered after crash even if SQLite commit has not finished.
    let spool_batch_id = if let Some(sp) = spool {
        match sp.append_batch(pending) {
            Ok(r) => Some(r.batch_id),
            Err(e) => {
                health.write_failures.fetch_add(1, Ordering::Relaxed);
                health.spool_failures.fetch_add(1, Ordering::Relaxed);
                let msg = format!("spool append failed (disk full or I/O): {e}");
                for ack in pending_acks.drain(..) {
                    let _ = ack.send(Err(anyhow::anyhow!("{msg}")));
                }
                // Do not clear pending here — caller may retry; disk-full is backpressure.
                return Err(anyhow::anyhow!(msg));
            }
        }
    } else {
        None
    };

    let result = store.insert_events_batch(pending).await;
    let ms = t0.elapsed().as_millis() as u64;

    health.batches.fetch_add(1, Ordering::Relaxed);
    health.max_batch_size.fetch_max(n, Ordering::Relaxed);
    health.max_flush_ms.fetch_max(ms, Ordering::Relaxed);
    health.total_flush_ms.fetch_add(ms, Ordering::Relaxed);

    match result {
        Ok(()) => {
            if let (Some(sp), Some(id)) = (spool, spool_batch_id) {
                if let Err(e) = sp.acknowledge(&id) {
                    tracing::warn!(error = %e, batch = %id, "spool ack after commit failed");
                }
            }
            health.events_flushed.fetch_add(n, Ordering::Relaxed);
            pending.clear();
            for ack in pending_acks.drain(..) {
                let _ = ack.send(Ok(()));
            }
            Ok(())
        }
        Err(e) => {
            health.write_failures.fetch_add(1, Ordering::Relaxed);
            let msg = e.to_string();
            for ack in pending_acks.drain(..) {
                let _ = ack.send(Err(anyhow::anyhow!("{msg}")));
            }
            // Leave spool pending so recovery can replay. Clear memory buffer
            // to avoid double-insert from subsequent flushes of the same events.
            let lost = pending.len() as u64;
            if spool.is_none() {
                // Without spool, cleared buffer is a real loss boundary.
                health.lost_events.fetch_add(lost, Ordering::Relaxed);
            }
            pending.clear();
            Err(anyhow::anyhow!(
                "batch flush failed after {lost} pending event(s) (spool retained for recovery when enabled): {msg}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::EventSource;
    use crate::core::run::Run;
    use crate::storage::sqlite::SqliteStore;

    #[tokio::test]
    async fn batches_multiple_events() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();

        let ingest = BatchIngestor::spawn(
            store.clone(),
            BatchIngestConfig {
                max_batch: 8,
                flush_interval: Duration::from_millis(50),
                queue_capacity: 64,
            },
        );

        for i in 0..20 {
            let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
            e.sequence = i + 1;
            ingest.enqueue(e, false).await.unwrap();
        }
        ingest.flush().await.unwrap();
        assert_eq!(store.count_events(&run.id).await.unwrap(), 20);
        let h = ingest.health_snapshot();
        assert!(h.batches >= 1);
        assert_eq!(h.events_flushed, 20);
        ingest.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn barrier_flushes_immediately() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();

        let ingest = BatchIngestor::spawn(
            store.clone(),
            BatchIngestConfig {
                max_batch: 10_000,
                flush_interval: Duration::from_secs(60),
                queue_capacity: 64,
            },
        );

        let mut e = TraceEvent::new(&run.id, EventSource::System, "run.completed");
        e.sequence = 1;
        // barrier=true must return only after durable write despite huge max_batch.
        ingest.enqueue(e, true).await.unwrap();
        assert_eq!(store.count_events(&run.id).await.unwrap(), 1);
        ingest.shutdown().await.unwrap();
    }

    #[test]
    fn barrier_kinds() {
        assert!(is_barrier_kind("run.completed"));
        assert!(is_barrier_kind("capture.coverage"));
        assert!(is_barrier_kind("checkpoint.created"));
        assert!(!is_barrier_kind("terminal.output"));
        assert!(!is_barrier_kind("tool.call"));
    }
}
