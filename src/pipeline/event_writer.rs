//! Single-writer event ingress with a monotonic sequence counter.
//!
//! All capture paths (PTY, git, fs, process, adapters) should funnel
//! through an `EventWriter` so sequence numbers and persistence stay consistent.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::core::event::TraceEvent;
use crate::storage::TraceStore;

/// Owns the per-run sequence counter and persists events.
pub struct EventWriter {
    store: Arc<dyn TraceStore>,
    seq: AtomicU64,
    run_id: String,
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
    pub async fn write(&self, mut event: TraceEvent) -> anyhow::Result<TraceEvent> {
        if event.run_id.is_empty() {
            event.run_id = self.run_id.clone();
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
