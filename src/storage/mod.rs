pub mod store;
pub mod sqlite;

use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Storage backend for run traces, events, checkpoints, and blobs.
///
/// The recommended MVP storage is SQLite for metadata +
/// a content-addressed blob store for large payloads.
#[async_trait::async_trait]
pub trait TraceStore: Send + Sync + 'static {
    // ── Runs ──

    /// Insert a new run record.
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()>;

    /// Update an existing run record.
    async fn update_run(&self, run: &Run) -> anyhow::Result<()>;

    /// Load a run by ID.
    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>>;

    /// List all runs, most recent first.
    async fn list_runs(&self) -> anyhow::Result<Vec<Run>>;

    /// Delete a run and its events/checkpoints.
    ///
    /// Blob files are left on disk; use scrub --gc to reclaim unreferenced blobs.
    async fn delete_run(&self, run_id: &str) -> anyhow::Result<bool>;

    // ── Events ──

    /// Append an event to a run's trace.
    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()>;

    /// Load events for a run in sequence order.
    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>>;

    /// Load a single event by ID.
    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>>;

    /// Replace an existing event (same id) with an updated version.
    async fn update_event(&self, event: &TraceEvent) -> anyhow::Result<()>;

    // ── Checkpoints ──

    /// Insert a checkpoint.
    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()>;

    /// Load checkpoints for a run.
    async fn get_checkpoints(&self, run_id: &str) -> anyhow::Result<Vec<Checkpoint>>;

    // ── Blobs ──

    /// Store blob content, returning a reference.
    async fn store_blob(&self, data: &[u8]) -> anyhow::Result<BlobReference>;

    /// Retrieve blob content by reference.
    async fn load_blob(&self, reference: &BlobReference) -> anyhow::Result<Vec<u8>>;

    /// Rename a blob from `from_key` to `to_key`.
    ///
    /// Used during portable archive import when the expected key differs
    /// from the content-addressed SHA-256 hash. Default is a no-op.
    async fn move_blob(
        &self,
        _from_key: &str,
        _to_key: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    // ── Search ──

    /// Full-text search over events when the backend supports it (e.g. SQLite FTS5).
    ///
    /// Returns `(event_id, run_id, rank)` ordered by relevance, or `None` if
    /// the backend has no FTS index (caller should fall back to scanning).
    async fn fts_event_ids(
        &self,
        _query: &str,
        _limit: usize,
    ) -> anyhow::Result<Option<Vec<(String, String, f64)>>> {
        Ok(None)
    }

    /// Insert multiple events atomically within a single transaction.
    ///
    /// Default implementation falls back to individual inserts (non-atomic).
    /// Backends SHOULD override with a transactional batch for atomicity.
    async fn insert_events_batch(&self, events: &[TraceEvent]) -> anyhow::Result<()> {
        for event in events {
            self.insert_event(event).await?;
        }
        Ok(())
    }

    /// Return all blob keys currently tracked in the blob metadata table.
    ///
    /// Used by scrub GC to cross-reference blobs table entries against
    /// event and checkpoint references. Returns empty vec on backends
    /// that do not maintain a blob metadata table.
    async fn all_blob_keys(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}
