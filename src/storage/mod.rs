pub mod store;

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

    // ── Events ──

    /// Append an event to a run's trace.
    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()>;

    /// Load events for a run in sequence order.
    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>>;

    /// Load a single event by ID.
    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>>;

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
}
