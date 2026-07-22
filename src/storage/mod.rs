//! Trace storage: SQLite backend, blob keys, and pagination helpers.

/// Cursor / page types for run and event listing.
pub mod page;
/// SQLite-backed [`TraceStore`] implementation.
pub mod sqlite;
/// Shared store path helpers and open options.
pub mod store;

use crate::aggregates::RunAggregates;
use crate::boundary::{
    BoundaryFinding, ContainmentReceipt, EvidenceEdge, ProvenanceRecord, ResolvedBoundary,
    TraceIdentity,
};
use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::evidence::ExternalEvidenceEvent;
use crate::experiment::{ExperimentManifest, RunExperimentMeta};
use crate::incident::{Incident, IncidentPage, IncidentPageCursor};
use crate::verification::VerificationReceipt;

pub use page::{
    decode_event_cursor, decode_run_cursor, encode_event_cursor, encode_run_cursor, EventPage,
    EventPageCursor, RunFilters, RunPage, RunPageCursor,
};

#[async_trait::async_trait]
/// Storage backend for run traces, events, checkpoints, and blobs.
///
/// The recommended MVP storage is SQLite for metadata plus a
/// content-addressed blob store for large payloads.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use blackbox::storage::sqlite::SqliteStore;
/// use blackbox::storage::TraceStore;
/// use blackbox::core::run::Run;
///
/// # async fn demo() -> anyhow::Result<()> {
/// let store = Arc::new(SqliteStore::open_memory()?) as Arc<dyn TraceStore>;
/// let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
/// store.insert_run(&run).await?;
/// assert!(store.get_run(&run.id).await?.is_some());
/// # Ok(())
/// # }
/// ```
pub trait TraceStore: Send + Sync + 'static {
    // ── Runs ──

    /// Insert a new run record.
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()>;

    /// Update an existing run record.
    async fn update_run(&self, run: &Run) -> anyhow::Result<()>;

    /// Load a run by ID.
    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>>;

    /// List all runs, most recent first.
    ///
    /// Prefer [`Self::list_runs_page`] for large stores — this may load everything.
    async fn list_runs(&self) -> anyhow::Result<Vec<Run>>;

    /// Cursor-based run listing (most recent first). Does not load the full table.
    ///
    /// Default: full `list_runs` then slice (backends SHOULD override with SQL LIMIT).
    async fn list_runs_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
        filters: &RunFilters,
    ) -> anyhow::Result<RunPage> {
        let mut runs = self.list_runs().await?;
        if let Some(status) = &filters.status {
            let s = status.to_lowercase();
            runs.retain(|r| format!("{:?}", r.status).to_lowercase().contains(&s));
        }
        if let Some(tag) = &filters.tag {
            runs.retain(|r| r.tags.iter().any(|t| t == tag));
        }
        if let Some(cur) = cursor.and_then(decode_run_cursor) {
            runs.retain(|r| {
                r.started_at < cur.started_at
                    || (r.started_at == cur.started_at && r.id.as_str() < cur.id.as_str())
            });
        }
        let limit = limit.max(1);
        let has_more = runs.len() > limit;
        runs.truncate(limit);
        let next_cursor = if has_more {
            runs.last().map(|r| {
                encode_run_cursor(&RunPageCursor {
                    started_at: r.started_at,
                    id: r.id.clone(),
                })
            })
        } else {
            None
        };
        Ok(RunPage {
            runs,
            next_cursor,
            has_more,
        })
    }

    /// Delete a run and its events/checkpoints.
    ///
    /// Blob files are left on disk; use scrub --gc to reclaim unreferenced blobs.
    async fn delete_run(&self, run_id: &str) -> anyhow::Result<bool>;

    // ── Events ──

    /// Append an event to a run's trace.
    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()>;

    /// Load events for a run in sequence order.
    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>>;

    /// Load at most `limit` events (ascending sequence). Returns `(events, truncated)`.
    ///
    /// Default implementation loads all events then truncates (backends SHOULD
    /// override with SQL LIMIT). Prefer newest-first SQL + reverse for large runs.
    async fn get_events_limited(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<(Vec<TraceEvent>, bool)> {
        let all = self.get_events(run_id).await?;
        if all.len() <= limit {
            Ok((all, false))
        } else {
            // Prefer the *last* N events (tail of the run) for postmortem signal.
            let start = all.len() - limit;
            Ok((all[start..].to_vec(), true))
        }
    }

    /// Count events for a run. Default: full load length.
    async fn count_events(&self, run_id: &str) -> anyhow::Result<usize> {
        Ok(self.get_events(run_id).await?.len())
    }

    /// Load events with `sequence > after_seq`, ascending, up to `limit`.
    ///
    /// Used by live SSE to avoid reloading the entire run every tick.
    /// Default falls back to full scan + filter (backends SHOULD override).
    async fn get_events_since(
        &self,
        run_id: &str,
        after_seq: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        let all = self.get_events(run_id).await?;
        Ok(all
            .into_iter()
            .filter(|e| e.sequence > after_seq)
            .take(limit)
            .collect())
    }

    /// Range query: `after_sequence < sequence < before_sequence` (bounds optional via 0 / u64::MAX).
    ///
    /// Returns ascending sequence order. Default: filter in memory.
    async fn get_events_range(
        &self,
        run_id: &str,
        after_sequence: u64,
        before_sequence: u64,
        limit: usize,
    ) -> anyhow::Result<EventPage> {
        let limit = limit.max(1);
        let all = self.get_events(run_id).await?;
        let mut events: Vec<_> = all
            .into_iter()
            .filter(|e| e.sequence > after_sequence && e.sequence < before_sequence)
            .collect();
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if has_more {
            events.last().map(|e| {
                encode_event_cursor(&EventPageCursor {
                    sequence: e.sequence,
                })
            })
        } else {
            None
        };
        Ok(EventPage {
            events,
            next_cursor,
            has_more,
        })
    }

    /// Kind-filtered events with optional sequence cursor (exclusive lower bound).
    async fn get_events_by_kind_page(
        &self,
        run_id: &str,
        kinds: &[&str],
        cursor: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<EventPage> {
        let after = cursor
            .and_then(decode_event_cursor)
            .map(|c| c.sequence)
            .unwrap_or(0);
        let limit = limit.max(1);
        let all = self.get_events(run_id).await?;
        let mut events: Vec<_> = all
            .into_iter()
            .filter(|e| e.sequence > after && kinds.iter().any(|k| e.kind == *k))
            .collect();
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if has_more {
            events.last().map(|e| {
                encode_event_cursor(&EventPageCursor {
                    sequence: e.sequence,
                })
            })
        } else {
            None
        };
        Ok(EventPage {
            events,
            next_cursor,
            has_more,
        })
    }

    /// Load a single event by ID.
    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>>;

    /// Replace an existing event (same id) with an updated version.
    async fn update_event(&self, event: &TraceEvent) -> anyhow::Result<()>;

    // ── Checkpoints ──

    /// Insert a checkpoint.
    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()>;

    /// Update an existing checkpoint (same id). Default: re-insert is not used.
    async fn update_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()> {
        // Default: delete not available — backends SHOULD override with SQL UPDATE.
        let _ = cp;
        anyhow::bail!("update_checkpoint not supported by this store")
    }

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
    async fn move_blob(&self, _from_key: &str, _to_key: &str) -> anyhow::Result<()> {
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
    /// Used by scrub GC to find metadata rows that no longer have live
    /// event/checkpoint references. Returns empty vec on backends that do
    /// not maintain a blob metadata table.
    async fn all_blob_keys(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Delete blob metadata rows for the given keys.
    ///
    /// Used after orphan file GC so the `blobs` table does not retain rows
    /// for content that is no longer referenced. Does not remove on-disk
    /// files (callers use `gc_orphan_blobs` for that). Returns the number of
    /// rows deleted. Default is a no-op.
    async fn delete_blob_keys(&self, _keys: &[String]) -> anyhow::Result<usize> {
        Ok(0)
    }

    // ── Aggregates / salient queries (1.5 L1) ──

    /// Load incremental run aggregates when the backend stores them.
    ///
    /// Default: `None` (caller may recompute from events).
    async fn get_run_aggregates(&self, _run_id: &str) -> anyhow::Result<Option<RunAggregates>> {
        Ok(None)
    }

    /// Persist run aggregates (upsert). Default: no-op.
    async fn put_run_aggregates(&self, _agg: &RunAggregates) -> anyhow::Result<()> {
        Ok(())
    }

    /// Recompute aggregates from the full event table and store them.
    ///
    /// Default: load all events, recompute, put.
    async fn recompute_run_aggregates(&self, run_id: &str) -> anyhow::Result<RunAggregates> {
        let events = self.get_events(run_id).await?;
        let agg = RunAggregates::recompute(run_id, &events);
        self.put_run_aggregates(&agg).await?;
        Ok(agg)
    }

    /// Load first `limit` events by ascending sequence (run head).
    async fn get_events_head(&self, run_id: &str, limit: usize) -> anyhow::Result<Vec<TraceEvent>> {
        let all = self.get_events(run_id).await?;
        Ok(all.into_iter().take(limit).collect())
    }

    /// Load last `limit` events by ascending sequence (run tail).
    async fn get_events_tail(&self, run_id: &str, limit: usize) -> anyhow::Result<Vec<TraceEvent>> {
        let (events, _) = self.get_events_limited(run_id, limit).await?;
        Ok(events)
    }

    /// Load events matching any of the given kinds (ascending), up to `limit`.
    async fn get_events_by_kinds(
        &self,
        run_id: &str,
        kinds: &[&str],
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if kinds.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let all = self.get_events(run_id).await?;
        Ok(all
            .into_iter()
            .filter(|e| kinds.iter().any(|k| e.kind == *k))
            .take(limit)
            .collect())
    }

    /// Load events with Error status (ascending), up to `limit`.
    async fn get_error_events(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let all = self.get_events(run_id).await?;
        Ok(all
            .into_iter()
            .filter(|e| matches!(e.status, crate::core::event::EventStatus::Error))
            .take(limit)
            .collect())
    }

    // ── Verification receipts (1.6 Phase C) ──

    /// Insert an immutable verification receipt.
    async fn insert_verification_receipt(
        &self,
        _receipt: &VerificationReceipt,
    ) -> anyhow::Result<()> {
        anyhow::bail!("verification receipts not supported by this store backend")
    }

    /// List receipts for a run (oldest first).
    async fn list_verification_receipts(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Vec<VerificationReceipt>> {
        Ok(Vec::new())
    }

    /// Load one receipt by id.
    async fn get_verification_receipt(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<VerificationReceipt>> {
        Ok(None)
    }

    // ── Experiments (1.6 Phase D) ──

    /// Insert or update an experiment manifest.
    async fn upsert_experiment(&self, _manifest: &ExperimentManifest) -> anyhow::Result<()> {
        anyhow::bail!("experiments not supported by this store backend")
    }

    /// Load an experiment manifest by id.
    async fn get_experiment(&self, _id: &str) -> anyhow::Result<Option<ExperimentManifest>> {
        Ok(None)
    }

    /// List all experiment manifests.
    async fn list_experiments(&self) -> anyhow::Result<Vec<ExperimentManifest>> {
        Ok(Vec::new())
    }

    /// Attach typed experiment metadata to a run.
    async fn put_run_experiment_meta(
        &self,
        _run_id: &str,
        _meta: &RunExperimentMeta,
    ) -> anyhow::Result<()> {
        anyhow::bail!("run experiment meta not supported by this store backend")
    }

    /// Load experiment metadata for a run, if any.
    async fn get_run_experiment_meta(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Option<RunExperimentMeta>> {
        Ok(None)
    }

    /// List run ids linked to an experiment (stable order).
    async fn list_runs_for_experiment(
        &self,
        _experiment_id: &str,
    ) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Rebuild the full-text search index from events (1.6 fsck repair).
    /// Default is a no-op for backends without FTS.
    async fn reindex_fts(&self) -> anyhow::Result<usize> {
        Ok(0)
    }

    // ── Boundary contracts & containment (1.7) ──

    /// Store the immutable resolved boundary for a run (overwrite replaces prior).
    async fn put_run_boundary(
        &self,
        _boundary: &ResolvedBoundary,
    ) -> anyhow::Result<()> {
        anyhow::bail!("run boundaries not supported by this store backend")
    }

    /// Load the resolved boundary for a run, if any.
    async fn get_run_boundary(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Option<ResolvedBoundary>> {
        Ok(None)
    }

    /// Insert an immutable containment receipt.
    async fn insert_containment_receipt(
        &self,
        _receipt: &ContainmentReceipt,
    ) -> anyhow::Result<()> {
        anyhow::bail!("containment receipts not supported by this store backend")
    }

    /// List containment receipts for a run (oldest first).
    async fn list_containment_receipts(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Vec<ContainmentReceipt>> {
        Ok(Vec::new())
    }

    /// Load one containment receipt by id.
    async fn get_containment_receipt(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<ContainmentReceipt>> {
        Ok(None)
    }

    // ── External evidence, edges, identity, provenance, incidents (1.7) ──

    /// Insert external evidence event; returns false if duplicate (source, source_event_id).
    async fn insert_external_evidence(
        &self,
        _event: &ExternalEvidenceEvent,
    ) -> anyhow::Result<bool> {
        anyhow::bail!("external evidence not supported by this store backend")
    }

    /// List external evidence for a linked run (oldest first).
    async fn list_external_evidence_for_run(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Vec<ExternalEvidenceEvent>> {
        Ok(Vec::new())
    }

    /// List recent external evidence (newest first), bounded.
    async fn list_external_evidence(
        &self,
        _limit: usize,
    ) -> anyhow::Result<Vec<ExternalEvidenceEvent>> {
        Ok(Vec::new())
    }

    /// Get one external evidence event by id.
    async fn get_external_evidence(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<ExternalEvidenceEvent>> {
        Ok(None)
    }

    /// Insert an evidence correlation edge.
    async fn insert_evidence_edge(&self, _edge: &EvidenceEdge) -> anyhow::Result<()> {
        anyhow::bail!("evidence edges not supported by this store backend")
    }

    /// List edges for a run.
    async fn list_evidence_edges(&self, _run_id: &str) -> anyhow::Result<Vec<EvidenceEdge>> {
        Ok(Vec::new())
    }

    /// Store run trace identity.
    async fn put_trace_identity(&self, _identity: &TraceIdentity) -> anyhow::Result<()> {
        anyhow::bail!("trace identity not supported by this store backend")
    }

    /// Load run trace identity.
    async fn get_trace_identity(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Option<TraceIdentity>> {
        Ok(None)
    }

    /// Insert a provenance record.
    async fn insert_provenance_record(
        &self,
        _record: &ProvenanceRecord,
    ) -> anyhow::Result<()> {
        anyhow::bail!("provenance records not supported by this store backend")
    }

    /// List provenance records for a run.
    async fn list_provenance_records(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Vec<ProvenanceRecord>> {
        Ok(Vec::new())
    }

    /// Insert a boundary finding.
    async fn insert_boundary_finding(
        &self,
        _finding: &BoundaryFinding,
    ) -> anyhow::Result<()> {
        anyhow::bail!("boundary findings not supported by this store backend")
    }

    /// List boundary findings for a run.
    async fn list_boundary_findings(
        &self,
        _run_id: &str,
    ) -> anyhow::Result<Vec<BoundaryFinding>> {
        Ok(Vec::new())
    }

    /// Upsert an incident.
    async fn upsert_incident(&self, _incident: &Incident) -> anyhow::Result<()> {
        anyhow::bail!("incidents not supported by this store backend")
    }

    /// Get incident by id.
    async fn get_incident(&self, _id: &str) -> anyhow::Result<Option<Incident>> {
        Ok(None)
    }

    /// List incidents (newest first).
    async fn list_incidents(&self) -> anyhow::Result<Vec<Incident>> {
        Ok(Vec::new())
    }

    /// Cursor page of incidents (newest first). Default uses full list + in-memory page.
    async fn list_incidents_page(
        &self,
        cursor: Option<&IncidentPageCursor>,
        limit: usize,
    ) -> anyhow::Result<IncidentPage> {
        let all = self.list_incidents().await?;
        Ok(crate::incident::page_incidents(&all, cursor, limit))
    }
}
