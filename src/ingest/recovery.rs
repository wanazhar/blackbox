//! Crash recovery: promote pending spool batches into SQLite idempotently.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;

use crate::storage::TraceStore;

use super::spool::EventSpool;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecoveryStats {
    pub batches_seen: usize,
    pub batches_replayed: usize,
    pub events_inserted: usize,
    pub events_skipped_duplicate: usize,
    pub errors: Vec<String>,
}

/// On store open: replay any pending spool batches. Event IDs make inserts idempotent
/// when the store rejects or we skip existing IDs.
pub async fn recover_spool_on_open(
    store: Arc<dyn TraceStore>,
    spool_dir: &Path,
) -> anyhow::Result<RecoveryStats> {
    if !spool_dir.exists() {
        return Ok(RecoveryStats::default());
    }
    let spool = EventSpool::open(spool_dir)?;
    let mut stats = RecoveryStats::default();
    let pending = spool.list_pending()?;
    stats.batches_seen = pending.len();

    for batch in pending {
        // Filter out events already present (idempotent replay).
        let mut to_insert = Vec::new();
        for ev in batch.events {
            match store.get_event(&ev.id).await {
                Ok(Some(_)) => stats.events_skipped_duplicate += 1,
                Ok(None) => to_insert.push(ev),
                Err(e) => {
                    stats.errors.push(format!("lookup {}: {e}", ev.id));
                }
            }
        }
        if !to_insert.is_empty() {
            // Ensure parent runs exist for events (best-effort: skip orphans).
            let mut by_run: std::collections::HashMap<String, Vec<_>> =
                std::collections::HashMap::new();
            for ev in to_insert {
                by_run.entry(ev.run_id.clone()).or_default().push(ev);
            }
            for (run_id, events) in by_run {
                if store.get_run(&run_id).await?.is_none() {
                    stats.errors.push(format!(
                        "spool batch {} references missing run {}",
                        batch.batch_id, run_id
                    ));
                    continue;
                }
                // Dedup within batch by id
                let mut seen = HashSet::new();
                let events: Vec<_> = events
                    .into_iter()
                    .filter(|e| seen.insert(e.id.clone()))
                    .collect();
                let n = events.len();
                match store.insert_events_batch(&events).await {
                    Ok(()) => {
                        stats.events_inserted += n;
                        stats.batches_replayed += 1;
                    }
                    Err(e) => {
                        // Fall back to per-event insert for partial progress.
                        for ev in events {
                            match store.insert_event(&ev).await {
                                Ok(()) => stats.events_inserted += 1,
                                Err(ie) => {
                                    // Unique constraint → already present
                                    if ie.to_string().to_lowercase().contains("unique") {
                                        stats.events_skipped_duplicate += 1;
                                    } else {
                                        stats.errors.push(format!("insert {}: {ie}", ev.id));
                                    }
                                }
                            }
                        }
                        stats.batches_replayed += 1;
                        let _ = e;
                    }
                }
            }
        } else {
            stats.batches_replayed += 1;
        }
        if let Err(e) = spool.acknowledge(&batch.batch_id) {
            stats.errors.push(format!("ack {}: {e}", batch.batch_id));
        }
    }
    Ok(stats)
}
