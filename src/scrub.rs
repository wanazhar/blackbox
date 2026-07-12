//! Re-redact historical traces that may contain secrets at rest.

use std::sync::Arc;

use anyhow::Context;

use crate::core::blob::BlobReference;
use crate::core::event::TraceEvent;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;

/// Result of a scrub pass.
#[derive(Debug, Default, Clone)]
pub struct ScrubReport {
    pub runs_scanned: usize,
    pub runs_updated: usize,
    pub events_scanned: usize,
    pub events_updated: usize,
    pub checkpoints_scanned: usize,
    pub blobs_rewritten: usize,
    pub dry_run: bool,
}

/// Scrub secrets from all runs/events/blobs in the store.
pub async fn scrub_store(
    store: Arc<dyn TraceStore>,
    dry_run: bool,
    run_filter: Option<&str>,
    redaction_config: Option<RedactionConfig>,
) -> anyhow::Result<ScrubReport> {
    let config = redaction_config.unwrap_or_default();
    let scanner = SecretScanner::new(config);
    let mut report = ScrubReport {
        dry_run,
        ..Default::default()
    };

    let runs = store.list_runs().await?;
    for mut run in runs {
        if let Some(filter) = run_filter {
            if filter != "all" && run.id != filter && !run.id.starts_with(filter) {
                continue;
            }
        }
        report.runs_scanned += 1;

        let mut run_dirty = false;
        let redacted_cmd = scanner.redact_command(&run.command);
        if redacted_cmd != run.command {
            run.command = redacted_cmd;
            run_dirty = true;
        }
        if let Some(ref notes) = run.notes {
            let n = scanner.redact(notes);
            if n != *notes {
                run.notes = Some(n);
                run_dirty = true;
            }
        }
        if run_dirty {
            report.runs_updated += 1;
            if !dry_run {
                store.update_run(&run).await?;
            }
        }

        let events = store.get_events(&run.id).await?;
        for event in events {
            report.events_scanned += 1;
            if let Some(updated) =
                scrub_event(store.as_ref(), &scanner, event, dry_run, &mut report).await?
            {
                report.events_updated += 1;
                if !dry_run {
                    store.update_event(&updated).await?;
                }
            }
        }
    }

    Ok(report)
}

async fn scrub_event(
    store: &dyn TraceStore,
    scanner: &SecretScanner,
    mut event: TraceEvent,
    dry_run: bool,
    report: &mut ScrubReport,
) -> anyhow::Result<Option<TraceEvent>> {
    let mut dirty = false;

    // Redact metadata JSON strings
    let mut meta = serde_json::to_value(&event.metadata).unwrap_or_else(|_| serde_json::json!({}));
    let before = meta.clone();
    scanner.redact_json(&mut meta);
    if meta != before {
        if let Ok(m) = serde_json::from_value(meta) {
            event.metadata = m;
            dirty = true;
        }
    }

    // Drop legacy raw plaintext fields entirely (never keep secrets at rest)
    if event.metadata.remove("raw").is_some() {
        dirty = true;
    }

    // Rewrite output / input / error blobs if they contain secrets
    for field in ["output", "input", "error"] {
        let key_slot = match field {
            "output" => &mut event.output_blob,
            "input" => &mut event.input_blob,
            "error" => &mut event.error_blob,
            _ => unreachable!(),
        };
        if let Some(key) = key_slot.clone() {
            if let Some(bref) = BlobReference::try_new(key.clone(), 0) {
                match store.load_blob(&bref).await {
                    Ok(data) => {
                        // Prefer UTF-8 redaction; binary left alone unless it looks like text
                        if let Ok(text) = std::str::from_utf8(&data) {
                            let redacted = scanner.redact(text);
                            if redacted.as_bytes() != data.as_slice() {
                                dirty = true;
                                report.blobs_rewritten += 1;
                                if !dry_run {
                                    let new_ref = store.store_blob(redacted.as_bytes()).await?;
                                    *key_slot = Some(new_ref.key);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, blob = %key, "scrub: blob missing, skipping");
                    }
                }
            } else {
                tracing::debug!(blob = %key, "scrub: invalid blob key, skipping");
            }
        }
    }

    Ok(if dirty { Some(event) } else { None })
}

/// Human-readable summary line.
pub fn format_report(report: &ScrubReport) -> String {
    format!(
        "{}runs={}/{} events={}/{} checkpoints={} blobs_rewritten={}{}",
        if report.dry_run { "[dry-run] " } else { "" },
        report.runs_updated,
        report.runs_scanned,
        report.events_updated,
        report.events_scanned,
        report.checkpoints_scanned,
        report.blobs_rewritten,
        if report.dry_run {
            " (no changes written)"
        } else {
            ""
        }
    )
}

/// Collect every blob key still referenced by runs/events/checkpoints.
///
/// Only live references count. Keys that merely exist in the `blobs`
/// metadata table (e.g. after `delete_run`, or after scrub rewrote a secret
/// blob to a new key) are *not* treated as live — callers must GC those.
pub async fn collect_referenced_blobs(
    store: &dyn TraceStore,
) -> anyhow::Result<std::collections::HashSet<String>> {
    use std::collections::HashSet;
    let mut keys = HashSet::new();

    for run in store.list_runs().await? {
        for ev in store.get_events(&run.id).await? {
            if let Some(k) = ev.output_blob {
                keys.insert(k);
            }
            if let Some(k) = ev.input_blob {
                keys.insert(k);
            }
            if let Some(k) = ev.error_blob {
                keys.insert(k);
            }
            // Check all metadata values for 64-char hex blob references
            for v in ev.metadata.values() {
                if let Some(s) = v.as_str() {
                    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                        keys.insert(s.to_string());
                    }
                }
            }
        }
        for cp in store.get_checkpoints(&run.id).await? {
            if let Some(k) = cp.git_diff_blob {
                keys.insert(k);
            }
            if let Some(k) = cp.filesystem_manifest_blob {
                keys.insert(k);
            }
            if let Some(k) = cp.environment_blob {
                keys.insert(k);
            }
            if let Some(k) = cp.transcript_blob {
                keys.insert(k);
            }
        }
    }
    Ok(keys)
}

/// Delete blob files on disk that are not referenced. Returns count deleted.
pub async fn gc_orphan_blobs(
    blob_dir: &std::path::Path,
    referenced: &std::collections::HashSet<String>,
    dry_run: bool,
) -> anyhow::Result<usize> {
    let blob_dir = blob_dir.to_path_buf();
    let referenced = referenced.clone();
    tokio::task::spawn_blocking(move || {
        if !blob_dir.is_dir() {
            return Ok(0usize);
        }
        let mut deleted = 0usize;
        for entry in std::fs::read_dir(&blob_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Content-addressed keys are 64-char hex
            if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if !referenced.contains(&name) {
                let should_count = if dry_run {
                    true
                } else {
                    std::fs::remove_file(entry.path()).is_ok()
                };
                if should_count {
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    })
    .await
    .context("spawn_blocking panicked for gc_orphan_blobs")?
}

/// Full GC pass: remove unreferenced blob files *and* their metadata rows.
///
/// Returns `(files_deleted, metadata_rows_deleted)`.
///
/// Note: do not run while an active recording may be writing blobs that are
/// not yet linked from events — the race window can reclaim in-flight content.
pub async fn gc_unreferenced_blobs(
    store: &dyn TraceStore,
    blob_dir: &std::path::Path,
    dry_run: bool,
) -> anyhow::Result<(usize, usize)> {
    let referenced = collect_referenced_blobs(store).await?;
    let files = gc_orphan_blobs(blob_dir, &referenced, dry_run).await?;

    // Prune metadata rows that have no live event/checkpoint reference.
    // (R2-H3: earlier "fix" treated every blobs-table key as live, which
    // made GC a no-op and left secret-bearing blobs after scrub rewrites.)
    let all_keys = store.all_blob_keys().await.unwrap_or_default();
    let orphan_keys: Vec<String> = all_keys
        .into_iter()
        .filter(|k| !referenced.contains(k))
        .collect();
    let meta = if dry_run {
        orphan_keys.len()
    } else if orphan_keys.is_empty() {
        0
    } else {
        store.delete_blob_keys(&orphan_keys).await?
    };
    Ok((files, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;

    #[tokio::test]
    async fn scrub_removes_secret_from_command_and_metadata() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(
            vec![
                "sh".into(),
                "-c".into(),
                "echo sk-abcdefghijklmnopqrstuvwxyz012345".into(),
            ],
            "/tmp".into(),
        );
        store.insert_run(&run).await.unwrap();

        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.metadata.insert(
            "preview".into(),
            serde_json::json!("token sk-abcdefghijklmnopqrstuvwxyz012345"),
        );
        ev.metadata.insert(
            "raw".into(),
            serde_json::json!("sk-abcdefghijklmnopqrstuvwxyz012345"),
        );
        store.insert_event(&ev).await.unwrap();

        let report = scrub_store(store.clone(), false, Some("all"), None)
            .await
            .unwrap();
        assert!(report.runs_updated >= 1);
        assert!(report.events_updated >= 1);

        let loaded = store.get_run(&run.id).await.unwrap().unwrap();
        assert!(!loaded.command.join(" ").contains("sk-abcdef"));

        let events = store.get_events(&run.id).await.unwrap();
        let preview = events[0]
            .metadata
            .get("preview")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(preview.contains("[REDACTED]"));
        assert!(!events[0].metadata.contains_key("raw"));
    }
    #[tokio::test]
    async fn test_scrub_rewrites_blobs() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["echo".into(), "test".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();

        let secret_content = b"output from command:AKIAIOSFODNN7EXAMPLE";
        let blob_ref = store.store_blob(secret_content).await.unwrap();
        let original_key = blob_ref.key.clone();

        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.output_blob = Some(original_key.clone());
        store.insert_event(&ev).await.unwrap();

        let report = scrub_store(store.clone(), false, Some("all"), None)
            .await
            .unwrap();

        assert!(
            report.blobs_rewritten >= 1,
            "expected blobs_rewritten >= 1, got {}",
            report.blobs_rewritten
        );

        let events = store.get_events(&run.id).await.unwrap();
        let new_key = events[0].output_blob.as_ref().unwrap();
        assert_ne!(new_key, &original_key, "blob key should change after scrub");

        let new_blob = store
            .load_blob(&crate::core::blob::BlobReference::new(new_key.clone(), 0))
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&new_blob);
        assert!(
            !text.contains("AKIAIOSFODNN7"),
            "secret must not appear in scrubbed blob: {text}"
        );
        assert!(text.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn gc_removes_unreferenced_blob_after_delete_run() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();
        let store = SqliteStore::open_with_blobs(&db, &blob_dir).unwrap();

        let run = crate::core::run::Run::new(vec!["echo".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let blob = store.store_blob(b"orphan-after-delete").await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.output_blob = Some(blob.key.clone());
        store.insert_event(&ev).await.unwrap();

        // Blob file and metadata exist
        assert!(blob_dir.join(&blob.key).exists());
        assert!(store.all_blob_keys().await.unwrap().contains(&blob.key));

        // Delete run → event reference gone; blob remains until GC
        assert!(store.delete_run(&run.id).await.unwrap());
        assert!(blob_dir.join(&blob.key).exists());

        let (files, meta) = gc_unreferenced_blobs(&store, &blob_dir, false)
            .await
            .unwrap();
        assert_eq!(files, 1, "should delete orphan blob file");
        assert_eq!(meta, 1, "should prune orphan blobs-table row");
        assert!(!blob_dir.join(&blob.key).exists());
        assert!(!store.all_blob_keys().await.unwrap().contains(&blob.key));
    }

    #[tokio::test]
    async fn gc_preserves_still_referenced_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();
        let store = SqliteStore::open_with_blobs(&db, &blob_dir).unwrap();

        let run = crate::core::run::Run::new(vec!["echo".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let blob = store.store_blob(b"keep-me").await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.output_blob = Some(blob.key.clone());
        store.insert_event(&ev).await.unwrap();

        let (files, meta) = gc_unreferenced_blobs(&store, &blob_dir, false)
            .await
            .unwrap();
        assert_eq!(files, 0);
        assert_eq!(meta, 0);
        assert!(blob_dir.join(&blob.key).exists());
    }

    #[tokio::test]
    async fn gc_reclaims_old_blob_after_scrub_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();
        let store = Arc::new(SqliteStore::open_with_blobs(&db, &blob_dir).unwrap());

        let run = crate::core::run::Run::new(vec!["echo".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let secret = b"token AKIAIOSFODNN7EXAMPLE leftover";
        let old = store.store_blob(secret).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.output_blob = Some(old.key.clone());
        store.insert_event(&ev).await.unwrap();

        scrub_store(store.clone(), false, Some("all"), None)
            .await
            .unwrap();
        let events = store.get_events(&run.id).await.unwrap();
        let new_key = events[0].output_blob.as_ref().unwrap().clone();
        assert_ne!(new_key, old.key);
        // Old secret blob still on disk until GC
        assert!(blob_dir.join(&old.key).exists());

        let (files, meta) = gc_unreferenced_blobs(store.as_ref(), &blob_dir, false)
            .await
            .unwrap();
        assert!(files >= 1, "old secret blob file must be reclaimed");
        assert!(meta >= 1, "old secret blob metadata must be pruned");
        assert!(!blob_dir.join(&old.key).exists());
        assert!(blob_dir.join(&new_key).exists());
    }
}
