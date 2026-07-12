//! Multi-machine sync via a shared directory of portable archives.
//!
//! Layout:
//! ```text
//! <dir>/
//!   manifest.json
//!   runs/<run_id>.json   # portable v2 (with blobs)
//! ```
//!
//! Designed for rsync/NFS/Dropbox-style folders. Push exports local runs
//! missing (or outdated) remotely; pull imports remote runs missing locally.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::export::portable::{export_portable, import_portable};
use crate::storage::TraceStore;

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncManifest {
    pub version: u32,
    /// run_id → metadata
    pub runs: HashMap<String, SyncRunEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRunEntry {
    pub file: String,
    pub sha256: String,
    pub exported_at: String,
    pub name: Option<String>,
    pub command: Vec<String>,
    pub status: String,
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Push local runs into a sync directory (export portable v2 files).
pub async fn sync_push(
    store: &dyn TraceStore,
    dir: &Path,
    redact: bool,
) -> anyhow::Result<SyncReport> {
    ensure_layout(dir)?;
    let mut manifest = load_manifest(dir)?;
    let runs_dir = dir.join("runs");
    let local = store.list_runs().await?;
    let mut report = SyncReport::default();

    for run in local {
        let events = store.get_events(&run.id).await?;
        let json = match export_portable(store, &run, &events, redact).await {
            Ok(j) => j,
            Err(e) => {
                report.errors.push(format!("{}: export failed: {e}", short(&run.id)));
                continue;
            }
        };
        let hash = sha256_hex(json.as_bytes());
        let filename = format!("{}.json", run.id);
        let path = runs_dir.join(&filename);

        let needs_write = match manifest.runs.get(&run.id) {
            Some(entry) => entry.sha256 != hash || !path.exists(),
            None => true,
        };

        if !needs_write {
            report.skipped += 1;
            continue;
        }

        std::fs::write(&path, json.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        manifest.runs.insert(
            run.id.clone(),
            SyncRunEntry {
                file: format!("runs/{filename}"),
                sha256: hash,
                exported_at: chrono::Utc::now().to_rfc3339(),
                name: run.name.clone(),
                command: run.command.clone(),
                status: format!("{:?}", run.status),
            },
        );
        report.pushed += 1;
        tracing::info!(run_id = %run.id, "sync push");
    }

    save_manifest(dir, &manifest)?;
    Ok(report)
}

/// Pull remote runs from a sync directory into the local store.
///
/// Skips runs whose id already exists locally (idempotent).
pub async fn sync_pull(store: &dyn TraceStore, dir: &Path) -> anyhow::Result<SyncReport> {
    let manifest = load_manifest(dir)?;
    let mut report = SyncReport::default();

    for (run_id, entry) in &manifest.runs {
        if store.get_run(run_id).await?.is_some() {
            report.skipped += 1;
            continue;
        }
        let path = dir.join(&entry.file);
        let json = match std::fs::read_to_string(&path) {
            Ok(j) => j,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: read {}: {e}", short(run_id), path.display()));
                continue;
            }
        };
        // Verify checksum when present
        let hash = sha256_hex(json.as_bytes());
        if hash != entry.sha256 {
            report.errors.push(format!(
                "{}: checksum mismatch (manifest {} vs file {})",
                short(run_id),
                &entry.sha256[..12.min(entry.sha256.len())],
                &hash[..12.min(hash.len())]
            ));
            // still attempt import
        }

        // keep_ids=true path: new_ids=false so shared ids match across machines
        match import_portable(store, &json, false).await {
            Ok(_) => {
                report.pulled += 1;
                tracing::info!(run_id = %run_id, "sync pull");
            }
            Err(e) => {
                // If id conflict somehow, try remapped import as fallback
                match import_portable(store, &json, true).await {
                    Ok(r) => {
                        report.pulled += 1;
                        report.errors.push(format!(
                            "{}: kept-id import failed ({e}); imported as {}",
                            short(run_id),
                            short(&r.run_id)
                        ));
                    }
                    Err(e2) => {
                        report
                            .errors
                            .push(format!("{}: import failed: {e2}", short(run_id)));
                    }
                }
            }
        }
    }

    Ok(report)
}

fn ensure_layout(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("runs"))
        .with_context(|| format!("create sync dir {}", dir.display()))?;
    let man = dir.join("manifest.json");
    if !man.exists() {
        save_manifest(
            dir,
            &SyncManifest {
                version: MANIFEST_VERSION,
                runs: HashMap::new(),
            },
        )?;
    }
    Ok(())
}

fn load_manifest(dir: &Path) -> anyhow::Result<SyncManifest> {
    let path = dir.join("manifest.json");
    if !path.exists() {
        return Ok(SyncManifest {
            version: MANIFEST_VERSION,
            runs: HashMap::new(),
        });
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut man: SyncManifest =
        serde_json::from_str(&text).context("parse manifest.json")?;
    if man.version == 0 {
        man.version = MANIFEST_VERSION;
    }
    Ok(man)
}

fn save_manifest(dir: &Path, man: &SyncManifest) -> anyhow::Result<()> {
    let path = dir.join("manifest.json");
    let mut out = man.clone();
    out.version = MANIFEST_VERSION;
    let text = serde_json::to_string_pretty(&out)?;
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Resolve a user-supplied sync directory path.
pub fn resolve_sync_dir(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.as_os_str().is_empty() {
        PathBuf::from(".blackbox/sync")
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, TraceEvent};
    use crate::core::run::Run;
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn push_pull_across_stores() {
        let a = Arc::new(SqliteStore::open_memory().unwrap());
        let b = Arc::new(SqliteStore::open_memory().unwrap());
        let dir = std::env::temp_dir().join(format!("bb-sync-{}", uuid::Uuid::new_v4()));

        let mut run = Run::new(vec!["echo".into(), "sync".into()], "/tmp".into());
        run.status = crate::core::run::RunStatus::Succeeded;
        run.exit_code = Some(0);
        a.insert_run(&run).await.unwrap();
        let blob = a.store_blob(b"sync-blob").await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.sequence = 1;
        ev.output_blob = Some(blob.key);
        a.insert_event(&ev).await.unwrap();

        let push = sync_push(a.as_ref(), &dir, false).await.unwrap();
        assert_eq!(push.pushed, 1);

        let pull = sync_pull(b.as_ref(), &dir).await.unwrap();
        assert_eq!(pull.pulled, 1);
        assert!(b.get_run(&run.id).await.unwrap().is_some());
        let events = b.get_events(&run.id).await.unwrap();
        assert_eq!(events.len(), 1);
        let key = events[0].output_blob.as_ref().unwrap();
        let data = b
            .load_blob(&crate::core::blob::BlobReference::new(key.clone(), 0))
            .await
            .unwrap();
        assert_eq!(data, b"sync-blob");

        // Second pull is idempotent
        let pull2 = sync_pull(b.as_ref(), &dir).await.unwrap();
        assert_eq!(pull2.skipped, 1);
        assert_eq!(pull2.pulled, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
