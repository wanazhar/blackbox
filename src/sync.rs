//! Multi-machine sync: shared directory, HTTP (blackbox serve), or S3.
//!
//! ## Directory layout
//! ```text
//! <dir>/
//!   manifest.json
//!   runs/<run_id>.json   # portable v2 (with blobs)
//! ```
//!
//! ## HTTP remote
//! Talks to another `blackbox serve` instance:
//! - `GET  /api/sync/manifest`
//! - `GET  /api/sync/runs/{id}`
//! - `PUT  /api/sync/runs/{id}`  (body = portable JSON)
//!
//! ## S3 remote
//! `s3://bucket/prefix` using credentials from the environment
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, …).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, PutPayload};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::export::export_portable_secure;
use crate::export::portable::import_portable;
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

// ── Directory backend ─────────────────────────────────────────────

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
        let json = match export_portable_secure(store, &run, &events, redact).await {
            Ok(j) => j,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: export failed: {e}", short(&run.id)));
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
        tracing::info!(run_id = %run.id, "sync push (dir)");
    }

    save_manifest(dir, &manifest)?;
    Ok(report)
}

/// Pull remote runs from a sync directory into the local store.
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
        let hash = sha256_hex(json.as_bytes());
        if hash != entry.sha256 {
            report.errors.push(format!(
                "{}: checksum mismatch (manifest {} vs file {})",
                short(run_id),
                &entry.sha256[..12.min(entry.sha256.len())],
                &hash[..12.min(hash.len())]
            ));
            continue;
        }

        match import_with_fallback(store, &json).await {
            Ok(()) => {
                report.pulled += 1;
                tracing::info!(run_id = %run_id, "sync pull (dir)");
            }
            Err(e) => report
                .errors
                .push(format!("{}: import failed: {e}", short(run_id))),
        }
    }

    Ok(report)
}

// ── HTTP remote (blackbox serve) ──────────────────────────────────

/// Push local runs to a remote `blackbox serve` instance.
pub async fn sync_push_http(
    store: &dyn TraceStore,
    base_url: &str,
    token: Option<&str>,
    redact: bool,
) -> anyhow::Result<SyncReport> {
    let client = http_client()?;
    let base = base_url.trim_end_matches('/');
    let remote = http_get_manifest(&client, base, token).await?;
    let local = store.list_runs().await?;
    let mut report = SyncReport::default();

    for run in local {
        if remote.runs.contains_key(&run.id) {
            report.skipped += 1;
            continue;
        }
        let events = store.get_events(&run.id).await?;
        let json = match export_portable_secure(store, &run, &events, redact).await {
            Ok(j) => j,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: export failed: {e}", short(&run.id)));
                continue;
            }
        };
        match http_put_run(&client, base, token, &run.id, &json).await {
            Ok(()) => {
                report.pushed += 1;
                tracing::info!(run_id = %run.id, "sync push (http)");
            }
            Err(e) => report
                .errors
                .push(format!("{}: put failed: {e}", short(&run.id))),
        }
    }
    Ok(report)
}

/// Pull missing runs from a remote `blackbox serve` instance.
pub async fn sync_pull_http(
    store: &dyn TraceStore,
    base_url: &str,
    token: Option<&str>,
) -> anyhow::Result<SyncReport> {
    let client = http_client()?;
    let base = base_url.trim_end_matches('/');
    let remote = http_get_manifest(&client, base, token).await?;
    let mut report = SyncReport::default();

    for run_id in remote.runs.keys() {
        if store.get_run(run_id).await?.is_some() {
            report.skipped += 1;
            continue;
        }
        let json = match http_get_run(&client, base, token, run_id).await {
            Ok(j) => j,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: get failed: {e}", short(run_id)));
                continue;
            }
        };

        // Verify SHA-256 checksum against manifest entry if available.
        if let Some(entry) = remote.runs.get(run_id) {
            if !entry.sha256.is_empty() {
                let actual = sha256_hex(json.as_bytes());
                if actual != entry.sha256 {
                    report.errors.push(format!(
                        "{}: checksum mismatch (expected {}, got {})",
                        short(run_id),
                        entry.sha256,
                        actual
                    ));
                    continue;
                }
            }
        }
        match import_with_fallback(store, &json).await {
            Ok(()) => {
                report.pulled += 1;
                tracing::info!(run_id = %run_id, "sync pull (http)");
            }
            Err(e) => report
                .errors
                .push(format!("{}: import failed: {e}", short(run_id))),
        }
    }
    Ok(report)
}

/// Build an HTTP client for sync operations.
///
/// TLS uses the system-native certificate store (via `rustls-tls` in reqwest).
/// No custom certificate pinning or root CA configuration is applied — the
/// platform defaults (e.g. `/etc/ssl/certs` on Linux, system keychain on macOS)
/// are trusted. This is appropriate for most deployments but should be
/// documented for air-gapped or certificate-restricted environments.
fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("build http client")
}

fn auth_headers(token: Option<&str>) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Some(t) = token {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {t}")) {
            h.insert(reqwest::header::AUTHORIZATION, v);
        }
    }
    h
}

async fn http_get_manifest(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
) -> anyhow::Result<SyncManifest> {
    let url = format!("{base}/api/sync/manifest");
    let resp = client
        .get(&url)
        .headers(auth_headers(token))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url} → {}", resp.status());
    }
    resp.json().await.context("parse remote manifest")
}

async fn http_get_run(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
    run_id: &str,
) -> anyhow::Result<String> {
    let url = format!("{base}/api/sync/runs/{run_id}");
    let resp = client
        .get(&url)
        .headers(auth_headers(token))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url} → {}", resp.status());
    }
    resp.text().await.context("read portable body")
}

async fn http_put_run(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
    run_id: &str,
    json: &str,
) -> anyhow::Result<()> {
    let url = format!("{base}/api/sync/runs/{run_id}");
    let resp = client
        .put(&url)
        .headers(auth_headers(token))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json.to_string())
        .send()
        .await
        .with_context(|| format!("PUT {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("PUT {url} → {status}: {body}");
    }
    Ok(())
}

// ── S3 remote ─────────────────────────────────────────────────────

/// Push local runs to `s3://bucket/prefix`.
pub async fn sync_push_s3(
    store: &dyn TraceStore,
    bucket: &str,
    prefix: &str,
    redact: bool,
) -> anyhow::Result<SyncReport> {
    let (s3, root) = s3_client(bucket, prefix)?;
    let mut manifest = s3_load_manifest(&s3, &root).await?;
    let local = store.list_runs().await?;
    let mut report = SyncReport::default();

    for run in local {
        let events = store.get_events(&run.id).await?;
        let json = match export_portable_secure(store, &run, &events, redact).await {
            Ok(j) => j,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: export failed: {e}", short(&run.id)));
                continue;
            }
        };
        let hash = sha256_hex(json.as_bytes());
        let file = format!("runs/{}.json", run.id);
        let needs = match manifest.runs.get(&run.id) {
            Some(e) => e.sha256 != hash,
            None => true,
        };
        if !needs {
            report.skipped += 1;
            continue;
        }
        let key = obj_path(&root, &file);
        s3.put(&key, PutPayload::from(Bytes::from(json)))
            .await
            .with_context(|| format!("s3 put {file}"))?;
        manifest.runs.insert(
            run.id.clone(),
            SyncRunEntry {
                file,
                sha256: hash,
                exported_at: chrono::Utc::now().to_rfc3339(),
                name: run.name.clone(),
                command: run.command.clone(),
                status: format!("{:?}", run.status),
            },
        );
        report.pushed += 1;
        tracing::info!(run_id = %run.id, "sync push (s3)");
    }
    s3_save_manifest(&s3, &root, &manifest).await?;
    Ok(report)
}

/// Pull missing runs from `s3://bucket/prefix`.
pub async fn sync_pull_s3(
    store: &dyn TraceStore,
    bucket: &str,
    prefix: &str,
) -> anyhow::Result<SyncReport> {
    let (s3, root) = s3_client(bucket, prefix)?;
    let manifest = s3_load_manifest(&s3, &root).await?;
    let mut report = SyncReport::default();

    for (run_id, entry) in &manifest.runs {
        if store.get_run(run_id).await?.is_some() {
            report.skipped += 1;
            continue;
        }
        let key = obj_path(&root, &entry.file);
        let result = s3.get(&key).await;
        let data = match result {
            Ok(r) => r.bytes().await.context("s3 read body")?,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: s3 get {}: {e}", short(run_id), entry.file));
                continue;
            }
        };
        let json = String::from_utf8_lossy(&data).to_string();
        let hash = sha256_hex(json.as_bytes());
        if hash != entry.sha256 {
            report.errors.push(format!(
                "{}: checksum mismatch (manifest {} vs file {})",
                short(run_id),
                &entry.sha256[..12.min(entry.sha256.len())],
                &hash[..12.min(hash.len())]
            ));
            continue;
        }
        match import_with_fallback(store, &json).await {
            Ok(()) => {
                report.pulled += 1;
                tracing::info!(run_id = %run_id, "sync pull (s3)");
            }
            Err(e) => report
                .errors
                .push(format!("{}: import failed: {e}", short(run_id))),
        }
    }
    Ok(report)
}

fn s3_client(bucket: &str, prefix: &str) -> anyhow::Result<(Arc<dyn ObjectStore>, String)> {
    use object_store::aws::AmazonS3Builder;
    let s3 = AmazonS3Builder::from_env()
        .with_bucket_name(bucket)
        .build()
        .context("build S3 client (set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION)")?;
    let root = prefix.trim_matches('/').to_string();
    Ok((Arc::new(s3), root))
}

fn obj_path(root: &str, rel: &str) -> ObjPath {
    let full = if root.is_empty() {
        rel.to_string()
    } else {
        format!("{root}/{rel}")
    };
    ObjPath::from(full)
}

async fn s3_load_manifest(s3: &dyn ObjectStore, root: &str) -> anyhow::Result<SyncManifest> {
    let key = obj_path(root, "manifest.json");
    match s3.get(&key).await {
        Ok(r) => {
            let bytes = r.bytes().await?;
            let text = String::from_utf8_lossy(&bytes);
            let mut man: SyncManifest = serde_json::from_str(&text).context("parse s3 manifest")?;
            if man.version == 0 {
                man.version = MANIFEST_VERSION;
            }
            Ok(man)
        }
        Err(_) => Ok(SyncManifest {
            version: MANIFEST_VERSION,
            runs: HashMap::new(),
        }),
    }
}

async fn s3_save_manifest(
    s3: &dyn ObjectStore,
    root: &str,
    man: &SyncManifest,
) -> anyhow::Result<()> {
    let mut out = man.clone();
    out.version = MANIFEST_VERSION;
    let text = serde_json::to_string_pretty(&out)?;
    let key = obj_path(root, "manifest.json");
    s3.put(&key, PutPayload::from(Bytes::from(text)))
        .await
        .context("s3 put manifest")?;
    Ok(())
}

/// Parse `s3://bucket/optional/prefix` into (bucket, prefix).
pub fn parse_s3_url(url: &str) -> anyhow::Result<(String, String)> {
    let rest = url
        .strip_prefix("s3://")
        .ok_or_else(|| anyhow::anyhow!("S3 URL must start with s3://"))?;
    let (bucket, prefix) = match rest.split_once('/') {
        Some((b, p)) => (b.to_string(), p.trim_matches('/').to_string()),
        None => (rest.to_string(), String::new()),
    };
    if bucket.is_empty() {
        anyhow::bail!("empty S3 bucket");
    }
    Ok((bucket, prefix))
}

// ── Shared helpers ────────────────────────────────────────────────

async fn import_with_fallback(store: &dyn TraceStore, json: &str) -> anyhow::Result<()> {
    match import_portable(store, json, false).await {
        Ok(_) => Ok(()),
        Err(e) => import_portable(store, json, true)
            .await
            .map(|_| ())
            .with_context(|| format!("keep-id import failed ({e}); remapped also failed")),
    }
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
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut man: SyncManifest = serde_json::from_str(&text).context("parse manifest.json")?;
    // Validate schema version — refuse manifests from a newer writer that
    // may contain fields we cannot safely round-trip.
    if man.version > MANIFEST_VERSION {
        anyhow::bail!(
            "manifest version {} exceeds supported version {} — upgrade blackbox to sync with this remote",
            man.version,
            MANIFEST_VERSION,
        );
    }
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

/// Build a directory-style manifest from the live store (for HTTP API).
pub async fn manifest_from_store(store: &dyn TraceStore) -> anyhow::Result<SyncManifest> {
    let runs = store.list_runs().await?;
    let mut man = SyncManifest {
        version: MANIFEST_VERSION,
        runs: HashMap::new(),
    };
    for run in runs {
        let events = store.get_events(&run.id).await?;
        let json = match export_portable_secure(store, &run, &events, true).await {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(run_id = %run.id, error = %e, "manifest: export failed, skipping sha256");
                // Insert entry without SHA-256; pull will skip checksum verification
                man.runs.insert(
                    run.id.clone(),
                    SyncRunEntry {
                        file: format!("runs/{}.json", run.id),
                        sha256: String::new(),
                        exported_at: run.ended_at.unwrap_or(run.started_at).to_rfc3339(),
                        name: run.name.clone(),
                        command: run.command.clone(),
                        status: format!("{:?}", run.status),
                    },
                );
                continue;
            }
        };
        let hash = sha256_hex(json.as_bytes());
        man.runs.insert(
            run.id.clone(),
            SyncRunEntry {
                file: format!("runs/{}.json", run.id),
                sha256: hash,
                exported_at: run.ended_at.unwrap_or(run.started_at).to_rfc3339(),
                name: run.name.clone(),
                command: run.command.clone(),
                status: format!("{:?}", run.status),
            },
        );
    }
    Ok(man)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, TraceEvent};
    use crate::core::run::Run;
    use crate::storage::sqlite::SqliteStore;

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

        let pull2 = sync_pull(b.as_ref(), &dir).await.unwrap();
        assert_eq!(pull2.skipped, 1);
        assert_eq!(pull2.pulled, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_s3_url_ok() {
        let (b, p) = parse_s3_url("s3://my-bucket/path/to").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(p, "path/to");
        let (b2, p2) = parse_s3_url("s3://bucket-only").unwrap();
        assert_eq!(b2, "bucket-only");
        assert!(p2.is_empty());
    }
    #[tokio::test]
    async fn test_sync_checksum() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let dir = std::env::temp_dir().join(format!("bb-sync-checksum-{}", uuid::Uuid::new_v4()));
        let mut run = Run::new(vec!["echo".into(), "checksum".into()], "/tmp".into());
        run.status = crate::core::run::RunStatus::Succeeded;
        run.exit_code = Some(0);
        store.insert_run(&run).await.unwrap();
        let push = sync_push(store.as_ref(), &dir, false).await.unwrap();
        assert_eq!(push.pushed, 1);
        let file_path = dir.join("runs").join(format!("{}.json", run.id));
        let mut content = std::fs::read_to_string(&file_path).unwrap();
        content.push_str("\nCORRUPTED");
        std::fs::write(&file_path, &content).unwrap();
        let store2 = Arc::new(SqliteStore::open_memory().unwrap());
        let pull = sync_pull(store2.as_ref(), &dir).await.unwrap();
        assert_eq!(pull.pulled, 0, "corrupted file should not be imported");
        assert!(
            pull.errors.iter().any(|e| e.contains("checksum mismatch")),
            "should report checksum mismatch, errors: {:?}",
            pull.errors
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
