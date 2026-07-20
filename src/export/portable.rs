//! Portable JSON archives for sharing runs offline (optionally with blobs).
//!
//! Import (1.5 A1) validates content hashes, applies size limits, redacts nested
//! metadata, and rolls back permanent writes on failure. Declared blob keys must
//! equal the computed plaintext SHA-256 — content is never renamed to an
//! unverified caller-supplied key.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use base64::Engine;

use crate::core::blob::{is_valid_blob_key, BlobReference};
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::crypto::content_key;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;

const PORTABLE_VERSION: u64 = 2;
/// Directory layout format (streaming-friendly). Import still accepts v1/v2 JSON files.
const PORTABLE_DIR_FORMAT: &str = "blackbox.portable.dir/v1";

/// Hard limits for untrusted portable archives (1.5 import integrity).
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024; // 256 MiB JSON text
const MAX_EVENTS: usize = 500_000;
const MAX_BLOBS: usize = 50_000;
const MAX_SINGLE_BLOB_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
const MAX_TOTAL_BLOB_BYTES: usize = 200 * 1024 * 1024; // 200 MiB decoded

/// Export a run and its events as a self-contained portable JSON archive.
///
/// Version 2 embeds referenced blob payloads (base64) so the archive is
/// fully offline-shareable. Version 1 archives (no blobs) remain importable.
pub async fn export_portable(
    store: &dyn TraceStore,
    run: &Run,
    events: &[TraceEvent],
    redact: bool,
) -> anyhow::Result<String> {
    let mut run_val = serde_json::to_value(run)?;
    if redact {
        redact_run(&mut run_val);
    }

    let mut events_val: Vec<serde_json::Value> = events
        .iter()
        .filter_map(|e| {
            let mut v = serde_json::to_value(e).ok()?;
            if redact {
                redact_event(&mut v);
            }
            Some(v)
        })
        .collect();

    events_val.sort_by_key(|v| v["sequence"].as_u64().unwrap_or(0));

    // Collect + embed blobs
    let keys = collect_blob_keys(events);
    let mut blobs = serde_json::Map::new();
    for key in keys {
        let bref = match BlobReference::try_new(key.clone(), 0) {
            Some(b) => b,
            None => {
                tracing::warn!(key = %key, "portable export: skipping blob with invalid key");
                continue;
            }
        };
        match store.load_blob(&bref).await {
            Ok(bytes) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                blobs.insert(
                    key,
                    serde_json::json!({
                        "encoding": "base64",
                        "size": bytes.len(),
                        "data": b64,
                    }),
                );
            }
            Err(e) => {
                tracing::debug!(key = %key, error = %e, "portable export: skip missing blob");
            }
        }
    }

    let output = serde_json::json!({
        "version": PORTABLE_VERSION,
        "run": run_val,
        "events": events_val,
        "blobs": blobs,
        "exported_at": chrono::Utc::now().to_rfc3339(),
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Export a run as a **directory** archive (streaming-friendly layout).
///
/// Layout:
/// ```text
/// manifest.json     # format + version + counts
/// run.json          # single run object
/// events.jsonl      # one TraceEvent JSON per line (sequence order)
/// blobs/<sha256>    # raw blob bytes (content key = filename)
/// ```
///
/// Does not hold the full archive as one in-memory string. Events are written
/// line-by-line; blobs are written one file at a time.
pub async fn export_portable_dir(
    store: &dyn TraceStore,
    run: &Run,
    events: &[TraceEvent],
    dir: &std::path::Path,
    redact: bool,
) -> anyhow::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let blobs_dir = dir.join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;

    let mut run_val = serde_json::to_value(run)?;
    if redact {
        redact_run(&mut run_val);
    }
    std::fs::write(
        dir.join("run.json"),
        serde_json::to_string_pretty(&run_val)?,
    )?;

    // Load + optional secret-scan blobs; rekey when redaction changes bytes.
    let scanner = if redact {
        Some(SecretScanner::new(RedactionConfig::default()))
    } else {
        None
    };
    let keys = collect_blob_keys(events);
    let mut key_remap: HashMap<String, String> = HashMap::new();
    let mut blob_count = 0usize;
    for key in keys {
        let Some(bref) = BlobReference::try_new(key.clone(), 0) else {
            continue;
        };
        match store.load_blob(&bref).await {
            Ok(bytes) => {
                let computed = content_key(&bytes);
                if computed != key {
                    anyhow::bail!(
                        "export blob integrity: key {key} != content hash {computed}"
                    );
                }
                let out_bytes = if let Some(ref sc) = scanner {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        let red = sc.redact(text);
                        if red != text {
                            red.into_bytes()
                        } else {
                            bytes
                        }
                    } else {
                        bytes
                    }
                } else {
                    bytes
                };
                let out_key = content_key(&out_bytes);
                if out_key != key {
                    key_remap.insert(key, out_key.clone());
                }
                std::fs::write(blobs_dir.join(&out_key), &out_bytes)?;
                blob_count += 1;
            }
            Err(e) => {
                tracing::debug!(key = %key, error = %e, "portable dir export: skip missing blob");
            }
        }
    }

    let mut events_sorted: Vec<TraceEvent> = events.to_vec();
    events_sorted.sort_by_key(|e| e.sequence);
    let mut events_file = std::fs::File::create(dir.join("events.jsonl"))?;
    for mut ev in events_sorted.iter().cloned() {
        if !key_remap.is_empty() {
            remap_event_blob_keys(&mut ev, &key_remap);
        }
        let mut v = serde_json::to_value(&ev)?;
        if redact {
            redact_event(&mut v);
        }
        writeln!(events_file, "{}", serde_json::to_string(&v)?)?;
    }

    let manifest = serde_json::json!({
        "format": PORTABLE_DIR_FORMAT,
        "version": PORTABLE_VERSION,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "events": events_sorted.len(),
        "blobs": blob_count,
        "run_id": run.id,
        "redacted": redact,
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(())
}

fn remap_event_blob_keys(ev: &mut TraceEvent, remap: &HashMap<String, String>) {
    if let Some(ref k) = ev.input_blob {
        if let Some(n) = remap.get(k) {
            ev.input_blob = Some(n.clone());
        }
    }
    if let Some(ref k) = ev.output_blob {
        if let Some(n) = remap.get(k) {
            ev.output_blob = Some(n.clone());
        }
    }
    if let Some(ref k) = ev.error_blob {
        if let Some(n) = remap.get(k) {
            ev.error_blob = Some(n.clone());
        }
    }
}

/// Import a directory archive written by [`export_portable_dir`].
///
/// Validates blob hashes (filename must equal SHA-256 of file bytes), then
/// reuses the same integrity pipeline as JSON portable import.
pub async fn import_portable_dir(
    store: &dyn TraceStore,
    dir: &std::path::Path,
    new_ids: bool,
) -> anyhow::Result<ImportResult> {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json"))
            .context("read manifest.json")?,
    )?;
    let format = manifest
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if format != PORTABLE_DIR_FORMAT {
        anyhow::bail!("unsupported portable directory format: {format}");
    }

    let run_val: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("run.json")).context("read run.json")?,
    )?;

    let events_path = dir.join("events.jsonl");
    {
        let meta = std::fs::metadata(&events_path).context("stat events.jsonl")?;
        if meta.len() as usize > MAX_ARCHIVE_BYTES {
            anyhow::bail!(
                "events.jsonl too large: {} bytes (max {})",
                meta.len(),
                MAX_ARCHIVE_BYTES
            );
        }
        if meta.file_type().is_symlink() {
            anyhow::bail!("events.jsonl must not be a symlink");
        }
    }
    let events_text = std::fs::read_to_string(&events_path).context("read events.jsonl")?;
    let mut events_val = Vec::new();
    for (i, line) in events_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if events_val.len() >= MAX_EVENTS {
            anyhow::bail!("portable dir has too many events (max {MAX_EVENTS})");
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("events.jsonl line {}", i + 1))?;
        events_val.push(v);
    }

    let blobs_dir = dir.join("blobs");
    let mut blobs = serde_json::Map::new();
    let mut total_blob_bytes = 0usize;
    if blobs_dir.is_dir() {
        for entry in std::fs::read_dir(&blobs_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_valid_blob_key(&name) {
                anyhow::bail!("invalid blob filename (expected sha256 hex): {name}");
            }
            let ftype = entry.file_type()?;
            if ftype.is_symlink() || !ftype.is_file() {
                anyhow::bail!("blob {name} must be a regular file (no symlinks)");
            }
            let meta = entry.metadata()?;
            if meta.len() as usize > MAX_SINGLE_BLOB_BYTES {
                anyhow::bail!("blob {name} too large");
            }
            total_blob_bytes = total_blob_bytes.saturating_add(meta.len() as usize);
            if total_blob_bytes > MAX_TOTAL_BLOB_BYTES {
                anyhow::bail!(
                    "portable dir total blob bytes exceed max {MAX_TOTAL_BLOB_BYTES}"
                );
            }
            if blobs.len() >= MAX_BLOBS {
                anyhow::bail!("portable dir has too many blobs (max {MAX_BLOBS})");
            }
            let bytes = std::fs::read(entry.path())?;
            let computed = content_key(&bytes);
            if computed != name {
                anyhow::bail!(
                    "blob hash mismatch: file {name} content SHA-256 is {computed}"
                );
            }
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            blobs.insert(
                name,
                serde_json::json!({
                    "encoding": "base64",
                    "size": bytes.len(),
                    "data": b64,
                }),
            );
        }
    }

    let root = serde_json::json!({
        "version": PORTABLE_VERSION,
        "run": run_val,
        "events": events_val,
        "blobs": blobs,
        "exported_at": manifest.get("exported_at").cloned().unwrap_or(serde_json::Value::Null),
    });
    let json = serde_json::to_string(&root)?;
    import_portable(store, &json, new_ids).await
}

/// Result of importing a portable archive.
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub run_id: String,
    pub events: usize,
    pub blobs: usize,
    pub remapped: bool,
}

/// Import a portable JSON archive (v1 or v2) into the store.
///
/// If `new_ids` is true, assigns a fresh run id and regenerates event ids.
/// If false, keeps ids and fails if the run already exists.
///
/// **Integrity (1.5 A1):**
/// - Declared blob keys must equal SHA-256 of decoded plaintext (no rename).
/// - Duplicate-run checks run before permanent writes.
/// - Events insert as a single batch transaction.
/// - Failures roll back the run and any newly created blob keys.
pub async fn import_portable(
    store: &dyn TraceStore,
    json: &str,
    new_ids: bool,
) -> anyhow::Result<ImportResult> {
    if json.len() > MAX_ARCHIVE_BYTES {
        anyhow::bail!(
            "portable archive too large: {} bytes (max {})",
            json.len(),
            MAX_ARCHIVE_BYTES
        );
    }

    let root: serde_json::Value = serde_json::from_str(json).context("invalid portable JSON")?;
    let version = root.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != 1 && version != 2 {
        anyhow::bail!("unsupported portable version: {version} (expected 1 or 2)");
    }

    let mut run: Run = serde_json::from_value(
        root.get("run")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing run object"))?,
    )
    .context("invalid run payload")?;

    if run.id.trim().is_empty() {
        anyhow::bail!("invalid run payload: empty run id");
    }
    if !crate::util::is_safe_id(&run.id) {
        anyhow::bail!(
            "invalid run id (must be alphanumeric/hyphen/underscore, no path separators): {}",
            run.id
        );
    }

    let mut events: Vec<TraceEvent> = serde_json::from_value(
        root.get("events")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )
    .context("invalid events payload")?;

    if events.len() > MAX_EVENTS {
        anyhow::bail!(
            "portable archive has too many events: {} (max {})",
            events.len(),
            MAX_EVENTS
        );
    }

    // ── Decode + hash-verify blobs into memory (no permanent writes yet) ──
    let verified_blobs = decode_and_verify_blobs(root.get("blobs"))?;

    // ── Validate event blob references against verified keys ──
    let blob_key_set: HashSet<&str> = verified_blobs.iter().map(|(k, _)| k.as_str()).collect();
    validate_event_blob_refs(&events, &blob_key_set)?;

    // ── ID remapping (in memory) ──
    let remapped;
    if new_ids {
        let old_id = run.id.clone();
        run.id = uuid::Uuid::new_v4().to_string();
        run.parent_run_id = run.parent_run_id.or(Some(old_id.clone()));
        if let Some(notes) = run.notes.take() {
            run.notes = Some(format!("imported from {old_id}; {notes}"));
        } else {
            run.notes = Some(format!("imported from {old_id}"));
        }
        if !run.tags.iter().any(|t| t == "imported") {
            run.tags.push("imported".into());
        }
        let mut id_map = HashMap::new();
        for ev in &mut events {
            let old_ev_id = ev.id.clone();
            ev.id = uuid::Uuid::new_v4().to_string();
            ev.run_id = run.id.clone();
            id_map.insert(old_ev_id, ev.id.clone());
        }
        for ev in &mut events {
            if let Some(pid) = &ev.parent_event_id {
                if let Some(new_pid) = id_map.get(pid) {
                    ev.parent_event_id = Some(new_pid.clone());
                } else {
                    anyhow::bail!(
                        "malformed parent_event_id reference: {pid} not present in archive"
                    );
                }
            }
        }
        remapped = true;
    } else {
        // Keep-ids: ensure every event's run_id matches the run.
        for ev in &mut events {
            if ev.run_id != run.id {
                ev.run_id = run.id.clone();
            }
        }
        // Parent refs must point at events in this archive (or null).
        let event_ids: HashSet<&str> = events.iter().map(|e| e.id.as_str()).collect();
        for ev in &events {
            if let Some(pid) = &ev.parent_event_id {
                if !event_ids.contains(pid.as_str()) {
                    anyhow::bail!(
                        "malformed parent_event_id reference: {pid} not present in archive"
                    );
                }
            }
        }
        remapped = false;
    }

    // ── Duplicate-run check BEFORE permanent writes ──
    if !new_ids && store.get_run(&run.id).await?.is_some() {
        anyhow::bail!(
            "run {} already exists (omit --keep-ids or delete first)",
            &run.id[..8.min(run.id.len())]
        );
    }

    events.sort_by_key(|e| e.sequence);

    // ── Recursive redaction of nested metadata ──
    let scanner = SecretScanner::new(RedactionConfig::default());
    for ev in &mut events {
        redact_event_metadata(&scanner, &mut ev.metadata);
    }
    if let Some(ref mut notes) = run.notes {
        *notes = scanner.redact(notes);
    }

    // ── Permanent writes with rollback journal ──
    let mut journal = ImportJournal::default();
    match promote_import(store, &run, &events, &verified_blobs, &mut journal).await {
        Ok(blobs_restored) => Ok(ImportResult {
            run_id: run.id,
            events: events.len(),
            blobs: blobs_restored,
            remapped,
        }),
        Err(e) => {
            if let Err(rb) = journal.rollback(store).await {
                tracing::warn!(error = %rb, "import rollback incomplete");
            }
            Err(e)
        }
    }
}

/// Tracks permanent side-effects so a failed import can clean up.
#[derive(Default)]
struct ImportJournal {
    run_id: Option<String>,
    /// Blob keys that did not exist before this import (safe to delete).
    new_blob_keys: Vec<String>,
}

impl ImportJournal {
    async fn rollback(&self, store: &dyn TraceStore) -> anyhow::Result<()> {
        if let Some(ref run_id) = self.run_id {
            let _ = store.delete_run(run_id).await;
        }
        if !self.new_blob_keys.is_empty() {
            // SqliteStore also removes on-disk files for these keys.
            let _ = store.delete_blob_keys(&self.new_blob_keys).await;
        }
        Ok(())
    }
}

async fn promote_import(
    store: &dyn TraceStore,
    run: &Run,
    events: &[TraceEvent],
    verified_blobs: &[(String, Vec<u8>)],
    journal: &mut ImportJournal,
) -> anyhow::Result<usize> {
    // Persist verified blobs under their content keys only.
    let mut blobs_restored = 0usize;
    for (key, data) in verified_blobs {
        let existed = blob_exists(store, key).await;
        let stored = store.store_blob(data).await?;
        if stored.key != *key {
            // Defensive: should be impossible after verify.
            anyhow::bail!(
                "blob integrity failure after store: declared key {} != computed {}",
                key,
                stored.key
            );
        }
        if !existed {
            journal.new_blob_keys.push(key.clone());
        }
        blobs_restored += 1;
    }

    store.insert_run(run).await?;
    journal.run_id = Some(run.id.clone());

    store.insert_events_batch(events).await?;
    Ok(blobs_restored)
}

async fn blob_exists(store: &dyn TraceStore, key: &str) -> bool {
    let Some(bref) = BlobReference::try_new(key.to_string(), 0) else {
        return false;
    };
    store.load_blob(&bref).await.is_ok()
}

/// Decode blob map entries and require declared key == SHA-256(plaintext).
fn decode_and_verify_blobs(
    blobs_val: Option<&serde_json::Value>,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let Some(obj) = blobs_val.and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    if obj.len() > MAX_BLOBS {
        anyhow::bail!(
            "portable archive has too many blobs: {} (max {})",
            obj.len(),
            MAX_BLOBS
        );
    }

    let mut out = Vec::with_capacity(obj.len());
    let mut total: usize = 0;
    for (key, entry) in obj {
        if !is_valid_blob_key(key) {
            anyhow::bail!("invalid blob key (expected 64-char hex SHA-256): {key}");
        }
        let data = decode_blob_entry(entry).with_context(|| format!("blob {key}"))?;
        if data.len() > MAX_SINGLE_BLOB_BYTES {
            anyhow::bail!(
                "blob {key} too large: {} bytes (max {})",
                data.len(),
                MAX_SINGLE_BLOB_BYTES
            );
        }
        total = total.saturating_add(data.len());
        if total > MAX_TOTAL_BLOB_BYTES {
            anyhow::bail!(
                "portable archive total blob size exceeds limit ({} bytes)",
                MAX_TOTAL_BLOB_BYTES
            );
        }
        let computed = content_key(&data);
        if computed != *key {
            anyhow::bail!(
                "blob hash mismatch: declared key {} but content SHA-256 is {} — archive rejected",
                key,
                computed
            );
        }
        out.push((key.clone(), data));
    }
    Ok(out)
}

fn validate_event_blob_refs(
    events: &[TraceEvent],
    known: &HashSet<&str>,
) -> anyhow::Result<()> {
    for ev in events {
        for (field, key) in [
            ("input_blob", ev.input_blob.as_deref()),
            ("output_blob", ev.output_blob.as_deref()),
            ("error_blob", ev.error_blob.as_deref()),
        ] {
            if let Some(k) = key {
                if !is_valid_blob_key(k) {
                    anyhow::bail!("event {} has invalid {field} key: {k}", ev.id);
                }
                // v1 archives may omit blobs map; v2 with refs must include them.
                // Allow missing only when no blobs were declared at all (v1).
                if !known.is_empty() && !known.contains(k) {
                    anyhow::bail!(
                        "event {} references {field}={k} not present in archive blobs",
                        ev.id
                    );
                }
            }
        }
    }
    Ok(())
}

fn redact_event_metadata(
    scanner: &SecretScanner,
    metadata: &mut HashMap<String, serde_json::Value>,
) {
    for val in metadata.values_mut() {
        scanner.redact_json(val);
    }
}

fn decode_blob_entry(entry: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    // v2 object form
    if let Some(obj) = entry.as_object() {
        let enc = obj
            .get("encoding")
            .and_then(|v| v.as_str())
            .unwrap_or("base64");
        let data = obj
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing blob data"))?;
        return match enc {
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(data)
                .context("base64 decode"),
            other => anyhow::bail!("unsupported blob encoding: {other}"),
        };
    }
    // plain base64 string
    if let Some(s) = entry.as_str() {
        return base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("base64 decode");
    }
    anyhow::bail!("invalid blob entry")
}

fn collect_blob_keys(events: &[TraceEvent]) -> HashSet<String> {
    let mut keys = HashSet::new();
    for ev in events {
        if let Some(k) = &ev.input_blob {
            keys.insert(k.clone());
        }
        if let Some(k) = &ev.output_blob {
            keys.insert(k.clone());
        }
        if let Some(k) = &ev.error_blob {
            keys.insert(k.clone());
        }
        for (k, v) in &ev.metadata {
            if k.contains("blob") {
                if let Some(s) = v.as_str() {
                    if looks_like_blob_key(s) {
                        keys.insert(s.to_string());
                    }
                }
            }
        }
    }
    keys
}

fn looks_like_blob_key(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn redact_run(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(cwd) = obj.get("cwd").and_then(|v| v.as_str()) {
            let basename = std::path::Path::new(cwd)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "(redacted)".to_string());
            obj.insert("cwd".to_string(), serde_json::json!(basename));
        }
    }
}

fn redact_event(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(meta) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            meta.remove("raw");
            if meta.contains_key("diff_preview") {
                meta.insert("diff_preview".to_string(), serde_json::json!("[REDACTED]"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;
    use chrono::Utc;
    use std::sync::Arc;

    fn make_run() -> Run {
        let mut r = Run::new(
            vec!["echo".into(), "hello".into()],
            "/home/user/project".into(),
        );
        r.id = "run-port001".into();
        r.status = crate::core::run::RunStatus::Succeeded;
        r.ended_at = Some(Utc::now());
        r.exit_code = Some(0);
        r.next_sequence = 1;
        r
    }

    fn make_event(seq: u64) -> TraceEvent {
        TraceEvent {
            id: format!("evt-{}", seq),
            run_id: "run-port001".into(),
            parent_event_id: None,
            sequence: seq,
            source: EventSource::Terminal,
            kind: "terminal.output".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            duration_ms: Some(50),
            status: EventStatus::Success,
            side_effect: crate::core::event::SideEffect::None,
            input_blob: None,
            output_blob: None,
            error_blob: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn portable_export_valid_json_v2() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        store.insert_run(&run).await.unwrap();
        let blob = store.store_blob(b"hello blob").await.unwrap();
        let mut ev = make_event(1);
        ev.output_blob = Some(blob.key.clone());
        store.insert_event(&ev).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        let output = export_portable(store.as_ref(), &run, &events, false)
            .await
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], 2);
        assert_eq!(parsed["run"]["id"], "run-port001");
        assert!(parsed["blobs"][&blob.key].is_object());
        assert_eq!(parsed["blobs"][&blob.key]["size"].as_u64().unwrap(), 10);
    }

    #[tokio::test]
    async fn portable_export_empty_events() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        let output = export_portable(store.as_ref(), &run, &[], false)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["events"].as_array().unwrap().len(), 0);
        assert!(parsed["blobs"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn portable_export_redacted() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        let output = export_portable(store.as_ref(), &run, &[], true)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["run"]["cwd"], "project");
    }

    #[tokio::test]
    async fn portable_export_events_sorted() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        store.insert_run(&run).await.unwrap();
        let events = vec![make_event(3), make_event(1), make_event(2)];
        for e in &events {
            store.insert_event(e).await.unwrap();
        }
        let loaded = store.get_events(&run.id).await.unwrap();
        let output = export_portable(store.as_ref(), &run, &loaded, false)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed["events"].as_array().unwrap();
        assert_eq!(arr[0]["sequence"], 1);
        assert_eq!(arr[1]["sequence"], 2);
        assert_eq!(arr[2]["sequence"], 3);
    }

    #[tokio::test]
    async fn portable_round_trip_with_blobs() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        store.insert_run(&run).await.unwrap();
        let blob = store.store_blob(b"payload-bytes").await.unwrap();
        let mut ev = make_event(1);
        ev.output_blob = Some(blob.key.clone());
        store.insert_event(&ev).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        let json = export_portable(store.as_ref(), &run, &events, false)
            .await
            .unwrap();

        // Fresh store simulates another machine
        let store2 = Arc::new(SqliteStore::open_memory().unwrap());
        let result = import_portable(store2.as_ref(), &json, true).await.unwrap();
        assert_ne!(result.run_id, run.id);
        assert_eq!(result.events, 1);
        assert_eq!(result.blobs, 1);
        assert!(result.remapped);

        let imported_events = store2.get_events(&result.run_id).await.unwrap();
        let key = imported_events[0].output_blob.as_ref().unwrap();
        let data = store2
            .load_blob(&BlobReference::new(key.clone(), 0))
            .await
            .unwrap();
        assert_eq!(data, b"payload-bytes");
    }

    #[tokio::test]
    async fn portable_dir_round_trip() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        store.insert_run(&run).await.unwrap();
        let blob = store.store_blob(b"dir-payload").await.unwrap();
        let mut ev = make_event(1);
        ev.output_blob = Some(blob.key.clone());
        store.insert_event(&ev).await.unwrap();
        let events = store.get_events(&run.id).await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        export_portable_dir(store.as_ref(), &run, &events, dir.path(), false)
            .await
            .unwrap();
        assert!(dir.path().join("manifest.json").is_file());
        assert!(dir.path().join("events.jsonl").is_file());
        assert!(dir.path().join("blobs").join(&blob.key).is_file());

        let store2 = Arc::new(SqliteStore::open_memory().unwrap());
        let result = import_portable_dir(store2.as_ref(), dir.path(), true)
            .await
            .unwrap();
        assert_eq!(result.events, 1);
        assert_eq!(result.blobs, 1);
        let imported = store2.get_events(&result.run_id).await.unwrap();
        let key = imported[0].output_blob.as_ref().unwrap();
        let data = store2
            .load_blob(&BlobReference::try_new(key.clone(), 0).unwrap())
            .await
            .unwrap();
        assert_eq!(data, b"dir-payload");
    }

    #[tokio::test]
    async fn import_v1_still_works() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let v1 = r#"{
            "version": 1,
            "run": {
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": null,
                "command": ["echo","hi"],
                "cwd": "/tmp",
                "project_dir": "/tmp",
                "tags": [],
                "notes": null,
                "status": "Succeeded",
                "started_at": "2026-01-01T00:00:00Z",
                "ended_at": "2026-01-01T00:00:01Z",
                "exit_code": 0,
                "parent_run_id": null,
                "next_sequence": 1
            },
            "events": [],
            "exported_at": "2026-01-01T00:00:02Z"
        }"#;
        let result = import_portable(store.as_ref(), v1, true).await.unwrap();
        assert_eq!(result.events, 0);
        assert_eq!(result.blobs, 0);
        assert!(store.get_run(&result.run_id).await.unwrap().is_some());
    }
    #[tokio::test]
    async fn import_new_ids_remaps_parent_event_id() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());

        // Build a JSON archive with events that have parent_event_id references
        let parent_id = "aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa";
        let child_id = "bbbbbbbb-4444-5555-6666-bbbbbbbbbbbb";
        let json = serde_json::json!({
            "version": 2,
            "run": {
                "id": "run-old001",
                "name": null,
                "command": ["echo", "hi"],
                "cwd": "/tmp",
                "project_dir": "/tmp",
                "tags": [],
                "notes": null,
                "status": "Succeeded",
                "started_at": "2026-01-01T00:00:00Z",
                "ended_at": "2026-01-01T00:00:01Z",
                "exit_code": 0,
                "parent_run_id": null,
                "next_sequence": 3
            },
            "events": [
                {
                    "id": parent_id,
                    "run_id": "run-old001",
                    "parent_event_id": null,
                    "sequence": 1,
                    "source": "Terminal",
                    "kind": "terminal.output",
                    "started_at": "2026-01-01T00:00:00Z",
                    "ended_at": null,
                    "duration_ms": null,
                    "status": "Success",
                    "side_effect": "None",
                    "input_blob": null,
                    "output_blob": null,
                    "error_blob": null,
                    "metadata": {}
                },
                {
                    "id": child_id,
                    "run_id": "run-old001",
                    "parent_event_id": parent_id,
                    "sequence": 2,
                    "source": "Tool",
                    "kind": "tool.call",
                    "started_at": "2026-01-01T00:00:00Z",
                    "ended_at": null,
                    "duration_ms": null,
                    "status": "Success",
                    "side_effect": "None",
                    "input_blob": null,
                    "output_blob": null,
                    "error_blob": null,
                    "metadata": {}
                }
            ],
            "blobs": {},
            "exported_at": "2026-01-01T00:00:02Z"
        });

        let result = import_portable(store.as_ref(), &json.to_string(), true)
            .await
            .unwrap();
        assert!(result.remapped);
        assert_eq!(result.events, 2);

        let imported = store.get_events(&result.run_id).await.unwrap();
        assert_eq!(imported.len(), 2);

        // Parent event should have no parent_event_id (it was null originally)
        let parent = imported
            .iter()
            .find(|e| e.parent_event_id.is_none())
            .unwrap();
        // Child event should have parent_event_id pointing to the parent's new ID
        let child = imported
            .iter()
            .find(|e| e.parent_event_id.is_some())
            .unwrap();
        assert_eq!(
            child.parent_event_id.as_deref(),
            Some(parent.id.as_str()),
            "parent_event_id must be remapped to the new parent ID"
        );
        // Ensure the old IDs are gone
        assert_ne!(parent.id, parent_id);
        assert_ne!(child.id, child_id);
        assert_ne!(
            child.parent_event_id.as_deref(),
            Some(parent_id),
            "parent_event_id must NOT still reference the old ID"
        );
    }
    #[tokio::test]
    async fn test_portable_redact() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = make_run();
        run.cwd = "/home/user/.ssh/keys/secret-project".into();
        store.insert_run(&run).await.unwrap();
        let secret_blob = b"AKIAIOSFODNN7EXAMPLE is the access key";
        let blob_ref = store.store_blob(secret_blob).await.unwrap();
        let mut ev = make_event(1);
        ev.output_blob = Some(blob_ref.key.clone());
        ev.metadata.insert(
            "diff_preview".into(),
            serde_json::json!("secret token sk-abcdefghijklmnopqrstuvwxyz012345"),
        );
        ev.metadata
            .insert("raw".into(), serde_json::json!("raw content with secret"));
        store.insert_event(&ev).await.unwrap();
        let events = store.get_events(&run.id).await.unwrap();
        let output = export_portable(store.as_ref(), &run, &events, true)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["run"]["cwd"], "secret-project");
        let event_meta = &parsed["events"][0]["metadata"];
        assert!(
            !event_meta.get("raw").is_some_and(|v| !v.is_null()),
            "raw metadata should be removed"
        );
        assert_eq!(
            event_meta["diff_preview"], "[REDACTED]",
            "diff_preview should be redacted"
        );
    }
}
