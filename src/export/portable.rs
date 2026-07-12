//! Portable JSON archives for sharing runs offline (optionally with blobs).

use std::collections::HashSet;

use anyhow::Context;
use base64::Engine;

use crate::core::blob::BlobReference;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

const PORTABLE_VERSION: u64 = 2;

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
        let bref = BlobReference::new(key.clone(), 0);
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
pub async fn import_portable(
    store: &dyn TraceStore,
    json: &str,
    new_ids: bool,
) -> anyhow::Result<ImportResult> {
    let root: serde_json::Value =
        serde_json::from_str(json).context("invalid portable JSON")?;
    let version = root
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if version != 1 && version != 2 {
        anyhow::bail!("unsupported portable version: {version} (expected 1 or 2)");
    }

    let mut run: Run = serde_json::from_value(
        root.get("run")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing run object"))?,
    )
    .context("invalid run payload")?;

    let mut events: Vec<TraceEvent> = serde_json::from_value(
        root.get("events")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )
    .context("invalid events payload")?;

    // Restore blobs first so content-addressed keys remain valid
    let mut blobs_restored = 0usize;
    if let Some(obj) = root.get("blobs").and_then(|v| v.as_object()) {
        for (key, entry) in obj {
            let data = decode_blob_entry(entry)
                .with_context(|| format!("blob {key}"))?;
            let stored = store.store_blob(&data).await?;
            if stored.key != *key {
                // Blob stored under its computed hash, but events reference
                // the expected key. Rename so load_blob(key) succeeds.
                if let Err(e) = store.move_blob(&stored.key, key).await {
                    tracing::warn!(
                        expected = %key,
                        got = %stored.key,
                        error = %e,
                        "failed to rename mismatched blob"
                    );
                } else {
                    tracing::debug!(
                        expected = %key,
                        computed = %stored.key,
                        "renamed blob to expected key"
                    );
                }
            }
            blobs_restored += 1;
        }
    }

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
        // Build old→new ID map so parent_event_id references stay valid
        let mut id_map = std::collections::HashMap::new();
        for ev in &mut events {
            let old_ev_id = ev.id.clone();
            ev.id = uuid::Uuid::new_v4().to_string();
            ev.run_id = run.id.clone();
            id_map.insert(old_ev_id, ev.id.clone());
        }
        // Remap parent_event_id to new IDs
        for ev in &mut events {
            if let Some(pid) = &ev.parent_event_id {
                if let Some(new_pid) = id_map.get(pid) {
                    ev.parent_event_id = Some(new_pid.clone());
                }
            }
        }
        remapped = true;
    } else {
        if store.get_run(&run.id).await?.is_some() {
            anyhow::bail!(
                "run {} already exists (omit --keep-ids or delete first)",
                &run.id[..8.min(run.id.len())]
            );
        }
        remapped = false;
    }

    events.sort_by_key(|e| e.sequence);
    store.insert_run(&run).await?;
    for ev in &events {
        store.insert_event(ev).await?;
    }

    Ok(ImportResult {
        run_id: run.id,
        events: events.len(),
        blobs: blobs_restored,
        remapped,
    })
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
                meta.insert(
                    "diff_preview".to_string(),
                    serde_json::json!("[REDACTED]"),
                );
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
        Run {
            id: "run-port001".into(),
            name: None,
            command: vec!["echo".into(), "hello".into()],
            cwd: "/home/user/project".into(),
            project_dir: "/home/user/project".into(),
            tags: vec![],
            notes: None,
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 1,
        }
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
        assert_eq!(
            parsed["blobs"][&blob.key]["size"].as_u64().unwrap(),
            10
        );
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
        let result = import_portable(store2.as_ref(), &json, true)
            .await
            .unwrap();
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
        let parent = imported.iter().find(|e| e.parent_event_id.is_none()).unwrap();
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
}
