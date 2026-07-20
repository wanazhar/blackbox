//! 1.5 A1: portable import hash validation and atomic staging.

use std::sync::Arc;

use base64::Engine;
use blackbox::core::blob::BlobReference;
use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::crypto::content_key;
use blackbox::export::portable::{export_portable, import_portable};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use chrono::Utc;

fn base_run(id: &str) -> Run {
    let mut r = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
    r.id = id.into();
    r.status = blackbox::core::run::RunStatus::Succeeded;
    r.ended_at = Some(Utc::now());
    r.exit_code = Some(0);
    r.next_sequence = 2;
    r
}

fn base_event(run_id: &str, seq: u64, id: &str) -> TraceEvent {
    TraceEvent {
        id: id.into(),
        run_id: run_id.into(),
        parent_event_id: None,
        sequence: seq,
        source: EventSource::Terminal,
        kind: "terminal.output".into(),
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        duration_ms: Some(1),
        status: EventStatus::Success,
        side_effect: blackbox::core::event::SideEffect::None,
        input_blob: None,
        output_blob: None,
        error_blob: None,
        metadata: Default::default(),
    }
}

#[tokio::test]
async fn hash_mismatch_rejects_archive() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let declared = "a".repeat(64);
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-hash-bad",
            "name": null,
            "command": ["echo"],
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
        "blobs": {
            declared: {
                "encoding": "base64",
                "size": 5,
                "data": base64::engine::general_purpose::STANDARD.encode(b"hello")
            }
        },
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("hash mismatch") || msg.contains("blob hash"),
        "expected hash mismatch, got: {msg}"
    );
    assert!(store.list_runs().await.unwrap().is_empty());
    assert!(store.all_blob_keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_run_checked_before_writes() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = base_run("run-dup-001");
    store.insert_run(&run).await.unwrap();

    let payload = b"shared-content";
    let key = content_key(payload);
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-dup-001",
            "name": null,
            "command": ["echo"],
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
        "blobs": {
            key.clone(): {
                "encoding": "base64",
                "size": payload.len(),
                "data": b64
            }
        },
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), false)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("already exists"),
        "got: {err:#}"
    );
    // Duplicate check runs before blob writes — nothing new should be loadable.
    let bref = BlobReference::try_new(key.clone(), 0).unwrap();
    assert!(
        store.load_blob(&bref).await.is_err(),
        "rejected import must not leave blob loadable"
    );
    assert!(!store
        .all_blob_keys()
        .await
        .unwrap()
        .iter()
        .any(|k| k == &key));
}

#[tokio::test]
async fn verified_round_trip_keeps_content() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = base_run("run-ok-001");
    store.insert_run(&run).await.unwrap();
    let blob = store.store_blob(b"payload-bytes-xyz").await.unwrap();
    let mut ev = base_event(&run.id, 1, "evt-ok-1");
    ev.output_blob = Some(blob.key.clone());
    store.insert_event(&ev).await.unwrap();

    let events = store.get_events(&run.id).await.unwrap();
    let json = export_portable(store.as_ref(), &run, &events, false)
        .await
        .unwrap();

    let dest = Arc::new(SqliteStore::open_memory().unwrap());
    let result = import_portable(dest.as_ref(), &json, true).await.unwrap();
    assert_eq!(result.events, 1);
    assert_eq!(result.blobs, 1);

    let imported = dest.get_events(&result.run_id).await.unwrap();
    let key = imported[0].output_blob.as_ref().unwrap();
    let data = dest
        .load_blob(&BlobReference::try_new(key.clone(), 0).unwrap())
        .await
        .unwrap();
    assert_eq!(data, b"payload-bytes-xyz");
}

#[tokio::test]
async fn malformed_parent_reference_rejected() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-parent-bad",
            "name": null,
            "command": ["echo"],
            "cwd": "/tmp",
            "project_dir": "/tmp",
            "tags": [],
            "notes": null,
            "status": "Succeeded",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:00:01Z",
            "exit_code": 0,
            "parent_run_id": null,
            "next_sequence": 2
        },
        "events": [{
            "id": "evt-child",
            "run_id": "run-parent-bad",
            "parent_event_id": "does-not-exist",
            "sequence": 1,
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
        }],
        "blobs": {},
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("parent_event_id"),
        "got: {err:#}"
    );
    assert!(store.list_runs().await.unwrap().is_empty());
}

#[tokio::test]
async fn missing_blob_reference_rejected() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let real = content_key(b"actual");
    let missing = "b".repeat(64);
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"actual");
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-missing-blob",
            "name": null,
            "command": ["echo"],
            "cwd": "/tmp",
            "project_dir": "/tmp",
            "tags": [],
            "notes": null,
            "status": "Succeeded",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:00:01Z",
            "exit_code": 0,
            "parent_run_id": null,
            "next_sequence": 2
        },
        "events": [{
            "id": "evt-1",
            "run_id": "run-missing-blob",
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
            "output_blob": missing,
            "error_blob": null,
            "metadata": {}
        }],
        "blobs": {
            real: {
                "encoding": "base64",
                "size": 6,
                "data": b64
            }
        },
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not present in archive blobs"),
        "got: {err:#}"
    );
    assert!(store.list_runs().await.unwrap().is_empty());
}

#[tokio::test]
async fn nested_secret_in_metadata_is_redacted() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-secret",
            "name": null,
            "command": ["echo"],
            "cwd": "/tmp",
            "project_dir": "/tmp",
            "tags": [],
            "notes": null,
            "status": "Succeeded",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:00:01Z",
            "exit_code": 0,
            "parent_run_id": null,
            "next_sequence": 2
        },
        "events": [{
            "id": "evt-secret",
            "run_id": "run-secret",
            "parent_event_id": null,
            "sequence": 1,
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
            "metadata": {
                "nested": {
                    "token": "sk-abcdefghijklmnopqrstuvwxyz012345"
                }
            }
        }],
        "blobs": {},
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let result = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap();
    let events = store.get_events(&result.run_id).await.unwrap();
    let meta = serde_json::to_string(&events[0].metadata).unwrap();
    assert!(
        !meta.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
        "nested secret survived import: {meta}"
    );
}

#[tokio::test]
async fn keep_ids_import_is_batch_and_complete() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let payload = b"batch-blob";
    let key = content_key(payload);
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "name": null,
            "command": ["echo"],
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
                "id": "eeeeeeee-1111-1111-1111-eeeeeeeeeeee",
                "run_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
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
                "output_blob": key.clone(),
                "error_blob": null,
                "metadata": {}
            },
            {
                "id": "eeeeeeee-2222-2222-2222-eeeeeeeeeeee",
                "run_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "parent_event_id": "eeeeeeee-1111-1111-1111-eeeeeeeeeeee",
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
        "blobs": {
            key.clone(): {
                "encoding": "base64",
                "size": payload.len(),
                "data": b64
            }
        },
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let result = import_portable(store.as_ref(), &json.to_string(), false)
        .await
        .unwrap();
    assert!(!result.remapped);
    assert_eq!(result.run_id, "cccccccc-cccc-cccc-cccc-cccccccccccc");
    assert_eq!(result.events, 2);
    assert_eq!(result.blobs, 1);
    assert_eq!(store.count_events(&result.run_id).await.unwrap(), 2);
    let data = store
        .load_blob(&BlobReference::try_new(key, 0).unwrap())
        .await
        .unwrap();
    assert_eq!(data, payload);
}
