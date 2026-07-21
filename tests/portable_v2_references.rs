//! 1.6 A: portable v2 rejects unresolved blob references even when blobs is empty.

use std::sync::Arc;

use blackbox::export::portable::import_portable;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn v2_event_ref_with_empty_blobs_is_rejected() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let key = "a".repeat(64);
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-empty-blobs",
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
            "run_id": "run-empty-blobs",
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
            "output_blob": key,
            "error_blob": null,
            "metadata": {}
        }],
        "blobs": {},
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("not present in archive blobs"),
        "v2 empty blobs must not waive refs: {msg}"
    );
    assert!(store.list_runs().await.unwrap().is_empty());
}

#[tokio::test]
async fn v1_missing_blobs_still_accepted() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let key = "c".repeat(64);
    let json = serde_json::json!({
        "version": 1,
        "run": {
            "id": "run-v1-missing",
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
            "id": "evt-v1",
            "run_id": "run-v1-missing",
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
            "output_blob": key,
            "error_blob": null,
            "metadata": {}
        }],
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let result = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap();
    assert_eq!(result.events, 1);
    assert_eq!(result.blobs, 0);
}

#[tokio::test]
async fn v2_metadata_blob_ref_must_resolve() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let key = "d".repeat(64);
    let json = serde_json::json!({
        "version": 2,
        "run": {
            "id": "run-meta-blob",
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
            "id": "evt-meta",
            "run_id": "run-meta-blob",
            "parent_event_id": null,
            "sequence": 1,
            "source": "Git",
            "kind": "git.diff",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": null,
            "duration_ms": null,
            "status": "Success",
            "side_effect": "None",
            "input_blob": null,
            "output_blob": null,
            "error_blob": null,
            "metadata": {
                "diff_blob": key
            }
        }],
        "blobs": {},
        "exported_at": "2026-01-01T00:00:02Z"
    });

    let err = import_portable(store.as_ref(), &json.to_string(), true)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not present in archive blobs"),
        "got: {err:#}"
    );
}
