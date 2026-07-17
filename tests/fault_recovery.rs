//! 1.4 Phase D — Crash / fault recovery honesty (WS9).
//!
//! Simulates an abandoned `Running` row (supervisor killed mid-run) and asserts
//! reopen recovers to Failed without inventing success, while preserving events.

use std::sync::Arc;

use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn abandoned_running_recovers_to_failed_not_success() {
    let dir = std::env::temp_dir().join(format!("bb-fault-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    let db = dir.join("blackbox.db");
    let blobs = dir.join("blobs");

    // Create store, insert Running run + some events, drop without finalize.
    {
        let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
        let mut run = Run::new(
            vec!["sleep".into(), "999".into()],
            dir.display().to_string(),
        );
        run.status = RunStatus::Running;
        run.name = Some("abandoned".into());
        store.insert_run(&run).await.unwrap();

        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.sequence = 1;
        ev.status = EventStatus::Success;
        ev.metadata.insert(
            "preview".into(),
            serde_json::json!("partial output before kill"),
        );
        store.insert_event(&ev).await.unwrap();

        let mut ev2 = TraceEvent::new(&run.id, EventSource::Process, "process.spawned");
        ev2.sequence = 2;
        ev2.status = EventStatus::Success;
        ev2.metadata.insert("pid".into(), serde_json::json!(12345));
        store.insert_event(&ev2).await.unwrap();

        // Intentionally no apply_run_outcome / status update — simulates SIGKILL.
        drop(store);
    }

    // Re-open triggers recover_stale_runs.
    let store2: Arc<dyn TraceStore> = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());
    let runs = store2.list_runs().await.unwrap();
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert_eq!(
        run.status,
        RunStatus::Failed,
        "abandoned Running must become Failed, not Succeeded/Running"
    );
    assert_ne!(run.status, RunStatus::Succeeded);
    assert!(run.ended_at.is_some(), "recovered run must have ended_at");
    let notes = run.notes.as_deref().unwrap_or("");
    assert!(
        notes.contains("recovered") || notes.contains("interrupted"),
        "notes should record recovery: {notes}"
    );
    assert!(
        notes.contains("incomplete") || notes.contains("interrupted"),
        "notes should warn final events may be incomplete: {notes}"
    );

    // Events must survive recovery.
    let events = store2.get_events(&run.id).await.unwrap();
    assert!(
        events.iter().any(|e| e.kind == "terminal.output"),
        "committed events must be preserved"
    );
    assert!(
        events.iter().any(|e| e.kind == "process.spawned"),
        "process.spawned must be preserved"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn recover_is_idempotent() {
    let dir = std::env::temp_dir().join(format!("bb-fault-idemp-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    let db = dir.join("blackbox.db");
    let blobs = dir.join("blobs");

    {
        let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
        let mut run = Run::new(vec!["true".into()], dir.display().to_string());
        run.status = RunStatus::Running;
        store.insert_run(&run).await.unwrap();
        drop(store);
    }

    let s1 = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let r1 = s1.list_runs().await.unwrap();
    assert_eq!(r1[0].status, RunStatus::Failed);
    let notes1 = r1[0].notes.clone();
    drop(s1);

    let s2 = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let r2 = s2.list_runs().await.unwrap();
    assert_eq!(r2[0].status, RunStatus::Failed);
    // Notes should not grow unbounded on re-open.
    assert_eq!(r2[0].notes, notes1);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn layer_failed_event_does_not_imply_run_success() {
    // Capture-layer failure is a system event; run outcome stays independent.
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["echo".into(), "x".into()], "/tmp".into());
    run.status = RunStatus::Failed;
    run.exit_code = Some(1);
    store.insert_run(&run).await.unwrap();

    let mut fail = TraceEvent::new(&run.id, EventSource::System, "capture.layer.failed");
    fail.status = EventStatus::Error;
    fail.metadata
        .insert("layer".into(), serde_json::json!("filesystem"));
    fail.metadata
        .insert("message".into(), serde_json::json!("watcher crashed"));
    store.insert_event(&fail).await.unwrap();

    let got = store.get_run(&run.id).await.unwrap().unwrap();
    assert_eq!(got.status, RunStatus::Failed);
    assert_eq!(got.exit_code, Some(1));
    let events = store.get_events(&run.id).await.unwrap();
    assert!(events.iter().any(|e| e.kind == "capture.layer.failed"));
}
