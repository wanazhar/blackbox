//! 1.5 D1: safe tool deduplication — preserve retries; merge proven cross-source dupes only.

use std::sync::Arc;

use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::pipeline::EventWriter;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn repeated_idless_commands_survive() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["agent".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    for _ in 0..3 {
        let mut call = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        call.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        call.metadata
            .insert("input".into(), serde_json::json!({"cmd": "cargo test"}));
        writer.write(call).await.unwrap();
    }

    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(
        events.iter().filter(|e| e.kind == "tool.call").count(),
        3,
        "three ID-less cargo test calls must all be stored"
    );
}

#[tokio::test]
async fn proven_pty_native_log_duplicates_merge() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["agent".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    let mut pty = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    pty.status = EventStatus::Running;
    pty.metadata
        .insert("tool_use_id".into(), serde_json::json!("call-42"));
    pty.metadata
        .insert("tool_name".into(), serde_json::json!("Read"));
    pty.metadata
        .insert("input".into(), serde_json::json!({"path": "src/main.rs"}));
    pty.metadata
        .insert("from_pty".into(), serde_json::json!(true));
    let kept = writer.write(pty).await.unwrap();

    let mut native = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    native
        .metadata
        .insert("tool_use_id".into(), serde_json::json!("call-42"));
    native
        .metadata
        .insert("tool_name".into(), serde_json::json!("Read"));
    native
        .metadata
        .insert("input".into(), serde_json::json!({"path": "src/main.rs"}));
    native
        .metadata
        .insert("native_log".into(), serde_json::json!("/tmp/session.jsonl"));
    let skipped = writer.write(native).await.unwrap();

    assert_eq!(
        skipped.metadata.get("deduped").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        skipped
            .metadata
            .get("duplicate_of")
            .and_then(|v| v.as_str()),
        Some(kept.id.as_str())
    );
    assert_eq!(
        skipped
            .metadata
            .get("duplicate_reason")
            .and_then(|v| v.as_str()),
        Some("same_tool_use_id_cross_source")
    );

    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(events.iter().filter(|e| e.kind == "tool.call").count(), 1);

    // Kept event annotated with provenance.
    let stored = store.get_event(&kept.id).await.unwrap().unwrap();
    let prov = stored
        .metadata
        .get("capture_provenance")
        .and_then(|v| v.as_array())
        .expect("capture_provenance on kept event");
    let labels: Vec<&str> = prov.iter().filter_map(|v| v.as_str()).collect();
    assert!(labels.contains(&"pty"), "{labels:?}");
    assert!(labels.contains(&"native_log"), "{labels:?}");
}

#[tokio::test]
async fn payload_mismatch_prevents_dedupe() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["agent".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    let mut a = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    a.metadata
        .insert("tool_use_id".into(), serde_json::json!("shared-id"));
    a.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    a.metadata
        .insert("input".into(), serde_json::json!({"cmd": "ls"}));

    let mut b = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    b.metadata
        .insert("tool_use_id".into(), serde_json::json!("shared-id"));
    b.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    b.metadata
        .insert("input".into(), serde_json::json!({"cmd": "pwd"}));

    writer.write(a).await.unwrap();
    writer.write(b).await.unwrap();

    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(events.iter().filter(|e| e.kind == "tool.call").count(), 2);
}
