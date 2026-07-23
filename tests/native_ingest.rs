//! 1.9 Phase B: native ingestion without `blackbox run` / PTY.
//!
//! Exit gate: a test harness produces a complete Blackbox run via
//! [`NativeRecorder`] and NDJSON transport with idempotent retries.

use std::sync::Arc;

use blackbox::core::event::EventStatus;
use blackbox::core::run::RunStatus;
use blackbox::native::{
    FinishRunOpts, IngestOp, NativeIngestEnvelope, NativeRecorder, NdjsonIngestServer,
    StartRunOpts,
};
use blackbox::storage::store::InMemoryStore;
use blackbox::storage::TraceStore;
use serde_json::json;

#[tokio::test]
async fn complete_run_without_blackbox_run_or_pty() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::new(store.clone());

    let run = rec
        .start_run(StartRunOpts {
            name: Some("phase-b".into()),
            command: vec!["agent".into(), "--native".into()],
            cwd: Some("/tmp/project".into()),
            adapter: Some("test-harness".into()),
            tags: vec!["native".into()],
            ..Default::default()
        })
        .await
        .unwrap();

    rec.record_model(&run.id, Some("gpt-test"), Some(100), Some(50))
        .await
        .unwrap();
    rec.record_tool(
        &run.id,
        "edit",
        Some(json!({"path": "src/main.rs"})),
        Some(json!({"ok": true})),
        EventStatus::Success,
    )
    .await
    .unwrap();
    rec.record_handoff(&run.id, Some("continuing"))
        .await
        .unwrap();
    rec.record_approval(&run.id, true, Some("operator"))
        .await
        .unwrap();
    rec.record_security_decision(
        &run.id,
        json!({
            "schema": "blackbox.security.decision/v1",
            "id": "d1",
            "provider": "harness",
            "decision": "allow",
            "action_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "decided_at": "2026-07-23T00:00:00Z"
        }),
    )
    .await
    .unwrap();
    rec.attach_evidence(&run.id, "evext-1", Some("proxy"))
        .await
        .unwrap();

    let finished = rec
        .finish_run(
            &run.id,
            FinishRunOpts {
                exit_code: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(finished.status, RunStatus::Succeeded);
    assert_eq!(finished.adapter.as_deref(), Some("test-harness"));

    let events = store.get_events(&run.id).await.unwrap();
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"run.started"));
    assert!(kinds.contains(&"model.completion"));
    assert!(kinds.contains(&"tool.call"));
    assert!(kinds.contains(&"session.handoff"));
    assert!(kinds.contains(&"approval"));
    assert!(kinds.contains(&"security.decision"));
    assert!(kinds.contains(&"evidence.attached"));
    assert!(kinds.contains(&"run.ended"));

    // Monotonic recorder sequence (not client timestamps).
    let seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted);
}

#[tokio::test]
async fn ndjson_retry_and_malformed_isolation() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::new(store.clone());
    let server = NdjsonIngestServer::default();

    let start = r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"k-start","payload":{"cwd":"/tmp","command":["x"]}}"#;
    let outs = server
        .process_buffer(&rec, &format!("{start}\n{start}\nnot-json\n"))
        .await;
    assert_eq!(outs.len(), 3);
    assert!(!outs[0]["duplicate"].as_bool().unwrap());
    assert!(outs[1]["duplicate"].as_bool().unwrap());
    assert_eq!(outs[2]["code"], "malformed_json");
    assert_eq!(store.list_runs().await.unwrap().len(), 1);

    let run_id = outs[0]["run_id"].as_str().unwrap();
    let tool = format!(
        r#"{{"schema":"blackbox.native.ingest/v1","op":"record_tool","idempotency_key":"k-tool","run_id":"{run_id}","payload":{{"tool_name":"bash"}}}}"#
    );
    let outs = server
        .process_buffer(&rec, &format!("{tool}\n{tool}\n"))
        .await;
    assert!(!outs[0]["duplicate"].as_bool().unwrap());
    assert!(outs[1]["duplicate"].as_bool().unwrap());
    assert_eq!(
        store
            .get_events(run_id)
            .await
            .unwrap()
            .iter()
            .filter(|e| e.kind == "tool.call")
            .count(),
        1
    );
}

#[tokio::test]
async fn partial_ndjson_frame_not_committed() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::new(store.clone());
    let server = NdjsonIngestServer::default();
    let partial = r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"partial","payload":{"cwd":"/tmp"}"#;
    let outs = server.process_buffer(&rec, partial).await;
    assert!(outs.is_empty());
    assert!(store.list_runs().await.unwrap().is_empty());
}

#[tokio::test]
async fn envelope_api_covers_lifecycle() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::new(store.clone());

    let start = NativeIngestEnvelope::new(IngestOp::StartRun, "e-start")
        .with_payload(json!({"cwd": "/tmp", "command": ["agent"]}))
        .with_producer("hooks-test");
    let ack = rec.apply_envelope(start).await.unwrap();
    let run_id = ack.run_id.unwrap();

    for (key, op, payload) in [
        (
            "e-model",
            IngestOp::RecordModel,
            json!({"model": "m", "input_tokens": 1}),
        ),
        (
            "e-tool",
            IngestOp::RecordTool,
            json!({"tool_name": "read"}),
        ),
        (
            "e-hand",
            IngestOp::RecordHandoff,
            json!({"summary": "s"}),
        ),
        (
            "e-appr",
            IngestOp::RecordApproval,
            json!({"approved": true, "actor": "u"}),
        ),
        (
            "e-sec",
            IngestOp::RecordSecurityDecision,
            json!({
                "schema": "blackbox.security.decision/v1",
                "id": "d",
                "provider": "opa",
                "decision": "deny",
                "action_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "decided_at": "2026-07-23T00:00:00Z"
            }),
        ),
        (
            "e-ev",
            IngestOp::AttachEvidence,
            json!({"evidence_id": "ext-1"}),
        ),
    ] {
        let env = NativeIngestEnvelope::new(op, key)
            .with_run_id(&run_id)
            .with_payload(payload);
        assert!(!rec.apply_envelope(env).await.unwrap().duplicate);
    }

    let fin = NativeIngestEnvelope::new(IngestOp::FinishRun, "e-fin")
        .with_run_id(&run_id)
        .with_payload(json!({"exit_code": 1}));
    rec.apply_envelope(fin).await.unwrap();

    let run = store.get_run(&run_id).await.unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Failed);
    assert!(store.count_events(&run_id).await.unwrap() >= 8);
}

#[tokio::test]
async fn backpressure_when_pending_saturated() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::with_config(
        store,
        blackbox::native::NativeRecorderConfig {
            max_pending: 0, // immediate backpressure
            ..Default::default()
        },
    );
    let env = NativeIngestEnvelope::new(IngestOp::StartRun, "bp")
        .with_payload(json!({"cwd": "/tmp"}));
    let err = rec.apply_envelope(env).await.unwrap_err();
    assert_eq!(err.code, "backpressure");
    assert!(err.retryable);
}
