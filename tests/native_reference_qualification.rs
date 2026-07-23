//! Release qualification for the Claude Code hooks native reference adapter.

use std::sync::Arc;
use std::time::{Duration, Instant};

use blackbox::integrations::ClaudeHooksAdapter;
use blackbox::native::NativeRecorder;
use blackbox::storage::store::InMemoryStore;
use blackbox::storage::TraceStore;
use serde_json::json;

#[tokio::test]
async fn claude_hooks_overhead_loss_isolation_and_upgrade_compatibility() {
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let recorder = NativeRecorder::new(store.clone());
    let adapter = ClaudeHooksAdapter::new();
    let coverage = adapter.coverage();
    assert_eq!(coverage.conformance_level, "recorder");
    assert!(!coverage.failure_modes.is_empty());
    assert!(!coverage.unsupported.is_empty());

    for envelope in adapter
        .map_hook(
            "reference-run",
            &json!({
                "hook_event_name": "SessionStart",
                "session_id": "qualification",
                "cwd": "/tmp"
            }),
            0,
        )
        .unwrap()
    {
        recorder.apply_envelope(envelope).await.unwrap();
    }
    let run_id = store.list_runs().await.unwrap()[0].id.clone();

    let mut latencies = Vec::with_capacity(500);
    for sequence in 1..=500 {
        let envelopes = adapter
            .map_hook(
                &run_id,
                &json!({
                    "hook_event_name": "PreToolUse",
                    "session_id": "qualification",
                    "tool_name": "Read",
                    "tool_input": {"path": "README.md"}
                }),
                sequence,
            )
            .unwrap();
        let started = Instant::now();
        for envelope in envelopes {
            recorder.apply_envelope(envelope).await.unwrap();
        }
        latencies.push(started.elapsed());
    }
    latencies.sort_unstable();
    let p99 = latencies[latencies.len() * 99 / 100];
    eprintln!(
        "claude-hooks qualification: events=500 p99_us={}",
        p99.as_micros()
    );
    assert!(
        p99 < Duration::from_millis(100),
        "in-memory reference path p99 was {p99:?}"
    );
    assert_eq!(store.count_events(&run_id).await.unwrap(), 501);

    // A malformed producer payload is rejected and cannot alter the run.
    let before = store.count_events(&run_id).await.unwrap();
    assert!(adapter
        .map_hook(&run_id, &json!({"session_id": "qualification"}), 501)
        .is_err());
    assert_eq!(store.count_events(&run_id).await.unwrap(), before);

    // Unknown future hooks degrade to a generic evidence event while unknown
    // additive fields survive inside raw_hook metadata.
    let future = json!({
        "hook_event_name": "FutureHookV2",
        "session_id": "qualification",
        "new_field": {"preserve": true}
    });
    let envelopes = adapter.map_hook(&run_id, &future, 502).unwrap();
    assert_eq!(envelopes.len(), 1);
    recorder
        .apply_envelope(envelopes.into_iter().next().unwrap())
        .await
        .unwrap();
    let events = store.get_events(&run_id).await.unwrap();
    let generic = events
        .iter()
        .find(|event| event.kind == "hook.FutureHookV2")
        .expect("future hook recorded generically");
    assert_eq!(generic.metadata["raw_hook"]["new_field"]["preserve"], true);
}
