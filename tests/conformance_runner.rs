//! 1.9 Phase F: public conformance runner and Claude hooks reference.

use std::path::PathBuf;
use std::sync::Arc;

use blackbox::conformance::{run_conformance, ConformanceLevel};
use blackbox::integrations::{ClaudeHooksAdapter, CLAUDE_HOOKS_CONFORMANCE_LEVEL};
use blackbox::native::NativeRecorder;
use blackbox::storage::store::InMemoryStore;
use blackbox::storage::TraceStore;
use serde_json::json;

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

#[test]
fn core_profile_passes() {
    let report = run_conformance(ConformanceLevel::Core, Some(&vectors_root()));
    assert!(
        report.passed,
        "core failed: {:?}",
        report
            .cases
            .iter()
            .filter(|c| c.status != "pass")
            .collect::<Vec<_>>()
    );
}

#[test]
fn recorder_profile_passes() {
    let report = run_conformance(ConformanceLevel::Recorder, Some(&vectors_root()));
    assert!(
        report.passed,
        "recorder failed: {:?}",
        report
            .cases
            .iter()
            .filter(|c| c.status != "pass")
            .collect::<Vec<_>>()
    );
}

#[test]
fn boundary_profile_passes() {
    let report = run_conformance(ConformanceLevel::Boundary, Some(&vectors_root()));
    assert!(report.passed, "{:?}", report.cases);
}

#[test]
fn forensic_profile_passes() {
    let report = run_conformance(ConformanceLevel::Forensic, Some(&vectors_root()));
    assert!(report.passed, "{:?}", report.cases);
}

#[test]
fn claude_hooks_reference_passes_recorder_level() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let rec = NativeRecorder::new(store.clone());
    let adapter = ClaudeHooksAdapter::new();
    assert_eq!(
        adapter.coverage().conformance_level,
        CLAUDE_HOOKS_CONFORMANCE_LEVEL.as_str()
    );

    rt.block_on(async {
        let start = json!({
            "hook_event_name": "SessionStart",
            "session_id": "s-conf",
            "cwd": "/tmp"
        });
        for env in adapter.map_hook("ignored", &start, 0).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }
        let rid = store.list_runs().await.unwrap()[0].id.clone();
        let pre = json!({
            "hook_event_name": "PreToolUse",
            "session_id": "s-conf",
            "tool_name": "Read",
            "tool_input": {"path": "README.md"},
            "permission_decision": "allow"
        });
        for env in adapter.map_hook(&rid, &pre, 1).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }
        let end = json!({
            "hook_event_name": "SessionEnd",
            "session_id": "s-conf",
            "exit_code": 0
        });
        for env in adapter.map_hook(&rid, &end, 2).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }
        assert!(store.count_events(&rid).await.unwrap() >= 3);
    });

    // Drop runtime before conformance (which may build its own runtime).
    drop(rt);

    // Reference integration must pass the same public Recorder suite.
    let report = run_conformance(ConformanceLevel::Recorder, Some(&vectors_root()));
    assert!(report.passed);
}
