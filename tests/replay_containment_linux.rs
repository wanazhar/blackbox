//! 1.5 R1: contained replay capability preflight and fail-closed behavior.
//!
//! Contained mode requires Linux + bubblewrap (`bwrap`). When unavailable the
//! engine must fail closed rather than silently degrade to workspace-only.

use blackbox::core::event::{EventSource, SideEffect, TraceEvent};
use blackbox::core::run::Run;
use blackbox::replay::sandbox::{capability_report, probe_contained_backend, SandboxReplay};
use blackbox::replay::{ReplayEngine, ReplayPolicy};

#[test]
fn contained_probe_is_honest_about_platform() {
    let status = probe_contained_backend();
    if cfg!(target_os = "linux") {
        // Either available or a clear reason — never claim available without a tool.
        if status.available {
            assert_eq!(status.tool.as_deref(), Some("bwrap"));
            assert!(status.reason.contains("bubblewrap") || status.reason.contains("bwrap"));
        } else {
            assert!(status.tool.is_none());
            assert!(!status.reason.is_empty());
        }
    } else {
        assert!(!status.available);
        assert!(status.reason.contains("Linux"));
    }
}

#[test]
fn capability_report_distinguishes_workspace_and_contained() {
    let ws = capability_report(ReplayPolicy::Sandbox, false);
    let backend = ws
        .iter()
        .find(|(k, _)| k == "backend")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(backend, "workspace");
    let kernel = ws
        .iter()
        .find(|(k, _)| k == "kernel isolation")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        kernel.contains("not available") || kernel.contains("contained"),
        "workspace kernel claim: {kernel}"
    );

    let contained = capability_report(ReplayPolicy::Sandbox, true);
    let c_backend = contained
        .iter()
        .find(|(k, _)| k == "backend")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let probe = probe_contained_backend();
    if probe.available {
        assert_eq!(c_backend, "contained-bwrap");
    } else {
        assert_eq!(c_backend, "contained-unavailable");
    }
}

#[tokio::test]
async fn contained_replay_fails_closed_when_backend_missing() {
    let probe = probe_contained_backend();
    if probe.available {
        // Host has bwrap — skip fail-closed path.
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let mut engine = SandboxReplay::new()
        .with_workspace(dir.path().to_path_buf())
        .without_seed()
        .with_contained(true);

    let mut run = Run::new(vec!["true".into()], dir.path().to_string_lossy().into());
    run.name = Some("contain-test".into());
    run.status = blackbox::core::run::RunStatus::Succeeded;
    run.ended_at = Some(chrono::Utc::now());
    run.exit_code = Some(0);

    let err = engine
        .start(&run, &[], None)
        .await
        .expect_err("contained without bwrap must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("unavailable") || msg.contains("bwrap") || msg.contains("Linux"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn contained_replay_runs_when_bwrap_present() {
    let probe = probe_contained_backend();
    if !probe.available {
        eprintln!("skip: {}", probe.reason);
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("marker.txt"), b"ok").unwrap();

    let mut engine = SandboxReplay::new()
        .with_workspace(dir.path().to_path_buf())
        .without_seed()
        .with_contained(true);

    let mut run = Run::new(vec!["true".into()], dir.path().to_string_lossy().into());
    run.name = Some("contain-ok".into());
    run.status = blackbox::core::run::RunStatus::Succeeded;
    run.ended_at = Some(chrono::Utc::now());
    run.exit_code = Some(0);

    // Process event with exact argv for re-execution.
    let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.exec");
    ev.sequence = 1;
    ev.side_effect = SideEffect::None;
    ev.metadata
        .insert("argv".into(), serde_json::json!(["/bin/cat", "marker.txt"]));
    ev.metadata
        .insert("capture_method".into(), serde_json::json!("proc_cmdline"));
    ev.metadata
        .insert("fidelity".into(), serde_json::json!("exact"));
    ev.metadata
        .insert("lossless".into(), serde_json::json!(true));

    let outcome = engine
        .start(&run, &[ev], None)
        .await
        .expect("contained start should succeed with bwrap");
    assert!(outcome.success(), "outcome: {outcome}");
}
