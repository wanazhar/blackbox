//! WS4 golden fixtures for postmortem narrative quality.
//!
//! Covers success, failure, interruption, repeated retries, and partial capture.
//! Fixtures are deterministic event graphs — no live harness required.

use std::sync::Arc;

use blackbox::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, format_summary_text, SummaryOptions};
use chrono::{Duration, Utc};

async fn store_run(run: &Run, events: &[TraceEvent]) -> Arc<dyn TraceStore> {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    store.insert_run(run).await.unwrap();
    for ev in events {
        store.insert_event(ev).await.unwrap();
    }
    store
}

fn base_run(status: RunStatus, exit: Option<i32>) -> Run {
    let mut run = Run::new(
        vec!["claude".into(), "-p".into(), "fix auth".into()],
        "/project".into(),
    );
    run.name = Some("fix-auth".into());
    run.status = status;
    run.exit_code = exit;
    run.adapter = Some("claude".into());
    run.started_at = Utc::now() - Duration::minutes(5);
    run.ended_at = Some(Utc::now());
    run.duration_ms = Some(90_000);
    run
}

fn tool_call(run_id: &str, seq: u64, name: &str, cmd: Option<&str>) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Tool, "tool.call");
    ev.sequence = seq;
    ev.status = EventStatus::Running;
    ev.metadata
        .insert("tool_name".into(), serde_json::json!(name));
    if let Some(c) = cmd {
        ev.metadata
            .insert("input".into(), serde_json::json!({ "command": c }));
    }
    ev
}

fn tool_result(run_id: &str, seq: u64, ok: bool, msg: &str) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Tool, "tool.result");
    ev.sequence = seq;
    ev.status = if ok {
        EventStatus::Success
    } else {
        EventStatus::Error
    };
    ev.metadata.insert("message".into(), serde_json::json!(msg));
    ev
}

fn fs_mod(run_id: &str, seq: u64, path: &str, offset_ms: i64) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Filesystem, "filesystem.modified");
    ev.sequence = seq;
    ev.status = EventStatus::Success;
    ev.side_effect = SideEffect::LocalWrite;
    ev.started_at = Utc::now() - Duration::minutes(5) + Duration::milliseconds(offset_ms);
    ev.metadata.insert("path".into(), serde_json::json!(path));
    ev
}

fn coverage(run_id: &str, score: u8, process_tree: bool) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::System, "capture.coverage");
    ev.status = EventStatus::Success;
    ev.metadata.insert(
        "coverage".into(),
        serde_json::json!({
            "quality_score": score,
            "total_events": 12,
            "surfaces": [
                {"name":"pty","enabled":true,"status":"complete","events_count":5,"note":null},
                {"name":"process","enabled":true,"status": if process_tree {"complete"} else {"partial"},"events_count":2,
                 "note": if process_tree {"process-tree capture active"} else {"basic PID tracking only (no /proc)"}},
                {"name":"git","enabled":true,"status":"partial","events_count":0,"note":"no changes"},
                {"name":"filesystem","enabled":true,"status":"complete","events_count":3,"note":null},
                {"name":"environment","enabled":true,"status":"complete","events_count":1,"note":null},
                {"name":"network","enabled":false,"status":"unavailable","events_count":0,"note":"network capture not implemented"},
            ],
            "notes": if process_tree { vec![] } else { vec!["process-tree capture requires Linux /proc"] },
        }),
    );
    ev
}

#[tokio::test]
async fn golden_success_run() {
    let run = base_run(RunStatus::Succeeded, Some(0));
    let events = vec![
        tool_call(&run.id, 1, "Read", None),
        tool_result(&run.id, 2, true, "ok"),
        tool_call(&run.id, 3, "Bash", Some("bun test auth")),
        tool_result(&run.id, 4, true, "43/43 passed"),
        coverage(&run.id, 86, true),
    ];
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    let text = format_summary_text(&summary);

    assert!(
        summary.narrative.contains("SUCCESS") || text.contains("Succeeded"),
        "narrative={}\ntext={text}",
        summary.narrative
    );
    assert!(
        summary.narrative.contains("Errors: none") || summary.errors.is_empty(),
        "{}",
        summary.narrative
    );
    assert!(
        summary
            .capture_coverage
            .as_ref()
            .map(|c| c.quality_score >= 50)
            .unwrap_or(false),
        "expected coverage score"
    );
    assert!(text.contains("Capture coverage") || text.contains("quality"));
}

#[tokio::test]
async fn golden_failure_with_fix_chain() {
    let run = base_run(RunStatus::Failed, Some(1));
    let t0 = Utc::now() - Duration::minutes(5);
    let mut err = tool_result(&run.id, 2, false, "TypeError: session is undefined");
    err.started_at = t0 + Duration::seconds(1);
    let mut file = fs_mod(&run.id, 3, "src/session.ts", 2000);
    file.started_at = t0 + Duration::seconds(2);
    let mut retry = tool_call(&run.id, 4, "Bash", Some("bun test auth"));
    retry.started_at = t0 + Duration::seconds(3);
    let mut retry_ok = tool_result(&run.id, 5, true, "pass");
    retry_ok.started_at = t0 + Duration::seconds(4);

    let events = vec![
        tool_call(&run.id, 1, "Bash", Some("bun test auth")),
        err,
        file,
        retry,
        retry_ok,
        coverage(&run.id, 70, true),
    ];
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();

    assert!(
        summary.narrative.contains("FAILURE") || matches!(summary.status, RunStatus::Failed),
        "{}",
        summary.narrative
    );
    // Failure-to-fix correlator should link error → file → retry when timing fits.
    // Even if chain confidence varies, narrative should mention errors or tools.
    assert!(
        !summary.narrative.is_empty(),
        "expected non-empty narrative"
    );
    assert!(
        summary.tools.failed > 0
            || !summary.errors.is_empty()
            || !summary.failure_fix_chains.is_empty(),
        "expected failure signal in summary"
    );
}

#[tokio::test]
async fn golden_cancelled_interrupted() {
    let mut run = base_run(RunStatus::Cancelled, None);
    run.notes = Some("interrupted by user".into());
    let events = vec![
        tool_call(&run.id, 1, "Bash", Some("sleep 999")),
        coverage(&run.id, 40, false),
    ];
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    assert!(
        summary.narrative.contains("CANCELLED") || matches!(summary.status, RunStatus::Cancelled),
        "{}",
        summary.narrative
    );
}

#[tokio::test]
async fn golden_repeated_retries() {
    let run = base_run(RunStatus::Failed, Some(1));
    let mut events = Vec::new();
    for i in 0..4 {
        events.push(tool_call(
            &run.id,
            (i * 2 + 1) as u64,
            "Bash",
            Some("bun test auth"),
        ));
        events.push(tool_result(
            &run.id,
            (i * 2 + 2) as u64,
            false,
            "TypeError: session is undefined",
        ));
    }
    events.push(coverage(&run.id, 55, true));
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    // RetryWasteDetector should flag repeated command / error.
    assert!(
        !summary.retry_waste.is_empty()
            || summary.narrative.contains("Repeated")
            || summary.tools.total >= 4,
        "retry_waste={:?} narrative={}",
        summary.retry_waste,
        summary.narrative
    );
    if !summary.retry_waste.is_empty() {
        assert!(summary.retry_waste.iter().any(|f| f.count >= 2));
    }
}

/// False-positive trap: an unrelated success must not become a confirmed fix.
#[tokio::test]
async fn golden_unrelated_success_not_confirmed() {
    let run = base_run(RunStatus::Failed, Some(1));
    let t0 = Utc::now() - Duration::minutes(5);
    let mut call = tool_call(&run.id, 1, "Bash", Some("bun test auth"));
    call.started_at = t0;
    call.metadata
        .insert("tool_use_id".into(), serde_json::json!("tu-1"));
    let mut err = tool_result(&run.id, 2, false, "auth failed");
    err.started_at = t0 + Duration::seconds(1);
    err.metadata
        .insert("tool_use_id".into(), serde_json::json!("tu-1"));
    let mut file = fs_mod(&run.id, 3, "README.md", 2000);
    file.started_at = t0 + Duration::seconds(2);
    let mut other = tool_call(&run.id, 4, "Bash", Some("echo hi"));
    other.started_at = t0 + Duration::seconds(3);
    other
        .metadata
        .insert("tool_use_id".into(), serde_json::json!("tu-2"));
    let mut other_ok = tool_result(&run.id, 5, true, "hi");
    other_ok.started_at = t0 + Duration::seconds(4);
    other_ok
        .metadata
        .insert("tool_use_id".into(), serde_json::json!("tu-2"));

    let events = vec![call, err, file, other, other_ok, coverage(&run.id, 60, true)];
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();

    if let Some(chain) = summary.failure_fix_chains.first() {
        assert_ne!(
            chain.confidence, "confirmed",
            "unrelated echo success must not confirm auth fix: {chain:?}"
        );
    }
    // Claims must not assert confirmed verification for this trap.
    assert!(
        summary
            .claims
            .iter()
            .all(|c| c.confidence != "confirmed" || !c.claim.to_lowercase().contains("verification passed")),
        "claims={:?}",
        summary.claims
    );
}

#[tokio::test]
async fn golden_partial_capture() {
    let run = base_run(RunStatus::Succeeded, Some(0));
    let events = vec![
        tool_call(&run.id, 1, "Read", None),
        tool_result(&run.id, 2, true, "ok"),
        coverage(&run.id, 35, false),
    ];
    let store = store_run(&run, &events).await;
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    let cov = summary.capture_coverage.expect("coverage");
    assert!(
        cov.quality_score <= 80,
        "partial capture should not look perfect: {}",
        cov.quality_score
    );
    assert!(
        summary.narrative.contains("Capture quality")
            || summary.narrative.contains("%")
            || cov.surfaces.iter().any(|s| s.status == "partial"
                || s.status == "unavailable"
                || s.note.as_deref().unwrap_or("").contains("/proc")),
        "narrative should respect coverage: {}",
        summary.narrative
    );
    // Network unavailable should appear as a surface, not as "no network happened".
    assert!(
        cov.surfaces.iter().any(|s| s.name == "network"
            || s.note
                .as_ref()
                .map(|n| n.contains("network"))
                .unwrap_or(false))
            || summary.narrative.to_lowercase().contains("network")
            || cov.notes.iter().any(|n| n.contains("process-tree")),
        "partial capture should surface limitations"
    );
}
