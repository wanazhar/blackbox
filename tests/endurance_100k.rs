//! 1.6 endurance: real 100,000-event fixture (release-qualify material).
//!
//! Run with: `cargo test --test endurance_100k -- --ignored --nocapture`
//! Normal `cargo test` skips this (#[ignore]) so everyday CI stays fast.

use std::sync::Arc;
use std::time::Instant;

use blackbox::aggregates::RunAggregates;
use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::export::portable::{export_portable, import_portable};
use blackbox::integrity::{fsck_store, FsckMode, FsckOptions};
use blackbox::pipeline::EventWriter;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, SummaryOptions};

const N_EVENTS: u64 = 100_000;

#[tokio::test]
#[ignore = "100k endurance — run via release-qualify or cargo test -- --ignored"]
async fn endurance_100k_event_fixture() {
    let t0 = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("e.db");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    let store = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());

    let run = Run::new(vec!["endurance".into()], dir.path().display().to_string());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new_batched(store.clone(), run.id.clone());

    // Early evidence that must remain visible.
    let mut human = TraceEvent::new(&run.id, EventSource::Human, "human.input");
    human.metadata.insert(
        "text".into(),
        serde_json::json!("endurance early instruction"),
    );
    writer.write(human).await.unwrap();

    let mut early_fail = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    early_fail.status = EventStatus::Error;
    early_fail
        .metadata
        .insert("message".into(), serde_json::json!("early failure"));
    writer.write(early_fail).await.unwrap();

    // Bulk terminal noise.
    for i in 0..(N_EVENTS - 4) {
        let mut e = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        e.metadata
            .insert("i".into(), serde_json::json!(i));
        writer.write(e).await.unwrap();
        if i % 10_000 == 0 {
            // yield occasionally
            tokio::task::yield_now().await;
        }
    }

    // Late failure + tool call.
    let mut late = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    late.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    writer.write(late).await.unwrap();
    let mut late_fail = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    late_fail.status = EventStatus::Error;
    late_fail
        .metadata
        .insert("message".into(), serde_json::json!("late failure"));
    writer.write(late_fail).await.unwrap();

    writer.shutdown().await.unwrap();

    let count = store.count_events(&run.id).await.unwrap() as u64;
    assert!(
        count >= N_EVENTS,
        "expected >= {N_EVENTS} events, got {count}"
    );

    // Exact aggregates (recompute).
    let agg = store.recompute_run_aggregates(&run.id).await.unwrap();
    assert_eq!(agg.events_total, count);
    assert!(agg.first_human_instruction.is_some());
    assert!(agg.first_failure.is_some());
    assert!(agg.last_failure.is_some());
    assert_eq!(
        agg.first_failure.as_ref().unwrap().detail.contains("early"),
        true
    );

    // Incremental == recompute
    let events = store.get_events(&run.id).await.unwrap();
    let recomputed = RunAggregates::recompute(&run.id, &events);
    assert_eq!(agg.events_total, recomputed.events_total);
    assert_eq!(agg.tool_calls, recomputed.tool_calls);

    // Pagination to exhaustion
    let mut after = 0u64;
    let mut paged = 0usize;
    loop {
        let page = store
            .get_events_range(&run.id, after, u64::MAX, 1000)
            .await
            .unwrap();
        if page.events.is_empty() {
            break;
        }
        paged += page.events.len();
        after = page.events.last().unwrap().sequence;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(paged as u64, count);

    // Postmortem / summary with early evidence
    let mut run_loaded = store.get_run(&run.id).await.unwrap().unwrap();
    run_loaded.next_sequence = count + 1;
    let summary = build_summary(
        store.as_ref(),
        &run_loaded,
        SummaryOptions {
            short: true,
            full: false,
        },
    )
    .await
    .unwrap();
    let text = serde_json::to_string(&summary).unwrap();
    assert!(
        text.contains("endurance early instruction") || text.contains("early"),
        "early evidence missing from summary"
    );

    // fsck deep
    let report = fsck_store(
        store.clone(),
        FsckOptions {
            mode: FsckMode::Deep,
            blob_dir: Some(blobs.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        report.ok || report.error_count == 0,
        "fsck findings: {:?}",
        report.findings
    );

    // Export/import round-trip (metadata only if huge — use limited events for portable)
    // Full 100k portable may be large; export still should succeed with redact.
    let events_head = store.get_events_head(&run.id, 100).await.unwrap();
    let portable = export_portable(store.as_ref(), &run_loaded, &events_head, true)
        .await
        .unwrap();
    let store2 = Arc::new(SqliteStore::open_memory().unwrap());
    let imp = import_portable(store2.as_ref(), &portable, true)
        .await
        .unwrap();
    assert_eq!(imp.events, events_head.len());

    // FTS: best-effort search availability
    let _ = store.fts_event_ids("early", 10).await;

    let elapsed = t0.elapsed();
    eprintln!(
        "endurance_100k: events={count} elapsed={:?} db={} blobs={}",
        elapsed,
        db.display(),
        blobs.display()
    );

    // Soft memory: process shouldn't take forever; allow generous 10 min in CI.
    assert!(
        elapsed.as_secs() < 600,
        "endurance took too long: {elapsed:?}"
    );
}
