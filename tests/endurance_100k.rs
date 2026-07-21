//! 1.6 endurance: real 100,000-event fixture — runs on every PR/CI suite.
//!
//! Uses transactional batch inserts (production high-volume path). Validates
//! exact totals, incremental aggregates, cursor pagination to exhaustion,
//! postmortem early evidence, deep fsck, and portable export/import — without
//! reloading all 100k events into RAM for a second recompute pass.

use std::sync::Arc;
use std::time::Instant;

use blackbox::aggregates::RunAggregates;
use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::export::portable::{export_portable, import_portable};
use blackbox::integrity::{fsck_store, FsckMode, FsckOptions};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, SummaryOptions};

const N_EVENTS: u64 = 100_000;
const BATCH: usize = 2_000;

#[tokio::test]
async fn endurance_100k_event_fixture() {
    let t0 = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("e.db");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    let store = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());

    let mut run = Run::new(vec!["endurance".into()], dir.path().display().to_string());
    store.insert_run(&run).await.unwrap();

    let mut local = RunAggregates::new(&run.id);
    let mut batch = Vec::with_capacity(BATCH);
    let mut seq = 0u64;

    let push = |ev: TraceEvent, batch: &mut Vec<TraceEvent>, local: &mut RunAggregates| {
        local.observe(&ev);
        batch.push(ev);
    };

    seq += 1;
    let mut human = TraceEvent::new(&run.id, EventSource::Human, "human.input");
    human.sequence = seq;
    human.id = format!("e-{seq}");
    human.metadata.insert(
        "text".into(),
        serde_json::json!("endurance early instruction"),
    );
    push(human, &mut batch, &mut local);

    seq += 1;
    let mut early_fail = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    early_fail.sequence = seq;
    early_fail.id = format!("e-{seq}");
    early_fail.status = EventStatus::Error;
    early_fail
        .metadata
        .insert("message".into(), serde_json::json!("early failure"));
    push(early_fail, &mut batch, &mut local);

    let bulk = N_EVENTS.saturating_sub(4);
    for i in 0..bulk {
        seq += 1;
        let mut e = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        e.sequence = seq;
        e.id = format!("e-{seq}");
        e.metadata.insert("i".into(), serde_json::json!(i));
        local.observe(&e);
        batch.push(e);
        if batch.len() >= BATCH {
            store.insert_events_batch(&batch).await.unwrap();
            batch.clear();
        }
    }

    seq += 1;
    let mut late = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    late.sequence = seq;
    late.id = format!("e-{seq}");
    late.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    push(late, &mut batch, &mut local);

    seq += 1;
    let mut late_fail = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    late_fail.sequence = seq;
    late_fail.id = format!("e-{seq}");
    late_fail.status = EventStatus::Error;
    late_fail
        .metadata
        .insert("message".into(), serde_json::json!("late failure"));
    push(late_fail, &mut batch, &mut local);

    if !batch.is_empty() {
        store.insert_events_batch(&batch).await.unwrap();
    }

    local.aggregates_complete = true;
    store.put_run_aggregates(&local).await.unwrap();

    run.next_sequence = seq + 1;
    store.update_run(&run).await.unwrap();

    let count = store.count_events(&run.id).await.unwrap() as u64;
    assert_eq!(count, local.events_total);
    assert!(count >= N_EVENTS, "got {count}");

    let stored = store
        .get_run_aggregates(&run.id)
        .await
        .unwrap()
        .expect("aggregates");
    assert_eq!(stored.events_total, count);
    assert_eq!(stored.tool_calls, local.tool_calls);
    assert!(stored.first_human_instruction.is_some());
    assert!(
        stored
            .first_failure
            .as_ref()
            .unwrap()
            .detail
            .contains("early"),
        "{:?}",
        stored.first_failure
    );
    assert!(
        stored
            .last_failure
            .as_ref()
            .unwrap()
            .detail
            .contains("late"),
        "{:?}",
        stored.last_failure
    );

    // Pagination to exhaustion (does not load all rows at once).
    let mut after = 0u64;
    let mut paged = 0usize;
    loop {
        let page = store
            .get_events_range(&run.id, after, u64::MAX, 5000)
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

    // Kind-filtered page still works late in the stream.
    let tools = store
        .get_events_by_kind_page(&run.id, &["tool.call", "tool.result"], None, 10)
        .await
        .unwrap();
    assert!(tools.events.len() >= 3);

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

    let events_head = store.get_events_head(&run.id, 50).await.unwrap();
    let portable = export_portable(store.as_ref(), &run_loaded, &events_head, true)
        .await
        .unwrap();
    let store2 = Arc::new(SqliteStore::open_memory().unwrap());
    let imp = import_portable(store2.as_ref(), &portable, true)
        .await
        .unwrap();
    assert_eq!(imp.events, events_head.len());

    let elapsed = t0.elapsed();
    eprintln!(
        "endurance_100k: events={count} elapsed={:?} db={}",
        elapsed,
        db.display()
    );
    assert!(
        elapsed.as_secs() < 180,
        "endurance took too long for PR CI: {elapsed:?}"
    );
}
