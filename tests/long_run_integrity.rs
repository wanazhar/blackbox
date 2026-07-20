//! 1.5 L1/L2: long-run aggregates and analysis_scope stay correct beyond load caps.

use std::sync::Arc;

use blackbox::aggregates::RunAggregates;
use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::pipeline::EventWriter;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, SummaryOptions};

/// Large enough that default/short windows cannot see early events without salient load.
/// Exceeds DEFAULT_TAIL (4k) and SHORT_TAIL; 100k scale is release-qualify material.
const N_EVENTS: usize = 8_000;

#[tokio::test]
async fn aggregates_exact_totals_for_large_run() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["agent".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    // Early human instruction + failure that must remain visible later.
    let mut human = TraceEvent::new(&run.id, EventSource::Human, "human.input");
    human.metadata.insert(
        "text".into(),
        serde_json::json!("fix the flaky integration test"),
    );
    writer.write(human).await.unwrap();

    let mut fail = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    fail.status = EventStatus::Error;
    fail.metadata
        .insert("tool_use_id".into(), serde_json::json!("early-fail"));
    fail.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    fail.metadata.insert(
        "message".into(),
        serde_json::json!("test failed: assert eq"),
    );
    writer.write(fail).await.unwrap();

    let mut call = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    call.metadata
        .insert("tool_use_id".into(), serde_json::json!("early-call"));
    call.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    writer.write(call).await.unwrap();

    // Flood the timeline in batches (still updates aggregates).
    let next_seq = writer.next_sequence();
    let mut batch = Vec::with_capacity(500);
    for i in 0..N_EVENTS {
        let mut e = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        e.sequence = next_seq + i as u64;
        e.metadata.insert("chunk".into(), serde_json::json!(i));
        batch.push(e);
        if batch.len() >= 500 {
            store.insert_events_batch(&batch).await.unwrap();
            batch.clear();
        }
    }
    if !batch.is_empty() {
        store.insert_events_batch(&batch).await.unwrap();
    }

    let expected_total = (N_EVENTS + 3) as u64;
    let agg = store
        .get_run_aggregates(&run.id)
        .await
        .unwrap()
        .expect("aggregates row");
    assert_eq!(agg.events_total, expected_total);
    assert_eq!(agg.tool_calls, 1);
    assert_eq!(agg.tool_results, 1);
    assert_eq!(agg.tool_failures, 1);
    assert_eq!(
        agg.first_human_instruction.as_ref().unwrap().detail,
        "fix the flaky integration test"
    );
    assert!(
        agg.first_failure
            .as_ref()
            .unwrap()
            .detail
            .contains("test failed"),
        "early failure detail: {:?}",
        agg.first_failure
    );

    // Short summary must still report exact totals and early evidence.
    let summary = build_summary(
        store.as_ref(),
        &run,
        SummaryOptions {
            short: true,
            full: false,
        },
    )
    .await
    .unwrap();

    let scope = summary.analysis_scope.as_ref().expect("analysis_scope");
    assert_eq!(scope.events_total, expected_total);
    assert!(
        (scope.events_loaded as u64) < scope.events_total,
        "short mode should not load every event"
    );
    assert_eq!(scope.strategy, "head_tail_salient");
    assert!(scope.aggregates_complete);

    assert_eq!(summary.tools.total, 1);
    assert_eq!(summary.tools.failed, 1);
    assert_eq!(summary.total_events, Some(expected_total as usize));
    assert!(
        summary.goal.contains("flaky integration"),
        "goal should surface early human instruction: {}",
        summary.goal
    );
    assert_eq!(summary.goal_source, "human_instruction");

    // Default vs short: same factual totals.
    let fullish = build_summary(
        store.as_ref(),
        &run,
        SummaryOptions {
            short: false,
            full: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(fullish.tools.total, summary.tools.total);
    assert_eq!(
        fullish.analysis_scope.as_ref().unwrap().events_total,
        expected_total
    );
}

#[tokio::test]
async fn recompute_recovers_missing_aggregates() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    // Insert events without going through EventWriter aggregate path? insert_event still updates.
    // Simulate "lost" aggregates by overwriting with empty incomplete row then recompute.
    let mut events = Vec::new();
    for i in 1..=100 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
        e.sequence = i;
        store.insert_event(&e).await.unwrap();
        events.push(e);
    }

    let rebuilt = store.recompute_run_aggregates(&run.id).await.unwrap();
    assert_eq!(rebuilt.events_total, 100);
    assert_eq!(rebuilt.by_kind.get("tick"), Some(&100));
    assert!(rebuilt.aggregates_complete);

    let loaded = store.get_run_aggregates(&run.id).await.unwrap().unwrap();
    assert_eq!(loaded.events_total, 100);

    // Manual recompute matches helper.
    let manual = RunAggregates::recompute(&run.id, &events);
    assert_eq!(manual.events_total, loaded.events_total);
}
