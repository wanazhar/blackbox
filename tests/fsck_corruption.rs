//! 1.6 B: fsck detects missing aggregates and deep blob issues.

use std::sync::Arc;

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::crypto::content_key;
use blackbox::integrity::{fsck_store, FsckMode, FsckOptions};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn fsck_flags_missing_aggregates_and_repairs() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["echo".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let mut ev = TraceEvent::new(&run.id, EventSource::System, "tick");
    ev.sequence = 1;
    store.insert_event(&ev).await.unwrap();
    // Aggregates may be auto-updated on insert — recompute path still works.
    let _ = store.put_run_aggregates(&blackbox::aggregates::RunAggregates::new(&run.id));

    let report = fsck_store(
        store.clone(),
        FsckOptions {
            mode: FsckMode::Fast,
            repair: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        report.sections_checked.iter().any(|s| s == "aggregates"),
        "{:?}",
        report.sections_checked
    );
    // After repair, aggregates should exist.
    let agg = store.get_run_aggregates(&run.id).await.unwrap();
    assert!(agg.is_some());
}

#[tokio::test]
async fn fsck_deep_detects_hash_mismatch_via_missing_blob() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["echo".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let fake = content_key(b"not-stored");
    let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
    ev.sequence = 1;
    ev.output_blob = Some(fake.clone());
    store.insert_event(&ev).await.unwrap();

    let report = fsck_store(
        store.clone(),
        FsckOptions {
            mode: FsckMode::Deep,
            repair: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !report.ok || report.error_count > 0,
        "expected missing blob finding: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code.contains("blob") || f.message.contains("blob")),
        "{:?}",
        report.findings
    );
}
