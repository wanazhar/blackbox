//! 1.5 S1: batched storage ingest — barriers, flush, no silent drops.

use std::sync::Arc;
use std::time::Duration;

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::pipeline::{
    is_barrier_kind, BatchIngestConfig, BatchIngestor, EventWriter, DEFAULT_BATCH_SIZE,
};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn live_batched_writer_persists_via_batch() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let writer = EventWriter::new_batched(store.clone(), run.id.clone());
    assert!(writer.is_batched());

    for i in 0..100 {
        let mut e = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        e.metadata.insert("i".into(), serde_json::json!(i));
        writer.write(e).await.unwrap();
    }
    // Non-barrier: may still be in queue
    writer.flush().await.unwrap();
    assert_eq!(store.count_events(&run.id).await.unwrap(), 100);

    let h = writer.health_snapshot();
    let batch = h.batch.expect("batch health");
    assert!(batch.batches >= 1);
    assert_eq!(batch.events_flushed, 100);
    assert!(batch.max_batch_size <= DEFAULT_BATCH_SIZE as u64 || batch.batches >= 2);
    writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn barrier_kinds_flush_without_explicit_flush() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let writer = EventWriter::new_batched(store.clone(), run.id.clone());
    for kind in [
        "run.started",
        "environment.captured",
        "capture.coverage",
        "capture.warning",
        "capture.layer.failed",
        "run.completed",
    ] {
        assert!(is_barrier_kind(kind), "{kind}");
        let e = TraceEvent::new(&run.id, EventSource::System, kind);
        writer.write(e).await.unwrap();
        // Each barrier returns only after durable write.
        assert!(
            store.count_events(&run.id).await.unwrap() > 0,
            "{kind} should be durable"
        );
    }
    writer.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_persists_pending_or_errors() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let writer = EventWriter::with_start_batched(
        store.clone(),
        run.id.clone(),
        1,
        BatchIngestConfig {
            max_batch: 10_000,
            flush_interval: Duration::from_secs(3600),
            queue_capacity: 256,
        },
    );

    for i in 0..50 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
        e.metadata.insert("i".into(), serde_json::json!(i));
        writer.write(e).await.unwrap();
    }
    // Huge max_batch + long interval → still in queue until shutdown.
    writer.shutdown().await.unwrap();
    assert_eq!(
        store.count_events(&run.id).await.unwrap(),
        50,
        "shutdown must persist every accepted event"
    );
}

#[tokio::test]
async fn batch_ingestor_backpressure_queue_is_bounded() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let ingest = BatchIngestor::spawn(
        store.clone(),
        BatchIngestConfig {
            max_batch: 32,
            flush_interval: Duration::from_millis(5),
            queue_capacity: 16,
        },
    );

    for i in 0..200 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "storm");
        e.sequence = i + 1;
        // send().await applies backpressure when full — must not drop.
        ingest.enqueue(e, false).await.unwrap();
    }
    ingest.flush().await.unwrap();
    assert_eq!(store.count_events(&run.id).await.unwrap(), 200);
    let h = ingest.health_snapshot();
    assert_eq!(h.write_failures, 0);
    assert!(h.queue_high_water <= 16 + 4); // small slack for in-flight
    ingest.shutdown().await.unwrap();
}

#[tokio::test]
async fn sync_writer_still_works() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());
    assert!(!writer.is_batched());
    let e = TraceEvent::new(&run.id, EventSource::System, "sync");
    writer.write(e).await.unwrap();
    assert_eq!(store.count_events(&run.id).await.unwrap(), 1);
}
