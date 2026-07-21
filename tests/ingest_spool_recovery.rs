//! 1.6 B: durable spool survives crash and replays idempotently.

use std::sync::Arc;

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::ingest::spool::EventSpool;
use blackbox::ingest::recover_spool_on_open;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn spool_replay_inserts_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let spool = EventSpool::open(dir.path()).unwrap();
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["echo".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let mut events = Vec::new();
    for i in 1..=5 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
        e.sequence = i;
        e.id = format!("evt-{i}");
        events.push(e);
    }
    let res = spool.append_batch(&events).unwrap();
    assert!(res.path.exists());
    assert_eq!(spool.list_pending().unwrap().len(), 1);

    // Simulate crash before SQLite commit: pending remains.
    let stats = recover_spool_on_open(store.clone(), dir.path())
        .await
        .unwrap();
    assert_eq!(stats.events_inserted, 5);
    assert_eq!(store.count_events(&run.id).await.unwrap(), 5);
    assert!(spool.list_pending().unwrap().is_empty());

    // Re-append same ids and recover again — no duplicates.
    spool.append_batch(&events).unwrap();
    let stats2 = recover_spool_on_open(store.clone(), dir.path())
        .await
        .unwrap();
    assert_eq!(stats2.events_skipped_duplicate, 5);
    assert_eq!(store.count_events(&run.id).await.unwrap(), 5);
}

#[tokio::test]
async fn torn_spool_record_detected() {
    let dir = tempfile::tempdir().unwrap();
    let spool = EventSpool::open(dir.path()).unwrap();
    let mut e = TraceEvent::new("r", EventSource::System, "t");
    e.id = "e1".into();
    let res = spool.append_batch(&[e]).unwrap();
    // Corrupt file
    let mut data = std::fs::read(&res.path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(&res.path, data).unwrap();
    let info = blackbox::ingest::inspect_spool(dir.path()).unwrap();
    assert_eq!(info.torn_records, 1);
}
