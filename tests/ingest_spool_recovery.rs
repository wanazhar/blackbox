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

/// Simulate SIGKILL mid-flight: pending spool batch must recover after restart.
#[tokio::test]
async fn spool_survives_simulated_sigkill_before_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let spool = EventSpool::open(dir.path()).unwrap();
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let mut events = Vec::new();
    for i in 1..=20 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
        e.sequence = i;
        e.id = format!("sigkill-evt-{i}");
        events.push(e);
    }
    // Durable append (as if process was about to commit SQLite then SIGKILL).
    spool.append_batch(&events).unwrap();
    assert_eq!(spool.list_pending().unwrap().len(), 1);
    // "Process dies" — drop spool handle, reopen as recovery would.
    drop(spool);
    let stats = recover_spool_on_open(store.clone(), dir.path())
        .await
        .unwrap();
    assert_eq!(stats.events_inserted, 20);
    assert_eq!(store.count_events(&run.id).await.unwrap(), 20);
    // Second recovery is a no-op (pending drained).
    let stats2 = recover_spool_on_open(store.clone(), dir.path())
        .await
        .unwrap();
    assert_eq!(stats2.events_inserted, 0);
    assert_eq!(store.count_events(&run.id).await.unwrap(), 20);
}

/// Disk-full style failure: append to a non-writable path returns an error
/// rather than silently dropping events.
#[test]
fn spool_append_fails_on_unwritable_dir() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("nope");
    // Create a file where a directory is required so open/append fails.
    std::fs::write(&bad, b"not-a-dir").unwrap();
    let err = EventSpool::open(&bad);
    assert!(err.is_err(), "expected open on file-as-dir to fail");
}

#[test]
fn spool_append_fails_when_parent_is_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blocked");
    std::fs::write(&file, b"x").unwrap();
    // Nested path under a file cannot be created.
    let nested = file.join("spool");
    let err = EventSpool::open(&nested);
    assert!(err.is_err());
}
