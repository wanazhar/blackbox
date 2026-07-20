//! 1.5 P1: cursor pagination for runs/events; blob compression round-trip.

use std::sync::Arc;

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::storage::page::{decode_run_cursor, encode_run_cursor, RunPageCursor};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::{RunFilters, TraceStore};
use chrono::{Duration, Utc};

#[tokio::test]
async fn list_runs_page_is_cursor_based() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let base = Utc::now();
    for i in 0..25 {
        let mut run = Run::new(vec!["cmd".into(), format!("{i}")], "/tmp".into());
        run.started_at = base - Duration::seconds(i);
        run.id = format!("run-{i:04}");
        store.insert_run(&run).await.unwrap();
    }

    let page1 = store
        .list_runs_page(None, 10, &RunFilters::default())
        .await
        .unwrap();
    assert_eq!(page1.runs.len(), 10);
    assert!(page1.has_more);
    assert!(page1.next_cursor.is_some());

    let page2 = store
        .list_runs_page(page1.next_cursor.as_deref(), 10, &RunFilters::default())
        .await
        .unwrap();
    assert_eq!(page2.runs.len(), 10);
    assert!(page2.has_more);

    // No overlap between pages.
    let ids1: std::collections::HashSet<_> = page1.runs.iter().map(|r| r.id.clone()).collect();
    for r in &page2.runs {
        assert!(!ids1.contains(&r.id), "duplicate {}", r.id);
    }

    let page3 = store
        .list_runs_page(page2.next_cursor.as_deref(), 10, &RunFilters::default())
        .await
        .unwrap();
    assert_eq!(page3.runs.len(), 5);
    assert!(!page3.has_more);
    assert!(page3.next_cursor.is_none());
}

#[tokio::test]
async fn get_events_range_pages() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    for i in 1..=50 {
        let mut e = TraceEvent::new(&run.id, EventSource::System, "tick");
        e.sequence = i;
        store.insert_event(&e).await.unwrap();
    }

    let p1 = store
        .get_events_range(&run.id, 0, u64::MAX, 20)
        .await
        .unwrap();
    assert_eq!(p1.events.len(), 20);
    assert!(p1.has_more);
    assert_eq!(p1.events[0].sequence, 1);
    assert_eq!(p1.events[19].sequence, 20);

    let after = p1.events.last().unwrap().sequence;
    let p2 = store
        .get_events_range(&run.id, after, u64::MAX, 20)
        .await
        .unwrap();
    assert_eq!(p2.events[0].sequence, 21);
    assert_eq!(p2.events.len(), 20);
}

#[tokio::test]
async fn get_events_by_kind_page() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    for i in 1..=30 {
        let kind = if i % 3 == 0 {
            "tool.call"
        } else {
            "terminal.output"
        };
        let mut e = TraceEvent::new(
            &run.id,
            if kind == "tool.call" {
                EventSource::Tool
            } else {
                EventSource::Terminal
            },
            kind,
        );
        e.sequence = i;
        store.insert_event(&e).await.unwrap();
    }

    let page = store
        .get_events_by_kind_page(&run.id, &["tool.call"], None, 5)
        .await
        .unwrap();
    assert_eq!(page.events.len(), 5);
    assert!(page.events.iter().all(|e| e.kind == "tool.call"));
    assert!(page.has_more);

    let page2 = store
        .get_events_by_kind_page(&run.id, &["tool.call"], page.next_cursor.as_deref(), 20)
        .await
        .unwrap();
    assert!(!page2.events.is_empty());
    assert!(page2.events.iter().all(|e| e.kind == "tool.call"));
    // No sequence overlap
    let last1 = page.events.last().unwrap().sequence;
    assert!(page2.events[0].sequence > last1);
}

#[tokio::test]
async fn blob_compression_round_trip() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    // Highly compressible payload
    let data = vec![b'A'; 8_000];
    let bref = store.store_blob(&data).await.unwrap();
    assert_eq!(bref.size, 8_000);
    // compressed flag may be set when savings apply
    let loaded = store.load_blob(&bref).await.unwrap();
    assert_eq!(loaded, data);

    // Incompressible small payload still round-trips
    let small = b"unique-bytes-xyz";
    let b2 = store.store_blob(small).await.unwrap();
    assert_eq!(store.load_blob(&b2).await.unwrap(), small);
}

#[test]
fn run_cursor_codec() {
    let c = RunPageCursor {
        started_at: Utc::now(),
        id: "abc".into(),
    };
    let enc = encode_run_cursor(&c);
    let dec = decode_run_cursor(&enc).unwrap();
    assert_eq!(dec.id, "abc");
}
