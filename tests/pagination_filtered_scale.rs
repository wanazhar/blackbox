//! 1.6 A: run filters and event-kind cursors applied in SQL before LIMIT.

use std::sync::Arc;

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::{RunFilters, TraceStore};
use chrono::{Duration, Utc};

#[tokio::test]
async fn sparse_status_filter_paginates_to_exhaustion() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let base = Utc::now();

    // 40 succeeded runs and 5 failed runs interleaved by time.
    for i in 0..45 {
        let mut run = Run::new(vec!["cmd".into(), format!("{i}")], "/tmp".into());
        run.started_at = base - Duration::seconds(i);
        run.id = format!("run-{i:04}");
        run.status = if i % 9 == 0 {
            RunStatus::Failed
        } else {
            RunStatus::Succeeded
        };
        store.insert_run(&run).await.unwrap();
    }

    let filters = RunFilters {
        status: Some("failed".into()),
        tag: None,
    };

    let mut cursor = None;
    let mut total = 0usize;
    let mut seen = std::collections::HashSet::new();
    loop {
        let page = store
            .list_runs_page(cursor.as_deref(), 2, &filters)
            .await
            .unwrap();
        assert!(
            !page.runs.is_empty() || total > 0,
            "must not return a false empty first page for sparse filter"
        );
        for r in &page.runs {
            assert!(
                matches!(r.status, RunStatus::Failed),
                "non-failed run leaked into filtered page: {:?}",
                r.status
            );
            assert!(seen.insert(r.id.clone()), "duplicate run {}", r.id);
        }
        total += page.runs.len();
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        assert!(cursor.is_some());
    }
    assert_eq!(total, 5, "expected all 5 failed runs across pages");
}

#[tokio::test]
async fn sparse_tag_filter_paginates_to_exhaustion() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let base = Utc::now();
    for i in 0..30 {
        let mut run = Run::new(vec!["cmd".into()], "/tmp".into());
        run.started_at = base - Duration::seconds(i);
        run.id = format!("tag-run-{i:04}");
        if i % 7 == 0 {
            run.tags = vec!["ci".into(), "nightly".into()];
        } else {
            run.tags = vec!["local".into()];
        }
        store.insert_run(&run).await.unwrap();
    }

    let filters = RunFilters {
        status: None,
        tag: Some("ci".into()),
    };
    let mut cursor = None;
    let mut total = 0usize;
    loop {
        let page = store
            .list_runs_page(cursor.as_deref(), 2, &filters)
            .await
            .unwrap();
        for r in &page.runs {
            assert!(r.tags.iter().any(|t| t == "ci"));
        }
        total += page.runs.len();
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(total, 5); // i = 0,7,14,21,28
}

#[tokio::test]
async fn kind_filtered_event_pagination_after_late_cursor() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    // 100 terminal ticks, with tool.call sparsely at sequences 5, 55, 95.
    for i in 1..=100 {
        let kind = if matches!(i, 5 | 55 | 95) {
            "tool.call"
        } else {
            "terminal.output"
        };
        let mut e = TraceEvent::new(&run.id, EventSource::System, kind);
        e.sequence = i;
        store.insert_event(&e).await.unwrap();
    }

    // First page of tool.call after sequence 0.
    let p1 = store
        .get_events_by_kind_page(&run.id, &["tool.call"], None, 1)
        .await
        .unwrap();
    assert_eq!(p1.events.len(), 1);
    assert_eq!(p1.events[0].sequence, 5);
    assert!(p1.has_more);
    let c1 = p1.next_cursor.expect("cursor");

    // After cursor past first tool.call, next page must still find later ones.
    // The old overfetch-from-start approach fails once the first fixed prefix
    // is past the overfetch window.
    let p2 = store
        .get_events_by_kind_page(&run.id, &["tool.call"], Some(&c1), 1)
        .await
        .unwrap();
    assert_eq!(p2.events.len(), 1);
    assert_eq!(p2.events[0].sequence, 55);
    assert!(p2.has_more);

    let c2 = p2.next_cursor.unwrap();
    let p3 = store
        .get_events_by_kind_page(&run.id, &["tool.call"], Some(&c2), 1)
        .await
        .unwrap();
    assert_eq!(p3.events.len(), 1);
    assert_eq!(p3.events[0].sequence, 95);
    assert!(!p3.has_more);
}
