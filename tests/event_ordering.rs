//! 1.5 O1: source sequences, timing provenance, occurrence vs storage order.

use std::sync::Arc;

use blackbox::analysis::ordering::occurrence_timeline;
use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::core::timing::{
    relate_occurrence, BoundedReorderBuffer, ClockSource, EventTiming, OrderingRelation,
};
use blackbox::pipeline::EventWriter;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use chrono::{Duration, Utc};

#[tokio::test]
async fn every_written_event_gets_source_sequence_and_ingest_stamp() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    for kind in ["terminal.output", "terminal.output", "fs.modified"] {
        let source = if kind.starts_with("fs") {
            EventSource::Filesystem
        } else {
            EventSource::Terminal
        };
        let e = TraceEvent::new(&run.id, source, kind);
        writer.write(e).await.unwrap();
    }

    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(events.len(), 3);
    for ev in &events {
        assert!(
            ev.source_sequence().is_some(),
            "missing source_sequence on {}",
            ev.kind
        );
        let t = ev.timing();
        assert!(t.ingested_at.is_some(), "missing ingested_at");
        assert!(t.occurred_at_wall.is_some() || ev.started_at.timestamp() > 0);
    }

    // Terminal source sequences are local (1, 2); filesystem starts at 1.
    let term: Vec<_> = events
        .iter()
        .filter(|e| e.source == EventSource::Terminal)
        .collect();
    assert_eq!(term[0].source_sequence(), Some(1));
    assert_eq!(term[1].source_sequence(), Some(2));
    let fs = events
        .iter()
        .find(|e| e.source == EventSource::Filesystem)
        .unwrap();
    assert_eq!(fs.source_sequence(), Some(1));
}

#[test]
fn delayed_cross_layer_does_not_create_false_strict_ordering() {
    let t0 = Utc::now();

    // Filesystem event occurred first but was delayed into the writer.
    let mut fs = TraceEvent::new("r", EventSource::Filesystem, "filesystem.modified");
    fs.sequence = 50; // storage order late
    fs.started_at = t0;
    fs.set_timing(&EventTiming {
        occurred_at_wall: Some(t0),
        observed_at: Some(t0 + Duration::milliseconds(80)),
        clock_source: ClockSource::OsEvent,
        ordering_uncertainty_ms: 5,
        ..Default::default()
    });
    fs.set_source_sequence(1);

    // Terminal event occurred later but was ingested first.
    let mut pty = TraceEvent::new("r", EventSource::Terminal, "terminal.output");
    pty.sequence = 3;
    pty.started_at = t0 + Duration::milliseconds(100);
    pty.set_timing(&EventTiming {
        occurred_at_wall: Some(pty.started_at),
        observed_at: Some(pty.started_at),
        clock_source: ClockSource::CaptureWall,
        ordering_uncertainty_ms: 5,
        ..Default::default()
    });
    pty.set_source_sequence(1);

    assert!(
        pty.sequence < fs.sequence,
        "storage order inverted vs reality"
    );
    assert_eq!(relate_occurrence(&fs, &pty), OrderingRelation::Before);
    assert_eq!(relate_occurrence(&pty, &fs), OrderingRelation::After);

    let summary = occurrence_timeline(&[pty.clone(), fs.clone()]);
    assert_eq!(summary.occurrence_order_ids[0], fs.id);
    assert_eq!(summary.occurrence_order_ids[1], pty.id);
    assert!(summary.storage_vs_occurrence_disagreements >= 1);

    // UI/JSON can distinguish fields.
    let v = &summary.events.iter().find(|e| e.event_id == fs.id).unwrap();
    assert_eq!(v.storage_sequence, 50);
    assert_eq!(v.source_sequence, Some(1));
    assert!(v.occurred_at_wall.is_some());
}

#[test]
fn reorder_buffer_only_when_clocks_comparable() {
    let t0 = Utc::now();
    let mut buf = BoundedReorderBuffer::new(2);

    let mut late = TraceEvent::new("r", EventSource::Git, "git.diff");
    late.started_at = t0 + Duration::milliseconds(100);
    late.set_timing(&EventTiming {
        occurred_at_wall: Some(late.started_at),
        clock_source: ClockSource::CaptureWall,
        ordering_uncertainty_ms: 5,
        ..Default::default()
    });

    let mut early = TraceEvent::new("r", EventSource::Process, "process.spawned");
    early.started_at = t0;
    early.set_timing(&EventTiming {
        occurred_at_wall: Some(t0),
        clock_source: ClockSource::OsEvent,
        ordering_uncertainty_ms: 5,
        ..Default::default()
    });

    assert!(buf.push(late).is_empty());
    let out = buf.push(early);
    assert_eq!(out[0].kind, "process.spawned");
    assert_eq!(out[1].kind, "git.diff");
}

#[tokio::test]
async fn layer_preassigned_source_sequence_is_preserved() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["x".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();
    let writer = EventWriter::new(store.clone(), run.id.clone());

    let mut e = TraceEvent::new(&run.id, EventSource::Process, "process.spawned");
    e.set_source_sequence(42);
    writer.write(e).await.unwrap();
    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(events[0].source_sequence(), Some(42));
}
