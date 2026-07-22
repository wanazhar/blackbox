//! 1.6 A: file_ops and process counts match documented semantics.

use blackbox::aggregates::RunAggregates;
use blackbox::core::event::{EventSource, TraceEvent};

#[test]
fn filesystem_events_count_as_file_ops() {
    let mut agg = RunAggregates::new("r");
    for (i, kind) in [
        "filesystem.created",
        "filesystem.modified",
        "filesystem.renamed",
        "filesystem.removed",
    ]
    .iter()
    .enumerate()
    {
        let mut e = TraceEvent::new("r", EventSource::Filesystem, kind);
        e.sequence = (i + 1) as u64;
        e.metadata
            .insert("path".into(), serde_json::json!(format!("p{i}")));
        agg.observe(&e);
    }
    // Non-ops
    for (i, kind) in [
        "filesystem.snapshot",
        "filesystem.overflow",
        "filesystem.out_of_scope",
    ]
    .iter()
    .enumerate()
    {
        let mut e = TraceEvent::new("r", EventSource::Filesystem, kind);
        e.sequence = 10 + i as u64;
        agg.observe(&e);
    }
    assert_eq!(agg.file_ops, 4);
    assert_eq!(agg.files_touched_unique, 4);
}

#[test]
fn unique_process_identity_collapses_samples() {
    let mut agg = RunAggregates::new("r");
    let mut spawned = TraceEvent::new("r", EventSource::Process, "process.spawned");
    spawned.sequence = 1;
    spawned.metadata.insert("pid".into(), serde_json::json!(7));
    spawned
        .metadata
        .insert("start_time".into(), serde_json::json!(99));
    agg.observe(&spawned);

    for i in 0..20 {
        let mut s = TraceEvent::new("r", EventSource::Process, "process.resource.sample");
        s.sequence = 2 + i;
        s.metadata.insert("pid".into(), serde_json::json!(7));
        s.metadata
            .insert("start_time".into(), serde_json::json!(99));
        agg.observe(&s);
    }

    let mut exited = TraceEvent::new("r", EventSource::Process, "process.exited");
    exited.sequence = 30;
    exited.metadata.insert("pid".into(), serde_json::json!(7));
    exited
        .metadata
        .insert("start_time".into(), serde_json::json!(99));
    agg.observe(&exited);

    assert_eq!(agg.process_events, 22);
    assert_eq!(
        agg.processes_observed, 1,
        "one pid+start_time must count as one process"
    );
}

#[test]
fn recompute_matches_incremental_for_file_and_process() {
    let mut events = Vec::new();
    for i in 1..=5 {
        let mut e = TraceEvent::new("r", EventSource::Filesystem, "filesystem.modified");
        e.sequence = i;
        e.metadata
            .insert("path".into(), serde_json::json!(format!("f{}.rs", i % 2)));
        events.push(e);
    }
    for i in 6..=10 {
        let mut e = TraceEvent::new("r", EventSource::Process, "process.resource.sample");
        e.sequence = i;
        e.metadata.insert("pid".into(), serde_json::json!(1));
        events.push(e);
    }

    let mut inc = RunAggregates::new("r");
    for e in &events {
        inc.observe(e);
    }
    let full = RunAggregates::recompute("r", &events);
    assert_eq!(inc.file_ops, full.file_ops);
    assert_eq!(inc.files_touched_unique, full.files_touched_unique);
    assert_eq!(inc.process_events, full.process_events);
    assert_eq!(inc.processes_observed, full.processes_observed);
    assert_eq!(inc.file_ops, 5);
    assert_eq!(inc.files_touched_unique, 2);
    assert_eq!(inc.processes_observed, 1);
}
