//! 1.7 end-to-end: evidence import, correlation, detect, provenance, incident, forensic.

use std::sync::Arc;

use blackbox::boundary::{
    correlate_external_batch, detect_boundary_findings, evaluate_provenance,
    record_from_observations, resolve_boundary, BoundaryContract, CorrelationContext,
    DetectInputs, ResolveOpts, TraceIdentity,
};
use blackbox::core::run::{Run, RunStatus};
use blackbox::evidence::{
    import_evidence_ndjson_str, EvidenceAction, ExternalEvidenceEvent, ImportOptions,
};
use blackbox::forensic::{build_forensic_pack, validate_claim_citations, ForensicPackOpts};
use blackbox::incident::{
    attach_to_incident, build_incident_graph, GraphInputs, Incident, IncidentAttachmentKind,
};
use blackbox::storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use blackbox::storage::TraceStore;

#[tokio::test]
async fn schema_v10_and_full_pipeline() {
    assert_eq!(SCHEMA_VERSION, 10);
    let store = Arc::new(SqliteStore::open_memory().unwrap());

    let mut run = Run::new(vec!["agent".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    store.insert_run(&run).await.unwrap();

    // Boundary + identity
    let resolved = resolve_boundary(
        &BoundaryContract::eval_example(),
        ResolveOpts::default(),
    )
    .unwrap()
    .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();
    let identity = TraceIdentity::mint(&run.id);
    store.put_trace_identity(&identity).await.unwrap();

    // External evidence NDJSON (proxy deny + public HTTP)
    let ndjson = format!(
        r#"{{"schema":"blackbox.evidence.event/v1","id":"evext-a","source":"proxy","sensor":"proxy","source_event_id":"p1","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"success","integrity":"unverified","destination":"https://evil.example/answer","identity":{{"run_id":"{rid}","trace_id":"{tid}"}}}}
{{"id":"g2","action":"credential_access","host":"worker","run_id":"{rid}"}}
"#,
        rid = run.id,
        tid = identity.trace_id
    );
    let opts = ImportOptions {
        default_run_id: Some(run.id.clone()),
        ..Default::default()
    };
    let (events, report) = import_evidence_ndjson_str(&ndjson, &opts).unwrap();
    assert!(report.accepted >= 2);
    for ev in &events {
        assert!(store.insert_external_evidence(ev).await.unwrap());
    }
    // Idempotent re-import
    assert!(!store.insert_external_evidence(&events[0]).await.unwrap());

    let loaded = store
        .list_external_evidence_for_run(&run.id)
        .await
        .unwrap();
    assert!(loaded.len() >= 2);

    // Correlation
    let ctx = CorrelationContext {
        run_id: run.id.clone(),
        trace_id: Some(identity.trace_id.clone()),
        ..Default::default()
    };
    let edges = correlate_external_batch(&loaded, &ctx);
    assert!(!edges.is_empty());
    for e in &edges {
        store.insert_evidence_edge(e).await.unwrap();
    }

    // Detect
    let findings = detect_boundary_findings(DetectInputs {
        run_id: &run.id,
        contract: Some(&resolved.contract),
        events: &[],
        external: &loaded,
    });
    assert!(
        findings
            .iter()
            .any(|f| f.detector == "unexpected_destination" || f.detector == "credential_access"),
        "findings={:?}",
        findings.iter().map(|f| &f.detector).collect::<Vec<_>>()
    );
    for f in &findings {
        store.insert_boundary_finding(f).await.unwrap();
    }

    // Provenance: correct task, invalid network path
    let rec = record_from_observations(
        &run.id,
        &["local-dataset".into()],
        &["https://evil.example/answer".into()],
    );
    store.insert_provenance_record(&rec).await.unwrap();
    let report = evaluate_provenance(
        &run.id,
        &store.list_provenance_records(&run.id).await.unwrap(),
        &loaded,
        &["local-dataset".into()],
        Some(true),
        true,
    );
    assert!(report.task_passed.unwrap());
    assert!(report.provenance_gate_failed);
    assert!(!report.overall_passed);

    // Second run for incident reuse
    let mut run2 = Run::new(vec!["agent".into()], "/tmp".into());
    run2.status = RunStatus::Succeeded;
    store.insert_run(&run2).await.unwrap();
    let mut ext2 = ExternalEvidenceEvent::new(
        "proxy",
        "proxy",
        "p2",
        EvidenceAction::HttpRequest,
    );
    ext2.destination = Some("https://evil.example/answer".into());
    ext2.linked_run_id = Some(run2.id.clone());
    store.insert_external_evidence(&ext2).await.unwrap();
    let findings2 = detect_boundary_findings(DetectInputs {
        run_id: &run2.id,
        contract: Some(&resolved.contract),
        events: &[],
        external: &[ext2],
    });
    for f in &findings2 {
        store.insert_boundary_finding(f).await.unwrap();
    }

    // Incident graph
    let mut inc = Incident::new(Some("egress-swarm".into()));
    attach_to_incident(
        &mut inc,
        IncidentAttachmentKind::Run,
        &run.id,
        Some("seed".into()),
    );
    attach_to_incident(
        &mut inc,
        IncidentAttachmentKind::Run,
        &run2.id,
        Some("reuse".into()),
    );
    store.upsert_incident(&inc).await.unwrap();

    let graph = build_incident_graph(
        &inc,
        &GraphInputs {
            findings_by_run: vec![
                (
                    run.id.clone(),
                    store.list_boundary_findings(&run.id).await.unwrap(),
                ),
                (
                    run2.id.clone(),
                    store.list_boundary_findings(&run2.id).await.unwrap(),
                ),
            ],
            external: store
                .list_external_evidence_for_run(&run.id)
                .await
                .unwrap(),
            edges: store.list_evidence_edges(&run.id).await.unwrap(),
            run_end_times: vec![(run.id.clone(), run.ended_at), (run2.id.clone(), None)],
        },
    );
    assert_eq!(graph.run_count, 2);
    assert!(graph.earliest_signal.is_some() || graph.finding_count > 0);

    // Forensic pack
    let pack = build_forensic_pack(
        &run.id,
        Some(&resolved),
        &[],
        &loaded,
        &store.list_boundary_findings(&run.id).await.unwrap(),
        &store.list_evidence_edges(&run.id).await.unwrap(),
        &ForensicPackOpts::default(),
    );
    assert!(!pack.pack_hash.is_empty());
    validate_claim_citations(&pack).unwrap();
    assert!(pack.policy_hash.is_some());
}

#[tokio::test]
async fn forged_trace_id_not_confirmed() {
    use blackbox::core::event::Confidence;
    use blackbox::boundary::correlate_external_event;

    let mut ev = ExternalEvidenceEvent::new("otel", "otel", "1", EvidenceAction::HttpRequest);
    ev.identity.trace_id = Some("forged".into());
    let ctx = CorrelationContext {
        run_id: "r1".into(),
        trace_id: Some("real".into()),
        ..Default::default()
    };
    // Conflicting id alone may still produce weak edge or none — never Confirmed.
    if let Some(edge) = correlate_external_event(&ev, &ctx) {
        assert!(!matches!(edge.confidence, Confidence::Confirmed));
    }
}

#[tokio::test]
async fn evidence_import_rejects_malicious_paths() {
    let ndjson = r#"{"id":"x","action":"read","path":"../../etc/passwd"}"#;
    let (_e, report) =
        import_evidence_ndjson_str(ndjson, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 0);
    assert!(report.rejected >= 1);
}
