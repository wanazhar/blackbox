//! 1.7 depth: score fails on provenance; portable round-trip; trust rollup.

use std::sync::Arc;

use blackbox::boundary::{
    resolve_boundary, BoundaryContract, ContainmentClaimState, ContainmentReceipt,
    ContainmentResult, EntityKind, EvidenceEdge, EvidenceRelation, ResolveOpts,
};
use blackbox::core::event::Confidence;
use blackbox::core::run::{Run, RunStatus};
use blackbox::evidence::{EvidenceAction, ExternalEvidenceEvent};
use blackbox::export::portable::{export_portable, import_portable};
use blackbox::score::EvalScore;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, SummaryOptions};

#[tokio::test]
async fn score_fails_when_provenance_gate_fails_despite_exit_zero() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["agent".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    store.insert_run(&run).await.unwrap();

    let resolved = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();

    // Verified containment + process/network so only provenance fails hard path
    let mut containment = ContainmentReceipt::new(
        &run.id,
        ContainmentClaimState::Verified,
        ContainmentResult::Held,
        "canary",
        "post_run_canary",
    );
    containment.scope.control = Some("network_egress".into());
    containment.policy_hash = Some(resolved.policy_hash.clone());
    containment.evidence_hashes.push("a".repeat(64));
    store
        .insert_containment_receipt(&containment)
        .await
        .unwrap();

    let mut ext =
        ExternalEvidenceEvent::new("proxy", "proxy", "cheat-1", EvidenceAction::HttpRequest);
    ext.destination = Some("https://answers.leaked.example/q1".into());
    ext.linked_run_id = Some(run.id.clone());
    store.insert_external_evidence(&ext).await.unwrap();
    let mut edge = EvidenceEdge::new(
        EntityKind::Run,
        &run.id,
        EntityKind::ExternalEvidence,
        &ext.id,
        EvidenceRelation::NetworkConnection,
        Confidence::StronglyCorrelated,
    );
    edge.run_id = Some(run.id.clone());
    store.insert_evidence_edge(&edge).await.unwrap();

    let rec = blackbox::boundary::record_from_observations(
        &run.id,
        &["local-dataset".into()],
        &["https://answers.leaked.example/q1".into()],
    );
    store.insert_provenance_record(&rec).await.unwrap();

    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    assert!(summary.boundary_trust.is_some());
    let trust = summary.boundary_trust.as_ref().unwrap();
    assert!(trust.provenance_gate_failed || !trust.trust_ok);

    let score = EvalScore::from_run_summary(&run, &summary);
    assert!(
        score.failed,
        "score must fail on provenance/trust even with exit 0"
    );
    assert!(
        score.provenance_gate_failed || score.boundary_gate_failed || score.trust_ok == Some(false)
    );
}

#[tokio::test]
async fn portable_round_trip_restores_boundary_artifacts() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    let resolved = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();
    store
        .insert_containment_receipt(&ContainmentReceipt::new(
            &run.id,
            ContainmentClaimState::Configured,
            ContainmentResult::NotObserved,
            "blackbox",
            "launch_record",
        ))
        .await
        .unwrap();
    let mut ext = ExternalEvidenceEvent::new("proxy", "proxy", "p1", EvidenceAction::ProxyDeny);
    ext.destination = Some("https://evil.example".into());
    ext.linked_run_id = Some(run.id.clone());
    store.insert_external_evidence(&ext).await.unwrap();
    let mut edge = EvidenceEdge::new(
        EntityKind::Run,
        &run.id,
        EntityKind::ExternalEvidence,
        &ext.id,
        EvidenceRelation::NetworkConnection,
        Confidence::StronglyCorrelated,
    );
    edge.run_id = Some(run.id.clone());
    store.insert_evidence_edge(&edge).await.unwrap();

    let events = store.get_events(&run.id).await.unwrap();
    let json = export_portable(store.as_ref(), &run, &events, true)
        .await
        .unwrap();
    assert!(json.contains("boundary"));
    assert!(json.contains("containment_receipts"));
    assert!(json.contains("external_evidence"));

    let store2 = Arc::new(SqliteStore::open_memory().unwrap());
    let imported = import_portable(store2.as_ref(), &json, true).await.unwrap();
    let b = store2
        .get_run_boundary(&imported.run_id)
        .await
        .unwrap()
        .expect("boundary restored");
    assert_eq!(b.policy_hash, resolved.policy_hash);
    let receipts = store2
        .list_containment_receipts(&imported.run_id)
        .await
        .unwrap();
    assert!(!receipts.is_empty());
    let ext2 = store2
        .list_external_evidence_for_run(&imported.run_id)
        .await
        .unwrap();
    assert!(!ext2.is_empty());
    let edges = store2.list_evidence_edges(&imported.run_id).await.unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].from_id, imported.run_id);
    assert_eq!(edges[0].to_id, ext2[0].id);
    assert_ne!(edges[0].to_id, ext.id);
}

#[tokio::test]
async fn portable_rejects_malformed_1_7_field_without_writes() {
    let source = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    source.insert_run(&run).await.unwrap();
    let json = export_portable(source.as_ref(), &run, &[], true)
        .await
        .unwrap();
    let mut root: serde_json::Value = serde_json::from_str(&json).unwrap();
    root["containment_receipts"] = serde_json::json!({"not": "an array"});

    let destination = Arc::new(SqliteStore::open_memory().unwrap());
    let error = import_portable(destination.as_ref(), &root.to_string(), true)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("invalid portable field containment_receipts"));
    assert!(destination.list_runs().await.unwrap().is_empty());
}
