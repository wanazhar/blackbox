//! 1.7 Phase A: boundary contracts, containment receipts, evidence gates.

use std::sync::Arc;

use blackbox::boundary::{
    evaluate_required_evidence, resolve_boundary, BoundaryContract, ContainmentClaimState,
    ContainmentReceipt, ContainmentResult, EvidenceStatus, ObservedEvidence, ResolveOpts,
    BOUNDARY_SCHEMA,
};
use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use blackbox::storage::TraceStore;

#[tokio::test]
async fn schema_migration_v9_and_roundtrip() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    assert_eq!(SCHEMA_VERSION, 10);

    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    store.insert_run(&run).await.unwrap();

    let contract = BoundaryContract::eval_example();
    assert_eq!(contract.schema, BOUNDARY_SCHEMA);
    let resolved = resolve_boundary(&contract, ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();

    let loaded = store.get_run_boundary(&run.id).await.unwrap().unwrap();
    assert_eq!(loaded.policy_hash, resolved.policy_hash);
    assert_eq!(loaded.contract.purpose, contract.purpose);
    assert!(loaded.contract.fail_closed);
    assert!(loaded
        .contract
        .prohibited
        .iter()
        .any(|p| p == "public_network"));
}

#[tokio::test]
async fn containment_receipts_immutable_append() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();
    let resolved = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();

    let mut configured = ContainmentReceipt::new(
        &run.id,
        ContainmentClaimState::Configured,
        ContainmentResult::NotObserved,
        "blackbox",
        "launch_record",
    );
    configured.scope.control = Some("network_egress".into());
    configured.scope.backend = Some("none".into());
    configured.policy_hash = Some(resolved.policy_hash.clone());
    store.insert_containment_receipt(&configured).await.unwrap();

    let mut verified = ContainmentReceipt::new(
        &run.id,
        ContainmentClaimState::Verified,
        ContainmentResult::Held,
        "canary",
        "post_run_canary",
    );
    verified.scope.control = Some("network_egress".into());
    verified.policy_hash = Some(resolved.policy_hash.clone());
    verified.evidence_hashes.push("a".repeat(64));
    verified.parent_receipt_id = Some(configured.id.clone());
    store.insert_containment_receipt(&verified).await.unwrap();

    let list = store.list_containment_receipts(&run.id).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, configured.id);
    assert_eq!(
        list[1].parent_receipt_id.as_deref(),
        Some(configured.id.as_str())
    );
    // Configured ≠ verified
    assert_ne!(list[0].claim_state, list[1].claim_state);
}

#[tokio::test]
async fn fail_closed_gate_rejects_missing_and_configured_only() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    store.insert_run(&run).await.unwrap();

    let resolved = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();

    // Task succeeded, but only a configured receipt + partial sensors.
    let configured = ContainmentReceipt::new(
        &run.id,
        ContainmentClaimState::Configured,
        ContainmentResult::NotObserved,
        "blackbox",
        "launch_record",
    );
    store.insert_containment_receipt(&configured).await.unwrap();
    let receipts = store.list_containment_receipts(&run.id).await.unwrap();

    let observed = ObservedEvidence {
        present_classes: vec!["process".into()],
        containment_receipts: receipts,
        has_artifact_provenance: false,
        ..Default::default()
    };
    let report = evaluate_required_evidence(
        store.get_run_boundary(&run.id).await.unwrap().as_ref(),
        &observed,
    );
    assert!(report.gate_failed);
    assert!(matches!(
        report.status,
        EvidenceStatus::ContainmentUnproven | EvidenceStatus::InsufficientEvidence
    ));
}

#[tokio::test]
async fn verified_held_with_sensors_passes_gate() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["echo".into(), "ok".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    let resolved = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&resolved).await.unwrap();

    let mut verified = ContainmentReceipt::new(
        &run.id,
        ContainmentClaimState::Verified,
        ContainmentResult::Held,
        "canary",
        "post_run_canary",
    );
    verified.scope.control = Some("network_egress".into());
    verified.policy_hash = Some(resolved.policy_hash.clone());
    verified.evidence_hashes.push("a".repeat(64));
    store.insert_containment_receipt(&verified).await.unwrap();

    let observed = ObservedEvidence {
        present_classes: vec!["process".into(), "network".into()],
        containment_receipts: store.list_containment_receipts(&run.id).await.unwrap(),
        has_artifact_provenance: true,
        ..Default::default()
    };
    let report = evaluate_required_evidence(
        store.get_run_boundary(&run.id).await.unwrap().as_ref(),
        &observed,
    );
    assert_eq!(report.status, EvidenceStatus::Sufficient);
    assert!(!report.gate_failed);
}

#[tokio::test]
async fn policy_hash_stable_and_inheritance() {
    let mut parent = BoundaryContract::new();
    parent.purpose = Some("experiment".into());
    parent.allowed.targets.push("local-range".into());
    parent.required_evidence.push("process".into());

    let mut child = BoundaryContract::new();
    child.purpose = Some("run".into());
    child.prohibited.push("public_network".into());
    child.fail_closed = true;

    let r1 = resolve_boundary(
        &child,
        ResolveOpts {
            parents: vec![parent.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    let r2 = resolve_boundary(
        &child,
        ResolveOpts {
            parents: vec![parent],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r1.policy_hash, r2.policy_hash);
    assert!(r1.contract.fail_closed);
    assert!(r1.contract.prohibited.iter().any(|p| p == "public_network"));
    assert!(r1
        .contract
        .allowed
        .targets
        .iter()
        .any(|t| t == "local-range"));
}

#[tokio::test]
async fn boundary_policy_is_immutable_after_first_write() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["true".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    let mut a = BoundaryContract::new();
    a.purpose = Some("first".into());
    let ra = resolve_boundary(&a, ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    store.put_run_boundary(&ra).await.unwrap();

    let mut b = BoundaryContract::new();
    b.purpose = Some("second".into());
    b.prohibited.push("public_network".into());
    let rb = resolve_boundary(&b, ResolveOpts::default())
        .unwrap()
        .with_run_id(&run.id);
    let error = store.put_run_boundary(&rb).await.unwrap_err();
    assert!(error.to_string().contains("immutable"));

    let loaded = store.get_run_boundary(&run.id).await.unwrap().unwrap();
    assert_eq!(loaded.contract.purpose.as_deref(), Some("first"));
    assert_eq!(loaded.policy_hash, ra.policy_hash);
}
