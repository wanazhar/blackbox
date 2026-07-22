//! Cross-module completion gate for the 1.7 boundary-to-incident evidence path.

use blackbox::boundary::{
    correlate_external_batch, evaluate_required_evidence, resolve_boundary, BoundaryContract,
    ContainmentClaimState, ContainmentReceipt, ContainmentResult, CorrelationContext, EntityKind,
    EvidenceEdge, EvidenceRelation, EvidenceStatus, ObservedEvidence, ResolveOpts,
};
use blackbox::core::{Confidence, EventSource, TraceEvent};
use blackbox::evidence::{import_evidence_ndjson_str, ImportOptions};
use blackbox::forensic::{
    apply_model_analysis, build_forensic_pack, validate_claim_citations, ForensicPack,
    ForensicPackOpts, ModelAnalysisInput,
};
use blackbox::incident::{
    attach_to_incident, build_incident_export, build_incident_graph_with_limits,
    validate_incident_export, GraphInputs, Incident, IncidentAttachmentKind, IncidentGraphLimits,
};
use blackbox::{
    cli::{Cli, Command},
    cli_ext::ForensicAction,
};
use clap::Parser;

const CLOUD_AUDIT: &str = include_str!("fixtures/boundary_1_7/orchestration/cloud_audit.ndjson");

fn flow_edge(
    relation: EvidenceRelation,
    from_kind: EntityKind,
    from_id: &str,
    to_kind: EntityKind,
    to_id: &str,
    run_id: &str,
) -> EvidenceEdge {
    let mut edge = EvidenceEdge::new(
        from_kind,
        from_id,
        to_kind,
        to_id,
        relation,
        Confidence::StronglyCorrelated,
    );
    edge.run_id = Some(run_id.into());
    edge.reasons = vec!["completion_fixture".into()];
    edge
}

#[test]
fn governed_evidence_reconstructs_a_bounded_shareable_incident() {
    let run_id = "run-completion";
    let boundary = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id(run_id);

    let missing = evaluate_required_evidence(Some(&boundary), &ObservedEvidence::default());
    assert!(missing.gate_failed);
    assert!(matches!(
        missing.status,
        EvidenceStatus::InsufficientEvidence | EvidenceStatus::ContainmentUnproven
    ));

    let mut receipt = ContainmentReceipt::new(
        run_id,
        ContainmentClaimState::Verified,
        ContainmentResult::Held,
        "completion-fixture",
        "independent-canary",
    );
    receipt.scope.control = Some("network_egress".into());
    receipt.policy_hash = Some(boundary.policy_hash.clone());
    receipt.evidence_hashes.push("a".repeat(64));
    let sufficient = evaluate_required_evidence(
        Some(&boundary),
        &ObservedEvidence {
            present_classes: vec!["process".into(), "network".into()],
            containment_receipts: vec![receipt],
            has_artifact_provenance: true,
            ..Default::default()
        },
    );
    assert_eq!(sufficient.status, EvidenceStatus::Sufficient);
    assert!(!sufficient.gate_failed);

    let (external, report) =
        import_evidence_ndjson_str(CLOUD_AUDIT, &ImportOptions::default()).unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert!(external.iter().all(|event| event.linked_run_id.is_none()));
    let mut edges = correlate_external_batch(
        &external,
        &CorrelationContext {
            run_id: run_id.into(),
            trace_id: Some("projects/eval-project/traces/trace-cloud-001".into()),
            workload: Some("worker-001".into()),
            principal: Some("agent-runner@eval-project.iam.gserviceaccount.com".into()),
            ..Default::default()
        },
    );
    assert!(edges
        .iter()
        .all(|edge| edge.confidence != Confidence::Confirmed));

    edges.extend([
        flow_edge(
            EvidenceRelation::Delegation,
            EntityKind::Run,
            "run-parent",
            EntityKind::Run,
            run_id,
            run_id,
        ),
        flow_edge(
            EvidenceRelation::CredentialUse,
            EntityKind::Run,
            run_id,
            EntityKind::Credential,
            "credential:deploy",
            run_id,
        ),
        flow_edge(
            EvidenceRelation::ArtifactDerivation,
            EntityKind::ExternalEvidence,
            &external[1].id,
            EntityKind::Artifact,
            "sha256:result",
            run_id,
        ),
    ]);

    let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
    let mut trace = TraceEvent::new(run_id, EventSource::Tool, "tool.call");
    trace.metadata.insert(
        "command".into(),
        serde_json::json!(format!("TOKEN={secret}")),
    );
    let event_id = trace.id.clone();
    let mut pack = build_forensic_pack(
        run_id,
        Some(&boundary),
        &[trace],
        &external,
        &[],
        &edges,
        &ForensicPackOpts::default(),
    );
    apply_model_analysis(
        &mut pack,
        &ModelAnalysisInput {
            model: "local/model@sha256:1234".into(),
            prompt: b"credential review prompt".to_vec(),
            configuration: br#"{"temperature":0}"#.to_vec(),
            claims: vec![(
                "credential use requires review".into(),
                vec![format!("event:{event_id}")],
            )],
            refused: false,
            failure: None,
        },
    )
    .unwrap();
    validate_claim_citations(&pack).unwrap();
    assert!(!serde_json::to_string(&pack).unwrap().contains(secret));

    let mut incident = Incident::new(Some(format!("credential exposure {secret}")));
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        run_id,
        Some("governed run".into()),
    );
    let graph = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            external,
            edges,
            ..Default::default()
        },
        IncidentGraphLimits {
            nodes: 2,
            edges: 2,
            flows: 2,
            techniques: 1,
        },
    );
    assert_eq!(graph.flow_count, Some(3));
    assert_eq!(graph.flows.len(), 2);
    assert!(graph.truncation.as_ref().unwrap().is_truncated());
    assert!(graph.counts_exact);

    let export = build_incident_export(
        &incident,
        Some(&graph),
        &[(run_id.into(), serde_json::to_string(&pack).unwrap())],
        true,
    );
    validate_incident_export(&export, false).unwrap();
    assert!(!serde_json::to_string(&export).unwrap().contains(secret));
    assert!(export
        .transformations
        .iter()
        .any(|step| step == "sanitize:enabled"));

    let mut tampered = export;
    tampered.incident.title = Some("tampered".into());
    assert!(validate_incident_export(&tampered, false).is_err());
}

#[test]
fn forensic_cli_requires_exact_model_input_files() {
    assert!(Cli::try_parse_from([
        "blackbox",
        "forensic",
        "analyze",
        "pack.json",
        "--claim",
        "derived",
        "--cite",
        "event-1",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "blackbox",
        "forensic",
        "analyze",
        "pack.json",
        "--prompt-fingerprint",
        "not-a-hash",
        "--configuration-fingerprint",
        "also-not-a-hash",
        "--claim",
        "derived",
        "--cite",
        "event:event-1",
    ])
    .is_err());

    let cli = Cli::try_parse_from([
        "blackbox",
        "forensic",
        "analyze",
        "pack.json",
        "--model",
        "local/model@sha256:1234",
        "--prompt-file",
        "prompt.txt",
        "--configuration-file",
        "configuration.json",
        "--claim",
        "derived",
        "--cite",
        "event-1",
    ])
    .unwrap();

    let Command::Forensic(args) = cli.command else {
        panic!("expected forensic command");
    };
    let ForensicAction::Analyze {
        prompt_file,
        configuration_file,
        ..
    } = args.action
    else {
        panic!("expected analyze action");
    };
    assert_eq!(prompt_file, std::path::PathBuf::from("prompt.txt"));
    assert_eq!(
        configuration_file,
        std::path::PathBuf::from("configuration.json")
    );
}

#[test]
fn forensic_cli_rejects_tampered_pack_without_rewriting_it() {
    let directory = tempfile::tempdir().unwrap();
    let pack_path = directory.path().join("pack.json");
    let prompt_path = directory.path().join("prompt.txt");
    let configuration_path = directory.path().join("configuration.json");
    let event = TraceEvent::new("run-cli", EventSource::Tool, "tool.call");
    let mut pack = build_forensic_pack(
        "run-cli",
        None,
        &[event],
        &[],
        &[],
        &[],
        &ForensicPackOpts::default(),
    );
    pack.coverage_gaps.push("tampered-after-hash".into());
    let before = serde_json::to_vec_pretty(&pack).unwrap();
    std::fs::write(&pack_path, &before).unwrap();
    std::fs::write(&prompt_path, b"exact prompt").unwrap();
    std::fs::write(&configuration_path, br#"{"temperature":0}"#).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_blackbox"))
        .args([
            "forensic",
            "analyze",
            pack_path.to_str().unwrap(),
            "--prompt-file",
            prompt_path.to_str().unwrap(),
            "--configuration-file",
            configuration_path.to_str().unwrap(),
            "--claim",
            "",
            "--refused",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pack_hash mismatch"));
    assert_eq!(std::fs::read(&pack_path).unwrap(), before);
    let unchanged: ForensicPack = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        unchanged.coverage_gaps.last().unwrap(),
        "tampered-after-hash"
    );
}
