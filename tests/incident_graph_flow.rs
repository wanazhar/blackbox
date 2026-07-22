//! Typed incident flow reconstruction and bounded graph detail.

use blackbox::boundary::{EntityKind, EvidenceEdge, EvidenceRelation};
use blackbox::core::event::Confidence;
use blackbox::incident::{
    attach_to_incident, build_incident_graph, build_incident_graph_with_limits, GraphInputs,
    Incident, IncidentAttachmentKind, IncidentFlowKind, IncidentGraphLimits,
};

fn edge(
    id: &str,
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
    edge.id = id.into();
    edge.run_id = Some(run_id.into());
    edge.reasons = vec![format!("fixture:{id}"), "identity_match".into()];
    edge
}

#[test]
fn reconstructs_typed_flows_without_losing_edge_provenance() {
    let mut incident = Incident::new(Some("cross-boundary flow".into()));
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-parent",
        None::<String>,
    );
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-child",
        None::<String>,
    );

    let delegation = edge(
        "edge-delegation",
        EvidenceRelation::Delegation,
        EntityKind::Run,
        "run-parent",
        EntityKind::Run,
        "run-child",
        "run-parent",
    );
    let credential = edge(
        "edge-credential",
        EvidenceRelation::CredentialUse,
        EntityKind::Run,
        "run-child",
        EntityKind::Credential,
        "credential:prod-deploy",
        "run-child",
    );
    let artifact = edge(
        "edge-artifact",
        EvidenceRelation::ArtifactDerivation,
        EntityKind::ExternalEvidence,
        "evidence-build-log",
        EntityKind::Artifact,
        "sha256:artifact",
        "run-child",
    );
    let unrelated = edge(
        "edge-network",
        EvidenceRelation::NetworkConnection,
        EntityKind::Run,
        "run-child",
        EntityKind::ExternalEvidence,
        "evidence-network",
        "run-child",
    );

    let graph = build_incident_graph(
        &incident,
        &GraphInputs {
            edges: vec![delegation, credential.clone(), artifact, unrelated],
            ..Default::default()
        },
    );

    assert_eq!(graph.schema, "blackbox.incident.graph/v2");
    assert!(graph.counts_exact);
    assert_eq!(graph.edge_count, Some(4));
    assert_eq!(graph.flow_count, Some(3));
    let flow_counts = graph.flow_counts.unwrap();
    assert_eq!(flow_counts.delegation, 1);
    assert_eq!(flow_counts.credential_use, 1);
    assert_eq!(flow_counts.artifact_derivation, 1);
    assert_eq!(graph.flows.len(), 3);
    assert_eq!(graph.flows[0].kind, IncidentFlowKind::Delegation);
    assert_eq!(graph.flows[1].kind, IncidentFlowKind::CredentialUse);
    assert_eq!(graph.flows[2].kind, IncidentFlowKind::ArtifactDerivation);

    let reconstructed = &graph.flows[1];
    assert_eq!(reconstructed.edge_id, credential.id);
    assert_eq!(reconstructed.from_kind, credential.from_kind);
    assert_eq!(reconstructed.from_id, credential.from_id);
    assert_eq!(reconstructed.to_kind, credential.to_kind);
    assert_eq!(reconstructed.to_id, credential.to_id);
    assert_eq!(reconstructed.run_id, credential.run_id);
    assert_eq!(reconstructed.confidence, credential.confidence);
    assert_eq!(reconstructed.reasons, credential.reasons);
}

#[test]
fn graph_limits_bound_details_but_preserve_exact_totals() {
    let mut incident = Incident::new(Some("bounded".into()));
    for run in ["run-1", "run-2", "run-3"] {
        attach_to_incident(
            &mut incident,
            IncidentAttachmentKind::Run,
            run,
            None::<String>,
        );
    }

    let edges = (0..12)
        .map(|index| {
            edge(
                &format!("edge-{index:02}"),
                match index % 3 {
                    0 => EvidenceRelation::Delegation,
                    1 => EvidenceRelation::CredentialUse,
                    _ => EvidenceRelation::ArtifactDerivation,
                },
                EntityKind::Run,
                "run-1",
                EntityKind::Artifact,
                &format!("target-{index:02}"),
                "run-1",
            )
        })
        .collect();

    let graph = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            edges,
            ..Default::default()
        },
        IncidentGraphLimits {
            nodes: 2,
            edges: 4,
            flows: 3,
            techniques: 1,
        },
    );

    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.edges.len(), 4);
    assert_eq!(graph.flows.len(), 3);
    assert_eq!(graph.edge_count, Some(12));
    assert_eq!(graph.flow_count, Some(12));
    let flow_counts = graph.flow_counts.unwrap();
    assert_eq!(flow_counts.delegation, 4);
    assert_eq!(flow_counts.credential_use, 4);
    assert_eq!(flow_counts.artifact_derivation, 4);
    let truncation = graph.truncation.as_ref().unwrap();
    assert_eq!(truncation.nodes.total, 3);
    assert_eq!(truncation.nodes.truncated, 1);
    assert_eq!(truncation.edges.truncated, 8);
    assert_eq!(truncation.flows.truncated, 9);
    assert!(truncation.is_truncated());

    let json = serde_json::to_value(&graph).unwrap();
    assert_eq!(json["truncation"]["edges"]["total"], 12);
    assert_eq!(json["detail_limits"]["edges"], 4);
}

#[test]
fn legacy_v1_counts_are_lower_bounds_and_truncation_is_unknown() {
    const LEGACY_GRAPH_V1: &str = r#"{
      "schema":"blackbox.incident.graph/v1",
      "incident_id":"inc-legacy",
      "nodes":[{"kind":"run","id":"run-1","run_id":"run-1","label":"run run-1"}],
      "edges":[{
        "schema":"blackbox.evidence.edge/v1",
        "id":"edge-legacy",
        "from_kind":"run",
        "from_id":"run-1",
        "to_kind":"credential",
        "to_id":"credential:legacy",
        "relation":"credential_use",
        "confidence":"strongly_correlated",
        "reasons":["legacy_fixture"],
        "created_at":"2026-07-22T00:00:00Z",
        "run_id":"run-1"
      }],
      "techniques":[{
        "technique":"credential_use",
        "first_run_id":"run-1",
        "first_ref":"edge-legacy",
        "reused_by_runs":["run-2"]
      }],
      "run_count":2,
      "evidence_count":0,
      "finding_count":0
    }"#;

    let graph: blackbox::incident::IncidentGraph = serde_json::from_str(LEGACY_GRAPH_V1).unwrap();
    assert_eq!(graph.schema, "blackbox.incident.graph/v1");
    assert_eq!(graph.edge_total(), 1);
    assert_eq!(graph.flow_total(), 1);
    assert_eq!(graph.technique_total(), 1);
    assert_eq!(graph.reuse_total(), 1);
    assert!(!graph.counts_exact);
    assert_eq!(graph.detail_limits, None);
    assert_eq!(graph.is_detail_truncated(), None);

    let mut incident = Incident::new(Some("legacy".into()));
    incident.id = "inc-legacy".into();
    let aggregates =
        blackbox::incident::compute_incident_aggregates_from_graph(&incident, &graph, 0, 0);
    assert_eq!(aggregates.technique_count, 1);
    assert_eq!(aggregates.reuse_count, 1);
    assert!(!aggregates.counts_exact);
}

#[test]
fn tied_edge_detail_is_stable_by_id() {
    let incident = Incident::new(Some("stable detail".into()));
    let at = chrono::Utc::now();
    let mut edges: Vec<_> = (0..8)
        .rev()
        .map(|index| {
            let mut item = edge(
                &format!("edge-{index:02}"),
                EvidenceRelation::Delegation,
                EntityKind::Run,
                "run-parent",
                EntityKind::Run,
                "run-child",
                "run-parent",
            );
            item.created_at = at;
            item
        })
        .collect();
    let limits = IncidentGraphLimits {
        nodes: 1,
        edges: 3,
        flows: 3,
        techniques: 1,
    };
    let first = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            edges: edges.clone(),
            ..Default::default()
        },
        limits,
    );
    edges.rotate_left(3);
    let second = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            edges,
            ..Default::default()
        },
        limits,
    );

    let first_ids: Vec<_> = first.edges.iter().map(|edge| edge.id.as_str()).collect();
    let second_ids: Vec<_> = second.edges.iter().map(|edge| edge.id.as_str()).collect();
    assert_eq!(first_ids, vec!["edge-00", "edge-01", "edge-02"]);
    assert_eq!(first_ids, second_ids);
    assert_eq!(
        first
            .flows
            .iter()
            .map(|flow| flow.edge_id.as_str())
            .collect::<Vec<_>>(),
        vec!["edge-00", "edge-01", "edge-02"]
    );
}
