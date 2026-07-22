//! 1.7 incident storage/cursor and bounded graph qualification at 10k records.

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use blackbox::boundary::{EntityKind, EvidenceEdge, EvidenceRelation};
use blackbox::core::event::Confidence;
use blackbox::evidence::{EvidenceAction, ExternalEvidenceEvent};
use blackbox::incident::{
    attach_to_incident, build_incident_graph_with_limits, compute_incident_aggregates_from_graph,
    decode_incident_cursor, GraphInputs, Incident, IncidentAttachmentKind, IncidentGraphLimits,
};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

const RECORD_COUNT: usize = 10_000;

#[tokio::test]
async fn storage_cursor_exhausts_ten_thousand_tied_records_exactly_once() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let timestamp = chrono::Utc::now();
    let started = Instant::now();

    for index in 0..RECORD_COUNT {
        let mut incident = Incident::new(Some(format!("scale-{index}")));
        incident.id = format!("inc-{index:05}");
        incident.created_at = timestamp;
        store.upsert_incident(&incident).await.unwrap();
    }

    let mut cursor = None;
    let mut ordered = Vec::with_capacity(RECORD_COUNT);
    loop {
        let page = store
            .list_incidents_page(cursor.as_ref(), 317)
            .await
            .unwrap();
        ordered.extend(page.incidents.into_iter().map(|incident| incident.id));
        if !page.has_more {
            break;
        }
        cursor = Some(decode_incident_cursor(page.next_cursor.as_deref().unwrap()).unwrap());
    }

    let unique: BTreeSet<_> = ordered.iter().collect();
    assert_eq!(ordered.len(), RECORD_COUNT, "lost incident IDs");
    assert_eq!(unique.len(), RECORD_COUNT, "duplicate incident IDs");
    assert_eq!(ordered.first().map(String::as_str), Some("inc-09999"));
    assert_eq!(ordered.last().map(String::as_str), Some("inc-00000"));
    assert!(
        ordered.windows(2).all(|pair| pair[0] > pair[1]),
        "tied timestamps must use descending ID as a deterministic tiebreaker"
    );
    // Diagnostic only: correctness is host-independent; CI does not fail on wall time.
    eprintln!(
        "incident storage pagination: {RECORD_COUNT} records in {:?}",
        started.elapsed()
    );
}

#[test]
fn graph_reconstruction_bounds_ten_thousand_record_details() {
    let mut incident = Incident::new(Some("10k graph".into()));
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-scale-a",
        None::<String>,
    );
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-scale-b",
        None::<String>,
    );

    let mut external = Vec::with_capacity(RECORD_COUNT);
    let mut edges = Vec::with_capacity(RECORD_COUNT);
    for index in 0..RECORD_COUNT {
        let mut event = ExternalEvidenceEvent::new(
            "scale",
            "fixture",
            format!("source-{index:05}"),
            EvidenceAction::CredentialAccess,
        );
        event.id = format!("evidence-{index:05}");
        let run_id = if (index / 250) % 2 == 0 {
            "run-scale-a"
        } else {
            "run-scale-b"
        };
        event.linked_run_id = Some(run_id.into());
        event.destination = Some(format!("service-{:03}.example", index % 250));
        external.push(event);

        let relation = match index % 4 {
            0 => EvidenceRelation::Delegation,
            1 => EvidenceRelation::CredentialUse,
            2 => EvidenceRelation::ArtifactDerivation,
            _ => EvidenceRelation::NetworkConnection,
        };
        let mut edge = EvidenceEdge::new(
            EntityKind::Run,
            run_id,
            EntityKind::ExternalEvidence,
            format!("evidence-{index:05}"),
            relation,
            Confidence::StronglyCorrelated,
        );
        edge.id = format!("edge-{index:05}");
        edge.run_id = Some(run_id.into());
        edge.reasons = vec!["scale_fixture".into()];
        edges.push(edge);
    }

    let limits = IncidentGraphLimits {
        nodes: 128,
        edges: 96,
        flows: 64,
        techniques: 32,
    };
    let started = Instant::now();
    let graph = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            external,
            edges,
            ..Default::default()
        },
        limits,
    );

    assert_eq!(graph.evidence_count, RECORD_COUNT);
    assert_eq!(graph.edge_count, Some(RECORD_COUNT));
    assert_eq!(graph.flow_count, Some(7_500));
    let flow_counts = graph.flow_counts.unwrap();
    assert_eq!(flow_counts.delegation, 2_500);
    assert_eq!(flow_counts.credential_use, 2_500);
    assert_eq!(flow_counts.artifact_derivation, 2_500);
    assert_eq!(graph.technique_count, Some(251));
    assert_eq!(graph.reuse_count, Some(251));
    assert_eq!(graph.techniques.len(), limits.techniques);
    let truncation = graph.truncation.as_ref().unwrap();
    assert_eq!(truncation.nodes.total, RECORD_COUNT + 2);
    assert_eq!(graph.nodes.len(), limits.nodes);
    assert_eq!(graph.edges.len(), limits.edges);
    assert_eq!(graph.flows.len(), limits.flows);
    assert_eq!(truncation.edges.truncated, RECORD_COUNT - limits.edges);
    assert_eq!(truncation.flows.truncated, 7_500 - limits.flows);
    assert_eq!(truncation.techniques.total, 251);
    assert_eq!(truncation.techniques.included, limits.techniques);
    assert_eq!(truncation.techniques.truncated, 251 - limits.techniques);

    // This is the same assembly helper used by CLI and dashboard consumers;
    // aggregates must use exact pre-truncation totals, not detail vector lengths.
    let aggregates = compute_incident_aggregates_from_graph(&incident, &graph, 0, 0);
    assert_eq!(aggregates.technique_count, 251);
    assert_eq!(aggregates.reuse_count, 251);
    assert!(aggregates.counts_exact);
    // Diagnostic only: memory is qualified separately in incident_memory_bound.
    eprintln!(
        "incident graph reconstruction: {RECORD_COUNT} evidence + edges in {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn incident_show_reports_exact_totals_and_visible_truncation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("incident-show.db");
    let store = SqliteStore::open(&database).unwrap();
    let mut incident = Incident::new(Some("CLI aggregate honesty".into()));
    incident.id = "inc-cli-exact".into();
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-cli",
        None::<String>,
    );
    store.upsert_incident(&incident).await.unwrap();

    let events: Vec<_> = (0..1_001)
        .map(|index| {
            let mut event = ExternalEvidenceEvent::new(
                "cli-scale",
                "fixture",
                format!("source-{index:04}"),
                EvidenceAction::NetworkConnect,
            );
            event.id = format!("evidence-cli-{index:04}");
            event.linked_run_id = Some("run-cli".into());
            event.destination = Some(format!("unique-{index:04}.example"));
            event
        })
        .collect();
    let inserted = store
        .insert_external_evidence_batch(&events, &[])
        .await
        .unwrap();
    assert_eq!(inserted, (1_001, 0));
    drop(store);

    let database_arg = database.to_string_lossy().into_owned();
    let json_output = Command::new(env!("CARGO_BIN_EXE_blackbox"))
        .args([
            "--store",
            database_arg.as_str(),
            "--json",
            "incident",
            "show",
            "inc-cli-exact",
            "--graph",
        ])
        .output()
        .unwrap();
    assert!(
        json_output.status.success(),
        "incident show failed: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(
        json["data"]["graph"]["techniques"]
            .as_array()
            .unwrap()
            .len(),
        1_000
    );
    assert_eq!(json["data"]["graph"]["technique_count"], 1_001);
    assert_eq!(json["data"]["aggregates"]["technique_count"], 1_001);
    assert_eq!(json["data"]["aggregates"]["counts_exact"], true);
    assert_eq!(
        json["data"]["graph"]["truncation"]["techniques"]["truncated"],
        1
    );

    let human_output = Command::new(env!("CARGO_BIN_EXE_blackbox"))
        .args([
            "--store",
            database_arg.as_str(),
            "incident",
            "show",
            "inc-cli-exact",
            "--graph",
        ])
        .output()
        .unwrap();
    assert!(human_output.status.success());
    let human = String::from_utf8(human_output.stdout).unwrap();
    assert!(human.contains("techniques=1001"), "{human}");
    assert!(human.contains("graph_detail=truncated"), "{human}");
    assert!(human.contains("techniques=1000/1001"), "{human}");
}
