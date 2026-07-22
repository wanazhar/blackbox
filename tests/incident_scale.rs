//! 1.7 incident storage/cursor and bounded graph qualification at 10k records.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blackbox::boundary::{EntityKind, EvidenceEdge, EvidenceRelation};
use blackbox::core::event::Confidence;
use blackbox::evidence::{EvidenceAction, ExternalEvidenceEvent};
use blackbox::incident::{
    attach_to_incident, build_incident_graph_with_limits, decode_incident_cursor, GraphInputs,
    Incident, IncidentAttachmentKind, IncidentGraphLimits,
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
    assert!(started.elapsed() < Duration::from_secs(30));
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
        "run-scale",
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
        event.linked_run_id = Some("run-scale".into());
        external.push(event);

        let relation = match index % 4 {
            0 => EvidenceRelation::Delegation,
            1 => EvidenceRelation::CredentialUse,
            2 => EvidenceRelation::ArtifactDerivation,
            _ => EvidenceRelation::NetworkConnection,
        };
        let mut edge = EvidenceEdge::new(
            EntityKind::Run,
            "run-scale",
            EntityKind::ExternalEvidence,
            format!("evidence-{index:05}"),
            relation,
            Confidence::StronglyCorrelated,
        );
        edge.id = format!("edge-{index:05}");
        edge.run_id = Some("run-scale".into());
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
    assert_eq!(graph.edge_count, RECORD_COUNT);
    assert_eq!(graph.flow_count, 7_500);
    assert_eq!(graph.flow_counts.delegation, 2_500);
    assert_eq!(graph.flow_counts.credential_use, 2_500);
    assert_eq!(graph.flow_counts.artifact_derivation, 2_500);
    assert_eq!(graph.truncation.nodes.total, RECORD_COUNT + 1);
    assert_eq!(graph.nodes.len(), limits.nodes);
    assert_eq!(graph.edges.len(), limits.edges);
    assert_eq!(graph.flows.len(), limits.flows);
    assert_eq!(
        graph.truncation.edges.truncated,
        RECORD_COUNT - limits.edges
    );
    assert_eq!(graph.truncation.flows.truncated, 7_500 - limits.flows);
    assert!(started.elapsed() < Duration::from_secs(10));
    eprintln!(
        "incident graph reconstruction: {RECORD_COUNT} evidence + edges in {:?}",
        started.elapsed()
    );
}
