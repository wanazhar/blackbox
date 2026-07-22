//! Auto provenance from experiment dataset_case metadata.

use std::sync::Arc;

use blackbox::boundary::{auto_provenance_record, ProvenanceStatus};
use blackbox::core::run::{Run, RunStatus};
use blackbox::evidence::{EvidenceAction, ExternalEvidenceEvent};
use blackbox::experiment::{ExperimentRole, RunExperimentMeta};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn auto_provenance_from_dataset_case_and_observed_network() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["eval".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    let meta = RunExperimentMeta {
        experiment_id: Some("exp1".into()),
        dataset_case: Some("bench-case-9".into()),
        task_id: Some("task-a".into()),
        role: ExperimentRole::Candidate,
        ..Default::default()
    };
    store.put_run_experiment_meta(&run.id, &meta).await.unwrap();

    let mut ext = ExternalEvidenceEvent::new("proxy", "proxy", "x1", EvidenceAction::HttpRequest);
    ext.destination = Some("https://answers.leaked.example/q".into());
    ext.linked_run_id = Some(run.id.clone());
    store.insert_external_evidence(&ext).await.unwrap();

    let external = store.list_external_evidence_for_run(&run.id).await.unwrap();
    let rec = auto_provenance_record(&run.id, Some(&meta), &external).unwrap();
    assert!(rec
        .declared_sources
        .iter()
        .any(|s| s.contains("bench-case-9")));
    assert_eq!(rec.status, ProvenanceStatus::InvalidUndeclaredSource);

    store.insert_provenance_record(&rec).await.unwrap();
    let loaded = store.list_provenance_records(&run.id).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].status, ProvenanceStatus::InvalidUndeclaredSource);
}

#[tokio::test]
async fn auto_provenance_insufficient_when_only_declared() {
    let meta = RunExperimentMeta {
        dataset_case: Some("local-only".into()),
        ..Default::default()
    };
    let rec = auto_provenance_record("r1", Some(&meta), &[]).unwrap();
    assert_eq!(rec.status, ProvenanceStatus::InsufficientEvidence);
}
