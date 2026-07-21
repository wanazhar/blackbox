//! 1.6: experiment metadata attaches to runs (CLI flag surface via store API).

use std::sync::Arc;

use blackbox::core::run::{Run, RunStatus};
use blackbox::experiment::{ExperimentManifest, ExperimentRole, RunExperimentMeta};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn experiment_meta_survives_round_trip() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let m = ExperimentManifest::new("login-fix", "Login Fix");
    store.upsert_experiment(&m).await.unwrap();

    let mut run = Run::new(vec!["cargo".into(), "test".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    let meta = RunExperimentMeta {
        experiment_id: Some("login-fix".into()),
        task_id: Some("invalid-session".into()),
        variant: Some("glm".into()),
        attempt: Some(3),
        role: ExperimentRole::Candidate,
        model: Some("glm-5.2".into()),
        provider: Some("zhipu".into()),
        harness: Some("claude".into()),
        harness_version: Some("1.0".into()),
        seed: Some("42".into()),
        dataset_case: Some("case-1".into()),
        ..Default::default()
    };
    store
        .put_run_experiment_meta(&run.id, &meta)
        .await
        .unwrap();

    let loaded = store
        .get_run_experiment_meta(&run.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.experiment_id.as_deref(), Some("login-fix"));
    assert_eq!(loaded.attempt, Some(3));
    assert!(matches!(loaded.role, ExperimentRole::Candidate));

    let runs = store.list_runs_for_experiment("login-fix").await.unwrap();
    assert_eq!(runs, vec![run.id]);
}
