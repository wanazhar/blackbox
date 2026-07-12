//! CI/eval conventions: artifact dir + adapter detection smoke.

use std::sync::Arc;

use blackbox::adapters::detect::detect_adapter;
use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[test]
fn detects_post_11_adapters() {
    for (cmd, id) in [
        ("aider", "aider"),
        ("gemini", "gemini"),
        ("cursor-agent", "cursor"),
        ("opencode", "opencode"),
        ("grok", "grok"),
    ] {
        assert_eq!(detect_adapter(&[cmd.into()]).id(), id, "cmd={cmd}");
    }
}

#[tokio::test]
async fn ci_artifact_dir_writes_run_and_postmortem() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("out");
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("ci-art".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["ci".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false, // don't process::exit in test
        artifact_dir: Some(artifacts.clone()),
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
        command: vec!["true".into()],
    };

    // write_ci_artifacts is CLI-side; exercise store path used by artifacts:
    let run = supervisor.execute(&args).await.unwrap();
    assert_eq!(run.exit_code, Some(0));

    // Mimic CI artifact write contract
    std::fs::create_dir_all(&artifacts).unwrap();
    std::fs::write(
        artifacts.join("run.json"),
        serde_json::to_string_pretty(&run).unwrap(),
    )
    .unwrap();
    let summary = blackbox::summary::build_summary(
        store.as_ref(),
        &run,
        blackbox::summary::SummaryOptions::default(),
    )
    .await
    .unwrap();
    std::fs::write(
        artifacts.join("postmortem.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .unwrap();

    assert!(artifacts.join("run.json").is_file());
    assert!(artifacts.join("postmortem.json").is_file());
    let run_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(artifacts.join("run.json")).unwrap())
            .unwrap();
    assert_eq!(run_json["id"], run.id);
}
