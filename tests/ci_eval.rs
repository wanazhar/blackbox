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
        eval: false,
        observe_only: false,
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
    // Eval harness contract: anomalies.json + summary.txt first-class artifacts
    std::fs::write(
        artifacts.join("anomalies.json"),
        serde_json::to_string_pretty(&summary.anomalies).unwrap(),
    )
    .unwrap();
    std::fs::write(
        artifacts.join("summary.txt"),
        format!(
            "headline: {}\nnext: {}\nstatus: {:?}\nexit: {:?}\nanomalies: {}\n",
            summary.headline,
            summary.next_action,
            summary.status,
            summary.exit_code,
            summary.anomalies.len()
        ),
    )
    .unwrap();
    let score = blackbox::score::EvalScore::from_run_summary(&run, &summary);
    std::fs::write(
        artifacts.join("score.json"),
        score.to_pretty_json().unwrap(),
    )
    .unwrap();

    assert!(artifacts.join("run.json").is_file());
    assert!(artifacts.join("postmortem.json").is_file());
    assert!(artifacts.join("anomalies.json").is_file());
    assert!(artifacts.join("summary.txt").is_file());
    assert!(artifacts.join("score.json").is_file());
    let run_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(artifacts.join("run.json")).unwrap())
            .unwrap();
    assert_eq!(run_json["id"], run.id);
    let anoms: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(artifacts.join("anomalies.json")).unwrap())
            .unwrap();
    assert!(anoms.is_array());
    let summary_txt = std::fs::read_to_string(artifacts.join("summary.txt")).unwrap();
    assert!(summary_txt.contains("headline:"));
    assert!(summary_txt.contains("anomalies:"));
    let score_v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(artifacts.join("score.json")).unwrap())
            .unwrap();
    assert_eq!(score_v["schema"], "blackbox.score/v1");
    assert_eq!(score_v["run_id"], run.id);
    assert_eq!(score_v["exit_code"], 0);
    assert_eq!(score_v["failed"], false);
    assert!(score_v["anomaly_count"].as_u64().is_some());
}

#[tokio::test]
async fn score_json_from_failed_eval_run() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());
    let args = RunArgs {
        name: Some("eval-fail".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["eval".into(), "ci".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: true,
        artifact_dir: None,
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
        command: vec!["false".into()],
    };
    let run = supervisor.execute(&args).await.unwrap();
    assert_eq!(run.exit_code, Some(1));
    let summary = blackbox::summary::build_summary(
        store.as_ref(),
        &run,
        blackbox::summary::SummaryOptions::default(),
    )
    .await
    .unwrap();
    let score = blackbox::score::EvalScore::from_run_summary(&run, &summary);
    assert_eq!(score.schema, blackbox::score::SCORE_SCHEMA);
    assert!(score.failed);
    assert_eq!(score.exit_code, Some(1));
    assert!(score.tags.iter().any(|t| t == "eval"));
}

#[test]
fn eval_flag_documented_in_clap_help() {
    use blackbox::cli::Cli;
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let run = cmd
        .find_subcommand_mut("run")
        .expect("run subcommand exists");
    let help = run.render_long_help().to_string();
    assert!(
        help.contains("--eval"),
        "run --help should mention --eval harness mode; got:\n{help}"
    );
}
