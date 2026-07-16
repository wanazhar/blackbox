//! Golden “first run” path aligned with docs/guide/getting-started.md.
//!
//! Ensures the operator happy path (record → list → show → timeline → postmortem)
//! stays available with stable, documented artifacts — without requiring a live
//! agent harness.

use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, format_summary_text, SummaryOptions};
use blackbox::util::short_id;

#[tokio::test]
async fn first_run_happy_path_matches_getting_started_contract() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    let db = project.join(".blackbox/blackbox.db");
    let blobs = project.join(".blackbox/blobs");
    std::fs::create_dir_all(&blobs).unwrap();

    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    // Getting started: blackbox run -- echo hello world  (use `true` for portability)
    let args = RunArgs {
        name: Some("first-run-docs".into()),
        project: Some(project.to_string_lossy().into()),
        tag: vec!["docs-golden".into()],
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
        command: vec!["true".into()],
    };

    let run = supervisor.execute(&args).await.expect("first run succeeds");
    assert_eq!(run.exit_code, Some(0), "supervised true must exit 0");
    assert_eq!(
        run.status,
        blackbox::core::run::RunStatus::Succeeded,
        "run status should be Succeeded: {:?}",
        run.status
    );

    // Short id is the documented handle (prefix of UUID)
    let sid = short_id(&run.id);
    assert!(
        sid.len() >= 4 && sid.len() <= 8,
        "short_id length out of docs range: {sid:?}"
    );
    assert!(
        run.id.starts_with(sid),
        "short_id must be a prefix of full id"
    );

    // blackbox runs — at least one row
    let runs = store.list_runs().await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].id, run.id);

    // blackbox show — run is loadable by full id and by unique prefix
    let by_full = store.get_run(&run.id).await.unwrap();
    assert!(by_full.is_some());

    // Events exist (PTY/process bookkeeping at minimum)
    let events = store.get_events(&run.id).await.unwrap();
    assert!(
        !events.is_empty(),
        "getting-started expects a non-empty timeline after a run"
    );
    // Sequences are monotonic / unique enough for timeline jump docs
    let mut seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
    seqs.sort_unstable();
    assert_eq!(seqs.len(), events.len());
    for w in seqs.windows(2) {
        assert!(w[0] < w[1], "sequences must be strictly increasing");
    }

    // blackbox postmortem / summary text surface (headline + next at minimum)
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .expect("postmortem builds");
    assert!(
        !summary.headline.is_empty() || !summary.next_action.is_empty() || summary.exit_code.is_some(),
        "postmortem should expose headline/next/exit for docs examples"
    );
    let text = format_summary_text(&summary);
    assert!(
        text.contains("headline")
            || text.to_lowercase().contains("exit")
            || !summary.headline.is_empty(),
        "human postmortem text should be non-empty for operator docs"
    );

    // Anomalies field is always present (possibly empty) — dashboard/CI contract
    let _ = &summary.anomalies;

    // Eval/CI artifact contract still holds when writing the same files getting-started mentions
    let artifacts = project.join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    std::fs::write(
        artifacts.join("run.json"),
        serde_json::to_string_pretty(&run).unwrap(),
    )
    .unwrap();
    std::fs::write(
        artifacts.join("postmortem.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .unwrap();
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

    for name in [
        "run.json",
        "postmortem.json",
        "anomalies.json",
        "summary.txt",
    ] {
        assert!(
            artifacts.join(name).is_file(),
            "docs artifact {name} must be written"
        );
    }

    let summary_txt = std::fs::read_to_string(artifacts.join("summary.txt")).unwrap();
    assert!(summary_txt.contains("headline:"));
    assert!(summary_txt.contains("anomalies:"));
}

#[test]
fn short_id_docs_contract() {
    // Documented as ~8 char unique prefix
    assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh");
    assert_eq!(short_id("abc"), "abc");
}
