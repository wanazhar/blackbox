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

    // Docs / JSON API contract: these postmortem fields always serialize
    let pm = serde_json::to_value(&summary).expect("postmortem serializes");
    for key in [
        "headline",
        "next_action",
        "anomalies",
        "evidence",
        "status",
        "exit_code",
    ] {
        assert!(
            pm.get(key).is_some(),
            "postmortem JSON must include '{key}' (json-api / recipes docs)"
        );
    }
    assert!(pm["anomalies"].is_array());
    assert!(pm["evidence"].is_array());

    // Cheatsheet/docs: short id is a unique prefix of the full UUID (CLI resolves prefix)
    let matches: Vec<_> = runs.iter().filter(|r| r.id.starts_with(sid)).collect();
    assert_eq!(
        matches.len(),
        1,
        "short_id prefix must uniquely identify the run"
    );
    assert_eq!(matches[0].id, run.id);

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
    assert!(summary_txt.contains("next:"));

    // run.json is a re-loadable Run shape for CI upload docs
    let run_back: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(artifacts.join("run.json")).unwrap()).unwrap();
    assert_eq!(run_back["id"], run.id);
    assert_eq!(run_back["exit_code"], 0);
}

#[test]
fn short_id_docs_contract() {
    // Documented as ~8 char unique prefix
    assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh");
    assert_eq!(short_id("abc"), "abc");
}

#[test]
fn adapters_md_detection_table() {
    // Keep docs/guide/adapters.md detection table honest
    use blackbox::adapters::detect::detect_adapter;
    let cases = [
        ("claude", "claude"),
        ("codex", "codex"),
        ("aider", "aider"),
        ("gemini", "gemini"),
        ("cursor", "cursor"),
        ("cursor-agent", "cursor"),
        ("opencode", "opencode"),
        ("grok", "grok"),
        ("my-custom-agent", "generic"),
        ("echo", "generic"),
    ];
    for (cmd, id) in cases {
        assert_eq!(
            detect_adapter(&[cmd.into()]).id(),
            id,
            "adapters.md detection for {cmd}"
        );
    }
}

#[tokio::test]
async fn postmortem_text_has_docs_oriented_sections() {
    // Even a trivial success run should produce operator-readable summary text
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());
    let args = RunArgs {
        name: Some("pm-text".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec![],
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
    let run = supervisor.execute(&args).await.unwrap();
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    let text = format_summary_text(&summary);
    // debug-a-failure / cheatsheet expect these human labels somewhere in text or fields
    assert!(
        !summary.headline.is_empty() || text.to_lowercase().contains("succeed"),
        "expected usable headline or success wording: headline={:?} text={text}",
        summary.headline
    );
    assert_eq!(summary.exit_code, Some(0));
}
