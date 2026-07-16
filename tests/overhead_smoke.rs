//! A6 — Capture overhead smoke (loose CI budget).
//!
//! Supervising a trivial command must not take more than a few seconds of
//! wall time on a healthy machine. This is a regression guard, not a microbench.

use std::sync::Arc;
use std::time::Instant;

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

/// Soft budget for `blackbox run -- true` style supervision (debug builds).
const MAX_OVERHEAD_MS: u128 = 8_000;

#[tokio::test]
async fn a6_run_true_overhead_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store);

    let args = RunArgs {
        name: Some("overhead".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["overhead".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: false,
        artifact_dir: None,
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
        command: vec!["true".into()],
    };

    let t0 = Instant::now();
    let run = supervisor.execute(&args).await.expect("run true");
    let ms = t0.elapsed().as_millis();

    assert_eq!(run.exit_code, Some(0));
    assert!(
        ms < MAX_OVERHEAD_MS,
        "capture overhead too high: {ms}ms (budget {MAX_OVERHEAD_MS}ms)"
    );
}
