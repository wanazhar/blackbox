//! 1.4 Phase D — Process spawn-storm fixture (WS6).
//!
//! Spawns many short-lived descendants under a supervised shell and measures
//! how many process events blackbox observed. Short-lived loss is expected
//! with polling; this test **quantifies** it and asserts root lifecycle
//! completeness rather than perfect capture of every `/bin/true`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::transcript::rebuild_terminal_transcript;

fn probe() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pty_fidelity_probe.sh");
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

#[tokio::test]
async fn spawn_storm_reports_lifecycle_and_measures_loss() {
    let ws = std::env::temp_dir().join(format!("bb-storm-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(ws.join(".blackbox/blobs")).unwrap();
    let db = ws.join(".blackbox/blackbox.db");
    let blobs = ws.join(".blackbox/blobs");
    let store: Arc<dyn TraceStore> =
        Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());
    let supervisor = RunSupervisor::new(store.clone());

    let storm_n = 80u64;
    let p = probe();
    let args = RunArgs {
        name: Some("spawn-storm".into()),
        project: Some(ws.display().to_string()),
        tag: vec!["process-storm".into()],
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
        command: vec![
            p.display().to_string(),
            "storm".into(),
            storm_n.to_string(),
        ],
    };

    let run = supervisor.execute(&args).await.expect("run");
    assert_eq!(run.exit_code, Some(0));

    let events = store.get_events(&run.id).await.unwrap();
    let text = rebuild_terminal_transcript(store.as_ref(), &events)
        .await
        .unwrap_or_default();
    assert!(
        text.contains(&format!("storm_done={storm_n}")) || text.contains("storm_done"),
        "probe output missing: {text}"
    );

    let process_events: Vec<_> = events
        .iter()
        .filter(|e| e.source == blackbox::core::event::EventSource::Process)
        .collect();
    let exec_like = process_events
        .iter()
        .filter(|e| {
            e.kind == "process.exec"
                || e.kind == "process.discovered"
                || e.kind == "process.spawned"
        })
        .count();

    // Root lifecycle must be complete for honesty (1.4 C2 / Phase D).
    assert!(
        events.iter().any(|e| e.kind == "process.observer.started"),
        "observer.started missing"
    );
    assert!(
        events.iter().any(|e| e.kind == "process.spawned"),
        "process.spawned missing"
    );
    assert!(
        events.iter().any(|e| e.kind == "process.observer.stopped"),
        "observer.stopped missing"
    );

    // Capture method / backend should be identified on observer.started.
    if let Some(ev) = events.iter().find(|e| e.kind == "process.observer.started") {
        assert!(
            ev.metadata.contains_key("process_tree_backend")
                || ev.metadata.contains_key("process_tree_capture"),
            "backend metadata missing: {:?}",
            ev.metadata
        );
    }

    // Measure loss: we never require capturing all short-lived children.
    // Soft bound: at least the root is observed; miss rate is logged for CI.
    let observed = exec_like as u64;
    // Each storm iteration runs /bin/true and /bin/echo → up to 2*n short lives,
    // plus the shell itself. Perfect capture would be >> n; polling may see few.
    eprintln!(
        "spawn_storm: requested_ops≈{} process_exec_like_events={} (short-lived loss expected under polling)",
        storm_n * 2,
        observed
    );
    assert!(
        observed >= 1,
        "expected at least root process observation, got {observed}"
    );

    // Coverage process surface must not claim complete without lifecycle —
    // already enforced in coverage unit tests; here assert coverage event exists.
    assert!(
        events.iter().any(|e| e.kind == "capture.coverage"),
        "missing capture.coverage"
    );

    let _ = std::fs::remove_dir_all(ws);
}
