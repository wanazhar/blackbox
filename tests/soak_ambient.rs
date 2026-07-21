//! Soft soak: repeated ambient-style observe-only runs under load.
//!
//! Not a multi-hour wall; exercises store growth, observe-only neutrality,
//! and capture coverage for N back-to-back supervisions.

use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

const N: usize = 8;

/// Extended soak (ignored by default): more iterations + nested process + PTY volume.
///
/// ```bash
/// cargo test --test soak_ambient soak_extended -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "extended soak — run with --ignored for longer multi-scenario load"]
async fn soak_extended_multi_scenario() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("soak-ext.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let scenarios: Vec<Vec<String>> = vec![
        vec!["true".into()],
        vec![
            "sh".into(),
            "-c".into(),
            "i=0; while [ $i -lt 40 ]; do echo line-$i; i=$((i+1)); done".into(),
        ],
        vec![
            "sh".into(),
            "-c".into(),
            "sh -c 'sh -c \"echo nested; sleep 0.05\"'".into(),
        ],
        vec![
            "sh".into(),
            "-c".into(),
            "echo secret=sk-abcdefghijklmnopqrstuvwxyz012345".into(),
        ],
    ];

    for round in 0..12 {
        let cmd = scenarios[round % scenarios.len()].clone();
        let args = RunArgs {
            name: Some(format!("ext-soak-{round}")),
            project: Some(dir.path().to_string_lossy().into()),
            tag: vec!["soak-ext".into()],
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
            ambient: true,
            command: cmd,
        ..Default::default()
    };
        let run = supervisor.execute(&args).await.expect("ext soak run");
        assert!(
            run.notes.as_deref().unwrap_or("").contains("observe-only"),
            "must stay observe-only"
        );
        let events = store.get_events(&run.id).await.unwrap();
        assert!(events.iter().any(|e| e.kind == "capture.coverage"));
        // Secret planted in one scenario must not survive previews unredacted when redacted path used
        for ev in &events {
            if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
                assert!(
                    !p.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
                    "secret leaked in preview: {p}"
                );
            }
        }
    }
}

#[tokio::test]
async fn soak_observe_only_repeated_true() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("soak.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let mut ids = Vec::new();
    for i in 0..N {
        let args = RunArgs {
            name: Some(format!("soak-{i}")),
            project: Some(dir.path().to_string_lossy().into()),
            tag: vec!["soak".into()],
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
            ambient: true,
            command: vec!["true".into()],
        ..Default::default()
    };
        let run = supervisor.execute(&args).await.expect("soak run");
        assert_eq!(run.exit_code, Some(0));
        assert!(
            run.notes.as_deref().unwrap_or("").contains("observe-only"),
            "ambient soak must stay observe-only: {:?}",
            run.notes
        );
        assert!(run.parent_run_id.is_none());
        ids.push(run.id);
    }

    assert_eq!(ids.len(), N);
    // Store should contain coverage for each run
    for id in &ids {
        let events = store.get_events(id).await.unwrap();
        assert!(
            events.iter().any(|e| e.kind == "capture.coverage"),
            "missing coverage for {id}"
        );
        assert!(
            events.iter().any(|e| e.kind.starts_with("capture.layer.")),
            "missing layer health for {id}"
        );
    }

    // Soft growth bound: blobs + db shouldn't explode for N×true
    let blob_bytes: u64 = std::fs::read_dir(&blobs)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);
    let db_bytes = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
    assert!(
        db_bytes + blob_bytes < 50 * 1024 * 1024,
        "soak store too large: db={db_bytes} blobs={blob_bytes}"
    );
}
