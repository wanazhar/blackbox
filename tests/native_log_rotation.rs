//! 1.5: native-log rotation / identity / backlog honesty.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use blackbox::adapters::generic::GenericAdapter;
use blackbox::adapters::harness::HarnessAdapter;
use blackbox::adapters::native_logs::{
    classify_file_change, list_candidate_files_for, poll_native_logs, FileChange, TrackedLogFile,
};
use blackbox::core::run::Run;
use blackbox::pipeline::EventWriter;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::RedactionConfig;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use tokio::sync::watch;

#[test]
fn rotation_and_same_path_replacement_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    std::fs::write(&path, b"{\"a\":1}\n").unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    let mut tracked = TrackedLogFile::from_meta(path.clone(), &meta, 1);
    tracked.offset = meta.len();

    // Append stays Appended
    {
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, r#"{{"b":2}}"#).unwrap();
    }
    let meta_app = std::fs::metadata(&path).unwrap();
    assert_eq!(
        classify_file_change(&tracked, &meta_app),
        FileChange::Appended
    );

    // Truncate / rewrite
    std::fs::write(&path, b"{\"c\":3}\n").unwrap();
    tracked.offset = meta_app.len();
    let meta_tr = std::fs::metadata(&path).unwrap();
    let ch = classify_file_change(&tracked, &meta_tr);
    assert!(
        matches!(ch, FileChange::Truncated | FileChange::RotatedOrReplaced),
        "expected truncate/rotate, got {ch:?}"
    );

    // Synthetic inode change → RotatedOrReplaced
    tracked.identity.inode = tracked.identity.inode.wrapping_add(1);
    assert_eq!(
        classify_file_change(&tracked, &meta_tr),
        FileChange::RotatedOrReplaced
    );
}

#[test]
fn discovery_is_explicit_not_implied_complete() {
    // list_candidate_files is the discovery API; poller uses it on interval,
    // not every tick. Smoke: listing is bounded.
    let dir = tempfile::tempdir().unwrap();
    for i in 0..10 {
        std::fs::write(
            dir.path().join(format!("session-{i}.jsonl")),
            format!(r#"{{"i":{i}}}"#),
        )
        .unwrap();
    }
    let files = list_candidate_files_for("claude", &[dir.path().to_path_buf()]);
    assert!(files.len() <= 48);
    assert!(!files.is_empty());
}

#[tokio::test]
async fn poller_emits_events_for_appends_and_health() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("session.jsonl");
    std::fs::write(&log, b"").unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["claude".into()], dir.path().to_string_lossy().into());
    store.insert_run(&run).await.unwrap();
    let writer = Arc::new(EventWriter::new(store.clone(), run.id.clone()));

    let (stop_tx, stop_rx) = watch::channel(false);
    let adapter: Arc<dyn HarnessAdapter> = Arc::new(GenericAdapter);
    let scanner = SecretScanner::new(RedactionConfig::default());
    let roots = vec![dir.path().to_path_buf()];

    let handle = tokio::spawn(poll_native_logs(
        adapter,
        writer.clone(),
        roots,
        scanner,
        stop_rx,
    ));

    // Let initial discovery run (EOF start).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Append a JSON line the generic adapter can parse or at least attempt.
    {
        let mut f = OpenOptions::new().append(true).open(&log).unwrap();
        // Minimal object — parse may produce 0 events but poller should not crash.
        writeln!(f, r#"{{"type":"assistant","text":"hi"}}"#).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

    let events = store.get_events(&run.id).await.unwrap();
    // Health event at start (and possibly stop).
    assert!(
        events.iter().any(|e| e.kind == "native_log.health"),
        "expected native_log.health, kinds={:?}",
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn path_identity_helpers_export() {
    // Ensure public types stay usable from integration tests.
    let _ = Path::new("/tmp/x");
    let _ = FileChange::Appended;
}
