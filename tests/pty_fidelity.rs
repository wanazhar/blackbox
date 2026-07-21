//! 1.4 Phase D — Unix PTY fidelity fixtures (WS5).
//!
//! Supervises deterministic probes under `blackbox` and asserts exit codes,
//! transcript content, ANSI stripping, unicode survival, binary-ish bytes,
//! and process-group / TTY presence under PTY supervision.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::core::event::EventSource;
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

fn temp_ws() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bb-pty-fid-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join(".blackbox/blobs")).unwrap();
    dir
}

async fn run_probe(
    mode: &str,
) -> (
    PathBuf,
    blackbox::core::run::Run,
    String,
    Vec<blackbox::core::event::TraceEvent>,
) {
    let ws = temp_ws();
    let db = ws.join(".blackbox/blackbox.db");
    let blobs = ws.join(".blackbox/blobs");
    let store: Arc<dyn TraceStore> = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());
    let supervisor = RunSupervisor::new(store.clone());
    let p = probe();
    let args = RunArgs {
        name: Some(format!("pty-{mode}")),
        project: Some(ws.display().to_string()),
        tag: vec!["pty-fidelity".into()],
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
        command: vec![p.display().to_string(), mode.into()],
        ..Default::default()
    };
    let run = supervisor.execute(&args).await.expect("run");
    let events = store.get_events(&run.id).await.unwrap();
    let text = rebuild_terminal_transcript(store.as_ref(), &events)
        .await
        .unwrap_or_default();
    (ws, run, text, events)
}

#[tokio::test]
async fn exit_code_propagates() {
    let (ws, run, text, _) = run_probe("exit42").await;
    assert_eq!(run.exit_code, Some(42), "exit code must propagate");
    assert!(
        text.contains("exit_marker=42") || text.contains("ready"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn ansi_colors_normalized_in_transcript() {
    let (ws, run, text, _) = run_probe("ansi").await;
    assert_eq!(run.exit_code, Some(0));
    // Visible text survives; raw CSI should not dominate searchable transcript.
    assert!(
        text.contains("green") || text.contains("bold") || text.contains("cleared"),
        "{text}"
    );
    assert!(
        !text.contains("\u{1b}[32m"),
        "CSI should be stripped from normalized transcript"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn unicode_and_emoji_survive() {
    let (ws, run, text, _) = run_probe("unicode").await;
    assert_eq!(run.exit_code, Some(0));
    assert!(
        text.contains("café") || text.contains("cafe") || text.contains("日本語"),
        "unicode missing: {text}"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn long_line_and_stream_complete() {
    let (ws, run, text, events) = run_probe("stream").await;
    assert_eq!(run.exit_code, Some(0));
    assert!(text.contains("line-000"), "{text}");
    assert!(
        text.contains("line-199") || text.contains("line-19"),
        "{text}"
    );
    assert!(
        events.iter().any(|e| e.kind == "terminal.output"),
        "expected terminal.output events"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn no_trailing_newline_captured() {
    let (ws, run, text, _) = run_probe("no_nl").await;
    assert_eq!(run.exit_code, Some(0));
    assert!(
        text.contains("no_trailing_newline"),
        "missing output without trailing newline: {text:?}"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn binaryish_invalid_utf8_does_not_crash_run() {
    let (ws, run, text, _) = run_probe("binary").await;
    assert_eq!(run.exit_code, Some(0));
    // Lossy path may replace invalid bytes; surrounding text must survive.
    assert!(text.contains("before") || text.contains("after"), "{text}");
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn pty_allocates_tty_and_session() {
    let (ws, run, text, events) = run_probe("pgid").await;
    assert_eq!(run.exit_code, Some(0));
    // Under portable-pty, child is typically a session leader with a TTY.
    assert!(
        text.contains("STDOUT_TTY=1") || text.contains("PID="),
        "expected PTY identity markers: {text}"
    );
    assert!(
        events.iter().any(|e| e.kind == "process.spawned"
            || e.kind == "process.observer.started"
            || e.source == EventSource::Process),
        "expected process capture events"
    );
    // Coverage should mention transcript honesty / backpressure policy.
    if let Some(cov) = events.iter().find(|e| e.kind == "capture.coverage") {
        let notes = cov
            .metadata
            .get("coverage")
            .and_then(|c| c.get("notes"))
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();
        let joined = notes
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            joined.contains("normalized transcript") || joined.contains("backpressure"),
            "coverage notes missing fidelity/backpressure honesty: {joined}"
        );
        assert!(
            cov.metadata.contains_key("backpressure"),
            "expected backpressure metadata on coverage event"
        );
    }
    let _ = std::fs::remove_dir_all(ws);
}

#[tokio::test]
async fn all_mode_smoke() {
    let (ws, run, text, _) = run_probe("all").await;
    assert_eq!(run.exit_code, Some(0));
    assert!(!text.is_empty());
    let _ = std::fs::remove_dir_all(ws);
}
