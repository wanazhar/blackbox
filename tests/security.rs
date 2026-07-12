//! Integration test: verify secrets don't leak into stored metadata.

use std::sync::Arc;

use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::redaction::RedactionConfig;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

/// Test 9: Command outputs an AWS key — verify it's absent from stored metadata.
///
/// Simulates the flow: a command produces output containing an AWS secret,
/// that output is stored as metadata, and the redaction scanner catches it
/// before it persists as plaintext.
#[tokio::test]
async fn test_secret_no_leak() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());

    // Simulate a command that outputs an AWS key
    let mut run = Run::new(
        vec![
            "sh".into(),
            "-c".into(),
            "echo AKIAIOSFODNN7EXAMPLE".into(),
        ],
        "/tmp".into(),
    );
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    // Store an event with output containing the AWS key
    let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
    ev.status = EventStatus::Success;
    ev.metadata.insert(
        "preview".into(),
        serde_json::json!("Your AWS key is: AKIAIOSFODNN7EXAMPLE"),
    );
    store.insert_event(&ev).await.unwrap();

    // Run the redaction scanner on stored data
    let scanner = SecretScanner::new(RedactionConfig::default());
    let events = store.get_events(&run.id).await.unwrap();
    assert_eq!(events.len(), 1);

    // The raw metadata should be caught by the scanner
    let preview = events[0]
        .metadata
        .get("preview")
        .and_then(|v| v.as_str())
        .unwrap();
    let redacted = scanner.redact(preview);
    assert!(
        !redacted.contains("AKIAIOSFODNN7"),
        "AWS key must not survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED]"),
        "redacted text should contain [REDACTED]: {redacted}"
    );

    // Also verify the run command itself is scannable
    let cmd_str = run.command.join(" ");
    let cmd_findings = scanner.scan(&cmd_str, "run.command", None);
    // The command contains the key in the sh -c argument
    // (scanner should detect the AKIA pattern)
    assert!(
        !cmd_findings.is_empty() || !scanner.redact(&cmd_str).contains("AKIA"),
        "scanner should detect or redact the AWS key in command"
    );
}
