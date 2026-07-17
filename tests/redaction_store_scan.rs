//! 1.4 S1 — Store-level secret scan after holdback stream redaction.
//!
//! Runs a supervised probe that emits a known non-live secret (including a
//! split-across-write form), then scans SQLite + WAL + blobs for recoverable
//! fragments. Structural IDs in the same stream must survive.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::store_scan::{scan_bytes, scan_store_paths};
use blackbox::redaction::RedactionConfig;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

fn temp_ws() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bb-store-scan-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join(".blackbox/blobs")).unwrap();
    dir
}

fn write_secret_probe(bin_dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("secret-probe.sh");
    // Non-live fixtures only. Print structural ID + secret in two writes.
    let script = r#"#!/bin/sh
# Structural survivor
echo "commit ea950d8180f520d808274579577db86bc6365a7a"
# Split secret across two flushes (simulates PTY chunking)
printf 'export KEY=sk-abcdefghijklmn'
printf 'opqrstuvwxyz012345\n'
# Full-line secret
echo 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12'
echo 'done'
"#;
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[tokio::test]
async fn holdback_run_leaves_no_secret_in_store_bytes() {
    let ws = temp_ws();
    let probe = write_secret_probe(&ws.join("bin"));
    let db = ws.join(".blackbox/blackbox.db");
    let blobs = ws.join(".blackbox/blobs");

    let store: Arc<dyn TraceStore> = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("store-scan".into()),
        project: Some(ws.display().to_string()),
        tag: vec!["security".into()],
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
        command: vec![probe.display().to_string()],
    };

    let run = supervisor.execute(&args).await.expect("run succeeds");
    assert_eq!(run.exit_code, Some(0));

    // Checkpoint SQLite so WAL content is in the main DB when possible.
    // Best-effort: open a connection via re-open.
    drop(store);
    let store2: Arc<dyn TraceStore> = Arc::new(SqliteStore::open_with_blobs(&db, &blobs).unwrap());
    let events = store2.get_events(&run.id).await.unwrap();
    assert!(
        events.iter().any(|e| e.kind == "terminal.output"),
        "expected terminal.output events"
    );

    // Transcript must not contain raw secrets; structural SHA must survive.
    let text = blackbox::transcript::rebuild_terminal_transcript(store2.as_ref(), &events)
        .await
        .unwrap();
    assert!(
        text.contains("ea950d8180f520d808274579577db86bc6365a7a"),
        "structural sha missing from transcript: {text}"
    );
    assert!(
        !text.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
        "openai key in transcript: {text}"
    );
    assert!(
        !text.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"),
        "github token in transcript: {text}"
    );
    assert!(
        text.contains("[REDACTED]") || !text.contains("sk-abcdef"),
        "expected redaction in transcript: {text}"
    );

    // Store-level byte scan (DB + WAL/SHM + blobs).
    let scanner = SecretScanner::new(RedactionConfig::default());
    // Drop store to release locks before reading files on some platforms.
    drop(store2);

    let findings = scan_store_paths(&scanner, &db, &blobs);
    // Filter: argv might still appear in redacted form; raw prefixes must not.
    let leaks: Vec<_> = findings
        .iter()
        .filter(|f| f.detail.contains("raw prefix") || f.detail.contains("scanner span match"))
        .collect();

    // Allow findings only if they are false positives on structural data —
    // scan_bytes already skips pure SHAs. Any hit is a failure for this test.
    assert!(
        leaks.is_empty(),
        "store-level secret fragments survived: {leaks:#?}"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn store_scan_detects_planted_secret_in_blob_file() {
    let dir = temp_ws();
    let blob = dir.join(".blackbox/blobs/planted");
    std::fs::write(&blob, b"planted sk-abcdefghijklmnopqrstuvwxyz012345 end").unwrap();
    let scanner = SecretScanner::new(RedactionConfig::default());
    let findings = scan_store_paths(
        &scanner,
        &dir.join(".blackbox/none.db"),
        &dir.join(".blackbox/blobs"),
    );
    assert!(!findings.is_empty(), "expected to detect planted secret");
    let hits = scan_bytes(&scanner, b"sk-abcdefghijklmnopqrstuvwxyz012345", "x");
    assert!(!hits.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
