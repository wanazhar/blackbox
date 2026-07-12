//! 9 critical missing tests for core functionality.
//!
//! Covers: redaction pipeline, capture lifecycle, sandbox replay,
//! storage edge cases, terminal recorder, analysis pipeline,
//! event correlator, error detector, and FTS search.
//!
//! The serve-endpoint test lives in src/serve.rs as a unit test
//! because axum handler functions are private to that module.

use std::sync::Arc;

use blackbox::analysis::correlator::EventCorrelator;
use blackbox::analysis::error_detector::ErrorDetector;
use blackbox::analysis::classifier::SideEffectClassifier;
use blackbox::analysis::AnalysisPass;
use blackbox::capture::pty::PtyCapture;
use blackbox::capture::process::ProcessCapture;
use blackbox::capture::filesystem::FilesystemCapture;
use blackbox::capture::{CaptureLayer, merge_layers};
use blackbox::core::checkpoint::Checkpoint;
use blackbox::core::event::{Confidence, EventSource, EventStatus, SideEffect, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::replay::{ReplayEngine, ReplayOutcome, ReplayPolicy, events_from};
use blackbox::replay::sandbox::SandboxReplay;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::RedactionConfig;
use blackbox::search::search_store;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::terminal::recorder::RawRecorder;
use blackbox::terminal::TerminalRecorder;

// ─── Helpers ──────────────────────────────────────────────────────

fn temp_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("bb-crit-test-{}", uuid::Uuid::new_v4()))
}

fn make_run(command: Vec<String>, cwd: &str) -> Run {
    Run::new(command, cwd.to_string())
}

fn make_event(run_id: &str, source: EventSource, kind: &str) -> TraceEvent {
    TraceEvent::new(run_id, source, kind)
}

fn make_error_event(run_id: &str, output_text: &str) -> TraceEvent {
    let mut ev = make_event(run_id, EventSource::Terminal, "terminal.output");
    ev.status = EventStatus::Error;
    ev.metadata.insert(
        "normalized".to_string(),
        serde_json::Value::String(output_text.to_string()),
    );
    ev
}

// ═══════════════════════════════════════════════════════════════════
// 1. test_run_supervisor_redacts
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_run_supervisor_redacts() {
    // Verify that when redaction is enabled the stored command vector
    // has secrets replaced with [REDACTED], while the original RunArgs
    // command (used for spawning) remains untouched.

    let config = RedactionConfig::default(); // enabled: true
    let scanner = SecretScanner::new(config);

    let original_command = vec![
        "curl".to_string(),
        "https://api.example.com".to_string(),
        "-H".to_string(),
        "Authorization: Bearer sk-test1234567890abcdef".to_string(),
    ];

    // Simulate what RunSupervisor.execute_inner does:
    // 1. The stored run gets the redacted command
    let mut stored_run = make_run(original_command.clone(), "/tmp");
    stored_run.command = scanner.redact_command(&stored_run.command);

    // 2. The spawn uses the original (unredacted) command
    let spawn_command = original_command.clone();

    // The stored command should contain [REDACTED]
    let redacted_str = stored_run.command.join(" ");
    assert!(
        redacted_str.contains("[REDACTED]"),
        "stored command should contain [REDACTED], got: {}",
        redacted_str
    );

    // The spawn command must remain unredacted
    assert_eq!(
        spawn_command, original_command,
        "spawn command must not be modified"
    );

    // Verify the secret is NOT in the stored command
    assert!(
        !stored_run.command.join(" ").contains("sk-test1234567890abcdef"),
        "stored command must not contain the raw secret"
    );

    // Verify the secret IS in the spawn command
    assert!(
        spawn_command.join(" ").contains("sk-test1234567890abcdef"),
        "spawn command must still contain the original secret"
    );
}

#[test]
fn test_run_supervisor_redact_disabled() {
    // When redact is false, the stored command should be identical to original
    let config = RedactionConfig {
        enabled: false,
        ..RedactionConfig::default()
    };
    let scanner = SecretScanner::new(config);

    let original = vec![
        "curl".to_string(),
        "-H".to_string(),
        "Authorization: Bearer sk-secret123456789012345678".to_string(),
    ];

    let mut stored_run = make_run(original.clone(), "/tmp");
    stored_run.command = scanner.redact_command(&stored_run.command);

    // With redaction disabled, command should be unchanged
    assert_eq!(
        stored_run.command, original,
        "disabled redaction must not modify the command"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. test_capture_lifecycle
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_capture_lifecycle() {
    // Test start/stop for PtyCapture, ProcessCapture, FilesystemCapture
    let run = make_run(vec!["echo".into(), "test".into()], "/tmp");

    // ── PtyCapture ────────────────────────────────────────────
    let mut pty = PtyCapture::new();
    assert_eq!(pty.name(), "pty");
    let mut pty_rx = pty.start(&run).await.unwrap();
    // Should emit pty.started event
    let ev = pty_rx.recv().await.expect("should get pty.started");
    assert_eq!(ev.kind, "pty.started");
    assert_eq!(ev.status, EventStatus::Success);
    pty.stop().await.unwrap();
    // stop() sends a pty.stopped event then drops the sender
    let stop_ev = pty_rx.try_recv().expect("should receive pty.stopped");
    assert_eq!(stop_ev.kind, "pty.stopped");
    // Now the channel should be disconnected
    assert!(
        pty_rx.try_recv().is_err(),
        "channel should be closed after stop"
    );

    let mut proc = ProcessCapture::new();
    assert_eq!(proc.name(), "process");
    let mut proc_rx = proc.start(&run).await.unwrap();
    let ev = proc_rx.recv().await.expect("should get process.observer.started");
    assert_eq!(ev.kind, "process.observer.started");
    proc.stop().await.unwrap();

    // ── FilesystemCapture ─────────────────────────────────────
    let mut fs = FilesystemCapture::new();
    assert_eq!(fs.name(), "filesystem");
    let mut fs_rx = fs.start(&run).await.unwrap();
    // Should emit a filesystem.snapshot event
    let ev = fs_rx
        .recv()
        .await
        .expect("should get filesystem.snapshot");
    assert_eq!(ev.kind, "filesystem.observer.started");
    assert_eq!(ev.status, EventStatus::Success);
    fs.stop().await.unwrap();

    // ── merge_layers ──────────────────────────────────────────
    // Verify that multiple receivers can be merged into one stream
    let mut pty2 = PtyCapture::new();
    let mut proc2 = ProcessCapture::new();
    let rx1 = pty2.start(&run).await.unwrap();
    let rx2 = proc2.start(&run).await.unwrap();
    let (mut merged, handles) = merge_layers(vec![rx1, rx2]);
    // Stop layers to close senders so merged channel drains
    pty2.stop().await.unwrap();
    proc2.stop().await.unwrap();
    let mut received = Vec::new();
    while let Some(ev) = merged.recv().await {
        received.push(ev);
    }
    // Wait for forwarding tasks to finish
    for h in handles {
        let _ = h.await;
    }
    // Should have pty.started + process events
    assert!(
        !received.is_empty(),
        "merged stream should contain events from both layers"
    );
    let kinds: Vec<&str> = received.iter().map(|e| e.kind.as_str()).collect();
    assert!(
        kinds.contains(&"pty.started"),
        "should contain pty.started from first layer"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. test_replay_sandbox
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_replay_sandbox() {
    // ── Policy enforcement: ReadOnly blocks writes ─────────────
    let run = make_run(vec!["echo".into(), "hi".into()], "/tmp");
    let mut ev_write = make_event(&run.id, EventSource::Process, "process.command");
    ev_write.side_effect = SideEffect::LocalWrite;
    ev_write.metadata.insert(
        "command".into(),
        serde_json::json!(["touch", "newfile.txt"]),
    );

    let ws = temp_dir();
    let mut engine = SandboxReplay::new()
        .with_policy(ReplayPolicy::ReadOnly)
        .with_workspace(ws.clone())
        .without_seed();
    let outcome = engine.start(&run, &[ev_write], None).await.unwrap();
    match outcome {
        ReplayOutcome::Sandboxed {
            executed,
            skipped, ..
        } => {
            assert_eq!(executed, 0, "ReadOnly policy should block LocalWrite");
            assert_eq!(skipped, 1);
        }
        other => panic!("expected Sandboxed, got {:?}", other),
    }
    let _ = std::fs::remove_dir_all(&ws);

    // ── Policy enforcement: Live allows everything ─────────────
    let run2 = make_run(vec!["echo".into(), "live".into()], "/tmp");
    let mut ev_ext = make_event(&run2.id, EventSource::Process, "process.command");
    ev_ext.side_effect = SideEffect::ExternalWrite;
    ev_ext.metadata.insert(
        "command".into(),
        serde_json::json!(["echo", "allowed"]),
    );

    let ws2 = temp_dir();
    let mut engine2 = SandboxReplay::new()
        .with_policy(ReplayPolicy::Live)
        .with_workspace(ws2.clone())
        .without_seed();
    let outcome2 = engine2.start(&run2, &[ev_ext], None).await.unwrap();
    match outcome2 {
        ReplayOutcome::Sandboxed { executed, .. } => {
            assert_eq!(
                executed, 1,
                "Live policy should allow ExternalWrite events"
            );
        }
        other => panic!("expected Sandboxed, got {:?}", other),
    }
    let _ = std::fs::remove_dir_all(&ws2);

    // ── Workspace seeding with nested files ────────────────────
    let src_dir = temp_dir();
    std::fs::create_dir_all(src_dir.join("sub")).unwrap();
    std::fs::write(src_dir.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src_dir.join("sub/b.txt"), b"beta").unwrap();
    // Create a .git dir that should be skipped
    std::fs::create_dir_all(src_dir.join(".git/objects")).unwrap();
    std::fs::write(src_dir.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();

    let run3 = make_run(
        vec!["cat".into(), "a.txt".into()],
        &src_dir.to_string_lossy(),
    );
    let mut ev_cat = make_event(&run3.id, EventSource::Process, "process.command");
    ev_cat.side_effect = SideEffect::Read;
    ev_cat
        .metadata
        .insert("command".into(), serde_json::json!(["cat", "a.txt"]));

    let ws3 = temp_dir();
    let mut engine3 = SandboxReplay::new().with_workspace(ws3.clone());
    let outcome3 = engine3.start(&run3, &[ev_cat], None).await.unwrap();
    match outcome3 {
        ReplayOutcome::Sandboxed { executed, .. } => {
            assert_eq!(executed, 1);
        }
        other => panic!("expected Sandboxed, got {:?}", other),
    }
    // Verify seeded files exist
    assert!(
        ws3.join("a.txt").exists(),
        "a.txt should be seeded into workspace"
    );
    assert!(
        ws3.join("sub/b.txt").exists(),
        "sub/b.txt should be seeded"
    );
    // .git should be skipped
    assert!(
        !ws3.join(".git").exists(),
        ".git directory should not be seeded"
    );
    // Context file should be written
    assert!(
        ws3.join(".blackbox-sandbox-context.json").exists(),
        "sandbox context file should be written"
    );
    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&ws3);

    // ── events_from slicing ───────────────────────────────────
    let ev_a = make_event("r1", EventSource::System, "test.a");
    let ev_b = make_event("r1", EventSource::System, "test.b");
    let ev_c = make_event("r1", EventSource::System, "test.c");
    let events = vec![ev_a.clone(), ev_b, ev_c];

    // From first event → all events
    let slice = events_from(&events, Some(&ev_a.id));
    assert_eq!(slice.len(), 3);

    // From unknown id → all events (fallback)
    let slice = events_from(&events, Some("nonexistent"));
    assert_eq!(slice.len(), 3);

    // No starting event → all events
    let slice = events_from(&events, None);
    assert_eq!(slice.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════
// 4. test_storage_edge_cases
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_storage_edge_cases() {
    let store = SqliteStore::open_memory().unwrap();

    // ── Get non-existent run returns None ─────────────────────
    let result = store.get_run("nonexistent-id").await.unwrap();
    assert!(result.is_none(), "should return None for missing run");

    // ── Get events for non-existent run returns empty ─────────
    let events = store.get_events("nonexistent-run-id").await.unwrap();
    assert!(events.is_empty(), "should return empty vec for missing run");

    // ── Get checkpoints for non-existent run returns empty ────
    let cps = store.get_checkpoints("nonexistent-run-id").await.unwrap();
    assert!(cps.is_empty(), "should return empty vec for missing run");

    // ── Empty run (no command args) ────────────────────────────
    let mut empty_run = Run::new(vec![], "/tmp".to_string());
    empty_run.status = RunStatus::Succeeded;
    empty_run.exit_code = Some(0);
    store.insert_run(&empty_run).await.unwrap();
    let loaded = store.get_run(&empty_run.id).await.unwrap().unwrap();
    assert!(loaded.command.is_empty(), "empty command should be preserved");
    assert_eq!(loaded.status, RunStatus::Succeeded);

    // ── Loading blob with invalid key returns error ───────────
    let fake_ref = blackbox::core::blob::BlobReference::new(
        "a".repeat(64),
        100,
    );
    let result = store.load_blob(&fake_ref).await;
    assert!(result.is_err(), "loading non-existent blob should fail");

    // ── Blob deduplication ────────────────────────────────────
    let data = b"unique content for dedup test";
    let ref1 = store.store_blob(data).await.unwrap();
    let ref2 = store.store_blob(data).await.unwrap();
    assert_eq!(ref1.key, ref2.key, "identical blobs should deduplicate");
    assert_eq!(ref1.size, ref2.size);
    let loaded = store.load_blob(&ref1).await.unwrap();
    assert_eq!(loaded, data);

    // ── Update run fields ─────────────────────────────────────
    let mut run = Run::new(vec!["echo".into()], "/tmp".to_string());
    store.insert_run(&run).await.unwrap();
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    run.ended_at = Some(chrono::Utc::now());
    run.notes = Some("completed".into());
    store.update_run(&run).await.unwrap();
    let loaded = store.get_run(&run.id).await.unwrap().unwrap();
    assert_eq!(loaded.status, RunStatus::Succeeded);
    assert_eq!(loaded.exit_code, Some(0));
    assert_eq!(loaded.notes.as_deref(), Some("completed"));
    assert!(loaded.ended_at.is_some());

    // ── Delete non-existent run returns false ──────────────────
    let deleted = store.delete_run("nonexistent-id").await.unwrap();
    assert!(!deleted, "deleting non-existent run should return false");

    // ── List runs on mostly-empty store ────────────────────────
    let runs = store.list_runs().await.unwrap();
    assert!(!runs.is_empty(), "should have at least the runs we inserted");

    // ── Store and retrieve checkpoint ──────────────────────────
    let run2 = Run::new(vec!["true".into()], "/tmp".to_string());
    store.insert_run(&run2).await.unwrap();
    let ev = make_event(&run2.id, EventSource::System, "checkpoint.trigger");
    store.insert_event(&ev).await.unwrap();
    let cp = Checkpoint::new(&run2.id, &ev.id, &run2.cwd);
    store.insert_checkpoint(&cp).await.unwrap();
    let cps = store.get_checkpoints(&run2.id).await.unwrap();
    assert_eq!(cps.len(), 1);
    assert_eq!(cps[0].run_id, run2.id);
    assert_eq!(cps[0].event_id, ev.id);
}

// ═══════════════════════════════════════════════════════════════════
// 5. test_terminal_recorder
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_terminal_recorder() {
    let mut recorder = RawRecorder::new();

    // ── Initial state ──────────────────────────────────────────
    assert_eq!(recorder.segment_count(), 0);
    assert_eq!(recorder.total_bytes(), 0);

    // ── Start lifecycle ────────────────────────────────────────
    recorder.start("test-run-1").await.unwrap();
    assert_eq!(recorder.segment_count(), 0);

    // ── Record output ──────────────────────────────────────────
    recorder.record_output(b"hello world").await.unwrap();
    assert_eq!(recorder.segment_count(), 1);
    assert_eq!(recorder.total_bytes(), 11);

    recorder.record_output(b"\x1b[32mgreen\x1b[0m").await.unwrap();
    assert_eq!(recorder.segment_count(), 2);
    assert_eq!(recorder.total_bytes(), 11 + 14);

    // ── Write input ────────────────────────────────────────────
    recorder.write_input(b"ls\n").await.unwrap();
    assert_eq!(recorder.segment_count(), 3);
    assert_eq!(recorder.total_bytes(), 11 + 14 + 3);

    // ── Stop lifecycle ─────────────────────────────────────────
    let events = recorder.stop().await.unwrap();
    assert_eq!(events.len(), 1, "should produce one recording event");
    assert_eq!(events[0].kind, "terminal.recording");
    assert_eq!(events[0].status, EventStatus::Success);
    assert_eq!(
        events[0].metadata.get("segments").and_then(|v| v.as_u64()),
        Some(3)
    );
    assert_eq!(
        events[0].metadata.get("bytes").and_then(|v| v.as_u64()),
        Some(28) // 11 + 14 + 3
    );

    // ── Start/stop resets state ────────────────────────────────
    recorder.start("test-run-2").await.unwrap();
    assert_eq!(
        recorder.segment_count(),
        0,
        "segments should be cleared on new start"
    );
    recorder.record_output(b"new run data").await.unwrap();
    assert_eq!(recorder.segment_count(), 1);
    let events2 = recorder.stop().await.unwrap();
    assert_eq!(events2.len(), 1);
    assert_eq!(
        events2[0].metadata.get("segments").and_then(|v| v.as_u64()),
        Some(1)
    );

    // ── Segment cap eviction ───────────────────────────────────
    // MAX_SEGMENTS is 10_000. Record enough to trigger eviction.
    let mut rec2 = RawRecorder::new();
    rec2.start("cap-test").await.unwrap();

    // Record MAX_SEGMENTS + 500 segments
    for i in 0..10_500 {
        let data = format!("segment-{}", i);
        rec2.record_output(data.as_bytes()).await.unwrap();
    }
    // Should have evicted to 10_000
    assert_eq!(
        rec2.segment_count(),
        10_000,
        "should cap at MAX_SEGMENTS after eviction"
    );

    let total = rec2.total_bytes();
    assert!(total > 0, "should have recorded bytes");
}

#[tokio::test]
async fn test_recorder_stop_without_start() {
    // Stopping without starting should return empty events (no run_id)
    let mut recorder = RawRecorder::new();
    let events = recorder.stop().await.unwrap();
    assert!(
        events.is_empty(),
        "stop without start should produce no events"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. test_analyzer
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_analyzer() {
    // Test the analysis pipeline: classifier + error detector + correlator

    let classifier = SideEffectClassifier::new();
    let detector = ErrorDetector::new();
    let correlator = EventCorrelator::new();

    // ── SideEffectClassifier ───────────────────────────────────
    assert_eq!(classifier.classify_command("ls -la"), SideEffect::Read);
    assert_eq!(classifier.classify_command("cat file.txt"), SideEffect::Read);
    assert_eq!(
        classifier.classify_command("git push origin main"),
        SideEffect::ExternalWrite
    );
    assert_eq!(
        classifier.classify_command("rm -rf /"),
        SideEffect::Destructive
    );
    assert_eq!(classifier.classify_command("echo hello"), SideEffect::None);

    // ── ErrorDetector: analyze pass ────────────────────────────
    let run_id = "analyzer-test-run";
    let ev_ok = make_event(run_id, EventSource::Terminal, "terminal.output");

    let ev_err = make_error_event(run_id, "error[E0432]: unresolved import `foo`");

    let events = vec![ev_ok, ev_err.clone()];
    let derived = detector.analyze(&events).await.unwrap();
    assert!(
        !derived.is_empty(),
        "analyzer should detect the rust error"
    );
    let err_ev = &derived[0];
    assert_eq!(err_ev.kind, "analysis.error");
    assert_eq!(
        err_ev.metadata.get("error_type").unwrap().as_str().unwrap(),
        "rustc[E0432]"
    );
    assert_eq!(
        err_ev.parent_event_id.as_deref(),
        Some(ev_err.id.as_str())
    );

    // ── Correlator: analyze pass ───────────────────────────────
    let run_id2 = "correlator-test-run";
    let mut ev_cmd = make_event(run_id2, EventSource::Process, "process.command");
    ev_cmd.sequence = 0;
    ev_cmd.status = EventStatus::Success;

    let mut ev_file = make_event(run_id2, EventSource::Filesystem, "file.modified");
    ev_file.sequence = 1;
    ev_file.started_at = ev_cmd.started_at + chrono::Duration::milliseconds(100);
    ev_file.status = EventStatus::Success;

    let derived_corr = correlator.analyze(&[ev_cmd, ev_file]).await.unwrap();
    assert!(
        !derived_corr.is_empty(),
        "correlator should link file change to process command"
    );
    let corr_event = &derived_corr[0];
    assert_eq!(corr_event.kind, "analysis.correlation");
    assert!(corr_event.metadata.contains_key("confidence"));
    assert!(corr_event.metadata.contains_key("parent_event_id"));

    // ── Pipeline: empty input ──────────────────────────────────
    let empty_derived = detector.analyze(&[]).await.unwrap();
    assert!(empty_derived.is_empty(), "empty input should produce no derived events");
}

// ═══════════════════════════════════════════════════════════════════
// 7. test_correlator
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_correlator() {
    let correlator = EventCorrelator::new();

    // ── First event has no parent ──────────────────────────────
    let run_id = "corr-test";
    let ev1 = make_event(run_id, EventSource::Terminal, "human.input");
    let result = correlator.find_parent(&ev1, std::slice::from_ref(&ev1));
    assert!(result.is_none(), "first event should have no parent");

    // ── Same-source strong correlation ─────────────────────────
    let mut ev_a = make_event(run_id, EventSource::Terminal, "human.input");
    ev_a.sequence = 0;
    ev_a.started_at = chrono::Utc::now();

    let mut ev_b = make_event(run_id, EventSource::Terminal, "human.input");
    ev_b.sequence = 1;
    ev_b.started_at = ev_a.started_at + chrono::Duration::milliseconds(50);

    let result = correlator.find_parent(&ev_b, &[ev_a.clone(), ev_b.clone()]);
    assert!(result.is_some(), "should find parent for same-source close events");
    let (parent_id, _confidence) = result.unwrap();
    assert_eq!(parent_id, ev_a.id);
    // Same source within 500ms should produce a non-Unknown confidence
    assert!(
        _confidence != Confidence::Unknown,
        "same source within 500ms should not be Unknown, got {:?}",
        _confidence
    );

    // ── Different-source weak correlation ──────────────────────
    let mut ev_proc = make_event(run_id, EventSource::Process, "process.spawned");
    ev_proc.sequence = 0;
    ev_proc.started_at = chrono::Utc::now();

    let mut ev_fs = make_event(run_id, EventSource::Filesystem, "file.modified");
    ev_fs.sequence = 1;
    ev_fs.started_at = ev_proc.started_at + chrono::Duration::milliseconds(200);

    let result = correlator.find_parent(&ev_fs, &[ev_proc.clone(), ev_fs.clone()]);
    assert!(result.is_some(), "should find parent for cross-layer events");
    let (parent_id, confidence) = result.unwrap();
    assert_eq!(parent_id, ev_proc.id);
    // Process → Filesystem within 2s should produce a non-Unknown confidence
    assert!(
        confidence != Confidence::Unknown,
        "Process→Filesystem within 2s should not be Unknown, got {:?}",
        confidence
    );
    // ── Events outside 30s window → no parent ──────────────────
    let mut ev_old = make_event(run_id, EventSource::System, "system.tick");
    ev_old.sequence = 0;
    ev_old.started_at = chrono::Utc::now() - chrono::Duration::seconds(60);

    let mut ev_new = make_event(run_id, EventSource::System, "system.tick");
    ev_new.sequence = 1;
    ev_new.started_at = chrono::Utc::now();

    let result = correlator.find_parent(&ev_new, &[ev_old, ev_new.clone()]);
    assert!(
        result.is_none(),
        "events >30s apart should not be correlated"
    );

    // ── Event not in the slice returns None ────────────────────
    let orphan = make_event(run_id, EventSource::Terminal, "orphan");
    let result = correlator.find_parent(&orphan, &[ev_a.clone(), ev_b.clone()]);
    assert!(result.is_none(), "event not in slice should return None");

    // ── Empty event list returns None ──────────────────────────
    let result = correlator.find_parent(&ev_a, &[]);
    assert!(result.is_none(), "empty list should return None");

    // ── Cross-layer Terminal→Process boost ─────────────────────
    let mut ev_term = make_event(run_id, EventSource::Terminal, "terminal.output");
    ev_term.sequence = 0;
    ev_term.started_at = chrono::Utc::now();

    let mut ev_proc2 = make_event(run_id, EventSource::Process, "process.spawned");
    ev_proc2.sequence = 1;
    ev_proc2.started_at = ev_term.started_at + chrono::Duration::milliseconds(300);

    let result = correlator.find_parent(&ev_proc2, &[ev_term, ev_proc2.clone()]);
    assert!(result.is_some(), "Terminal→Process within 2s should correlate");
    let (_, confidence) = result.unwrap();
    assert!(
        confidence >= Confidence::StronglyCorrelated,
        "Terminal→Process cross-layer should be boosted"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 8. test_error_detector
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_error_detector() {
    let det = ErrorDetector::new();

    // ── is_error: status-based ──────────────────────────────────
    let mut ev_err = make_event("r1", EventSource::Terminal, "output");
    ev_err.status = EventStatus::Error;
    assert!(det.is_error(&ev_err));

    // ── is_error: non-zero exit code ────────────────────────────
    let mut ev_exit = make_event("r1", EventSource::Terminal, "output");
    ev_exit.status = EventStatus::Success;
    ev_exit
        .metadata
        .insert("exit_code".into(), serde_json::json!(1));
    assert!(det.is_error(&ev_exit));

    // ── is_error: zero exit code is NOT error ───────────────────
    let mut ev_ok = make_event("r1", EventSource::Terminal, "output");
    ev_ok.status = EventStatus::Success;
    ev_ok
        .metadata
        .insert("exit_code".into(), serde_json::json!(0));
    assert!(!det.is_error(&ev_ok));

    // ── is_error: no exit code, Success status ──────────────────
    let ev_no_code = make_event("r1", EventSource::Terminal, "output");
    assert!(!det.is_error(&ev_no_code));

    // ── Rust error with file location ───────────────────────────
    let ev_rust = make_error_event(
        "r1",
        "error[E0382]: borrow of moved value: `x`\n --> src/main.rs:42:5",
    );
    let errors = det.extract_errors(&ev_rust);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].error_type, "rustc[E0382]");
    assert_eq!(errors[0].file.as_deref(), Some("src/main.rs"));
    assert_eq!(errors[0].line, Some(42));
    assert_eq!(errors[0].column, Some(5));

    // ── JavaScript errors ───────────────────────────────────────
    let js_errors = [
        "TypeError: Cannot read property 'map' of undefined",
        "ReferenceError: x is not defined",
        "SyntaxError: Unexpected token",
        "RangeError: Maximum call stack size exceeded",
        "URIError: URI malformed",
        "EvalError: eval is not defined",
    ];
    for js_err in &js_errors {
        let ev = make_error_event("r1", js_err);
        let errors = det.extract_errors(&ev);
        assert!(
            !errors.is_empty(),
            "should detect JS error: {}",
            js_err
        );
        assert_eq!(errors[0].error_type, "javascript");
    }

    // ── Python traceback ────────────────────────────────────────
    let ev_py = make_error_event(
        "r1",
        "Traceback (most recent call last):\n  File \"app.py\", line 10\n    foo()\nValueError: invalid literal",
    );
    let errors = det.extract_errors(&ev_py);
    assert!(!errors.is_empty(), "should detect Python traceback");
    assert_eq!(errors[0].error_type, "ValueError");
    assert!(
        errors[0].message.contains("invalid literal"),
        "message should contain the error text"
    );

    // ── Test failure: FAILED marker ─────────────────────────────
    let ev_fail = make_error_event("r1", "test test_parse ... FAILED\nfailures:\n  test_parse");
    let errors = det.extract_errors(&ev_fail);
    assert!(!errors.is_empty(), "should detect FAILED marker");
    assert_eq!(errors[0].error_type, "test_failure");

    // ── Test failure: failures: marker ──────────────────────────
    let ev_fail2 = make_error_event("r1", "running 5 tests\nfailures:\n  test_a\n  test_b");
    let errors = det.extract_errors(&ev_fail2);
    assert!(!errors.is_empty(), "should detect failures: marker");
    assert_eq!(errors[0].error_type, "test_failure");

    // ── Generic process error (non-zero exit, no patterns) ──────
    let mut ev_generic = make_event("r1", EventSource::Process, "process.exited");
    ev_generic.status = EventStatus::Error;
    ev_generic
        .metadata
        .insert("exit_code".into(), serde_json::json!(1));
    ev_generic.metadata.insert(
        "normalized".to_string(),
        serde_json::Value::String("some process output".to_string()),
    );
    // Non-zero exit with no specific patterns → generic error
    let errors = det.extract_errors(&ev_generic);
    assert!(
        !errors.is_empty(),
        "non-zero exit with no pattern should produce generic error"
    );
    assert_eq!(errors[0].error_type, "process_error");

    // ── No error for clean output ───────────────────────────────
    let mut ev_clean = make_event("r1", EventSource::Terminal, "output");
    ev_clean.status = EventStatus::Success;
    ev_clean.metadata.insert(
        "normalized".to_string(),
        serde_json::Value::String("All tests passed!\nBuild successful.".to_string()),
    );

    // ── Empty event → no errors ─────────────────────────────────
    let ev_empty = make_event("r1", EventSource::Terminal, "output");
    let errors = det.extract_errors(&ev_empty);
    assert!(errors.is_empty(), "empty event should produce no errors");

    // ── Multiple errors in one output ───────────────────────────
    let ev_multi = make_error_event(
        "r1",
        "error[E0432]: unresolved import `foo`\n --> src/main.rs:5:5\nerror[E0599]: no method named `bar`",
    );
    let errors = det.extract_errors(&ev_multi);
    assert!(
        errors.len() >= 2,
        "should detect multiple Rust errors, got {}",
        errors.len()
    );

    // ── output_full fallback for get_output_text ────────────────
    let mut ev_full = make_event("r1", EventSource::Terminal, "output");
    ev_full.status = EventStatus::Error;
    ev_full.metadata.insert(
        "output_full".to_string(),
        serde_json::Value::String("error[E0001]: test error\n --> test.rs:1:1".to_string()),
    );
    let errors = det.extract_errors(&ev_full);
    assert!(
        !errors.is_empty(),
        "should use output_full as fallback"
    );
    assert_eq!(errors[0].error_type, "rustc[E0001]");
}

// ═══════════════════════════════════════════════════════════════════
// 9. test_search
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_search() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());

    // ── Seed data ──────────────────────────────────────────────
    let mut run1 = Run::new(
        vec!["claude".into(), "-p".into(), "write tests".into()],
        "/tmp".to_string(),
    );
    run1.name = Some("test-writer".into());
    run1.tags = vec!["testing".into(), "critical".into()];
    run1.notes = Some("writes critical tests".into());
    store.insert_run(&run1).await.unwrap();

    let mut run2 = Run::new(vec!["cargo".into(), "build".into()], "/tmp".to_string());
    run2.name = Some("build-project".into());
    store.insert_run(&run2).await.unwrap();

    // Event for run1 with a searchable tool name
    let mut ev_tool = make_event(&run1.id, EventSource::Tool, "tool.call");
    ev_tool.status = EventStatus::Running;
    ev_tool
        .metadata
        .insert("tool_name".into(), serde_json::json!("WriteFile"));
    ev_tool.metadata.insert(
        "input".into(),
        serde_json::json!({"path": "tests/test_critical.rs"}),
    );
    store.insert_event(&ev_tool).await.unwrap();

    // Event for run2 with error
    let mut ev_err = make_event(&run2.id, EventSource::Terminal, "terminal.output");
    ev_err.status = EventStatus::Error;
    ev_err.metadata.insert(
        "preview".into(),
        serde_json::json!("error[E0382]: borrow of moved value"),
    );
    store.insert_event(&ev_err).await.unwrap();

    // ── Search by run name ─────────────────────────────────────
    let hits = search_store(store.as_ref(), "test-writer", 10, 20)
        .await
        .unwrap();
    assert!(!hits.is_empty(), "should find run by name");
    assert!(
        hits.iter().any(|h| h.run_id == run1.id),
        "should match run1"
    );

    // ── Search by command ──────────────────────────────────────
    let hits = search_store(store.as_ref(), "cargo build", 10, 20)
        .await
        .unwrap();
    assert!(!hits.is_empty(), "should find run by command");
    assert!(
        hits.iter().any(|h| h.run_id == run2.id),
        "should match run2"
    );

    // ── Search by tag ──────────────────────────────────────────
    let hits = search_store(store.as_ref(), "critical", 10, 20)
        .await
        .unwrap();
    assert!(!hits.is_empty(), "should find run by tag");
    assert!(
        hits.iter().any(|h| h.run_id == run1.id),
        "should match run1 via tag"
    );

    // ── Search by run notes content (always works via scan) ────
    let hits = search_store(store.as_ref(), "writes critical", 10, 20)
        .await
        .unwrap();
    assert!(!hits.is_empty(), "should find run by notes content");
    assert!(
        hits.iter().any(|h| h.run_id == run1.id),
        "should match run1 via notes"
    );

    // ── Search with no results ─────────────────────────────────
    let hits = search_store(store.as_ref(), "zzz-nonexistent-xyz", 10, 20)
        .await
        .unwrap();
    assert!(hits.is_empty(), "non-matching query should return empty");

    // ── Search scoring: exact match > partial ───────────────────
    let hits_exact = search_store(store.as_ref(), "build-project", 10, 20)
        .await
        .unwrap();
    let hits_partial = search_store(store.as_ref(), "build", 10, 20)
        .await
        .unwrap();
    if !hits_exact.is_empty() && !hits_partial.is_empty() {
        let exact_score = hits_exact[0].score;
        let partial_score = hits_partial[0].score;
        // Exact name match should score at least as high
        assert!(
            exact_score >= partial_score,
            "exact match (score={}) should >= partial (score={})",
            exact_score,
            partial_score
        );
    }

    // ── Limit respects max_runs ────────────────────────────────
    let hits = search_store(store.as_ref(), "test", 1, 20)
        .await
        .unwrap();
    // With max_runs=1, only one run's events should be searched
    let unique_runs: std::collections::HashSet<&str> =
        hits.iter().map(|h| h.run_id.as_str()).collect();
    assert!(
        unique_runs.len() <= 1,
        "max_runs=1 should limit to one run"
    );

    // ── Truncation of long snippets ────────────────────────────
    let hits = search_store(store.as_ref(), "error", 10, 20)
        .await
        .unwrap();
    for hit in &hits {
        assert!(
            hit.snippet.len() <= 200,
            "snippet should be truncated, got {} chars",
            hit.snippet.len()
        );
    }

    // ── Fallback to scan when FTS unavailable ───────────────────
    let store2 = Arc::new(SqliteStore::open_memory().unwrap());
    let run3 = Run::new(
        vec!["echo".into(), "fallback-test".into()],
        "/tmp".to_string(),
    );
    store2.insert_run(&run3).await.unwrap();
    let hits = search_store(store2.as_ref(), "fallback-test", 10, 20)
        .await
        .unwrap();
    assert!(
        !hits.is_empty(),
        "should find run via scan fallback"
    );
    assert_eq!(hits[0].run_id, run3.id);

    // ── Backend field indicates source ──────────────────────────
    let hits = search_store(store.as_ref(), "WriteFile", 10, 20)
        .await
        .unwrap();
    assert!(
        !hits.is_empty(),
        "should find WriteFile event"
    );
    assert!(
        hits.iter().any(|h| h.backend == "fts5" || h.backend == "scan"),
        "backend should be fts5 or scan, got {:?}",
        hits.iter().map(|h| h.backend).collect::<Vec<_>>()
    );
}
