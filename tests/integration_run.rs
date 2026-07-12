//! End-to-end capture against a fake harness binary.
//!
//! Spawns a script named `claude` that prints stream-json tool_use lines,
//! records it under blackbox, and asserts structured tool events land.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

fn temp_workspace() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bb-int-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_fake_claude(bin_dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("claude");
    // Minimal stream-json harness: tool call + session + exit
    let script = r#"#!/bin/sh
# Consume flags so -p / --output-format don't confuse us
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--print|--verbose|--output-format) shift; [ "$1" = "stream-json" ] || [ "$1" = "json" ] && shift || true ;;
    *) break ;;
  esac
done
echo '{"type":"system","session_id":"sess-integration-01"}'
echo '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tool-int-1","name":"Bash","input":{"command":"echo hello-from-fake-claude"}}]}}'
echo '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tool-int-1","content":"hello-from-fake-claude"}]}}'
echo 'done'
"#;
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[tokio::test]
async fn records_tool_events_from_fake_claude() {
    let ws = temp_workspace();
    let bin = ws.join("bin");
    let claude = write_fake_claude(&bin);
    let db = ws.join("test.db");
    let blobs = ws.join("blobs");

    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("integration-fake-claude".into()),
        project: Some(ws.to_string_lossy().into()),
        tag: vec!["integration".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        ci: false,
        artifact_dir: None,
        resume_injection: None,
        command: vec![claude.to_string_lossy().into(), "-p".into(), "hi".into()],
    };

    let run = supervisor.execute(&args).await.expect("run succeeds");
    assert_eq!(run.exit_code, Some(0));
    assert!(
        run.notes
            .as_deref()
            .unwrap_or("")
            .contains("adapter:claude"),
        "expected claude adapter, notes={:?}",
        run.notes
    );

    let events = store.get_events(&run.id).await.unwrap();
    assert!(!events.is_empty(), "expected captured events");

    let tool_calls: Vec<_> = events.iter().filter(|e| e.kind == "tool.call").collect();
    assert!(
        !tool_calls.is_empty(),
        "expected tool.call from stream-json; kinds={:?}",
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        tool_calls[0]
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str()),
        Some("Bash")
    );

    let results: Vec<_> = events.iter().filter(|e| e.kind == "tool.result").collect();
    assert!(!results.is_empty(), "expected tool.result");

    let sessions: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "harness.session")
        .collect();
    assert!(
        !sessions.is_empty() || run.notes.as_deref().unwrap_or("").contains("session:"),
        "expected session discovery"
    );

    // Terminal output should be coalesced (few events, not one per byte)
    let term_outs: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "terminal.output")
        .collect();
    assert!(
        !term_outs.is_empty() && term_outs.len() < 50,
        "unexpected terminal.output count {}",
        term_outs.len()
    );

    // Secrets: no raw key field
    for ev in &events {
        assert!(
            !ev.metadata.contains_key("raw"),
            "raw terminal text must not be stored in metadata"
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn redacts_secret_in_command_argv() {
    let ws = temp_workspace();
    let db = ws.join("test.db");
    let blobs = ws.join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("secret-argv".into()),
        project: Some(ws.to_string_lossy().into()),
        tag: vec![],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        ci: false,
        artifact_dir: None,
        resume_injection: None,
        command: vec![
            "sh".into(),
            "-c".into(),
            "echo sk-abcdefghijklmnopqrstuvwxyz0123456789".into(),
        ],
    };

    let run = supervisor.execute(&args).await.unwrap();
    assert!(!run.command.join(" ").contains("sk-abcdef"));
    assert!(
        run.command.join(" ").contains("[REDACTED]")
            || run.command.iter().any(|c| c.contains("[REDACTED]"))
    );

    let events = store.get_events(&run.id).await.unwrap();
    for ev in events {
        let blob = format!("{:?}", ev.metadata);
        assert!(
            !blob.contains("sk-abcdefghijklmnop"),
            "secret leaked in metadata: {blob}"
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn tags_persist_on_run() {
    let ws = temp_workspace();
    let db = ws.join("test.db");
    let blobs = ws.join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("tagged".into()),
        project: Some(ws.to_string_lossy().into()),
        tag: vec!["alpha".into(), "beta".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        ci: false,
        artifact_dir: None,
        resume_injection: None,
        command: vec!["true".into()],
    };
    let run = supervisor.execute(&args).await.unwrap();
    let loaded = store.get_run(&run.id).await.unwrap().unwrap();
    assert!(loaded.tags.contains(&"alpha".into()));
    assert!(loaded.tags.contains(&"beta".into()));

    let mut updated = loaded;
    updated.tags.retain(|t| t != "beta");
    updated.tags.push("gamma".into());
    store.update_run(&updated).await.unwrap();
    let again = store.get_run(&run.id).await.unwrap().unwrap();
    assert!(again.tags.contains(&"alpha".into()));
    assert!(again.tags.contains(&"gamma".into()));
    assert!(!again.tags.contains(&"beta".into()));

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn portable_export_import_round_trip() {
    use blackbox::export::export_run;
    use blackbox::export::portable::import_portable;

    let ws = temp_workspace();
    let db = ws.join("test.db");
    let blobs = ws.join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("portable-src".into()),
        project: Some(ws.to_string_lossy().into()),
        tag: vec!["orig".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        ci: false,
        artifact_dir: None,
        resume_injection: None,
        command: vec!["sh".into(), "-c".into(), "echo portable-payload".into()],
    };
    let run = supervisor.execute(&args).await.unwrap();
    let events = store.get_events(&run.id).await.unwrap();
    let portable = export_run(store.as_ref(), &run, &events, "portable", true)
        .await
        .unwrap();
    assert!(
        portable.contains("\"version\": 2") || portable.contains("\"version\":2"),
        "expected portable v2"
    );

    let imported = import_portable(store.as_ref(), &portable, true)
        .await
        .unwrap();
    assert_ne!(imported.run_id, run.id);
    let loaded = store.get_run(&imported.run_id).await.unwrap().unwrap();
    assert!(loaded.tags.contains(&"imported".into()));
    assert!(!store.get_events(&imported.run_id).await.unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn export_jsonl_transcript_and_delete_run() {
    use blackbox::export::export_run;

    let ws = temp_workspace();
    let db = ws.join("test.db");
    let blobs = ws.join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some("export-me".into()),
        project: Some(ws.to_string_lossy().into()),
        tag: vec![],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        ci: false,
        artifact_dir: None,
        resume_injection: None,
        command: vec!["sh".into(), "-c".into(), "echo export-ok".into()],
    };
    let run = supervisor.execute(&args).await.unwrap();
    let events = store.get_events(&run.id).await.unwrap();

    let jsonl = export_run(store.as_ref(), &run, &events, "jsonl", true)
        .await
        .unwrap();
    assert!(jsonl.contains("export-me") || jsonl.contains(&run.id));
    assert!(jsonl.lines().count() >= 2);

    let text = blackbox::transcript::rebuild_terminal_transcript(store.as_ref(), &events)
        .await
        .unwrap();
    assert!(
        text.contains("export-ok") || events.iter().any(|e| e.kind == "terminal.output"),
        "expected terminal content, got {text:?}"
    );

    assert!(store.delete_run(&run.id).await.unwrap());
    assert!(store.get_run(&run.id).await.unwrap().is_none());
    assert!(store.get_events(&run.id).await.unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&ws);
}
