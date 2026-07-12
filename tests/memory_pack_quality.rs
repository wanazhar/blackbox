//! M2a structural pack quality gate (blackbox 1.2).

use std::path::PathBuf;
use std::sync::Arc;

use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::memory::{
    build_project_memory, shrink_pack, write_memory_files, MemoryBuildOptions, ProjectMemoryPack,
};
use blackbox::state::{
    apply_run_outcome, with_state_lock, AttentionLevel, OutcomeExtras, ProjectState,
};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

async fn store_with_run(run: &Run) -> Arc<dyn TraceStore> {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    store.insert_run(run).await.unwrap();
    store
}

#[tokio::test]
async fn m2a_1_failed_bash_has_tools_and_budget() {
    let mut run = Run::new(
        vec!["claude".into(), "-p".into(), "fix".into()],
        "/tmp".into(),
    );
    run.status = RunStatus::Failed;
    run.exit_code = Some(1);
    let store = store_with_run(&run).await;

    let mut call = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    call.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    store.insert_event(&call).await.unwrap();

    let mut res = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    res.status = EventStatus::Error;
    res.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    res.metadata
        .insert("error".into(), serde_json::json!("bash: permission denied"));
    store.insert_event(&res).await.unwrap();

    let mut sticky = ProjectState::default();
    apply_run_outcome(&mut sticky, &run, OutcomeExtras::default());

    let pack = build_project_memory(
        Some(store.as_ref()),
        &sticky,
        MemoryBuildOptions {
            max_tokens: 4000,
            project_root: PathBuf::from("/tmp"),
            store_db: PathBuf::from("/tmp/db"),
            skip_porcelain_if_none: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(!pack.headline.is_empty());
    assert!(!pack.next_action.is_empty());
    assert!(pack.attention_level == "continue" || pack.attention_level == "blocked");
    assert!(!pack.failed_tools.is_empty());
    assert!(pack.approx_tokens <= 4000);
}

#[tokio::test]
async fn m2a_2_tiny_budget_keeps_failed_tools_drops_transcript() {
    let mut run = Run::new(vec!["claude".into()], "/tmp".into());
    run.status = RunStatus::Failed;
    run.exit_code = Some(1);
    let store = store_with_run(&run).await;

    let mut res = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    res.status = EventStatus::Error;
    res.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    res.metadata
        .insert("error".into(), serde_json::json!("boom"));
    store.insert_event(&res).await.unwrap();

    // Huge terminal transcript
    let mut term = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
    term.metadata
        .insert("preview".into(), serde_json::json!("X".repeat(20_000)));
    store.insert_event(&term).await.unwrap();

    let mut sticky = ProjectState::default();
    apply_run_outcome(&mut sticky, &run, OutcomeExtras::default());

    let pack = build_project_memory(
        Some(store.as_ref()),
        &sticky,
        MemoryBuildOptions {
            max_tokens: 500,
            project_root: PathBuf::from("/tmp"),
            store_db: PathBuf::from("/tmp/db"),
            skip_porcelain_if_none: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(!pack.failed_tools.is_empty());
    let tlen = pack.transcript_tail.as_ref().map(|t| t.len()).unwrap_or(0);
    assert!(tlen < 200 || pack.transcript_tail.is_none());
    assert!(pack.truncated);
}

#[tokio::test]
async fn m2a_3_success_wip_not_noop() {
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    let store = store_with_run(&run).await;

    let mut fs = TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.write");
    fs.metadata
        .insert("path".into(), serde_json::json!("src/foo.rs"));
    store.insert_event(&fs).await.unwrap();

    let mut sticky = ProjectState::default();
    apply_run_outcome(
        &mut sticky,
        &run,
        OutcomeExtras {
            files_touched_nonempty: true,
            git_dirty: true,
            ..Default::default()
        },
    );

    let pack = build_project_memory(
        Some(store.as_ref()),
        &sticky,
        MemoryBuildOptions {
            max_tokens: 4000,
            project_root: PathBuf::from("/tmp"),
            store_db: PathBuf::from("/tmp/db"),
            skip_porcelain_if_none: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_ne!(pack.attention_level, "none");
    assert!(
        !pack.files_touched.is_empty() || pack.git.dirty,
        "expected files or dirty"
    );
    assert!(!pack.next_action.contains("No failure attention required"));
}

#[tokio::test]
async fn m2a_4_clean_success_tiny_ok_pack() {
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    let store = store_with_run(&run).await;

    let mut sticky = ProjectState::default();
    apply_run_outcome(&mut sticky, &run, OutcomeExtras::default());
    assert_eq!(sticky.attention_level, AttentionLevel::None);

    let pack = build_project_memory(
        Some(store.as_ref()),
        &sticky,
        MemoryBuildOptions {
            max_tokens: 4000,
            project_root: PathBuf::from("/tmp"),
            store_db: PathBuf::from("/tmp/db"),
            skip_porcelain_if_none: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(!pack.headline.is_empty());
    assert!(pack.approx_tokens <= 400);
    assert!(pack.transcript_tail.is_none());
}

#[tokio::test]
async fn m2a_5_planted_secret_redacted_in_memory_json() {
    let secret = "sk-ant-api03-PLANTEDSECRETVALUE0000000000000000000000000";
    let mut run = Run::new(vec!["claude".into()], "/tmp".into());
    run.status = RunStatus::Failed;
    run.exit_code = Some(1);
    let store = store_with_run(&run).await;

    let mut res = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
    res.status = EventStatus::Error;
    res.metadata
        .insert("tool_name".into(), serde_json::json!("Bash"));
    res.metadata.insert(
        "error".into(),
        serde_json::json!(format!("failed with key {secret}")),
    );
    store.insert_event(&res).await.unwrap();

    let mut sticky = ProjectState::default();
    apply_run_outcome(&mut sticky, &run, OutcomeExtras::default());

    let pack = build_project_memory(
        Some(store.as_ref()),
        &sticky,
        MemoryBuildOptions {
            max_tokens: 4000,
            project_root: PathBuf::from("/tmp"),
            store_db: PathBuf::from("/tmp/db"),
            skip_porcelain_if_none: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".blackbox");
    std::fs::create_dir_all(&root).unwrap();
    write_memory_files(&root, &pack, true).unwrap();
    let json = std::fs::read_to_string(root.join("MEMORY.json")).unwrap();
    assert!(
        !json.contains(secret),
        "planted secret leaked into MEMORY.json"
    );
    // Structural IDs survive
    assert!(json.contains(&run.id) || json.contains(&run.id[..8]));
}

#[test]
fn m2a_6_shrink_order_transcript_before_headline() {
    let mut pack = ProjectMemoryPack {
        schema: "blackbox.memory/v1".into(),
        purpose: "test".into(),
        degraded: false,
        project_root: "/tmp".into(),
        store_db: "/tmp/db".into(),
        generated_at: chrono::Utc::now(),
        continuity_mode: "always".into(),
        headline: "HEADLINE_KEEP".into(),
        next_action: "NEXT_KEEP".into(),
        attention_reason: "failed".into(),
        attention_level: "continue".into(),
        intent: blackbox::memory::IntentView {
            goal: Some("g".into()),
            open_items: vec!["item".into()],
            ..Default::default()
        },
        claims: Default::default(),
        last_run: None,
        predecessor_run: None,
        focus_run_id: None,
        files_touched: vec![],
        destructive_paths: vec![],
        side_effects_top: vec![],
        secret_redaction_events: 0,
        git: Default::default(),
        failed_tools: vec![blackbox::context::FailedTool {
            sequence: 1,
            name: "Bash".into(),
            detail: "err".into(),
        }],
        errors_top: vec![],
        summary: None,
        last_tools: vec!["t".into(); 25],
        transcript_tail: Some("T".repeat(8000)),
        resume_command: None,
        approx_tokens: 0,
        truncated: false,
        build_ms: 0,
    };
    shrink_pack(&mut pack, 180);
    assert_eq!(pack.headline, "HEADLINE_KEEP");
    assert_eq!(pack.next_action, "NEXT_KEEP");
    assert!(!pack.failed_tools.is_empty());
    assert!(pack.intent.goal.is_some());
    assert!(pack.transcript_tail.is_none() || pack.transcript_tail.as_ref().unwrap().len() < 200);
    assert!(pack.truncated);
}

#[test]
fn m6_and_lock_integration_smoke() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".blackbox");
    std::fs::create_dir_all(&root).unwrap();

    let mut bad = Run::new(vec!["x".into()], "/tmp".into());
    bad.status = RunStatus::Failed;
    bad.exit_code = Some(2);

    with_state_lock(&root, |state| {
        apply_run_outcome(state, &bad, OutcomeExtras::default());
        Ok(())
    })
    .unwrap();

    let mut good = Run::new(vec!["true".into()], "/tmp".into());
    good.status = RunStatus::Succeeded;
    good.exit_code = Some(0);
    with_state_lock(&root, |state| {
        apply_run_outcome(state, &good, OutcomeExtras::default());
        Ok(())
    })
    .unwrap();

    let s = ProjectState::load(&root).unwrap().unwrap();
    assert_eq!(s.unresolved_failure_id.as_deref(), Some(bad.id.as_str()));
    assert_eq!(s.attention_level, AttentionLevel::Continue);
}
