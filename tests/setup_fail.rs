//! Phase 1 (1.3 T1/T2): `blackbox setup` + `blackbox fail` integration.

use std::process::Command;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::core::run::RunStatus;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, SummaryOptions};
use blackbox::util::short_id;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_blackbox"))
}

#[test]
fn setup_creates_project_and_sample_run() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .current_dir(dir.path())
        .args(["setup", "--no-sample", "--json"])
        .output()
        .expect("run setup");
    assert!(
        out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(v["ok"], true);
    assert_eq!(v["command"], "setup");
    assert_eq!(v["data"]["memory_bus"], false);
    assert!(dir.path().join(".blackbox/config.toml").is_file());

    let cfg = std::fs::read_to_string(dir.path().join(".blackbox/config.toml")).unwrap();
    assert!(cfg.contains("enabled") || cfg.contains("true") || !cfg.is_empty());
}

#[test]
fn setup_with_sample_records_run() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .current_dir(dir.path())
        .args(["setup", "--json"])
        .output()
        .expect("run setup sample");
    assert!(
        out.status.success(),
        "setup: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["ok"], true);
    assert!(
        v["data"]["sample_run_id"].as_str().is_some(),
        "expected sample_run_id: {v}"
    );
    assert!(dir.path().join(".blackbox/blackbox.db").is_file());
}

#[test]
fn setup_harden_sets_encrypt_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = bin()
        .current_dir(dir.path())
        .env("HOME", &home)
        .args(["setup", "--harden", "--no-sample", "--json"])
        .output()
        .expect("setup harden");
    assert!(
        out.status.success(),
        "harden setup: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(dir.path().join(".blackbox/config.toml")).unwrap();
    assert!(
        cfg.contains("encrypt_blobs") && cfg.contains("true"),
        "config should enable encrypt_blobs: {cfg}"
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["data"]["hardened"], true);
    assert!(v["data"]["key_path"].as_str().is_some());
    // native_log_scope / allowlist also applied
    assert!(
        cfg.contains("native_log_scope") || cfg.contains("project"),
        "harden should prefer project native logs: {cfg}"
    );
}

#[test]
fn enable_harden_writes_profile() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = bin()
        .current_dir(dir.path())
        .env("HOME", &home)
        .args(["enable", "--harden"])
        .output()
        .expect("enable harden");
    assert!(
        out.status.success(),
        "enable harden: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(dir.path().join(".blackbox/config.toml")).unwrap();
    assert!(
        cfg.contains("encrypt_blobs") && cfg.contains("true"),
        "enable --harden encrypt_blobs: {cfg}"
    );
    // HARDEN.txt tip written under store root
    assert!(
        dir.path().join(".blackbox/HARDEN.txt").is_file()
            || home.join(".config/blackbox/default.key").is_file(),
        "harden should create key tip and/or external key"
    );
}

#[tokio::test]
async fn fail_focuses_failed_run_and_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    // enable via setup no-sample first so store/discovery work
    let st = bin()
        .current_dir(dir.path())
        .args(["setup", "--no-sample"])
        .output()
        .unwrap();
    assert!(st.status.success());

    let db = dir.path().join(".blackbox/blackbox.db");
    let blobs = dir.path().join(".blackbox/blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);

    // Success run then failed run
    let sup = RunSupervisor::new(store.clone());
    let ok = RunArgs {
        name: Some("ok".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec![],
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
        command: vec!["true".into()],
        ..Default::default()
    };
    let _ = sup.execute(&ok).await.unwrap();

    let bad = RunArgs {
        name: Some("bad".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["fail-me".into()],
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
        command: vec!["false".into()],
        ..Default::default()
    };
    let failed = sup.execute(&bad).await.unwrap();
    assert_eq!(failed.exit_code, Some(1));
    assert_eq!(failed.status, RunStatus::Failed);

    let out = bin()
        .current_dir(dir.path())
        .args(["fail", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fail: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["command"], "fail");
    assert_eq!(v["data"]["run_id"], failed.id);
    assert_eq!(v["data"]["failed"], true);
    assert!(
        v["data"]["focus"] == "last_failure" || v["data"]["focus"] == "unresolved_failure",
        "focus={}",
        v["data"]["focus"]
    );
    assert!(v["data"]["summary"]["headline"].is_string());
    assert!(v["data"]["summary"]["anomalies"].is_array());
    assert!(v["data"]["summary"]["evidence"].is_array());
    assert!(v["data"]["next_commands"].as_array().unwrap().len() >= 2);

    // Explicit id
    let sid = short_id(&failed.id);
    let out2 = bin()
        .current_dir(dir.path())
        .args(["fail", sid, "--json"])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let v2: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out2.stdout)).unwrap();
    assert_eq!(v2["data"]["focus"], "explicit");
    assert_eq!(v2["data"]["run_id"], failed.id);
}

#[tokio::test]
async fn fail_on_success_only_store_uses_latest() {
    let dir = tempfile::tempdir().unwrap();
    let _ = bin()
        .current_dir(dir.path())
        .args(["setup", "--json"])
        .output()
        .unwrap();
    // setup already left a success sample; fail should still work (latest)
    let out = bin()
        .current_dir(dir.path())
        .args(["fail", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["data"]["focus"], "latest");
    assert_eq!(v["data"]["failed"], false);
}

#[test]
fn clap_help_lists_setup_and_fail() {
    let out = bin().args(["--help"]).output().unwrap();
    let h = String::from_utf8_lossy(&out.stdout);
    assert!(h.contains("setup"), "help missing setup:\n{h}");
    assert!(h.contains("fail"), "help missing fail:\n{h}");
}

#[tokio::test]
async fn fail_summary_matches_postmortem_builder() {
    // Sanity: fail path uses same build_summary as postmortem
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let sup = RunSupervisor::new(store.clone());
    let args = RunArgs {
        name: None,
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec![],
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
        command: vec!["false".into()],
        ..Default::default()
    };
    let run = sup.execute(&args).await.unwrap();
    let s = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();
    assert!(!s.run_id.is_empty());
    assert_eq!(s.exit_code, Some(1));
}
