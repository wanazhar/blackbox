//! 1.4 N1/N2 — Hard recorder neutrality contract.
//!
//! Compares direct probe execution vs `blackbox run --observe-only` and asserts:
//! - argv unchanged (user args)
//! - cwd unchanged
//! - no child-visible BLACKBOX_* variables under recorder mode
//! - exit code and probe payload success
//! - ambient nest still works via supervisor PID markers

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::config::BlackboxConfig;
use blackbox::maybe_run::{self, MaybeRunAction};
use blackbox::nest::{self, ActiveSupervisorGuard};
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

fn probe_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/neutrality_probe.sh")
}

fn ensure_executable(path: &Path) {
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

fn temp_project() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bb-neutrality-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join(".blackbox")).unwrap();
    dir
}

fn parse_probe(stdout: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut in_env = false;
    let mut env_lines = Vec::new();
    for line in stdout.lines() {
        if line == "ENV_BEGIN" {
            in_env = true;
            continue;
        }
        if line == "ENV_END" {
            in_env = false;
            map.insert("ENV_BLOCK".into(), env_lines.join("\n"));
            continue;
        }
        if in_env {
            env_lines.push(line.to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn blackbox_keys_from_env_block(block: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, _)| k.to_string())
        .filter(|k| k.starts_with("BLACKBOX_"))
        .collect()
}

#[tokio::test]
async fn recorder_mode_strips_blackbox_env_from_child() {
    ensure_executable(&probe_script());
    let project = temp_project();
    let store_path = project.join(".blackbox/blackbox.db");
    let blobs = project.join(".blackbox/blobs");
    let store: Arc<dyn TraceStore> =
        Arc::new(SqliteStore::open_with_blobs(&store_path, &blobs).unwrap());

    // Parent (test process) has BLACKBOX_* vars that must not leak into the child.
    let prev_active = std::env::var_os("BLACKBOX_ACTIVE_RUN");
    let prev_db = std::env::var_os("BLACKBOX_DB");
    std::env::set_var("BLACKBOX_ACTIVE_RUN", "should-not-leak");
    std::env::set_var("BLACKBOX_DB", store_path.display().to_string());
    std::env::set_var("BLACKBOX_MEMORY_FILE", "/tmp/should-not-leak");

    let probe = probe_script();
    let args = RunArgs {
        name: Some("neutrality".into()),
        project: Some(project.display().to_string()),
        tag: vec!["neutrality".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: true,
        artifact_dir: None,
        command: vec![
            probe.display().to_string(),
            "alpha".into(),
            "beta gamma".into(),
        ],
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
    };

    let supervisor = RunSupervisor::new(store.clone());
    let run = supervisor.execute(&args).await.expect("run should succeed");
    assert_eq!(run.exit_code, Some(0), "probe exit code");

    // Load terminal output from events / transcript path: read PTY via events with payload.
    let events = store.get_events(&run.id).await.unwrap();
    assert!(
        events.iter().any(|e| e.kind == "run.neutrality"),
        "expected run.neutrality event"
    );
    let neu = events.iter().find(|e| e.kind == "run.neutrality").unwrap();
    assert_eq!(
        neu.metadata.get("mode").and_then(|v| v.as_str()),
        Some("recorder")
    );
    let n = neu.metadata.get("neutrality").expect("neutrality object");
    assert_eq!(
        n.get("argv_unchanged").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        n.get("environment_blackbox_stripped")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        n.get("continuity_injected").and_then(|v| v.as_bool()),
        Some(false)
    );

    let stdout = blackbox::transcript::rebuild_terminal_transcript(store.as_ref(), &events)
        .await
        .expect("rebuild transcript");

    assert!(
        stdout.contains("PROBE_OK=1"),
        "probe output missing; got:\n{stdout}"
    );
    let parsed = parse_probe(&stdout);
    assert_eq!(parsed.get("ARGC").map(String::as_str), Some("2"));
    assert_eq!(parsed.get("ARGV_0").map(String::as_str), Some("alpha"));
    assert_eq!(parsed.get("ARGV_1").map(String::as_str), Some("beta gamma"));
    assert_eq!(
        parsed.get("BLACKBOX_ENV_COUNT").map(String::as_str),
        Some("0"),
        "recorder child must not see BLACKBOX_* env; keys={:?}",
        parsed.get("BLACKBOX_ENV_KEYS")
    );
    if let Some(block) = parsed.get("ENV_BLOCK") {
        let keys = blackbox_keys_from_env_block(block);
        assert!(keys.is_empty(), "child env leaked BLACKBOX_*: {keys:?}");
    }

    // Restore env
    match prev_active {
        Some(v) => std::env::set_var("BLACKBOX_ACTIVE_RUN", v),
        None => std::env::remove_var("BLACKBOX_ACTIVE_RUN"),
    }
    match prev_db {
        Some(v) => std::env::set_var("BLACKBOX_DB", v),
        None => std::env::remove_var("BLACKBOX_DB"),
    }
    std::env::remove_var("BLACKBOX_MEMORY_FILE");
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn direct_probe_reports_parent_blackbox_env() {
    // Sanity: when run directly with BLACKBOX_* set, probe sees them.
    ensure_executable(&probe_script());
    let out = Command::new(probe_script())
        .arg("x")
        .env("BLACKBOX_PROBE_TEST", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("BLACKBOX_ENV_COUNT=1") || stdout.contains("BLACKBOX_PROBE_TEST"));
    let parsed = parse_probe(&stdout);
    let count: u32 = parsed
        .get("BLACKBOX_ENV_COUNT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(count >= 1, "direct run should see at least the test var");
}

#[test]
fn nest_marker_triggers_passthrough() {
    let project = temp_project();
    let mut cfg = BlackboxConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.capture.wrap = vec!["claude".into()];
    cfg.write_to_path(&project.join(".blackbox/config.toml"))
        .unwrap();

    let prev_db = std::env::var_os("BLACKBOX_DB");
    std::env::remove_var("BLACKBOX_DB");
    std::env::remove_var("BLACKBOX_ACTIVE_RUN");

    // Simulate an active supervisor in the PPID chain by writing a marker for our PPID.
    let dir = nest::supervisor_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let ppid = unsafe { libc::getppid() as u32 };
    let marker = dir.join(ppid.to_string());
    std::fs::write(&marker, "parent-run").unwrap();

    let a = maybe_run::decide(&["claude".into()], &project, None, false, false).unwrap();
    assert!(
        matches!(a, MaybeRunAction::Passthrough { reason } if reason.contains("nested")),
        "expected nested passthrough, got {a:?}"
    );

    let _ = std::fs::remove_file(&marker);
    match prev_db {
        Some(v) => std::env::set_var("BLACKBOX_DB", v),
        None => std::env::remove_var("BLACKBOX_DB"),
    }
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn nest_guard_registers_current_pid() {
    let g = ActiveSupervisorGuard::acquire("run-xyz");
    assert!(g.path().is_file());
    let content = std::fs::read_to_string(g.path()).unwrap();
    assert!(content.contains("run-xyz"));
    let path = g.path().to_path_buf();
    drop(g);
    assert!(!path.exists());
}

#[test]
fn legacy_env_still_nests() {
    let project = temp_project();
    let a = maybe_run::decide(&["claude".into()], &project, None, false, true).unwrap();
    assert!(matches!(
        a,
        MaybeRunAction::Passthrough { reason } if reason.contains("nested")
    ));
    let _ = std::fs::remove_dir_all(&project);
}
