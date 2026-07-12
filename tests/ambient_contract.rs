//! A1 — Ambient shell contract (1.1 adoption bar).
//!
//! Normative decision order and shell install guarantees from
//! `docs/plan/adoption-1.1.md` / `docs/ambient-contract.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::config::BlackboxConfig;
use blackbox::maybe_run::{self, MaybeRunAction};
use blackbox::run::RunSupervisor;
use blackbox::shell_install::{self, ShellKind};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

fn temp_project() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bb-ambient-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join(".blackbox")).unwrap();
    dir
}

fn write_enabled_config(project: &Path, wrap: &[&str]) {
    let mut cfg = BlackboxConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.capture.wrap = wrap.iter().map(|s| (*s).to_string()).collect();
    cfg.write_to_path(&project.join(".blackbox/config.toml"))
        .unwrap();
}

fn write_fake_harness(bin_dir: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join(name);
    std::fs::write(&path, "#!/bin/sh\necho ambient-ok\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Clear BLACKBOX_DB so discovery uses the temp project, not the caller's env.
fn without_db_override<T>(f: impl FnOnce() -> T) -> T {
    let prev = std::env::var("BLACKBOX_DB").ok();
    std::env::remove_var("BLACKBOX_DB");
    let out = f();
    match prev {
        Some(v) => std::env::set_var("BLACKBOX_DB", v),
        None => std::env::remove_var("BLACKBOX_DB"),
    }
    out
}

#[test]
fn a1_off_never_records_decision() {
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    without_db_override(|| {
        let a = maybe_run::decide(
            &["claude".into(), "-p".into(), "x".into()],
            &project,
            None,
            true,
            false,
        )
        .unwrap();
        assert!(
            matches!(a, MaybeRunAction::Passthrough { reason } if reason == "BLACKBOX_OFF"),
            "got {a:?}"
        );
    });
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a1_nest_passthrough() {
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    without_db_override(|| {
        let a = maybe_run::decide(
            &["claude".into()],
            &project,
            None,
            false,
            true, // BLACKBOX_ACTIVE_RUN
        )
        .unwrap();
        assert!(
            matches!(a, MaybeRunAction::Passthrough { reason } if reason.contains("nested")),
            "got {a:?}"
        );
    });
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a1_wrap_miss_and_disabled() {
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    without_db_override(|| {
        let miss =
            maybe_run::decide(&["echo".into(), "hi".into()], &project, None, false, false).unwrap();
        assert!(
            matches!(miss, MaybeRunAction::Passthrough { reason } if reason.contains("wrap")),
            "got {miss:?}"
        );
    });

    let cfg = BlackboxConfig {
        enabled: false,
        ..Default::default()
    };
    cfg.write_to_path(&project.join(".blackbox/config.toml"))
        .unwrap();
    without_db_override(|| {
        let off = maybe_run::decide(&["claude".into()], &project, None, false, false).unwrap();
        assert!(
            matches!(off, MaybeRunAction::Passthrough { reason } if reason.contains("disabled")),
            "got {off:?}"
        );
    });
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a1_enabled_wrap_records_decision() {
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    without_db_override(|| {
        let a = maybe_run::decide(
            &["claude".into(), "-p".into(), "hi".into()],
            &project,
            None,
            false,
            false,
        )
        .unwrap();
        match a {
            MaybeRunAction::Record { project_root, tags } => {
                let root = PathBuf::from(&project_root);
                assert_eq!(
                    root.canonicalize().unwrap(),
                    project.canonicalize().unwrap()
                );
                // ambient tags may be empty in config; run_args_for_record adds "auto"
                let _ = tags;
            }
            other => panic!("expected Record, got {other:?}"),
        }
    });
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn a1_record_path_creates_one_run_nest_does_not() {
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    let bin = project.join("bin");
    let harness = write_fake_harness(&bin, "claude");

    let db = project.join(".blackbox/blackbox.db");
    let blobs = project.join(".blackbox/blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);

    let decision = without_db_override(|| {
        maybe_run::decide(
            &[harness.to_string_lossy().into(), "-p".into(), "hi".into()],
            &project,
            None,
            false,
            false,
        )
        .unwrap()
    });

    // Basename of absolute path is still "claude" — wrap list matches.
    let MaybeRunAction::Record { project_root, tags } = decision else {
        panic!("expected Record, got {decision:?}");
    };

    let args = maybe_run::run_args_for_record(
        vec![harness.to_string_lossy().into(), "-p".into(), "hi".into()],
        project_root,
        tags,
        Some("ambient-contract".into()),
    );
    // run_args_for_record may set project; ensure command is absolute harness
    let args = RunArgs {
        command: vec![harness.to_string_lossy().into()],
        ..args
    };

    let supervisor = RunSupervisor::new(store.clone());
    let run = supervisor.execute(&args).await.expect("record run");
    assert_eq!(run.exit_code, Some(0));

    let runs = store.list_runs().await.unwrap();
    assert_eq!(runs.len(), 1, "exactly one ambient run");

    // Nest decision must not produce a second record action
    let nested = without_db_override(|| {
        maybe_run::decide(
            &[harness.to_string_lossy().into()],
            &project,
            None,
            false,
            true,
        )
        .unwrap()
    });
    assert!(
        matches!(nested, MaybeRunAction::Passthrough { .. }),
        "nested must passthrough: {nested:?}"
    );
    assert_eq!(store.list_runs().await.unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a1_shell_install_idempotent_and_uninstall_clean() {
    let home = tempfile::tempdir().unwrap();
    let wrap = vec!["claude".into(), "codex".into()];

    let r1 = shell_install::install_shell(ShellKind::Bash, &wrap, home.path()).unwrap();
    assert!(matches!(r1.action, "installed" | "updated" | "unchanged"));
    let text1 = std::fs::read_to_string(&r1.path).unwrap();
    assert!(text1.contains(shell_install::BEGIN_MARKER));
    assert!(text1.contains(shell_install::END_MARKER));
    assert!(text1.contains("maybe-run"));
    assert!(text1.contains("command -v blackbox"));
    // Missing-binary fallback: bare command path
    assert!(
        text1.contains("command claude") || text1.contains("claude \"$@\""),
        "wrapper must fall back to bare command: {text1}"
    );

    let r2 = shell_install::install_shell(ShellKind::Bash, &wrap, home.path()).unwrap();
    assert!(
        r2.action == "unchanged" || r2.action == "updated",
        "re-install must be idempotent, got {}",
        r2.action
    );
    let text2 = std::fs::read_to_string(&r2.path).unwrap();
    let begins = text2.matches(shell_install::BEGIN_MARKER).count();
    assert_eq!(begins, 1, "exactly one managed block after re-install");

    let removed = shell_install::uninstall_shell(ShellKind::Bash, home.path()).unwrap();
    assert!(removed.is_some());
    let text3 = std::fs::read_to_string(shell_install::rc_path(ShellKind::Bash, home.path()))
        .unwrap_or_default();
    assert!(
        !text3.contains(shell_install::BEGIN_MARKER),
        "uninstall must remove managed block"
    );
    assert!(!text3.contains("maybe-run"));
}

#[test]
fn a1_snippets_missing_binary_fallback() {
    let fish = maybe_run::shell_snippet_fish(&["claude".into()]);
    assert!(fish.contains("command -q blackbox"));
    assert!(fish.contains("command blackbox maybe-run -- claude"));
    assert!(fish.contains("command claude $argv"));

    let bash = maybe_run::shell_snippet_bash(&["codex".into()]);
    assert!(bash.contains("command -v blackbox"));
    assert!(bash.contains("command blackbox maybe-run -- codex"));
    assert!(bash.contains("command codex \"$@\""));
}

#[test]
fn a1_decision_order_off_before_nest() {
    // OFF wins even if nest is also set — both passthrough, OFF reason preferred.
    let project = temp_project();
    write_enabled_config(&project, &["claude"]);
    without_db_override(|| {
        let a = maybe_run::decide(&["claude".into()], &project, None, true, true).unwrap();
        assert!(
            matches!(a, MaybeRunAction::Passthrough { reason } if reason == "BLACKBOX_OFF"),
            "OFF must win decision order: {a:?}"
        );
    });
    let _ = std::fs::remove_dir_all(&project);
}
