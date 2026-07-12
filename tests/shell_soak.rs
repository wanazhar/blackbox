//! Real-shell soak: install wrappers into a temp HOME, source them in bash,
//! and verify ambient maybe-run records a harness launch.
//!
//! Skips cleanly when bash is unavailable. Unix-only (shell rc + shebangs).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use blackbox::config::BlackboxConfig;
use blackbox::shell_install::{self, ShellKind};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

fn have_bash() -> bool {
    Command::new("bash")
        .arg("-c")
        .arg("exit 0")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn real_bash_wrapper_records_ambient_run() {
    if !have_bash() {
        eprintln!("skip: bash not available");
        return;
    }

    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("proj");
    std::fs::create_dir_all(project.join(".blackbox")).unwrap();

    let mut cfg = BlackboxConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.capture.wrap = vec!["claude".into()];
    cfg.write_to_path(&project.join(".blackbox/config.toml"))
        .unwrap();

    // Install wrappers into temp HOME
    shell_install::install_shell(ShellKind::Bash, &["claude".into()], home.path()).unwrap();
    let bashrc = shell_install::rc_path(ShellKind::Bash, home.path());
    assert!(bashrc.exists());

    // Fake claude on PATH
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let claude = bin.join("claude");
    std::fs::write(&claude, "#!/bin/sh\necho soak-ok\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&claude).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&claude, perms).unwrap();

    // blackbox binary under test
    let blackbox = option_env!("CARGO_BIN_EXE_blackbox")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Fallback: target/debug/blackbox relative to cwd
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/blackbox")
        });
    if !blackbox.exists() {
        eprintln!("skip: blackbox binary missing at {}", blackbox.display());
        return;
    }

    // Prepend bin + blackbox dir to PATH; source bashrc; call claude
    let bb_dir = blackbox.parent().unwrap();
    let path = format!(
        "{}:{}:{}",
        bin.display(),
        bb_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Non-interactive bash ignores --rcfile; source explicitly via -c.
    let script = format!("source '{}' && claude", bashrc.display());
    let status = Command::new("bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(&script)
        .current_dir(&project)
        .env("HOME", home.path())
        .env("PATH", &path)
        .env_remove("BLACKBOX_DB")
        .env_remove("BLACKBOX_OFF")
        .env_remove("BLACKBOX_ACTIVE_RUN")
        .status()
        .expect("bash spawn");

    assert!(status.success(), "bash claude wrapper failed: {status:?}");

    // Store should have recorded a run
    let db = project.join(".blackbox/blackbox.db");
    assert!(
        db.exists(),
        "expected store at {} after ambient capture",
        db.display()
    );
    let store = SqliteStore::open_with_blobs(&db, project.join(".blackbox/blobs")).unwrap();
    let runs = store.list_runs().await.unwrap();
    assert!(
        !runs.is_empty(),
        "expected at least one ambient run from bash wrapper"
    );
    assert!(
        runs.iter().any(|r| r.tags.iter().any(|t| t == "auto")
            || r.command.iter().any(|c| c.contains("claude"))),
        "run should be ambient-tagged or claude command: {runs:?}"
    );
}

#[test]
fn real_bash_off_passthrough_no_store() {
    if !have_bash() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("proj");
    std::fs::create_dir_all(project.join(".blackbox")).unwrap();
    let mut cfg = BlackboxConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.capture.wrap = vec!["claude".into()];
    cfg.write_to_path(&project.join(".blackbox/config.toml"))
        .unwrap();
    shell_install::install_shell(ShellKind::Bash, &["claude".into()], home.path()).unwrap();

    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let claude = bin.join("claude");
    std::fs::write(&claude, "#!/bin/sh\necho off-ok\n").unwrap();
    let mut perms = std::fs::metadata(&claude).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&claude, perms).unwrap();

    let blackbox = option_env!("CARGO_BIN_EXE_blackbox")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/blackbox"));
    if !blackbox.exists() {
        return;
    }
    let path = format!(
        "{}:{}:{}",
        bin.display(),
        blackbox.parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let bashrc = shell_install::rc_path(ShellKind::Bash, home.path());
    let script = format!("source '{}' && claude", bashrc.display());
    let out = Command::new("bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(&script)
        .current_dir(&project)
        .env("HOME", home.path())
        .env("PATH", path)
        .env("BLACKBOX_OFF", "1")
        .env_remove("BLACKBOX_DB")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !project.join(".blackbox/blackbox.db").exists(),
        "BLACKBOX_OFF must not create store"
    );
}
