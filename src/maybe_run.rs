//! Project-gated ambient capture entrypoint (`blackbox maybe-run`).

use std::path::Path;
use std::process::Command;

use crate::cli::RunArgs;
use crate::config::{discover_project, BlackboxConfig};

/// Env vars controlling ambient capture.
pub const ENV_OFF: &str = "BLACKBOX_OFF";
pub const ENV_ACTIVE_RUN: &str = "BLACKBOX_ACTIVE_RUN";

/// Decision for maybe-run (testable without exec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeRunAction {
    /// Pass through to bare command (do not open store).
    Passthrough { reason: &'static str },
    /// Record under blackbox.
    Record {
        project_root: String,
        tags: Vec<String>,
    },
}

/// Decide whether to record or passthrough.
pub fn decide(
    command: &[String],
    cwd: &Path,
    db_override: Option<&Path>,
    off_set: bool,
    active_run_set: bool,
) -> anyhow::Result<MaybeRunAction> {
    if off_set {
        return Ok(MaybeRunAction::Passthrough {
            reason: "BLACKBOX_OFF",
        });
    }
    if active_run_set {
        return Ok(MaybeRunAction::Passthrough {
            reason: "nested under BLACKBOX_ACTIVE_RUN",
        });
    }
    if command.is_empty() {
        anyhow::bail!("maybe-run requires a command after --");
    }

    let discovery = discover_project(cwd, db_override)?;
    let Some(cfg) = discovery.config.as_ref() else {
        return Ok(MaybeRunAction::Passthrough {
            reason: "no project config",
        });
    };
    if !cfg.enabled {
        return Ok(MaybeRunAction::Passthrough {
            reason: "project disabled",
        });
    }

    let basename = Path::new(&command[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command[0].as_str());

    if !cfg
        .capture
        .wrap
        .iter()
        .any(|w| w.eq_ignore_ascii_case(basename))
    {
        return Ok(MaybeRunAction::Passthrough {
            reason: "basename not in wrap list",
        });
    }

    Ok(MaybeRunAction::Record {
        project_root: discovery.project_root.to_string_lossy().to_string(),
        tags: cfg.capture.default_tags.clone(),
    })
}

/// Build RunArgs for a record decision.
pub fn run_args_for_record(
    command: Vec<String>,
    project_root: String,
    mut tags: Vec<String>,
    name: Option<String>,
) -> RunArgs {
    if !tags.iter().any(|t| t == "auto") {
        tags.push("auto".into());
    }
    RunArgs {
        name,
        project: Some(project_root),
        tag: tags,
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: false,
        auto_resume: false,
        command,
        resume_injection: None,
    }
}

/// Exec the bare command, replacing the current process (Unix).
///
/// On failure to exec, returns an error. Never returns `Ok` on success.
#[cfg(unix)]
pub fn exec_passthrough(command: &[String]) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    if command.is_empty() {
        anyhow::bail!("empty command");
    }
    let err = Command::new(&command[0]).args(&command[1..]).exec();
    Err(anyhow::anyhow!("failed to exec {}: {err}", command[0]))
}

/// Non-Unix fallback: spawn and wait, then exit with child code.
#[cfg(not(unix))]
pub fn exec_passthrough(command: &[String]) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("empty command");
    }
    let status = Command::new(&command[0]).args(&command[1..]).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Shell function snippets for enable output.
pub fn shell_snippet_fish(wrap: &[String]) -> String {
    let mut out = String::from("# blackbox ambient capture (fish)\n");
    for name in wrap {
        out.push_str(&format!(
            "function {name}\n  if command -q blackbox\n    command blackbox maybe-run -- {name} $argv\n  else\n    command {name} $argv\n  end\nend\n\n"
        ));
    }
    out
}

pub fn shell_snippet_bash(wrap: &[String]) -> String {
    let mut out = String::from("# blackbox ambient capture (bash/zsh)\n");
    for name in wrap {
        out.push_str(&format!(
            "{name}() {{\n  if command -v blackbox >/dev/null 2>&1; then\n    command blackbox maybe-run -- {name} \"$@\"\n  else\n    command {name} \"$@\"\n  fi\n}}\n\n"
        ));
    }
    out
}

/// Default config written by `enable`.
pub fn default_enable_config() -> BlackboxConfig {
    BlackboxConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlackboxConfig;
    use std::fs;

    #[test]
    fn off_passthrough() {
        let a = decide(&["claude".into()], Path::new("."), None, true, false).unwrap();
        assert!(matches!(a, MaybeRunAction::Passthrough { reason } if reason == "BLACKBOX_OFF"));
    }

    #[test]
    fn nested_passthrough() {
        let a = decide(&["claude".into()], Path::new("."), None, false, true).unwrap();
        assert!(matches!(
            a,
            MaybeRunAction::Passthrough { reason } if reason.contains("nested")
        ));
    }

    #[test]
    fn enabled_wrap_records() {
        let dir = tempfile::tempdir().unwrap();
        let bb = dir.path().join(".blackbox");
        fs::create_dir_all(&bb).unwrap();
        let cfg = BlackboxConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.write_to_path(&bb.join("config.toml")).unwrap();

        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");

        let a = decide(
            &["claude".into(), "-p".into(), "hi".into()],
            dir.path(),
            None,
            false,
            false,
        )
        .unwrap();
        match a {
            MaybeRunAction::Record { project_root, tags } => {
                assert!(
                    project_root.contains(dir.path().file_name().unwrap().to_str().unwrap())
                        || Path::new(&project_root) == dir.path().canonicalize().unwrap()
                );
                assert!(tags.contains(&"auto".to_string()) || !tags.is_empty());
            }
            other => panic!("expected Record, got {other:?}"),
        }

        if let Some(v) = prev {
            std::env::set_var("BLACKBOX_DB", v);
        }
    }

    #[test]
    fn disabled_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let bb = dir.path().join(".blackbox");
        fs::create_dir_all(&bb).unwrap();
        let cfg = BlackboxConfig {
            enabled: false,
            ..Default::default()
        };
        cfg.write_to_path(&bb.join("config.toml")).unwrap();

        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");

        let a = decide(&["claude".into()], dir.path(), None, false, false).unwrap();
        assert!(matches!(
            a,
            MaybeRunAction::Passthrough { reason } if reason.contains("disabled")
        ));

        if let Some(v) = prev {
            std::env::set_var("BLACKBOX_DB", v);
        }
    }

    #[test]
    fn wrap_miss_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let bb = dir.path().join(".blackbox");
        fs::create_dir_all(&bb).unwrap();
        BlackboxConfig::default()
            .write_to_path(&bb.join("config.toml"))
            .unwrap();

        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");

        let a = decide(
            &["echo".into(), "hi".into()],
            dir.path(),
            None,
            false,
            false,
        )
        .unwrap();
        assert!(matches!(
            a,
            MaybeRunAction::Passthrough { reason } if reason.contains("wrap")
        ));

        if let Some(v) = prev {
            std::env::set_var("BLACKBOX_DB", v);
        }
    }
}
