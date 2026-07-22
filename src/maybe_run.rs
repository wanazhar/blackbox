//! Project-gated ambient capture entrypoint (`blackbox maybe-run`).

use std::path::Path;
use std::process::Command;

use crate::cli::RunArgs;
use crate::config::{discover_project, BlackboxConfig};

/// Env vars controlling ambient capture.
pub const ENV_OFF: &str = "BLACKBOX_OFF";
/// Legacy nest env (still honored if set). Prefer PID markers — see [`crate::nest`].
pub const ENV_ACTIVE_RUN: &str = crate::nest::ENV_ACTIVE_RUN;

/// Decision for maybe-run (testable without exec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeRunAction {
    /// Pass through to bare command (do not open store).
    Passthrough {
        /// Why recording was skipped.
        reason: &'static str,
    },
    /// Record under blackbox.
    Record {
        /// Project root directory for store discovery.
        project_root: String,
        /// Tags applied to the new run.
        tags: Vec<String>,
    },
}

/// Decide whether to record or passthrough.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `decide` — see module docs for full workflow.
/// ```
pub fn decide(
    command: &[String],
    cwd: &Path,
    db_override: Option<&Path>,
    off_set: bool,
    active_run_set: bool,
) -> anyhow::Result<MaybeRunAction> {
    if off_set {
        // Still record why ambient skipped when project exists (best-effort).
        if let Ok(d) = discover_project(cwd, db_override) {
            append_ambient_log(&d.paths.root, "PASSTHROUGH BLACKBOX_OFF");
        }
        return Ok(MaybeRunAction::Passthrough {
            reason: "BLACKBOX_OFF",
        });
    }
    // Nest: legacy env (tests/older supervisors) OR ancestor PID marker (1.4 N1).
    let nested = active_run_set || crate::nest::nested_under_marker();
    if nested {
        if let Ok(d) = discover_project(cwd, db_override) {
            let why = if active_run_set {
                "PASSTHROUGH nested under BLACKBOX_ACTIVE_RUN (legacy)"
            } else {
                "PASSTHROUGH nested under active supervisor marker"
            };
            append_ambient_log(&d.paths.root, why);
        }
        return Ok(MaybeRunAction::Passthrough {
            reason: if active_run_set {
                "nested under BLACKBOX_ACTIVE_RUN"
            } else {
                "nested under active supervisor"
            },
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
        append_ambient_log(
            &discovery.paths.root,
            &format!("PASSTHROUGH basename_not_in_wrap={basename}"),
        );
        return Ok(MaybeRunAction::Passthrough {
            reason: "basename not in wrap list",
        });
    }

    // Self-observability: decision is always logged at debug; ambient decisions
    // are also appended to project `.blackbox/ambient.log` for "why wrap?" forensics.
    let root = discovery.project_root.to_string_lossy().to_string();
    append_ambient_log(
        &discovery.paths.root,
        &format!(
            "RECORD wrap={} product={} observe_only={}",
            basename,
            cfg.capture.product_mode().as_str(),
            cfg.capture.observe_only
        ),
    );
    Ok(MaybeRunAction::Record {
        project_root: root,
        tags: cfg.capture.default_tags.clone(),
    })
}

fn append_ambient_log(bb_root: &Path, line: &str) {
    let path = bb_root.join("ambient.log");
    let _ = std::fs::create_dir_all(bb_root);
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let ts = chrono::Utc::now().to_rfc3339();
        let _ = writeln!(f, "{ts} {line}");
    }
}

/// Build RunArgs for a record decision.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `run_args_for_record` — see module docs for full workflow.
/// ```
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
        // Ambient shell wrap is always neutral recording. Continuity/memory
        // inject only applies to explicit `blackbox run` (non-ambient).
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: true,
        artifact_dir: None,
        experiment: None,
        task: None,
        variant: None,
        attempt: None,
        role: None,
        seed: None,
        dataset_case: None,
        model: None,
        provider: None,
        harness: None,
        boundary: None,
        boundary_parent: Vec::new(),
        boundary_fail_closed: false,
        harness_version: None,
        max_wall: None,
        max_processes: None,
        max_output: None,
        max_tool_calls: None,
        max_tokens: None,
        max_memory: None,
        max_cpu_percent: None,
        contained: false,
        command,
        resume_injection: None,
        claim_id_note: None,
        ambient: true,
    }
}

/// Exec the bare command, replacing the current process (Unix).
///
/// On failure to exec, returns an error. Never returns `Ok` on success.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `exec_passthrough` — see module docs for full workflow.
/// ```
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
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `exec_passthrough` — see module docs for full workflow.
/// ```
#[cfg(not(unix))]
pub fn exec_passthrough(command: &[String]) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("empty command");
    }
    let status = Command::new(&command[0]).args(&command[1..]).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Shell function snippets for enable output.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `shell_snippet_fish` — see module docs for full workflow.
/// ```
pub fn shell_snippet_fish(wrap: &[String]) -> String {
    let mut out = String::from("# blackbox ambient capture (fish)\n");
    for name in wrap {
        if !crate::util::is_safe_wrap_name(name) {
            tracing::warn!(name = %name, "skipping unsafe wrap name in fish snippet");
            continue;
        }
        out.push_str(&format!(
            "function {name}\n  if command -q blackbox\n    command blackbox maybe-run -- {name} $argv\n  else\n    command {name} $argv\n  end\nend\n\n"
        ));
    }
    out
}

/// Shell snippet bash.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `shell_snippet_bash` — see module docs for full workflow.
/// ```
pub fn shell_snippet_bash(wrap: &[String]) -> String {
    let mut out = String::from("# blackbox ambient capture (bash/zsh)\n");
    for name in wrap {
        if !crate::util::is_safe_wrap_name(name) {
            tracing::warn!(name = %name, "skipping unsafe wrap name in bash snippet");
            continue;
        }
        out.push_str(&format!(
            "{name}() {{\n  if command -v blackbox >/dev/null 2>&1; then\n    command blackbox maybe-run -- {name} \"$@\"\n  else\n    command {name} \"$@\"\n  fi\n}}\n\n"
        ));
    }
    out
}

/// Default config written by `enable`.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `default_enable_config` — see module docs for full workflow.
/// ```
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
    fn ambient_record_args_are_observe_only() {
        let args = run_args_for_record(
            vec!["claude".into(), "-p".into(), "hi".into()],
            "/proj".into(),
            vec!["auto".into()],
            None,
        );
        assert!(args.observe_only, "ambient wrap must be observe-only");
        assert!(args.ambient);
        assert!(args.no_auto_resume);
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
