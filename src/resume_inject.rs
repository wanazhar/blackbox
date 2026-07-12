//! Auto-resume: inject prior failure context into the next harness launch.

use std::path::{Path, PathBuf};

use crate::config::BlackboxConfig;
use crate::context::{build_context_pack, ContextOptions, ContextPackView};
use crate::core::run::RunStatus;
use crate::state::ProjectState;
use crate::storage::TraceStore;

/// Env vars set for auto-resume (also discoverable by harnesses/agents).
pub const ENV_AUTO_RESUME: &str = "BLACKBOX_AUTO_RESUME";
pub const ENV_RESUME_FILE: &str = "BLACKBOX_RESUME_FILE";
pub const ENV_RESUME_RUN_ID: &str = "BLACKBOX_RESUME_RUN_ID";
pub const ENV_RESUME_HINT: &str = "BLACKBOX_RESUME_HINT";

/// Whether auto-resume is active (config + env).
pub fn auto_resume_enabled(cfg: Option<&BlackboxConfig>) -> bool {
    if let Ok(v) = std::env::var(ENV_AUTO_RESUME) {
        let v = v.to_ascii_lowercase();
        if v == "0" || v == "false" || v == "off" || v == "no" {
            return false;
        }
        if v == "1" || v == "true" || v == "on" || v == "yes" {
            return true;
        }
    }
    cfg.map(|c| c.capture.auto_resume).unwrap_or(false)
}

/// Materialized resume injection for a launch.
#[derive(Debug, Clone)]
pub struct ResumeInjection {
    pub run_id: String,
    pub short_id: String,
    pub file_path: PathBuf,
    pub preamble: String,
    pub hint: String,
    pub pack: ContextPackView,
}

/// Build resume injection from sticky state + store when attention is needed.
pub async fn prepare_resume_injection(
    store: &dyn TraceStore,
    blackbox_root: &Path,
    max_tokens: usize,
) -> anyhow::Result<Option<ResumeInjection>> {
    let sticky = ProjectState::load(blackbox_root)?.unwrap_or_default();
    if !sticky.attention_needed {
        // Also check last_run status from sticky
        let bad = sticky
            .last_run
            .as_ref()
            .map(|r| r.status == "failed" || r.status == "cancelled")
            .unwrap_or(false);
        if !bad {
            return Ok(None);
        }
    }

    let target_id = sticky
        .last_run
        .as_ref()
        .filter(|r| r.status == "failed" || r.status == "cancelled")
        .or(sticky.last_failure.as_ref())
        .map(|r| r.id.clone());

    let Some(run_id) = target_id else {
        return Ok(None);
    };

    let Some(run) = store.get_run(&run_id).await? else {
        return Ok(None);
    };
    if !matches!(run.status, RunStatus::Failed | RunStatus::Cancelled) {
        // Prefer DB truth if sticky is stale
        if !sticky.attention_needed {
            return Ok(None);
        }
    }

    let pack = build_context_pack(
        store,
        &run,
        ContextOptions {
            max_tokens,
            include_transcript: true,
        },
    )
    .await?;

    std::fs::create_dir_all(blackbox_root)?;
    let file_path = blackbox_root.join("RESUME.md");
    let preamble = format_resume_preamble(&pack);
    std::fs::write(&file_path, &preamble)?;

    // Also write JSON pack for machine agents
    let json_path = blackbox_root.join("RESUME.json");
    let _ = std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&pack).unwrap_or_default(),
    );

    let short = crate::util::short_id(&run_id).to_string();
    let hint = format!(
        "Prior blackbox run {short} needs attention (status={:?}, exit={:?}). Resume pack: {}",
        run.status,
        run.exit_code,
        file_path.display()
    );

    Ok(Some(ResumeInjection {
        run_id,
        short_id: short,
        file_path,
        preamble,
        hint,
        pack,
    }))
}

fn format_resume_preamble(pack: &ContextPackView) -> String {
    let mut out = String::new();
    out.push_str("# blackbox resume context\n\n");
    out.push_str(&format!("{}\n\n", pack.headline));
    out.push_str(&format!(
        "Attention: {} · tokens≈{}{}\n\n",
        pack.attention_reason,
        pack.approx_tokens,
        if pack.truncated { " (truncated)" } else { "" }
    ));
    out.push_str(&format!("## Next action\n{}\n\n", pack.next_action));
    if !pack.failed_tools.is_empty() {
        out.push_str("## Failed tools\n");
        for t in &pack.failed_tools {
            out.push_str(&format!("- seq={} {} {}\n", t.sequence, t.name, t.detail));
        }
        out.push('\n');
    }
    if !pack.errors_top.is_empty() {
        out.push_str("## Top errors\n");
        for e in pack.errors_top.iter().take(8) {
            out.push_str(&format!(
                "- seq={} [{}] {}\n",
                e.sequence, e.error_type, e.message
            ));
        }
        out.push('\n');
    }
    if !pack.last_tools.is_empty() {
        out.push_str(&format!(
            "## Last tools\n{}\n\n",
            pack.last_tools.join(", ")
        ));
    }
    if !pack.filesystem_writes.is_empty() {
        out.push_str("## Filesystem activity\n");
        for w in pack.filesystem_writes.iter().take(15) {
            out.push_str(&format!("- {w}\n"));
        }
        out.push('\n');
    }
    if let Some(ref cmd) = pack.resume_command {
        out.push_str(&format!(
            "## Suggested resume command\n`{}`\n\n",
            cmd.join(" ")
        ));
    }
    if let Some(ref tail) = pack.transcript_tail {
        out.push_str("## Transcript tail\n```\n");
        out.push_str(tail);
        if !tail.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n\n");
    }
    out.push_str(
        "Continue the task. Do not re-do completed work unless needed. \
         Fix the failure and verify.\n",
    );
    out
}

/// Apply resume injection to a launch command + environment.
///
/// - Sets BLACKBOX_RESUME_* env vars
/// - For Claude `-p` / `--print` prompts: prepends a short resume header to the prompt text
/// - For Codex `exec <prompt>`: prepends to the trailing prompt arg when present
pub fn apply_to_launch(
    command: &[String],
    env: &mut std::collections::HashMap<String, String>,
    inj: &ResumeInjection,
) -> Vec<String> {
    env.insert(
        ENV_RESUME_FILE.to_string(),
        inj.file_path.display().to_string(),
    );
    env.insert(ENV_RESUME_RUN_ID.to_string(), inj.run_id.clone());
    env.insert(ENV_RESUME_HINT.to_string(), inj.hint.clone());

    let mut cmd = command.to_vec();
    if cmd.is_empty() {
        return cmd;
    }

    let basename = Path::new(&cmd[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd[0].as_str())
        .to_ascii_lowercase();

    // Compact preamble for argv (avoid huge prompts)
    let compact = compact_preamble(inj);

    if basename.contains("claude") {
        // Find -p / --print value and prepend
        prepend_prompt_after_flag(&mut cmd, &["-p", "--print"], &compact);
    } else if basename.contains("codex") {
        // `codex exec "prompt"` — last non-flag arg after exec
        if let Some(exec_idx) = cmd.iter().position(|a| a == "exec") {
            if exec_idx + 1 < cmd.len() {
                let prompt_idx = cmd.len() - 1;
                if prompt_idx > exec_idx && !cmd[prompt_idx].starts_with('-') {
                    cmd[prompt_idx] = format!("{compact}\n\n{}", cmd[prompt_idx]);
                }
            }
        }
    } else if basename == "aider" || basename.contains("gemini") || basename.contains("grok") {
        // Best-effort: prepend to last non-flag arg
        if let Some(i) = cmd
            .iter()
            .rposition(|a| !a.starts_with('-') && a != &cmd[0])
        {
            if i > 0 {
                cmd[i] = format!("{compact}\n\n{}", cmd[i]);
            }
        }
    }

    cmd
}

fn compact_preamble(inj: &ResumeInjection) -> String {
    let mut s = format!(
        "[blackbox resume {}] Prior run failed (exit={:?}). See {} for full context.\n",
        inj.short_id,
        inj.pack.summary.exit_code,
        inj.file_path.display()
    );
    if !inj.pack.failed_tools.is_empty() {
        s.push_str("Failed tools: ");
        let names: Vec<_> = inj
            .pack
            .failed_tools
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        s.push_str(&names.join(", "));
        s.push('\n');
    }
    s.push_str("Continue from that failure; do not restart from scratch unless necessary.");
    // Cap argv injection size
    if s.len() > 1500 {
        s.truncate(s.floor_char_boundary(1500));
        s.push('…');
    }
    s
}

fn prepend_prompt_after_flag(cmd: &mut [String], flags: &[&str], preamble: &str) {
    for i in 0..cmd.len() {
        if flags.iter().any(|f| cmd[i] == *f) && i + 1 < cmd.len() {
            cmd[i + 1] = format!("{preamble}\n\n{}", cmd[i + 1]);
            return;
        }
        for f in flags {
            let prefix = format!("{f}=");
            if cmd[i].starts_with(&prefix) {
                let rest = &cmd[i][prefix.len()..];
                cmd[i] = format!("{f}={preamble}\n\n{rest}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_claude_p() {
        let mut cmd = vec!["claude".into(), "-p".into(), "fix the bug".into()];
        prepend_prompt_after_flag(&mut cmd, &["-p", "--print"], "RESUME");
        assert!(cmd[2].starts_with("RESUME"));
        assert!(cmd[2].contains("fix the bug"));
    }

    #[test]
    fn auto_resume_env_off() {
        std::env::set_var(ENV_AUTO_RESUME, "0");
        assert!(!auto_resume_enabled(None));
        std::env::remove_var(ENV_AUTO_RESUME);
    }
}
