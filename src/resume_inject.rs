//! Continuity / auto-resume: inject project memory into the next harness launch.

use std::path::{Path, PathBuf};

use crate::config::{resolve_continuity, BlackboxConfig, ContinuityMode};
use crate::memory::{
    build_project_memory, compact_memory_preamble, write_memory_files, MemoryBuildOptions,
    ProjectMemoryPack, MEMORY_SCHEMA,
};
use crate::state::{AttentionLevel, ProjectState};
use crate::storage::TraceStore;

/// Env vars set for auto-resume / continuity (also discoverable by harnesses/agents).
pub const ENV_AUTO_RESUME: &str = "BLACKBOX_AUTO_RESUME";
pub const ENV_RESUME_FILE: &str = "BLACKBOX_RESUME_FILE";
pub const ENV_RESUME_RUN_ID: &str = "BLACKBOX_RESUME_RUN_ID";
pub const ENV_RESUME_HINT: &str = "BLACKBOX_RESUME_HINT";
pub const ENV_MEMORY_FILE: &str = "BLACKBOX_MEMORY_FILE";
pub const ENV_MEMORY_SCHEMA: &str = "BLACKBOX_MEMORY_SCHEMA";
pub const ENV_CONTINUITY: &str = "BLACKBOX_CONTINUITY";

/// Whether auto-resume is active (config + env) — 1.1 compat (true when continuity ≠ off).
pub fn auto_resume_enabled(cfg: Option<&BlackboxConfig>) -> bool {
    resolve_continuity(cfg, false, false) != ContinuityMode::Off
}

/// Materialized continuity injection for a launch.
#[derive(Debug, Clone)]
pub struct ResumeInjection {
    pub run_id: String,
    pub short_id: String,
    pub file_path: PathBuf,
    pub preamble: String,
    pub hint: String,
    /// Legacy single-run-shaped fields kept for apply_to_launch / tests.
    pub pack: crate::context::ContextPackView,
    /// Full project memory pack (1.2).
    pub memory: ProjectMemoryPack,
    /// Predecessor for parent_run_id when attention ≥ continue.
    pub predecessor_run_id: Option<String>,
    pub attention_level: AttentionLevel,
}

/// Options for continuity prepare.
#[derive(Debug, Clone)]
pub struct ContinuityPrepareOpts {
    pub max_tokens: usize,
    pub continuity: ContinuityMode,
    pub project_root: PathBuf,
    pub store_db: PathBuf,
    /// End-of-run write path: always write MEMORY when continuity ≠ off.
    pub end_of_run_write: bool,
}

impl Default for ContinuityPrepareOpts {
    fn default() -> Self {
        Self {
            max_tokens: 4000,
            continuity: ContinuityMode::Always,
            project_root: PathBuf::from("."),
            store_db: PathBuf::from(".blackbox/blackbox.db"),
            end_of_run_write: false,
        }
    }
}

/// Build resume injection from sticky state + store when continuity requires launch inject.
///
/// 1.1-compatible entry: uses attention/failure gate equivalent to continuity=attention.
pub async fn prepare_resume_injection(
    store: &dyn TraceStore,
    blackbox_root: &Path,
    max_tokens: usize,
) -> anyhow::Result<Option<ResumeInjection>> {
    prepare_continuity_injection(
        Some(store),
        blackbox_root,
        ContinuityPrepareOpts {
            max_tokens,
            continuity: ContinuityMode::Attention,
            project_root: blackbox_root
                .parent()
                .unwrap_or(blackbox_root)
                .to_path_buf(),
            store_db: blackbox_root.join("blackbox.db"),
            end_of_run_write: false,
        },
    )
    .await
}

/// Prepare continuity injection (launch path).
///
/// Returns None when continuity is off, or attention-only with attention_level=none.
pub async fn prepare_continuity_injection(
    store: Option<&dyn TraceStore>,
    blackbox_root: &Path,
    opts: ContinuityPrepareOpts,
) -> anyhow::Result<Option<ResumeInjection>> {
    if opts.continuity == ContinuityMode::Off {
        return Ok(None);
    }

    // Load sticky under brief lock for consistent snapshot
    let sticky = match crate::state::with_state_lock(blackbox_root, |state| {
        state.expire_claim_if_needed(chrono::Utc::now());
        Ok(state.clone())
    }) {
        Ok(s) => s,
        Err(_) => ProjectState::load(blackbox_root)?.unwrap_or_default(),
    };

    // Launch inject gate
    if opts.continuity == ContinuityMode::Attention && sticky.attention_level.is_none() {
        // Also honor 1.1: last_run failed/cancelled even if level unset on stale sticky
        let bad = sticky
            .last_run
            .as_ref()
            .map(|r| r.status == "failed" || r.status == "cancelled")
            .unwrap_or(false);
        if !bad && !sticky.attention_needed {
            return Ok(None);
        }
    }

    let pack = build_project_memory(
        store,
        &sticky,
        MemoryBuildOptions {
            max_tokens: opts.max_tokens,
            purpose: "for-resume".into(),
            continuity_mode: opts.continuity.as_str().into(),
            project_root: opts.project_root.clone(),
            store_db: opts.store_db.clone(),
            skip_porcelain_if_none: sticky.attention_level.is_none(),
        },
    )
    .await?;

    let file_path = write_memory_files(blackbox_root, &pack, true)?;
    // Touch memory_updated_at best-effort
    let _ = crate::state::with_state_lock(blackbox_root, |state| {
        state.memory_updated_at = Some(chrono::Utc::now());
        Ok(())
    });

    let run_id = pack
        .focus_run_id
        .clone()
        .or_else(|| pack.last_run.as_ref().map(|r| r.id.clone()))
        .unwrap_or_default();
    let short = if run_id.is_empty() {
        "none".into()
    } else {
        crate::util::short_id(&run_id).to_string()
    };

    let preamble = compact_memory_preamble(&pack, &file_path);
    let hint = format!(
        "blackbox project memory (attention={}, continuity={}). Full pack: {}",
        pack.attention_level,
        pack.continuity_mode,
        file_path.display()
    );

    let predecessor_run_id = if sticky.attention_level.at_least_continue() {
        pack.predecessor_run
            .as_ref()
            .map(|r| r.id.clone())
            .or(pack.focus_run_id.clone())
    } else {
        None
    };

    // Legacy ContextPackView bridge for older apply paths / tests
    let legacy = memory_to_context_pack(&pack, &run_id, &short);

    Ok(Some(ResumeInjection {
        run_id,
        short_id: short,
        file_path,
        preamble,
        hint,
        pack: legacy,
        memory: pack,
        predecessor_run_id,
        attention_level: sticky.attention_level,
    }))
}

/// End-of-run: always refresh MEMORY files when continuity ≠ off.
pub async fn refresh_memory_files_end_of_run(
    store: Option<&dyn TraceStore>,
    blackbox_root: &Path,
    project_root: &Path,
    store_db: &Path,
    continuity: ContinuityMode,
    max_tokens: usize,
) -> anyhow::Result<Option<PathBuf>> {
    if continuity == ContinuityMode::Off {
        return Ok(None);
    }
    let sticky = ProjectState::load(blackbox_root)?.unwrap_or_default();
    let pack = build_project_memory(
        store,
        &sticky,
        MemoryBuildOptions {
            max_tokens,
            purpose: "project-memory".into(),
            continuity_mode: continuity.as_str().into(),
            project_root: project_root.to_path_buf(),
            store_db: store_db.to_path_buf(),
            skip_porcelain_if_none: sticky.attention_level.is_none(),
        },
    )
    .await?;
    let path = write_memory_files(blackbox_root, &pack, true)?;
    let _ = crate::state::with_state_lock(blackbox_root, |state| {
        state.memory_updated_at = Some(chrono::Utc::now());
        Ok(())
    });
    Ok(Some(path))
}

fn memory_to_context_pack(
    pack: &ProjectMemoryPack,
    run_id: &str,
    short_id: &str,
) -> crate::context::ContextPackView {
    use crate::summary::{GitSummary, SummaryView, ToolsSummary};
    use crate::views::ResumeView;
    crate::context::ContextPackView {
        run_id: run_id.to_string(),
        short_id: short_id.to_string(),
        purpose: pack.purpose.clone(),
        headline: pack.headline.clone(),
        next_action: pack.next_action.clone(),
        attention_reason: pack.attention_reason.clone(),
        summary: pack.summary.clone().unwrap_or(SummaryView {
            run_id: run_id.to_string(),
            short_id: short_id.to_string(),
            status: crate::core::run::RunStatus::Unknown,
            exit_code: None,
            duration_ms: None,
            command: vec![],
            tags: vec![],
            tools: ToolsSummary {
                total: 0,
                failed: 0,
                names: vec![],
            },
            errors: vec![],
            side_effects: vec![],
            git: GitSummary {
                start: None,
                end: None,
            },
            resume: ResumeView {
                available: false,
                command: None,
            },
            truncated: false,
            events_scanned: 0,
            total_events: None,
            hints: vec![],
            failure_fix_chains: vec![],
            narrative: String::new(),
            capture_coverage: None,
            retry_waste: vec![],
            turning_points: vec![],
            next_action: String::new(),
            evidence: vec![],
            headline: String::new(),
            anomalies: vec![],
            claims: vec![],
            goal_source: "unavailable".into(),
            goal: "goal unavailable".into(),
            verification_coverage: None,
        }),
        failed_tools: pack.failed_tools.clone(),
        errors_top: pack.errors_top.clone(),
        last_tools: pack.last_tools.clone(),
        filesystem_writes: pack.files_touched.clone(),
        transcript_tail: pack.transcript_tail.clone(),
        resume_command: pack.resume_command.clone(),
        approx_tokens: pack.approx_tokens,
        truncated: pack.truncated,
    }
}

/// Apply continuity injection to a launch command + environment.
///
/// - Sets BLACKBOX_RESUME_* and BLACKBOX_MEMORY_* env vars
/// - For Claude `-p` / `--print` prompts: prepends compact memory preamble
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
    env.insert(
        ENV_MEMORY_FILE.to_string(),
        inj.file_path.display().to_string(),
    );
    env.insert(ENV_MEMORY_SCHEMA.to_string(), MEMORY_SCHEMA.to_string());
    env.insert(ENV_CONTINUITY.to_string(), "1".to_string());

    let mut cmd = command.to_vec();
    if cmd.is_empty() {
        return cmd;
    }

    let basename = Path::new(&cmd[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd[0].as_str())
        .to_ascii_lowercase();

    let compact = if inj.preamble.is_empty() {
        compact_memory_preamble(&inj.memory, &inj.file_path)
    } else {
        inj.preamble.clone()
    };

    if basename.contains("claude") {
        prepend_prompt_after_flag(&mut cmd, &["-p", "--print"], &compact);
    } else if basename.contains("codex") {
        if let Some(exec_idx) = cmd.iter().position(|a| a == "exec") {
            if exec_idx + 1 < cmd.len() {
                let prompt_idx = cmd.len() - 1;
                if prompt_idx > exec_idx && !cmd[prompt_idx].starts_with('-') {
                    cmd[prompt_idx] = format!("{compact}\n\n{}", cmd[prompt_idx]);
                }
            }
        }
    } else if basename == "aider" || basename.contains("gemini") || basename.contains("grok") {
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
        std::env::remove_var("BLACKBOX_CONTINUITY");
        assert!(!auto_resume_enabled(None));
        std::env::remove_var(ENV_AUTO_RESUME);
    }

    #[test]
    fn continuity_cli_auto_resume_forces_always() {
        std::env::remove_var("BLACKBOX_CONTINUITY");
        std::env::remove_var(ENV_AUTO_RESUME);
        assert_eq!(
            resolve_continuity(None, false, true),
            ContinuityMode::Always
        );
        assert_eq!(resolve_continuity(None, true, false), ContinuityMode::Off);
    }
}
