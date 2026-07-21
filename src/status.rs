//! Project status / agent handoff views.

use serde::Serialize;

use crate::config::ProjectDiscovery;
use crate::context::{build_context_pack, ContextOptions, ContextPackView};
use crate::core::run::RunStatus;
use crate::memory::{build_project_memory, MemoryBuildOptions, ProjectMemoryPack};
use crate::state::{AttentionLevel, ProjectState, RunPointer};
use crate::storage::TraceStore;

#[derive(Debug, Serialize)]
/// `StatusView` value.
pub struct StatusView {
    /// Project root.
    pub project_root: String,
    /// Store db.
    pub store_db: String,
    /// Enabled.
    pub enabled: bool,
    /// Hard observe-only mode (no launch mutation / continuity inject).
    pub observe_only: bool,
    /// Continuity plane mode: always | attention | off.
    pub continuity_mode: String,
    /// Wrap.
    pub wrap: Vec<String>,
    /// Shell integration.
    pub shell_integration: ShellIntegrationView,
    /// Retention.
    pub retention: RetentionStatusView,
    /// Last run.
    pub last_run: Option<RunPointer>,
    /// Last failure.
    pub last_failure: Option<RunPointer>,
    /// Attention.
    pub attention: AttentionView,
    /// Next commands.
    pub next_commands: Vec<String>,
    /// Agent instructions.
    pub agent_instructions: Option<String>,
    /// Present when resume pack is requested and a target run exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_pack: Option<ContextPackView>,
    /// Project memory pack (1.2); present when enabled and built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_memory: Option<ProjectMemoryPack>,
    /// Product posture: recorder | continuity.
    #[serde(default)]
    pub product_mode: String,
    /// First-class postmortem excerpt for handoff (when resume pack requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postmortem: Option<PostmortemHandoffView>,
}

#[derive(Debug, Serialize)]
/// `PostmortemHandoffView` value.
pub struct PostmortemHandoffView {
    /// Owning run id.
    pub run_id: String,
    /// Short id.
    pub short_id: String,
    /// Narrative.
    pub narrative: String,
    /// Next action.
    pub next_action: String,
    /// Failure count.
    pub failure_count: usize,
    /// Turning points.
    pub turning_points: Vec<String>,
}

#[derive(Debug, Serialize)]
/// `ShellIntegrationView` value.
pub struct ShellIntegrationView {
    /// Detected shell.
    pub detected_shell: String,
    /// True if any managed wrapper block is present in fish/bash/zsh rc paths.
    pub installed: bool,
    /// Paths that currently contain a managed blackbox block.
    pub paths: Vec<String>,
    /// Legacy single path for the detected shell (may be uninstalled).
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
/// `RetentionStatusView` value.
pub struct RetentionStatusView {
    /// Keep runs.
    pub keep_runs: u32,
    /// Max age days.
    pub max_age_days: Option<u32>,
    /// Auto apply.
    pub auto_apply: bool,
    /// Auto gc blobs.
    pub auto_gc_blobs: bool,
}

#[derive(Debug, Serialize)]
/// `AttentionView` value.
pub struct AttentionView {
    /// Needed.
    pub needed: bool,
    /// Additive 1.2 field.
    pub level: AttentionLevel,
    /// Reason.
    pub reason: Option<String>,
    /// Owning run id.
    pub run_id: Option<String>,
}

#[derive(Debug, Clone)]
/// `StatusOptions` value.
pub struct StatusOptions {
    /// Include resume.
    pub include_resume: bool,
    /// Max tokens.
    pub max_tokens: usize,
    /// When true, attach resume pack for last_run even without attention (handoff).
    pub force_resume: bool,
    /// Attach project_memory when project enabled (handoff default).
    pub include_project_memory: bool,
}

impl Default for StatusOptions {
    fn default() -> Self {
        Self {
            include_resume: false,
            max_tokens: 4000,
            force_resume: false,
            include_project_memory: false,
        }
    }
}

/// Build status.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `build_status` — see module docs for full workflow.
/// ```
pub async fn build_status(
    discovery: &ProjectDiscovery,
    store: Option<&dyn TraceStore>,
    opts: StatusOptions,
) -> anyhow::Result<StatusView> {
    let cfg = discovery.config.clone().unwrap_or_default();

    let sticky = ProjectState::load(&discovery.paths.root)?.unwrap_or_default();

    // Prefer sticky state; fall back to DB latest if store open.
    let mut last_run = sticky.last_run.clone();
    let mut last_failure = sticky.last_failure.clone();
    if last_run.is_none() {
        if let Some(store) = store {
            if let Ok(runs) = store.list_runs().await {
                if let Some(r) = runs.first() {
                    last_run = Some(RunPointer::from_run(r));
                }
                if last_failure.is_none() {
                    last_failure = runs
                        .iter()
                        .find(|r| matches!(r.status, RunStatus::Failed | RunStatus::Cancelled))
                        .map(RunPointer::from_run);
                }
            }
        }
    }

    let last_is_bad = last_run
        .as_ref()
        .map(|r| r.status == "failed" || r.status == "cancelled")
        .unwrap_or(false);

    let mut attention_level = sticky.attention_level;
    if attention_level.is_none() && (sticky.attention_needed || last_is_bad) {
        attention_level = AttentionLevel::Continue;
    }
    let attention_needed = !attention_level.is_none();

    // Status attention.run_id: unresolved failure first, else last_run when wip/continue
    let attention_run_id = if attention_needed {
        sticky.unresolved_failure_id.clone().or_else(|| {
            if last_is_bad {
                last_run.as_ref().map(|r| r.id.clone())
            } else {
                last_failure
                    .as_ref()
                    .map(|r| r.id.clone())
                    .or_else(|| last_run.as_ref().map(|r| r.id.clone()))
            }
        })
    } else {
        None
    };

    let attention_reason = if attention_needed {
        sticky.attention_reason.clone().or_else(|| {
            last_run.as_ref().and_then(|r| {
                if r.status == "failed" || r.status == "cancelled" {
                    Some(format!(
                        "last run {} ended with status {}",
                        r.short_id, r.status
                    ))
                } else {
                    last_failure
                        .as_ref()
                        .map(|f| format!("unresolved failure {} ({})", f.short_id, f.status))
                }
            })
        })
    } else {
        None
    };

    let attention = AttentionView {
        needed: attention_needed,
        level: attention_level,
        reason: attention_reason,
        run_id: attention_run_id,
    };

    let mut next_commands = Vec::new();
    if !discovery.paths.root.join("config.toml").exists() {
        next_commands.push("blackbox enable".into());
        next_commands.push("blackbox enable --install-shell".into());
    } else if !cfg.enabled {
        next_commands.push("blackbox enable".into());
    }

    if attention.needed {
        if let Some(ref id) = attention.run_id {
            let short = crate::util::short_id(id);
            next_commands.push("blackbox memory show --json".into());
            next_commands.push(format!(
                "blackbox context {short} --for-resume --json --max-tokens {}",
                opts.max_tokens
            ));
            next_commands.push(format!("blackbox postmortem {short} --json"));
            next_commands.push("blackbox handoff --json".into());
        }
    } else if last_run.is_some() {
        next_commands.push("blackbox memory show --json".into());
        next_commands.push("blackbox runs --json".into());
        next_commands.push("blackbox postmortem latest --json".into());
    } else {
        next_commands.push("blackbox run -- echo hello".into());
    }

    let agent_path = discovery.paths.root.join("AGENT.md");
    let agent_instructions = if agent_path.exists() {
        Some(agent_path.display().to_string())
    } else {
        None
    };

    let shell = crate::shell_install::ShellKind::detect();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut installed_paths = Vec::new();
    if let Some(ref h) = home {
        for kind in [
            crate::shell_install::ShellKind::Fish,
            crate::shell_install::ShellKind::Bash,
            crate::shell_install::ShellKind::Zsh,
            crate::shell_install::ShellKind::PowerShell,
        ] {
            let p = crate::shell_install::rc_path(kind, h);
            if std::fs::read_to_string(&p)
                .map(|t| t.contains(crate::shell_install::BEGIN_MARKER))
                .unwrap_or(false)
            {
                installed_paths.push(p.display().to_string());
            }
        }
    }
    let installed = !installed_paths.is_empty();
    let rc = home
        .as_ref()
        .map(|h| crate::shell_install::rc_path(shell, h));

    let mut resume_pack = None;
    let want_resume = opts.include_resume && (opts.force_resume || attention.needed);
    if want_resume {
        if let Some(store) = store {
            let target_id = attention
                .run_id
                .as_ref()
                .or_else(|| last_run.as_ref().map(|r| &r.id));
            if let Some(run_id) = target_id {
                if let Ok(Some(run)) = store.get_run(run_id).await {
                    if let Ok(pack) = build_context_pack(
                        store,
                        &run,
                        ContextOptions {
                            max_tokens: opts.max_tokens,
                            include_transcript: true,
                        },
                    )
                    .await
                    {
                        resume_pack = Some(pack);
                    }
                }
            }
        }
    }

    let mut project_memory = None;
    let enabled = cfg.enabled && discovery.config.is_some();
    if opts.include_project_memory && enabled {
        let continuity = cfg.capture.continuity_from_config();
        if let Ok(pack) = build_project_memory(
            store,
            &sticky,
            MemoryBuildOptions {
                max_tokens: opts.max_tokens,
                purpose: "handoff".into(),
                continuity_mode: continuity.as_str().into(),
                project_root: discovery.project_root.clone(),
                store_db: discovery.paths.db_path.clone(),
                skip_porcelain_if_none: sticky.attention_level.is_none(),
            },
        )
        .await
        {
            project_memory = Some(pack);
        }
    }

    let observe_only = cfg.capture.observe_only;
    let continuity_mode = if observe_only {
        "off".to_string()
    } else {
        cfg.capture.continuity_from_config().as_str().to_string()
    };
    let product_mode = cfg.capture.product_mode().as_str().to_string();

    // Attach postmortem for handoff when resume pack is requested and we have a target run.
    let mut postmortem = None;
    if opts.force_resume || opts.include_resume {
        if let Some(store) = store {
            let target = attention
                .run_id
                .as_ref()
                .or_else(|| last_run.as_ref().map(|r| &r.id));
            if let Some(run_id) = target {
                if let Ok(Some(run)) = store.get_run(run_id).await {
                    if let Ok(summary) = crate::summary::build_summary(
                        store,
                        &run,
                        crate::summary::SummaryOptions {
                            short: true,
                            full: false,
                        },
                    )
                    .await
                    {
                        // Prefer headline + next_action for agents; keep short narrative.
                        let narrative = if !summary.headline.is_empty() {
                            format!(
                                "{}\n{}",
                                summary.headline,
                                summary.narrative.chars().take(1000).collect::<String>()
                            )
                        } else {
                            summary.narrative.chars().take(1200).collect()
                        };
                        postmortem = Some(PostmortemHandoffView {
                            run_id: summary.run_id.clone(),
                            short_id: summary.short_id.clone(),
                            narrative,
                            next_action: summary.next_action.clone(),
                            failure_count: summary.errors.len() + summary.tools.failed,
                            turning_points: summary
                                .turning_points
                                .iter()
                                .map(|p| format!("[{}] {}", p.kind, p.detail))
                                .collect(),
                        });
                    }
                }
            }
        }
    }

    Ok(StatusView {
        project_root: discovery.project_root.display().to_string(),
        store_db: discovery.paths.db_path.display().to_string(),
        enabled,
        observe_only,
        continuity_mode,
        wrap: cfg.capture.wrap,
        shell_integration: ShellIntegrationView {
            detected_shell: shell.as_str().into(),
            installed,
            paths: installed_paths,
            path: rc.map(|p| p.display().to_string()),
        },
        retention: RetentionStatusView {
            keep_runs: cfg.retention.keep_runs,
            max_age_days: cfg.retention.max_age_days,
            auto_apply: cfg.retention.auto_apply,
            auto_gc_blobs: cfg.retention.auto_gc_blobs,
        },
        last_run,
        last_failure,
        attention,
        next_commands,
        agent_instructions,
        resume_pack,
        project_memory,
        product_mode,
        postmortem,
    })
}

/// Format status text.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `format_status_text` — see module docs for full workflow.
/// ```
pub fn format_status_text(v: &StatusView) -> String {
    let mut out = String::new();
    out.push_str(&format!("blackbox status — {}\n", v.project_root));
    out.push_str(&format!(
        "  enabled: {}   store: {}\n",
        v.enabled, v.store_db
    ));
    out.push_str(&format!("  product: {}\n", v.product_mode));
    if v.observe_only {
        out.push_str("  mode: observe-only (no continuity, no prompt mutation)\n");
    } else {
        out.push_str(&format!("  mode: continuity={}\n", v.continuity_mode));
    }
    if let Some(ref pm) = v.postmortem {
        out.push_str(&format!(
            "  postmortem: {} next_action={}\n",
            pm.short_id, pm.next_action
        ));
    }
    out.push_str(&format!("  wrap: {}\n", v.wrap.join(", ")));
    if v.shell_integration.installed {
        out.push_str(&format!(
            "  shell: detected={} · wrappers installed in {}\n",
            v.shell_integration.detected_shell,
            v.shell_integration.paths.join(", ")
        ));
    } else {
        out.push_str(&format!(
            "  shell: detected={} · wrappers NOT installed — run: blackbox enable --install-shell\n",
            v.shell_integration.detected_shell
        ));
    }
    out.push_str(&format!(
        "  retention: keep={} max_age_days={:?} auto_apply={}\n",
        v.retention.keep_runs, v.retention.max_age_days, v.retention.auto_apply
    ));
    if let Some(ref r) = v.last_run {
        out.push_str(&format!(
            "  last_run: {}  {}  exit={:?}  {}\n",
            r.short_id, r.status, r.exit_code, r.command_preview
        ));
    } else {
        out.push_str("  last_run: (none)\n");
    }
    if v.attention.needed {
        out.push_str(&format!(
            "  ATTENTION [{}]: {}\n",
            v.attention.level.as_str(),
            v.attention
                .reason
                .as_deref()
                .unwrap_or("check last failure")
        ));
    } else {
        out.push_str("  attention: none\n");
    }
    if let Some(ref p) = v.agent_instructions {
        out.push_str(&format!("  agent instructions: {p}\n"));
    }
    if !v.next_commands.is_empty() {
        out.push_str("  next:\n");
        for c in &v.next_commands {
            out.push_str(&format!("    {c}\n"));
        }
    }
    if let Some(ref pack) = v.project_memory {
        out.push_str(&format!(
            "  project_memory: attached (≈{} tokens{}, attention={})\n",
            pack.approx_tokens,
            if pack.truncated { ", truncated" } else { "" },
            pack.attention_level
        ));
        if !pack.headline.is_empty() {
            out.push_str(&format!("    headline: {}\n", pack.headline));
        }
        if !pack.next_action.is_empty() {
            out.push_str(&format!("    next_action: {}\n", pack.next_action));
        }
    }
    if let Some(ref pack) = v.resume_pack {
        out.push_str(&format!(
            "  resume_pack: attached (≈{} tokens{})\n",
            pack.approx_tokens,
            if pack.truncated { ", truncated" } else { "" }
        ));
        if !pack.headline.is_empty() {
            out.push_str(&format!("    headline: {}\n", pack.headline));
        }
        if !pack.next_action.is_empty() {
            out.push_str(&format!("    next_action: {}\n", pack.next_action));
        }
    }
    out
}
