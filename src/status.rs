//! Project status / agent handoff views.

use serde::Serialize;

use crate::config::ProjectDiscovery;
use crate::context::{build_context_pack, ContextOptions, ContextPackView};
use crate::core::run::RunStatus;
use crate::state::{ProjectState, RunPointer};
use crate::storage::TraceStore;

#[derive(Debug, Serialize)]
pub struct StatusView {
    pub project_root: String,
    pub store_db: String,
    pub enabled: bool,
    pub wrap: Vec<String>,
    pub shell_integration: ShellIntegrationView,
    pub retention: RetentionStatusView,
    pub last_run: Option<RunPointer>,
    pub last_failure: Option<RunPointer>,
    pub attention: AttentionView,
    pub next_commands: Vec<String>,
    pub agent_instructions: Option<String>,
    /// Present when resume pack is requested and a target run exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_pack: Option<ContextPackView>,
}

#[derive(Debug, Serialize)]
pub struct ShellIntegrationView {
    pub detected_shell: String,
    /// True if any managed wrapper block is present in fish/bash/zsh rc paths.
    pub installed: bool,
    /// Paths that currently contain a managed blackbox block.
    pub paths: Vec<String>,
    /// Legacy single path for the detected shell (may be uninstalled).
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RetentionStatusView {
    pub keep_runs: u32,
    pub max_age_days: Option<u32>,
    pub auto_apply: bool,
    pub auto_gc_blobs: bool,
}

#[derive(Debug, Serialize)]
pub struct AttentionView {
    pub needed: bool,
    pub reason: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StatusOptions {
    pub include_resume: bool,
    pub max_tokens: usize,
    /// When true, attach resume pack for last_run even without attention (handoff).
    pub force_resume: bool,
}

impl Default for StatusOptions {
    fn default() -> Self {
        Self {
            include_resume: false,
            max_tokens: 4000,
            force_resume: false,
        }
    }
}

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

    let attention_needed = sticky.attention_needed || last_is_bad;
    let attention_run_id = if attention_needed {
        if last_is_bad {
            last_run.as_ref().map(|r| r.id.clone())
        } else {
            last_failure
                .as_ref()
                .map(|r| r.id.clone())
                .or_else(|| last_run.as_ref().map(|r| r.id.clone()))
        }
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
            next_commands.push(format!(
                "blackbox context {short} --for-resume --json --max-tokens {}",
                opts.max_tokens
            ));
            next_commands.push(format!("blackbox postmortem {short} --json"));
            next_commands.push("blackbox handoff --json".into());
        }
    } else if last_run.is_some() {
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

    Ok(StatusView {
        project_root: discovery.project_root.display().to_string(),
        store_db: discovery.paths.db_path.display().to_string(),
        enabled: cfg.enabled && discovery.config.is_some(),
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
    })
}

pub fn format_status_text(v: &StatusView) -> String {
    let mut out = String::new();
    out.push_str(&format!("blackbox status — {}\n", v.project_root));
    out.push_str(&format!(
        "  enabled: {}   store: {}\n",
        v.enabled, v.store_db
    ));
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
            "  ATTENTION: {}\n",
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
    if let Some(ref pack) = v.resume_pack {
        out.push_str(&format!(
            "  resume_pack: attached (≈{} tokens{})\n",
            pack.approx_tokens,
            if pack.truncated { ", truncated" } else { "" }
        ));
    }
    out
}
