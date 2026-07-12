//! One-command postmortem / summary for a run.

use chrono::Utc;
use serde::Serialize;

use crate::analysis::error_detector::ErrorDetector;
use crate::core::event::{EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::storage::TraceStore;
use crate::views::{ResumeView, StructuredErrorView};

const DEFAULT_LIMIT: usize = 10_000;
const SHORT_LIMIT: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct SummaryView {
    pub run_id: String,
    pub short_id: String,
    pub status: crate::core::run::RunStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub command: Vec<String>,
    pub tags: Vec<String>,
    pub tools: ToolsSummary,
    pub errors: Vec<StructuredErrorView>,
    pub side_effects: Vec<SideEffectSample>,
    pub git: GitSummary,
    pub resume: ResumeView,
    pub truncated: bool,
    pub events_scanned: usize,
    pub total_events: Option<usize>,
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolsSummary {
    pub total: usize,
    pub failed: usize,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SideEffectSample {
    pub sequence: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitSummary {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SummaryOptions {
    pub short: bool,
    pub full: bool,
}

/// Build a SummaryView using SQL-limited event fetch.
pub async fn build_summary(
    store: &dyn TraceStore,
    run: &Run,
    opts: SummaryOptions,
) -> anyhow::Result<SummaryView> {
    let limit = if opts.short {
        SHORT_LIMIT
    } else if opts.full {
        DEFAULT_LIMIT * 2
    } else {
        DEFAULT_LIMIT
    };

    let total = store.count_events(&run.id).await.ok();
    let (events, truncated) = store.get_events_limited(&run.id, limit).await?;
    let events_scanned = events.len();
    let truncated = truncated || total.map(|t| t > events_scanned).unwrap_or(false);

    let detector = ErrorDetector::new();
    let mut errors = Vec::new();
    for ev in &events {
        for err in detector.extract_errors(ev) {
            errors.push(StructuredErrorView {
                sequence: ev.sequence,
                error_type: err.error_type,
                message: err.message,
                file: err.file,
                line: err.line,
            });
        }
        if matches!(ev.status, EventStatus::Error) && errors.len() < 50 {
            // already covered by extract; skip noise
        }
    }
    // Cap errors for agent consumption
    errors.truncate(40);

    let mut tool_names = Vec::new();
    let mut tools_failed = 0usize;
    let mut tools_total = 0usize;
    for ev in &events {
        if ev.kind == "tool.call" {
            tools_total += 1;
            if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
                if !tool_names.iter().any(|n| n == name) {
                    tool_names.push(name.to_string());
                }
            }
            if matches!(ev.status, EventStatus::Error) {
                tools_failed += 1;
            }
        }
        if ev.kind == "tool.result" && matches!(ev.status, EventStatus::Error) {
            tools_failed += 1;
        }
    }

    let mut side_effects = Vec::new();
    if !opts.short {
        for ev in events.iter().filter(|e| {
            matches!(
                e.side_effect,
                crate::core::event::SideEffect::LocalWrite
                    | crate::core::event::SideEffect::ExternalWrite
                    | crate::core::event::SideEffect::Destructive
            )
        }) {
            side_effects.push(SideEffectSample {
                sequence: ev.sequence,
                kind: ev.kind.clone(),
                detail: ev
                    .metadata
                    .get("path")
                    .or_else(|| ev.metadata.get("tool_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
            if side_effects.len() >= 20 {
                break;
            }
        }
    }

    let mut git_start = None;
    let mut git_end = None;
    for ev in &events {
        if ev.kind == "git.commit" {
            git_start = ev
                .metadata
                .get("commit")
                .and_then(|v| v.as_str())
                .map(|s| s.chars().take(12).collect());
        }
        if ev.kind == "git.commit.after" {
            git_end = ev
                .metadata
                .get("commit")
                .and_then(|v| v.as_str())
                .map(|s| s.chars().take(12).collect());
        }
    }

    let checkpoints = store.get_checkpoints(&run.id).await.unwrap_or_default();
    let resume_cmd = crate::resume::resume_command(run, &events, &checkpoints);

    let duration_ms = match (run.started_at, run.ended_at) {
        (s, Some(e)) => Some((e - s).num_milliseconds().max(0) as u64),
        _ => {
            let now = Utc::now();
            Some((now - run.started_at).num_milliseconds().max(0) as u64)
        }
    };

    let short = crate::util::short_id(&run.id).to_string();
    let mut hints = vec![
        format!("blackbox timeline {} --semantic", short),
        format!("blackbox analyze {}", short),
        format!("blackbox show {} --tools", short),
    ];
    if resume_cmd.is_some() {
        hints.push(format!("blackbox fork {} --launch", short));
    }
    if truncated {
        hints.push("summary truncated; use --full or inspect timeline".into());
    }

    Ok(SummaryView {
        run_id: run.id.clone(),
        short_id: short,
        status: run.status.clone(),
        exit_code: run.exit_code,
        duration_ms,
        command: run.command.clone(),
        tags: run.tags.clone(),
        tools: ToolsSummary {
            total: tools_total,
            failed: tools_failed,
            names: tool_names,
        },
        errors,
        side_effects,
        git: GitSummary {
            start: git_start,
            end: git_end,
        },
        resume: ResumeView {
            available: resume_cmd.is_some(),
            command: resume_cmd,
        },
        truncated,
        events_scanned,
        total_events: total,
        hints,
    })
}

/// Human-readable summary text.
pub fn format_summary_text(s: &SummaryView) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Postmortem {}  status={:?}  exit={:?}  duration_ms={:?}\n",
        s.short_id, s.status, s.exit_code, s.duration_ms
    ));
    out.push_str(&format!("  command: {}\n", s.command.join(" ")));
    if !s.tags.is_empty() {
        out.push_str(&format!("  tags: {}\n", s.tags.join(", ")));
    }
    out.push_str(&format!(
        "  tools: {} total ({} failed) {}\n",
        s.tools.total,
        s.tools.failed,
        if s.tools.names.is_empty() {
            String::new()
        } else {
            format!("[{}]", s.tools.names.join(", "))
        }
    ));
    if !s.errors.is_empty() {
        out.push_str(&format!("  structured errors: {}\n", s.errors.len()));
        for e in s.errors.iter().take(10) {
            out.push_str(&format!(
                "    seq={} {} {}\n",
                e.sequence,
                e.error_type,
                e.message.chars().take(80).collect::<String>()
            ));
        }
    }
    if let (Some(a), Some(b)) = (&s.git.start, &s.git.end) {
        out.push_str(&format!("  git: {} → {}\n", a, b));
    } else if let Some(a) = &s.git.start {
        out.push_str(&format!("  git: {}\n", a));
    }
    if s.truncated {
        out.push_str(&format!(
            "  (truncated: scanned {} of {:?})\n",
            s.events_scanned, s.total_events
        ));
    }
    out.push_str("  next:\n");
    for h in &s.hints {
        out.push_str(&format!("    {}\n", h));
    }
    out
}

// silence unused import if TraceEvent only used indirectly
#[allow(dead_code)]
fn _touch(_: &TraceEvent) {}
