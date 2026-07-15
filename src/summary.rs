//! One-command postmortem / summary for a run.

use chrono::Utc;
use serde::Serialize;

use crate::analysis::error_detector::ErrorDetector;
use crate::analysis::failure_fix::FailureFixCorrelator;
use crate::core::event::EventStatus;
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
    /// Failure-to-fix correlation chains.
    #[serde(default)]
    pub failure_fix_chains: Vec<FailureFixChainView>,
    /// Narrative summary of what happened.
    #[serde(default)]
    pub narrative: String,
    /// Capture coverage summary.
    #[serde(default)]
    pub capture_coverage: Option<CaptureCoverageView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureFixChainView {
    pub error_message: String,
    pub files_changed: Vec<String>,
    pub retry_occurred: bool,
    pub retry_successful: Option<bool>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CaptureCoverageView {
    pub total_events: u64,
    pub surfaces: Vec<SurfaceView>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SurfaceView {
    pub name: String,
    pub enabled: bool,
    pub events_count: u64,
    pub note: Option<String>,
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

    // ── Failure-to-fix correlation ───────────────────────────────────
    let fix_corr = FailureFixCorrelator::new();
    let fix_chains: Vec<FailureFixChainView> = fix_corr
        .find_chains(&events)
        .into_iter()
        .take(10)
        .map(|chain| FailureFixChainView {
            error_message: chain.error_message,
            files_changed: chain.files_changed,
            retry_occurred: chain.retry_occurred,
            retry_successful: chain.retry_successful,
            confidence: format!("{:?}", chain.confidence),
        })
        .collect();

    // ── Capture coverage ─────────────────────────────────────────────
    let coverage_ev = events.iter().find(|e| e.kind == "capture.coverage");
    let capture_coverage: Option<CaptureCoverageView> = coverage_ev.and_then(|ev| {
        let cov = ev.metadata.get("coverage")?;
        serde_json::from_value(cov.clone()).ok()
    });

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

    // Build narrative before moving values into SummaryView
    let narrative = build_narrative(&SummaryNarrativeData {
        command: &run.command,
        status: &run.status,
        exit_code: run.exit_code,
        tools_total,
        tools_failed,
        errors: &errors,
        fix_chains: &fix_chains,
        side_effects: &side_effects,
        git_start: &git_start,
        git_end: &git_end,
        duration_ms,
        capture_coverage: &capture_coverage,
        truncated,
        events_scanned,
        total_events: total,
    });

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
        failure_fix_chains: fix_chains,
        narrative,
        capture_coverage,
    })
}

/// Data used to build the narrative summary.
struct SummaryNarrativeData<'a> {
    command: &'a [String],
    status: &'a crate::core::run::RunStatus,
    exit_code: Option<i32>,
    tools_total: usize,
    tools_failed: usize,
    errors: &'a [StructuredErrorView],
    fix_chains: &'a [FailureFixChainView],
    side_effects: &'a [SideEffectSample],
    git_start: &'a Option<String>,
    git_end: &'a Option<String>,
    duration_ms: Option<u64>,
    capture_coverage: &'a Option<CaptureCoverageView>,
    truncated: bool,
    events_scanned: usize,
    total_events: Option<usize>,
}

/// Build a narrative summary of the run.
fn build_narrative(data: &SummaryNarrativeData) -> String {
    let mut n = String::new();

    // Opening statement
    let command_preview = if data.command.len() <= 4 {
        data.command.join(" ")
    } else {
        format!(
            "{} … ({} args)",
            data.command[..3].join(" "),
            data.command.len()
        )
    };
    n.push_str(&format!("Command: {}\n", command_preview));

    // Outcome
    match data.status {
        crate::core::run::RunStatus::Succeeded => {
            n.push_str("Outcome: SUCCESS");
            if let Some(code) = data.exit_code {
                n.push_str(&format!(" (exit code {})", code));
            }
        }
        crate::core::run::RunStatus::Failed => {
            n.push_str("Outcome: FAILURE");
            if let Some(code) = data.exit_code {
                n.push_str(&format!(" (exit code {})", code));
            }
        }
        crate::core::run::RunStatus::Cancelled => {
            n.push_str("Outcome: CANCELLED");
        }
        crate::core::run::RunStatus::Running => {
            n.push_str("Outcome: STILL RUNNING");
        }
        _ => {
            n.push_str(&format!("Outcome: {:?}", data.status));
        }
    }
    if let Some(dur) = data.duration_ms {
        n.push_str(&format!(" — duration {:.1}s", dur as f64 / 1000.0));
    }
    n.push('\n');

    // What was attempted
    n.push_str(&format!("Attempts: {} tool calls", data.tools_total,));
    if data.tools_failed > 0 {
        n.push_str(&format!(" ({} failed)", data.tools_failed));
    }
    n.push('\n');

    // What failed
    if !data.errors.is_empty() {
        n.push_str(&format!("Errors: {} detected\n", data.errors.len()));
        for e in data.errors.iter().take(5) {
            let msg = if e.message.len() > 80 {
                format!("{}...", &e.message[..e.message.floor_char_boundary(80)])
            } else {
                e.message.clone()
            };
            n.push_str(&format!("  - [{}] {}\n", e.error_type, msg));
        }
        if data.errors.len() > 5 {
            n.push_str(&format!("  ... and {} more\n", data.errors.len() - 5));
        }
    } else if data.tools_failed > 0 {
        n.push_str("Errors: tool failures detected (structured parsing pending)\n");
    } else {
        n.push_str("Errors: none\n");
    }

    // Failure-to-fix summary
    if !data.fix_chains.is_empty() {
        n.push_str("Fix attempts:\n");
        for chain in data.fix_chains.iter().take(5) {
            let msg = if chain.error_message.len() > 60 {
                format!(
                    "{}...",
                    &chain.error_message[..chain.error_message.floor_char_boundary(60)]
                )
            } else {
                chain.error_message.clone()
            };
            n.push_str(&format!("  - \"{}\"\n", msg));
            for f in &chain.files_changed {
                n.push_str(&format!("    → edited: {}\n", f));
            }
            if chain.retry_occurred {
                if chain.retry_successful == Some(true) {
                    n.push_str("    ✓ retry succeeded\n");
                } else {
                    n.push_str("    ✗ retry failed or incomplete\n");
                }
            }
        }
        if data.fix_chains.len() > 5 {
            n.push_str(&format!(
                "  ... and {} more fix chains\n",
                data.fix_chains.len() - 5
            ));
        }
    }

    // Git changes
    match (&data.git_start, &data.git_end) {
        (Some(start), Some(end)) => {
            n.push_str(&format!("Git: {} → {}\n", start, end));
        }
        (Some(start), None) => {
            n.push_str(&format!("Git: {} (start)\n", start));
        }
        _ => {}
    }

    // Side effects
    if !data.side_effects.is_empty() {
        n.push_str(&format!(
            "Side effects: {} detected\n",
            data.side_effects.len()
        ));
    }

    // Capture coverage
    if let Some(ref cov) = data.capture_coverage {
        n.push_str(&format!(
            "Coverage: {} events across {} surfaces\n",
            cov.total_events,
            cov.surfaces.len()
        ));
        for s in &cov.surfaces {
            n.push_str(&format!("  {}: {} events", s.name, s.events_count));
            if !s.enabled {
                n.push_str(" (disabled)");
            }
            if let Some(ref note) = s.note {
                n.push_str(&format!(" [{}]", note));
            }
            n.push('\n');
        }
        if !cov.notes.is_empty() {
            for note in &cov.notes {
                n.push_str(&format!("  note: {}\n", note));
            }
        }
    }

    // Truncation warning
    if data.truncated {
        n.push_str(&format!(
            "Note: scanned {} of {} events (truncated)\n",
            data.events_scanned,
            data.total_events.unwrap_or(0)
        ));
    }

    // What remains unresolved
    if data.tools_failed > 0 && !data.fix_chains.is_empty() {
        let unresolved = data
            .fix_chains
            .iter()
            .filter(|c| c.retry_successful != Some(true))
            .count();
        if unresolved > 0 {
            n.push_str(&format!(
                "Unresolved: {} failure(s) without confirmed fix\n",
                unresolved
            ));
        }
    }

    n
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

    // Narrative section
    if !s.narrative.is_empty() {
        out.push_str("\n── Narrative ──────────────────────────────────────\n");
        for line in s.narrative.lines() {
            out.push_str(&format!("  {}\n", line));
        }
    }

    // Failure-to-fix chains
    if !s.failure_fix_chains.is_empty() {
        out.push_str("\n── Failure-to-fix chains ───────────────────────────\n");
        for chain in &s.failure_fix_chains {
            let msg = if chain.error_message.len() > 80 {
                format!(
                    "{}...",
                    &chain.error_message[..chain.error_message.floor_char_boundary(80)]
                )
            } else {
                chain.error_message.clone()
            };
            out.push_str(&format!("  error: {}\n", msg));
            if !chain.files_changed.is_empty() {
                out.push_str(&format!("  files: {}\n", chain.files_changed.join(", ")));
            }
            if chain.retry_occurred {
                out.push_str(&format!(
                    "  retry: {}\n",
                    if chain.retry_successful == Some(true) {
                        String::from("success")
                    } else {
                        String::from("failed/incomplete")
                    }
                ));
            }
            out.push_str(&format!("  confidence: {}\n", chain.confidence));
        }
    }

    // Capture coverage
    if let Some(ref cov) = s.capture_coverage {
        out.push_str("\n── Capture coverage ───────────────────────────────\n");
        out.push_str(&format!("  total events: {}\n", cov.total_events));
        for surface in &cov.surfaces {
            out.push_str(&format!(
                "  {}: {} events{}\n",
                surface.name,
                surface.events_count,
                if let Some(ref note) = surface.note {
                    format!(" [{}]", note)
                } else {
                    String::new()
                }
            ));
        }
        for note in &cov.notes {
            out.push_str(&format!("  note: {}\n", note));
        }
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
