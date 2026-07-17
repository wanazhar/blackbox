//! One-command postmortem / summary for a run.

use chrono::Utc;
use serde::Serialize;

use crate::analysis::anomalies::{detect_anomalies, Anomaly};
use crate::analysis::error_detector::ErrorDetector;
use crate::analysis::failure_fix::FailureFixCorrelator;
use crate::analysis::retry_waste::RetryWasteDetector;
use crate::analysis::turning_points::{detect_turning_points, TurningPoint};
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
    /// Repeated / non-progressing work findings.
    #[serde(default)]
    pub retry_waste: Vec<RetryWasteView>,
    /// Turning points in the execution story.
    #[serde(default)]
    pub turning_points: Vec<TurningPointView>,
    /// Recommended next action for handoff.
    #[serde(default)]
    pub next_action: String,
    /// Evidence-linked anchors (event sequences / files) for the next action.
    #[serde(default)]
    pub evidence: Vec<EvidenceLink>,
    /// One-line headline for agents (≤120 chars).
    #[serde(default)]
    pub headline: String,
    /// First-class anomaly markers (loops, destructive, token spike, …).
    #[serde(default)]
    pub anomalies: Vec<AnomalyView>,
    /// Evidence-linked material claims (1.4 Phase C).
    #[serde(default)]
    pub claims: Vec<PostmortemClaim>,
    /// Goal inference source: human_instruction | harness_prompt | run_name | command | unavailable
    #[serde(default)]
    pub goal_source: String,
    /// Inferred goal text (never hallucinated from file changes alone).
    #[serde(default)]
    pub goal: String,
    /// Overall verification coverage for the primary failure (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_coverage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AnomalyView {
    pub kind: String,
    pub severity: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

impl From<Anomaly> for AnomalyView {
    fn from(a: Anomaly) -> Self {
        Self {
            kind: a.kind,
            severity: a.severity,
            detail: a.detail,
            event_id: a.event_id,
            sequence: a.sequence,
            count: a.count,
        }
    }
}

/// A pointer agents can use to jump to evidence in the timeline.
#[derive(Debug, Clone, Serialize, Default)]
pub struct EvidenceLink {
    pub role: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TurningPointView {
    pub kind: String,
    pub detail: String,
    pub event_id: Option<String>,
    pub sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetryWasteView {
    pub kind: String,
    pub detail: String,
    pub count: usize,
    pub sample_event_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureFixChainView {
    pub error_event_id: String,
    pub error_message: String,
    pub files_changed: Vec<String>,
    pub retry_occurred: bool,
    pub retry_successful: Option<bool>,
    /// Snake_case confidence: confirmed | strongly_correlated | weakly_correlated | unknown
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_coverage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceLink>,
}

/// Material postmortem claim with confidence + evidence (1.4 G1).
#[derive(Debug, Clone, Serialize, Default)]
pub struct PostmortemClaim {
    pub claim: String,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CaptureCoverageView {
    pub total_events: u64,
    #[serde(default)]
    pub quality_score: u8,
    pub surfaces: Vec<SurfaceView>,
    pub notes: Vec<String>,
    /// Weighted contribution math (1.4 C3); empty on older runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SurfaceView {
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub status: String,
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

    // ── Failure-to-fix correlation (evidence-based confidence) ─────
    let fix_corr = FailureFixCorrelator::new();
    let fix_chains: Vec<FailureFixChainView> = fix_corr
        .find_chains(&events)
        .into_iter()
        .take(10)
        .map(|chain| FailureFixChainView {
            error_event_id: chain.error_event_id,
            error_message: chain.error_message,
            files_changed: chain.files_changed,
            retry_occurred: chain.retry_occurred,
            retry_successful: chain.retry_successful,
            confidence: chain.confidence.as_str().to_string(),
            failure_fingerprint: chain.failure_fingerprint,
            verification_fingerprint: chain.verification_fingerprint,
            verification_coverage: Some(chain.verification_coverage.as_str().to_string()),
            reasons: chain.reasons,
            evidence: chain
                .evidence
                .into_iter()
                .map(|e| EvidenceLink {
                    role: e.role,
                    detail: format!("seq {}", e.sequence),
                    event_id: Some(e.event_id),
                    sequence: Some(e.sequence),
                    path: None,
                })
                .collect(),
        })
        .collect();

    // ── Repeated / non-progressing work ──────────────────────────────
    let retry_waste: Vec<RetryWasteView> = RetryWasteDetector::new()
        .find(&events)
        .into_iter()
        .take(10)
        .map(|f| RetryWasteView {
            kind: f.kind,
            detail: f.detail,
            count: f.count,
            sample_event_ids: f.sample_event_ids,
        })
        .collect();

    // ── Turning points ───────────────────────────────────────────────
    let turning_points: Vec<TurningPointView> = detect_turning_points(&events)
        .into_iter()
        .map(|p: TurningPoint| TurningPointView {
            kind: p.kind,
            detail: p.detail,
            event_id: p.event_id,
            sequence: p.sequence,
        })
        .collect();

    // ── Anomalies (loops / destructive / tokens / silence) ───────────
    let anomalies: Vec<AnomalyView> = detect_anomalies(&events)
        .into_iter()
        .map(AnomalyView::from)
        .collect();

    let (next_action, evidence) = recommend_next_action(
        run,
        &fix_chains,
        &retry_waste,
        &turning_points,
        &errors,
        &anomalies,
    );

    // ── Goal inference (explicit sources only — never from file diffs) ─
    let (goal_source, goal) = infer_goal(run, &events);

    // ── Evidence-linked claims from fix chains + status ───────────────
    let claims = build_claims(run, &fix_chains, &errors);
    let verification_coverage = fix_chains
        .first()
        .and_then(|c| c.verification_coverage.clone());

    // ── Capture coverage ─────────────────────────────────────────────
    let coverage_ev = events.iter().find(|e| e.kind == "capture.coverage");
    let capture_coverage: Option<CaptureCoverageView> = coverage_ev.and_then(|ev| {
        let cov = ev.metadata.get("coverage")?;
        // Prefer typed CaptureCoverage so status/score fields map cleanly.
        if let Ok(typed) =
            serde_json::from_value::<crate::capture::coverage::CaptureCoverage>(cov.clone())
        {
            let contributions = typed
                .contributions
                .iter()
                .filter_map(|c| serde_json::to_value(c).ok())
                .collect();
            return Some(CaptureCoverageView {
                total_events: typed.total_events,
                quality_score: typed.quality_score,
                surfaces: typed
                    .surfaces
                    .into_iter()
                    .map(|s| SurfaceView {
                        name: s.name,
                        enabled: s.enabled,
                        status: s.status.as_str().to_string(),
                        events_count: s.events_count,
                        note: s.note,
                    })
                    .collect(),
                notes: typed.notes,
                contributions,
            });
        }
        // Fallback for older events missing status/score.
        serde_json::from_value::<CaptureCoverageView>(cov.clone()).ok()
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
    let headline = build_headline(run, &errors, tools_failed, &fix_chains);
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
        retry_waste: &retry_waste,
        turning_points: &turning_points,
        next_action: &next_action,
        truncated,
        events_scanned,
        total_events: total,
        headline: &headline,
        anomalies: &anomalies,
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
        retry_waste,
        turning_points,
        next_action,
        evidence,
        headline,
        anomalies,
        claims,
        goal_source,
        goal,
        verification_coverage,
    })
}

/// Prefer explicit goal sources; never invent intent from file changes.
fn infer_goal(run: &Run, events: &[crate::core::event::TraceEvent]) -> (String, String) {
    // 1. Human instruction events
    for ev in events {
        if ev.source == crate::core::event::EventSource::Human
            || ev.kind == "human.input"
            || ev.kind == "user.message"
        {
            if let Some(text) = ev
                .metadata
                .get("text")
                .or_else(|| ev.metadata.get("message"))
                .or_else(|| ev.metadata.get("content"))
                .and_then(|v| v.as_str())
            {
                let t = text.trim();
                if !t.is_empty() {
                    return (
                        "human_instruction".into(),
                        t.chars().take(200).collect(),
                    );
                }
            }
        }
    }
    // 2. Harness initial prompt in metadata
    for ev in events.iter().take(20) {
        if let Some(text) = ev
            .metadata
            .get("prompt")
            .or_else(|| ev.metadata.get("initial_prompt"))
            .and_then(|v| v.as_str())
        {
            let t = text.trim();
            if !t.is_empty() {
                return ("harness_prompt".into(), t.chars().take(200).collect());
            }
        }
    }
    // 3. Run name
    if let Some(ref name) = run.name {
        let t = name.trim();
        if !t.is_empty() {
            return ("run_name".into(), t.to_string());
        }
    }
    // 4. Command line (lossy)
    if !run.command.is_empty() {
        return ("command".into(), run.command.join(" "));
    }
    ("unavailable".into(), "goal unavailable".into())
}

fn build_claims(
    run: &Run,
    fix_chains: &[FailureFixChainView],
    errors: &[StructuredErrorView],
) -> Vec<PostmortemClaim> {
    use crate::core::run::RunStatus;
    let mut claims = Vec::new();

    for chain in fix_chains.iter().take(5) {
        let claim = if chain.retry_successful == Some(true)
            && chain.confidence == "confirmed"
        {
            format!(
                "Verification passed for failure «{}»",
                chain.error_message.chars().take(80).collect::<String>()
            )
        } else if chain.retry_successful == Some(true) {
            format!(
                "A later success was observed after «{}» but is not confirmed as verifying the same domain",
                chain.error_message.chars().take(60).collect::<String>()
            )
        } else if chain.retry_occurred {
            format!(
                "Verification was attempted after «{}» but did not pass",
                chain.error_message.chars().take(60).collect::<String>()
            )
        } else if !chain.files_changed.is_empty() {
            format!(
                "Files changed after «{}» without observed matching verification",
                chain.error_message.chars().take(60).collect::<String>()
            )
        } else {
            format!(
                "Failure observed: {}",
                chain.error_message.chars().take(80).collect::<String>()
            )
        };
        claims.push(PostmortemClaim {
            claim,
            confidence: chain.confidence.clone(),
            evidence: chain.evidence.clone(),
            reasons: chain.reasons.clone(),
        });
    }

    if claims.is_empty() {
        match run.status {
            RunStatus::Succeeded => {
                claims.push(PostmortemClaim {
                    claim: "Run completed successfully".into(),
                    confidence: "confirmed".into(),
                    evidence: vec![],
                    reasons: vec!["run_status".into()],
                });
            }
            RunStatus::Failed | RunStatus::Cancelled => {
                let msg = errors
                    .first()
                    .map(|e| e.message.chars().take(80).collect::<String>())
                    .unwrap_or_else(|| format!("{:?}", run.status));
                claims.push(PostmortemClaim {
                    claim: format!("Run ended in {:?}: {msg}", run.status),
                    confidence: if errors.is_empty() {
                        "weakly_correlated".into()
                    } else {
                        "strongly_correlated".into()
                    },
                    evidence: errors
                        .first()
                        .map(|e| {
                            vec![EvidenceLink {
                                role: "top_error".into(),
                                detail: e.message.chars().take(120).collect(),
                                event_id: None,
                                sequence: Some(e.sequence),
                                path: e.file.clone(),
                            }]
                        })
                        .unwrap_or_default(),
                    reasons: vec!["run_status".into()],
                });
            }
            _ => {}
        }
    }

    claims
}

fn build_headline(
    run: &Run,
    errors: &[StructuredErrorView],
    tools_failed: usize,
    fix_chains: &[FailureFixChainView],
) -> String {
    use crate::core::run::RunStatus;
    let short = crate::util::short_id(&run.id);
    match &run.status {
        RunStatus::Succeeded => {
            if tools_failed > 0 {
                format!("{short}: succeeded with {tools_failed} tool failure(s) during the run")
            } else {
                format!("{short}: succeeded")
            }
        }
        RunStatus::Failed | RunStatus::Cancelled => {
            if let Some(e) = errors.first() {
                let msg: String = e.message.chars().take(60).collect();
                format!("{short}: {:?} — {msg}", run.status)
            } else if let Some(c) = fix_chains.first() {
                let msg: String = c.error_message.chars().take(60).collect();
                format!("{short}: {:?} — {msg}", run.status)
            } else {
                format!("{short}: {:?} (exit {:?})", run.status, run.exit_code)
            }
        }
        other => format!("{short}: {other:?}"),
    }
}

fn recommend_next_action(
    run: &Run,
    fix_chains: &[FailureFixChainView],
    retry_waste: &[RetryWasteView],
    turning_points: &[TurningPointView],
    errors: &[StructuredErrorView],
    anomalies: &[AnomalyView],
) -> (String, Vec<EvidenceLink>) {
    use crate::core::run::RunStatus;
    let short = crate::util::short_id(&run.id).to_string();
    let mut evidence = Vec::new();

    // High-severity anomalies influence next action even on success.
    if let Some(a) = anomalies.iter().find(|a| a.severity == "high") {
        evidence.push(EvidenceLink {
            role: format!("anomaly:{}", a.kind),
            detail: a.detail.clone(),
            event_id: a.event_id.clone(),
            sequence: a.sequence,
            path: None,
        });
        if a.kind == "destructive" {
            return (
                format!(
                    "Destructive action detected — inspect seq {:?} before continuing ({})",
                    a.sequence, short
                ),
                evidence,
            );
        }
        if a.kind == "tool_loop" || a.kind == "error_storm" {
            return (
                format!(
                    "Agent may be stuck ({}) — change approach; `blackbox timeline {} --semantic`",
                    a.kind, short
                ),
                evidence,
            );
        }
    }

    if matches!(run.status, RunStatus::Failed | RunStatus::Cancelled) {
        if let Some(tp) = turning_points.iter().find(|p| p.kind == "first_failure") {
            evidence.push(EvidenceLink {
                role: "first_failure".into(),
                detail: tp.detail.clone(),
                event_id: tp.event_id.clone(),
                sequence: tp.sequence,
                path: None,
            });
        }
        if let Some(e) = errors.first() {
            evidence.push(EvidenceLink {
                role: "top_error".into(),
                detail: e.message.chars().take(120).collect(),
                event_id: None,
                sequence: Some(e.sequence),
                path: e.file.clone(),
            });
        }
        if let Some(chain) = fix_chains.first() {
            for e in chain.evidence.iter().take(6) {
                evidence.push(e.clone());
            }
            for f in chain.files_changed.iter().take(5) {
                if !evidence.iter().any(|x| x.path.as_deref() == Some(f.as_str())) {
                    evidence.push(EvidenceLink {
                        role: "edited_after_failure".into(),
                        detail: f.clone(),
                        event_id: Some(chain.error_event_id.clone()),
                        sequence: None,
                        path: Some(f.clone()),
                    });
                }
            }
            let action = if chain.confidence == "confirmed"
                && chain.retry_successful == Some(true)
            {
                format!(
                    "Confirmed verification for «{}»; then `blackbox resolve` if attention is sticky",
                    chain.error_message.chars().take(60).collect::<String>()
                )
            } else if chain.retry_successful == Some(true) {
                format!(
                    "A success followed «{}» but confidence is {} — re-run matching verification; `blackbox timeline {} --semantic`",
                    chain.error_message.chars().take(50).collect::<String>(),
                    chain.confidence,
                    short
                )
            } else if !chain.files_changed.is_empty() {
                format!(
                    "Re-run verification after reviewing edits to {}; start with `blackbox timeline {} --semantic`",
                    chain.files_changed.join(", "),
                    short
                )
            } else {
                format!(
                    "Open first failure (seq evidence) via `blackbox timeline {} --semantic`, fix, re-verify",
                    short
                )
            };
            return (action, evidence);
        }
        if turning_points.iter().any(|p| p.kind == "unresolved") {
            return (
                format!(
                    "Unresolved failure on {short}: `blackbox handoff --json` then fix and re-verify"
                ),
                evidence,
            );
        }
        return (
            format!("blackbox handoff --json  # resume pack for {short}"),
            evidence,
        );
    }
    if retry_waste.iter().any(|r| r.kind == "no_progress_retry") {
        if let Some(r) = retry_waste.first() {
            evidence.push(EvidenceLink {
                role: "retry_waste".into(),
                detail: r.detail.clone(),
                event_id: r.sample_event_ids.first().cloned(),
                sequence: None,
                path: None,
            });
        }
        return (
            "Non-progressing retries detected — change approach before continuing; inspect retry samples in postmortem JSON".into(),
            evidence,
        );
    }
    if matches!(run.status, RunStatus::Succeeded) {
        return (
            "Run succeeded — `blackbox status --json` then merge or clear WIP if done".into(),
            evidence,
        );
    }
    ("blackbox status --json".into(), evidence)
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
    retry_waste: &'a [RetryWasteView],
    turning_points: &'a [TurningPointView],
    next_action: &'a str,
    truncated: bool,
    events_scanned: usize,
    total_events: Option<usize>,
    headline: &'a str,
    anomalies: &'a [AnomalyView],
}

/// Build a narrative summary of the run (story-first for agents).
fn build_narrative(data: &SummaryNarrativeData) -> String {
    let mut n = String::new();

    // Story headline first (10-second answer)
    n.push_str(&format!("Story: {}\n", data.headline));

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

    // Causal arc from turning points
    if data.turning_points.len() >= 2 {
        n.push_str("Arc:");
        for p in data.turning_points.iter().take(6) {
            n.push_str(&format!(" [{}]", p.kind));
        }
        n.push('\n');
    }

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

    // Turning points
    if !data.turning_points.is_empty() {
        n.push_str("Turning points:\n");
        for p in data.turning_points.iter().take(8) {
            n.push_str(&format!("  - [{}] {}\n", p.kind, p.detail));
        }
    }

    // Repeated / non-progressing work
    if !data.retry_waste.is_empty() {
        n.push_str("Repeated work:\n");
        for f in data.retry_waste.iter().take(5) {
            n.push_str(&format!("  - {}\n", f.detail));
        }
    }

    // Anomalies
    if !data.anomalies.is_empty() {
        n.push_str("Anomalies:\n");
        for a in data.anomalies.iter().take(8) {
            n.push_str(&format!("  - [{}|{}] {}\n", a.severity, a.kind, a.detail));
        }
    }

    if !data.next_action.is_empty() {
        n.push_str(&format!("Recommended next action: {}\n", data.next_action));
    }

    // Capture coverage
    if let Some(ref cov) = data.capture_coverage {
        n.push_str(&format!(
            "Capture quality: {}% — {} events across {} surfaces\n",
            cov.quality_score,
            cov.total_events,
            cov.surfaces.len()
        ));
        for s in &cov.surfaces {
            n.push_str(&format!(
                "  {}: {} ({} events)",
                s.name,
                if s.status.is_empty() {
                    if s.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else {
                    s.status.as_str()
                },
                s.events_count
            ));
            if let Some(ref note) = s.note {
                n.push_str(&format!(" [{}]", note));
            }
            n.push('\n');
        }
        // Keep algorithm notes out of the narrative body; surface only material limitations.
        for note in &cov.notes {
            if note.starts_with("quality_score:") {
                continue;
            }
            n.push_str(&format!("  note: {}\n", note));
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

    // What remains unresolved (confirmed only when confidence == confirmed)
    if data.tools_failed > 0 && !data.fix_chains.is_empty() {
        let unresolved = data
            .fix_chains
            .iter()
            .filter(|c| c.confidence != "confirmed")
            .count();
        if unresolved > 0 {
            n.push_str(&format!(
                "Unresolved: {} failure(s) without confirmed verification\n",
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
    if !s.headline.is_empty() {
        out.push_str(&format!("  headline: {}\n", s.headline));
    }
    out.push_str(&format!("  command: {}\n", s.command.join(" ")));
    if !s.tags.is_empty() {
        out.push_str(&format!("  tags: {}\n", s.tags.join(", ")));
    }
    if !s.next_action.is_empty() {
        out.push_str(&format!("  next: {}\n", s.next_action));
    }
    if !s.goal.is_empty() {
        out.push_str(&format!("  goal ({}) : {}\n", s.goal_source, s.goal));
    }
    if let Some(ref vc) = s.verification_coverage {
        out.push_str(&format!("  verification_coverage: {vc}\n"));
    }
    if !s.claims.is_empty() {
        out.push_str("  claims:\n");
        for c in s.claims.iter().take(6) {
            out.push_str(&format!("    - [{}] {}\n", c.confidence, c.claim));
        }
    }
    if !s.evidence.is_empty() {
        out.push_str("  evidence:\n");
        for e in s.evidence.iter().take(8) {
            out.push_str(&format!("    - [{}] {}", e.role, e.detail));
            if let Some(seq) = e.sequence {
                out.push_str(&format!(" (seq={seq})"));
            }
            if let Some(ref p) = e.path {
                out.push_str(&format!(" path={p}"));
            }
            out.push('\n');
        }
    }
    if !s.anomalies.is_empty() {
        out.push_str("  anomalies:\n");
        for a in s.anomalies.iter().take(8) {
            out.push_str(&format!("    - [{}|{}] {}\n", a.severity, a.kind, a.detail));
        }
    }

    // Narrative section
    if !s.narrative.is_empty() {
        out.push_str("\n── Narrative ──────────────────────────────────────\n");
        for line in s.narrative.lines() {
            out.push_str(&format!("  {}\n", line));
        }
    }

    // Repeated work
    if !s.retry_waste.is_empty() {
        out.push_str("\n── Repeated / non-progressing work ────────────────\n");
        for f in &s.retry_waste {
            out.push_str(&format!("  [{}×] {}\n", f.count, f.detail));
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
        out.push_str(&format!("  quality score: {}%\n", cov.quality_score));
        out.push_str(&format!("  total events: {}\n", cov.total_events));
        for surface in &cov.surfaces {
            out.push_str(&format!(
                "  {}: status={} events={}{}\n",
                surface.name,
                if surface.status.is_empty() {
                    "unknown"
                } else {
                    surface.status.as_str()
                },
                surface.events_count,
                if let Some(ref note) = surface.note {
                    format!(" [{note}]")
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
