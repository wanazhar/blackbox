//! Bounded resume context packs for agents (`context --for-resume`).
//!
//! 1.1 adoption bar (A3): packs must be actionable (headline + next_action),
//! budget-bounded, and prefer structured failure signal over raw transcript.

use serde::Serialize;

use crate::core::event::{EventStatus, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::storage::TraceStore;
use crate::summary::{build_summary, SummaryOptions, SummaryView};

#[derive(Debug, Clone, Serialize)]
pub struct ContextPackView {
    pub run_id: String,
    pub short_id: String,
    pub purpose: String,
    /// One-line status for agents scanning handoff JSON.
    pub headline: String,
    /// What the next agent should do first.
    pub next_action: String,
    /// Why attention/handoff fired (or "ok" when healthy).
    pub attention_reason: String,
    pub summary: SummaryView,
    pub failed_tools: Vec<FailedTool>,
    /// Top structured errors (capped); preferred over scraping transcript.
    pub errors_top: Vec<ErrorTop>,
    pub last_tools: Vec<String>,
    pub filesystem_writes: Vec<String>,
    pub transcript_tail: Option<String>,
    pub resume_command: Option<Vec<String>>,
    pub approx_tokens: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailedTool {
    pub sequence: u64,
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorTop {
    pub sequence: u64,
    pub error_type: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ContextOptions {
    pub max_tokens: usize,
    pub include_transcript: bool,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            max_tokens: 4000,
            include_transcript: true,
        }
    }
}

/// Rough token estimate: chars / 4.
fn approx_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = s.floor_char_boundary(max);
    format!("{}…", &s[..end])
}

/// Prefer error/output preview over raw tool input dump.
fn tool_failure_detail(ev: &TraceEvent) -> String {
    for key in ["error", "output", "result", "message"] {
        if let Some(v) = ev.metadata.get(key) {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let t = s.trim();
            if !t.is_empty() && t != "null" {
                return truncate_str(t, 240);
            }
        }
    }
    if let Some(v) = ev.metadata.get("input") {
        let s = v.to_string();
        return truncate_str(&s, 200);
    }
    if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
        return truncate_str(p, 200);
    }
    String::new()
}

fn build_headline(run: &Run, failed_tools: &[FailedTool], errors_top: &[ErrorTop]) -> String {
    let short = crate::util::short_id(&run.id);
    match &run.status {
        RunStatus::Failed | RunStatus::Cancelled => {
            let hint = failed_tools
                .first()
                .map(|t| format!("; last failed tool: {}", t.name))
                .or_else(|| {
                    errors_top
                        .first()
                        .map(|e| format!("; error: {}", truncate_str(&e.message, 80)))
                })
                .unwrap_or_default();
            format!(
                "Run {short} {:?} (exit {:?}){hint}",
                run.status, run.exit_code
            )
        }
        RunStatus::Running => format!("Run {short} appears abandoned/still Running"),
        RunStatus::Succeeded => format!("Run {short} Succeeded (exit {:?})", run.exit_code),
        other => format!("Run {short} {other:?}"),
    }
}

fn build_attention_reason(run: &Run) -> String {
    match &run.status {
        RunStatus::Failed => "failed".into(),
        RunStatus::Cancelled => "cancelled".into(),
        RunStatus::Running => "abandoned_or_running".into(),
        RunStatus::Succeeded => "ok".into(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

fn build_next_action(run: &Run, failed_tools: &[FailedTool]) -> String {
    let short = crate::util::short_id(&run.id);
    match &run.status {
        RunStatus::Failed | RunStatus::Cancelled => {
            if let Some(t) = failed_tools.first() {
                format!(
                    "Inspect failed tool '{}' (seq {}), fix root cause, then retry; postmortem: blackbox postmortem {short} --json",
                    t.name, t.sequence
                )
            } else {
                format!(
                    "Read errors_top and summary, fix root cause, retry; postmortem: blackbox postmortem {short} --json"
                )
            }
        }
        RunStatus::Running => {
            format!(
                "Treat as abandoned if store recovered it; blackbox postmortem {short} --json then continue carefully"
            )
        }
        RunStatus::Succeeded => {
            "No failure attention required; continue with user task or blackbox runs --json".into()
        }
        _ => format!("Review blackbox postmortem {short} --json before continuing"),
    }
}

pub async fn build_context_pack(
    store: &dyn TraceStore,
    run: &Run,
    opts: ContextOptions,
) -> anyhow::Result<ContextPackView> {
    let summary = build_summary(
        store,
        run,
        SummaryOptions {
            short: false,
            full: false,
        },
    )
    .await?;

    let (events, _) = store
        .get_events_limited(&run.id, 5_000)
        .await
        .unwrap_or((Vec::new(), false));

    let mut failed_tools = Vec::new();
    let mut last_tools = Vec::new();
    let mut filesystem_writes = Vec::new();
    let mut errors_top = Vec::new();

    for ev in &events {
        if ev.kind == "tool.call" || ev.kind == "tool.result" {
            if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
                if ev.kind == "tool.call" {
                    last_tools.push(name.to_string());
                }
                if matches!(ev.status, EventStatus::Error) {
                    failed_tools.push(FailedTool {
                        sequence: ev.sequence,
                        name: name.to_string(),
                        detail: tool_failure_detail(ev),
                    });
                }
            } else if matches!(ev.status, EventStatus::Error) && ev.kind == "tool.result" {
                failed_tools.push(FailedTool {
                    sequence: ev.sequence,
                    name: ev
                        .metadata
                        .get("tool_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    detail: tool_failure_detail(ev),
                });
            }
        }
        if matches!(ev.status, EventStatus::Error) && errors_top.len() < 12 {
            if let Some(msg) = ev
                .metadata
                .get("error")
                .and_then(|v| v.as_str())
                .or_else(|| ev.metadata.get("message").and_then(|v| v.as_str()))
                .or_else(|| ev.metadata.get("preview").and_then(|v| v.as_str()))
            {
                let msg = msg.trim();
                if !msg.is_empty() {
                    errors_top.push(ErrorTop {
                        sequence: ev.sequence,
                        error_type: ev.kind.clone(),
                        message: truncate_str(msg, 200),
                    });
                }
            }
        }
        if ev.kind.starts_with("filesystem.")
            && !ev.kind.contains("observer")
            && !ev.kind.contains("snapshot")
        {
            if let Some(p) = ev.metadata.get("path").and_then(|v| v.as_str()) {
                filesystem_writes.push(format!("{}:{}", ev.kind, p));
            }
        }
    }

    // Prefer summary structured errors if event scan found little
    if errors_top.is_empty() {
        for e in summary.errors.iter().take(12) {
            errors_top.push(ErrorTop {
                sequence: e.sequence,
                error_type: e.error_type.clone(),
                message: truncate_str(&e.message, 200),
            });
        }
    }

    // Keep last K tool names
    if last_tools.len() > 30 {
        last_tools = last_tools.split_off(last_tools.len() - 30);
    }
    failed_tools.truncate(20);
    filesystem_writes.truncate(40);
    errors_top.truncate(12);

    let headline = build_headline(run, &failed_tools, &errors_top);
    let attention_reason = build_attention_reason(run);
    let next_action = build_next_action(run, &failed_tools);
    let resume_command = summary.resume.command.clone();

    // Transcript is lowest priority: only attach if budget likely allows.
    let mut transcript_tail = None;
    if opts.include_transcript {
        if let Ok(full) = crate::transcript::rebuild_terminal_transcript(store, &events).await {
            // Start with a modest tail; shrink loop will drop further.
            let tail_chars = opts.max_tokens.saturating_mul(2).min(8_000);
            if full.len() > tail_chars {
                let start = full
                    .char_indices()
                    .rev()
                    .nth(tail_chars)
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                transcript_tail = Some(full[start..].to_string());
            } else if !full.is_empty() {
                transcript_tail = Some(full);
            }
        }
    }

    let mut pack = ContextPackView {
        run_id: run.id.clone(),
        short_id: crate::util::short_id(&run.id).to_string(),
        purpose: "for-resume".into(),
        headline,
        next_action,
        attention_reason,
        summary,
        failed_tools,
        errors_top,
        last_tools,
        filesystem_writes,
        transcript_tail,
        resume_command,
        approx_tokens: 0,
        truncated: false,
    };

    // Shrink until under budget: transcript → FS → last_tools → failed detail → errors
    // Never drop headline/next_action/attention_reason.
    loop {
        let json = serde_json::to_string(&pack).unwrap_or_default();
        pack.approx_tokens = approx_tokens(&json);
        if pack.approx_tokens <= opts.max_tokens {
            break;
        }
        if let Some(ref mut t) = pack.transcript_tail {
            if t.len() > 200 {
                let new_len = t.len() / 2;
                let start = t.len() - new_len;
                let start = t.floor_char_boundary(start);
                *t = t[start..].to_string();
                pack.truncated = true;
                continue;
            } else {
                pack.transcript_tail = None;
                pack.truncated = true;
                continue;
            }
        }
        if pack.filesystem_writes.len() > 5 {
            pack.filesystem_writes.truncate(5);
            pack.truncated = true;
            continue;
        }
        if !pack.filesystem_writes.is_empty() {
            pack.filesystem_writes.clear();
            pack.truncated = true;
            continue;
        }
        if pack.last_tools.len() > 10 {
            pack.last_tools = pack
                .last_tools
                .split_off(pack.last_tools.len().saturating_sub(10));
            pack.truncated = true;
            continue;
        }
        if pack.last_tools.len() > 3 {
            pack.last_tools = pack
                .last_tools
                .split_off(pack.last_tools.len().saturating_sub(3));
            pack.truncated = true;
            continue;
        }
        if pack.failed_tools.len() > 3 {
            pack.failed_tools.truncate(3);
            pack.truncated = true;
            continue;
        }
        // Truncate failed tool details
        let mut shrunk_detail = false;
        for t in &mut pack.failed_tools {
            if t.detail.len() > 40 {
                t.detail = truncate_str(&t.detail, 40);
                shrunk_detail = true;
            }
        }
        if shrunk_detail {
            pack.truncated = true;
            continue;
        }
        if pack.errors_top.len() > 3 {
            pack.errors_top.truncate(3);
            pack.truncated = true;
            continue;
        }
        // Shrink embedded postmortem (headline/next stay; drop bulk narrative)
        if pack.summary.narrative.len() > 200 {
            pack.summary.narrative = truncate_str(&pack.summary.narrative, 200);
            pack.truncated = true;
            continue;
        }
        if pack.summary.evidence.len() > 2 {
            pack.summary.evidence.truncate(2);
            pack.truncated = true;
            continue;
        }
        if !pack.summary.evidence.is_empty() {
            pack.summary.evidence.clear();
            pack.truncated = true;
            continue;
        }
        if pack.summary.turning_points.len() > 3 {
            pack.summary.turning_points.truncate(3);
            pack.truncated = true;
            continue;
        }
        if pack.summary.failure_fix_chains.len() > 1 {
            pack.summary.failure_fix_chains.truncate(1);
            pack.truncated = true;
            continue;
        }
        if pack.summary.side_effects.len() > 3 {
            pack.summary.side_effects.truncate(3);
            pack.truncated = true;
            continue;
        }
        if !pack.summary.side_effects.is_empty() {
            pack.summary.side_effects.clear();
            pack.truncated = true;
            continue;
        }
        if pack.summary.anomalies.len() > 3 {
            pack.summary.anomalies.truncate(3);
            pack.truncated = true;
            continue;
        }
        if !pack.summary.anomalies.is_empty() && pack.approx_tokens > opts.max_tokens {
            // Keep high severity only
            pack.summary
                .anomalies
                .retain(|a| a.severity == "high");
            if pack.summary.anomalies.len() > 2 {
                pack.summary.anomalies.truncate(2);
            }
            pack.truncated = true;
            continue;
        }
        if pack.summary.errors.len() > 3 {
            pack.summary.errors.truncate(3);
            pack.truncated = true;
            continue;
        }
        if pack.summary.narrative.len() > 40 {
            pack.summary.narrative = truncate_str(&pack.summary.narrative, 40);
            pack.truncated = true;
            continue;
        }
        pack.truncated = true;
        break;
    }

    Ok(pack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, TraceEvent};
    use crate::core::run::{Run, RunStatus};
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;
    use std::sync::Arc;

    async fn store_with_failed_tool() -> (Arc<dyn TraceStore>, Run) {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = Run::new(
            vec!["claude".into(), "-p".into(), "fix".into()],
            "/tmp".into(),
        );
        run.status = RunStatus::Failed;
        run.exit_code = Some(1);
        run.notes = Some("adapter:claude".into());
        store.insert_run(&run).await.unwrap();

        let mut ok = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        ok.sequence = 1;
        ok.status = EventStatus::Success;
        ok.metadata
            .insert("tool_name".into(), serde_json::json!("Read"));
        store.insert_event(&ok).await.unwrap();

        let mut bad = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        bad.sequence = 2;
        bad.status = EventStatus::Error;
        bad.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        bad.metadata.insert(
            "error".into(),
            serde_json::json!("exit 1: permission denied on /etc/shadow"),
        );
        bad.metadata.insert(
            "input".into(),
            serde_json::json!({"command": "cat /etc/shadow"}),
        );
        store.insert_event(&bad).await.unwrap();

        (store, run)
    }

    #[tokio::test]
    async fn a3_failed_pack_has_headline_next_action_and_failed_tool() {
        let (store, run) = store_with_failed_tool().await;
        let pack = build_context_pack(
            store.as_ref(),
            &run,
            ContextOptions {
                max_tokens: 4000,
                include_transcript: false,
            },
        )
        .await
        .unwrap();

        assert!(!pack.headline.is_empty());
        assert!(
            pack.headline.contains("Failed") || pack.attention_reason == "failed",
            "headline/attention must signal failure: {} / {}",
            pack.headline,
            pack.attention_reason
        );
        assert_eq!(pack.attention_reason, "failed");
        assert!(!pack.next_action.is_empty());
        assert!(
            pack.next_action.to_ascii_lowercase().contains("bash")
                || pack.next_action.contains("postmortem"),
            "next_action should guide retry: {}",
            pack.next_action
        );
        assert!(
            !pack.failed_tools.is_empty(),
            "failed tools must be present"
        );
        assert_eq!(pack.failed_tools[0].name, "Bash");
        assert!(
            pack.failed_tools[0].detail.contains("permission denied")
                || pack.failed_tools[0].detail.contains("exit 1"),
            "prefer error detail over input dump: {}",
            pack.failed_tools[0].detail
        );
        assert!(pack.approx_tokens <= 4000);
        assert!(pack.approx_tokens > 0);
    }

    #[tokio::test]
    async fn a3_budget_drops_transcript_before_failed_tools() {
        let (store, run) = store_with_failed_tool().await;

        // Inject a huge terminal event so transcript rebuild has bulk.
        let mut term = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        term.sequence = 3;
        term.status = EventStatus::Success;
        let huge = "x".repeat(50_000);
        term.metadata
            .insert("preview".into(), serde_json::json!(huge));
        store.insert_event(&term).await.unwrap();

        let pack = build_context_pack(
            store.as_ref(),
            &run,
            ContextOptions {
                max_tokens: 600,
                include_transcript: true,
            },
        )
        .await
        .unwrap();

        assert!(pack.approx_tokens <= 600, "tokens={}", pack.approx_tokens);
        assert!(
            !pack.failed_tools.is_empty(),
            "failed tools must survive tight budget"
        );
        assert!(!pack.headline.is_empty());
        assert!(!pack.next_action.is_empty());
        // Transcript should be gone or tiny under tight budget
        if let Some(ref t) = pack.transcript_tail {
            assert!(t.len() < 2000, "transcript still huge: {}", t.len());
        }
        assert!(pack.truncated);
    }

    #[tokio::test]
    async fn a3_success_pack_ok_attention() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        store.insert_run(&run).await.unwrap();

        let pack = build_context_pack(
            store.as_ref(),
            &run,
            ContextOptions {
                max_tokens: 2000,
                include_transcript: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(pack.attention_reason, "ok");
        assert!(pack.headline.contains("Succeeded"));
    }
}
