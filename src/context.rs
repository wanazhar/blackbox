//! Bounded resume context packs for agents (`context --for-resume`).

use serde::Serialize;

use crate::core::event::{EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::storage::TraceStore;
use crate::summary::{build_summary, SummaryOptions, SummaryView};

#[derive(Debug, Serialize)]
pub struct ContextPackView {
    pub run_id: String,
    pub short_id: String,
    pub purpose: String,
    pub summary: SummaryView,
    pub failed_tools: Vec<FailedTool>,
    pub last_tools: Vec<String>,
    pub filesystem_writes: Vec<String>,
    pub transcript_tail: Option<String>,
    pub resume_command: Option<Vec<String>>,
    pub approx_tokens: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct FailedTool {
    pub sequence: u64,
    pub name: String,
    pub detail: String,
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

    for ev in &events {
        if ev.kind == "tool.call" {
            if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
                last_tools.push(name.to_string());
                if matches!(ev.status, EventStatus::Error) {
                    failed_tools.push(FailedTool {
                        sequence: ev.sequence,
                        name: name.to_string(),
                        detail: ev
                            .metadata
                            .get("input")
                            .map(|v| {
                                let s = v.to_string();
                                if s.len() > 200 {
                                    format!("{}…", &s[..s.floor_char_boundary(200)])
                                } else {
                                    s
                                }
                            })
                            .unwrap_or_default(),
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
    // Keep last K tool names
    if last_tools.len() > 30 {
        last_tools = last_tools.split_off(last_tools.len() - 30);
    }
    failed_tools.truncate(20);
    filesystem_writes.truncate(40);

    let resume_command = summary.resume.command.clone();

    let mut transcript_tail = None;
    if opts.include_transcript {
        if let Ok(full) = crate::transcript::rebuild_terminal_transcript(store, &events).await {
            let tail_chars = opts.max_tokens.saturating_mul(3); // ~3 chars/token budget for tail
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
        summary,
        failed_tools,
        last_tools,
        filesystem_writes,
        transcript_tail,
        resume_command,
        approx_tokens: 0,
        truncated: false,
    };

    // Shrink transcript until under budget
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
        // Drop FS and failed tool details further
        if pack.filesystem_writes.len() > 5 {
            pack.filesystem_writes.truncate(5);
            pack.truncated = true;
            continue;
        }
        if pack.failed_tools.len() > 3 {
            pack.failed_tools.truncate(3);
            pack.truncated = true;
            continue;
        }
        pack.truncated = true;
        break;
    }

    Ok(pack)
}

#[allow(dead_code)]
fn _touch_event(_: &TraceEvent) {}
