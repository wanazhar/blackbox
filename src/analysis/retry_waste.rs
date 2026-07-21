//! Retry and non-progressing work detection.
//!
//! Surfaces repeated commands, repeated errors, and loops with no useful
//! state change. Language is descriptive ("repeated", "no progress"), not
//! judgmental.

use std::collections::HashMap;

use crate::analysis::AnalysisPass;
use crate::core::event::{EventSource, EventStatus, TraceEvent};

/// A pattern of repeated or non-progressing work.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetryWasteFinding {
    /// Event or item kind string.
    pub kind: String,
    /// Detail.
    pub detail: String,
    /// Count.
    pub count: usize,
    /// Sample event ids.
    pub sample_event_ids: Vec<String>,
}

/// Detects repeated commands/errors and non-progressing loops.
pub struct RetryWasteDetector;

impl Default for RetryWasteDetector {
    fn default() -> Self {
        Self
    }
}

impl RetryWasteDetector {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Find.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `find` — see module docs for full workflow.
    /// ```
    pub fn find(&self, events: &[TraceEvent]) -> Vec<RetryWasteFinding> {
        let mut findings = Vec::new();

        // Repeated tool commands (by tool_name + command/argv signature).
        let mut cmd_counts: HashMap<String, (usize, Vec<String>)> = HashMap::new();
        for ev in events {
            if ev.kind != "tool.call" && ev.source != EventSource::Process {
                continue;
            }
            let sig = command_signature(ev);
            if sig.is_empty() {
                continue;
            }
            let entry = cmd_counts.entry(sig).or_insert_with(|| (0, Vec::new()));
            entry.0 += 1;
            if entry.1.len() < 5 {
                entry.1.push(ev.id.clone());
            }
        }
        for (sig, (count, ids)) in cmd_counts {
            if count >= 3 {
                findings.push(RetryWasteFinding {
                    kind: "repeated_command".into(),
                    detail: format!("command repeated {count} times: {sig}"),
                    count,
                    sample_event_ids: ids,
                });
            }
        }

        // Repeated error messages.
        let mut err_counts: HashMap<String, (usize, Vec<String>)> = HashMap::new();
        for ev in events {
            if ev.status != EventStatus::Error {
                continue;
            }
            let msg = ev
                .metadata
                .get("message")
                .or_else(|| ev.metadata.get("error_message"))
                .or_else(|| ev.metadata.get("stderr"))
                .and_then(|v| v.as_str())
                .unwrap_or(ev.kind.as_str());
            let key = normalize_error(msg);
            if key.is_empty() {
                continue;
            }
            let entry = err_counts.entry(key).or_insert_with(|| (0, Vec::new()));
            entry.0 += 1;
            if entry.1.len() < 5 {
                entry.1.push(ev.id.clone());
            }
        }
        for (msg, (count, ids)) in err_counts {
            if count >= 2 {
                findings.push(RetryWasteFinding {
                    kind: "repeated_error".into(),
                    detail: format!("same error pattern {count} times: {msg}"),
                    count,
                    sample_event_ids: ids,
                });
            }
        }

        // Tool calls with no filesystem / git change between identical retries.
        let mut last_fs_seq: Option<u64> = None;
        let mut pending_calls: Vec<(String, u64, String)> = Vec::new(); // sig, seq, id
        let mut no_progress = 0usize;
        let mut no_progress_ids = Vec::new();
        for ev in events {
            if ev.source == EventSource::Filesystem
                && !ev.kind.contains("observer")
                && !ev.kind.contains("snapshot")
            {
                last_fs_seq = Some(ev.sequence);
            }
            if ev.kind == "tool.call" {
                let sig = command_signature(ev);
                if sig.is_empty() {
                    continue;
                }
                // Look for prior identical call with no fs change after it.
                if let Some((_, prev_seq, _)) =
                    pending_calls.iter().rev().find(|(s, _, _)| s == &sig)
                {
                    let no_fs = last_fs_seq.map(|s| s <= *prev_seq).unwrap_or(true);
                    if no_fs {
                        no_progress += 1;
                        if no_progress_ids.len() < 5 {
                            no_progress_ids.push(ev.id.clone());
                        }
                    }
                }
                pending_calls.push((sig, ev.sequence, ev.id.clone()));
            }
        }
        if no_progress >= 2 {
            findings.push(RetryWasteFinding {
                kind: "no_progress_retry".into(),
                detail: format!(
                    "{no_progress} repeated tool call(s) with no intervening filesystem change"
                ),
                count: no_progress,
                sample_event_ids: no_progress_ids,
            });
        }

        findings.sort_by_key(|b| std::cmp::Reverse(b.count));
        findings
    }
}

fn command_signature(ev: &TraceEvent) -> String {
    if let Some(argv) = ev.metadata.get("argv").and_then(|v| v.as_array()) {
        let parts: Vec<&str> = argv.iter().filter_map(|v| v.as_str()).collect();
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }
    if let Some(arr) = ev.metadata.get("command").and_then(|v| v.as_array()) {
        let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }
    if let Some(s) = ev.metadata.get("command").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(input) = ev.metadata.get("input") {
        if let Some(cmd) = input
            .get("command")
            .and_then(|c| c.as_str())
            .or_else(|| input.get("cmd").and_then(|c| c.as_str()))
        {
            let tool = ev
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("tool");
            return format!("{tool}:{cmd}");
        }
    }
    if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
        return format!("tool:{name}");
    }
    String::new()
}

fn normalize_error(msg: &str) -> String {
    let trimmed = msg.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Collapse whitespace and truncate for grouping.
    let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 120 {
        collapsed[..collapsed.floor_char_boundary(120)].to_string()
    } else {
        collapsed
    }
}

#[async_trait::async_trait]
impl AnalysisPass for RetryWasteDetector {
    fn name(&self) -> &'static str {
        "retry_waste"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let findings = self.find(events);
        let mut derived = Vec::with_capacity(findings.len());
        for f in findings {
            let mut ev = TraceEvent::new(
                events.first().map(|e| e.run_id.as_str()).unwrap_or(""),
                EventSource::System,
                "analysis.retry_waste",
            );
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("finding_kind".into(), serde_json::json!(f.kind));
            ev.metadata
                .insert("detail".into(), serde_json::json!(f.detail));
            ev.metadata
                .insert("count".into(), serde_json::json!(f.count));
            ev.metadata.insert(
                "sample_event_ids".into(),
                serde_json::json!(f.sample_event_ids),
            );
            derived.push(ev);
        }
        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn tool_call(cmd: &str, id: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.call");
        ev.id = id.into();
        ev.status = EventStatus::Success;
        ev.started_at = Utc::now();
        ev.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        ev.metadata
            .insert("input".into(), serde_json::json!({ "command": cmd }));
        ev
    }

    fn error_ev(msg: &str, id: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.result");
        ev.id = id.into();
        ev.status = EventStatus::Error;
        ev.started_at = Utc::now();
        ev.metadata.insert("message".into(), serde_json::json!(msg));
        ev
    }

    #[test]
    fn detects_repeated_command() {
        let events = vec![
            tool_call("bun test auth", "a"),
            tool_call("bun test auth", "b"),
            tool_call("bun test auth", "c"),
        ];
        let findings = RetryWasteDetector::new().find(&events);
        assert!(findings.iter().any(|f| f.kind == "repeated_command"));
        assert!(findings.iter().any(|f| f.count >= 3));
    }

    #[test]
    fn detects_repeated_error() {
        let events = vec![
            error_ev("TypeError: x is not a function", "e1"),
            error_ev("TypeError: x is not a function", "e2"),
        ];
        let findings = RetryWasteDetector::new().find(&events);
        assert!(findings.iter().any(|f| f.kind == "repeated_error"));
    }

    #[test]
    fn no_finding_for_unique_commands() {
        let events = vec![
            tool_call("ls", "a"),
            tool_call("pwd", "b"),
            tool_call("cat x", "c"),
        ];
        let findings = RetryWasteDetector::new().find(&events);
        assert!(!findings.iter().any(|f| f.kind == "repeated_command"));
    }
}
