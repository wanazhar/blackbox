//! Incremental, recoverable per-run aggregates (1.5 L1).
//!
//! Totals and first/last anchors must not depend on summary/postmortem
//! event-load windows. Aggregates are updated on each insert and can be
//! recomputed from the event table after interruption.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};

/// Pointer to a salient event kept inside aggregates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateEventRef {
    pub event_id: String,
    pub sequence: u64,
    pub kind: String,
    /// Short detail (instruction text, error message, tool name, …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Incremental counters and anchors for one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAggregates {
    pub run_id: String,
    pub events_total: u64,
    /// Counts keyed by source name (e.g. `"Tool"`).
    #[serde(default)]
    pub by_source: BTreeMap<String, u64>,
    /// Counts keyed by event kind.
    #[serde(default)]
    pub by_kind: BTreeMap<String, u64>,
    pub tool_calls: u64,
    pub tool_results: u64,
    pub tool_failures: u64,
    pub file_ops: u64,
    pub side_effect_writes: u64,
    pub processes_observed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_human_instruction: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failure: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_session_id: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    pub capture_lag_samples: u64,
    pub capture_send_failures: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<DateTime<Utc>>,
    pub last_sequence: u64,
    /// True when aggregates match the full event table (or were rebuilt from it).
    pub aggregates_complete: bool,
    pub updated_at: DateTime<Utc>,
}

impl RunAggregates {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            events_total: 0,
            by_source: BTreeMap::new(),
            by_kind: BTreeMap::new(),
            tool_calls: 0,
            tool_results: 0,
            tool_failures: 0,
            file_ops: 0,
            side_effect_writes: 0,
            processes_observed: 0,
            first_human_instruction: None,
            first_failure: None,
            last_failure: None,
            first_session_id: None,
            last_session_id: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            models: Vec::new(),
            providers: Vec::new(),
            capture_lag_samples: 0,
            capture_send_failures: 0,
            first_timestamp: None,
            last_timestamp: None,
            last_sequence: 0,
            aggregates_complete: true,
            updated_at: Utc::now(),
        }
    }

    /// Fold one persisted event into the aggregate.
    pub fn observe(&mut self, event: &TraceEvent) {
        self.events_total = self.events_total.saturating_add(1);

        let sk = source_key(&event.source);
        *self.by_source.entry(sk).or_insert(0) += 1;
        *self.by_kind.entry(event.kind.clone()).or_insert(0) += 1;

        if event.sequence > self.last_sequence {
            self.last_sequence = event.sequence;
        }

        match self.first_timestamp {
            None => self.first_timestamp = Some(event.started_at),
            Some(t) if event.started_at < t => self.first_timestamp = Some(event.started_at),
            _ => {}
        }
        match self.last_timestamp {
            None => self.last_timestamp = Some(event.started_at),
            Some(t) if event.started_at > t => self.last_timestamp = Some(event.started_at),
            _ => {}
        }

        match event.kind.as_str() {
            "tool.call" => {
                self.tool_calls = self.tool_calls.saturating_add(1);
                if matches!(event.status, EventStatus::Error) {
                    self.tool_failures = self.tool_failures.saturating_add(1);
                }
            }
            "tool.result" => {
                self.tool_results = self.tool_results.saturating_add(1);
                if matches!(event.status, EventStatus::Error) {
                    self.tool_failures = self.tool_failures.saturating_add(1);
                }
            }
            k if k.starts_with("file.") || k.starts_with("fs.") => {
                self.file_ops = self.file_ops.saturating_add(1);
            }
            k if k.starts_with("process.") => {
                self.processes_observed = self.processes_observed.saturating_add(1);
            }
            _ => {}
        }

        if matches!(
            event.side_effect,
            SideEffect::LocalWrite | SideEffect::ExternalWrite | SideEffect::Destructive
        ) {
            self.side_effect_writes = self.side_effect_writes.saturating_add(1);
        }

        if self.first_human_instruction.is_none() && is_human_instruction(event) {
            if let Some(detail) = human_text(event) {
                self.first_human_instruction = Some(AggregateEventRef {
                    event_id: event.id.clone(),
                    sequence: event.sequence,
                    kind: event.kind.clone(),
                    detail: crate::util::truncate(&detail, 200),
                });
            }
        }

        if is_failure(event) {
            let detail = failure_detail(event);
            let r = AggregateEventRef {
                event_id: event.id.clone(),
                sequence: event.sequence,
                kind: event.kind.clone(),
                detail,
            };
            if self.first_failure.is_none() {
                self.first_failure = Some(r.clone());
            }
            self.last_failure = Some(r);
        }

        if let Some(sid) = session_id_from(event) {
            if self.first_session_id.is_none() {
                self.first_session_id = Some(sid.clone());
            }
            self.last_session_id = Some(sid);
        }

        accumulate_tokens(self, event);
        push_unique(&mut self.models, model_from(event));
        push_unique(&mut self.providers, provider_from(event));

        if event.kind.starts_with("capture.") {
            if let Some(bp) = event.metadata.get("backpressure") {
                if let Some(lag) = bp.get("lag_samples").and_then(|v| v.as_u64()) {
                    self.capture_lag_samples = self.capture_lag_samples.max(lag);
                }
                if let Some(sf) = bp.get("send_failures").and_then(|v| v.as_u64()) {
                    self.capture_send_failures = self.capture_send_failures.max(sf);
                }
            }
            if let Some(lag) = event.metadata.get("lag_samples").and_then(|v| v.as_u64()) {
                self.capture_lag_samples = self.capture_lag_samples.max(lag);
            }
            if event.kind == "capture.layer.failed" {
                self.capture_send_failures = self.capture_send_failures.saturating_add(1);
            }
        }

        self.updated_at = Utc::now();
    }

    /// Alias for [`observe`](Self::observe).
    #[inline]
    pub fn apply(&mut self, event: &TraceEvent) {
        self.observe(event);
    }

    /// Rebuild aggregates from a full event list (recovery path).
    pub fn recompute(run_id: &str, events: &[TraceEvent]) -> Self {
        let mut agg = Self::new(run_id);
        for ev in events {
            agg.observe(ev);
        }
        agg.aggregates_complete = true;
        agg
    }
}

fn source_key(source: &EventSource) -> String {
    match source {
        EventSource::Human => "Human".into(),
        EventSource::Harness => "Harness".into(),
        EventSource::Terminal => "Terminal".into(),
        EventSource::Process => "Process".into(),
        EventSource::Filesystem => "Filesystem".into(),
        EventSource::Git => "Git".into(),
        EventSource::Tool => "Tool".into(),
        EventSource::Network => "Network".into(),
        EventSource::Browser => "Browser".into(),
        EventSource::System => "System".into(),
    }
}

fn is_human_instruction(event: &TraceEvent) -> bool {
    matches!(event.source, EventSource::Human)
        || event.kind == "human.input"
        || event.kind == "user.message"
        || event.kind == "human.instruction"
}

fn human_text(event: &TraceEvent) -> Option<String> {
    event
        .metadata
        .get("text")
        .or_else(|| event.metadata.get("message"))
        .or_else(|| event.metadata.get("content"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn is_failure(event: &TraceEvent) -> bool {
    matches!(event.status, EventStatus::Error)
        || event.kind == "error"
        || event.kind.ends_with(".error")
        || (event.kind == "tool.result"
            && event
                .metadata
                .get("is_error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false))
}

fn failure_detail(event: &TraceEvent) -> String {
    event
        .metadata
        .get("message")
        .or_else(|| event.metadata.get("error"))
        .or_else(|| event.metadata.get("tool_name"))
        .and_then(|v| v.as_str())
        .map(|s| crate::util::truncate(s, 200))
        .unwrap_or_else(|| event.kind.clone())
}

fn session_id_from(event: &TraceEvent) -> Option<String> {
    for key in ["session_id", "harness_session_id", "conversation_id"] {
        if let Some(s) = event.metadata.get(key).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn accumulate_tokens(agg: &mut RunAggregates, event: &TraceEvent) {
    let meta = &event.metadata;
    let input = meta
        .get("input_tokens")
        .or_else(|| meta.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = meta
        .get("output_tokens")
        .or_else(|| meta.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total = meta
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(input.saturating_add(output));
    if input == 0 && output == 0 && total == 0 {
        return;
    }
    // Count only on usage-bearing events to avoid double-count on every tool row.
    let usage_like = event.kind.contains("usage")
        || event.kind.contains("token")
        || event.kind == "model.response"
        || event.kind == "llm.usage"
        || meta.get("input_tokens").is_some()
        || meta.get("total_tokens").is_some();
    if !usage_like {
        return;
    }
    agg.input_tokens = agg.input_tokens.saturating_add(input);
    agg.output_tokens = agg.output_tokens.saturating_add(output);
    if total > 0 {
        agg.total_tokens = agg.total_tokens.saturating_add(total);
    } else {
        agg.total_tokens = agg
            .total_tokens
            .saturating_add(input.saturating_add(output));
    }
}

fn model_from(event: &TraceEvent) -> Option<String> {
    event
        .metadata
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn provider_from(event: &TraceEvent) -> Option<String> {
    event
        .metadata
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn push_unique(list: &mut Vec<String>, value: Option<String>) {
    if let Some(v) = value {
        if !list.iter().any(|x| x == &v) {
            list.push(v);
            if list.len() > 32 {
                list.remove(0);
            }
        }
    }
}

/// What analysis loaded vs total facts available (1.5 L2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisScope {
    pub events_total: u64,
    pub events_loaded: usize,
    /// e.g. `head_tail_salient`, `full`, `tail_only`
    pub strategy: String,
    pub aggregates_complete: bool,
    pub event_evidence_complete: bool,
    #[serde(default)]
    pub limitations: Vec<String>,
}

impl AnalysisScope {
    pub fn full(events_total: u64) -> Self {
        Self {
            events_total,
            events_loaded: events_total as usize,
            strategy: "full".into(),
            aggregates_complete: true,
            event_evidence_complete: true,
            limitations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};

    #[test]
    fn observes_tools_and_human_and_failure() {
        let run = "r1";
        let mut agg = RunAggregates::new(run);

        let mut human = TraceEvent::new(run, EventSource::Human, "human.input");
        human.sequence = 1;
        human
            .metadata
            .insert("text".into(), serde_json::json!("fix the flaky test"));
        agg.observe(&human);

        let mut call = TraceEvent::new(run, EventSource::Tool, "tool.call");
        call.sequence = 2;
        call.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        agg.observe(&call);

        let mut err = TraceEvent::new(run, EventSource::Tool, "tool.result");
        err.sequence = 3;
        err.status = EventStatus::Error;
        err.metadata
            .insert("message".into(), serde_json::json!("exit 1"));
        agg.observe(&err);

        for i in 4..104 {
            let mut e = TraceEvent::new(run, EventSource::Terminal, "terminal.output");
            e.sequence = i;
            agg.observe(&e);
        }

        assert_eq!(agg.events_total, 103);
        assert_eq!(agg.tool_calls, 1);
        assert_eq!(agg.tool_results, 1);
        assert_eq!(agg.tool_failures, 1);
        assert_eq!(
            agg.first_human_instruction.as_ref().unwrap().detail,
            "fix the flaky test"
        );
        assert_eq!(agg.first_failure.as_ref().unwrap().sequence, 3);
        assert_eq!(agg.last_failure.as_ref().unwrap().sequence, 3);
        assert_eq!(agg.by_kind.get("terminal.output"), Some(&100));
    }

    #[test]
    fn recompute_matches_incremental() {
        let run = "r2";
        let mut events = Vec::new();
        for i in 1..=50 {
            let mut e = TraceEvent::new(run, EventSource::System, "run.tick");
            e.sequence = i;
            events.push(e);
        }
        let mut a = RunAggregates::new(run);
        for e in &events {
            a.observe(e);
        }
        let b = RunAggregates::recompute(run, &events);
        assert_eq!(a.events_total, b.events_total);
        assert_eq!(a.by_kind, b.by_kind);
        assert_eq!(a.last_sequence, 50);
    }
}
