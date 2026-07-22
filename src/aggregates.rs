//! Incremental, recoverable per-run aggregates (1.5 L1).
//!
//! Totals and first/last anchors must not depend on summary/postmortem
//! event-load windows. Aggregates are updated on each insert and can be
//! recomputed from the event table after interruption.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};

/// Cap unique path / process identity sets stored in aggregates payload.
const UNIQUE_SET_CAP: usize = 10_000;

/// Pointer to a salient event kept inside aggregates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateEventRef {
    /// Event id.
    pub event_id: String,
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Event or item kind string.
    pub kind: String,
    /// Short detail (instruction text, error message, tool name, …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Incremental counters and anchors for one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAggregates {
    /// Owning run id.
    pub run_id: String,
    /// Events total.
    pub events_total: u64,
    /// Counts keyed by source name (e.g. `"Tool"`).
    #[serde(default)]
    pub by_source: BTreeMap<String, u64>,
    /// Counts keyed by event kind.
    #[serde(default)]
    pub by_kind: BTreeMap<String, u64>,
    /// Tool calls.
    pub tool_calls: u64,
    /// Tool results.
    pub tool_results: u64,
    /// Tool failures.
    pub tool_failures: u64,
    /// Count of create/modify/rename/remove filesystem operations
    /// (`filesystem.created|modified|renamed|removed`, plus legacy `file.*`/`fs.*`).
    pub file_ops: u64,
    /// Unique project-relative (or reported) paths touched by file ops.
    #[serde(default)]
    pub files_touched_unique: u64,
    /// Side effect writes.
    pub side_effect_writes: u64,
    /// Total process-source events (spawned, exited, resource samples, …).
    #[serde(default)]
    pub process_events: u64,
    /// Unique process identities observed (prefer `pid` + `start_time` when present).
    ///
    /// One process with many resource samples counts as one.
    pub processes_observed: u64,
    /// Internal set backing `files_touched_unique` (capped).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    files_touched: BTreeSet<String>,
    /// Internal set backing `processes_observed` (capped).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    process_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// First human instruction.
    pub first_human_instruction: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// First failure.
    pub first_failure: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Last failure.
    pub last_failure: Option<AggregateEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// First session id.
    pub first_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Last session id.
    pub last_session_id: Option<String>,
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Total tokens.
    pub total_tokens: u64,
    #[serde(default)]
    /// Models.
    pub models: Vec<String>,
    #[serde(default)]
    /// Providers.
    pub providers: Vec<String>,
    /// Capture lag samples.
    pub capture_lag_samples: u64,
    /// Capture send failures.
    pub capture_send_failures: u64,
    /// Capture-layer failure events (`capture.layer.failed`, etc.) — not generic run failures.
    #[serde(default)]
    pub capture_failures: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// First timestamp.
    pub first_timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Last timestamp.
    pub last_timestamp: Option<DateTime<Utc>>,
    /// Last sequence.
    pub last_sequence: u64,
    /// True when aggregates match the full event table (or were rebuilt from it).
    pub aggregates_complete: bool,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl RunAggregates {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
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
            files_touched_unique: 0,
            side_effect_writes: 0,
            process_events: 0,
            processes_observed: 0,
            files_touched: BTreeSet::new(),
            process_ids: BTreeSet::new(),
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
            capture_failures: 0,
            first_timestamp: None,
            last_timestamp: None,
            last_sequence: 0,
            aggregates_complete: true,
            updated_at: Utc::now(),
        }
    }

    /// Fold one persisted event into the aggregate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `observe` — see module docs for full workflow.
    /// ```
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
            k if is_file_op_kind(k) => {
                self.file_ops = self.file_ops.saturating_add(1);
                if let Some(path) = file_path_from(event) {
                    if self.files_touched.len() < UNIQUE_SET_CAP {
                        self.files_touched.insert(path);
                    }
                    self.files_touched_unique = self.files_touched.len() as u64;
                }
            }
            k if k.starts_with("process.") => {
                self.process_events = self.process_events.saturating_add(1);
                // Observer lifecycle is not a process identity.
                if k != "process.observer.started" && k != "process.observer.stopped" {
                    if let Some(id) = process_identity_from(event) {
                        if self.process_ids.len() < UNIQUE_SET_CAP {
                            self.process_ids.insert(id);
                        }
                        self.processes_observed = self.process_ids.len() as u64;
                    }
                }
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
                self.capture_failures = self.capture_failures.saturating_add(1);
            }
            if event.kind == "capture.layer.failed"
                || event.kind == "capture.failed"
                || event.kind.ends_with(".capture_failed")
            {
                // capture_failures already counted for layer.failed above
                if event.kind != "capture.layer.failed" {
                    self.capture_failures = self.capture_failures.saturating_add(1);
                }
            }
        }

        self.updated_at = Utc::now();
    }

    /// Alias for [`observe`](Self::observe).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `apply` — see module docs for full workflow.
    /// ```
    #[inline]
    pub fn apply(&mut self, event: &TraceEvent) {
        self.observe(event);
    }

    /// Rebuild aggregates from a full event list (recovery path).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `recompute` — see module docs for full workflow.
    /// ```
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

/// True for create/modify/rename/remove filesystem operation events.
fn is_file_op_kind(kind: &str) -> bool {
    matches!(
        kind,
        "filesystem.created"
            | "filesystem.modified"
            | "filesystem.renamed"
            | "filesystem.removed"
            | "file.created"
            | "file.modified"
            | "file.renamed"
            | "file.removed"
            | "fs.created"
            | "fs.modified"
            | "fs.renamed"
            | "fs.removed"
    ) || kind.starts_with("file.")
        || kind.starts_with("fs.")
}

fn file_path_from(event: &TraceEvent) -> Option<String> {
    for key in ["path", "rel_path", "relative_path", "from", "to"] {
        if let Some(s) = event.metadata.get(key).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Prefer `pid` + `start_time` / `starttime`; fall back to pid alone.
fn process_identity_from(event: &TraceEvent) -> Option<String> {
    let pid = event
        .metadata
        .get("pid")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_i64().map(|n| n.to_string()))
                .or_else(|| v.as_str().map(|s| s.trim().to_string()))
        })
        .filter(|s| !s.is_empty())?;
    let start = event
        .metadata
        .get("start_time")
        .or_else(|| event.metadata.get("starttime"))
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_i64().map(|n| n.to_string()))
                .or_else(|| v.as_str().map(|s| s.trim().to_string()))
        })
        .filter(|s| !s.is_empty());
    Some(match start {
        Some(st) => format!("{pid}:{st}"),
        None => pid,
    })
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
    /// Events total.
    pub events_total: u64,
    /// Events loaded.
    pub events_loaded: usize,
    /// e.g. `head_tail_salient`, `full`, `tail_only`
    pub strategy: String,
    /// Aggregates complete.
    pub aggregates_complete: bool,
    /// Event evidence complete.
    pub event_evidence_complete: bool,
    #[serde(default)]
    /// Limitations.
    pub limitations: Vec<String>,
}

impl AnalysisScope {
    /// Full.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `full` — see module docs for full workflow.
    /// ```
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

    #[test]
    fn filesystem_ops_increment_file_ops_and_unique_paths() {
        let run = "r3";
        let mut agg = RunAggregates::new(run);

        for (i, kind) in [
            "filesystem.created",
            "filesystem.modified",
            "filesystem.renamed",
            "filesystem.removed",
        ]
        .iter()
        .enumerate()
        {
            let mut e = TraceEvent::new(run, EventSource::Filesystem, kind);
            e.sequence = (i + 1) as u64;
            e.metadata
                .insert("path".into(), serde_json::json!(format!("src/f{i}.rs")));
            agg.observe(&e);
        }
        // Second modify of same path should not increase unique count.
        let mut again = TraceEvent::new(run, EventSource::Filesystem, "filesystem.modified");
        again.sequence = 5;
        again
            .metadata
            .insert("path".into(), serde_json::json!("src/f1.rs"));
        agg.observe(&again);

        // Snapshots / overflow are not file ops.
        let mut snap = TraceEvent::new(run, EventSource::Filesystem, "filesystem.snapshot");
        snap.sequence = 6;
        agg.observe(&snap);

        assert_eq!(agg.file_ops, 5);
        assert_eq!(agg.files_touched_unique, 4);
    }

    #[test]
    fn capture_failures_count_layer_and_capture_failed() {
        let run = "r-cap";
        let mut agg = RunAggregates::new(run);
        let mut layer = TraceEvent::new(run, EventSource::System, "capture.layer.failed");
        layer.sequence = 1;
        agg.observe(&layer);
        let mut cap = TraceEvent::new(run, EventSource::System, "capture.failed");
        cap.sequence = 2;
        agg.observe(&cap);
        // Only kinds under the capture.* prefix are counted.
        let mut other = TraceEvent::new(run, EventSource::System, "capture.pty.capture_failed");
        other.sequence = 3;
        agg.observe(&other);
        assert_eq!(agg.capture_failures, 3);
        assert_eq!(agg.capture_send_failures, 1); // layer.failed only
    }

    #[test]
    fn process_samples_count_as_one_unique_process() {
        let run = "r4";
        let mut agg = RunAggregates::new(run);

        let mut spawned = TraceEvent::new(run, EventSource::Process, "process.spawned");
        spawned.sequence = 1;
        spawned.metadata.insert("pid".into(), serde_json::json!(42));
        spawned
            .metadata
            .insert("start_time".into(), serde_json::json!(1000));
        agg.observe(&spawned);

        for i in 0..10 {
            let mut sample = TraceEvent::new(run, EventSource::Process, "process.resource.sample");
            sample.sequence = 2 + i;
            sample.metadata.insert("pid".into(), serde_json::json!(42));
            sample
                .metadata
                .insert("start_time".into(), serde_json::json!(1000));
            agg.observe(&sample);
        }

        let mut other = TraceEvent::new(run, EventSource::Process, "process.spawned");
        other.sequence = 20;
        other.metadata.insert("pid".into(), serde_json::json!(99));
        agg.observe(&other);

        assert_eq!(agg.process_events, 12);
        assert_eq!(agg.processes_observed, 2);
    }
}
