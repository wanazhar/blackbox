//! Ordered trajectory diff between two runs (greedy LCP) + explain text.

use std::collections::HashSet;

use serde::Serialize;

use crate::core::event::{EventStatus, TraceEvent};

/// Semantic key for alignment (ignores harness-internal tool_use ids).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrajectoryKey {
    pub kind: String,
    pub tool_or_kind: String,
    pub status: String,
}

impl TrajectoryKey {
    pub fn from_event(ev: &TraceEvent) -> Self {
        let tool_or_kind = ev
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or(ev.kind.as_str())
            .to_string();
        let status = format!("{:?}", ev.status);
        Self {
            kind: ev.kind.clone(),
            tool_or_kind,
            status,
        }
    }

    pub fn label(&self) -> String {
        if self.kind == "tool.call" {
            format!("tool.{} ({})", self.tool_or_kind, self.status)
        } else {
            format!("{} ({})", self.kind, self.status)
        }
    }
}

/// Filter to semantic events for trajectory comparison.
pub fn semantic_events(events: &[TraceEvent]) -> Vec<&TraceEvent> {
    events
        .iter()
        .filter(|e| {
            matches!(
                e.kind.as_str(),
                "tool.call"
                    | "tool.result"
                    | "harness.assistant"
                    | "harness.result"
                    | "harness.usage"
                    | "process.spawned"
                    | "process.exec"
                    | "filesystem.modified"
                    | "filesystem.created"
                    | "filesystem.deleted"
            ) || matches!(e.status, EventStatus::Error)
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct TrajectoryDiffView {
    pub run_a: String,
    pub run_b: String,
    pub common_prefix_len: usize,
    pub first_divergence: Option<DivergencePoint>,
    pub only_a: Vec<TrajectoryStep>,
    pub only_b: Vec<TrajectoryStep>,
    pub prefix: Vec<TrajectoryStep>,
    /// Human-readable explanation of where/why the runs diverge.
    #[serde(default)]
    pub explanation: String,
    /// Suggested follow-up command for agents.
    #[serde(default)]
    pub next_hint: String,
    /// Files touched only after divergence in A.
    #[serde(default)]
    pub files_only_a: Vec<String>,
    /// Files touched only after divergence in B.
    #[serde(default)]
    pub files_only_b: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DivergencePoint {
    pub index: usize,
    pub a: Option<TrajectoryStep>,
    pub b: Option<TrajectoryStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrajectoryStep {
    pub sequence: u64,
    pub kind: String,
    pub label: String,
    pub status: String,
}

impl TrajectoryStep {
    fn from_event(ev: &TraceEvent) -> Self {
        let key = TrajectoryKey::from_event(ev);
        Self {
            sequence: ev.sequence,
            kind: ev.kind.clone(),
            label: key.label(),
            status: format!("{:?}", ev.status),
        }
    }
}

fn paths_after_seq(events: &[TraceEvent], min_seq: u64) -> Vec<String> {
    let mut set = HashSet::new();
    let mut out = Vec::new();
    for ev in events {
        if ev.sequence < min_seq {
            continue;
        }
        if !ev.kind.starts_with("filesystem.") && !ev.kind.contains("write") {
            // Include tool-side local writes when path present
            if ev.side_effect != crate::core::event::SideEffect::LocalWrite
                && ev.side_effect != crate::core::event::SideEffect::Destructive
            {
                continue;
            }
        }
        if let Some(p) = ev.metadata.get("path").and_then(|v| v.as_str()) {
            if set.insert(p.to_string()) {
                out.push(p.to_string());
            }
        }
    }
    out.truncate(30);
    out
}

fn explain(
    lcp: usize,
    div: &Option<DivergencePoint>,
    only_a: &[TrajectoryStep],
    only_b: &[TrajectoryStep],
    files_a: &[String],
    files_b: &[String],
) -> (String, String) {
    if div.is_none() && only_a.is_empty() && only_b.is_empty() {
        return (
            "Trajectories share a full semantic prefix — no tool-level divergence.".into(),
            "Runs are aligned; compare postmortems if outcomes still differ.".into(),
        );
    }
    let mut parts = Vec::new();
    parts.push(format!("Shared semantic prefix: {lcp} step(s)."));
    if let Some(d) = div {
        match (&d.a, &d.b) {
            (Some(a), Some(b)) => {
                parts.push(format!(
                    "First divergence at index {}: A did «{}» while B did «{}».",
                    d.index, a.label, b.label
                ));
            }
            (Some(a), None) => {
                parts.push(format!(
                    "After prefix, only A continued (first extra: «{}»).",
                    a.label
                ));
            }
            (None, Some(b)) => {
                parts.push(format!(
                    "After prefix, only B continued (first extra: «{}»).",
                    b.label
                ));
            }
            _ => {}
        }
    }
    if !only_a.is_empty() || !only_b.is_empty() {
        parts.push(format!(
            "Tail length: A has {} exclusive step(s), B has {}.",
            only_a.len(),
            only_b.len()
        ));
    }
    if !files_a.is_empty() || !files_b.is_empty() {
        parts.push(format!(
            "Files after divergence — only A: {}; only B: {}.",
            if files_a.is_empty() {
                "none".into()
            } else {
                files_a
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if files_b.is_empty() {
                "none".into()
            } else {
                files_b
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }

    let hint = if let Some(d) = div {
        if let (Some(a), Some(b)) = (&d.a, &d.b) {
            format!(
                "Inspect seq {} on A and seq {} on B (`blackbox timeline <id> --semantic`)",
                a.sequence, b.sequence
            )
        } else {
            "Inspect the first exclusive step on the longer run with `blackbox timeline <id> --semantic`".into()
        }
    } else {
        "Compare postmortems: `blackbox postmortem <a>` vs `blackbox postmortem <b>`".into()
    };

    (parts.join(" "), hint)
}

/// Greedy longest common prefix on semantic keys, then tails + explanation.
pub fn diff_trajectories(
    run_a: &str,
    events_a: &[TraceEvent],
    run_b: &str,
    events_b: &[TraceEvent],
) -> TrajectoryDiffView {
    let sem_a = semantic_events(events_a);
    let sem_b = semantic_events(events_b);
    let keys_a: Vec<_> = sem_a.iter().map(|e| TrajectoryKey::from_event(e)).collect();
    let keys_b: Vec<_> = sem_b.iter().map(|e| TrajectoryKey::from_event(e)).collect();

    let mut lcp = 0usize;
    while lcp < keys_a.len() && lcp < keys_b.len() && keys_a[lcp] == keys_b[lcp] {
        lcp += 1;
    }

    let prefix: Vec<_> = sem_a
        .iter()
        .take(lcp)
        .map(|e| TrajectoryStep::from_event(e))
        .collect();

    let first_divergence = if lcp < keys_a.len() || lcp < keys_b.len() {
        Some(DivergencePoint {
            index: lcp,
            a: sem_a.get(lcp).map(|e| TrajectoryStep::from_event(e)),
            b: sem_b.get(lcp).map(|e| TrajectoryStep::from_event(e)),
        })
    } else {
        None
    };

    let only_a: Vec<_> = sem_a
        .iter()
        .skip(lcp)
        .map(|e| TrajectoryStep::from_event(e))
        .collect();
    let only_b: Vec<_> = sem_b
        .iter()
        .skip(lcp)
        .map(|e| TrajectoryStep::from_event(e))
        .collect();

    // Files after the sequence of the last common step (or 0)
    let min_seq_a = only_a.first().map(|s| s.sequence).unwrap_or(u64::MAX);
    let min_seq_b = only_b.first().map(|s| s.sequence).unwrap_or(u64::MAX);
    let files_only_a = if min_seq_a == u64::MAX {
        Vec::new()
    } else {
        paths_after_seq(events_a, min_seq_a)
    };
    let files_only_b = if min_seq_b == u64::MAX {
        Vec::new()
    } else {
        paths_after_seq(events_b, min_seq_b)
    };

    // Symmetric difference of file sets for "only" display
    let set_a: HashSet<_> = files_only_a.iter().cloned().collect();
    let set_b: HashSet<_> = files_only_b.iter().cloned().collect();
    let files_only_a: Vec<_> = files_only_a
        .into_iter()
        .filter(|p| !set_b.contains(p))
        .collect();
    let files_only_b: Vec<_> = files_only_b
        .into_iter()
        .filter(|p| !set_a.contains(p))
        .collect();

    let (explanation, next_hint) = explain(
        lcp,
        &first_divergence,
        &only_a,
        &only_b,
        &files_only_a,
        &files_only_b,
    );

    TrajectoryDiffView {
        run_a: run_a.to_string(),
        run_b: run_b.to_string(),
        common_prefix_len: lcp,
        first_divergence,
        only_a,
        only_b,
        prefix,
        explanation,
        next_hint,
        files_only_a,
        files_only_b,
    }
}

/// Human-readable compare text for CLI / agents.
pub fn format_diff_text(d: &TrajectoryDiffView) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Compare {} vs {}  common_prefix={}\n",
        &d.run_a[..8.min(d.run_a.len())],
        &d.run_b[..8.min(d.run_b.len())],
        d.common_prefix_len
    ));
    if !d.explanation.is_empty() {
        out.push_str(&format!("Explain: {}\n", d.explanation));
    }
    if !d.next_hint.is_empty() {
        out.push_str(&format!("Next: {}\n", d.next_hint));
    }
    if let Some(div) = &d.first_divergence {
        out.push_str(&format!("First divergence at index {}\n", div.index));
        if let Some(a) = &div.a {
            out.push_str(&format!("  A: seq={} {}\n", a.sequence, a.label));
        }
        if let Some(b) = &div.b {
            out.push_str(&format!("  B: seq={} {}\n", b.sequence, b.label));
        }
    }
    if !d.files_only_a.is_empty() {
        out.push_str(&format!(
            "Files only after divergence in A: {}\n",
            d.files_only_a.join(", ")
        ));
    }
    if !d.files_only_b.is_empty() {
        out.push_str(&format!(
            "Files only after divergence in B: {}\n",
            d.files_only_b.join(", ")
        ));
    }
    if !d.only_a.is_empty() {
        out.push_str(&format!("Only in A ({}):\n", d.only_a.len()));
        for s in d.only_a.iter().take(15) {
            out.push_str(&format!("  seq={} {}\n", s.sequence, s.label));
        }
    }
    if !d.only_b.is_empty() {
        out.push_str(&format!("Only in B ({}):\n", d.only_b.len()));
        for s in d.only_b.iter().take(15) {
            out.push_str(&format!("  seq={} {}\n", s.sequence, s.label));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};

    fn tool(seq: u64, name: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("r", EventSource::Tool, "tool.call");
        ev.sequence = seq;
        ev.status = EventStatus::Success;
        ev.side_effect = SideEffect::Read;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!(name));
        ev
    }

    fn fs(seq: u64, path: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("r", EventSource::Filesystem, "filesystem.modified");
        ev.sequence = seq;
        ev.status = EventStatus::Success;
        ev.side_effect = SideEffect::LocalWrite;
        ev.metadata.insert("path".into(), serde_json::json!(path));
        ev
    }

    #[test]
    fn lcp_and_divergence() {
        let a = vec![tool(1, "Read"), tool(2, "Bash"), tool(3, "Write")];
        let b = vec![tool(1, "Read"), tool(2, "Edit"), tool(3, "Write")];
        let d = diff_trajectories("a", &a, "b", &b);
        assert_eq!(d.common_prefix_len, 1);
        assert!(d.first_divergence.is_some());
        assert_eq!(d.only_a.len(), 2);
        assert_eq!(d.only_b.len(), 2);
        assert!(d.explanation.contains("divergence"));
        assert!(!d.next_hint.is_empty());
    }

    #[test]
    fn files_after_divergence() {
        let a = vec![tool(1, "Read"), tool(2, "Bash"), fs(3, "src/a.rs")];
        let b = vec![tool(1, "Read"), tool(2, "Edit"), fs(3, "src/b.rs")];
        let d = diff_trajectories("a", &a, "b", &b);
        assert!(d.files_only_a.iter().any(|p| p == "src/a.rs"));
        assert!(d.files_only_b.iter().any(|p| p == "src/b.rs"));
        let text = format_diff_text(&d);
        assert!(text.contains("Explain:"));
    }
}
