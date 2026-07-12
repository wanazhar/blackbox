//! Ordered trajectory diff between two runs (greedy LCP).

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

/// Greedy longest common prefix on semantic keys, then tails.
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

    TrajectoryDiffView {
        run_a: run_a.to_string(),
        run_b: run_b.to_string(),
        common_prefix_len: lcp,
        first_divergence,
        only_a,
        only_b,
        prefix,
    }
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

    #[test]
    fn lcp_and_divergence() {
        let a = vec![tool(1, "Read"), tool(2, "Bash"), tool(3, "Write")];
        let b = vec![tool(1, "Read"), tool(2, "Edit"), tool(3, "Write")];
        let d = diff_trajectories("a", &a, "b", &b);
        assert_eq!(d.common_prefix_len, 1);
        assert!(d.first_divergence.is_some());
        assert_eq!(d.only_a.len(), 2);
        assert_eq!(d.only_b.len(), 2);
    }
}
