//! First-class anomaly markers for agent runs.
//!
//! Surfaces loops, destructive side effects, token spikes, long silences, and
//! runaway process trees — as structured markers, not buried event kinds.

use std::collections::HashMap;

use crate::core::event::{EventStatus, SideEffect, TraceEvent};

/// A first-class anomaly worth showing in postmortem / TUI.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct Anomaly {
    /// Stable kind: `tool_loop`, `destructive`, `token_spike`, `long_silence`,
    /// `error_storm`, `process_fanout`.
    pub kind: String,
    /// Severity: `info` | `warn` | `high`.
    pub severity: String,
    /// Detail.
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Event id.
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Monotonic sequence number within the run.
    pub sequence: Option<u64>,
    /// How many times / magnitude when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

/// Detect anomalies from a run event stream (deterministic, no LLM).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `detect_anomalies` — see module docs for full workflow.
/// ```
pub fn detect_anomalies(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut out = Vec::new();
    out.extend(detect_tool_loops(events));
    out.extend(detect_destructive(events));
    out.extend(detect_error_storm(events));
    out.extend(detect_token_spike(events));
    out.extend(detect_long_silence(events));
    out.extend(detect_process_fanout(events));
    // Highest severity first, then sequence
    out.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then(a.sequence.unwrap_or(0).cmp(&b.sequence.unwrap_or(0)))
    });
    out.truncate(20);
    out
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "high" => 3,
        "warn" => 2,
        _ => 1,
    }
}

fn detect_tool_loops(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut counts: HashMap<String, (usize, Option<String>, Option<u64>)> = HashMap::new();
    for ev in events {
        if ev.kind != "tool.call" {
            continue;
        }
        let name = ev
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("tool");
        // Include short command fingerprint when present
        let cmd = ev
            .metadata
            .get("input")
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let sig = if cmd.is_empty() {
            name.to_string()
        } else {
            let end = cmd.floor_char_boundary(80.min(cmd.len()));
            format!("{name}:{cmd}", cmd = &cmd[..end])
        };
        let e = counts.entry(sig).or_insert((0, None, None));
        e.0 += 1;
        e.1 = Some(ev.id.clone());
        e.2 = Some(ev.sequence);
    }
    let mut out = Vec::new();
    for (sig, (count, id, seq)) in counts {
        if count >= 5 {
            out.push(Anomaly {
                kind: "tool_loop".into(),
                severity: if count >= 10 { "high" } else { "warn" }.into(),
                detail: format!("tool loop: «{sig}» invoked {count} times"),
                event_id: id,
                sequence: seq,
                count: Some(count),
            });
        }
    }
    out
}

fn detect_destructive(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut out = Vec::new();
    for ev in events {
        if ev.side_effect == SideEffect::Destructive {
            let path = ev
                .metadata
                .get("path")
                .or_else(|| ev.metadata.get("tool_name"))
                .and_then(|v| v.as_str())
                .unwrap_or(ev.kind.as_str());
            out.push(Anomaly {
                kind: "destructive".into(),
                severity: "high".into(),
                detail: format!("destructive side effect: {path}"),
                event_id: Some(ev.id.clone()),
                sequence: Some(ev.sequence),
                count: None,
            });
        }
        // Heuristic: rm -rf / git reset --hard in tool input
        if ev.kind == "tool.call" {
            let blob = ev
                .metadata
                .get("input")
                .map(|v| v.to_string())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if blob.contains("rm -rf")
                || blob.contains("rm -fr")
                || blob.contains("git reset --hard")
                || blob.contains("drop table")
                || blob.contains("mkfs.")
            {
                out.push(Anomaly {
                    kind: "destructive".into(),
                    severity: "high".into(),
                    detail: "tool input matches destructive command pattern".into(),
                    event_id: Some(ev.id.clone()),
                    sequence: Some(ev.sequence),
                    count: None,
                });
            }
        }
    }
    out
}

fn detect_error_storm(events: &[TraceEvent]) -> Vec<Anomaly> {
    // Sliding window: ≥5 errors within 10 consecutive semantic events
    let mut window: Vec<&TraceEvent> = Vec::new();
    let mut out = Vec::new();
    for ev in events {
        if !matches!(
            ev.kind.as_str(),
            "tool.call" | "tool.result" | "process.exec" | "process.spawned"
        ) && ev.status != EventStatus::Error
        {
            continue;
        }
        window.push(ev);
        if window.len() > 10 {
            window.remove(0);
        }
        let errs = window
            .iter()
            .filter(|e| e.status == EventStatus::Error)
            .count();
        if errs >= 5 {
            let last = window.last().copied();
            out.push(Anomaly {
                kind: "error_storm".into(),
                severity: "high".into(),
                detail: format!("{errs} errors in a short window of tool/process events"),
                event_id: last.map(|e| e.id.clone()),
                sequence: last.map(|e| e.sequence),
                count: Some(errs),
            });
            break; // one storm marker is enough
        }
    }
    out
}

fn detect_token_spike(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut samples: Vec<(u64, u64, String)> = Vec::new(); // seq, tokens, id
    for ev in events {
        let tokens = ev
            .metadata
            .get("total_tokens")
            .or_else(|| ev.metadata.get("output_tokens"))
            .or_else(|| ev.metadata.get("tokens"))
            .and_then(|v| v.as_u64())
            .or_else(|| {
                // Nested usage object
                ev.metadata
                    .get("usage")
                    .and_then(|u| u.get("total_tokens").or_else(|| u.get("output_tokens")))
                    .and_then(|v| v.as_u64())
            });
        if let Some(t) = tokens {
            if t > 0 {
                samples.push((ev.sequence, t, ev.id.clone()));
            }
        }
    }
    if samples.len() < 2 {
        // Single large sample still worth flagging
        if let Some((seq, t, id)) = samples.first() {
            if *t >= 50_000 {
                return vec![Anomaly {
                    kind: "token_spike".into(),
                    severity: "warn".into(),
                    detail: format!("large token sample: {t} tokens"),
                    event_id: Some(id.clone()),
                    sequence: Some(*seq),
                    count: Some(*t as usize),
                }];
            }
        }
        return Vec::new();
    }
    let mut out = Vec::new();
    for w in samples.windows(2) {
        let (s0, t0, _) = &w[0];
        let (s1, t1, id1) = &w[1];
        let _ = s0;
        if *t0 > 0 && *t1 >= t0.saturating_mul(3) && *t1 >= 10_000 {
            out.push(Anomaly {
                kind: "token_spike".into(),
                severity: if *t1 >= 80_000 { "high" } else { "warn" }.into(),
                detail: format!("token spike: {t0} → {t1} (≥3× jump)"),
                event_id: Some(id1.clone()),
                sequence: Some(*s1),
                count: Some(*t1 as usize),
            });
        }
    }
    // Also flag absolute large total
    if let Some((seq, t, id)) = samples.iter().max_by_key(|(_, t, _)| *t) {
        if *t >= 100_000 {
            out.push(Anomaly {
                kind: "token_spike".into(),
                severity: "high".into(),
                detail: format!("very high token sample: {t}"),
                event_id: Some(id.clone()),
                sequence: Some(*seq),
                count: Some(*t as usize),
            });
        }
    }
    out
}

fn detect_long_silence(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut out = Vec::new();
    let mut last: Option<&TraceEvent> = None;
    for ev in events {
        // Skip pure resource samples for silence calc
        if ev.kind.starts_with("process.resource") || ev.kind.contains("observer") {
            continue;
        }
        if let Some(prev) = last {
            let gap_ms = (ev.started_at - prev.started_at).num_milliseconds();
            if gap_ms >= 120_000 {
                // 2 minutes
                out.push(Anomaly {
                    kind: "long_silence".into(),
                    severity: if gap_ms >= 600_000 { "high" } else { "warn" }.into(),
                    detail: format!(
                        "silence of {:.1}m between seq {} and {}",
                        gap_ms as f64 / 60_000.0,
                        prev.sequence,
                        ev.sequence
                    ),
                    event_id: Some(ev.id.clone()),
                    sequence: Some(ev.sequence),
                    count: Some(gap_ms as usize),
                });
            }
        }
        last = Some(ev);
    }
    out.truncate(5);
    out
}

fn detect_process_fanout(events: &[TraceEvent]) -> Vec<Anomaly> {
    let mut pids = HashSetLite::default();
    let mut last_seq = None;
    let mut last_id = None;
    for ev in events {
        if ev.kind == "process.exec"
            || ev.kind == "process.spawned"
            || ev.kind == "process.discovered"
        {
            if let Some(pid) = ev.metadata.get("pid").and_then(|v| v.as_u64()) {
                pids.insert(pid);
                last_seq = Some(ev.sequence);
                last_id = Some(ev.id.clone());
            }
        }
    }
    if pids.len() >= 25 {
        vec![Anomaly {
            kind: "process_fanout".into(),
            severity: if pids.len() >= 50 { "high" } else { "warn" }.into(),
            detail: format!(
                "process tree fan-out: {} distinct PIDs observed",
                pids.len()
            ),
            event_id: last_id,
            sequence: last_seq,
            count: Some(pids.len()),
        }]
    } else {
        Vec::new()
    }
}

/// Tiny HashSet without importing HashSet name clash in tests.
#[derive(Default)]
struct HashSetLite {
    inner: std::collections::HashSet<u64>,
}
impl HashSetLite {
    fn insert(&mut self, v: u64) -> bool {
        self.inner.insert(v)
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
    use chrono::{Duration, Utc};

    fn tool_call(seq: u64, name: &str, cmd: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("r", EventSource::Tool, "tool.call");
        ev.sequence = seq;
        ev.status = EventStatus::Success;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!(name));
        ev.metadata
            .insert("input".into(), serde_json::json!({ "command": cmd }));
        ev
    }

    #[test]
    fn detects_tool_loop() {
        let mut events = Vec::new();
        for i in 0..6 {
            events.push(tool_call(i, "Bash", "cargo test"));
        }
        let a = detect_anomalies(&events);
        assert!(a.iter().any(|x| x.kind == "tool_loop"));
    }

    #[test]
    fn detects_destructive_side_effect() {
        let mut ev = TraceEvent::new("r", EventSource::Filesystem, "filesystem.deleted");
        ev.sequence = 1;
        ev.side_effect = SideEffect::Destructive;
        ev.metadata
            .insert("path".into(), serde_json::json!("/tmp/important"));
        let a = detect_anomalies(&[ev]);
        assert!(a
            .iter()
            .any(|x| x.kind == "destructive" && x.severity == "high"));
    }

    #[test]
    fn detects_error_storm() {
        let mut events = Vec::new();
        for i in 0..8 {
            let mut ev = TraceEvent::new("r", EventSource::Tool, "tool.result");
            ev.sequence = i;
            ev.status = EventStatus::Error;
            events.push(ev);
        }
        let a = detect_anomalies(&events);
        assert!(a.iter().any(|x| x.kind == "error_storm"));
    }

    #[test]
    fn detects_long_silence() {
        let mut a = TraceEvent::new("r", EventSource::Tool, "tool.call");
        a.sequence = 1;
        a.started_at = Utc::now() - Duration::minutes(10);
        let mut b = TraceEvent::new("r", EventSource::Tool, "tool.call");
        b.sequence = 2;
        b.started_at = Utc::now();
        let anoms = detect_anomalies(&[a, b]);
        assert!(anoms.iter().any(|x| x.kind == "long_silence"));
    }

    #[test]
    fn detects_token_spike() {
        let mut a = TraceEvent::new("r", EventSource::System, "harness.usage");
        a.sequence = 1;
        a.metadata
            .insert("total_tokens".into(), serde_json::json!(5_000u64));
        let mut b = TraceEvent::new("r", EventSource::System, "harness.usage");
        b.sequence = 2;
        b.metadata
            .insert("total_tokens".into(), serde_json::json!(40_000u64));
        let anoms = detect_anomalies(&[a, b]);
        assert!(anoms.iter().any(|x| x.kind == "token_spike"));
    }
}
