//! Turning-point detection for postmortem narratives.
//!
//! Highlights first failure, first corrective edit, verification, and unresolved warnings.

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};

/// A meaningful turning point in a run's execution story.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TurningPoint {
    pub kind: String,
    pub detail: String,
    pub event_id: Option<String>,
    pub sequence: Option<u64>,
}

/// Detect deterministic turning points from an event stream.
pub fn detect_turning_points(events: &[TraceEvent]) -> Vec<TurningPoint> {
    let mut points = Vec::new();
    let mut first_tool = false;
    let mut first_failure = false;
    let mut first_write = false;
    let mut first_verify_pass = false;

    for ev in events {
        // First meaningful tool/process work
        if !first_tool
            && (ev.kind == "tool.call"
                || ev.kind == "process.exec"
                || ev.kind == "process.spawned")
        {
            first_tool = true;
            let label = ev
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ev.metadata
                        .get("argv")
                        .and_then(|a| a.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                })
                .unwrap_or(ev.kind.as_str());
            points.push(TurningPoint {
                kind: "first_attempt".into(),
                detail: format!("First work: {label}"),
                event_id: Some(ev.id.clone()),
                sequence: Some(ev.sequence),
            });
        }

        if !first_failure
            && (ev.status == EventStatus::Error
                || ev
                    .metadata
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .map(|c| c != 0)
                    .unwrap_or(false))
        {
            first_failure = true;
            let msg = ev
                .metadata
                .get("message")
                .or_else(|| ev.metadata.get("error_message"))
                .and_then(|v| v.as_str())
                .unwrap_or(ev.kind.as_str());
            let msg = if msg.len() > 100 {
                format!("{}…", &msg[..msg.floor_char_boundary(100)])
            } else {
                msg.to_string()
            };
            points.push(TurningPoint {
                kind: "first_failure".into(),
                detail: format!("First failure: {msg}"),
                event_id: Some(ev.id.clone()),
                sequence: Some(ev.sequence),
            });
        }

        if !first_write
            && (ev.side_effect == SideEffect::LocalWrite
                || (ev.source == EventSource::Filesystem
                    && !ev.kind.contains("observer")
                    && !ev.kind.contains("snapshot")))
        {
            first_write = true;
            let path = ev
                .metadata
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("workspace");
            points.push(TurningPoint {
                kind: "corrective_change".into(),
                detail: format!("First write: {path}"),
                event_id: Some(ev.id.clone()),
                sequence: Some(ev.sequence),
            });
        }

        // Final verification: successful test/build-ish tool after a failure
        if first_failure
            && !first_verify_pass
            && ev.kind == "tool.result"
            && ev.status == EventStatus::Success
        {
            let prev_call = events
                .iter()
                .rev()
                .find(|e| e.kind == "tool.call" && e.sequence < ev.sequence);
            let looks_like_verify = prev_call
                .and_then(|e| e.metadata.get("input"))
                .and_then(|i| i.get("command").and_then(|c| c.as_str()).or(i.as_str()))
                .map(|c| {
                    let l = c.to_lowercase();
                    l.contains("test")
                        || l.contains("cargo check")
                        || l.contains("pytest")
                        || l.contains("npm test")
                        || l.contains("bun test")
                        || l.contains("make test")
                })
                .unwrap_or(false);
            if looks_like_verify {
                first_verify_pass = true;
                points.push(TurningPoint {
                    kind: "verification".into(),
                    detail: "Verification succeeded after prior failure".into(),
                    event_id: Some(ev.id.clone()),
                    sequence: Some(ev.sequence),
                });
            }
        }
    }

    // Unresolved: last error without later success verification
    if first_failure && !first_verify_pass {
        if let Some(ev) = events
            .iter()
            .rev()
            .find(|e| e.status == EventStatus::Error)
        {
            points.push(TurningPoint {
                kind: "unresolved".into(),
                detail: "Run ended with unresolved failure (no successful verification after)"
                    .into(),
                event_id: Some(ev.id.clone()),
                sequence: Some(ev.sequence),
            });
        }
    }

    points
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ev(kind: &str, status: EventStatus) -> TraceEvent {
        let mut e = TraceEvent::new("r", EventSource::Tool, kind);
        e.status = status;
        e.started_at = Utc::now();
        e
    }

    #[test]
    fn detects_first_failure_and_unresolved() {
        let mut call = ev("tool.call", EventStatus::Running);
        call.sequence = 1;
        let mut err = ev("tool.result", EventStatus::Error);
        err.sequence = 2;
        err.metadata
            .insert("message".into(), serde_json::json!("boom"));
        let points = detect_turning_points(&[call, err]);
        assert!(points.iter().any(|p| p.kind == "first_failure"));
        assert!(points.iter().any(|p| p.kind == "unresolved"));
    }
}
